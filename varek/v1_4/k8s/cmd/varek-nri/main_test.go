// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"varek.dev/varek-k8s/internal/kube"
)

// a stand-in for the Warden: it writes a small filter for any policy, or
// fails for one named "bad", or takes 5 s for one named "slow"; v1.35: it
// is given the pod's plan (--plan FILE) or --no-plan, refuses --no-plan for
// a policy named "needsplan" and a plan named "badplan", and writes what it
// was given to calls beside itself; v1.36: for a policy named "creds" it
// names the credential gh (varekCredentials), for "credsbad" one that is
// not a credential's name, and copies the credential list it was given
// beside itself
const fakeWarden = `#!/bin/sh
echo "$*" >> "$(dirname "$0")/calls"
for a in "$@"; do [ "$prev" = --credential-list ] && cp "$a" "$(dirname "$0")/list.seen"; prev="$a"; done
case "$1" in */bad.policy) echo "[warden] policy: line 1: no" >&2; exit 1 ;; esac
case "$1" in */slow.policy) exec sleep 5 ;; esac
[ "$2" = --oci-filter ] || exit 2
case "$3" in --plan) [ -f "$4" ] || exit 2; case "$4" in */badplan.plan) echo "[warden] --oci-filter: the plan $4: the plan does not read: line 2: an unknown kind of step" >&2; exit 1 ;; esac ;;
  --no-plan) case "$1" in */needsplan.policy) echo "[warden] --oci-filter: the policy says ` + "`require plan`" + `: a pod under it names its plan (varek.dev/plan)" >&2; exit 1 ;; esac ;;
  *) exit 2 ;; esac
creds=; case "$1" in */creds.policy) creds=',"varekCredentials":["gh"]' ;; */credsbad.policy) creds=',"varekCredentials":["GH-x"]' ;; esac
echo '{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64"],"syscalls":[{"names":["openat"],"action":"SCMP_ACT_NOTIFY","args":[]},{"names":["ioctl"],"action":"SCMP_ACT_ALLOW","args":[{"index":1,"value":21505,"valueTwo":0,"op":"SCMP_CMP_EQ"}]}]'"$creds"'}'
`

func setup(t *testing.T) *plugin {
	d := t.TempDir()
	w := filepath.Join(d, "warden")
	if err := os.WriteFile(w, []byte(fakeWarden), 0o755); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(d, "policies")
	os.MkdirAll(filepath.Join(pol, "ns"), 0o755)
	for _, n := range []string{"agent", "bad", "slow", "needsplan", "creds", "credsbad"} {
		os.WriteFile(filepath.Join(pol, "ns", n+".policy"), []byte("allow path /tmp/\n"), 0o644)
	}
	// the filter is kept by the bytes' hash: the Warden's verdict is theirs
	os.WriteFile(filepath.Join(pol, "ns", "needsplan.policy"), []byte("require warden 1.35\nrequire plan\nallow path /tmp/\n"), 0o644)
	// v1.36 step 4: each its own bytes (the filter, and the credentials it names, are kept by them)
	os.WriteFile(filepath.Join(pol, "ns", "creds.policy"), []byte("credential gh from file:/var/lib/varek/credentials/gh/token\n"), 0o644)
	os.WriteFile(filepath.Join(pol, "ns", "credsbad.policy"), []byte("credential bad from file:/x\n"), 0o644)
	for _, n := range []string{"p1", "p2", "badplan"} { // v1.35 step 4c
		os.WriteFile(filepath.Join(pol, "ns", n+".plan"), []byte("plan 1.35\naction a file_open /tmp/"+n+"\n"), 0o644)
	}
	return &plugin{warden: w, policies: pol, listener: "/run/varek/node.sock", launcher: "/opt/varek/varek-init",
		handlers: map[string]bool{"runc": true, "crun": true}, filters: map[string]*ociProfile{}}
}

func pod(ann map[string]string) *api.PodSandbox {
	return &api.PodSandbox{Name: "p", Namespace: "ns", Uid: "u-1", Annotations: ann}
}

// a container as the runtime describes it: its own namespaces, VAREK's
// unsupervised profile
func ctr(args ...string) *api.Container {
	l := &api.LinuxContainer{SeccompProfile: &api.SecurityProfile{ProfileType: api.SecurityProfile_LOCALHOST,
		LocalhostRef: "/var/lib/kubelet/seccomp/varek/unsupervised.json"}}
	for _, t := range []string{"pid", "network", "ipc", "uts", "mount"} {
		l.Namespaces = append(l.Namespaces, &api.LinuxNamespace{Type: t, Path: "/proc/1/ns/" + t})
	}
	return &api.Container{Name: "c", Args: args, Linux: l, Mounts: []*api.Mount{
		{Destination: "/work", Type: "bind", Source: "/var/lib/x", Options: []string{"rbind", "rw"}},
		{Destination: "/etc/config", Type: "bind", Source: "/var/lib/y", Options: []string{"rbind", "ro"}},
		{Destination: "/dev/shm", Type: "bind", Source: "/run/shm", Options: []string{"rbind", "noexec"}},
		{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid"}},
	}}
}

func TestOtherPodsLeftAlone(t *testing.T) {
	p := setup(t)
	adj, err := p.adjust(context.Background(), pod(map[string]string{"other": "x"}), ctr("/bin/agent"))
	if adj != nil || err != nil {
		t.Fatalf("a pod without %s: %v %v", annotation, adj, err)
	}
}

func TestAdjustment(t *testing.T) {
	p := setup(t)
	adj, err := p.adjust(context.Background(), pod(map[string]string{annotation: "agent"}), ctr("/bin/agent", "--flag"))
	if err != nil || adj == nil {
		t.Fatalf("adjust: %v", err)
	}
	if got := strings.Join(adj.GetArgs(), " "); got != "/varek/init -- /bin/agent --flag" {
		t.Errorf("args: %q", got)
	}
	s := adj.GetLinux().GetSeccompPolicy()
	if s == nil || s.ListenerPath != "/run/varek/node.sock" || s.ListenerMetadata != "ns/p/c" || len(s.Syscalls) != 2 ||
		s.DefaultAction != "SCMP_ACT_ERRNO" || s.DefaultErrno.GetValue() != 1 || s.Syscalls[1].Args[0].Value != 21505 {
		t.Errorf("seccomp policy: %+v", s)
	}
	mounts := map[string][]string{}
	for _, m := range adj.GetMounts() {
		mounts[m.Destination] = m.Options
	}
	if strings.Join(mounts["/varek/init"], ",") != "bind,ro,nosuid,nodev" {
		t.Errorf("the launcher's mount: %v", mounts["/varek/init"])
	}
	if !has(mounts["/work"], "noexec") || !has(mounts["/work"], "rw") {
		t.Errorf("a writable mount made noexec: %v", mounts["/work"])
	}
	for _, d := range []string{"/etc/config", "/dev/shm", "/proc"} {
		if _, ok := mounts[d]; ok {
			t.Errorf("%s (read-only, noexec already, or proc) changed", d)
		}
	}
	if a := adj.GetAnnotations(); a["varek.dev/pod-namespace"] != "ns" || a["varek.dev/pod-name"] != "p" ||
		a["varek.dev/pod-uid"] != "u-1" || a["varek.dev/container"] != "c" {
		t.Errorf("the pod's names in the container's annotations: %v", a)
	}
	if want := sha256.Sum256([]byte("allow path /tmp/\n")); adj.GetAnnotations()["varek.dev/policy-sha256"] != hex.EncodeToString(want[:]) {
		t.Errorf("the policy's SHA-256: %v", adj.GetAnnotations())
	}
	if adj.GetAnnotations()[annotation] != "agent" {
		t.Errorf("the policy's name in the container's annotations: %v", adj.GetAnnotations())
	}
}

func TestRefused(t *testing.T) {
	p := setup(t)
	for _, c := range []struct {
		name string
		ann  string
		args []string
		why  string
	}{
		{"no command", "agent", nil, "no command"},
		{"a relative command", "agent", []string{"python"}, "absolute path"},
		{"the launcher already", "agent", []string{"/varek/init", "--", "/bin/x"}, "already /varek/init"},
		{"a bad name", "Agent_1", []string{"/bin/x"}, "is not 1 to 63"},
		{"a name too long", strings.Repeat("a", 64), []string{"/bin/x"}, "is not 1 to 63"},
		{"no such policy", "nosuch", []string{"/bin/x"}, "no policy named nosuch"},
		{"a policy the Warden refuses", "bad", []string{"/bin/x"}, "does not write the filter for policy bad"},
	} {
		adj, err := p.adjust(context.Background(), pod(map[string]string{annotation: c.ann}), ctr(c.args...))
		if adj != nil || err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v %v", c.name, adj, err)
		}
	}
	// review (G-1, G-4, G-5): what the runtime describes
	for _, c := range []struct {
		name   string
		change func(*api.PodSandbox, *api.Container)
		why    string
	}{
		{"a sandboxed runtime", func(p *api.PodSandbox, _ *api.Container) { p.RuntimeHandler = "kata" }, `runtime handler "kata"`},
		{"the node's network", func(_ *api.PodSandbox, c *api.Container) { c.Linux.Namespaces = c.Linux.Namespaces[:1] }, "node's network namespace"},
		{"the node's PID namespace", func(_ *api.PodSandbox, c *api.Container) { c.Linux.Namespaces = c.Linux.Namespaces[1:] }, "node's pid namespace"},
		{"the runtime's default profile", func(_ *api.PodSandbox, c *api.Container) {
			c.Linux.SeccompProfile = &api.SecurityProfile{ProfileType: api.SecurityProfile_RUNTIME_DEFAULT}
		}, "its seccomp profile is RUNTIME_DEFAULT"},
		{"another Localhost profile", func(_ *api.PodSandbox, c *api.Container) {
			c.Linux.SeccompProfile.LocalhostRef = "/var/lib/kubelet/seccomp/other/unsupervised.json.x"
		}, "not Localhost varek/unsupervised.json"},
		{"a policy that allows", func(_ *api.PodSandbox, c *api.Container) {
			c.Linux.SeccompProfile = nil
			c.Linux.SeccompPolicy = &api.LinuxSeccomp{DefaultAction: "SCMP_ACT_ALLOW"}
		}, "default is SCMP_ACT_ALLOW"},
	} {
		pd, k := pod(map[string]string{annotation: "agent"}), ctr("/bin/x")
		c.change(pd, k)
		adj, err := p.adjust(context.Background(), pd, k)
		if adj != nil || err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v %v", c.name, adj, err)
		}
	}
	for _, h := range []string{"", "runc"} {
		pd := pod(map[string]string{annotation: "agent"})
		pd.RuntimeHandler = h
		if _, err := p.adjust(context.Background(), pd, ctr("/bin/x")); err != nil {
			t.Errorf("runtime handler %q: %v", h, err)
		}
	}
	k := ctr("/bin/x")
	k.Linux.SeccompProfile = nil
	k.Linux.SeccompPolicy = &api.LinuxSeccomp{DefaultAction: "SCMP_ACT_ERRNO"}
	if _, err := p.adjust(context.Background(), pod(map[string]string{annotation: "agent"}), k); err != nil {
		t.Errorf("the unsupervised profile known by its policy: %v", err)
	}
}

// G-1: the answer comes before the runtime's deadline, saying why
func TestDeadline(t *testing.T) {
	p := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	t0 := time.Now()
	_, _, err := p.CreateContainer(ctx, pod(map[string]string{annotation: "slow"}), ctr("/bin/x"))
	if err == nil || !strings.Contains(err.Error(), "in the time the runtime gives") {
		t.Fatalf("a filter not written in time: %v", err)
	}
	if d := time.Since(t0); d > time.Second-answerMargin/2 {
		t.Errorf("answered %v after a 1 s deadline", d)
	}
}

func TestFilterKeptByHash(t *testing.T) {
	p := setup(t)
	a, s1, _, err := filter3(p, "ns", "agent", "")
	b, s2, _, err2 := filter3(p, "ns", "agent", "")
	if err != nil || err2 != nil || a != b || s1 != s2 || len(s1) != 64 {
		t.Fatalf("kept: %v %v", err, err2)
	}
	os.WriteFile(filepath.Join(p.policies, "ns", "agent.policy"), []byte("allow path /tmp/\nallow path /var/\n"), 0o644)
	c, s3, _, err := filter3(p, "ns", "agent", "")
	if err != nil || c == a || s3 == s1 {
		t.Fatalf("a changed policy is written again, with its own hash: %v", err)
	}
	if _, _, _, err := filter3(p, "other", "agent", ""); err == nil || !strings.Contains(err.Error(), "in namespace other") {
		t.Fatalf("another namespace's policy: %v", err)
	}
	// v1.35 step 4c: kept by the policy's and the plan's hashes together
	d, _, ps1, err := filter3(p, "ns", "agent", "p1")
	e, _, ps2, err2 := filter3(p, "ns", "agent", "p2")
	if err != nil || err2 != nil || d == c || e == d || ps1 == ps2 || len(ps1) != 64 {
		t.Fatalf("a plan checked apart from the policy alone, and from another plan: %v %v", err, err2)
	}
}

// v1.35 step 4c (D11): a pod's plan, checked by the Warden with its policy,
// its name and SHA-256 in the container's annotations
func TestPlan(t *testing.T) {
	p := setup(t)
	adj, err := p.adjust(context.Background(), pod(map[string]string{annotation: "agent", planAnnotation: "p1"}), ctr("/bin/agent"))
	if err != nil || adj == nil {
		t.Fatalf("adjust: %v", err)
	}
	want := sha256.Sum256([]byte("plan 1.35\naction a file_open /tmp/p1\n"))
	if a := adj.GetAnnotations(); a[planAnnotation] != "p1" || a["varek.dev/plan-sha256"] != hex.EncodeToString(want[:]) {
		t.Errorf("the plan's name and SHA-256 in the container's annotations: %v", a)
	}
	calls, _ := os.ReadFile(filepath.Join(filepath.Dir(p.warden), "calls"))
	if !strings.Contains(string(calls), "--oci-filter --plan ") || !strings.Contains(string(calls), "/p1.plan") {
		t.Errorf("the Warden given the plan: %q", calls)
	}
	adj, err = p.adjust(context.Background(), pod(map[string]string{annotation: "agent"}), ctr("/bin/agent"))
	if err != nil || adj.GetAnnotations()[planAnnotation] != "" || adj.GetAnnotations()["varek.dev/plan-sha256"] != "" {
		t.Errorf("a pod naming no plan: %v %v", err, adj.GetAnnotations())
	}
	if calls, _ = os.ReadFile(filepath.Join(filepath.Dir(p.warden), "calls")); !strings.Contains(string(calls), "--oci-filter --no-plan") {
		t.Errorf("the Warden told the pod names no plan: %q", calls)
	}
	for _, c := range []struct {
		what string
		ann  map[string]string
		why  string
	}{
		{"a plan name that is not one", map[string]string{annotation: "agent", planAnnotation: "Plan_1"}, "the plan name \"Plan_1\""},
		{"no such plan", map[string]string{annotation: "agent", planAnnotation: "nosuch"}, "no plan named nosuch in namespace ns"},
		{"a plan the Warden refuses", map[string]string{annotation: "agent", planAnnotation: "badplan"}, "the plan badplan.plan: the plan does not read"},
		{"`require plan`, no plan named", map[string]string{annotation: "needsplan"}, "a pod under it names its plan"},
	} {
		adj, err := p.adjust(context.Background(), pod(c.ann), ctr("/bin/x"))
		if adj != nil || err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v %v", c.what, adj, err)
		}
	}
}

func TestRuntimes(t *testing.T) {
	for _, c := range []struct {
		rt, v string
		ok    bool
	}{
		{"containerd", "v2.2.0", true}, {"containerd", "2.3.4", true}, {"containerd", "v2.1.4", false},
		{"containerd", "1.7.27", false}, {"cri-o", "1.35.0", true}, {"cri-o", "1.37.2", true},
		{"cri-o", "1.34.3", false}, {"podman", "5.0.0", false}, {"containerd", "garbage", false},
	} {
		if err := runtimeOK(c.rt, c.v); (err == nil) != c.ok {
			t.Errorf("%s %s: %v", c.rt, c.v, err)
		}
	}
}

// step 9: NRI before v0.12 writes a rule's errno through a nil pointer (CRI-O
// 1.35.9 panicked), so there no rule carries one
func TestRuleErrno(t *testing.T) {
	for _, c := range []struct {
		rt, v string
		ok    bool
	}{
		{"containerd", "v2.2.1", false}, {"containerd", "v2.3.0", true}, {"containerd", "2.3.5", true},
		{"cri-o", "1.35.9-12.rhaos4.22.git4c168db.el9", false}, {"cri-o", "1.36.3", false},
		{"cri-o", "1.37.0", true}, {"CRI-O", "2.0.0", true}, {"containerd", "garbage", false},
	} {
		if ruleErrnoOK(c.rt, c.v) != c.ok {
			t.Errorf("%s %s: %v", c.rt, c.v, !c.ok)
		}
	}
	u := func(v uint32) *uint32 { return &v }
	f := &ociProfile{DefaultAction: "SCMP_ACT_ERRNO", DefaultErrnoRet: u(1), Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []ociSyscall{
			{Names: []string{"ptrace"}, Action: "SCMP_ACT_ERRNO", ErrnoRet: u(1)},
			{Names: []string{"clone3"}, Action: "SCMP_ACT_ERRNO", ErrnoRet: u(38)},
			{Names: []string{"setsockopt"}, Action: "SCMP_ACT_ERRNO", ErrnoRet: u(13),
				Args: []ociArg{{Index: 1, Value: 0, ValueTwo: 0xffffffff, Op: "SCMP_CMP_MASKED_EQ"}}},
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"openat"}, Action: "SCMP_ACT_NOTIFY"},
		}}
	p := setup(t)
	s := p.policy(f, "ns/p/c")
	if s.Syscalls[1].ErrnoRet.GetValue() != 38 || s.Syscalls[1].Action != "SCMP_ACT_ERRNO" {
		t.Errorf("a runtime with NRI v0.12: the rule's errno kept: %+v", s.Syscalls[1])
	}
	p.noRuleErrno = true
	s = p.policy(f, "ns/p/c")
	want := []string{"SCMP_ACT_ERRNO", "SCMP_ACT_NOTIFY", "SCMP_ACT_NOTIFY", "SCMP_ACT_ALLOW", "SCMP_ACT_NOTIFY"}
	for i, r := range s.Syscalls {
		if r.ErrnoRet != nil || r.Action != want[i] || strings.Join(r.Names, ",") != strings.Join(f.Syscalls[i].Names, ",") {
			t.Errorf("rule %d: %+v, want %s and no errno", i, r, want[i])
		}
	}
	if len(s.Syscalls[2].Args) != 1 || s.Syscalls[2].Args[0].ValueTwo != 0xffffffff {
		t.Errorf("a notified rule keeps its arguments: %+v", s.Syscalls[2])
	}
}

// v1.36 step 4 (D1, D2): a policy that names credentials: the Warden given
// the cluster's list and the pod's namespace, each credential's placeholder
// set in the container's environment, made for that container
func TestCredentials(t *testing.T) {
	p := setup(t)
	list := "gh\tns\tfile:/var/lib/varek/credentials/gh/token\tgh-token\n"
	os.WriteFile(filepath.Join(p.policies, ".credentials"), []byte(list), 0o644)
	adj, err := p.adjust(context.Background(), pod(map[string]string{annotation: "creds"}), ctr("/bin/agent"))
	if err != nil || adj == nil {
		t.Fatalf("adjust: %v", err)
	}
	ph := ""
	for _, e := range adj.GetEnv() {
		if e.Key == "VAREK_CRED_GH" {
			ph = e.Value
		}
	}
	if len(ph) != len("varek_ph_gh_")+43 || !strings.HasPrefix(ph, "varek_ph_gh_") ||
		strings.Trim(ph[len("varek_ph_gh_"):], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		t.Errorf("the placeholder in the container's environment: %q (%v)", ph, adj.GetEnv())
	}
	d := filepath.Dir(p.warden)
	calls, _ := os.ReadFile(filepath.Join(d, "calls"))
	if !strings.Contains(string(calls), "--credential-list ") || !strings.Contains(string(calls), "--pod-namespace ns") {
		t.Errorf("the Warden given the list and the namespace: %q", calls)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "list.seen")); string(b) != list {
		t.Errorf("the Warden given the cluster's list (a copy): %q", b)
	}
	adj2, _ := p.adjust(context.Background(), pod(map[string]string{annotation: "creds"}), ctr("/bin/agent"))
	if adj2 == nil || len(adj2.GetEnv()) != 1 || adj2.GetEnv()[0].Value == ph {
		t.Errorf("a second container: its own placeholder (%v)", adj2.GetEnv())
	}
	// the list changed: checked again, not taken from the filters kept
	n := strings.Count(string(calls), "\n")
	os.WriteFile(filepath.Join(p.policies, ".credentials"), []byte(list+"x\tns\tfile:/x\tx\n"), 0o644)
	p.adjust(context.Background(), pod(map[string]string{annotation: "creds"}), ctr("/bin/agent"))
	if calls, _ = os.ReadFile(filepath.Join(d, "calls")); strings.Count(string(calls), "\n") != n+1 {
		t.Errorf("the list changed, the policy not checked again: %q", calls)
	}
	if adj, err := p.adjust(context.Background(), pod(map[string]string{annotation: "agent"}), ctr("/bin/agent")); err != nil || len(adj.GetEnv()) != 0 {
		t.Errorf("a policy naming no credential: no placeholder (%v, %v)", adj.GetEnv(), err)
	}
	if adj, err := p.adjust(context.Background(), pod(map[string]string{annotation: "credsbad"}), ctr("/bin/agent")); adj != nil || err == nil ||
		!strings.Contains(err.Error(), "not a credential's name") {
		t.Errorf("a name the Warden gives that is not a credential's: %v %v", adj, err)
	}
}

// v1.36 step 6 (D5): a pod acting for a user. The Secret's name goes in each
// container's annotations; the webhook's init container is let through as
// it is; one of its name otherwise is carried as any other
func TestOnBehalfOf(t *testing.T) {
	p := setup(t)
	p.oboImage = "registry.example/varek-node@sha256:abc"
	ann := map[string]string{annotation: "agent", oboAnnotation: "alice-token"}
	adj, err := p.adjust(context.Background(), pod(ann), ctr("/bin/agent"))
	if err != nil || adj == nil || adj.GetAnnotations()[oboAnnotation] != "alice-token" {
		t.Fatalf("the Secret's name in the container's annotations: %v %v", adj, err)
	}
	if adj, _ := p.adjust(context.Background(), pod(map[string]string{annotation: "agent"}), ctr("/bin/agent")); adj == nil ||
		adj.GetAnnotations()[oboAnnotation] != "" {
		t.Errorf("a pod acting for no one: %v", adj)
	} else if _, ok := adj.GetAnnotations()["-"+oboAnnotation]; !ok {
		t.Errorf("a pod acting for no one: the annotation removed (%v)", adj.GetAnnotations())
	}
	if _, err := p.adjust(context.Background(), pod(map[string]string{annotation: "agent", oboAnnotation: "Alice/x"}),
		ctr("/bin/agent")); err == nil || !strings.Contains(err.Error(), "not a Secret's name") {
		t.Errorf("a name that is not a Secret's: %v", err)
	}
	init := func(img *api.Image, args ...string) *api.Container {
		c := ctr(args...)
		c.Name, c.Image = oboInit, img
		c.Linux.SeccompProfile = &api.SecurityProfile{ProfileType: api.SecurityProfile_RUNTIME_DEFAULT}
		return c
	}
	for _, c := range []struct {
		what string
		img  *api.Image
	}{
		{"the runtime says no image", nil},
		{"its digest", &api.Image{Name: "registry.example/varek-node@sha256:abc", Digest: "sha256:abc"}},
	} {
		if adj, err := p.adjust(context.Background(), pod(ann), init(c.img, "/bin/true")); adj != nil || err != nil {
			t.Errorf("the init container, %s: let through as it is (%v %v)", c.what, adj, err)
		}
	}
	for _, c := range []struct {
		what string
		ann  map[string]string
		img  *api.Image
		args []string
	}{
		{"another image", ann, &api.Image{Name: "evil", Digest: "sha256:def"}, []string{"/bin/true"}},
		{"another command", ann, nil, []string{"/bin/sh", "-c", "x"}},
		{"a pod acting for no one", map[string]string{annotation: "agent"}, nil, []string{"/bin/true"}},
		{"another image by name", ann, &api.Image{Name: "varek-node:evil"}, []string{"/bin/true"}},
	} {
		if _, err := p.adjust(context.Background(), pod(c.ann), init(c.img, c.args...)); err == nil ||
			!strings.Contains(err.Error(), "seccomp profile is RUNTIME_DEFAULT") {
			t.Errorf("a container named %s, %s: carried as any other (refused here for its profile): %v", oboInit, c.what, err)
		}
	}
	// by name, as the runtime resolves it (the chart's image by its tag)
	p.oboImage = "varek-node:ci"
	if adj, err := p.adjust(context.Background(), pod(ann), init(&api.Image{Name: "docker.io/library/varek-node:ci"}, "/bin/true")); adj != nil || err != nil {
		t.Errorf("the image by its name as the runtime resolves it: %v %v", adj, err)
	}
	for ref, want := range map[string]string{"busybox": "docker.io/library/busybox", "kwdoug63/x:1": "docker.io/kwdoug63/x:1",
		"ghcr.io/kwdoug63/x:1": "ghcr.io/kwdoug63/x:1", "localhost/x": "localhost/x", "reg:5000/x": "reg:5000/x"} {
		if fullName(ref) != want {
			t.Errorf("fullName(%q) = %q", ref, fullName(ref))
		}
	}
}

// filter3 is filter's filter and its policy's and plan's SHA-256s
func filter3(p *plugin, ns, name, plan string) (*ociProfile, string, string, error) {
	fd, err := p.filter(context.Background(), ns, name, plan)
	if err != nil {
		return nil, "", "", err
	}
	return fd.f, fd.sha, fd.psha, nil
}

// a stand-in for the API server's pods (v1.36 step 7)
type fakePods map[string]*kube.Pod

func (f fakePods) GetPod(_ context.Context, ns, name string) (*kube.Pod, error) {
	return f[ns+"/"+name], nil
}

func apiPod(uid, sa string) *kube.Pod {
	o := &kube.Pod{}
	o.Metadata.UID, o.Spec.ServiceAccountName = uid, sa
	return o
}

// v1.36 step 7 (D6, D7, D7b): a VarekPolicy's dry run, trust bundle and flow
// policy, from the files -sync writes beside it
func TestDryRunTrustFlow(t *testing.T) {
	p := setup(t)
	dir := filepath.Join(p.policies, "ns")
	os.WriteFile(filepath.Join(dir, "dry.policy"), []byte("allow path /tmp/dry\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "dry.run"), []byte(`{"dryRun":true,"trustBundle":"corp.pem"}`+"\n"), 0o644)
	adj, err := p.adjust(context.Background(), pod(map[string]string{annotation: "dry"}), ctr("/bin/agent"))
	if err != nil {
		t.Fatalf("a dry run: %v", err)
	}
	a := adj.GetAnnotations()
	if a[dryAnnotation] != "true" || a[trustAnnotation] != "corp.pem" {
		t.Errorf("the dry run and trust bundle in the container's annotations: %v", a)
	}
	if _, ok := a[api.MarkForRemoval(flowAnnotation)]; !ok {
		t.Errorf("a flow policy's hash the container came with is removed: %v", a)
	}
	for _, m := range adj.GetMounts() {
		if m.Destination == "/work" {
			t.Errorf("a dry run makes no mount noexec: %v", m.Options)
		}
	}
	calls, _ := os.ReadFile(filepath.Join(filepath.Dir(p.warden), "calls"))
	if !strings.Contains(string(calls), "--dry-run") {
		t.Errorf("the Warden asked for a dry run's filter: %q", calls)
	}
	// the pod's own annotations are not taken
	adj, err = p.adjust(context.Background(), pod(map[string]string{annotation: "agent", dryAnnotation: "true",
		trustAnnotation: "x", flowAnnotation: strings.Repeat("a", 64), saAnnotation: "admin"}), ctr("/bin/agent"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{dryAnnotation, trustAnnotation, flowAnnotation, saAnnotation} {
		if _, ok := adj.GetAnnotations()[api.MarkForRemoval(k)]; !ok || adj.GetAnnotations()[k] != "" {
			t.Errorf("%s: the plugin's alone (removed for a policy that says none): %v", k, adj.GetAnnotations())
		}
	}
	// a flow policy: its hash, and the pod's service account from the API server
	os.WriteFile(filepath.Join(dir, "flowy.policy"), []byte("allow path /tmp/flowy\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "flowy.flow"), []byte("varek_policy 1\n"), 0o644)
	ann := map[string]string{annotation: "flowy", planAnnotation: "p1"}
	if _, err := p.adjust(context.Background(), pod(ann), ctr("/bin/agent")); err == nil || !strings.Contains(err.Error(), "-sync") {
		t.Errorf("a flow policy, and no API server to read the pod's service account from: %v", err)
	}
	p.api = fakePods{"ns/p": apiPod("u-1", "agent-sa")}
	adj, err = p.adjust(context.Background(), pod(ann), ctr("/bin/agent"))
	want := sha256.Sum256([]byte("varek_policy 1\n"))
	if err != nil || adj.GetAnnotations()[flowAnnotation] != hex.EncodeToString(want[:]) || adj.GetAnnotations()[saAnnotation] != "agent-sa" {
		t.Fatalf("a flow policy's hash and the pod's service account: %v %v", err, adj.GetAnnotations())
	}
	if calls, _ = os.ReadFile(filepath.Join(filepath.Dir(p.warden), "calls")); !strings.Contains(string(calls), "--flow-policy ") {
		t.Errorf("the Warden given the flow policy: %q", calls)
	}
	p.api = fakePods{"ns/p": apiPod("u-2", "agent-sa")}
	if _, err := p.adjust(context.Background(), pod(ann), ctr("/bin/agent")); err == nil || !strings.Contains(err.Error(), "of uid u-1") {
		t.Errorf("the API server's pod of another uid (created again by the name): %v", err)
	}
	p.api = fakePods{"ns/p": apiPod("u-1", "")}
	if adj, err = p.adjust(context.Background(), pod(ann), ctr("/bin/agent")); err != nil || adj.GetAnnotations()[saAnnotation] != "default" {
		t.Errorf("a pod naming no service account runs as default: %v", err)
	}
	// options that do not read, or a trust bundle that is not a key
	os.WriteFile(filepath.Join(dir, "dry.run"), []byte(`{"dryRun":true,"other":1}`), 0o644)
	if _, err := p.adjust(context.Background(), pod(map[string]string{annotation: "dry"}), ctr("/bin/agent")); err == nil {
		t.Errorf("options with an unknown field are refused")
	}
	os.WriteFile(filepath.Join(dir, "dry.run"), []byte(`{"trustBundle":"../x"}`), 0o644)
	if _, err := p.adjust(context.Background(), pod(map[string]string{annotation: "dry"}), ctr("/bin/agent")); err == nil ||
		!strings.Contains(err.Error(), "not a ConfigMap's key") {
		t.Errorf("a trust bundle that is not a key: %v", err)
	}
}
