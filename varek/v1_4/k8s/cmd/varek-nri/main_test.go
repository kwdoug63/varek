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
)

// a stand-in for the Warden: it writes a small filter for any policy, or
// fails for one named "bad", or takes 5 s for one named "slow"; v1.35: it
// is given the pod's plan (--plan FILE) or --no-plan, refuses --no-plan for
// a policy named "needsplan" and a plan named "badplan", and writes what it
// was given to calls beside itself
const fakeWarden = `#!/bin/sh
echo "$*" >> "$(dirname "$0")/calls"
case "$1" in */bad.policy) echo "[warden] policy: line 1: no" >&2; exit 1 ;; esac
case "$1" in */slow.policy) exec sleep 5 ;; esac
[ "$2" = --oci-filter ] || exit 2
case "$3" in --plan) [ -f "$4" ] || exit 2; case "$4" in */badplan.plan) echo "[warden] --oci-filter: the plan $4: the node agent does not carry mcp_call steps yet (step m)" >&2; exit 1 ;; esac ;;
  --no-plan) case "$1" in */needsplan.policy) echo "[warden] --oci-filter: the policy says ` + "`require plan`" + `: a pod under it names its plan (varek.dev/plan)" >&2; exit 1 ;; esac ;;
  *) exit 2 ;; esac
echo '{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64"],"syscalls":[{"names":["openat"],"action":"SCMP_ACT_NOTIFY","args":[]},{"names":["ioctl"],"action":"SCMP_ACT_ALLOW","args":[{"index":1,"value":21505,"valueTwo":0,"op":"SCMP_CMP_EQ"}]}]}'
`

func setup(t *testing.T) *plugin {
	d := t.TempDir()
	w := filepath.Join(d, "warden")
	if err := os.WriteFile(w, []byte(fakeWarden), 0o755); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(d, "policies")
	os.MkdirAll(filepath.Join(pol, "ns"), 0o755)
	for _, n := range []string{"agent", "bad", "slow", "needsplan"} {
		os.WriteFile(filepath.Join(pol, "ns", n+".policy"), []byte("allow path /tmp/\n"), 0o644)
	}
	// the filter is kept by the bytes' hash: the Warden's verdict is theirs
	os.WriteFile(filepath.Join(pol, "ns", "needsplan.policy"), []byte("require warden 1.35\nrequire plan\nallow path /tmp/\n"), 0o644)
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
	a, s1, _, err := p.filter(context.Background(), "ns", "agent", "")
	b, s2, _, err2 := p.filter(context.Background(), "ns", "agent", "")
	if err != nil || err2 != nil || a != b || s1 != s2 || len(s1) != 64 {
		t.Fatalf("kept: %v %v", err, err2)
	}
	os.WriteFile(filepath.Join(p.policies, "ns", "agent.policy"), []byte("allow path /tmp/\nallow path /var/\n"), 0o644)
	c, s3, _, err := p.filter(context.Background(), "ns", "agent", "")
	if err != nil || c == a || s3 == s1 {
		t.Fatalf("a changed policy is written again, with its own hash: %v", err)
	}
	if _, _, _, err := p.filter(context.Background(), "other", "agent", ""); err == nil || !strings.Contains(err.Error(), "in namespace other") {
		t.Fatalf("another namespace's policy: %v", err)
	}
	// v1.35 step 4c: kept by the policy's and the plan's hashes together
	d, _, ps1, err := p.filter(context.Background(), "ns", "agent", "p1")
	e, _, ps2, err2 := p.filter(context.Background(), "ns", "agent", "p2")
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
		{"a plan the Warden refuses", map[string]string{annotation: "agent", planAnnotation: "badplan"}, "the plan badplan.plan: the node agent does not carry mcp_call steps"},
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
