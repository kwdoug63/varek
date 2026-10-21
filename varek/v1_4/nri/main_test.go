// SPDX-License-Identifier: MIT
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// a stand-in for the Warden: it writes a small filter for any policy, or
// fails for one named "bad"
const fakeWarden = `#!/bin/sh
case "$1" in */bad.policy) echo "[warden] policy: line 1: no" >&2; exit 1 ;; esac
[ "$2" = --oci-filter ] || exit 2
echo '{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64"],"syscalls":[{"names":["openat"],"action":"SCMP_ACT_NOTIFY","args":[]},{"names":["ioctl"],"action":"SCMP_ACT_ALLOW","args":[{"index":1,"value":21505,"valueTwo":0,"op":"SCMP_CMP_EQ"}]}]}'
`

func setup(t *testing.T) *plugin {
	d := t.TempDir()
	w := filepath.Join(d, "warden")
	if err := os.WriteFile(w, []byte(fakeWarden), 0o755); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(d, "policies")
	os.Mkdir(pol, 0o755)
	for _, n := range []string{"agent", "bad"} {
		os.WriteFile(filepath.Join(pol, n+".policy"), []byte("allow path /tmp/\n"), 0o644)
	}
	return &plugin{warden: w, policies: pol, listener: "/run/varek/node.sock", launcher: "/opt/varek/varek-init",
		filters: map[string]cached{}}
}

func pod(ann map[string]string) *api.PodSandbox {
	return &api.PodSandbox{Name: "p", Namespace: "ns", Uid: "u-1", Annotations: ann}
}

func ctr(args ...string) *api.Container {
	return &api.Container{Name: "c", Args: args, Mounts: []*api.Mount{
		{Destination: "/work", Type: "bind", Source: "/var/lib/x", Options: []string{"rbind", "rw"}},
		{Destination: "/etc/config", Type: "bind", Source: "/var/lib/y", Options: []string{"rbind", "ro"}},
		{Destination: "/dev/shm", Type: "bind", Source: "/run/shm", Options: []string{"rbind", "noexec"}},
		{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid"}},
	}}
}

func TestOtherPodsLeftAlone(t *testing.T) {
	p := setup(t)
	adj, err := p.adjust(pod(map[string]string{"other": "x"}), ctr("/bin/agent"))
	if adj != nil || err != nil {
		t.Fatalf("a pod without %s: %v %v", annotation, adj, err)
	}
}

func TestAdjustment(t *testing.T) {
	p := setup(t)
	adj, err := p.adjust(pod(map[string]string{annotation: "agent"}), ctr("/bin/agent", "--flag"))
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
		adj, err := p.adjust(pod(map[string]string{annotation: c.ann}), ctr(c.args...))
		if adj != nil || err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v %v", c.name, adj, err)
		}
	}
}

func TestFilterCachedWhileUnchanged(t *testing.T) {
	p := setup(t)
	a, err := p.filter("agent")
	b, err2 := p.filter("agent")
	if err != nil || err2 != nil || a != b {
		t.Fatalf("cached: %v %v", err, err2)
	}
	os.WriteFile(filepath.Join(p.policies, "agent.policy"), []byte("allow path /tmp/\nallow path /var/\n"), 0o644)
	c, err := p.filter("agent")
	if err != nil || c == a {
		t.Fatalf("a changed policy is written again: %v", err)
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
