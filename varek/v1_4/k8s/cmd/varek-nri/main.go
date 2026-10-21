// SPDX-License-Identifier: MIT
//
// varek-nri — v1.34 step 3 (docs/security/v1.34-kubernetes.md, D3 and D4):
// VAREK's plugin for the Node Resource Interface, which containerd and CRI-O
// call as each container is created. It runs on each node beside the node
// agent (warden POLICY_DIR --node-agent ...). For each container of a pod
// annotated varek.dev/policy: NAME it asks the runtime for:
//   - the Warden's filter for that policy in OCI's form (written by the
//     Warden itself, warden POLICY_DIR/NAME.policy --oci-filter, so the
//     plugin carries no copy that could drift) as the container's seccomp
//     policy, its listenerPath the node agent's socket: the pod's own
//     profile (RuntimeDefault, as Pod Security's "restricted" requires) is
//     replaced;
//   - the launcher (varek-init) bound read-only, nosuid, nodev at
//     /varek/init and put first in the command: /varek/init -- COMMAND ...;
//   - every writable mount noexec (D4);
//   - the policy's name in the container's own annotations, since the state
//     the runtime sends the node agent carries the container's, not the pod's,
//     and the pod's namespace, name and uid and the container's name.
//
// A container that cannot be carried (no command, a command not named by an
// absolute path, a policy name that is not one, no such policy, a filter the
// Warden does not write) is refused: the runtime does not create it, and the
// reason is in the pod's events. Other pods are left as they are. The node
// agent checks what it receives again (the launcher's identity, the
// container's mounts, the root read-only) and refuses what does not hold.
//
// On a runtime whose NRI cannot set a seccomp policy or the command (NRI
// before v0.10: containerd before 2.2, CRI-O before 1.35) the plugin refuses
// to start, naming the version.
//
//	varek-nri -warden FILE -policies DIR -listener SOCKET -launcher FILE [-socket NRI_SOCKET] [-sync]
//
// v1.34 step 5: a pod's policy is POLICY_DIR/<namespace>/<name>.policy, and
// -sync writes there the cluster's VarekPolicy resources (sync.go).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	"varek.dev/varek-k8s/internal/kube"
)

const (
	annotation = "varek.dev/policy"
	launcherAt = "/varek/init"
)

var policyName = kube.Name

type ociArg struct {
	Index    uint32 `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo"`
	Op       string `json:"op"`
}

type ociSyscall struct {
	Names    []string `json:"names"`
	Action   string   `json:"action"`
	ErrnoRet *uint32  `json:"errnoRet"`
	Args     []ociArg `json:"args"`
}

type ociProfile struct {
	DefaultAction   string       `json:"defaultAction"`
	DefaultErrnoRet *uint32      `json:"defaultErrnoRet"`
	Architectures   []string     `json:"architectures"`
	Syscalls        []ociSyscall `json:"syscalls"`
}

type plugin struct {
	warden, policies, listener, launcher string
	mu                                   sync.Mutex
	filters                              map[string]*ociProfile // by the SHA-256 of the policy written for
}

// The runtimes whose NRI sets a seccomp policy and the command (v0.10)
var minRuntime = map[string][2]int{"containerd": {2, 2}, "cri-o": {1, 35}}

func version(v string) (int, int, bool) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	a, e1 := strconv.Atoi(parts[0])
	b, e2 := strconv.Atoi(strings.SplitN(parts[1], "-", 2)[0])
	return a, b, e1 == nil && e2 == nil
}

func runtimeOK(runtime, ver string) error {
	min, known := minRuntime[strings.ToLower(runtime)]
	if !known {
		return fmt.Errorf("varek-nri: runtime %s %s: only containerd (2.2 or later) and CRI-O (1.35 or later) are known to "+
			"let a plugin set a container's seccomp policy and command", runtime, ver)
	}
	a, b, ok := version(ver)
	if !ok || a < min[0] || (a == min[0] && b < min[1]) {
		return fmt.Errorf("varek-nri: runtime %s %s: its NRI cannot set a container's seccomp policy or command "+
			"(NRI v0.10, from %s %d.%d); refusing to start", runtime, ver, runtime, min[0], min[1])
	}
	return nil
}

func (p *plugin) Configure(_ context.Context, _, runtime, ver string) (api.EventMask, error) {
	if err := runtimeOK(runtime, ver); err != nil {
		return 0, err
	}
	fmt.Fprintf(os.Stderr, "varek-nri: runtime %s %s; policies in %s; node agent %s; launcher %s\n",
		runtime, ver, p.policies, p.listener, p.launcher)
	return api.MustParseEventMask("CreateContainer"), nil
}

// The Warden's filter, in OCI's form, for the policy of the pod's namespace
// (v1.34 step 5: POLICY_DIR/<namespace>/<name>.policy, as the policy sync
// writes each VarekPolicy resource), and the SHA-256 of the bytes it was
// written for: the node agent loads the policy again, and refuses it if it
// is not those bytes (it changed in between). The filter is written from a
// private copy of those bytes, and kept by their hash.
func (p *plugin) filter(ns, name string) (*ociProfile, string, error) {
	path := filepath.Join(p.policies, ns, name+".policy")
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return nil, "", fmt.Errorf("no policy named %s in namespace %s (%s)", name, ns, path)
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 8<<20 {
		return nil, "", fmt.Errorf("cannot read the policy %s (%v; at most 8 MiB)", path, err)
	}
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])
	p.mu.Lock()
	f, ok := p.filters[sha]
	p.mu.Unlock()
	if ok {
		return f, sha, nil
	}
	dir, err := os.MkdirTemp("", "varek-nri-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, name+".policy")
	if err := os.WriteFile(copyPath, b, 0o600); err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.warden, copyPath, "--oci-filter")
	var errb strings.Builder
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		return nil, "", fmt.Errorf("the Warden does not write the filter for policy %s: %v: %s", name, err, lastLine(errb.String()))
	}
	f = &ociProfile{}
	if err := json.Unmarshal(out, f); err != nil || len(f.Syscalls) == 0 {
		return nil, "", fmt.Errorf("the Warden's filter for policy %s does not read: %v", name, err)
	}
	p.mu.Lock()
	if len(p.filters) >= 256 {
		p.filters = map[string]*ociProfile{}
	}
	p.filters[sha] = f
	p.mu.Unlock()
	return f, sha, nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func optional(v *uint32) *api.OptionalUInt32 {
	if v == nil {
		return nil
	}
	return &api.OptionalUInt32{Value: *v}
}

// the filter as NRI's seccomp policy, with the node agent's socket
func (p *plugin) policy(f *ociProfile, meta string) *api.LinuxSeccomp {
	s := &api.LinuxSeccomp{
		DefaultAction:    f.DefaultAction,
		DefaultErrno:     optional(f.DefaultErrnoRet),
		Architectures:    f.Architectures,
		ListenerPath:     p.listener,
		ListenerMetadata: meta,
	}
	for _, c := range f.Syscalls {
		r := &api.LinuxSyscall{Names: c.Names, Action: c.Action, ErrnoRet: optional(c.ErrnoRet)}
		for _, a := range c.Args {
			r.Args = append(r.Args, &api.LinuxSeccompArg{Index: a.Index, Value: a.Value, ValueTwo: a.ValueTwo, Op: a.Op})
		}
		s.Syscalls = append(s.Syscalls, r)
	}
	return s
}

func has(opts []string, o string) bool {
	for _, x := range opts {
		if x == o {
			return true
		}
	}
	return false
}

// kinds of mount nothing written to can be run from (the node agent's D4
// check makes the same exception)
var kernelKinds = map[string]bool{"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "mqueue": true, "devpts": true}

// adjust is CreateContainer's work, apart from NRI: the adjustment for a
// container of a pod VAREK supervises, nil for another pod's, or why it is
// refused.
func (p *plugin) adjust(pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, error) {
	name, ok := pod.GetAnnotations()[annotation]
	if !ok {
		return nil, nil
	}
	refuse := func(why string, a ...interface{}) error {
		return fmt.Errorf("varek: container %s of pod %s/%s: %s", ctr.GetName(), pod.GetNamespace(), pod.GetName(),
			fmt.Sprintf(why, a...))
	}
	if !policyName.MatchString(name) {
		return nil, refuse("the policy name %q (%s) is not 1 to 63 of a-z, 0-9 and -", name, annotation)
	}
	args := ctr.GetArgs()
	if len(args) == 0 {
		return nil, refuse("no command for the launcher to run")
	}
	if !strings.HasPrefix(args[0], "/") {
		return nil, refuse("the command must be named by an absolute path (it is %q)", args[0])
	}
	if args[0] == launcherAt {
		return nil, refuse("the command is already %s", launcherAt)
	}
	if !policyName.MatchString(pod.GetNamespace()) {
		return nil, refuse("the pod's namespace %q is not a name a policy can be under", pod.GetNamespace())
	}
	f, sha, err := p.filter(pod.GetNamespace(), name)
	if err != nil {
		return nil, refuse("%v", err)
	}
	adj := &api.ContainerAdjustment{}
	adj.SetLinuxSeccompPolicy(p.policy(f, pod.GetNamespace()+"/"+pod.GetName()+"/"+ctr.GetName()))
	adj.AddMount(&api.Mount{Destination: launcherAt, Type: "bind", Source: p.launcher,
		Options: []string{"bind", "ro", "nosuid", "nodev"}})
	for _, m := range ctr.GetMounts() {
		if m.Destination == launcherAt {
			return nil, refuse("it has a mount at %s already", launcherAt)
		}
		if has(m.Options, "ro") || has(m.Options, "noexec") || kernelKinds[m.Type] {
			continue
		}
		// the same destination again: the runtime puts it in the place of
		// the container's (step 1: so measured on containerd and CRI-O)
		adj.AddMount(&api.Mount{Destination: m.Destination, Type: m.Type, Source: m.Source,
			Options: append(append([]string{}, m.Options...), "noexec")})
	}
	adj.SetArgs(append([]string{launcherAt, "--"}, args...))
	adj.AddAnnotation(annotation, name)
	adj.AddAnnotation("varek.dev/policy-sha256", sha)
	// the pod's names, for the node agent's record (CRI-O puts the
	// kubelet's in one JSON string; a runtime's own, where it has them,
	// must agree)
	adj.AddAnnotation("varek.dev/pod-namespace", pod.GetNamespace())
	adj.AddAnnotation("varek.dev/pod-name", pod.GetName())
	adj.AddAnnotation("varek.dev/pod-uid", pod.GetUid())
	adj.AddAnnotation("varek.dev/container", ctr.GetName())
	return adj, nil
}

func (p *plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	adj, err := p.adjust(pod, ctr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "varek-nri: refused:", err)
		return nil, nil, err
	}
	if adj != nil {
		fmt.Fprintf(os.Stderr, "varek-nri: %s/%s/%s: policy %s, under the node agent\n", pod.GetNamespace(), pod.GetName(),
			ctr.GetName(), pod.GetAnnotations()[annotation])
	}
	return adj, nil, nil
}

func main() {
	p := &plugin{filters: map[string]*ociProfile{}}
	flag.StringVar(&p.warden, "warden", "", "the warden binary (it writes each policy's filter)")
	flag.StringVar(&p.policies, "policies", "", "the policies' directory (NAME.policy), the node agent's")
	flag.StringVar(&p.listener, "listener", "", "the node agent's socket")
	flag.StringVar(&p.launcher, "launcher", "", "the launcher (varek-init) on the node")
	socket := flag.String("socket", "", "the runtime's NRI socket (default: NRI's)")
	// v1.34 step 5 (D7): the cluster's VarekPolicy resources into -policies
	syncAPI := flag.Bool("sync", false, "write the cluster's VarekPolicy resources to -policies (in a cluster)")
	api := flag.String("api", "", "-sync: the API server (default: the cluster's, from the service account)")
	apiToken := flag.String("api-token", "", "-sync: the service account's token file")
	apiCA := flag.String("api-ca", "", "-sync: the cluster's CA")
	flag.Parse()
	for _, v := range []struct{ name, val string }{{"-warden", p.warden}, {"-policies", p.policies},
		{"-listener", p.listener}, {"-launcher", p.launcher}} {
		if !strings.HasPrefix(v.val, "/") {
			fmt.Fprintf(os.Stderr, "varek-nri: %s takes an absolute path\n", v.name)
			os.Exit(2)
		}
	}
	if *syncAPI {
		c, err := kube.InCluster(*api, *apiToken, *apiCA)
		if err != nil {
			fmt.Fprintln(os.Stderr, "varek-nri: -sync:", err)
			os.Exit(2)
		}
		s := &syncer{c: c, dir: p.policies, logf: func(f string, a ...interface{}) { fmt.Fprintf(os.Stderr, f+"\n", a...) }}
		go s.run(context.Background())
	}
	opts := []stub.Option{stub.WithPluginName("varek"), stub.WithPluginIdx("10")}
	if *socket != "" {
		opts = append(opts, stub.WithSocketPath(*socket))
	}
	s, err := stub.New(p, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "varek-nri:", err)
		os.Exit(1)
	}
	if err := s.Run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "varek-nri:", err)
		os.Exit(1)
	}
}
