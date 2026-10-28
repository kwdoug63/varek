// SPDX-License-Identifier: MIT
//
// varek-nri — v1.34 step 3 (docs/security/v1.34-kubernetes.md, D3 and D4):
// VAREK's plugin for the Node Resource Interface, which containerd and CRI-O
// call as each container is created. It runs on each node beside the node
// agent (warden POLICY_DIR --node-agent ...). For each container of a pod
// annotated varek.dev/policy: NAME it asks the runtime for:
//   - the Warden's filter for that policy in OCI's form (written by the
//     Warden itself, warden NAME.policy --oci-filter on a private copy of
//     POLICY_DIR/<namespace>/NAME.policy, so the plugin carries no copy
//     that could drift) as the container's seccomp policy, its listenerPath
//     the node agent's socket: the pod's own profile (VAREK's unsupervised
//     one, step 8) is replaced;
//   - the launcher (varek-init) bound read-only, nosuid, nodev at
//     /varek/init and put first in the command: /varek/init -- COMMAND ...;
//   - every writable mount noexec (D4);
//   - the policy's name in the container's own annotations, since the state
//     the runtime sends the node agent carries the container's, not the pod's,
//     and the pod's namespace, name and uid and the container's name.
//
// A container that cannot be carried (no command, a command not named by an
// absolute path, a policy name that is not one, no such policy, a filter the
// Warden does not write in the time the runtime gives, a runtime handler
// that does not run the filter's listener, one of the node's namespaces
// shared, a seccomp profile other than VAREK's unsupervised one) is refused: the runtime does not create it, and the
// reason is in the pod's events. Other pods are left as they are. The node
// agent checks what it receives again (the launcher's identity, the
// container's mounts, the root read-only) and refuses what does not hold.
//
// v1.34 step 8 (review, G-1): every container of an annotated pod names, as
// its seccomp profile, VAREK's unsupervised one (Localhost
// varek/unsupervised.json: every call refused, its exec first), which the
// chart installs on each node and the admission webhook requires. The filter
// set here replaces it; a container this plugin does not adjust (the plugin
// not running, not answering in time, a node without it) keeps it, and does
// not run.
//
// On a runtime whose NRI cannot set a seccomp policy or the command (NRI
// before v0.10: containerd before 2.2, CRI-O before 1.35) the plugin refuses
// to start, naming the version. On one whose NRI carries no errno on a rule
// of the policy (before NRI v0.12: containerd before 2.3, CRI-O before 1.37,
// so OpenShift 4.22's CRI-O 1.35; step 9) no rule is given one: NRI's
// conversion there writes it through a nil pointer, and the runtime panics
// as it creates the container. A rule whose errno is EPERM names none (EPERM
// is runc's and crun's when a rule names none); one with another (ENOSYS for
// clone3 and io_uring_setup, EACCES for the setsockopt options refused) is
// notified instead, and from the command's launch the node agent answers it
// with that errno, from the Warden's own filter, as it answers each call
// that filter refuses and the pod's notifies (warden_oci.c).
//
//	varek-nri -warden FILE -policies DIR -listener SOCKET -launcher FILE [-socket NRI_SOCKET] [-sync]
//	          [-runtime-handlers runc,crun]
//
// v1.34 step 5: a pod's policy is POLICY_DIR/<namespace>/<name>.policy, and
// -sync writes there the cluster's VarekPolicy resources (sync.go).
//
// v1.35 step 4c (D11): a pod's plan, by the name it gives (varek.dev/plan),
// is POLICY_DIR/<namespace>/<name>.plan (-sync writes the VarekPlan
// resources there too). The Warden checks it with the policy (warden
// NAME.policy --oci-filter --plan NAME.plan: it reads, and names no step of a
// kind the node agent does not carry yet); a pod naming none is checked
// with --no-plan, which a policy that says `require plan` refuses. The
// plan's name and the SHA-256 of the bytes checked go in the container's
// annotations, where the node agent takes them.
//
// v1.36 step 4 (docs/security/v1.36-kubernetes-parity.md, D1 and D2): a
// policy that names credentials. The Warden checks each against the
// cluster's VarekCredential list (-sync writes it as POLICY_DIR/.credentials;
// a private copy is given, with the pod's namespace: --credential-list,
// --pod-namespace) and names them in its output (varekCredentials). For each,
// the container's environment gets its placeholder, VAREK_CRED_<NAME> =
// varek_ph_<name>_ and 43 random base64url characters, made for that
// container; the node agent takes it from there and hands it to the proxy,
// which swaps in the value. The value is never here.
//
// v1.36 step 6 (D5): a pod acting for a user (varek.dev/on-behalf-of: the
// Secret its user's token is in). The name goes in each container's
// annotations, where the node agent takes it, and the pod's token is read
// by the node agent from the kubelet's copy of the varek-obo volume. That
// volume is mounted by the webhook's init container alone (varek-obo,
// /bin/true, the node image: the kubelet mounts no volume no container
// names), which is let through as it is: it runs no agent. A container of
// that name otherwise (another command, another image where the runtime
// says it, a pod naming no Secret) is carried, or refused, as any other.
//
//	-obo-image REF: the init container's image (the node image, by digest)
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	"varek.dev/varek-k8s/internal/kube"
)

const (
	annotation     = "varek.dev/policy"
	planAnnotation = "varek.dev/plan"         // v1.35 step 4c
	oboAnnotation  = "varek.dev/on-behalf-of" // v1.36 step 6
	// v1.36 step 7: the plugin's alone, from the pod's VarekPolicy and the API server
	dryAnnotation   = "varek.dev/dry-run"
	trustAnnotation = "varek.dev/trust-bundle"
	flowAnnotation  = "varek.dev/flow-sha256"
	saAnnotation    = "varek.dev/service-account"
	oboInit         = "varek-obo" // the webhook's init container, and its volume
	oboCommand      = "/bin/true"
	launcherAt      = "/varek/init"
	// the profile every container of an annotated pod names (G-1), under
	// the kubelet's seccomp root
	unsupervised = "varek/unsupervised.json"
)

var policyName = kube.Name

// a Secret's name (a DNS subdomain), as the node agent takes it
var secretName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

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
	// v1.36 step 4: the credentials the policy names, whose placeholders the
	// container's environment gets (the Warden's, beside the profile)
	VarekCredentials []string `json:"varekCredentials"`
}

type plugin struct {
	warden, policies, listener, launcher string
	oboImage                             string          // -obo-image: the webhook's init container's (step 6)
	handlers                             map[string]bool // runtime handlers that run the filter's listener (G-4)
	noRuleErrno                          bool            // the runtime's NRI carries no errno on a rule (before v0.12)
	api                                  podReader       // v1.36 step 7: the API server (-sync), for a pod's service account
	mu                                   sync.Mutex
	filters                              map[string]*ociProfile // by the SHA-256s of the policy written for and the plan checked
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

// The runtimes whose NRI carries a rule's own errno (v0.12). Before it,
// ToOCILinuxSyscalls writes the errno through a nil pointer: CRI-O 1.35.9
// (NRI v0.11.0) panicked creating each supervised container (step 9).
var errnoRuntime = map[string][2]int{"containerd": {2, 3}, "cri-o": {1, 37}}

func ruleErrnoOK(runtime, ver string) bool {
	min, known := errnoRuntime[strings.ToLower(runtime)]
	a, b, ok := version(ver)
	return known && ok && (a > min[0] || (a == min[0] && b >= min[1]))
}

func (p *plugin) Configure(_ context.Context, _, runtime, ver string) (api.EventMask, error) {
	if err := runtimeOK(runtime, ver); err != nil {
		return 0, err
	}
	p.noRuleErrno = !ruleErrnoOK(runtime, ver)
	fmt.Fprintf(os.Stderr, "varek-nri: runtime %s %s; policies in %s; node agent %s; launcher %s\n",
		runtime, ver, p.policies, p.listener, p.launcher)
	if p.noRuleErrno {
		fmt.Fprintf(os.Stderr, "varek-nri: runtime %s %s: its NRI carries no errno on a rule (before NRI v0.12): "+
			"rules refusing with EPERM name none, the others are notified and the node agent answers them\n", runtime, ver)
	}
	return api.MustParseEventMask("CreateContainer"), nil
}

// The Warden's filter, in OCI's form, for the policy of the pod's namespace
// (v1.34 step 5: POLICY_DIR/<namespace>/<name>.policy, as the policy sync
// writes each VarekPolicy resource), and the SHA-256 of the bytes it was
// written for: the node agent loads the policy again, and refuses it if it
// is not those bytes (it changed in between). The filter is written from a
// private copy of those bytes, and kept by their hash. v1.35 step 4c: with
// the pod's plan (plan, or "" for none), checked the same way from a copy of
// its bytes, whose SHA-256 is returned too ("" for none).
func (p *plugin) read(ns, name, ext, what string) ([]byte, string, error) {
	path := filepath.Join(p.policies, ns, name+ext)
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return nil, "", fmt.Errorf("no %s named %s in namespace %s (%s)", what, name, ns, path)
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 8<<20 {
		return nil, "", fmt.Errorf("cannot read the %s %s (%v; at most 8 MiB)", what, path, err)
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}

// v1.36 step 7: the pod's API object, for its service account (the breaker's session)
type podReader interface {
	GetPod(ctx context.Context, ns, name string) (*kube.Pod, error)
}

// what the plugin checked for a container: the filter, the SHA-256s of the
// policy, the plan and (v1.36 step 7) the flow policy, and the policy's dry
// run and trust bundle (POLICY.run, as -sync writes it)
type filtered struct {
	f               *ociProfile
	sha, psha, fsha string
	run             runOptions
}

// a policy's optional file beside it: its bytes and SHA-256, or none
func (p *plugin) optional(ns, name, ext, what string) ([]byte, string, error) {
	if _, err := os.Lstat(filepath.Join(p.policies, ns, name+ext)); os.IsNotExist(err) {
		return nil, "", nil
	}
	return p.read(ns, name, ext, what)
}

func (p *plugin) filter(ctx context.Context, ns, name, plan string) (*filtered, error) {
	b, sha, err := p.read(ns, name, ".policy", "policy")
	if err != nil {
		return nil, err
	}
	var pb []byte
	psha := ""
	if plan != "" {
		if pb, psha, err = p.read(ns, plan, ".plan", "plan"); err != nil {
			return nil, err
		}
	}
	// v1.36 step 7 (D6, D7, D7b): the policy's flow policy, dry run and trust bundle
	fb, fsha, err := p.optional(ns, name, ".flow", "flow policy")
	if err != nil {
		return nil, err
	}
	rb, _, err := p.optional(ns, name, ".run", "policy's options")
	if err != nil {
		return nil, err
	}
	var run runOptions
	if rb != nil {
		dec := json.NewDecoder(strings.NewReader(string(rb)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&run); err != nil {
			return nil, fmt.Errorf("the options of policy %s (%s.run) do not read: %v", name, name, err)
		}
	}
	if run.TrustBundle != "" && !kube.TrustKeyOK(run.TrustBundle) {
		return nil, fmt.Errorf("policy %s names a trust bundle %q that is not a ConfigMap's key", name, run.TrustBundle)
	}
	res := &filtered{sha: sha, psha: psha, fsha: fsha, run: run}
	// v1.36 step 4 (D2): the cluster's VarekCredential list, as -sync wrote it
	// (none: an empty one), checked with the pod's namespace
	lb, err := os.ReadFile(filepath.Join(p.policies, kube.CredentialListFile))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("cannot read the credential list: %v", err)
	}
	lsum := sha256.Sum256(lb)
	key := sha + "/" + psha + "/" + ns + "/" + hex.EncodeToString(lsum[:]) + "/" + fsha + "/" + strconv.FormatBool(run.DryRun)
	p.mu.Lock()
	f, ok := p.filters[key]
	p.mu.Unlock()
	if ok {
		res.f = f
		return res, nil
	}
	dir, err := os.MkdirTemp("", "varek-nri-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, name+".policy")
	if err := os.WriteFile(copyPath, b, 0o600); err != nil {
		return nil, err
	}
	args := []string{copyPath, "--oci-filter", "--no-plan"}
	if plan != "" {
		planPath := filepath.Join(dir, plan+".plan")
		if err := os.WriteFile(planPath, pb, 0o600); err != nil {
			return nil, err
		}
		args = []string{copyPath, "--oci-filter", "--plan", planPath}
	}
	listPath := filepath.Join(dir, "credentials")
	if err := os.WriteFile(listPath, lb, 0o600); err != nil {
		return nil, err
	}
	args = append(args, "--credential-list", listPath, "--pod-namespace", ns)
	if run.DryRun { // v1.36 step 7 (D6): every call outside the allowlist notified
		args = append(args, "--dry-run")
	}
	if fb != nil { // (D7b): it loads, is certified, and checks the pod's plan
		flowPath := filepath.Join(dir, name+".flow")
		if err := os.WriteFile(flowPath, fb, 0o600); err != nil {
			return nil, err
		}
		args = append(args, "--flow-policy", flowPath)
	}
	cmd := exec.CommandContext(ctx, p.warden, args...)
	var errb strings.Builder
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("the Warden did not write the filter for policy %s in the time the runtime gives (%v)", name, ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("the Warden does not write the filter for policy %s: %v: %s", name, err,
			strings.ReplaceAll(lastLine(errb.String()), dir+"/", ""))
	}
	f = &ociProfile{}
	if err := json.Unmarshal(out, f); err != nil || len(f.Syscalls) == 0 {
		return nil, fmt.Errorf("the Warden's filter for policy %s does not read: %v", name, err)
	}
	for _, c := range f.VarekCredentials {
		if !kube.CredentialName.MatchString(c) {
			return nil, fmt.Errorf("the Warden names a credential %q that is not a credential's name", c)
		}
	}
	p.mu.Lock()
	if len(p.filters) >= 256 {
		p.filters = map[string]*ociProfile{}
	}
	p.filters[key] = f
	p.mu.Unlock()
	res.f = f
	return res, nil
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
		if p.noRuleErrno && c.ErrnoRet != nil {
			// NRI before v0.12 (Configure): EPERM is the runtime's own for a
			// rule that names none; another errno is the node agent's to give
			r.ErrnoRet = nil
			if *c.ErrnoRet != uint32(syscall.EPERM) {
				r.Action = "SCMP_ACT_NOTIFY"
			}
		}
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

// the namespaces a container of a pod VAREK supervises has of its own, not
// the node's (D5; the webhook refuses hostNetwork, hostPID and hostIPC first)
var ownNamespaces = []string{"network", "pid", "ipc", "mount"}

// Whether the seccomp profile the runtime is to give the container is VAREK's
// unsupervised one: by the profile's name where the runtime says it, or by
// the policy itself (every call refused) where it says only that. A runtime
// that says neither is let through: the webhook required the profile.
func unsupervisedProfile(l *api.LinuxContainer) (bool, string) {
	if sp := l.GetSeccompProfile(); sp != nil {
		ref := sp.GetLocalhostRef()
		if sp.GetProfileType() == api.SecurityProfile_LOCALHOST && (ref == unsupervised || strings.HasSuffix(ref, "/"+unsupervised)) {
			return true, ""
		}
		return false, fmt.Sprintf("%s %s", sp.GetProfileType(), ref)
	}
	if sc := l.GetSeccompPolicy(); sc != nil {
		if (sc.DefaultAction == "SCMP_ACT_ERRNO" || strings.HasPrefix(sc.DefaultAction, "SCMP_ACT_KILL")) && len(sc.Syscalls) == 0 {
			return true, ""
		}
		return false, fmt.Sprintf("a policy whose default is %s, with %d rules", sc.DefaultAction, len(sc.Syscalls))
	}
	return true, "unsaid"
}

// adjust is CreateContainer's work, apart from NRI: the adjustment for a
// container of a pod VAREK supervises, nil for another pod's, or why it is
// refused.
func (p *plugin) adjust(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, error) {
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
	plan, named := pod.GetAnnotations()[planAnnotation]
	if named && !policyName.MatchString(plan) {
		return nil, refuse("the plan name %q (%s) is not 1 to 63 of a-z, 0-9 and -", plan, planAnnotation)
	}
	obo, acting := pod.GetAnnotations()[oboAnnotation]
	if acting && !secretName.MatchString(obo) {
		return nil, refuse("%s %q is not a Secret's name", oboAnnotation, obo)
	}
	if acting && p.oboContainer(ctr) {
		return nil, nil
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
	// G-4: a sandboxed runtime (Kata, gVisor) runs no seccomp listener
	if h := pod.GetRuntimeHandler(); h != "" && !p.handlers[h] {
		return nil, refuse("its runtime handler %q is not one that runs the Warden's filter (-runtime-handlers)", h)
	}
	// G-5: D5 held here too, not by admission alone
	have := map[string]bool{}
	for _, n := range ctr.GetLinux().GetNamespaces() {
		have[n.GetType()] = true
	}
	for _, t := range ownNamespaces {
		if !have[t] {
			return nil, refuse("it shares the node's %s namespace (the node agent takes a container in its own)", t)
		}
	}
	if ok, what := unsupervisedProfile(ctr.GetLinux()); !ok {
		return nil, refuse("its seccomp profile is %s, not Localhost %s (VAREK's unsupervised profile, which keeps a "+
			"container this plugin does not adjust from running)", what, unsupervised)
	} else if what == "unsaid" {
		fmt.Fprintf(os.Stderr, "varek-nri: %s/%s/%s: the runtime does not say the container's seccomp profile (the webhook "+
			"required VAREK's unsupervised one)\n", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	}
	fd, err := p.filter(ctx, pod.GetNamespace(), name, plan)
	if err != nil {
		return nil, refuse("%v", err)
	}
	f, sha, psha := fd.f, fd.sha, fd.psha
	// v1.36 step 7 (D7b): the breaker's session, the pod's service account,
	// from the API server (the pod's author does not write it)
	sa := ""
	if fd.fsha != "" {
		if sa, err = p.serviceAccount(ctx, pod); err != nil {
			return nil, refuse("its policy has a flow policy, and %v", err)
		}
	}
	adj := &api.ContainerAdjustment{}
	adj.SetLinuxSeccompPolicy(p.policy(f, pod.GetNamespace()+"/"+pod.GetName()+"/"+ctr.GetName()))
	adj.AddMount(&api.Mount{Destination: launcherAt, Type: "bind", Source: p.launcher,
		Options: []string{"bind", "ro", "nosuid", "nodev"}})
	for _, m := range ctr.GetMounts() {
		if m.Destination == launcherAt {
			return nil, refuse("it has a mount at %s already", launcherAt)
		}
		// v1.36 step 7 (D6): a dry run holds no launch, as on a host: no
		// mount is made noexec
		if has(m.Options, "ro") || has(m.Options, "noexec") || kernelKinds[m.Type] || fd.run.DryRun {
			continue
		}
		// the same destination again: the runtime puts it in the place of
		// the container's (step 1: so measured on containerd and CRI-O)
		adj.AddMount(&api.Mount{Destination: m.Destination, Type: m.Type, Source: m.Source,
			Options: append(append([]string{}, m.Options...), "noexec")})
	}
	adj.SetArgs(append([]string{launcherAt, "--"}, args...))
	// v1.36 step 4 (D1): each credential's placeholder, made for this container
	for _, c := range f.VarekCredentials {
		ph, err := placeholder(c)
		if err != nil {
			return nil, refuse("cannot make a placeholder for credential %s: %v", c, err)
		}
		adj.AddEnv("VAREK_CRED_"+strings.ToUpper(c), ph)
	}
	adj.AddAnnotation(annotation, name)
	adj.AddAnnotation("varek.dev/policy-sha256", sha)
	if plan != "" { // v1.35 step 4c: the plan checked, for the node agent to hold the run to
		adj.AddAnnotation(planAnnotation, plan)
		adj.AddAnnotation("varek.dev/plan-sha256", psha)
	} else { // step 9 (review): and none the container came with, for a pod naming no plan
		adj.RemoveAnnotation(planAnnotation)
		adj.RemoveAnnotation("varek.dev/plan-sha256")
	}
	if acting { // v1.36 step 6 (D5): the Secret its user's token is in
		adj.AddAnnotation(oboAnnotation, obo)
	} else {
		adj.RemoveAnnotation(oboAnnotation)
	}
	// v1.36 step 7 (D6, D7, D7b): its VarekPolicy's dry run, trust bundle and
	// flow policy, each set or removed (the pod's own are not taken)
	own := func(key, val string, set bool) {
		if set {
			adj.AddAnnotation(key, val)
		} else {
			adj.RemoveAnnotation(key)
		}
	}
	own(dryAnnotation, "true", fd.run.DryRun)
	own(trustAnnotation, fd.run.TrustBundle, fd.run.TrustBundle != "")
	own(flowAnnotation, fd.fsha, fd.fsha != "")
	own(saAnnotation, sa, sa != "")
	// the pod's names, for the node agent's record (CRI-O puts the
	// kubelet's in one JSON string; a runtime's own, where it has them,
	// must agree)
	adj.AddAnnotation("varek.dev/pod-namespace", pod.GetNamespace())
	adj.AddAnnotation("varek.dev/pod-name", pod.GetName())
	adj.AddAnnotation("varek.dev/pod-uid", pod.GetUid())
	adj.AddAnnotation("varek.dev/container", ctr.GetName())
	return adj, nil
}

// serviceAccount is the pod's, as the API server has it (its uid the
// runtime's: the same pod, not one created again by its name)
func (p *plugin) serviceAccount(ctx context.Context, pod *api.PodSandbox) (string, error) {
	if p.api == nil {
		return "", fmt.Errorf("the plugin reads no pod from the API server (-sync), for its service account (the breaker's session)")
	}
	o, err := p.api.GetPod(ctx, pod.GetNamespace(), pod.GetName())
	if err != nil {
		return "", fmt.Errorf("its pod cannot be read from the API server: %v", err)
	}
	if o == nil || o.Metadata.UID != pod.GetUid() {
		return "", fmt.Errorf("the API server has no pod %s/%s of uid %s", pod.GetNamespace(), pod.GetName(), pod.GetUid())
	}
	sa := o.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	if !secretName.MatchString(sa) {
		return "", fmt.Errorf("its service account's name %q is not one", sa)
	}
	return sa, nil
}

// oboContainer: whether the container is the webhook's init container for a
// pod acting for a user: its name, its command alone, and its image where
// the runtime says it (by digest, where -obo-image names one)
func (p *plugin) oboContainer(ctr *api.Container) bool {
	if ctr.GetName() != oboInit || len(ctr.GetArgs()) != 1 || ctr.GetArgs()[0] != oboCommand {
		return false
	}
	img := ctr.GetImage()
	if p.oboImage == "" || img == nil || (img.GetName() == "" && img.GetDigest() == "") {
		return true
	}
	if i := strings.LastIndex(p.oboImage, "@"); i >= 0 && img.GetDigest() != "" {
		return img.GetDigest() == p.oboImage[i+1:]
	}
	return fullName(img.GetName()) == fullName(p.oboImage)
}

// fullName: an image's name as a runtime may give it (docker.io/library/
// for one with no registry, as containerd and CRI-O resolve it)
func fullName(ref string) string {
	first, _, named := strings.Cut(ref, "/")
	switch {
	case !named:
		return "docker.io/library/" + ref
	case !strings.ContainsAny(first, ".:") && first != "localhost":
		return "docker.io/" + ref
	}
	return ref
}

// placeholder is a credential's placeholder, as the Warden makes one on a host
// (varek_ph_<name>_ and 32 random bytes in base64url, unpadded: 43 characters)
func placeholder(name string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "varek_ph_" + name + "_" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// the time the plugin keeps of the runtime's for answering: past its
// deadline NRI drops the plugin, and the container keeps its unsupervised
// profile (it does not run); an answer before it says why
const answerMargin = 250 * time.Millisecond

func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	if d, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, d.Add(-answerMargin))
		defer cancel()
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
	}
	adj, err := p.adjust(ctx, pod, ctr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "varek-nri: refused:", err)
		return nil, nil, err
	}
	if adj == nil && ctr.GetName() == oboInit {
		if _, ok := pod.GetAnnotations()[oboAnnotation]; ok {
			fmt.Fprintf(os.Stderr, "varek-nri: %s/%s/%s: the init container of a pod acting for a user (its token's volume), as it is\n",
				pod.GetNamespace(), pod.GetName(), ctr.GetName())
		}
	}
	if adj != nil {
		plan := ""
		if n, ok := pod.GetAnnotations()[planAnnotation]; ok {
			plan = ", plan " + n
		}
		fmt.Fprintf(os.Stderr, "varek-nri: %s/%s/%s: policy %s%s, under the node agent\n", pod.GetNamespace(), pod.GetName(),
			ctr.GetName(), pod.GetAnnotations()[annotation], plan)
	}
	return adj, nil, nil
}

func main() {
	p := &plugin{filters: map[string]*ociProfile{}}
	flag.StringVar(&p.warden, "warden", "", "the warden binary (it writes each policy's filter)")
	flag.StringVar(&p.policies, "policies", "", "the policies' directory (<namespace>/NAME.policy), the node agent's")
	flag.StringVar(&p.listener, "listener", "", "the node agent's socket")
	flag.StringVar(&p.launcher, "launcher", "", "the launcher (varek-init) on the node")
	socket := flag.String("socket", "", "the runtime's NRI socket (default: NRI's)")
	flag.StringVar(&p.oboImage, "obo-image", "", "the image of the webhook's init container for a pod acting for a user (the node image)")
	handlers := flag.String("runtime-handlers", "runc,crun", "the runtime handlers (RuntimeClass) whose containers run the Warden's filter; "+
		"a pod of another is refused (the default handler, unnamed, is taken)")
	// v1.34 step 5 (D7): the cluster's VarekPolicy resources into -policies
	// (v1.35 step 4c: and its VarekPlan resources)
	syncAPI := flag.Bool("sync", false, "write the cluster's VarekPolicy, VarekPlan and VarekCredential resources to -policies (in a cluster)")
	api := flag.String("api", "", "-sync: the API server (default: the cluster's, from the service account)")
	apiToken := flag.String("api-token", "", "-sync: the service account's token file")
	apiCA := flag.String("api-ca", "", "-sync: the cluster's CA")
	flag.Parse()
	p.handlers = map[string]bool{}
	for _, h := range strings.Split(*handlers, ",") {
		if h = strings.TrimSpace(h); h != "" {
			p.handlers[h] = true
		}
	}
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
		logf := func(f string, a ...interface{}) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
		go (&syncer{c: c, dir: p.policies, logf: logf}).run(context.Background())
		go (&syncer{c: c, dir: p.policies, logf: logf, resource: kube.Plans}).run(context.Background())
		go (&credSyncer{c: c, dir: p.policies, logf: logf}).run(context.Background()) // v1.36 step 4 (D2)
		p.api = c                                                                     // v1.36 step 7 (D7b)
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
