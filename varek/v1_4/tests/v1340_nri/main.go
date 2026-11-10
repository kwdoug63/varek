// SPDX-License-Identifier: MIT
//
// v1340_nri — v1.34 step 1 (docs/security/v1.34-kubernetes.md): a stand-in
// for VAREK's NRI plugin, run on a node beside the stand-in node agent
// (tests/v1340_listener.c). For each container of a pod annotated
// varek.dev/policy it asks the runtime, through NRI, for what D3 and D4 and
// the node agent need, and logs what it was given and asked:
//   - the Warden's filter in OCI's form (FILTER, as tests/v1340_k8s.sh
//     writes it) as the container's seccomp policy, with listenerPath, so
//     the pod's spec names no profile;
//   - the launcher (D3): LAUNCHER mounted read-only at /varek/init and put
//     first in the container's command, with the launch set (LAUNCH) before
//     the container's own command; a container without a command refused;
//   - each writable mount made noexec (D4).
//
// Other pods are logged and left as they are.
//
//	v1340_nri -filter FILE -listener SOCKET -launcher FILE -launch PATH[,PATH] -log FILE
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

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
	Flags           []string     `json:"flags"`
	Syscalls        []ociSyscall `json:"syscalls"`
}

type plugin struct {
	filter   *ociProfile
	listener string
	launcher string
	launch   []string
	mu       sync.Mutex
	log      *os.File
}

func (p *plugin) logf(format string, a ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.log, format+"\n", a...)
	p.log.Sync()
}

func (p *plugin) Configure(_ context.Context, config, runtime, version string) (api.EventMask, error) {
	p.logf("configure: runtime %s %s", runtime, version)
	return api.MustParseEventMask("CreateContainer"), nil
}

func optional(v *uint32) *api.OptionalUInt32 {
	if v == nil {
		return nil
	}
	return &api.OptionalUInt32{Value: *v}
}

// the filter as NRI's seccomp policy, with the listener
func (p *plugin) policy(meta string) *api.LinuxSeccomp {
	s := &api.LinuxSeccomp{
		DefaultAction:    p.filter.DefaultAction,
		DefaultErrno:     optional(p.filter.DefaultErrnoRet),
		Architectures:    p.filter.Architectures,
		Flags:            p.filter.Flags,
		ListenerPath:     p.listener,
		ListenerMetadata: meta,
	}
	for _, c := range p.filter.Syscalls {
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

// kinds of mount nothing can be executed from, or already noexec
var noExecKinds = map[string]bool{"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "mqueue": true, "devpts": true}

func (p *plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	seen, _ := json.Marshal(map[string]interface{}{
		"pod": pod.GetNamespace() + "/" + pod.GetName(), "runtime_handler": pod.GetRuntimeHandler(),
		"container": ctr.GetName(), "args": ctr.GetArgs(), "user": ctr.GetUser(), "image": ctr.GetImage(),
		"mounts": ctr.GetMounts(), "seccomp_profile": ctr.GetLinux().GetSeccompProfile(),
		"seccomp_policy_given": ctr.GetLinux().GetSeccompPolicy() != nil,
	})
	p.logf("create: %s", seen)
	if pod.GetAnnotations()["varek.dev/policy"] == "" {
		p.logf("  not annotated: left as it is")
		return nil, nil, nil
	}
	if len(ctr.GetArgs()) == 0 {
		p.logf("  refused: no command")
		return nil, nil, fmt.Errorf("varek: container %s has no command for the launcher to run", ctr.GetName())
	}
	adj := &api.ContainerAdjustment{}
	meta := pod.GetNamespace() + "/" + pod.GetName() + "/" + ctr.GetName()
	adj.SetLinuxSeccompPolicy(p.policy(meta))
	adj.AddMount(&api.Mount{Destination: "/varek/init", Type: "bind", Source: p.launcher,
		Options: []string{"bind", "ro", "nosuid", "nodev"}})
	var made []string
	for _, m := range ctr.GetMounts() {
		if has(m.Options, "ro") || has(m.Options, "noexec") || noExecKinds[m.Type] || m.Destination == "/varek/init" {
			continue
		}
		opts := append(append([]string{}, m.Options...), "noexec")
		adj.AddMount(&api.Mount{Destination: m.Destination, Type: m.Type, Source: m.Source, Options: opts})
		made = append(made, m.Destination)
	}
	args := append([]string{"/varek/init"}, p.launch...)
	args = append(append(args, "--"), ctr.GetArgs()...)
	adj.SetArgs(args)
	p.logf("  adjusted: seccomp policy (%d rules, listener %s, metadata %s); command %q ...; noexec %v",
		len(p.filter.Syscalls), p.listener, meta, args[:len(p.launch)+3], made)
	return adj, nil, nil
}

func main() {
	var filter, logPath, launch string
	p := &plugin{}
	flag.StringVar(&filter, "filter", "", "the filter in OCI's form")
	flag.StringVar(&p.listener, "listener", "", "the node agent's socket")
	flag.StringVar(&p.launcher, "launcher", "", "the launcher on the node")
	flag.StringVar(&launch, "launch", "", "the launch set, comma-separated")
	flag.StringVar(&logPath, "log", "", "the log")
	socket := flag.String("socket", "", "the runtime's NRI socket (default: NRI's)")
	flag.Parse()
	var err error
	if p.log, err = os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b, err := os.ReadFile(filter)
	if err == nil {
		p.filter = &ociProfile{}
		err = json.Unmarshal(b, p.filter)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "v1340_nri: the filter:", err)
		os.Exit(1)
	}
	if launch != "" {
		p.launch = strings.Split(launch, ",")
	}
	opts := []stub.Option{stub.WithPluginName("varek"), stub.WithPluginIdx("10")}
	if *socket != "" {
		opts = append(opts, stub.WithSocketPath(*socket))
	}
	s, err := stub.New(p, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "v1340_nri:", err)
		os.Exit(1)
	}
	p.logf("v1340_nri: starting")
	if err := s.Run(context.Background()); err != nil {
		p.logf("v1340_nri: %v", err)
		os.Exit(1)
	}
}
