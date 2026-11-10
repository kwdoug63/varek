# Why the node agent is privileged, and how much less it can be

**Status:** an explanation of v1.36.0 as built, and a plan to reduce what
it holds (`docs/roadmap/production-readiness.md`, section 4). Nothing here
is built yet; what is not yet measured says so.
**Author:** Kenneth Wayne Douglas, MD
**Last updated:** October 30, 2026 (Central)

On Kubernetes, VAREK's node agent (`packaging/helm/varek/templates/daemonset.yaml`)
runs with `privileged: true`, as root, in the node's PID namespace. A
platform team will ask why. The short answer: it decides each call of
containers it did not start, from outside them, so it needs the kernel's
rights to look into and act on another process. It needs fewer rights than
`privileged: true` gives, and step 1 below names them.

## The trade it makes

The privilege sits in one place so that the agent pods hold none.

- **The agent pods get no added capability,** no custom profile, and pass
  Pod Security Standards' "restricted" level and OpenShift's default
  security context constraints (`docs/security/v1.34-kubernetes.md`). Their
  images, commands and network setup are unchanged; a pod is supervised by
  an annotation and a policy.
- **One node agent per node holds the privilege,** as the node agents of
  runtime-security tools and of CNI and CSI node plugins do. Its chart binds
  the privileged security context constraint on OpenShift to the node
  agent's service account alone (`templates/scc.yaml`).
- **The alternative is a supervisor inside each pod.** v1.32's image is
  that: the Warden in the agent's container, which needs ten capabilities
  in every agent pod, CAP_SYS_ADMIN among them, because it makes the
  agent's namespaces. A supervisor in the pod that holds no capability has
  to start the agent itself (the pod's entrypoint changes), and it leaves
  the pod's network fence to the cluster's NetworkPolicy, so a CNI that does
  not enforce NetworkPolicy leaves the agent's network open. The node agent
  decides each `connect` from the kernel's seccomp listener, whatever the
  CNI does.

## What the node agent does that needs privilege

Each row is an operation the code makes on a container it supervises, and
what the kernel requires for it.

| Operation | Why | The kernel requires | Code |
|---|---|---|---|
| See the runtime and the container's processes by pid; read their `/proc` (status, namespaces, cgroup) | Tie the listener the runtime sends to the container's process (the peer's credentials, its namespaces, the first call) | the node's PID namespace (`hostPID`); CAP_SYS_PTRACE to read another user's `/proc/<pid>` entries | `warden_node.inc.c` (`node_peer_read`, `node_admit`, `node_tie`) |
| Read the agent's memory, and write answers into it | A call's arguments (paths, addresses) are in the agent's memory; some answers are written back | CAP_SYS_PTRACE (`/proc/<pid>/mem`, ptrace access) | `warden.c` (`xproc_read_str`, `xproc_write`), `warden_exec.inc.c`, `warden_net.inc.c` |
| Take one of the agent's descriptors | The egress proxy's hand-over of a decided connection | CAP_SYS_PTRACE (`pidfd_getfd`, ptrace attach access) | `warden.c` (descriptor hand-over) |
| Enter the container's network and mount namespaces | The stub resolver and the egress proxy run in the pod's network; files are opened in the container's view | CAP_SYS_ADMIN, and CAP_SYS_CHROOT for a mount namespace (`setns` by the container init's pidfd) | `warden_node.inc.c` (`node_enter`) |
| Open files as the agent | A file the agent opens is opened with the agent's user and groups, never root's | CAP_SETUID and CAP_SETGID (the filesystem user and groups switched, then back) | `warden_asagent.inc.c`, `warden_net.inc.c` |
| Make a control group for each sub-agent | Sub-agents and confined MCP servers (v1.36) | CAP_SYS_ADMIN (its own mount of the cgroup filesystem, `fsopen`), writing the container's cgroup | `warden_subagent.inc.c` |
| End a container | Revocation, a token's expiry, a refused start | CAP_KILL for another user's process (`pidfd_send_signal`) | `warden_node.inc.c` |
| Read the kubelet's copy of a pod's volume; root-owned node directories | The on-behalf-of token (v1.36), the policies, the socket | root, and CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH | `daemonset.yaml` mounts |
| Not confined by the node's seccomp, AppArmor or SELinux defaults | The runtime's default seccomp profile allows `setns` and `pidfd_getfd` only to a container holding the matching capabilities; AppArmor's default profile limits ptrace to its own peers; SELinux `container_t` cannot reach other containers' processes | a seccomp profile of VAREK's (or none), AppArmor unconfined where it is used, SELinux `spc_t` | `daemonset.yaml` |

Already contained:

- **Its children hold nothing.** A process the node agent starts drops every
  capability, the bounding, ambient and inheritable sets included, and
  checks that it did (`drop_privileges`, `warden.c`).
- **Its socket is root's.** Each connection's peer is checked by the
  kernel's credentials (`SO_PEERCRED`) and its namespaces. A process that
  is not the runtime, or the runtime's parent, ties a listener only to a
  process that then makes the first call on it (step 12 of
  `docs/security/v1.36-kubernetes-parity.md`).
- **It fails closed.** A container whose supervision cannot be set up is
  not run, and a container the node agent cannot decide for is ended.

## What `privileged: true` gives beyond that

`privileged: true` gives every capability and every device, leaves `/proc`
and `/sys` unmasked and writable, and turns off seccomp, AppArmor and the
SELinux type. The table above uses none of these:

- devices (`/dev`), and CAP_MKNOD, CAP_SYS_RAWIO;
- kernel modules, the clock, reboot (CAP_SYS_MODULE, CAP_SYS_TIME,
  CAP_SYS_BOOT);
- the node's network configuration and raw sockets (CAP_NET_ADMIN,
  CAP_NET_RAW);
- eBPF and performance monitoring (CAP_BPF, CAP_PERFMON);
- writable `/sys`, and `/proc` without the runtime's masks.

## The plan

1. **Name the capabilities instead of `privileged: true`** (a v1.37
   candidate). `privileged: false`, `capabilities: drop: [ALL]`, and add
   only CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_CHROOT, CAP_SETUID,
   CAP_SETGID, CAP_KILL, CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH. Plus
   `hostPID`, SELinux `spc_t` (as the plugin and the exporter already run),
   AppArmor unconfined, and a seccomp profile of VAREK's that admits what
   the node agent calls. On OpenShift, `allowPrivilegedContainer: false`
   and the same list in `allowedCapabilities`. *To be measured:* the set is
   read from the code, not yet run. It is measured on every cell of the
   matrix (CRI-O 1.35 to 1.37 under runc and crun, containerd 2.2 and 2.3,
   amd64 and arm64, SELinux enforcing) with `test_v1340` and the kind
   sections. A right that is missing fails closed (the container is refused
   or ended, never run unsupervised), so the measurement shows any gap as a
   refusal, not a silent loss.
2. **A seccomp profile for the node agent itself:** the calls it makes,
   from the suites' runs, so it no longer runs unconfined.
3. **Split what holds the rights** (later, scoped with the review of the
   trusted computing base, `docs/security/TRUSTED-COMPUTING-BASE.md`). The
   decisions, the policy parsers and the stream do not need the
   capabilities above; only `setns`, `pidfd_getfd`, the memory reads and
   writes, the signals and the file opens as the agent do. A small helper
   holding the rights, with the rest of the node agent holding none, would
   put the parsers that read untrusted input outside the privileged
   process.

What cannot be removed: `hostPID`, CAP_SYS_ADMIN and CAP_SYS_PTRACE are the
supervision itself. With them a process can act on any process of the node,
so the node agent stays as trusted as the node's root, with or without
step 1. Step 1 removes what it does not use (devices, modules, the
network's configuration), so a fault in it reaches less of the node, and a
platform team can read exactly what it holds. It does not make the node
agent a different kind of component.

## For a platform team, in one paragraph

VAREK puts its privilege in one DaemonSet so that agent pods need none:
they pass the "restricted" level unchanged. The node agent decides each
call of a supervised container from outside it, which takes the kernel's
rights to read and act on another process (ptrace access, entering the
pod's network namespace, switching to the agent's user to open its files,
ending it). It holds those in the node's PID namespace, bound on OpenShift
to its own service account. Its children drop every right, and anything it
cannot set up fails closed. v1.36.0 runs it as `privileged: true`; the next
step is a named set of eight capabilities, measured on every supported
runtime, with no device access or kernel and network configuration.

## Sources

- `packaging/helm/varek/templates/daemonset.yaml`, `templates/scc.yaml`.
- `docs/security/v1.34-kubernetes.md` (what v1.32 leaves open; sections 1
  and 2).
- `docs/security/v1.36-kubernetes-parity.md` (step 12: the tie).
- `varek/v1_4/warden.c`, `warden_node.inc.c`, `warden_asagent.inc.c`,
  `warden_net.inc.c`, `warden_exec.inc.c`, `warden_subagent.inc.c`.
- Linux man pages: `setns(2)`, `pidfd_getfd(2)`, `proc(5)` (ptrace access
  mode), `capabilities(7)`.
