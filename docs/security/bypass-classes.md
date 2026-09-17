# Bypass Classes and Mediation Completeness

This section enumerates the classes by which a process that *wants out* could
sidestep VAREK's mediation, and the status of each. It is organized as an
auditor checklist: every policy-relevant effect must have an argument that we
have enumerated *all* the syscalls producing it, across *all* ABIs. Completeness
of mediation is a closure property, not a feature — the default-deny allowlist
(v1.9.2) is what makes that argument tractable, because the residual
("everything not admitted") is denied by construction.

Status legend: **closed** (mitigated in shipped code), **contained**
(structurally prevented by the model), **roadmap** (named, mitigation planned —
see `v1.10-architecture-roadmap.md`), **out of scope** (below the boundary;
disclosed, not claimed covered).

## The three meta-decisions

Most classes below collapse under three architectural choices, all in v1.9.2
except where noted:

1. **Default-deny allowlist, not allow + denylist.** Unknown syscalls, variant
   syscalls, and multiplexers are denied until explicitly admitted. *(closed —
   `warden_seccomp_baseline.c`)*
2. **Block every non-native ABI explicitly.** *(closed — native-only filter,
   secondary architectures removed, asserted by `test_v192_abi_lockdown.c`)*
3. **Mediate capability acquisition, not use; push enforcement into kernel
   primitives (Landlock) where possible.** *(partial — acquisition-time
   mediation is the design today via `SCMP_ACT_NOTIFY` on open/connect/exec;
   Landlock filesystem enforcement is roadmap for v1.10)*

## Class checklist

| # | Class | Status | Mitigation |
|---|-------|--------|------------|
| 1 | Alternate-ABI / syscall-table (compat int 0x80, x32 `__X32_SYSCALL_BIT`, arm compat, 32-bit multiplexers `socketcall`/`ipc`) | closed | Native-only default-deny. Secondary arches removed; multiplexers unreachable. Asserted on live kernel by `test_v192_abi_lockdown.c`. |
| 2 | Variant-syscall evasion (`clone3`, `openat2`, `faccessat2`, `pidfd_*`) | closed | Default-deny allowlist: a variant is denied unless admitted. `clone3` hard-denied (pointer-flags, uninspectable). When we mediate an effect we mediate **every** syscall producing it. |
| 3 | Off-path I/O dispatch | closed (send path, v1.12); partial elsewhere | `io_uring_*` denied (v1.9.1, retained). `process_vm_readv/writev`, `pidfd_getfd`, `memfd_create` hard-denied. **mmap-after-open** contained by acquisition-time mediation: the `open` was mediated, so the fd is authorized; the mapping rides an authorized capability. **Datagram egress** (`sendto`/`sendmsg` reaching the network without `connect`) **closed in v1.12**: both are mediated as `net.send` and refused for an inet destination under the deny-only network posture; inbound `recvfrom`/`recvmsg` stay admitted. **SCM_RIGHTS fd passing** contained by the fd-provenance invariant below. |
| 4 | Deterministic TOCTOU primitives (`userfaultfd`, FUSE/attacker mounts, symlink/magic-link swaps) | partial | `userfaultfd` and the mount/FUSE family (`mount`, `umount2`, `fsopen`, `fsconfig`, `fsmount`, `move_mount`, `open_tree`) hard-denied. Path races and symlink/magic-link swaps: the supervisor resolves the object **once** with `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`, decides policy on the **resolved canonical path** (`readlink` of the resolved fd), and injects that same fd (v1.12 resolve-then-decide) — a symlink component fails resolution and is denied, and a `..` traversal is decided on the post-collapse path. Before v1.12 the shipped resolver set only `RESOLVE_NO_MAGICLINKS`, so a symlink inside an allowed directory was followed, and the decision was made on the raw pathname rather than the resolved object; both are fixed. `RESOLVE_BENEATH` is intentionally **not** set (allow rules legitimately name absolute paths outside the cwd); `..` is defanged by deciding on the canonical path, not by forbidding it. Race-free kernel-side resolution via **Landlock** remains roadmap (reserved v1.10). |
| 4a | Supervisor-context path confusion (`/proc/self/*`) | closed (v1.12) | `/proc/self` and `/proc/thread-self` are magic symlinks the kernel resolves in the **caller's** context — the supervisor's — so an agent naming `/proc/self/mem` would receive a handle on the Warden. `RESOLVE_NO_MAGICLINKS` (now actually set) refuses them. Reading the resolved fd's own `/proc/self/fd/N` link to canonicalize is safe: that link is dereferenced by the supervisor on a fd it already holds, not on an agent-named path. |
| 5 | New-execution-context / privilege surface (unprivileged user namespaces `CLONE_NEWUSER`, `ptrace`, unexpected `execve` helpers) | closed | `clone`/`unshare` scalar-flag filter denies `CLONE_NEWUSER` (and the namespace set) race-free; `setns`/`clone3` hard-denied. `ptrace` hard-denied. `execve`/`execveat` mediated against a supervisor-enforced exec-target allowlist. |
| 6 | Direct kernel / memory / device access (`bpf`, `init_module`/`finit_module`, `/dev/mem`, `/dev/kmem`, `/dev/port`, `/proc/kcore`, raw block devices, `perf_event_open`, `keyctl`) | closed | Syscall side hard-denied (`bpf`, module ops, `kexec_*`, `perf_event_open`, `keyctl`/`add_key`/`request_key`, `modify_ldt`). Device-special-file access is contained because **the `open` is mediated** — device paths are refused at acquisition, not merely matched as named files. |
| 7 | Supervisor-as-target / lifecycle | closed (v1.9.3); partial in v1.9.2 | **v1.9.3:** the live Warden runs the target as init of its own PID namespace and SIGKILLs it on supervisor death (`PR_SET_PDEATHSIG`, with a liveness-pipe check for the fork/prctl race); when the target dies, the kernel kills every process it spawned. Orderly shutdown kills the whole tree (namespace + process group). The supervisor watches the target via pidfd. The Warden requires `CAP_SYS_ADMIN` and refuses to start without it; `VAREK_WARDEN_NO_PIDNS=1` opts out, and in that mode the class is **partial** (descendants are not covered on a supervisor crash). Injected fds carry `O_CLOEXEC` (no leak across exec). The single-threaded v1.4 Warden handles one notification at a time, so pending requests queue in the kernel; `WD_MAX_INFLIGHT_NOTIFS` applies to a future multi-threaded supervisor. Asserted end to end by `varek/v1_4/tests/test_v193_lifecycle.c` (`make test-lifecycle`). **v1.9.2:** only `O_CLOEXEC` was enforced by the live Warden; the lifecycle module was not yet wired in. *(`warden_lifecycle.{h,c}`)* |
| 8 | Post-grant capability reuse (durable fd/socket reused for later actions the policy never re-checks) | contained / roadmap | fd-provenance invariant narrows grants. Use-path **re-mediation** offered as an optional high-assurance mode, defaulted off so the common case does not pay the latency. *(design in v1.10 roadmap)* |
| 9 | Below the boundary (kernel 0-day, hypervisor escape, DMA, microarchitectural side channels, Rowhammer, timing/power covert channels) | out of scope | Defense-in-depth (minimal syscall surface, dropped caps, namespaces, Landlock) shrinks the surface; it does not close these. Disclosed here rather than implied covered. |

## The fd-provenance invariant (classes 3, 8)

A capability is authorized only if the **supervisor granted it**. The Warden
maintains, per target, the set of fds it injected via ADDFD. Any fd that appears
by another route — received over a unix socket (`SCM_RIGHTS`), inherited across a
boundary, duplicated from an unauthorized source — is **unauthorized by
default**. This is what contains SCM_RIGHTS teleportation (class 3) and durable
post-grant reuse narrowing (class 8): the question is never "is this fd open" but
"did we grant this fd, for this effect, and is the grant still in force."

## Acquisition vs. use (the latency/completeness resolution)

Mediation lands at capability **acquisition**, in three tiers:

- **Fast path (in-kernel BPF):** scalar-argument allow/deny with no supervisor
  round-trip — sub-microsecond, the bulk of decisions.
- **Supervisor round-trip (unotify):** reserved for acquisition syscalls needing
  pointer/path inspection (`openat`, `connect`, `execve`, `execveat`, and — as of
  v1.12 — `sendto`/`sendmsg`, whose destination sockaddr is inspected so an inet
  send is refused like `connect`). `mount`*/`ptrace`* are denied rather than
  inspected.
- **Use path:** nothing mediates `read`/`write`/`recv`/`send` on
  already-authorized fds.

The accepted cost: durable capabilities are not re-checked by default (class 8).
Optional use-path re-mediation is the configurable, high-assurance answer — see
the v1.10 roadmap. Do not make every workload pay latency for assurance only some
need.

## Resolve-then-decide (classes 4, 4a)

A policy decision is only as sound as the identity of the object it is made
about. Through v1.9.3 the Warden decided on the **pathname string** the agent
supplied and then, separately, opened whatever that string resolved to — two
steps that could name two different inodes (`..` collapse, a symlink component,
a `/proc/self` magic link resolving in the supervisor's context). v1.12 collapses
them: the object is opened **once** with `RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS`, its canonical path is read back from the resolved fd, the
policy decision is made on that canonical path, and *that same fd* is injected
into the agent. There is no second open, so there is no resolve/decide/deliver
TOCTOU window, and the object decided on is by construction the object delivered.
Resolution failure (a symlink component, an over-long path, an untracked dirfd,
or a deleted inode) is a hard deny before any policy match.

## Audit-log integrity

The pathology stream is evidence, so it must be unforgeable by the subject it
describes. Through v1.9.3 the agent-controlled pathname was interpolated into the
JSON verdict record unescaped, so a crafted path (`/x","decision_final":"ALLOW"}`
plus a newline and a second object) could inject a forged authorization record
into the stream a downstream consumer reads. v1.12 JSON-escapes every
agent-controlled field (`target`, `resolved`); every record is well-formed JSON
for any byte sequence, and no agent input can begin, end, or fabricate a record.
The `varek_cyclonedx.py` exporter refuses to emit a BOM from a stream that does
not parse cleanly line by line, so a corrupted log cannot be laundered into an
attestation.
