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
| 3 | Off-path I/O dispatch | partial | `io_uring_*` denied (v1.9.1, retained). `process_vm_readv/writev`, `pidfd_getfd`, `memfd_create` hard-denied. **mmap-after-open** contained by acquisition-time mediation: the `open` was mediated, so the fd is authorized; the mapping rides an authorized capability. **SCM_RIGHTS fd passing** contained by the fd-provenance invariant below; sendmsg/recvmsg routed to the supervisor. |
| 4 | Deterministic TOCTOU primitives (`userfaultfd`, FUSE/attacker mounts, symlink/magic-link swaps) | partial | `userfaultfd` and the mount/FUSE family (`mount`, `umount2`, `fsopen`, `fsconfig`, `fsmount`, `move_mount`, `open_tree`) hard-denied. Path races: supervisor resolves via `openat2` with `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`. Race-free kernel-side resolution via **Landlock** is roadmap (v1.10). |
| 5 | New-execution-context / privilege surface (unprivileged user namespaces `CLONE_NEWUSER`, `ptrace`, unexpected `execve` helpers) | closed | `clone`/`unshare` scalar-flag filter denies `CLONE_NEWUSER` (and the namespace set) race-free; `setns`/`clone3` hard-denied. `ptrace` hard-denied. `execve`/`execveat` mediated against a supervisor-enforced exec-target allowlist. |
| 6 | Direct kernel / memory / device access (`bpf`, `init_module`/`finit_module`, `/dev/mem`, `/dev/kmem`, `/dev/port`, `/proc/kcore`, raw block devices, `perf_event_open`, `keyctl`) | closed | Syscall side hard-denied (`bpf`, module ops, `kexec_*`, `perf_event_open`, `keyctl`/`add_key`/`request_key`, `modify_ldt`). Device-special-file access is contained because **the `open` is mediated** — device paths are refused at acquisition, not merely matched as named files. |
| 7 | Supervisor-as-target / lifecycle | closed | Lifetime coupling: target SIGKILLed on supervisor death (`PR_SET_PDEATHSIG` + re-parent re-check + cgroup.kill fallback); supervisor watches target via pidfd. Notification flood bounded (`WD_MAX_INFLIGHT_NOTIFS`, excess → EPERM + bounded-refusal breaker). Injected fds carry `O_CLOEXEC` (no leak across exec). *(`warden_lifecycle.{h,c}`)* |
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
  pointer/path inspection (`openat`, `openat2`, `connect`, `execve`, `mount`*,
  `ptrace`* — the starred ones being denied rather than inspected).
- **Use path:** nothing mediates `read`/`write`/`recv`/`send` on
  already-authorized fds.

The accepted cost: durable capabilities are not re-checked by default (class 8).
Optional use-path re-mediation is the configurable, high-assurance answer — see
the v1.10 roadmap. Do not make every workload pay latency for assurance only some
need.
