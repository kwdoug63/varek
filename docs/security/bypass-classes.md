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
| 2 | Variant-syscall evasion (`clone3`, `openat2`, `faccessat2`, `pidfd_*`) | closed | Default-deny allowlist: a variant is denied unless admitted. `clone3` (pointer-flags, uninspectable) never executes: hard-denied through v1.12.1, answered `ENOSYS` from v1.12.2 so libc falls back to the flag-filtered `clone`. When we mediate an effect we mediate **every** syscall producing it. |
| 3 | Off-path I/O dispatch | closed (send path, v1.12; inbound, v1.12.1); partial elsewhere | `io_uring_*` denied (v1.9.1, retained). `process_vm_readv/writev`, `pidfd_getfd`, `memfd_create` hard-denied. **mmap-after-open** contained by acquisition-time mediation: the `open` was mediated, so the fd is authorized; the mapping rides an authorized capability. **Datagram egress** (`sendto`/`sendmsg` reaching the network without `connect`) **closed in v1.12**: both are mediated as `net.send` and refused for an inet destination under the deny-only network posture; inbound `recvfrom`/`recvmsg` stay admitted. **Inbound networking** (`bind`/`listen`/`accept`/`accept4`, a TCP listener or an abstract unix socket the host can reach) was left admitted through v1.12.0; **closed in v1.12.1**: the four calls are refused, and the agent runs in its own network namespace holding only a loopback interface that is down. **SCM_RIGHTS fd passing** contained by the fd-provenance invariant below. |
| 4 | Deterministic TOCTOU primitives (`userfaultfd`, FUSE/attacker mounts, symlink/magic-link swaps) | partial | `userfaultfd` and the mount/FUSE family (`mount`, `umount2`, `fsopen`, `fsconfig`, `fsmount`, `move_mount`, `open_tree`) hard-denied. Path races and symlink/magic-link swaps: the supervisor resolves the object **once** with `openat2(RESOLVE_NO_MAGICLINKS)`, decides policy on the **resolved canonical path** (`readlink` of the pinned `O_PATH` fd), and injects that **same fd** (v1.12 resolve-then-decide-then-inject) — so the object decided on is the object delivered, and a symlink swapped after the decision cannot change which inode the agent receives. A symlink is **followed** (v1.12.3) and the decision is made on its canonical target, so a symlink inside an allowed directory pointing at a denied object is decided as the denied object and refused; a `..` traversal is decided on the post-collapse path. Before v1.12 the decision was made on the raw pathname rather than the resolved object (both traversal and symlink escapes mis-authorized); v1.12.0–v1.12.2 instead set `RESOLVE_NO_SYMLINKS`, refusing every symlinked path outright, which also blocked every dynamically linked agent's loader — v1.12.3 follows symlinks while keeping the decide-on-canonical-target property. For `/proc`: a leading `/proc/self`/`thread-self` (a magic link) is mapped to the agent's own `/proc/<tgid>` before resolution; a planted symlink to a magic link such as `/proc/self/mem` is refused by `RESOLVE_NO_MAGICLINKS` during resolution; and a numeric `/proc/<pid>` object that is not the agent's own fails a post-resolution check. Non-process `/proc` entries (`/proc/kcore`, `/proc/sys/…`) are governed by policy, so name them narrowly. `RESOLVE_BENEATH` is intentionally **not** set (allow rules legitimately name absolute paths outside the cwd); `..` is defanged by deciding on the canonical path, not by forbidding it. Race-free kernel-side resolution via **Landlock** remains roadmap (reserved v1.10). |
| 4a | Supervisor-context path confusion (`/proc/self/*`) | closed (v1.12) | `/proc/self` and `/proc/thread-self` are magic symlinks the kernel resolves in the **caller's** context — the supervisor's — so an agent naming `/proc/self/mem` would receive a handle on the Warden. `RESOLVE_NO_MAGICLINKS` (now actually set) refuses them. Reading the resolved fd's own `/proc/self/fd/N` link to canonicalize is safe: that link is dereferenced by the supervisor on a fd it already holds, not on an agent-named path. |
| 5 | New-execution-context / privilege surface (unprivileged user namespaces `CLONE_NEWUSER`, `ptrace`, unexpected `execve` helpers) | closed | `clone`/`unshare` scalar-flag filter denies `CLONE_NEWUSER` (and the namespace set) race-free; `setns` hard-denied; `clone3` never executes (`ENOSYS` from v1.12.2, so threads fall back to `clone` and pass the same flag filter). `ptrace` hard-denied. `execve`/`execveat` mediated against a supervisor-enforced exec-target allowlist. The one exec answered with `CONTINUE`, the agent's own launch, was granted once per pid through v1.12.1, so a new thread or child could race its path; from v1.12.2 it is granted once per run, to the launched process only. **v1.17.0:** the agent runs as an unprivileged user (`--run-as`, default `nobody`) with an empty capability bounding set, no ambient or permitted capabilities and no supplementary groups; through v1.16.3 it ran as root with every capability and only the filter held it back. |
| 6 | Direct kernel / memory / device access (`bpf`, `init_module`/`finit_module`, `/dev/mem`, `/dev/kmem`, `/dev/port`, `/proc/kcore`, raw block devices, `perf_event_open`, `keyctl`) | closed | Syscall side hard-denied (`bpf`, module ops, `kexec_*`, `perf_event_open`, `keyctl`/`add_key`/`request_key`, `modify_ldt`). Device-special-file access and `/proc/kcore`, `/proc/mem`-class paths are contained because **the `open` is mediated** — they are refused at acquisition unless the policy names them. This is default-deny, not a hard rule: a policy that broadly allowed their directory (e.g. `allow path /proc/` or `/dev/`) would expose them, so name device and kernel-interface paths narrowly. **v1.17.0: now a hard rule.** Whatever the policy says and whatever path reaches them (a bind mount, a device node planted in an allowed tree), block devices, `/dev/mem`, `/dev/kmem`, `/dev/port`, the sg/bsg/nvme command devices and `/proc/kcore` are refused by identity after resolution (`raw_device`). |
| 7 | Supervisor-as-target / lifecycle | closed (v1.9.3); partial in v1.9.2 | **v1.9.3:** the live Warden runs the target as init of its own PID namespace and SIGKILLs it on supervisor death (`PR_SET_PDEATHSIG`, with a liveness-pipe check for the fork/prctl race); when the target dies, the kernel kills every process it spawned. Orderly shutdown kills the whole tree (namespace + process group). The supervisor watches the target via pidfd. The Warden requires `CAP_SYS_ADMIN` and refuses to start without it; `VAREK_WARDEN_NO_PIDNS=1` opts out, and in that mode the class is **partial** (descendants are not covered on a supervisor crash). Injected fds carry `O_CLOEXEC` (no leak across exec). The single-threaded v1.4 Warden handles one notification at a time, so pending requests queue in the kernel; `WD_MAX_INFLIGHT_NOTIFS` applies to a future multi-threaded supervisor. Asserted end to end by `varek/v1_4/tests/test_v193_lifecycle.c` (`make test-lifecycle`). **v1.9.2:** only `O_CLOEXEC` was enforced by the live Warden; the lifecycle module was not yet wired in. *(`warden_lifecycle.{h,c}`)* |
| 8 | Post-grant capability reuse (durable fd/socket reused for later actions the policy never re-checks) | contained / roadmap | fd-provenance invariant narrows grants. Use-path **re-mediation** offered as an optional high-assurance mode, defaulted off so the common case does not pay the latency. *(design in v1.10 roadmap)* |
| 9 | Below the boundary (kernel 0-day, hypervisor escape, DMA, microarchitectural side channels, Rowhammer, timing/power covert channels) | out of scope | Defense-in-depth (minimal syscall surface, dropped caps, namespaces, Landlock) shrinks the surface; it does not close these. Disclosed here rather than implied covered. |
| 10 | Metadata and link lookups outside mediation (`stat`, `statx`, `access`, `readlink`) | closed (v1.17.0) | Through v1.16.3 `newfstatat`, `statx`, `access`, `faccessat(2)`, `readlink(at)` were admitted and never logged: an agent could learn whether any file existed, its size, owner and times, and read where any link pointed, including the Warden's own `/proc/<pid>/fd` entries. From v1.17.0 they are mediated: resolved like an open, refused by identity if protected, decided as a read-only open of the same object (`access(W_OK)` as a write), certified, recorded and answered by the Warden. A name that does not exist is decided on where it would be (`ENOENT` inside the policy, `EACCES` outside); a name that exists but cannot be followed fails closed, so a link cannot be used to probe outside the policy. Answered without a decision: `stat`/`statx` of a descriptor the agent already holds (not the working directory), and a read-type lookup on a directory an allow rule's literal start leads to and no deny rule covers (`metadata_ancestor`, recorded; existence and type only, times zeroed), so `realpath()` works. `fstat` (syscall 5) on a held descriptor stays admitted. |
| 11 | Aliases of the Warden's own files (signing key, anchor, verdict stream) | closed (v1.17.0) | Through v1.16.3 the Warden refused to start if the policy allowed these by their real path only; a bind mount of the key's directory into an allowed tree let the agent read the private key. From v1.17.0 every open and lookup is checked, after resolution and before the policy, against their device and inode (`protected_object`), which covers bind mounts, hard links and renames. A stacked filesystem that re-presents a file under a new device (overlayfs) is not recognized, and a stream written through a pipe protects the pipe, not the file at its far end. |

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
a `/proc/self` magic link resolving in the supervisor's context). v1.12 collapsed
them: the object is resolved **once** with `openat2(RESOLVE_NO_MAGICLINKS)`, its
canonical path read back from the pinned fd, the policy decision made on that
canonical path, and *that same fd* injected into the agent. Through v1.12.2 the
resolve also set `RESOLVE_NO_SYMLINKS`, refusing any symlinked path; **v1.12.3**
follows ordinary symlinks and decides on the canonical target instead (a symlink
to a denied object is still refused, and every dynamically linked agent's loader
now works). Resolution failure (an over-long path, an untracked dirfd, a deleted
inode, or a trailing symlink opened `O_NOFOLLOW`) is a hard deny before any
policy match, and a procfs object outside the agent's own `/proc/<tgid>` fails
closed.

**v1.14: name matchers decide on the same canonical path.** `suffix`,
`contains` and `glob` rules (v1.14) are matched on the canonical path read back
from the pinned fd, like every path rule, so a symlink with an innocent name is
decided by its target's name. They judge a *name*, not a file's identity: a hard
link that already exists under another name is decided by that name. While the
Warden enforces, the agent cannot create one — `rename*`, `link*` and
`symlink*` are outside the default-deny allowlist — but in observe mode
(`VAREK_WARDEN_OBSERVE=1`) those syscalls are only logged, so name matchers are
not a boundary there. Matching is byte-wise and case-sensitive.

**v1.12.1: resolve, decide, then open.** v1.12.0 performed that single
resolution as a real open with the agent's own flags, before the decision. A
denied open therefore still had effects: `O_TRUNC` emptied a denied file,
`O_CREAT` created a root-owned file in a denied directory, and a blocking open
(a FIFO with no peer) wedged the single-threaded supervisor. v1.12.1 pins the
object with an `O_PATH` descriptor, which opens nothing, decides on its
canonical path, and only after ALLOW opens it with the agent's flags **through
the pinned descriptor** (`/proc/self/fd/N` of the supervisor's own fd), so the
object decided on is still the object delivered. For `O_CREAT` of a name that
does not exist, the parent directory is pinned, the decision is made on
`<canonical parent>/<name>`, and the file is created with
`openat(parent_fd, name, O_NOFOLLOW)` under the agent's umask. The real open
adds `O_NONBLOCK` and clears it afterwards unless the agent asked for it, so a
FIFO or device cannot block the supervisor; opening a FIFO for writing with no
reader returns `ENXIO` instead of waiting. Asserted by `make test-v1121`.

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

**v1.12.1: an authenticated stream.** Escaping stopped forgery *inside* a
record, but the agent still shared the Warden's stderr, so it could write a
whole, well-formed record of its own, and the exporter listed the object it
named as authorized. v1.12.1 closes that:

- The agent's stderr is a pipe the Warden relays line by line with an
  `[agent] ` prefix and control bytes escaped, so no agent byte can begin a line
  of the verdict stream, and a `\r` cannot split one.
- Records go through a private close-on-exec descriptor, fully buffered and
  flushed once per record, so each record reaches the file in one `write()`.
- Every record carries a per-run id (128 random bits the agent never sees) and a
  `seq` counting up from 0; `run_start` and `run_end` records frame the stream.
- `varek_cyclonedx.py` refuses a stream with no `run_start`, a record with a
  foreign run id (for example the agent's stdout merged in with `2>&1`), a `seq`
  gap or repeat, or no `run_end` (unless `--allow-incomplete`). v1.12.0 logs carry
  no run id and are refused.

**v1.16: against the log's holder.** Every record is hash-chained (`"chain"`,
SHA-256 over the previous value and the record's bytes); with `--sign-key`,
run_start, a checkpoint every 64 records (and at least once a second) and
run_end are Ed25519-signed; with `--anchor`, those records are also appended
to storage the holder cannot rewrite. `varek_audit.py --pubkey --anchor`
verifies all three with its own RFC 8032 verifier. The Warden refuses to start
if the policy would let the agent open the key, the anchor, its own verdict
stream file, or (with a key or anchor) a raw disk or memory device.

Residual: someone holding the log and the signing key can rewrite whatever was
not anchored (all of it, without an anchor); root on the Warden host during
the run can forge records before they are signed; status lines, the agent's
relayed stderr and `--plan` gate records are not chained; raw storage devices
the startup check does not recognize.

