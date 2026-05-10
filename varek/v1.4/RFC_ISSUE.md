# RFC: Warden v1.4 design — seccomp-unotify supervisor with supervisor-side path resolution

**Status:** design RFC, looking for feedback before implementation lands on `main`.
**Scope:** kernel-level enforcement architecture for VAREK Warden.
**Audience:** anyone with seccomp, BPF-LSM, or sandbox-containment background.

---

## Why this RFC

VAREK v1.0–v1.3 shipped with a **demonstration-grade** Python supervisor
(`varek/v1_3/warden.py`, `varek/v1_3/seccomp_bridge.py`) that contains
hardcoded interception examples and stubbed kernel calls. It was useful
for showing the policy/evaluator/decision-log pipeline at the
language level, but it does not perform real syscall enforcement.

v1.4 is the first release where the Warden actually touches the kernel.
This RFC covers the design before code lands on `main`. The reference
implementation is in `v1_4/warden.c` on a feature branch and builds
cleanly under `gcc -Wall -Wextra -Wpedantic` against Linux ≥ 5.14;
that file is what this RFC describes, and the goal of the RFC is to
get the architecture reviewed before we declare it stable.

If you've worked on `seccomp-unotify`, BPF-LSM, sandbox supervisors,
or written about TOCTOU on pointer-argument syscalls, your feedback
on the three specific questions below would be very welcome.

## Architecture summary

A privileged parent process forks a child, installs a seccomp filter
in the child via `prctl(PR_SET_NO_NEW_PRIVS) + seccomp(SECCOMP_SET_MODE_FILTER,
SECCOMP_FILTER_FLAG_NEW_LISTENER, ...)`, and acquires the supervisor
side of the unotify channel via `SCM_RIGHTS` over a `socketpair`.

Trapped syscalls in v1.4: `openat`, `connect`, `execve`, `execveat`.
Everything else is allowed by the BPF program. The receive loop:

1. `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` to get the notification.
2. `derive_intent()` — read pointer arguments via `/proc/<pid>/mem`
   guarded by `SECCOMP_IOCTL_NOTIF_ID_VALID`, materialize them into
   a structured `Action {kind, target, parameters}`.
3. `policy_decide()` — three-state return `ALLOW / DENY / UNKNOWN`.
   `UNKNOWN` and `DENY` are both suppressed at the kernel boundary
   (symmetric suppression).
4. For path-arg syscalls on `ALLOW`, resolve the path supervisor-side
   with `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` rooted
   at `/proc/<pid>/cwd`, and inject the resolved fd via
   `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`. The
   kernel does **not** re-read the userspace pathname pointer.
5. For non-path-arg syscalls or `DENY`, send a simple response with
   `SECCOMP_IOCTL_NOTIF_SEND` (with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
   only on the `ALLOW` non-path path).
6. Emit a JSON pathology record with `CLOCK_MONOTONIC` decision
   latency in microseconds.

A working reproducer for the path-arg TOCTOU race that motivates step
4 is at `test/seccomp_toctou_harness.c` in the same branch. It runs
two supervisors against the same adversarial workload and confirms
that the naive `CONTINUE`-based approach leaks the sentinel while the
`openat2 + ADDFD` approach does not.

## What I want feedback on

Three narrow questions where I'd value an informed second opinion:

### 1. Address-space-share coverage

The supervisor materializes pointer arguments via `/proc/<pid>/mem`
under `SECCOMP_IOCTL_NOTIF_ID_VALID`. For path-arg syscalls, the
supervisor then resolves the path itself and injects an fd, so even
if a `CLONE_VM` sibling overwrites the path bytes after the read, the
kernel never re-acts on the userspace pointer.

For non-path-arg syscalls (`connect` reading a `sockaddr`, `execve`
reading the path), the supervisor reads, decides, and sends `CONTINUE`
or `EPERM`. **Are there residual races on these paths I'm missing?**
Specifically:

- `connect` with a sockaddr in shared memory mutated between read
  and `CONTINUE`. Because `connect` re-reads the address on
  re-execution after `CONTINUE`, this is exactly the same race as
  `openat`. Should `connect` also go through an `ADDFD`-style
  supervisor-side resolution (e.g., resolve the address into a
  socket pre-bound to the destination, hand back the connected fd)?
  Or is there a cleaner pattern?
- `execve` with `argv` and `envp` arrays of pointers, all in shared
  memory. The supervisor doesn't currently materialize argv/envp at
  all in v1.4; the policy decision is made on the executable path
  alone. Is allowing `execve` after only path-validation
  fundamentally unsound, given that argv/envp can change between
  read and re-execution?

### 2. `ADDFD` re-issue soundness

The `openat`-via-`ADDFD` pattern works because the kernel's job after
the notification is just "return this fd as the syscall result." Are
there path-argument syscalls where this pattern is unsound — i.e.,
where kernel-internal state depends on the original calling thread's
context in ways `ADDFD` doesn't preserve (credentials at moment of
call, mount propagation, audit context, fanotify subscriptions)?
`openat`, `openat2` themselves seem fine; what about `name_to_handle_at`,
`open_by_handle_at`, `mount` family?

### 3. Namespace-transition completeness

The Execution Context tracks per-pid state but not namespace identity.
Specific concern: a target that issues `unshare(CLONE_NEWNS)` followed
immediately by `mount`. If a single notification window straddles two
evaluation contexts (different mount namespaces), the supervisor's
`/proc/<pid>/cwd` snapshot at notification time may resolve to a
different mount table than the one the target sees post-`unshare`.

In v1.4 we don't trap `unshare` or `setns` at all — they fall through
the BPF filter. Should we be trapping them and invalidating the
Execution Context? Or is there a cleaner namespace-tracking primitive
(e.g., reading `/proc/<pid>/ns/mnt` as part of every `derive_intent`)
that doesn't require trapping more syscalls?

## Threat model

- **Supervised process**: fully adversarial, may spawn `CLONE_VM`
  siblings that share its address space.
- **Supervisor**: privileged, isolated, not co-resident in the
  supervised `mm`.
- **Kernel**: trusted.

Out of scope: kernel exploits, hypervisor escapes, side-channels,
`ptrace` from privileged peers outside the seccomp domain.

## Prior art I've read

- M. Sarai, "Adventures in implementing seccomp notify" (LWN, 2020).
- LKML discussion on `SECCOMP_IOCTL_NOTIF_ADDFD` introduction.
- Project Zero notes on supervisor-side argument resolution.
- `openat2(RESOLVE_*)` introduction (5.6+).
- BPF-LSM (5.7+) as an alternative enforcement primitive.

If there's prior art I've missed — particularly anything that already
addresses questions (1)–(3) above — please point me at it. I'd rather
inherit a known-good pattern than invent a new one.

## Non-goals for this RFC

- General code review of VAREK at large.
- Policy-language design feedback.
- Performance discussion (separate issue, separate benchmarks).
- Anything about the SMT/Z3 layer above the seccomp supervisor.
- Anything outside the seccomp-unotify enforcement path.

## How to engage

- Comment on this issue.
- File a separate issue if you want to discuss something narrow.
- Open a PR against the v1.4 feature branch if you have a fix.

No expectation of response, but the project is better for external
scrutiny and I'd rather find a flaw here than in production.
