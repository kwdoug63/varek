# RFC: Warden v1.4 — seccomp-unotify supervisor with supervisor-side path resolution

**Status:** Implementation merged on `main`. Looking for review of correctness, not approval to ship.
**Scope:** kernel-level enforcement architecture for VAREK Warden.
**Audience:** anyone with seccomp, BPF-LSM, sandbox-containment, or kernel-security background.

---

## Why this RFC

VAREK v1.4 introduces native kernel-level enforcement via a privileged seccomp-unotify supervisor written in C. The implementation lives at [`varek/v1_4/warden.c`](../varek/v1_4/warden.c) on `main`.

This RFC asks for review of two things:

1. **Three architectural questions** where I'd value an informed second opinion before relying on the current behavior in production (see *Open questions*).
2. **Four implementation gotchas** I hit during development that are worth knowing for anyone building this pattern (see *Notes for implementers*).

If you've worked on seccomp-unotify, BPF-LSM, sandbox supervisors, or written about TOCTOU on pointer-argument syscalls, your feedback would be very welcome.

---

## Architecture summary

A privileged parent process forks a child, installs a seccomp filter in the child via
`prctl(PR_SET_NO_NEW_PRIVS) + seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ...)`,
and acquires the supervisor side of the unotify channel via `SCM_RIGHTS` over a `socketpair`.

Trapped syscalls in v1.4: `openat`, `connect`, `execve`, `execveat`. Everything else passes through `SECCOMP_RET_ALLOW`. The receive loop:

1. `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` to get the notification.
2. `derive_intent()` reads pointer arguments via `/proc/<pid>/mem` guarded by `SECCOMP_IOCTL_NOTIF_ID_VALID`, materializing them into a structured Action.
3. `policy_decide()` returns `ALLOW` / `DENY` / `UNKNOWN`. `UNKNOWN` and `DENY` both surface as kernel `EPERM` (symmetric-suppression invariant).
4. For path-arg syscalls on `ALLOW`: resolve supervisor-side via `openat2(RESOLVE_NO_MAGICLINKS)` rooted at `/proc/<pid>/cwd`, return resolved fd via `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`. Kernel does not re-read the userspace pathname pointer.
5. For non-path-arg syscalls or `DENY`: send a simple response with `SECCOMP_IOCTL_NOTIF_SEND`.
6. Emit a JSON pathology record with `CLOCK_MONOTONIC` decision latency in microseconds.

Code: [`varek/v1_4/warden.c`](../varek/v1_4/warden.c) (~660 lines, single-file C11, no external deps beyond glibc).

---

## Measured behavior

End-to-end run on Ubuntu 24.04 / kernel 6.8.0-110 / 1 vCPU / 512 MB:

| Metric | Value |
|--------|-------|
| Decisions observed | 10,006 |
| Wall-clock | 0.40 s |
| P50 | 16 µs |
| P95 | 39 µs |
| **P99** | **57 µs** |
| P99.9 | 106 µs |
| Max | 588 µs |
| False negatives observed | 0 |
| `UNKNOWN` suppressions | 1,000 of 1,000 |

The distribution is multimodal: three distinct peaks centered around 12 µs (fast denies), 24 µs (intent-derived denies), and 38 µs (authorized `openat` injections via `ADDFD`). Each cluster maps to a specific code path in the supervisor.

Provenance file: [`varek/v1_4/bench_results_v1_4.txt`](../varek/v1_4/bench_results_v1_4.txt). Reproduce with `make run-bench` from `varek/v1_4/`.

---

## Open questions (request for review)

Three narrow points where I'd value an informed second opinion.

### Q1: Address-space-share coverage on non-path-arg syscalls

For path-arg syscalls (`openat`), the supervisor resolves the path itself and injects an fd via `ADDFD`, so a `CLONE_VM` sibling overwriting the path bytes between supervisor read and kernel re-execution doesn't matter — the kernel never re-acts on the userspace pointer.

For non-path-arg syscalls, the supervisor reads the argument, decides, and sends `CONTINUE` or `EPERM`. **Two specific concerns:**

- **`connect`** with a sockaddr in shared memory mutated between read and `CONTINUE`. Because `connect` re-reads the address on re-execution after `CONTINUE`, this is the same race class as `openat`. Should `connect` also go through an `ADDFD`-style supervisor-side resolution (e.g., resolve into a socket pre-bound to the destination, hand back the connected fd)? Or is there a cleaner pattern?

- **`execve`** with `argv` and `envp` arrays of pointers, all in potentially shared memory. v1.4 doesn't materialize argv/envp at all; the policy decision is made on the executable path alone. Is allowing `execve` after only path-validation fundamentally unsound, given that argv/envp can change between read and re-execution?

### Q2: `ADDFD` re-issue soundness

The `openat`-via-`ADDFD` pattern works because the kernel's job after notification is just "return this fd as the syscall result." Are there path-argument syscalls where this pattern is unsound — i.e., where kernel-internal state depends on the original calling thread's context in ways `ADDFD` doesn't preserve (credentials at moment of call, mount propagation, audit context, fanotify subscriptions)?

`openat`, `openat2` themselves seem fine. What about `name_to_handle_at`, `open_by_handle_at`, the `mount` family?

### Q3: Namespace-transition completeness

The per-pid Execution Context tracks state but not namespace identity. Specific concern: a target that issues `unshare(CLONE_NEWNS)` followed immediately by `mount`. If a single notification window straddles two evaluation contexts (different mount namespaces), the supervisor's `/proc/<pid>/cwd` snapshot at notification time may resolve to a different mount table than the one the target sees post-`unshare`.

In v1.4 we don't trap `unshare` or `setns` — they fall through the BPF filter. Should we be trapping them and invalidating the Execution Context on transition? Or is there a cleaner namespace-tracking primitive (e.g., reading `/proc/<pid>/ns/mnt` as part of every `derive_intent`) that doesn't require trapping more syscalls?

---

## Notes for implementers

Four implementation gotchas worth knowing if you build this pattern. None are subtle bugs in the kernel; all are behaviors that surprised me on first encounter and cost real debugging time.

1. **`openat2` rejects nonzero `mode` without `O_CREAT` or `O_TMPFILE`.** Per the man page: *"If flags does not contain O_CREAT or O_TMPFILE, mode must be zero, otherwise it will fail with EINVAL."* When proxying an `openat()` call, the syscall ABI always carries a `mode` argument register, but for `O_RDONLY` opens it's uninitialized garbage. You must explicitly zero `open_how.mode` unless `O_CREAT`/`O_TMPFILE` is in flags. See [`inject_resolved_fd()`](../varek/v1_4/warden.c).

2. **`RESOLVE_NO_SYMLINKS` is too aggressive for normal Linux.** On modern Ubuntu and Debian, `/lib → /usr/lib` (usrmerge), and `libc.so.6` itself is often a versioned symlink. Adding `RESOLVE_NO_SYMLINKS` to `open_how.resolve` causes every dynamic-loader path resolution to fail with `ELOOP`. v1.4 uses only `RESOLVE_NO_MAGICLINKS`, which still defeats `/proc/self/fd/N` resolution attacks without breaking ordinary library loading.

3. **`SECCOMP_IOCTL_NOTIF_ADDFD` returns the new fd in the target on success, not 0.** Easy to misread `if (ioctl(...) == 0)` as "success" when a successful `ADDFD` returns the target's new fd (a positive integer). Failure is `-1`. The bug is silent if you don't cross-check supervisor logs against target observed behavior — the kernel sends the fd to the target while the supervisor logs DENY.

4. **`signal()` defaults to `SA_RESTART` on glibc.** This auto-restarts the supervisor's blocking `ioctl(NOTIF_RECV)` after a signal handler fires, so a `SIGINT` handler that sets a stop flag never gets a chance to break the loop. Use `sigaction()` with `sa_flags = 0`. Add a `SIGCHLD` handler that sets the stop flag, so the supervisor exits cleanly when the supervised process dies (otherwise the receive loop blocks forever waiting for notifications that will never come).

---

## What this v1.4 is not

Honest scope statement. The following are tracked separately and explicitly out of scope here:

- **SMT-discharged policy decisions.** v1.4's `policy_decide()` is string-prefix matching; the formal-verification layer is future work.
- **Workflow-graph (whole-plan) verification.** Decisions are made per-syscall.
- **BPF-LSM enforcement.** seccomp-unotify only.
- **Compliance-framework mappings in pathology output.** The JSON shape is there to extend.
- **Multi-host coordination.** Single supervisor, single supervised process.
- **Standalone TOCTOU reproducer.** A separate harness demonstrating the race that motivates supervisor-side resolution is planned for a follow-up commit at `test/seccomp_toctou_harness.c`.

---

## Threat model

- **Supervised process**: fully adversarial. May spawn `CLONE_VM` siblings that share its address space.
- **Supervisor**: privileged, isolated, not co-resident in supervised `mm`. Runs as root in the reference; production deployment would use `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`, `CAP_DAC_READ_SEARCH`.
- **Kernel**: trusted.

Out of scope for the threat model: kernel exploits, hypervisor escapes, side-channels, `ptrace` from privileged peers outside the seccomp domain.

---

## Prior art consulted

- M. Sarai, *Adventures in implementing seccomp notify* (LWN, 2020).
- LKML thread on `SECCOMP_IOCTL_NOTIF_ADDFD` introduction.
- Project Zero notes on supervisor-side argument resolution races.
- `openat2(RESOLVE_*)` introduction (5.6+).
- BPF-LSM (5.7+) as an alternative enforcement primitive.

If there's prior art that already addresses Q1–Q3, please point me at it. I'd rather inherit a known-good pattern than invent a new one.

---

## Non-goals for this RFC

- General code review of VAREK at large.
- Policy-language design feedback.
- Performance tuning.
- The SMT verification layer above the seccomp supervisor.
- Anything outside the seccomp-unotify enforcement path.

---

## How to engage

- Comment on the GitHub issue linking this RFC.
- File a separate issue for narrow concerns.
- Open a PR against `main` if you have a fix.

No expectation of response. The project benefits from external scrutiny and I'd rather find a flaw here than in production.
