# VAREK v1.12.2 — Threads and Child Processes

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

v1.12.2 fixes three gaps in the baseline seccomp filter that stopped ordinary
agents from running under the live Warden, and one exec-allowlist bypass that
admitting threads would have made routine. The three filter gaps date from the
default-deny allowlist in v1.9.2:

- **An agent that started a thread was killed.** `clone3` was on the kill list,
  and glibc 2.34 and later creates every thread with `clone3`. That covers every
  current mainstream distribution (Ubuntu 22.04+, Debian 12+, RHEL 9+), and with
  it most Python, Java and Node agents.
- **An agent could start a child process but never collect it.** `wait4` and
  `waitid` were not admitted, so `waitpid()`, `subprocess.run()` and
  `os.system()` failed after the child had already run.
- **`ioctl` was not admitted at all.** `isatty()` failed with `EPERM` instead of
  `ENOTTY`, and CPython, which marks every descriptor it opens close-on-exec with
  `ioctl(FIOCLEX)`, could not open its own script.

Testing the thread fix turned up the bypass: the Warden's one-time "bootstrap"
exec allow was granted once per *process id*, not once per run, and is answered
by letting the kernel re-read the path. A thread could use it to execute a
binary the policy never allowed. It is fixed here (see Security).

No verdict *semantics* change. The policy rules, the three-state verdict with
UNKNOWN suppressed to DENY, and the symmetric-suppression invariant (**no
extension may move a genuinely unsafe action to SATISFIED**) are untouched, and
no namespace denial is weaker.

Every fix is covered by `make test-v1122`, which fails against v1.12.1. The
v1.12.1, v1.12.0 and v1.9.3 lifecycle suites and the conformance target still
pass.

## Security

### The bootstrap exec is granted once per run

The Warden authorizes the agent's own launch, its first `execve` of the binary
the operator named, by answering `CONTINUE`: the kernel then re-reads the path
from the agent's memory and runs it. That is sound only while nothing else can
touch that memory, which holds for the launching process: single-threaded,
blocked in `execve`, before running any agent code.

Through v1.12.1 the allow was granted once per *process id*. Every new thread or
child started with a fresh allowance, so a thread could `execve` the agent's own
binary, get `CONTINUE`, and have a sibling thread rewrite the path between the
Warden's read and the kernel's. The kernel then ran a binary the exec policy had
never allowed. It still ran under the same filter, so its opens and connects
were still mediated, but the exec allowlist was bypassed. A deliberate agent
could already reach this through a raw `clone(CLONE_VM)`. With threads admitted,
ordinary thread code could reach it too, and the race was reproduced against
the v1.12.2 filter before this fix.

v1.12.2 grants the bootstrap allow exactly once per run, and only to the process
the Warden launched. Every later exec, including a thread or child re-executing
the agent's own binary, falls to the deny-only exec path and is refused. In the
same reproduction, 20,000 attempts were all refused.

## Changes

### clone3 answers ENOSYS

`clone3` takes its flags inside a struct in the caller's memory. A seccomp
filter cannot read that memory, so it cannot apply the namespace-bit checks it
applies to `clone` and `unshare`. `clone3` must therefore never run. Through
v1.12.1 the filter enforced that by killing the process.

v1.12.2 enforces it by answering `ENOSYS` ("this kernel has no clone3"). The C
library is written to handle that answer: glibc and Rust's standard library
retry with `clone()`, whose flags are a register argument the filter does check.
(musl and the Go runtime never use `clone3`.) Docker's default seccomp profile,
systemd, Chromium and Flatpak answer `clone3` the same way, for the same reason.

What this does and does not change:

- `clone3` still never executes, with or without namespace bits.
- Every thread and child the agent creates goes through `clone`, and the
  `CLONE_NEWUSER` / namespace-bit denial on `clone` still kills the process.
- A thread's file opens are mediated exactly like the main thread's: the Warden
  reads the path from that thread, resolves, decides, opens and injects the fd.
  Records name the requesting thread in `agent_pid`.
- No new race comes with threads. File opens never use `CONTINUE`, so a sibling
  thread has no checked pointer to swap, and `connect`, `sendto`/`sendmsg` and
  `execve` remain deny-only. A deliberately adversarial agent could already
  create threads with a raw `clone(CLONE_VM | CLONE_THREAD ...)` call; what
  changes is that a normal C library can do it too.
- The rule is the same in enforce, observe and non-strict builds.

### wait4 and waitid admitted

Both only reap children of the caller, so neither reaches outside the agent's
own process tree.

### ioctl admitted for six requests

| Request | What it does |
|---|---|
| `TCGETS` | `isatty()`, `tcgetattr()` |
| `TIOCGWINSZ` | read the terminal size |
| `FIOCLEX` / `FIONCLEX` | set / clear close-on-exec (same as `fcntl F_SETFD`) |
| `FIONBIO` | set / clear non-blocking (same as `fcntl F_SETFL`) |
| `FIONREAD` | bytes ready to read |

Each one only reads state or changes a flag on the caller's own descriptor that
the already-admitted `fcntl` can change. Every other request is still refused,
including `TIOCSTI`, which could push input into a terminal the operator is
sitting at, and `TCSETS`. The match is on the full 64-bit argument, so an
admitted request with junk in the upper bits matches nothing and is refused.

### A killed agent is reported

Through v1.12.1, an agent the filter killed left only an exit status of 1. That
is how a thread-starting agent could be killed on every run without a word. The
Warden now prints, for example:

```
[warden] agent killed by signal 31 (Bad system call): a hard-denied system call
```

### Exporter names the Warden that made the decisions

`varek_cyclonedx.py` now takes the Warden version for the BOM from the stream's
`run_start` record rather than from its own version constant. A v1.12.1 log
exported with this tool is labelled 1.12.1, not 1.12.2.

## Testing

- `make test-v1122`: 11 filter unit checks, then 37 assertions against a live
  Warden. Against v1.12.1 the probe is killed at its first `pthread_create` and
  the suite fails. Against a build with the thread fix but not the bootstrap
  fix, the re-exec checks fail.
  - Threads: one thread's allowed open is delivered and its denied open refused
    and recorded; 8 threads × 50 concurrent opens are all delivered and
    attributed to their own thread ids.
  - `clone3` plain and with `CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWNET`,
    `CLONE_NEWPID` and `CLONE_INTO_CGROUP` returns `ENOSYS` and creates nothing;
    `clone(CLONE_NEWUSER)` is still killed with `SIGSYS`.
  - `waitpid`, `wait4` with `rusage`, `waitid` and `WNOHANG` report the child's
    real status.
  - The `ioctl` allowlist behaves as above.
  - A thread and a forked child that `execve` the agent's own binary are
    refused, and the run holds exactly one bootstrap allow.
  - `posix_spawn` of a binary the policy does not name fails, is recorded, and
    the agent survives.
  - The multithreaded stream exports as a CycloneDX BOM, and a killed agent is
    reported.
- `make test-v1121`, `make test-v112`, `make test-lifecycle` and
  `make run-conformance` pass unchanged.
- Decision latency is unchanged within run-to-run noise (P50 5 µs; P99 59–66 µs
  before and 56–58 µs after, three runs each of `bench_target 10000` on the same
  host).

## Compatibility

- A `clone3` call now returns `ENOSYS` instead of killing the process.
  `clone3` has left the hard-deny list.
- Agents that start threads, wait for children, or call `isatty()` now run.
- An agent can no longer re-execute its own binary from a thread or child (for
  example Python `multiprocessing` in `spawn` mode). Exec is deny-only apart
  from the one launch, as documented since v1.9.1.
- `vfork` is still not admitted and returns `EPERM`; glibc and CPython fall back
  to `clone`.
- No policy-file, plan-file or record-format change. `run_start` reads
  `"warden":"1.12.2"`.

## Known issues, not addressed here

- **Dynamically linked agents still cannot start (fix planned for v1.12.3).**
  Since v1.12.0, file resolution refuses any path with a symlink in it. On
  merged-`/usr` distributions `/lib` is a symlink, and library names such as
  `libz.so.1` are symlinks to the versioned file. So the dynamic loader cannot
  open most shared libraries, and a dynamically linked program, CPython
  included, fails before `main()`. Static targets are unaffected, which is why
  every suite in this repository, all of which use static targets, passes.
  Following symlinks safely has to account for `/proc/self`, which would resolve
  to the Warden's own process, so it ships as its own release. In a test build
  with that change, a CPython agent using a thread pool, `fork`/`waitpid` and a
  denied open ran correctly end to end under the v1.12.2 filter.
- The `--plan` gate still refuses any plan that contains a `file_open` action,
  as it has since v1.12.0.

## Requirements

Unchanged from v1.12.1: Linux ≥ 5.14, `pidfd_getfd` (Linux ≥ 5.6),
`CAP_SYS_ADMIN` for the PID and network namespaces, x86_64.
