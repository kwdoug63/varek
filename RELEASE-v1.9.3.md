# VAREK v1.9.3 — Lifecycle Coupling in the Live Warden

Released 2026-09-15 · MIT · github.com/kwdoug63/varek

## Summary

v1.9.3 is a hardening patch. It changes no verdict semantics and does not
touch the v1.9 progress-safety proof. It wires the v1.9.2 lifecycle module into
the live Warden and extends it, so that **if the supervisor stops, the agent
stops, and so does everything the agent started.** The invariant is unchanged:
**no extension may move a genuinely unsafe action to SATISFIED.**

It also corrects the v1.9.2 record. At v1.9.2 the lifecycle module shipped but
was not called by the live Warden, so bypass class 7 (supervisor-as-target /
lifecycle) was **partial**, not closed. As of v1.9.3 it is closed in the
default configuration.

## Security

### The agent dies with the supervisor

The target sets `PR_SET_PDEATHSIG(SIGKILL)` after fork and before it installs
its seccomp filter. `prctl` is outside the baseline allowlist, so the agent
cannot clear it afterwards. If the supervisor died between fork and that call,
the death signal would never fire; the target detects this through a pipe whose
write end only the supervisor holds, and refuses to run unmonitored. The pipe
replaces the v1.9.2 `getppid()` re-check, which returns 0 inside a PID
namespace. `wd_target_couple_to_supervisor()` now takes the pipe fd.

### So does everything the agent spawned

A death signal applies to one process, not to its children. The Warden now
runs the target as init of a dedicated PID namespace; when that process dies,
the kernel kills every other process in the namespace. On orderly shutdown the
Warden kills the whole tree (namespace and process group; `setpgid`/`setsid`
are outside the allowlist, so the agent cannot leave the group).

### Supervisor watches the target via pidfd

The receive loop waits on the target's pidfd alongside the notification
listener. This also fixes a hang in which the target exited just before the
supervisor blocked in `SECCOMP_IOCTL_NOTIF_RECV`.

### CAP_SYS_ADMIN is required

Creating the namespace needs `CAP_SYS_ADMIN`. The Warden checks for it at
startup and refuses to run without it. `VAREK_WARDEN_NO_PIDNS=1` skips the
namespace and the check, with a warning; in that mode the agent still dies with
the supervisor, but processes it spawned are not guaranteed to on a supervisor
crash, and class 7 is partial.

## Validation

`make test-lifecycle` (`varek/v1_4/tests/test_v193_lifecycle.c`) runs the live
Warden over an agent that spawns a child, then:

| Scenario | Pre-fix Warden | v1.9.3 |
|---|---|---|
| Supervisor killed (`SIGKILL`) | agent and child survive | no survivors |
| Supervisor stopped (`SIGTERM`) | child survives | no survivors |
| Supervisor dead before coupling | not detected | target refuses to run |

With `VAREK_WARDEN_NO_PIDNS=1` the crash scenario leaves the child alive, as
documented. Policy decisions on the demo, plan-verification, benchmark (2,000
iterations), and conformance workloads are identical to the pre-fix Warden. The
baseline filter test still passes. Validated on Linux 6.18, x86_64.

## Fixed

- **Conformance target setup.** `target_conformance` failed `allowed_open`
  when `/tmp/varek_conf` did not exist, because the target cannot create
  directories under enforcement. It now reports a `setup` failure with the fix.
  `make run-conformance` builds the target, creates the directory, and runs it.

## Changed

- Inside its namespace the agent sees its own PID as 1 and `getppid()` returns
  0. Pathology records still carry the host PID.
- `WD_MAX_INFLIGHT_NOTIFS` is documented as applying to a future
  multi-threaded supervisor. The v1.4 Warden handles one notification at a
  time, and pending requests queue in the kernel.
- Spec paper updated to v1.9.3 (`varek-spec-paper-v1.12.md`, §2.9).

## Not in this release

- The cgroup `cgroup.kill` helper remains in `warden_lifecycle.c` but is not
  used; the PID namespace covers the same case.
- An allowed `openat` whose supervisor-side resolution fails (for example, a
  missing parent directory) is reported to the agent as `EACCES` and logged as
  a deny, rather than surfacing the underlying error. Tracked for a later
  release.

The project is patent-pending; nothing in this release is granted.
