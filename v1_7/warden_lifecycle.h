// SPDX-License-Identifier: MIT
// warden_lifecycle.h — v1.9.2 supervisor/target lifetime + notification hygiene
//
// Addresses bypass class 7 (supervisor-as-target / lifecycle). The enforcement
// model assumes the supervisor is alive and watching. If it is not, unmediated
// syscalls keep running on a now-unmonitored target. Three couplings:
//
//   - target dies if supervisor dies  (PR_SET_PDEATHSIG + liveness-pipe race
//                                       check)
//   - target's descendants die with it (dedicated PID namespace, target = init)
//   - supervisor learns if target dies (pidfd poll), to release state
//   - injected fds carry O_CLOEXEC      (ADDFD must not leak across exec)
//   - a bound on in-flight notifications (flood DoS containment)
//
// Integrated into the v1.4 Warden (varek/v1_4/warden.c) and covered end to
// end by varek/v1_4/tests/test_v192_lifecycle.c.
#ifndef WARDEN_LIFECYCLE_H
#define WARDEN_LIFECYCLE_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Call in the SUPERVISOR, once, before forking the target. Places the NEXT
// child the supervisor forks into a fresh PID namespace as its init (pid 1).
// When that init dies, the kernel SIGKILLs every other process in the
// namespace, so anything the agent spawned dies with it. Requires
// CAP_SYS_ADMIN. The supervisor must fork exactly one child afterwards.
// Returns 0 / -errno.
int wd_supervisor_isolate_pids(void);

// Call in the TARGET, after fork and before installing the seccomp filter /
// execing the agent. Requests SIGKILL when the supervisor (the thread that
// forked this process) dies. liveness_fd is the read end of a pipe whose write
// end only the supervisor holds; if it already reports POLLHUP, the supervisor
// died before PR_SET_PDEATHSIG took effect (the fork/prctl race) and the
// target must not continue. A pipe is used instead of getppid() because
// getppid() returns 0 inside a PID namespace. Returns 0, -ESRCH if the
// supervisor is already gone, or -errno.
int wd_target_couple_to_supervisor(int liveness_fd);

// Call in the SUPERVISOR for a managed target. Returns a pidfd (>=0) that
// becomes readable when the target exits, so the supervisor can release the
// target's authorized-fd set and notification slots. -errno on failure.
int wd_supervisor_watch_target(pid_t target_pid);

// cgroup v2 kill fallback: write "1" to <cgroup>/cgroup.kill to atomically
// SIGKILL the whole subtree if PDEATHSIG coupling is insufficient (e.g. the
// target re-parents). cgroup_dir is the target's cgroup path. 0 / -errno.
int wd_cgroup_kill(const char *cgroup_dir);

// ---- notification hygiene -------------------------------------------------

// Bound on concurrently-handled notifications, for a future multi-threaded
// supervisor. NOT enforced by the v1.4 Warden: it handles one notification at
// a time (in-flight concurrency is 1) and pending requests queue in the
// kernel, so there is no supervisor-side state to exhaust. A multi-threaded
// supervisor must enforce this bound (excess -> EPERM, fail closed).
#ifndef WD_MAX_INFLIGHT_NOTIFS
#define WD_MAX_INFLIGHT_NOTIFS 256
#endif

// Inject a supervisor-opened fd into the target via SECCOMP_IOCTL_NOTIF_ADDFD,
// forcing O_CLOEXEC on the target's copy so it does NOT survive a subsequent
// execve (an ADDFD without O_CLOEXEC silently leaks a capability across exec).
// notify_fd is the seccomp listener fd; id is the notification id; src_fd is the
// supervisor's open fd to inject. Revalidates NOTIF_ID_VALID before injecting
// (consistent with the v1.9.1 TOCTOU discipline). Returns the target-side fd
// number (>=0) or -errno.
int wd_addfd_cloexec(int notify_fd, uint64_t id, int src_fd);

#ifdef __cplusplus
}
#endif
#endif // WARDEN_LIFECYCLE_H
