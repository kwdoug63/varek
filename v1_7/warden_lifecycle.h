// SPDX-License-Identifier: MIT
// warden_lifecycle.h — v1.9.2 supervisor/target lifetime + notification hygiene
//
// Addresses bypass class 7 (supervisor-as-target / lifecycle). The enforcement
// model assumes the supervisor is alive and watching. If it is not, unmediated
// syscalls keep running on a now-unmonitored target. Three couplings:
//
//   - target dies if supervisor dies  (PR_SET_PDEATHSIG + cgroup.kill fallback)
//   - supervisor learns if target dies (pidfd poll), to release state
//   - injected fds carry O_CLOEXEC      (ADDFD must not leak across exec)
//   - a bound on in-flight notifications (flood DoS containment)
//
// Reference-quality against the public kernel API; integrate and test before
// tagging.
#ifndef WARDEN_LIFECYCLE_H
#define WARDEN_LIFECYCLE_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Call in the TARGET, after fork/clone and before installing the seccomp
// filter / execing the agent. Requests SIGKILL when the supervisor (this
// process's parent) dies. Re-checks getppid() to defeat the
// parent-died-before-prctl race. Returns 0 / -errno.
int wd_target_couple_to_supervisor(pid_t expected_supervisor_pid);

// Call in the SUPERVISOR for a managed target. Returns a pidfd (>=0) that
// becomes readable when the target exits, so the supervisor can release the
// target's authorized-fd set and notification slots. -errno on failure.
int wd_supervisor_watch_target(pid_t target_pid);

// cgroup v2 kill fallback: write "1" to <cgroup>/cgroup.kill to atomically
// SIGKILL the whole subtree if PDEATHSIG coupling is insufficient (e.g. the
// target re-parents). cgroup_dir is the target's cgroup path. 0 / -errno.
int wd_cgroup_kill(const char *cgroup_dir);

// ---- notification hygiene -------------------------------------------------

// Bound on concurrently-handled notifications. A target spamming mediated
// syscalls must not exhaust supervisor memory or stall mediation for siblings.
// Past the bound, the supervisor responds to excess notifications with EPERM
// (fail closed) and trips the bounded-refusal breaker (v1.8.2) for the source.
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
