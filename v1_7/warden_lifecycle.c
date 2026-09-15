// SPDX-License-Identifier: MIT
// warden_lifecycle.c — v1.9.2
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   // unshare(), CLONE_NEWPID
#endif
#include "warden_lifecycle.h"

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <poll.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

// pidfd_open / SECCOMP_IOCTL_NOTIF_* may be absent from older libc headers;
// fall back to raw numbers so the file builds against a lean toolchain.
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

int wd_supervisor_isolate_pids(void) {
    if (unshare(CLONE_NEWPID) != 0)
        return -errno;
    return 0;
}

int wd_target_couple_to_supervisor(int liveness_fd) {
    // SIGKILL the target the moment the supervisor dies. PDEATHSIG tracks the
    // thread that forked us; the v1.4 Warden is single-threaded, so that is
    // the supervisor's lifetime. The agent cannot clear it afterwards: prctl
    // is not in the baseline allowlist.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0)
        return -errno;
    // Race: the supervisor may have died between fork and this prctl, in which
    // case PDEATHSIG will never fire. The supervisor is the only holder of the
    // pipe's write end, so POLLHUP here means it is already gone. Refuse to
    // continue as an unmonitored target.
    struct pollfd pfd = { .fd = liveness_fd, .events = POLLIN };
    int r;
    do { r = poll(&pfd, 1, 0); } while (r < 0 && errno == EINTR);
    if (r < 0)
        return -errno;
    if (r > 0 && (pfd.revents & (POLLHUP | POLLERR | POLLIN)))
        return -ESRCH;
    return 0;
}

int wd_supervisor_watch_target(pid_t target_pid) {
    long fd = syscall(__NR_pidfd_open, target_pid, 0u);
    if (fd < 0) return -errno;
    return (int)fd;  // becomes readable (POLLIN) on target exit
}

int wd_cgroup_kill(const char *cgroup_dir) {
    if (!cgroup_dir) return -EINVAL;
    char path[4096];
    int n = snprintf(path, sizeof path, "%s/cgroup.kill", cgroup_dir);
    if (n <= 0 || (size_t)n >= sizeof path) return -ENAMETOOLONG;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t w = write(fd, "1", 1);
    int e = (w == 1) ? 0 : -errno;
    close(fd);
    return e;
}

int wd_addfd_cloexec(int notify_fd, uint64_t id, int src_fd) {
    // Revalidate the notification before acting (TOCTOU discipline, v1.9.1):
    // if the target thread died/was signalled, the id is stale and we must not
    // inject into a different syscall context.
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) != 0)
        return -errno;  // typically -ENOENT if the id is no longer valid

    struct seccomp_notif_addfd addfd;
    memset(&addfd, 0, sizeof addfd);
    addfd.id      = id;
    addfd.srcfd   = (uint32_t)src_fd;
    addfd.newfd   = 0;
    addfd.flags   = 0;            // auto-assign newfd in the target
    // O_CLOEXEC on the target's copy: the injected capability must not survive
    // an execve in the target. This is the fix for the ADDFD-leak hygiene gap.
    addfd.newfd_flags = O_CLOEXEC;

    int rc = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    if (rc < 0) return -errno;
    return rc;  // target-side fd number
}
