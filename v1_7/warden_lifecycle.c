// SPDX-License-Identifier: MIT
// warden_lifecycle.c — v1.9.2
#include "warden_lifecycle.h"

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
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

int wd_target_couple_to_supervisor(pid_t expected_supervisor_pid) {
    // SIGKILL the target the moment the supervisor (parent) dies.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0)
        return -errno;
    // Race: the supervisor may have died between fork and this prctl, in which
    // case we have re-parented and PDEATHSIG now refers to the WRONG parent.
    // Detect by confirming our parent is still who we expect; if not, refuse to
    // continue as an unmonitored target.
    if (getppid() != expected_supervisor_pid)
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
