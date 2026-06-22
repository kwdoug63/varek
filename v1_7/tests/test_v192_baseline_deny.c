// SPDX-License-Identifier: MIT
// test_v192_baseline_deny.c
//
// Asserts the hard-deny set and the scalar-arg CLONE_NEWUSER filter under the
// v1.9.2 baseline. Each case runs in its own forked child so a strict-mode
// KILL_PROCESS is observable and does not abort the test harness.
//
// Build: cc -o test_v192_baseline_deny test_v192_baseline_deny.c \
//            warden_seccomp_baseline.c -lseccomp

#define _GNU_SOURCE
#include "warden_seccomp_baseline.h"

#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sched.h>
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static void load_baseline_or_die(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(70);
    scmp_filter_ctx ctx;
    if (wd_seccomp_build_baseline(&ctx) != 0) _exit(71);
    if (seccomp_load(ctx) != 0) _exit(72);
    seccomp_release(ctx);
}

// returns 0 if the syscall was denied (EPERM) or the process was killed; 1 if
// it unexpectedly succeeded.
static int expect_denied(long nr, long a0, long a1, long a2) {
    pid_t pid = fork();
    if (pid == 0) {
        load_baseline_or_die();
        errno = 0;
        long r = syscall(nr, a0, a1, a2);
        // success or any errno other than EPERM is a finding worth surfacing,
        // but for the deny property we only require "not serviced".
        if (r >= 0) _exit(50);          // SERVICED -> deny failed
        _exit(errno == EPERM ? 0 : 51); // denied
    }
    int st;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) return 0;                  // killed -> denied (strict)
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) return 0;
    return 1;
}

int main(void) {
    struct { const char *name; long nr; long a0, a1, a2; } cases[] = {
        { "ptrace",        SYS_ptrace,        0, 0, 0 },
        { "bpf",           SYS_bpf,           0, 0, 0 },
        { "userfaultfd",   SYS_userfaultfd,   0, 0, 0 },
#ifdef SYS_process_vm_readv
        { "process_vm_readv", SYS_process_vm_readv, 0, 0, 0 },
#endif
#ifdef SYS_pidfd_getfd
        { "pidfd_getfd",   SYS_pidfd_getfd,   0, 0, 0 },
#endif
#ifdef SYS_perf_event_open
        { "perf_event_open", SYS_perf_event_open, 0, 0, 0 },
#endif
        // CLONE_NEWUSER via the clone scalar-flag filter (no actual new task is
        // created because the call is refused before the kernel acts).
        { "clone(CLONE_NEWUSER)", SYS_clone, CLONE_NEWUSER, 0, 0 },
        { "unshare(CLONE_NEWUSER)", SYS_unshare, CLONE_NEWUSER, 0, 0 },
    };

    int fails = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        int bad = expect_denied(cases[i].nr, cases[i].a0, cases[i].a1, cases[i].a2);
        printf("%-24s %s\n", cases[i].name, bad ? "FAIL (serviced)" : "ok (denied)");
        fails += bad;
    }
    if (fails) { fprintf(stderr, "%d case(s) not denied\n", fails); return 1; }
    printf("PASS\n");
    return 0;
}
