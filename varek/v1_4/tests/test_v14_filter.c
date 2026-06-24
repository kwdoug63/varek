// SPDX-License-Identifier: MIT
// test_v14_filter.c — validates install_baseline_user_notif_filter()
// cc -O2 -I. -o /tmp/t14 test_v14_filter.c warden_baseline_filter.c -lseccomp
#define _GNU_SOURCE
#include "warden_baseline_filter.h"
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000
#endif

// child installs the enforce-mode filter, then runs one probe; exit code encodes
// the outcome the parent checks.
static int run_probe(const char *what) {
    pid_t pid = fork();
    if (pid == 0) {
        int nfd = install_baseline_user_notif_filter(0);   // enforce
        if (nfd < 0) _exit(90);            // install failed / no listener
        // a listener fd means the NOTIFY (mediate) rules took effect
        errno = 0;
        long r;
        if (!strcmp(what, "getpid"))      { r = syscall(SYS_getpid);        _exit(r>0?0:80); }
        if (!strcmp(what, "socket"))      { r = syscall(SYS_socket,2,1,0);  _exit(r>=0?0:81); }
        if (!strcmp(what, "ptrace"))      { r = syscall(SYS_ptrace,0,0,0,0);_exit(r>=0?60:(errno==EPERM?0:61)); }
        if (!strcmp(what, "bpf"))         { r = syscall(SYS_bpf,0,0,0);     _exit(r>=0?60:(errno==EPERM?0:61)); }
        if (!strcmp(what, "userfaultfd")) { r = syscall(SYS_userfaultfd,0); _exit(r>=0?60:(errno==EPERM?0:61)); }
        if (!strcmp(what, "clone_newuser")){ r = syscall(SYS_clone,CLONE_NEWUSER,0,0,0,0); _exit(r>=0?60:(errno==EPERM?0:61)); }
        if (!strcmp(what, "x32"))         { r = syscall(SYS_getpid|__X32_SYSCALL_BIT); _exit(r>=0?70:0); }
        _exit(99);
    }
    int st; waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) return 1000 + WTERMSIG(st);   // killed
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(void) {
    struct { const char *probe; const char *want; } t[] = {
        { "getpid",        "allow" },
        { "socket",        "allow" },
        { "ptrace",        "deny"  },
        { "bpf",           "deny"  },
        { "userfaultfd",   "deny"  },
        { "clone_newuser", "deny"  },
        { "x32",           "deny"  },
    };
    int fails = 0;
    for (size_t i = 0; i < sizeof t/sizeof t[0]; ++i) {
        int rc = run_probe(t[i].probe);
        int ok;
        if (!strcmp(t[i].want, "allow")) ok = (rc == 0);
        else ok = (rc == 0) || (rc >= 1000);   // EPERM-exit-0 or killed-by-signal
        printf("%-14s -> rc=%-5d %s\n", t[i].probe, rc, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    if (fails) { fprintf(stderr, "%d failure(s)\n", fails); return 1; }
    printf("PASS\n");
    return 0;
}
