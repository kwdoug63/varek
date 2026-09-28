// SPDX-License-Identifier: MIT
// test_v14_filter.c — validates install_baseline_user_notif_filter()
// cc -O2 -I. -o /tmp/t14 test_v14_filter.c warden_baseline_filter.c -lseccomp
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
        // v1.12.2: clone3 answers ENOSYS (libc falls back to clone), not KILL.
        if (!strcmp(what, "clone3"))      { unsigned long a[11]={0}; a[4]=SIGCHLD; r = syscall(435,a,sizeof a); if(r==0)_exit(0); _exit(r>0?60:(errno==ENOSYS?0:61)); }
        if (!strcmp(what, "wait4"))       { pid_t c=fork(); if(c==0)_exit(3); int s2; r = wait4(c,&s2,0,NULL); _exit(r==c&&WIFEXITED(s2)&&WEXITSTATUS(s2)==3?0:82); }
        if (!strcmp(what, "ioctl_tcgets")){ r = syscall(SYS_ioctl,0,0x5401UL,(char[64]){0}); _exit(r==0||errno==ENOTTY?0:83); }
        if (!strcmp(what, "ioctl_tiocsti")){ char c='x'; r = syscall(SYS_ioctl,0,0x5412UL,&c); _exit(r>=0?60:(errno==EPERM?0:61)); }
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
        { "clone3",        "enosys" },
        { "wait4",         "allow" },
        { "ioctl_tcgets",  "allow" },
        { "ioctl_tiocsti", "deny"  },
    };
    int fails = 0;
    for (size_t i = 0; i < sizeof t/sizeof t[0]; ++i) {
        int rc = run_probe(t[i].probe);
        int ok;
        if (!strcmp(t[i].want, "allow")) ok = (rc == 0);
        else if (!strcmp(t[i].want, "enosys")) ok = (rc == 0);   // must NOT be killed
        else ok = (rc == 0) || (rc >= 1000);   // EPERM-exit-0 or killed-by-signal
        printf("%-14s -> rc=%-5d %s\n", t[i].probe, rc, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    if (fails) { fprintf(stderr, "%d failure(s)\n", fails); return 1; }
    printf("PASS\n");
    return 0;
}
