// SPDX-License-Identifier: MIT
// test_v14_filter.c — validates install_baseline_user_notif_filter()
// cc -O2 -I. -o /tmp/t14 test_v14_filter.c warden_baseline_filter.c -lseccomp
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "warden_baseline_filter.h"
#include <pthread.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>

#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000
#endif

// child installs the enforce-mode filter, then runs one probe; exit code encodes
// the outcome the parent checks.
static void *x32_thread(void *arg) {
    (void)arg;
    syscall(SYS_getpid | __X32_SYSCALL_BIT);
    return NULL;
}

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
        // on a pipe: the kernel would say ENOTTY, so EPERM is the filter's
        if (!strcmp(what, "ioctl_tiocsti")){ int p[2]; if(pipe(p))_exit(84); char c='x'; r = syscall(SYS_ioctl,p[0],0x5412UL,&c); _exit(r>=0?60:(errno==EPERM?0:61)); }
        // v1.12.2: a removed-ABI call from a non-main thread kills the whole
        // process (badarch = KILL_PROCESS), not just that thread.
        if (!strcmp(what, "x32_in_thread")){ pthread_t t; if (pthread_create(&t,NULL,x32_thread,NULL)) _exit(85); pthread_join(t,NULL); _exit(62); }
        // v1.18.0: io_uring (bypass class 3, closed in v1.9.1) under the live
        // filter. v1.21: instance creation answers ENOSYS (libuv falls back
        // to epoll); no ring exists, and entering or registering one kills.
        if (!strcmp(what, "io_uring_setup")){ r = syscall(425,1,(char[120]){0}); _exit(r>=0?60:(errno==ENOSYS?0:61)); }
        if (!strcmp(what, "io_uring_enter")){ r = syscall(426,0,0,0,0,0,0); _exit(r>=0?60:63); }
        // v1.21: sendto with no destination is admitted (the kernel answers:
        // no peer, EDESTADDRREQ); routing options are refused with EACCES,
        // also with junk above the 32 bits the kernel reads; other options
        // stay admitted.
        if (!strcmp(what, "sendto_null")) { int u = socket(AF_INET, SOCK_DGRAM, 0); r = sendto(u, "x", 1, 0, NULL, 0); _exit(r < 0 && errno == EDESTADDRREQ ? 0 : 86); }
        if (!strcmp(what, "ip_options"))  { int u = socket(AF_INET, SOCK_DGRAM, 0); unsigned char o[8] = {0x83,7,4,1,2,3,4,0}; r = syscall(SYS_setsockopt, u, 0, 4, o, 8); _exit(r < 0 && errno == EACCES ? 0 : 87); }
        // The filter answers before the kernel looks at the socket, so these
        // use an IPv4 socket (this also runs on hosts without IPv6): a refused
        // pair gets the filter's EACCES; an admitted IPv6-level option reaches
        // the kernel, which says ENOPROTOOPT for an IPv4 socket.
        if (!strcmp(what, "ipv6_rthdr"))  { int u = socket(AF_INET, SOCK_DGRAM, 0); int one = 1; r = syscall(SYS_setsockopt, u, 41, 57, &one, 4); _exit(r < 0 && errno == EACCES ? 0 : 88); }
        if (!strcmp(what, "rthdr_hibits")){ int u = socket(AF_INET, SOCK_DGRAM, 0); int one = 1; r = syscall(SYS_setsockopt, u, 41UL | (1UL << 40), 57UL | (1UL << 33), &one, 4); _exit(r < 0 && errno == EACCES ? 0 : 89); }
        if (!strcmp(what, "ipv6_2292rthdr")){ int u = socket(AF_INET, SOCK_DGRAM, 0); int one = 1; r = syscall(SYS_setsockopt, u, 41, 5, &one, 4); _exit(r < 0 && errno == EACCES ? 0 : 88); }
        if (!strcmp(what, "ipv6_pktoptions")){ int u = socket(AF_INET, SOCK_DGRAM, 0); int one = 1; r = syscall(SYS_setsockopt, u, 41UL | (1UL << 50), 6, &one, 4); _exit(r < 0 && errno == EACCES ? 0 : 88); }
        if (!strcmp(what, "setsockopt_ok")) {
            int t4 = socket(AF_INET, SOCK_STREAM, 0), u4 = socket(AF_INET, SOCK_DGRAM, 0), one = 1, tos = 16;
            if (setsockopt(t4, IPPROTO_TCP, TCP_NODELAY, &one, 4) || setsockopt(t4, SOL_SOCKET, SO_KEEPALIVE, &one, 4) ||
                setsockopt(t4, IPPROTO_IP, IP_TOS, &tos, 4) || setsockopt(u4, IPPROTO_UDP, 1 /* UDP_CORK */, &one, 4))
                _exit(90);
            static const int v6opts[] = { 1, 4, 7, 8, 15, 16, 26, 31, 32, 47, 48, 55, 56, 58, 67 };
            for (size_t k = 0; k < sizeof v6opts / sizeof v6opts[0]; k++)
                if (setsockopt(u4, IPPROTO_IPV6, v6opts[k], &one, 4) == 0 || errno != ENOPROTOOPT) _exit(91);
            if (setsockopt(u4, IPPROTO_IP, 3, &one, 4) == 0 && 0) _exit(92);
            if (setsockopt(u4, IPPROTO_IP, 5, &one, 4) < 0 && errno == EPERM) _exit(93);
            _exit(0);
        }
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
        { "x32_in_thread", "killed" },
        { "io_uring_setup","enosys" },
        { "io_uring_enter","killed" },
        { "sendto_null",   "allow" },
        { "ip_options",    "allow" },
        { "ipv6_rthdr",    "allow" },
        { "rthdr_hibits",  "allow" },
        { "ipv6_2292rthdr","allow" },
        { "ipv6_pktoptions","allow" },
        { "setsockopt_ok", "allow" },
    };
    int fails = 0;
    for (size_t i = 0; i < sizeof t/sizeof t[0]; ++i) {
        int rc = run_probe(t[i].probe);
        int ok;
        if (!strcmp(t[i].want, "allow")) ok = (rc == 0);
        else if (!strcmp(t[i].want, "enosys")) ok = (rc == 0);   // must NOT be killed
        else if (!strcmp(t[i].want, "killed")) ok = (rc >= 1000); // whole process
        else ok = (rc == 0) || (rc >= 1000);   // EPERM-exit-0 or killed-by-signal
        printf("%-14s -> rc=%-5d %s\n", t[i].probe, rc, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    if (fails) { fprintf(stderr, "%d failure(s)\n", fails); return 1; }
    printf("PASS\n");
    return 0;
}
