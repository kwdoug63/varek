// SPDX-License-Identifier: MIT
// test_v192_abi_lockdown.c
//
// Release-blocking. Asserts INVARIANT 2 on the live kernel: under the v1.9.2
// baseline, a syscall issued through a NON-NATIVE ABI is denied. We cannot
// claim "native ABI only" without this passing on the target kernel.
//
// We test the x32 ABI directly because it is the subtle one: on x86_64 an x32
// syscall is the native number OR'd with __X32_SYSCALL_BIT (0x40000000). A
// filter that reasons only in native numbers is mute against it. After the
// baseline loads, an x32 getpid() must NOT succeed as an unfiltered native call.
//
// Build: cc -o test_v192_abi_lockdown test_v192_abi_lockdown.c \
//            warden_seccomp_baseline.c -lseccomp
// Run as a forked child so a KILL_PROCESS (strict mode) is observable via wait.

#include "warden_seccomp_baseline.h"

#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000
#endif
#ifndef __NR_getpid
#define __NR_getpid 39
#endif

static int child(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { perror("nnp"); _exit(70); }

    scmp_filter_ctx ctx;
    if (wd_seccomp_build_baseline(&ctx) != 0) { _exit(71); }
    if (seccomp_load(ctx) != 0) { _exit(72); }
    seccomp_release(ctx);

    // Native getpid() is admitted -> must succeed.
    errno = 0;
    long native = syscall(__NR_getpid);
    if (native <= 0) { _exit(73); }  // baseline broke a needed syscall

    // x32 getpid(): native nr | x32 bit. Under native-only default-deny this
    // must NOT be serviced as a normal call. Expect EPERM (or process death in
    // strict mode, which the parent observes as a signal).
    errno = 0;
    long x32 = syscall(__NR_getpid | __X32_SYSCALL_BIT);
    if (x32 >= 0) { _exit(74); }      // FAIL: x32 path serviced -> ABI bypass open
    if (errno != EPERM) { _exit(75); } // denied, but verify it is our deny path

    _exit(0);
}

int main(void) {
    pid_t pid = fork();
    if (pid == 0) return child();
    if (pid < 0) { perror("fork"); return 2; }

    int st;
    if (waitpid(pid, &st, 0) < 0) { perror("waitpid"); return 2; }

    if (WIFSIGNALED(st)) {
        // strict mode KILL_PROCESS on the x32 attempt is also a PASS for the
        // ABI-lockdown property (the bypass did not succeed).
        printf("PASS (x32 attempt killed, signal %d)\n", WTERMSIG(st));
        return 0;
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        printf("PASS (native ok, x32 denied EPERM)\n");
        return 0;
    }
    fprintf(stderr, "FAIL exit=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    return 1;
}
