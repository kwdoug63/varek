// SPDX-License-Identifier: MIT
// test_v191_io_uring.c — assert the baseline denies io_uring instance creation.
//
// Must run in a context where the Warden's baseline seccomp filter is already
// installed (e.g. invoke from the child after seccomp_load, or wrap with the
// same filter the Warden installs). With the filter active, io_uring_setup must
// return EPERM. Without a filter the kernel returns EFAULT/EINVAL for these
// probe args (still < 0), which the test reports as INCONCLUSIVE rather than a
// pass — a pass requires the explicit EPERM denial.

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

int main(void)
{
    errno = 0;
    long r = syscall(__NR_io_uring_setup, 1 /*entries*/, (void *)0 /*params*/);

    if (r >= 0) {
        fprintf(stderr, "FAIL: io_uring_setup succeeded (fd=%ld) — bypass is OPEN\n", r);
        return 1;
    }
    if (errno == EPERM) {
        printf("PASS: io_uring_setup denied with EPERM\n");
        return 0;
    }
    fprintf(stderr,
        "INCONCLUSIVE: io_uring_setup failed with errno=%d (expected EPERM). "
        "Is the Warden filter installed in this process?\n", errno);
    return 2;
}
