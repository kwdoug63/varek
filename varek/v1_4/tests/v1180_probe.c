// SPDX-License-Identifier: MIT
// v1180_probe.c — agent for the v1.18.0 regression test (tests/test_v1180.sh).
//
// Built static, so the policy needs no library paths. Each argument is one
// file to open read-only; for each the probe prints one line:
//
//   PROBE open <path> OK <first bytes>
//   PROBE open <path> REFUSED <errno name> (<errno>)
//
// The test asserts on these lines and on the Warden's verdict stream.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *ename(int e) {
    switch (e) {
        case EACCES: return "EACCES";
        case EPERM:  return "EPERM";
        case ENOENT: return "ENOENT";
        default:     return "OTHER";
    }
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            int e = errno;
            printf("PROBE open %s REFUSED %s (%d)\n", argv[i], ename(e), e);
            continue;
        }
        char buf[64] = {0};
        ssize_t n = read(fd, buf, sizeof buf - 1);
        close(fd);
        for (ssize_t k = 0; k < n; k++)
            if (buf[k] == '\n' || buf[k] == '\r') buf[k] = ' ';
        printf("PROBE open %s OK %s\n", argv[i], n > 0 ? buf : "");
    }
    fflush(stdout);
    return 0;
}
