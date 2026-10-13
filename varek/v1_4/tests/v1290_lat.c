// SPDX-License-Identifier: MIT
// v1290_lat.c — v1.29 latency (tests/latency_v1290.sh): the time of one kind
// of call, made N times after a warm-up, as the agent sees it.
//
//   v1290_lat unlisted N     getpriority(2), outside the Warden's allowlist:
//                            refused in the kernel when enforcing (EPERM),
//                            sent to the Warden and let through in a dry run
//   v1290_lat open N PATH    open(PATH, O_RDONLY) and close
//
// Prints "KIND p50 p90 ok" (microseconds, and how many calls succeeded).
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static int one(const char *kind, const char *path) {
    if (!strcmp(kind, "unlisted")) return syscall(SYS_getpriority, 0, 0) >= 0 ? 1 : 0;   /* PRIO_PROCESS, self */
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3 || (strcmp(argv[1], "unlisted") && (strcmp(argv[1], "open") || argc < 4))) {
        fprintf(stderr, "usage: v1290_lat unlisted N | open N PATH\n");
        return 2;
    }
    int n = atoi(argv[2]);
    const char *path = argc > 3 ? argv[3] : NULL;
    if (n < 10) n = 10;
    double *t = calloc((size_t)n, sizeof *t);
    if (!t) return 1;
    for (int i = 0; i < 100; i++) one(argv[1], path);
    int ok = 0;
    for (int i = 0; i < n; i++) {
        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        ok += one(argv[1], path);
        clock_gettime(CLOCK_MONOTONIC, &b);
        t[i] = (double)(b.tv_sec - a.tv_sec) * 1e6 + (double)(b.tv_nsec - a.tv_nsec) / 1e3;
    }
    qsort(t, (size_t)n, sizeof *t, cmp);
    printf("%s %.1f %.1f %d\n", argv[1], t[n / 2], t[(n * 9) / 10], ok);
    return 0;
}
