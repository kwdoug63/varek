// SPDX-License-Identifier: MIT
/*
 * bench_target.c — synthetic adversarial workload for Warden v1.4
 *                  microbenchmarking.
 *
 * Drives a configurable number of trapped syscalls under the live
 * Warden supervisor. The Warden emits one JSON pathology record per
 * decision with a real CLOCK_MONOTONIC latency measurement; this
 * binary pairs with bench_summarize.py (separate file) which reads
 * those records from the Warden's stderr and computes percentiles.
 *
 * No randomness, no scripted constants, no hardcoded summary. Every
 * number that ends up in the deck must come from a real run of this
 * binary against a real Warden.
 *
 * Invocation:
 *   sudo ./warden policy.txt -- ./bench_target [iterations] 2> bench.log
 *   python3 bench_summarize.py bench.log
 *
 * Suggested iterations for a stable P99: 10000.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *PATHS[] = {
    "/tmp/varek_allowed_bench_a",
    "/tmp/varek_allowed_bench_b",
    "/tmp/varek_allowed_bench_c",
    "/etc/shadow",                   /* should DENY */
    "/tmp/no_match_in_policy",       /* should UNKNOWN -> DENY */
};
static const size_t N_PATHS = sizeof(PATHS) / sizeof(PATHS[0]);

static void seed_files(void) {
    for (size_t i = 0; i < 3; i++) {
        int fd = open(PATHS[i], O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) { (void)!write(fd, "x", 1); close(fd); }
    }
}

static void hammer_openat(int n) {
    for (int i = 0; i < n; i++) {
        const char *p = PATHS[i % N_PATHS];
        int fd = openat(AT_FDCWD, p, O_RDONLY);
        if (fd >= 0) close(fd);
    }
}

static void hammer_connect(int n) {
    for (int i = 0; i < n; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(8080);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        (void)connect(s, (struct sockaddr *)&sa, sizeof(sa));
        close(s);
    }
}

int main(int argc, char **argv) {
    int iter = (argc >= 2) ? atoi(argv[1]) : 10000;
    if (iter <= 0) iter = 10000;

    seed_files();

    printf("[bench] iterations=%d  (pid=%d)\n", iter, getpid());
    fflush(stdout);

    int half = iter / 2;
    hammer_openat(half);
    hammer_connect(iter - half);

    printf("[bench] done — see Warden stderr for pathology records\n");
    return 0;
}
