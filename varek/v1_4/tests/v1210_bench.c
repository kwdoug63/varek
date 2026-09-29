// SPDX-License-Identifier: MIT
// v1210_bench.c — time each connect() to a TCP (or Unix) server.
//
//   v1210_bench <ip> <port> <n> [--nonblock] [--samples FILE]
//   v1210_bench unix:<path> 0 <n> [--samples FILE]
//
// Opens n connections one after another, times each connect() call with
// CLOCK_MONOTONIC (for --nonblock: until the socket is writable), closes it,
// and prints
//   BENCH <label> n=<n> p50=<us> p90=<us> p99=<us> max=<us> mean=<us>
// Run natively and under the Warden to measure what deciding and dialing each
// connection costs. Built static, so the run under the Warden has no loader
// opens; the connects are the only mediated calls in the loop.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <ip|unix:path> <port> <n> [--nonblock] [--samples FILE]\n", argv[0]);
        return 2;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]), n = atoi(argv[3]), nonblock = 0;
    const char *samples = NULL;
    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "--nonblock")) nonblock = 1;
        else if (!strcmp(argv[i], "--samples") && i + 1 < argc) samples = argv[++i];
    }
    int is_unix = !strncmp(host, "unix:", 5);
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof ss);
    if (is_unix) {
        struct sockaddr_un *u = (struct sockaddr_un *)&ss;
        u->sun_family = AF_UNIX;
        snprintf(u->sun_path, sizeof u->sun_path, "%s", host + 5);
        sl = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(u->sun_path) + 1);
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons((unsigned short)port);
        if (inet_pton(AF_INET, host, &a->sin_addr) != 1) { fprintf(stderr, "bad address\n"); return 2; }
        sl = sizeof *a;
    }
    double *t = calloc((size_t)n, sizeof *t);
    int errors = 0;
    for (int i = 0; i < n; i++) {
        int s = socket(is_unix ? AF_UNIX : AF_INET, SOCK_STREAM | (nonblock ? SOCK_NONBLOCK : 0), 0);
        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        int r = connect(s, (struct sockaddr *)&ss, sl);
        if (r < 0 && errno == EINPROGRESS) {
            struct pollfd pf = { s, POLLOUT, 0 };
            poll(&pf, 1, 5000);
            int so = 0;
            socklen_t l = sizeof so;
            getsockopt(s, SOL_SOCKET, SO_ERROR, &so, &l);
            r = so ? -1 : 0;
        }
        clock_gettime(CLOCK_MONOTONIC, &b);
        if (r < 0) errors++;
        t[i] = (b.tv_sec - a.tv_sec) * 1e6 + (b.tv_nsec - a.tv_nsec) / 1e3;
        close(s);
    }
    if (samples) {
        FILE *f = fopen(samples, "w");
        if (f) { for (int i = 0; i < n; i++) fprintf(f, "%.1f\n", t[i]); fclose(f); }
    }
    double sum = 0;
    for (int i = 0; i < n; i++) sum += t[i];
    qsort(t, (size_t)n, sizeof *t, cmp);
    printf("BENCH %s%s n=%d errors=%d p50=%.0f p90=%.0f p99=%.0f max=%.0f mean=%.0f (us)\n",
           is_unix ? "unix" : "tcp", nonblock ? "-nonblock" : "", n, errors,
           t[n / 2], t[(n * 9) / 10], t[(n * 99) / 100], t[n - 1], sum / n);
    return errors ? 1 : 0;
}
