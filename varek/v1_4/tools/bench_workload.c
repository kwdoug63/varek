// SPDX-License-Identifier: MIT
/*
 * bench_workload.c — the fixed workload behind `varek bench` (v1.22).
 *
 * Two modes, both started by `varek bench`:
 *
 *   bench_workload serve
 *       Three TCP listeners on 127.0.0.1 (ephemeral ports), run natively,
 *       outside the agent's network namespace. Prints "PORTS <a> <d> <r>":
 *         a  accepts and closes        (the allowed connect)
 *         d  accepts and closes        (the denied connect: under the Warden
 *                                       it must never see a connection)
 *         r  answers one small HTTP/1.0 request with a 1 KiB body
 *       Each line "count" on stdin is answered "ACCEPTS <a> <d> <r>" (running
 *       totals), so the caller can prove the denied listener was never reached
 *       during the runs under the Warden. EOF on stdin ends it.
 *
 *   bench_workload run <dir> <a> <d> <r> <n> <warmup>
 *       Run natively, or as the agent under the Warden. Makes warmup + n
 *       calls of each kind below, round-robin (one of each per iteration, so
 *       drift on the host spreads over every kind), and times each call with
 *       CLOCK_MONOTONIC around the system call only:
 *         open_allowed    openat(<dir>/allowed/f, O_RDONLY)
 *         open_denied     openat(<dir>/denied/f, O_RDONLY)   a deny rule
 *         open_unknown    openat(<dir>/unknown/f, O_RDONLY)  no rule: UNKNOWN
 *         connect_allowed connect(127.0.0.1:<a>)             dialed by the Warden
 *         connect_denied  connect(127.0.0.1:<d>)             a deny rule
 *         request         connect(127.0.0.1:<r>), send a request, read the
 *                         reply to EOF: a whole small request, for scale
 *       All three files exist and are readable, and all three listeners
 *       accept, so natively every call succeeds: the native run is the same
 *       work with no decision in front of it. Prints, after the calls:
 *         BENCHW 1 n=<n> warmup=<w>
 *         CLASS <kind> ok=<k> fail=<f> errnos=<errno>:<count>,...   (all warmup + n calls)
 *         SAMPLES <kind> <us> <us> ...       (the n timed calls, warm-up dropped)
 *         END
 *
 *   bench_workload launch <dir> <n> <warmup>          (v1.27, varek bench --launches)
 *       Makes warmup + n of each, round-robin, timed around the whole call:
 *         launch_allowed  vfork, execve(<dir>/bin/ok, "noop"), wait: a launch the
 *                         policy allows (the program exits at once)
 *         launch_denied   the same with <dir>/bin/denied, which a deny rule
 *                         refuses (natively it runs like the other)
 *         open_allowed    openat(<dir>/allowed/f, O_RDONLY), to measure what
 *                         deciding launches adds to an ordinary call
 *       A launch whose execve fails exits 100 + errno, which is the call's
 *       errno here. Prints as `run` does.
 *
 *   bench_workload noop
 *       Exits 0 at once: the program the launches above run.
 *
 * Built static where the host has a static libc, so a run under the Warden
 * has no loader opens: the calls above are the only mediated ones. Sockets are
 * closed with SO_LINGER 0, so thousands of connections leave no TIME_WAIT
 * entries behind to exhaust the ephemeral ports.
 *
 * No randomness and no constants in the output: every number printed is a
 * measured call.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BODY_LEN 1024
static const char REQ_LINE[] = "GET /varek-bench HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";

enum { OPEN_ALLOWED, OPEN_DENIED, OPEN_UNKNOWN, CONNECT_ALLOWED, CONNECT_DENIED, REQUEST, NKIND };
static const char *KIND[NKIND] = {
    "open_allowed", "open_denied", "open_unknown", "connect_allowed", "connect_denied", "request",
};

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e6 + (double)t.tv_nsec / 1e3;
}

static void close_rst(int s) {
    struct linger l = { 1, 0 };
    (void)setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof l);
    close(s);
}

/* ------------------------------------------------------------------ serve */

static int listen_on_loopback(int *port) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    int one = 1;
    (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t l = sizeof a;
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 4096) < 0 ||
        getsockname(s, (struct sockaddr *)&a, &l) < 0) {
        close(s);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return s;
}

static int reply_head(char *head, size_t cap) {
    return snprintf(head, cap, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
                    BODY_LEN);
}

static size_t reply_len(void) {
    char head[128];
    return (size_t)reply_head(head, sizeof head) + BODY_LEN;
}

static void answer_request(int c) {
    struct timeval tv = { 1, 0 };
    (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char buf[1024];
    size_t got = 0;
    while (got < sizeof buf - 1) {
        ssize_t r = recv(c, buf + got, sizeof buf - 1 - got, 0);
        if (r <= 0) break;
        got += (size_t)r;
        buf[got] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    char body[BODY_LEN];
    memset(body, 'v', sizeof body);
    char head[128];
    int hl = reply_head(head, sizeof head);
    (void)!send(c, head, (size_t)hl, MSG_NOSIGNAL);
    (void)!send(c, body, sizeof body, MSG_NOSIGNAL);
}

/* Accept everything waiting on listener i (it is non-blocking). */
static void drain(int ls, int i, unsigned long *accepts) {
    for (;;) {
        int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) {
            if (errno == EINTR) continue;
            return; /* EAGAIN: nothing left waiting */
        }
        accepts[i]++;
        if (i == 2) answer_request(c);
        close(c); /* FIN; the client's SO_LINGER 0 close ends it without TIME_WAIT */
    }
}

static int serve(void) {
    int port[3], ls[3];
    for (int i = 0; i < 3; i++) {
        ls[i] = listen_on_loopback(&port[i]);
        if (ls[i] < 0) { perror("bench_workload: listen"); return 1; }
        int fl = fcntl(ls[i], F_GETFL);
        if (fl < 0 || fcntl(ls[i], F_SETFL, fl | O_NONBLOCK) < 0) {
            perror("bench_workload: fcntl");
            return 1;
        }
    }
    unsigned long accepts[3] = { 0, 0, 0 };
    printf("PORTS %d %d %d\n", port[0], port[1], port[2]);
    fflush(stdout);
    char line[64];
    size_t ll = 0;
    for (;;) {
        struct pollfd pf[4] = {
            { ls[0], POLLIN, 0 }, { ls[1], POLLIN, 0 }, { ls[2], POLLIN, 0 }, { 0, POLLIN, 0 },
        };
        if (poll(pf, 4, -1) < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        for (int i = 0; i < 3; i++)
            if (pf[i].revents & POLLIN) drain(ls[i], i, accepts);
        if (!(pf[3].revents & (POLLIN | POLLHUP))) continue;
        char buf[256];
        ssize_t r = read(0, buf, sizeof buf);
        if (r <= 0) return 0;
        for (ssize_t j = 0; j < r; j++) {
            if (buf[j] != '\n') {
                if (ll < sizeof line - 1) line[ll++] = buf[j];
                continue;
            }
            line[ll] = 0;
            ll = 0;
            if (strcmp(line, "count")) continue;
            /* Count only after taking every connection already queued, so a
             * connection made before the question is never counted after it. */
            for (int i = 0; i < 3; i++) drain(ls[i], i, accepts);
            printf("ACCEPTS %lu %lu %lu\n", accepts[0], accepts[1], accepts[2]);
            fflush(stdout);
        }
    }
}

/* -------------------------------------------------------------------- run */

struct outcome {
    unsigned long ok, fail;
    int err[8];
    unsigned long errn[8];
};

static void note(struct outcome *o, int ok, int e) {
    if (ok) { o->ok++; return; }
    o->fail++;
    for (int i = 0; i < 8; i++) {
        if (o->errn[i] && o->err[i] == e) { o->errn[i]++; return; }
        if (!o->errn[i]) { o->err[i] = e; o->errn[i] = 1; return; }
    }
}

static double timed_open(const char *path, int *ok, int *e) {
    errno = 0;
    double a = now_us();
    int fd = openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    double b = now_us();
    *e = errno;
    *ok = fd >= 0;
    if (fd >= 0) close(fd);
    return b - a;
}

static void loopback(struct sockaddr_in *sa, int port) {
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port = htons((unsigned short)port);
    sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static double timed_connect(int port, int *ok, int *e) {
    struct sockaddr_in sa;
    loopback(&sa, port);
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) { *ok = 0; *e = errno; return 0; }
    errno = 0;
    double a = now_us();
    int r = connect(s, (struct sockaddr *)&sa, sizeof sa);
    double b = now_us();
    *e = errno;
    *ok = r == 0;
    close_rst(s);
    return b - a;
}

static double timed_request(int port, int *ok, int *e) {
    struct sockaddr_in sa;
    loopback(&sa, port);
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) { *ok = 0; *e = errno; return 0; }
    struct timeval tv = { 2, 0 };
    (void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    size_t got = 0;
    *ok = 0;
    *e = 0;
    errno = 0;
    double a = now_us();
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) == 0 &&
        send(s, REQ_LINE, sizeof REQ_LINE - 1, MSG_NOSIGNAL) == (ssize_t)(sizeof REQ_LINE - 1)) {
        char buf[4096];
        ssize_t r;
        while ((r = recv(s, buf, sizeof buf, 0)) > 0) got += (size_t)r;
        if (r == 0) *ok = 1;
    }
    double b = now_us();
    if (!*ok) *e = errno ? errno : EPROTO;
    else if (got < reply_len()) { *ok = 0; *e = EPROTO; } /* a short reply is a failure */
    close_rst(s);
    return b - a;
}

static int run(int argc, char **argv) {
    if (argc != 8) {
        fprintf(stderr, "usage: %s run <dir> <port-allowed> <port-denied> <port-request> <n> <warmup>\n",
                argv[0]);
        return 2;
    }
    const char *dir = argv[2];
    int pa = atoi(argv[3]), pd = atoi(argv[4]), pr = atoi(argv[5]);
    int n = atoi(argv[6]), w = atoi(argv[7]);
    if (n <= 0 || w < 0 || n > 10000000 || w > 10000000 || pa <= 0 || pd <= 0 || pr <= 0) {
        fprintf(stderr, "bench_workload: bad arguments\n");
        return 2;
    }
    char path[3][4096];
    static const char *sub[3] = { "allowed", "denied", "unknown" };
    for (int i = 0; i < 3; i++) snprintf(path[i], sizeof path[i], "%s/%s/f", dir, sub[i]);

    double *t[NKIND];
    struct outcome out[NKIND];
    memset(out, 0, sizeof out);
    for (int k = 0; k < NKIND; k++) {
        t[k] = calloc((size_t)n, sizeof(double));
        if (!t[k]) { fprintf(stderr, "bench_workload: out of memory\n"); return 1; }
    }
    for (int i = 0; i < w + n; i++) {
        for (int k = 0; k < NKIND; k++) {
            int ok = 0, e = 0;
            double us;
            switch (k) {
            case OPEN_ALLOWED:    us = timed_open(path[0], &ok, &e); break;
            case OPEN_DENIED:     us = timed_open(path[1], &ok, &e); break;
            case OPEN_UNKNOWN:    us = timed_open(path[2], &ok, &e); break;
            case CONNECT_ALLOWED: us = timed_connect(pa, &ok, &e); break;
            case CONNECT_DENIED:  us = timed_connect(pd, &ok, &e); break;
            default:              us = timed_request(pr, &ok, &e); break;
            }
            note(&out[k], ok, e); /* every call's outcome, warm-up included */
            if (i >= w) t[k][i - w] = us;
        }
    }
    printf("BENCHW 1 n=%d warmup=%d\n", n, w);
    for (int k = 0; k < NKIND; k++) {
        printf("CLASS %s ok=%lu fail=%lu errnos=", KIND[k], out[k].ok, out[k].fail);
        int first = 1;
        for (int j = 0; j < 8 && out[k].errn[j]; j++) {
            printf("%s%d:%lu", first ? "" : ",", out[k].err[j], out[k].errn[j]);
            first = 0;
        }
        printf("\n");
    }
    for (int k = 0; k < NKIND; k++) {
        printf("SAMPLES %s", KIND[k]);
        for (int i = 0; i < n; i++) printf(" %.1f", t[k][i]);
        printf("\n");
    }
    printf("END\n");
    fflush(stdout);
    return 0;
}

/* ----------------------------------------------------------------- launch */

/* vfork, execve(path), wait: the whole launch, timed. ok when the child
 * exited 0; else e is the execve errno (exit 100 + errno), or -1. */
static double timed_launch(const char *path, int *ok, int *e) {
    char *const av[] = { (char *)path, (char *)"noop", NULL };
    char *const ev[] = { NULL };
    double t0 = now_us();
    pid_t pid = vfork();
    if (pid == 0) {
        execve(path, av, ev);
        _exit(100 + (errno & 0x7f));
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) < 0) { *ok = 0; *e = errno; return now_us() - t0; }
    double us = now_us() - t0;
    *ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    *e = *ok ? 0 : WIFEXITED(st) && WEXITSTATUS(st) >= 100 ? WEXITSTATUS(st) - 100 : -1;
    return us;
}

static int launch(int argc, char **argv) {
    if (argc != 5) { fprintf(stderr, "usage: bench_workload launch <dir> <n> <warmup>\n"); return 2; }
    const char *dir = argv[2];
    int n = atoi(argv[3]), w = atoi(argv[4]);
    if (n <= 0 || w < 0 || n > 1000000 || w > 1000000) {
        fprintf(stderr, "bench_workload: bad arguments\n");
        return 2;
    }
    enum { L_OK, L_DENIED, L_OPEN, NL };
    static const char *LK[NL] = { "launch_allowed", "launch_denied", "open_allowed" };
    char ok_p[4096], den_p[4096], open_p[4096];
    snprintf(ok_p, sizeof ok_p, "%s/bin/ok", dir);
    snprintf(den_p, sizeof den_p, "%s/bin/denied", dir);
    snprintf(open_p, sizeof open_p, "%s/allowed/f", dir);
    double *t[NL];
    struct outcome out[NL];
    memset(out, 0, sizeof out);
    for (int k = 0; k < NL; k++) {
        t[k] = calloc((size_t)n, sizeof(double));
        if (!t[k]) { fprintf(stderr, "bench_workload: out of memory\n"); return 1; }
    }
    for (int i = 0; i < w + n; i++) {
        for (int k = 0; k < NL; k++) {
            int ok = 0, e = 0;
            double us = k == L_OK ? timed_launch(ok_p, &ok, &e) : k == L_DENIED ? timed_launch(den_p, &ok, &e)
                                  : timed_open(open_p, &ok, &e);
            note(&out[k], ok, e);
            if (i >= w) t[k][i - w] = us;
        }
    }
    printf("BENCHW 1 n=%d warmup=%d\n", n, w);
    for (int k = 0; k < NL; k++) {
        printf("CLASS %s ok=%lu fail=%lu errnos=", LK[k], out[k].ok, out[k].fail);
        for (int j = 0; j < 8 && out[k].errn[j]; j++) printf("%s%d:%lu", j ? "," : "", out[k].err[j], out[k].errn[j]);
        printf("\n");
    }
    for (int k = 0; k < NL; k++) {
        printf("SAMPLES %s", LK[k]);
        for (int i = 0; i < n; i++) printf(" %.1f", t[k][i]);
        printf("\n");
    }
    printf("END\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc >= 2 && !strcmp(argv[1], "noop")) return 0;                   /* v1.27 */
    if (argc >= 2 && !strcmp(argv[1], "launch")) return launch(argc, argv);  /* v1.27 */
    if (argc >= 2 && !strcmp(argv[1], "serve")) return serve();
    if (argc >= 2 && !strcmp(argv[1], "run")) return run(argc, argv);
    fprintf(stderr, "usage: %s serve | run <dir> <port-allowed> <port-denied> <port-request> <n> <warmup>\n",
            argv[0]);
    return 2;
}
