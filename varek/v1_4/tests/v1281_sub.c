// SPDX-License-Identifier: MIT
// v1281_sub.c — a program for test_v1281.sh section 3 (sub-agents): run as
// the agent, or launched as a sub-agent, it does one thing and opens the
// file it is given so each process leaves a record.
//
//   v1281_sub open FILE               open FILE
//   v1281_sub fork FILE               open FILE, fork: the child opens it
//   v1281_sub doublefork FILE         fork; the child forks and exits; the
//                                     grandchild (reparented) opens FILE
//   v1281_sub thread FILE             a thread opens FILE
//   v1281_sub exec PROG ARGS...       open nothing; launch PROG ARGS
//   v1281_sub spawn FILE PROG ARGS... fork: the child launches PROG ARGS; the
//                                     parent waits, then opens FILE
//   v1281_sub threaded PROG ARGS...   start a thread, then launch PROG ARGS
//                                     (refused: a threaded launcher)
//   v1281_sub e2big FILE PROG         launch PROG with arguments over the
//                                     kernel's limit (allowed, then failed by
//                                     the kernel: E2BIG); fork: the child
//                                     opens FILE; the parent opens it too
//   v1281_sub write FILE              open FILE for writing; print the result
//   v1281_sub loop FILE SECONDS       open FILE every 250 ms for SECONDS; print
//                                     how many opens worked and how many not
//   v1281_sub repeat N PROG ARGS...   v1.36 step 12: N times, one after the
//                                     other, fork: the child launches PROG
//                                     ARGS; print how many ran and how many
//                                     launches were refused
//   v1281_sub hold N PROG ARGS...     v1.36 step 12: fork N children at once,
//                                     each launching PROG ARGS; wait for all;
//                                     print how many launches were refused
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void touch(const char *f) {
    int fd = open(f, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) close(fd);
}

static void *thr(void *f) { touch(f); return NULL; }
static void *idle(void *u) { (void)u; for (;;) usleep(100000); return NULL; }

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: see the source\n"); return 2; }
    const char *m = argv[1], *f = argv[2];
    if (!strcmp(m, "open")) { touch(f); return 0; }
    if (!strcmp(m, "fork")) {
        touch(f);
        pid_t c = fork();
        if (c == 0) { touch(f); _exit(0); }
        waitpid(c, NULL, 0);
        return 0;
    }
    if (!strcmp(m, "doublefork")) {
        pid_t c = fork();
        if (c == 0) {
            if (fork() == 0) { usleep(200000); touch(f); _exit(0); }
            _exit(0);
        }
        waitpid(c, NULL, 0);
        usleep(500000);
        return 0;
    }
    if (!strcmp(m, "thread")) {
        pthread_t t;
        if (pthread_create(&t, NULL, thr, (void *)f)) return 1;
        pthread_join(t, NULL);
        return 0;
    }
    if (!strcmp(m, "exec")) { execv(argv[2], argv + 2); perror("execv"); return 127; }
    if (!strcmp(m, "spawn") && argc >= 4) {
        pid_t c = fork();
        if (c == 0) { execv(argv[3], argv + 3); _exit(127); }
        int st = 0;
        waitpid(c, &st, 0);
        touch(f);
        return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
    }
    if (!strcmp(m, "threaded")) {
        pthread_t t;
        if (pthread_create(&t, NULL, idle, NULL)) return 1;
        execv(argv[2], argv + 2);
        printf("launch refused: %s\n", strerror(errno));
        fflush(stdout);
        _exit(0);
    }
    if (!strcmp(m, "e2big") && argc >= 4) {
        /* each argument at most 128 KiB (MAX_ARG_STRLEN); 64 of them pass every limit */
        size_t n = 128 * 1024 - 1;
        char *big = malloc(n + 1);
        if (!big) return 1;
        memset(big, 'x', n);
        big[n] = '\0';
        char *av[66];
        av[0] = argv[3];
        for (int i = 1; i < 65; i++) av[i] = big;
        av[65] = NULL;
        execv(argv[3], av);
        printf("launch failed: %s\n", strerror(errno));
        fflush(stdout);
        pid_t c = fork();
        if (c == 0) { touch(f); _exit(0); }
        waitpid(c, NULL, 0);
        touch(f);
        return 0;
    }
    if (!strcmp(m, "loop") && argc >= 4) {
        int ok = 0, no = 0, n = atoi(argv[3]) * 4;
        for (int i = 0; i < n; i++) {
            int fd = open(f, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) { ok++; close(fd); } else no++;
            usleep(250000);
        }
        printf("opened %d refused %d\n", ok, no);
        return 0;
    }
    if ((!strcmp(m, "repeat") || !strcmp(m, "hold")) && argc >= 4) {
        int n = atoi(argv[2]), ran = 0, refused = 0;
        bool hold = !strcmp(m, "hold");
        for (int i = 0; i < n; i++) {
            pid_t c = fork();
            if (c < 0) return 1;
            if (c == 0) { execv(argv[3], argv + 3); _exit(errno == EACCES ? 126 : 127); }
            if (!hold) {
                int st = 0;
                waitpid(c, &st, 0);
                if (WIFEXITED(st) && WEXITSTATUS(st) == 126) refused++; else ran++;
            }
        }
        if (hold) {
            int st = 0;
            while (wait(&st) > 0) { if (WIFEXITED(st) && WEXITSTATUS(st) == 126) refused++; else ran++; }
        }
        printf("ran %d refused %d\n", ran, refused);
        fflush(stdout);
        return 0;
    }
    if (!strcmp(m, "write")) {
        int fd = open(f, O_WRONLY | O_CLOEXEC);
        printf("write open: %s\n", fd >= 0 ? "ok" : strerror(errno));
        if (fd >= 0) close(fd);
        return 0;
    }
    return 2;
}
