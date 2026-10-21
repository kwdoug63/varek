// SPDX-License-Identifier: MIT
// v1340_probe.c — v1.34 step 2 (tests/test_v1340.sh): a container's command
// under the node agent, built static. One line per check, "NAME: ok ..." or
// "NAME: <errno name>":
//   read_allowed   /data/allowed, which the policy allows to read
//   read_denied    /data/denied, which it does not name
//   read_rootonly  /data/rootonly, which it allows, root's alone (0600):
//                  opened as the container's user, refused
//   write_allowed  /data/allowed for writing (a read-only rule)
//   proc_self      /proc/self/status (resolved in the container's /proc)
//   connect        127.0.0.1:9 (no connect rule)
//   exec_again     itself (a launch after the first, launches not decided)
// With the argument "wait" it prints "waiting" and waits.
// Step 3, with the argument "launch" (under the launcher, a policy that
// decides launches):
//   launch_ok      /ok, which the policy allows to launch
//   launch_ok2     /ok2, a hardlink of /ok, which it allows too
//   launch_no      /no, which it does not
//   launch_written a copy of /ok written to /work (writable, noexec) and launched
//   arch32         (x86_64) an i386 call from a second thread of a child:
//                  "process killed" (the launcher's filter) or "thread only"
// and with "arch", arch32 alone.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *en(int e) {
    switch (e) {
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case EROFS: return "EROFS";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ENETUNREACH: return "ENETUNREACH";
    default: return strerror(e);
    }
}

static void readf(const char *name, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("%s: %s\n", name, en(errno)); return; }
    char b[128] = "";
    ssize_t n = read(fd, b, sizeof b - 1);
    close(fd);
    if (n > 0) b[n] = '\0';
    char *nl = strchr(b, '\n');
    if (nl) *nl = '\0';
    printf("%s: ok %s\n", name, b);
}

static void launch(const char *name, const char *path) {
    pid_t k = fork();
    if (k == 0) {
        char *const av[] = { (char *)path, NULL };
        execv(path, av);
        _exit(errno == EACCES ? 100 : 101);
    }
    int st = 0;
    if (k < 0 || waitpid(k, &st, 0) < 0) { printf("%s: %s\n", name, en(errno)); return; }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) printf("%s: ran\n", name);
    else if (WIFEXITED(st) && WEXITSTATUS(st) == 100) printf("%s: EACCES\n", name);
    else printf("%s: status %d\n", name, st);
}

static int copy(const char *from, const char *to) {
    int a = open(from, O_RDONLY), b = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    char buf[65536];
    ssize_t n;
    int rc = a >= 0 && b >= 0 ? 0 : -1;
    while (rc == 0 && (n = read(a, buf, sizeof buf)) > 0) if (write(b, buf, (size_t)n) != n) rc = -1;
    if (a >= 0) close(a);
    if (b >= 0) close(b);
    return rc;
}

#if defined(__x86_64__)
static void *call32(void *x) {
    (void)x;
    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(20L) : "memory");   /* i386 getpid */
    return NULL;
}
#endif

static void arch32(void) {
#if defined(__x86_64__)
    pid_t k = fork();
    if (k == 0) {
        pthread_t t;
        if (pthread_create(&t, NULL, call32, NULL) != 0) _exit(3);
        sleep(1);
        _exit(0);
    }
    int st = 0;
    if (k < 0 || waitpid(k, &st, 0) < 0) { printf("arch32: %s\n", en(errno)); return; }
    printf("arch32: %s\n", WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS ? "process killed" :
                           WIFEXITED(st) && WEXITSTATUS(st) == 0 ? "thread only" : "other");
#else
    printf("arch32: not x86_64\n");
#endif
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "wait")) { printf("waiting\n"); fflush(stdout); for (;;) sleep(1); }
    if (argc > 1 && !strcmp(argv[1], "launch")) {
        setvbuf(stdout, NULL, _IONBF, 0);
        launch("launch_ok", "/ok");
        launch("launch_ok2", "/ok2");
        launch("launch_no", "/no");
        printf("copy: %s\n", copy("/ok", "/work/copy") == 0 ? "ok" : en(errno));
        launch("launch_written", "/work/copy");
        arch32();
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "arch")) { setvbuf(stdout, NULL, _IONBF, 0); arch32(); return 0; }
    if (argc > 1) { printf("exec_again: ran\n"); return 0; }
    setvbuf(stdout, NULL, _IONBF, 0);
    readf("read_allowed", "/data/allowed");
    readf("read_denied", "/data/denied");
    readf("read_rootonly", "/data/rootonly");
    int w = open("/data/allowed", O_WRONLY);
    printf("write_allowed: %s\n", w >= 0 ? "ok" : en(errno));
    if (w >= 0) close(w);
    readf("proc_self", "/proc/self/status");
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(9) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    printf("connect: %s\n", s >= 0 && connect(s, (struct sockaddr *)&a, sizeof a) == 0 ? "ok" : en(errno));
    char *const av[] = { argv[0], "again", NULL };
    execv("/probe", av);
    printf("exec_again: %s\n", en(errno));
    return 0;
}
