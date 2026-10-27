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
// Step 4, with "net ALLOWED WILD [hold]" (the pod's network):
//   hosts          ALLOWED's address in /etc/hosts (the Warden's view)
//   get_allowed    an HTTP GET to ALLOWED:80 by that address
//   numeric        a connect to 10.77.0.2:80 (no rule, and no allowed name has it)
//   stub           the nameserver /etc/resolv.conf names (the stub's view)
//   get_wild       WILD asked of that nameserver (A), then an HTTP GET to it
// and with "hold", waiting 4 s after.
// v1.36 step 4, with "env NAME": its value in the environment (env: VALUE,
// or env: none), the placeholder the NRI plugin set.
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
#include <time.h>
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

/* the first address /etc/hosts gives name, or "" */
static void hosts_lookup(const char *name, char *out, size_t on) {
    out[0] = '\0';
    FILE *f = fopen("/etc/hosts", "r");
    if (!f) return;
    char line[512], a[64], n[256];
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "%63s %255s", a, n) == 2 && !strcmp(n, name) && strchr(a, '.')) { snprintf(out, on, "%s", a); break; }
    fclose(f);
}

/* an HTTP GET to addr:80 for host: its status line, or an errno's name */
static void http_get(const char *what, const char *addr, const char *host) {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(80) };
    if (inet_pton(AF_INET, addr, &a.sin_addr) != 1) { printf("%s: no address\n", what); return; }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
        printf("%s: %s\n", what, en(errno));
        if (s >= 0) close(s);
        return;
    }
    char req[512], b[512] = "";
    int n = snprintf(req, sizeof req, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host);
    ssize_t r = write(s, req, (size_t)n) == n ? read(s, b, sizeof b - 1) : -1;
    close(s);
    if (r <= 0) { printf("%s: no answer\n", what); return; }
    b[r] = '\0';
    char *nl = strpbrk(b, "\r\n");
    if (nl) *nl = '\0';
    printf("%s: %s\n", what, b);
}

/* name's first A record, asked of server:53 over UDP */
static int dns_a(const char *server, const char *name, char *out, size_t on) {
    unsigned char q[512] = { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 }, r[512];
    size_t k = 12;
    for (const char *p = name; *p; ) {
        const char *d = strchr(p, '.');
        size_t l = d ? (size_t)(d - p) : strlen(p);
        q[k++] = (unsigned char)l;
        memcpy(q + k, p, l);
        k += l;
        p += l + (d ? 1 : 0);
    }
    q[k++] = 0; q[k++] = 0; q[k++] = 1; q[k++] = 0; q[k++] = 1;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(53) };
    if (inet_pton(AF_INET, server, &a.sin_addr) != 1) return -1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval tv = { 5, 0 };
    if (s < 0) return -1;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ssize_t n = sendto(s, q, k, 0, (struct sockaddr *)&a, sizeof a) == (ssize_t)k ? recv(s, r, sizeof r, 0) : -1;
    close(s);
    if (n < 12 || (r[3] & 0x0f) || !(r[6] | r[7])) return -1;
    size_t o = 12;
    while (o < (size_t)n && r[o]) o += (size_t)r[o] + 1;      /* the question's name */
    o += 5;
    for (int an = 0; an < (r[6] << 8 | r[7]) && o + 12 <= (size_t)n; an++) {
        if ((r[o] & 0xc0) == 0xc0) o += 2; else { while (o < (size_t)n && r[o]) o += (size_t)r[o] + 1; o++; }
        unsigned type = (unsigned)(r[o] << 8 | r[o + 1]), len = (unsigned)(r[o + 8] << 8 | r[o + 9]);
        o += 10;
        if (type == 1 && len == 4 && o + 4 <= (size_t)n) { snprintf(out, on, "%u.%u.%u.%u", r[o], r[o + 1], r[o + 2], r[o + 3]); return 0; }
        o += len;
    }
    return -1;
}

static void net(const char *allowed, const char *wild) {
    char a[64], ns[64] = "", line[256];
    hosts_lookup(allowed, a, sizeof a);
    printf("hosts: %s %s\n", a[0] ? a : "none", allowed);
    http_get("get_allowed", a, allowed);
    http_get("numeric", "10.77.0.2", allowed);
    FILE *f = fopen("/etc/resolv.conf", "r");
    while (f && fgets(line, sizeof line, f)) if (sscanf(line, "nameserver %63s", ns) == 1) break;
    if (f) fclose(f);
    printf("stub: %s\n", ns[0] ? ns : "none");
    char w[64] = "";
    if (ns[0] && dns_a(ns, wild, w, sizeof w) == 0) http_get("get_wild", w, wild);
    else printf("get_wild: no address\n");
}

int main(int argc, char **argv) {
    if (argc > 3 && !strcmp(argv[1], "net")) {
        setvbuf(stdout, NULL, _IONBF, 0);
        net(argv[2], argv[3]);
        if (argc > 4) { struct timespec t = { 4, 0 }; nanosleep(&t, NULL); }
        return 0;
    }
    if (argc > 2 && !strcmp(argv[1], "env")) { const char *v = getenv(argv[2]); printf("env: %s\n", v ? v : "none"); return 0; }
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
