// SPDX-License-Identifier: MIT
// v1340_probe.c — v1.34 step 2 (tests/test_v1340.sh): a container's command
// under the node agent, built static. One line per check, "NAME: ok ..." or
// "NAME: <errno name>":
//   read_allowed   /data/allowed, which the policy allows to read
//   read_denied    /data/denied, which it does not name
//   write_allowed  /data/allowed for writing (a read-only rule)
//   proc_self      /proc/self/status (resolved in the container's /proc)
//   connect        127.0.0.1:9 (no connect rule)
//   exec_again     itself (a launch after the first, launches not decided)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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

int main(int argc, char **argv) {
    if (argc > 1) { printf("exec_again: ran\n"); return 0; }
    setvbuf(stdout, NULL, _IONBF, 0);
    readf("read_allowed", "/data/allowed");
    readf("read_denied", "/data/denied");
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
