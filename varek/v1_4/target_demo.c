// SPDX-License-Identifier: MIT
/*
 * target_demo.c — toy supervised workload for Warden v1.4.
 *
 * Performs a small, mixed sequence of trapped syscalls:
 *
 *   - openat("/tmp/varek_allowed_demo", O_RDONLY)   -> should ALLOW (resolved fd)
 *   - openat("/etc/shadow", O_RDONLY)               -> should DENY
 *   - openat("/tmp/not_in_policy", O_RDONLY)        -> UNKNOWN -> DENY
 *   - connect to 127.0.0.1:8080                     -> should ALLOW
 *   - connect to 8.8.8.8:53                         -> UNKNOWN -> DENY
 *
 * The point isn't realistic agent behavior; it's that every line of
 * output below is produced by the kernel honoring (or denying) the
 * supervisor's verdict on a real syscall.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static void try_open(const char *path) {
    int fd = openat(AT_FDCWD, path, O_RDONLY);
    if (fd >= 0) {
        printf("[target] open  %-30s OK   fd=%d\n", path, fd);
        close(fd);
    } else {
        printf("[target] open  %-30s FAIL %s\n", path, strerror(errno));
    }
}

static void try_connect(const char *ip, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);

    int rc = connect(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rc == 0 || (rc < 0 && errno == ECONNREFUSED)) {
        /* ECONNREFUSED is fine — the supervisor allowed the syscall;
         * nothing was listening. Both prove the verdict was ALLOW. */
        printf("[target] conn  %s:%-7d              %s\n",
               ip, port, rc == 0 ? "OK" : "ALLOWED (refused)");
    } else {
        printf("[target] conn  %s:%-7d              FAIL %s\n",
               ip, port, strerror(errno));
    }
    close(s);
}

int main(void) {
    /* Make sure the allowlist target exists. */
    int seed = open("/tmp/varek_allowed_demo",
                    O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (seed >= 0) { (void)!write(seed, "hello\n", 6); close(seed); }

    printf("[target] starting workload (pid=%d)\n", getpid());
    try_open("/tmp/varek_allowed_demo");
    try_open("/etc/shadow");
    try_open("/tmp/not_in_policy");
    try_connect("127.0.0.1", 8080);
    try_connect("8.8.8.8",   53);
    printf("[target] done\n");
    return 0;
}
