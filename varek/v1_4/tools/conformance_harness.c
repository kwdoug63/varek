// SPDX-License-Identifier: MIT
// conformance_harness.c — validation-only supervisor for target_conformance.
// Mirrors the relevant behavior of warden.c's supervise(): openat -> resolve &
// inject fd for an allowed prefix else EACCES; connect -> deny; bootstrap execve
// -> allow (CONTINUE) so the target can launch. NOT a shipping component; the
// real supervisor is warden.c. Exists so the target can be exercised here.
#define _GNU_SOURCE
#include "warden_baseline_filter.h"
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS 0x02
#endif
#ifndef SECCOMP_ADDFD_FLAG_SEND
#define SECCOMP_ADDFD_FLAG_SEND (1UL << 1)
#endif
struct open_how_l { uint64_t flags, mode, resolve; };

#define ALLOW_PREFIX "/tmp/varek_conf"

static int send_fd(int sock, int fd) {
    char b[CMSG_SPACE(sizeof(int))] = {0}; char d = 'x';
    struct iovec io = { &d, 1 };
    struct msghdr m = { .msg_iov=&io, .msg_iovlen=1, .msg_control=b, .msg_controllen=sizeof b };
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return sendmsg(sock, &m, 0) < 0 ? -1 : 0;
}
static int recv_fd(int sock) {
    char b[CMSG_SPACE(sizeof(int))] = {0}; char d;
    struct iovec io = { &d, 1 };
    struct msghdr m = { .msg_iov=&io, .msg_iovlen=1, .msg_control=b, .msg_controllen=sizeof b };
    if (recvmsg(sock, &m, 0) < 0) return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    if (!c || c->cmsg_type != SCM_RIGHTS) return -1;
    int fd; memcpy(&fd, CMSG_DATA(c), sizeof(int)); return fd;
}
static int read_str(pid_t pid, uint64_t addr, char *out, size_t n) {
    char p[64]; snprintf(p, sizeof p, "/proc/%d/mem", pid);
    int fd = open(p, O_RDONLY); if (fd < 0) return -1;
    if (lseek(fd, (off_t)addr, SEEK_SET) < 0) { close(fd); return -1; }
    ssize_t r = read(fd, out, n - 1); close(fd);
    if (r < 0) return -1; out[r] = 0; return 0;
}
static void respond(int nfd, uint64_t id, int err) {
    struct seccomp_notif_resp r = { .id=id, .val=0, .error=err, .flags=0 };
    if (err == 0) r.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;  // allow (bootstrap exec)
    ioctl(nfd, SECCOMP_IOCTL_NOTIF_SEND, &r);
}
static int inject(int nfd, uint64_t id, pid_t pid, const char *path, int flags, int mode) {
    char pc[64]; snprintf(pc, sizeof pc, "/proc/%d/cwd", pid);
    int cwd = open(pc, O_PATH | O_DIRECTORY); if (cwd < 0) return -1;
    struct open_how_l how = { .flags=(uint64_t)flags & ~(uint64_t)O_PATH,
                              .mode=(flags & O_CREAT) ? (uint64_t)(mode & 0777) : 0,
                              .resolve=RESOLVE_NO_MAGICLINKS };
    int res = (int)syscall(__NR_openat2, cwd, path, &how, sizeof how);
    close(cwd); if (res < 0) return -1;
    struct seccomp_notif_addfd a = { .id=id, .flags=SECCOMP_ADDFD_FLAG_SEND,
                                     .srcfd=(uint32_t)res, .newfd=0, .newfd_flags=O_CLOEXEC };
    int rc = ioctl(nfd, SECCOMP_IOCTL_NOTIF_ADDFD, &a);
    close(res); return rc < 0 ? -1 : 0;
}

static void supervise(int nfd) {
    for (;;) {
        struct seccomp_notif req; memset(&req, 0, sizeof req);
        if (ioctl(nfd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR) continue; return;
        }
        int nr = (int)req.data.nr;
        if (nr == __NR_execve || nr == __NR_execveat) {
            respond(nfd, req.id, 0);            // allow bootstrap launch
        } else if (nr == __NR_openat) {
            char path[4096] = {0};
            if (read_str(req.pid, req.data.args[1], path, sizeof path) == 0 &&
                strncmp(path, ALLOW_PREFIX, strlen(ALLOW_PREFIX)) == 0) {
                if (inject(nfd, req.id, req.pid, path,
                           (int)req.data.args[2], (int)req.data.args[3]) != 0)
                    respond(nfd, req.id, -EACCES);
            } else {
                respond(nfd, req.id, -EACCES);  // denied path
            }
        } else if (nr == __NR_connect) {
            respond(nfd, req.id, -EACCES);      // deny-only network (v1.9.1)
        } else {
            respond(nfd, req.id, -EACCES);
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <target> [args...]\n", argv[0]); return 2; }
    mkdir(ALLOW_PREFIX, 0755);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return 1; }
    pid_t t = fork();
    if (t == 0) {
        close(sv[0]);
        int nfd = install_baseline_user_notif_filter(0);
        if (nfd < 0) { perror("install filter"); _exit(1); }
        if (send_fd(sv[1], nfd) < 0) { perror("send_fd"); _exit(1); }
        close(nfd); close(sv[1]);
        execvp(argv[1], &argv[1]);
        perror("execvp"); _exit(127);
    }
    close(sv[1]);
    int nfd = recv_fd(sv[0]); close(sv[0]);
    if (nfd < 0) { fprintf(stderr, "no notify fd\n"); kill(t, 9); return 1; }
    fprintf(stderr, "[harness] supervising pid=%d notify_fd=%d\n", t, nfd);
    supervise(nfd);
    int st = 0; waitpid(t, &st, 0); close(nfd);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
