// SPDX-License-Identifier: MIT
//
// v1340_runtime.c — test-v1340's stand-in for a runtime that ends as soon
// as it has sent the node agent a container's listener, as runc create does
// under containerd: its shim, a subreaper, has it reaped, and the container's
// process is then the shim's child. As root:
//
//   v1340_runtime SOCKET ID zombie|reaped
//
// Run as the shim: holds the node agent with a connection that sends
// nothing (it reads one connection at a time, for at most 5 s); forks the
// runtime, which forks the container's process (no-new-privileges, a filter
// with a listener, then waiting), sends the node agent its state (pid, id
// ID, bundle /nonexistent) with the listener, and ends; waits for the
// runtime's end, leaving it a zombie (zombie) or reaping it (reaped); then
// lets the node agent go on, so it reads the runtime's connection with the
// runtime ended. Prints the container process's pid, waits 3 s for the
// node agent and ends it. 0, or 1 (said why) if it could not.
#define _GNU_SOURCE
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int dial(const char *path) {
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0 || strlen(path) >= sizeof a.sun_path) return -1;
    memcpy(a.sun_path, path, strlen(path) + 1);
    return connect(s, (struct sockaddr *)&a, sizeof a) == 0 ? s : -1;
}

static int send_fd(int s, const void *b, size_t n, int fd) {
    char cb[CMSG_SPACE(sizeof(int))];
    struct iovec iov = { (void *)b, n };
    struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cb, .msg_controllen = sizeof cb };
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &fd, sizeof fd);
    return sendmsg(s, &m, 0) == (ssize_t)n ? 0 : -1;
}

static int recv_fd(int s) {
    char b, cb[CMSG_SPACE(sizeof(int))];
    struct iovec iov = { &b, 1 };
    struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cb, .msg_controllen = sizeof cb };
    if (recvmsg(s, &m, 0) != 1) return -1;
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    int fd;
    if (!h || h->cmsg_type != SCM_RIGHTS) return -1;
    memcpy(&fd, CMSG_DATA(h), sizeof fd);
    return fd;
}

// the container's process: a filter whose listener is told of getppid, the
// listener to the runtime, then waiting to be ended
static void container(int sp) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = { sizeof f / sizeof f[0], f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) _exit(1);
    int l = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &p);
    if (l < 0 || send_fd(sp, "l", 1, l) < 0) _exit(1);
    close(l);
    for (;;) pause();
}

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[3], "zombie") && strcmp(argv[3], "reaped"))) {
        fprintf(stderr, "usage: v1340_runtime SOCKET ID zombie|reaped\n");
        return 2;
    }
    bool zombie = strcmp(argv[3], "zombie") == 0;
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0) { perror("v1340_runtime: subreaper"); return 1; }
    int hold = dial(argv[1]);
    if (hold < 0) { perror("v1340_runtime: the node agent's socket"); return 1; }
    int pp[2];
    if (pipe(pp) < 0) return 1;
    pid_t rt = fork();
    if (rt < 0) return 1;
    if (rt == 0) {   // the runtime
        close(pp[0]);
        close(hold);   // the shim's alone: the node agent goes on when the shim closes it
        int sp[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) _exit(1);
        pid_t c = fork();
        if (c < 0) _exit(1);
        if (c == 0) { close(sp[0]); container(sp[1]); }
        close(sp[1]);
        int l = recv_fd(sp[0]);
        int s = dial(argv[1]);
        char st[512];
        int n = snprintf(st, sizeof st,
                         "{\"ociVersion\":\"1.2.1\",\"fds\":[\"seccompFd\"],\"pid\":%d,\"metadata\":\"\",\"state\":"
                         "{\"ociVersion\":\"1.2.1\",\"id\":\"%s\",\"status\":\"creating\",\"pid\":%d,"
                         "\"bundle\":\"/nonexistent\"}}", (int)c, argv[2], (int)c);
        if (l < 0 || s < 0 || n <= 0 || (size_t)n >= sizeof st || send_fd(s, st, (size_t)n, l) < 0) _exit(1);
        (void)!write(pp[1], &c, sizeof c);
        _exit(0);   // the connection closed with it, as runc create ends
    }
    close(pp[1]);
    pid_t c = 0;
    siginfo_t si = { 0 };
    // its end waited for; a zombie left as one (WNOWAIT), else reaped
    if (read(pp[0], &c, sizeof c) != (ssize_t)sizeof c ||
        waitid(P_PID, (id_t)rt, &si, WEXITED | (zombie ? WNOWAIT : 0)) < 0 || si.si_code != CLD_EXITED || si.si_status) {
        fprintf(stderr, "v1340_runtime: the runtime did not send the listener\n");
        return 1;
    }
    printf("%d\n", (int)c);
    fflush(stdout);
    close(hold);    // the node agent goes on, to the runtime's connection
    sleep(3);
    kill(c, SIGKILL);
    while (waitpid(-1, NULL, 0) > 0) {}
    return 0;
}
