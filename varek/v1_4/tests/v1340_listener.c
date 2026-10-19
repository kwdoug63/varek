// SPDX-License-Identifier: MIT
//
// v1340_listener.c — v1.34 step 1 (docs/security/v1.34-kubernetes.md): what a
// node agent receives from the runtime when a pod's seccomp profile names a
// listener (OCI's linux.seccomp.listenerPath), and what it can do with it. It
// stands in for the node agent, on the node, as root:
//
//   v1340_listener SOCKET LOG [MAX]
//
// It accepts each container's connection; logs the container's state (the
// JSON the runtime sends) and the descriptors with it; then, on the seccomp
// descriptor, answers up to MAX notifications (default 200) with "continue",
// after measuring, once each, on the notifying process:
//   - a read of the call's path argument from its memory (/proc/PID/mem);
//   - pidfd_getfd of its descriptor 0;
//   - an openat2 of that path with RESOLVE_IN_ROOT below /proc/PID/root, as
//     the process's own user (setfsuid/setfsgid), the way the Warden opens a
//     file as the agent (v1.29).
// And, when the descriptor arrives, the container's mounts (D4): whether its
// root is read-only, and each writable mount without noexec.
// Each result is one line of LOG.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

static FILE *lg;
static void L(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(lg, fmt, ap);
    va_end(ap);
    fputc('\n', lg);
    fflush(lg);
}

static int read_str(pid_t pid, unsigned long addr, char *out, size_t n) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/mem", pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t r = pread(fd, out, n - 1, (off_t)addr);
    int e = errno;
    close(fd);
    if (r < 0) return -e;
    out[r] = 0;
    out[strnlen(out, n - 1)] = 0;
    return 0;
}

static void ids(pid_t pid, unsigned *uid, unsigned *gid) {
    char p[64], line[256];
    snprintf(p, sizeof p, "/proc/%d/status", pid);
    FILE *f = fopen(p, "r");
    *uid = *gid = (unsigned)-1;
    if (!f) return;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "Uid:", 4)) sscanf(line + 4, "%*u %u", uid);
        if (!strncmp(line, "Gid:", 4)) sscanf(line + 4, "%*u %u", gid);
    }
    fclose(f);
}

static int done_mem, done_getfd, done_open;

static void measure(const struct seccomp_notif *n) {
    pid_t pid = (pid_t)n->pid;
    int nr = n->data.nr;
    unsigned long patharg = 0;
    if (nr == SYS_openat || nr == SYS_execve || nr == SYS_newfstatat || nr == SYS_faccessat2)
        patharg = nr == SYS_execve ? n->data.args[0] : n->data.args[1];
    char path[4096] = "";
    if (patharg && !done_mem) {
        int r = read_str(pid, patharg, path, sizeof path);
        L("memory read: pid %d call %d path arg %s", pid, nr, r ? strerror(-r) : path);
        if (!r && path[0]) done_mem = 1;
    } else if (patharg) {
        read_str(pid, patharg, path, sizeof path);
    }
    if (!done_getfd) {
        int pfd = (int)syscall(SYS_pidfd_open, pid, 0);
        int got = pfd < 0 ? -1 : (int)syscall(SYS_pidfd_getfd, pfd, 0, 0);
        char t[256] = "", lp[64];
        if (got >= 0) {
            snprintf(lp, sizeof lp, "/proc/self/fd/%d", got);
            ssize_t k = readlink(lp, t, sizeof t - 1);
            if (k > 0) t[k] = 0;
        }
        L("pidfd_getfd: pid %d fd 0 -> %s", pid, got >= 0 ? t : strerror(errno));
        if (got >= 0) close(got);
        if (pfd >= 0) close(pfd);
        done_getfd = 1;
    }
    if (nr == SYS_openat && path[0] == '/' && !done_open) {
        unsigned uid, gid;
        ids(pid, &uid, &gid);
        char rp[64];
        snprintf(rp, sizeof rp, "/proc/%d/root", pid);
        int root = open(rp, O_PATH | O_DIRECTORY | O_CLOEXEC);
        setfsgid(gid);
        setfsuid(uid);
        struct open_how how = { .flags = O_RDONLY | O_CLOEXEC, .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS };
        int fd = root < 0 ? -1 : (int)syscall(SYS_openat2, root, path, &how, sizeof how);
        int e = errno;
        setfsuid(0);
        setfsgid(0);
        L("openat2 RESOLVE_IN_ROOT as %u:%u: %s -> %s", uid, gid, path, fd >= 0 ? "opened" : strerror(e));
        if (fd >= 0) {
            struct stat st;
            if (!fstat(fd, &st)) L("  ... size %lld, owner %u", (long long)st.st_size, st.st_uid);
            close(fd);
            done_open = 1;
        }
        if (root >= 0) close(root);
    }
}

// v1.34 step 1, D4: what the node agent can see of the container's mounts
// when the descriptor arrives, before it answers a call: the root's options,
// and each writable mount without noexec (from the state's pid)
static void mounts_at_receipt(const char *state) {
    const char *p = strstr(state, "\"pid\":");
    if (!p) { L("mounts at receipt: no pid in the state"); return; }
    char path[64], line[4096], writable[2048] = "";
    snprintf(path, sizeof path, "/proc/%ld/mountinfo", strtol(p + 6, NULL, 10));
    FILE *f = fopen(path, "r");
    if (!f) { L("mounts at receipt: %s: %s", path, strerror(errno)); return; }
    size_t o = 0;
    while (fgets(line, sizeof line, f)) {
        char mp[1024], opts[512];
        if (sscanf(line, "%*s %*s %*s %*s %1023s %511s", mp, opts) != 2) continue;
        int ro = !strncmp(opts, "ro", 2) && (opts[2] == ',' || !opts[2]);
        if (!strcmp(mp, "/")) L("mounts at receipt: the root is %s (%s)", ro ? "read-only" : "WRITABLE", opts);
        else if (!ro && !strstr(opts, "noexec") && o < sizeof writable - 64)
            o += (size_t)snprintf(writable + o, sizeof writable - o, " %s", mp);
    }
    fclose(f);
    L("mounts at receipt: writable without noexec:%s", o ? writable : " none");
}

static void serve(int sfd, int max) {
    struct seccomp_notif_sizes sz;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sz) < 0) { L("notif sizes: %s", strerror(errno)); return; }
    struct seccomp_notif *req = calloc(1, sz.seccomp_notif > sizeof *req ? sz.seccomp_notif : sizeof *req);
    struct seccomp_notif_resp *resp = calloc(1, sz.seccomp_notif_resp > sizeof *resp ? sz.seccomp_notif_resp : sizeof *resp);
    int counts[600] = { 0 }, total = 0;
    while (total < max) {
        struct pollfd pf = { sfd, POLLIN, 0 };
        int pr = poll(&pf, 1, 20000);
        if (pr == 0) { L("idle 20 s"); break; }
        if (pr < 0 || (pf.revents & (POLLHUP | POLLERR))) { L("descriptor closed (the container ended)"); break; }
        memset(req, 0, sz.seccomp_notif);
        if (ioctl(sfd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) { if (errno == EINTR || errno == ENOENT) continue; L("recv: %s", strerror(errno)); break; }
        measure(req);
        if (req->data.nr >= 0 && req->data.nr < 600) counts[req->data.nr]++;
        total++;
        memset(resp, 0, sz.seccomp_notif_resp);
        resp->id = req->id;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        if (ioctl(sfd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 && errno != ENOENT) L("send: %s", strerror(errno));
    }
    char line[2048] = "";
    size_t o = 0;
    for (int i = 0; i < 600; i++)
        if (counts[i]) o += (size_t)snprintf(line + o, sizeof line - o, " %d:%d", i, counts[i]);
    L("notifications answered: %d (call:count%s)", total, line);
    free(req);
    free(resp);
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s SOCKET LOG [MAX]\n", argv[0]); return 2; }
    lg = fopen(argv[2], "a");
    if (!lg) { perror(argv[2]); return 1; }
    int max = argc > 3 ? atoi(argv[3]) : 200;
    int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s", argv[1]);
    unlink(argv[1]);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0 || listen(ls, 8) < 0) { perror("bind"); return 1; }
    L("listening on %s", argv[1]);
    for (;;) {
        int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) continue;
        static char buf[65536];
        char cbuf[CMSG_SPACE(sizeof(int) * 8)];
        struct iovec iov = { buf, sizeof buf - 1 };
        struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf };
        ssize_t r = recvmsg(c, &m, MSG_CMSG_CLOEXEC);
        close(c);
        if (r <= 0) { L("connection without a message"); continue; }
        buf[r] = 0;
        L("state (%zd bytes): %s", r, buf);
        int fds[8], nfd = 0;
        for (struct cmsghdr *h = CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h))
            if (h->cmsg_level == SOL_SOCKET && h->cmsg_type == SCM_RIGHTS) {
                nfd = (int)((h->cmsg_len - CMSG_LEN(0)) / sizeof(int));
                memcpy(fds, CMSG_DATA(h), sizeof(int) * (size_t)nfd);
            }
        L("descriptors received: %d", nfd);
        mounts_at_receipt(buf);
        for (int i = 0; i < nfd; i++) {
            char lp[64], t[256] = "";
            snprintf(lp, sizeof lp, "/proc/self/fd/%d", fds[i]);
            ssize_t k = readlink(lp, t, sizeof t - 1);
            if (k > 0) t[k] = 0;
            L("  descriptor %d: %s", i, t);
        }
        if (nfd > 0) {
            done_mem = done_getfd = done_open = 0;
            serve(fds[0], max);
        }
        for (int i = 0; i < nfd; i++) close(fds[i]);
    }
}
