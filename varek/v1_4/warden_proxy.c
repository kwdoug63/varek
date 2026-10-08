// SPDX-License-Identifier: MIT
// warden_proxy.c — v1.26: the egress proxy process. See warden_proxy.h.

#include "warden_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int wp_start(wp_t *w, const char *exe, uid_t uid, gid_t gid) {
    w->ctl = -1;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) return -1;
    char ids[32];
    snprintf(ids, sizeof ids, "%u:%u", (unsigned)uid, (unsigned)gid);
    /* As the resolver helper: an intermediate starts the proxy and exits at
     * once, so the proxy is not the Warden's child (its exit is no SIGCHLD
     * to the Warden, which waits only for the agent). */
    pid_t mid = fork();
    if (mid < 0) { close(sv[0]); close(sv[1]); return -1; }
    if (mid == 0) {
        close(sv[0]);
        pid_t h = fork();
        if (h != 0) _exit(h < 0 ? 1 : 0);
        if (dup2(sv[1], 3) < 0) _exit(1);              /* dup2 clears close-on-exec */
        int nul = open("/dev/null", O_RDWR);
        /* stderr too: the Warden's stderr is often the verdict stream, which
         * the proxy (an unprivileged process) must not be able to write */
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        if (syscall(SYS_close_range, 4U, ~0U, 0U) < 0)
            for (int fd = 4; fd < 65536; fd++) close(fd);
        char *const av[] = { (char *)exe, (char *)"--proxy-helper", ids, NULL };
        execv(exe, av);
        _exit(127);
    }
    close(sv[1]);
    int st = 0;
    while (waitpid(mid, &st, 0) < 0 && errno == EINTR) { }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { close(sv[0]); errno = ECHILD; return -1; }
    /* The proxy proves who it runs as with SCM_CREDENTIALS, which the kernel
     * checks against the sender (SO_PEERCRED would report the socketpair's
     * creator: the Warden). */
    int one = 1;
    if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof one) < 0) { close(sv[0]); return -1; }
    struct pollfd pf = { .fd = sv[0], .events = POLLIN };
    struct wp_msg m;
    int pr;
    while ((pr = poll(&pf, 1, 5000)) < 0 && errno == EINTR) { }
    union { char b[CMSG_SPACE(sizeof(struct ucred))]; struct cmsghdr al; } cb;
    struct iovec v = { &m, sizeof m };
    struct msghdr mh = { .msg_iov = &v, .msg_iovlen = 1, .msg_control = cb.b, .msg_controllen = sizeof cb.b };
    ssize_t n = pr == 1 ? recvmsg(sv[0], &mh, 0) : -1;
    if (n != (ssize_t)sizeof m || m.type != WP_MSG_READY || m.port == 0 || m.port > 65535) {
        close(sv[0]);
        errno = pr == 0 ? ETIMEDOUT : EPROTO;
        return -1;
    }
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    struct ucred cr;
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_CREDENTIALS ||
        c->cmsg_len != CMSG_LEN(sizeof cr)) { close(sv[0]); errno = EPROTO; return -1; }
    memcpy(&cr, CMSG_DATA(c), sizeof cr);
    if (cr.uid != uid || cr.gid != gid) {
        close(sv[0]);
        errno = EPERM;                                  /* it did not drop to the proxy's user */
        return -1;
    }
    w->ctl = sv[0];
    w->pid = cr.pid;
    w->port = m.port;
    w->uid = uid;
    w->gid = gid;
    return 0;
}

int wp_announce(const wp_t *w, uint64_t id, unsigned from_port, pid_t tid, const char *dest) {
    if (w->ctl < 0) { errno = ENOTCONN; return -1; }
    struct wp_conn m;
    memset(&m, 0, sizeof m);
    m.type = WP_MSG_CONN;
    m.from_port = from_port;
    m.id = id;
    m.tid = (int32_t)tid;
    snprintf(m.dest, sizeof m.dest, "%s", dest);
    ssize_t n = send(w->ctl, &m, sizeof m, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n != (ssize_t)sizeof m) { if (n >= 0) errno = EMSGSIZE; return -1; }
    return 0;
}

static int64_t mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* The proxy's state: announcements waiting for their connection, and the
 * connections it holds. */
struct wp_ann  { bool used; uint32_t from_port; uint64_t id; int64_t at; };
struct wp_held { int fd; uint64_t id; int64_t last; };
static struct wp_ann  g_ann[WP_MAX_ANNOUNCED];
static struct wp_held g_held[WP_MAX_HELD];
static int g_nheld = 0;

/* Read every control message waiting. Returns -1 when the Warden has gone. */
static int wp_drain_ctl(int ctl) {
    for (;;) {
        struct wp_conn m;
        ssize_t n = recv(ctl, &m, sizeof m, MSG_DONTWAIT);
        if (n == 0) return -1;
        if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
        if (n != (ssize_t)sizeof m || m.type != WP_MSG_CONN || m.from_port == 0 || m.from_port > 65535)
            continue;                                   /* not one the Warden sends */
        int64_t now = mono_ms();
        int slot = -1, oldest = 0;
        for (int k = 0; k < WP_MAX_ANNOUNCED; k++) {
            if (g_ann[k].used && (now - g_ann[k].at > WP_ANNOUNCE_MS || g_ann[k].from_port == m.from_port))
                g_ann[k].used = false;                  /* expired, or its port is reused */
            if (!g_ann[k].used && slot < 0) slot = k;
            if (g_ann[k].at < g_ann[oldest].at) oldest = k;
        }
        if (slot < 0) slot = oldest;                    /* full: the oldest goes */
        g_ann[slot] = (struct wp_ann){ .used = true, .from_port = m.from_port, .id = m.id, .at = now };
    }
}

/* A connection accepted: hold it if the Warden announced it, else close it. */
static void wp_accepted(int c, const struct sockaddr_in *peer) {
    int64_t now = mono_ms();
    int found = -1;
    if (peer->sin_family == AF_INET && peer->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
        for (int k = 0; k < WP_MAX_ANNOUNCED; k++)
            if (g_ann[k].used && g_ann[k].from_port == ntohs(peer->sin_port) &&
                now - g_ann[k].at <= WP_ANNOUNCE_MS) { found = k; break; }
    if (found < 0 || g_nheld >= WP_MAX_HELD) { close(c); return; }
    g_ann[found].used = false;
    g_held[g_nheld++] = (struct wp_held){ .fd = c, .id = g_ann[found].id, .last = now };
}

int wp_helper_main(int ctl) {
    signal(SIGPIPE, SIG_IGN);
    int ls = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (ls < 0) { perror("[proxy] socket"); return 1; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    socklen_t al = sizeof a;
    if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0 || listen(ls, 1024) < 0 ||
        getsockname(ls, (struct sockaddr *)&a, &al) < 0) {
        perror("[proxy] listen");
        return 1;
    }
    struct wp_msg m = { .type = WP_MSG_READY, .port = ntohs(a.sin_port) };
    struct ucred cr = { .pid = getpid(), .uid = getuid(), .gid = getgid() };
    union { char b[CMSG_SPACE(sizeof cr)]; struct cmsghdr al; } cb;
    memset(&cb, 0, sizeof cb);
    struct iovec v = { &m, sizeof m };
    struct msghdr mh = { .msg_iov = &v, .msg_iovlen = 1, .msg_control = cb.b, .msg_controllen = sizeof cb.b };
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_CREDENTIALS;
    c->cmsg_len = CMSG_LEN(sizeof cr);
    memcpy(CMSG_DATA(c), &cr, sizeof cr);
    if (sendmsg(ctl, &mh, MSG_NOSIGNAL) != (ssize_t)sizeof m) return 1;
    static struct pollfd pf[2 + WP_MAX_HELD];
    for (;;) {
        pf[0] = (struct pollfd){ .fd = ctl, .events = POLLIN };
        pf[1] = (struct pollfd){ .fd = ls, .events = POLLIN };
        for (int k = 0; k < g_nheld; k++) pf[2 + k] = (struct pollfd){ .fd = g_held[k].fd, .events = POLLIN };
        int nh = g_nheld;
        if (poll(pf, (nfds_t)(2 + nh), 1000) < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        if (pf[0].revents && wp_drain_ctl(ctl) < 0) return 0;      /* the Warden went */
        if (pf[1].revents & POLLIN) {
            /* The Warden announces a connection before making it: read the
             * control socket again first, so its announcement is here. */
            if (wp_drain_ctl(ctl) < 0) return 0;
            for (;;) {
                struct sockaddr_in peer;
                socklen_t pl = sizeof peer;
                memset(&peer, 0, sizeof peer);
                int c = accept4(ls, (struct sockaddr *)&peer, &pl, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (c < 0) break;
                wp_accepted(c, &peer);
            }
        }
        /* Step 4: a held connection is read and discarded (step 5 parses
         * it), and closed when the client closes it or after 60 s idle. */
        int64_t now = mono_ms();
        for (int k = nh - 1; k >= 0; k--) {
            bool drop = now - g_held[k].last > 60000;
            if (pf[2 + k].revents) {
                char b[4096];
                ssize_t n = recv(g_held[k].fd, b, sizeof b, MSG_DONTWAIT);
                if (n > 0) g_held[k].last = now;
                else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) drop = true;
            }
            if (drop) {
                close(g_held[k].fd);
                g_held[k] = g_held[--g_nheld];
            }
        }
    }
}
