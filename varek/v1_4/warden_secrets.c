// SPDX-License-Identifier: MIT
// warden_secrets.c — v1.28: the Warden's side of warden-secrets: starting
// it and asking it for the credentials. See warden_secrets.h. The helper
// itself is warden_secrets_helper.c.

#include "warden_secrets.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int ws_start(ws_t *w, int exe_fd, uid_t uid, gid_t gid) {
    w->ctl = -1;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) return -1;
    char ids[32];
    snprintf(ids, sizeof ids, "%u:%u", (unsigned)uid, (unsigned)gid);
    /* As warden-proxy: an intermediate starts the helper and exits, so the
     * helper is not the Warden's child (the Warden waits only for the agent) */
    pid_t mid = fork();
    if (mid < 0) { close(sv[0]); close(sv[1]); return -1; }
    if (mid == 0) {
        close(sv[0]);
        pid_t h = fork();
        if (h != 0) _exit(h < 0 ? 1 : 0);
        int ex = fcntl(exe_fd, F_DUPFD_CLOEXEC, 10);
        if (ex < 0) _exit(1);
        if (dup2(sv[1], 3) < 0) _exit(1);
        if (dup2(ex, 4) < 0 || fcntl(4, F_SETFD, FD_CLOEXEC) < 0) _exit(1);
        int nul = open("/dev/null", O_RDWR);
        /* not the Warden's stderr: that is often the verdict stream */
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        if (syscall(SYS_close_range, 5U, ~0U, 0U) < 0)
            for (int fd = 5; fd < 65536; fd++) close(fd);
        char *const av[] = { (char *)"warden-secrets", ids, NULL };
        char *const env[] = { NULL };
        fexecve(4, av, env);
        _exit(127);
    }
    close(sv[1]);
    int st = 0;
    while (waitpid(mid, &st, 0) < 0 && errno == EINTR) { }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { close(sv[0]); errno = ECHILD; return -1; }
    int one = 1;
    if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof one) < 0) { close(sv[0]); return -1; }
    w->ctl = sv[0];
    w->pid = 0;
    w->uid = uid;
    w->gid = gid;
    return 0;
}

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static bool send_all(int fd, const void *m, size_t n) {
    ssize_t r;
    while ((r = send(fd, m, n, MSG_NOSIGNAL)) < 0 && errno == EINTR) { }
    return r == (ssize_t)n;
}

int ws_fetch(ws_t *w, const char *conf, size_t n, const int *store, const char *const *ref,
             ws_meta_t *meta, char (*files)[4096], size_t *nfiles, int timeout_ms,
             char *why, size_t wn) {
    *nfiles = 0;
    if (w->ctl < 0 || n > WS_MAX_CREDS) { snprintf(why, wn, "the helper is not running"); return -1; }
    struct ws_setup su;
    memset(&su, 0, sizeof su);
    su.type = WS_MSG_SETUP;
    su.ncreds = (uint32_t)n;
    if (strlen(conf) >= sizeof su.conf) { snprintf(why, wn, "the configuration path is too long"); return -1; }
    memcpy(su.conf, conf, strlen(conf) + 1);
    if (!send_all(w->ctl, &su, sizeof su)) { snprintf(why, wn, "the helper did not take its setup"); return -1; }
    for (size_t i = 0; i < n; i++) {
        struct ws_cred c;
        memset(&c, 0, sizeof c);
        c.type = WS_MSG_CRED;
        c.index = (uint32_t)i;
        c.store = (uint32_t)store[i];
        snprintf(c.ref, sizeof c.ref, "%s", ref[i]);
        if (!send_all(w->ctl, &c, sizeof c)) { snprintf(why, wn, "the helper did not take credential %zu", i); return -1; }
    }
    bool got[WS_MAX_CREDS] = { false };
    size_t ngot = 0;
    long long end = now_ms() + timeout_ms;
    for (;;) {
        long long left = end - now_ms();
        if (left <= 0) { snprintf(why, wn, "the helper did not answer within %d s", timeout_ms / 1000); return -1; }
        struct pollfd pf = { .fd = w->ctl, .events = POLLIN };
        int pr = poll(&pf, 1, (int)left);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) continue;
        union { struct ws_file f; struct ws_result r; struct ws_ready y; uint32_t type; } m;
        union { char b[CMSG_SPACE(sizeof(struct ucred))]; struct cmsghdr al; } cb;
        struct iovec v = { &m, sizeof m };
        struct msghdr mh = { .msg_iov = &v, .msg_iovlen = 1, .msg_control = cb.b, .msg_controllen = sizeof cb.b };
        ssize_t k = recvmsg(w->ctl, &mh, 0);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) { snprintf(why, wn, "the helper ended before it was ready"); return -1; }
        if ((size_t)k < sizeof m.type) goto bad;
        if (m.type == WS_MSG_FILE && k == (ssize_t)sizeof m.f) {
            if (*nfiles >= WS_MAX_FILES || !memchr(m.f.path, '\0', sizeof m.f.path) || m.f.path[0] != '/') goto bad;
            memcpy(files[(*nfiles)++], m.f.path, strlen(m.f.path) + 1);
        } else if (m.type == WS_MSG_RESULT && k == (ssize_t)sizeof m.r) {
            if (m.r.index >= n || got[m.r.index] || !memchr(m.r.version, '\0', sizeof m.r.version) ||
                !memchr(m.r.why, '\0', sizeof m.r.why))
                goto bad;
            /* v1.28 review: both are printed, and the version recorded:
             * printable ASCII, no quote or backslash, or the message is not
             * the helper's */
            for (const char *c = m.r.version; *c; c++) if (*c < 0x20 || *c > 0x7e || *c == '"' || *c == '\\') goto bad;
            for (const char *c = m.r.why; *c; c++) if (*c < 0x20 || *c > 0x7e) goto bad;
            if (!m.r.ok) {
                snprintf(why, wn, "credential %u: %s", m.r.index, m.r.why);
                return -1;
            }
            if (m.r.len == 0 || m.r.len > WS_MAX_VALUE) goto bad;
            got[m.r.index] = true;
            ngot++;
            memcpy(meta[m.r.index].version, m.r.version, sizeof meta[m.r.index].version);
            meta[m.r.index].len = m.r.len;
        } else if (m.type == WS_MSG_READY && k == (ssize_t)sizeof m.y) {
            /* the helper proves who it runs as (SCM_CREDENTIALS, checked by
             * the kernel against the sender) */
            struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
            struct ucred cr;
            if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_CREDENTIALS ||
                c->cmsg_len != CMSG_LEN(sizeof cr))
                goto bad;
            memcpy(&cr, CMSG_DATA(c), sizeof cr);
            if (cr.uid != w->uid || cr.gid != w->gid) {
                snprintf(why, wn, "the helper did not drop to its user (%u:%u)", (unsigned)w->uid, (unsigned)w->gid);
                return -1;
            }
            if (ngot != n || m.y.n != n) goto bad;
            w->pid = cr.pid;
            return 0;
        } else {
            goto bad;
        }
    }
bad:
    snprintf(why, wn, "the helper sent a malformed message");
    return -1;
}

int ws_hand_to(ws_t *w, int fd) {
    if (w->ctl < 0) { errno = ENOTCONN; return -1; }
    struct ws_ready m = { .type = WS_MSG_PROXY, .n = 0 };
    union { char b[CMSG_SPACE(sizeof(int))]; struct cmsghdr al; } cb;
    memset(&cb, 0, sizeof cb);
    struct iovec v = { &m, sizeof m };
    struct msghdr mh = { .msg_iov = &v, .msg_iovlen = 1, .msg_control = cb.b, .msg_controllen = sizeof cb.b };
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof fd);
    ssize_t r;
    while ((r = sendmsg(w->ctl, &mh, MSG_NOSIGNAL)) < 0 && errno == EINTR) { }
    return r == (ssize_t)sizeof m ? 0 : -1;
}

int ws_revoke(ws_t *w) {
    if (w->ctl < 0) { errno = ENOTCONN; return -1; }
    struct ws_ready m = { .type = WS_MSG_REVOKE, .n = 0 };
    return send_all(w->ctl, &m, sizeof m) ? 0 : -1;
}

void ws_stop(ws_t *w) {
    if (w->ctl >= 0) close(w->ctl);
    w->ctl = -1;
}
