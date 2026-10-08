// SPDX-License-Identifier: MIT
// warden_proxy.c — v1.26: the Warden's side of the egress proxy: starting it
// and talking to it. The proxy itself is warden_proxy_helper.c (v1.26.1: its
// own binary, warden-proxy). See warden_proxy.h.

#include "warden_proxy.h"

#include <sodium.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>

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
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int wp_start(wp_t *w, int exe_fd, uid_t uid, gid_t gid) {
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
        /* the binary's copy goes to descriptor 4, close-on-exec (the proxy
         * does not keep it); out of the way first, in case it is 3 */
        int ex = fcntl(exe_fd, F_DUPFD_CLOEXEC, 10);
        if (ex < 0) _exit(1);
        if (dup2(sv[1], 3) < 0) _exit(1);              /* dup2 clears close-on-exec */
        if (dup2(ex, 4) < 0 || fcntl(4, F_SETFD, FD_CLOEXEC) < 0) _exit(1);
        int nul = open("/dev/null", O_RDWR);
        /* stderr too: the Warden's stderr is often the verdict stream, which
         * the proxy (an unprivileged process) must not be able to write */
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        if (syscall(SYS_close_range, 5U, ~0U, 0U) < 0)
            for (int fd = 5; fd < 65536; fd++) close(fd);
        /* v1.26.1: the sealed copy the Warden hashed (see warden_proxy.h);
         * it is close-on-exec, which an ELF binary does not need past exec */
        char *const av[] = { (char *)"warden-proxy", ids, NULL };
        char *const env[] = { NULL };
        fexecve(4, av, env);
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

int wp_verdict(const wp_t *w, uint64_t id, bool allow) {
    if (w->ctl < 0) { errno = ENOTCONN; return -1; }
    struct wp_verdict m = { .type = WP_MSG_VERDICT, .allow = allow ? 1u : 0u, .id = id };
    return send(w->ctl, &m, sizeof m, MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)sizeof m ? 0 : -1;
}


/* v1.26.1: memfd flags; MFD_EXEC (Linux 6.3) says the copy is to be run */
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

int wp_load(const char *path, char sha256_hex[65], char *why, size_t wn) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) { snprintf(why, wn, "cannot open %s: %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        snprintf(why, wn, "%s is not a regular file", path);
        close(fd);
        return -1;
    }
    if (st.st_mode & 022) {
        snprintf(why, wn, "%s is writable by its group or by others (mode %03o)", path,
                 (unsigned)(st.st_mode & 0777));
        close(fd);
        return -1;
    }
    int m = (int)syscall(SYS_memfd_create, "warden-proxy", MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC);
    if (m < 0 && errno == EINVAL)          /* a kernel before 6.3 */
        m = (int)syscall(SYS_memfd_create, "warden-proxy", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (m < 0) { snprintf(why, wn, "memfd_create: %s", strerror(errno)); close(fd); return -1; }
    crypto_hash_sha256_state h;
    crypto_hash_sha256_init(&h);
    unsigned char buf[65536];
    ssize_t n;
    size_t total = 0;
    while ((n = read(fd, buf, sizeof buf)) != 0) {
        if (n < 0) {
            if (errno == EINTR) continue;
            snprintf(why, wn, "reading %s: %s", path, strerror(errno));
            goto fail;
        }
        crypto_hash_sha256_update(&h, buf, (unsigned long long)n);
        for (ssize_t off = 0; off < n;) {
            ssize_t w = write(m, buf + off, (size_t)(n - off));
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) { snprintf(why, wn, "copying %s: %s", path, strerror(errno)); goto fail; }
            off += w;
        }
        total += (size_t)n;
    }
    if (total < 4 || pread(m, buf, 4, 0) != 4 || memcmp(buf, "\x7f" "ELF", 4) != 0) {
        snprintf(why, wn, "%s is not an ELF executable", path);
        goto fail;
    }
    if (fchmod(m, 0500) < 0 ||
        fcntl(m, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL) < 0) {
        snprintf(why, wn, "sealing the copy of %s: %s", path, strerror(errno));
        goto fail;
    }
    unsigned char d[32];
    crypto_hash_sha256_final(&h, d);
    sodium_bin2hex(sha256_hex, 65, d, sizeof d);
    close(fd);
    return m;
fail:
    close(fd);
    close(m);
    return -1;
}

/* v1.26.1: inspecting mode's setup (see warden_proxy.h). */
int wp_inspect_setup(const wp_t *w, const char *run_id, const char *bundle, char *const *names,
                     size_t nnames, const char (*excl)[254], size_t nexcl, unsigned char **pem, size_t *pem_len, unsigned char **p12,
                     size_t *p12_len, int *secure_heap, int *nroots, char *why, size_t wn) {
    *pem = *p12 = NULL;
    *pem_len = *p12_len = 0;
    struct wp_inspect in;
    memset(&in, 0, sizeof in);
    in.type = WP_MSG_INSPECT;
    in.nnames = (uint32_t)nnames;
    if (strlen(run_id) >= sizeof in.run_id || strlen(bundle) >= sizeof in.bundle) {
        snprintf(why, wn, "run id or trust bundle path too long");
        return -1;
    }
    strcpy(in.run_id, run_id);
    strcpy(in.bundle, bundle);
    if (send(w->ctl, &in, sizeof in, MSG_NOSIGNAL) != (ssize_t)sizeof in) goto gone;
    for (size_t i = 0; i < nnames; i++) {
        struct wp_ca_name cn;
        memset(&cn, 0, sizeof cn);
        cn.type = WP_MSG_CA_NAME;
        snprintf(cn.name, sizeof cn.name, "%s", names[i]);
        if (send(w->ctl, &cn, sizeof cn, MSG_NOSIGNAL) != (ssize_t)sizeof cn) goto gone;
    }
    for (size_t i = 0; i < nexcl; i++) {               /* review: the names the CA excludes */
        struct wp_ca_name cn;
        memset(&cn, 0, sizeof cn);
        cn.type = WP_MSG_CA_NAME;
        cn.excluded = 1;
        snprintf(cn.name, sizeof cn.name, "%s", excl[i]);
        if (send(w->ctl, &cn, sizeof cn, MSG_NOSIGNAL) != (ssize_t)sizeof cn) goto gone;
    }
    struct wp_msg go = { .type = WP_MSG_CA_GO, .port = 0 };
    if (send(w->ctl, &go, sizeof go, MSG_NOSIGNAL) != (ssize_t)sizeof go) goto gone;
    /* the blobs, each in order, then the proxy's word */
    unsigned char *buf[3] = { NULL, NULL, NULL };
    size_t total[3] = { 0, 0, 0 }, have[3] = { 0, 0, 0 };
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        struct timespec t;
        clock_gettime(CLOCK_MONOTONIC, &t);
        long left = 15000 - ((t.tv_sec - t0.tv_sec) * 1000 + (t.tv_nsec - t0.tv_nsec) / 1000000);
        struct pollfd pf = { .fd = w->ctl, .events = POLLIN };
        int pr = left > 0 ? poll(&pf, 1, (int)left) : 0;
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) { snprintf(why, wn, "the proxy did not make the run's CA within 15 s"); break; }
        static union { struct wp_blob b; struct wp_ca_done d; uint32_t type; } m;
        ssize_t n = recv(w->ctl, &m, sizeof m, 0);
        if (n <= 0) goto gone_free;
        if (n == (ssize_t)sizeof m.b && m.type == WP_MSG_BLOB) {
            uint32_t k = m.b.kind;
            if ((k != WP_BLOB_CA_PEM && k != WP_BLOB_P12) || m.b.total == 0 || m.b.total > WP_BLOB_MAX ||
                m.b.len == 0 || m.b.len > WP_BLOB_CHUNK || m.b.off != have[k] ||
                (have[k] && m.b.total != total[k]) || m.b.len > m.b.total - m.b.off) {
                snprintf(why, wn, "the proxy sent a malformed blob");
                break;
            }
            if (!buf[k]) {
                total[k] = m.b.total;
                if (!(buf[k] = malloc(total[k]))) { snprintf(why, wn, "out of memory"); break; }
            }
            memcpy(buf[k] + m.b.off, m.b.data, m.b.len);
            have[k] += m.b.len;
            continue;
        }
        if (n == (ssize_t)sizeof m.d && m.type == WP_MSG_CA_DONE) {
            if (!memchr(m.d.why, 0, sizeof m.d.why)) { snprintf(why, wn, "the proxy sent a malformed answer"); break; }
            if (!m.d.ok) { snprintf(why, wn, "the proxy could not make the run's CA: %s", m.d.why); break; }
            if (!buf[1] || !buf[2] || have[1] != total[1] || have[2] != total[2]) {
                snprintf(why, wn, "the proxy did not send the CA and the trust store");
                break;
            }
            *pem = buf[1]; *pem_len = total[1];
            *p12 = buf[2]; *p12_len = total[2];
            *secure_heap = m.d.secure_heap != 0;
            *nroots = (int)m.d.nroots;
            return 0;
        }
        snprintf(why, wn, "the proxy sent an unexpected message");
        break;
    }
    free(buf[1]);
    free(buf[2]);
    return -1;
gone_free:
    free(buf[1]);
    free(buf[2]);
gone:
    snprintf(why, wn, "the proxy has gone");
    return -1;
}
