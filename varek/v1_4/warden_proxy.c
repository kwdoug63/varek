// SPDX-License-Identifier: MIT
// warden_proxy.c — v1.26: the egress proxy process. See warden_proxy.h.

#include "warden_proxy.h"
#include "proxy_parse.h"

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

int wp_verdict(const wp_t *w, uint64_t id, bool allow) {
    if (w->ctl < 0) { errno = ENOTCONN; return -1; }
    struct wp_verdict m = { .type = WP_MSG_VERDICT, .allow = allow ? 1u : 0u, .id = id };
    return send(w->ctl, &m, sizeof m, MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)sizeof m ? 0 : -1;
}

static int64_t mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* The proxy's state: announcements waiting for their connection, and the
 * connections it holds. A held connection is read (step 5) until the parser
 * has a name, then waits for the Warden's verdict. */
struct wp_ann  { bool used; uint32_t from_port; unsigned dport; uint64_t id; int64_t at; };
enum { WH_READING = 0, WH_WAITING = 1, WH_RELAY = 2, WH_UPSTREAM = 3 };
#define WP_RELAY_BUF   32768     /* each direction */
#define WP_RELAY_IDLE  3600000   /* a relayed connection idle this long is closed */
struct wp_held {
    int       fd;
    uint64_t  id;
    unsigned  dport;             /* the port the agent connected to */
    int       state;
    bool      acked;             /* its CONNECT was answered */
    pp_kind_t kind;
    int64_t   since;             /* accepted, or (waiting) asked */
    uint8_t  *buf;               /* what it sent, up to PP_IN_MAX; relaying: client -> server */
    size_t    len, off;          /* relaying: buf[off, len) is still to send */
    size_t    skip;              /* bytes of buf the server is not sent (an answered CONNECT) */
    /* step 6: relaying */
    int       up;                /* the socket the Warden dialed, or -1 */
    uint8_t  *down;              /* server -> client */
    size_t    dlen, doff;
    bool      eof_c, eof_s;      /* the client's, the server's side has closed */
    bool      shut_s, shut_c;    /* the close was passed on to the server, the client */
    uint64_t  bytes_up, bytes_down;
    unsigned  up_status;         /* section 5: the upstream's reply status */
    int64_t   relay_at;          /* when relaying began */
    const char *why;             /* step 7: why the relay ended */
    /* v1.26 review: plain HTTP is checked request by request. Client bytes
     * are passed on only up to fwd: the heads read so far (each for the
     * name and port decided) and their bodies. */
    char      name[PP_NAME_MAX + 1]; /* the name decided */
    int       gate;              /* WG_OPEN (TLS, CONNECT: not read), WG_HEAD, WG_LENGTH, WG_CHUNKED */
    size_t    fwd;
    uint64_t  body_left;
    pp_chunked_t ck;
    bool      refused;           /* a later request was refused: no more is read from the client */
};
enum { WG_OPEN = 0, WG_HEAD, WG_LENGTH, WG_CHUNKED };
static struct wp_ann  g_ann[WP_MAX_ANNOUNCED];
static struct wp_held g_held[WP_MAX_HELD];
static int g_nheld = 0;
static int g_max_held = WP_MAX_HELD;   /* v1.26 review: fewer if the descriptor limit is lower */
static int g_ctl = -1;

/* Step 7: a relayed connection ends: report it (bytes each way, how long). */
static void report_close(const struct wp_held *h, const char *why) {
    struct wp_close m;
    memset(&m, 0, sizeof m);
    m.type = WP_MSG_CLOSED;
    m.upstream_status = h->up_status;
    m.id = h->id;
    m.bytes_up = h->bytes_up;
    m.bytes_down = h->bytes_down;
    int64_t d = mono_ms() - h->relay_at;
    m.ms = d > 0 ? (uint64_t)d : 0;
    snprintf(m.why, sizeof m.why, "%s", why);
    (void)send(g_ctl, &m, sizeof m, MSG_NOSIGNAL);   /* blocking: a close report is never dropped */
}

static void held_drop(int k) {
    if (g_held[k].state == WH_UPSTREAM)            /* the run ended while asking the upstream */
        report_close(&g_held[k], g_held[k].why ? g_held[k].why : "upstream_refused");
    else if (g_held[k].state == WH_RELAY) report_close(&g_held[k], g_held[k].why ? g_held[k].why : "closed");
    close(g_held[k].fd);
    if (g_held[k].up >= 0) close(g_held[k].up);
    free(g_held[k].buf);
    free(g_held[k].down);
    g_held[k] = g_held[--g_nheld];
}

/* Tell the client no, in its own protocol, and close. */
static void held_refuse(int k) {
    static const uint8_t alert[] = { 21, 3, 3, 0, 2, 2, 40 };          /* fatal handshake_failure */
    static const char forbidden[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    struct wp_held *h = &g_held[k];
    if (h->kind == PP_KIND_TLS || (h->kind == PP_KIND_CONNECT && h->acked))
        (void)send(h->fd, alert, sizeof alert, MSG_DONTWAIT | MSG_NOSIGNAL);
    else if (h->kind == PP_KIND_HTTP || h->kind == PP_KIND_CONNECT)
        (void)send(h->fd, forbidden, sizeof forbidden - 1, MSG_DONTWAIT | MSG_NOSIGNAL);
    held_drop(k);
}

/* Report a connection to the Warden: its name (WP_MSG_REQUEST) or why it
 * could not be read (WP_MSG_UNREADABLE). */
static void report(const struct wp_held *h, uint32_t type, const pp_result_t *r, const char *why) {
    struct wp_req m;
    memset(&m, 0, sizeof m);
    m.type = type;
    m.kind = (uint32_t)(r ? r->kind : h->kind);
    m.id = h->id;
    if (type == WP_MSG_REQUEST) {
        m.port = r->port;
        snprintf(m.name, sizeof m.name, "%s", r->name);
    } else {
        snprintf(m.why, sizeof m.why, "%s", why);
    }
    /* v1.26 review: blocking, as report_close: a report the control socket
     * had no room for was dropped, and its connection waited, unrecorded */
    (void)send(g_ctl, &m, sizeof m, MSG_NOSIGNAL);
}

/* v1.26 review: an allowed connection the proxy could not relay (the client
 * had gone, or relaying could not start): the Warden counted it open, so
 * report its close, with nothing relayed. */
static void report_gone(uint64_t id) {
    struct wp_close m;
    memset(&m, 0, sizeof m);
    m.type = WP_MSG_CLOSED;
    m.id = id;
    snprintf(m.why, sizeof m.why, "client_gone");
    (void)send(g_ctl, &m, sizeof m, MSG_NOSIGNAL);
}

static int held_find(uint64_t id) {
    for (int k = 0; k < g_nheld; k++) if (g_held[k].id == id) return k;
    return -1;
}

/* Step 6: the Warden dialed the server for held connection k (fd): send it
 * what the client sent (after an answered CONNECT, what followed it), then
 * relay both ways. 0, or -1. */
static int held_relay(int k, int fd) {
    struct wp_held *h = &g_held[k];
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
    if (!(h->down = malloc(WP_RELAY_BUF))) return -1;
    if (!h->buf && !(h->buf = malloc(PP_IN_MAX))) return -1;
    h->up = fd;
    h->off = h->skip;
    h->fwd = h->kind == PP_KIND_HTTP ? h->skip : h->len;   /* HTTP: each head read before it is sent */
    h->gate = h->kind == PP_KIND_HTTP ? WG_HEAD : WG_OPEN;
    h->state = WH_RELAY;
    h->since = h->relay_at = mono_ms();
    return 0;
}

/* Section 5: the Warden dialed the upstream proxy for held connection k:
 * ask it for name:port; relaying starts when it answers 2xx (held_upstream). */
static int held_relay_up(int k, int fd, const char *name, unsigned port) {
    if (held_relay(k, fd) < 0) return -1;
    struct wp_held *h = &g_held[k];
    char req[600];
    int rl = snprintf(req, sizeof req, "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n", name, port, name, port);
    if (rl <= 0 || (size_t)rl >= sizeof req ||
        send(h->up, req, (size_t)rl, MSG_DONTWAIT | MSG_NOSIGNAL) != rl) return -1;
    h->state = WH_UPSTREAM;
    h->since = mono_ms();
    return 0;
}

/* Section 5: bytes from the upstream while waiting for its reply. False when
 * the connection is done (refused: reported, and the client refused). */
static bool held_upstream(int k) {
    struct wp_held *h = &g_held[k];
    ssize_t n = recv(h->up, h->down + h->dlen, WP_RELAY_BUF - h->dlen, MSG_DONTWAIT);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return true;
    if (n > 0) h->dlen += (size_t)n;
    unsigned st;
    size_t len;
    const char *why;
    pp_status_t ps = n <= 0 ? PP_REFUSE : pp_upstream_reply(h->down, h->dlen, &st, &len, &why);
    if (n <= 0) st = 0;
    if (ps == PP_MORE && h->dlen < WP_RELAY_BUF) return true;
    if (ps != PP_OK) {
        h->up_status = st;
        return false;                                  /* held_drop reports upstream_refused */
    }
    h->up_status = st;
    h->doff = len;                                     /* what follows the reply is the server's */
    if (h->doff == h->dlen) h->doff = h->dlen = 0;
    h->state = WH_RELAY;
    h->since = h->relay_at = mono_ms();
    return true;
}

/* v1.26 review: a request the gate refuses. What came before it is still
 * sent, and the server's reply to it relayed; nothing after it is: the
 * client is treated as closed there, and the close is recorded as
 * "refused_request". */
static void gate_refuse(struct wp_held *h) {
    h->refused = true;
    h->len = h->fwd;
    h->eof_c = true;
}

/* v1.26 review: let through the client's bytes that are whole requests for
 * the name and port decided: each head is read (as the first was) before a
 * byte of it is sent, and its body is passed as its framing says. A request
 * for another host, or one that cannot be read, stops it (gate_refuse). */
static bool held_gate(struct wp_held *h) {
    while (h->fwd < h->len) {
        if (h->gate == WG_OPEN) { h->fwd = h->len; break; }
        if (h->gate == WG_HEAD) {
            pp_result_t r;
            pp_status_t st = pp_parse(h->buf + h->fwd, h->len - h->fwd, h->dport, false, &r);
            if (st == PP_MORE) {
                if (h->len - h->fwd >= PP_HTTP_MAX) gate_refuse(h);
                break;
            }
            if (st != PP_OK || r.kind != PP_KIND_HTTP || strcmp(r.name, h->name) || r.port != h->dport) {
                gate_refuse(h);                         /* another host, or not a request */
                break;
            }
            h->fwd += r.head_len;
            h->gate = r.body == PP_BODY_LENGTH && r.body_len ? WG_LENGTH :
                      r.body == PP_BODY_CHUNKED ? WG_CHUNKED : WG_HEAD;
            h->body_left = r.body_len;
            memset(&h->ck, 0, sizeof h->ck);
        } else if (h->gate == WG_LENGTH) {
            uint64_t take = h->len - h->fwd < h->body_left ? h->len - h->fwd : h->body_left;
            h->fwd += (size_t)take;
            h->body_left -= take;
            if (!h->body_left) h->gate = WG_HEAD;
        } else {
            bool done;
            long c = pp_chunked_feed(&h->ck, h->buf + h->fwd, h->len - h->fwd, &done);
            if (c < 0) { gate_refuse(h); break; }
            h->fwd += (size_t)c;
            if (done) h->gate = WG_HEAD;
        }
    }
    return true;
}

/* Move what can be moved on relayed connection k; false when it is done. */
static bool held_pump(int k, short crev, short srev) {
    struct wp_held *h = &g_held[k];
    h->why = "reset";
    if ((crev | srev) & POLLNVAL) return false;
    bool moved = false;
    /* client -> server: only what the gate let through (up to fwd) */
    if (!held_gate(h)) return false;
    if (h->off < h->fwd) {
        ssize_t n = send(h->up, h->buf + h->off, h->fwd - h->off, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
        if (n > 0) { h->off += (size_t)n; h->bytes_up += (uint64_t)n; moved = true; }
    }
    if (h->off > 0 && h->off == h->fwd) {          /* sent: keep only what is not yet let through */
        memmove(h->buf, h->buf + h->off, h->len - h->off);
        h->len -= h->off;
        h->fwd -= h->off;
        h->off = 0;
    }
    if (!h->eof_c && h->len < PP_IN_MAX && (crev & (POLLIN | POLLHUP | POLLERR))) {
        ssize_t n = recv(h->fd, h->buf + h->len, PP_IN_MAX - h->len, MSG_DONTWAIT);
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) h->eof_c = true;
        else if (n > 0) { h->len += (size_t)n; moved = true; if (!held_gate(h)) return false; }
    }
    /* server -> client */
    if (h->doff < h->dlen) {
        ssize_t n = send(h->fd, h->down + h->doff, h->dlen - h->doff, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
        if (n > 0) { h->doff += (size_t)n; h->bytes_down += (uint64_t)n; moved = true; }
        if (h->doff == h->dlen) h->doff = h->dlen = 0;
    }
    if (!h->eof_s && h->dlen < WP_RELAY_BUF && (srev & (POLLIN | POLLHUP | POLLERR))) {
        ssize_t n = recv(h->up, h->down + h->dlen, WP_RELAY_BUF - h->dlen, MSG_DONTWAIT);
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) h->eof_s = true;
        else if (n > 0) { h->dlen += (size_t)n; moved = true; }
    }
    /* a side that closed, once what it sent is passed on, closes the other's write side */
    if (h->eof_c && h->off == h->len && !h->shut_s) { shutdown(h->up, SHUT_WR); h->shut_s = true; }
    if (h->eof_c && h->len > h->fwd && h->off == h->fwd) {
        gate_refuse(h);                              /* closed in the middle of a request */
        if (!h->shut_s) { shutdown(h->up, SHUT_WR); h->shut_s = true; }
    }
    if (h->eof_s && h->doff == h->dlen && !h->shut_c) { shutdown(h->fd, SHUT_WR); h->shut_c = true; }
    int64_t now = mono_ms();
    if (moved) h->since = now;
    h->why = h->refused ? "refused_request" : "closed";
    if (h->shut_s && h->shut_c) return false;
    h->why = "idle";
    return now - h->since <= WP_RELAY_IDLE;
}

/* Read every control message waiting. Returns -1 when the Warden has gone. */
static int wp_drain_ctl(int ctl) {
    for (;;) {
        union { struct wp_conn c; struct wp_verdict v; struct wp_verdict_up u; uint32_t type; } m;
        union { char b[CMSG_SPACE(sizeof(int))]; struct cmsghdr al; } cb;
        struct iovec iv = { &m, sizeof m };
        struct msghdr mh = { .msg_iov = &iv, .msg_iovlen = 1, .msg_control = cb.b, .msg_controllen = sizeof cb.b };
        ssize_t n = recvmsg(ctl, &mh, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (n == 0) return -1;
        if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
        int fd = -1;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(sizeof(int)))
                memcpy(&fd, CMSG_DATA(c), sizeof fd);
        /* v1.26 review: a socket that could not be received (no descriptor
         * free) leaves an allow without one: refused below, and reported */
        bool ctrunc = mh.msg_flags & MSG_CTRUNC;
        if (n == (ssize_t)sizeof m.v && m.type == WP_MSG_VERDICT) {
            /* step 6: allow carries the socket the Warden dialed */
            int k = held_find(m.v.id);
            bool passed = m.v.allow && (fd >= 0 || ctrunc);  /* the Warden counted it open */
            if (k < 0 || g_held[k].state != WH_WAITING) {
                if (fd >= 0) close(fd);
                if (passed) report_gone(m.v.id);
                continue;
            }
            if (!m.v.allow || fd < 0 || held_relay(k, fd) < 0) {
                if (fd >= 0) close(fd);
                if (passed) report_gone(m.v.id);
                held_refuse(k);
            }
            continue;
        }
        if (n == (ssize_t)sizeof m.u && m.type == WP_MSG_VERDICT_UP) {
            /* section 5: allow, dialed to the upstream proxy */
            int k = held_find(m.u.id);
            bool passed = m.u.allow && (fd >= 0 || ctrunc);
            if (k < 0 || g_held[k].state != WH_WAITING || fd < 0 || m.u.port == 0 || m.u.port > 65535 ||
                !memchr(m.u.name, 0, sizeof m.u.name)) {
                if (fd >= 0) close(fd);
                if (passed) report_gone(m.u.id);
                if (k >= 0 && g_held[k].state == WH_WAITING) held_refuse(k);
                continue;
            }
            if (!m.u.allow || fd < 0 || held_relay_up(k, fd, m.u.name, m.u.port) < 0) {
                if (g_held[k].state == WH_UPSTREAM || g_held[k].up >= 0) {
                    g_held[k].state = WH_UPSTREAM;     /* reported as upstream_refused */
                    held_refuse(k);
                } else {
                    if (fd >= 0) close(fd);
                    held_refuse(k);
                }
            }
            continue;
        }
        if (fd >= 0) close(fd);
        if (n == (ssize_t)sizeof(struct wp_msg) && m.type == WP_MSG_FLUSH) {
            /* the run is ending: close everything, reporting each relay */
            while (g_nheld) {
                if (g_held[g_nheld - 1].state == WH_RELAY || g_held[g_nheld - 1].state == WH_UPSTREAM)
                    g_held[g_nheld - 1].why = "run_end";
                held_drop(g_nheld - 1);
            }
            struct wp_msg f = { .type = WP_MSG_FLUSHED, .port = 0 };
            (void)send(ctl, &f, sizeof f, MSG_NOSIGNAL);
            continue;
        }
        if (n != (ssize_t)sizeof m.c || m.type != WP_MSG_CONN || m.c.from_port == 0 || m.c.from_port > 65535)
            continue;                                   /* not one the Warden sends */
        if (!memchr(m.c.dest, 0, sizeof m.c.dest)) continue;
        const char *colon = strrchr(m.c.dest, ':');
        unsigned long dpl = colon ? strtoul(colon + 1, NULL, 10) : 0;
        if (dpl == 0 || dpl > 65535) continue;
        unsigned dport = (unsigned)dpl;
        int64_t now = mono_ms();
        int slot = -1, oldest = 0;
        for (int k = 0; k < WP_MAX_ANNOUNCED; k++) {
            if (g_ann[k].used && (now - g_ann[k].at > WP_ANNOUNCE_MS || g_ann[k].from_port == m.c.from_port))
                g_ann[k].used = false;                  /* expired, or its port is reused */
            if (!g_ann[k].used && slot < 0) slot = k;
            if (g_ann[k].at < g_ann[oldest].at) oldest = k;
        }
        if (slot < 0) slot = oldest;                    /* full: the oldest goes */
        g_ann[slot] = (struct wp_ann){ .used = true, .from_port = m.c.from_port, .dport = dport,
                                       .id = m.c.id, .at = now };
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
    if (found < 0 || g_nheld >= g_max_held) { close(c); return; }
    g_ann[found].used = false;
    g_held[g_nheld++] = (struct wp_held){ .fd = c, .id = g_ann[found].id, .dport = g_ann[found].dport,
                                          .state = WH_READING, .since = now, .up = -1 };
}

/* Bytes arrived on held connection k (READING): read them and parse. */
static void held_read(int k) {
    struct wp_held *h = &g_held[k];
    if (!h->buf && !(h->buf = malloc(PP_IN_MAX))) { held_drop(k); return; }
    ssize_t n = recv(h->fd, h->buf + h->len, PP_IN_MAX - h->len, MSG_DONTWAIT);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
    if (n <= 0) {
        report(h, WP_MSG_UNREADABLE, NULL, h->len ? "closed before a whole request" : "closed before sending");
        held_drop(k);
        return;
    }
    h->len += (size_t)n;
    pp_result_t r;
    pp_status_t st = pp_parse(h->buf, h->len, h->dport, h->acked, &r);
    if (r.kind != PP_KIND_NONE) h->kind = r.kind;
    if (st == PP_MORE && h->len == PP_IN_MAX) { st = PP_REFUSE; r.why = "too much before a decision"; }
    if (st == PP_MORE) return;
    if (st == PP_ACK) {
        static const char ok[] = "HTTP/1.1 200 Connection established\r\n\r\n";
        if (send(h->fd, ok, sizeof ok - 1, MSG_DONTWAIT | MSG_NOSIGNAL) != (ssize_t)sizeof ok - 1) {
            report(h, WP_MSG_UNREADABLE, NULL, "could not answer the CONNECT");
            held_drop(k);
            return;
        }
        h->acked = true;
        return;
    }
    if (st == PP_REFUSE) {
        report(h, WP_MSG_UNREADABLE, NULL, r.why);
        held_refuse(k);
        return;
    }
    report(h, WP_MSG_REQUEST, &r, NULL);
    snprintf(h->name, sizeof h->name, "%s", r.name);       /* later requests must name it too */
    if (r.kind == PP_KIND_CONNECT) h->skip = r.connect_len;   /* the server gets what follows it */
    h->state = WH_WAITING;
    h->since = mono_ms();
}

int wp_helper_main(int ctl) {
    signal(SIGPIPE, SIG_IGN);
    g_ctl = ctl;
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
    static struct pollfd pf[2 + 2 * WP_MAX_HELD];
    static int pfc[WP_MAX_HELD], pfs[WP_MAX_HELD];   /* each held connection's fds as polled */
    /* v1.26 review: room for every held connection's two sockets, beyond
     * the inherited limit (often 1024); held connections are capped to it */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rlim_t want = 2 * WP_MAX_HELD + 64;
        if (rl.rlim_cur < want) {
            rl.rlim_cur = rl.rlim_max < want ? rl.rlim_max : want;
            (void)setrlimit(RLIMIT_NOFILE, &rl);
            (void)getrlimit(RLIMIT_NOFILE, &rl);
        }
        long cap = ((long)rl.rlim_cur - 64) / 2;
        g_max_held = cap < 1 ? 1 : cap < WP_MAX_HELD ? (int)cap : WP_MAX_HELD;
    }
    int reserve = open("/dev/null", O_RDONLY | O_CLOEXEC);   /* freed to refuse a connection at EMFILE */
    int64_t listen_pause = 0;
    for (;;) {
        pf[0] = (struct pollfd){ .fd = ctl, .events = POLLIN };
        pf[1] = (struct pollfd){ .fd = ls, .events = POLLIN };
        int nh = g_nheld;
        for (int k = 0; k < nh; k++) {
            struct wp_held *h = &g_held[k];
            short ce = 0, se = 0;
            if (h->state == WH_READING) ce = POLLIN;
            else if (h->state == WH_RELAY) {
                if (!h->eof_c && h->len < PP_IN_MAX) ce |= POLLIN;
                if (h->doff < h->dlen) ce |= POLLOUT;
                if (!h->eof_s && h->dlen < WP_RELAY_BUF) se |= POLLIN;
                if (h->off < h->len) se |= POLLOUT;
            }
            if (h->state == WH_UPSTREAM) se = POLLIN;
            pfc[k] = h->fd;
            pfs[k] = h->state == WH_RELAY || h->state == WH_UPSTREAM ? h->up : -1;
            /* v1.26 review: a relay side that can make no progress is not
             * polled at all (its POLLHUP or POLLERR would wake the loop at
             * once, again and again); the relay is still visited each pass */
            bool relay = h->state == WH_RELAY || h->state == WH_UPSTREAM;
            pf[2 + 2 * k] = (struct pollfd){ .fd = relay && !ce ? -1 : pfc[k], .events = ce };
            pf[3 + 2 * k] = (struct pollfd){ .fd = relay && !se ? -1 : pfs[k], .events = se };
        }
        pf[1].fd = mono_ms() < listen_pause ? -1 : ls;
        if (poll(pf, (nfds_t)(2 + 2 * nh), 1000) < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        if (pf[0].revents && wp_drain_ctl(ctl) < 0) return 0;      /* the Warden went */
        /* Held connections first (by fd: a verdict above may have dropped
         * some, moving others), then new ones. */
        int64_t now = mono_ms();
        for (int j = 0; j < nh; j++) {
            int cfd = pfc[j], k = -1;
            for (int x = 0; x < g_nheld; x++) if (g_held[x].fd == cfd) { k = x; break; }
            if (k < 0) continue;
            struct wp_held *h = &g_held[k];
            short crev = pf[2 + 2 * j].revents, srev = pf[3 + 2 * j].revents;
            if (h->state == WH_UPSTREAM) {
                bool ok = pfs[j] != h->up || !(srev & (POLLIN | POLLHUP | POLLERR)) || held_upstream(k);
                if (ok && h->state == WH_UPSTREAM && now - h->since > WP_READ_MS) ok = false;
                if (!ok) held_refuse(k);                            /* reported, then refused */
                continue;
            }
            if (h->state == WH_RELAY) {
                if (pfs[j] != h->up) { srev = 0; crev = 0; }   /* became a relay just now */
                if (!held_pump(k, crev, srev)) held_drop(k);
                continue;
            }
            if (h->state == WH_READING && (crev & (POLLIN | POLLHUP | POLLERR))) {
                held_read(k);
                /* v1.26 review: the deadline holds for a client that sends
                 * a byte at a time, too */
                k = -1;
                for (int x = 0; x < g_nheld; x++) if (g_held[x].fd == cfd) { k = x; break; }
                if (k < 0 || g_held[k].state != WH_READING) continue;
                h = &g_held[k];
            }
            if (h->state == WH_READING && now - h->since > WP_READ_MS) {
                report(h, WP_MSG_UNREADABLE, NULL, "no whole request within 10 s");
                held_refuse(k);
            } else if (h->state == WH_WAITING && (crev & (POLLHUP | POLLERR))) {
                held_drop(k);                                       /* the client went */
            } else if (h->state == WH_WAITING && now - h->since > WP_VERDICT_MS) {
                held_refuse(k);                                     /* no verdict: refused */
            }
        }
        if (pf[1].revents & POLLIN) {
            /* The Warden announces a connection before making it: read the
             * control socket again first, so its announcement is here. */
            if (wp_drain_ctl(ctl) < 0) return 0;
            for (;;) {
                struct sockaddr_in peer;
                socklen_t pl = sizeof peer;
                memset(&peer, 0, sizeof peer);
                int c2 = accept4(ls, (struct sockaddr *)&peer, &pl, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (c2 < 0 && (errno == EMFILE || errno == ENFILE) && reserve >= 0) {
                    /* v1.26 review: no descriptor free: refuse the
                     * connection (the agent's connect fails rather than
                     * hangs) with the one held in reserve */
                    close(reserve);
                    c2 = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
                    if (c2 >= 0) close(c2);
                    reserve = open("/dev/null", O_RDONLY | O_CLOEXEC);
                    if (reserve < 0) listen_pause = mono_ms() + 100;
                    continue;
                }
                if (c2 < 0) break;
                wp_accepted(c2, &peer);
            }
        }
    }
}
