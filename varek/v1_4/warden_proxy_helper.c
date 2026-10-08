// SPDX-License-Identifier: MIT
// warden_proxy_helper.c — v1.26: the egress proxy process (v1.26.1: its own
// binary, warden-proxy, which the Warden starts; see warden_proxy.h). It
// reads what clients send, reports names to the Warden over its control
// socket (descriptor 3), and relays the sockets the Warden passes back.

#include "warden_proxy.h"
#include "proxy_parse.h"
#include "proxy_ca.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int64_t mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* The proxy's state: announcements waiting for their connection, and the
 * connections it holds. A held connection is read (step 5) until the parser
 * has a name, then waits for the Warden's verdict. */
struct wp_ann  { bool used; uint32_t from_port; unsigned dport; uint64_t id; int64_t at; };
enum { WH_READING = 0, WH_WAITING = 1, WH_RELAY = 2, WH_UPSTREAM = 3, WH_TLS = 4 /* v1.26.1 */ };
/* v1.26.1, step 4: an inspected connection's stages: the server's handshake
 * (verified), then the client's (with a leaf from the run's CA), then its
 * first request, then the answer flushed */
enum { TS_SERVER = 0, TS_CLIENT = 1, TS_REQUEST = 2, TS_FLUSH = 3 };
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
    /* v1.26.1, step 4: inspecting mode */
    bool      inspect;           /* terminate its TLS */
    int       tstage;            /* TS_* */
    short     swant;             /* the server handshake waits for this (POLLIN, POLLOUT) */
    SSL      *ss, *cs;           /* toward the server (on up), toward the client (memory BIOs) */
    BIO      *crb, *cwb;         /* the client's TLS bytes in, out */
    uint8_t   server_cert[32];   /* SHA-256 of the server's certificate */
    char      tls_why[96];
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
    if (h->inspect) {                                /* v1.26.1 */
        m.inspected = 1;
        memcpy(m.server_cert, h->server_cert, sizeof m.server_cert);
        snprintf(m.tls_why, sizeof m.tls_why, "%s", h->tls_why);
    }
    (void)send(g_ctl, &m, sizeof m, MSG_NOSIGNAL);   /* blocking: a close report is never dropped */
}

static void held_drop(int k) {
    if (g_held[k].state == WH_UPSTREAM)            /* the run ended while asking the upstream */
        report_close(&g_held[k], g_held[k].why ? g_held[k].why : "upstream_refused");
    else if (g_held[k].state == WH_RELAY) report_close(&g_held[k], g_held[k].why ? g_held[k].why : "closed");
    else if (g_held[k].state == WH_TLS) report_close(&g_held[k], g_held[k].why ? g_held[k].why : "reset");
    if (g_held[k].ss && SSL_is_init_finished(g_held[k].ss))
        (void)SSL_shutdown(g_held[k].ss);            /* v1.26.1: a close_notify to the server */
    SSL_free(g_held[k].ss);                          /* (the client's SSL frees its BIOs) */
    SSL_free(g_held[k].cs);
    close(g_held[k].fd);
    if (g_held[k].up >= 0) close(g_held[k].up);
    free(g_held[k].buf);
    free(g_held[k].down);
    g_held[k] = g_held[--g_nheld];
}

/* v1.26.1: an inspected client whose handshake has not begun: a fatal
 * handshake_failure alert, in the clear */
static void held_refuse_alert(struct wp_held *h) {
    static const uint8_t alert[] = { 21, 3, 3, 0, 2, 2, 40 };
    (void)send(h->fd, alert, sizeof alert, MSG_DONTWAIT | MSG_NOSIGNAL);
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

static bool tls_begin(int k);                     /* v1.26.1, below */

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
    /* v1.26.1: an inspected connection: TLS to the server through the tunnel
     * (the server sends nothing before the ClientHello it is owed) */
    if (h->inspect) {
        if (h->dlen) { h->why = "server_tls"; snprintf(h->tls_why, sizeof h->tls_why, "the server spoke first"); }
        return h->dlen == 0 && tls_begin(k);
    }
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

/* v1.26.1: inspecting mode. The run's CA, made once, on WP_MSG_CA_GO. */
static pca_t g_ca;
static bool  g_inspect, g_ca_made;
static char  g_ca_run[48], g_ca_bundle[1024];
static char *g_ca_names[PCA_MAX_NAMES];
static size_t g_ca_nnames, g_ca_want;

static int send_blob(int ctl, uint32_t kind, const unsigned char *d, size_t n) {
    static struct wp_blob b;
    for (size_t off = 0; off < n; off += WP_BLOB_CHUNK) {
        memset(&b, 0, sizeof b);
        b.type = WP_MSG_BLOB;
        b.kind = kind;
        b.total = (uint32_t)n;
        b.off = (uint32_t)off;
        b.len = (uint32_t)(n - off < WP_BLOB_CHUNK ? n - off : WP_BLOB_CHUNK);
        memcpy(b.data, d + off, b.len);
        if (send(ctl, &b, sizeof b, MSG_NOSIGNAL) != (ssize_t)sizeof b) return -1;
    }
    return 0;
}

static void ca_go(int ctl) {
    struct wp_ca_done d;
    memset(&d, 0, sizeof d);
    d.type = WP_MSG_CA_DONE;
    unsigned char *pem = NULL, *p12 = NULL;
    size_t pl = 0, ql = 0;
    if (!g_inspect || g_ca_made || g_ca_nnames != g_ca_want)
        snprintf(d.why, sizeof d.why, "the setup messages were not as expected");
    else if (pca_init(&g_ca), pca_load_roots(&g_ca, g_ca_bundle, d.why, sizeof d.why) < 0) { }
    else if (pca_make_ca(&g_ca, g_ca_run, g_ca_names, g_ca_nnames, PCA_VALID_S, d.why, sizeof d.why) < 0) { }
    else if (pca_tls_init(&g_ca, d.why, sizeof d.why) < 0) { }     /* step 4 */
    else if (pca_pem(&g_ca, &pem, &pl) < 0 || pca_p12(&g_ca, &p12, &ql) < 0 || pl > WP_BLOB_MAX || ql > WP_BLOB_MAX)
        snprintf(d.why, sizeof d.why, "encoding the CA and the trust store");
    else if (send_blob(ctl, WP_BLOB_CA_PEM, pem, pl) < 0 || send_blob(ctl, WP_BLOB_P12, p12, ql) < 0)
        snprintf(d.why, sizeof d.why, "sending the CA to the Warden");
    else {
        d.ok = 1;
        d.secure_heap = (uint32_t)g_ca.secure_heap;
        d.nroots = (uint32_t)pca_nroots(&g_ca);
        g_ca_made = true;
    }
    free(pem);
    free(p12);
    (void)send(ctl, &d, sizeof d, MSG_NOSIGNAL);
}


/* ---- v1.26.1, step 4: terminating TLS on an inspected connection ---- */

static void tls_err(struct wp_held *h, const char *why, const char *what) {
    h->why = why;
    unsigned long e = ERR_get_error();
    char b[120] = "";
    if (e) ERR_error_string_n(e, b, sizeof b);
    const char *r = e ? ERR_reason_error_string(e) : NULL;
    snprintf(h->tls_why, sizeof h->tls_why, "%.40s%s%.50s", what, r || e ? ": " : "", r ? r : b);
    ERR_clear_error();
}

/* Move the client's TLS bytes: what OpenSSL wrote, out to the client; what
 * the client sent, in. -1 on an error sending; sets eof_c. */
static int tls_client_io(struct wp_held *h, short crev) {
    while (h->dlen < WP_RELAY_BUF && BIO_ctrl_pending(h->cwb) > 0) {
        int n = BIO_read(h->cwb, h->down + h->dlen, (int)(WP_RELAY_BUF - h->dlen));
        if (n <= 0) break;
        h->dlen += (size_t)n;
    }
    if (h->doff < h->dlen) {
        ssize_t n = send(h->fd, h->down + h->doff, h->dlen - h->doff, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
        if (n > 0) h->doff += (size_t)n;
        if (h->doff == h->dlen) h->doff = h->dlen = 0;
    }
    if (!h->eof_c && (crev & (POLLIN | POLLHUP | POLLERR))) {
        uint8_t b[16384];
        ssize_t n = recv(h->fd, b, sizeof b, MSG_DONTWAIT);
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) h->eof_c = true;
        else if (n > 0 && BIO_write(h->crb, b, (int)n) != (int)n) return -1;
    }
    return 0;
}

/* Start an inspected connection: the Warden dialed the server (h->up, after
 * the upstream's CONNECT if there is one). The server's handshake comes
 * first, so a server that cannot be verified never meets the client. */
static bool tls_begin(int k) {
    struct wp_held *h = &g_held[k];
    h->state = WH_TLS;
    h->tstage = TS_SERVER;
    h->swant = POLLOUT;
    h->since = h->relay_at = mono_ms();
    h->why = "server_tls";
    if (!g_ca_made || !(h->ss = SSL_new(g_ca.sctx)) || !SSL_set_fd(h->ss, h->up) ||
        !SSL_set_tlsext_host_name(h->ss, h->name) || !SSL_set1_host(h->ss, h->name)) {
        tls_err(h, "server_tls", "setting up TLS to the server");
        return false;
    }
    SSL_set_hostflags(h->ss, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    SSL_set_connect_state(h->ss);
    return true;
}

/* The server's certificate, as presented: its SHA-256. */
static void tls_note_cert(struct wp_held *h) {
    X509 *x = SSL_get0_peer_certificate(h->ss);
    unsigned char *der = NULL;
    int l = x ? i2d_X509(x, &der) : -1;
    unsigned int ml = 0;
    if (l > 0) (void)EVP_Digest(der, (size_t)l, h->server_cert, &ml, EVP_sha256(), NULL);
    OPENSSL_free(der);
}

#define NOT_BUILT_BODY "VAREK: this request was not sent; inspecting mode does not decide requests yet.\n"
static char kNotBuilt[256];                       /* the 403, its length computed (tls_step) */

/* One pass over inspected connection k. False when it is done (h->why says
 * why; held_drop reports it). */
static bool tls_step(int k, short crev, short srev) {
    struct wp_held *h = &g_held[k];
    if ((crev | srev) & POLLNVAL) { h->why = "reset"; return false; }
    if (h->tstage == TS_SERVER) {
        if (!(srev & (POLLIN | POLLOUT | POLLHUP | POLLERR)) && h->swant) return true;
        ERR_clear_error();
        int r = SSL_do_handshake(h->ss);
        if (r != 1) {
            int e = SSL_get_error(h->ss, r);
            if (e == SSL_ERROR_WANT_READ) { h->swant = POLLIN; return true; }
            if (e == SSL_ERROR_WANT_WRITE) { h->swant = POLLOUT; return true; }
            tls_note_cert(h);
            long v = SSL_get_verify_result(h->ss);
            if (v != X509_V_OK) {
                h->why = "server_tls";
                snprintf(h->tls_why, sizeof h->tls_why, "certificate: %s", X509_verify_cert_error_string(v));
                ERR_clear_error();
            } else tls_err(h, "server_tls", "handshake");
            held_refuse_alert(h);
            return false;
        }
        tls_note_cert(h);
        const unsigned char *ap = NULL;
        unsigned int al = 0;
        SSL_get0_alpn_selected(h->ss, &ap, &al);
        if (al && !(al == 8 && !memcmp(ap, "http/1.1", 8))) {
            h->why = "server_tls";
            snprintf(h->tls_why, sizeof h->tls_why, "the server chose a protocol other than http/1.1");
            held_refuse_alert(h);
            return false;
        }
        /* the client's handshake, from the ClientHello already read */
        char why[96];
        X509 *leaf = pca_leaf(&g_ca, h->name, why, sizeof why);
        h->crb = BIO_new(BIO_s_mem());
        h->cwb = BIO_new(BIO_s_mem());
        if (!leaf || !h->crb || !h->cwb || !(h->cs = SSL_new(g_ca.cctx))) {
            BIO_free(h->crb); BIO_free(h->cwb); h->crb = h->cwb = NULL;
            h->why = "client_tls";
            snprintf(h->tls_why, sizeof h->tls_why, "%s", leaf ? "setting up TLS to the client" : why);
            held_refuse_alert(h);
            return false;
        }
        SSL_set_bio(h->cs, h->crb, h->cwb);
        if (!SSL_use_certificate(h->cs, leaf) || !SSL_use_PrivateKey(h->cs, g_ca.leaf_key) ||
            BIO_write(h->crb, h->buf + h->skip, (int)(h->len - h->skip)) != (int)(h->len - h->skip)) {
            tls_err(h, "client_tls", "setting up TLS to the client");
            return false;
        }
        SSL_set_accept_state(h->cs);
        h->len = h->skip = h->off = h->fwd = 0;      /* buf now holds the client's plaintext */
        h->tstage = TS_CLIENT;
        h->since = mono_ms();
        crev |= POLLOUT;                              /* run the client's stage now */
    }
    if (tls_client_io(h, crev) < 0) { h->why = "reset"; return false; }
    if (h->tstage == TS_CLIENT) {
        ERR_clear_error();
        int r = SSL_do_handshake(h->cs);
        if (r == 1) {
            h->tstage = TS_REQUEST;
            h->since = mono_ms();
        } else {
            int e = SSL_get_error(h->cs, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                tls_err(h, "client_tls", "handshake");
                (void)tls_client_io(h, 0);            /* its alert */
                return false;
            }
            if (h->eof_c) {
                h->why = "client_tls";
                snprintf(h->tls_why, sizeof h->tls_why, "the client closed during the handshake");
                return false;
            }
        }
    }
    if (h->tstage == TS_REQUEST) {
        /* step 4: the first request's head is read, then answered 403 (step
         * 6 decides each request instead); nothing reaches the server */
        for (;;) {
            ERR_clear_error();
            int r = SSL_read(h->cs, h->buf + h->len, (int)(PP_HTTP_MAX - h->len));
            if (r > 0) { h->len += (size_t)r; if (h->len < PP_HTTP_MAX) continue; }
            break;
        }
        bool head = h->len >= PP_HTTP_MAX || memmem(h->buf, h->len, "\r\n\r\n", 4) != NULL;
        if (!head && !h->eof_c) return true;
        h->why = "inspect_not_built";
        if (!kNotBuilt[0])
            snprintf(kNotBuilt, sizeof kNotBuilt, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s", sizeof NOT_BUILT_BODY - 1, NOT_BUILT_BODY);
        (void)SSL_write(h->cs, kNotBuilt, (int)strlen(kNotBuilt));
        (void)SSL_shutdown(h->cs);
        h->tstage = TS_FLUSH;
        if (tls_client_io(h, 0) < 0) return false;
    }
    if (h->tstage == TS_FLUSH)
        return BIO_ctrl_pending(h->cwb) > 0 || h->doff < h->dlen;
    return true;
}

/* Read every control message waiting. Returns -1 when the Warden has gone. */
static int wp_drain_ctl(int ctl) {
    for (;;) {
        union { struct wp_conn c; struct wp_verdict v; struct wp_verdict_up u; struct wp_inspect in;
                struct wp_ca_name cn; uint32_t type; } m;
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
            /* v1.26.1: inspect, only with the run's CA made */
            g_held[k].inspect = m.v.allow && m.v.inspect;
            if (!m.v.allow || fd < 0 || held_relay(k, fd) < 0) {
                if (fd >= 0) close(fd);
                if (passed) report_gone(m.v.id);
                g_held[k].inspect = false;
                held_refuse(k);
            } else if (g_held[k].inspect && !tls_begin(k)) {
                held_drop(k);                       /* reported: server_tls */
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
            g_held[k].inspect = m.u.allow && m.u.inspect;     /* v1.26.1 */
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
        /* v1.26.1: inspecting mode's setup (once, before the agent runs) */
        if (n == (ssize_t)sizeof m.in && m.type == WP_MSG_INSPECT && !g_inspect) {
            if (!memchr(m.in.run_id, 0, sizeof m.in.run_id) || !memchr(m.in.bundle, 0, sizeof m.in.bundle) ||
                m.in.nnames > PCA_MAX_NAMES)
                continue;
            g_inspect = true;
            memcpy(g_ca_run, m.in.run_id, sizeof g_ca_run);
            memcpy(g_ca_bundle, m.in.bundle, sizeof g_ca_bundle);
            g_ca_want = m.in.nnames;
            continue;
        }
        if (n == (ssize_t)sizeof m.cn && m.type == WP_MSG_CA_NAME) {
            if (g_inspect && !g_ca_made && g_ca_nnames < g_ca_want && memchr(m.cn.name, 0, sizeof m.cn.name) &&
                (g_ca_names[g_ca_nnames] = strdup(m.cn.name)) != NULL)
                g_ca_nnames++;
            continue;
        }
        if (n == (ssize_t)sizeof(struct wp_msg) && m.type == WP_MSG_CA_GO) { ca_go(ctl); continue; }
        if (n == (ssize_t)sizeof(struct wp_msg) && m.type == WP_MSG_FLUSH) {
            /* the run is ending: close everything, reporting each relay */
            while (g_nheld) {
                if (g_held[g_nheld - 1].state == WH_RELAY || g_held[g_nheld - 1].state == WH_UPSTREAM ||
                    g_held[g_nheld - 1].state == WH_TLS)
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
    /* v1.26.1: not dumpable, so no process of the proxy's own user can read
     * its memory (where the run's CA key is) or take a core of it */
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
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
            if (h->state == WH_TLS) {                   /* v1.26.1 */
                if (h->tstage == TS_SERVER) se = h->swant;
                else {
                    if (!h->eof_c && h->tstage != TS_FLUSH) ce |= POLLIN;
                    if (h->doff < h->dlen || BIO_ctrl_pending(h->cwb) > 0) ce |= POLLOUT;
                }
            }
            pfc[k] = h->fd;
            pfs[k] = h->state == WH_RELAY || h->state == WH_UPSTREAM || h->state == WH_TLS ? h->up : -1;
            /* v1.26 review: a relay side that can make no progress is not
             * polled at all (its POLLHUP or POLLERR would wake the loop at
             * once, again and again); the relay is still visited each pass */
            bool relay = h->state == WH_RELAY || h->state == WH_UPSTREAM || h->state == WH_TLS;
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
            if (h->state == WH_TLS) {                       /* v1.26.1 */
                if (pfs[j] != h->up) { srev = h->swant; crev = 0; }   /* began just now */
                bool ok = tls_step(k, crev, srev);
                if (ok && now - h->since > WP_READ_MS) {
                    h->why = "tls_timeout";
                    ok = false;
                }
                if (!ok) held_drop(k);
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

/* v1.26.1: warden-proxy UID:GID, started by the Warden (as root) with its
 * control socket as descriptor 3. It drops to UID:GID at once (no
 * supplementary groups, an empty bounding set, no capabilities,
 * no-new-privileges), then serves. Run any other way, it exits. */
static int parse_ids(const char *s, uid_t *u, gid_t *g) {
    char *e;
    unsigned long a = strtoul(s, &e, 10);
    if (e == s || *e != ':') return -1;
    const char *t = e + 1;
    unsigned long b = strtoul(t, &e, 10);
    if (e == t || *e || a == 0 || b == 0 || a > 0xfffffffeUL || b > 0xfffffffeUL) return -1;
    *u = (uid_t)a;
    *g = (gid_t)b;
    return 0;
}

static int drop_to(uid_t u, gid_t g) {
    if (setgroups(0, NULL) < 0) return -1;
    for (int cap = 0; cap <= 63; cap++)
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno != EINVAL) return -1;
    (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    if (setresgid(g, g, g) < 0 || setresuid(u, u, u) < 0) return -1;
    struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    if (syscall(SYS_capget, &hdr, data) != 0) return -1;
    for (int i = 0; i < 2; i++)
        if (data[i].effective || data[i].permitted || data[i].inheritable) { errno = EPERM; return -1; }
    if (getuid() != u || geteuid() != u || getgid() != g || getegid() != g) { errno = EPERM; return -1; }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    return 0;
}

int main(int argc, char **argv) {
    uid_t u;
    gid_t g;
    int fl;
    if (argc != 2 || parse_ids(argv[1], &u, &g) < 0 || (fl = fcntl(3, F_GETFD)) < 0) {
        fprintf(stderr, "warden-proxy: the Warden starts this program (v1.26 egress proxy); "
                "it is not run by hand\n");
        return 2;
    }
    if (drop_to(u, g) < 0) {
        fprintf(stderr, "[proxy] cannot drop to %s (%s)\n", argv[1], strerror(errno));
        return 2;
    }
    return wp_helper_main(3);
}
