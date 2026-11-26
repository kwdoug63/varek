/* SPDX-License-Identifier: MIT
 * warden_notify_helper.c — v1.42 step 7: warden-notify, the helper that
 * posts each proposed grant of a `step_up ... notify=URL` rule to its
 * webhook (docs/security/v1.42-step-up-defer.md, "Notification"). The
 * messages are warden_notify.h's.
 *
 * Started by the Warden as root with the user to run as ("UID:GID"), its
 * socket on fd 3. It drops to that user at once (no capabilities, no new
 * privileges, not dumpable) and then:
 *   - for each wn_post, a child of its own posts the body (one HTTP/1.1
 *     POST, Content-Type application/json; no redirect followed), each
 *     attempt within WN_TIMEOUT_MS; an attempt that fails (no connection,
 *     TLS refused, no answer in time, an answer other than 2xx) is made
 *     again once, WN_RETRY_MS later; the outcome is one wn_result;
 *   - https:// is verified against the host's trust store (OpenSSL's
 *     default paths; SSL_CERT_FILE and SSL_CERT_DIR, when the Warden was
 *     given them, are passed on), with the URL's host checked against the
 *     certificate (its name, or its address for a literal address) and
 *     sent as SNI for a name; http:// only to a literal loopback address;
 *   - when the socket ends (the Warden's run is over), its posts still
 *     being made are ended and it exits.
 * It holds no secret beyond the URLs it is sent, and it can approve
 * nothing: the Warden reads only its outcomes, for the record.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "warden_notify.h"
#include "varek_fips.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

static int g_ctl = 3;

static long long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

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

/* As warden-secrets' drop_to: the user, no supplementary groups, no
 * capability in any set, the bounding set empty, no new privileges */
static int drop_to(uid_t u, gid_t g) {
    if (setgroups(0, NULL) < 0) return -1;
    for (int cap = 0; cap <= 63; cap++)
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno != EINVAL) return -1;
    (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    if (setresgid(g, g, g) < 0 || setresuid(u, u, u) < 0) return -1;
    struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    if (syscall(SYS_capset, &hdr, data) != 0) return -1;
    if (syscall(SYS_capget, &hdr, data) != 0) return -1;
    for (int i = 0; i < 2; i++)
        if (data[i].effective || data[i].permitted || data[i].inheritable) { errno = EPERM; return -1; }
    if (getuid() != u || geteuid() != u || getgid() != g || getegid() != g) { errno = EPERM; return -1; }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0) return -1;
    return 0;
}

/* a why: printable ASCII only */
static void why_set(char *why, size_t wn, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void why_set(char *why, size_t wn, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(why, wn, fmt, ap);
    va_end(ap);
    for (char *c = why; *c; c++)
        if ((unsigned char)*c < 0x20 || (unsigned char)*c > 0x7e || *c == '"' || *c == '\\') *c = '?';
}

static int left_ms(long long end) {
    long long l = end - mono_ms();
    return l <= 0 ? 0 : (int)l;
}

static int tcp_connect(const struct wn_url *u, long long end, char *why, size_t wn) {
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res = NULL;
    int e = getaddrinfo(u->host, u->port, &hints, &res);
    if (e) { why_set(why, wn, "%.100s: %s", u->host, gai_strerror(e)); return -1; }
    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, a->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        if (errno == EINPROGRESS) {
            struct pollfd pf = { .fd = fd, .events = POLLOUT };
            int soerr = 0;
            socklen_t sl = sizeof soerr;
            if (left_ms(end) > 0 && poll(&pf, 1, left_ms(end)) == 1 &&
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 && soerr == 0)
                break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { why_set(why, wn, "cannot connect to %.100s port %s", u->host, u->port); return -1; }
    int fl = fcntl(fd, F_GETFL);
    (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    int ms = left_ms(end) > 0 ? left_ms(end) : 1;
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return fd;
}

/* One POST: the answer's status (0: none), or -1 with why */
static int post_once(const struct wn_url *u, const char *body, size_t bl, int *status, char *why, size_t wn) {
    *status = 0;
    long long end = mono_ms() + WN_TIMEOUT_MS;
    int fd = tcp_connect(u, end, why, wn);
    if (fd < 0) return -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int rc = -1;
    if (u->tls) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) || SSL_CTX_set_default_verify_paths(ctx) != 1) {
            why_set(why, wn, "TLS setup failed (the host's trust store)");
            goto done;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        ssl = SSL_new(ctx);
        unsigned char ab[16];
        bool lit = inet_pton(AF_INET, u->host, ab) == 1 || inet_pton(AF_INET6, u->host, ab) == 1;
        if (!ssl || SSL_set_fd(ssl, fd) != 1 ||
            (lit ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), u->host) != 1
                 : SSL_set_tlsext_host_name(ssl, u->host) != 1 || SSL_set1_host(ssl, u->host) != 1)) {
            why_set(why, wn, "TLS setup failed");
            goto done;
        }
        if (SSL_connect(ssl) != 1) {
            long vr = SSL_get_verify_result(ssl);
            why_set(why, wn, "TLS to %.100s failed: %s", u->host,
                    vr != X509_V_OK ? X509_verify_cert_error_string(vr) : "the handshake");
            goto done;
        }
    }
    char head[WN_URL_MAX + 600];
    bool defport = (u->tls && !strcmp(u->port, "443")) || (!u->tls && !strcmp(u->port, "80"));
    bool v6 = strchr(u->host, ':') != NULL;
    int hn = snprintf(head, sizeof head,
                      "POST %s HTTP/1.1\r\nHost: %s%s%s%s%s\r\nUser-Agent: varek-warden-notify/1\r\n"
                      "Content-Type: application/json; charset=utf-8\r\nContent-Length: %zu\r\n"
                      "Connection: close\r\n\r\n",
                      u->path, v6 ? "[" : "", u->host, v6 ? "]" : "", defport ? "" : ":", defport ? "" : u->port, bl);
    if (hn < 0 || (size_t)hn >= sizeof head) { why_set(why, wn, "the request is too long"); goto done; }
    for (int part = 0; part < 2; part++) {
        const char *p = part ? body : head;
        size_t n = part ? bl : (size_t)hn, off = 0;
        while (off < n) {
            int w = u->tls ? SSL_write(ssl, p + off, (int)(n - off)) : (int)send(fd, p + off, n - off, MSG_NOSIGNAL);
            if (w <= 0) { why_set(why, wn, "sending to %.100s failed", u->host); goto done; }
            off += (size_t)w;
        }
    }
    char buf[4096];
    size_t got = 0;
    while (got < sizeof buf - 1 && !memmem(buf, got, "\r\n", 2)) {
        if (left_ms(end) <= 0) break;
        int r = u->tls ? SSL_read(ssl, buf + got, (int)(sizeof buf - 1 - got)) : (int)recv(fd, buf + got, sizeof buf - 1 - got, 0);
        if (r <= 0) break;
        got += (size_t)r;
    }
    buf[got] = '\0';
    if (got < 12 || strncmp(buf, "HTTP/1.", 7) || buf[8] != ' ' || buf[9] < '1' || buf[9] > '5' ||
        buf[10] < '0' || buf[10] > '9' || buf[11] < '0' || buf[11] > '9') {
        why_set(why, wn, "%.100s sent no HTTP answer in time", u->host);
        goto done;
    }
    *status = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
    rc = 0;
done:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
    ERR_clear_error();
    close(fd);
    return rc;
}

/* In a child: the post, retried once; its result to the Warden */
static void post(const struct wn_post *m, const char *url, const char *body) {
    struct wn_result r = { .type = WN_MSG_RESULT };
    memcpy(r.id, m->id, sizeof r.id);
    struct wn_url u;
    if (wn_url_parse(url, &u) < 0) {
        why_set(r.why, sizeof r.why, "not a URL this helper posts to");
    } else {
        for (int a = 1; a <= 2; a++) {
            if (a == 2) {
                struct timespec ts = { .tv_sec = WN_RETRY_MS / 1000, .tv_nsec = (WN_RETRY_MS % 1000) * 1000000L };
                while (nanosleep(&ts, &ts) < 0 && errno == EINTR) { }
            }
            r.attempts = a;
            char why[sizeof r.why];
            why[0] = '\0';
            int st = 0;
            int rc = post_once(&u, body, m->body_len, &st, why, sizeof why);
            r.status = st;
            if (rc == 0 && st >= 200 && st <= 299) { r.sent = 1; r.why[0] = '\0'; break; }
            if (rc == 0) why_set(r.why, sizeof r.why, "%.100s answered %d", u.host, st);
            else memcpy(r.why, why, sizeof r.why);
        }
    }
    r.why[sizeof r.why - 1] = '\0';
    (void)send(g_ctl, &r, sizeof r, MSG_NOSIGNAL);
}

struct inflight { pid_t pid; char id[17]; };
static struct inflight g_in[WN_MAX_INFLIGHT];
static size_t g_nin;

static void answer_failed(const char *id, const char *why) {
    struct wn_result r = { .type = WN_MSG_RESULT };
    memcpy(r.id, id, sizeof r.id);
    r.id[sizeof r.id - 1] = '\0';
    why_set(r.why, sizeof r.why, "%s", why);
    (void)send(g_ctl, &r, sizeof r, MSG_NOSIGNAL);
}

static void reap(void) {
    int st;
    pid_t k;
    while ((k = waitpid(-1, &st, WNOHANG)) > 0)
        for (size_t i = 0; i < g_nin; i++)
            if (g_in[i].pid == k) {
                if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
                    answer_failed(g_in[i].id, "the post's process ended without an outcome");
                g_in[i] = g_in[--g_nin];
                break;
            }
}

static void end_all(void) {
    for (size_t i = 0; i < g_nin; i++) kill(g_in[i].pid, SIGKILL);
    while (g_nin) {
        int st;
        pid_t k = waitpid(-1, &st, 0);
        if (k < 0 && errno != EINTR) break;
        for (size_t i = 0; k > 0 && i < g_nin; i++)
            if (g_in[i].pid == k) { g_in[i] = g_in[--g_nin]; break; }
    }
}

int main(int argc, char **argv) {
    uid_t u;
    gid_t g;
    if (argc != 2 || parse_ids(argv[1], &u, &g) < 0 || fcntl(3, F_GETFD) < 0 || geteuid() != 0) {
        fprintf(stderr, "warden-notify: the Warden starts this program (v1.42 notify=); it is not run by hand\n");
        return 2;
    }
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    (void)signal(SIGPIPE, SIG_IGN);
    /* v1.41's crypto backend: the host's OpenSSL configuration (system
     * crypto policy, the FIPS provider in FIPS mode; the Defense build
     * refuses to run without it), then the drop */
    char cwhy[256] = {0};
    if (vfips_init(0, cwhy, sizeof cwhy) != 0) return 2;
    if (drop_to(u, g) < 0) return 2;
    pid_t self = getpid();
    static unsigned char msg[sizeof(struct wn_post) + WN_URL_MAX + 1 + WN_BODY_MAX + 1];
    for (;;) {
        reap();
        struct pollfd pf = { .fd = g_ctl, .events = POLLIN };
        int pr = poll(&pf, 1, g_nin ? 200 : 1000);
        if (pr < 0 && errno != EINTR) break;
        if (pr <= 0) continue;
        ssize_t n = recv(g_ctl, msg, sizeof msg, MSG_TRUNC);
        if (n == 0) break;                                   /* the Warden's run is over */
        if (n < 0) { if (errno == EINTR) continue; break; }
        struct wn_post m;
        if ((size_t)n < sizeof m || (size_t)n > sizeof msg) continue;
        memcpy(&m, msg, sizeof m);
        if (m.type != WN_MSG_POST || !memchr(m.id, '\0', sizeof m.id) || m.url_len == 0 || m.url_len > WN_URL_MAX ||
            m.body_len > WN_BODY_MAX || (size_t)n != sizeof m + m.url_len + m.body_len)
            continue;
        char url[WN_URL_MAX + 1];
        memcpy(url, msg + sizeof m, m.url_len);
        url[m.url_len] = '\0';
        char *body = (char *)msg + sizeof m + m.url_len;
        if (g_nin == WN_MAX_INFLIGHT) { answer_failed(m.id, "too many posts at once"); continue; }
        pid_t k = fork();
        if (k < 0) { answer_failed(m.id, "cannot start the post"); continue; }
        if (k == 0) {
            (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
            if (getppid() != self) _exit(1);
            post(&m, url, body);
            _exit(0);
        }
        g_in[g_nin].pid = k;
        memcpy(g_in[g_nin].id, m.id, sizeof g_in[g_nin].id);
        g_nin++;
    }
    end_all();
    return 0;
}
