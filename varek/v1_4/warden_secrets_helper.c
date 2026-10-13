// SPDX-License-Identifier: MIT
// warden_secrets_helper.c — v1.28: warden-secrets, the helper that fetches
// the credentials a policy names (docs/security/v1.28-credential-release.md,
// section 2; the messages are in warden_secrets.h).
//
// The Warden starts it as root, with its control socket as descriptor 3.
// As root it reads only local files: its configuration and each file store,
// each of which must be a regular file owned by root and readable by no
// group or other user. Then it drops to its own user (no groups, no
// capabilities, no-new-privileges, not dumpable) and fetches each network
// store over HTTPS, verified against the host's trust store or the CA the
// configuration names. Plain HTTP only to a loopback address, or to the
// instance metadata service for AWS credentials.
//
// Values are kept in one locked, non-dumped arena, never sent to the
// Warden, never written; when the control socket closes they are cleared.
//
// The configuration (the Warden's --secrets-conf, default
// /etc/varek/secrets.conf), one `key = value` a line, `#` comments:
//   vault_addr            https://vault.example.com:8200 (or http://127.0.0.1:8200)
//   vault_token_file      a file holding the Vault token (root-owned, 0600/0400)
//   vault_ca              a PEM CA bundle to verify Vault with (else the host's)
//   aws_region            the region (else the ARN's)
//   aws_endpoint          https://... (else https://secretsmanager.REGION.amazonaws.com)
//   aws_ca                a PEM CA bundle to verify the endpoint with (else the host's)
//   aws_credentials_file  aws_access_key_id, aws_secret_access_key and optionally
//                         aws_session_token, `key = value` (else the instance's role,
//                         through the metadata service, IMDSv2)
//   aws_imds              the metadata service's base URL (default http://169.254.169.254)

#include "warden_secrets.h"

#include <ctype.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define STORE_FILE  1                 /* VDP_CRED_* in smt_decide.h */
#define STORE_VAULT 2
#define STORE_AWSSM 3

#define RESP_MAX    (1u << 20)        /* a store's response, at most 1 MiB */
#define IO_TIMEOUT_MS 10000

static int g_ctl = 3;

/* ---- the arena: every value, locked and not dumped ---- */

static unsigned char *g_arena;
static size_t g_arena_len;
static struct { size_t off, len; } g_val[WS_MAX_CREDS];

static int arena_init(void) {
    g_arena_len = (size_t)WS_MAX_CREDS * WS_MAX_VALUE;
    g_arena = mmap(NULL, g_arena_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_arena == MAP_FAILED) { g_arena = NULL; return -1; }
    if (mlock(g_arena, g_arena_len) < 0) return -1;
    (void)madvise(g_arena, g_arena_len, MADV_DONTDUMP);
    return 0;
}

static void arena_clear(void) {
    if (g_arena) OPENSSL_cleanse(g_arena, g_arena_len);
}

/* A value goes in one header: 1 to WS_MAX_VALUE bytes, no CR, LF or NUL. */
static const char *value_store(unsigned idx, const unsigned char *v, size_t n) {
    if (n == 0) return "the value is empty";
    if (n > WS_MAX_VALUE) return "the value is longer than 8192 bytes";
    for (size_t i = 0; i < n; i++)
        if (v[i] == '\r' || v[i] == '\n' || v[i] == '\0')
            return "the value holds a CR, LF or NUL byte (it goes in one header)";
    g_val[idx].off = (size_t)idx * WS_MAX_VALUE;
    g_val[idx].len = n;
    memcpy(g_arena + g_val[idx].off, v, n);
    return NULL;
}

/* ---- messages ---- */

static bool ctl_send(const void *m, size_t n) {
    ssize_t r;
    while ((r = send(g_ctl, m, n, MSG_NOSIGNAL)) < 0 && errno == EINTR) { }
    return r == (ssize_t)n;
}

static void report_file(const char *path) {
    struct ws_file f;
    memset(&f, 0, sizeof f);
    f.type = WS_MSG_FILE;
    snprintf(f.path, sizeof f.path, "%s", path);
    ctl_send(&f, sizeof f);
}

static void report(unsigned idx, bool ok, const char *version, size_t len, const char *why) {
    struct ws_result r;
    memset(&r, 0, sizeof r);
    r.type = WS_MSG_RESULT;
    r.index = idx;
    r.ok = ok;
    r.len = (uint32_t)len;
    if (version) snprintf(r.version, sizeof r.version, "%s", version);
    if (why) snprintf(r.why, sizeof r.why, "%s", why);
    ctl_send(&r, sizeof r);
}

/* ---- local files (as root) ---- */

/* Read a file that must be regular, owned by root and readable by no group
 * or other user, into buf (at most cap bytes). The path is reported to the
 * Warden. 0, or -1 with why. */
static int read_private(const char *path, unsigned char *buf, size_t cap, size_t *len, struct stat *out,
                        char *why, size_t wn) {
    report_file(path);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0) { snprintf(why, wn, "cannot open %s: %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        snprintf(why, wn, "%s is not a regular file", path);
        close(fd);
        return -1;
    }
    if (st.st_uid != 0 || (st.st_mode & 077)) {
        snprintf(why, wn, "%s must be owned by root and readable by no group or other user (it is %u, mode %03o)",
                 path, (unsigned)st.st_uid, (unsigned)(st.st_mode & 0777));
        close(fd);
        return -1;
    }
    if ((size_t)st.st_size > cap) {
        snprintf(why, wn, "%s is larger than %zu bytes", path, cap);
        close(fd);
        return -1;
    }
    size_t n = 0;
    for (;;) {
        ssize_t r = read(fd, buf + n, cap - n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) { snprintf(why, wn, "reading %s: %s", path, strerror(errno)); close(fd); return -1; }
        if (r == 0) break;
        n += (size_t)r;
        if (n == cap) {
            char extra;
            if (read(fd, &extra, 1) > 0) { snprintf(why, wn, "%s is larger than %zu bytes", path, cap); close(fd); return -1; }
            break;
        }
    }
    close(fd);
    *len = n;
    if (out) *out = st;
    return 0;
}

/* One trailing newline (LF or CR LF) is not part of a value kept in a file. */
static size_t chomp(const unsigned char *b, size_t n) {
    if (n && b[n - 1] == '\n') n--;
    if (n && b[n - 1] == '\r') n--;
    return n;
}

/* ---- the configuration ---- */

static struct {
    char vault_addr[512], vault_token_file[4096], vault_ca[4096];
    char aws_region[64], aws_endpoint[512], aws_ca[4096], aws_credentials_file[4096], aws_imds[512];
} g_conf;

static char g_vault_token[4096];
static struct { char id[256], secret[256], token[4096]; bool have; } g_aws;

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) s[--n] = '\0';
    return s;
}

/* key = value lines into a callback; -1 with why on a malformed line */
static int kv_parse(char *text, const char *path, int (*cb)(const char *k, const char *v, char *why, size_t wn),
                    char *why, size_t wn) {
    int ln = 0;
    for (char *save = NULL, *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        ln++;
        char *l = trim(line);
        if (!*l || *l == '#') continue;
        char *eq = strchr(l, '=');
        if (!eq) { snprintf(why, wn, "%s:%d: need key = value", path, ln); return -1; }
        *eq = '\0';
        if (cb(trim(l), trim(eq + 1), why, wn) < 0) {
            size_t k = strlen(why);
            snprintf(why + k, wn - k, " (%s:%d)", path, ln);
            return -1;
        }
    }
    return 0;
}

static int conf_key(const char *k, const char *v, char *why, size_t wn) {
    static const struct { const char *key; size_t off, cap; } kKeys[] = {
#define K(f) { #f, offsetof(__typeof__(g_conf), f), sizeof g_conf.f }
        K(vault_addr), K(vault_token_file), K(vault_ca), K(aws_region), K(aws_endpoint), K(aws_ca),
        K(aws_credentials_file), K(aws_imds),
#undef K
    };
    for (size_t i = 0; i < sizeof kKeys / sizeof kKeys[0]; i++) {
        if (strcmp(k, kKeys[i].key)) continue;
        char *dst = (char *)&g_conf + kKeys[i].off;
        if (dst[0]) { snprintf(why, wn, "%s given twice", k); return -1; }
        if (!*v || strlen(v) >= kKeys[i].cap) { snprintf(why, wn, "%s: empty or too long", k); return -1; }
        memcpy(dst, v, strlen(v) + 1);
        return 0;
    }
    snprintf(why, wn, "unknown key %s", k);
    return -1;
}

static int aws_key(const char *k, const char *v, char *why, size_t wn) {
    char *dst = !strcmp(k, "aws_access_key_id") ? g_aws.id : !strcmp(k, "aws_secret_access_key") ? g_aws.secret :
                !strcmp(k, "aws_session_token") ? g_aws.token : NULL;
    size_t cap = dst == g_aws.token ? sizeof g_aws.token : sizeof g_aws.id;
    if (!dst) { snprintf(why, wn, "unknown key %s", k); return -1; }
    if (!*v || strlen(v) >= cap) { snprintf(why, wn, "%s: empty or too long", k); return -1; }
    memcpy(dst, v, strlen(v) + 1);
    return 0;
}

/* ---- URLs and HTTP ---- */

struct url { bool tls; char host[256]; char port[8]; char path[1024]; };

static int url_parse(const char *s, struct url *u) {
    memset(u, 0, sizeof *u);
    const char *p;
    if (!strncmp(s, "https://", 8)) { u->tls = true; p = s + 8; snprintf(u->port, sizeof u->port, "443"); }
    else if (!strncmp(s, "http://", 7)) { p = s + 7; snprintf(u->port, sizeof u->port, "80"); }
    else return -1;
    const char *slash = strchr(p, '/');
    size_t hl = slash ? (size_t)(slash - p) : strlen(p);
    char hp[300];
    if (hl == 0 || hl >= sizeof hp) return -1;
    memcpy(hp, p, hl);
    hp[hl] = '\0';
    if (strchr(hp, '@')) return -1;
    char *colon = hp[0] == '[' ? strstr(hp, "]:") : strrchr(hp, ':');
    if (colon) {
        if (hp[0] == '[') colon++;
        *colon = '\0';
        const char *pt = colon + 1;
        if (!*pt || strlen(pt) > 5 || strspn(pt, "0123456789") != strlen(pt)) return -1;
        snprintf(u->port, sizeof u->port, "%s", pt);
    }
    if (hp[0] == '[') {
        size_t n = strlen(hp);
        if (n < 3 || hp[n - 1] != ']') return -1;
        hp[n - 1] = '\0';
        memmove(hp, hp + 1, n - 1);
    }
    if (!hp[0] || strlen(hp) >= sizeof u->host) return -1;
    snprintf(u->host, sizeof u->host, "%s", hp);
    snprintf(u->path, sizeof u->path, "%s", slash ? slash : "");
    size_t pl = strlen(u->path);
    while (pl && u->path[pl - 1] == '/') u->path[--pl] = '\0';     /* a base: no trailing '/' */
    return 0;
}

static bool loopback(const char *h) {
    return !strcmp(h, "127.0.0.1") || !strcmp(h, "::1") || !strcmp(h, "localhost");
}

static long long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int tcp_connect(const struct url *u, char *why, size_t wn) {
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res = NULL;
    int e = getaddrinfo(u->host, u->port, &hints, &res);
    if (e) { snprintf(why, wn, "%.100s: %s", u->host, gai_strerror(e)); return -1; }
    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, a->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        if (errno == EINPROGRESS) {
            struct pollfd pf = { .fd = fd, .events = POLLOUT };
            int soerr = 0;
            socklen_t sl = sizeof soerr;
            if (poll(&pf, 1, IO_TIMEOUT_MS) == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 && soerr == 0)
                break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { snprintf(why, wn, "cannot connect to %.100s:%s", u->host, u->port); return -1; }
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    struct timeval tv = { .tv_sec = IO_TIMEOUT_MS / 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return fd;
}

/* One request; the response's status and body (chunked or not), at most
 * RESP_MAX. ca: a PEM bundle, or NULL for the host's trust store. allow_plain:
 * plain HTTP to this host is allowed. 0, or -1 with why. */
static int http_do(const struct url *u, const char *ca, bool allow_plain, const char *method, const char *path,
                   const char *headers, const char *body, size_t blen, int *status, char **out, size_t *olen,
                   char *why, size_t wn) {
    *out = NULL;
    *olen = 0;
    if (!u->tls && !allow_plain && !loopback(u->host)) {
        snprintf(why, wn, "plain http to %.100s (only https, or http to a loopback address)", u->host);
        return -1;
    }
    int fd = tcp_connect(u, why, wn);
    if (fd < 0) return -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int rc = -1;
    char *req = NULL, *buf = NULL;
    if (u->tls) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) { snprintf(why, wn, "TLS setup failed"); goto done; }
        if (ca ? SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1 : SSL_CTX_set_default_verify_paths(ctx) != 1) {
            snprintf(why, wn, "cannot load the CA %s", ca ? ca : "(the host's trust store)");
            goto done;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        ssl = SSL_new(ctx);
        if (!ssl || SSL_set_fd(ssl, fd) != 1 || SSL_set_tlsext_host_name(ssl, u->host) != 1 ||
            SSL_set1_host(ssl, u->host) != 1) {
            snprintf(why, wn, "TLS setup failed");
            goto done;
        }
        if (SSL_connect(ssl) != 1) {
            long vr = SSL_get_verify_result(ssl);
            snprintf(why, wn, "TLS to %.100s failed: %s", u->host,
                     vr != X509_V_OK ? X509_verify_cert_error_string(vr) : "handshake");
            goto done;
        }
    }
    size_t rl = strlen(method) + strlen(path) + strlen(u->host) + strlen(headers) + 256;
    req = malloc(rl);
    if (!req) { snprintf(why, wn, "out of memory"); goto done; }
    bool defport = (u->tls && !strcmp(u->port, "443")) || (!u->tls && !strcmp(u->port, "80"));
    bool v6 = strchr(u->host, ':') != NULL;
    int hn = snprintf(req, rl, "%s %s HTTP/1.1\r\nHost: %s%s%s%s%s\r\n%sContent-Length: %zu\r\nConnection: close\r\n\r\n",
                      method, path, v6 ? "[" : "", u->host, v6 ? "]" : "", defport ? "" : ":", defport ? "" : u->port,
                      headers, blen);
    if (hn < 0 || (size_t)hn >= rl) { snprintf(why, wn, "request too long"); goto done; }
    for (int part = 0; part < 2; part++) {
        const char *p = part ? body : req;
        size_t n = part ? blen : (size_t)hn, off = 0;
        while (off < n) {
            int w = u->tls ? SSL_write(ssl, p + off, (int)(n - off)) : (int)send(fd, p + off, n - off, MSG_NOSIGNAL);
            if (w <= 0) { snprintf(why, wn, "sending to %.100s failed", u->host); goto done; }
            off += (size_t)w;
        }
    }
    buf = malloc(RESP_MAX + 1);
    if (!buf) { snprintf(why, wn, "out of memory"); goto done; }
    size_t got = 0;
    long long end = mono_ms() + IO_TIMEOUT_MS;
    for (;;) {
        if (got == RESP_MAX) { snprintf(why, wn, "the response from %.100s is over 1 MiB", u->host); goto done; }
        int r = u->tls ? SSL_read(ssl, buf + got, (int)(RESP_MAX - got)) : (int)recv(fd, buf + got, RESP_MAX - got, 0);
        if (r <= 0) break;
        got += (size_t)r;
        if (mono_ms() > end) { snprintf(why, wn, "%.100s did not answer in time", u->host); goto done; }
    }
    buf[got] = '\0';
    char *he = strstr(buf, "\r\n\r\n");
    if (got < 12 || strncmp(buf, "HTTP/1.", 7) || !he) { snprintf(why, wn, "%.100s sent no HTTP response", u->host); goto done; }
    *status = atoi(buf + 9);
    char *b = he + 4;
    size_t bl = got - (size_t)(b - buf);
    *he = '\0';
    bool chunked = false;
    for (char *h = strstr(buf, "\r\n"); h; h = strstr(h + 2, "\r\n")) {
        char *line = h + 2;
        if (!strncasecmp(line, "Transfer-Encoding:", 18) && strcasestr(line + 18, "chunked")) chunked = true;
    }
    if (chunked) {
        size_t w = 0, r = 0;
        for (;;) {
            char *eol = memmem(b + r, bl - r, "\r\n", 2);
            if (!eol) { snprintf(why, wn, "a malformed chunked response"); goto done; }
            unsigned long cl = strtoul(b + r, NULL, 16);
            r = (size_t)(eol - b) + 2;
            if (cl == 0) break;
            if (cl > bl - r) { snprintf(why, wn, "a truncated chunked response"); goto done; }
            memmove(b + w, b + r, cl);
            w += cl;
            r += cl + 2;
            if (r > bl) { snprintf(why, wn, "a truncated chunked response"); goto done; }
        }
        bl = w;
    }
    *out = malloc(bl + 1);
    if (!*out) { snprintf(why, wn, "out of memory"); goto done; }
    memcpy(*out, b, bl);
    (*out)[bl] = '\0';
    *olen = bl;
    rc = 0;
done:
    if (buf) { OPENSSL_cleanse(buf, RESP_MAX + 1); free(buf); }
    if (req) free(req);
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
    close(fd);
    return rc;
}

/* ---- a minimal JSON reader: find a key's value, read a string ---- */

static const char *jws(const char *p, const char *e) {
    while (p < e && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

static const char *jskip(const char *p, const char *e, int depth) {
    p = jws(p, e);
    if (p >= e || depth > 32) return NULL;
    if (*p == '"') {
        for (p++; p < e; p++) {
            if (*p == '\\') { p++; continue; }
            if (*p == '"') return p + 1;
        }
        return NULL;
    }
    if (*p == '{' || *p == '[') {
        char close = *p == '{' ? '}' : ']';
        p = jws(p + 1, e);
        if (p < e && *p == close) return p + 1;
        for (;;) {
            if (close == '}') {
                p = jskip(p, e, depth + 1);                    /* the key */
                if (!p) return NULL;
                p = jws(p, e);
                if (p >= e || *p != ':') return NULL;
                p++;
            }
            p = jskip(p, e, depth + 1);
            if (!p) return NULL;
            p = jws(p, e);
            if (p < e && *p == ',') { p++; continue; }
            if (p < e && *p == close) return p + 1;
            return NULL;
        }
    }
    const char *s = p;
    while (p < e && (isalnum((unsigned char)*p) || *p == '-' || *p == '+' || *p == '.')) p++;
    return p > s ? p : NULL;
}

/* Decode the JSON string at p into out (cap bytes); its length, or -1. */
static long jstr(const char *p, const char *e, char *out, size_t cap) {
    p = jws(p, e);
    if (p >= e || *p != '"') return -1;
    size_t n = 0;
    for (p++; p < e && *p != '"'; p++) {
        unsigned long c = (unsigned char)*p;
        if (c < 0x20) return -1;
        if (c == '\\') {
            if (++p >= e) return -1;
            switch (*p) {
            case '"': c = '"'; break;    case '\\': c = '\\'; break;   case '/': c = '/'; break;
            case 'b': c = '\b'; break;   case 'f': c = '\f'; break;    case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;   case 't': c = '\t'; break;
            case 'u': {
                if (e - p < 5) return -1;
                char h[5] = { p[1], p[2], p[3], p[4], 0 };
                if (strspn(h, "0123456789abcdefABCDEF") != 4) return -1;
                c = strtoul(h, NULL, 16);
                p += 4;
                if (c >= 0xd800 && c <= 0xdbff) {
                    if (e - p < 7 || p[1] != '\\' || p[2] != 'u') return -1;
                    char l[5] = { p[3], p[4], p[5], p[6], 0 };
                    if (strspn(l, "0123456789abcdefABCDEF") != 4) return -1;
                    unsigned long lo = strtoul(l, NULL, 16);
                    if (lo < 0xdc00 || lo > 0xdfff) return -1;
                    c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
                    p += 6;
                } else if (c >= 0xdc00 && c <= 0xdfff) return -1;
                unsigned char u8[4];
                size_t k = c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
                if (k == 1) u8[0] = (unsigned char)c;
                else if (k == 2) { u8[0] = (unsigned char)(0xc0 | (c >> 6)); u8[1] = (unsigned char)(0x80 | (c & 0x3f)); }
                else if (k == 3) { u8[0] = (unsigned char)(0xe0 | (c >> 12)); u8[1] = (unsigned char)(0x80 | ((c >> 6) & 0x3f));
                                   u8[2] = (unsigned char)(0x80 | (c & 0x3f)); }
                else { u8[0] = (unsigned char)(0xf0 | (c >> 18)); u8[1] = (unsigned char)(0x80 | ((c >> 12) & 0x3f));
                       u8[2] = (unsigned char)(0x80 | ((c >> 6) & 0x3f)); u8[3] = (unsigned char)(0x80 | (c & 0x3f)); }
                if (n + k > cap) return -1;
                memcpy(out + n, u8, k);
                n += k;
                continue;
            }
            default: return -1;
            }
        }
        if (n + 1 > cap) return -1;
        out[n++] = (char)c;
    }
    if (p >= e) return -1;
    return (long)n;
}

/* The value of key in the object at p, or NULL. */
static const char *jget(const char *p, const char *e, const char *key) {
    p = jws(p, e);
    if (p >= e || *p != '{') return NULL;
    p = jws(p + 1, e);
    if (p < e && *p == '}') return NULL;
    for (;;) {
        char k[256];
        long kl = jstr(p, e, k, sizeof k - 1);
        const char *ke = jskip(p, e, 0);
        if (kl < 0 || !ke) return NULL;
        k[kl] = '\0';
        p = jws(ke, e);
        if (p >= e || *p != ':') return NULL;
        p = jws(p + 1, e);
        if ((size_t)kl == strlen(key) && !strcmp(k, key)) return p;
        p = jskip(p, e, 0);
        if (!p) return NULL;
        p = jws(p, e);
        if (p < e && *p == ',') { p = jws(p + 1, e); continue; }
        return NULL;
    }
}

/* ---- Vault ---- */

static void vault_fetch(unsigned idx, const char *ref) {
    char why[256];
    struct url u;
    if (!g_conf.vault_addr[0] || url_parse(g_conf.vault_addr, &u) < 0) {
        report(idx, false, NULL, 0, g_conf.vault_addr[0] ? "vault_addr is not an http(s) URL" :
               "a vault credential needs vault_addr in the configuration");
        return;
    }
    if (!g_vault_token[0]) { report(idx, false, NULL, 0, "a vault credential needs vault_token_file"); return; }
    const char *h = strchr(ref, '#');
    char path[1400], hdr[4200];
    snprintf(path, sizeof path, "%s/v1/%.*s", u.path, (int)(h - ref), ref);
    snprintf(hdr, sizeof hdr, "X-Vault-Token: %s\r\nAccept: application/json\r\n", g_vault_token);
    int status = 0;
    char *body = NULL;
    size_t bl = 0;
    if (http_do(&u, g_conf.vault_ca[0] ? g_conf.vault_ca : NULL, false, "GET", path, hdr, "", 0, &status, &body, &bl,
                why, sizeof why) < 0) {
        OPENSSL_cleanse(hdr, sizeof hdr);
        report(idx, false, NULL, 0, why);
        return;
    }
    OPENSSL_cleanse(hdr, sizeof hdr);
    const char *e = body + bl;
    char version[160] = "";
    const char *data = status == 200 ? jget(body, e, "data") : NULL;
    const char *inner = data ? jget(data, e, "data") : NULL, *meta = data ? jget(data, e, "metadata") : NULL;
    const char *fv = NULL;
    if (inner && meta && *jws(inner, e) == '{') {                            /* KV version 2 */
        fv = jget(inner, e, h + 1);
        const char *ver = jget(meta, e, "version");
        const char *ve = ver ? jskip(ver, e, 0) : NULL;
        if (ver && ve && ve - ver < 20 && isdigit((unsigned char)*ver))
            snprintf(version, sizeof version, "kv2:%.*s", (int)(ve - ver), ver);
        else snprintf(version, sizeof version, "kv2");
    } else if (data) {                                                       /* KV version 1, or a lease */
        fv = jget(data, e, h + 1);
        const char *lid = jget(body, e, "lease_id");
        char lease[140] = "";
        long ll = lid ? jstr(lid, e, lease, sizeof lease - 1) : -1;
        if (ll > 0) { lease[ll] = '\0'; snprintf(version, sizeof version, "lease:%s", lease); }
        else snprintf(version, sizeof version, "kv1");
    }
    char *val = malloc(WS_MAX_VALUE + 1);
    long vl = fv && val ? jstr(fv, e, val, WS_MAX_VALUE + 1) : -1;
    const char *bad = NULL;
    if (status != 200) {
        snprintf(why, sizeof why, "vault answered %d for %.*s", status, (int)(h - ref), ref);
        bad = why;
    } else if (!data) bad = "vault's answer has no data";
    else if (!fv) bad = "vault's answer has no such field";
    else if (vl < 0) bad = "the field is not a string, or is longer than 8192 bytes";
    else bad = value_store(idx, (unsigned char *)val, (size_t)vl);
    if (val) { OPENSSL_cleanse(val, WS_MAX_VALUE + 1); free(val); }
    OPENSSL_cleanse(body, bl);
    free(body);
    if (bad) report(idx, false, NULL, 0, bad);
    else report(idx, true, version, (size_t)vl, NULL);
}

/* ---- AWS Secrets Manager (SigV4) ---- */

static void hexs(const unsigned char *d, size_t n, char *out) {
    static const char x[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = x[d[i] >> 4]; out[2 * i + 1] = x[d[i] & 15]; }
    out[2 * n] = '\0';
}

static void sha256_hex(const void *d, size_t n, char out[65]) {
    unsigned char h[32];
    unsigned int hl = 0;
    EVP_Digest(d, n, h, &hl, EVP_sha256(), NULL);
    hexs(h, 32, out);
}

static void hmac(const void *k, size_t kl, const void *d, size_t dl, unsigned char out[32]) {
    size_t ol = 0;
    EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, k, kl, d, dl, out, 32, &ol);
}

/* The instance's role credentials, through IMDSv2. 0, or -1 with why. */
static int imds_credentials(char *why, size_t wn) {
    struct url u;
    if (url_parse(g_conf.aws_imds[0] ? g_conf.aws_imds : "http://169.254.169.254", &u) < 0) {
        snprintf(why, wn, "aws_imds is not an http URL");
        return -1;
    }
    int st = 0;
    char *tok = NULL, *role = NULL, *cred = NULL;
    size_t tl = 0, rl = 0, cl = 0;
    char p[1400], h[700];
    int rc = -1;
    snprintf(p, sizeof p, "%s/latest/api/token", u.path);
    if (http_do(&u, NULL, true, "PUT", p, "X-aws-ec2-metadata-token-ttl-seconds: 60\r\n", "", 0, &st, &tok, &tl, why, wn) < 0)
        return -1;
    if (st != 200 || tl == 0 || tl > 512 || strpbrk(tok, "\r\n")) { snprintf(why, wn, "the metadata service gave no token"); goto out; }
    snprintf(h, sizeof h, "X-aws-ec2-metadata-token: %s\r\n", tok);
    snprintf(p, sizeof p, "%s/latest/meta-data/iam/security-credentials/", u.path);
    if (http_do(&u, NULL, true, "GET", p, h, "", 0, &st, &role, &rl, why, wn) < 0) goto out;
    char *nl = strchr(role, '\n');
    if (nl) *nl = '\0';
    if (st != 200 || !role[0] || strlen(role) > 128 || strpbrk(role, "/ ")) {
        snprintf(why, wn, "the instance has no role");
        goto out;
    }
    snprintf(p, sizeof p, "%s/latest/meta-data/iam/security-credentials/%s", u.path, role);
    if (http_do(&u, NULL, true, "GET", p, h, "", 0, &st, &cred, &cl, why, wn) < 0) goto out;
    const char *e = cred + cl, *a = jget(cred, e, "AccessKeyId"), *s = jget(cred, e, "SecretAccessKey"),
               *t = jget(cred, e, "Token");
    long al = a ? jstr(a, e, g_aws.id, sizeof g_aws.id - 1) : -1;
    long sl = s ? jstr(s, e, g_aws.secret, sizeof g_aws.secret - 1) : -1;
    long xl = t ? jstr(t, e, g_aws.token, sizeof g_aws.token - 1) : -1;
    if (st != 200 || al <= 0 || sl <= 0 || xl <= 0) { snprintf(why, wn, "the role's credentials could not be read"); goto out; }
    g_aws.id[al] = g_aws.secret[sl] = g_aws.token[xl] = '\0';
    g_aws.have = true;
    rc = 0;
out:
    if (tok) { OPENSSL_cleanse(tok, tl); free(tok); }
    free(role);
    if (cred) { OPENSSL_cleanse(cred, cl); free(cred); }
    OPENSSL_cleanse(h, sizeof h);
    return rc;
}

static void aws_fetch(unsigned idx, const char *arn) {
    char why[256];
    /* arn:PARTITION:secretsmanager:REGION:ACCOUNT:secret:NAME */
    char region[64] = "";
    const char *f = arn;
    for (int k = 0; k < 3 && f; k++) { f = strchr(f, ':'); if (f) f++; }
    if (f) { const char *fe = strchr(f, ':'); if (fe && fe > f && (size_t)(fe - f) < sizeof region) memcpy(region, f, (size_t)(fe - f)); }
    if (g_conf.aws_region[0]) snprintf(region, sizeof region, "%s", g_conf.aws_region);
    if (!region[0] || strspn(region, "abcdefghijklmnopqrstuvwxyz0123456789-") != strlen(region)) {
        report(idx, false, NULL, 0, "no region (aws_region, or the ARN's)");
        return;
    }
    char ep[600];
    if (g_conf.aws_endpoint[0]) snprintf(ep, sizeof ep, "%s", g_conf.aws_endpoint);
    else snprintf(ep, sizeof ep, "https://secretsmanager.%s.amazonaws.com", region);
    struct url u;
    if (url_parse(ep, &u) < 0) { report(idx, false, NULL, 0, "aws_endpoint is not an http(s) URL"); return; }
    if (!g_aws.have && imds_credentials(why, sizeof why) < 0) { report(idx, false, NULL, 0, why); return; }
    /* the request */
    char body[1200];
    int bl = snprintf(body, sizeof body, "{\"SecretId\":\"%s\"}", arn);    /* the ARN has no '"' or '\\' (printable, checked) */
    if (strpbrk(arn, "\"\\")) { report(idx, false, NULL, 0, "the ARN holds a quote or a backslash"); return; }
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    char amzdate[20], day[10];
    strftime(amzdate, sizeof amzdate, "%Y%m%dT%H%M%SZ", &tm);
    strftime(day, sizeof day, "%Y%m%d", &tm);
    bool defport = (u.tls && !strcmp(u.port, "443")) || (!u.tls && !strcmp(u.port, "80"));
    char hosthdr[300];
    snprintf(hosthdr, sizeof hosthdr, "%s%s%s", u.host, defport ? "" : ":", defport ? "" : u.port);
    char bodyhash[65];
    sha256_hex(body, (size_t)bl, bodyhash);
    bool tok = g_aws.token[0] != '\0';
    const char *signed_h = tok ? "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
                               : "content-type;host;x-amz-date;x-amz-target";
    char *canon = malloc(16384), *sts = malloc(1024), *hdrs = malloc(16384);
    if (!canon || !sts || !hdrs) { free(canon); free(sts); free(hdrs); report(idx, false, NULL, 0, "out of memory"); return; }
    snprintf(canon, 16384, "POST\n%s/\n\ncontent-type:application/x-amz-json-1.1\nhost:%s\nx-amz-date:%s\n%s%s%s"
             "x-amz-target:secretsmanager.GetSecretValue\n\n%s\n%s",
             u.path, hosthdr, amzdate, tok ? "x-amz-security-token:" : "", tok ? g_aws.token : "", tok ? "\n" : "",
             signed_h, bodyhash);
    char canonhash[65];
    sha256_hex(canon, strlen(canon), canonhash);
    char scope[160];
    snprintf(scope, sizeof scope, "%s/%s/secretsmanager/aws4_request", day, region);
    snprintf(sts, 1024, "AWS4-HMAC-SHA256\n%s\n%s\n%s", amzdate, scope, canonhash);
    unsigned char k[32], k2[32];
    char kseed[300];
    snprintf(kseed, sizeof kseed, "AWS4%s", g_aws.secret);
    hmac(kseed, strlen(kseed), day, strlen(day), k);
    hmac(k, 32, region, strlen(region), k2);
    hmac(k2, 32, "secretsmanager", 14, k);
    hmac(k, 32, "aws4_request", 12, k2);
    unsigned char sig[32];
    hmac(k2, 32, sts, strlen(sts), sig);
    char sighex[65];
    hexs(sig, 32, sighex);
    OPENSSL_cleanse(kseed, sizeof kseed);
    OPENSSL_cleanse(k, sizeof k);
    OPENSSL_cleanse(k2, sizeof k2);
    snprintf(hdrs, 16384, "Content-Type: application/x-amz-json-1.1\r\nX-Amz-Target: secretsmanager.GetSecretValue\r\n"
             "X-Amz-Date: %s\r\n%s%s%sAuthorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\n",
             amzdate, tok ? "X-Amz-Security-Token: " : "", tok ? g_aws.token : "", tok ? "\r\n" : "",
             g_aws.id, scope, signed_h, sighex);
    char path[1100];
    snprintf(path, sizeof path, "%s/", u.path);
    int status = 0;
    char *resp = NULL;
    size_t rl = 0;
    int r = http_do(&u, g_conf.aws_ca[0] ? g_conf.aws_ca : NULL, false, "POST", path, hdrs, body, (size_t)bl,
                    &status, &resp, &rl, why, sizeof why);
    OPENSSL_cleanse(hdrs, 16384);
    free(canon); free(sts); free(hdrs);
    if (r < 0) { report(idx, false, NULL, 0, why); return; }
    const char *e = resp + rl;
    const char *ss = status == 200 ? jget(resp, e, "SecretString") : NULL, *vid = status == 200 ? jget(resp, e, "VersionId") : NULL;
    char version[160] = "aws";
    if (vid) {
        char v[140];
        long vl = jstr(vid, e, v, sizeof v - 1);
        if (vl > 0) { v[vl] = '\0'; snprintf(version, sizeof version, "aws:%s", v); }
    }
    char *val = malloc(WS_MAX_VALUE + 1);
    long vl = ss && val ? jstr(ss, e, val, WS_MAX_VALUE + 1) : -1;
    const char *bad = NULL;
    if (status != 200) { snprintf(why, sizeof why, "Secrets Manager answered %d", status); bad = why; }
    else if (!ss) bad = status == 200 && jget(resp, e, "SecretBinary") ? "a binary secret (only SecretString is used)"
                                                                       : "Secrets Manager's answer has no SecretString";
    else if (vl < 0) bad = "SecretString is not a string, or is longer than 8192 bytes";
    else bad = value_store(idx, (unsigned char *)val, (size_t)vl);
    if (val) { OPENSSL_cleanse(val, WS_MAX_VALUE + 1); free(val); }
    OPENSSL_cleanse(resp, rl);
    free(resp);
    if (bad) report(idx, false, NULL, 0, bad);
    else report(idx, true, version, (size_t)vl, NULL);
}

/* ---- privileges ---- */

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
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0) return -1;
    return 0;
}

static ssize_t ctl_recv(void *m, size_t n) {
    ssize_t r;
    while ((r = recv(g_ctl, m, n, 0)) < 0 && errno == EINTR) { }
    return r;
}

int main(int argc, char **argv) {
    uid_t u;
    gid_t g;
    if (argc != 2 || parse_ids(argv[1], &u, &g) < 0 || fcntl(3, F_GETFD) < 0 || geteuid() != 0) {
        fprintf(stderr, "warden-secrets: the Warden starts this program (v1.28 credential release); "
                "it is not run by hand\n");
        return 2;
    }
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (arena_init() < 0) return 2;
    /* the setup and the credentials */
    struct ws_setup su;
    if (ctl_recv(&su, sizeof su) != (ssize_t)sizeof su || su.type != WS_MSG_SETUP || su.ncreds > WS_MAX_CREDS ||
        !memchr(su.conf, '\0', sizeof su.conf))
        return 2;
    static struct ws_cred cr[WS_MAX_CREDS];
    bool need_vault = false, need_aws = false;
    for (uint32_t i = 0; i < su.ncreds; i++) {
        if (ctl_recv(&cr[i], sizeof cr[i]) != (ssize_t)sizeof cr[i] || cr[i].type != WS_MSG_CRED || cr[i].index != i ||
            !memchr(cr[i].ref, '\0', sizeof cr[i].ref) || cr[i].store < STORE_FILE || cr[i].store > STORE_AWSSM)
            return 2;
        need_vault |= cr[i].store == STORE_VAULT;
        need_aws |= cr[i].store == STORE_AWSSM;
    }
    /* as root: the configuration and the local files */
    char why[512];
    bool failed = false;
    static unsigned char fbuf[65536];
    size_t fl;
    if (su.conf[0] && (need_vault || need_aws)) {
        if (read_private(su.conf, fbuf, sizeof fbuf - 1, &fl, NULL, why, sizeof why) < 0 ||
            (fbuf[fl] = '\0', kv_parse((char *)fbuf, su.conf, conf_key, why, sizeof why) < 0)) {
            for (uint32_t i = 0; i < su.ncreds; i++)
                if (cr[i].store != STORE_FILE) report(i, false, NULL, 0, why);
            failed = true;
        }
    }
    if (!failed && need_vault && g_conf.vault_token_file[0]) {
        if (read_private(g_conf.vault_token_file, fbuf, sizeof g_vault_token - 1, &fl, NULL, why, sizeof why) < 0) {
            for (uint32_t i = 0; i < su.ncreds; i++) if (cr[i].store == STORE_VAULT) report(i, false, NULL, 0, why);
            failed = true;
        } else {
            fl = chomp(fbuf, fl);
            if (memchr(fbuf, '\n', fl) || memchr(fbuf, '\r', fl) || memchr(fbuf, '\0', fl)) {
                for (uint32_t i = 0; i < su.ncreds; i++)
                    if (cr[i].store == STORE_VAULT) report(i, false, NULL, 0, "the vault token file holds more than one line");
                failed = true;
            } else memcpy(g_vault_token, fbuf, fl);
        }
        OPENSSL_cleanse(fbuf, sizeof fbuf);
    }
    if (!failed && need_aws && g_conf.aws_credentials_file[0]) {
        if (read_private(g_conf.aws_credentials_file, fbuf, sizeof fbuf - 1, &fl, NULL, why, sizeof why) < 0 ||
            (fbuf[fl] = '\0', kv_parse((char *)fbuf, g_conf.aws_credentials_file, aws_key, why, sizeof why) < 0) ||
            (!g_aws.id[0] || !g_aws.secret[0] ? (snprintf(why, sizeof why, "%.300s needs aws_access_key_id and "
                                                          "aws_secret_access_key", g_conf.aws_credentials_file), 1) : 0)) {
            for (uint32_t i = 0; i < su.ncreds; i++) if (cr[i].store == STORE_AWSSM) report(i, false, NULL, 0, why);
            failed = true;
        } else g_aws.have = true;
        OPENSSL_cleanse(fbuf, sizeof fbuf);
    }
    for (uint32_t i = 0; !failed && i < su.ncreds; i++) {
        if (cr[i].store != STORE_FILE) continue;
        struct stat st;
        if (read_private(cr[i].ref, fbuf, WS_MAX_VALUE + 2, &fl, &st, why, sizeof why) < 0) {
            report(i, false, NULL, 0, why);
            failed = true;
            continue;
        }
        const char *bad = value_store(i, fbuf, chomp(fbuf, fl));
        OPENSSL_cleanse(fbuf, sizeof fbuf);
        if (bad) { report(i, false, NULL, 0, bad); failed = true; continue; }
        char version[160];
        snprintf(version, sizeof version, "inode:%lu mtime:%lld", (unsigned long)st.st_ino, (long long)st.st_mtime);
        report(i, true, version, g_val[i].len, NULL);
    }
    /* its own user, then the network */
    if (drop_to(u, g) < 0) return 2;
    for (uint32_t i = 0; !failed && i < su.ncreds; i++) {
        if (cr[i].store == STORE_VAULT) vault_fetch(i, cr[i].ref);
        else if (cr[i].store == STORE_AWSSM) aws_fetch(i, cr[i].ref);
    }
    OPENSSL_cleanse(g_vault_token, sizeof g_vault_token);
    OPENSSL_cleanse(&g_aws, sizeof g_aws);
    if (!failed) {
        size_t n = 0;
        for (uint32_t i = 0; i < su.ncreds; i++) n += g_val[i].len != 0;
        if (n == su.ncreds) {
            struct ws_ready y = { .type = WS_MSG_READY, .n = su.ncreds };
            ctl_send(&y, sizeof y);
        }
    }
    /* step 3: hand the values to warden-proxy, over the socket the Warden
     * gives, then clear them here; wait until the control socket closes */
    for (;;) {
        struct ws_ready m;
        union { char b[CMSG_SPACE(sizeof(int))]; struct cmsghdr al; } cb;
        struct iovec v = { &m, sizeof m };
        struct msghdr mh = { .msg_iov = &v, .msg_iovlen = 1, .msg_control = cb.b, .msg_controllen = sizeof cb.b };
        ssize_t r = recvmsg(g_ctl, &mh, MSG_CMSG_CLOEXEC);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        int fd = -1;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(sizeof(int)))
                memcpy(&fd, CMSG_DATA(c), sizeof fd);
        if (r != (ssize_t)sizeof m || m.type != WS_MSG_PROXY || fd < 0 || failed) {
            if (fd >= 0) close(fd);
            continue;
        }
        static struct ws_value wv;
        for (uint32_t i = 0; i < su.ncreds; i++) {
            memset(&wv, 0, sizeof wv);
            wv.type = WS_MSG_VALUE;
            wv.index = i;
            wv.len = (uint32_t)g_val[i].len;
            memcpy(wv.value, g_arena + g_val[i].off, g_val[i].len);
            ssize_t w;
            while ((w = send(fd, &wv, sizeof wv, MSG_NOSIGNAL)) < 0 && errno == EINTR) { }
            OPENSSL_cleanse(&wv, sizeof wv);
            if (w != (ssize_t)sizeof wv) break;
        }
        close(fd);
        arena_clear();                       /* handed: no copy stays here */
    }
    arena_clear();
    return 0;
}
