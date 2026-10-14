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
// Warden, never written; once handed to warden-proxy, or when the control
// socket closes, they are cleared.
//
// Step 4 (section 4 of the plan): a Vault secret with a lease is renewed at
// two thirds of its lease (WS_MSG_RENEWED, each time, renewed or not; a
// renewal that fails is not retried), and on WS_MSG_REVOKE every lease of
// the run is revoked (WS_MSG_REVOKED). For that the Vault token stays, in
// the arena's last page, while the run holds a lease; else it is cleared
// after the fetch.
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
//   oidc_ca               v1.28.1: a PEM CA bundle to verify token issuers with (else the
//                         host's); with no credentials and no such file, the host's
//
// v1.28.1 (docs/security/v1.28.1-delegation-chain.md, section 2): it also
// verifies the user's token and the agent's X.509-SVID; see "identities"
// below.

#include "warden_secrets.h"
#include "mcp_json.h"             /* v1.31: an MCP token's claims */
#include "mcp_aud.h"

#include <ctype.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
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

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define STORE_FILE  1                 /* VDP_CRED_* in smt_decide.h */
#define STORE_VAULT 2
#define STORE_AWSSM 3

#define RESP_MAX    (1u << 20)        /* a store's response, at most 1 MiB */
#define LEEWAY_S    60                /* v1.28.1: a token's times; v1.31: an MCP token's expiry */
#define IO_TIMEOUT_MS 10000

static int g_ctl = 3;

/* ---- the arena: every value, locked and not dumped ---- */

#define VALUES_LEN  ((size_t)WS_MAX_CREDS * WS_MAX_VALUE)
#define TOKEN_MAX   4096

static unsigned char *g_arena;
static size_t g_arena_len;
static struct { size_t off, len; } g_val[WS_MAX_CREDS];
static char *g_vault_token;           /* the arena's last page */
static char *g_user_token;            /* v1.28.1: the user's token, after it (WS_MAX_TOKEN + 1) */
/* v1.28.1 review: and its decoded parts, while it is checked */
#define HDR_MAX 4096
#define SIG_MAX 1024
static char *g_hdr, *g_pay;
static unsigned char *g_sig;

static int arena_init(void) {
    g_arena_len = VALUES_LEN + TOKEN_MAX + WS_MAX_TOKEN + 1 + HDR_MAX + WS_MAX_TOKEN + SIG_MAX;
    g_arena = mmap(NULL, g_arena_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_arena == MAP_FAILED) { g_arena = NULL; return -1; }
    if (mlock(g_arena, g_arena_len) < 0) return -1;
    (void)madvise(g_arena, g_arena_len, MADV_DONTDUMP);
    g_vault_token = (char *)g_arena + VALUES_LEN;
    g_user_token = g_vault_token + TOKEN_MAX;
    g_hdr = g_user_token + WS_MAX_TOKEN + 1;
    g_pay = g_hdr + HDR_MAX;
    g_sig = (unsigned char *)g_pay + WS_MAX_TOKEN;
    return 0;
}

static void arena_clear(void) {
    if (g_arena) OPENSSL_cleanse(g_arena, VALUES_LEN);
}

static void token_clear(void) {
    if (g_vault_token) OPENSSL_cleanse(g_vault_token, TOKEN_MAX);
}

static void user_token_clear(void) {
    if (g_user_token) OPENSSL_cleanse(g_user_token, WS_MAX_TOKEN + 1);
}

/* Step 4: the run's Vault leases (a credential's index is its slot) */
static struct {
    char id[140];
    uint32_t ttl;                     /* seconds */
    long long due_ms;                 /* the next renewal (mono_ms) */
    bool live, renewable;
} g_lease[WS_MAX_CREDS];

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

static void report_file(const char *path, uint32_t kind) {
    struct ws_file f;
    memset(&f, 0, sizeof f);
    f.type = WS_MSG_FILE;
    f.kind = kind;
    snprintf(f.path, sizeof f.path, "%s", path);
    ctl_send(&f, sizeof f);
}

/* v1.31 step 5: each credential that is an MCP token: its server's URL
 * (canonical) and whether it is opaque */
static struct { char aud[1025]; bool opaque; } g_mcpcred[WS_MAX_CREDS];

/* v1.31 step 5: an MCP token, as fetched (credential idx's value): a JWT whose
 * aud names its server and whose exp is at least 60 s away (its signature is
 * the server's to check; an opaque one is checked by none of this). NULL and
 * its exp (-1: opaque), or why not. */
static const char *mcp_token_check(unsigned idx, int64_t *exp) {
    static char w[256];
    *exp = -1;
    mj_jwt_t *j = calloc(1, sizeof *j);
    if (!j) return "out of memory";
    char jw[72] = "";
    int r = mj_jwt((const char *)g_arena + g_val[idx].off, g_val[idx].len, j, jw, sizeof jw);
    /* an opaque line's value is not read, unless it is a readable JWT after
     * all (v1.31 review: a store that moved to JWTs is checked as one) */
    if (g_mcpcred[idx].opaque && r != 1) { free(j); return NULL; }
    const char *bad = NULL;
    int64_t now = (int64_t)time(NULL);
    bool named = false;
    for (uint32_t k = 0; r == 1 && k < j->naud && !named; k++) named = mcp_aud_names(g_mcpcred[idx].aud, j->aud[k]);
    if (r == 0) bad = "it is an MCP token (audience=) that is not a JWT, and its line does not say opaque";
    else if (r < 0) { snprintf(w, sizeof w, "it is an MCP token in a JWT's form that cannot be read: %s", jw); bad = w; }
    else if (!named) { snprintf(w, sizeof w, "its audience (aud) does not name %.200s", g_mcpcred[idx].aud); bad = w; }
    else if (!j->has_exp) bad = "it is an MCP token without an expiry (exp)";
    else if (j->exp <= now) { snprintf(w, sizeof w, "it expired %lld s ago", (long long)(now - j->exp)); bad = w; }
    else if (j->exp < now + LEEWAY_S) { snprintf(w, sizeof w, "it expires in %lld s, under 60 s", (long long)(j->exp - now)); bad = w; }
    else if (j->exp >= (int64_t)1 << 53) bad = "its expiry (exp) is past any date this Warden records";
    else *exp = g_mcpcred[idx].opaque ? -1 : j->exp;      /* an opaque line's: checked, not recorded as one */
    free(j);
    return bad;
}

static void report(unsigned idx, bool ok, const char *version, size_t len, const char *why) {
    struct ws_result r;
    memset(&r, 0, sizeof r);
    r.type = WS_MSG_RESULT;
    r.index = idx;
    r.exp = -1;
    /* v1.31: an MCP token is checked before it is reported fetched; one
     * that fails is cleared and reported as not */
    if (ok && idx < WS_MAX_CREDS && g_mcpcred[idx].aud[0]) {
        const char *bad = mcp_token_check(idx, &r.exp);
        if (bad) {
            OPENSSL_cleanse(g_arena + g_val[idx].off, WS_MAX_VALUE);
            g_val[idx].len = 0;
            ok = false;
            why = bad;
            version = NULL;
            len = 0;
            r.exp = -1;
        }
    }
    r.ok = ok;
    r.len = (uint32_t)len;
    if (version) snprintf(r.version, sizeof r.version, "%s", version);
    if (why) snprintf(r.why, sizeof r.why, "%s", why);
    /* v1.28 review: a store's text (a version id) is printed by the Warden:
     * printable ASCII only, no quote or backslash */
    for (char *c = r.version; *c; c++) if (*c < 0x20 || *c > 0x7e || *c == '"' || *c == '\\') *c = '?';
    for (char *c = r.why; *c; c++) if (*c < 0x20 || *c > 0x7e || *c == '"' || *c == '\\') *c = '?';
    ctl_send(&r, sizeof r);
}

/* ---- local files (as root) ---- */

/* Read a file that must be regular, owned by root and readable by no group
 * or other user, into buf (at most cap bytes). The path is reported to the
 * Warden. 0, or -1 with why. v1.28.1: kind WS_FILE_TRUSTED (a trust bundle)
 * is a file writable by no group or other user instead; anyone may read it. */
static int read_file(const char *path, uint32_t kind, unsigned char *buf, size_t cap, size_t *len, struct stat *out,
                     char *why, size_t wn) {
    report_file(path, kind);
    /* v1.28 review: every directory above it root's, and writable by no other
     * user unless sticky (as /tmp): no one else can put another file at the
     * name between the policy's checks and this read */
    if (path[0] != '/') { snprintf(why, wn, "%.300s is not an absolute path", path); return -1; }
    char dir[PATH_MAX], real[PATH_MAX];
    snprintf(dir, sizeof dir, "%s", path);
    char *sl = strrchr(dir, '/');
    if (sl == dir) sl[1] = '\0'; else *sl = '\0';
    if (!realpath(dir, real)) { snprintf(why, wn, "cannot open %.300s: %s", path, strerror(errno)); return -1; }
    /* v1.28.1 review: the file is opened in the directory that was checked
     * (its resolved path), not through the name given, which a symlink
     * above it could point elsewhere after the check */
    char checked[PATH_MAX + 2];
    const char *base = strrchr(path, '/') + 1;
    if (!*base || (size_t)snprintf(checked, sizeof checked, "%s/%s", strcmp(real, "/") ? real : "", base) >= sizeof checked) {
        snprintf(why, wn, "%.300s is not a file's path", path);
        return -1;
    }
    for (char *c = real + strlen(real); ; ) {
        struct stat ds;
        if (stat(real[0] ? real : "/", &ds) < 0 || ds.st_uid != 0 ||
            ((ds.st_mode & 022) && !(ds.st_mode & S_ISVTX))) {
            snprintf(why, wn, "%.200s: the directory %.200s must be root's and writable by no other user",
                     path, real[0] ? real : "/");
            return -1;
        }
        if (!real[0]) break;
        while (c > real && *c != '/') c--;
        *c = '\0';                                       /* up one ("" is /) */
    }
    /* review: O_NONBLOCK, so a FIFO put at the name cannot hold the helper */
    int fd = open(checked, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) { snprintf(why, wn, "cannot open %s: %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        snprintf(why, wn, "%s is not a regular file", path);
        close(fd);
        return -1;
    }
    if (st.st_uid != 0 || (st.st_mode & (kind == WS_FILE_TRUSTED ? 022 : 077))) {
        snprintf(why, wn, "%s must be owned by root and %s by no group or other user (it is %u, mode %03o)",
                 path, kind == WS_FILE_TRUSTED ? "writable" : "readable",
                 (unsigned)st.st_uid, (unsigned)(st.st_mode & 0777));
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

static int read_private(const char *path, unsigned char *buf, size_t cap, size_t *len, struct stat *out,
                        char *why, size_t wn) {
    return read_file(path, WS_FILE_SECRET, buf, cap, len, out, why, wn);
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
    char oidc_ca[4096];               /* v1.28.1: a PEM CA bundle to verify issuers with (else the host's) */
} g_conf;

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

/* v1.28 review: a key is named in a refusal only if it looks like one: a
 * line missing its " = " may hold a secret before its first '=' */
static void unknown_key(const char *k, char *why, size_t wn) {
    if (strlen(k) <= 32 && strspn(k, "abcdefghijklmnopqrstuvwxyz_") == strlen(k))
        snprintf(why, wn, "unknown key %s", k);
    else
        snprintf(why, wn, "a line that is not key = value with a known key (its text is not shown)");
}

static int conf_key(const char *k, const char *v, char *why, size_t wn) {
    static const struct { const char *key; size_t off, cap; } kKeys[] = {
#define K(f) { #f, offsetof(__typeof__(g_conf), f), sizeof g_conf.f }
        K(vault_addr), K(vault_token_file), K(vault_ca), K(aws_region), K(aws_endpoint), K(aws_ca),
        K(aws_credentials_file), K(aws_imds), K(oidc_ca),
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
    unknown_key(k, why, wn);
    return -1;
}

static int aws_key(const char *k, const char *v, char *why, size_t wn) {
    char *dst = !strcmp(k, "aws_access_key_id") ? g_aws.id : !strcmp(k, "aws_secret_access_key") ? g_aws.secret :
                !strcmp(k, "aws_session_token") ? g_aws.token : NULL;
    size_t cap = dst == g_aws.token ? sizeof g_aws.token : sizeof g_aws.id;
    if (!dst) { unknown_key(k, why, wn); return -1; }
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

/* v1.28.1 review: the start's network work ends by one deadline, inside the
 * Warden's 30 s wait, so a slow server is named (0: none, after the start) */
static long long g_deadline;

static int io_ms(void) {
    if (!g_deadline) return IO_TIMEOUT_MS;
    long long left = g_deadline - mono_ms();
    return left <= 0 ? 0 : left < IO_TIMEOUT_MS ? (int)left : IO_TIMEOUT_MS;
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
            if (io_ms() > 0 && poll(&pf, 1, io_ms()) == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 &&
                soerr == 0)
                break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { snprintf(why, wn, "cannot connect to %.100s:%s", u->host, u->port); return -1; }
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    int ms = io_ms() > 0 ? io_ms() : 1;
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return fd;
}

/* One request; the response's status and body (chunked or not), at most
 * RESP_MAX. ca: a PEM bundle, or NULL for the host's trust store. allow_plain:
 * plain HTTP to this host is allowed. 0, or -1 with why. */
/* v1.28.1 review: each CA file the configuration names, read as root as a
 * trusted file (root-owned, writable by no other user, reported to the
 * Warden, which refuses a policy that lets the agent write it) and kept
 * here; a connection is verified against the one its key names */
static struct { char path[4096]; X509_STORE *store; } g_ca[3];

static X509_STORE *ca_store(const char *path) {
    for (size_t i = 0; i < sizeof g_ca / sizeof g_ca[0]; i++)
        if (g_ca[i].store && !strcmp(g_ca[i].path, path)) return g_ca[i].store;
    return NULL;
}

static int no_passphrase(char *buf, int size, int rw, void *u);

/* Read a CA bundle (as root): 0, or -1 with why */
static int ca_load(const char *path, char *why, size_t wn) {
    if (ca_store(path)) return 0;
    size_t slot = 0;
    while (slot < sizeof g_ca / sizeof g_ca[0] && g_ca[slot].store) slot++;
    if (slot == sizeof g_ca / sizeof g_ca[0] || strlen(path) >= sizeof g_ca[0].path) {
        snprintf(why, wn, "too many CA files, or a path too long");
        return -1;
    }
    static unsigned char buf[1 << 20];
    size_t bl = 0;
    char rw[512];
    if (read_file(path, WS_FILE_TRUSTED, buf, sizeof buf, &bl, NULL, rw, sizeof rw) < 0) {
        snprintf(why, wn, "its CA file: %.400s", rw);
        return -1;
    }
    X509_STORE *st = X509_STORE_new();
    BIO *b = BIO_new_mem_buf(buf, (int)bl);
    int n = 0;
    for (X509 *x; st && b && (x = PEM_read_bio_X509(b, NULL, no_passphrase, NULL)); X509_free(x))
        n += X509_STORE_add_cert(st, x) == 1;
    BIO_free(b);
    ERR_clear_error();
    if (!n) {
        X509_STORE_free(st);
        snprintf(why, wn, "the CA %.300s holds no certificate", path);
        return -1;
    }
    memcpy(g_ca[slot].path, path, strlen(path) + 1);
    g_ca[slot].store = st;
    return 0;
}

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
    size_t rl = 0;
    if (u->tls) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) { snprintf(why, wn, "TLS setup failed"); goto done; }
        if (ca && ca_store(ca)) SSL_CTX_set1_cert_store(ctx, ca_store(ca));
        if (ca ? !ca_store(ca) : SSL_CTX_set_default_verify_paths(ctx) != 1) {
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
    rl = strlen(method) + strlen(path) + strlen(u->host) + strlen(headers) + 256;
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
    long long end = mono_ms() + (io_ms() > 0 ? io_ms() : 1);
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
    if (req) { OPENSSL_cleanse(req, rl); free(req); }     /* v1.28 review: it held a token */
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
    char version[160] = "", lease[140] = "";
    uint32_t lttl = 0;
    bool lrenew = false;
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
        long ll = lid ? jstr(lid, e, lease, sizeof lease - 1) : -1;
        if (ll > 0) {
            lease[ll] = '\0';
            snprintf(version, sizeof version, "lease:%s", lease);
            const char *ld = jget(body, e, "lease_duration"), *rn = jget(body, e, "renewable");
            if (ld && isdigit((unsigned char)*ld)) {
                unsigned long long t = strtoull(ld, NULL, 10);
                lttl = t > 86400ULL * 3650 ? 86400u * 3650 : (uint32_t)t;
            }
            lrenew = rn && e - rn >= 4 && !strncmp(rn, "true", 4);
        } else {
            lease[0] = '\0';
            snprintf(version, sizeof version, "kv1");
        }
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
    else if (lease[0] && strspn(lease, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/._-") !=
             strlen(lease))
        bad = "vault's lease id holds a character outside A-Z a-z 0-9 / . _ -";
    else bad = value_store(idx, (unsigned char *)val, (size_t)vl);
    if (val) { OPENSSL_cleanse(val, WS_MAX_VALUE + 1); free(val); }
    OPENSSL_cleanse(body, bl);
    free(body);
    if (!bad && lease[0]) {                                                  /* step 4 */
        memcpy(g_lease[idx].id, lease, sizeof lease);
        g_lease[idx].ttl = lttl;
        g_lease[idx].renewable = lrenew && lttl > 0;
        g_lease[idx].due_ms = mono_ms() + (long long)lttl * 2000 / 3;
        g_lease[idx].live = true;
    }
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
    /* v1.28 review: plain HTTP only to the metadata service's own address */
    bool imds = !strcmp(u.host, "169.254.169.254") || !strcmp(u.host, "fd00:ec2::254");
    snprintf(p, sizeof p, "%s/latest/api/token", u.path);
    if (http_do(&u, NULL, imds, "PUT", p, "X-aws-ec2-metadata-token-ttl-seconds: 60\r\n", "", 0, &st, &tok, &tl, why, wn) < 0)
        return -1;
    if (st != 200 || tl == 0 || tl > 512 || strpbrk(tok, "\r\n")) { snprintf(why, wn, "the metadata service gave no token"); goto out; }
    snprintf(h, sizeof h, "X-aws-ec2-metadata-token: %s\r\n", tok);
    snprintf(p, sizeof p, "%s/latest/meta-data/iam/security-credentials/", u.path);
    if (http_do(&u, NULL, imds, "GET", p, h, "", 0, &st, &role, &rl, why, wn) < 0) goto out;
    char *nl = strchr(role, '\n');
    if (nl) *nl = '\0';
    if (st != 200 || !role[0] || strlen(role) > 128 || strpbrk(role, "/ ")) {
        snprintf(why, wn, "the instance has no role");
        goto out;
    }
    snprintf(p, sizeof p, "%s/latest/meta-data/iam/security-credentials/%s", u.path, role);
    if (http_do(&u, NULL, imds, "GET", p, h, "", 0, &st, &cred, &cl, why, wn) < 0) goto out;
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

/* v1.28 review: the key material goes into request headers: printable
 * ASCII only (the metadata service's JSON, or a key file, could carry an
 * escaped or inner CR/LF) */
static bool aws_creds_ok(void) {
    const char *f[] = { g_aws.id, g_aws.secret, g_aws.token };
    for (size_t i = 0; i < 3; i++)
        for (const char *c = f[i]; *c; c++)
            if (*c < 0x21 || *c > 0x7e) return false;
    return g_aws.id[0] && g_aws.secret[0];
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
    if (!aws_creds_ok()) {
        report(idx, false, NULL, 0, "the AWS key, secret or session token holds a character that is not printable");
        return;
    }
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
    bool v6 = strchr(u.host, ':') != NULL;                /* review: as http_do sends it */
    snprintf(hosthdr, sizeof hosthdr, "%s%s%s%s%s", v6 ? "[" : "", u.host, v6 ? "]" : "", defport ? "" : ":",
             defport ? "" : u.port);
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
    OPENSSL_cleanse(canon, 16384);                       /* v1.28 review: the session token */
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

/* ---- step 4: the run's Vault leases ---- */

/* PUT /v1/sys/leases/OP with the run's token */
static int lease_put(const char *op, unsigned idx, uint32_t increment, int *status, char **out, size_t *ol,
                     char *why, size_t wn) {
    struct url u;
    if (url_parse(g_conf.vault_addr, &u) < 0) { snprintf(why, wn, "vault_addr is not an http(s) URL"); return -1; }
    char path[1100], hdr[TOKEN_MAX + 128], json[200];
    snprintf(path, sizeof path, "%s/v1/sys/leases/%s", u.path, op);
    snprintf(hdr, sizeof hdr, "X-Vault-Token: %s\r\nContent-Type: application/json\r\nAccept: application/json\r\n",
             g_vault_token);
    if (increment) snprintf(json, sizeof json, "{\"lease_id\":\"%s\",\"increment\":%u}", g_lease[idx].id, increment);
    else snprintf(json, sizeof json, "{\"lease_id\":\"%s\"}", g_lease[idx].id);
    int rc = http_do(&u, g_conf.vault_ca[0] ? g_conf.vault_ca : NULL, false, "PUT", path, hdr, json, strlen(json),
                     status, out, ol, why, wn);
    OPENSSL_cleanse(hdr, sizeof hdr);
    return rc;
}

/* Revoke every lease the run holds; then the token goes. */
static void leases_revoke_all(struct ws_revoked *r) {
    for (unsigned i = 0; i < WS_MAX_CREDS; i++) {
        if (!g_lease[i].live) continue;
        char why[256], *o = NULL;
        size_t ol = 0;
        int st = 0;
        if (lease_put("revoke", i, 0, &st, &o, &ol, why, sizeof why) == 0 && (st == 200 || st == 204)) r->revoked++;
        else r->failed++;
        if (o) { OPENSSL_cleanse(o, ol); free(o); }
        g_lease[i].live = false;
    }
    token_clear();
}

/* WS_MSG_REVOKE: the run is revoked; say how it went */
static void leases_revoke(void) {
    struct ws_revoked r = { .type = WS_MSG_REVOKED };
    leases_revoke_all(&r);
    ctl_send(&r, sizeof r);
}

/* Renew each renewable lease that is due, at two thirds of its lease; a
 * renewal that fails is reported and not retried (the secret is not
 * fetched again: the lease ends when Vault says) */
static void leases_renew(void) {
    long long now = mono_ms();
    for (unsigned i = 0; i < WS_MAX_CREDS; i++) {
        if (!g_lease[i].live || !g_lease[i].renewable || g_lease[i].due_ms > now) continue;
        struct ws_renewed m = { .type = WS_MSG_RENEWED, .index = i };
        char *o = NULL;
        size_t ol = 0;
        int st = 0;
        if (lease_put("renew", i, g_lease[i].ttl, &st, &o, &ol, m.why, sizeof m.why) < 0) {
        } else if (st != 200) {
            snprintf(m.why, sizeof m.why, "vault answered %d", st);
        } else {
            const char *ld = jget(o, o + ol, "lease_duration");
            if (!ld || !isdigit((unsigned char)*ld)) snprintf(m.why, sizeof m.why, "vault's answer has no lease_duration");
            else {
                unsigned long long t = strtoull(ld, NULL, 10);
                m.ok = 1;
                m.ttl = t > 86400ULL * 3650 ? 86400u * 3650 : (uint32_t)t;
            }
        }
        if (o) { OPENSSL_cleanse(o, ol); free(o); }
        if (m.ok && m.ttl > 0) {
            g_lease[i].ttl = m.ttl;
            g_lease[i].due_ms = mono_ms() + (long long)m.ttl * 2000 / 3;
        } else {
            g_lease[i].renewable = false;         /* at its longest, or failed: no more renewals */
        }
        ctl_send(&m, sizeof m);
    }
}

/* How long until the next renewal is due: -1 for none */
static int leases_wait(void) {
    long long next = -1, now = mono_ms();
    for (unsigned i = 0; i < WS_MAX_CREDS; i++)
        if (g_lease[i].live && g_lease[i].renewable && (next < 0 || g_lease[i].due_ms < next)) next = g_lease[i].due_ms;
    if (next < 0) return -1;
    if (next <= now) return 0;
    return next - now > 3600000 ? 3600000 : (int)(next - now);
}

/* ---- v1.28.1: identities (docs/security/v1.28.1-delegation-chain.md, section 2) ----
 *
 * The user's token: one JWT (compact form) in a file held as a file store.
 * Its header names the algorithm: RS256, PS256 (salt the hash's length),
 * ES256 or EdDSA (Ed25519); `none` and every HMAC algorithm are refused, as
 * is any other, and a `crit` header. Keys a token carries or points to (jwk,
 * jku, x5c, x5u) are never used: the keys are the issuer's, fetched over
 * verified HTTPS from the `jwks` URL the policy names or the issuer's
 * discovery document (whose `issuer` must be the policy's, and whose
 * `jwks_uri` must be https). The key is the one whose `kid` the token names,
 * or, when it names none, the issuer's only key for its algorithm. Then:
 * `iss` one the policy trusts, `aud` (a string or an array) holding that
 * issuer's audience, `exp` at least 60 s ahead, `nbf` and `iat` not more
 * than 60 s ahead, `sub` given; an `act` claim a chain of actors (RFC 8693),
 * each with its `sub` (and its `iss` if given), at most 8 deep. Every claim
 * recorded is printable ASCII, and a claim the checks read may appear once.
 *
 * The agent's X.509-SVID: a PEM file with the leaf certificate first, any
 * intermediates, and its private key (a file store: it holds the key). The
 * leaf has exactly one URI SAN, a SPIFFE ID in a trust domain the policy
 * trusts, is not a CA, may not sign certificates, chains (now) to that
 * domain's bundle, and matches the key. Checked as root, before the drop:
 * no network is needed. */

static struct ws_issuer g_iss[WS_MAX_ISSUERS];
static struct ws_spiffe g_spf[WS_MAX_SPIFFE];
static uint32_t g_niss, g_nspf;
/* v1.31: the MCP resources trusted for the user's token, and the
 * authorization servers found through them */
static struct ws_mcpres g_mcpres[WS_MAX_MCPRES];
static uint32_t g_nmcpres;
#define AS_PER_RESOURCE 4
static struct { char iss[256]; char jwks[1025]; uint32_t res; } g_found[WS_MAX_MCPRES * AS_PER_RESOURCE];
static uint32_t g_nfound;
static char g_found_why[400];             /* the first thing that failed, for a token none of them issued */
static void discover_mcp(void);
static struct ws_identity g_id;

/* base64url, unpadded, strict; the decoded length, or -1 */
static long b64url(const char *s, size_t n, unsigned char *out, size_t cap) {
    static signed char t[256];
    if (!t['B']) {
        memset(t, -1, sizeof t);
        const char *a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (int i = 0; i < 64; i++) t[(unsigned char)a[i]] = (signed char)i;
    }
    if (n % 4 == 1) return -1;
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        int v = t[(unsigned char)s[i]];
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (unsigned char)(acc >> bits);
        }
    }
    /* v1.28.1 review: the bits left over are zero (one encoding for each
     * value, so a token's hash names it) */
    if (bits && (acc & ((1u << bits) - 1))) return -1;
    return (long)o;
}

/* how many times key appears in the object at p (-1: not an object) */
static int jcount(const char *p, const char *e, const char *key) {
    p = jws(p, e);
    if (p >= e || *p != '{') return -1;
    p = jws(p + 1, e);
    if (p < e && *p == '}') return 0;
    int n = 0;
    for (;;) {
        char k[256];
        long kl = jstr(p, e, k, sizeof k - 1);
        const char *ke = jskip(p, e, 0);
        if (!ke || kl < 0) return -1;            /* review: a key jget could not read: unreadable */
        k[kl] = '\0';
        if ((size_t)kl == strlen(key) && !strcmp(k, key)) n++;
        p = jws(ke, e);
        if (p >= e || *p != ':') return -1;
        p = jskip(p + 1, e, 0);
        if (!p) return -1;
        p = jws(p, e);
        if (p < e && *p == ',') { p = jws(p + 1, e); continue; }
        return n;
    }
}

/* key's string value: 1, 0 when absent, -1 when not a string or too long
 * (cap includes the NUL); a key given twice is -1 */
static int jgets(const char *o, const char *e, const char *key, char *out, size_t cap) {
    int c = jcount(o, e, key);
    if (c == 0) return 0;
    if (c != 1) return -1;
    const char *v = jget(o, e, key);
    long n = v ? jstr(v, e, out, cap - 1) : -1;
    if (n < 0) return -1;
    out[n] = '\0';
    if (memchr(out, '\0', (size_t)n)) return -1;
    return 1;
}

/* a NumericDate (seconds; a fraction is dropped): 1, 0 when absent, -1 when
 * not a non-negative number below 2^53, or given twice */
static int jgetn(const char *o, const char *e, const char *key, int64_t *out) {
    int c = jcount(o, e, key);
    if (c == 0) return 0;
    if (c != 1) return -1;
    const char *g = jget(o, e, key);
    const char *v = g ? jws(g, e) : NULL;
    if (!v || v >= e || !isdigit((unsigned char)*v)) return -1;
    int64_t n = 0;
    const char *q = v;
    for (; q < e && isdigit((unsigned char)*q); q++) {
        if (q - v >= 16) return -1;
        n = n * 10 + (*q - '0');
    }
    if (q < e && *q == '.') for (q++; q < e && isdigit((unsigned char)*q); q++) { }
    if (q < e && (*q == 'e' || *q == 'E')) return -1;
    q = jws(q, e);                              /* review: nothing more in the number */
    if (q < e && *q != ',' && *q != '}') return -1;
    if (n >= (int64_t)1 << 53) return -1;
    *out = n;
    return 1;
}

/* the first element of the array at p, NULL when empty or not an array */
static const char *jarr_first(const char *p, const char *e) {
    p = jws(p, e);
    if (p >= e || *p != '[') return NULL;
    p = jws(p + 1, e);
    return p < e && *p != ']' ? p : NULL;
}

static const char *jarr_next(const char *p, const char *e) {
    p = jskip(p, e, 0);
    if (!p) return NULL;
    p = jws(p, e);
    return p < e && *p == ',' ? jws(p + 1, e) : NULL;
}

static bool printable(const char *s) {
    for (; *s; s++) if (*s < 0x20 || *s > 0x7e) return false;
    return true;
}

/* text from outside, fit to print: printable ASCII, at most 100 bytes */
static const char *shown(const char *s, char *buf, size_t cap) {
    size_t i = 0;
    for (; s[i] && i < 100 && i + 4 < cap; i++) buf[i] = s[i] >= 0x20 && s[i] <= 0x7e ? s[i] : '?';
    if (s[i]) { buf[i++] = '.'; buf[i++] = '.'; buf[i++] = '.'; }
    buf[i] = '\0';
    return buf;
}

/* GET an https URL's JSON (200); 0, or -1 with why */
static int get_json(const char *url, char **out, size_t *ol, char *why, size_t wn) {
    struct url u;
    char sb[128];
    bool odd = false;
    for (const char *c = url; *c; c++) odd |= *c <= 0x20 || *c >= 0x7f;     /* review: no space, CR or LF */
    if (odd || strlen(url) >= 1024 || url_parse(url, &u) < 0 || !u.tls) {
        snprintf(why, wn, "%s is not an https URL", shown(url, sb, sizeof sb));
        return -1;
    }
    int st = 0;
    /* v1.31 review: the path as written (url_parse trims a trailing '/' for
     * the base URLs it is also used for; a well-known URL keeps it) */
    const char *rp = strstr(url, "://");
    rp = rp ? strchr(rp + 3, '/') : NULL;
    if (http_do(&u, g_conf.oidc_ca[0] ? g_conf.oidc_ca : NULL, false, "GET", rp ? rp : "/",
                "Accept: application/json\r\n", "", 0, &st, out, ol, why, wn) < 0)
        return -1;
    if (st != 200) {
        snprintf(why, wn, "%s answered %d", shown(url, sb, sizeof sb), st);
        free(*out);
        *out = NULL;
        return -1;
    }
    return 0;
}

enum { ALG_RS256 = 1, ALG_PS256, ALG_ES256, ALG_EDDSA };

/* the key a JWK describes, for alg; NULL with why */
static EVP_PKEY *jwk_key(const char *k, const char *e, int alg, char *why, size_t wn) {
    char kty[16], crv[16], a[4096], b[4096];
    unsigned char ab[1024], bb[1024];
    EVP_PKEY *pk = NULL;
    if (jgets(k, e, "kty", kty, sizeof kty) != 1) { snprintf(why, wn, "the issuer's key has no kty"); return NULL; }
    if (alg == ALG_RS256 || alg == ALG_PS256) {
        if (strcmp(kty, "RSA")) { snprintf(why, wn, "the issuer's key for the token is not an RSA key"); return NULL; }
        long nl = jgets(k, e, "n", a, sizeof a) == 1 ? b64url(a, strlen(a), ab, sizeof ab) : -1;
        long el = jgets(k, e, "e", b, sizeof b) == 1 ? b64url(b, strlen(b), bb, sizeof bb) : -1;
        if (nl <= 0 || el <= 0 || el > 8) { snprintf(why, wn, "the issuer's RSA key is malformed"); return NULL; }
        BIGNUM *n = BN_bin2bn(ab, (int)nl, NULL), *x = BN_bin2bn(bb, (int)el, NULL);
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM *ps = NULL;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (n && x && bld && c && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, x) && (ps = OSSL_PARAM_BLD_to_param(bld)) &&
            EVP_PKEY_fromdata_init(c) == 1)
            (void)EVP_PKEY_fromdata(c, &pk, EVP_PKEY_PUBLIC_KEY, ps);
        OSSL_PARAM_free(ps);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(c);
        BN_free(n);
        BN_free(x);
        if (pk && EVP_PKEY_get_bits(pk) < 2048) {
            snprintf(why, wn, "the issuer's RSA key is shorter than 2048 bits");
            EVP_PKEY_free(pk);
            return NULL;
        }
    } else if (alg == ALG_ES256) {
        if (strcmp(kty, "EC") || jgets(k, e, "crv", crv, sizeof crv) != 1 || strcmp(crv, "P-256")) {
            snprintf(why, wn, "the issuer's key for the token is not a P-256 key");
            return NULL;
        }
        unsigned char pub[65] = { 4 };
        long xl = jgets(k, e, "x", a, sizeof a) == 1 ? b64url(a, strlen(a), pub + 1, 32) : -1;
        long yl = jgets(k, e, "y", b, sizeof b) == 1 ? b64url(b, strlen(b), pub + 33, 32) : -1;
        if (xl != 32 || yl != 32) { snprintf(why, wn, "the issuer's P-256 key is malformed"); return NULL; }
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM *ps = NULL;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (bld && c && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) &&
            OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof pub) &&
            (ps = OSSL_PARAM_BLD_to_param(bld)) && EVP_PKEY_fromdata_init(c) == 1)
            (void)EVP_PKEY_fromdata(c, &pk, EVP_PKEY_PUBLIC_KEY, ps);
        OSSL_PARAM_free(ps);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(c);
        if (pk) {                                         /* on the curve */
            EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_pkey(NULL, pk, NULL);
            int ok = pc && EVP_PKEY_public_check(pc) == 1;
            EVP_PKEY_CTX_free(pc);
            if (!ok) { EVP_PKEY_free(pk); pk = NULL; }
        }
    } else {
        if (strcmp(kty, "OKP") || jgets(k, e, "crv", crv, sizeof crv) != 1 || strcmp(crv, "Ed25519")) {
            snprintf(why, wn, "the issuer's key for the token is not an Ed25519 key");
            return NULL;
        }
        long xl = jgets(k, e, "x", a, sizeof a) == 1 ? b64url(a, strlen(a), ab, sizeof ab) : -1;
        if (xl == 32) pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, ab, 32);
    }
    if (!pk) snprintf(why, wn, "the issuer's key could not be read");
    ERR_clear_error();
    return pk;
}

/* the signature over the signing input, by alg; 1 good, 0 not */
static int jws_verify(EVP_PKEY *pk, int alg, const char *in, size_t inl, const unsigned char *sig, size_t sl) {
    unsigned char der[80];
    if (alg == ALG_ES256) {                               /* JOSE's r || s, as DER */
        if (sl != 64) return 0;
        BIGNUM *r = BN_bin2bn(sig, 32, NULL), *s = BN_bin2bn(sig + 32, 32, NULL);
        ECDSA_SIG *es = ECDSA_SIG_new();
        if (!r || !s || !es || ECDSA_SIG_set0(es, r, s) != 1) { BN_free(r); BN_free(s); ECDSA_SIG_free(es); return 0; }
        unsigned char *q = der;
        int dl = i2d_ECDSA_SIG(es, NULL);
        if (dl <= 0 || dl > (int)sizeof der) { ECDSA_SIG_free(es); return 0; }
        dl = i2d_ECDSA_SIG(es, &q);
        ECDSA_SIG_free(es);
        sig = der;
        sl = (size_t)dl;
    }
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int ok = mc && EVP_DigestVerifyInit(mc, &pc, alg == ALG_EDDSA ? NULL : EVP_sha256(), NULL, pk) == 1;
    if (ok && alg == ALG_RS256) ok = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PADDING) == 1;
    if (ok && alg == ALG_PS256)
        ok = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1 &&
             EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST) == 1 &&
             EVP_PKEY_CTX_set_rsa_mgf1_md(pc, EVP_sha256()) == 1;
    if (ok) ok = EVP_DigestVerify(mc, sig, sl, (const unsigned char *)in, inl) == 1;
    EVP_MD_CTX_free(mc);
    ERR_clear_error();
    return ok;
}

/* The user's token (g_user_token), as its own user. 0 with g_id filled, or
 * -1 with why (the check that failed). */

/* v1.31 review: the claims' aud (one, a string or an array) holds want */
static bool aud_holds(const char *pay, const char *pe, const char *want) {
    char aud[256];
    if (jcount(pay, pe, "aud") != 1) return false;
    const char *ag = jget(pay, pe, "aud");
    const char *av = ag ? jws(ag, pe) : NULL;
    if (av && *av == '"') return jgets(pay, pe, "aud", aud, sizeof aud) == 1 && !strcmp(aud, want);
    for (const char *x = jarr_first(av, pe); x; x = jarr_next(x, pe)) {
        long n = jstr(x, pe, aud, sizeof aud - 1);
        if (n >= 0) { aud[n] = '\0'; if ((size_t)n == strlen(want) && !strcmp(aud, want)) return true; }
    }
    return false;
}

static int verify_token_parts(char *why, size_t wn) {
    char sb[128], sb2[128];
    const char *tok = g_user_token;
    size_t tl = strlen(tok);
    const char *d1 = memchr(tok, '.', tl), *d2 = d1 ? memchr(d1 + 1, '.', tl - (size_t)(d1 + 1 - tok)) : NULL;
    if (!d1 || !d2 || memchr(d2 + 1, '.', tl - (size_t)(d2 + 1 - tok))) {
        snprintf(why, wn, "it is not a JWT in compact form (three parts)");
        return -1;
    }
    char *hdr = g_hdr, *pay = g_pay;
    unsigned char *sig = g_sig;
    long hl = b64url(tok, (size_t)(d1 - tok), (unsigned char *)hdr, HDR_MAX - 1);
    long pl = b64url(d1 + 1, (size_t)(d2 - d1 - 1), (unsigned char *)pay, WS_MAX_TOKEN - 1);
    long sl = b64url(d2 + 1, tl - (size_t)(d2 + 1 - tok), sig, SIG_MAX);
    if (hl <= 0 || pl <= 0 || sl < 0) { snprintf(why, wn, "a part is not base64url"); return -1; }
    hdr[hl] = pay[pl] = '\0';
    const char *he = hdr + hl, *pe = pay + pl;
    const char *hx = jskip(hdr, he, 0), *px = jskip(pay, pe, 0);
    if (memchr(hdr, '\0', (size_t)hl) || memchr(pay, '\0', (size_t)pl) || !hx || !px ||
        *jws(hdr, he) != '{' || jws(hx, he) != he || *jws(pay, pe) != '{' || jws(px, pe) != pe) {
        snprintf(why, wn, "its header or claims are not one JSON object");
        return -1;
    }
    /* v1.28.1 review: every member name readable (at most 255 bytes, its
     * escapes valid), so a claim is found the same way it is counted */
    if (jcount(hdr, he, "") < 0 || jcount(pay, pe, "") < 0) {
        snprintf(why, wn, "its header or claims hold a member name over 255 bytes, or one that cannot be read");
        return -1;
    }
    /* the algorithm, before any key */
    char alg[32], kid[256] = "";
    int a = jgets(hdr, he, "alg", alg, sizeof alg);
    if (a != 1) { snprintf(why, wn, "its header names no algorithm"); return -1; }
    if (!strcmp(alg, "none")) { snprintf(why, wn, "algorithm none is refused (an unsigned token)"); return -1; }
    if (!strncmp(alg, "HS", 2)) { snprintf(why, wn, "algorithm %s is refused (HMAC: the key would be shared)", shown(alg, sb, sizeof sb)); return -1; }
    int ai = !strcmp(alg, "RS256") ? ALG_RS256 : !strcmp(alg, "PS256") ? ALG_PS256 : !strcmp(alg, "ES256") ? ALG_ES256 :
             !strcmp(alg, "EdDSA") ? ALG_EDDSA : 0;
    if (!ai) { snprintf(why, wn, "algorithm %s is not one of RS256, PS256, ES256, EdDSA", shown(alg, sb, sizeof sb)); return -1; }
    if (jcount(hdr, he, "crit") != 0) { snprintf(why, wn, "its header has crit (an extension this Warden does not know)"); return -1; }
    int kr = jgets(hdr, he, "kid", kid, sizeof kid);
    if (kr < 0 || (kr == 1 && (!kid[0] || !printable(kid)))) { snprintf(why, wn, "its key id (kid) is malformed"); return -1; }
    /* the issuer, before its keys */
    char iss[256];
    if (jgets(pay, pe, "iss", iss, sizeof iss) != 1) { snprintf(why, wn, "it has no issuer (iss)"); return -1; }
    uint32_t ix = g_niss;
    for (uint32_t i = 0; i < g_niss; i++) if (!strcmp(g_iss[i].iss, iss)) { ix = i; break; }
    /* v1.31: else an authorization server of a trusted MCP resource */
    int fx = -1;
    if (ix == g_niss && g_nmcpres) {
        discover_mcp();
        for (uint32_t i = 0; i < g_nfound && fx < 0; i++) if (!strcmp(g_found[i].iss, iss)) fx = (int)i;
    }
    if (ix == g_niss && fx < 0) {
        snprintf(why, wn, "its issuer %s is not one the policy trusts%s%.300s%s", shown(iss, sb, sizeof sb),
                 g_found_why[0] ? " (trust mcp-resource: " : "", g_found_why, g_found_why[0] ? ")" : "");
        return -1;
    }
    const char *want_aud = fx >= 0 ? (g_mcpres[g_found[fx].res].aud[0] ? g_mcpres[g_found[fx].res].aud
                                                                      : g_mcpres[g_found[fx].res].url)
                                   : g_iss[ix].aud;
    /* its keys: the policy's jwks URL, or the discovery document's (v1.31:
     * or the authorization server's metadata's) */
    char *doc = NULL, *ks = NULL;
    size_t dl = 0, kl = 0;
    char jwks[1100];
    snprintf(jwks, sizeof jwks, "%s", fx >= 0 ? g_found[fx].jwks : g_iss[ix].jwks);
    if (!jwks[0]) {
        char disc[400], ub[1100];
        size_t il = strlen(iss);
        while (il && iss[il - 1] == '/') il--;
        snprintf(disc, sizeof disc, "%.*s/.well-known/openid-configuration", (int)il, iss);
        if (get_json(disc, &doc, &dl, ub, sizeof ub) < 0) {
            snprintf(why, wn, "the issuer's discovery document: %.400s", ub);
            return -1;
        }
        char diss[256];
        int r1 = jgets(doc, doc + dl, "issuer", diss, sizeof diss);
        int r2 = jgets(doc, doc + dl, "jwks_uri", jwks, sizeof jwks);
        free(doc);
        if (r1 != 1 || strcmp(diss, iss)) {
            snprintf(why, wn, "the issuer's discovery document names another issuer (%s)", r1 == 1 ? shown(diss, sb2, sizeof sb2) : "none");
            return -1;
        }
        if (r2 != 1) { snprintf(why, wn, "the issuer's discovery document has no jwks_uri"); return -1; }
    }
    {
        char ub[1100];
        if (get_json(jwks, &ks, &kl, ub, sizeof ub) < 0) { snprintf(why, wn, "the issuer's keys: %.400s", ub); return -1; }
    }
    const char *ke = ks + kl, *keys = jget(ks, ke, "keys");
    const char *pick = NULL;
    int ncompat = 0;
    static const char *const kKty[] = { "", "RSA", "RSA", "EC", "OKP" };
    for (const char *k = keys ? jarr_first(keys, ke) : NULL; k; k = jarr_next(k, ke)) {
        char kk[256], kty[16], use[16], kalg[32];
        if (*jws(k, ke) != '{') continue;
        int r = jgets(k, ke, "kid", kk, sizeof kk);
        /* review: a key named by kid but of another type is passed over (one
         * kid may name keys of several types); none of the right type: refused below */
        if (jgets(k, ke, "kty", kty, sizeof kty) != 1 || strcmp(kty, kKty[ai])) continue;
        /* review: use and alg, when given, must be readable and match */
        int ru = jgets(k, ke, "use", use, sizeof use), ra = jgets(k, ke, "alg", kalg, sizeof kalg);
        if (ru < 0 || (ru == 1 && strcmp(use, "sig")) || ra < 0 || (ra == 1 && strcmp(kalg, alg))) continue;
        if (kid[0]) {
            if (r == 1 && !strcmp(kk, kid)) { pick = k; break; }
        } else {
            ncompat++;
            pick = k;
        }
    }
    if (!kid[0] && ncompat > 1) {
        snprintf(why, wn, "it names no key (kid) and the issuer has %d keys for %s", ncompat, alg);
        free(ks);
        return -1;
    }
    if (!pick) {
        if (kid[0]) snprintf(why, wn, "its key %s is not among the issuer's keys", shown(kid, sb, sizeof sb));
        else snprintf(why, wn, "the issuer has no key for %s", alg);
        free(ks);
        return -1;
    }
    char kw[256];
    EVP_PKEY *pk = jwk_key(pick, ke, ai, kw, sizeof kw);
    free(ks);
    if (!pk) { snprintf(why, wn, "%s", kw); return -1; }
    int good = jws_verify(pk, ai, tok, (size_t)(d2 - tok), sig, (size_t)sl);
    EVP_PKEY_free(pk);
    if (!good) { snprintf(why, wn, "its signature does not verify with the issuer's key"); return -1; }
    /* the claims (signed: the issuer's) */
    bool aud_ok = aud_holds(pay, pe, want_aud);
    /* v1.31 review: an authorization server two trusted resources share:
     * the token is for one of them; the one its audience names */
    for (uint32_t i = 0; !aud_ok && fx >= 0 && i < g_nfound; i++) {
        if ((int)i == fx || strcmp(g_found[i].iss, iss)) continue;
        const char *wa = g_mcpres[g_found[i].res].aud[0] ? g_mcpres[g_found[i].res].aud : g_mcpres[g_found[i].res].url;
        if (aud_holds(pay, pe, wa)) { aud_ok = true; fx = (int)i; want_aud = wa; }
    }
    if (!aud_ok) { snprintf(why, wn, "its audience (aud) does not hold %s", want_aud); return -1; }
    int64_t exp = 0, nbf = -1, iat = -1, now = (int64_t)time(NULL);
    if (jgetn(pay, pe, "exp", &exp) != 1) { snprintf(why, wn, "it has no expiry (exp)"); return -1; }
    if (exp <= now) { snprintf(why, wn, "it expired %lld s ago", (long long)(now - exp)); return -1; }
    if (exp < now + LEEWAY_S) { snprintf(why, wn, "it expires in %lld s, under 60 s", (long long)(exp - now)); return -1; }
    int r = jgetn(pay, pe, "nbf", &nbf);
    if (r < 0) { snprintf(why, wn, "its nbf is malformed"); return -1; }
    if (r == 1 && nbf > now + LEEWAY_S) { snprintf(why, wn, "it is not valid for %lld s yet (nbf)", (long long)(nbf - now)); return -1; }
    r = jgetn(pay, pe, "iat", &iat);
    if (r < 0) { snprintf(why, wn, "its iat is malformed"); return -1; }
    if (r == 1 && iat > now + LEEWAY_S) { snprintf(why, wn, "it was issued %lld s in the future (iat)", (long long)(iat - now)); return -1; }
    if (jgets(pay, pe, "sub", g_id.sub, sizeof g_id.sub) != 1 || !g_id.sub[0]) {
        snprintf(why, wn, "it has no subject (sub), or one longer than 255 bytes");
        return -1;
    }
    if (!printable(g_id.sub)) { snprintf(why, wn, "its subject (sub) is not printable ASCII"); return -1; }
    r = jgets(pay, pe, "jti", g_id.jti, sizeof g_id.jti);
    if (r < 0 || !printable(g_id.jti)) { snprintf(why, wn, "its jti is malformed, or not printable ASCII"); return -1; }
    /* act: the current actor, then the one it acted for, ... */
    const char *o = pay;
    for (uint32_t depth = 0;; depth++) {
        int n = jcount(o, pe, "act");
        if (n == 0) break;
        if (n != 1) { snprintf(why, wn, "an act claim is given twice"); return -1; }
        if (depth == WS_MAX_ACTORS) { snprintf(why, wn, "its act chain is nested deeper than %d", WS_MAX_ACTORS); return -1; }
        const char *ag = jget(o, pe, "act");
        o = ag ? jws(ag, pe) : NULL;
        if (!o || o >= pe || *o != '{') { snprintf(why, wn, "an act claim is not an object"); return -1; }
        struct ws_actor *ac = &g_id.act[depth];
        if (jgets(o, pe, "sub", ac->sub, sizeof ac->sub) != 1 || !ac->sub[0] || !printable(ac->sub)) {
            snprintf(why, wn, "actor %u of its act chain has no printable subject (sub)", depth + 1);
            return -1;
        }
        if (jgets(o, pe, "iss", ac->iss, sizeof ac->iss) < 0 || !printable(ac->iss)) {
            snprintf(why, wn, "actor %u of its act chain has a malformed iss", depth + 1);
            return -1;
        }
        g_id.nact = depth + 1;
    }
    g_id.has_user = 1;
    g_id.issuer = fx >= 0 ? 0 : ix;
    if (fx >= 0) {                                       /* v1.31 */
        g_id.mcp_resource = g_found[fx].res + 1;
        snprintf(g_id.found_iss, sizeof g_id.found_iss, "%s", iss);
        snprintf(g_id.found_aud, sizeof g_id.found_aud, "%s", want_aud);
    }
    g_id.exp = exp;
    g_id.iat = iat;
    g_id.nbf = nbf;
    snprintf(g_id.alg, sizeof g_id.alg, "%.15s", alg);
    snprintf(g_id.kid, sizeof g_id.kid, "%s", kid);
    sha256_hex(tok, tl, g_id.token_sha256);
    {   /* v1.31 review: the signing input, so a re-signed copy is known too */
        const char *d1 = memchr(tok, '.', tl), *d2 = d1 ? memchr(d1 + 1, '.', tl - (size_t)(d1 + 1 - tok)) : NULL;
        sha256_hex(tok, d2 ? (size_t)(d2 - tok) : tl, g_id.token_sin_sha256);
    }
    return 0;
}

/* v1.31 step 5: a .well-known URL for id (an https URL with no query):
 * the well-known path inserted between its authority and its path (RFC 9728
 * section 3.1, RFC 8414 section 3.1), or appended (OpenID discovery). */
static int well_known(const char *id, const char *wk, bool append, char *out, size_t cap) {
    const char *auth = strncmp(id, "https://", 8) ? NULL : id + 8;
    if (!auth) return -1;
    const char *path = strchr(auth, '/');
    size_t al = path ? (size_t)(path - id) : strlen(id);
    if (!path || !strcmp(path, "/")) path = "";
    int n;
    if (append) {
        size_t il = strlen(id);
        while (il && id[il - 1] == '/') il--;
        n = snprintf(out, cap, "%.*s/.well-known/%s", (int)il, id, wk);
    } else n = snprintf(out, cap, "%.*s/.well-known/%s%s", (int)al, id, wk, path);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

/* v1.31 step 5: the authorization servers of each trusted MCP resource:
 * its protected resource metadata (RFC 9728), whose "resource" must be the
 * URL as written; for each of its first AS_PER_RESOURCE
 * authorization_servers, its metadata (RFC 8414, else OpenID discovery),
 * whose "issuer" must be identical to the identifier it was fetched for,
 * and its jwks_uri. What fails is kept for the refusal's reason. */
static void discover_mcp(void) {
    char sb[128];
    for (uint32_t k = 0; k < g_nmcpres; k++) {
        const char *url = g_mcpres[k].url;
        char prm[1100], ub[1100];
        char *doc = NULL;
        size_t dl = 0;
        if (well_known(url, "oauth-protected-resource", false, prm, sizeof prm) < 0) continue;
        if (get_json(prm, &doc, &dl, ub, sizeof ub) < 0) {
            if (!g_found_why[0]) snprintf(g_found_why, sizeof g_found_why, "%.120s: its metadata: %.250s", url, ub);
            continue;
        }
        char res[300];
        int rr = jgets(doc, doc + dl, "resource", res, sizeof res);
        if (rr != 1 || strcmp(res, url)) {
            if (!g_found_why[0]) snprintf(g_found_why, sizeof g_found_why, "%.120s: its metadata names another resource (%s)",
                                          url, rr == 1 ? shown(res, sb, sizeof sb) : "none");
            free(doc);
            continue;
        }
        if (jcount(doc, doc + dl, "authorization_servers") != 1) {     /* review: once, as resource is */
            if (!g_found_why[0]) snprintf(g_found_why, sizeof g_found_why, "%.120s: its metadata has authorization_servers "
                                          "other than once", url);
            free(doc);
            continue;
        }
        const char *ar = jget(doc, doc + dl, "authorization_servers");
        int nas = 0;
        for (const char *x = ar ? jarr_first(ar, doc + dl) : NULL; x && nas < AS_PER_RESOURCE; x = jarr_next(x, doc + dl), nas++) {
            char as[256], amd[1100], aw[1100];
            long al = jstr(x, doc + dl, as, sizeof as - 1);
            if (al <= 0) continue;
            as[al] = '\0';
            if (!printable(as)) continue;
            char *md = NULL;
            size_t ml = 0;
            bool got = false;
            for (int pass = 0; pass < 2 && !got; pass++) {
                if (well_known(as, pass ? "openid-configuration" : "oauth-authorization-server", pass == 1, amd, sizeof amd) < 0)
                    break;
                got = get_json(amd, &md, &ml, aw, sizeof aw) == 0;
            }
            if (!got) {
                if (!g_found_why[0]) snprintf(g_found_why, sizeof g_found_why, "authorization server %.100s: %.250s",
                                              shown(as, sb, sizeof sb), aw);
                continue;
            }
            char iss[256], jwks[1025];
            int r1 = jgets(md, md + ml, "issuer", iss, sizeof iss), r2 = jgets(md, md + ml, "jwks_uri", jwks, sizeof jwks);
            free(md);
            if (r1 != 1 || strcmp(iss, as)) {
                if (!g_found_why[0]) snprintf(g_found_why, sizeof g_found_why, "authorization server %.100s: its metadata "
                                              "names another issuer", shown(as, sb, sizeof sb));
                continue;
            }
            if (r2 != 1) {
                if (!g_found_why[0]) snprintf(g_found_why, sizeof g_found_why, "authorization server %.100s: its metadata "
                                              "has no jwks_uri", shown(as, sb, sizeof sb));
                continue;
            }
            if (g_nfound < sizeof g_found / sizeof *g_found) {
                snprintf(g_found[g_nfound].iss, sizeof g_found[g_nfound].iss, "%s", iss);
                snprintf(g_found[g_nfound].jwks, sizeof g_found[g_nfound].jwks, "%s", jwks);
                g_found[g_nfound++].res = k;
            }
        }
        free(doc);
    }
}

/* ... and nothing of it stays, whatever came of the checks */
static int verify_token(char *why, size_t wn) {
    int rc = verify_token_parts(why, wn);
    OPENSSL_cleanse(g_hdr, HDR_MAX);
    OPENSSL_cleanse(g_pay, WS_MAX_TOKEN);
    OPENSSL_cleanse(g_sig, SIG_MAX);
    return rc;
}

static int no_passphrase(char *buf, int size, int rw, void *u) { (void)buf; (void)size; (void)rw; (void)u; return -1; }

/* A SPIFFE ID: spiffe://DOMAIN/PATH, the domain [a-z0-9.-_], each path
 * segment [A-Za-z0-9.-_], none empty, `.` or `..`; at most 2048 bytes */
static bool spiffe_id_ok(const char *s, size_t n, size_t *dlen) {
    if (n > 2048 || n < 11 || strncmp(s, "spiffe://", 9)) return false;
    const char *d = s + 9, *sl = memchr(d, '/', n - 9);
    if (!sl || sl == d) return false;
    for (const char *c = d; c < sl; c++)
        if (!(islower((unsigned char)*c) || isdigit((unsigned char)*c) || *c == '.' || *c == '-' || *c == '_')) return false;
    *dlen = (size_t)(sl - d);
    const char *end = s + n, *seg = sl + 1;
    if (seg >= end) return false;
    for (const char *c = seg;; c++) {
        if (c == end || *c == '/') {
            size_t l = (size_t)(c - seg);
            if (l == 0 || (l == 1 && seg[0] == '.') || (l == 2 && seg[0] == '.' && seg[1] == '.')) return false;
            if (c == end) return true;
            seg = c + 1;
            continue;
        }
        if (!(isalnum((unsigned char)*c) || *c == '.' || *c == '-' || *c == '_')) return false;
    }
}

/* The agent's SVID (as root). 0 with g_id's SVID part filled, or -1 with why. */
static int verify_svid(const char *path, char *why, size_t wn) {
    static unsigned char buf[65536];
    size_t bl = 0;
    char rw[512];
    if (read_private(path, buf, sizeof buf, &bl, NULL, rw, sizeof rw) < 0) { snprintf(why, wn, "%.400s", rw); return -1; }
    int rc = -1;
    X509 *leaf = NULL;
    STACK_OF(X509) *chain = sk_X509_new_null();
    EVP_PKEY *key = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    GENERAL_NAMES *san = NULL;
    BIO *bio = BIO_new_mem_buf(buf, (int)bl);
    for (X509 *x; bio && chain && (x = PEM_read_bio_X509(bio, NULL, no_passphrase, NULL)); ) {
        if (!leaf) leaf = x;
        else if (!sk_X509_push(chain, x)) X509_free(x);
    }
    BIO_free(bio);
    bio = BIO_new_mem_buf(buf, (int)bl);
    if (bio) key = PEM_read_bio_PrivateKey(bio, NULL, no_passphrase, NULL);
    EVP_PKEY *key2 = key && bio ? PEM_read_bio_PrivateKey(bio, NULL, no_passphrase, NULL) : NULL;
    BIO_free(bio);
    /* review: one private key block, counted by its header (a second one that
     * cannot be read is still a second key) */
    int nkeys = 0;
    for (size_t i = 0; i + 11 <= bl; i++)
        if (!memcmp(buf + i, "-----BEGIN ", 11)) {
            const unsigned char *eol = memchr(buf + i, '\n', bl - i);
            size_t ll = eol ? (size_t)(eol - (buf + i)) : bl - i;
            if (memmem(buf + i, ll, "PRIVATE KEY-----", 16)) nkeys++;
        }
    OPENSSL_cleanse(buf, sizeof buf);
    ERR_clear_error();
    if (!leaf) { snprintf(why, wn, "%.300s holds no certificate", path); goto out; }
    if (!key || key2 || nkeys != 1) { snprintf(why, wn, "%.300s must hold exactly one private key (unencrypted)", path); goto out; }
    /* its SPIFFE ID: the one URI SAN */
    san = X509_get_ext_d2i(leaf, NID_subject_alt_name, NULL, NULL);
    const char *id = NULL;
    int idl = 0, nuri = 0;
    for (int i = 0; san && i < sk_GENERAL_NAME_num(san); i++) {
        GENERAL_NAME *g = sk_GENERAL_NAME_value(san, i);
        if (g->type != GEN_URI) continue;
        nuri++;
        id = (const char *)ASN1_STRING_get0_data(g->d.uniformResourceIdentifier);
        idl = ASN1_STRING_length(g->d.uniformResourceIdentifier);
    }
    size_t dlen = 0;
    if (nuri != 1) { snprintf(why, wn, "its certificate has %d URI names; an SVID has exactly one", nuri); goto out; }
    if (!spiffe_id_ok(id, (size_t)idl, &dlen) || memchr(id, '\0', (size_t)idl)) {
        snprintf(why, wn, "its URI name is not a SPIFFE ID (spiffe://DOMAIN/PATH)");
        goto out;
    }
    uint32_t sx = g_nspf;
    for (uint32_t i = 0; i < g_nspf; i++)
        if (strlen(g_spf[i].domain) == dlen && !strncmp(g_spf[i].domain, id + 9, dlen)) { sx = i; break; }
    char sb[128], idc[2049];
    memcpy(idc, id, (size_t)idl);
    idc[idl] = '\0';
    if (sx == g_nspf) { snprintf(why, wn, "its trust domain (%s) is not one the policy trusts", shown(idc, sb, sizeof sb)); goto out; }
    if (X509_check_ca(leaf) != 0) { snprintf(why, wn, "its certificate is a CA's"); goto out; }
    /* review: an X.509-SVID's leaf has basicConstraints (CA false) and a key
     * usage with digitalSignature (the SPIFFE X.509-SVID standard) */
    if (!(X509_get_extension_flags(leaf) & EXFLAG_BCONS)) {
        snprintf(why, wn, "its certificate has no basicConstraints (an SVID's says CA:false)");
        goto out;
    }
    uint32_t ku = X509_get_key_usage(leaf);
    if (ku == UINT32_MAX || (ku & (KU_KEY_CERT_SIGN | KU_CRL_SIGN)) || !(ku & KU_DIGITAL_SIGNATURE)) {
        snprintf(why, wn, "its certificate's key usage is not an SVID's (digitalSignature, no certificate or CRL signing)");
        goto out;
    }
    if (X509_check_private_key(leaf, key) != 1) { snprintf(why, wn, "its key does not match its certificate"); goto out; }
    /* the bundle for its trust domain */
    {
        static unsigned char bb[262144];
        size_t bbl = 0;
        if (read_file(g_spf[sx].bundle, WS_FILE_TRUSTED, bb, sizeof bb, &bbl, NULL, rw, sizeof rw) < 0) {
            snprintf(why, wn, "the bundle for %.100s: %.300s", g_spf[sx].domain, rw);
            goto out;
        }
        store = X509_STORE_new();
        BIO *b = BIO_new_mem_buf(bb, (int)bbl);
        int nroots = 0;
        for (X509 *x; store && b && (x = PEM_read_bio_X509(b, NULL, no_passphrase, NULL)); X509_free(x))
            nroots += X509_STORE_add_cert(store, x) == 1;
        BIO_free(b);
        ERR_clear_error();
        if (!nroots) { snprintf(why, wn, "the bundle for %s holds no certificate", g_spf[sx].domain); goto out; }
    }
    /* every certificate of the bundle is an anchor (a SPIFFE bundle is the
     * domain's signing authorities, not only self-signed roots) */
    X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_X509_STRICT);
    ctx = X509_STORE_CTX_new();
    if (!ctx || X509_STORE_CTX_init(ctx, store, leaf, chain) != 1) { snprintf(why, wn, "out of memory"); goto out; }
    if (X509_verify_cert(ctx) != 1) {
        snprintf(why, wn, "it does not chain to the bundle for %s: %s", g_spf[sx].domain,
                 X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        goto out;
    }
    struct tm tm;
    unsigned char *der = NULL;
    int derl = i2d_X509(leaf, &der);
    if (derl <= 0 || ASN1_TIME_to_tm(X509_get0_notAfter(leaf), &tm) != 1) { OPENSSL_free(der); snprintf(why, wn, "its certificate is malformed"); goto out; }
    sha256_hex(der, (size_t)derl, g_id.svid_sha256);
    OPENSSL_free(der);
    g_id.svid_not_after = (int64_t)timegm(&tm);
    memcpy(g_id.spiffe_id, idc, (size_t)idl + 1);
    g_id.spiffe = sx;
    g_id.has_svid = 1;
    rc = 0;
out:
    ERR_clear_error();
    GENERAL_NAMES_free(san);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    EVP_PKEY_free(key);
    EVP_PKEY_free(key2);
    X509_free(leaf);
    sk_X509_pop_free(chain, X509_free);
    return rc;
}

/* WS_MSG_IDENTITY: what was verified, or why not (printable, for the Warden) */
static void send_identity(bool ok, const char *why) {
    g_id.type = WS_MSG_IDENTITY;
    g_id.ok = ok;
    memset(g_id.why, 0, sizeof g_id.why);
    if (why) snprintf(g_id.why, sizeof g_id.why, "%s", why);
    for (char *c = g_id.why; *c; c++) if (*c < 0x20 || *c > 0x7e) *c = '?';
    if (!ok) {                                            /* nothing half-verified goes */
        char w[sizeof g_id.why];
        memcpy(w, g_id.why, sizeof w);
        memset(&g_id, 0, sizeof g_id);
        g_id.type = WS_MSG_IDENTITY;
        memcpy(g_id.why, w, sizeof w);
    }
    ctl_send(&g_id, sizeof g_id);
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
    /* v1.28 review: a store that resets the connection must not kill the
     * helper (SIGPIPE): it reports the failure instead */
    (void)signal(SIGPIPE, SIG_IGN);
    if (arena_init() < 0) return 2;
    /* the setup and the credentials */
    static struct ws_setup su;
    if (ctl_recv(&su, sizeof su) != (ssize_t)sizeof su || su.type != WS_MSG_SETUP || su.ncreds > WS_MAX_CREDS ||
        !memchr(su.conf, '\0', sizeof su.conf) || !memchr(su.token, '\0', sizeof su.token) ||
        !memchr(su.svid, '\0', sizeof su.svid) || su.nissuers > WS_MAX_ISSUERS || su.nspiffe > WS_MAX_SPIFFE ||
        su.nmcpres > WS_MAX_MCPRES || (su.nmcpres && !su.token[0] && !su.svid[0]))
        return 2;
    /* v1.28.1: the trusted issuers and trust domains */
    g_niss = su.nissuers;
    g_nspf = su.nspiffe;
    for (uint32_t i = 0; i < g_niss; i++)
        if (ctl_recv(&g_iss[i], sizeof g_iss[i]) != (ssize_t)sizeof g_iss[i] || g_iss[i].type != WS_MSG_ISSUER ||
            g_iss[i].index != i || !memchr(g_iss[i].iss, '\0', sizeof g_iss[i].iss) ||
            !memchr(g_iss[i].aud, '\0', sizeof g_iss[i].aud) || !memchr(g_iss[i].jwks, '\0', sizeof g_iss[i].jwks))
            return 2;
    for (uint32_t i = 0; i < g_nspf; i++)
        if (ctl_recv(&g_spf[i], sizeof g_spf[i]) != (ssize_t)sizeof g_spf[i] || g_spf[i].type != WS_MSG_SPIFFE ||
            g_spf[i].index != i || !memchr(g_spf[i].domain, '\0', sizeof g_spf[i].domain) ||
            !memchr(g_spf[i].bundle, '\0', sizeof g_spf[i].bundle))
            return 2;
    g_nmcpres = su.nmcpres;                   /* v1.31 */
    for (uint32_t i = 0; i < g_nmcpres; i++)
        if (ctl_recv(&g_mcpres[i], sizeof g_mcpres[i]) != (ssize_t)sizeof g_mcpres[i] || g_mcpres[i].type != WS_MSG_MCPRES ||
            g_mcpres[i].index != i || !memchr(g_mcpres[i].url, '\0', sizeof g_mcpres[i].url) ||
            !memchr(g_mcpres[i].aud, '\0', sizeof g_mcpres[i].aud))
            return 2;
    bool want_id = su.token[0] || su.svid[0];
    static struct ws_cred cr[WS_MAX_CREDS];
    bool need_vault = false, need_aws = false;
    for (uint32_t i = 0; i < su.ncreds; i++) {
        if (ctl_recv(&cr[i], sizeof cr[i]) != (ssize_t)sizeof cr[i] || cr[i].type != WS_MSG_CRED || cr[i].index != i ||
            !memchr(cr[i].ref, '\0', sizeof cr[i].ref) || cr[i].store < STORE_FILE || cr[i].store > STORE_AWSSM ||
            !memchr(cr[i].audience, '\0', sizeof cr[i].audience) || cr[i].opaque > 1 || (cr[i].opaque && !cr[i].audience[0]))
            return 2;
        memcpy(g_mcpcred[i].aud, cr[i].audience, sizeof g_mcpcred[i].aud);      /* v1.31 */
        g_mcpcred[i].opaque = cr[i].opaque;
        need_vault |= cr[i].store == STORE_VAULT;
        need_aws |= cr[i].store == STORE_AWSSM;
    }
    /* as root: the configuration and the local files */
    char why[512];
    bool failed = false;
    static unsigned char fbuf[65536];
    size_t fl;
    /* v1.28.1: an issuer's CA may be named in it; with no credential that
     * needs it, a configuration that is not there is not needed */
    bool conf_failed = false;
    char idwhy_ca[512] = "";
    if (su.conf[0] && (need_vault || need_aws || (su.token[0] && access(su.conf, F_OK) == 0))) {
        if (read_private(su.conf, fbuf, sizeof fbuf - 1, &fl, NULL, why, sizeof why) < 0 ||
            (fbuf[fl] = '\0', kv_parse((char *)fbuf, su.conf, conf_key, why, sizeof why) < 0)) {
            for (uint32_t i = 0; i < su.ncreds; i++)
                if (cr[i].store != STORE_FILE) report(i, false, NULL, 0, why);
            failed = true;
            conf_failed = true;
        }
    }
    /* v1.28.1 review: the CA files, as root, as trusted files */
    if (!failed) {
        const char *cas[3] = { need_vault ? g_conf.vault_ca : "", need_aws ? g_conf.aws_ca : "",
                               su.token[0] ? g_conf.oidc_ca : "" };
        for (int k = 0; k < 3; k++) {
            if (!cas[k][0] || ca_load(cas[k], why, sizeof why) == 0) continue;
            if (k == 2) {
                if (!conf_failed) { conf_failed = true; }
                if (want_id) snprintf(idwhy_ca, sizeof idwhy_ca, "the user's token: %.450s", why);
            } else {
                for (uint32_t i = 0; i < su.ncreds; i++)
                    if (cr[i].store == (k == 0 ? STORE_VAULT : STORE_AWSSM)) report(i, false, NULL, 0, why);
                failed = true;
            }
        }
    }
    if (!failed && need_vault && g_conf.vault_token_file[0]) {
        if (read_private(g_conf.vault_token_file, fbuf, TOKEN_MAX - 1, &fl, NULL, why, sizeof why) < 0) {
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
    /* v1.28.1: the user's token and the agent's SVID, as root (each a file
     * store); the SVID is checked here, the token once the keys are in */
    char idwhy[512] = "";
    bool id_failed = false;
    if (conf_failed && want_id) {                /* v1.28.1: say so, though no credential needed it */
        if (idwhy_ca[0]) snprintf(idwhy, sizeof idwhy, "%s", idwhy_ca);
        else snprintf(idwhy, sizeof idwhy, "%s: %.450s", su.token[0] ? "the user's token" : "the agent's SVID", why);
        id_failed = true;
    }
    if (!failed && su.token[0]) {
        size_t tl = 0;
        if (read_private(su.token, (unsigned char *)g_user_token, WS_MAX_TOKEN, &tl, NULL, why, sizeof why) < 0) {
            snprintf(idwhy, sizeof idwhy, "%s: %.450s", su.token[0] ? "the user's token" : "the agent's SVID", why);
            id_failed = true;
        } else {
            tl = chomp((unsigned char *)g_user_token, tl);
            g_user_token[tl] = '\0';
            if (!tl || strspn(g_user_token, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.") != tl) {
                snprintf(idwhy, sizeof idwhy, "the user's token: %.300s is not one JWT (base64url parts, one line)", su.token);
                id_failed = true;
            }
        }
    }
    if (!failed && !id_failed && su.svid[0]) {
        char w[480];
        if (verify_svid(su.svid, w, sizeof w) < 0) {
            snprintf(idwhy, sizeof idwhy, "the agent's SVID: %s", w);
            id_failed = true;
        }
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
    /* its own user, then the network: the identity first, so no store is
     * asked anything (no lease made) for a run that will not start */
    if (drop_to(u, g) < 0) return 2;
    g_deadline = mono_ms() + 25000;           /* v1.28.1 review: inside the Warden's 30 s */
    if (want_id && (!failed || id_failed)) {
        if (!id_failed && su.token[0]) {
            char w[480];
            if (verify_token(w, sizeof w) < 0) {
                snprintf(idwhy, sizeof idwhy, "the user's token: %s", w);
                id_failed = true;
            }
        }
        user_token_clear();
        send_identity(!id_failed, id_failed ? idwhy : NULL);
        failed |= id_failed;
    }
    user_token_clear();
    for (uint32_t i = 0; !failed && i < su.ncreds; i++) {
        if (cr[i].store == STORE_VAULT) vault_fetch(i, cr[i].ref);
        else if (cr[i].store == STORE_AWSSM) aws_fetch(i, cr[i].ref);
    }
    bool leased = false;
    for (uint32_t i = 0; i < su.ncreds; i++) leased |= g_lease[i].live;
    /* v1.28 review: no run: the leases made are revoked at once */
    if (failed && leased) { struct ws_revoked r = { 0 }; leases_revoke_all(&r); }
    if (failed || !leased) token_clear();
    OPENSSL_cleanse(&g_aws, sizeof g_aws);
    if (!failed) {
        size_t n = 0;
        for (uint32_t i = 0; i < su.ncreds; i++) n += g_val[i].len != 0;
        if (n == su.ncreds) {
            struct ws_ready y = { .type = WS_MSG_READY, .n = su.ncreds };
            ctl_send(&y, sizeof y);
        }
    }
    g_deadline = 0;                           /* renewals and revocations: each its own timeout */
    /* step 3: hand the values to warden-proxy, over the socket the Warden
     * gives, then clear them here; step 4: renew leases when due, revoke
     * them when asked; until the control socket closes */
    for (;;) {
        struct pollfd pf = { .fd = g_ctl, .events = POLLIN };
        int pr = poll(&pf, 1, leases_wait());
        if (pr < 0 && errno == EINTR) continue;
        if (pr < 0) break;
        if (pr == 0) { leases_renew(); continue; }
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
        if (r == (ssize_t)sizeof m && m.type == WS_MSG_REVOKE && fd < 0) {
            arena_clear();
            leases_revoke();
            continue;
        }
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
    /* v1.28 review: the run has ended (or the Warden refused it, or has gone):
     * its leases are revoked, not left to their duration */
    struct ws_revoked r = { 0 };
    leases_revoke_all(&r);
    token_clear();
    return 0;
}
