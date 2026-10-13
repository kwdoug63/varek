// SPDX-License-Identifier: MIT
// vdp_checker.c — VAREK certificate checker (v1.15). See vdp_checker.h.
//
// Written to be read: every function is short, there is no cache, no bit
// trick and no shortcut beyond what the definitions say. It shares no code
// with smt_decide.c and does not include its header.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE                   /* memmem */
#endif
#include "vdp_checker.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* SHA-256 (FIPS 180-4)                                                      */
/* ------------------------------------------------------------------------ */

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_block(uint32_t h[8], const unsigned char *b) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 |
               (uint32_t)b[4 * i + 2] << 8 | (uint32_t)b[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & bb) ^ (a & c) ^ (bb & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void vdpc_sha256(const void *data, size_t len, unsigned char out[32]) {
    uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    const unsigned char *p = data;
    size_t left = len;
    while (left >= 64) { sha256_block(h, p); p += 64; left -= 64; }
    unsigned char tail[128];
    memset(tail, 0, sizeof tail);
    memcpy(tail, p, left);
    tail[left] = 0x80;
    size_t tl = (left < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) tail[tl - 1 - i] = (unsigned char)(bits >> (8 * i));
    sha256_block(h, tail);
    if (tl == 128) sha256_block(h, tail + 64);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (unsigned char)(h[i] >> 24); out[4 * i + 1] = (unsigned char)(h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(h[i] >> 8); out[4 * i + 3] = (unsigned char)h[i];
    }
}

void vdpc_digest_hex(const vdpc_policy_t *p, char out[65]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i] = hx[p->sha256[i] >> 4];
        out[2 * i + 1] = hx[p->sha256[i] & 15];
    }
    out[64] = '\0';
}

/* ------------------------------------------------------------------------ */
/* Policy model                                                              */
/* ------------------------------------------------------------------------ */

/* x86_64 open(2) flag bits (uapi asm-generic/fcntl.h), by clause name. */
static const struct { const char *name; uint32_t bit; } FLAGS[] = {
    { "O_CREAT", 0100 },        { "O_EXCL", 0200 },          { "O_NOCTTY", 0400 },
    { "O_TRUNC", 01000 },       { "O_APPEND", 02000 },       { "O_NONBLOCK", 04000 },
    { "O_DSYNC", 010000 },      { "O_ASYNC", 020000 },       { "O_DIRECT", 040000 },
    { "O_LARGEFILE", 0100000 }, { "O_DIRECTORY", 0200000 },  { "O_NOFOLLOW", 0400000 },
    { "O_NOATIME", 01000000 },  { "O_CLOEXEC", 02000000 },   { "O_SYNC", 04000000 },
    { "O_PATH", 010000000 },    { "O_TMPFILE", 020000000 },
};
#define ACCMODE 3u

static uint32_t known_bits(void) {
    uint32_t k = ACCMODE;
    for (size_t i = 0; i < sizeof FLAGS / sizeof FLAGS[0]; i++) k |= FLAGS[i].bit;
    return k;
}

static uint32_t flag_named(const char *s) {
    for (size_t i = 0; i < sizeof FLAGS / sizeof FLAGS[0]; i++)
        if (!strcmp(s, FLAGS[i].name)) return FLAGS[i].bit;
    return 0;
}

enum { M_PREFIX = VDPC_M_PREFIX, M_EXACT = VDPC_M_EXACT, M_SUFFIX = VDPC_M_SUFFIX,
       M_CONTAINS = VDPC_M_CONTAINS, M_GLOB = VDPC_M_GLOB, M_HOST = VDPC_M_HOST };
enum { G_LIT, G_SET, G_STAR, G_DSTAR, G_SEGS };

typedef struct {
    int           type;
    unsigned char byte;               /* G_LIT */
    unsigned char set[32];            /* G_SET: bit b of set = byte b allowed */
} gtok_t;

struct vdpc_rule {
    bool     allow;
    int      kind;
    int      match;
    char    *c;                       /* the constant (for a glob, the pattern) */
    size_t   clen;
    gtok_t  *g;                       /* glob tokens */
    size_t   ng;
    /* Glob pre-filters, read off the tokens: a match starts with the literal
     * tokens before the first other token, ends with the literal tokens after
     * the last other token, and has at least one byte per literal or set
     * token (exactly that many if there is no stretch token). */
    size_t   npre, nsuf, minlen;
    bool     fixed;
    uint32_t mask, value;             /* flag atom (f & mask) == value */
    int      line;
    bool     portless;                /* host: no port, so every port matches */
    bool     name;                    /* host (v1.24): a host name rule */
    bool     wild;                    /* host (v1.25): a wildcard rule, held as a glob */
    uint32_t names, rate;             /* host (v1.25): a wildcard allow rule's budgets, 0: not set */
    uint32_t max_body;                /* request (v1.26.1): max_body=, 0: not set */
    char     rhost[254];              /* request (v1.26.1): the URL's host (a wildcard's suffix) */
    /* request (v1.26.1 review): a URL without a query: 1, an allow rule (holds
     * on no string with a '?'); 2, a deny rule (holds when the glob matches
     * the string up to its first '?'); 0, the glob alone */
    int      qmode;
    bool     rwild;
    unsigned rport;
    int      cred;                    /* request (v1.28): 1 + credential index, 0: none */
    char     hdr[65], scheme[33];     /* request (v1.28): header=NAME[:SCHEME] */
    char     subagent[33];            /* exec (v1.28.1): subagent=NAME ("" : none) */
    int      subj;                    /* v1.31: for=NAME: 1 + the subject's index; 0: the agent */
    int      csubj;                   /* v1.31: the confined subject this rule launches, 0: none */
    bool     confined;                /* v1.31: `confined` was given (registered by vdpc_load) */
    bool     mcp_server;              /* v1.31: an `mcp server` line */
    char     sha256[65];              /* v1.31: its sha256= */
};

void vdpc_free(vdpc_policy_t *p) {
    for (size_t i = 0; i < p->n; i++) {
        free(p->rules[i].c);
        free(p->rules[i].g);
    }
    free(p->rules);
    p->rules = NULL;
    p->n = 0;
}

static bool set_has(const unsigned char set[32], unsigned b) { return (set[b / 8] >> (b % 8)) & 1; }
static void set_add(unsigned char set[32], unsigned b) { set[b / 8] |= (unsigned char)(1u << (b % 8)); }

/* ------------------------------------------------------------------------ */
/* Glob parsing                                                              */
/* ------------------------------------------------------------------------ */

static int push_tok(gtok_t **v, size_t *n, size_t *cap, gtok_t t) {
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        gtok_t *nv = realloc(*v, nc * sizeof *nv);
        if (!nv) return -1;
        *v = nv;
        *cap = nc;
    }
    (*v)[(*n)++] = t;
    return 0;
}

/* Returns NULL on success, else an error text. */
static const char *parse_glob(const char *pat, size_t len, gtok_t **out, size_t *nout) {
    gtok_t *v = NULL;
    size_t n = 0, cap = 0;
    int wild = 0;
    bool slash_before = false;        /* the previous token is an unescaped '/' or a unit */
    size_t i = 0;
    const char *e = NULL;
    while (i < len && !e) {
        gtok_t t;
        memset(&t, 0, sizeof t);
        char ch = pat[i];
        if (ch == '\\') {
            if (i + 1 >= len) { e = "glob ends in a lone backslash"; break; }
            t.type = G_LIT;
            t.byte = (unsigned char)pat[i + 1];
            i += 2;
            slash_before = false;
        } else if (ch == '*' && i + 1 < len && pat[i + 1] == '*') {
            if (i + 2 < len && pat[i + 2] == '*') { e = "'***' in a glob"; break; }
            if (slash_before && i + 2 < len && pat[i + 2] == '/') {
                t.type = G_SEGS;              /* the '/' before is already a token */
                i += 3;
                slash_before = true;
            } else {
                t.type = G_DSTAR;
                i += 2;
                slash_before = false;
            }
            wild++;
        } else if (ch == '*') {
            t.type = G_STAR;
            i += 1;
            slash_before = false;
            wild++;
        } else if (ch == '?') {
            t.type = G_SET;
            for (unsigned b = 1; b < 256; b++) if (b != '/') set_add(t.set, b);
            i += 1;
            slash_before = false;
            wild++;
        } else if (ch == '[') {
            size_t j = i + 1;
            bool neg = false;
            if (j < len && (pat[j] == '!' || pat[j] == '^')) { neg = true; j++; }
            unsigned char m[32];
            memset(m, 0, sizeof m);
            bool first = true, closed = false;
            while (j < len && !e) {
                unsigned char lo = (unsigned char)pat[j];
                if (lo == ']' && !first) { closed = true; j++; break; }
                first = false;
                if (lo == '\\') {
                    if (j + 1 >= len) { e = "glob ends in a lone backslash"; break; }
                    j++;
                    lo = (unsigned char)pat[j];
                }
                j++;
                unsigned char hi = lo;
                if (j + 1 < len && pat[j] == '-' && pat[j + 1] != ']') {
                    j++;
                    hi = (unsigned char)pat[j];
                    if (hi == '\\') {
                        if (j + 1 >= len) { e = "glob ends in a lone backslash"; break; }
                        j++;
                        hi = (unsigned char)pat[j];
                    }
                    j++;
                    if (hi < lo) { e = "bad range in a glob set"; break; }
                }
                for (unsigned b = lo; b <= hi; b++) {
                    if (b == '/') { e = "'/' in a glob set"; break; }
                    set_add(m, b);
                }
            }
            if (e) break;
            if (!closed) { e = "unterminated '[' in a glob"; break; }
            t.type = G_SET;
            for (unsigned b = 1; b < 256; b++) {
                bool in = set_has(m, b);
                if (neg ? (!in && b != '/') : in) set_add(t.set, b);
            }
            i = j;
            slash_before = false;
            wild++;
        } else {
            t.type = G_LIT;
            t.byte = (unsigned char)ch;
            i += 1;
            slash_before = (ch == '/');
        }
        if (wild > VDPC_MAX_STRETCH) { e = "more than 32 wildcards in a glob"; break; }
        if (push_tok(&v, &n, &cap, t) < 0) { e = "out of memory"; break; }
    }
    if (e) { free(v); return e; }
    *out = v;
    *nout = n;
    return NULL;
}

/* ------------------------------------------------------------------------ */
/* Policy parsing                                                            */
/* ------------------------------------------------------------------------ */

static int fail(char *err, size_t n, const char *name, int line, const char *fmt, ...) {
    if (err && n) {
        int k = snprintf(err, n, "%s:%d: ", name, line);
        if (k < 0) k = 0;
        if ((size_t)k < n) {
            va_list ap;
            va_start(ap, fmt);
            vsnprintf(err + k, n - (size_t)k, fmt, ap);
            va_end(ap);
        }
    }
    return -1;
}

/* v1.26 section 5: "http://HOST:PORT" (one trailing '/'), HOST a host name
 * (LDH labels 1-63, at most 253, last label not all digits) or a dotted IPv4
 * address without leading zeros, PORT 1-65535. 0 (host lowercased), or -1. */
static int up_parse(const char *v, char host[254], unsigned *port) {
    if (strncmp(v, "http://", 7) != 0) return -1;
    const char *a = v + 7;
    size_t n = strlen(a);
    if (n > 0 && a[n - 1] == '/') n--;
    size_t c = n;
    while (c > 0 && a[c - 1] != ':') c--;
    if (c == 0) return -1;
    size_t hl = c - 1, pl = n - c;
    if (pl < 1 || pl > 5 || a[c] == '0') return -1;
    unsigned long x = 0;
    for (size_t i = c; i < n; i++) {
        if (!isdigit((unsigned char)a[i])) return -1;
        x = x * 10 + (unsigned long)(a[i] - '0');
    }
    if (x < 1 || x > 65535 || hl < 1 || hl > 253) return -1;
    int dots = 0, alpha = 0;
    for (size_t i = 0; i < hl; i++) {
        unsigned char ch = (unsigned char)a[i];
        if (ch == '.') dots++;
        else if (isalpha(ch) || ch == '-') alpha++;
        else if (!isdigit(ch)) return -1;
    }
    if (!alpha) {                                     /* an IPv4 address */
        if (dots != 3) return -1;
        size_t i = 0;
        for (int part = 0; part < 4; part++) {
            size_t st = i;
            unsigned long o = 0;
            while (i < hl && a[i] != '.') o = o * 10 + (unsigned long)(a[i++] - '0');
            if (i == st || i - st > 3 || (i - st > 1 && a[st] == '0') || o > 255) return -1;
            i++;
        }
    } else {                                          /* a host name */
        size_t st = 0;
        for (size_t i = 0; i <= hl; i++) {
            if (i < hl && a[i] != '.') continue;
            size_t ll = i - st;
            if (ll < 1 || ll > 63 || a[st] == '-' || a[i - 1] == '-') return -1;
            st = i + 1;
        }
        size_t last = hl;
        while (last > 0 && a[last - 1] != '.') last--;
        bool all_digits = true;
        for (size_t i = last; i < hl; i++) if (!isdigit((unsigned char)a[i])) all_digits = false;
        if (all_digits) return -1;
    }
    for (size_t i = 0; i < hl; i++) host[i] = (char)tolower((unsigned char)a[i]);
    host[hl] = '\0';
    *port = (unsigned)x;
    return 0;
}

static bool is_ws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'; }

static bool is_clause(const char *t) {
    return !strcmp(t, "readonly") || !strcmp(t, "access=ro") || !strcmp(t, "access=wo") ||
           !strcmp(t, "access=rw") || ((t[0] == '+' || t[0] == '-') && flag_named(t + 1));
}

/* "<1-6 digits>.<1-6 digits>" */
static bool parse_ver(const char *s, int *maj, int *mn) {
    int v[2] = { 0, 0 };
    for (int part = 0; part < 2; part++) {
        int nd = 0;
        while (*s >= '0' && *s <= '9') {
            if (++nd > 6) return false;
            v[part] = v[part] * 10 + (*s - '0');
            s++;
        }
        if (nd == 0) return false;
        if (part == 0) { if (*s != '.') return false; s++; }
    }
    if (*s) return false;
    *maj = v[0];
    *mn = v[1];
    return true;
}

static bool ver_ge(int a, int b, int c, int d) { return a > c || (a == c && b >= d); }

static bool ipv4_quad(const char *c, size_t n);

/* v1.24: a host constant in name form (written independently of
 * smt_decide.c's vdp_host_name_form, which documents the form). 0: a numeric
 * form ('[', "unix:", or only digits and dots before the first ':'), 1: a
 * valid name constant, -1: in name form but not a valid name. */
static int host_name_form(const char *c, size_t n, const char **why) {
    if (n > 0 && c[0] == '[') return 0;
    if (n >= 5 && memcmp(c, "unix:", 5) == 0) return 0;
    size_t h = 0;
    bool only_num = true;
    while (h < n && c[h] != ':') {
        if (c[h] != '.' && (c[h] < '0' || c[h] > '9')) only_num = false;
        h++;
    }
    if (only_num) return 0;
    if (memchr(c, '*', h)) { *why = "wildcard host name"; return -1; }
    if (h > 253) { *why = "host name over 253 bytes"; return -1; }
    size_t lab = 0;                   /* bytes in the current label */
    bool lab_digits = true;
    for (size_t i = 0; i < h; i++) {
        char ch = c[i];
        if (ch == '.') {
            if (lab == 0 || c[i - 1] == '-') { *why = "bad label"; return -1; }
            lab = 0;
            lab_digits = true;
            continue;
        }
        bool lower = ch >= 'a' && ch <= 'z', digit = ch >= '0' && ch <= '9';
        if (!lower && !digit && ch != '-') { *why = "byte not allowed in a host name"; return -1; }
        if (lab == 0 && ch == '-') { *why = "bad label"; return -1; }
        if (++lab > 63) { *why = "label over 63 bytes"; return -1; }
        if (!digit) lab_digits = false;
    }
    if (lab == 0 || c[h - 1] == '-') { *why = "bad label"; return -1; }   /* trailing dot or '-' */
    if (lab_digits) { *why = "last label all digits"; return -1; }
    if (h == 4 && memcmp(c, "unix", 4) == 0) { *why = "host name unix is reserved"; return -1; }
    if (h < n) {
        size_t pl = n - h - 1;
        unsigned long v = 0;
        if (pl < 1 || pl > 5 || (pl > 1 && c[h + 1] == '0')) { *why = "bad port"; return -1; }
        for (size_t i = h + 1; i < n; i++) {
            if (c[i] < '0' || c[i] > '9') { *why = "bad port"; return -1; }
            v = v * 10 + (unsigned long)(c[i] - '0');
        }
        if (v > 65535) { *why = "bad port"; return -1; }
    }
    return 1;
}

/* v1.26.1: METHOD and URL of a request rule (smt_decide.h has the grammar),
 * as the glob over "METHOD scheme://host:port/path?query" (each '?' of the
 * URL escaped). 0 with r->c set, or -1 with *why. */
static int hexd(char c) {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
         : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

static int req_parse(const char *m, const char *u, vdpc_rule_t *r, const char **why) {
    *why = "";
    size_t ml = strlen(m);
    if (!(ml == 1 && m[0] == '*')) {
        if (ml < 1 || ml > 20) { *why = "bad method"; return -1; }
        for (size_t i = 0; i < ml; i++) if (m[i] < 'A' || m[i] > 'Z') { *why = "bad method"; return -1; }
    }
    size_t sl;
    unsigned port;
    if (strncmp(u, "https://", 8) == 0) { sl = 5; port = 443; }
    else if (strncmp(u, "http://", 7) == 0) { sl = 4; port = 80; }
    else { *why = "bad request URL scheme"; return -1; }
    const char *a = u + sl + 3;
    size_t al = 0;
    while (a[al] && a[al] != '/') al++;
    if (!a[al]) { *why = "request URL without a path"; return -1; }
    size_t hl = 0;
    while (hl < al && a[hl] != ':') hl++;
    if (hl < al) {
        size_t pl = al - hl - 1;
        unsigned long x = 0;
        if (pl < 1 || pl > 5 || a[hl + 1] == '0') { *why = "bad request URL port"; return -1; }
        for (size_t i = hl + 1; i < al; i++) {
            if (a[i] < '0' || a[i] > '9') { *why = "bad request URL port"; return -1; }
            x = x * 10 + (unsigned long)(a[i] - '0');
        }
        if (x < 1 || x > 65535) { *why = "bad request URL port"; return -1; }
        port = (unsigned)x;
    }
    bool wild = hl >= 2 && a[0] == '*' && a[1] == '.';
    const char *h = wild ? a + 2 : a;
    size_t hn = wild ? hl - 2 : hl;
    if (hn < 1 || hn > 253) { *why = "bad request URL host"; return -1; }
    if (host_name_form(h, hn, why) != 1) { if (!**why) *why = "bad request URL host"; return -1; }
    if (wild && !memchr(h, '.', hn)) { *why = "wildcard over one label"; return -1; }
    /* path and query */
    const char *p = a + al;
    size_t pl = strlen(p);
    bool q = false;
    size_t segst = 1;
    for (size_t i = 1; i <= pl; i++) {
        char c = i < pl ? p[i] : '\0';
        if (!q && (c == '/' || c == '?' || c == '\0')) {
            size_t n = i - segst;
            if (n == 0 && c == '/') { *why = "empty path segment"; return -1; }
            if (n == 1 && p[segst] == '.') { *why = "dot segment"; return -1; }
            if (n == 2 && p[segst] == '.' && p[segst + 1] == '.') { *why = "dot segment"; return -1; }
            segst = i + 1;
            if (c == '?') q = true;
            if (c == '\0') break;
            continue;
        }
        if (c == '\0') break;
        unsigned char b = (unsigned char)c;
        if (b <= 0x20 || b >= 0x7f || b == '\\' || b == ';' || b == '#') { *why = "byte not allowed in a request path"; return -1; }
        if (b == '?') { *why = "more than one '?' in a request URL"; return -1; }   /* review */
        if (b == '%') {
            if (i + 2 >= pl) { *why = "bad percent escape"; return -1; }
            int d1 = hexd(p[i + 1]), d2 = hexd(p[i + 2]);
            if (d1 < 0 || d2 < 0) { *why = "bad percent escape"; return -1; }
            unsigned v = (unsigned)(d1 * 16 + d2);
            if (v == '/' || v == '\\' || (v >= '0' && v <= '9') || (v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z') ||
                v == '-' || v == '.' || v == '_' || v == '~') {
                *why = "percent escape of '/' or an unreserved byte"; return -1;
            }
        }
    }
    if (p[0] != '/') { *why = "request path"; return -1; }
    /* the glob */
    char head[300];
    int n = snprintf(head, sizeof head, "%.*s %.*s://%s%.*s:%u", (int)ml, m, (int)sl, u,
                     wild ? "?*." : "", (int)hn, h, port);
    if (n < 0 || (size_t)n >= sizeof head) { *why = "request object over the bound"; return -1; }
    size_t nq = 0;
    for (size_t i = 0; i < pl; i++) if (p[i] == '?') nq++;
    size_t gl = (size_t)n + pl + nq;
    if (gl > VDPC_MAX_S) { *why = "request object over the bound"; return -1; }
    char *g = malloc(gl + 1);
    if (!g) { *why = "out of memory"; return -1; }
    memcpy(g, head, (size_t)n);
    size_t k = (size_t)n;
    for (size_t i = 0; i < pl; i++) {
        if (p[i] == '?') g[k++] = '\\';
        g[k++] = p[i];
    }
    g[k] = '\0';
    r->c = g;
    r->clen = k;
    r->match = M_GLOB;
    memcpy(r->rhost, h, hn);
    r->rhost[hn] = '\0';
    r->rwild = wild;
    r->rport = port;
    return 0;
}

/* One line: tokens (NUL-terminated copies in `line`). Returns -1 on error. */
/* v1.28: an HTTP token character (RFC 9110 tchar) */
static bool tchar(unsigned char c) {
    if (c >= '0' && c <= '9') return true;
    if ((c | 0x20) >= 'a' && (c | 0x20) <= 'z') return true;
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+': case '-':
    case '.': case '^': case '_': case '`': case '|': case '~': return true;
    default: return false;
    }
}

static bool all_tchar(const char *s, size_t n, size_t max) {
    if (n == 0 || n > max) return false;
    for (size_t i = 0; i < n; i++) if (!tchar((unsigned char)s[i])) return false;
    return true;
}

/* v1.28: does a lowercase copy of h name a framing header? */
static bool framing_header(const char *h) {
    char low[65];
    size_t n = strlen(h);
    if (n >= sizeof low) return false;
    for (size_t i = 0; i <= n; i++) low[i] = (char)((h[i] >= 'A' && h[i] <= 'Z') ? h[i] + 32 : h[i]);
    /* v1.28 review: each name compared whole ('|' is a token character, so
     * a search in a '|'-joined list matched "te|trailer") */
    static const char *const kFraming[] = { "host", "content-length", "transfer-encoding", "connection",
                                            "upgrade", "te", "trailer", "keep-alive", "proxy-connection",
                                            "proxy-authorization" };
    for (size_t i = 0; i < sizeof kFraming / sizeof *kFraming; i++)
        if (!strcmp(low, kFraming[i])) return true;
    return false;
}

/* v1.28.1: [a-z][a-z0-9_]{0,31}, a credential's or a sub-agent's name */
static bool short_name(const char *n) {
    size_t nl = strlen(n);
    if (nl < 1 || nl > 32 || n[0] < 'a' || n[0] > 'z') return false;
    for (size_t i = 1; i < nl; i++)
        if (!((n[i] >= 'a' && n[i] <= 'z') || (n[i] >= '0' && n[i] <= '9') || n[i] == '_')) return false;
    return true;
}

/* v1.28.1: an absolute path with no empty, "." or ".." segment */
static bool clean_abs_path(const char *r) {
    size_t rl = strlen(r);
    if (r[0] != '/' || rl < 2) return false;
    const char *seg = r + 1;
    for (;;) {
        const char *e = strchr(seg, '/');
        size_t sl = e ? (size_t)(e - seg) : strlen(seg);
        if (sl == 0 || (sl == 1 && seg[0] == '.') || (sl == 2 && seg[0] == '.' && seg[1] == '.')) return false;
        if (!e) return true;
        seg = e + 1;
    }
}

/* v1.28.1: bytes 0x21 to 0x7e, lo to hi of them */
static bool printable(const char *v, size_t lo, size_t hi) {
    size_t l = strlen(v);
    if (l < lo || l > hi) return false;
    for (size_t i = 0; i < l; i++)
        if ((unsigned char)v[i] <= 0x20 || (unsigned char)v[i] >= 0x7f) return false;
    return true;
}

/* v1.28.1: an https URL with a host, at most hi bytes */
static bool https_with_host(const char *u, size_t hi) {
    return printable(u, 9, hi) && !strncmp(u, "https://", 8) && u[8] != '/' && u[8] != '?' && u[8] != '#';
}

/* v1.31: an MCP server's URL in canonical form, "scheme://host:port/path"
 * (vdp_checker.h; smt_decide.h's vdp_mcp_url has the same form, written
 * separately). 0, or -1. host (254 bytes) and *port are set when given. */
static int mcp_canon(const char *u, int https_only, char *out, size_t outn, char *host, unsigned *port) {
    size_t skip;
    unsigned pt;
    const char *sch;
    if (!strncmp(u, "https://", 8)) { skip = 8; pt = 443; sch = "https"; }
    else if (!https_only && !strncmp(u, "http://", 7)) { skip = 7; pt = 80; sch = "http"; }
    else return -1;
    const char *a = u + skip;
    size_t al = 0;
    while (a[al] && a[al] != '/') al++;
    size_t hl = 0;
    while (hl < al && a[hl] != ':') hl++;
    if (hl < al) {
        size_t dl = al - hl - 1;
        unsigned long x = 0;
        if (dl < 1 || dl > 5 || a[hl + 1] == '0') return -1;
        for (size_t i = hl + 1; i < al; i++) {
            if (a[i] < '0' || a[i] > '9') return -1;
            x = x * 10 + (unsigned long)(a[i] - '0');
        }
        if (x < 1 || x > 65535) return -1;
        pt = (unsigned)x;
    }
    if (hl < 1 || hl > 253) return -1;
    for (size_t i = 0; i < hl; i++) if (a[i] == '@' || a[i] == '*') return -1;
    const char *why = "";
    if (host_name_form(a, hl, &why) != 1) return -1;
    const char *path = a[al] ? a + al : "/";
    size_t pl = strlen(path);
    /* segments: none empty but the last, none "." or ".." */
    size_t st = 1;
    for (size_t i = 1; i <= pl; i++) {
        if (i < pl && path[i] != '/') continue;
        size_t n = i - st;
        if (n == 0 && i < pl) return -1;
        if ((n == 1 && path[st] == '.') || (n == 2 && path[st] == '.' && path[st + 1] == '.')) return -1;
        st = i + 1;
    }
    for (size_t i = 0; i < pl; i++) {
        unsigned char b = (unsigned char)path[i];
        if (b <= 0x20 || b >= 0x7f) return -1;
        if (b == '\\' || b == ';' || b == '#' || b == '?' || b == '*' || b == '[' || b == ']') return -1;
        if (b == '%') {
            if (i + 2 >= pl) return -1;
            int d1 = hexd(path[i + 1]), d2 = hexd(path[i + 2]);
            if (d1 < 0 || d2 < 0) return -1;
            unsigned v = (unsigned)(d1 * 16 + d2);
            if (v == '/' || v == '\\' || (v >= '0' && v <= '9') || (v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z') ||
                v == '-' || v == '.' || v == '_' || v == '~')
                return -1;
        }
    }
    int n = snprintf(out, outn, "%s://%.*s:%u%s", sch, (int)hl, a, pt, path);
    if (n < 0 || (size_t)n >= outn) return -1;
    if (host) { memcpy(host, a, hl); host[hl] = '\0'; }
    if (port) *port = pt;
    return 0;
}

/* v1.31: an MCP method (with '*' when glob) */
static bool mcp_method(const char *m, bool glob) {
    size_t ml = strlen(m);
    if (ml < 1 || ml > 128) return false;
    for (size_t i = 0; i < ml; i++) {
        char c = m[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '.' || c == '/' || c == '-' || (glob && c == '*');
        if (!ok) return false;
    }
    return true;
}

/* v1.31: a shell, an interpreter, the loader or a launcher, by basename (the
 * list smt_decide.c keeps, written here again) */
static bool runs_others(const char *path) {
    static const char *const kAny[] = {
        "sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "ash", "busybox",
        "python", "python2", "python3", "pypy", "pypy3", "perl", "ruby", "node", "nodejs",
        "deno", "bun", "php", "lua", "luajit", "tclsh", "wish", "pwsh", "Rscript", "R",
        "julia", "guile", "awk", "gawk", "mawk", "nawk", "java", "jshell", "osascript",
        "rbash", "toybox", "ipython", "ipython3", "gdb", "expect", NULL
    };
    static const char *const kLaunchers[] = {
        "npx", "npm", "pnpm", "pnpx", "yarn", "bunx", "corepack", "uvx", "uv", "pipx", "pip", "pip3",
        "docker", "podman", "nerdctl", "ctr", "env", "sudo", "doas", "su", "nix", "nix-shell",
        "flatpak", "snap", "xargs", "nohup", "setsid", "timeout", "stdbuf", "nice", "ionice",
        "chroot", "unshare", "nsenter", "systemd-run", "runuser", "sg", NULL
    };
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    for (size_t i = 0; kLaunchers[i]; i++) if (!strcmp(b, kLaunchers[i])) return true;
    if (!strncmp(b, "ld-linux", 8) || !strncmp(b, "ld-musl", 7) || !strcmp(b, "ld.so")) return true;
    if (!strncmp(b, "ld-", 3) && b[3] >= '0' && b[3] <= '9' && strstr(b, ".so")) return true;
    for (size_t i = 0; kAny[i]; i++) {
        size_t k = strlen(kAny[i]);
        if (strncmp(b, kAny[i], k)) continue;
        const char *t = b + k;
        while (*t && ((*t >= '0' && *t <= '9') || *t == '.')) t++;
        if (!*t) return true;
    }
    return false;
}

/* v1.31: 1 + the index of the confined subject named n, or 0 */
static int subj_named(const vdpc_policy_t *p, const char *n) {
    for (size_t k = 0; k < p->nsubjects; k++)
        if (!strcmp(p->subjects[k].name, n)) return (int)k + 1;
    return 0;
}

/* v1.31: register rule i's sub-agent as a confined subject */
static int subj_register(vdpc_policy_t *p, size_t i, bool mcp, char *err, size_t en, const char *name, int ln) {
    vdpc_rule_t *r = &p->rules[i];
    if (subj_named(p, r->subagent)) return fail(err, en, name, ln, "a confined subject declared twice");
    for (size_t j = 0; j < i; j++)
        if (p->rules[j].subagent[0] && !p->rules[j].csubj && !strcmp(p->rules[j].subagent, r->subagent))
            return fail(err, en, name, ln, "a confined name already used by an unconfined sub-agent");
    if (p->nsubjects == 32) return fail(err, en, name, ln, "more than 32 confined subjects");
    vdpc_subject_t *sj = &p->subjects[p->nsubjects++];
    memcpy(sj->name, r->subagent, strlen(r->subagent) + 1);
    sj->rule = (int)i;
    sj->mcp = mcp;
    sj->line = ln;
    r->csubj = (int)p->nsubjects;
    return 0;
}

/* v1.31: mcp server NAME exec PATH [sha256=HEX], held as an allow exec rule */
static int parse_mcp_server(const char *name, int ln, char **tok, int nt, int req_maj, int req_min,
                            vdpc_rule_t *r, char *err, size_t en) {
    memset(r, 0, sizeof *r);
    r->line = ln;
    if (!ver_ge(req_maj, req_min, 1, 31)) return fail(err, en, name, ln, "mcp server before 1.31");
    if (!((nt == 5 || nt == 6) && !strcmp(tok[1], "server") && !strcmp(tok[3], "exec")))
        return fail(err, en, name, ln, "bad mcp server directive");
    if (!short_name(tok[2])) return fail(err, en, name, ln, "bad server name");
    if (!printable(tok[4], 2, 1024) || !clean_abs_path(tok[4])) return fail(err, en, name, ln, "bad server path");
    if (runs_others(tok[4])) return fail(err, en, name, ln, "a server's file is an interpreter or a launcher");
    if (nt == 6) {
        if (strncmp(tok[5], "sha256=", 7) || strlen(tok[5]) != 71) return fail(err, en, name, ln, "bad sha256");
        for (const char *q = tok[5] + 7; *q; q++)
            if (!((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f'))) return fail(err, en, name, ln, "bad sha256");
        memcpy(r->sha256, tok[5] + 7, 65);
    }
    size_t cl = strlen(tok[4]);
    r->c = malloc(cl + 1);
    if (!r->c) return fail(err, en, name, ln, "out of memory");
    memcpy(r->c, tok[4], cl + 1);
    r->clen = cl;
    r->allow = true;
    r->kind = VDPC_EXEC;
    r->match = M_EXACT;
    memcpy(r->subagent, tok[2], strlen(tok[2]) + 1);
    r->mcp_server = true;
    return 0;
}

/* v1.31: <verb> mcp URL METHOD [NAME] [max_body=N] [credential=C [header=H[:S]]] [for=NAME] */
static int parse_mcp_rule(const char *name, int ln, char **tok, int nt, int req_maj, int req_min,
                          size_t *glob_total, vdpc_rule_t *r, char *err, size_t en, const vdpc_policy_t *pol) {
    if (!ver_ge(req_maj, req_min, 1, 31)) return fail(err, en, name, ln, "mcp rule before 1.31");
    if (nt < 4) return fail(err, en, name, ln, "bad mcp rule");
    char cu[4200];
    if (mcp_canon(tok[2], 0, cu, sizeof cu, r->rhost, &r->rport) < 0) return fail(err, en, name, ln, "bad MCP URL");
    if (!mcp_method(tok[3], true)) return fail(err, en, name, ln, "bad MCP method");
    int k = 4;
    const char *nm = "**";
    if (nt > 4 && strncmp(tok[4], "max_body=", 9) && strncmp(tok[4], "credential=", 11) &&
        strncmp(tok[4], "header=", 7) && strncmp(tok[4], "for=", 4)) {
        if (!printable(tok[4], 1, 4095)) return fail(err, en, name, ln, "bad MCP name");
        nm = tok[4];
        k = 5;
    }
    size_t gl = strlen(cu) + 1 + strlen(tok[3]) + 1 + strlen(nm);
    if (gl > VDPC_MAX_S) return fail(err, en, name, ln, "mcp object over the bound");
    r->c = malloc(gl + 1);
    if (!r->c) return fail(err, en, name, ln, "out of memory");
    snprintf(r->c, gl + 1, "%s#%s#%s", cu, tok[3], nm);
    r->clen = gl;
    r->match = M_GLOB;
    const char *ge = parse_glob(r->c, r->clen, &r->g, &r->ng);
    if (ge) return fail(err, en, name, ln, "%s", ge);
    *glob_total += r->ng;
    if (*glob_total > VDPC_GLOB_MAX_TOTAL) return fail(err, en, name, ln, "glob tokens over the policy total");
    r->fixed = true;
    for (size_t q = 0; q < r->ng; q++) {
        if (r->g[q].type == G_LIT || r->g[q].type == G_SET) r->minlen++;
        else r->fixed = false;
    }
    while (r->npre < r->ng && r->g[r->npre].type == G_LIT) r->npre++;
    while (r->nsuf < r->ng && r->g[r->ng - 1 - r->nsuf].type == G_LIT) r->nsuf++;
    bool hdr = false;
    for (; k < nt; k++) {
        const char *t = tok[k];
        if (!strncmp(t, "for=", 4)) {
            if (r->subj) return fail(err, en, name, ln, "for= given twice");
            if (!(r->subj = subj_named(pol, t + 4))) return fail(err, en, name, ln, "for= names no confined subject");
            continue;
        }
        if (!r->allow) return fail(err, en, name, ln, "an option on a deny mcp rule");
        if (!strncmp(t, "credential=", 11)) {
            if (r->cred) return fail(err, en, name, ln, "credential given twice");
            for (size_t q = 0; q < pol->ncreds && !r->cred; q++)
                if (!strcmp(pol->creds[q].name, t + 11)) r->cred = (int)q + 1;
            if (!r->cred) return fail(err, en, name, ln, "unknown credential");
        } else if (!strncmp(t, "header=", 7)) {
            if (hdr) return fail(err, en, name, ln, "header given twice");
            const char *v = t + 7, *colon = strchr(v, ':');
            size_t hn = colon ? (size_t)(colon - v) : strlen(v);
            if (!all_tchar(v, hn, 64) || (colon && !all_tchar(colon + 1, strlen(colon + 1), 32)))
                return fail(err, en, name, ln, "bad header");
            memcpy(r->hdr, v, hn);
            r->hdr[hn] = '\0';
            if (colon) memcpy(r->scheme, colon + 1, strlen(colon + 1) + 1);
            if (framing_header(r->hdr)) return fail(err, en, name, ln, "a framing header");
            hdr = true;
        } else if (!strncmp(t, "max_body=", 9)) {
            if (r->max_body) return fail(err, en, name, ln, "max_body given twice");
            const char *d = t + 9;
            size_t dl = strlen(d);
            unsigned long long mul = 1, x = 0;
            if (dl > 0 && d[dl - 1] == 'k') { mul = 1024; dl--; }
            else if (dl > 0 && d[dl - 1] == 'm') { mul = 1024 * 1024; dl--; }
            if (dl < 1 || dl > 7 || d[0] == '0') return fail(err, en, name, ln, "bad max_body");
            for (size_t q = 0; q < dl; q++) {
                if (d[q] < '0' || d[q] > '9') return fail(err, en, name, ln, "bad max_body");
                x = x * 10 + (unsigned long long)(d[q] - '0');
            }
            x *= mul;
            if (x > 1073741824ULL) return fail(err, en, name, ln, "bad max_body");
            r->max_body = (uint32_t)x;
        } else return fail(err, en, name, ln, "unknown mcp rule option");
    }
    if (hdr && !r->cred) return fail(err, en, name, ln, "header without credential");
    if (r->cred) {
        const vdpc_cred_t *cr = &pol->creds[r->cred - 1];
        if (strncmp(cu, "https://", 8)) return fail(err, en, name, ln, "credential on http");
        if (!hdr) { memcpy(r->hdr, "Authorization", 14); memcpy(r->scheme, "Bearer", 7); }
        if (cr->audience[0] && strcmp(cr->audience, cu)) return fail(err, en, name, ln, "a token for another server");
        if (cr->audience[0] && (strcasecmp(r->hdr, "authorization") || strcasecmp(r->scheme, "bearer")))
            return fail(err, en, name, ln, "an MCP access token outside Authorization: Bearer");
    }
    return 0;
}

/* v1.28.1: trust issuer URL audience AUD [jwks URL] | trust spiffe DOMAIN bundle PATH */
static int parse_trust(const char *name, int ln, char **tok, int nt, vdpc_policy_t *p, char *err, size_t en,
                       int req_maj, int req_min) {
    if (nt >= 2 && !strcmp(tok[1], "mcp-resource")) {        /* v1.31 */
        if (!ver_ge(req_maj, req_min, 1, 31)) return fail(err, en, name, ln, "mcp-resource before 1.31");
        if (!(nt == 3 || (nt == 5 && !strcmp(tok[3], "audience"))))
            return fail(err, en, name, ln, "bad trust mcp-resource directive");
        char cu[4200];
        if (strlen(tok[2]) > 255 || mcp_canon(tok[2], 1, cu, sizeof cu, NULL, NULL) < 0)
            return fail(err, en, name, ln, "bad MCP resource URL");
        if (nt == 5 && !printable(tok[4], 1, 255)) return fail(err, en, name, ln, "bad audience");
        for (size_t k = 0; k < p->nmcpres; k++)
            if (!strcmp(p->mcpres[k].url, tok[2])) return fail(err, en, name, ln, "MCP resource trusted twice");
        if (p->nmcpres == 8) return fail(err, en, name, ln, "more than 8 MCP resources");
        vdpc_mcpres_t *m = &p->mcpres[p->nmcpres++];
        memcpy(m->url, tok[2], strlen(tok[2]) + 1);
        if (nt == 5) memcpy(m->aud, tok[4], strlen(tok[4]) + 1);
        m->line = ln;
        return 0;
    }
    if (nt >= 2 && !strcmp(tok[1], "issuer")) {
        if (!((nt == 5 || nt == 7) && !strcmp(tok[3], "audience") && (nt == 5 || !strcmp(tok[5], "jwks"))))
            return fail(err, en, name, ln, "bad trust issuer directive");
        if (!https_with_host(tok[2], 255) || !printable(tok[4], 1, 255) ||
            (nt == 7 && !https_with_host(tok[6], 1024)))
            return fail(err, en, name, ln, "bad issuer, audience or jwks");
        for (size_t k = 0; k < p->nissuers; k++)
            if (!strcmp(p->issuers[k].iss, tok[2])) return fail(err, en, name, ln, "issuer trusted twice");
        if (p->nissuers == VDPC_MAX_ISSUERS) return fail(err, en, name, ln, "more than 8 issuers");
        vdpc_issuer_t *is = &p->issuers[p->nissuers++];
        memcpy(is->iss, tok[2], strlen(tok[2]) + 1);
        memcpy(is->aud, tok[4], strlen(tok[4]) + 1);
        if (nt == 7) memcpy(is->jwks, tok[6], strlen(tok[6]) + 1);
        is->line = ln;
        return 0;
    }
    if (nt >= 2 && !strcmp(tok[1], "spiffe")) {
        if (nt != 5 || strcmp(tok[3], "bundle")) return fail(err, en, name, ln, "bad trust spiffe directive");
        const char *d = tok[2];
        size_t dl = strlen(d);
        bool ok = dl >= 1 && dl <= 255 && ((d[0] >= 'a' && d[0] <= 'z') || (d[0] >= '0' && d[0] <= '9'));
        for (size_t i = 0; ok && i < dl; i++)
            ok = (d[i] >= 'a' && d[i] <= 'z') || (d[i] >= '0' && d[i] <= '9') || strchr("._-", d[i]);
        if (!ok) return fail(err, en, name, ln, "bad trust domain");
        if (!printable(tok[4], 2, 1024) || !clean_abs_path(tok[4])) return fail(err, en, name, ln, "bad bundle path");
        for (size_t k = 0; k < p->nspiffe; k++)
            if (!strcmp(p->spiffe[k].domain, d)) return fail(err, en, name, ln, "trust domain twice");
        if (p->nspiffe == VDPC_MAX_SPIFFE) return fail(err, en, name, ln, "more than 8 trust domains");
        vdpc_spiffe_t *sp = &p->spiffe[p->nspiffe++];
        memcpy(sp->domain, d, dl + 1);
        memcpy(sp->bundle, tok[4], strlen(tok[4]) + 1);
        sp->line = ln;
        return 0;
    }
    return fail(err, en, name, ln, "bad trust directive");
}

/* v1.28: credential NAME from STORE:REF; 0, or -1 (the reason in err) */
static int parse_credential(const char *name, int ln, char **tok, int nt, vdpc_policy_t *p,
                            char *err, size_t en, int req_maj, int req_min) {
    if (nt < 4 || nt > 6 || strcmp(tok[2], "from")) return fail(err, en, name, ln, "bad credential directive");
    /* v1.31: audience=URL [opaque] */
    char aud[4200] = "";
    if (nt >= 5) {
        if (!ver_ge(req_maj, req_min, 1, 31)) return fail(err, en, name, ln, "audience before 1.31");
        if (strncmp(tok[4], "audience=", 9) || (nt == 6 && strcmp(tok[5], "opaque")))
            return fail(err, en, name, ln, "bad credential directive");
        if (mcp_canon(tok[4] + 9, 1, aud, sizeof aud, NULL, NULL) < 0)
            return fail(err, en, name, ln, "bad audience URL");
    }
    const char *n = tok[1];
    size_t nl = strlen(n);
    bool ok = nl >= 1 && nl <= 32 && n[0] >= 'a' && n[0] <= 'z';
    for (size_t i = 1; ok && i < nl; i++)
        ok = (n[i] >= 'a' && n[i] <= 'z') || (n[i] >= '0' && n[i] <= '9') || n[i] == '_';
    if (!ok) return fail(err, en, name, ln, "bad credential name");
    for (size_t k = 0; k < p->ncreds; k++)
        if (!strcmp(p->creds[k].name, n)) return fail(err, en, name, ln, "credential named twice");
    if (p->ncreds == VDPC_MAX_CREDS) return fail(err, en, name, ln, "more than 32 credentials");
    const char *v = tok[3];
    int store;
    size_t pl;
    if (!strncmp(v, "file:", 5))        { store = 1; pl = 5; }
    else if (!strncmp(v, "vault:", 6))  { store = 2; pl = 6; }
    else if (!strncmp(v, "aws-sm:", 7)) { store = 3; pl = 7; }
    else return fail(err, en, name, ln, "bad credential store");
    const char *r = v + pl;
    size_t rl = strlen(r);
    if (rl == 0 || rl > 1024) return fail(err, en, name, ln, "bad credential reference");
    for (size_t i = 0; i < rl; i++)
        if ((unsigned char)r[i] <= 0x20 || (unsigned char)r[i] >= 0x7f)
            return fail(err, en, name, ln, "bad credential reference");
    if (store == 1) {
        /* an absolute path: segments between '/'s, none empty, "." or ".." */
        if (r[0] != '/' || rl < 2) return fail(err, en, name, ln, "bad file credential path");
        const char *seg = r + 1;
        for (;;) {
            const char *e = strchr(seg, '/');
            size_t sl = e ? (size_t)(e - seg) : strlen(seg);
            if (sl == 0 || (sl == 1 && seg[0] == '.') || (sl == 2 && seg[0] == '.' && seg[1] == '.'))
                return fail(err, en, name, ln, "bad file credential path");
            if (!e) break;
            seg = e + 1;
        }
    } else if (store == 2) {
        const char *h = strchr(r, '#');
        if (!h || h == r || r[0] == '/' || strchr(h + 1, '#') || h[1] == '\0')
            return fail(err, en, name, ln, "bad vault credential reference");
        for (const char *q = h + 1; *q; q++) {
            char c = *q;
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '.' || c == '-'))
                return fail(err, en, name, ln, "bad vault credential field");
        }
    } else if (rl < 4 || memcmp(r, "arn:", 4) || !strstr(r, ":secretsmanager:")) {
        return fail(err, en, name, ln, "bad aws-sm credential reference");
    }
    vdpc_cred_t *c = &p->creds[p->ncreds++];
    memcpy(c->name, n, nl + 1);
    memcpy(c->ref, r, rl + 1);
    c->store = store;
    c->line = ln;
    memcpy(c->audience, aud, strlen(aud) + 1);
    c->opaque = nt == 6;
    return 0;
}

static int parse_rule(const char *name, int ln, char **tok, int nt, int req_maj, int req_min,
                      int *legacy_name, size_t *glob_total, vdpc_rule_t *r, char *err, size_t en,
                      const vdpc_policy_t *pol) {
    memset(r, 0, sizeof *r);
    r->line = ln;
    if (!strcmp(tok[0], "allow")) r->allow = true;
    else if (strcmp(tok[0], "deny")) return fail(err, en, name, ln, "unknown verb");
    if (!strcmp(tok[1], "path"))      { r->kind = VDPC_PATH; r->match = M_PREFIX; }
    else if (!strcmp(tok[1], "host")) { r->kind = VDPC_HOST; r->match = M_HOST; }
    else if (!strcmp(tok[1], "exec")) { r->kind = VDPC_EXEC; r->match = M_EXACT; }
    else if (!strcmp(tok[1], "request")) r->kind = VDPC_REQUEST;      /* v1.26.1 */
    else if (!strcmp(tok[1], "mcp")) r->kind = VDPC_MCP;              /* v1.31 */
    else return fail(err, en, name, ln, "unknown kind");

    if (r->kind == VDPC_MCP)
        return parse_mcp_rule(name, ln, tok, nt, req_maj, req_min, glob_total, r, err, en, pol);

    if (r->kind == VDPC_REQUEST) {
        /* v1.26.1: <verb> request METHOD URL [max_body=N] */
        if (!ver_ge(req_maj, req_min, 1, 26)) return fail(err, en, name, ln, "request rule before 1.26");
        if (nt < 4) return fail(err, en, name, ln, "bad request rule");
        for (int k = 2; k < 4; k++)
            for (const char *q = tok[k]; *q; q++)
                if ((unsigned char)*q < 0x20 || *q == 0x7f) return fail(err, en, name, ln, "control byte in constant");
        const char *why = "";
        if (req_parse(tok[2], tok[3], r, &why) < 0) return fail(err, en, name, ln, "%s", why);
        if (!strchr(tok[3], '?')) r->qmode = r->allow ? 1 : 2;      /* review: no query */
        const char *ge = parse_glob(r->c, r->clen, &r->g, &r->ng);
        if (ge) return fail(err, en, name, ln, "%s", ge);
        *glob_total += r->ng;
        if (*glob_total > VDPC_GLOB_MAX_TOTAL) return fail(err, en, name, ln, "glob tokens over the policy total");
        r->fixed = true;
        for (size_t k = 0; k < r->ng; k++) {
            if (r->g[k].type == G_LIT || r->g[k].type == G_SET) r->minlen++;
            else r->fixed = false;
        }
        while (r->npre < r->ng && r->g[r->npre].type == G_LIT) r->npre++;
        while (r->nsuf < r->ng && r->g[r->ng - 1 - r->nsuf].type == G_LIT) r->nsuf++;
        bool hdr = false;
        for (int k = 4; k < nt; k++) {
            const char *t = tok[k];
            if (!strncmp(t, "for=", 4)) {                         /* v1.31 */
                if (!ver_ge(req_maj, req_min, 1, 31)) return fail(err, en, name, ln, "for= before 1.31");
                if (r->subj) return fail(err, en, name, ln, "for= given twice");
                if (!(r->subj = subj_named(pol, t + 4))) return fail(err, en, name, ln, "for= names no confined subject");
                continue;
            }
            /* v1.28: credential=NAME, header=NAME[:SCHEME], on allow rules after 1.28 */
            if (!strncmp(t, "credential=", 11) || !strncmp(t, "header=", 7)) {
                if (!ver_ge(req_maj, req_min, 1, 28)) return fail(err, en, name, ln, "credential option before 1.28");
                if (!r->allow) return fail(err, en, name, ln, "credential option on a deny rule");
                if (t[0] == 'c') {
                    if (r->cred) return fail(err, en, name, ln, "credential given twice");
                    for (size_t q = 0; q < pol->ncreds && !r->cred; q++)
                        if (!strcmp(pol->creds[q].name, t + 11)) r->cred = (int)q + 1;
                    if (!r->cred) return fail(err, en, name, ln, "unknown credential");
                } else {
                    if (hdr) return fail(err, en, name, ln, "header given twice");
                    const char *v = t + 7, *colon = strchr(v, ':');
                    size_t hn = colon ? (size_t)(colon - v) : strlen(v);
                    if (!all_tchar(v, hn, 64) || (colon && !all_tchar(colon + 1, strlen(colon + 1), 32)))
                        return fail(err, en, name, ln, "bad header");
                    memcpy(r->hdr, v, hn);
                    r->hdr[hn] = '\0';
                    if (colon) memcpy(r->scheme, colon + 1, strlen(colon + 1) + 1);
                    if (framing_header(r->hdr)) return fail(err, en, name, ln, "a framing header");
                    hdr = true;
                }
                continue;
            }
            if (strncmp(t, "max_body=", 9) != 0) return fail(err, en, name, ln, "unknown request rule option");
            if (!r->allow) return fail(err, en, name, ln, "max_body on a deny rule");
            if (r->max_body) return fail(err, en, name, ln, "max_body given twice");
            const char *d = t + 9;
            size_t dl = strlen(d);
            unsigned long long mul = 1, x = 0;
            if (dl > 0 && d[dl - 1] == 'k') { mul = 1024; dl--; }
            else if (dl > 0 && d[dl - 1] == 'm') { mul = 1024 * 1024; dl--; }
            if (dl < 1 || dl > 7 || d[0] == '0') return fail(err, en, name, ln, "bad max_body");
            for (size_t q = 0; q < dl; q++) {
                if (d[q] < '0' || d[q] > '9') return fail(err, en, name, ln, "bad max_body");
                x = x * 10 + (unsigned long long)(d[q] - '0');
            }
            x *= mul;
            if (x > 1073741824ULL) return fail(err, en, name, ln, "bad max_body");
            r->max_body = (uint32_t)x;
        }
        if ((r->cred != 0) != hdr) return fail(err, en, name, ln, "credential and header go together");
        if (r->cred && pol->creds[r->cred - 1].audience[0])
            return fail(err, en, name, ln, "an MCP access token on a request rule");     /* v1.31 */
        if (r->cred && strncmp(tok[3], "https://", 8) != 0) return fail(err, en, name, ln, "credential on http");
        return 0;
    }

    static const struct { const char *kw; int m; } KW[] = {
        { "exact", M_EXACT }, { "prefix", M_PREFIX }, { "suffix", M_SUFFIX },
        { "contains", M_CONTAINS }, { "glob", M_GLOB },
    };
    int ci = 2;
    for (size_t k = 0; k < sizeof KW / sizeof KW[0]; k++) {
        if (strcmp(tok[2], KW[k].kw)) continue;
        if (nt >= 4 && !is_clause(tok[3])) {
            if (r->kind == VDPC_HOST) return fail(err, en, name, ln, "matcher on a host rule");
            r->match = KW[k].m;
            ci = 3;
        } else if (ver_ge(req_maj, req_min, 1, 14)) {
            return fail(err, en, name, ln, "matcher without a constant");
        }
        break;
    }
    const char *c = tok[ci];
    size_t cl = strlen(c);
    if (cl < 1 || cl > VDPC_MAX_S) return fail(err, en, name, ln, "constant length");
    for (size_t k = 0; k < cl; k++) {
        unsigned char b = (unsigned char)c[k];
        if (b < 0x20 || b == 0x7f) return fail(err, en, name, ln, "control byte in constant");
    }
    r->c = malloc(cl + 1);
    if (!r->c) return fail(err, en, name, ln, "out of memory");
    memcpy(r->c, c, cl + 1);
    r->clen = cl;
    if (r->kind == VDPC_HOST) {
        /* v1.24: names only after `require warden 1.24`; before it a constant
         * in name form is matched exactly, as in v1.21. */
        const char *why = "";
        int nf = host_name_form(c, cl, &why);
        if (cl >= 2 && c[0] == '*' && c[1] == '.' && ver_ge(req_maj, req_min, 1, 24)) {
            /* v1.25: *.<suffix>[:port], held as the glob ?*.<suffix>:<port>
             * (or :* without a port). <suffix> is a valid name of at least
             * two labels. */
            if (!ver_ge(req_maj, req_min, 1, 25)) return fail(err, en, name, ln, "wildcard before 1.25");
            if (host_name_form(c + 2, cl - 2, &why) != 1) return fail(err, en, name, ln, "bad wildcard");
            size_t h = 2;
            while (h < cl && c[h] != ':') h++;
            if (!memchr(c + 2, '.', h - 2)) return fail(err, en, name, ln, "wildcard over one label");
            size_t gl = 3 + (h - 2) + 1 + (h < cl ? cl - h - 1 : 1);
            if (gl > VDPC_MAX_S) return fail(err, en, name, ln, "constant length");
            char *g = malloc(gl + 1);
            if (!g) return fail(err, en, name, ln, "out of memory");
            memcpy(g, "?*.", 3);
            memcpy(g + 3, c + 2, h - 2);
            g[3 + h - 2] = ':';
            if (h < cl) memcpy(g + 3 + (h - 2) + 1, c + h + 1, cl - h - 1);
            else g[3 + (h - 2) + 1] = '*';
            g[gl] = '\0';
            free(r->c);
            r->c = g;
            r->clen = gl;
            r->match = M_GLOB;
            r->name = r->wild = true;
            c = r->c;
            cl = r->clen;
        } else if (nf != 0 && ver_ge(req_maj, req_min, 1, 24)) {
            if (nf < 0) return fail(err, en, name, ln, "%s", why);
            r->name = true;
            r->portless = memchr(c, ':', cl) == NULL;
        } else {
            if (nf != 0 && !*legacy_name) *legacy_name = ln;
            /* v1.21: a dotted-quad IPv4 address, or a bracketed IPv6 address
             * ("[::1]"), without a port */
            r->portless = memchr(c, ':', cl) ? (cl >= 2 && c[0] == '[' && c[cl - 1] == ']' &&
                                                !memchr(c + 1, ']', cl - 2))
                                             : ipv4_quad(c, cl);
        }
    }
    if (r->match == M_GLOB) {
        const char *ge = parse_glob(c, cl, &r->g, &r->ng);
        if (ge) return fail(err, en, name, ln, "%s", ge);
        *glob_total += r->ng;
        if (*glob_total > VDPC_GLOB_MAX_TOTAL) return fail(err, en, name, ln, "glob tokens over the policy total");
        r->fixed = true;
        for (size_t k = 0; k < r->ng; k++) {
            if (r->g[k].type == G_LIT || r->g[k].type == G_SET) r->minlen++;
            else r->fixed = false;
        }
        while (r->npre < r->ng && r->g[r->npre].type == G_LIT) r->npre++;
        while (r->nsuf < r->ng && r->g[r->ng - 1 - r->nsuf].type == G_LIT) r->nsuf++;
    }
    int ack = 0;            /* v1.25: acknowledge=dns-channel */
    for (int k = ci + 1; k < nt; k++) {
        const char *t = tok[k];
        /* v1.25: a wildcard allow rule must acknowledge the name channel */
        if (r->kind == VDPC_HOST && strncmp(t, "acknowledge=", 12) == 0) {
            if (strcmp(t + 12, "dns-channel") != 0) return fail(err, en, name, ln, "unknown acknowledgment");
            if (!r->wild || !r->allow)
                return fail(err, en, name, ln, "an acknowledgment on a rule that is not a wildcard allow");
            if (ack) return fail(err, en, name, ln, "acknowledgment given twice");
            ack = 1;
            continue;
        }
        /* v1.25: the budgets of a wildcard allow rule (no part of any decision) */
        if (r->kind == VDPC_HOST && (strncmp(t, "names=", 6) == 0 || strncmp(t, "rate=", 5) == 0)) {
            int nm = t[0] == 'n';
            const char *d = strchr(t, '=') + 1;
            unsigned long lim = nm ? 100000UL : 10000UL, x = 0;
            size_t dl = strlen(d);
            if (!r->wild || !r->allow)
                return fail(err, en, name, ln, "a budget on a rule that is not a wildcard allow");
            if (dl == 0 || dl > 6 || d[0] == '0') return fail(err, en, name, ln, "bad budget");
            for (size_t q = 0; q < dl; q++) {
                if (d[q] < '0' || d[q] > '9') return fail(err, en, name, ln, "bad budget");
                x = x * 10 + (unsigned long)(d[q] - '0');
            }
            if (x > lim) return fail(err, en, name, ln, "budget out of range");
            uint32_t *slot = nm ? &r->names : &r->rate;
            if (*slot) return fail(err, en, name, ln, "budget given twice");
            *slot = (uint32_t)x;
            continue;
        }
        /* v1.31: for=NAME and confined */
        if (!strncmp(t, "for=", 4)) {
            if (!ver_ge(req_maj, req_min, 1, 31)) return fail(err, en, name, ln, "for= before 1.31");
            if (r->subj) return fail(err, en, name, ln, "for= given twice");
            if (!(r->subj = subj_named(pol, t + 4))) return fail(err, en, name, ln, "for= names no confined subject");
            continue;
        }
        if (!strcmp(t, "confined")) {
            if (!ver_ge(req_maj, req_min, 1, 31)) return fail(err, en, name, ln, "confined before 1.31");
            if (r->confined) return fail(err, en, name, ln, "confined given twice");
            r->confined = true;
            continue;
        }
        /* v1.28.1: subagent=NAME on an allow exec rule */
        if (!strncmp(t, "subagent=", 9)) {
            if (!ver_ge(req_maj, req_min, 1, 28)) return fail(err, en, name, ln, "subagent before 1.28");
            if (r->kind != VDPC_EXEC || !r->allow) return fail(err, en, name, ln, "subagent on a rule that is not allow exec");
            if (r->subagent[0]) return fail(err, en, name, ln, "subagent given twice");
            if (!short_name(t + 9)) return fail(err, en, name, ln, "bad sub-agent name");
            memcpy(r->subagent, t + 9, strlen(t + 9) + 1);
            continue;
        }
        if (r->kind != VDPC_PATH) return fail(err, en, name, ln, "flag clause on a non-path rule");
        uint32_t m, v;
        if (!strcmp(t, "readonly"))       { m = ACCMODE | 0100 | 01000; v = 0; }
        else if (!strcmp(t, "access=ro")) { m = ACCMODE; v = 0; }
        else if (!strcmp(t, "access=wo")) { m = ACCMODE; v = 1; }
        else if (!strcmp(t, "access=rw")) { m = ACCMODE; v = 2; }
        else if ((t[0] == '+' || t[0] == '-') && flag_named(t + 1)) {
            m = flag_named(t + 1);
            v = (t[0] == '+') ? m : 0;
        } else return fail(err, en, name, ln, "unknown flag clause");
        if ((r->value & (r->mask & m)) != (v & (r->mask & m)))
            return fail(err, en, name, ln, "contradictory flag clause");
        r->mask |= m;
        r->value |= v & m;
    }
    if (r->kind == VDPC_HOST && r->wild && r->allow && !ack)
        return fail(err, en, name, ln, "a wildcard allow without acknowledge=dns-channel");
    if (r->confined && !r->subagent[0]) return fail(err, en, name, ln, "confined without subagent=");
    return 0;
}

int vdpc_load(const char *name, const char *buf, size_t len, vdpc_policy_t *p,
              char *err, size_t en) {
    memset(p, 0, sizeof *p);
    vdpc_sha256(buf, len, p->sha256);
    p->rules = calloc(VDPC_MAX_RULES, sizeof *p->rules);
    if (!p->rules) return fail(err, en, name, 0, "out of memory");
    int req_maj = 0, req_min = 0;
    int legacy_name = 0;              /* v1.24: line of a host name read before `require warden 1.24` */
    size_t glob_total = 0;
    int ln = 0;
    size_t pos = 0;
    char line[16384];
    while (pos < len) {
        ln++;
        size_t end = pos;
        while (end < len && buf[end] != '\n') end++;
        size_t ll = end - pos;
        if (memchr(buf + pos, '\0', ll)) { vdpc_free(p); return fail(err, en, name, ln, "NUL byte"); }
        char *heap = NULL, *l = line;
        if (ll + 1 > sizeof line) {
            heap = malloc(ll + 1);
            if (!heap) { vdpc_free(p); return fail(err, en, name, ln, "out of memory"); }
            l = heap;
        }
        memcpy(l, buf + pos, ll);
        l[ll] = '\0';
        pos = (end < len) ? end + 1 : end;

        char *tok[65];
        int nt = 0;
        int rc = 0;
        for (char *q = l; *q && rc == 0;) {
            while (*q && is_ws(*q)) q++;
            if (!*q) break;
            if (*q == '#') break;
            if (nt == 64) { rc = fail(err, en, name, ln, "more than 64 tokens"); break; }
            tok[nt++] = q;
            while (*q && !is_ws(*q)) q++;
            if (*q) *q++ = '\0';
        }
        if (rc == 0 && nt > 0) {
            if (!strcmp(tok[0], "require") && nt >= 2 && !strcmp(tok[1], "on-behalf-of")) {
                /* v1.28.1 */
                if (nt != 2) rc = fail(err, en, name, ln, "bad require on-behalf-of");
                else if (!ver_ge(req_maj, req_min, 1, 28)) rc = fail(err, en, name, ln, "on-behalf-of before 1.28");
                else if (p->require_obo) rc = fail(err, en, name, ln, "on-behalf-of twice");
                else p->require_obo = 1;
            } else if (!strcmp(tok[0], "require")) {
                int a, b;
                if (nt != 3 || strcmp(tok[1], "warden") || !parse_ver(tok[2], &a, &b))
                    rc = fail(err, en, name, ln, "bad directive");
                else if (!ver_ge(VDPC_GRAMMAR_MAJOR, VDPC_GRAMMAR_MINOR, a, b))
                    rc = fail(err, en, name, ln, "policy requires a newer Warden");
                else if (legacy_name && ver_ge(a, b, 1, 24))
                    rc = fail(err, en, name, ln, "require warden after a host name it would change");
                else if (ver_ge(a, b, req_maj, req_min)) { req_maj = a; req_min = b; }
            } else if (!strcmp(tok[0], "proxy")) {
                /* v1.26: proxy on | proxy ports P... (inspect: v1.26.1) */
                if (!ver_ge(req_maj, req_min, 1, 26))
                    rc = fail(err, en, name, ln, "proxy before require warden 1.26");
                else if (nt == 2 && (!strcmp(tok[1], "on") || !strcmp(tok[1], "inspect"))) {
                    /* v1.26.1: proxy inspect, inspecting mode, never with proxy on */
                    if (p->proxy) rc = fail(err, en, name, ln, "proxy mode given twice");
                    p->proxy = 1;
                    p->proxy_inspect = tok[1][0] == 'i';
                } else if (nt == 4 && !strcmp(tok[1], "passthrough") && !strcmp(tok[2], "host")) {
                    /* v1.26.1: proxy passthrough host NAME, a name without a port */
                    const char *why = "";
                    size_t hl = strlen(tok[3]);
                    if (memchr(tok[3], ':', hl) || host_name_form(tok[3], hl, &why) != 1 || hl > 253)
                        rc = fail(err, en, name, ln, "bad passthrough host");
                    for (size_t q = 0; rc == 0 && q < p->proxy_npass; q++)
                        if (!strcmp(p->proxy_pass[q], tok[3])) rc = fail(err, en, name, ln, "passthrough host twice");
                    if (rc == 0 && p->proxy_npass == 64) rc = fail(err, en, name, ln, "more than 64 passthrough hosts");
                    if (rc == 0) memcpy(p->proxy_pass[p->proxy_npass++], tok[3], hl + 1);
                } else if (nt >= 3 && !strcmp(tok[1], "ports") && !p->proxy_nports && nt - 2 <= 16) {
                    for (int k = 2; k < nt && rc == 0; k++) {
                        const char *d = tok[k];
                        size_t dl = strlen(d);
                        unsigned long x = 0;
                        if (dl == 0 || dl > 5 || d[0] == '0') rc = fail(err, en, name, ln, "bad port");
                        for (size_t q = 0; rc == 0 && q < dl; q++) {
                            if (d[q] < '0' || d[q] > '9') rc = fail(err, en, name, ln, "bad port");
                            x = x * 10 + (unsigned long)(d[q] - '0');
                        }
                        if (rc == 0 && x > 65535) rc = fail(err, en, name, ln, "bad port");
                        for (size_t q = 0; rc == 0 && q < p->proxy_nports; q++)
                            if (p->proxy_ports[q] == x) rc = fail(err, en, name, ln, "port twice");
                        if (rc == 0) p->proxy_ports[p->proxy_nports++] = (unsigned)x;
                    }
                } else if (nt == 3 && !strcmp(tok[1], "upstream") && !p->proxy_up_port) {
                    /* v1.26 section 5: proxy upstream http://HOST:PORT */
                    if (up_parse(tok[2], p->proxy_up_host, &p->proxy_up_port) < 0) {
                        p->proxy_up_port = 0;
                        rc = fail(err, en, name, ln, "bad proxy upstream");
                    }
                } else
                    rc = fail(err, en, name, ln, "bad proxy directive");
            } else if (!strcmp(tok[0], "trust")) {
                /* v1.28.1 */
                if (!ver_ge(req_maj, req_min, 1, 28))
                    rc = fail(err, en, name, ln, "trust before require warden 1.28");
                else
                    rc = parse_trust(name, ln, tok, nt, p, err, en, req_maj, req_min);
            } else if (!strcmp(tok[0], "credential")) {
                /* v1.28 */
                if (!ver_ge(req_maj, req_min, 1, 28))
                    rc = fail(err, en, name, ln, "credential before require warden 1.28");
                else
                    rc = parse_credential(name, ln, tok, nt, p, err, en, req_maj, req_min);
            } else if (!strcmp(tok[0], "mcp")) {
                /* v1.31: mcp server NAME exec PATH [sha256=HEX] */
                if (p->n == VDPC_MAX_RULES) rc = fail(err, en, name, ln, "more than 256 rules");
                else {
                    rc = parse_mcp_server(name, ln, tok, nt, req_maj, req_min, &p->rules[p->n], err, en);
                    p->n++;
                    if (rc == 0) rc = subj_register(p, p->n - 1, true, err, en, name, ln);
                }
            } else if (nt < 3) {
                rc = fail(err, en, name, ln, "bad rule");
            } else if (p->n == VDPC_MAX_RULES) {
                rc = fail(err, en, name, ln, "more than 256 rules");
            } else {
                rc = parse_rule(name, ln, tok, nt, req_maj, req_min, &legacy_name, &glob_total,
                                &p->rules[p->n], err, en, p);
                p->n++;                       /* counted either way: freed below */
                /* v1.31: a confined sub-agent is registered; an unconfined one may not share a confined name */
                if (rc == 0 && p->rules[p->n - 1].confined)
                    rc = subj_register(p, p->n - 1, false, err, en, name, ln);
                else if (rc == 0 && p->rules[p->n - 1].subagent[0] && subj_named(p, p->rules[p->n - 1].subagent))
                    rc = fail(err, en, name, ln, "a confined name used by an unconfined sub-agent");
            }
        }
        free(heap);
        if (rc < 0) { vdpc_free(p); return -1; }
    }
    if (p->proxy_nports && !p->proxy) {
        vdpc_free(p);
        return fail(err, en, name, ln, "proxy ports without proxy on");
    }
    if (p->proxy_up_port && !p->proxy) {
        vdpc_free(p);
        return fail(err, en, name, ln, "proxy upstream without proxy on");
    }
    /* v1.26.1: passthrough hosts and request rules need inspecting mode;
     * request rules only on proxied ports, and never on a passthrough host */
    if (p->proxy_npass && !p->proxy_inspect) {
        vdpc_free(p);
        return fail(err, en, name, ln, "proxy passthrough without proxy inspect");
    }
    for (size_t i = 0; i < p->n; i++) {
        const vdpc_rule_t *r = &p->rules[i];
        if (r->kind != VDPC_REQUEST && r->kind != VDPC_MCP) continue;      /* v1.31: mcp rules too */
        int bad = !p->proxy_inspect;
        bool on = false;
        if (p->proxy_nports == 0) on = r->rport == 80 || r->rport == 443;
        for (size_t q = 0; q < p->proxy_nports; q++) on = on || p->proxy_ports[q] == r->rport;
        if (!on) bad = 1;
        for (size_t q = 0; q < p->proxy_npass; q++) {
            const char *h = p->proxy_pass[q];
            size_t hn = strlen(h), sn = strlen(r->rhost);
            if (r->rwild ? (hn > sn && h[hn - sn - 1] == '.' && memcmp(h + hn - sn, r->rhost, sn) == 0)
                         : strcmp(h, r->rhost) == 0)
                bad = 1;
        }
        if (bad) {
            int l = r->line;
            vdpc_free(p);
            return fail(err, en, name, l, "request rule not allowed here (needs proxy inspect, a proxied "
                        "port, and a host that is not passthrough)");
        }
    }
    /* v1.27: launches after the first are decided only after require warden 1.27 */
    p->launches = ver_ge(req_maj, req_min, 1, 27);
    /* v1.29: files are opened with the agent's credentials after require warden 1.29 */
    p->open_as_agent = ver_ge(req_maj, req_min, 1, 29);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Matchers                                                                  */
/* ------------------------------------------------------------------------ */

/* Does glob token t consume byte b (for the one-byte and stretch tokens)? */
static bool tok_takes(const gtok_t *t, unsigned char b) {
    switch (t->type) {
        case G_LIT:   return b == t->byte;
        case G_SET:   return set_has(t->set, b);
        case G_STAR:  return b != '/';
        case G_DSTAR: return true;
        default:      return true;          /* G_SEGS: any byte inside */
    }
}

static bool is_stretch(int type) { return type == G_STAR || type == G_DSTAR || type == G_SEGS; }

/* Row dynamic programming. at[j]: tokens [0, j) match s[0, i). inside[j]:
 * token j is a SEGS that has taken at least one byte of s[.., i) and not yet
 * ended. Each new row is computed from the previous one in a single pass
 * (v1.16: no per-byte clearing or copying, so many short globs cost no more
 * per token than one long one); the two rows are then swapped. */
#define MAXG (VDPC_MAX_S + 3)
static bool glob_match(const gtok_t *g, size_t n, const char *s, size_t sl) {
    static __thread bool row_a[MAXG], row_b[MAXG], seg_a[MAXG], seg_b[MAXG];
    if (n + 1 > MAXG) return false;
    bool *at = row_a, *nat = row_b, *inside = seg_a, *ninside = seg_b;
    at[0] = true;
    inside[0] = false;
    for (size_t j = 0; j < n; j++) {
        at[j + 1] = at[j] && is_stretch(g[j].type);                   /* empty stretch */
        inside[j + 1] = false;
    }
    for (size_t i = 0; i < sl; i++) {
        unsigned char b = (unsigned char)s[i];
        bool any = false;
        nat[0] = false;                       /* no token prefix matches a nonempty string emptily */
        for (size_t j = 0; j < n; j++) {
            const gtok_t *t = &g[j];
            bool v, in = false;               /* v: nat[j + 1]; in: ninside[j] */
            if (t->type == G_LIT || t->type == G_SET) {
                v = at[j] && tok_takes(t, b);
            } else if (t->type == G_STAR || t->type == G_DSTAR) {
                v = at[j + 1] && tok_takes(t, b);                     /* the stretch grows */
            } else {                                                  /* G_SEGS */
                in = at[j] || inside[j];
                v = in && b == '/';
            }
            if (nat[j] && is_stretch(t->type)) v = true;              /* empty stretch */
            nat[j + 1] = v;
            ninside[j] = in;
            any = any || v || in;
        }
        ninside[n] = false;
        bool *tmp = at; at = nat; nat = tmp;
        tmp = inside; inside = ninside; ninside = tmp;
        if (!any) return false;
    }
    return at[n];
}

/* v1.21: a dotted-quad IPv4 address (four decimal parts, 1-3 digits, <= 255,
 * no leading zero), written independently of smt_decide.c. */
static bool ipv4_quad(const char *c, size_t n) {
    size_t i = 0;
    int parts = 0;
    while (parts < 4) {
        size_t st = i;
        unsigned v = 0;
        while (i < n && c[i] >= '0' && c[i] <= '9') {
            if (i - st == 3) return false;
            v = v * 10 + (unsigned)(c[i] - '0');
            i++;
        }
        if (i == st || v > 255 || (c[st] == '0' && i - st > 1)) return false;
        parts++;
        if (parts < 4) {
            if (i >= n || c[i] != '.') return false;
            i++;
        }
    }
    return i == n;
}

static bool str_holds(const vdpc_rule_t *r, const char *s, size_t sl) {
    const char *c = r->c;
    size_t cl = r->clen;
    switch (r->match) {
        case M_PREFIX: return sl >= cl && memcmp(s, c, cl) == 0;
        case M_EXACT:  return sl == cl && memcmp(s, c, cl) == 0;
        case M_SUFFIX: return sl >= cl && memcmp(s + sl - cl, c, cl) == 0;
        case M_CONTAINS:
            /* memmem (libc, linear time): a byte-by-byte search is quadratic
             * in the worst case, and 256 such rules on a 4,095-byte path would
             * dominate the cost of an open. */
            return memmem(s, sl, c, cl) != NULL;
        case M_HOST:
            /* v1.21: a constant with no port matches every port: a dotted-quad
             * IPv4 address, a bracketed IPv6 address ("[::1]"), or (v1.24) a
             * host name; decided at load (r->portless). Any other constant
             * matches only itself (so `allow host unix` does not match
             * unix:<path>). */
            if (sl == cl && memcmp(s, c, cl) == 0) return true;
            if (!r->portless) return false;
            return sl > cl && memcmp(s, c, cl) == 0 && s[cl] == ':';
        case M_GLOB:
            if (r->qmode) {                   /* v1.26.1 review: a request rule without a query */
                const char *q = memchr(s, '?', sl);
                if (q && r->qmode == 1) return false;
                if (q) sl = (size_t)(q - s);
            }
            if (sl < r->minlen || (r->fixed && sl != r->minlen)) return false;
            for (size_t k = 0; k < r->npre; k++)
                if ((unsigned char)s[k] != r->g[k].byte) return false;
            for (size_t k = 0; k < r->nsuf; k++)
                if ((unsigned char)s[sl - 1 - k] != r->g[r->ng - 1 - k].byte) return false;
            return glob_match(r->g, r->ng, s, sl);
    }
    return false;
}

static bool flag_holds(const vdpc_rule_t *r, uint32_t f) { return (f & r->mask) == r->value; }

int vdpc_rule_info(const vdpc_policy_t *p, size_t i, vdpc_rule_info_t *o) {
    if (i >= p->n) return -1;
    const vdpc_rule_t *r = &p->rules[i];
    o->allow = r->allow;
    o->kind = r->kind;
    o->match = r->match;
    o->line = r->line;
    o->c = r->c;
    o->clen = r->clen;
    o->mask = r->mask;
    o->value = r->value;
    o->portless = r->portless;
    o->name = r->name;
    o->wild = r->wild;
    o->names = r->names;
    o->rate = r->rate;
    o->max_body = r->max_body;
    o->cred = r->cred;
    o->cred_hdr = r->hdr;
    o->cred_scheme = r->scheme;
    o->subagent = r->subagent;
    o->subj = r->subj;
    o->confined_subj = r->csubj;
    o->mcp_server = r->mcp_server;
    o->sha256 = r->sha256;
    return 0;
}

int vdpc_holds(const vdpc_policy_t *p, size_t i, const char *s, size_t sl) {
    if (i >= p->n) return -1;
    return str_holds(&p->rules[i], s, sl) ? 1 : 0;
}

/* The witness for rule r's string atom. */
static bool witness_holds(const vdpc_rule_t *r, const char *s, size_t sl, const vdpc_cert_t *c,
                          const char **why) {
    if (r->match == M_CONTAINS) {
        if (c->wkind != 1) { *why = "contains rule without an offset witness"; return false; }
        if ((size_t)c->off > sl || r->clen > sl - c->off ||
            memcmp(s + c->off, r->c, r->clen) != 0) { *why = "contains witness does not match"; return false; }
        return true;
    }
    if (r->match != M_GLOB) {
        if (c->wkind != 0) { *why = "unexpected witness"; return false; }
        if (!str_holds(r, s, sl)) { *why = "deciding rule's constant does not match"; return false; }
        return true;
    }
    if (c->wkind != 2) { *why = "glob rule without a span witness"; return false; }
    if (r->qmode) {                           /* v1.26.1 review: a request rule without a query */
        const char *q = memchr(s, '?', sl);
        if (q && r->qmode == 1) { *why = "a request rule without a query, on a request with one"; return false; }
        if (q) sl = (size_t)(q - s);          /* a deny rule: its witness is on the path */
    }
    size_t pos = 0, k = 0;
    for (size_t j = 0; j < r->ng; j++) {
        const gtok_t *t = &r->g[j];
        if (!is_stretch(t->type)) {
            if (pos >= sl || !tok_takes(t, (unsigned char)s[pos])) { *why = "glob witness: byte mismatch"; return false; }
            pos++;
            continue;
        }
        if (k >= c->nspan) { *why = "glob witness: too few spans"; return false; }
        size_t a = c->span[k][0], b = c->span[k][1];
        k++;
        if (a != pos || b < a || b > sl) { *why = "glob witness: span out of place"; return false; }
        if (t->type == G_SEGS) {
            if (b > a && s[b - 1] != '/') { *why = "glob witness: /**/ span does not end in '/'"; return false; }
        } else {
            for (size_t x = a; x < b; x++)
                if (!tok_takes(t, (unsigned char)s[x])) { *why = "glob witness: '/' inside '*'"; return false; }
        }
        pos = b;
    }
    if (k != c->nspan) { *why = "glob witness: too many spans"; return false; }
    if (pos != sl) { *why = "glob witness: string not consumed"; return false; }
    return true;
}

/* ------------------------------------------------------------------------ */
/* Certificates                                                              */
/* ------------------------------------------------------------------------ */

static int reject(char *why, size_t n, const char *msg) {
    if (why && n) snprintf(why, n, "%s", msg);
    return 0;
}

int vdpc_check(const vdpc_policy_t *p, int kind, const char *s, size_t sl,
               uint32_t f, bool has_flags, const vdpc_cert_t *c, char *why, size_t wn) {
    return vdpc_check_subj(p, 0, kind, s, sl, f, has_flags, c, why, wn);
}

int vdpc_check_subj(const vdpc_policy_t *p, int subj, int kind, const char *s, size_t sl,
                    uint32_t f, bool has_flags, const vdpc_cert_t *c, char *why, size_t wn) {
    if (why && wn) why[0] = '\0';
    if (kind != VDPC_PATH && kind != VDPC_HOST && kind != VDPC_EXEC && kind != VDPC_REQUEST && kind != VDPC_MCP)
        return reject(why, wn, "bad kind");
    if (subj < 0 || (size_t)subj > p->nsubjects) return reject(why, wn, "no such subject");
    if (sl > VDPC_MAX_S) return reject(why, wn, "string over the length bound");
    if (memchr(s, '\0', sl)) return reject(why, wn, "NUL byte in the string");
    if (kind != VDPC_PATH) { f = 0; has_flags = true; }
    else if (has_flags) {
        if (f & ~known_bits()) return reject(why, wn, "flag bits outside open(2)");
        if ((f & ACCMODE) == ACCMODE) return reject(why, wn, "access mode 3");
    }

    if (has_flags) {
        if (c->r < 0 || (size_t)c->r >= p->n) return reject(why, wn, "no such rule");
        const vdpc_rule_t *r = &p->rules[c->r];
        if (r->kind != kind) return reject(why, wn, "deciding rule is of another kind");
        if (r->subj != subj) return reject(why, wn, "deciding rule is another subject's");
        if (!r->allow) return reject(why, wn, "deciding rule is not an allow rule");
        if (!flag_holds(r, f)) return reject(why, wn, "deciding rule's flag clause does not hold");
        const char *w = NULL;
        if (!witness_holds(r, s, sl, c, &w)) return reject(why, wn, w);
        for (int j = 0; j < c->r; j++) {
            const vdpc_rule_t *e = &p->rules[j];
            if (e->kind == kind && e->subj == subj && flag_holds(e, f) && str_holds(e, s, sl))
                return reject(why, wn, "an earlier rule holds");
        }
        return 1;
    }

    /* Symbolic flags: every admissible f must be decided by an allow rule. A
     * certificate naming one deciding rule carries that rule's witness. */
    if (c->r < 0 && c->wkind != 0) return reject(why, wn, "unexpected witness");
    if (c->r >= 0) {
        if ((size_t)c->r >= p->n || p->rules[c->r].kind != VDPC_PATH || p->rules[c->r].subj != subj)
            return reject(why, wn, "no such path rule");
        const char *w = NULL;
        if (!witness_holds(&p->rules[c->r], s, sl, c, &w)) return reject(why, wn, w);
    }
    size_t hold[VDPC_MAX_RULES], nh = 0;
    uint32_t bits = 0;
    for (size_t j = 0; j < p->n; j++) {
        const vdpc_rule_t *e = &p->rules[j];
        if (e->kind != VDPC_PATH || e->subj != subj || !str_holds(e, s, sl)) continue;
        hold[nh++] = j;
        bits |= e->mask;
        if (e->mask == 0) break;              /* it holds for every f: no later rule decides */
    }
    if (nh == 0) return reject(why, wn, "no rule holds");
    int deciding = -2;                        /* -2 unset; the rule every f reaches, or -1 */
    uint32_t sub = 0;
    for (;;) {
        if ((sub & ACCMODE) != ACCMODE) {
            int first = -1;
            for (size_t k = 0; k < nh && first < 0; k++)
                if (flag_holds(&p->rules[hold[k]], sub)) first = (int)hold[k];
            if (first < 0) return reject(why, wn, "some flags value is decided by no rule");
            if (!p->rules[first].allow) return reject(why, wn, "some flags value is denied");
            deciding = (deciding == -2 || deciding == first) ? first : -1;
        }
        if (sub == bits) break;
        sub = (sub - bits) & bits;            /* next subset of bits */
    }
    if (c->r >= 0 && c->r != deciding) return reject(why, wn, "certificate names the wrong rule");
    return 1;
}

/* v1.16: could the agent open path s with SOME admissible flags value? The
 * Warden asks this of its signing key and its anchor file at startup and
 * refuses to run a policy that would let the agent open either. Same
 * enumeration as the symbolic claim above: only the flag bits of the rules
 * whose string atom holds on s matter. */
static int path_openable_if(const vdpc_policy_t *p, const char *s, size_t sl, bool writing);

int vdpc_path_openable(const vdpc_policy_t *p, const char *s, size_t sl) {
    return path_openable_if(p, s, sl, false);
}

/* v1.28.1: as vdpc_path_openable, for the flags that write: an access mode
 * of O_WRONLY or O_RDWR, or O_TRUNC (which truncates whatever the mode). */
int vdpc_path_writable(const vdpc_policy_t *p, const char *s, size_t sl) {
    return path_openable_if(p, s, sl, true);
}

static int path_openable_subj(const vdpc_policy_t *p, int subj, const char *s, size_t sl, bool writing);

/* v1.31: openable (or writable) by any subject: the agent, or a confined one */
static int path_openable_if(const vdpc_policy_t *p, const char *s, size_t sl, bool writing) {
    for (size_t k = 0; k <= p->nsubjects; k++)
        if (path_openable_subj(p, (int)k, s, sl, writing)) return 1;
    return 0;
}

static int path_openable_subj(const vdpc_policy_t *p, int subj, const char *s, size_t sl, bool writing) {
    if (sl > VDPC_MAX_S || memchr(s, '\0', sl)) return 0;   /* outside the fragment: refused */
    size_t hold[VDPC_MAX_RULES], nh = 0;
    uint32_t bits = 0;
    for (size_t j = 0; j < p->n; j++) {
        const vdpc_rule_t *e = &p->rules[j];
        if (e->kind != VDPC_PATH || e->subj != subj || !str_holds(e, s, sl)) continue;
        hold[nh++] = j;
        bits |= e->mask;
        if (e->mask == 0) break;
    }
    uint32_t sub = 0;
    for (;;) {
        /* writing: some flags value with these rule bits writes. Bits no
         * rule names are free: O_TRUNC, or an access-mode bit that makes
         * O_WRONLY or O_RDWR (never 3) */
        bool writes = (sub & ACCMODE) || (sub & 01000) || !(bits & 01000) ||
                      (!(bits & 1u) && !(sub & 2u)) || (!(bits & 2u) && !(sub & 1u));
        if ((sub & ACCMODE) != ACCMODE && (!writing || writes)) {
            for (size_t k = 0; k < nh; k++) {
                const vdpc_rule_t *e = &p->rules[hold[k]];
                if (flag_holds(e, sub)) {
                    if (e->allow) return 1;
                    break;
                }
            }
        }
        if (sub == bits) break;
        sub = (sub - bits) & bits;
    }
    return 0;
}
