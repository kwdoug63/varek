// SPDX-License-Identifier: MIT
// vdp_checker.c — VAREK certificate checker (v1.15). See vdp_checker.h.
//
// Written to be read: every function is short, there is no cache, no bit
// trick and no shortcut beyond what the definitions say. It shares no code
// with smt_decide.c and does not include its header.

#include "vdp_checker.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
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

/* One line: tokens (NUL-terminated copies in `line`). Returns -1 on error. */
static int parse_rule(const char *name, int ln, char **tok, int nt, int req_maj, int req_min,
                      size_t *glob_total, vdpc_rule_t *r, char *err, size_t en) {
    memset(r, 0, sizeof *r);
    r->line = ln;
    if (!strcmp(tok[0], "allow")) r->allow = true;
    else if (strcmp(tok[0], "deny")) return fail(err, en, name, ln, "unknown verb");
    if (!strcmp(tok[1], "path"))      { r->kind = VDPC_PATH; r->match = M_PREFIX; }
    else if (!strcmp(tok[1], "host")) { r->kind = VDPC_HOST; r->match = M_HOST; }
    else if (!strcmp(tok[1], "exec")) { r->kind = VDPC_EXEC; r->match = M_EXACT; }
    else return fail(err, en, name, ln, "unknown kind");

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
    if (r->match == M_GLOB) {
        const char *ge = parse_glob(c, cl, &r->g, &r->ng);
        if (ge) return fail(err, en, name, ln, "%s", ge);
        *glob_total += r->ng;
        if (*glob_total > 65536) return fail(err, en, name, ln, "glob tokens over the policy total");
        r->fixed = true;
        for (size_t k = 0; k < r->ng; k++) {
            if (r->g[k].type == G_LIT || r->g[k].type == G_SET) r->minlen++;
            else r->fixed = false;
        }
        while (r->npre < r->ng && r->g[r->npre].type == G_LIT) r->npre++;
        while (r->nsuf < r->ng && r->g[r->ng - 1 - r->nsuf].type == G_LIT) r->nsuf++;
    }
    for (int k = ci + 1; k < nt; k++) {
        const char *t = tok[k];
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
    return 0;
}

int vdpc_load(const char *name, const char *buf, size_t len, vdpc_policy_t *p,
              char *err, size_t en) {
    memset(p, 0, sizeof *p);
    vdpc_sha256(buf, len, p->sha256);
    p->rules = calloc(VDPC_MAX_RULES, sizeof *p->rules);
    if (!p->rules) return fail(err, en, name, 0, "out of memory");
    int req_maj = 0, req_min = 0;
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
            if (!strcmp(tok[0], "require")) {
                int a, b;
                if (nt != 3 || strcmp(tok[1], "warden") || !parse_ver(tok[2], &a, &b))
                    rc = fail(err, en, name, ln, "bad directive");
                else if (!ver_ge(VDPC_GRAMMAR_MAJOR, VDPC_GRAMMAR_MINOR, a, b))
                    rc = fail(err, en, name, ln, "policy requires a newer Warden");
                else if (ver_ge(a, b, req_maj, req_min)) { req_maj = a; req_min = b; }
            } else if (nt < 3) {
                rc = fail(err, en, name, ln, "bad rule");
            } else if (p->n == VDPC_MAX_RULES) {
                rc = fail(err, en, name, ln, "more than 256 rules");
            } else {
                rc = parse_rule(name, ln, tok, nt, req_maj, req_min, &glob_total,
                                &p->rules[p->n], err, en);
                p->n++;                       /* counted either way: freed below */
            }
        }
        free(heap);
        if (rc < 0) { vdpc_free(p); return -1; }
    }
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
 * ended. */
#define MAXG (VDPC_MAX_S + 3)
static bool glob_match(const gtok_t *g, size_t n, const char *s, size_t sl) {
    static __thread bool at[MAXG], nat[MAXG], inside[MAXG], ninside[MAXG];
    if (n + 1 > MAXG) return false;
    memset(at, 0, n + 1);
    memset(inside, 0, n + 1);
    at[0] = true;
    for (size_t j = 0; j < n; j++)
        if (at[j] && is_stretch(g[j].type)) at[j + 1] = true;       /* empty stretch */
    for (size_t i = 0; i < sl; i++) {
        unsigned char b = (unsigned char)s[i];
        memset(nat, 0, n + 1);
        memset(ninside, 0, n + 1);
        bool any = false;
        for (size_t j = 0; j < n; j++) {
            const gtok_t *t = &g[j];
            if (t->type == G_LIT || t->type == G_SET) {
                if (at[j] && tok_takes(t, b)) nat[j + 1] = true;
            } else if (t->type == G_STAR || t->type == G_DSTAR) {
                if (at[j + 1] && tok_takes(t, b)) nat[j + 1] = true;  /* the stretch grows */
            } else {                                                    /* G_SEGS */
                if (at[j] || inside[j]) {
                    ninside[j] = true;
                    if (b == '/') nat[j + 1] = true;
                }
            }
            if (nat[j] && is_stretch(t->type)) nat[j + 1] = true;      /* empty stretch */
            any = any || nat[j] || ninside[j];
        }
        any = any || nat[n];
        memcpy(at, nat, n + 1);
        memcpy(inside, ninside, n + 1);
        if (!any) return false;
    }
    return at[n];
}

static bool str_holds(const vdpc_rule_t *r, const char *s, size_t sl) {
    const char *c = r->c;
    size_t cl = r->clen;
    switch (r->match) {
        case M_PREFIX: return sl >= cl && memcmp(s, c, cl) == 0;
        case M_EXACT:  return sl == cl && memcmp(s, c, cl) == 0;
        case M_SUFFIX: return sl >= cl && memcmp(s + sl - cl, c, cl) == 0;
        case M_CONTAINS:
            for (size_t k = 0; k + cl <= sl; k++)
                if (memcmp(s + k, c, cl) == 0) return true;
            return false;
        case M_HOST:
            if (sl == cl && memcmp(s, c, cl) == 0) return true;
            if (memchr(c, ':', cl)) return false;
            return sl > cl && memcmp(s, c, cl) == 0 && s[cl] == ':';
        case M_GLOB:
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
    if (why && wn) why[0] = '\0';
    if (kind != VDPC_PATH && kind != VDPC_HOST && kind != VDPC_EXEC) return reject(why, wn, "bad kind");
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
        if (!r->allow) return reject(why, wn, "deciding rule is not an allow rule");
        if (!flag_holds(r, f)) return reject(why, wn, "deciding rule's flag clause does not hold");
        const char *w = NULL;
        if (!witness_holds(r, s, sl, c, &w)) return reject(why, wn, w);
        for (int j = 0; j < c->r; j++) {
            const vdpc_rule_t *e = &p->rules[j];
            if (e->kind == kind && flag_holds(e, f) && str_holds(e, s, sl))
                return reject(why, wn, "an earlier rule holds");
        }
        return 1;
    }

    /* Symbolic flags: every admissible f must be decided by an allow rule. A
     * certificate naming one deciding rule carries that rule's witness. */
    if (c->r < 0 && c->wkind != 0) return reject(why, wn, "unexpected witness");
    if (c->r >= 0) {
        if ((size_t)c->r >= p->n || p->rules[c->r].kind != VDPC_PATH)
            return reject(why, wn, "no such path rule");
        const char *w = NULL;
        if (!witness_holds(&p->rules[c->r], s, sl, c, &w)) return reject(why, wn, w);
    }
    size_t hold[VDPC_MAX_RULES], nh = 0;
    uint32_t bits = 0;
    for (size_t j = 0; j < p->n; j++) {
        const vdpc_rule_t *e = &p->rules[j];
        if (e->kind != VDPC_PATH || !str_holds(e, s, sl)) continue;
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
