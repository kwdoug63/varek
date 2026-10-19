// SPDX-License-Identifier: MIT
// node_json.c — v1.34 step 2: the node agent's strict JSON reader (node_json.h).
#include "node_json.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *s;
    size_t n, i;
    int depth;
    char *why;
    size_t wn;
    bool skip;          /* a checked document: values skipped, names not compared again */
} cur_t;

static int fail(cur_t *c, const char *what) {
    if (c->why && c->wn) snprintf(c->why, c->wn, "%s at byte %zu", what, c->i);
    return -1;
}

static void ws(cur_t *c) {
    while (c->i < c->n && (c->s[c->i] == ' ' || c->s[c->i] == '\t' || c->s[c->i] == '\n' || c->s[c->i] == '\r'))
        c->i++;
}

static int hex4(const char *p, unsigned *out) {
    unsigned v = 0;
    for (int k = 0; k < 4; k++) {
        char h = p[k];
        v <<= 4;
        if (h >= '0' && h <= '9') v |= (unsigned)(h - '0');
        else if (h >= 'a' && h <= 'f') v |= (unsigned)(h - 'a' + 10);
        else if (h >= 'A' && h <= 'F') v |= (unsigned)(h - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

/* One UTF-8 sequence at s[0..n): its length, or 0 if malformed (overlong,
 * a surrogate, past U+10FFFF, truncated). */
static size_t utf8_len(const unsigned char *s, size_t n) {
    unsigned char b = s[0];
    if (b < 0x80) return 1;
    size_t len;
    uint32_t cp;
    if ((b & 0xE0) == 0xC0) { len = 2; cp = b & 0x1F; }
    else if ((b & 0xF0) == 0xE0) { len = 3; cp = b & 0x0F; }
    else if ((b & 0xF8) == 0xF0) { len = 4; cp = b & 0x07; }
    else return 0;
    if (len > n) return 0;
    for (size_t k = 1; k < len; k++) {
        if ((s[k] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (s[k] & 0x3F);
    }
    if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return 0;
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    return len;
}

static size_t put_utf8(uint32_t cp, char *o) {
    if (cp < 0x80) { o[0] = (char)cp; return 1; }
    if (cp < 0x800) { o[0] = (char)(0xC0 | (cp >> 6)); o[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) {
        o[0] = (char)(0xE0 | (cp >> 12)); o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        o[2] = (char)(0x80 | (cp & 0x3F)); return 3;
    }
    o[0] = (char)(0xF0 | (cp >> 18)); o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); o[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/* A string at c->i (the opening quote), checked; decoded into out when out is
 * given (*on its length; -1 if it does not fit or holds a NUL). */
static int string(cur_t *c, char *out, size_t outn, size_t *on) {
    if (c->i >= c->n || c->s[c->i] != '"') return fail(c, "a string expected");
    c->i++;
    size_t o = 0;
    bool fits = true;
    while (c->i < c->n) {
        unsigned char b = (unsigned char)c->s[c->i];
        if (b == '"') {
            c->i++;
            if (out) {
                if (!fits) return -2;
                out[o] = '\0';
                if (on) *on = o;
            }
            return 0;
        }
        if (b < 0x20) return fail(c, "a control character in a string");
        char buf[4];
        size_t bl;
        if (b == '\\') {
            if (c->i + 1 >= c->n) return fail(c, "a truncated escape");
            char e = c->s[c->i + 1];
            c->i += 2;
            switch (e) {
            case '"': buf[0] = '"'; bl = 1; break;
            case '\\': buf[0] = '\\'; bl = 1; break;
            case '/': buf[0] = '/'; bl = 1; break;
            case 'b': buf[0] = '\b'; bl = 1; break;
            case 'f': buf[0] = '\f'; bl = 1; break;
            case 'n': buf[0] = '\n'; bl = 1; break;
            case 'r': buf[0] = '\r'; bl = 1; break;
            case 't': buf[0] = '\t'; bl = 1; break;
            case 'u': {
                unsigned u, u2;
                if (c->i + 4 > c->n || hex4(c->s + c->i, &u) < 0) return fail(c, "a bad \\u escape");
                c->i += 4;
                uint32_t cp = u;
                if (u >= 0xD800 && u <= 0xDBFF) {
                    if (c->i + 6 > c->n || c->s[c->i] != '\\' || c->s[c->i + 1] != 'u' ||
                        hex4(c->s + c->i + 2, &u2) < 0 || u2 < 0xDC00 || u2 > 0xDFFF)
                        return fail(c, "a lone surrogate");
                    c->i += 6;
                    cp = 0x10000 + ((u - 0xD800) << 10) + (u2 - 0xDC00);
                } else if (u >= 0xDC00 && u <= 0xDFFF) return fail(c, "a lone surrogate");
                if (cp == 0) fits = false;            /* a NUL: never in a name the Warden uses */
                bl = put_utf8(cp, buf);
                break;
            }
            default: return fail(c, "a bad escape");
            }
        } else {
            bl = utf8_len((const unsigned char *)c->s + c->i, c->n - c->i);
            if (!bl) return fail(c, "malformed UTF-8");
            memcpy(buf, c->s + c->i, bl);
            c->i += bl;
        }
        if (out) {
            if (o + bl >= outn) fits = false;
            else { memcpy(out + o, buf, bl); o += bl; }
        }
    }
    return fail(c, "an unterminated string");
}

static int number(cur_t *c) {
    size_t i = c->i;
    if (i < c->n && c->s[i] == '-') i++;
    if (i >= c->n) return fail(c, "a bad number");
    if (c->s[i] == '0') i++;
    else if (c->s[i] >= '1' && c->s[i] <= '9') while (i < c->n && c->s[i] >= '0' && c->s[i] <= '9') i++;
    else return fail(c, "a bad number");
    if (i < c->n && c->s[i] == '.') {
        i++;
        size_t d = i;
        while (i < c->n && c->s[i] >= '0' && c->s[i] <= '9') i++;
        if (i == d) return fail(c, "a bad number");
    }
    if (i < c->n && (c->s[i] == 'e' || c->s[i] == 'E')) {
        i++;
        if (i < c->n && (c->s[i] == '+' || c->s[i] == '-')) i++;
        size_t d = i;
        while (i < c->n && c->s[i] >= '0' && c->s[i] <= '9') i++;
        if (i == d) return fail(c, "a bad number");
    }
    c->i = i;
    return 0;
}

static int value(cur_t *c);

/* A member name as Go's encoding/json matches it to a field: ASCII letters
 * in either case, and the two letters outside ASCII that Go folds onto ASCII
 * (U+017F to s, U+212A to k). Two names the same folded are the same field to
 * the runtime's reader, which takes the last. */
static size_t fold(const char *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t k = 0; k < n;) {
        unsigned char b = (unsigned char)in[k];
        if (b >= 'A' && b <= 'Z') { out[o++] = (char)(b - 'A' + 'a'); k++; }
        else if (k + 1 < n && b == 0xC5 && (unsigned char)in[k + 1] == 0xBF) { out[o++] = 's'; k += 2; }
        else if (k + 2 < n && b == 0xE2 && (unsigned char)in[k + 1] == 0x84 && (unsigned char)in[k + 2] == 0xAA) { out[o++] = 'k'; k += 3; }
        else out[o++] = in[k++];
    }
    return o;
}

#define NJ_MEMBERS 512
#define NJ_SLOTS 1024                         /* a power of two, twice NJ_MEMBERS */

/* An object's names, each folded once, in a hash set: a name given twice is
 * found without comparing it to every name before it. */
typedef struct {
    char *buf;
    size_t len, cap;
    struct { uint64_t h; size_t off, n; bool used; } slot[NJ_SLOTS];
} names_t;

static int names_add(names_t *t, const char *name, size_t n) {
    uint64_t h = 1469598103934665603ULL;      /* FNV-1a */
    for (size_t k = 0; k < n; k++) { h ^= (unsigned char)name[k]; h *= 1099511628211ULL; }
    size_t at = (size_t)h & (NJ_SLOTS - 1);
    while (t->slot[at].used) {
        if (t->slot[at].h == h && t->slot[at].n == n && !memcmp(t->buf + t->slot[at].off, name, n)) return 1;
        at = (at + 1) & (NJ_SLOTS - 1);
    }
    if (t->len + n > t->cap) {
        size_t cap = t->cap ? t->cap : 4096;
        while (cap < t->len + n) cap *= 2;
        char *b = realloc(t->buf, cap);
        if (!b) return -1;
        t->buf = b;
        t->cap = cap;
    }
    memcpy(t->buf + t->len, name, n);
    t->slot[at].h = h;
    t->slot[at].off = t->len;
    t->slot[at].n = n;
    t->slot[at].used = true;
    t->len += n;
    return 0;
}

static int members(cur_t *c, names_t *t) {
    size_t nk = 0;
    char *a = malloc(4096), *f = malloc(4096);
    int rc = -1;
    if (!a || !f) { rc = fail(c, "out of memory"); goto out; }
    for (;;) {
        ws(c);
        size_t an = 0;
        int r = string(c, t ? a : NULL, t ? 4096 : 0, &an);
        if (r == -2) { rc = fail(c, "a member name too long, or holding a NUL"); goto out; }
        if (r < 0) goto out;
        if (t) {
            if (nk == NJ_MEMBERS) { rc = fail(c, "too many members"); goto out; }
            int d = names_add(t, f, fold(a, an, f));
            if (d < 0) { rc = fail(c, "out of memory"); goto out; }
            if (d) { rc = fail(c, "a member name given twice (compared as the runtime's reader does)"); goto out; }
            nk++;
        }
        ws(c);
        if (c->i >= c->n || c->s[c->i] != ':') { rc = fail(c, "':' expected"); goto out; }
        c->i++;
        if (value(c) < 0) goto out;
        ws(c);
        if (c->i < c->n && c->s[c->i] == ',') { c->i++; continue; }
        if (c->i < c->n && c->s[c->i] == '}') { c->i++; rc = 0; goto out; }
        rc = fail(c, "',' or '}' expected");
        goto out;
    }
out:
    free(a);
    free(f);
    return rc;
}

static int object(cur_t *c) {
    if (++c->depth > NJ_MAX_DEPTH) return fail(c, "nesting too deep");
    c->i++;                                   /* { */
    ws(c);
    if (c->i < c->n && c->s[c->i] == '}') { c->i++; c->depth--; return 0; }
    names_t *t = NULL;
    if (!c->skip && !(t = calloc(1, sizeof *t))) return fail(c, "out of memory");
    int rc = members(c, t);
    if (t) free(t->buf);
    free(t);
    if (rc == 0) c->depth--;
    return rc;
}

static int array(cur_t *c) {
    if (++c->depth > NJ_MAX_DEPTH) return fail(c, "nesting too deep");
    c->i++;                                   /* [ */
    ws(c);
    if (c->i < c->n && c->s[c->i] == ']') { c->i++; c->depth--; return 0; }
    for (;;) {
        if (value(c) < 0) return -1;
        ws(c);
        if (c->i < c->n && c->s[c->i] == ',') { c->i++; continue; }
        if (c->i < c->n && c->s[c->i] == ']') { c->i++; c->depth--; return 0; }
        return fail(c, "',' or ']' expected");
    }
}

static int literal(cur_t *c, const char *w) {
    size_t l = strlen(w);
    if (c->n - c->i < l || memcmp(c->s + c->i, w, l)) return fail(c, "a bad literal");
    c->i += l;
    return 0;
}

static int value(cur_t *c) {
    ws(c);
    if (c->i >= c->n) return fail(c, "a value expected");
    char ch = c->s[c->i];
    if (ch == '{') return object(c);
    if (ch == '[') return array(c);
    if (ch == '"') return string(c, NULL, 0, NULL);
    if (ch == 't') return literal(c, "true");
    if (ch == 'f') return literal(c, "false");
    if (ch == 'n') return literal(c, "null");
    return number(c);
}

int nj_check(const char *doc, size_t n, char *why, size_t wn) {
    cur_t c = { doc, n, 0, 0, why, wn, false };
    if (n >= 3 && (unsigned char)doc[0] == 0xEF && (unsigned char)doc[1] == 0xBB && (unsigned char)doc[2] == 0xBF)
        return fail(&c, "a byte-order mark");
    if (value(&c) < 0) return -1;
    ws(&c);
    if (c.i != n) return fail(&c, "data after the document");
    return 0;
}

int nj_find(const char *doc, size_t n, const char *const *path, size_t depth,
            const char **v, size_t *vn) {
    cur_t c = { doc, n, 0, 0, NULL, 0, true };
    ws(&c);
    for (size_t d = 0; d < depth; d++) {
        ws(&c);
        if (c.i >= n) return -1;
        const char *want = path[d];
        bool found = false;
        if (want[0] == '#') {
            if (c.s[c.i] != '[') return -1;
            if (!want[1] || strspn(want + 1, "0123456789") != strlen(want + 1)) return -1;
            char *e;
            long idx = strtol(want + 1, &e, 10);
            if (*e || idx < 0) return -1;
            c.i++;
            ws(&c);
            if (c.i < n && c.s[c.i] == ']') return -1;
            for (long k = 0;; k++) {
                ws(&c);
                if (k == idx) { found = true; break; }
                if (value(&c) < 0) return -1;
                ws(&c);
                if (c.i < n && c.s[c.i] == ',') { c.i++; continue; }
                return -1;
            }
        } else {
            if (c.s[c.i] != '{') return -1;
            c.i++;
            ws(&c);
            if (c.i < n && c.s[c.i] == '}') return -1;
            for (;;) {
                ws(&c);
                static char k[4096];
                if (string(&c, k, sizeof k, NULL) < 0) return -1;
                ws(&c);
                if (c.i >= n || c.s[c.i] != ':') return -1;
                c.i++;
                ws(&c);
                if (!strcmp(k, want)) { found = true; break; }
                if (value(&c) < 0) return -1;
                ws(&c);
                if (c.i < n && c.s[c.i] == ',') { c.i++; continue; }
                return -1;
            }
        }
        if (!found) return -1;
    }
    ws(&c);
    size_t start = c.i;
    if (value(&c) < 0) return -1;
    *v = doc + start;
    *vn = c.i - start;
    return 0;
}

int nj_string(const char *v, size_t vn, char *out, size_t outn) {
    cur_t c = { v, vn, 0, 0, NULL, 0, false };
    if (!outn || string(&c, out, outn, NULL) != 0 || c.i != vn) return -1;
    return 0;
}

int nj_int(const char *v, size_t vn, long long *out) {
    char buf[32];
    if (!vn || vn >= sizeof buf) return -1;
    memcpy(buf, v, vn);
    buf[vn] = '\0';
    for (size_t k = 0; k < vn; k++)
        if (!((buf[k] >= '0' && buf[k] <= '9') || (k == 0 && buf[k] == '-'))) return -1;
    if ((buf[0] == '0' && vn > 1) || (buf[0] == '-' && (vn == 1 || buf[1] == '0'))) return -1;
    errno = 0;
    char *e;
    long long x = strtoll(buf, &e, 10);
    if (errno || *e) return -1;
    *out = x;
    return 0;
}
