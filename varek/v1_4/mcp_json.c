// SPDX-License-Identifier: MIT
// mcp_json.c — v1.31: the strict JSON parser warden-proxy reads an MCP call
// with (mcp_json.h says what it accepts). Recursive descent over the bytes,
// bounded in depth and in string length; every value is checked, the few the
// call is decided on are kept.

#include "mcp_json.h"

#include <stdlib.h>
#include <string.h>

enum { CAP_NONE = 0, CAP_PARAMS, CAP_META };

struct mj {
    const uint8_t *s;
    size_t n, i;
    const char *why;
    mj_call_t *out;
    char *sb;                    /* a decoded string */
    size_t sl, scap;
    int depth;
};

static int fail(struct mj *p, const char *why) { if (!p->why) p->why = why; return -1; }

static void ws(struct mj *p) {
    while (p->i < p->n && (p->s[p->i] == ' ' || p->s[p->i] == '\t' || p->s[p->i] == '\n' || p->s[p->i] == '\r'))
        p->i++;
}

static int put(struct mj *p, const uint8_t *b, size_t k) {
    if (p->sl + k > MJ_MAX_STR) return fail(p, "a string over 1 MiB");
    if (p->sl + k + 1 > p->scap) {
        size_t nc = p->scap ? p->scap : 256;
        while (nc < p->sl + k + 1) nc *= 2;
        char *nb = realloc(p->sb, nc);
        if (!nb) return fail(p, "out of memory");
        p->sb = nb;
        p->scap = nc;
    }
    memcpy(p->sb + p->sl, b, k);
    p->sl += k;
    p->sb[p->sl] = '\0';
    return 0;
}

static int hex4(const uint8_t *h, unsigned *v) {
    *v = 0;
    for (int k = 0; k < 4; k++) {
        uint8_t c = h[k];
        unsigned d = c >= '0' && c <= '9' ? (unsigned)(c - '0') : c >= 'a' && c <= 'f' ? (unsigned)(c - 'a' + 10)
                   : c >= 'A' && c <= 'F' ? (unsigned)(c - 'A' + 10) : 16;
        if (d > 15) return -1;
        *v = *v * 16 + d;
    }
    return 0;
}

/* The length of the UTF-8 sequence at s[0, n), valid and shortest, or 0. */
static size_t utf8_len(const uint8_t *s, size_t n) {
    uint8_t c = s[0];
    if (c < 0x80) return 1;
    size_t k;
    uint32_t cp;
    if (c >= 0xc2 && c <= 0xdf) { k = 2; cp = c & 0x1f; }
    else if (c >= 0xe0 && c <= 0xef) { k = 3; cp = c & 0x0f; }
    else if (c >= 0xf0 && c <= 0xf4) { k = 4; cp = c & 0x07; }
    else return 0;
    if (n < k) return 0;
    for (size_t j = 1; j < k; j++) {
        if ((s[j] & 0xc0) != 0x80) return 0;
        cp = (cp << 6) | (s[j] & 0x3f);
    }
    if ((k == 3 && cp < 0x800) || (k == 4 && (cp < 0x10000 || cp > 0x10ffff)) || (cp >= 0xd800 && cp <= 0xdfff))
        return 0;
    return k;
}

static int enc_utf8(struct mj *p, uint32_t cp) {
    uint8_t b[4];
    size_t k;
    if (cp < 0x80) { b[0] = (uint8_t)cp; k = 1; }
    else if (cp < 0x800) { b[0] = (uint8_t)(0xc0 | (cp >> 6)); b[1] = (uint8_t)(0x80 | (cp & 0x3f)); k = 2; }
    else if (cp < 0x10000) {
        b[0] = (uint8_t)(0xe0 | (cp >> 12)); b[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3f));
        b[2] = (uint8_t)(0x80 | (cp & 0x3f)); k = 3;
    } else {
        b[0] = (uint8_t)(0xf0 | (cp >> 18)); b[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3f));
        b[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3f)); b[3] = (uint8_t)(0x80 | (cp & 0x3f)); k = 4;
    }
    return put(p, b, k);
}

/* A string at s[i] == '"', decoded into p->sb (p->sl bytes). */
static int string(struct mj *p) {
    p->sl = 0;
    if (put(p, (const uint8_t *)"", 0) < 0) return -1;
    p->i++;
    for (;;) {
        if (p->i >= p->n) return fail(p, "an unterminated string");
        uint8_t c = p->s[p->i];
        if (c == '"') { p->i++; return 0; }
        if (c < 0x20) return fail(p, "a control character in a string");
        if (c == '\\') {
            if (p->i + 1 >= p->n) return fail(p, "an unterminated string");
            uint8_t e = p->s[p->i + 1];
            const char *map = "\"\\/bfnrt", *rep = "\"\\/\b\f\n\r\t";
            const char *m = e ? strchr(map, e) : NULL;
            if (m) {
                uint8_t r = (uint8_t)rep[m - map];
                if (put(p, &r, 1) < 0) return -1;
                p->i += 2;
                continue;
            }
            if (e != 'u') return fail(p, "a bad escape in a string");
            unsigned v, w;
            if (p->i + 6 > p->n || hex4(p->s + p->i + 2, &v) < 0) return fail(p, "a bad \\u escape");
            p->i += 6;
            if (v >= 0xdc00 && v <= 0xdfff) return fail(p, "a lone surrogate in a \\u escape");
            if (v >= 0xd800 && v <= 0xdbff) {
                if (p->i + 6 > p->n || p->s[p->i] != '\\' || p->s[p->i + 1] != 'u' || hex4(p->s + p->i + 2, &w) < 0 ||
                    w < 0xdc00 || w > 0xdfff)
                    return fail(p, "a lone surrogate in a \\u escape");
                p->i += 6;
                v = 0x10000 + ((v - 0xd800) << 10) + (w - 0xdc00);
            }
            if (enc_utf8(p, v) < 0) return -1;
            continue;
        }
        size_t k = utf8_len(p->s + p->i, p->n - p->i);
        if (!k) return fail(p, "a string that is not UTF-8");
        if (put(p, p->s + p->i, k) < 0) return -1;
        p->i += k;
    }
}

static int number(struct mj *p) {
    size_t st = p->i;
    if (p->i < p->n && p->s[p->i] == '-') p->i++;
    if (p->i >= p->n) return fail(p, "a bad number");
    if (p->s[p->i] == '0') p->i++;
    else if (p->s[p->i] >= '1' && p->s[p->i] <= '9') while (p->i < p->n && p->s[p->i] >= '0' && p->s[p->i] <= '9') p->i++;
    else return fail(p, "a bad number");
    if (p->i < p->n && p->s[p->i] == '.') {
        p->i++;
        size_t d = p->i;
        while (p->i < p->n && p->s[p->i] >= '0' && p->s[p->i] <= '9') p->i++;
        if (p->i == d) return fail(p, "a bad number");
    }
    if (p->i < p->n && (p->s[p->i] == 'e' || p->s[p->i] == 'E')) {
        p->i++;
        if (p->i < p->n && (p->s[p->i] == '+' || p->s[p->i] == '-')) p->i++;
        size_t d = p->i;
        while (p->i < p->n && p->s[p->i] >= '0' && p->s[p->i] <= '9') p->i++;
        if (p->i == d) return fail(p, "a bad number");
    }
    return p->i > st ? 0 : fail(p, "a bad number");
}

/* An object's member names, to refuse one given twice: an open-addressing
 * set of (hash, offset into the key store) */
struct keys {
    char *store;
    size_t sl, scap;
    struct { uint64_t h; size_t off, len; } *t;
    size_t cap, cnt;
};

static uint64_t fnv(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 1099511628211ULL; }
    return h;
}

static void keys_free(struct keys *k) { free(k->store); free(k->t); }

/* 1 if added, 0 if already there, -1 out of memory */
static int keys_add(struct keys *k, const char *s, size_t n) {
    if ((k->cnt + 1) * 2 > k->cap) {
        size_t nc = k->cap ? k->cap * 2 : 16;
        void *nt = calloc(nc, sizeof *k->t);
        if (!nt) return -1;
        __typeof__(k->t) t = nt;
        for (size_t i = 0; i < k->cap; i++) {
            if (!k->t[i].h) continue;
            size_t j = k->t[i].h & (nc - 1);
            while (t[j].h) j = (j + 1) & (nc - 1);
            t[j] = k->t[i];
        }
        free(k->t);
        k->t = t;
        k->cap = nc;
    }
    uint64_t h = fnv(s, n) | 1;
    size_t j = h & (k->cap - 1);
    while (k->t[j].h) {
        if (k->t[j].h == h && k->t[j].len == n && !memcmp(k->store + k->t[j].off, s, n)) return 0;
        j = (j + 1) & (k->cap - 1);
    }
    if (k->sl + n > k->scap) {
        size_t nc = k->scap ? k->scap : 256;
        while (nc < k->sl + n) nc *= 2;
        char *ns = realloc(k->store, nc);
        if (!ns) return -1;
        k->store = ns;
        k->scap = nc;
    }
    if (n) memcpy(k->store + k->sl, s, n);
    k->t[j].h = h;
    k->t[j].off = k->sl;
    k->t[j].len = n;
    k->sl += n;
    k->cnt++;
    return 1;
}

static int value(struct mj *p, int cap);

enum { M_OTHER = 0, M_JSONRPC, M_METHOD, M_ID, M_PARAMS, M_NAME, M_URI, M_META, M_TP };

/* What member name sb is, at this level */
static int member_kind(const struct mj *p, int cap) {
    const char *k = p->sb;
    size_t n = p->sl;
#define IS(s) (n == sizeof(s) - 1 && !memcmp(k, s, n))
    if (cap == -1) {                                     /* the top level */
        if (IS("jsonrpc")) return M_JSONRPC;
        if (IS("method")) return M_METHOD;
        if (IS("id")) return M_ID;
        if (IS("params")) return M_PARAMS;
    } else if (cap == CAP_PARAMS) {
        if (IS("name")) return M_NAME;
        if (IS("uri")) return M_URI;
        if (IS("_meta")) return M_META;
    } else if (cap == CAP_META) {
        if (IS("traceparent")) return M_TP;
    }
#undef IS
    return M_OTHER;
}

/* An object at s[i] == '{'. cap: -1 the call itself, CAP_PARAMS, CAP_META,
 * or CAP_NONE. */
static int object(struct mj *p, int cap) {
    if (++p->depth > MJ_MAX_DEPTH) return fail(p, "nesting over 64 deep");
    struct keys ks = { 0 };
    int rc = 0;
    bool seen_jsonrpc = false, seen_method = false;
    p->i++;
    ws(p);
    if (p->i < p->n && p->s[p->i] == '}') {
        p->i++;
        if (cap == -1) rc = fail(p, "an empty object, not a call");
        goto done;
    }
    for (;;) {
        ws(p);
        if (p->i >= p->n || p->s[p->i] != '"') { rc = fail(p, "an object member without a name"); break; }
        if (string(p) < 0) { rc = -1; break; }
        if (memchr(p->sb, 0, p->sl)) { rc = fail(p, "a member name holding a NUL"); break; }
        int a = keys_add(&ks, p->sb, p->sl);
        if (a < 0) { rc = fail(p, "out of memory"); break; }
        if (a == 0) { rc = fail(p, "a member name given twice"); break; }
        int mk = member_kind(p, cap);
        ws(p);
        if (p->i >= p->n || p->s[p->i] != ':') { rc = fail(p, "a member without ':'"); break; }
        p->i++;
        ws(p);
        if (p->i >= p->n) { rc = fail(p, "a truncated body"); break; }
        uint8_t c = p->s[p->i];
        size_t vst = p->i;
        mj_call_t *o = p->out;
        if (mk == M_JSONRPC) {
            if (c != '"' || string(p) < 0 || p->sl != 3 || memcmp(p->sb, "2.0", 3)) { rc = fail(p, "\"jsonrpc\" is not \"2.0\""); break; }
            seen_jsonrpc = true;
        } else if (mk == M_METHOD) {
            if (c != '"' || string(p) < 0) { rc = fail(p, "\"method\" is not a string"); break; }
            if (p->sl >= sizeof o->method || memchr(p->sb, 0, p->sl)) { rc = fail(p, "a method over 255 bytes or holding a NUL"); break; }
            memcpy(o->method, p->sb, p->sl + 1);
            seen_method = true;
        } else if (mk == M_ID) {
            if (c == '"') { if (string(p) < 0) { rc = -1; break; } }
            else if (c == '-' || (c >= '0' && c <= '9')) { if (number(p) < 0) { rc = -1; break; } }
            else { rc = fail(p, "an \"id\" that is not a string or a number"); break; }
            size_t il = p->i - vst;
            if (il >= sizeof o->id) { rc = fail(p, "an \"id\" over 159 bytes"); break; }
            for (size_t q = vst; q < p->i; q++)
                if (p->s[q] < 0x20 || p->s[q] > 0x7e) { rc = fail(p, "an \"id\" that is not printable ASCII"); break; }
            if (rc) break;
            memcpy(o->id, p->s + vst, il);
            o->id[il] = '\0';
            o->notification = false;
        } else if (mk == M_PARAMS) {
            if (c != '{') { rc = fail(p, "\"params\" is not an object"); break; }
            if (object(p, CAP_PARAMS) < 0) { rc = -1; break; }
        } else if (mk == M_NAME || mk == M_URI) {
            if (c != '"' || string(p) < 0) { rc = fail(p, mk == M_NAME ? "params.name is not a string" : "params.uri is not a string"); break; }
            if (o->has_name) { rc = fail(p, "params holds both name and uri"); break; }
            if (p->sl >= sizeof o->name || memchr(p->sb, 0, p->sl)) { rc = fail(p, "a name over 4,095 bytes or holding a NUL"); break; }
            memcpy(o->name, p->sb, p->sl + 1);
            o->has_name = true;
        } else if (mk == M_META && c == '{') {
            if (object(p, CAP_META) < 0) { rc = -1; break; }
        } else if (mk == M_TP && c == '"') {
            if (string(p) < 0) { rc = -1; break; }
            bool ok = p->sl >= 1 && p->sl < sizeof o->traceparent;
            for (size_t q = 0; ok && q < p->sl; q++) ok = (uint8_t)p->sb[q] >= 0x21 && (uint8_t)p->sb[q] <= 0x7e;
            if (ok) memcpy(o->traceparent, p->sb, p->sl + 1);
        } else if (value(p, CAP_NONE) < 0) { rc = -1; break; }
        ws(p);
        if (p->i < p->n && p->s[p->i] == ',') { p->i++; continue; }
        if (p->i < p->n && p->s[p->i] == '}') { p->i++; break; }
        rc = fail(p, "an object without ',' or '}'");
        break;
    }
    if (rc == 0 && cap == -1 && (!seen_jsonrpc || !seen_method))
        rc = fail(p, seen_jsonrpc ? "no \"method\" (a JSON-RPC response, or not a call)" : "no \"jsonrpc\": \"2.0\"");
done:
    keys_free(&ks);
    p->depth--;
    return rc;
}

static int array(struct mj *p) {
    if (++p->depth > MJ_MAX_DEPTH) return fail(p, "nesting over 64 deep");
    p->i++;
    ws(p);
    if (p->i < p->n && p->s[p->i] == ']') { p->i++; p->depth--; return 0; }
    for (;;) {
        ws(p);
        if (value(p, CAP_NONE) < 0) return -1;
        ws(p);
        if (p->i < p->n && p->s[p->i] == ',') { p->i++; continue; }
        if (p->i < p->n && p->s[p->i] == ']') { p->i++; break; }
        return fail(p, "an array without ',' or ']'");
    }
    p->depth--;
    return 0;
}

static int literal(struct mj *p, const char *w) {
    size_t l = strlen(w);
    if (p->i + l > p->n || memcmp(p->s + p->i, w, l)) return fail(p, "a bad literal");
    p->i += l;
    return 0;
}

static int value(struct mj *p, int cap) {
    ws(p);
    if (p->i >= p->n) return fail(p, "a truncated body");
    uint8_t c = p->s[p->i];
    if (c == '{') return object(p, cap);
    if (c == '[') return array(p);
    if (c == '"') return string(p);
    if (c == 't') return literal(p, "true");
    if (c == 'f') return literal(p, "false");
    if (c == 'n') return literal(p, "null");
    if (c == '-' || (c >= '0' && c <= '9')) return number(p);
    return fail(p, "not JSON");
}

int mj_call(const uint8_t *body, size_t n, mj_call_t *out, char *why, size_t wn) {
    memset(out, 0, sizeof *out);
    out->notification = true;
    struct mj p = { .s = body, .n = n, .out = out };
    int rc;
    p.i = 0;
    ws(&p);
    if (p.i >= n) rc = fail(&p, "an empty body");
    else if (body[p.i] == '[') rc = fail(&p, "a batch (an array); MCP calls are sent one by one");
    else if (body[p.i] != '{') rc = fail(&p, "the body is not a JSON object");
    else {
        rc = object(&p, -1);
        if (rc == 0) {
            ws(&p);
            if (p.i != n) rc = fail(&p, "bytes after the JSON object");
        }
    }
    free(p.sb);
    if (rc < 0) {
        if (wn) { size_t l = strlen(p.why); if (l >= wn) l = wn - 1; memcpy(why, p.why, l); why[l] = '\0'; }
        memset(out, 0, sizeof *out);
        return -1;
    }
    return 0;
}

static int b64v(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int mj_header_value(const char *v, size_t vn, char *out, size_t outn) {
    static const char pre[] = "=?base64?", suf[] = "?=";
    size_t pl = sizeof pre - 1, sl = sizeof suf - 1;
    if (!outn) return -1;
    if (vn >= pl + sl && !memcmp(v, pre, pl) && !memcmp(v + vn - sl, suf, sl)) {
        const uint8_t *b = (const uint8_t *)v + pl;
        size_t bn = vn - pl - sl, o = 0;
        if (bn % 4) return -1;
        for (size_t i = 0; i < bn; i += 4) {
            int a[4];
            int pad = 0;
            for (int k = 0; k < 4; k++) {
                if (b[i + k] == '=' && i + 4 == bn && k >= 2) { a[k] = 0; pad++; continue; }
                if (pad) return -1;                          /* '=' then a digit */
                if ((a[k] = b64v(b[i + k])) < 0) return -1;
            }
            if (pad == 2 && b[i + 2] != '=') return -1;
            uint32_t w = (uint32_t)a[0] << 18 | (uint32_t)a[1] << 12 | (uint32_t)a[2] << 6 | (uint32_t)a[3];
            uint8_t by[3] = { (uint8_t)(w >> 16), (uint8_t)(w >> 8), (uint8_t)w };
            int cnt = 3 - pad;
            /* the unused bits of the last digit are zero (one spelling only) */
            if ((pad == 1 && (a[2] & 3)) || (pad == 2 && (a[1] & 15))) return -1;
            for (int k = 0; k < cnt; k++) {
                if (o + 1 >= outn || by[k] == 0) return -1;
                out[o++] = (char)by[k];
            }
        }
        out[o] = '\0';
        return 0;
    }
    if (vn + 1 > outn || memchr(v, 0, vn)) return -1;
    memcpy(out, v, vn);
    out[vn] = '\0';
    return 0;
}
