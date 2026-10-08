// SPDX-License-Identifier: MIT
// proxy_parse.c — v1.26: what the egress proxy reads. See proxy_parse.h.

#include "proxy_parse.h"

#include <string.h>

const char *pp_kind_name(pp_kind_t k) {
    switch (k) {
        case PP_KIND_TLS:     return "tls";
        case PP_KIND_HTTP:    return "http";
        case PP_KIND_CONNECT: return "connect";
        default:              return "none";
    }
}

static pp_status_t refuse(pp_result_t *r, const char *why) {
    r->why = why;
    return PP_REFUSE;
}

static unsigned be16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }
static size_t   be24(const uint8_t *p) { return (size_t)p[0] << 16 | (size_t)p[1] << 8 | p[2]; }

/* A host name: LDH labels of 1 to 63 bytes, at most PP_NAME_MAX in all, an
 * optional trailing dot only where allowed, and not an IP literal (a last
 * label of digits only). Written lowercase, without the dot, to out.
 * 1, or 0. */
static int name_ok(const uint8_t *s, size_t n, bool dot_ok, char *out) {
    if (n > 0 && s[n - 1] == '.' && dot_ok) n--;
    if (n == 0 || n > PP_NAME_MAX) return 0;
    size_t label = 0;
    bool digits = true;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = s[i];
        if (c == '.') {
            if (label == 0 || s[i - 1] == '-') return 0;
            label = 0;
            digits = true;
            out[i] = '.';
            continue;
        }
        if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
        bool d = c >= '0' && c <= '9';
        if (!(d || (c >= 'a' && c <= 'z') || c == '-')) return 0;
        if (c == '-' && label == 0) return 0;
        if (!d) digits = false;
        if (++label > 63) return 0;
        out[i] = (char)c;
    }
    if (label == 0 || s[n - 1] == '-' || digits) return 0;   /* empty last label, or numeric */
    out[n] = '\0';
    return 1;
}

/* ---- TLS ---- */

/* The SNI host name of a ClientHello body (b, m bytes). */
static pp_status_t client_hello(const uint8_t *b, size_t m, pp_result_t *r) {
    size_t p = 0;
    if (m < 2 + 32 + 1) return refuse(r, "short ClientHello");
    if (b[0] != 3 || b[1] < 1 || b[1] > 3) return refuse(r, "not a TLS 1.0-1.3 ClientHello");
    p = 34;
    size_t sid = b[p++];
    if (sid > 32 || m - p < sid) return refuse(r, "bad session id");
    p += sid;
    if (m - p < 2) return refuse(r, "short ClientHello");
    size_t cs = be16(b + p);
    p += 2;
    if (cs < 2 || cs % 2 || m - p < cs) return refuse(r, "bad cipher suites");
    p += cs;
    if (m - p < 1) return refuse(r, "short ClientHello");
    size_t cm = b[p++];
    if (cm < 1 || m - p < cm) return refuse(r, "bad compression methods");
    p += cm;
    if (p == m) return refuse(r, "no SNI (no extensions)");
    if (m - p < 2 || be16(b + p) != m - p - 2) return refuse(r, "bad extensions length");
    p += 2;
    static const unsigned kMaxExt = 128;           /* real clients send ~20 */
    unsigned seen[128], nseen = 0;
    bool have_sni = false;
    while (p < m) {
        if (m - p < 4) return refuse(r, "bad extension");
        unsigned type = be16(b + p);
        size_t len = be16(b + p + 2);
        p += 4;
        if (m - p < len) return refuse(r, "bad extension length");
        for (unsigned k = 0; k < nseen; k++)
            if (seen[k] == type) return refuse(r, "an extension given twice");
        if (nseen == kMaxExt) return refuse(r, "too many extensions");
        seen[nseen++] = type;
        const uint8_t *e = b + p;
        p += len;
        if (type == 0xfe0d) return refuse(r, "encrypted_client_hello");
        if (type == 0xffce) return refuse(r, "encrypted SNI");
        if (type != 0) continue;
        /* server_name: a list of (type, name); one host_name, nothing else */
        if (len < 2 || be16(e) != len - 2) return refuse(r, "bad server_name");
        size_t q = 2;
        unsigned names = 0;
        while (q < len) {
            if (len - q < 3) return refuse(r, "bad server_name");
            uint8_t nt = e[q];
            size_t nl = be16(e + q + 1);
            q += 3;
            if (len - q < nl) return refuse(r, "bad server_name");
            if (nt != 0) return refuse(r, "a server_name that is not a host name");
            if (++names > 1) return refuse(r, "more than one SNI name");
            if (!name_ok(e + q, nl, false, r->name)) return refuse(r, "an SNI that is not a host name");
            q += nl;
        }
        if (names == 0) return refuse(r, "an empty server_name");
        have_sni = true;
    }
    if (!have_sni) return refuse(r, "no SNI");
    return PP_OK;
}

/* A ClientHello in handshake records (in, n). */
static pp_status_t tls(const uint8_t *in, size_t n, pp_result_t *r) {
    uint8_t hs[PP_TLS_MAX];
    size_t hl = 0, off = 0;
    unsigned recs = 0;
    for (;;) {
        if (n - off < 5) break;                                    /* more to read */
        if (in[off] != 22) return refuse(r, "not a TLS handshake record");
        if (in[off + 1] != 3 || in[off + 2] < 1 || in[off + 2] > 3)
            return refuse(r, "not a TLS 1.0-1.3 record");
        size_t len = be16(in + off + 3);
        if (len == 0 || len > 16384) return refuse(r, "bad record length");
        if (n - off - 5 < len) break;
        if (++recs > PP_TLS_RECORDS) return refuse(r, "a ClientHello over too many records");
        if (len > PP_TLS_MAX - hl) return refuse(r, "a ClientHello over 16 KB");
        memcpy(hs + hl, in + off + 5, len);
        hl += len;
        off += 5 + len;
        if (hs[0] != 1) return refuse(r, "not a ClientHello");
        if (hl < 4) continue;
        size_t ml = be24(hs + 1);
        if (ml > PP_TLS_MAX - 4) return refuse(r, "a ClientHello over 16 KB");
        if (hl < 4 + ml) continue;
        if (hl > 4 + ml) return refuse(r, "more than a ClientHello in its records");
        r->kind = PP_KIND_TLS;
        return client_hello(hs + 4, ml, r);
    }
    if (n >= 5 * PP_TLS_RECORDS + PP_TLS_MAX) return refuse(r, "a ClientHello over 16 KB");
    return PP_MORE;
}

/* ---- HTTP ---- */

static bool tchar(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c && strchr("!#$%&'*+-.^_`|~", c));
}

/* The end of the request line and headers (the index after CRLF CRLF), or
 * 0 if not there yet; -1 if malformed (a CR or LF not in CRLF, a NUL). */
static long head_end(const uint8_t *in, size_t n) {
    size_t lim = n < PP_HTTP_MAX ? n : PP_HTTP_MAX;
    for (size_t i = 0; i < lim; i++) {
        uint8_t c = in[i];
        if (c == 0) return -1;
        if (c == '\n') return -1;                       /* bare LF */
        if (c != '\r') continue;
        if (i + 1 >= lim) return 0;
        if (in[i + 1] != '\n') return -1;               /* bare CR */
        if (i + 3 < lim && in[i + 2] == '\r' && in[i + 3] == '\n') return (long)(i + 4);
        if (i + 2 >= lim || (i + 3 >= lim && in[i + 2] == '\r')) return 0;
        i++;                                            /* past this CRLF */
    }
    return 0;
}

/* host[:port] (s, n): a host name (a trailing dot allowed) and the port
 * (0: none given). 1, or 0. */
static int authority(const uint8_t *s, size_t n, char *name, unsigned *port) {
    size_t h = n;
    *port = 0;
    for (size_t i = n; i > 0; i--)
        if (s[i - 1] == ':') { h = i - 1; break; }
    if (h < n) {
        size_t pl = n - h - 1;
        if (pl == 0 || pl > 5 || s[h + 1] == '0') return 0;
        unsigned v = 0;
        for (size_t i = h + 1; i < n; i++) {
            if (s[i] < '0' || s[i] > '9') return 0;
            v = v * 10 + (unsigned)(s[i] - '0');
        }
        if (v == 0 || v > 65535) return 0;
        *port = v;
    }
    return name_ok(s, h, true, name);
}

/* The request line's three parts, and the header lines after it. */
struct req {
    const uint8_t *method, *target, *version;
    size_t ml, tl, vl;
    size_t hdr;                                         /* the first header line */
};

static int request_line(const uint8_t *in, size_t end, struct req *q) {
    size_t i = 0;
    q->method = in;
    while (i < end && in[i] >= 'A' && in[i] <= 'Z') i++;
    q->ml = i;
    if (q->ml == 0 || q->ml > 16 || i >= end || in[i] != ' ') return 0;
    q->target = in + ++i;
    while (i < end && in[i] > ' ' && in[i] < 0x7f) i++;
    q->tl = (size_t)(in + i - q->target);
    if (q->tl == 0 || i >= end || in[i] != ' ') return 0;
    q->version = in + ++i;
    while (i < end && in[i] != '\r') i++;
    q->vl = (size_t)(in + i - q->version);
    if (!((q->vl == 8 && !memcmp(q->version, "HTTP/1.1", 8)) ||
          (q->vl == 8 && !memcmp(q->version, "HTTP/1.0", 8))))
        return 0;
    q->hdr = i + 2;
    return 1;
}

/* The Host header's value (trimmed), if exactly one. 1 (found), 0 (none),
 * -1 (malformed, or more than one). */
static int host_header(const uint8_t *in, size_t hdr, size_t end, const uint8_t **v, size_t *vl) {
    int found = 0;
    size_t i = hdr;
    while (i + 2 <= end - 2) {                          /* each line up to the final CRLF */
        size_t ls = i;
        while (in[i] != '\r') i++;
        size_t le = i;
        i += 2;
        if (le == ls) break;                            /* the blank line */
        if (in[ls] == ' ' || in[ls] == '\t') return -1; /* obs-fold */
        size_t c = ls;
        while (c < le && tchar(in[c])) c++;
        if (c == ls || c >= le || in[c] != ':') return -1;   /* no name, or space before ':' */
        size_t a = c + 1, b = le;
        while (a < b && (in[a] == ' ' || in[a] == '\t')) a++;
        while (b > a && (in[b - 1] == ' ' || in[b - 1] == '\t')) b--;
        for (size_t k = a; k < b; k++)
            if (in[k] < 0x20 && in[k] != '\t') return -1;
        if (c - ls == 4 && (in[ls] | 32) == 'h' && (in[ls + 1] | 32) == 'o' &&
            (in[ls + 2] | 32) == 's' && (in[ls + 3] | 32) == 't') {
            if (found) return -1;
            found = 1;
            *v = in + a;
            *vl = b - a;
        }
    }
    return found;
}

static pp_status_t http(const uint8_t *in, size_t n, unsigned dport, pp_result_t *r) {
    long end = head_end(in, n);
    if (end < 0) return refuse(r, "a malformed HTTP request (CR, LF or NUL)");
    if (end == 0) return n >= PP_HTTP_MAX ? refuse(r, "HTTP headers over 8 KB") : PP_MORE;
    struct req q;
    if (!request_line(in, (size_t)end, &q)) return refuse(r, "a malformed HTTP request line");
    r->kind = PP_KIND_HTTP;
    if (q.ml == 7 && !memcmp(q.method, "CONNECT", 7)) return refuse(r, "a CONNECT out of place");
    const uint8_t *v = NULL;
    size_t vl = 0;
    int h = host_header(in, q.hdr, (size_t)end, &v, &vl);
    if (h < 0) return refuse(r, "malformed headers, or more than one Host");
    if (h == 0) return refuse(r, "no Host header");
    unsigned hp;
    if (!authority(v, vl, r->name, &hp)) return refuse(r, "a Host that is not a host name");
    if (hp && hp != dport) return refuse(r, "a Host port that is not the one connected to");
    if (q.tl >= 7 && !memcmp(q.target, "http://", 7)) {
        /* absolute-form: its authority must be the Host's */
        const uint8_t *a = q.target + 7, *e = q.target + q.tl;
        const uint8_t *s = a;
        while (s < e && *s != '/' && *s != '?' && *s != '#') s++;
        char an[PP_NAME_MAX + 1];
        unsigned ap;
        if (!authority(a, (size_t)(s - a), an, &ap) || strcmp(an, r->name) || (ap ? ap : 80) != (hp ? hp : dport))
            return refuse(r, "a target that is not the Host");
    } else if (!(q.target[0] == '/' || (q.tl == 1 && q.target[0] == '*' && q.ml == 7 &&
                                        !memcmp(q.method, "OPTIONS", 7)))) {
        return refuse(r, "a request target the proxy does not take");
    }
    r->port = dport;
    return PP_OK;
}

/* ---- CONNECT ---- */

static pp_status_t connect_req(const uint8_t *in, size_t n, bool acked, pp_result_t *r) {
    long end = head_end(in, n);
    if (end < 0) return refuse(r, "a malformed CONNECT (CR, LF or NUL)");
    if (end == 0) return n >= PP_HTTP_MAX ? refuse(r, "CONNECT headers over 8 KB") : PP_MORE;
    struct req q;
    r->kind = PP_KIND_CONNECT;
    if (!request_line(in, (size_t)end, &q) || q.ml != 7 || memcmp(q.method, "CONNECT", 7))
        return refuse(r, "a malformed CONNECT line");
    char name[PP_NAME_MAX + 1];
    unsigned port;
    if (!authority(q.target, q.tl, name, &port) || port == 0)
        return refuse(r, "a CONNECT target that is not host:port");
    const uint8_t *v = NULL;
    size_t vl = 0;
    int h = host_header(in, q.hdr, (size_t)end, &v, &vl);
    if (h < 0) return refuse(r, "malformed headers, or more than one Host");
    if (h == 1) {
        char hn[PP_NAME_MAX + 1];
        unsigned hp;
        if (!authority(v, vl, hn, &hp) || strcmp(hn, name) || (hp && hp != port))
            return refuse(r, "a Host that is not the CONNECT target");
    }
    r->connect_len = (size_t)end;
    r->port = port;
    if (!acked) {
        if ((size_t)end < n) return refuse(r, "data before the CONNECT was answered");
        memcpy(r->name, name, strlen(name) + 1);
        return PP_ACK;
    }
    /* the ClientHello inside: its SNI must be the CONNECT's name */
    pp_status_t st = tls(in + end, n - (size_t)end, r);
    r->kind = PP_KIND_CONNECT;
    r->port = port;
    if (st != PP_OK) return st;
    if (strcmp(r->name, name)) return refuse(r, "an SNI that is not the CONNECT target");
    return PP_OK;
}

pp_status_t pp_parse(const uint8_t *in, size_t n, unsigned dport, bool acked, pp_result_t *r) {
    memset(r, 0, sizeof *r);
    if (n == 0) return PP_MORE;
    if (n > PP_IN_MAX) return refuse(r, "too much before a decision");
    if (in[0] == 22) {
        if (acked) return refuse(r, "a ClientHello where a CONNECT was answered");
        pp_status_t st = tls(in, n, r);
        r->port = dport;                                /* the SNI's port: the one connected to */
        return st;
    }
    static const char kc[] = "CONNECT ";
    size_t k = 0;
    while (k < n && k < 8 && in[k] == (uint8_t)kc[k]) k++;
    if (k == 8) return connect_req(in, n, acked, r);
    if (acked) return refuse(r, "an answered CONNECT that is not one");
    if (k == n) return PP_MORE;                         /* could still be a CONNECT */
    if (in[0] >= 'A' && in[0] <= 'Z') return http(in, n, dport, r);
    return refuse(r, "neither TLS nor HTTP");
}
