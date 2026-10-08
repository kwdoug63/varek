// SPDX-License-Identifier: MIT
// proxy_parse.c — v1.26: what the egress proxy reads. See proxy_parse.h.

#include "proxy_parse.h"

#include <string.h>
#include <strings.h>

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

/* v1.26 review: how the request's body is framed (RFC 9112 6.3): a
 * Content-Length, Transfer-Encoding: chunked, or none. Refused: both, either
 * twice, a Content-Length that is not digits, any other transfer coding, and
 * a protocol upgrade (WebSocket, h2c), whose bytes the proxy could not read
 * as requests. The head is well formed (host_header read it). 0, or -1. */
static int framing(const uint8_t *in, size_t hdr, size_t end, pp_result_t *r) {
    int cl = 0, te = 0;
    r->body = PP_BODY_NONE;
    r->body_len = 0;
    size_t i = hdr;
    while (i + 2 <= end - 2) {
        size_t ls = i;
        while (in[i] != '\r') i++;
        size_t le = i;
        i += 2;
        if (le == ls) break;
        size_t c = ls;
        while (c < le && in[c] != ':') c++;
        size_t nl = c - ls, a = c + 1, b = le;
        while (a < b && (in[a] == ' ' || in[a] == '\t')) a++;
        while (b > a && (in[b - 1] == ' ' || in[b - 1] == '\t')) b--;
        #define HN(s) (nl == sizeof(s) - 1 && !strncasecmp((const char *)in + ls, s, nl))
        if (HN("content-length")) {
            if (cl++ || b == a || b - a > 18) { r->why = "a Content-Length twice, or too long"; return -1; }
            uint64_t v = 0;
            for (size_t k = a; k < b; k++) {
                if (in[k] < '0' || in[k] > '9') { r->why = "a Content-Length that is not a number"; return -1; }
                v = v * 10 + (uint64_t)(in[k] - '0');
            }
            r->body = PP_BODY_LENGTH;
            r->body_len = v;
        } else if (HN("transfer-encoding")) {
            if (te++ || b - a != 7 || strncasecmp((const char *)in + a, "chunked", 7)) {
                r->why = "a transfer coding other than chunked";
                return -1;
            }
        } else if (HN("upgrade")) {
            r->why = "a protocol upgrade (not read in SNI mode)";
            return -1;
        }
        #undef HN
    }
    if (cl && te) { r->why = "both Content-Length and Transfer-Encoding"; return -1; }
    if (te) { r->body = PP_BODY_CHUNKED; r->body_len = 0; }
    return 0;
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
    if (framing(in, q.hdr, (size_t)end, r) < 0) return PP_REFUSE;
    r->head_len = (size_t)end;
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

/* ---- section 5: the upstream proxy's reply ---- */

pp_status_t pp_upstream_reply(const uint8_t *in, size_t n, unsigned *status, size_t *len, const char **why) {
    *status = 0;
    *len = 0;
    *why = NULL;
    long end = head_end(in, n);
    if (end < 0) { *why = "a malformed reply from the upstream"; return PP_REFUSE; }
    if (end == 0) {
        if (n >= PP_HTTP_MAX) { *why = "a reply from the upstream over 8 KB"; return PP_REFUSE; }
        return PP_MORE;
    }
    if (end < 14 || memcmp(in, "HTTP/1.", 7) || (in[7] != '0' && in[7] != '1') || in[8] != ' ' ||
        in[9] < '1' || in[9] > '5' || in[10] < '0' || in[10] > '9' || in[11] < '0' || in[11] > '9' ||
        (in[12] != ' ' && in[12] != '\r')) {
        *why = "a malformed reply from the upstream";
        return PP_REFUSE;
    }
    *status = (unsigned)((in[9] - '0') * 100 + (in[10] - '0') * 10 + (in[11] - '0'));
    *len = (size_t)end;
    if (*status < 200 || *status > 299) { *why = "the upstream refused"; return PP_REFUSE; }
    return PP_OK;
}

/* ---- v1.26 review: a chunked request body ---- */

enum { CK_SIZE, CK_EXT, CK_SIZE_LF, CK_DATA, CK_DATA_CR, CK_DATA_LF, CK_TR_START, CK_TR_LINE, CK_TR_LF, CK_END_LF };

static int hexv(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

long pp_chunked_feed(pp_chunked_t *c, const uint8_t *in, size_t n, bool *done) {
    *done = false;
    size_t i = 0;
    while (i < n) {
        uint8_t b = in[i];
        switch (c->st) {
        case CK_SIZE: {
            int v = hexv(b);
            if (v >= 0) {
                if (++c->digits > 15) return -1;
                c->left = c->left * 16 + (uint64_t)v;
                i++;
                break;
            }
            if (c->digits == 0) return -1;
            if (b == '\r') { c->st = CK_SIZE_LF; i++; break; }
            if (b == ';' || b == ' ' || b == '\t') { c->st = CK_EXT; c->line = 0; i++; break; }
            return -1;
        }
        case CK_EXT:
            if (b == '\n' || b == 0) return -1;
            if (b == '\r') c->st = CK_SIZE_LF;
            else if (++c->line > 4096) return -1;
            i++;
            break;
        case CK_SIZE_LF:
            if (b != '\n') return -1;
            i++;
            c->digits = 0;
            c->st = c->left ? CK_DATA : CK_TR_START;
            break;
        case CK_DATA: {
            size_t take = n - i < c->left ? n - i : (size_t)c->left;
            i += take;
            c->left -= take;
            if (!c->left) c->st = CK_DATA_CR;
            break;
        }
        case CK_DATA_CR:
            if (b != '\r') return -1;
            c->st = CK_DATA_LF;
            i++;
            break;
        case CK_DATA_LF:
            if (b != '\n') return -1;
            c->st = CK_SIZE;
            c->left = 0;
            i++;
            break;
        case CK_TR_START:
            if (b == '\r') { c->st = CK_END_LF; i++; break; }
            if (b == '\n' || b == 0 || ++c->lines > 64) return -1;
            c->st = CK_TR_LINE;
            c->line = 0;
            break;
        case CK_TR_LINE:
            if (b == '\n' || b == 0) return -1;
            if (b == '\r') c->st = CK_TR_LF;
            else if (++c->line > 4096) return -1;
            i++;
            break;
        case CK_TR_LF:
            if (b != '\n') return -1;
            c->st = CK_TR_START;
            i++;
            break;
        case CK_END_LF:
            if (b != '\n') return -1;
            i++;
            *done = true;
            return (long)i;
        default:
            return -1;
        }
    }
    return (long)i;
}
