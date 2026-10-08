// SPDX-License-Identifier: MIT
// proxy_parse_test.c — v1.26 step 5: the proxy's parsers (proxy_parse.c).
// Built with -fsanitize=address,undefined (make test-proxy-parse).
//
//   proxy_parse_test unit                 the vectors below
//   proxy_parse_test file PATH DPORT [acked]
//                                         parse a file, print the result
//   proxy_parse_test fuzz N SEED          N mutations of the seed inputs
//
// With -DPP_LIBFUZZER the file is a libFuzzer target instead (no main).

#include "../proxy_parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The checks every result must pass, whatever the input. */
static void invariants(const uint8_t *in, size_t n, unsigned dport, bool acked, pp_status_t st,
                       const pp_result_t *r) {
    (void)in; (void)n; (void)acked;
    if (st == PP_REFUSE && !r->why) { fprintf(stderr, "refusal without a reason\n"); abort(); }
    if (st != PP_OK && st != PP_ACK) return;
    size_t l = strlen(r->name);
    if (l == 0 || l > PP_NAME_MAX) { fprintf(stderr, "bad name length\n"); abort(); }
    for (size_t i = 0; i < l; i++) {
        char c = r->name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) {
            fprintf(stderr, "name byte 0x%02x\n", (unsigned char)c);
            abort();
        }
    }
    if (r->port == 0 || r->port > 65535) { fprintf(stderr, "bad port\n"); abort(); }
    if (st == PP_OK && r->kind != PP_KIND_CONNECT && r->port != dport) { fprintf(stderr, "port\n"); abort(); }
}

/* v1.26.1, step 5: what every pp_request result must satisfy. */
static void req_invariants(const uint8_t *in, size_t n, pp_status_t st, const pp_req_t *q) {
    (void)in;
    if (st == PP_REFUSE && !q->why) { fprintf(stderr, "request refusal without a reason\n"); abort(); }
    if (st != PP_OK) return;
    static const char pre[] = " https://api.example.com:443/";
    size_t ml = strlen(q->method);
    if (ml == 0 || ml > PP_METHOD_MAX || q->object_len != strlen(q->object) || q->object_len > PP_OBJ_MAX ||
        strncmp(q->object, q->method, ml) || strncmp(q->object + ml, pre, sizeof pre - 1) ||
        q->head_len == 0 || q->head_len > n) {
        fprintf(stderr, "bad request result %s\n", q->object);
        abort();
    }
    for (size_t i = 0; i < ml; i++) if (q->method[i] < 'A' || q->method[i] > 'Z') abort();
    /* the target: printable, no space, no '\\' ';' '#', no "//", "/./" or "/../" before the query */
    const char *t = q->object + ml + sizeof pre - 2;
    const char *qm = strchr(t, '?');
    size_t pl = qm ? (size_t)(qm - t) : strlen(t);
    for (const char *c = t; *c; c++)
        if (*c < 0x21 || *c > 0x7e || *c == '\\' || *c == ';' || *c == '#') { fprintf(stderr, "target byte\n"); abort(); }
    for (size_t i = 0; i + 1 < pl; i++) {
        if (t[i] == '/' && t[i + 1] == '/') { fprintf(stderr, "//\n"); abort(); }
        if (t[i] == '/' && t[i + 1] == '.' && (i + 2 == pl || t[i + 2] == '/' ||
                                              (t[i + 2] == '.' && (i + 3 == pl || t[i + 3] == '/')))) {
            fprintf(stderr, "dot segment\n"); abort();
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    if (n < 3) return 0;
    bool acked = d[0] & 1;
    unsigned dport = (unsigned)(d[1] << 8 | d[2]);
    if (dport == 0) dport = 443;
    pp_result_t r;
    pp_status_t st = pp_parse(d + 3, n - 3, dport, acked, &r);
    invariants(d + 3, n - 3, dport, acked, st, &r);
    pp_req_t q;                                         /* v1.26.1 */
    pp_status_t qs = pp_request(d + 3, n - 3, "https", "api.example.com", 443, &q);
    req_invariants(d + 3, n - 3, qs, &q);
    return 0;
}

#ifndef PP_LIBFUZZER

/* ---- inputs ---- */

static size_t put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2; }

/* A ClientHello in one or more records. sni: NULL for none; ext_extra: a
 * raw extension block appended; split: bytes per record (0: one record). */
static size_t client_hello(uint8_t *out, const char *sni, int nsni, const uint8_t *ext_extra, size_t exl,
                           size_t split) {
    uint8_t body[20000];
    size_t b = 0;
    body[b++] = 3; body[b++] = 3;
    memset(body + b, 0x42, 32); b += 32;
    body[b++] = 0;                                   /* session id */
    b += put16(body + b, 4); b += put16(body + b, 0x1301); b += put16(body + b, 0xc02f);
    body[b++] = 1; body[b++] = 0;                    /* compression: null */
    size_t extlen_at = b;
    b += 2;
    if (sni) {
        size_t nl = strlen(sni);
        b += put16(body + b, 0);
        b += put16(body + b, (unsigned)(2 + nsni * (3 + nl)));
        b += put16(body + b, (unsigned)(nsni * (3 + nl)));
        for (int k = 0; k < nsni; k++) {
            body[b++] = 0;
            b += put16(body + b, (unsigned)nl);
            memcpy(body + b, sni, nl); b += nl;
        }
    }
    b += put16(body + b, 0x002b); b += put16(body + b, 3); body[b++] = 2; b += put16(body + b, 0x0304);
    if (exl) { memcpy(body + b, ext_extra, exl); b += exl; }
    put16(body + extlen_at, (unsigned)(b - extlen_at - 2));
    uint8_t hs[20010];
    size_t h = 0;
    hs[h++] = 1;
    hs[h++] = (uint8_t)(b >> 16); hs[h++] = (uint8_t)(b >> 8); hs[h++] = (uint8_t)b;
    memcpy(hs + h, body, b); h += b;
    size_t o = 0;
    if (!split) split = h;
    for (size_t off = 0; off < h; off += split) {
        size_t l = h - off < split ? h - off : split;
        out[o++] = 22; out[o++] = 3; out[o++] = 1;
        o += put16(out + o, (unsigned)l);
        memcpy(out + o, hs + off, l); o += l;
    }
    return o;
}

static int fails = 0;

static void expect(const char *what, const uint8_t *in, size_t n, unsigned dport, bool acked,
                   pp_status_t want, const char *name_or_why) {
    pp_result_t r;
    pp_status_t st = pp_parse(in, n, dport, acked, &r);
    invariants(in, n, dport, acked, st, &r);
    bool ok = st == want;
    if (ok && (want == PP_OK || want == PP_ACK) && name_or_why) ok = !strcmp(r.name, name_or_why);
    if (ok && want == PP_REFUSE && name_or_why) ok = strstr(r.why, name_or_why) != NULL;
    printf("  %s   %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        printf("         got %d name=%s why=%s\n", st, r.name, r.why ? r.why : "");
        fails = 1;
    }
}

static void expect_s(const char *what, const char *s, unsigned dport, pp_status_t want, const char *x) {
    expect(what, (const uint8_t *)s, strlen(s), dport, false, want, x);
}

static int unit(void) {
    static uint8_t b[40000];
    size_t n;
    n = client_hello(b, "api.example.com", 1, NULL, 0, 0);
    expect("TLS: the SNI", b, n, 443, false, PP_OK, "api.example.com");
    expect("TLS: every prefix asks for more", b, n - 1, 443, false, PP_MORE, NULL);
    expect("TLS: the first byte alone asks for more", b, 1, 443, false, PP_MORE, NULL);
    n = client_hello(b, "API.Example.COM", 1, NULL, 0, 0);
    expect("TLS: the SNI, lowercased", b, n, 443, false, PP_OK, "api.example.com");
    n = client_hello(b, "api.example.com", 1, NULL, 0, 7);
    expect("TLS: over many records", b, n, 443, false, PP_OK, "api.example.com");
    n = client_hello(b, "api.example.com", 1, NULL, 0, 1);
    expect("TLS: one byte per record (too many records)", b, n, 443, false, PP_REFUSE, "too many records");
    n = client_hello(b, NULL, 0, NULL, 0, 0);
    expect("TLS: no SNI", b, n, 443, false, PP_REFUSE, "no SNI");
    n = client_hello(b, "a.example.com", 2, NULL, 0, 0);
    expect("TLS: two names", b, n, 443, false, PP_REFUSE, "more than one");
    n = client_hello(b, "192.0.2.1", 1, NULL, 0, 0);
    expect("TLS: an IP literal", b, n, 443, false, PP_REFUSE, "not a host name");
    n = client_hello(b, "api.example.com.", 1, NULL, 0, 0);
    expect("TLS: a trailing dot", b, n, 443, false, PP_REFUSE, "not a host name");
    n = client_hello(b, "api_x.example.com", 1, NULL, 0, 0);
    expect("TLS: an underscore", b, n, 443, false, PP_REFUSE, "not a host name");
    n = client_hello(b, "-a.example.com", 1, NULL, 0, 0);
    expect("TLS: a label starting with '-'", b, n, 443, false, PP_REFUSE, "not a host name");
    char longl[80];
    memset(longl, 'a', 64); memcpy(longl + 64, ".com", 5);
    n = client_hello(b, longl, 1, NULL, 0, 0);
    expect("TLS: a label over 63 bytes", b, n, 443, false, PP_REFUSE, "not a host name");
    uint8_t ech[] = { 0xfe, 0x0d, 0, 4, 1, 2, 3, 4 };
    n = client_hello(b, "api.example.com", 1, ech, sizeof ech, 0);
    expect("TLS: encrypted_client_hello", b, n, 443, false, PP_REFUSE, "encrypted_client_hello");
    uint8_t esni[] = { 0xff, 0xce, 0, 0 };
    n = client_hello(b, "api.example.com", 1, esni, sizeof esni, 0);
    expect("TLS: encrypted SNI", b, n, 443, false, PP_REFUSE, "encrypted SNI");
    uint8_t dup[] = { 0x00, 0x2b, 0, 3, 2, 3, 4 };
    n = client_hello(b, "api.example.com", 1, dup, sizeof dup, 0);
    expect("TLS: an extension given twice", b, n, 443, false, PP_REFUSE, "twice");
    uint8_t sni2[] = { 0, 0, 0, 8, 0, 6, 0, 0, 3, 'x', '.', 'y' };
    n = client_hello(b, "api.example.com", 1, sni2, sizeof sni2, 0);
    expect("TLS: two server_name extensions", b, n, 443, false, PP_REFUSE, "twice");
    static uint8_t pad[17000];
    pad[0] = 0; pad[1] = 21; put16(pad + 2, 15000); memset(pad + 4, 0, 15000);
    n = client_hello(b, "api.example.com", 1, pad, 15004, 4000);
    expect("TLS: a large ClientHello (15 KB of padding)", b, n, 443, false, PP_OK, "api.example.com");
    put16(pad + 2, 16500);
    memset(pad + 4, 0, 16500);
    n = client_hello(b, "api.example.com", 1, pad, 16504, 8000);
    expect("TLS: a ClientHello over 16 KB", b, n, 443, false, PP_REFUSE, "over 16 KB");
    n = client_hello(b, "api.example.com", 1, NULL, 0, 0);
    b[0] = 23;
    expect("TLS: application data first", b, n, 443, false, PP_REFUSE, "neither TLS nor HTTP");
    n = client_hello(b, "api.example.com", 1, NULL, 0, 0);
    b[5] = 2;
    expect("TLS: not a ClientHello", b, n, 443, false, PP_REFUSE, "not a ClientHello");
    n = client_hello(b, "api.example.com", 1, NULL, 0, 0);
    b[3] = 0; b[4] = 0;
    expect("TLS: an empty record", b, n, 443, false, PP_REFUSE, "record length");
    n = client_hello(b, "api.example.com", 1, NULL, 0, 0);
    b[8] += 1;                                   /* the handshake says one byte more */
    expect("TLS: a handshake longer than its records (waits)", b, n, 443, false, PP_MORE, NULL);

    expect_s("HTTP: the Host", "GET / HTTP/1.1\r\nHost: api.example.com\r\nAccept: */*\r\n\r\n",
             80, PP_OK, "api.example.com");
    expect_s("HTTP: Host with the port connected to", "GET /x HTTP/1.1\r\nhost:  API.example.com:8080 \r\n\r\n",
             8080, PP_OK, "api.example.com");
    expect_s("HTTP: Host with a trailing dot", "GET / HTTP/1.1\r\nHost: api.example.com.\r\n\r\n",
             80, PP_OK, "api.example.com");
    expect_s("HTTP: absolute-form, the same authority",
             "GET http://api.example.com/x HTTP/1.1\r\nHost: api.example.com\r\n\r\n", 80, PP_OK, "api.example.com");
    expect_s("HTTP: OPTIONS *", "OPTIONS * HTTP/1.1\r\nHost: api.example.com\r\n\r\n", 80, PP_OK, "api.example.com");
    expect_s("HTTP: headers not ended yet", "GET / HTTP/1.1\r\nHost: api.example.com\r\n", 80, PP_MORE, NULL);
    expect_s("HTTP: one CR short", "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r", 80, PP_MORE, NULL);
    expect_s("HTTP: no Host", "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", 80, PP_REFUSE, "no Host");
    expect_s("HTTP: two Hosts", "GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n",
             80, PP_REFUSE, "more than one Host");
    expect_s("HTTP: another port", "GET / HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n", 80, PP_REFUSE, "port");
    expect_s("HTTP: an IP literal", "GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n", 80, PP_REFUSE, "not a host name");
    expect_s("HTTP: an IPv6 literal", "GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n", 80, PP_REFUSE, "not a host name");
    expect_s("HTTP: userinfo", "GET / HTTP/1.1\r\nHost: u@api.example.com\r\n\r\n", 80, PP_REFUSE, "not a host name");
    expect_s("HTTP: a bare LF", "GET / HTTP/1.1\nHost: api.example.com\n\n", 80, PP_REFUSE, "malformed");
    expect_s("HTTP: a bare CR", "GET / HTTP/1.1\r\nHost: api.example.com\rX\r\n\r\n", 80, PP_REFUSE, "malformed");
    expect_s("HTTP: obs-fold", "GET / HTTP/1.1\r\nX: a\r\n b\r\nHost: api.example.com\r\n\r\n", 80, PP_REFUSE,
             "malformed headers");
    expect_s("HTTP: space before the colon", "GET / HTTP/1.1\r\nHost : api.example.com\r\n\r\n", 80, PP_REFUSE,
             "malformed headers");
    expect_s("HTTP: an absolute-form target elsewhere",
             "GET http://other.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n", 80, PP_REFUSE, "not the Host");
    expect_s("HTTP: HTTP/2 preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 80, PP_REFUSE, "request line");
    expect_s("HTTP: lowercase method", "get / HTTP/1.1\r\nHost: a.example.com\r\n\r\n", 80, PP_REFUSE,
             "neither TLS nor HTTP");
    {
        static char big[9000];
        memcpy(big, "GET / HTTP/1.1\r\nX: ", 19);
        memset(big + 19, 'a', sizeof big - 20);
        big[sizeof big - 1] = 0;
        expect_s("HTTP: headers over 8 KB", big, 80, PP_REFUSE, "over 8 KB");
    }

    const char *con = "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n";
    expect_s("CONNECT: answered first", con, 3128, PP_ACK, "api.example.com");
    expect_s("CONNECT: a prefix asks for more", "CONNE", 3128, PP_MORE, NULL);
    expect_s("CONNECT: no port", "CONNECT api.example.com HTTP/1.1\r\n\r\n", 3128, PP_REFUSE, "host:port");
    expect_s("CONNECT: another Host", "CONNECT api.example.com:443 HTTP/1.1\r\nHost: x.example.com\r\n\r\n",
             3128, PP_REFUSE, "not the CONNECT target");
    expect_s("CONNECT: an IP literal", "CONNECT 192.0.2.1:443 HTTP/1.1\r\n\r\n", 3128, PP_REFUSE, "host:port");
    {
        size_t cl = strlen(con);
        memcpy(b, con, cl);
        n = cl + client_hello(b + cl, "api.example.com", 1, NULL, 0, 0);
        expect("CONNECT: data before the answer", b, n, 3128, false, PP_REFUSE, "before the CONNECT was answered");
        pp_result_t r;
        pp_status_t st = pp_parse(b, n, 3128, true, &r);
        bool ok = st == PP_OK && r.kind == PP_KIND_CONNECT && r.port == 443 && !strcmp(r.name, "api.example.com");
        printf("  %s   CONNECT: then the ClientHello with the same SNI (port 443)\n", ok ? "PASS" : "FAIL");
        if (!ok) fails = 1;
        expect("CONNECT: the ClientHello not there yet", b, cl + 3, 3128, true, PP_MORE, NULL);
        n = cl + client_hello(b + cl, "other.example.com", 1, NULL, 0, 0);
        expect("CONNECT: an SNI that is not the target", b, n, 3128, true, PP_REFUSE, "not the CONNECT target");
        memcpy(b + cl, "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n", 42);
        expect("CONNECT: plain HTTP inside", b, cl + 42, 3128, true, PP_REFUSE, "not a TLS handshake");
    }
    n = client_hello(b, "api.example.com", 1, NULL, 0, 0);
    expect("a ClientHello where a CONNECT was answered", b, n, 443, true, PP_REFUSE, "answered");
    expect_s("neither TLS nor HTTP", "\x01\x02\x03", 443, PP_REFUSE, "neither");
    {
        /* every proper prefix of a whole request asks for more */
        bool all = true;
        n = client_hello(b, "api.example.com", 1, NULL, 0, 40);
        for (size_t k = 0; k < n; k++) { pp_result_t r; if (pp_parse(b, k, 443, false, &r) != PP_MORE) all = false; }
        const char *hq = "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        for (size_t k = 0; k < strlen(hq); k++) { pp_result_t r; if (pp_parse((const uint8_t *)hq, k, 80, false, &r) != PP_MORE) all = false; }
        for (size_t k = 0; k < strlen(con); k++) { pp_result_t r; if (pp_parse((const uint8_t *)con, k, 3128, false, &r) != PP_MORE) all = false; }
        printf("  %s   every proper prefix of a ClientHello, a request or a CONNECT asks for more\n", all ? "PASS" : "FAIL");
        if (!all) fails = 1;
    }
    {
        /* section 5: the upstream proxy's reply to the proxy's CONNECT */
        struct { const char *in; pp_status_t want; unsigned st; size_t len; } v[] = {
            { "HTTP/1.1 200 Connection established\r\n\r\n", PP_OK, 200, 39 },
            { "HTTP/1.0 200 OK\r\nVia: squid\r\n\r\nXY", PP_OK, 200, 31 },
            { "HTTP/1.1 204\r\n\r\n", PP_OK, 204, 16 },
            { "HTTP/1.1 403 Forbidden\r\n\r\n", PP_REFUSE, 403, 28 },
            { "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", PP_REFUSE, 407, 49 },
            { "HTTP/1.1 200 OK\r\n", PP_MORE, 0, 0 },
            { "HTTP/1.1 2", PP_MORE, 0, 0 },
            { "HTTP/2 200\r\n\r\n", PP_REFUSE, 0, 0 },
            { "HTTP/1.1 600 X\r\n\r\n", PP_REFUSE, 0, 0 },
            { "HTTP/1.1 20 X\r\n\r\n", PP_REFUSE, 0, 0 },
            { "HTTP/1.1 200 OK\nX: y\n\n", PP_REFUSE, 0, 0 },
            { "SSH-2.0-OpenSSH\r\n\r\n", PP_REFUSE, 0, 0 },
        };
        bool all = true;
        for (size_t k = 0; k < sizeof v / sizeof *v; k++) {
            unsigned st; size_t len; const char *why;
            pp_status_t got = pp_upstream_reply((const uint8_t *)v[k].in, strlen(v[k].in), &st, &len, &why);
            bool ok = got == v[k].want && st == v[k].st && (got != PP_OK || len == v[k].len) &&
                      (got != PP_REFUSE || why);
            if (!ok) { printf("         upstream reply %zu: got %d status %u len %zu\n", k, got, st, len); all = false; }
        }
        printf("  %s   the upstream's reply: 2xx relays, anything else (or malformed) refuses, partial waits\n",
               all ? "PASS" : "FAIL");
        if (!all) fails = 1;
    }
    {
        /* v1.26 review: each request's head length and body framing */
        pp_result_t r;
        const char *a = "POST /x HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\n\r\nhelloGET";
        bool ok = pp_parse((const uint8_t *)a, strlen(a), 80, false, &r) == PP_OK && r.head_len == strlen(a) - 8 &&
                  r.body == PP_BODY_LENGTH && r.body_len == 5;
        const char *b = "POST /x HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: Chunked\r\n\r\n";
        ok = ok && pp_parse((const uint8_t *)b, strlen(b), 80, false, &r) == PP_OK && r.body == PP_BODY_CHUNKED;
        const char *g = "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        ok = ok && pp_parse((const uint8_t *)g, strlen(g), 80, false, &r) == PP_OK && r.body == PP_BODY_NONE &&
             r.head_len == strlen(g);
        printf("  %s   HTTP: the head's length and its body's framing (Content-Length, chunked, none)\n", ok ? "PASS" : "FAIL");
        if (!ok) fails = 1;
    }
    expect_s("HTTP: Content-Length and Transfer-Encoding", "POST / HTTP/1.1\r\nHost: a.example.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
             80, PP_REFUSE, "both Content-Length");
    expect_s("HTTP: Content-Length twice", "POST / HTTP/1.1\r\nHost: a.example.com\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n",
             80, PP_REFUSE, "twice");
    expect_s("HTTP: a Content-Length that is not a number", "POST / HTTP/1.1\r\nHost: a.example.com\r\nContent-Length: +3\r\n\r\n",
             80, PP_REFUSE, "not a number");
    expect_s("HTTP: gzip, chunked", "POST / HTTP/1.1\r\nHost: a.example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
             80, PP_REFUSE, "other than chunked");
    expect_s("HTTP: a protocol upgrade", "GET / HTTP/1.1\r\nHost: a.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
             80, PP_REFUSE, "protocol upgrade");
    {
        /* v1.26 review: chunked bodies, whole and a byte at a time */
        struct { const char *in; long want; bool done; } v[] = {
            { "5\r\nhello\r\n0\r\n\r\nGET", 15, true },
            { "5;ext=1\r\nhello\r\n0\r\nX-T: 1\r\n\r\n", 29, true },
            { "5\r\nhel", 6, false },
            { "5\nhello\r\n0\r\n\r\n", -1, false },
            { "g\r\n", -1, false },
            { "1234567890abcdef0\r\n", -1, false },
            { "5\r\nhelloX", -1, false },
        };
        bool all = true;
        for (size_t k = 0; k < sizeof v / sizeof *v; k++) {
            pp_chunked_t c;
            memset(&c, 0, sizeof c);
            bool done;
            long got = pp_chunked_feed(&c, (const uint8_t *)v[k].in, strlen(v[k].in), &done);
            if (got != v[k].want || (got >= 0 && done != v[k].done)) {
                printf("         chunked %zu: got %ld done %d\n", k, got, done); all = false;
            }
            if (v[k].want >= 0 && v[k].done) {          /* the same, one byte at a time */
                memset(&c, 0, sizeof c);
                long tot = 0;
                done = false;
                for (size_t j = 0; j < strlen(v[k].in) && !done; j++) {
                    long g1 = pp_chunked_feed(&c, (const uint8_t *)v[k].in + j, 1, &done);
                    if (g1 < 0) { tot = -1; break; }
                    tot += g1;
                }
                if (tot != v[k].want || !done) { printf("         chunked %zu bytewise: %ld\n", k, tot); all = false; }
            }
        }
        printf("  %s   chunked bodies: whole, a byte at a time, and malformed ones refused\n", all ? "PASS" : "FAIL");
        if (!all) fails = 1;
    }
    {
        /* v1.26.1, step 5: requests inside terminated TLS (connection
         * https://api.example.com:443) */
        struct { const char *what, *in; pp_status_t want; const char *x; } v[] = {
            { "a GET", "GET /v1/models HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_OK,
              "GET https://api.example.com:443/v1/models" },
            { "a query, kept as sent", "GET /v1/files?limit=10&q=a%20b HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n", PP_OK,
              "GET https://api.example.com:443/v1/files?limit=10&q=a%20b" },
            { "a Host in capitals, with a trailing dot", "GET / HTTP/1.1\r\nHost: API.Example.com.\r\n\r\n", PP_OK,
              "GET https://api.example.com:443/" },
            { "absolute-form, read as its path", "GET https://api.example.com/v1/x?y HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
              PP_OK, "GET https://api.example.com:443/v1/x?y" },
            { "a 20-letter method", "ABCDEFGHIJKLMNOPQRST /x HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_OK,
              "ABCDEFGHIJKLMNOPQRST https://api.example.com:443/x" },
            { "a trailing slash, '..' inside a segment", "GET /a/b../..c/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_OK,
              "GET https://api.example.com:443/a/b../..c/" },
            { "a reserved escape (%3F), kept", "GET /a%3Fb HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_OK,
              "GET https://api.example.com:443/a%3Fb" },
            { "a '//' in the query", "GET /a?u=https://x HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_OK,
              "GET https://api.example.com:443/a?u=https://x" },
            { "a body: Content-Length", "POST /a HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\n\r\nhello", PP_OK,
              "POST https://api.example.com:443/a" },
            { "not whole yet", "GET /v1/models HTTP/1.1\r\nHost: api.exa", PP_MORE, NULL },
            { "a 21-letter method", "ABCDEFGHIJKLMNOPQRSTU /x HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "request line" },
            { "a lowercase method", "get /x HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "request line" },
            { "CONNECT", "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "CONNECT inside" },
            { "another Host (fronting)", "GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n", PP_REFUSE, "Host other than" },
            { "another Host port", "GET / HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\n", PP_REFUSE, "Host other than" },
            { "no Host", "GET / HTTP/1.1\r\nX: y\r\n\r\n", PP_REFUSE, "no Host" },
            { "two Hosts", "GET / HTTP/1.1\r\nHost: api.example.com\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "more than one Host" },
            { "absolute-form for another host", "GET https://other.example.com/x HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
              PP_REFUSE, "another authority" },
            { "absolute-form, another scheme", "GET http://api.example.com/x HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
              PP_REFUSE, "not a path" },
            { "absolute-form without a path", "GET https://api.example.com HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
              PP_REFUSE, "without a path" },
            { "OPTIONS *", "OPTIONS * HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "not a path" },
            { "a '..' segment", "GET /v1/../admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "'..' path segment" },
            { "a trailing '..'", "GET /v1/.. HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "'..' path segment" },
            { "a '.' segment", "GET /v1/./admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "'..' path segment" },
            { "'..' before the query", "GET /v1/..?x HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "'..' path segment" },
            { "an empty segment", "GET /v1//admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "('//')" },
            { "a ';'", "GET /v1/admin;x/y HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "';'" },
            { "a backslash", "GET /v1\\admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "';'" },
            { "a '#'", "GET /v1#x HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "';'" },
            { "an escaped letter (%61dmin)", "GET /v1/%61dmin HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "unreserved" },
            { "an escaped '.' (%2e%2e)", "GET /v1/%2e%2e/admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "unreserved" },
            { "an escaped '/' (%2F)", "GET /v1%2Fadmin HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "unreserved" },
            { "an escaped '\\' (%5c)", "GET /v1%5cadmin HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "unreserved" },
            { "an escaped letter in the query", "GET /a?x=%41 HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "unreserved" },
            { "a bad escape", "GET /a%4 HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "bad percent" },
            { "a bad escape, not hex", "GET /a%zz HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "bad percent" },
            { "a byte over 0x7e", "GET /a\xe9 HTTP/1.1\r\nHost: api.example.com\r\n\r\n", PP_REFUSE, "request line" },
            { "a protocol upgrade", "GET / HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\n\r\n", PP_REFUSE, "upgrade" },
            { "both framings", "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
              PP_REFUSE, "both" },
            { "a bare LF", "GET / HTTP/1.1\nHost: api.example.com\r\n\r\n", PP_REFUSE, "malformed" },
        };
        bool all = true;
        for (size_t k = 0; k < sizeof v / sizeof *v; k++) {
            pp_req_t q;
            pp_status_t st = pp_request((const uint8_t *)v[k].in, strlen(v[k].in), "https", "api.example.com", 443, &q);
            req_invariants((const uint8_t *)v[k].in, strlen(v[k].in), st, &q);
            bool ok = st == v[k].want && (st != PP_OK || !strcmp(q.object, v[k].x)) &&
                      (st != PP_REFUSE || strstr(q.why, v[k].x));
            if (!ok) {
                printf("         request: %s: got %d (%s)\n", v[k].what, st, st == PP_OK ? q.object : st == PP_REFUSE ? q.why : "more");
                all = false;
            }
        }
        /* an object at the bound, and one byte over it */
        static char big[PP_HTTP_MAX];
        size_t pre = strlen("GET https://api.example.com:443");
        for (int over = 0; over < 2; over++) {
            size_t tl = PP_OBJ_MAX - pre + (size_t)over;
            int l = snprintf(big, sizeof big, "GET /");
            memset(big + l, 'a', tl - 1);
            l += (int)tl - 1;
            l += snprintf(big + l, sizeof big - (size_t)l, " HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
            pp_req_t q;
            pp_status_t st = pp_request((const uint8_t *)big, (size_t)l, "https", "api.example.com", 443, &q);
            if (over ? st != PP_REFUSE : (st != PP_OK || q.object_len != PP_OBJ_MAX)) {
                printf("         request: an object of %zu bytes: %d\n", pre + tl, st); all = false;
            }
        }
        /* each accepted request, read a byte at a time, asks for more until whole */
        const char *one = "POST /v1/chat?x=1 HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        for (size_t j = 1; j < strlen(one); j++) {
            pp_req_t q;
            if (pp_request((const uint8_t *)one, j, "https", "api.example.com", 443, &q) != PP_MORE) {
                printf("         request: a prefix of %zu bytes was not asked for more\n", j); all = false; break;
            }
        }
        printf("  %s   requests inside TLS: the object, the Host, the target forms a server could read otherwise refused\n",
               all ? "PASS" : "FAIL");
        if (!all) fails = 1;
    }
    printf("proxy_parse unit: %s\n", fails ? "FAIL" : "PASS");
    return fails;
}

static int file_mode(const char *path, unsigned dport, bool acked) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 2; }
    static uint8_t b[PP_IN_MAX + 1024];
    size_t n = fread(b, 1, sizeof b, f);
    fclose(f);
    pp_result_t r;
    pp_status_t st = pp_parse(b, n, dport, acked, &r);
    invariants(b, n, dport, acked, st, &r);
    if (st == PP_OK || st == PP_ACK)
        printf("%s %s %s %u\n", st == PP_OK ? "OK" : "ACK", pp_kind_name(r.kind), r.name, r.port);
    else if (st == PP_MORE) printf("MORE\n");
    else printf("REFUSE %s\n", r.why);
    return 0;
}

/* A small mutational fuzzer (no libFuzzer runtime needed): each round takes
 * a seed, applies a few byte flips, inserts, deletes and splices, and parses
 * every prefix length of a sample under the sanitizers. */
static uint64_t rs;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)rs; }

static int fuzz(unsigned long iters, unsigned long seed) {
    rs = seed * 2654435761u + 1;
    static uint8_t seeds[6][40000];
    size_t sl[6];
    sl[0] = client_hello(seeds[0], "api.example.com", 1, NULL, 0, 0);
    sl[1] = client_hello(seeds[1], "a.b.example.com", 1, NULL, 0, 33);
    const char *h = "GET http://api.example.com/x HTTP/1.1\r\nHost: api.example.com:80\r\nX-A: b\r\n\r\n";
    sl[2] = strlen(h); memcpy(seeds[2], h, sl[2]);
    const char *c = "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
    sl[3] = strlen(c); memcpy(seeds[3], c, sl[3]);
    if (rnd() % 3 == 0) {                             /* v1.26 review: a chunked body in place of seed 1 */
        const char *ckb = "1a;x=y\r\nabcdefghijklmnopqrstuvwxyz\r\n3\r\nabc\r\n0\r\nT: v\r\n\r\n";
        sl[1] = strlen(ckb); memcpy(seeds[1], ckb, sl[1]);
    }
    if (rnd() % 2) {                                  /* section 5: an upstream's reply in place of seed 2 */
        const char *u = "HTTP/1.1 200 Connection established\r\nVia: 1.1 squid\r\n\r\n";
        sl[2] = strlen(u); memcpy(seeds[2], u, sl[2]);
    } else if (rnd() % 2) {                           /* v1.26.1: a request inside TLS in its place */
        const char *q = "POST /v1/chat/completions?model=a%20b&x=1 HTTP/1.1\r\nHost: api.example.com:443\r\n"
                        "Content-Length: 2\r\nX-Trace: ../a//b;c\r\n\r\n{}";
        sl[2] = strlen(q); memcpy(seeds[2], q, sl[2]);
    }
    memcpy(seeds[4], c, sl[3]);
    sl[4] = sl[3] + client_hello(seeds[4] + sl[3], "api.example.com", 1, NULL, 0, 50);
    uint8_t ech[] = { 0xfe, 0x0d, 0, 1, 0 };
    sl[5] = client_hello(seeds[5], "x.example.com", 1, ech, sizeof ech, 0);
    static uint8_t buf[PP_IN_MAX + 4096];
    unsigned long ok = 0, refused = 0, more = 0, reqs_ok = 0;
    for (unsigned long it = 0; it < iters; it++) {
        int s = (int)(rnd() % 6);
        size_t n = sl[s];
        memcpy(buf, seeds[s], n);
        int muts = 1 + (int)(rnd() % 8);
        for (int m = 0; m < muts; m++) {
            uint32_t op = rnd() % 6, at = n ? rnd() % (uint32_t)n : 0;
            if (op == 0 && n) buf[at] ^= (uint8_t)(1u << (rnd() % 8));
            else if (op == 1 && n) buf[at] = (uint8_t)rnd();
            else if (op == 2 && n < sizeof buf - 64) {                  /* insert */
                size_t k = 1 + rnd() % 32;
                memmove(buf + at + k, buf + at, n - at);
                for (size_t j = 0; j < k; j++) buf[at + j] = (uint8_t)rnd();
                n += k;
            } else if (op == 3 && n > 1) {                              /* delete */
                size_t k = 1 + rnd() % (n - at < 32 ? n - at : 32);
                if (at + k > n) k = n - at;
                memmove(buf + at, buf + at + k, n - at - k);
                n -= k;
            } else if (op == 4 && n) {                                  /* interesting values */
                static const uint8_t v[] = { 0, 1, 0x7f, 0x80, 0xff, 0xfe, '\r', '\n', ':', '.', ' ', 22 };
                buf[at] = v[rnd() % sizeof v];
            } else if (op == 5 && n > 4) {                              /* a length field */
                buf[at] = 0xff; if (at + 1 < n) buf[at + 1] = (uint8_t)rnd();
            }
        }
        unsigned dport = rnd() % 2 ? 443 : 1 + rnd() % 65535;
        for (int acked = 0; acked < 2; acked++) {
            size_t cut = rnd() % 4 == 0 ? rnd() % (n + 1) : n;
            pp_result_t r;
            pp_status_t st = pp_parse(buf, cut, dport, acked, &r);
            invariants(buf, cut, dport, acked, st, &r);
            {                                            /* v1.26 review: chunked bodies */
                pp_chunked_t ck;
                memset(&ck, 0, sizeof ck);
                bool cdone;
                long cg = pp_chunked_feed(&ck, buf, cut, &cdone);
                if (cg > (long)cut || cg < -1) abort();
                if (st == PP_OK && r.kind == PP_KIND_HTTP && (r.head_len == 0 || r.head_len > cut)) abort();
            }
            {                                            /* v1.26.1: a request inside TLS */
                pp_req_t q;
                pp_status_t qs = pp_request(buf, cut, "https", "api.example.com", 443, &q);
                req_invariants(buf, cut, qs, &q);
                if (qs == PP_OK) reqs_ok++;
            }
            unsigned us; size_t ul; const char *uw;        /* section 5: the upstream's reply */
            pp_status_t ust = pp_upstream_reply(buf, cut, &us, &ul, &uw);
            if ((ust == PP_OK && (us < 200 || us > 299 || ul == 0 || ul > cut)) || (ust == PP_REFUSE && !uw)) abort();
            if (st == PP_OK || st == PP_ACK) ok++;
            else if (st == PP_REFUSE) refused++;
            else more++;
        }
    }
    printf("proxy_parse fuzz: %lu inputs (seed %lu): %lu read, %lu refused, %lu asked for more; %lu requests "
           "read as inside TLS; no fault\n", iters * 2, seed, ok, refused, more, reqs_ok);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "unit")) return unit();
    if (argc >= 4 && !strcmp(argv[1], "file"))
        return file_mode(argv[2], (unsigned)strtoul(argv[3], NULL, 10), argc > 4 && !strcmp(argv[4], "acked"));
    if (argc == 4 && !strcmp(argv[1], "fuzz"))
        return fuzz(strtoul(argv[2], NULL, 10), strtoul(argv[3], NULL, 10));
    fprintf(stderr, "usage: %s unit | file PATH DPORT [acked] | fuzz N SEED\n", argv[0]);
    return 2;
}

#endif
