// SPDX-License-Identifier: MIT
// proxy_parse.h — v1.26: what the egress proxy reads from a client
// (docs/security/v1.26-egress-proxy.md, "Implementation plan", step 5).
//
// Bounded parsers for the first bytes a client sends on a connection the
// Warden handed to the proxy. They find the one thing the Warden decides on,
// a host name and a port, and refuse anything they cannot read exactly:
//
//   - a TLS ClientHello (handshake records reassembled, at most PP_TLS_MAX
//     bytes of handshake in at most PP_TLS_RECORDS records): the SNI host
//     name, on the port the client connected to. Refused: no SNI, more than
//     one name, a name that is not a host name (an IP literal, a trailing
//     dot), an encrypted_client_hello (or ESNI) extension, an extension
//     given twice, anything malformed;
//   - an HTTP/1.x request (request line and headers within PP_HTTP_MAX
//     bytes, CRLF only, no obs-fold): its one Host header, whose port (if
//     any) must be the one connected to; an absolute-form target must name
//     the same authority;
//   - a CONNECT host:port request (clients with HTTPS_PROXY): the proxy
//     answers 200 (PP_ACK), then the ClientHello that follows must carry
//     the same name in its SNI; the port is the CONNECT's.
//
// The parsers keep no state: each call is given every byte read so far and
// whether the CONNECT was answered, and says whether to read more. They
// allocate nothing and touch only the bytes given. Fuzzed under ASan and
// UBSan (tests/fuzz_proxy_parse.c).

#ifndef VAREK_PROXY_PARSE_H
#define VAREK_PROXY_PARSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PP_TLS_MAX      16384        /* handshake bytes of a ClientHello, reassembled */
#define PP_TLS_RECORDS  64           /* records it may be split over */
#define PP_HTTP_MAX     8192         /* request line and headers */
/* The most a client's first flight may take before it is read: CONNECT
 * headers, then a ClientHello in its records. */
#define PP_IN_MAX       (PP_HTTP_MAX + PP_TLS_MAX + 5 * PP_TLS_RECORDS)
#define PP_NAME_MAX     253

typedef enum {
    PP_MORE   = 0,                   /* read more, then call again */
    PP_OK     = 1,                   /* kind, name and port are set */
    PP_ACK    = 2,                   /* a CONNECT read: answer 200, then call again with acked */
    PP_REFUSE = -1,                  /* why is set */
} pp_status_t;

typedef enum { PP_KIND_NONE = 0, PP_KIND_TLS = 1, PP_KIND_HTTP = 2, PP_KIND_CONNECT = 3 } pp_kind_t;

typedef struct {
    pp_kind_t   kind;
    char        name[PP_NAME_MAX + 1];   /* lowercase, no trailing dot */
    unsigned    port;
    size_t      connect_len;         /* PP_ACK and after: the CONNECT request's length */
    const char *why;                 /* PP_REFUSE: a short reason (static text) */
    /* v1.26 review, HTTP: the request head's length and its body's framing,
     * so the proxy can check every request on a kept-alive connection */
    size_t      head_len;
    int         body;                /* PP_BODY_NONE, _LENGTH (body_len bytes) or _CHUNKED */
    uint64_t    body_len;
} pp_result_t;

enum { PP_BODY_NONE = 0, PP_BODY_LENGTH = 1, PP_BODY_CHUNKED = 2 };

/* v1.26 review: a chunked request body, read as it arrives. */
typedef struct {
    int      st;
    uint64_t left;                   /* data bytes left in this chunk */
    unsigned digits, line, lines;
} pp_chunked_t;

/* Read n bytes of a chunked body (c zeroed at its start). Returns how many
 * belong to the body (<= n; *done set when its last byte has been read), or
 * -1 if it is malformed (bare LF, a chunk size over 15 hex digits, a line
 * over 4 KB, more than 64 trailer lines). */
long pp_chunked_feed(pp_chunked_t *c, const uint8_t *in, size_t n, bool *done);

/* Parse the n bytes a client has sent (dport: the port it connected to;
 * acked: the proxy has answered its CONNECT). */
pp_status_t pp_parse(const uint8_t *in, size_t n, unsigned dport, bool acked, pp_result_t *r);

/* Section 5: the upstream proxy's reply to the proxy's CONNECT: a status
 * line "HTTP/1.x DDD ..." and headers, within PP_HTTP_MAX bytes, CRLF only.
 * PP_OK for a 2xx status (len: the reply's length; what follows it is the
 * server's), PP_REFUSE for any other (status set, or 0 if unreadable; why
 * set), PP_MORE to read more. */
pp_status_t pp_upstream_reply(const uint8_t *in, size_t n, unsigned *status, size_t *len, const char **why);

/* v1.26.1, step 5: one request of an inspected connection, after its TLS
 * is terminated (docs/security/v1.26.1-inspecting-mode.md, section 2). The
 * Warden decides its object,
 *     METHOD scheme://name:port/path?query
 * where scheme, name and port are the connection's (https, the SNI name,
 * the port connected to) and the method and target are the request's own
 * bytes. The head is read as for plain HTTP (CRLF only, within PP_HTTP_MAX,
 * one Host, the body framed by Content-Length or chunked, no upgrade).
 * Refused besides: a method that is not 1 to 20 letters A-Z, CONNECT, a Host
 * that is not the connection's name (and port, if it gives one), a target
 * neither origin-form (/...) nor absolute-form naming the connection's own
 * scheme and authority (then read as its path), and a target a server could
 * read as another path than the matcher does: a '.' or '..' segment, an
 * empty segment ('//'), '\', ';' or '#', a byte outside 0x21-0x7e, a bad
 * percent escape, or an escape of '/', '\' or an unreserved byte (A-Z a-z
 * 0-9 - . _ ~). An object over PP_OBJ_MAX bytes is refused, not cut. */
#define PP_OBJ_MAX     4095
#define PP_METHOD_MAX  20

typedef struct {
    char        method[PP_METHOD_MAX + 1];
    char        object[PP_OBJ_MAX + 1];
    size_t      object_len;
    size_t      head_len;            /* the request line and headers */
    int         body;                /* PP_BODY_NONE, _LENGTH (body_len bytes) or _CHUNKED */
    uint64_t    body_len;
    const char *why;                 /* PP_REFUSE */
} pp_req_t;

/* PP_OK (q set), PP_MORE, or PP_REFUSE (q->why). */
pp_status_t pp_request(const uint8_t *in, size_t n, const char *scheme, const char *name, unsigned port,
                       pp_req_t *q);

/* The kind's word in records ("tls", "http", "connect"). Inline (v1.26.1),
 * so the Warden, which does not link the parsers, has it too. */
static inline const char *pp_kind_name(pp_kind_t k) {
    switch (k) {
        case PP_KIND_TLS:     return "tls";
        case PP_KIND_HTTP:    return "http";
        case PP_KIND_CONNECT: return "connect";
        default:              return "none";
    }
}

#endif /* VAREK_PROXY_PARSE_H */
