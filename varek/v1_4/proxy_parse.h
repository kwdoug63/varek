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
} pp_result_t;

/* Parse the n bytes a client has sent (dport: the port it connected to;
 * acked: the proxy has answered its CONNECT). */
pp_status_t pp_parse(const uint8_t *in, size_t n, unsigned dport, bool acked, pp_result_t *r);

/* The kind's word in records ("tls", "http", "connect"). */
const char *pp_kind_name(pp_kind_t k);

#endif /* VAREK_PROXY_PARSE_H */
