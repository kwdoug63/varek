// SPDX-License-Identifier: MIT
// warden_proxy.h — v1.26: the egress proxy process
// (docs/security/v1.26-egress-proxy.md, "Implementation plan", step 2).
//
// The proxy is a mode of the Warden's own binary (`--proxy-helper`). The
// Warden starts it before the agent is forked, as root; it drops at once to
// its own unprivileged user (`--proxy-as`, never the agent's), keeps no
// capabilities, sets no-new-privileges, and closes every descriptor but its
// control socket. It runs in the host's network namespace and listens on
// 127.0.0.1:<port>; the agent's own namespace is empty, so the agent reaches
// the listener only through a socket the Warden hands it. It exits when the
// control socket closes, that is, when the Warden goes.
//
// The proxy only parses and relays. Every decision, record and dial is the
// Warden's (step 6).
//
// Step 4, the hand-off: a connect on a proxied port that no numeric rule
// allows (or to a synthetic address) is not dialed. The Warden binds a socket
// of the agent's kind to 127.0.0.1, announces the connection (WP_MSG_CONN),
// connects it to the listener and hands it to the agent. The proxy holds an
// announced connection and closes any other.
//
// Step 5: the proxy reads what the client sends with the bounded parsers of
// proxy_parse.c (a ClientHello's SNI, an HTTP Host, a CONNECT), within 10 s,
// and reports only the connection id, the kind, the name and the port
// (WP_MSG_REQUEST), or why it could not read one (WP_MSG_UNREADABLE, and the
// client is refused). It then waits for the Warden's verdict.

#ifndef VAREK_WARDEN_PROXY_H
#define VAREK_WARDEN_PROXY_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Control messages (SOCK_SEQPACKET, one per datagram). */
enum { WP_MSG_READY = 1, WP_MSG_CONN = 2, WP_MSG_REQUEST = 3, WP_MSG_UNREADABLE = 4, WP_MSG_VERDICT = 5,
       WP_MSG_CLOSED = 6, WP_MSG_FLUSH = 7, WP_MSG_FLUSHED = 8, WP_MSG_VERDICT_UP = 9,
       /* v1.26.1, inspecting mode */
       WP_MSG_INSPECT = 10, WP_MSG_CA_NAME = 11, WP_MSG_CA_GO = 12, WP_MSG_BLOB = 13, WP_MSG_CA_DONE = 14,
       WP_MSG_HTTPREQ = 15, WP_MSG_REQVERDICT = 16, WP_MSG_HTTPBODY = 17 };

/* v1.26.1, step 6: each request of an inspected connection is decided
 * before a byte of it is sent. Proxy -> Warden: WP_MSG_HTTPREQ, the request's
 * object (pp_request) and its body's framing, seq 1, 2, ... on the
 * connection. Warden -> proxy: WP_MSG_REQVERDICT for it. Proxy -> Warden,
 * after an allowed request's body (if it has one): WP_MSG_HTTPBODY, its
 * length and SHA-256, or that it passed max_body (then the connection is
 * cut). After a refusal the connection sends no more requests. */
enum { WP_BODY_NONE = 0, WP_BODY_LENGTH = 1, WP_BODY_CHUNKED = 2 };
struct wp_httpreq {
    uint32_t type;               /* WP_MSG_HTTPREQ */
    uint32_t body;               /* WP_BODY_* */
    uint64_t id;
    uint64_t seq;
    uint64_t body_len;           /* WP_BODY_LENGTH: the Content-Length */
    char     object[4096];       /* "METHOD scheme://name:port/path?query", NUL-terminated */
};
struct wp_reqverdict {
    uint32_t type;               /* WP_MSG_REQVERDICT */
    uint32_t allow;
    uint64_t id;
    uint64_t seq;
    uint64_t max_body;           /* the allowing rule's max_body= (0: none) */
    char     why[96];            /* a refusal: why, for the client's 403 (NUL-terminated) */
};
struct wp_httpbody {
    uint32_t type;               /* WP_MSG_HTTPBODY */
    uint32_t exceeded;           /* the body passed max_body: the connection was cut */
    uint64_t id;
    uint64_t seq;
    uint64_t len;                /* bytes of the body as sent (a chunked body's framing included) */
    uint8_t  sha256[32];         /* of those bytes (exceeded: of those sent) */
};

struct wp_msg {                  /* proxy -> Warden: WP_MSG_READY */
    uint32_t type;
    uint32_t port;               /* the listener's port */
};

/* Warden -> proxy, step 4: a connection the Warden is about to make to the
 * listener from 127.0.0.1:from_port, for the agent's connect to dest. Sent
 * before the connect, so the proxy has it by the time it accepts. A
 * connection the Warden did not announce is closed at once. */
struct wp_conn {
    uint32_t type;               /* WP_MSG_CONN */
    uint32_t from_port;
    uint64_t id;                 /* the Warden's connection id (records: proxy_conn) */
    int32_t  tid;                /* the agent's thread */
    uint32_t pad;
    char     dest[64];           /* the agent's destination, as decided ("a.b.c.d:port") */
};

/* Proxy -> Warden, step 5: what a held connection asks for (WP_MSG_REQUEST:
 * kind, name, port), or why it could not be read (WP_MSG_UNREADABLE: kind,
 * why). Only these leave the proxy; never the bytes the client sent. */
struct wp_req {
    uint32_t type;
    uint32_t kind;               /* pp_kind_t */
    uint64_t id;
    uint32_t port;
    uint32_t pad;
    char     name[256];          /* NUL-terminated, a host name (the Warden checks it again) */
    char     why[96];            /* NUL-terminated */
};

/* Warden -> proxy: the decision on a WP_MSG_REQUEST. allow 1 carries the
 * socket the Warden dialed (SCM_RIGHTS): the proxy sends it what the client
 * sent and relays both ways. allow 0: the proxy refuses the client (a TLS
 * handshake_failure alert, or an HTTP 403). */
struct wp_verdict {
    uint32_t type;               /* WP_MSG_VERDICT */
    uint32_t allow;
    uint64_t id;
    uint32_t inspect;            /* v1.26.1: terminate TLS (inspecting mode, not a passthrough host) */
    uint32_t pad;
};

/* Proxy -> Warden, step 7: a relayed connection ended (section 5: or the
 * upstream proxy refused it, "upstream_refused"). The byte counts are
 * the proxy's own (it is not trusted to count them; they are recorded as its
 * report). why: "closed" (both sides closed), "reset" (an error on either
 * side), "idle", "run_end" (closed when the run ended, on WP_MSG_FLUSH); v1.26
 * review: "refused_request" (a later HTTP request for another host, or not
 * a request, refused), "client_gone" (allowed, but the client had gone
 * before relaying began: nothing relayed). */
struct wp_close {
    uint32_t type;               /* WP_MSG_CLOSED */
    uint32_t upstream_status;    /* section 5, why "upstream_refused": its status (0: no reply) */
    uint64_t id;
    uint64_t bytes_up;           /* client -> server */
    uint64_t bytes_down;         /* server -> client */
    uint64_t ms;                 /* how long it was relayed */
    char     why[24];            /* NUL-terminated */
    /* v1.26.1, an inspected connection: the server's certificate (SHA-256
     * of its DER; zero if none was presented), and for server_tls and
     * client_tls why the handshake failed (OpenSSL's words) */
    uint32_t inspected;
    uint8_t  server_cert[32];
    char     tls_why[96];        /* NUL-terminated */
};
/* Warden -> proxy, section 5: allow, with the socket the Warden dialed to
 * the upstream proxy (SCM_RIGHTS). The proxy asks it for name:port
 * (CONNECT), relays on a 2xx reply, and otherwise refuses the client and
 * reports the close as "upstream_refused" with the status. */
struct wp_verdict_up {
    uint32_t type;               /* WP_MSG_VERDICT_UP */
    uint32_t allow;
    uint64_t id;
    uint32_t port;
    uint32_t inspect;            /* v1.26.1: as in struct wp_verdict */
    char     name[256];          /* NUL-terminated */
};

/* v1.26.1, inspecting mode, before the agent starts. Warden -> proxy:
 * WP_MSG_INSPECT (the run id, the host's trust bundle, how many names
 * follow), that many WP_MSG_CA_NAME (the names the CA may sign for), then
 * WP_MSG_CA_GO (a struct wp_msg). Proxy -> Warden: the CA certificate (PEM)
 * and the PKCS#12 trust store, each as WP_MSG_BLOB chunks in order, then
 * WP_MSG_CA_DONE. Only once a run. */
struct wp_inspect {
    uint32_t type;               /* WP_MSG_INSPECT */
    uint32_t nnames;
    char     run_id[48];         /* NUL-terminated */
    char     bundle[1024];       /* the host's trust bundle, NUL-terminated */
};
struct wp_ca_name {
    uint32_t type;               /* WP_MSG_CA_NAME */
    uint32_t pad;
    char     name[256];          /* NUL-terminated host name */
};
enum { WP_BLOB_CA_PEM = 1, WP_BLOB_P12 = 2 };
#define WP_BLOB_CHUNK   16384
#define WP_BLOB_MAX     (8u << 20)
struct wp_blob {
    uint32_t type;               /* WP_MSG_BLOB */
    uint32_t kind;               /* WP_BLOB_* */
    uint32_t total, off, len;    /* the whole blob's length; this chunk's offset and length */
    uint32_t pad;
    uint8_t  data[WP_BLOB_CHUNK];
};
struct wp_ca_done {
    uint32_t type;               /* WP_MSG_CA_DONE */
    uint32_t ok;
    uint32_t secure_heap;        /* the CA key is in locked memory */
    uint32_t nroots;             /* certificates read from the host's bundle */
    char     why[160];           /* !ok: why, NUL-terminated */
};

/* Warden -> proxy, step 7: the run is ending: close every connection,
 * report each relayed one (WP_MSG_CLOSED), then answer WP_MSG_FLUSHED (a
 * struct wp_msg). */

#define WP_READ_MS       10000   /* a whole request within this, or refused */
#define WP_VERDICT_MS    60000   /* the Warden's verdict within this, or refused */
#define WP_MAX_ANNOUNCED 1024    /* announcements not yet accepted */
#define WP_ANNOUNCE_MS   10000   /* an announcement not accepted by then is dropped */
#define WP_MAX_HELD      1024    /* connections the proxy holds */

typedef struct {
    int      ctl;                /* the Warden's end of the control socket, -1: no proxy */
    pid_t    pid;                /* the proxy, as reported by it */
    unsigned port;               /* its listener on 127.0.0.1 */
    uid_t    uid;
    gid_t    gid;
} wp_t;

/* Start the proxy as uid:gid. exe_fd: the warden-proxy binary, as the sealed
 * in-memory copy the Warden hashed (v1.26.1: see wp_load). Waits up to 5 s
 * for it to report its listener. 0, or -1 with errno set. */
int wp_start(wp_t *w, int exe_fd, uid_t uid, gid_t gid);

/* v1.26.1: read the warden-proxy binary at path into a sealed memfd (so what
 * runs is exactly what was hashed, whatever happens to the file after), with
 * its SHA-256 in hex. The file must be a regular file that neither its group
 * nor others may write. Returns the memfd, or -1 with the reason in why. */
int wp_load(const char *path, char sha256_hex[65], char *why, size_t wn);

/* Step 4: announce a hand-off (see struct wp_conn). Never blocks. 0, or -1
 * with errno set (the proxy is gone, or its control socket is full). */
int wp_announce(const wp_t *w, uint64_t id, unsigned from_port, pid_t tid, const char *dest);

/* Step 5: tell the proxy the verdict on connection id. Never blocks. 0 or -1. */
int wp_verdict(const wp_t *w, uint64_t id, bool allow);
/* v1.26.1: why a close report may give for an inspected connection, beyond
 * the others: the server's certificate or handshake failed (server_tls), the
 * client's handshake failed (client_tls), a handshake took over WP_READ_MS
 * (tls_timeout), or a body passed its rule's max_body (max_body: cut). */

/* v1.26.1: inspecting mode's setup, before the agent starts (see struct
 * wp_inspect): send the run id, the trust bundle's path and the names, and
 * receive the CA certificate (PEM) and the PKCS#12 trust store (malloc'd).
 * Waits up to 15 s. 0, or -1 with why. */
int wp_inspect_setup(const wp_t *w, const char *run_id, const char *bundle, char *const *names,
                     size_t nnames, unsigned char **pem, size_t *pem_len, unsigned char **p12,
                     size_t *p12_len, int *secure_heap, int *nroots, char *why, size_t wn);

/* The helper's own entry point, after it has dropped its privileges: serve
 * on the control socket fd until it closes. Returns the exit status. */
int wp_helper_main(int ctl);

#endif /* VAREK_WARDEN_PROXY_H */
