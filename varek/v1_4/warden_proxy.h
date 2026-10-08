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
enum { WP_MSG_READY = 1, WP_MSG_CONN = 2, WP_MSG_REQUEST = 3, WP_MSG_UNREADABLE = 4, WP_MSG_VERDICT = 5 };

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

/* Warden -> proxy: the decision on a WP_MSG_REQUEST. Step 5: allow is always
 * 0, and the proxy refuses (a TLS handshake_failure alert, or an HTTP 403).
 * Step 6 sends the dialed socket with it. */
struct wp_verdict {
    uint32_t type;               /* WP_MSG_VERDICT */
    uint32_t allow;
    uint64_t id;
};

#define WP_READ_MS       10000   /* a whole request within this, or refused */
#define WP_VERDICT_MS    30000   /* the Warden's verdict within this, or refused */
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

/* Start the proxy as uid:gid (exe: the Warden's binary, run with
 * --proxy-helper). Waits up to 5 s for it to report its listener. 0, or -1
 * with errno set. */
int wp_start(wp_t *w, const char *exe, uid_t uid, gid_t gid);

/* Step 4: announce a hand-off (see struct wp_conn). Never blocks. 0, or -1
 * with errno set (the proxy is gone, or its control socket is full). */
int wp_announce(const wp_t *w, uint64_t id, unsigned from_port, pid_t tid, const char *dest);

/* Step 5: tell the proxy the verdict on connection id. Never blocks. 0 or -1. */
int wp_verdict(const wp_t *w, uint64_t id, bool allow);

/* The helper's own entry point, after it has dropped its privileges: serve
 * on the control socket fd until it closes. Returns the exit status. */
int wp_helper_main(int ctl);

#endif /* VAREK_WARDEN_PROXY_H */
