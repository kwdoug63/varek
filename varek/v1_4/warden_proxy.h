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
// announced connection (until step 5 reads what the client sends, it only
// reads and discards) and closes any other.

#ifndef VAREK_WARDEN_PROXY_H
#define VAREK_WARDEN_PROXY_H

#include <stdint.h>
#include <sys/types.h>

/* Control messages (SOCK_SEQPACKET, one per datagram). */
enum { WP_MSG_READY = 1, WP_MSG_CONN = 2 };

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

/* The helper's own entry point, after it has dropped its privileges: serve
 * on the control socket fd until it closes. Returns the exit status. */
int wp_helper_main(int ctl);

#endif /* VAREK_WARDEN_PROXY_H */
