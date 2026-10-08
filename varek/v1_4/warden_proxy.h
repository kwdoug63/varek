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

#ifndef VAREK_WARDEN_PROXY_H
#define VAREK_WARDEN_PROXY_H

#include <stdint.h>
#include <sys/types.h>

/* Control messages (SOCK_SEQPACKET, one per datagram). */
enum { WP_MSG_READY = 1 };

struct wp_msg {
    uint32_t type;
    uint32_t port;               /* WP_MSG_READY: the listener's port */
};

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

/* The helper's own entry point, after it has dropped its privileges: serve
 * on the control socket fd until it closes. Returns the exit status. */
int wp_helper_main(int ctl);

#endif /* VAREK_WARDEN_PROXY_H */
