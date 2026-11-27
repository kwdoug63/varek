/* SPDX-License-Identifier: MIT
 * warden_notify.h — v1.42 step 7 (docs/security/v1.42-step-up-defer.md):
 * the messages between the Warden and warden-notify, the helper that posts
 * each proposed grant of a `step_up ... notify=URL` rule to its webhook.
 *
 * The Warden links no TLS code (as for warden-proxy and warden-secrets), and
 * its supervision loop stops on any child's SIGCHLD, so the posts are made
 * by this helper: started at the start, before the agent, from a sealed
 * copy whose SHA-256 is in run_start, as its own unprivileged user with no
 * capabilities, not the Warden's child. Over a SOCK_SEQPACKET socket (its
 * fd 3) the Warden sends one wn_post per proposal (the URL and the JSON
 * body after the header, in the same message); the helper posts each from
 * a child of its own, so posts never wait on each other, retries a failed
 * one once after WN_RETRY_MS, and answers one wn_result each. The socket's
 * end (the Warden's exit) ends the helper, and its posts not yet answered
 * with it. A post notifies and nothing more: nothing the Warden decides
 * depends on its outcome.
 */
#ifndef WARDEN_NOTIFY_H
#define WARDEN_NOTIFY_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define WN_URL_MAX      512             /* as notify= (VDP_SU_NOTIFY_MAX) */
#define WN_BODY_MAX     32768
#define WN_MAX_INFLIGHT 32              /* posts the helper makes at once */
#define WN_TIMEOUT_MS   10000           /* each attempt's connect, TLS, send and answer */
#define WN_RETRY_MS     5000            /* the wait before the one retry */

enum { WN_MSG_POST = 0x4e540001u, WN_MSG_RESULT = 0x4e540002u };

struct wn_post {
    uint32_t type;                      /* WN_MSG_POST */
    char     id[17];                    /* the proposal's id */
    uint32_t url_len, body_len;         /* the URL, then the body, follow */
};

struct wn_result {
    uint32_t type;                      /* WN_MSG_RESULT */
    char     id[17];
    int32_t  sent;                      /* 1: a 2xx answer */
    int32_t  status;                    /* the last answer's HTTP status (0: none) */
    int32_t  attempts;                  /* 1 or 2 (0: not attempted) */
    char     why[200];                  /* why it failed: printable, NUL-terminated */
};

/* A notify= URL's parts: https:// (any host), or http:// to a literal
 * loopback address (127.0.0.0/8, [::1]). The host without brackets, the
 * port (443, 80 or the URL's), the path from its first '/' ('/' when it
 * has none; a query is kept). User information (an '@') is refused. 0, or
 * -1. */
struct wn_url { bool tls; char host[256]; char port[6]; char path[WN_URL_MAX + 2]; };

static inline bool wn_loopback(const char *h) {
    if (!strcmp(h, "::1")) return true;
    int parts = 0;
    const char *p = h;
    for (;;) {
        int v = 0, nd = 0;
        while (*p >= '0' && *p <= '9' && nd < 4) { v = v * 10 + (*p++ - '0'); nd++; }
        if (nd < 1 || nd > 3 || v > 255 || (parts == 0 && v != 127)) return false;
        parts++;
        if (!*p) break;
        if (*p++ != '.' || parts == 4) return false;
    }
    return parts == 4;
}

static inline int wn_url_parse(const char *s, struct wn_url *u) {
    memset(u, 0, sizeof *u);
    const char *p;
    if (!strncmp(s, "https://", 8)) { u->tls = true; p = s + 8; memcpy(u->port, "443", 4); }
    else if (!strncmp(s, "http://", 7)) { p = s + 7; memcpy(u->port, "80", 3); }
    else return -1;
    size_t hl = strcspn(p, "/?#");
    if (hl == 0 || hl >= sizeof u->host + 8) return -1;
    char hp[sizeof u->host + 8];
    memcpy(hp, p, hl);
    hp[hl] = '\0';
    if (strchr(hp, '@')) return -1;
    char *colon = hp[0] == '[' ? strstr(hp, "]:") : strrchr(hp, ':');
    if (colon) {
        if (hp[0] == '[') colon++;
        *colon = '\0';
        const char *pt = colon + 1;
        size_t pl = strlen(pt);
        if (pl < 1 || pl > 5 || strspn(pt, "0123456789") != pl) return -1;
        long v = 0;
        for (const char *q = pt; *q; q++) v = v * 10 + (*q - '0');
        if (v < 1 || v > 65535) return -1;
        memcpy(u->port, pt, pl + 1);
    }
    if (hp[0] == '[') {
        size_t n = strlen(hp);
        if (n < 3 || hp[n - 1] != ']') return -1;
        hp[n - 1] = '\0';
        memmove(hp, hp + 1, n - 1);
    }
    if (!hp[0] || strlen(hp) >= sizeof u->host) return -1;
    memcpy(u->host, hp, strlen(hp) + 1);
    const char *rest = p + hl;
    if (*rest == '#') rest = "";
    const char *hash = strchr(rest, '#');
    size_t rl = hash ? (size_t)(hash - rest) : strlen(rest);
    if (rl + 2 > sizeof u->path) return -1;
    size_t k = 0;
    if (rest[0] != '/') u->path[k++] = '/';
    memcpy(u->path + k, rest, rl);
    u->path[k + rl] = '\0';
    if (!u->tls && !wn_loopback(u->host)) return -1;
    return 0;
}

#endif
