// SPDX-License-Identifier: MIT
// v1210_probe.c — the agent side of test_v1210.sh (decided connections).
//
// Runs under the Warden with tests/v1210_policy.txt, against the servers
// tests/v1210_servers.py starts. Prints one line per case:
//   PROBE <case> OK ...        the outcome the Warden promises
//   PROBE <case> FAIL ...      a wrong outcome (a functional bug)
//   PROBE <case> BYPASSED ...  a destination the policy denies was reached
//   PROBE <case> SKIP ...      not runnable on this host (no IPv6)
// and "PROBE done" at the end. Built static.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/netlink.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define P_ALLOW  18181     /* TCP echo, allowed */
#define P_DENY   18182     /* TCP echo, denied: greets with "D" */
#define P_UDP    18183     /* UDP echo, allowed */
#define P_SLOW   18184     /* TCP listener with a full backlog, allowed */
#define P_CLOSED 18185     /* nothing listens, allowed */
#define P_RACE   18186     /* TCP, allowed: greets with "A" */
#define SOCKDIR  "/tmp/varek_v1210/sock"

static int fails = 0, bypasses = 0;
static void ok(const char *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void ok(const char *c, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf("PROBE %-22s OK ", c); vprintf(fmt, ap); printf("\n"); va_end(ap);
}
static void bad(const char *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void bad(const char *c, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf("PROBE %-22s FAIL ", c); vprintf(fmt, ap); printf("\n"); va_end(ap);
    fails++;
}
static void bypass(const char *c, const char *what) {
    printf("PROBE %-22s BYPASSED %s\n", c, what);
    bypasses++;
}

static struct sockaddr_in in4(uint16_t port) {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}
static struct sockaddr_un un_path(const char *p, socklen_t *len) {
    struct sockaddr_un u = { .sun_family = AF_UNIX };
    snprintf(u.sun_path, sizeof u.sun_path, "%s", p);
    *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(u.sun_path) + 1);
    return u;
}

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

/* Send "ping" and expect it back (with a 2 s receive timeout). */
static bool echo(int s) {
    struct timeval tv = { 2, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (send(s, "ping", 4, MSG_NOSIGNAL) != 4) return false;
    char b[16];
    ssize_t n = recv(s, b, sizeof b, 0);
    return n == 4 && !memcmp(b, "ping", 4);
}

static int connect_errno(int s, const void *sa, socklen_t l) {
    return connect(s, sa, l) == 0 ? 0 : errno;
}

/* ---- TCP ---- */

static void tcp_basic(void) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int s2 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = in4(P_ALLOW);
    int e = connect_errno(s, &a, sizeof a);
    if (e) { bad("tcp4_blocking", "connect: %s", strerror(e)); return; }
    struct sockaddr_in peer;
    socklen_t pl = sizeof peer;
    if (getpeername(s, (void *)&peer, &pl) || ntohs(peer.sin_port) != P_ALLOW) bad("tcp4_blocking", "wrong peer");
    else if (!echo(s)) bad("tcp4_blocking", "no echo");
    else ok("tcp4_blocking", "connected, same descriptor %d, echo", s);
    int fdf = fcntl(s, F_GETFD), fl = fcntl(s, F_GETFL);
    if (!(fdf & FD_CLOEXEC)) bad("tcp4_cloexec_kept", "FD_CLOEXEC lost");
    else ok("tcp4_cloexec_kept", "FD_CLOEXEC still set");
    if (fl & O_NONBLOCK) bad("tcp4_blocking_kept", "became non-blocking");
    else ok("tcp4_blocking_kept", "still blocking");
    e = connect_errno(s2, &a, sizeof a);
    if (e || (fcntl(s2, F_GETFD) & FD_CLOEXEC)) bad("tcp4_no_cloexec_kept", "e=%d cloexec appeared", e);
    else ok("tcp4_no_cloexec_kept", "FD_CLOEXEC still clear");
    e = connect_errno(s, &a, sizeof a);
    if (e != EISCONN) bad("tcp4_connect_again", "second connect: %s (want EISCONN)", strerror(e));
    else ok("tcp4_connect_again", "EISCONN");
    /* listen and bind stay refused, even on a socket in the host's namespace */
    if (listen(s, 1) == 0) bypass("tcp4_listen_refused", "listen succeeded on a handed-over socket");
    else ok("tcp4_listen_refused", "%s", strerror(errno));
    struct sockaddr_in any = in4(0);
    if (bind(s2, (void *)&any, sizeof any) == 0) bypass("tcp4_bind_refused", "bind succeeded");
    else ok("tcp4_bind_refused", "%s", strerror(errno));
    close(s); close(s2);
}

/* Options set before connect must be on the socket afterwards. */
static void tcp_options(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct { int level, name; int v; const char *n; } io[] = {
        { IPPROTO_TCP, TCP_NODELAY, 1, "TCP_NODELAY" },
        { SOL_SOCKET, SO_KEEPALIVE, 1, "SO_KEEPALIVE" },
        { IPPROTO_TCP, TCP_KEEPIDLE, 77, "TCP_KEEPIDLE" },
        { IPPROTO_TCP, TCP_KEEPINTVL, 13, "TCP_KEEPINTVL" },
        { IPPROTO_TCP, TCP_KEEPCNT, 4, "TCP_KEEPCNT" },
        { IPPROTO_TCP, TCP_USER_TIMEOUT, 4321, "TCP_USER_TIMEOUT" },
        { SOL_SOCKET, SO_RCVBUF, 65536, "SO_RCVBUF" },
        { IPPROTO_IP, IP_TOS, 0x10, "IP_TOS" },
    };
    int before[16];
    for (size_t i = 0; i < sizeof io / sizeof io[0]; i++) {
        setsockopt(s, io[i].level, io[i].name, &io[i].v, sizeof(int));
        socklen_t l = sizeof(int);
        getsockopt(s, io[i].level, io[i].name, &before[i], &l);
    }
    /* Timeouts are kept in jiffies, so 2.25 s may read back as 2.252 s:
     * compare with what the kernel reported before the connect. */
    struct timeval rto = { 1, 500000 }, sto = { 2, 250000 }, g, rb, sb;
    struct linger lg = { 1, 3 }, lg2;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof rto);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof sto);
    setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    socklen_t tl = sizeof rb;
    getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rb, &tl);
    tl = sizeof sb;
    getsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &sb, &tl);
    (void)one;
    struct sockaddr_in a = in4(P_ALLOW);
    int e = connect_errno(s, &a, sizeof a);
    if (e) { bad("tcp4_options_carried", "connect: %s", strerror(e)); return; }
    char lost[256] = "";
    for (size_t i = 0; i < sizeof io / sizeof io[0]; i++) {
        int v = 0;
        socklen_t l = sizeof v;
        getsockopt(s, io[i].level, io[i].name, &v, &l);
        if (v != before[i]) snprintf(lost + strlen(lost), sizeof lost - strlen(lost), " %s(%d!=%d)", io[i].n, v, before[i]);
    }
    socklen_t l = sizeof g;
    getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &g, &l);
    if (g.tv_sec != rb.tv_sec || g.tv_usec != rb.tv_usec) strcat(lost, " SO_RCVTIMEO");
    l = sizeof g;
    getsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &g, &l);
    if (g.tv_sec != sb.tv_sec || g.tv_usec != sb.tv_usec || sb.tv_sec != 2) strcat(lost, " SO_SNDTIMEO");
    l = sizeof lg2;
    getsockopt(s, SOL_SOCKET, SO_LINGER, &lg2, &l);
    if (lg2.l_onoff != 1 || lg2.l_linger != 3) strcat(lost, " SO_LINGER");
    if (lost[0]) bad("tcp4_options_carried", "lost:%s", lost);
    else if (!echo(s)) bad("tcp4_options_carried", "no echo");
    else ok("tcp4_options_carried", "11 options as set before connect");
    close(s);
}

static void tcp_nonblock(void) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in a = in4(P_ALLOW);
    int e = connect_errno(s, &a, sizeof a);
    if (e && e != EINPROGRESS) { bad("tcp4_nonblocking", "connect: %s", strerror(e)); return; }
    struct pollfd pf = { s, POLLOUT, 0 };
    int so = -1;
    socklen_t l = sizeof so;
    if (poll(&pf, 1, 2000) != 1 || getsockopt(s, SOL_SOCKET, SO_ERROR, &so, &l) || so) {
        bad("tcp4_nonblocking", "not writable or SO_ERROR %d", so); return;
    }
    if (!(fcntl(s, F_GETFL) & O_NONBLOCK)) { bad("tcp4_nonblocking", "O_NONBLOCK lost"); return; }
    int fl = fcntl(s, F_GETFL);
    fcntl(s, F_SETFL, fl & ~O_NONBLOCK);
    if (!echo(s)) { bad("tcp4_nonblocking", "no echo"); return; }
    ok("tcp4_nonblocking", "connect said %s; poll, SO_ERROR 0, O_NONBLOCK kept, echo",
       e ? "EINPROGRESS" : "0");
    close(s);
}

static void tcp_denied(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = in4(P_DENY);
    int e = connect_errno(s, &a, sizeof a);
    if (e == 0) bypass("tcp4_denied", "a denied destination was connected");
    else if (e != EACCES) bad("tcp4_denied", "%s (want EACCES)", strerror(e));
    else ok("tcp4_denied", "EACCES");
    close(s);
    s = socket(AF_INET, SOCK_STREAM, 0);
    a = in4(P_CLOSED);
    e = connect_errno(s, &a, sizeof a);
    if (e != ECONNREFUSED) bad("tcp4_allowed_refused", "%s (want ECONNREFUSED)", strerror(e));
    else ok("tcp4_allowed_refused", "allowed but nothing listens: ECONNREFUSED");
    close(s);
}

/* IPv6 destinations: decided on their canonical text whatever this host can
 * dial. An IPv4 socket with an IPv6 address is decided, then the dial gets the
 * kernel's own answer (EAFNOSUPPORT) when allowed, EACCES when not. */
static void ipv6_decisions(void) {
    struct sockaddr_in6 m = { .sin6_family = AF_INET6, .sin6_port = htons(P_DENY) };
    inet_pton(AF_INET6, "::ffff:127.0.0.1", &m.sin6_addr);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int e = connect_errno(s, &m, sizeof m);
    if (e != EACCES) bad("mapped_denied", "%s (want EACCES: decided as 127.0.0.1:%d)", strerror(e), P_DENY);
    else ok("mapped_denied", "an IPv4-mapped address is decided as its IPv4 form");
    close(s);
    m.sin6_port = htons(P_ALLOW);
    s = socket(AF_INET, SOCK_STREAM, 0);
    e = connect_errno(s, &m, sizeof m);
    if (e == EACCES) bad("mapped_allowed", "EACCES: not decided as 127.0.0.1:%d", P_ALLOW);
    else ok("mapped_allowed", "allowed, dial said %s", e ? strerror(e) : "0");
    close(s);
    struct sockaddr_in6 d = { .sin6_family = AF_INET6, .sin6_port = htons(443) };
    inet_pton(AF_INET6, "2001:db8::1", &d.sin6_addr);
    s = socket(AF_INET, SOCK_STREAM, 0);
    e = connect_errno(s, &d, sizeof d);
    if (e == EACCES) bad("v6_allowed_decided", "EACCES for an allowed [2001:db8::1]:443");
    else ok("v6_allowed_decided", "allowed, dial said %s", e ? strerror(e) : "0");
    close(s);
    inet_pton(AF_INET6, "2001:db8::2", &d.sin6_addr);
    s = socket(AF_INET, SOCK_STREAM, 0);
    e = connect_errno(s, &d, sizeof d);
    if (e != EACCES) bad("v6_denied", "%s (want EACCES)", strerror(e));
    else ok("v6_denied", "EACCES");
    close(s);
    struct sockaddr_in6 sc = { .sin6_family = AF_INET6, .sin6_port = htons(443), .sin6_scope_id = 1 };
    inet_pton(AF_INET6, "2001:db8::1", &sc.sin6_addr);
    s = socket(AF_INET, SOCK_STREAM, 0);
    e = connect_errno(s, &sc, sizeof sc);
    if (e != EACCES) bad("v6_scope_refused", "%s (want EACCES)", strerror(e));
    else ok("v6_scope_refused", "a scope id is refused whatever the policy says");
    close(s);
    /* Live IPv6, where the host has it. */
    s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s < 0) { printf("PROBE %-22s SKIP no IPv6 on this host (%s)\n", "tcp6_live", strerror(errno)); return; }
    struct sockaddr_in6 l6 = { .sin6_family = AF_INET6, .sin6_port = htons(P_ALLOW), .sin6_addr = IN6ADDR_LOOPBACK_INIT };
    e = connect_errno(s, &l6, sizeof l6);
    if (e || !echo(s)) bad("tcp6_live", "connect %s", strerror(e));
    else ok("tcp6_live", "[::1] echo");
    close(s);
}

/* ---- UDP and relayed sends ---- */

static void udp(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = in4(P_UDP);
    int e = connect_errno(s, &a, sizeof a);
    if (e) { bad("udp4_connected", "connect: %s", strerror(e)); return; }
    struct timeval tv = { 2, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char b[64];
    if (send(s, "u1", 2, 0) != 2 || recv(s, b, sizeof b, 0) != 2) bad("udp4_send", "send/recv");
    else ok("udp4_send", "send() admitted by the filter, echo");
    struct iovec iv[2] = { { "u", 1 }, { "2", 1 } };
    struct msghdr mh = { .msg_iov = iv, .msg_iovlen = 2 };
    ssize_t n = sendmsg(s, &mh, 0);
    if (n != 2 || recv(s, b, sizeof b, 0) != 2 || memcmp(b, "u2", 2)) bad("udp4_sendmsg_relayed", "n=%zd %s", n, strerror(errno));
    else ok("udp4_sendmsg_relayed", "the Warden sent it, echo");
    struct mmsghdr mm[2];
    memset(mm, 0, sizeof mm);
    struct iovec m0 = { "m0", 2 }, m1 = { "m11", 3 };
    mm[0].msg_hdr.msg_iov = &m0; mm[0].msg_hdr.msg_iovlen = 1;
    mm[1].msg_hdr.msg_iov = &m1; mm[1].msg_hdr.msg_iovlen = 1;
    int r = sendmmsg(s, mm, 2, 0);
    ssize_t r0 = recv(s, b, sizeof b, 0), r1 = recv(s, b, sizeof b, 0);
    if (r != 2 || mm[0].msg_len != 2 || mm[1].msg_len != 3 || r0 != 2 || r1 != 3)
        bad("udp4_sendmmsg_relayed", "r=%d lens %u %u recv %zd %zd", r, mm[0].msg_len, mm[1].msg_len, r0, r1);
    else ok("udp4_sendmmsg_relayed", "2 messages, msg_len written back, echo");
    /* A send naming a destination is refused, even the connected peer's. */
    n = sendto(s, "x", 1, 0, (void *)&a, sizeof a);
    if (n == 1) bypass("udp4_sendto_dest", "sendto with a destination went out");
    else if (errno != EACCES) bad("udp4_sendto_dest", "%s", strerror(errno));
    else ok("udp4_sendto_dest", "EACCES");
    mh.msg_name = &a; mh.msg_namelen = sizeof a;
    n = sendmsg(s, &mh, 0);
    if (n >= 0) bypass("udp4_sendmsg_name", "sendmsg with msg_name went out");
    else if (errno != EACCES) bad("udp4_sendmsg_name", "%s", strerror(errno));
    else ok("udp4_sendmsg_name", "EACCES");
    char cb[CMSG_SPACE(sizeof(int))];
    memset(cb, 0, sizeof cb);
    struct msghdr mc = { .msg_iov = iv, .msg_iovlen = 1, .msg_control = cb, .msg_controllen = sizeof cb };
    struct cmsghdr *c = CMSG_FIRSTHDR(&mc);
    c->cmsg_level = IPPROTO_IP; c->cmsg_type = IP_TOS; c->cmsg_len = CMSG_LEN(sizeof(int));
    n = sendmsg(s, &mc, 0);
    if (n >= 0) bad("udp4_sendmsg_control", "control data relayed");
    else if (errno != EACCES) bad("udp4_sendmsg_control", "%s", strerror(errno));
    else ok("udp4_sendmsg_control", "EACCES");
    close(s);
    /* libuv binds a UDP socket to the wildcard address, port 0, before it
     * connects: that one bind is performed by the Warden (v1.21). */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in any = { .sin_family = AF_INET };
    if (bind(s, (void *)&any, sizeof any)) bad("udp4_wildcard_bind", "bind 0.0.0.0:0: %s", strerror(errno));
    else if (connect_errno(s, &a, sizeof a) || send(s, "w", 1, 0) != 1 || recv(s, b, sizeof b, 0) != 1)
        bad("udp4_wildcard_bind", "connect or echo after the bind: %s", strerror(errno));
    else ok("udp4_wildcard_bind", "bound by the Warden, then connected, echo");
    close(s);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in port = { .sin_family = AF_INET, .sin_port = htons(18199) };
    if (bind(s, (void *)&port, sizeof port) == 0) bypass("udp4_bind_port_refused", "bound a chosen port");
    else ok("udp4_bind_port_refused", "%s", strerror(errno));
    close(s);
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    n = sendto(u, "x", 1, 0, (void *)&a, sizeof a);
    if (n == 1) bypass("udp4_unconnected_sendto", "a datagram went out without connect");
    else ok("udp4_unconnected_sendto", "%s", strerror(errno));
    close(u);
}

static void fastopen_and_routing(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    ssize_t n = sendto(s, "x", 1, MSG_FASTOPEN, NULL, 0);
    if (n >= 0) bypass("tcp_fastopen_refused", "MSG_FASTOPEN send went out");
    else if (errno != EACCES) bad("tcp_fastopen_refused", "%s (want EACCES)", strerror(errno));
    else ok("tcp_fastopen_refused", "EACCES");
    struct sockaddr_in a = in4(P_ALLOW);
    connect(s, (void *)&a, sizeof a);
    unsigned char lsrr[8] = { 0x83, 7, 4, 127, 0, 0, 2, 0 };
    if (setsockopt(s, IPPROTO_IP, IP_OPTIONS, lsrr, 8) == 0) bypass("ip_source_route", "IP_OPTIONS accepted");
    else if (errno != EACCES) bad("ip_source_route", "%s", strerror(errno));
    else ok("ip_source_route", "IP_OPTIONS refused (EACCES)");
    int one = 1;
    if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one)) bad("setsockopt_ordinary", "%s", strerror(errno));
    else ok("setsockopt_ordinary", "TCP_NODELAY after connect");
    n = send(s, "x", 1, MSG_FASTOPEN);
    if (n >= 0) bad("tcp_fastopen_connected", "MSG_FASTOPEN admitted");
    else ok("tcp_fastopen_connected", "%s", strerror(errno));
    close(s);
}

/* ---- Unix ---- */

static void unix_cases(void) {
    socklen_t l;
    struct sockaddr_un u = un_path(SOCKDIR "/s.sock", &l);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    int e = connect_errno(s, &u, l);
    if (e || !echo(s)) bad("unix_stream", "%s", strerror(e));
    else ok("unix_stream", "echo");
    if (e == 0) {
        struct iovec iv = { "x", 1 };
        struct msghdr mh = { .msg_iov = &iv, .msg_iovlen = 1 };
        if (sendmsg(s, &mh, 0) >= 0 || errno != EACCES) bad("unix_sendmsg_refused", "%s", strerror(errno));
        else ok("unix_sendmsg_refused", "EACCES (write and send work)");
    }
    close(s);
    u = un_path(SOCKDIR "/d.sock", &l);
    s = socket(AF_UNIX, SOCK_DGRAM, 0);
    e = connect_errno(s, &u, l);
    if (e || send(s, "dgram", 5, 0) != 5) bad("unix_dgram", "%s", strerror(e ? e : errno));
    else ok("unix_dgram", "connected, 5 bytes sent");
    close(s);
    u = un_path(SOCKDIR "/q.sock", &l);
    s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    e = connect_errno(s, &u, l);
    if (e || !echo(s)) bad("unix_seqpacket", "%s", strerror(e));
    else ok("unix_seqpacket", "echo");
    close(s);
    u = un_path(SOCKDIR "/link-ok.sock", &l);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    e = connect_errno(s, &u, l);
    if (e || !echo(s)) bad("unix_symlink_to_allowed", "%s", strerror(e));
    else ok("unix_symlink_to_allowed", "decided on s.sock, echo");
    close(s);
    const char *deny[] = { SOCKDIR "/other.sock", SOCKDIR "/link-bad.sock", SOCKDIR "/root.sock", SOCKDIR "/missing.sock" };
    const char *name[] = { "unix_denied", "unix_symlink_to_denied", "unix_agent_permissions", "unix_missing" };
    for (int i = 0; i < 4; i++) {
        u = un_path(deny[i], &l);
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        e = connect_errno(s, &u, l);
        if (e == 0) bypass(name[i], deny[i]);
        else if (e != EACCES) bad(name[i], "%s (want EACCES)", strerror(e));
        else ok(name[i], "EACCES");
        close(s);
    }
    struct sockaddr_un ab = { .sun_family = AF_UNIX };
    memcpy(ab.sun_path, "\0varek_v1210_abs", 16);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    e = connect_errno(s, &ab, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 16));
    if (e == 0) bypass("unix_abstract", "reached the host's abstract socket");
    else if (e != EACCES) bad("unix_abstract", "%s", strerror(e));
    else ok("unix_abstract", "EACCES");
    close(s);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    e = connect_errno(s, &ab, sizeof(sa_family_t));
    if (e == 0) bypass("unix_unnamed", "connected");
    else ok("unix_unnamed", "%s", strerror(e));
    close(s);
}

/* ---- malformed and odd calls ---- */

static void odd(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_storage big;
    memset(&big, 0, sizeof big);
    int e = connect_errno(s, &big, 200);
    if (e != EINVAL) bad("addrlen_too_big", "%s (want EINVAL)", strerror(e));
    else ok("addrlen_too_big", "EINVAL");
    struct sockaddr_in a = in4(P_ALLOW);
    e = connect_errno(s, &a, 8);
    if (e != EINVAL) bad("addrlen_short", "%s (want EINVAL)", strerror(e));
    else ok("addrlen_short", "EINVAL");
    struct sockaddr un = { .sa_family = AF_UNSPEC };
    e = connect_errno(s, &un, sizeof un);
    if (e != EACCES) bad("af_unspec", "%s (want EACCES)", strerror(e));
    else ok("af_unspec", "EACCES");
    close(s);
    int p[2];
    if (pipe(p) == 0) {
        e = connect_errno(p[0], &a, sizeof a);
        if (e != ENOTSOCK) bad("not_a_socket", "%s (want ENOTSOCK)", strerror(e));
        else ok("not_a_socket", "ENOTSOCK");
        close(p[0]); close(p[1]);
    }
    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl >= 0) {
        struct sockaddr_nl sn = { .nl_family = AF_NETLINK };
        e = connect_errno(nl, &sn, sizeof sn);
        if (e != EACCES) bad("family_refused", "netlink: %s (want EACCES)", strerror(e));
        else ok("family_refused", "netlink EACCES");
        close(nl);
    }
    /* A descriptor duplicated before connect keeps the agent's own,
     * unconnected socket: the Warden replaces the descriptor that connected. */
    s = socket(AF_INET, SOCK_STREAM, 0);
    int d = dup(s);
    if (connect(s, (void *)&a, sizeof a) == 0) {
        struct sockaddr_in pr;
        socklen_t pl = sizeof pr;
        if (getpeername(d, (void *)&pr, &pl) == 0) ok("dup_before_connect", "the duplicate is connected too");
        else ok("dup_before_connect", "the duplicate stays unconnected (%s): a known difference", strerror(errno));
    } else bad("dup_before_connect", "connect %s", strerror(errno));
    close(s); close(d);
}

/* ---- the race: a second thread swaps the destination during connect ---- */

static struct sockaddr_in g_race;
static atomic_int g_race_stop;
static void *swapper(void *x) {
    (void)x;
    while (!atomic_load(&g_race_stop)) {
        g_race.sin_port = htons(P_DENY);
        __asm__ volatile("" ::: "memory");
        g_race.sin_port = htons(P_RACE);
        __asm__ volatile("" ::: "memory");
    }
    return NULL;
}

static void race(int iters) {
    g_race = in4(P_RACE);
    pthread_t t;
    if (pthread_create(&t, NULL, swapper, NULL)) { bad("toctou_race", "no thread: %s", strerror(errno)); return; }
    int allowed = 0, denied = 0, escapes = 0, other = 0;
    for (int i = 0; i < iters; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (void *)&g_race, sizeof g_race) == 0) {
            struct timeval tv = { 2, 0 };
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            char g = 0;
            struct sockaddr_in pr;
            socklen_t pl = sizeof pr;
            /* Judged twice: by the peer the socket reached, and by which
             * server answered ('A' allowed, 'D' denied). */
            if (recv(s, &g, 1, 0) == 1 && g == 'D') escapes++;
            else if (getpeername(s, (void *)&pr, &pl) == 0 && ntohs(pr.sin_port) == P_DENY) escapes++;
            else if (g == 'A') allowed++;
            else other++;
        } else if (errno == EACCES) denied++;
        else other++;
        close(s);
    }
    atomic_store(&g_race_stop, 1);
    pthread_join(t, NULL);
    if (escapes) bypass("toctou_race", "a connect reached the denied port");
    if (!allowed || !denied) bad("toctou_race", "both outcomes should occur: %d allowed, %d refused", allowed, denied);
    else ok("toctou_race", "%d attempts: %d connected to the allowed port, %d refused, %d other, 0 escapes",
            iters, allowed, denied, other);
}

/* ---- a slow connect does not stall the Warden ---- */

struct slow_arg { double ms; int err; };
static void *slow_connect(void *x) {
    struct slow_arg *a = x;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = { 0, 400000 };
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in sa = in4(P_SLOW);
    double t0 = now_ms();
    a->err = connect_errno(s, &sa, sizeof sa);
    a->ms = now_ms() - t0;
    close(s);
    return NULL;
}

static void slow(void) {
    struct slow_arg a = { 0, 0 };
    pthread_t t;
    pthread_create(&t, NULL, slow_connect, &a);
    usleep(50000);                           /* the slow one is waiting in the Warden now */
    double worst = 0;
    int good = 0;
    for (int i = 0; i < 20; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = in4(P_ALLOW);
        double t0 = now_ms();
        if (connect(s, (void *)&sa, sizeof sa) == 0 && echo(s)) good++;
        double d = now_ms() - t0;
        if (d > worst) worst = d;
        close(s);
    }
    pthread_join(t, NULL);
    if (a.err != EINPROGRESS || a.ms < 350 || a.ms > 1500)
        bad("slow_connect_timeout", "%s after %.0f ms (want EINPROGRESS after ~400 ms, SO_SNDTIMEO)", strerror(a.err), a.ms);
    else ok("slow_connect_timeout", "EINPROGRESS after %.0f ms, as the kernel does at SO_SNDTIMEO", a.ms);
    if (good != 20 || worst > 150) bad("warden_not_stalled", "%d/20 connects, worst %.1f ms", good, worst);
    else ok("warden_not_stalled", "20 other connects while one waited, worst %.1f ms", worst);
}

/* ---- a connect still waiting in the Warden ---- */

struct slow_on { int fd; int err; };
static void *slow_connect_on(void *x) {
    struct slow_on *a = x;
    struct sockaddr_in sa = in4(P_SLOW);
    a->err = connect_errno(a->fd, &sa, sizeof sa);
    return NULL;
}

static void pending_semantics(void) {
    /* Another connect on the same socket while the first waits: EALREADY, as
     * the kernel says, and nothing is dialed. */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = { 0, 400000 };
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct slow_on a = { s, 0 };
    pthread_t t;
    pthread_create(&t, NULL, slow_connect_on, &a);
    usleep(80000);
    struct sockaddr_in okd = in4(P_ALLOW);
    int e = connect_errno(s, &okd, sizeof okd);
    pthread_join(t, NULL);
    if (e != EALREADY) bad("connect_while_pending", "%s (want EALREADY)", strerror(e));
    else if (a.err != EINPROGRESS) bad("connect_while_pending", "first connect: %s", strerror(a.err));
    else ok("connect_while_pending", "EALREADY; the first connect then timed out (EINPROGRESS)");
    close(s);
    /* The descriptor closed and reused while the connect waits: the Warden
     * answers the connect and leaves the new occupant of the number alone. */
    s = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    a.fd = s;
    a.err = 0;
    pthread_create(&t, NULL, slow_connect_on, &a);
    usleep(80000);
    int p[2];
    close(s);
    if (pipe(p)) { bad("descriptor_replaced", "pipe"); pthread_join(t, NULL); return; }
    if (p[0] != s) { dup2(p[0], s); close(p[0]); }
    pthread_join(t, NULL);
    struct stat st;
    if (fstat(s, &st) || !S_ISFIFO(st.st_mode)) bad("descriptor_replaced", "the reused descriptor was overwritten");
    else ok("descriptor_replaced", "the connect returned %s; the pipe now at that number was left alone",
            a.err ? strerror(a.err) : "0");
    close(s); close(p[1]);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    int iters = argc > 1 ? atoi(argv[1]) : 2000;
    tcp_basic();
    tcp_options();
    tcp_nonblock();
    tcp_denied();
    ipv6_decisions();
    udp();
    fastopen_and_routing();
    unix_cases();
    odd();
    slow();
    pending_semantics();
    race(iters);
    printf("PROBE done fails=%d bypasses=%d\n", fails, bypasses);
    return fails || bypasses;
}
