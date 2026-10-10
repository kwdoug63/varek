/* ---------------- v1.21: decided connections ----------------
 *
 * Included by warden.c (one translation unit, so these functions share its
 * statics: the policy decision, the certificate checker, the verdict stream).
 *
 * Through v1.20.0 every connect was refused, whatever the policy said
 * (deny_only_nonfile_v191): letting an allowed connect continue in the kernel
 * would have let a second thread change the destination between the Warden's
 * check and the kernel's read (the v1.4 defect). v1.21 acts on an ALLOW the
 * way files have been handled since v1.12:
 *
 *   1. derive_intent() copies the destination out of the agent's memory ONCE.
 *      (The socket's kind, its options and flags, and for a Unix connect the
 *      agent's uid and gid, are read from the live agent afterwards; none of
 *      them can change where the connection goes.)
 *   2. It is spelt canonically (net_decision_string: a.b.c.d:port,
 *      [IPv6]:port with an IPv4-mapped address as its IPv4 form, or
 *      unix:<canonical path> for a path socket resolved like a file open) and
 *      decided against the policy's host rules by the SMT decision procedure;
 *      the independent checker must accept the certificate of any ALLOW.
 *   3. The Warden, which runs in the host's network namespace, makes its own
 *      socket of the same kind, carries over the options the agent set on its
 *      socket, and connects it to the copy it decided on.
 *   4. SECCOMP_IOCTL_NOTIF_ADDFD with SECCOMP_ADDFD_FLAG_SETFD puts the
 *      connected socket in place of the agent's descriptor (same number, the
 *      agent's close-on-exec and non-blocking state), and the agent's connect
 *      returns what its own would have: 0, or EINPROGRESS for a non-blocking
 *      socket whose connection is still being made.
 *
 * The kernel never reads the agent's sockaddr, so the v1.4 race stays closed.
 * The agent's own network namespace stays empty: the only way out is a socket
 * the Warden made. The Warden is single-threaded, so a blocking connect is
 * finished asynchronously: the agent's thread waits in its connect while the
 * Warden keeps answering every other request, and is answered when the
 * Warden's socket connects, fails, or reaches the agent's SO_SNDTIMEO.
 *
 * Covered: TCP and UDP (connected) over IPv4 and IPv6, and Unix-domain stream,
 * datagram and seqpacket sockets named by a path. Refused whatever the policy
 * says: abstract and unnamed Unix addresses (they would name sockets in the
 * Warden's namespace, not the agent's), IPv6 scope ids (an interface index of
 * the agent's namespace means nothing in the host's), other address families
 * and socket kinds (raw, SCTP, MPTCP, vsock, ...), AF_UNSPEC "disconnects",
 * sends that carry their own destination, and inbound calls (listen and
 * accept stay outside the allowlist; bind is performed by the Warden only for
 * the wildcard address and port 0, see net_bind).
 *
 * Sends on a connected socket: sendto() with no destination is admitted by the
 * filter itself (its destination is a register, so the kernel reads nothing
 * from the agent's memory); sendmsg() and sendmmsg() carry their destination
 * inside a structure in the agent's memory, so the Warden reads the message
 * once and sends it itself, with no destination and no control data
 * (net_send_relay). */

#include <linux/sockios.h>

#define STUB_ADDR_TEXT "127.53.53.53"   /* v1.25: STUB_ADDR in warden_stub.inc.c */
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifndef SECCOMP_ADDFD_FLAG_SETFD
#define SECCOMP_ADDFD_FLAG_SETFD (1UL << 0)
#endif
#ifndef SIOCGSKNS
#define SIOCGSKNS 0x894C
#endif
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#ifndef SO_RCVTIMEO_OLD
#define SO_RCVTIMEO_OLD SO_RCVTIMEO
#define SO_SNDTIMEO_OLD SO_SNDTIMEO
#endif

static int      g_host_netns  = -1;     /* the Warden's own network namespace */
static int      g_agent_netns = -1;     /* the agent's (empty) one */
static bool     g_netns_separate = false;
static uint64_t g_report_seq = 0;       /* report_id sequence (was supervise()'s seq) */

/* v1.25: the stub resolver (warden_stub.inc.c, included after this file) */
struct sock_kind;
static bool stub_is_dest(const struct sockaddr_storage *dial);
/* v1.26: is port one the proxy takes? (`proxy ports`, else 80 and 443) */
static bool proxied_port(const struct policy *p, unsigned port) {
    if (!p->v.proxy_nports) return port == 80 || port == 443;
    for (size_t k = 0; k < p->v.proxy_nports; k++) if (p->v.proxy_ports[k] == port) return true;
    return false;
}

/* v1.26: is the address dialed (IPv4, or IPv4-mapped) a synthetic one? */
static bool dial_synthetic(int fam, const void *addr) {
    wr_ip_t ip;
    memset(&ip, 0, sizeof ip);
    if (fam == AF_INET6 && !IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)addr)) return false;
    ip.fam = 4;
    memcpy(ip.a, fam == AF_INET6 ? (const unsigned char *)addr + 12 : (const unsigned char *)addr, 4);
    return syn_is_addr(&ip);
}
static void stub_connect(int notify_fd, const struct seccomp_notif *req, struct action *a,
                         int ag, const struct sock_kind *k, const struct timespec *t0);

static uint64_t ns_between(const struct timespec *a, const struct timespec *b) {
    int64_t d = (int64_t)(b->tv_sec - a->tv_sec) * 1000000000LL + (b->tv_nsec - a->tv_nsec);
    return d < 0 ? 0 : (uint64_t)d;
}

static void net_record(pid_t pid, struct action *a, decision_t d_raw, decision_t d_final,
                       const char *rule, const struct timespec *t0, int kerr) {
    /* v1.26: a connect handed to the proxy is recorded as that */
    if (a->proxy_handoff && rule) {
        if (!strcmp(rule, "dialed_fd_injection")) rule = "proxy_handoff";
        else if (!strcmp(rule, "dialed_in_progress")) rule = "proxy_handoff_in_progress";
        else if (!strcmp(rule, "dial_failed")) rule = "proxy_handoff_failed";
    }
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    emit_pathology(g_report_seq++, pid, a, d_raw, d_final, rule, ns_between(t0, &t1), kerr);
}

/* ---- the agent's socket ---- */

struct sock_kind { int dom, type, proto; const char *name; };

/* 0 with k filled, or -errno (ENOTSOCK for a descriptor that is not a
 * socket). */
static int sock_kind_of(int fd, struct sock_kind *k) {
    socklen_t l = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &k->dom, &l) < 0) return -errno;
    l = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &k->type, &l) < 0) return -errno;
    l = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &k->proto, &l) < 0) return -errno;
    k->name = NULL;
    if (k->dom == AF_INET || k->dom == AF_INET6) {
        if (k->type == SOCK_STREAM && k->proto == IPPROTO_TCP) k->name = "tcp";
        else if (k->type == SOCK_DGRAM && k->proto == IPPROTO_UDP) k->name = "udp";
    } else if (k->dom == AF_UNIX) {
        if (k->type == SOCK_STREAM) k->name = "unix-stream";
        else if (k->type == SOCK_DGRAM) k->name = "unix-dgram";
        else if (k->type == SOCK_SEQPACKET) k->name = "unix-seqpacket";
    }
    return 0;
}

/* The agent's descriptor's close-on-exec flag: 1, 0, or -1 (unknown). */
static int agent_fd_cloexec(pid_t tid, int fd) {
    char p[64], buf[512];
    snprintf(p, sizeof p, "/proc/%d/fdinfo/%d", tid, fd);
    int f = open(p, O_RDONLY | O_CLOEXEC);
    if (f < 0) return -1;
    ssize_t n = read(f, buf, sizeof buf - 1);
    close(f);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *fl = strstr(buf, "flags:");
    if (!fl) return -1;
    unsigned long v = strtoul(fl + 6, NULL, 8);
    return (v & O_CLOEXEC) ? 1 : 0;
}

/* The agent's effective uid and gid (for a Unix connect made on its behalf). */
static int agent_creds(pid_t tid, uid_t *uid, gid_t *gid) {
    char p[64], line[256];
    snprintf(p, sizeof p, "/proc/%d/status", tid);
    FILE *f = fopen(p, "re");
    if (!f) return -1;
    int got = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned r, e;
        if (sscanf(line, "Uid: %u %u", &r, &e) == 2) { *uid = (uid_t)e; got |= 1; }
        else if (sscanf(line, "Gid: %u %u", &r, &e) == 2) { *gid = (gid_t)e; got |= 2; }
    }
    fclose(f);
    return got == 3 ? 0 : -1;
}

/* ---- socket options the agent set before connect ----
 *
 * A socket the Warden makes starts with its namespace's defaults. Each option
 * in the table below is read from the agent's socket and compared with a
 * socket of the same kind freshly made in the AGENT's namespace (created once
 * per kind and kept): what differs, the agent set, and it is set on the
 * Warden's socket. An option the agent left alone is not copied, so, for one,
 * the kernel's receive-buffer autotuning stays on. If setting a difference
 * fails, the connect fails with that errno. Values the kernel clamps
 * (buffer sizes against the host's limits) are applied as the kernel allows,
 * as the agent's own setsockopt would have been. Options NOT in the table are
 * not carried over: device and interface binding (SO_BINDTODEVICE,
 * IP_MULTICAST_IF; interfaces of the agent's namespace mean nothing in the
 * host's), anything only a privileged process can set (SO_MARK, SO_PRIORITY
 * above 6, IP_TRANSPARENT), and rarer options not listed here. */
enum { OPT_INT, OPT_TIMEVAL, OPT_LINGER, OPT_STR };
#define FAM_IN4  1u
#define FAM_IN6  2u
#define FAM_UNIX 4u
#define TY_STREAM 1u
#define TY_DGRAM  2u
#define TY_SEQ    4u
struct sockopt_desc { int level, name, repr; unsigned fams, types; };
static const struct sockopt_desc k_sockopts[] = {
    { SOL_SOCKET,  SO_KEEPALIVE,          OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { SOL_SOCKET,  SO_RCVBUF,             OPT_INT,     7, 7 },
    { SOL_SOCKET,  SO_SNDBUF,             OPT_INT,     7, 7 },
    { SOL_SOCKET,  SO_RCVTIMEO_OLD,       OPT_TIMEVAL, 7, 7 },
    { SOL_SOCKET,  SO_SNDTIMEO_OLD,       OPT_TIMEVAL, 7, 7 },
    { SOL_SOCKET,  SO_LINGER,             OPT_LINGER,  7, 7 },
    { SOL_SOCKET,  SO_OOBINLINE,          OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { SOL_SOCKET,  SO_PRIORITY,           OPT_INT,     7, 7 },
    { SOL_SOCKET,  SO_RCVLOWAT,           OPT_INT,     7, 7 },
    { SOL_SOCKET,  SO_BROADCAST,          OPT_INT,     FAM_IN4 | FAM_IN6, TY_DGRAM },
    { SOL_SOCKET,  SO_TIMESTAMP,          OPT_INT,     7, 7 },
    { SOL_SOCKET,  SO_TIMESTAMPNS,        OPT_INT,     7, 7 },
    { SOL_SOCKET,  SO_PASSCRED,           OPT_INT,     FAM_UNIX, 7 },
    { SOL_SOCKET,  SO_ZEROCOPY,           OPT_INT,     FAM_IN4 | FAM_IN6, 7 },
    { SOL_SOCKET,  SO_REUSEADDR,          OPT_INT,     7, 7 },
    { SOL_SOCKET,  SO_REUSEPORT,          OPT_INT,     FAM_IN4 | FAM_IN6, 7 },
    { SOL_SOCKET,  SO_INCOMING_CPU,       OPT_INT,     FAM_IN4 | FAM_IN6, 7 },
    { IPPROTO_TCP, TCP_NODELAY,           OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_KEEPIDLE,          OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_KEEPINTVL,         OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_KEEPCNT,           OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_USER_TIMEOUT,      OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_SYNCNT,            OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_NOTSENT_LOWAT,     OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_CORK,              OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_MAXSEG,            OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_WINDOW_CLAMP,      OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_LINGER2,           OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_FASTOPEN_CONNECT,  OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_CONGESTION,        OPT_STR,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, OPT_INT,  FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_SAVE_SYN,          OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_TCP, TCP_INQ,               OPT_INT,     FAM_IN4 | FAM_IN6, TY_STREAM },
    { IPPROTO_IP,  IP_TOS,                OPT_INT,     FAM_IN4 | FAM_IN6, 7 },
    { IPPROTO_IP,  IP_TTL,                OPT_INT,     FAM_IN4 | FAM_IN6, 7 },
    { IPPROTO_IP,  IP_MTU_DISCOVER,       OPT_INT,     FAM_IN4 | FAM_IN6, 7 },
    { IPPROTO_IP,  IP_RECVERR,            OPT_INT,     FAM_IN4 | FAM_IN6, 7 },
    { IPPROTO_IP,  IP_RECVTOS,            OPT_INT,     FAM_IN4 | FAM_IN6, 7 },
    { IPPROTO_IP,  IP_RECVTTL,            OPT_INT,     FAM_IN4 | FAM_IN6, 7 },
    { IPPROTO_IP,  IP_PKTINFO,            OPT_INT,     FAM_IN4 | FAM_IN6, TY_DGRAM },
    { IPPROTO_IP,  IP_MULTICAST_TTL,      OPT_INT,     FAM_IN4 | FAM_IN6, TY_DGRAM },
    { IPPROTO_IP,  IP_MULTICAST_LOOP,     OPT_INT,     FAM_IN4 | FAM_IN6, TY_DGRAM },
    { IPPROTO_IP,  IP_BIND_ADDRESS_NO_PORT, OPT_INT,   FAM_IN4 | FAM_IN6, 7 },
    { IPPROTO_IP,  IP_FREEBIND,           OPT_INT,     FAM_IN4 | FAM_IN6, 7 },
    { IPPROTO_IP,  IP_RECVORIGDSTADDR,    OPT_INT,     FAM_IN4 | FAM_IN6, TY_DGRAM },
    { IPPROTO_IPV6, IPV6_V6ONLY,          OPT_INT,     FAM_IN6, 7 },
    { IPPROTO_IPV6, IPV6_TCLASS,          OPT_INT,     FAM_IN6, 7 },
    { IPPROTO_IPV6, IPV6_UNICAST_HOPS,    OPT_INT,     FAM_IN6, 7 },
    { IPPROTO_IPV6, IPV6_MTU_DISCOVER,    OPT_INT,     FAM_IN6, 7 },
    { IPPROTO_IPV6, IPV6_RECVERR,         OPT_INT,     FAM_IN6, 7 },
    { IPPROTO_IPV6, IPV6_RECVPKTINFO,     OPT_INT,     FAM_IN6, TY_DGRAM },
    { IPPROTO_IPV6, IPV6_RECVTCLASS,      OPT_INT,     FAM_IN6, 7 },
    { IPPROTO_IPV6, IPV6_MULTICAST_HOPS,  OPT_INT,     FAM_IN6, TY_DGRAM },
    { IPPROTO_IPV6, IPV6_MULTICAST_LOOP,  OPT_INT,     FAM_IN6, TY_DGRAM },
    { IPPROTO_IPV6, IPV6_RECVHOPLIMIT,    OPT_INT,     FAM_IN6, 7 },
    { IPPROTO_UDP, UDP_CORK,              OPT_INT,     FAM_IN4 | FAM_IN6, TY_DGRAM },
    { IPPROTO_UDP, UDP_SEGMENT,           OPT_INT,     FAM_IN4 | FAM_IN6, TY_DGRAM },
    { IPPROTO_UDP, UDP_GRO,               OPT_INT,     FAM_IN4 | FAM_IN6, TY_DGRAM },
};
#define N_SOCKOPTS (sizeof k_sockopts / sizeof k_sockopts[0])

struct optval { bool ok; socklen_t len; unsigned char v[24]; };
struct sockref { bool have; int dom, type, proto; struct optval o[N_SOCKOPTS]; };
static struct sockref g_sockref[8];

static unsigned fam_bit(int dom) {
    return dom == AF_INET ? FAM_IN4 : dom == AF_INET6 ? FAM_IN6 : dom == AF_UNIX ? FAM_UNIX : 0;
}
static unsigned type_bit(int t) {
    return t == SOCK_STREAM ? TY_STREAM : t == SOCK_DGRAM ? TY_DGRAM : t == SOCK_SEQPACKET ? TY_SEQ : 0;
}

static void read_opts(int fd, const struct sock_kind *k, struct optval *o) {
    for (size_t i = 0; i < N_SOCKOPTS; i++) {
        const struct sockopt_desc *d = &k_sockopts[i];
        o[i].ok = false;
        if (!(d->fams & fam_bit(k->dom)) || !(d->types & type_bit(k->type))) continue;
        o[i].len = sizeof o[i].v;
        memset(o[i].v, 0, sizeof o[i].v);
        if (getsockopt(fd, d->level, d->name, o[i].v, &o[i].len) == 0) o[i].ok = true;
    }
}

/* A socket of this kind made in the agent's namespace, for its defaults. The
 * Warden is single-threaded, so switching its namespace for one socket() call
 * affects nothing else; failing to switch back stops the Warden (every socket
 * it made afterwards would be in the wrong namespace). */
static const struct sockref *sockref_for(const struct sock_kind *k) {
    for (size_t i = 0; i < sizeof g_sockref / sizeof g_sockref[0]; i++)
        if (g_sockref[i].have && g_sockref[i].dom == k->dom && g_sockref[i].type == k->type &&
            g_sockref[i].proto == k->proto)
            return &g_sockref[i];
    for (size_t i = 0; i < sizeof g_sockref / sizeof g_sockref[0]; i++) {
        if (g_sockref[i].have) continue;
        if (g_netns_separate && setns(g_agent_netns, CLONE_NEWNET) < 0) return NULL;
        int s = socket(k->dom, k->type | SOCK_CLOEXEC, k->proto);
        int e = errno;
        if (g_netns_separate && setns(g_host_netns, CLONE_NEWNET) < 0) {
            fprintf(stderr, "[warden] internal error: cannot return to the host network "
                    "namespace (%s); stopping\n", strerror(errno));
            abort();
        }
        if (s < 0) { errno = e; return NULL; }   /* not cached: tried again next time */
        read_opts(s, k, g_sockref[i].o);
        close(s);
        g_sockref[i].dom = k->dom;
        g_sockref[i].type = k->type;
        g_sockref[i].proto = k->proto;
        g_sockref[i].have = true;
        return &g_sockref[i];
    }
    return NULL;
}

/* At startup, the reference sockets for the kinds agents use, so the first
 * connect does not pay for two namespace switches. A kind this kernel lacks
 * (IPv6, on a host built without it) is skipped; it is tried again on use. */
static void sockref_warm(void) {
    static const struct sock_kind kinds[] = {
        { AF_INET,  SOCK_STREAM, IPPROTO_TCP, "tcp" }, { AF_INET,  SOCK_DGRAM, IPPROTO_UDP, "udp" },
        { AF_INET6, SOCK_STREAM, IPPROTO_TCP, "tcp" }, { AF_INET6, SOCK_DGRAM, IPPROTO_UDP, "udp" },
        { AF_UNIX,  SOCK_STREAM, 0, "unix-stream" },    { AF_UNIX,  SOCK_DGRAM, 0, "unix-dgram" },
        { AF_UNIX,  SOCK_SEQPACKET, 0, "unix-seqpacket" },
    };
    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++) (void)sockref_for(&kinds[i]);
}

/* Copy what the agent set onto the Warden's socket. 0, or -errno. */
static int carry_sockopts(int agent, int mine, const struct sock_kind *k, int *failed_opt) {
    const struct sockref *ref = sockref_for(k);
    if (!ref) return -EAGAIN;
    struct optval cur[N_SOCKOPTS];
    read_opts(agent, k, cur);
    for (size_t i = 0; i < N_SOCKOPTS; i++) {
        const struct sockopt_desc *d = &k_sockopts[i];
        if (!cur[i].ok || !ref->o[i].ok) continue;
        if (cur[i].len == ref->o[i].len && !memcmp(cur[i].v, ref->o[i].v, cur[i].len)) continue;
        unsigned char v[24];
        socklen_t vl = cur[i].len;
        memcpy(v, cur[i].v, sizeof v);
        if (d->level == SOL_SOCKET && (d->name == SO_RCVBUF || d->name == SO_SNDBUF)) {
            int x;
            memcpy(&x, v, sizeof x);
            x /= 2;                         /* the kernel reports double what was set */
            memcpy(v, &x, sizeof x);
        }
        if (d->repr == OPT_STR) vl = (socklen_t)strnlen((char *)v, sizeof v);
        if (setsockopt(mine, d->level, d->name, v, vl) < 0) {
            *failed_opt = d->name;
            return -errno;
        }
    }
    return 0;
}

/* ---- the destination ---- */

/* Canonical text of a numeric inet address and port, as the decision is made:
 * a.b.c.d:port, or [IPv6]:port with an IPv4-mapped address in its IPv4 form. */
static void inet_decision_text(int fam, const void *addr, unsigned port, char *out, size_t n) {
    char ip[INET6_ADDRSTRLEN];
    if (fam == AF_INET6 && IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)addr)) {
        inet_ntop(AF_INET, (const unsigned char *)addr + 12, ip, sizeof ip);
        snprintf(out, n, "%s:%u", ip, port);
    } else if (fam == AF_INET6) {
        inet_ntop(AF_INET6, addr, ip, sizeof ip);
        snprintf(out, n, "[%s]:%u", ip, port);
    } else {
        inet_ntop(AF_INET, addr, ip, sizeof ip);
        snprintf(out, n, "%s:%u", ip, port);
    }
}

/* For an inet destination: the sockaddr the Warden will dial (only the
 * address and port the decision names) and the decision string. Returns 0, or
 * -1 with *rule and *err naming the refusal. */
static int inet_destination(struct action *a, struct sockaddr_storage *dial, socklen_t *dl,
                            const char **rule, int *err) {
    memset(dial, 0, sizeof *dial);
    sa_family_t fam;
    memcpy(&fam, a->sa, sizeof fam);
    if (fam == AF_INET) {
        if ((size_t)a->salen < sizeof(struct sockaddr_in)) { *rule = "bad_address"; *err = EINVAL; return -1; }
        struct sockaddr_in in, *d = (struct sockaddr_in *)dial;
        memcpy(&in, a->sa, sizeof in);
        d->sin_family = AF_INET;
        d->sin_port = in.sin_port;
        d->sin_addr = in.sin_addr;
        *dl = sizeof *d;
        inet_decision_text(AF_INET, &in.sin_addr, ntohs(in.sin_port), a->resolved, sizeof a->resolved);
        return 0;
    }
    /* AF_INET6. The kernel needs at least the RFC 2133 size (24 bytes; no
     * scope id). */
    if (a->salen < 24) { *rule = "bad_address"; *err = EINVAL; return -1; }
    struct sockaddr_in6 in6, *d6 = (struct sockaddr_in6 *)dial;
    memset(&in6, 0, sizeof in6);
    memcpy(&in6, a->sa, (size_t)a->salen < sizeof in6 ? (size_t)a->salen : sizeof in6);
    if ((size_t)a->salen >= sizeof in6 && in6.sin6_scope_id != 0) {
        *rule = "scope_id_refused"; *err = EACCES; return -1;
    }
    d6->sin6_family = AF_INET6;
    d6->sin6_port = in6.sin6_port;
    d6->sin6_addr = in6.sin6_addr;
    *dl = sizeof *d6;
    inet_decision_text(AF_INET6, &in6.sin6_addr, ntohs(in6.sin6_port), a->resolved,
                       sizeof a->resolved);
    return 0;
}

/* For a path Unix destination: resolved like a file open (relative to the
 * agent's working directory, symlinks followed, /proc/self mapped to the
 * agent, no magic links, procfs objects outside the agent's own refused), the
 * object must be a socket, protected objects are refused by identity, and the
 * decision is made on unix:<canonical path>. *pin is an O_PATH descriptor on
 * the socket; the Warden connects through /proc/self/fd/<pin>, so the socket
 * decided on is the socket reached even if the name is swapped afterwards.
 * Returns 0, or -1 with *rule and *err. */
static int unix_destination(pid_t tid, struct action *a, int *pin, const char **rule, int *err) {
    *pin = -1;
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof sun);
    memcpy(&sun, a->sa, (size_t)a->salen < sizeof sun ? (size_t)a->salen : sizeof sun);
    size_t pl = (size_t)a->salen > offsetof(struct sockaddr_un, sun_path)
              ? (size_t)a->salen - offsetof(struct sockaddr_un, sun_path) : 0;
    if (pl > sizeof sun.sun_path) pl = sizeof sun.sun_path;
    if (pl == 0 || sun.sun_path[0] == '\0') {
        /* Unnamed, or abstract: an abstract name lives in a network namespace,
         * so dialed from the Warden's it would reach the host's abstract
         * sockets (display servers, D-Bus, ...), which the agent's own
         * namespace never could. */
        *rule = "unix_abstract_refused"; *err = EACCES; return -1;
    }
    char raw[sizeof sun.sun_path + 1];
    size_t rl = strnlen(sun.sun_path, pl);
    memcpy(raw, sun.sun_path, rl);
    raw[rl] = '\0';
    char path[PATH_LIMIT];
    pid_t tgid = -1;
    bool thread_self = false;
    if (path_is_proc_self(raw, &thread_self)) {
        tgid = task_tgid(tid);
        if (tgid < 0 || rewrite_proc_self(raw, thread_self, tgid, tid, path, sizeof path) < 0)
            goto fail;
    } else {
        snprintf(path, sizeof path, "%s", raw);
    }
    int base = agent_fd(tid, VAREK_AT_FDCWD);
    if (base < 0) goto fail;
    int fd = openat2_path(base, path, 0);
    close(base);
    if (fd < 0) goto fail;
    struct stat st;
    char canon[PATH_LIMIT];
    if (fstat(fd, &st) < 0 || !S_ISSOCK(st.st_mode) ||
        fd_canonical_path(fd, canon, sizeof canon) < 0 ||
        check_proc_object(fd, tid, &tgid, canon, sizeof canon) < 0) {
        close(fd);
        goto fail;
    }
    const char *forbid = forbidden_object(fd, canon);
    if (forbid) {
        close(fd);
        *rule = forbid; *err = EACCES; return -1;
    }
    int n = snprintf(a->resolved, sizeof a->resolved, "unix:%s", canon);
    if (n < 0 || (size_t)n >= sizeof a->resolved) { close(fd); a->resolved[0] = '\0'; goto fail; }
    *pin = fd;
    return 0;
fail:
    a->resolved[0] = '\0';
    *rule = "resolution_failed"; *err = EACCES;
    return -1;
}

/* A Unix connect made with the agent's effective uid and gid, so the server
 * sees the agent's credentials (SO_PEERCRED; its pid is the Warden's) and the
 * socket file's permissions are checked against the agent, not root.
 *
 * Invariant: between dropping and restoring the credentials, the Warden runs
 * nothing but this one non-blocking connect (its sockets are made with
 * SOCK_NONBLOCK); the Warden is single-threaded and its signal handler only
 * sets flags. Never add other work inside this window: it would run with the
 * agent's credentials. A failure to restore stops the Warden. */
static int connect_as_agent(int s, const struct sockaddr *sa, socklen_t sl, uid_t uid, gid_t gid) {
    if (uid == 0 && gid == 0) return connect(s, sa, sl) < 0 ? -errno : 0;
    gid_t saved[64];
    int ng = getgroups(64, saved);
    if (ng < 0) return -EAGAIN;
    if (setgroups(0, NULL) < 0 || setresgid((gid_t)-1, gid, (gid_t)-1) < 0 ||
        setresuid((uid_t)-1, uid, (uid_t)-1) < 0) {
        int e = errno;
        if (setresuid((uid_t)-1, 0, (uid_t)-1) < 0 || setresgid((gid_t)-1, 0, (gid_t)-1) < 0 ||
            setgroups((size_t)ng, saved) < 0) {
            fprintf(stderr, "[warden] internal error: cannot restore the Warden's credentials; stopping\n");
            abort();
        }
        return -e;
    }
    int rc = connect(s, sa, sl) < 0 ? -errno : 0;
    if (setresuid((uid_t)-1, 0, (uid_t)-1) < 0 || setresgid((gid_t)-1, 0, (gid_t)-1) < 0 ||
        setgroups((size_t)ng, saved) < 0) {
        fprintf(stderr, "[warden] internal error: cannot restore the Warden's credentials; stopping\n");
        abort();
    }
    return rc;
}

/* ---- connects and sends that finish later ---- */

enum { PEND_CONNECT = 1, PEND_UNIX_RETRY, PEND_SEND, PEND_STUB };
/* Each entry is an agent thread blocked in its call (a thread can wait in one
 * call at a time), holding one socket and, for a send, its data. Bounded by
 * count and by bytes held; past either, the call gets ENOBUFS. */
#define MAX_PENDING 1024
#define MAX_PENDING_BYTES (32u << 20)
#define UNIX_RETRY_NS (5 * 1000000LL)

struct pending_op {
    int              kind;
    uint64_t         id;
    pid_t            tid;
    int              sock;          /* the Warden's socket (connect), a dup of the agent's (send) */
    int              agent_fd;
    dev_t            ag_dev;        /* the agent's socket this connect was made on */
    ino_t            ag_ino;
    bool             cloexec, nonblock, has_deadline;
    struct timespec  deadline, next_try, t0, t_dial;
    decision_t       d_raw;
    struct action   *act;
    /* PEND_UNIX_RETRY */
    struct sockaddr_un dial_un;
    socklen_t        dial_un_len;
    int              pin;
    uid_t            uid;
    gid_t            gid;
    /* PEND_SEND */
    void            *buf;
    size_t           len;
    int              flags;
    bool             want_sigpipe;
    uint64_t         mmsg_len_addr; /* sendmmsg: where msg_len of message 0 goes, else 0 */
};
static struct pending_op *g_pend[MAX_PENDING];
static int g_npend = 0;
static size_t g_pend_bytes = 0;

static void ts_add_ns(struct timespec *t, int64_t ns) {
    t->tv_sec += ns / 1000000000LL;
    t->tv_nsec += ns % 1000000000LL;
    if (t->tv_nsec >= 1000000000L) { t->tv_sec++; t->tv_nsec -= 1000000000L; }
}
static bool ts_ge(const struct timespec *a, const struct timespec *b) {
    return a->tv_sec > b->tv_sec || (a->tv_sec == b->tv_sec && a->tv_nsec >= b->tv_nsec);
}

/* A deadline from the socket's SO_SNDTIMEO, as the kernel applies it to a
 * blocking connect or send (0: none). */
static bool sndtimeo_deadline(int s, struct timespec *dl) {
    struct timeval tv;
    socklen_t l = sizeof tv;
    if (getsockopt(s, SOL_SOCKET, SO_SNDTIMEO_OLD, &tv, &l) < 0 || (tv.tv_sec == 0 && tv.tv_usec == 0))
        return false;
    clock_gettime(CLOCK_MONOTONIC, dl);
    ts_add_ns(dl, (int64_t)tv.tv_sec * 1000000000LL + (int64_t)tv.tv_usec * 1000LL);
    return true;
}

static struct pending_op *pend_new(void) {
    if (g_npend >= MAX_PENDING) return NULL;
    struct pending_op *op = calloc(1, sizeof *op);
    if (!op) return NULL;
    op->act = malloc(sizeof *op->act);
    if (!op->act) { free(op); return NULL; }
    op->sock = op->pin = -1;
    g_pend[g_npend++] = op;
    return op;
}

static void pend_free(int i) {
    struct pending_op *op = g_pend[i];
    if (op->sock >= 0) close(op->sock);
    if (op->pin >= 0) close(op->pin);
    g_pend_bytes -= op->buf ? op->len : 0;
    free(op->buf);
    free(op->act);
    free(op);
    g_pend[i] = g_pend[--g_npend];
}

/* Hand the Warden's socket to the agent in place of its descriptor, and
 * answer its connect with reply_err (0 or EINPROGRESS). Returns the rule for
 * the record. */
static const char *handover(int notify_fd, uint64_t id, pid_t tid, int s, int afd,
                            dev_t ag_dev, ino_t ag_ino, bool cloexec, bool nonblock,
                            int reply_err, int *kerr) {
    /* The descriptor must still hold the socket the connect was made on. If
     * another thread closed it, or put something else at that number, while
     * the Warden dialed, the kernel's own connect would finish on the socket
     * it started with and leave the descriptor table alone: so answer the
     * connect, install nothing, and let the Warden's socket go. (A swap in the
     * last instant between this check and ADDFD is not caught; it only hurts
     * the agent's own bookkeeping.) */
    int cur = agent_fd(tid, afd);
    struct stat cst;
    bool same = cur >= 0 && fstat(cur, &cst) == 0 && cst.st_dev == ag_dev && cst.st_ino == ag_ino;
    if (cur >= 0) close(cur);
    if (!same) {
        if (reply_err) send_errno(notify_fd, id, reply_err);
        else           send_value(notify_fd, id, 0);
        *kerr = reply_err;
        return "dialed_descriptor_replaced";
    }
    int fl = fcntl(s, F_GETFL);
    if (fl >= 0) (void)fcntl(s, F_SETFL, nonblock ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
    struct seccomp_notif_addfd addfd = {
        .id          = id,
        .flags       = SECCOMP_ADDFD_FLAG_SETFD,
        .srcfd       = (uint32_t)s,
        .newfd       = (uint32_t)afd,
        .newfd_flags = cloexec ? O_CLOEXEC : 0,
    };
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) < 0) {
        int e = errno;
        if (e == ENOENT) { *kerr = 0; return "requester_gone"; }
        send_errno(notify_fd, id, EACCES);
        *kerr = EACCES;
        return "injection_failed";
    }
    if (reply_err) send_errno(notify_fd, id, reply_err);
    else           send_value(notify_fd, id, 0);
    *kerr = reply_err;
    return reply_err ? "dialed_in_progress" : "dialed_fd_injection";
}

/* ---- connect ---- */

/* v1.26 (step 4): connect the Warden's socket s to the proxy's listener from
 * 127.0.0.1 (IPv4-mapped for an IPv6 socket), announcing the connection
 * first: bind, tell the proxy the local port, then connect. 0 or -errno. */
static int proxy_dial(int s, int dom, const struct sockaddr_storage *to, socklen_t tl, pid_t tid,
                      struct action *a) {
    struct sockaddr_storage me;
    memcpy(&me, to, sizeof me);
    if (dom == AF_INET6) ((struct sockaddr_in6 *)&me)->sin6_port = 0;
    else ((struct sockaddr_in *)&me)->sin_port = 0;
    socklen_t ml = tl;
    if (bind(s, (struct sockaddr *)&me, ml) < 0 || getsockname(s, (struct sockaddr *)&me, &ml) < 0)
        return -errno;
    unsigned from = ntohs(dom == AF_INET6 ? ((struct sockaddr_in6 *)&me)->sin6_port
                                          : ((struct sockaddr_in *)&me)->sin_port);
    size_t el = strlen(a->extra);
    snprintf(a->extra + el, sizeof a->extra - el, "\"proxy_from\":%u,", from);
    if (wp_announce(&g_proxy, g_proxy_conns, from, tid, a->dialed) < 0) return -(errno ? errno : EIO);
    {                                            /* v1.26 review: the port it may be reported on */
        const char *c = strrchr(a->dialed, ':');
        px_handed_off(g_proxy_conns, c ? (unsigned)strtoul(c + 1, NULL, 10) : 0);
    }
    return connect(s, (const struct sockaddr *)to, tl) < 0 ? -errno : 0;
}

static void net_connect(int notify_fd, const struct seccomp_notif *req, struct action *a,
                        const struct policy *p, const struct timespec *t0) {
    pid_t tid = (pid_t)req->pid;
    const char *rule = NULL;
    int err = 0;
    sa_family_t fam = AF_UNSPEC;
    if (!a->salen_bad && a->salen >= (int)sizeof(sa_family_t)) memcpy(&fam, a->sa, sizeof fam);

    if (a->salen_bad || a->salen < (int)sizeof(sa_family_t)) { rule = "bad_address"; err = EINVAL; }
    else if (fam == AF_UNSPEC) { rule = "unspec_refused"; err = EACCES; }
    else if (fam != AF_INET && fam != AF_INET6 && fam != AF_UNIX) { rule = "family_refused"; err = EACCES; }
    if (rule) {
        net_record(tid, a, DEC_DENY, DEC_DENY, rule, t0, err);
        send_errno(notify_fd, req->id, err);
        return;
    }

    int ag = agent_fd(tid, a->sock_fd);
    if (ag < 0) {
        net_record(tid, a, DEC_DENY, DEC_DENY, "bad_descriptor", t0, EBADF);
        send_errno(notify_fd, req->id, EBADF);
        return;
    }
    struct sock_kind k;
    int kr = sock_kind_of(ag, &k);
    if (kr < 0 || !k.name) {
        close(ag);
        err = kr < 0 ? -kr : EACCES;
        net_record(tid, a, DEC_DENY, DEC_DENY,
                   kr == -ENOTSOCK ? "not_a_socket" : kr < 0 ? "bad_descriptor" : "socket_kind_refused",
                   t0, err);
        send_errno(notify_fd, req->id, err);
        return;
    }
    a->sock_name = k.name;
    struct stat agst;
    if (fstat(ag, &agst) < 0) {
        close(ag);
        net_record(tid, a, DEC_DENY, DEC_DENY, "bad_descriptor", t0, EBADF);
        send_errno(notify_fd, req->id, EBADF);
        return;
    }

    struct sockaddr_storage dial;
    socklen_t dial_len = 0;
    int pin = -1;
    int dr = fam == AF_UNIX ? unix_destination(tid, a, &pin, &rule, &err)
                            : inet_destination(a, &dial, &dial_len, &rule, &err);
    if (dr < 0) {
        close(ag);
        net_record(tid, a, !strcmp(rule, "resolution_failed") ? DEC_UNKNOWN : DEC_DENY, DEC_DENY,
                   rule, t0, err);
        send_errno(notify_fd, req->id, err);
        return;
    }

    /* v1.24: while the policy has a host name rule, no connect reaches any
     * DNS server (the agent resolves only through the Warden's views), and a
     * destination is decided on its address and the names it belongs to
     * (warden_names.inc.c). */
    /* v1.26 (step 4): may this connect be handed to the egress proxy? A TCP
     * connect on a proxied port, with the proxy running. */
    bool handoff_ok = false, syn = false, on_proxied = false;
    if (fam != AF_UNIX) {
        const void *ad;
        unsigned port;
        if (dial.ss_family == AF_INET6) {
            const struct sockaddr_in6 *d6 = (const struct sockaddr_in6 *)&dial;
            ad = &d6->sin6_addr;
            port = ntohs(d6->sin6_port);
        } else {
            const struct sockaddr_in *d4 = (const struct sockaddr_in *)&dial;
            ad = &d4->sin_addr;
            port = ntohs(d4->sin_port);
        }
        rule = NULL;
        /* v1.25: the stub resolver's port 53 is the one that is reached */
        if (stub_is_dest(&dial) && (!strcmp(k.name, "udp") || !strcmp(k.name, "tcp"))) {
            snprintf(a->resolved, sizeof a->resolved, "%s:53", STUB_ADDR_TEXT);
            stub_connect(notify_fd, req, a, ag, &k, t0);
            return;
        }
        on_proxied = g_proxy.ctl >= 0 && proxied_port(p, port);
        handoff_ok = on_proxied && !strcmp(k.name, "tcp");
        syn = dial_synthetic(dial.ss_family, ad);
        if (g_any_name && port == 53) rule = "dns_refused";
        /* v1.26: a synthetic address reaches only the proxy (a UDP connect,
         * another port, or no proxy running: refused) */
        else if (syn && !handoff_ok) rule = "synthetic_address";
        else if (names_candidates(a, dial.ss_family, ad, port) < 0) rule = "out_of_memory";
        if (rule) {
            close(ag);
            net_record(tid, a, DEC_DENY, DEC_DENY, rule, t0, EACCES);
            send_simple(notify_fd, req->id, DEC_DENY);
            return;
        }
    }
    decision_t d_raw = names_decide(p, a);
    names_record_fields(a);
    decision_t d_final = d_raw == DEC_ALLOW ? DEC_ALLOW : DEC_DENY;
    /* v1.26 (step 4): on a proxied port, a connect is handed to the proxy,
     * which decides on the name the client sends (step 6), unless a numeric
     * rule allows the address itself (dialed directly, as in v1.21) or a rule
     * denies it. A synthetic address is always handed over. The hand-off
     * authorizes nothing beyond the proxy's listener, so it carries no
     * certificate. */
    if (handoff_ok && fam != AF_UNIX) {
        bool numeric_allow = d_raw == DEC_ALLOW && a->ncand > 0 && !strcmp(a->resolved, g_cand[0]);
        bool denied = d_raw == DEC_DENY && a->rule_index >= 0;
        if (syn || (!numeric_allow && !denied)) {
            a->proxy_handoff = true;
            d_final = DEC_ALLOW;
            size_t el = strlen(a->extra);
            snprintf(a->extra + el, sizeof a->extra - el, "\"proxy_handoff\":true,\"proxy_conn\":%llu,",
                     (unsigned long long)++g_proxy_conns);
            snprintf(a->resolved, sizeof a->resolved, "127.0.0.1:%u", g_proxy.port);
            /* the listener, in the socket's family */
            memset(&dial, 0, sizeof dial);
            if (k.dom == AF_INET6) {
                struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)&dial;
                d6->sin6_family = AF_INET6;
                d6->sin6_port = htons((uint16_t)g_proxy.port);
                d6->sin6_addr.s6_addr[10] = d6->sin6_addr.s6_addr[11] = 0xff;
                d6->sin6_addr.s6_addr[12] = 127;
                d6->sin6_addr.s6_addr[15] = 1;
                dial_len = sizeof *d6;
            } else {
                struct sockaddr_in *d4 = (struct sockaddr_in *)&dial;
                d4->sin_family = AF_INET;
                d4->sin_port = htons((uint16_t)g_proxy.port);
                d4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                dial_len = sizeof *d4;
            }
        }
    }
    /* v1.26 (step 8): on a proxied port only TCP goes to the proxy; anything
     * else (UDP: QUIC) is dialed only if a numeric rule allows the address
     * itself, so a name never reaches a proxied port around the proxy. */
    if (on_proxied && !handoff_ok && d_final == DEC_ALLOW &&
        !(a->ncand > 0 && !strcmp(a->resolved, g_cand[0]))) {
        close(ag);
        if (pin >= 0) close(pin);
        net_record(tid, a, d_raw, DEC_DENY, "proxy_tcp_only", t0, EACCES);
        send_simple(notify_fd, req->id, DEC_DENY);
        return;
    }
    bool cert_refused = false;
    if (d_final == DEC_ALLOW && !a->proxy_handoff && !certify(p, a)) {
        d_final = DEC_DENY;
        cert_refused = true;
        log_line_start();
        fprintf(g_log, "[warden] certificate refused (record seq %" PRIu64 "): %s\n",
                g_records, a->check_why);
    }
    if (d_final != DEC_ALLOW) {
        close(ag);
        if (pin >= 0) close(pin);
        net_record(tid, a, d_raw, d_final,
                   cert_refused ? "certificate_refused" : decision_rule_id(a, d_raw), t0, EACCES);
        send_simple(notify_fd, req->id, DEC_DENY);
        return;
    }

    /* A connect on a socket that is already connected, or still connecting,
     * reaches nothing new: answer what the kernel would. */
    if (k.type == SOCK_STREAM || k.type == SOCK_SEQPACKET) {
        struct sockaddr_storage peer;
        socklen_t pl = sizeof peer;
        int again = 0;
        if (getpeername(ag, (struct sockaddr *)&peer, &pl) == 0) again = EISCONN;
        /* A connect on this same socket still waiting in the Warden (another
         * thread's blocking connect): the kernel says EALREADY. */
        for (int i = 0; !again && i < g_npend; i++)
            if ((g_pend[i]->kind == PEND_CONNECT || g_pend[i]->kind == PEND_UNIX_RETRY ||
                 g_pend[i]->kind == PEND_STUB) &&
                g_pend[i]->ag_dev == agst.st_dev && g_pend[i]->ag_ino == agst.st_ino)
                again = EALREADY;
        else if (!strcmp(k.name, "tcp")) {
            struct tcp_info ti;
            socklen_t tl = sizeof ti;
            memset(&ti, 0, sizeof ti);
            if (getsockopt(ag, IPPROTO_TCP, TCP_INFO, &ti, &tl) == 0 &&
                (ti.tcpi_state == TCP_SYN_SENT || ti.tcpi_state == TCP_SYN_RECV))
                again = EALREADY;
        }
        if (again) {
            close(ag);
            if (pin >= 0) close(pin);
            net_record(tid, a, d_raw, d_final, "already_connected", t0, again);
            send_errno(notify_fd, req->id, again);
            return;
        }
    }

    /* Dial. */
    int s = socket(k.dom, k.type | SOCK_NONBLOCK | SOCK_CLOEXEC, k.proto);
    if (s < 0) {
        err = errno;
        close(ag);
        if (pin >= 0) close(pin);
        net_record(tid, a, d_raw, d_final, "dial_failed", t0, err);
        send_errno(notify_fd, req->id, err);
        return;
    }
    int bad_opt = 0;
    int cr = carry_sockopts(ag, s, &k, &bad_opt);
    int afl = fcntl(ag, F_GETFL);
    bool nonblock = afl >= 0 && (afl & O_NONBLOCK);
    int cx = agent_fd_cloexec(tid, a->sock_fd);
    close(ag);
    if (cr < 0 || cx < 0) {
        close(s);
        if (pin >= 0) close(pin);
        err = cr < 0 ? -cr : EBADF;
        if (cr < 0) {
            log_line_start();
            fprintf(g_log, "[warden] connect: could not carry socket option %d over to the "
                    "Warden's socket (%s); refused rather than handing over a socket that "
                    "behaves otherwise\n", bad_opt, strerror(err));
        }
        net_record(tid, a, d_raw, d_final, "socket_option_failed", t0, err);
        send_errno(notify_fd, req->id, err);
        return;
    }
    bool cloexec = cx == 1;

    struct timespec td;
    clock_gettime(CLOCK_MONOTONIC, &td);
    int rc;
    uid_t uid = 0;
    gid_t gid = 0;
    struct sockaddr_un un;
    socklen_t un_len = 0;
    if (fam == AF_UNIX) {
        if (agent_creds(tid, &uid, &gid) < 0) {
            close(s);
            close(pin);
            net_record(tid, a, d_raw, d_final, "dial_failed", t0, EACCES);
            send_errno(notify_fd, req->id, EACCES);
            return;
        }
        memset(&un, 0, sizeof un);
        un.sun_family = AF_UNIX;
        snprintf(un.sun_path, sizeof un.sun_path, "/proc/self/fd/%d", pin);
        un_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path) + 1);
        rc = connect_as_agent(s, (struct sockaddr *)&un, un_len, uid, gid);
    } else if (a->proxy_handoff) {
        rc = proxy_dial(s, k.dom, &dial, dial_len, tid, a);
    } else {
        rc = connect(s, (struct sockaddr *)&dial, dial_len) < 0 ? -errno : 0;
    }
    struct timespec tn;
    clock_gettime(CLOCK_MONOTONIC, &tn);
    if (rc == -EINPROGRESS && !nonblock) {
        /* A loopback or LAN handshake is often done already: finish it now
         * rather than on the next pass of the receive loop. */
        struct pollfd pf = { .fd = s, .events = POLLOUT };
        if (poll(&pf, 1, 0) == 1) {
            int so = 0;
            socklen_t l = sizeof so;
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, &so, &l) < 0) so = errno;
            rc = so ? -so : 0;
            clock_gettime(CLOCK_MONOTONIC, &tn);
        }
    }

    if (rc == 0 || (rc == -EINPROGRESS && nonblock)) {
        if (pin >= 0) close(pin);
        a->dial_ns = ns_between(&td, &tn);
        int kerr = 0;
        const char *r = handover(notify_fd, req->id, tid, s, a->sock_fd, agst.st_dev, agst.st_ino,
                                 cloexec, nonblock, rc == 0 ? 0 : EINPROGRESS, &kerr);
        close(s);
        net_record(tid, a, d_raw, d_final, r, t0, kerr);
        return;
    }
    if ((rc == -EINPROGRESS) || (rc == -EAGAIN && fam == AF_UNIX && !nonblock)) {
        /* A blocking connect still in progress (or a Unix listener's backlog
         * full): finish it without blocking the Warden. */
        struct pending_op *op = pend_new();
        if (!op) {
            close(s);
            if (pin >= 0) close(pin);
            log_line_start();
            fprintf(g_log, "[warden] connect: %d connects already waiting; refused (ENOBUFS)\n",
                    MAX_PENDING);
            net_record(tid, a, d_raw, d_final, "too_many_pending", t0, ENOBUFS);
            send_errno(notify_fd, req->id, ENOBUFS);
            return;
        }
        op->kind = rc == -EINPROGRESS ? PEND_CONNECT : PEND_UNIX_RETRY;
        op->id = req->id;
        op->tid = tid;
        op->sock = s;
        op->agent_fd = a->sock_fd;
        op->ag_dev = agst.st_dev;
        op->ag_ino = agst.st_ino;
        op->cloexec = cloexec;
        op->nonblock = nonblock;
        op->t0 = *t0;
        op->t_dial = td;
        op->d_raw = d_raw;
        memcpy(op->act, a, sizeof *a);
        op->has_deadline = sndtimeo_deadline(s, &op->deadline);
        if (op->kind == PEND_UNIX_RETRY) {
            op->pin = pin;
            op->dial_un = un;
            op->dial_un_len = un_len;
            op->uid = uid;
            op->gid = gid;
            op->next_try = tn;
            ts_add_ns(&op->next_try, UNIX_RETRY_NS);
        } else if (pin >= 0) {
            close(pin);
        }
        return;
    }
    /* The dial failed as the agent's own connect would have (ECONNREFUSED,
     * ENETUNREACH, EAGAIN for a full non-blocking Unix backlog, ...): the agent
     * keeps its own socket and gets the errno. */
    close(s);
    if (pin >= 0) close(pin);
    a->dial_ns = ns_between(&td, &tn);
    net_record(tid, a, d_raw, d_final, "dial_failed", t0, -rc);
    send_errno(notify_fd, req->id, -rc);
}

/* ---- sendmsg / sendmmsg on a connected socket ---- */

#define RELAY_MAX (256 * 1024)
struct msghdr_user {                      /* struct msghdr as the x86_64 kernel reads it */
    uint64_t name;
    uint32_t namelen, pad0;
    uint64_t iov;
    uint64_t iovlen;
    uint64_t control;
    uint64_t controllen;
    uint32_t flags, pad1;
};

/* Gather one message's data from the agent. Returns the byte count (>= 0),
 * or -errno. On success *out is malloc'd. */
static ssize_t gather_iov(pid_t tid, const struct msghdr_user *m, bool dgram, void **out) {
    *out = NULL;
    if (m->iovlen > 1024) return -EMSGSIZE;
    struct { uint64_t base, len; } iov[1024];
    if (m->iovlen && xproc_read_bytes(tid, m->iov, iov, (size_t)m->iovlen * sizeof iov[0]) < 0)
        return -EFAULT;
    uint64_t total = 0;
    for (uint64_t i = 0; i < m->iovlen; i++) {
        if (iov[i].len > (uint64_t)SSIZE_MAX || total + iov[i].len > (uint64_t)SSIZE_MAX) return -EINVAL;
        total += iov[i].len;
    }
    if (total > RELAY_MAX) {
        if (dgram) return -EMSGSIZE;
        total = RELAY_MAX;                /* a stream send may be partial */
    }
    char *buf = malloc(total ? total : 1);
    if (!buf) return -ENOBUFS;
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/mem", tid);
    int mf = open(p, O_RDONLY | O_CLOEXEC);
    if (mf < 0) { free(buf); return -EFAULT; }
    uint64_t off = 0;
    for (uint64_t i = 0; i < m->iovlen && off < total; i++) {
        uint64_t want = iov[i].len < total - off ? iov[i].len : total - off;
        if (want && pread(mf, buf + off, want, (off_t)iov[i].base) != (ssize_t)want) {
            close(mf);
            free(buf);
            return -EFAULT;
        }
        off += want;
    }
    close(mf);
    *out = buf;
    return (ssize_t)total;
}

static void send_sigpipe(pid_t tid) {
    pid_t tgid = task_tgid(tid);
    if (tgid > 0) (void)syscall(SYS_tgkill, tgid, tid, SIGPIPE);
}

/* Returns true when the send was answered (or queued) here; false to refuse
 * it on the common path (a send that names its own destination, MSG_FASTOPEN,
 * or a sendto the filter handed over). */
static bool net_send_relay(int notify_fd, const struct seccomp_notif *req, struct action *a,
                           const struct timespec *t0) {
    pid_t tid = (pid_t)req->pid;
    if (a->send_nr == __NR_sendto) return false;
    if (a->send_flags & MSG_FASTOPEN) return false;
    int flags = (int)a->send_flags;
    unsigned nmsg = 1;
    if (a->send_nr == __NR_sendmmsg) {
        if (a->mmsg_vlen == 0) { send_value(notify_fd, req->id, 0); return true; }
        nmsg = a->mmsg_vlen > 1024 ? 1024 : a->mmsg_vlen;
    }
    int ag = agent_fd(tid, a->sock_fd);
    if (ag < 0) { send_errno(notify_fd, req->id, EBADF); return true; }
    struct sock_kind k;
    int kr = sock_kind_of(ag, &k);
    if (kr < 0) { close(ag); send_errno(notify_fd, req->id, -kr); return true; }
    /* Relayed only on TCP and UDP sockets: a send the Warden makes on a Unix
     * socket would carry the Warden's credentials to a receiver that asks for
     * them (SO_PASSCRED). Unix clients send with write() or send(). */
    if (!k.name || (strcmp(k.name, "tcp") && strcmp(k.name, "udp"))) {
        close(ag);
        net_record(tid, a, DEC_DENY, DEC_DENY, "send_relay_refused", t0, EACCES);
        send_errno(notify_fd, req->id, EACCES);
        return true;
    }
    int afl = fcntl(ag, F_GETFL);
    bool nonblock = (afl >= 0 && (afl & O_NONBLOCK)) || (flags & MSG_DONTWAIT);
    int sent = 0;
    for (unsigned i = 0; i < nmsg; i++) {
        struct msghdr_user m;
        uint64_t maddr = a->send_nr == __NR_sendmmsg ? a->msg_addr + (uint64_t)i * 64 : a->msg_addr;
        if (xproc_read_bytes(tid, maddr, &m, sizeof m) < 0) {
            if (i == 0) { close(ag); send_errno(notify_fd, req->id, EFAULT); return true; }
            break;
        }
        if ((m.name && m.namelen) || m.controllen) {
            if (i > 0) break;             /* sent what came before; the rest is refused next call */
            close(ag);
            if (m.name && m.namelen) return false;   /* a destination: the common refusal */
            net_record(tid, a, DEC_DENY, DEC_DENY, "send_control_refused", t0, EACCES);
            send_errno(notify_fd, req->id, EACCES);
            return true;
        }
        void *buf = NULL;
        ssize_t len = gather_iov(tid, &m, k.type == SOCK_DGRAM, &buf);
        if (len < 0) {
            if (i == 0) { close(ag); send_errno(notify_fd, req->id, (int)-len); return true; }
            break;
        }
        struct iovec v = { buf, (size_t)len };
        struct msghdr mh = { .msg_iov = &v, .msg_iovlen = 1 };
        int sflags = (flags & ~(MSG_FASTOPEN | MSG_ZEROCOPY)) | MSG_DONTWAIT | MSG_NOSIGNAL;
        ssize_t r = sendmsg(ag, &mh, sflags);
        int e = errno;
        if (r < 0 && (e == EAGAIN || e == EWOULDBLOCK) && !nonblock && i == 0) {
            struct pending_op *op = g_pend_bytes + (size_t)len <= MAX_PENDING_BYTES ? pend_new() : NULL;
            if (!op) { free(buf); close(ag); send_errno(notify_fd, req->id, ENOBUFS); return true; }
            op->kind = PEND_SEND;
            op->id = req->id;
            op->tid = tid;
            op->sock = ag;
            op->t0 = *t0;
            memcpy(op->act, a, sizeof *a);
            op->buf = buf;
            op->len = (size_t)len;
            g_pend_bytes += (size_t)len;
            op->flags = sflags;
            op->want_sigpipe = !(flags & MSG_NOSIGNAL);
            op->mmsg_len_addr = a->send_nr == __NR_sendmmsg ? a->msg_addr + 56 : 0;
            op->has_deadline = sndtimeo_deadline(ag, &op->deadline);
            return true;
        }
        free(buf);
        if (r < 0) {
            if (i > 0) break;
            close(ag);
            if (e == EPIPE && !(flags & MSG_NOSIGNAL)) send_sigpipe(tid);
            send_errno(notify_fd, req->id, e);
            return true;
        }
        if (a->send_nr == __NR_sendmmsg) {
            uint32_t ml = (uint32_t)r;
            if (xproc_write(tid, notify_fd, req->id, maddr + 56, &ml, sizeof ml) < 0) break;
        } else {
            close(ag);
            send_value(notify_fd, req->id, r);
            return true;
        }
        sent++;
    }
    close(ag);
    send_value(notify_fd, req->id, sent);
    return true;
}

/* ---- bind ----
 *
 * v1.12.1 refused bind outright (it is the start of a listener, a bound UDP
 * receiver, a Unix socket file created outside open() mediation, or a name in
 * the host's abstract namespace on a socket the Warden made). But libuv, so
 * Node.js, binds every UDP socket to the wildcard address and port 0 before it
 * connects it, so no Node program could use UDP. That one form names no
 * address and no port: it asks for what a connect's own autobind gives. The
 * Warden performs exactly that bind itself, on the agent's socket, from the
 * copy of the address it read (no second read of the agent's memory), for a
 * TCP or UDP socket over IPv4 or IPv6. Any other bind is refused with EPERM,
 * as before, and recorded. listen and accept stay outside the allowlist. */
static void net_bind(int notify_fd, const struct seccomp_notif *req, struct action *a,
                     const struct timespec *t0) {
    pid_t tid = (pid_t)req->pid;
    sa_family_t fam = 0;
    if (!a->salen_bad && a->salen >= (int)sizeof fam) memcpy(&fam, a->sa, sizeof fam);
    bool wildcard = false;
    if (fam == AF_INET && (size_t)a->salen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in in;
        memcpy(&in, a->sa, sizeof in);
        wildcard = in.sin_addr.s_addr == htonl(INADDR_ANY) && in.sin_port == 0;
    } else if (fam == AF_INET6 && a->salen >= 24) {
        struct sockaddr_in6 in6;
        memset(&in6, 0, sizeof in6);
        memcpy(&in6, a->sa, (size_t)a->salen < sizeof in6 ? (size_t)a->salen : sizeof in6);
        wildcard = IN6_IS_ADDR_UNSPECIFIED(&in6.sin6_addr) && in6.sin6_port == 0 &&
                   in6.sin6_scope_id == 0;
    }
    int ag = wildcard ? agent_fd(tid, a->sock_fd) : -1;
    struct sock_kind k = { 0, 0, 0, NULL };
    if (ag >= 0 && (sock_kind_of(ag, &k) < 0 || !k.name || k.dom != (int)fam ||
                    (strcmp(k.name, "tcp") && strcmp(k.name, "udp")))) {
        close(ag);
        ag = -1;
    }
    if (ag < 0) {
        net_record(tid, a, DEC_DENY, DEC_DENY, "bind_refused", t0, EPERM);
        send_errno(notify_fd, req->id, EPERM);
        return;
    }
    int rc = bind(ag, (const struct sockaddr *)a->sa, (socklen_t)a->salen) < 0 ? errno : 0;
    close(ag);
    if (rc) send_errno(notify_fd, req->id, rc);
    else    send_value(notify_fd, req->id, 0);
}

/* ---- finishing what is pending ---- */

/* v1.25: a pending connect to the stub resolver (warden_stub.inc.c) */
static void stub_pend_restore(struct pending_op *op);
static void stub_connect_answer(int notify_fd, uint64_t id, pid_t tid, struct action *a,
                                const struct timespec *t0, int err);

static void pend_finish_connect(int notify_fd, struct pending_op *op, int so_error, bool timed_out) {
    struct timespec tn;
    clock_gettime(CLOCK_MONOTONIC, &tn);
    op->act->dial_ns = ns_between(&op->t_dial, &tn);
    if (timed_out || so_error == 0) {
        /* Connected, or the agent's SO_SNDTIMEO ran out first: the kernel
         * answers a timed-out blocking connect with EINPROGRESS and goes on
         * connecting, so the socket is handed over either way. */
        int kerr = 0;
        const char *r = handover(notify_fd, op->id, op->tid, op->sock, op->agent_fd, op->ag_dev,
                                 op->ag_ino, op->cloexec, op->nonblock,
                                 timed_out ? EINPROGRESS : 0, &kerr);
        net_record(op->tid, op->act, op->d_raw, DEC_ALLOW, r, &op->t0, kerr);
    } else {
        send_errno(notify_fd, op->id, so_error);
        net_record(op->tid, op->act, op->d_raw, DEC_ALLOW, "dial_failed", &op->t0, so_error);
    }
}

/* Called once per pass of the receive loop, before any new notification.
 * rev[i] is the poll result for g_pend[i]'s descriptor (0 if not polled). */
static void pend_service(int notify_fd, const short *rev, int n) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    for (int i = n - 1; i >= 0; i--) {
        struct pending_op *op = g_pend[i];
        /* The agent's thread may have gone (killed, or its call interrupted
         * by a signal and restarted as a new request). */
        if (!notif_id_valid(notify_fd, op->id)) {
            if (op->kind == PEND_STUB) stub_pend_restore(op);
            if (op->kind != PEND_SEND)
                net_record(op->tid, op->act, op->d_raw, DEC_ALLOW, "requester_gone", &op->t0, 0);
            pend_free(i);
            continue;
        }
        bool due = op->has_deadline && ts_ge(&now, &op->deadline);
        if (op->kind == PEND_CONNECT) {
            if (rev[i] & (POLLOUT | POLLERR | POLLHUP)) {
                int so = 0;
                socklen_t l = sizeof so;
                if (getsockopt(op->sock, SOL_SOCKET, SO_ERROR, &so, &l) < 0) so = errno;
                pend_finish_connect(notify_fd, op, so, false);
                pend_free(i);
            } else if (due) {
                pend_finish_connect(notify_fd, op, 0, true);
                pend_free(i);
            }
        } else if (op->kind == PEND_UNIX_RETRY) {
            if (due) {
                send_errno(notify_fd, op->id, EAGAIN);
                net_record(op->tid, op->act, op->d_raw, DEC_ALLOW, "dial_failed", &op->t0, EAGAIN);
                pend_free(i);
            } else if (ts_ge(&now, &op->next_try)) {
                int rc = connect_as_agent(op->sock, (struct sockaddr *)&op->dial_un,
                                          op->dial_un_len, op->uid, op->gid);
                if (rc == -EAGAIN) {
                    op->next_try = now;
                    ts_add_ns(&op->next_try, UNIX_RETRY_NS);
                } else {
                    pend_finish_connect(notify_fd, op, -rc, false);
                    pend_free(i);
                }
            }
        } else if (op->kind == PEND_STUB) {
            if (rev[i] & (POLLOUT | POLLERR | POLLHUP) || due) {
                int so = 0;
                socklen_t l = sizeof so;
                if (!(rev[i] & (POLLOUT | POLLERR | POLLHUP))) so = EINPROGRESS;   /* SO_SNDTIMEO */
                else if (getsockopt(op->sock, SOL_SOCKET, SO_ERROR, &so, &l) < 0) so = errno;
                stub_pend_restore(op);
                stub_connect_answer(notify_fd, op->id, op->tid, op->act, &op->t0, so);
                pend_free(i);
            }
        } else if (op->kind == PEND_SEND) {
            if (rev[i] & (POLLOUT | POLLERR | POLLHUP)) {
                struct iovec v = { op->buf, op->len };
                struct msghdr mh = { .msg_iov = &v, .msg_iovlen = 1 };
                ssize_t r = sendmsg(op->sock, &mh, op->flags);
                if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                if (r < 0) {
                    int e = errno;
                    if (e == EPIPE && op->want_sigpipe) send_sigpipe(op->tid);
                    send_errno(notify_fd, op->id, e);
                } else if (op->mmsg_len_addr) {
                    uint32_t ml = (uint32_t)r;
                    if (xproc_write(op->tid, notify_fd, op->id, op->mmsg_len_addr, &ml, sizeof ml) < 0)
                        send_errno(notify_fd, op->id, EFAULT);
                    else
                        send_value(notify_fd, op->id, 1);
                } else {
                    send_value(notify_fd, op->id, r);
                }
                pend_free(i);
            } else if (due) {
                send_errno(notify_fd, op->id, EAGAIN);
                pend_free(i);
            }
        }
    }
}

/* The poll() timeout the pending work needs, in ms (-1: none). */
static int pend_timeout_ms(void) {
    if (g_npend == 0) return -1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t best = 250;                   /* re-check that each requester is still there */
    for (int i = 0; i < g_npend; i++) {
        const struct pending_op *op = g_pend[i];
        const struct timespec *t = NULL;
        if (op->kind == PEND_UNIX_RETRY) t = &op->next_try;
        if (op->has_deadline && (!t || ts_ge(t, &op->deadline))) t = &op->deadline;
        if (!t) continue;
        int64_t ms = ((int64_t)(t->tv_sec - now.tv_sec) * 1000000000LL +
                      (t->tv_nsec - now.tv_nsec) + 999999) / 1000000;
        if (ms < best) best = ms < 0 ? 0 : ms;
    }
    return (int)best;
}

/* ---- the plan gate ---- */

/* The destination a plan's net_connect step names, in the spelling the
 * runtime decides on: a.b.c.d:port, [IPv6]:port (an IPv4-mapped address as
 * its IPv4 form), or unix:<lexically canonical absolute path>. v1.24: when
 * the policy has host name rules, also name:port (a valid name, as the policy
 * grammar has it), decided on the name without resolving it: the step is a
 * declaration, and the runtime decides the address it dials. Without name
 * rules a name cannot be decided before the agent runs, so it is refused with
 * the reason. Returns 0, or -1 with why filled. */
static int net_plan_canon(const char *in, char *out, size_t n, char *why, size_t wn) {
    if (!in) { snprintf(why, wn, "no target"); return -1; }
    if (g_any_name && strchr(in, ':')) {
        char nw[160];
        if (vdp_host_name_form(in, strlen(in), nw, sizeof nw) == 1) {
            if ((size_t)snprintf(out, n, "%s", in) >= n) { snprintf(why, wn, "too long"); return -1; }
            return 0;
        }
    }
    if (!strncmp(in, "unix:", 5)) {
        char c[PATH_LIMIT];
        if (plan_lexical_canon(in + 5, c, sizeof c) < 0) {
            snprintf(why, wn, "a unix: target must be an absolute path");
            return -1;
        }
        if ((size_t)snprintf(out, n, "unix:%s", c) >= n) { snprintf(why, wn, "too long"); return -1; }
        return 0;
    }
    char host[INET6_ADDRSTRLEN + 2];
    const char *port;
    int fam;
    if (in[0] == '[') {
        const char *rb = strchr(in, ']');
        if (!rb || rb[1] != ':' || (size_t)(rb - in - 1) >= sizeof host) goto bad;
        memcpy(host, in + 1, (size_t)(rb - in - 1));
        host[rb - in - 1] = '\0';
        port = rb + 2;
        fam = AF_INET6;
    } else {
        const char *c = strrchr(in, ':');
        if (!c || strchr(in, ':') != c || (size_t)(c - in) >= sizeof host) goto bad;
        memcpy(host, in, (size_t)(c - in));
        host[c - in] = '\0';
        port = c + 1;
        fam = AF_INET;
    }
    unsigned long pv = 0;
    size_t k = 0;
    for (; port[k] >= '0' && port[k] <= '9' && k < 6; k++) pv = pv * 10 + (unsigned)(port[k] - '0');
    if (k == 0 || port[k] || pv > 65535) goto bad;
    unsigned char bin[16];
    if (inet_pton(fam, host, bin) != 1) goto bad;
    inet_decision_text(fam, bin, (unsigned)pv, out, n);
    return 0;
bad:
    snprintf(why, wn, "not a numeric address with a port (a.b.c.d:port, [IPv6]:port or "
             "unix:/path)%s", g_any_name ? ", or a host name with a port"
                                         : "; host names need `require warden 1.24` and a host name rule");
    return -1;
}
