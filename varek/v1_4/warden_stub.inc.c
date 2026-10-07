/* ---------------- v1.25: the Warden's stub resolver (section 3) ----------------
 *
 * docs/security/v1.25-wildcard-host-names.md. Included by warden.c after
 * warden_names.inc.c and before warden_net.inc.c.
 *
 * A wildcard rule (`allow host *.example.com:443`) has no list of names the
 * Warden could resolve in advance, so the agent asks for them. While the
 * policy has a wildcard allow rule:
 *
 *   - The agent's /etc/resolv.conf view names STUB_ADDR (127.53.53.53) and its
 *     /etc/nsswitch.conf view says `hosts: files dns`.
 *   - The stub is a UDP socket and a TCP listener the Warden binds to
 *     STUB_ADDR:53 inside the agent's own network namespace, which is
 *     otherwise empty (its loopback is brought up for it). Nothing in that
 *     namespace reaches the host's network: every other connect is dialed by
 *     the Warden in the host's namespace (warden_net.inc.c).
 *   - A connect to STUB_ADDR:53 (UDP or TCP) is made by the Warden on the
 *     agent's own socket, to its own copy of the address; a sendto() naming
 *     STUB_ADDR:53 (musl sends without connecting) is sent by the Warden on the
 *     agent's socket. Both are records with rule dns_stub. Every other
 *     connect to port 53 stays refused (dns_refused).
 *   - The stub answers one question per message, class IN. A name that is not
 *     one an allow rule can reach (stub_name_rule) is answered NXDOMAIN at
 *     once, and nothing leaves the host. A name an exact rule names is
 *     answered from the resolution table. A name a wildcard matches becomes a
 *     dynamic entry of the table: the resolver helper looks it up through the
 *     host's resolver (a chained `resolution` record, "dynamic":true), and the
 *     agent gets its addresses. Questions other than A and AAAA for an allowed
 *     name get an empty answer and send nothing upstream.
 *   - Connects are decided as in v1.24: on the address dialed and name:port for
 *     every name (exact or dynamic) the table holds for it.
 *   - Section 4: a name the table does not hold yet is charged to the wildcard
 *     rule that allows it, within that rule's budgets (names= per run, rate=
 *     per minute, 63 bytes before the suffix); past one, NXDOMAIN and no
 *     lookup (rule wildcard_budget). Every question is a chained dns_question
 *     record (stub_record), and run_start lists each rule's budgets.
 *
 * Without a network namespace of its own for the agent there is no stub: the
 * views stay as in v1.24 and wildcard-matched names cannot be resolved. */

#include <net/if.h>

#define STUB_ADDR       STUB_ADDR_TEXT
#define STUB_MAX_Q      128              /* questions waiting on the resolver helper */
#define STUB_MAX_CONN   16               /* TCP connections to the stub */
#define STUB_MAX_DYN    4096             /* dynamic names per run, all rules (a backstop) */
#define STUB_MSG_MAX    512              /* a question, and an answer over UDP */

static bool     g_stub_on = false;
static int      g_stub_udp = -1, g_stub_tcp = -1;
static size_t   g_stub_dyn = 0;
static struct in_addr g_stub_in;

struct stub_conn {
    int     fd;
    uint8_t in[2 + STUB_MSG_MAX];
    size_t  inlen;
};
static struct stub_conn g_stub_conn[STUB_MAX_CONN];
static int g_stub_nconn = 0;

/* Section 4: each wildcard allow rule's budgets. A question that would add a
 * name (one the table does not hold yet) is charged to the rule that allows
 * it; past a budget it is answered NXDOMAIN and nothing is looked up:
 *   names  distinct new names per run (names=, default STUB_DEFAULT_NAMES)
 *   rate   distinct new names in any 60 s (rate=, default STUB_DEFAULT_RATE)
 *   label  bytes matched by `*` (STUB_LABEL_MAX)
 * A name asked again (even after its TTL passed) is not charged again. */
struct stub_budget {
    int      ri;                         /* the rule's index */
    uint32_t names, rate, used;
    int64_t *ts;                         /* when each of the last `rate` names was charged */
    uint32_t head, cnt;
    size_t   sfx_len;                    /* the suffix's length (*.<suffix>) */
};
static struct stub_budget *g_budget;
static size_t g_nbudget;
static bool   g_budget_init = false;

struct stub_q {
    bool     used;
    int      conn_fd;                    /* -1: answer over UDP to from */
    struct sockaddr_storage from;
    socklen_t fromlen;
    uint8_t  q[STUB_MSG_MAX];            /* header and question, as asked */
    size_t   qlen;
    uint16_t qtype;
    size_t   entry;
};
static struct stub_q g_stub_q[STUB_MAX_Q];

/* Is dial (as decided: an IPv4 address or an IPv4-mapped IPv6 one) the stub's
 * port 53? */
static bool stub_is_dest(const struct sockaddr_storage *dial) {
    if (!g_stub_on) return false;
    if (dial->ss_family == AF_INET) {
        const struct sockaddr_in *d = (const struct sockaddr_in *)dial;
        return d->sin_addr.s_addr == g_stub_in.s_addr && ntohs(d->sin_port) == 53;
    }
    if (dial->ss_family == AF_INET6) {
        const struct sockaddr_in6 *d = (const struct sockaddr_in6 *)dial;
        return IN6_IS_ADDR_V4MAPPED(&d->sin6_addr) && ntohs(d->sin6_port) == 53 &&
               !memcmp((const uint8_t *)&d->sin6_addr + 12, &g_stub_in, 4);
    }
    return false;
}

/* The stub's address in a socket's family (IPv4, or IPv4-mapped for IPv6). */
static socklen_t stub_sockaddr(int dom, struct sockaddr_storage *ss) {
    memset(ss, 0, sizeof *ss);
    if (dom == AF_INET6) {
        struct sockaddr_in6 *d = (struct sockaddr_in6 *)ss;
        d->sin6_family = AF_INET6;
        d->sin6_port = htons(53);
        d->sin6_addr.s6_addr[10] = d->sin6_addr.s6_addr[11] = 0xff;
        memcpy(&d->sin6_addr.s6_addr[12], &g_stub_in, 4);
        return sizeof *d;
    }
    struct sockaddr_in *d = (struct sockaddr_in *)ss;
    d->sin_family = AF_INET;
    d->sin_port = htons(53);
    d->sin_addr = g_stub_in;
    return sizeof *d;
}

/* At startup, once the agent's network namespace is known: bring its loopback
 * up and bind the stub there. A failure leaves the stub off (wildcard names
 * then do not resolve) and says so. */
static void stub_setup(void) {
    if (!g_any_wild) return;
    if (!g_netns_separate) {
        fprintf(stderr, "[warden] the agent has no network namespace of its own: no stub "
                "resolver, so names that only a wildcard rule allows will not resolve\n");
        return;
    }
    inet_pton(AF_INET, STUB_ADDR, &g_stub_in);
    if (setns(g_agent_netns, CLONE_NEWNET) < 0) {
        fprintf(stderr, "[warden] cannot enter the agent's network namespace (%s): no stub "
                "resolver\n", strerror(errno));
        return;
    }
    const char *step = NULL;
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "lo");
    if (s < 0 || ioctl(s, SIOCGIFFLAGS, &ifr) < 0) step = "read the loopback's flags";
    else {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) step = "bring the loopback up";
    }
    if (s >= 0) close(s);
    struct sockaddr_storage ss;
    socklen_t sl = stub_sockaddr(AF_INET, &ss);
    int one = 1;
    if (!step) {
        g_stub_udp = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (g_stub_udp < 0 || bind(g_stub_udp, (struct sockaddr *)&ss, sl) < 0) step = "bind the UDP stub";
    }
    if (!step) {
        g_stub_tcp = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (g_stub_tcp < 0 || setsockopt(g_stub_tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0 ||
            bind(g_stub_tcp, (struct sockaddr *)&ss, sl) < 0 || listen(g_stub_tcp, 64) < 0)
            step = "bind the TCP stub";
    }
    int e = errno;
    if (setns(g_host_netns, CLONE_NEWNET) < 0) {
        /* The Warden would dial the agent's connects from the wrong
         * namespace: stop. */
        fprintf(stderr, "[warden] cannot return to the host's network namespace (%s)\n",
                strerror(errno));
        exit(1);
    }
    if (step) {
        fprintf(stderr, "[warden] cannot %s in the agent's network namespace (%s): no stub "
                "resolver\n", step, strerror(e));
        if (g_stub_udp >= 0) close(g_stub_udp);
        if (g_stub_tcp >= 0) close(g_stub_tcp);
        g_stub_udp = g_stub_tcp = -1;
        return;
    }
    g_stub_on = true;
    for (int i = 0; i < STUB_MAX_CONN; i++) g_stub_conn[i].fd = -1;
    fprintf(stderr, "[warden] stub resolver at %s:53 in the agent's network namespace "
            "(names matched by wildcard rules are resolved when asked)\n", STUB_ADDR);
}

/* Can a connect to name reach an allow rule? Decided as a connect to
 * name:port would be, for every port a host rule names and one port no rule
 * names: if any of those is SATISFIED, the name may be resolved. (A glob over
 * ports is not expanded; a port only it allows is then not counted, which
 * answers NXDOMAIN: the safe side.) Returns the index of the rule the name is
 * charged to: an exact (non-wildcard) allow rule if one decides some port,
 * else the first wildcard rule that does; -1 if none. */
static int stub_name_rule(const struct policy *p, const char *name) {
    unsigned ports[64];
    size_t np = 0;
    for (size_t i = 0; i < p->v.n && np < 63; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->kind != VDP_KIND_HOST || r->s.portless) continue;
        const char *colon = NULL;
        for (size_t k = r->s.len; k > 0; k--)
            if (r->s.c[k - 1] == ':') { colon = &r->s.c[k - 1]; break; }
        if (!colon) continue;
        char *end;
        unsigned long v = strtoul(colon + 1, &end, 10);
        if (end == colon + 1 || end != r->s.c + r->s.len || v > 65535) continue;
        bool dup = false;
        for (size_t k = 0; k < np; k++) if (ports[k] == v) dup = true;
        if (!dup) ports[np++] = (unsigned)v;
    }
    unsigned other = 1;                   /* a port no rule names */
    for (bool clash = true; clash && other < 65535; ) {
        clash = false;
        for (size_t k = 0; k < np; k++) if (ports[k] == other) { clash = true; other++; break; }
    }
    ports[np++] = other;
    int best = -1;
    for (size_t k = 0; k < np; k++) {
        char s[WR_NAME_MAX + 8];
        snprintf(s, sizeof s, "%s:%u", name, ports[k]);
        int ri;
        vdp_why_t why;
        if (vdp_decide(&p->v, VDP_KIND_HOST, s, 0, false, &ri, &why) != VDP_SATISFIED || ri < 0) continue;
        if (!p->v.rules[ri].s.wild) return ri;
        if (best < 0 || ri < best) best = ri;
    }
    return best;
}

/* The budgets, from the policy (once). */
static void stub_budget_init(const struct policy *p) {
    if (g_budget_init) return;
    g_budget_init = true;
    g_budget = calloc(p->v.n ? p->v.n : 1, sizeof *g_budget);
    if (!g_budget) return;
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->kind != VDP_KIND_HOST || !r->s.wild || r->verb != VDP_ALLOW) continue;
        struct stub_budget *b = &g_budget[g_nbudget];
        char sfx[WR_NAME_MAX + 1];
        if (sd_wildcard_suffix(r->s.c, sfx, sizeof sfx) < 0) continue;
        b->ri = (int)i;
        b->names = r->names ? r->names : STUB_DEFAULT_NAMES;
        b->rate = r->rate ? r->rate : STUB_DEFAULT_RATE;
        b->sfx_len = strlen(sfx);
        b->ts = calloc(b->rate, sizeof *b->ts);
        if (!b->ts) continue;            /* not counted: questions it would allow get NXDOMAIN */
        g_nbudget++;
    }
}

static struct stub_budget *stub_budget_of(int ri) {
    for (size_t k = 0; k < g_nbudget; k++) if (g_budget[k].ri == ri) return &g_budget[k];
    return NULL;
}

/* Charge a lookup to b at now: NULL, or the budget it would exceed. A new
 * name (isnew) is checked against the label and names budgets and counted in
 * names; every lookup sent upstream, a new name's or (v1.25 review) a name's
 * asked again after its TTL, counts against rate. Without that, re-asking
 * chosen names after their TTL sent data upstream with no bound. */
static const char *stub_charge(struct stub_budget *b, const char *name, int64_t now, bool isnew) {
    if (!b) return "names";
    size_t nl = strlen(name);
    if (isnew && (nl <= b->sfx_len || nl - b->sfx_len - 1 > STUB_LABEL_MAX)) return "label";
    if (isnew && b->used >= b->names) return "names";
    while (b->cnt && b->ts[b->head] <= now - 60000) {          /* older than a minute */
        b->head = (b->head + 1) % b->rate;
        b->cnt--;
    }
    if (b->cnt >= b->rate) return "rate";
    b->ts[(b->head + b->cnt) % b->rate] = now;
    b->cnt++;
    if (isnew) b->used++;
    return NULL;
}

/* Undo the last charge (the lookup was not sent, or the name not added). */
static void stub_uncharge(struct stub_budget *b, bool isnew) {
    if (!b) return;
    if (b->cnt) b->cnt--;
    if (isnew && b->used) b->used--;
}

/* The dns_question record: one per question the stub receives.
 *   {"event":"dns_question","run":R,"name":N,"type":T,"transport":"udp|tcp",
 *    "rule":"policy_match|exact_name|wildcard_budget|no_rule|not_a_host_name|malformed",
 *    "policy_line":L,["budget":"names|rate|label",]["new":true,]["upstream":true,]
 *    "answer":"noerror|nxdomain|servfail|formerr|lookup",["addresses":[...],]
 *    "generation":G,"timestamp_ns":TS}
 * "lookup": the resolver helper was asked; the resolution record that follows
 * for the name is the answer. "new": the question added the name, charged to
 * the rule on policy_line. "upstream" (v1.25 review): the question sent a
 * lookup upstream, charged to that rule's rate budget. "addresses": what a
 * noerror answer carried. flags: STUB_NEW, STUB_UPSTREAM. */
#define STUB_NEW      1u
#define STUB_UPSTREAM 2u
/* v1.25 review: the Warden's monotonic time (ms) of the question being
 * answered, the clock the rate budget is charged on; recorded as "mono_ms" so
 * the audit counts the rate window as the Warden did. */
static int64_t g_stub_now;
static void stub_record(const char *name, uint16_t qtype, int conn_fd, const char *rule, int line,
                        const char *budget, unsigned flags, const char *answer, const wr_entry_t *e) {
    FILE *f = rec_begin();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(f, "{\"event\":\"dns_question\",\"run\":\"%s\",\"name\":\"%s\",\"type\":%u,"
               "\"transport\":\"%s\",\"rule\":\"%s\",\"policy_line\":%d,",
            g_run_id, name, (unsigned)qtype, conn_fd < 0 ? "udp" : "tcp", rule, line);
    if (budget) fprintf(f, "\"budget\":\"%s\",", budget);
    if (flags & STUB_NEW) fputs("\"new\":true,", f);
    if (flags & STUB_UPSTREAM) fputs("\"upstream\":true,", f);
    fprintf(f, "\"answer\":\"%s\",", answer);
    if (e && !strcmp(answer, "noerror") && (qtype == 1 || qtype == 28)) {
        fputs("\"addresses\":[", f);
        bool first = true;
        char a[INET6_ADDRSTRLEN];
        for (size_t k = 0; k < e->n; k++) {
            if (e->addrs[k].until_ms != 0 || e->addrs[k].ip.fam != (qtype == 1 ? 4 : 6)) continue;
            wr_ip_str(&e->addrs[k].ip, a, sizeof a);
            fprintf(f, "%s\"%s\"", first ? "" : ",", a);
            first = false;
        }
        fputs("],", f);
    }
    fprintf(f, "\"generation\":%llu,\"mono_ms\":%lld,\"timestamp_ns\":%lld}\n",
            (unsigned long long)g_names.generation, (long long)g_stub_now,
            (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    rec_end(NULL);
}

static const char *stub_answer_word(int rcode) {
    switch (rcode) {
        case 0: return "noerror";
        case 1: return "formerr";
        case 3: return "nxdomain";
        default: return "servfail";
    }
}

/* ---- messages ---- */

/* Parse a question: header, one question, class IN. Writes the name
 * (lowercase, no trailing dot) and type, and the length of header and
 * question. 0, -1 (malformed, answer FORMERR), or -2 (not a query: drop). */
static int stub_parse(const uint8_t *m, size_t n, char *name, uint16_t *qtype, size_t *qend) {
    if (n < 12) return -2;
    if (m[2] & 0x80) return -2;                         /* a response */
    if (((m[2] >> 3) & 0x0f) != 0) return -1;           /* not a standard query */
    unsigned qd = (unsigned)(m[4] << 8 | m[5]), an = (unsigned)(m[6] << 8 | m[7]),
             ns = (unsigned)(m[8] << 8 | m[9]);
    if (qd != 1 || an || ns) return -1;
    size_t o = 12, w = 0;
    for (;;) {
        if (o >= n) return -1;
        unsigned l = m[o++];
        if (l == 0) break;
        if (l > 63 || o + l > n || w + l + 1 > WR_NAME_MAX + 1) return -1;
        if (w) name[w++] = '.';
        for (unsigned k = 0; k < l; k++) {
            char c = (char)m[o + k];
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            if (c == '.' || c == '\0') return -1;
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) c = '_';  /* no host name */
            name[w++] = c;
        }
        o += l;
    }
    name[w] = '\0';
    if (o + 4 > n || w == 0) return -1;
    *qtype = (uint16_t)(m[o] << 8 | m[o + 1]);
    uint16_t qclass = (uint16_t)(m[o + 2] << 8 | m[o + 3]);
    if (qclass != 1) return -1;
    *qend = o + 4;
    return 0;
}

/* Build an answer to question q (header and question, qlen bytes) into out:
 * rcode, and for NOERROR the current addresses of entry e of the asked
 * family (none for other types, or e NULL). Returns the length. */
static size_t stub_build(const uint8_t *q, size_t qlen, int rcode, uint16_t qtype,
                         const wr_entry_t *e, int64_t now, uint8_t *out, size_t outn) {
    if (qlen > outn) qlen = outn;
    memcpy(out, q, qlen);
    out[2] = (uint8_t)(0x80 | (q[2] & 0x01));           /* QR, opcode 0, RD as asked */
    out[3] = (uint8_t)(0x80 | (rcode & 0x0f));          /* RA */
    out[4] = 0; out[5] = 1;
    memset(out + 6, 0, 6);
    size_t o = qlen;
    unsigned an = 0;
    if (rcode == 0 && e && (qtype == 1 || qtype == 28)) {
        uint8_t fam = qtype == 1 ? 4 : 6;
        size_t al = fam == 4 ? 4 : 16;
        uint32_t ttl = 1;
        if (e->next_ms != INT64_MAX && e->next_ms > now) {
            int64_t s = (e->next_ms - now) / 1000;
            ttl = s < 1 ? 1 : (uint32_t)s;
        }
        for (size_t k = 0; k < e->n; k++) {
            if (e->addrs[k].until_ms != 0 || e->addrs[k].ip.fam != fam) continue;
            if (o + 12 + al > outn) { out[2] |= 0x02; break; }   /* TC: ask over TCP */
            out[o++] = 0xc0; out[o++] = 0x0c;                    /* the question's name */
            out[o++] = 0; out[o++] = (uint8_t)qtype;
            out[o++] = 0; out[o++] = 1;
            out[o++] = (uint8_t)(ttl >> 24); out[o++] = (uint8_t)(ttl >> 16);
            out[o++] = (uint8_t)(ttl >> 8);  out[o++] = (uint8_t)ttl;
            out[o++] = 0; out[o++] = (uint8_t)al;
            memcpy(out + o, e->addrs[k].ip.a, al);
            o += al;
            an++;
        }
    }
    out[6] = (uint8_t)(an >> 8); out[7] = (uint8_t)an;
    return o;
}

static void stub_send(int conn_fd, const struct sockaddr_storage *from, socklen_t fl,
                      const uint8_t *m, size_t n) {
    if (conn_fd < 0) {
        (void)sendto(g_stub_udp, m, n, MSG_DONTWAIT | MSG_NOSIGNAL, (const struct sockaddr *)from, fl);
        return;
    }
    uint8_t buf[2 + 2 * STUB_MSG_MAX];
    if (n > 2 * STUB_MSG_MAX) return;
    buf[0] = (uint8_t)(n >> 8); buf[1] = (uint8_t)n;
    memcpy(buf + 2, m, n);
    (void)send(conn_fd, buf, n + 2, MSG_DONTWAIT | MSG_NOSIGNAL);   /* small: fits the buffer */
}

/* The rcode for entry e, asked for qtype, once looked up. */
static int stub_rcode(const wr_entry_t *e, uint16_t qtype) {
    if (e->st[0] == WR_ST_NXDOMAIN && e->st[1] == WR_ST_NXDOMAIN) return 3;
    int f = qtype == 28 ? 1 : 0;
    if (qtype != 1 && qtype != 28) return 0;
    bool have = false;
    for (size_t k = 0; k < e->n; k++)
        if (e->addrs[k].until_ms == 0 && e->addrs[k].ip.fam == (f ? 6 : 4)) have = true;
    if (!have && e->st[f] == WR_ST_FAIL) return 2;                  /* SERVFAIL */
    return 0;
}

/* One question, from the UDP socket (conn_fd -1) or a TCP connection. Every
 * question is a dns_question record. */
static void stub_question(const struct policy *p, int conn_fd, const struct sockaddr_storage *from,
                          socklen_t fl, const uint8_t *m, size_t n) {
    char name[WR_NAME_MAX + 2];
    uint16_t qtype = 0;
    size_t qend = 0;
    uint8_t out[2 * STUB_MSG_MAX];
    size_t outn = conn_fd < 0 ? STUB_MSG_MAX : sizeof out;
    stub_budget_init(p);
    g_stub_now = wr_now_ms();
    int pr = stub_parse(m, n, name, &qtype, &qend);
    if (pr == -2) return;
    if (pr == -1) {
        uint8_t hdr[12];
        memcpy(hdr, m, 12);
        hdr[4] = hdr[5] = 0;
        size_t l = stub_build(hdr, 12, 1, 0, NULL, 0, out, outn);       /* FORMERR */
        stub_send(conn_fd, from, fl, out, l);
        stub_record("", 0, conn_fd, "malformed", -1, NULL, false, "formerr", NULL);
        return;
    }
    int64_t now = g_stub_now;
    char why[8];
    if (vdp_host_name_form(name, strlen(name), why, sizeof why) != 1) {
        size_t l = stub_build(m, qend, 3, qtype, NULL, now, out, outn);  /* not a host name */
        stub_send(conn_fd, from, fl, out, l);
        /* the name is not one (it may hold '_'): recorded as such, not quoted */
        stub_record("", qtype, conn_fd, "not_a_host_name", -1, NULL, false, "nxdomain", NULL);
        return;
    }
    int i = wr_table_find(&g_names, name);
    /* a name only a deny rule names (v1.24 review) is in the table but allows nothing */
    bool exact = i >= 0 && !g_names.e[i].dynamic && !g_names.e[i].unlisted;
    int ri = stub_name_rule(p, name);
    int line = ri >= 0 ? p->v.rules[ri].line : -1;
    const char *rule = exact ? "exact_name" : "policy_match";
    if (!exact && ri < 0) {
        size_t l = stub_build(m, qend, 3, qtype, NULL, now, out, outn);  /* NXDOMAIN */
        stub_send(conn_fd, from, fl, out, l);
        stub_record(name, qtype, conn_fd, "no_rule", -1, NULL, false, "nxdomain", NULL);
        return;
    }
    if (!exact && qtype != 1 && qtype != 28) {
        size_t l = stub_build(m, qend, 0, qtype, NULL, now, out, outn);  /* nothing upstream */
        stub_send(conn_fd, from, fl, out, l);
        stub_record(name, qtype, conn_fd, rule, line, NULL, false, "noerror", NULL);
        return;
    }
    bool isnew = false;
    struct stub_budget *bud = ri >= 0 && p->v.rules[ri].s.wild ? stub_budget_of(ri) : NULL;
    if (i < 0) {
        /* A new name (never exact, so ri >= 0): charged to the wildcard rule
         * that allows it. */
        const char *over = p->v.rules[ri].s.wild ? stub_charge(bud, name, now, true) : NULL;
        if (over) {
            size_t l = stub_build(m, qend, 3, qtype, NULL, now, out, outn);
            stub_send(conn_fd, from, fl, out, l);
            stub_record(name, qtype, conn_fd, "wildcard_budget", line, over, 0, "nxdomain", NULL);
            return;
        }
        if (g_stub_dyn >= STUB_MAX_DYN || (i = wr_table_add_dynamic(&g_names, name)) < 0) {
            stub_uncharge(bud, true);                   /* v1.25 review: nothing was added */
            size_t l = stub_build(m, qend, 2, qtype, NULL, now, out, outn);  /* SERVFAIL */
            stub_send(conn_fd, from, fl, out, l);
            stub_record(name, qtype, conn_fd, rule, line, NULL, 0, "servfail", NULL);
            return;
        }
        g_stub_dyn++;
        isnew = true;
    }
    const wr_entry_t *e = &g_names.e[i];
    if (exact || wr_entry_fresh(e, now)) {
        int rc = e->lookups ? stub_rcode(e, qtype) : 2;
        size_t l = stub_build(m, qend, rc, qtype, e, now, out, outn);
        stub_send(conn_fd, from, fl, out, l);
        stub_record(name, qtype, conn_fd, rule, line, NULL, isnew ? STUB_NEW : 0, stub_answer_word(rc), e);
        return;
    }
    /* Look it up, and answer when the helper does. A lookup already on its
     * way is shared and charges nothing more; a name asked again after its
     * TTL charges the rule's rate (v1.25 review). */
    bool send_up = !e->pending;
    if (send_up && !isnew && bud) {
        const char *over = stub_charge(bud, name, now, false);
        if (over) {
            size_t l = stub_build(m, qend, 3, qtype, NULL, now, out, outn);
            stub_send(conn_fd, from, fl, out, l);
            stub_record(name, qtype, conn_fd, "wildcard_budget", line, over, 0, "nxdomain", NULL);
            return;
        }
    }
    int slot = -1;
    for (int k = 0; k < STUB_MAX_Q; k++) if (!g_stub_q[k].used) { slot = k; break; }
    if (slot < 0 || wr_async_request(&g_names, (size_t)i) < 0) {
        if (send_up) stub_uncharge(bud, false);         /* nothing went upstream */
        size_t l = stub_build(m, qend, 2, qtype, NULL, now, out, outn);
        stub_send(conn_fd, from, fl, out, l);
        stub_record(name, qtype, conn_fd, rule, line, NULL, isnew ? STUB_NEW : 0, "servfail", NULL);
        return;
    }
    stub_record(name, qtype, conn_fd, rule, line, NULL,
                (isnew ? STUB_NEW : 0) | (send_up ? STUB_UPSTREAM : 0), "lookup", NULL);
    struct stub_q *q = &g_stub_q[slot];
    q->used = true;
    q->conn_fd = conn_fd;
    if (fl > sizeof q->from) fl = sizeof q->from;
    if (from && fl) memcpy(&q->from, from, fl);
    q->fromlen = fl;
    memcpy(q->q, m, qend);
    q->qlen = qend;
    q->qtype = qtype;
    q->entry = (size_t)i;
}

/* The resolver helper answered entry i: answer every question waiting on it. */
static void stub_resolved(size_t i) {
    if (!g_stub_on) return;
    int64_t now = wr_now_ms();
    for (int k = 0; k < STUB_MAX_Q; k++) {
        struct stub_q *q = &g_stub_q[k];
        if (!q->used || q->entry != i) continue;
        uint8_t out[2 * STUB_MSG_MAX];
        const wr_entry_t *e = &g_names.e[i];
        size_t l = stub_build(q->q, q->qlen, stub_rcode(e, q->qtype), q->qtype, e, now, out,
                              q->conn_fd < 0 ? STUB_MSG_MAX : sizeof out);
        stub_send(q->conn_fd, &q->from, q->fromlen, out, l);
        q->used = false;
    }
}

static void stub_conn_close(int k) {
    for (int j = 0; j < STUB_MAX_Q; j++)
        if (g_stub_q[j].used && g_stub_q[j].conn_fd == g_stub_conn[k].fd) g_stub_q[j].used = false;
    close(g_stub_conn[k].fd);
    g_stub_conn[k] = g_stub_conn[--g_stub_nconn];
    g_stub_conn[g_stub_nconn].fd = -1;
}

/* ---- the supervise loop ---- */

/* Fill pfds with the stub's sockets; returns how many. */
static int stub_poll_fill(struct pollfd *pfds) {
    if (!g_stub_on) return 0;
    int n = 0;
    pfds[n++] = (struct pollfd){ .fd = g_stub_udp, .events = POLLIN };
    pfds[n++] = (struct pollfd){ .fd = g_stub_nconn < STUB_MAX_CONN ? g_stub_tcp : -1, .events = POLLIN };
    for (int k = 0; k < g_stub_nconn; k++)
        pfds[n++] = (struct pollfd){ .fd = g_stub_conn[k].fd, .events = POLLIN };
    return n;
}

static void stub_service(const struct policy *p, const struct pollfd *pfds, int n) {
    if (!g_stub_on || n == 0) return;
    if (pfds[0].revents & POLLIN) {
        for (int burst = 0; burst < 64; burst++) {
            uint8_t m[STUB_MSG_MAX];
            struct sockaddr_storage from;
            socklen_t fl = sizeof from;
            ssize_t r = recvfrom(g_stub_udp, m, sizeof m, MSG_DONTWAIT | MSG_TRUNC,
                                 (struct sockaddr *)&from, &fl);
            if (r < 0) break;
            if ((size_t)r > sizeof m) continue;                 /* larger than any question */
            stub_question(p, -1, &from, fl, m, (size_t)r);
        }
    }
    if (pfds[1].revents & POLLIN) {
        while (g_stub_nconn < STUB_MAX_CONN) {
            int c = accept4(g_stub_tcp, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (c < 0) break;
            g_stub_conn[g_stub_nconn].fd = c;
            g_stub_conn[g_stub_nconn].inlen = 0;
            g_stub_nconn++;
        }
    }
    /* The connections polled are pfds[2 .. n); a connection closed while
     * walking them moves the last one into its place, so walk by fd. */
    for (int j = 2; j < n; j++) {
        if (!(pfds[j].revents & (POLLIN | POLLHUP | POLLERR))) continue;
        int k = -1;
        for (int x = 0; x < g_stub_nconn; x++) if (g_stub_conn[x].fd == pfds[j].fd) k = x;
        if (k < 0) continue;
        struct stub_conn *c = &g_stub_conn[k];
        ssize_t r = recv(c->fd, c->in + c->inlen, sizeof c->in - c->inlen, MSG_DONTWAIT);
        if (r <= 0) {
            if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) stub_conn_close(k);
            continue;
        }
        c->inlen += (size_t)r;
        while (c->inlen >= 2) {
            size_t ml = (size_t)(c->in[0] << 8 | c->in[1]);
            if (ml > STUB_MSG_MAX) { stub_conn_close(k); break; }
            if (c->inlen < 2 + ml) break;
            stub_question(p, c->fd, NULL, 0, c->in + 2, ml);
            memmove(c->in, c->in + 2 + ml, c->inlen - 2 - ml);
            c->inlen -= 2 + ml;
        }
    }
}

/* ---- the agent's side: connects and sends to the stub ---- */

/* Answer a connect to the stub with err (0, EINPROGRESS or the connect's
 * errno), and record it. */
static void stub_connect_answer(int notify_fd, uint64_t id, pid_t tid, struct action *a,
                                const struct timespec *t0, int err) {
    net_record(tid, a, DEC_ALLOW, err && err != EINPROGRESS ? DEC_DENY : DEC_ALLOW, "dns_stub", t0, err);
    if (err) send_errno(notify_fd, id, err);
    else send_value(notify_fd, id, 0);
}

/* A pending stub connect is made on the agent's own socket, which was
 * blocking: make it blocking again. */
static void stub_pend_restore(struct pending_op *op) {
    int fl = fcntl(op->sock, F_GETFL);
    if (fl >= 0) (void)fcntl(op->sock, F_SETFL, fl & ~O_NONBLOCK);
}

/* A connect to the stub (stub_is_dest): connect the agent's own socket ag (a
 * TCP or UDP socket in the agent's namespace) to the Warden's copy of the
 * address, and answer what that connect returned.
 *
 * v1.25 review: the connect never blocks the Warden. A TCP handshake to the
 * stub's own listener normally completes at once, but the agent sets the
 * socket's options, and with TCP_MD5SIG or a long TCP_SYNCNT it can keep the
 * handshake from completing for minutes or hours. So the socket is made
 * non-blocking for the connect; a blocking connect that is still in progress
 * waits as a pending operation (warden_net.inc.c) and is answered when the
 * socket is writable, or with EINPROGRESS when the agent's SO_SNDTIMEO runs
 * out, as the kernel does. Until then other threads sharing the socket see it
 * non-blocking. */
static void stub_connect(int notify_fd, const struct seccomp_notif *req, struct action *a,
                         int ag, const struct sock_kind *k, const struct timespec *t0) {
    pid_t tid = (pid_t)req->pid;
    int err = 0;
    if (k->type == SOCK_STREAM && g_stub_nconn >= STUB_MAX_CONN) err = ECONNREFUSED;
    else {
        struct sockaddr_storage ss;
        socklen_t sl = stub_sockaddr(k->dom, &ss);
        int fl = fcntl(ag, F_GETFL);
        bool blocking = fl >= 0 && !(fl & O_NONBLOCK);
        if (blocking && fcntl(ag, F_SETFL, fl | O_NONBLOCK) < 0) err = errno;
        else if (connect(ag, (struct sockaddr *)&ss, sl) < 0) err = errno;
        if (blocking && err == EINPROGRESS) {
            struct pollfd pf = { .fd = ag, .events = POLLOUT };
            if (poll(&pf, 1, 0) == 1) {                /* done already, as on loopback */
                socklen_t l = sizeof err;
                if (getsockopt(ag, SOL_SOCKET, SO_ERROR, &err, &l) < 0) err = errno;
            }
        }
        if (blocking && err == EINPROGRESS) {
            struct stat st;
            struct pending_op *op = fstat(ag, &st) == 0 ? pend_new() : NULL;
            if (!op) {
                (void)fcntl(ag, F_SETFL, fl);
                close(ag);
                stub_connect_answer(notify_fd, req->id, tid, a, t0, ENOBUFS);
                return;
            }
            op->kind = PEND_STUB;
            op->id = req->id;
            op->tid = tid;
            op->sock = ag;                      /* the agent's socket; closed by pend_free */
            op->agent_fd = a->sock_fd;
            op->ag_dev = st.st_dev;
            op->ag_ino = st.st_ino;
            op->t0 = *t0;
            clock_gettime(CLOCK_MONOTONIC, &op->t_dial);
            memcpy(op->act, a, sizeof *a);
            op->has_deadline = sndtimeo_deadline(ag, &op->deadline);
            return;
        }
        if (blocking) (void)fcntl(ag, F_SETFL, fl);
    }
    close(ag);                           /* EINPROGRESS: a non-blocking TCP socket */
    stub_connect_answer(notify_fd, req->id, tid, a, t0, err);
}

/* A sendto() naming the stub on a UDP socket: send the message (read once)
 * from the agent's socket. Returns false if this is not such a send. */
static bool stub_sendto(int notify_fd, const struct seccomp_notif *req, struct action *a,
                        const struct timespec *t0) {
    if (!g_stub_on || a->send_nr != __NR_sendto || a->salen < (int)sizeof(sa_family_t)) return false;
    struct sockaddr_storage dest;
    memset(&dest, 0, sizeof dest);
    memcpy(&dest, a->sa, (size_t)a->salen < sizeof dest ? (size_t)a->salen : sizeof dest);
    if ((dest.ss_family == AF_INET && a->salen < (int)sizeof(struct sockaddr_in)) ||
        (dest.ss_family == AF_INET6 && a->salen < (int)sizeof(struct sockaddr_in6)) ||
        !stub_is_dest(&dest))
        return false;
    pid_t tid = (pid_t)req->pid;
    int ag = agent_fd(tid, a->sock_fd);
    if (ag < 0) { send_errno(notify_fd, req->id, EBADF); return true; }
    struct sock_kind k;
    if (sock_kind_of(ag, &k) < 0 || !k.name || strcmp(k.name, "udp")) {
        close(ag);
        return false;                    /* the common refusal */
    }
    uint64_t len = req->data.args[2];
    uint8_t m[STUB_MSG_MAX];
    int err = 0;
    ssize_t r = -1;
    if (len > sizeof m) err = EMSGSIZE;
    else if (xproc_read_bytes(tid, req->data.args[1], m, (size_t)len) < 0) err = EFAULT;
    else {
        struct sockaddr_storage ss;
        socklen_t sl = stub_sockaddr(k.dom, &ss);
        r = sendto(ag, m, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&ss, sl);
        if (r < 0) err = errno;
    }
    close(ag);
    snprintf(a->resolved, sizeof a->resolved, "%s:53", STUB_ADDR);
    net_record(tid, a, DEC_ALLOW, err ? DEC_DENY : DEC_ALLOW, "dns_stub", t0, err);
    if (err) send_errno(notify_fd, req->id, err);
    else send_value(notify_fd, req->id, r);
    return true;
}
