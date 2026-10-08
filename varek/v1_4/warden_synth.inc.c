/* ---------------- v1.26: synthetic addresses (plan step 3) ----------------
 *
 * docs/security/v1.26-egress-proxy.md, "Implementation plan", step 3.
 * Included by warden.c after warden_stub.inc.c.
 *
 * With `proxy on`, a name that host rules allow only on proxied ports (the
 * policy's `proxy ports`, else 80 and 443) is never resolved for the agent.
 * The stub (which runs with `proxy on` even without a wildcard rule) answers
 * its A question with a synthetic address from 198.18.0.0/15 (reserved for
 * benchmarking, RFC 2544), its AAAA and other questions with no data, so
 * clients use IPv4, and sends nothing upstream; no wildcard budget is
 * charged, since no name leaves the host. The hosts view lists exact names
 * the same way. A connect to a synthetic address on a proxied port goes to
 * the proxy (step 4), which decides on the name the client then sends.
 *
 * A name is given an address the first time it is asked for or listed, and
 * keeps it for the run: the k-th name (from 0) gets 198.18.0.0 + k + 1, up to
 * SYN_MAX names (198.19.255.254); past that, SERVFAIL. Each assignment is a
 * chained record:
 *   {"event":"synthetic_address","run":R,"name":N,"address":A,
 *    "policy_line":L,"timestamp_ns":TS}
 *
 * A name allowed on a port that is not proxied keeps the v1.24 and v1.25
 * behaviour (the resolution table and the stub's lookups), since a direct
 * connect needs its real address.
 *
 * Until the hand-off exists (step 4), a connect to a synthetic address is
 * refused (rule synthetic_address), whatever the policy says: the range is
 * the Warden's while the proxy is on. */

/* SYN_BASE, SYN_MAX, SYN_TTL: warden.c */

static char   (*g_syn_name)[WR_NAME_MAX + 1];
static size_t   g_syn_n, g_syn_cap;
static uint32_t *g_syn_hash;             /* open addressing: index + 1, 0 empty */
static size_t   g_syn_hcap;

static uint32_t syn_fnv(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) h = (h ^ (uint8_t)*s) * 16777619u;
    return h;
}

/* The slot of name in the hash (holding it, or empty where it would go). */
static size_t syn_slot(const char *name) {
    size_t m = g_syn_hcap - 1, k = syn_fnv(name) & m;
    while (g_syn_hash[k] && strcmp(g_syn_name[g_syn_hash[k] - 1], name)) k = (k + 1) & m;
    return k;
}

static bool syn_is_addr(const wr_ip_t *ip) {
    if (!g_syn_on || ip->fam != 4) return false;
    uint32_t v = (uint32_t)ip->a[0] << 24 | (uint32_t)ip->a[1] << 16 | (uint32_t)ip->a[2] << 8 | ip->a[3];
    return (v & 0xfffe0000u) == SYN_BASE;
}

/* The ports host rules name (as stub_name_rule reads them), the proxied
 * ports, and one port in neither: is name allowed on some proxied port and on
 * no other? (A glob over ports is not expanded; the port in neither stands
 * for the ports it covers, so a name a glob allows off the proxied ports is
 * not synthetic: the safe side, it keeps its real addresses and every connect
 * is decided as before.) */
static bool syn_qualifies(const struct policy *p, const char *name) {
    if (!g_syn_on) return false;
    static const unsigned dflt[2] = { 80, 443 };
    const unsigned *pp = p->v.proxy_nports ? p->v.proxy_ports : dflt;
    size_t npp = p->v.proxy_nports ? p->v.proxy_nports : 2;
    /* the ports host rules name, as stub_name_rule collects them (up to 63
     * distinct), then the proxied ports not among them */
    unsigned ports[64 + VDP_PROXY_MAX_PORTS + 1];
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
    for (size_t j = 0; j < npp; j++) {
        bool dup = false;
        for (size_t k = 0; k < np; k++) if (ports[k] == pp[j]) dup = true;
        if (!dup) ports[np++] = pp[j];
    }
    unsigned other = 1;
    for (bool clash = true; clash && other < 65535; ) {
        clash = false;
        for (size_t k = 0; k < np; k++) if (ports[k] == other) { clash = true; other++; break; }
    }
    ports[np++] = other;
    bool proxied_ok = false;
    for (size_t k = 0; k < np; k++) {
        char s[WR_NAME_MAX + 8];
        snprintf(s, sizeof s, "%s:%u", name, ports[k]);
        int ri;
        vdp_why_t why;
        if (vdp_decide(&p->v, VDP_KIND_HOST, s, 0, false, &ri, &why) != VDP_SATISFIED || ri < 0) continue;
        bool proxied = false;
        for (size_t j = 0; j < npp; j++) if (pp[j] == ports[k]) proxied = true;
        if (!proxied) return false;                    /* allowed off the proxied ports */
        proxied_ok = true;
    }
    return proxied_ok;
}

/* The synthetic address of name, given one now if it has none (a record).
 * 0, or -1 (the space is used up, or no memory). */
static int syn_assign(const char *name, int line, wr_ip_t *out) {
    if (!g_syn_hcap) {
        g_syn_hcap = 1024;
        g_syn_hash = calloc(g_syn_hcap, sizeof *g_syn_hash);
        if (!g_syn_hash) { g_syn_hcap = 0; return -1; }
    }
    size_t k = syn_slot(name);
    uint32_t ix;
    bool fresh = false;
    if (g_syn_hash[k]) ix = g_syn_hash[k] - 1;
    else {
        if (g_syn_n >= SYN_MAX) return -1;
        if (g_syn_n == g_syn_cap) {
            size_t nc = g_syn_cap ? g_syn_cap * 2 : 256;
            void *nn = realloc(g_syn_name, nc * sizeof *g_syn_name);
            if (!nn) return -1;
            g_syn_name = nn;
            g_syn_cap = nc;
        }
        if (2 * (g_syn_n + 1) > g_syn_hcap) {          /* grow: rehash every name */
            size_t nh = g_syn_hcap * 2;
            uint32_t *h = calloc(nh, sizeof *h);
            if (!h) return -1;
            free(g_syn_hash);
            g_syn_hash = h;
            g_syn_hcap = nh;
            for (size_t j = 0; j < g_syn_n; j++) g_syn_hash[syn_slot(g_syn_name[j])] = (uint32_t)j + 1;
            k = syn_slot(name);
        }
        ix = (uint32_t)g_syn_n++;
        snprintf(g_syn_name[ix], sizeof g_syn_name[ix], "%s", name);
        g_syn_hash[k] = ix + 1;
        fresh = true;
    }
    uint32_t v = SYN_BASE + ix + 1;
    memset(out, 0, sizeof *out);
    out->fam = 4;
    out->a[0] = (uint8_t)(v >> 24); out->a[1] = (uint8_t)(v >> 16);
    out->a[2] = (uint8_t)(v >> 8);  out->a[3] = (uint8_t)v;
    if (fresh) {
        char a[INET6_ADDRSTRLEN];
        wr_ip_str(out, a, sizeof a);
        FILE *f = rec_begin();
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        fprintf(f, "{\"event\":\"synthetic_address\",\"run\":\"%s\",\"name\":\"%s\",\"address\":\"%s\","
                   "\"policy_line\":%d,\"timestamp_ns\":%lld}\n",
                g_run_id, name, a, line, (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
        rec_end(NULL);
    }
    return 0;
}

/* The hosts view with the proxy on: as wr_hosts_view, but a name allowed only
 * on proxied ports is listed once, with its synthetic address (left out if
 * the space is used up). */
static void syn_hosts_view(const struct policy *p, FILE *f) {
    fputs("127.0.0.1 localhost\n::1 localhost\n", f);
    char a[INET6_ADDRSTRLEN];
    for (size_t i = 0; i < g_names.n; i++) {
        const wr_entry_t *e = &g_names.e[i];
        if (e->dynamic || e->unlisted) continue;
        int ri = stub_name_rule(p, e->name);
        if (ri >= 0 && syn_qualifies(p, e->name)) {
            wr_ip_t ip;
            if (syn_assign(e->name, p->v.rules[ri].line, &ip) == 0) {
                wr_ip_str(&ip, a, sizeof a);
                fprintf(f, "%s %s\n", a, e->name);
            }
            continue;
        }
        for (int fam = 4; fam <= 6; fam += 2)
            for (size_t k = 0; k < e->n; k++) {
                if (e->addrs[k].until_ms != 0 || e->addrs[k].ip.fam != fam) continue;
                wr_ip_str(&e->addrs[k].ip, a, sizeof a);
                fprintf(f, "%s %s\n", a, e->name);
            }
    }
}
