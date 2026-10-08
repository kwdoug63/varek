/* ---------------- v1.26: the Warden's decisions for the proxy (plan step 6) ----------------
 *
 * docs/security/v1.26-egress-proxy.md, "Implementation plan", step 6.
 * Included by warden.c after warden_synth.inc.c.
 *
 * The proxy reports what a handed-off connection asks for: a kind (tls, http,
 * connect), a host name and a port (WP_MSG_REQUEST). The Warden:
 *
 *   1. decides name:port with the decision procedure, and has the
 *      certificate checker accept the certificate, as for a connect;
 *   2. finds the name's addresses in the resolution table. An exact name is
 *      there (resolved at startup, refreshed at its TTL); a name a wildcard
 *      rule allows is added when first asked for, and every lookup sent
 *      upstream for it is charged to that rule's budgets as the stub charges
 *      a question (a dns_question record with "transport":"proxy");
 *   3. dials the first address it may: not a special address (loopback,
 *      link-local, metadata, ...), not a synthetic one, and not one a rule
 *      denies (decided as addr:port); IPv4 first, each for up to PX_DIAL_MS,
 *      at most PX_MAX_TRIES of them, without blocking (a dial waits in the
 *      supervise loop);
 *   4. passes the connected socket to the proxy (SCM_RIGHTS, WP_MSG_VERDICT
 *      allow), which sends what the client sent and then relays both ways;
 *      or answers allow 0, and the proxy refuses the client.
 *
 * Each request is one record, written when its outcome is known:
 *   "action":"net.proxy", "target" and "resolved" name:port, the decision and
 *   its certificate, "proxy_conn" (the hand-off's id), "proxy_kind", and,
 *   once dialed, "dialed" (addr:port). Rules: proxy_dialed (ALLOW, passed to
 *   the proxy), proxy_dial_failed (ALLOW, nothing could be reached),
 *   policy_match / default_deny_unknown (refused by the policy),
 *   certificate_refused, wildcard_budget (a budget would be exceeded),
 *   resolution_failed (no address), address_refused (every address special,
 *   synthetic or denied). */

#define PX_MAX_DIAL   64                 /* requests waiting on a lookup or a dial */
#define PX_DIAL_MS    5000               /* per address */
#define PX_MAX_TRIES  4                  /* addresses tried per request */
#define PX_LOOKUP_MS  15000              /* a lookup the resolver helper has not answered */

struct px_req {
    bool          used;
    uint64_t      id;
    uint32_t      kind;                  /* pp_kind_t */
    char          name[WR_NAME_MAX + 1];
    unsigned      port;
    bool          up;                    /* section 5: dialed to the upstream proxy */
    unsigned      dport;                 /* the port dialed (port, or the upstream's) */
    int           entry;                 /* in g_names (the upstream's: -1 for an address) */
    int           sock;                  /* the dial in progress, or -1 (waiting on the lookup) */
    int           tries;
    int64_t       deadline;              /* this dial's, or the lookup's (monotonic ms) */
    wr_ip_t       tried[PX_MAX_TRIES];
    struct timespec t0;
    struct action *a;                    /* the record being built */
};
static struct px_req g_px[PX_MAX_DIAL];

/* v1.26 review: each hand-off's state, by its id: 1 announced to the proxy
 * (with the port the agent connected to), 2 reported on. The proxy may
 * report on a hand-off once, so it can never make the Warden decide or dial
 * one twice. */
static uint8_t  *g_ho_state;
static uint16_t *g_ho_port;
static size_t    g_ho_cap;

static void px_handed_off(uint64_t id, unsigned port) {
    if (id >= g_ho_cap) {
        size_t nc = g_ho_cap ? g_ho_cap * 2 : 1024;
        while (nc <= id) nc *= 2;
        uint8_t *st = realloc(g_ho_state, nc);
        if (!st) return;                         /* not recorded: its report is refused */
        g_ho_state = st;
        uint16_t *pt = realloc(g_ho_port, nc * sizeof *pt);
        if (!pt) return;
        g_ho_port = pt;
        memset(g_ho_state + g_ho_cap, 0, nc - g_ho_cap);
        g_ho_cap = nc;
    }
    g_ho_state[id] = 1;
    g_ho_port[id] = (uint16_t)port;
}

/* Step 7: the connections passed to the proxy and not yet closed, and when
 * each was passed (monotonic ms). */
struct px_open { uint64_t id; int64_t at; };
static struct px_open *g_px_open;
static size_t g_px_nopen, g_px_capopen;

static void px_open_add(uint64_t id) {
    if (g_px_nopen == g_px_capopen) {
        size_t nc = g_px_capopen ? g_px_capopen * 2 : 64;
        struct px_open *o = realloc(g_px_open, nc * sizeof *o);
        if (!o) return;                  /* not tracked: its close is then refused as unknown */
        g_px_open = o;
        g_px_capopen = nc;
    }
    g_px_open[g_px_nopen++] = (struct px_open){ id, wr_now_ms() };
}

/* The proxy_close record (step 7), chained like a resolution record:
 *   {"event":"proxy_close","run":R,"proxy_conn":N,"why":"closed|reset|idle|
 *    run_end|unreported","bytes_up":U,"bytes_down":D,"relay_ms":M,
 *    "timestamp_ns":TS}
 * The byte counts and relay_ms are the proxy's report ("unreported": the
 * proxy never said, and they are absent). */
static void px_close_record(uint64_t id, const char *why, const struct wp_close *m) {
    FILE *f = rec_begin();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(f, "{\"event\":\"proxy_close\",\"run\":\"%s\",\"proxy_conn\":%llu,\"why\":\"%s\",",
            g_run_id, (unsigned long long)id, why);
    if (m) fprintf(f, "\"bytes_up\":%llu,\"bytes_down\":%llu,\"relay_ms\":%llu,",
                   (unsigned long long)m->bytes_up, (unsigned long long)m->bytes_down,
                   (unsigned long long)m->ms);
    if (m && !strcmp(why, "upstream_refused"))           /* section 5: what the upstream answered */
        fprintf(f, "\"upstream_status\":%u,", m->upstream_status);
    fprintf(f, "\"timestamp_ns\":%lld}\n", (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    rec_end(NULL);
}

/* A close report: 0, or -1 (not a connection passed to the proxy and still
 * open, or a malformed report: the proxy is not behaving). */
static int px_closed(const struct wp_close *m) {
    static const char *const kWhy[] = { "closed", "reset", "idle", "run_end", "upstream_refused",
                                         "refused_request", "client_gone" };
    bool ok = false;
    if (!memchr(m->why, 0, sizeof m->why)) return -1;
    for (size_t k = 0; k < sizeof kWhy / sizeof *kWhy; k++) if (!strcmp(m->why, kWhy[k])) ok = true;
    if (!ok) return -1;
    for (size_t k = 0; k < g_px_nopen; k++)
        if (g_px_open[k].id == m->id) {
            g_px_open[k] = g_px_open[--g_px_nopen];
            px_close_record(m->id, m->why, m);
            return 0;
        }
    return -1;
}

static void px_record(struct px_req *q, decision_t d_raw, decision_t d_final, const char *rule, int err) {
    size_t el = strlen(q->a->extra);
    snprintf(q->a->extra + el, sizeof q->a->extra - el, "\"proxy_conn\":%llu,\"proxy_kind\":\"%s\",",
             (unsigned long long)q->id, pp_kind_name((pp_kind_t)q->kind));
    if (q->up) {                                         /* section 5: the upstream used */
        el = strlen(q->a->extra);
        snprintf(q->a->extra + el, sizeof q->a->extra - el, "\"upstream\":\"%s:%u\",",
                 g_syn_p->v.proxy_up_host, g_syn_p->v.proxy_up_port);
    }
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    emit_pathology(g_report_seq++, 0, q->a, d_raw, d_final, rule, ns_between(&q->t0, &t1), err);
}

static void px_free(struct px_req *q) {
    if (q->sock >= 0) close(q->sock);
    free(q->a);
    memset(q, 0, sizeof *q);
    q->sock = -1;
}

/* Refuse request q (the proxy refuses the client) and record it. */
static void px_refuse(struct px_req *q, decision_t d_raw, const char *rule, int err) {
    (void)wp_verdict(&g_proxy, q->id, false);
    px_record(q, d_raw, DEC_DENY, rule, err);
    px_free(q);
}

/* Pass the connected socket s to the proxy for request q. */
static int px_pass(uint64_t id, int s) {
    struct wp_verdict m = { .type = WP_MSG_VERDICT, .allow = 1, .id = id };
    union { char b[CMSG_SPACE(sizeof(int))]; struct cmsghdr al; } cb;
    memset(&cb, 0, sizeof cb);
    struct iovec v = { &m, sizeof m };
    struct msghdr mh = { .msg_iov = &v, .msg_iovlen = 1, .msg_control = cb.b, .msg_controllen = sizeof cb.b };
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &s, sizeof s);
    return sendmsg(g_proxy.ctl, &mh, MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)sizeof m ? 0 : -1;
}

/* Section 5: pass the socket dialed to the upstream proxy, with the name and
 * port the proxy is to ask it for (CONNECT). */
static int px_pass_up(uint64_t id, int s, const char *name, unsigned port) {
    struct wp_verdict_up m;
    memset(&m, 0, sizeof m);
    m.type = WP_MSG_VERDICT_UP;
    m.allow = 1;
    m.id = id;
    m.port = port;
    snprintf(m.name, sizeof m.name, "%s", name);
    union { char b[CMSG_SPACE(sizeof(int))]; struct cmsghdr al; } cb;
    memset(&cb, 0, sizeof cb);
    struct iovec v = { &m, sizeof m };
    struct msghdr mh = { .msg_iov = &v, .msg_iovlen = 1, .msg_control = cb.b, .msg_controllen = sizeof cb.b };
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &s, sizeof s);
    return sendmsg(g_proxy.ctl, &mh, MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)sizeof m ? 0 : -1;
}

/* Section 5: names a wildcard allows that were sent to the upstream, each
 * charged once to the wildcard's names budget (the upstream resolves them). */
static char (*g_up_names)[WR_NAME_MAX + 1];
static size_t g_up_nnames;

static bool px_up_charged(const char *name) {
    for (size_t k = 0; k < g_up_nnames; k++) if (!strcmp(g_up_names[k], name)) return true;
    return false;
}

/* The next address of q's entry to dial, or false. Counts what was passed
 * over, so the record can say why none was dialed. */
static bool px_next_addr(const struct policy *p, struct px_req *q, wr_ip_t *out, int *nskipped) {
    if (q->up && q->entry < 0) {                       /* an upstream given as an address */
        if (q->tries) return false;
        *out = g_up_ip;
        return true;
    }
    const wr_entry_t *e = &g_names.e[q->entry];
    for (int fam = 4; fam <= 6; fam += 2)
        for (size_t k = 0; k < e->n; k++) {
            const wr_ip_t *ip = &e->addrs[k].ip;
            if (e->addrs[k].until_ms != 0 || ip->fam != fam) continue;
            bool done = false;
            for (int t = 0; t < q->tries; t++)
                if (!memcmp(&q->tried[t], ip, sizeof *ip)) done = true;
            if (done) continue;
            if (syn_is_addr(ip)) { (*nskipped)++; continue; }
            /* the upstream is the operator's: it may be on loopback or a
             * private address, and no rule is asked about it */
            if (q->up) { *out = *ip; return true; }
            if (wr_special_address(ip)) { (*nskipped)++; continue; }
            /* a rule that denies the address itself holds (decided as addr:port) */
            struct action na;
            memset(&na, 0, sizeof na);
            na.kind = ACT_NET_CONNECT;
            char at[INET6_ADDRSTRLEN];
            wr_ip_str(ip, at, sizeof at);
            snprintf(na.resolved, sizeof na.resolved, fam == 6 ? "[%s]:%u" : "%s:%u", at, q->dport);
            if (policy_decide(p, &na) == DEC_DENY && na.rule_index >= 0) { (*nskipped)++; continue; }
            *out = *ip;
            return true;
        }
    return false;
}

/* Dial q's next address, or finish q if there is none. */
static void px_dial(const struct policy *p, struct px_req *q) {
    for (;;) {
        wr_ip_t ip;
        int skipped = 0;
        if (q->tries >= PX_MAX_TRIES || !px_next_addr(p, q, &ip, &skipped)) {
            (void)wp_verdict(&g_proxy, q->id, false);
            if (q->tries) px_record(q, DEC_ALLOW, DEC_ALLOW, "proxy_dial_failed", ECONNREFUSED);
            else px_record(q, DEC_ALLOW, DEC_DENY, skipped ? "address_refused" : "resolution_failed", EACCES);
            px_free(q);
            return;
        }
        q->tried[q->tries++] = ip;
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof ss);
        socklen_t sl;
        char at[INET6_ADDRSTRLEN];
        wr_ip_str(&ip, at, sizeof at);
        if (ip.fam == 4) {
            struct sockaddr_in *d = (struct sockaddr_in *)&ss;
            d->sin_family = AF_INET;
            d->sin_port = htons((uint16_t)q->dport);
            memcpy(&d->sin_addr, ip.a, 4);
            sl = sizeof *d;
        } else {
            struct sockaddr_in6 *d = (struct sockaddr_in6 *)&ss;
            d->sin6_family = AF_INET6;
            d->sin6_port = htons((uint16_t)q->dport);
            memcpy(&d->sin6_addr, ip.a, 16);
            sl = sizeof *d;
        }
        size_t el = strlen(q->a->extra);
        /* the last address tried is the one the record names */
        char *dp = strstr(q->a->extra, "\"dialed\":");
        if (dp) { *dp = '\0'; el = strlen(q->a->extra); }
        snprintf(q->a->extra + el, sizeof q->a->extra - el, ip.fam == 6 ? "\"dialed\":\"[%s]:%u\"," :
                 "\"dialed\":\"%s:%u\",", at, q->dport);
        int s = socket(ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (s < 0) continue;
        if (connect(s, (struct sockaddr *)&ss, sl) == 0 || errno == EINPROGRESS) {
            q->sock = s;
            q->deadline = wr_now_ms() + PX_DIAL_MS;
            return;
        }
        close(s);
    }
}

/* The dial of q finished (so_error 0: connected). */
static void px_dialed(const struct policy *p, struct px_req *q, int so_error) {
    if (so_error) {
        close(q->sock);
        q->sock = -1;
        px_dial(p, q);
        return;
    }
    if ((q->up ? px_pass_up(q->id, q->sock, q->name, q->port) : px_pass(q->id, q->sock)) < 0) {
        (void)wp_verdict(&g_proxy, q->id, false);
        px_record(q, DEC_ALLOW, DEC_ALLOW, "proxy_dial_failed", EIO);
    } else {
        px_record(q, DEC_ALLOW, DEC_ALLOW, "proxy_dialed", 0);
        px_open_add(q->id);              /* step 7: its proxy_close follows */
    }
    px_free(q);
}

/* Entry q->entry has addresses to use, or a lookup to wait for. */
static void px_resolve(const struct policy *p, struct px_req *q) {
    const wr_entry_t *e = &g_names.e[q->entry];
    bool fresh = !e->dynamic || wr_entry_fresh(e, wr_now_ms());
    bool have = false;
    for (size_t k = 0; k < e->n; k++) if (e->addrs[k].until_ms == 0) have = true;
    if (fresh && (have || !e->pending)) { px_dial(p, q); return; }
    q->deadline = wr_now_ms() + PX_LOOKUP_MS;          /* waits for px_resolved */
}

/* A request from the proxy. */
/* v1.26.1: is name a passthrough host (kept in SNI mode)? */
static bool px_passthrough(const struct policy *p, const char *name) {
    for (size_t k = 0; k < p->v.proxy_npass; k++) if (!strcmp(p->v.proxy_pass[k], name)) return true;
    return false;
}

static void px_request(const struct policy *p, const struct wp_req *m) {
    struct px_req *q = NULL;
    for (int k = 0; k < PX_MAX_DIAL; k++) if (!g_px[k].used) { q = &g_px[k]; break; }
    struct action *a = calloc(1, sizeof *a);
    if (!q || !a) {
        free(a);
        (void)wp_verdict(&g_proxy, m->id, false);
        log_line_start();
        fprintf(g_log, "[warden] proxy: connection %llu refused: %d requests already waiting\n",
                (unsigned long long)m->id, PX_MAX_DIAL);
        return;
    }
    memset(q, 0, sizeof *q);
    q->used = true;
    q->id = m->id;
    q->kind = m->kind;
    q->port = q->dport = m->port;
    q->sock = -1;
    q->entry = -1;
    q->a = a;
    snprintf(q->name, sizeof q->name, "%s", m->name);
    clock_gettime(CLOCK_MONOTONIC, &q->t0);
    a->kind = ACT_NET_PROXY;
    a->policy_line = -1;
    snprintf(a->target, sizeof a->target, "%s:%u", q->name, q->port);
    snprintf(a->resolved, sizeof a->resolved, "%s:%u", q->name, q->port);
    decision_t d_raw = policy_decide(p, a);
    if (d_raw != DEC_ALLOW) { px_refuse(q, d_raw, decision_rule_id(a, d_raw), EACCES); return; }
    if (!certify(p, a)) {
        log_line_start();
        fprintf(g_log, "[warden] certificate refused (record seq %" PRIu64 "): %s\n", g_records, a->check_why);
        px_refuse(q, d_raw, "certificate_refused", EACCES);
        return;
    }
    /* v1.26.1 (until step 6 decides each request): in inspecting mode, a
     * connection to a host that is not a passthrough host is refused, not
     * relayed in SNI mode, which would let through requests the request
     * rules refuse. Passthrough hosts are SNI mode by design. */
    if (p->v.proxy_inspect && !px_passthrough(p, q->name)) {
        px_refuse(q, d_raw, "inspect_not_built", EACCES);
        return;
    }
    int i = wr_table_find(&g_names, q->name);
    if (i >= 0 && g_names.e[i].unlisted) i = -1;         /* only a deny rule names it */
    if (p->v.proxy_up_port) {
        /* Section 5: decided here, dialed to the customer's proxy, which
         * resolves the name. A name only a wildcard allows is charged to
         * that wildcard's budgets once (recorded as a question answered
         * "upstream"); nothing is looked up here. */
        if (i < 0 || g_names.e[i].dynamic) {
            /* v1.26 review: charged once, whether first by the stub (a
             * dynamic entry) or here */
            bool seen = i >= 0 || px_up_charged(q->name);
            if (!seen) {
                stub_budget_init(p);
                g_stub_now = wr_now_ms();
                int ri = stub_name_rule(p, q->name);
                int line = ri >= 0 ? p->v.rules[ri].line : -1;
                struct stub_budget *bud = ri >= 0 && p->v.rules[ri].s.wild ? stub_budget_of(ri) : NULL;
                const char *over = ri >= 0 && p->v.rules[ri].s.wild && g_up_nnames < STUB_MAX_DYN
                                   ? stub_charge(bud, q->name, g_stub_now, true) : "names";
                if (over) {
                    stub_record(q->name, 1, -2, "wildcard_budget", line, over, 0, "nxdomain", NULL);
                    px_refuse(q, d_raw, "wildcard_budget", EACCES);
                    return;
                }
                void *nn = realloc(g_up_names, (g_up_nnames + 1) * sizeof *g_up_names);
                if (nn) {
                    g_up_names = nn;
                    snprintf(g_up_names[g_up_nnames++], sizeof *g_up_names, "%s", q->name);
                }
                stub_record(q->name, 1, -2, "policy_match", line, NULL, STUB_NEW, "upstream", NULL);
            }
        }
        q->up = true;
        q->dport = p->v.proxy_up_port;
        q->entry = g_up_entry;
        if (q->entry < 0) { px_dial(p, q); return; }
        i = q->entry;
        const wr_entry_t *e = &g_names.e[i];
        bool have = false;
        for (size_t k = 0; k < e->n; k++) if (e->addrs[k].until_ms == 0) have = true;
        if (!have && !e->pending && wr_async_request(&g_names, (size_t)i) < 0) {
            px_refuse(q, d_raw, "resolution_failed", EACCES);
            return;
        }
        px_resolve(p, q);
        return;
    }
    if (i >= 0 && !g_names.e[i].dynamic) {                /* an exact name */
        q->entry = i;
        const wr_entry_t *e = &g_names.e[i];
        bool have = false;
        for (size_t k = 0; k < e->n; k++) if (e->addrs[k].until_ms == 0) have = true;
        if (!have && !e->pending && wr_async_request(&g_names, (size_t)i) < 0) {
            px_refuse(q, d_raw, "resolution_failed", EACCES);
            return;
        }
        px_resolve(p, q);
        return;
    }
    /* A name a wildcard allows: looked up through the resolver helper, each
     * lookup sent upstream charged to the wildcard rule as the stub charges a
     * question (warden_stub.inc.c), and recorded as one. */
    stub_budget_init(p);
    g_stub_now = wr_now_ms();
    int ri = stub_name_rule(p, q->name);
    int line = ri >= 0 ? p->v.rules[ri].line : -1;
    struct stub_budget *bud = ri >= 0 && p->v.rules[ri].s.wild ? stub_budget_of(ri) : NULL;
    if (ri < 0 || !p->v.rules[ri].s.wild) { px_refuse(q, d_raw, "resolution_failed", EACCES); return; }
    bool isnew = i < 0;
    if (isnew) {
        const char *over = stub_charge(bud, q->name, g_stub_now, true);
        if (over) {
            stub_record(q->name, 1, -2, "wildcard_budget", line, over, 0, "nxdomain", NULL);
            px_refuse(q, d_raw, "wildcard_budget", EACCES);
            return;
        }
        if (g_stub_dyn >= STUB_MAX_DYN || (i = wr_table_add_dynamic(&g_names, q->name)) < 0) {
            stub_uncharge(bud, true);
            px_refuse(q, d_raw, "resolution_failed", EACCES);
            return;
        }
        g_stub_dyn++;
    }
    q->entry = i;
    const wr_entry_t *e = &g_names.e[i];
    if (!isnew && wr_entry_fresh(e, g_stub_now)) { px_resolve(p, q); return; }
    bool send_up = !e->pending;
    if (send_up && !isnew) {
        const char *over = stub_charge(bud, q->name, g_stub_now, false);
        if (over) {
            stub_record(q->name, 1, -2, "wildcard_budget", line, over, 0, "nxdomain", NULL);
            px_refuse(q, d_raw, "wildcard_budget", EACCES);
            return;
        }
    }
    if (send_up && wr_async_request(&g_names, (size_t)i) < 0) {
        stub_uncharge(bud, isnew);
        stub_record(q->name, 1, -2, "policy_match", line, NULL, isnew ? STUB_NEW : 0, "servfail", NULL);
        px_refuse(q, d_raw, "resolution_failed", EACCES);
        return;
    }
    stub_record(q->name, 1, -2, "policy_match", line, NULL,
                (isnew ? STUB_NEW : 0) | (send_up ? STUB_UPSTREAM : 0), "lookup", NULL);
    q->deadline = wr_now_ms() + PX_LOOKUP_MS;
}

/* The resolver helper answered entry i (emit_resolution). */
static void px_resolved(size_t i) {
    if (!g_syn_p) return;
    for (int k = 0; k < PX_MAX_DIAL; k++)
        if (g_px[k].used && g_px[k].sock < 0 && g_px[k].entry == (int)i) px_dial(g_syn_p, &g_px[k]);
}

/* ---- the supervise loop ---- */

static int px_poll_fill(struct pollfd *pfds) {
    int n = 0;
    for (int k = 0; k < PX_MAX_DIAL; k++)
        pfds[n++] = (struct pollfd){ .fd = g_px[k].used ? g_px[k].sock : -1, .events = POLLOUT };
    return n;
}

static int px_timeout_ms(void) {
    int64_t now = wr_now_ms(), best = -1;
    for (int k = 0; k < PX_MAX_DIAL; k++)
        if (g_px[k].used && (best < 0 || g_px[k].deadline < best)) best = g_px[k].deadline;
    if (best < 0) return -1;
    return best <= now ? 0 : (int)(best - now);
}

static void px_service(const struct policy *p, const struct pollfd *pfds, int n) {
    int64_t now = wr_now_ms();
    for (int k = 0; k < n && k < PX_MAX_DIAL; k++) {
        struct px_req *q = &g_px[k];
        if (!q->used) continue;
        if (q->sock >= 0 && (pfds[k].revents & (POLLOUT | POLLERR | POLLHUP))) {
            int so = 0;
            socklen_t l = sizeof so;
            if (getsockopt(q->sock, SOL_SOCKET, SO_ERROR, &so, &l) < 0) so = errno;
            px_dialed(p, q, so);
        } else if (q->sock >= 0 && now >= q->deadline) {
            px_dialed(p, q, ETIMEDOUT);
        } else if (q->sock < 0 && now >= q->deadline) {
            px_dial(p, q);                               /* no answer: whatever the table holds */
        }
    }
}

static bool g_px_flushed = false;

/* The proxy's reports (WP_MSG_REQUEST, WP_MSG_UNREADABLE, and, step 7,
 * WP_MSG_CLOSED and WP_MSG_FLUSHED). A report that is
 * not well formed means the proxy is not behaving: -1, and the run stops. */
static int proxy_service(const struct policy *p) {
    for (;;) {
        union { struct wp_req r; struct wp_close c; struct wp_msg f; uint32_t type; } u;
        ssize_t n = recv(g_proxy.ctl, &u, sizeof u, MSG_DONTWAIT);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
        if (n <= 0) return -1;                                  /* the proxy is gone */
        if (n == (ssize_t)sizeof u.c && u.type == WP_MSG_CLOSED) {
            if (px_closed(&u.c) < 0) return -1;
            continue;
        }
        if (n == (ssize_t)sizeof u.f && u.type == WP_MSG_FLUSHED) { g_px_flushed = true; continue; }
        struct wp_req m;
        if (n != (ssize_t)sizeof m) return -1;
        memcpy(&m, &u.r, sizeof m);
        if (n != (ssize_t)sizeof m || (m.type != WP_MSG_REQUEST && m.type != WP_MSG_UNREADABLE) ||
            m.kind > PP_KIND_CONNECT || m.id == 0 || m.id > g_proxy_conns ||
            !memchr(m.name, 0, sizeof m.name) || !memchr(m.why, 0, sizeof m.why))
            return -1;
        /* v1.26 review: one report per hand-off, and (TLS, HTTP) on the port
         * the agent connected to; anything else and the proxy is not
         * behaving */
        if (m.id >= g_ho_cap || g_ho_state[m.id] != 1) return -1;
        if (m.type == WP_MSG_REQUEST && m.kind != PP_KIND_CONNECT && m.port != g_ho_port[m.id]) return -1;
        g_ho_state[m.id] = 2;
        if (m.type == WP_MSG_REQUEST) {
            char why[8];
            if (m.port == 0 || m.port > 65535 || m.kind == PP_KIND_NONE ||
                vdp_host_name_form(m.name, strlen(m.name), why, sizeof why) != 1)
                return -1;
            px_request(p, &m);
        } else {
            for (char *c = m.why; *c; c++) if (*c < ' ' || *c > '~' || *c == '"' || *c == '\\') *c = '?';
            log_line_start();
            fprintf(g_log, "[warden] proxy: connection %llu (%s) refused by the proxy: %s\n",
                    (unsigned long long)m.id, pp_kind_name((pp_kind_t)m.kind), m.why);
        }
    }
}

/* Step 7: the run is ending (emit_run_end). Requests still waiting on a
 * lookup or a dial are refused (rule run_ended); the proxy closes every
 * connection and reports each relayed one, within 2 s; a relay it never
 * reported is recorded "unreported". So every proxy_dialed has one
 * proxy_close in a complete stream. */
static void px_finish(void) {
    for (int k = 0; k < PX_MAX_DIAL; k++)
        if (g_px[k].used) px_refuse(&g_px[k], DEC_ALLOW, "run_ended", EACCES);
    if (g_proxy.ctl >= 0 && g_px_nopen) {
        struct wp_msg f = { .type = WP_MSG_FLUSH, .port = 0 };
        /* v1.26 review: never blocks (a proxy that stopped reading would
         * hold the run's end); on failure every open relay is unreported */
        if (send(g_proxy.ctl, &f, sizeof f, MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)sizeof f) {
            int64_t until = wr_now_ms() + 2000;
            g_px_flushed = false;
            while (!g_px_flushed && wr_now_ms() < until) {
                struct pollfd pf = { .fd = g_proxy.ctl, .events = POLLIN };
                int64_t left = until - wr_now_ms();
                if (poll(&pf, 1, left > 0 ? (int)left : 0) <= 0) break;
                if (proxy_service(g_syn_p) < 0) break;
            }
        }
    }
    for (int k = 0; k < PX_MAX_DIAL; k++)      /* any the proxy sent while flushing */
        if (g_px[k].used) px_refuse(&g_px[k], DEC_ALLOW, "run_ended", EACCES);
    while (g_px_nopen) {
        uint64_t id = g_px_open[--g_px_nopen].id;
        px_close_record(id, "unreported", NULL);
    }
}
