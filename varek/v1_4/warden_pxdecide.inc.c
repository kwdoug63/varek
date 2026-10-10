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
    bool          inspect;               /* v1.26.1: the proxy terminates its TLS */
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
struct px_open {
    uint64_t id;
    int64_t  at;
    bool     inspect;
    /* v1.26.1, step 6: an inspected connection's requests */
    char     scheme[6];                  /* https, or http (plain HTTP) */
    char     name[WR_NAME_MAX + 1];
    unsigned port;
    uint64_t next_seq;                   /* the next request's seq (from 1) */
    uint64_t body_seq;                   /* an allowed request whose body is still to be reported (0: none) */
    uint64_t max_body;                   /* its rule's max_body (0: none) */
    uint32_t body_kind;                  /* review: its framing (WP_BODY_*), and the length declared */
    uint64_t body_declared;
    bool     refused;                    /* a request was refused: no more come */
    bool     allowed;                    /* some request was allowed (so bytes may pass) */
    bool     cut;                        /* a body passed max_body */
};
static struct px_open *g_px_open;
static size_t g_px_nopen, g_px_capopen;

static void px_open_add(uint64_t id, bool inspect, const struct px_req *q) {
    if (g_px_nopen == g_px_capopen) {
        size_t nc = g_px_capopen ? g_px_capopen * 2 : 64;
        struct px_open *o = realloc(g_px_open, nc * sizeof *o);
        if (!o) return;                  /* not tracked: its close is then refused as unknown */
        g_px_open = o;
        g_px_capopen = nc;
    }
    struct px_open o = { .id = id, .at = wr_now_ms(), .inspect = inspect, .next_seq = 1 };
    if (q) {
        snprintf(o.scheme, sizeof o.scheme, "%s", q->kind == PP_KIND_HTTP ? "http" : "https");
        snprintf(o.name, sizeof o.name, "%s", q->name);
        o.port = q->port;
    }
    g_px_open[g_px_nopen++] = o;
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
    /* v1.26.1: an inspected connection: the server's certificate, and why a
     * handshake failed */
    if (m && m->inspected) {
        fprintf(f, "\"inspected\":true,\"requests\":%llu,", (unsigned long long)m->requests);
        static const uint8_t zero[32];
        if (memcmp(m->server_cert, zero, sizeof zero)) {
            char hx[65];
            sodium_bin2hex(hx, sizeof hx, m->server_cert, sizeof m->server_cert);
            fprintf(f, "\"server_cert_sha256\":\"%s\",", hx);
        }
        if (m->tls_why[0]) {
            /* step 5: a request the proxy's parser refused says why */
            fputs(!strcmp(why, "refused_request") ? "\"request_error\":\"" : "\"tls_error\":\"", f);
            json_escape(f, m->tls_why);
            fputs("\",", f);
        }
    }
    fprintf(f, "\"timestamp_ns\":%lld}\n", (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    rec_end(NULL);
}

/* A close report: 0, or -1 (not a connection passed to the proxy and still
 * open, or a malformed report: the proxy is not behaving). */
static int px_closed(const struct wp_close *m) {
    static const char *const kWhy[] = { "closed", "reset", "idle", "run_end", "upstream_refused",
                                         "refused_request", "client_gone",
                                         /* v1.26.1: an inspected connection only */
                                         "server_tls", "client_tls", "tls_timeout", "max_body" };
    bool ok = false;
    size_t wk = 0;
    if (!memchr(m->why, 0, sizeof m->why) || !memchr(m->tls_why, 0, sizeof m->tls_why)) return -1;
    for (size_t k = 0; k < sizeof kWhy / sizeof *kWhy; k++) if (!strcmp(m->why, kWhy[k])) { ok = true; wk = k; }
    if (!ok) return -1;
    for (const char *t = m->tls_why; *t; t++) if ((unsigned char)*t < 0x20 || *t == 0x7f) return -1;
    for (size_t k = 0; k < g_px_nopen; k++)
        if (g_px_open[k].id == m->id) {
            /* v1.26.1: the report says inspected exactly for a connection
             * passed on to be inspected; the TLS reasons are an inspected
             * one's; and until requests are decided (step 6) nothing was
             * sent to an inspected connection's server */
            if ((m->inspected != 0) != g_px_open[k].inspect || (wk >= 7 && !m->inspected) ||
                (m->inspected && !g_px_open[k].allowed && m->bytes_up != 0) ||
                (!strcmp(m->why, "max_body") != g_px_open[k].cut) ||
                /* step 7: the requests it counts are those it reported */
                m->requests != (m->inspected ? g_px_open[k].next_seq - 1 : 0) ||
                /* review: and every allowed body was reported before it */
                g_px_open[k].body_seq)
                return -1;
            g_px_open[k] = g_px_open[--g_px_nopen];
            px_close_record(m->id, m->why, m);
            return 0;
        }
    return -1;
}

static void px_record(struct px_req *q, decision_t d_raw, decision_t d_final, const char *rule, int err) {
    size_t el = strlen(q->a->extra);
    snprintf(q->a->extra + el, sizeof q->a->extra - el, "\"proxy_conn\":%llu,\"proxy_kind\":\"%s\",%s",
             (unsigned long long)q->id, pp_kind_name((pp_kind_t)q->kind),
             q->inspect ? "\"inspected\":true," : "");
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
static int px_pass(uint64_t id, int s, bool inspect) {
    struct wp_verdict m = { .type = WP_MSG_VERDICT, .allow = 1, .id = id, .inspect = inspect };
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
static int px_pass_up(uint64_t id, int s, const char *name, unsigned port, bool inspect) {
    struct wp_verdict_up m;
    memset(&m, 0, sizeof m);
    m.type = WP_MSG_VERDICT_UP;
    m.allow = 1;
    m.id = id;
    m.port = port;
    m.inspect = inspect;
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
    if ((q->up ? px_pass_up(q->id, q->sock, q->name, q->port, q->inspect)
               : px_pass(q->id, q->sock, q->inspect)) < 0) {
        (void)wp_verdict(&g_proxy, q->id, false);
        px_record(q, DEC_ALLOW, DEC_ALLOW, "proxy_dial_failed", EIO);
    } else {
        px_record(q, DEC_ALLOW, DEC_ALLOW, "proxy_dialed", 0);
        px_open_add(q->id, q->inspect, q);  /* step 7: its proxy_close follows */
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
    /* v1.26.1: in inspecting mode a host that is not a passthrough host is
     * inspected: the proxy terminates its TLS (TLS, and TLS inside an
     * answered CONNECT), or reads its plain HTTP, and each request is decided
     * here (px_httpreq) before a byte of it is sent. Passthrough hosts are
     * SNI mode by design. */
    if (p->v.proxy_inspect && !px_passthrough(p, q->name)) q->inspect = true;
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
/* v1.26.1, step 6: a request of an inspected connection. Decided on its
 * object with the decision procedure, certified by the checker, recorded
 * (net.request), and answered. 0, or -1 (a report the proxy should not have
 * sent: the run stops). */
/* v1.26.1 review: a request target (/path?query) in a form the proxy must
 * have refused (section 2: a server could read it as another path), as
 * proxy_parse.c's target_ok, written again here: the Warden does not take the
 * proxy's word for it. */
static bool px_target_ok(const char *t) {
    if (t[0] != '/') return false;
    bool query = false;
    const char *seg = t + 1;
    for (const char *c = t + 1;; c++) {
        bool in_query = query;                            /* the query had begun before this byte */
        if (!query && (*c == '/' || *c == '?' || *c == 0)) {
            size_t sl = (size_t)(c - seg);
            if (sl == 0 && *c == '/') return false;                              /* // */
            if ((sl == 1 && seg[0] == '.') || (sl == 2 && seg[0] == '.' && seg[1] == '.')) return false;
            seg = c + 1;
            if (*c == '?') query = true;
        }
        if (*c == 0) return true;
        unsigned char u = (unsigned char)*c;
        if (u < 0x21 || u > 0x7e || u == '\\' || u == ';' || u == '#') return false;
        if (u == '?' && in_query) return false;           /* review: a second '?' */
        if (u == '%') {
            int h1 = isxdigit((unsigned char)c[1]) ? (isdigit((unsigned char)c[1]) ? c[1] - '0' : (c[1] | 0x20) - 'a' + 10) : -1;
            int h2 = h1 >= 0 && isxdigit((unsigned char)c[2]) ?
                     (isdigit((unsigned char)c[2]) ? c[2] - '0' : (c[2] | 0x20) - 'a' + 10) : -1;
            if (h2 < 0) return false;
            int v = h1 * 16 + h2;
            if (v == '/' || v == '\\' || isalnum(v) || v == '-' || v == '.' || v == '_' || v == '~') return false;
        }
    }
}

static int px_httpreq(const struct policy *p, const struct wp_httpreq *m) {
    struct px_open *o = NULL;
    for (size_t k = 0; k < g_px_nopen; k++) if (g_px_open[k].id == m->id) o = &g_px_open[k];
    if (!o || !o->inspect || o->refused || o->cut || o->body_seq || m->seq != o->next_seq || m->body > WP_BODY_CHUNKED ||
        !memchr(m->object, 0, sizeof m->object))
        return -1;
    /* the object: METHOD scheme://name:port/..., the method 1 to 20 letters,
     * the rest the connection's, every byte printable (the proxy's parser
     * refused the rest) */
    const char *ob = m->object;
    size_t ml = 0, ol = strlen(ob);
    while (ob[ml] >= 'A' && ob[ml] <= 'Z') ml++;
    char pre[300];
    int pl = snprintf(pre, sizeof pre, " %s://%s:%u/", o->scheme, o->name, o->port);
    if (ml == 0 || ml > 20 || ol > VDP_STR_MAX || pl < 0 || strncmp(ob + ml, pre, (size_t)pl)) return -1;
    for (size_t i = ml + 1; i < ol; i++) if ((unsigned char)ob[i] < 0x21 || (unsigned char)ob[i] > 0x7e) return -1;
    if (!px_target_ok(ob + ml + pl - 1)) return -1;      /* review: a form the proxy must refuse */
    o->next_seq++;
    struct action *a = calloc(1, sizeof *a);
    if (!a) return -1;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    a->kind = ACT_NET_REQUEST;
    a->policy_line = -1;
    memcpy(a->target, ob, ol + 1);
    memcpy(a->resolved, ob, ol + 1);
    decision_t d_raw = policy_decide(p, a);
    decision_t d_final = d_raw == DEC_ALLOW ? DEC_ALLOW : DEC_DENY;
    const char *rule = d_raw == DEC_ALLOW ? "request_allowed" : decision_rule_id(a, d_raw);
    uint64_t maxb = 0;
    char why[96];
    if (d_final == DEC_ALLOW && !certify(p, a)) {
        d_final = DEC_DENY;
        rule = "certificate_refused";
        log_line_start();
        fprintf(g_log, "[warden] certificate refused (record seq %" PRIu64 "): %s\n", g_records, a->check_why);
    }
    if (d_final == DEC_ALLOW) {
        maxb = p->v.rules[a->rule_index].max_body;
        if (maxb && m->body == WP_BODY_LENGTH && m->body_len > maxb) {
            d_final = DEC_DENY;
            rule = "max_body";
        }
    }
    if (d_final == DEC_ALLOW) snprintf(why, sizeof why, "allowed");
    else if (!strcmp(rule, "max_body"))
        snprintf(why, sizeof why, "its body is over max_body=%llu (policy line %d)", (unsigned long long)maxb,
                 a->policy_line);
    else if (d_raw == DEC_DENY) snprintf(why, sizeof why, "the policy denies it (line %d)", a->policy_line);
    else snprintf(why, sizeof why, "no request rule allows it");
    static const char *const kBody[] = { "none", "length", "chunked" };
    snprintf(a->extra, sizeof a->extra, "\"proxy_conn\":%llu,\"request_seq\":%llu,\"body\":\"%s\",",
             (unsigned long long)m->id, (unsigned long long)m->seq, kBody[m->body]);
    if (m->body == WP_BODY_LENGTH) {
        size_t el = strlen(a->extra);
        snprintf(a->extra + el, sizeof a->extra - el, "\"body_declared\":%llu,", (unsigned long long)m->body_len);
    }
    if (d_final == DEC_ALLOW && maxb) {
        size_t el = strlen(a->extra);
        snprintf(a->extra + el, sizeof a->extra - el, "\"max_body\":%llu,", (unsigned long long)maxb);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    emit_pathology(g_report_seq++, 0, a, d_raw, d_final, rule, ns_between(&t0, &t1), d_final == DEC_ALLOW ? 0 : EACCES);
    free(a);
    struct wp_reqverdict v;
    memset(&v, 0, sizeof v);
    v.type = WP_MSG_REQVERDICT;
    v.allow = d_final == DEC_ALLOW;
    v.id = m->id;
    v.seq = m->seq;
    v.max_body = d_final == DEC_ALLOW ? maxb : 0;
    snprintf(v.why, sizeof v.why, "%s", why);
    if (d_final == DEC_ALLOW) {
        o->allowed = true;
        if (m->body != WP_BODY_NONE) {
            o->body_seq = m->seq;
            o->max_body = maxb;
            o->body_kind = m->body;
            o->body_declared = m->body_len;
        }
    } else o->refused = true;
    (void)send(g_proxy.ctl, &v, sizeof v, MSG_DONTWAIT | MSG_NOSIGNAL);
    return 0;
}

/* v1.26.1, step 6: an allowed request's body, as the proxy sent it: its
 * length and SHA-256 (the proxy's report), chained as request_body. */
static int px_httpbody(const struct wp_httpbody *m) {
    struct px_open *o = NULL;
    for (size_t k = 0; k < g_px_nopen; k++) if (g_px_open[k].id == m->id) o = &g_px_open[k];
    if (!o || !o->body_seq || m->seq != o->body_seq || m->exceeded > 2) return -1;
    /* passed max_body exactly when it says so (it stops at the limit; only a
     * chunked body can: a declared length over it was refused) */
    if (m->exceeded == 1 ? o->body_kind != WP_BODY_CHUNKED || !o->max_body || m->len != o->max_body
                         : o->max_body && m->len > o->max_body)
        return -1;
    /* review: a declared length is sent whole, or (the connection ended) less */
    if (o->body_kind == WP_BODY_LENGTH && (m->exceeded == 2 ? m->len >= o->body_declared : m->len != o->body_declared))
        return -1;
    o->body_seq = 0;
    if (m->exceeded == 1) o->cut = true;
    char hx[65];
    sodium_bin2hex(hx, sizeof hx, m->sha256, sizeof m->sha256);
    FILE *f = rec_begin();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(f, "{\"event\":\"request_body\",\"run\":\"%s\",\"proxy_conn\":%llu,\"request_seq\":%llu,"
            "\"body_len\":%llu,\"body_sha256\":\"%s\",%s\"timestamp_ns\":%lld}\n", g_run_id,
            (unsigned long long)m->id, (unsigned long long)m->seq, (unsigned long long)m->len, hx,
            m->exceeded == 1 ? "\"exceeded_max_body\":true," : m->exceeded == 2 ? "\"incomplete\":true," : "",
            (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    rec_end(NULL);
    return 0;
}

static int proxy_service(const struct policy *p) {
    for (;;) {
        static union { struct wp_req r; struct wp_close c; struct wp_msg f; struct wp_httpreq hr;
                       struct wp_httpbody hb; uint32_t type; } u;
        ssize_t n = recv(g_proxy.ctl, &u, sizeof u, MSG_DONTWAIT);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
        if (n <= 0) return -1;                                  /* the proxy is gone */
        /* v1.26.1, step 6 */
        if (n == (ssize_t)sizeof u.hr && u.type == WP_MSG_HTTPREQ) {
            if (px_httpreq(p, &u.hr) < 0) return -1;
            continue;
        }
        if (n == (ssize_t)sizeof u.hb && u.type == WP_MSG_HTTPBODY) {
            if (px_httpbody(&u.hb) < 0) return -1;
            continue;
        }
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
                if (proxy_service(g_syn_p) < 0) {
                    /* review: not dropped silently: the run is marked (run_end,
                     * the exit status) and its open connections unreported */
                    g_px_failed = true;
                    fprintf(stderr, "[warden] the egress proxy exited or sent a malformed report while the "
                                    "run ended; its open connections are recorded unreported\n");
                    break;
                }
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
