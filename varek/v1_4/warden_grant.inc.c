/* SPDX-License-Identifier: MIT
 * warden_grant.inc.c — v1.42 step 2 (docs/security/v1.42-step-up-defer.md):
 * runtime grants, mode=grant. Included by warden.c.
 *
 * A call a step_up rule decides is refused at once, as UNSATISFIED, and a
 * grant for it is proposed: the narrowest one (the exact object, the call's
 * own access, count 1, until the rule's timeout, for this run and the
 * call's user and sub-agent). The decision record names the proposal
 * ("step_up"), and a `step_up` record holds its text. An approver answers on
 * the run's approvers' socket (/run/varek-approve/<run>.sock):
 *   pending                    the open proposals the peer may answer, one
 *                              JSON line each;
 *   approve ID [reason R] [G]  approve proposal ID, as proposed, or narrowed
 *                              to grant text G (its count, time and scope no
 *                              wider than the proposal's);
 *   deny ID [reason R]         refuse it.
 * The approver is the peer the kernel names (SO_PEERCRED): a member of the
 * rule's approvers= group, or root when the rule names none; never the
 * agent's own user. An approved grant joins the run: the agent's next call
 * is decided by the procedure against the policy and the grant
 * (vdp_decide_grant), and allowed only if the checker accepts both halves of
 * its certificate (vdpc_check_grant). Each use is recorded on the decision
 * ("cert_grant") and counted; a grant allows nothing past its count, its
 * time, or its scope. A proposal not answered in time ends `timeout`.
 *
 * Records: `step_up` (proposed), `grant` (its text, id, approver, reason),
 * `step_up_end` (approved, denied, timeout). The audit replays them.
 *
 * Not in this step: mode=hold and scope=run (step 3 and 4), notify= (step
 * 7), proposals for requests and MCP calls; a policy that needs one of the
 * first three is refused at start. */

#define GRANT_MAX 64
#define PROP_TEXT_MAX 8192

struct live_grant {
    vdp_grant_t  v;                 /* the procedure's parse */
    vdpc_grant_t c;                 /* the checker's own */
    char         id[65];            /* SHA-256 of its text */
    uint32_t     used;
};

struct proposal {
    char        id[17];
    char       *text;
    int         su_rule;
    long long   expires_ms;         /* realtime: when it ends `timeout` */
    int64_t     until;              /* the proposed grant's until (s) */
    uint32_t    count;
    char        user[256], subagent[33];
};

static struct live_grant *g_live[GRANT_MAX];
static size_t g_nlive;
static struct proposal *g_prop;
static size_t g_nprop, g_prop_cap;
static const struct policy *g_gr_p;          /* the run's policy */
static uid_t g_agent_uid = (uid_t)-1;        /* the agent's own user: never an approver */
static int  g_apv_listen = -1;               /* the approvers' socket */
static char g_apv_path[100];

static long long gr_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static long long gr_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* At start: a policy that needs what this build does not carry out yet is
 * refused (fail closed). 0, or -1 with the reason on stderr. */
static int grant_policy_check(const struct policy *p, const char *path) {
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->verb != VDP_STEP_UP) continue;
        const char *what = r->su_mode == VDP_SU_HOLD ? "mode=hold" : r->su_scope == VDP_SCOPE_RUN ? "scope=run"
                         : r->su_notify[0] ? "notify=" : NULL;
        if (what) {
            fprintf(stderr, "[warden] policy %s:%d: %s is not built yet (v1.42 is being built in steps; "
                    "this one has mode=grant); refusing to start\n", path, r->line, what);
            return -1;
        }
    }
    g_gr_p = p;
    return 0;
}

/* Does live grant g apply to call a (its scope, count and time)? */
static bool grant_applies(const struct live_grant *g, const struct action *a) {
    if (g->v.count && g->used >= g->v.count) return false;
    if (g->v.until && (long long)time(NULL) >= g->v.until) return false;
    if (g->v.run[0] && strcmp(g->v.run, g_run_id)) return false;
    if (g->v.user[0] && (!g_identity.has_user || strcmp(g->v.user, g_identity.sub))) return false;
    if (g->v.subagent[0] && (a->subject <= 0 || !g_sub_on || (size_t)a->subject >= g_nsub ||
                             strcmp(g_sub[a->subject].name, g->v.subagent))) return false;
    return true;
}

/* policy_decide's procedure call: the run's live grants that apply take
 * part (vdp_decide_grant); *grant is 1 + the live grant's index, 0: none. */
static vdp_verdict_t grant_decide(const struct policy *p, const struct action *a, int subj, vdp_kind_t kind,
                                  const char *s, uint32_t flags, bool has_flags, int *ri, vdp_why_t *why,
                                  int *grant, int *grant_rule) {
    *grant = 0;
    *grant_rule = -1;
    if (!g_nlive || p != g_gr_p)
        return vdp_decide_subj(&p->v, subj, kind, s, flags, has_flags, ri, why);
    const vdp_grant_t *gs[GRANT_MAX];
    int map[GRANT_MAX];
    size_t n = 0;
    for (size_t i = 0; i < g_nlive; i++)
        if (grant_applies(g_live[i], a)) { gs[n] = &g_live[i]->v; map[n++] = (int)i; }
    int gi = -1, gr = -1;
    vdp_verdict_t v = vdp_decide_grant(&p->v, gs, n, subj, kind, s, flags, has_flags, ri, why, &gi, &gr);
    if (v == VDP_SATISFIED && gi >= 0) { *grant = map[gi] + 1; *grant_rule = gr; }
    return v;
}

/* certify's check for an ALLOW under a grant: the certificate's second
 * half, recorded in a->gcert, and the checker's verdict on both halves. A
 * use is counted when the checker accepts. */
static bool grant_certify(const struct policy *p, struct action *a, int subj, int kind, const char *s,
                          bool has_flags, const vdpc_cert_t *su) {
    a->gcert[0] = '\0';
    if (a->grant <= 0 || (size_t)a->grant > g_nlive) {
        snprintf(a->check_why, sizeof a->check_why, "no such grant");
        return false;
    }
    struct live_grant *g = g_live[a->grant - 1];
    vdp_cert_t vc;
    if (vdp_grant_certificate(&g->v, a->grant_rule, s, &vc) < 0) {
        snprintf(a->gcert, sizeof a->gcert, ",\"cert_grant\":\"%s\",\"cert_grant_rule\":%d,\"cert_grant_witness\":\"!\"",
                 g->id, a->grant_rule);
        snprintf(a->check_why, sizeof a->check_why, "the procedure built no witness for the grant");
        return false;
    }
    vdpc_cert_t gc;
    memset(&gc, 0, sizeof gc);
    gc.r = vc.rule;
    gc.wkind = vc.wkind;
    gc.off = vc.off;
    gc.nspan = vc.nspan;
    for (uint32_t k = 0; k < vc.nspan && k < VDPC_MAX_STRETCH; k++) {
        gc.span[k][0] = vc.span[k][0];
        gc.span[k][1] = vc.span[k][1];
    }
    size_t n = (size_t)snprintf(a->gcert, sizeof a->gcert, ",\"cert_grant\":\"%s\",\"cert_grant_rule\":%d,\"cert_grant_witness\":\"",
                                g->id, gc.r);
    if (gc.wkind == 1) n += (size_t)snprintf(a->gcert + n, sizeof a->gcert - n, "c:%u", gc.off);
    else if (gc.wkind == 2) {
        n += (size_t)snprintf(a->gcert + n, sizeof a->gcert - n, "g:");
        for (uint32_t k = 0; k < gc.nspan && n < sizeof a->gcert; k++)
            n += (size_t)snprintf(a->gcert + n, sizeof a->gcert - n, "%s%u-%u", k ? "," : "", gc.span[k][0], gc.span[k][1]);
    } else n += (size_t)snprintf(a->gcert + n, sizeof a->gcert - n, "-");
    if (n < sizeof a->gcert) snprintf(a->gcert + n, sizeof a->gcert - n, "\"");
    if (!vdpc_check_grant(&p->c, &g->c, subj, kind, s, strlen(s), vdp_oflags_from_native((uint32_t)a->open_flags),
                          has_flags, su, &gc, a->check_why, sizeof a->check_why)) {
        for (char *q = a->check_why; *q; q++)
            if (*q == '"' || *q == '\\' || (unsigned char)*q < 0x20) *q = '\'';
        return false;
    }
    g->used++;
    return true;
}

/* ---- proposals ---- */

/* A constant the grammar reads back as itself: one token of 0x21 to 0x7e. */
static bool gr_token_ok(const char *s) {
    if (!*s) return false;
    for (const char *c = s; *c; c++)
        if ((unsigned char)*c < 0x21 || (unsigned char)*c > 0x7e) return false;
    return true;
}

static void gr_utc(int64_t t, char out[21]) {
    time_t tt = (time_t)t;
    struct tm tm;
    gmtime_r(&tt, &tm);
    strftime(out, 21, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* The narrowest grant for refused call a, under step_up rule su; NULL with
 * the reason in why. */
static char *proposal_text(const struct action *a, const vdp_rule_t *su, uint32_t timeout, int64_t *until,
                           const char **why) {
    char rule[PATH_LIMIT + 160];
    const char *obj = a->resolved;
    switch (su->kind) {
        case VDP_KIND_PATH: {
            if (!gr_token_ok(obj)) { *why = "the object is not one token of printable bytes"; return NULL; }
            char clause[96] = "";
            if (a->kind == ACT_FILE_OPEN && a->flags_known) {
                uint32_t f = vdp_oflags_from_native((uint32_t)a->open_flags);
                static const char *const acc[] = { "access=ro", "access=wo", "access=rw" };
                if ((f & 3) == 3) { *why = "access mode 3"; return NULL; }
                snprintf(clause, sizeof clause, " %s %cO_CREAT %cO_TRUNC %cO_APPEND", acc[f & 3],
                         f & vdp_flag_bit("O_CREAT") ? '+' : '-', f & vdp_flag_bit("O_TRUNC") ? '+' : '-',
                         f & vdp_flag_bit("O_APPEND") ? '+' : '-');
            }
            snprintf(rule, sizeof rule, "allow path exact %s%s", obj, clause);
            break;
        }
        case VDP_KIND_HOST:
            if (!gr_token_ok(obj)) { *why = "the destination is not one token of printable bytes"; return NULL; }
            snprintf(rule, sizeof rule, "allow host %s", obj);
            break;
        case VDP_KIND_EXEC:
            obj = a->resolved[0] ? a->resolved : a->target;
            if (!gr_token_ok(obj)) { *why = "the program is not one token of printable bytes"; return NULL; }
            snprintf(rule, sizeof rule, "allow exec %s", obj);
            break;
        default:
            *why = "a proposal for a request or an MCP call is not built yet";
            return NULL;
    }
    char scope[400];
    int k = snprintf(scope, sizeof scope, "for run=%s", g_run_id);
    if (g_identity.has_user && gr_token_ok(g_identity.sub) && strlen(g_identity.sub) < 256)
        k += snprintf(scope + k, sizeof scope - (size_t)k, " user=%s", g_identity.sub);
    if (g_sub_on && a->subject > 0 && (size_t)a->subject < g_nsub && g_sub[a->subject].name[0])
        snprintf(scope + k, sizeof scope - (size_t)k, " subagent=%s", g_sub[a->subject].name);
    *until = (int64_t)time(NULL) + timeout;
    char ut[21];
    gr_utc(*until, ut);
    size_t tl = strlen(rule) + strlen(scope) + 96;
    char *t = malloc(tl);
    if (!t) { *why = "out of memory"; return NULL; }
    snprintf(t, tl, "grant\nstep_up line %d\n%s\n%s\ncount 1\nuntil %s\n", su->line, rule, scope, ut);
    return t;
}

static size_t prop_open_count(void) { return g_nprop; }

static void prop_free(size_t i) {
    free(g_prop[i].text);
    memmove(&g_prop[i], &g_prop[i + 1], (g_nprop - i - 1) * sizeof g_prop[0]);
    g_nprop--;
}

static int prop_find(const char *id) {
    for (size_t i = 0; i < g_nprop; i++) if (!strcmp(g_prop[i].id, id)) return (int)i;
    return -1;
}

/* The text after its last line (until) is the same proposal again */
static int prop_same(const char *text) {
    const char *u = strstr(text, "\nuntil ");
    size_t l = u ? (size_t)(u - text) : strlen(text);
    for (size_t i = 0; i < g_nprop; i++)
        if (!strncmp(g_prop[i].text, text, l) && !strncmp(g_prop[i].text + l, "\nuntil ", 7)) return (int)i;
    return -1;
}

/* For a refused call's record: when a step_up rule refused it, propose a
 * grant (or name the one already open) and write the record's field into
 * buf ("step_up":ID, or why none was made). *newp: a new proposal (its
 * index), for step_up_after. Empty when no step_up rule decided. */
static int g_new_prop = -1;

static void step_up_note(const struct action *a, decision_t d_raw, decision_t d_final, char *buf, size_t n) {
    buf[0] = '\0';
    g_new_prop = -1;
    if (!g_gr_p || d_final == DEC_ALLOW || d_raw != DEC_DENY || a->dry || a->rule_index < 0 ||
        (size_t)a->rule_index >= g_gr_p->v.n || g_gr_p->v.rules[a->rule_index].verb != VDP_STEP_UP ||
        (a->why && !strcmp(a->why, "revoked")))
        return;
    const vdp_rule_t *su = &g_gr_p->v.rules[a->rule_index];
    uint32_t timeout = su->su_timeout ? su->su_timeout : VDP_SU_TIMEOUT_DEFAULT;
    const char *why = NULL;
    int64_t until = 0;
    char *t = proposal_text(a, su, timeout, &until, &why);
    if (t) {
        /* both parsers must read it, as any grant */
        vdp_grant_t *vg = calloc(1, sizeof *vg);
        vdpc_grant_t cg;
        char e[300];
        if (!vg) why = "out of memory";
        else if (vdp_grant_parse(&g_gr_p->v, t, strlen(t), vg, e, sizeof e) < 0) why = "the proposal does not parse";
        else {
            vdp_grant_free(vg);
            if (vdpc_grant_load(&g_gr_p->c, t, strlen(t), &cg, e, sizeof e) < 0) why = "the checker does not read the proposal";
            else vdpc_grant_free(&cg);
        }
        free(vg);
    }
    if (t && !why) {
        int same = prop_same(t);
        if (same >= 0) {                       /* already proposed: name it */
            snprintf(buf, n, "\"step_up\":\"%s\",", g_prop[same].id);
            free(t);
            return;
        }
        uint32_t maxp = g_gr_p->v.max_pending ? g_gr_p->v.max_pending : VDP_MAX_PENDING_DEFAULT;
        unsigned char rnd[8];
        if (prop_open_count() >= maxp) why = "max_pending";
        else if (vfips_rand(rnd, sizeof rnd) != 0) why = "no random id";
        else if (g_nprop == g_prop_cap) {
            size_t nc = g_prop_cap ? g_prop_cap * 2 : 16;
            struct proposal *np = realloc(g_prop, nc * sizeof *np);
            if (!np) why = "out of memory";
            else { g_prop = np; g_prop_cap = nc; }
        }
        if (!why) {
            struct proposal *pp = &g_prop[g_nprop];
            memset(pp, 0, sizeof *pp);
            for (int i = 0; i < 8; i++) snprintf(pp->id + 2 * i, 3, "%02x", rnd[i]);
            pp->text = t;
            pp->su_rule = a->rule_index;
            pp->expires_ms = gr_now_ms() + (long long)timeout * 1000;
            pp->until = until;
            pp->count = 1;
            if (g_identity.has_user) snprintf(pp->user, sizeof pp->user, "%s", g_identity.sub);
            if (g_sub_on && a->subject > 0 && (size_t)a->subject < g_nsub)
                snprintf(pp->subagent, sizeof pp->subagent, "%s", g_sub[a->subject].name);
            g_new_prop = (int)g_nprop++;
            snprintf(buf, n, "\"step_up\":\"%s\",", pp->id);
            return;
        }
    }
    free(t);
    snprintf(buf, n, "\"step_up\":\"none\",\"step_up_why\":\"%s\",", why ? why : "?");
}

/* After the decision record (seq): the new proposal's own record */
static void step_up_after(uint64_t seq) {
    if (g_new_prop < 0) return;
    const struct proposal *pp = &g_prop[g_new_prop];
    const vdp_rule_t *su = &g_gr_p->v.rules[pp->su_rule];
    g_new_prop = -1;
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"step_up\",\"run\":\"%s\",\"id\":\"%s\",\"decision_seq\":%" PRIu64 ",\"mode\":\"grant\","
            "\"state\":\"proposed\",\"rule_line\":%d,\"timeout\":%u,\"approvers\":\"%s\",\"proposal\":\"",
            g_run_id, pp->id, seq, su->line, su->su_timeout ? su->su_timeout : VDP_SU_TIMEOUT_DEFAULT,
            su->su_approvers);
    json_escape(f, pp->text);
    fprintf(f, "\",\"timestamp_ns\":%lld}\n", gr_now_ns());
    rec_end(NULL);
}

static void step_up_end_record(const struct proposal *pp, const char *ending, const char *grant_id,
                               long long uid, const char *who, const char *reason) {
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"step_up_end\",\"run\":\"%s\",\"id\":\"%s\",\"ending\":\"%s\",", g_run_id, pp->id, ending);
    if (grant_id) fprintf(f, "\"grant\":\"%s\",", grant_id);
    if (uid >= 0) {
        fprintf(f, "\"approver_uid\":%lld,\"approver\":\"", uid);
        json_escape(f, who ? who : "");
        fputs("\",", f);
    }
    if (reason && *reason) { fputs("\"reason\":\"", f); json_escape(f, reason); fputs("\",", f); }
    fprintf(f, "\"timestamp_ns\":%lld}\n", gr_now_ns());
    rec_end(NULL);
}

/* The main loop's timeout: the next proposal to end, in ms (-1: none) */
static int grant_timeout_ms(void) {
    if (!g_nprop) return -1;
    long long now = gr_now_ms(), best = -1;
    for (size_t i = 0; i < g_nprop; i++) {
        long long d = g_prop[i].expires_ms - now;
        if (d < 0) d = 0;
        if (best < 0 || d < best) best = d;
    }
    return best > 3600000 ? 3600000 : (int)best;
}

/* Each round: a proposal past its time ends `timeout` */
static void grant_expire(void) {
    long long now = gr_now_ms();
    for (size_t i = g_nprop; i-- > 0;)
        if (g_prop[i].expires_ms <= now) {
            step_up_end_record(&g_prop[i], "timeout", NULL, -1, NULL, NULL);
            prop_free(i);
        }
}

/* At the run's end: each open proposal ends `abandoned` */
static void grant_end_all(void) {
    while (g_nprop) {
        step_up_end_record(&g_prop[g_nprop - 1], "abandoned", NULL, -1, NULL, NULL);
        prop_free(g_nprop - 1);
    }
}

/* ---- the approvers' socket ---- */

/* Open /run/varek-approve/<run>.sock (as root). Not fatal: without it no
 * grant can be approved, and every step_up call stays refused. */
static void apv_open(void) {
    if (!g_gr_p || geteuid() != 0) return;
    bool any = false;
    for (size_t i = 0; i < g_gr_p->v.n; i++) any = any || g_gr_p->v.rules[i].verb == VDP_STEP_UP;
    if (!any) return;
    if (mkdir("/run/varek-approve", 0711) < 0 && errno != EEXIST) goto fail;
    struct stat st;
    if (lstat("/run/varek-approve", &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
        errno = EPERM;
        goto fail;
    }
    snprintf(g_apv_path, sizeof g_apv_path, "/run/varek-approve/%s.sock", g_run_id);
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", g_apv_path);
    g_apv_listen = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (g_apv_listen < 0) goto fail;
    (void)unlink(g_apv_path);
    mode_t old = umask(0);
    int rc = bind(g_apv_listen, (struct sockaddr *)&sa, sizeof sa);
    umask(old);
    /* every local user may connect; each request is the peer's, as the kernel names it */
    if (rc < 0 || chmod(g_apv_path, 0666) < 0 || listen(g_apv_listen, 8) < 0) goto fail;
    fprintf(stderr, "[warden] approvals: %s (varek pending %s)\n", g_apv_path, g_run_id);
    return;
fail:
    fprintf(stderr, "[warden] note: no approvers' socket (%s): a call a step_up rule decides stays refused\n",
            strerror(errno));
    if (g_apv_listen >= 0) close(g_apv_listen);
    g_apv_listen = -1;
    g_apv_path[0] = '\0';
}

static void apv_close(void) {
    if (g_apv_listen >= 0) close(g_apv_listen);
    g_apv_listen = -1;
    if (g_apv_path[0] && getpid() == g_ctl_owner) (void)unlink(g_apv_path);
    g_apv_path[0] = '\0';
}

/* May uid approve under step_up rule su? NULL, or why not. *name: its user name. */
static const char *apv_may(uid_t uid, gid_t gid, const vdp_rule_t *su, char name[64]) {
    struct passwd pw, *pr = NULL;
    char pb[4096];
    name[0] = '\0';
    if (getpwuid_r(uid, &pw, pb, sizeof pb, &pr) == 0 && pr) snprintf(name, 64, "%s", pr->pw_name);
    if (uid == g_agent_uid) return "the agent's own user may not approve";
    if (!su->su_approvers[0]) return uid == 0 ? NULL : "only root may approve (the rule names no approvers=)";
    struct group gr, *grp = NULL;
    char gb[16384];
    if (getgrnam_r(su->su_approvers, &gr, gb, sizeof gb, &grp) != 0 || !grp) return "the approvers' group does not exist";
    if (gid == grp->gr_gid) return NULL;
    if (!pr) return "not a member of the approvers' group";
    gid_t groups[256];
    int ng = 256;
    if (getgrouplist(pr->pw_name, pr->pw_gid, groups, &ng) < 0) return "too many groups";
    for (int i = 0; i < ng; i++) if (groups[i] == grp->gr_gid) return NULL;
    return "not a member of the approvers' group";
}

static void apv_send(int c, const char *s) { (void)send(c, s, strlen(s), MSG_DONTWAIT | MSG_NOSIGNAL); }

/* End a connection: the peer's unread bytes are read first (without
 * waiting), so that closing does not reset the connection before the peer
 * has the answer */
static void apv_end(int c) {
    char junk[4096];
    (void)shutdown(c, SHUT_WR);
    for (int i = 0; i < 16 && recv(c, junk, sizeof junk, MSG_DONTWAIT) > 0; i++) {}
    close(c);
}

/* The open proposals this peer may answer (others' objects are not shown) */
static void apv_pending(int c, const struct ucred *cr) {
    char line[PROP_TEXT_MAX * 2 + 512];
    long long now = gr_now_ms();
    for (size_t i = 0; i < g_nprop; i++) {
        const struct proposal *pp = &g_prop[i];
        const vdp_rule_t *su = &g_gr_p->v.rules[pp->su_rule];
        char who[64];
        if (apv_may(cr->uid, cr->gid, su, who)) continue;
        int k = snprintf(line, sizeof line, "{\"id\":\"%s\",\"rule_line\":%d,\"approvers\":\"%s\",\"expires_in\":%lld,\"proposal\":\"",
                         pp->id, su->line, su->su_approvers, (pp->expires_ms - now + 999) / 1000);
        for (const char *q = pp->text; *q && (size_t)k + 8 < sizeof line; q++) {
            unsigned char u = (unsigned char)*q;
            if (u == '"' || u == '\\') { line[k++] = '\\'; line[k++] = (char)u; }
            else if (u == '\n') { line[k++] = '\\'; line[k++] = 'n'; }
            else if (u < 0x20 || u >= 0x7f) k += snprintf(line + k, sizeof line - (size_t)k, "\\u%04x", u);
            else line[k++] = (char)u;
        }
        snprintf(line + k, sizeof line - (size_t)k, "\"}\n");
        apv_send(c, line);
    }
    apv_send(c, "end\n");
}

/* approve ID / deny ID, from peer cr: the answer */
static const char *apv_answer(const struct ucred *cr, bool approve, const char *id, const char *reason,
                              const char *text, char *ans, size_t an) {
    int pi = prop_find(id);
    if (pi < 0) return "refused: no open proposal of that id";
    struct proposal *pp = &g_prop[pi];
    if (pp->expires_ms <= gr_now_ms()) return "refused: the proposal has ended";
    const vdp_rule_t *su = &g_gr_p->v.rules[pp->su_rule];
    char who[64];
    const char *no = apv_may(cr->uid, cr->gid, su, who);
    if (no) { snprintf(ans, an, "refused: %s", no); return ans; }
    if (!approve) {
        step_up_end_record(pp, "denied", NULL, (long long)cr->uid, who, reason);
        prop_free((size_t)pi);
        return "denied";
    }
    if (!text || !*text) text = pp->text;
    size_t tl = strlen(text);
    if (g_nlive >= GRANT_MAX) return "refused: the run holds as many grants as it may";
    struct live_grant *g = calloc(1, sizeof *g);
    char e[300];
    if (!g) return "refused: out of memory";
    if (vdp_grant_parse(&g_gr_p->v, text, tl, &g->v, e, sizeof e) < 0) {
        free(g);
        snprintf(ans, an, "refused: %s", e);
        return ans;
    }
    if (vdpc_grant_load(&g_gr_p->c, text, tl, &g->c, e, sizeof e) < 0) {
        vdp_grant_free(&g->v);
        free(g);
        snprintf(ans, an, "refused: the checker: %s", e);
        return ans;
    }
    /* narrowed, never widened: the same step_up rule, a count and a time no
     * greater than the proposal's, this run, and the proposal's user and
     * sub-agent */
    const char *wide = g->v.su_rule != pp->su_rule ? "it falls under another step_up rule"
                     : !g->v.count || g->v.count > pp->count ? "its count is wider than the proposal's"
                     : !g->v.until || g->v.until > pp->until ? "its time is later than the proposal's"
                     : strcmp(g->v.run, g_run_id) ? "it is not for this run (for run=)"
                     : pp->user[0] && strcmp(g->v.user, pp->user) ? "it is not for the proposal's user"
                     : pp->subagent[0] && strcmp(g->v.subagent, pp->subagent) ? "it is not for the proposal's sub-agent"
                     : NULL;
    if (wide) {
        vdp_grant_free(&g->v);
        vdpc_grant_free(&g->c);
        free(g);
        snprintf(ans, an, "refused: wider than the proposal: %s", wide);
        return ans;
    }
    unsigned char h[32];
    if (vfips_sha256(text, tl, h) != 0) {
        vdp_grant_free(&g->v);
        vdpc_grant_free(&g->c);
        free(g);
        return "refused: no digest";
    }
    for (int i = 0; i < 32; i++) snprintf(g->id + 2 * i, 3, "%02x", h[i]);
    g_live[g_nlive++] = g;
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"grant\",\"run\":\"%s\",\"id\":\"%s\",\"proposal\":\"%s\",\"approver_uid\":%u,\"approver\":\"",
            g_run_id, g->id, pp->id, (unsigned)cr->uid);
    json_escape(f, who);
    fprintf(f, "\",\"approvers\":\"%s\",", su->su_approvers);
    if (reason && *reason) { fputs("\"reason\":\"", f); json_escape(f, reason); fputs("\",", f); }
    fputs("\"text\":\"", f);
    json_escape(f, text);
    fprintf(f, "\",\"timestamp_ns\":%lld}\n", gr_now_ns());
    rec_end(NULL);
    step_up_end_record(pp, "approved", g->id, (long long)cr->uid, who, reason);
    prop_free((size_t)pi);
    snprintf(ans, an, "approved %s", g->id);
    return ans;
}

/* A peer on the approvers' socket: one request (read to its end), one answer */
static void apv_service(void) {
    int c = accept4(g_apv_listen, NULL, NULL, SOCK_CLOEXEC);
    if (c < 0) return;
    struct ucred cr;
    socklen_t cl = sizeof cr;
    char *req = malloc(VDP_GRANT_TEXT_MAX + 1024);
    size_t rl = 0, cap = VDP_GRANT_TEXT_MAX + 1023;
    const char *ans = NULL;
    char ansb[400];
    if (!req) { close(c); return; }
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0) ans = "refused: the peer cannot be named";
    /* Before reading anything: a peer who may approve under none of the
     * policy's step_up rules is answered at once, so another local user
     * cannot hold the Warden waiting for a request (the socket is 0666) */
    bool approver = false;
    for (size_t i = 0; !ans && !approver && i < g_gr_p->v.n; i++) {
        char who[64];
        approver = g_gr_p->v.rules[i].verb == VDP_STEP_UP && !apv_may(cr.uid, cr.gid, &g_gr_p->v.rules[i], who);
    }
    if (!ans && !approver) ans = "refused: not an approver in this run";
    long long deadline = gr_now_ms() + 500;
    while (!ans && rl < cap) {
        long long left = deadline - gr_now_ms();
        struct pollfd pf = { .fd = c, .events = POLLIN };
        if (left <= 0 || poll(&pf, 1, (int)left) != 1) { ans = "refused: the request did not end in time"; break; }
        ssize_t k = recv(c, req + rl, cap - rl, MSG_DONTWAIT);
        if (k < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (k <= 0) break;                           /* the peer's end */
        rl += (size_t)k;
    }
    if (!ans && rl >= cap) ans = "refused: the request is too long";
    req[rl] = '\0';
    if (!ans && memchr(req, '\0', rl)) ans = "refused: NUL in the request";
    if (!ans) {
        char *nl = strchr(req, '\n');
        char *rest = nl ? nl + 1 : req + rl;
        if (nl) *nl = '\0';
        char verb[16] = "", id[40] = "";
        if (sscanf(req, "%15s %39s", verb, id) < 1) ans = "refused: no request";
        else if (!strcmp(verb, "pending")) { apv_pending(c, &cr); free(req); apv_end(c); return; }
        else if (strcmp(verb, "approve") && strcmp(verb, "deny")) ans = "refused: unknown request";
        else if (!id[0]) ans = "refused: no proposal id";
        else {
            char *reason = NULL;
            if (!strncmp(rest, "reason ", 7)) {
                reason = rest + 7;
                char *e = strchr(reason, '\n');
                if (e) { *e = '\0'; rest = e + 1; } else rest = reason + strlen(reason);
                if (strlen(reason) > 1024) reason[1024] = '\0';
            }
            ans = apv_answer(&cr, verb[0] == 'a', id, reason, rest, ansb, sizeof ansb);
        }
    }
    char line[512];
    snprintf(line, sizeof line, "%s\n", ans);
    apv_send(c, line);
    free(req);
    apv_end(c);
}
