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
    int         su_rule;            /* the step_up (or defer) rule; -1: the `on unknown` line */
    int         su_kind;            /* v1.42 step 5: under the `on unknown` line, the call's kind */
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
static vdp_rule_t g_unk_rule;                /* v1.42 step 5: `on unknown defer escalate`, as a step_up rule */

/* v1.42 step 5: the step_up rule a proposal (or a held call) falls under:
 * a rule of the policy, or the `on unknown` line for a call's kind */
static const vdp_rule_t *unk_rule_of(int kind) {
    static vdp_rule_t r;
    r = g_unk_rule;
    r.kind = (vdp_kind_t)kind;
    return &r;
}
static int act_vkind(const struct action *a) {
    switch (a->kind) {
        case ACT_NET_CONNECT: case ACT_NET_PROXY: return VDP_KIND_HOST;
        case ACT_PROCESS_EXEC: return VDP_KIND_EXEC;
        case ACT_NET_REQUEST: return VDP_KIND_REQUEST;
        case ACT_NET_MCP: return VDP_KIND_MCP;
        default: return VDP_KIND_PATH;
    }
}
static const vdp_rule_t *act_su(const struct action *a) {
    return a->unk ? unk_rule_of(act_vkind(a)) : &g_gr_p->v.rules[a->rule_index];
}
struct proposal;
static const vdp_rule_t *prop_su(const struct proposal *pp);

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

static bool grant_holds(const struct policy *p);

/* At start: a policy that needs what this build does not carry out yet is
 * refused (fail closed). 0, or -1 with the reason on stderr. */
static int grant_policy_check(const struct policy *p, const char *path) {
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->verb != VDP_STEP_UP) continue;
        if (r->su_notify[0]) {
            fprintf(stderr, "[warden] policy %s:%d: notify= is not built yet (v1.42 is being built in steps; "
                    "this one has mode=grant, mode=hold and scope=run); refusing to start\n", path, r->line);
            return -1;
        }
    }
    /* v1.42 step 5: a marker the agent could write would let it release
     * its own deferred calls */
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->verb == VDP_DEFER && vdpc_path_writable(&p->c, r->df_until, strlen(r->df_until))) {
            fprintf(stderr, "[warden] policy %s:%d: the agent could write the defer rule's marker %s; refusing to start\n",
                    path, r->line, r->df_until);
            return -1;
        }
    }
    if (p->v.unk_line) {
        memset(&g_unk_rule, 0, sizeof g_unk_rule);
        g_unk_rule.verb = VDP_STEP_UP;
        g_unk_rule.su_mode = VDP_SU_HOLD;
        g_unk_rule.su_scope = p->v.unk_scope;
        g_unk_rule.su_timeout = p->v.unk_timeout;
        g_unk_rule.line = p->v.unk_line;
        memcpy(g_unk_rule.su_approvers, p->v.unk_approvers, sizeof g_unk_rule.su_approvers);
    }
    g_gr_p = p;
    /* v1.42 step 4: asked of the kernel itself (a child tries it), since
     * the filter is loaded with the flag whatever libseccomp's version */
    g_waitkill = grant_holds(p) && wd_filter_waitkill_built() && wd_filter_waitkill_kernel();
    if (grant_holds(p) && !g_waitkill)
        fprintf(stderr, "[warden] note: calls are held (mode=hold); this kernel cannot end a held call's wait on "
                "a fatal signal only (Linux 5.19 or later is needed), so a signal ends it: the call ends "
                "`abandoned` and, notified again, is held again\n");
    return 0;
}

/* v1.42 step 3: does the policy hold calls (a step_up rule with mode=hold)? */
static bool grant_holds(const struct policy *p) {
    for (size_t i = 0; i < p->v.n; i++)
        if ((p->v.rules[i].verb == VDP_STEP_UP && p->v.rules[i].su_mode == VDP_SU_HOLD) ||
            p->v.rules[i].verb == VDP_DEFER)                   /* v1.42 step 5: a deferral is held */
            return true;
    return p->v.unk_line != 0;
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
        case VDP_KIND_REQUEST: {
            /* v1.42 step 3b: the object is METHOD scheme://name:port/path[?query]; a request rule
             * reads it back as METHOD and URL (a glob: an object holding one of its specials is
             * not one the grammar can name exactly) */
            const char *sp = strchr(obj, ' ');
            if (!sp || !gr_token_ok(sp + 1) || strpbrk(obj, "*[]")) { *why = "the request is not one a rule can name exactly"; return NULL; }
            snprintf(rule, sizeof rule, "allow request %.*s %s", (int)(sp - obj), obj, sp + 1);
            break;
        }
        case VDP_KIND_MCP: {
            /* v1.42 step 3b: the object is <URL>#<method>#<name> */
            const char *h1 = strchr(obj, '#'), *h2 = h1 ? strchr(h1 + 1, '#') : NULL;
            if (!h2 || h2 == h1 + 1 || strpbrk(obj, "*?[]")) { *why = "the MCP call is not one a rule can name exactly"; return NULL; }
            if (h2[1]) snprintf(rule, sizeof rule, "allow mcp %.*s %.*s %s", (int)(h1 - obj), obj, (int)(h2 - h1 - 1), h1 + 1, h2 + 1);
            else snprintf(rule, sizeof rule, "allow mcp %.*s %.*s", (int)(h1 - obj), obj, (int)(h2 - h1 - 1), h1 + 1);
            break;
        }
        default:
            *why = "no proposal for this kind of call";
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

static const vdp_rule_t *prop_su(const struct proposal *pp) {
    return pp->su_rule >= 0 ? &g_gr_p->v.rules[pp->su_rule] : unk_rule_of(pp->su_kind);
}

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

/* A new proposal for refused call a under step_up rule a->rule_index: its
 * index in g_prop, or -1 with why (with dedupe, an open proposal of the
 * same text is named instead: *same its index). */
static int prop_make(const struct action *a, bool dedupe, const char **why, int *same) {
    const vdp_rule_t *su = act_su(a);                 /* v1.42 step 5: or the `on unknown` line */
    uint32_t timeout = su->su_timeout ? su->su_timeout : VDP_SU_TIMEOUT_DEFAULT;
    int64_t until = 0;
    *why = NULL;
    *same = -1;
    char *t = proposal_text(a, su, timeout, &until, why);
    if (!t) return -1;
    /* both parsers must read it, as any grant, and it must allow the very
     * call it is proposed for (v1.42 step 3b: a proposal never names more
     * or less than it means) */
    vdp_grant_t *vg = calloc(1, sizeof *vg);
    vdpc_grant_t cg;
    char e[300];
    if (!vg) *why = "out of memory";
    else if (vdp_grant_parse(&g_gr_p->v, t, strlen(t), vg, e, sizeof e) < 0) *why = "the proposal does not parse";
    else {
        const vdp_grant_t *one[1] = { vg };
        const char *obj = su->kind == VDP_KIND_EXEC && !a->resolved[0] ? a->target : a->resolved;
        bool hf = su->kind == VDP_KIND_PATH && a->flags_known;
        int ri = -1, gi = -1, gr = -1;
        vdp_why_t w;
        if (vdp_decide_grant(&g_gr_p->v, one, 1, act_policy_subject(a), su->kind, obj,
                             vdp_oflags_from_native((uint32_t)a->open_flags), hf, &ri, &w, &gi, &gr) != VDP_SATISFIED ||
            gi != 0)
            *why = "the proposal would not allow the call";
        vdp_grant_free(vg);
        if (!*why && vdpc_grant_load(&g_gr_p->c, t, strlen(t), &cg, e, sizeof e) < 0) *why = "the checker does not read the proposal";
        else if (!*why) vdpc_grant_free(&cg);
    }
    free(vg);
    if (*why) { free(t); return -1; }
    if (dedupe && (*same = prop_same(t)) >= 0) { free(t); return -1; }
    uint32_t maxp = g_gr_p->v.max_pending ? g_gr_p->v.max_pending : VDP_MAX_PENDING_DEFAULT;
    unsigned char rnd[8];
    if (prop_open_count() >= maxp) *why = "max_pending";
    else if (vfips_rand(rnd, sizeof rnd) != 0) *why = "no random id";
    else if (g_nprop == g_prop_cap) {
        size_t nc = g_prop_cap ? g_prop_cap * 2 : 16;
        struct proposal *np = realloc(g_prop, nc * sizeof *np);
        if (!np) *why = "out of memory";
        else { g_prop = np; g_prop_cap = nc; }
    }
    if (*why) { free(t); return -1; }
    struct proposal *pp = &g_prop[g_nprop];
    memset(pp, 0, sizeof *pp);
    for (int i = 0; i < 8; i++) snprintf(pp->id + 2 * i, 3, "%02x", rnd[i]);
    pp->text = t;
    pp->su_rule = a->unk ? -1 : a->rule_index;
    pp->su_kind = su->kind;
    pp->expires_ms = gr_now_ms() + (long long)timeout * 1000;
    pp->until = until;
    pp->count = 1;
    if (g_identity.has_user) snprintf(pp->user, sizeof pp->user, "%s", g_identity.sub);
    if (g_sub_on && a->subject > 0 && (size_t)a->subject < g_nsub)
        snprintf(pp->subagent, sizeof pp->subagent, "%s", g_sub[a->subject].name);
    return (int)g_nprop++;
}

/* For a refused call's record: when a step_up rule refused it, propose a
 * grant (or name the one already open) and write the record's field into
 * buf ("step_up":ID, or why none was made); g_new_prop is a new
 * proposal's index, for step_up_after. Empty when no step_up rule decided.
 * v1.42 step 3: a held call's ending (g_held_end) names its proposal; a
 * held call decided again after its approval (g_replaying) proposes
 * nothing. */
static int g_new_prop = -1;
static bool hold_kind(const struct action *a);
static size_t g_nheld;
static const char *g_held_end;               /* a held call's proposal, on its refusal's record */
static bool g_replaying;                     /* deciding a held call again, after its approval */

static const char *g_unheld;                 /* v1.42 step 4: why the call being decided was not held (scope=run) */
static bool su_scope_run(const vdp_rule_t *su) { return su->su_scope == VDP_SCOPE_RUN; }

/* v1.42 step 5: a deferral's fields on a record: its refusal (held), or
 * the call decided again once its marker passed (g_defer_note); why a call
 * a defer rule (or `on unknown`) decided was not deferred (g_defer_unheld) */
static const char *g_defer_note;
static char g_defer_note_buf[200];
static const char *g_defer_unheld;
static char g_replay_cur_did[17];            /* the deferral whose call is decided again now */

/* a JSON string's content: printable bytes, '"' and '\\' dropped */
static void gr_plain(char *out, size_t on, const char *w) {
    size_t l = 0;
    for (const char *c = w; *c && l + 1 < on; c++)
        if (*c != '"' && *c != '\\' && (unsigned char)*c >= 0x20) out[l++] = *c;
    out[l] = '\0';
}

static void step_up_note(const struct action *a, decision_t d_raw, decision_t d_final, char *buf, size_t n) {
    buf[0] = '\0';
    g_new_prop = -1;
    if (g_defer_note) { snprintf(buf, n, "%s", g_defer_note); return; }
    if (g_replaying && g_replay_cur_did[0]) {          /* v1.42 step 5 */
        snprintf(buf, n, "\"defer\":\"%s\",%s", g_replay_cur_did,
                 d_final == DEC_ALLOW ? "" : "\"defer_why\":\"its marker passed, then decided again: refused\",");
        return;
    }
    if (g_held_end) { snprintf(buf, n, "\"step_up\":\"%s\",\"held\":true,", g_held_end); return; }
    /* v1.42 step 5: a call a defer rule refused (its marker not passing),
     * or one `on unknown defer escalate` would hold, not held: why */
    bool df = g_gr_p && d_final != DEC_ALLOW && d_raw == DEC_DENY && !a->dry && a->rule_index >= 0 &&
              (size_t)a->rule_index < g_gr_p->v.n && g_gr_p->v.rules[a->rule_index].verb == VDP_DEFER;
    bool uk = g_gr_p && d_final != DEC_ALLOW && d_raw == DEC_UNKNOWN && !a->dry && g_gr_p->v.unk_line &&
              a->why && !strcmp(a->why, "no_rule") && g_defer_unheld;
    if (df || uk) {
        char w[160];
        gr_plain(w, sizeof w, g_defer_unheld ? g_defer_unheld : "its marker does not pass");
        g_defer_unheld = NULL;
        snprintf(buf, n, "\"defer\":\"none\",\"defer_why\":\"%s\",", w);
        return;
    }
    if (!g_gr_p || d_final == DEC_ALLOW || d_raw != DEC_DENY || a->dry || a->rule_index < 0 ||
        (size_t)a->rule_index >= g_gr_p->v.n || g_gr_p->v.rules[a->rule_index].verb != VDP_STEP_UP ||
        (a->why && !strcmp(a->why, "revoked")))
        return;
    if (g_replaying) {
        snprintf(buf, n, "\"step_up\":\"none\",\"step_up_why\":\"held and approved, then decided again: "
                 "not within the grant\",");
        return;
    }
    /* a hold rule's call that would be held, but max_held are: refused at once */
    const vdp_rule_t *su = &g_gr_p->v.rules[a->rule_index];
    uint32_t maxh = g_gr_p->v.max_held ? g_gr_p->v.max_held : VDP_MAX_HELD_DEFAULT;
    if (su->su_mode == VDP_SU_HOLD && hold_kind(a) && g_apv_listen >= 0 && g_nheld >= maxh) {
        snprintf(buf, n, "\"step_up\":\"none\",\"step_up_why\":\"max_held\",");
        return;
    }
    /* v1.42 step 4: a call a scope=run rule would hold, refused at once
     * because the run cannot be frozen: the record says why */
    char un[240] = "";
    if (su->su_mode == VDP_SU_HOLD && su_scope_run(su) && hold_kind(a) && g_apv_listen >= 0) {
        const char *w = g_unheld ? g_unheld : !g_frz_ok ? g_frz_why : NULL;
        g_unheld = NULL;                         /* this call's: used once */
        if (w) {
            size_t l = (size_t)snprintf(un, sizeof un, "\"unheld\":\"scope=run: ");
            for (const char *c = w; *c && l + 3 < sizeof un; c++)
                if (*c != '"' && *c != '\\' && (unsigned char)*c >= 0x20) un[l++] = *c;
            snprintf(un + l, sizeof un - l, "\",");
        }
    }
    const char *why;
    int same;
    int k = prop_make(a, true, &why, &same);
    if (same >= 0) { snprintf(buf, n, "%s\"step_up\":\"%s\",", un, g_prop[same].id); return; }
    if (k < 0) { snprintf(buf, n, "%s\"step_up\":\"none\",\"step_up_why\":\"%s\",", un, why ? why : "?"); return; }
    g_new_prop = k;
    snprintf(buf, n, "%s\"step_up\":\"%s\",", un, g_prop[k].id);
}

/* ---- v1.42 step 3: mode=hold, a call held at the kernel ----
 *
 * A call a step_up rule with mode=hold refuses is not answered: its
 * notification is kept, a grant is proposed, and the thread waits in the
 * kernel. Approved, the call is decided again from its notification (the
 * supervision loop's `decide`, as the node agent's first call is), now
 * within the grant: the object the kernel resolves then must be the
 * grant's. Denied or past its timeout, it is refused (EACCES) and recorded
 * then. A notification that ends while held (the caller interrupted or
 * gone) ends `abandoned`. At most max_held are held at once; one more is
 * refused at once. Held: opens and lookups, connects and launches. Not
 * held (refused at once with a proposal, as mode=grant): changes by name,
 * which decide two names, and what the egress proxy decides. Only with
 * the approvers' socket open: without it nobody could answer. */

struct held_call {
    int                  what;       /* v1.42 step 3b: 0 a notification; PXH_HTTP, PXH_MCP at the proxy */
    void                *msg;        /* PXH_*: the proxy's report, to decide again */
    uint64_t             conn;       /* PXH_*: its connection */
    bool                 f1, f2;
    struct seccomp_notif req;
    struct action       *act;        /* the call as decided, for its refusal's record */
    decision_t           d_raw;
    char                 rule_id[40];
    char                 prop[17];
    struct timespec      t0;
    bool                 frz;        /* v1.42 step 4: held with scope=run: the run is frozen */
    /* v1.42 step 5: a deferral (dkind 1) waits on its marker, its proposal
     * none until it is escalated (then dkind 0, as any held call) */
    int                  dkind;
    char                 did[17];
    int                  df_rule;
    long long            df_deadline_ms;
};

static struct held_call *g_held;
static size_t g_held_cap;
static struct seccomp_notif g_replay_q[VDP_MAX_HELD_LIMIT];  /* approved held calls, to decide again */
static bool g_replay_frz[VDP_MAX_HELD_LIMIT];                /* v1.42 step 4: ... held with scope=run */
static char g_replay_did[VDP_MAX_HELD_LIMIT][17];            /* v1.42 step 5: ... a deferral's, released by its marker */
static size_t g_nreplay;
static bool g_cur_set;                       /* g_cur_req is the notification being decided */
static struct seccomp_notif g_cur_req;
static uint64_t g_hold_swallow;              /* the refusal of this notification is not sent */
static int g_grant_notify_fd = -1;

/* ---- v1.42 step 4: scope=run ----
 * A call a scope=run rule holds freezes the run (frz_setup, in
 * warden_subagent.inc.c, says whether it can be): its other threads and
 * processes stop until the hold ends, its timeout included. The thaw
 * comes at the top of the supervision loop, once no call held with
 * scope=run is left, held or approved and waiting to be decided again: an
 * approved call is answered before the run goes on. Calls already in the
 * kernel when the freeze began are decided as any. Where the run cannot be
 * frozen, the call is not held: it is refused at once with a proposal (as
 * mode=grant), its record saying why (g_unheld). */
static char g_unheld_buf[160];

/* Freeze the run for a hold (proposal id prop): true when frozen (now or
 * before), false with g_unheld */
static bool frz_hold(void) {
    if (!g_frz_ok) { g_unheld = g_frz_why; return false; }
    if (g_frozen) return true;
    if (frz_set(true) < 0) {
        snprintf(g_unheld_buf, sizeof g_unheld_buf, "cannot freeze the run (%s)", strerror(errno));
        g_unheld = g_unheld_buf;
        return false;
    }
    return true;
}

static void frz_record(bool frozen, const char *prop, int err) {
    FILE *f = rec_begin();
    if (frozen)
        fprintf(f, "{\"event\":\"run_frozen\",\"run\":\"%s\",\"step_up\":\"%s\",\"cgroup\":\"", g_run_id, prop);
    else
        fprintf(f, "{\"event\":\"run_thawed\",\"run\":\"%s\",\"frozen_ms\":%lld,%s%s%s\"cgroup\":\"", g_run_id,
                mono_ms_sub() - g_frz_t0, err ? "\"error\":\"" : "", err ? strerror(err) : "", err ? "\"," : "");
    json_escape(f, g_cg_self);
    fprintf(f, "\",\"timestamp_ns\":%lld}\n", gr_now_ns());
    rec_end(NULL);
    if (!frozen && err) {
        log_line_start();
        fprintf(g_log, "[warden] cannot thaw the run's control group %s (%s)\n", g_cg_self, strerror(err));
    }
}

/* Each round: thaw the run once nothing held with scope=run is left */
static void frz_update(void) {
    if (!g_frozen) return;
    for (size_t i = 0; i < g_nheld; i++) if (g_held[i].frz) return;
    for (size_t i = 0; i < g_nreplay; i++) if (g_replay_frz[i]) return;
    int err = frz_set(false) < 0 ? errno : 0;
    frz_record(false, NULL, err);
}

static bool hold_kind(const struct action *a) {
    return a->kind == ACT_FILE_OPEN || a->kind == ACT_FILE_STAT || a->kind == ACT_FILE_ACCESS ||
           a->kind == ACT_FILE_READLINK || a->kind == ACT_NET_CONNECT || a->kind == ACT_PROCESS_EXEC ||
           a->kind == ACT_NET_REQUEST || a->kind == ACT_NET_MCP;       /* v1.42 step 3b: at the proxy */
}

static void held_refuse(size_t i);
static int held_find_req(uint64_t id) {
    for (size_t i = 0; i < g_nheld; i++) if (g_held[i].req.id == id) return (int)i;
    return -1;
}

/* Each round, before a notification: nothing is held or replayed yet. A
 * call held last round whose refusal was not withheld (it was answered
 * some other way) is not held: its refusal is recorded now, and its
 * proposal ends `abandoned`. */
static void step_up_end_record(const struct proposal *pp, const char *ending, const char *grant_id,
                               long long uid, const char *who, const char *reason);
static void hold_round(int notify_fd) {
    g_grant_notify_fd = notify_fd;
    if (g_hold_swallow && !notif_id_valid(notify_fd, g_hold_swallow)) {
        int hi = held_find_req(g_hold_swallow);
        if (hi >= 0) {
            char prop[17];
            memcpy(prop, g_held[hi].prop, sizeof prop);
            g_grant_notify_fd = -1;                   /* record it; it was answered already */
            held_refuse((size_t)hi);
            g_grant_notify_fd = notify_fd;
            int pi = prop_find(prop);
            if (pi >= 0) { step_up_end_record(&g_prop[pi], "abandoned", NULL, -1, NULL, NULL); prop_free((size_t)pi); }
        }
    }
    g_cur_set = false;
    g_replaying = false;
    g_hold_swallow = 0;
    g_unheld = NULL;
    g_defer_unheld = NULL;                           /* v1.42 step 5 */
    g_replay_cur_did[0] = '\0';
    frz_update();                                    /* v1.42 step 4 */
}

/* The notification about to be decided */
static void hold_cur(const struct seccomp_notif *req) {
    g_cur_req = *req;
    g_cur_set = true;
}

/* An approved held call to decide again: true with *req */
static bool hold_replay_pop(struct seccomp_notif *req) {
    if (!g_nreplay) return false;
    *req = g_replay_q[0];
    memmove(&g_replay_q[0], &g_replay_q[1], (g_nreplay - 1) * sizeof g_replay_q[0]);
    memmove(&g_replay_frz[0], &g_replay_frz[1], (g_nreplay - 1) * sizeof g_replay_frz[0]);
    memcpy(g_replay_cur_did, g_replay_did[0], sizeof g_replay_cur_did);
    memmove(&g_replay_did[0], &g_replay_did[1], (g_nreplay - 1) * sizeof g_replay_did[0]);
    g_nreplay--;
    g_replaying = true;
    return true;
}

/* send_simple / send_errno: a held call's refusal is not sent */
static bool hold_swallow(uint64_t id, bool refusal) {
    if (!refusal || !g_hold_swallow || id != g_hold_swallow) return false;
    g_hold_swallow = 0;
    return true;
}


/* ---- v1.42 step 5: DEFER ----
 *
 * A call a defer rule decides is allowed while its marker (until=FILE)
 * passes (policy_decide, df_marker), and deferred otherwise: held, at the
 * kernel or at the proxy as a held step_up call is, under the rule's scope
 * (run by default: the run is frozen), counted by max_held. Each second its
 * marker is checked again; when it passes, the call is decided again
 * (defer_end `resolved`). At its timeout it is refused (`timeout`), or with
 * escalate it becomes a step_up hold under the defer rule (`escalated`, a
 * proposal), approved, denied or timed out as any. `on unknown defer
 * escalate`: a ground call no rule holds is escalated at once, its proposal
 * under the `on unknown` line. A call that cannot be deferred is refused at
 * once, its record saying why. Records: `defer` (held), `defer_end`. */

/* Does rule r's marker pass? sha: its contents' SHA-256. It must be a
 * regular file (not a link), owned by root or by the rule's approvers=
 * group, writable by its owner alone, not the agent's own; at most 4 KiB;
 * its first line this run's id or `*`; an `until` line, if any, not past. */
static bool df_marker(const vdp_rule_t *r, char sha[65], char *why, size_t wn) {
    sha[0] = '\0';
    if (!r->df_until[0]) { snprintf(why, wn, "no marker"); return false; }
    int fd = open(r->df_until, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { snprintf(why, wn, "no marker (%s)", strerror(errno)); return false; }
    struct stat st;
    char buf[4097];
    ssize_t n = -1;
    const char *no = NULL;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) no = "the marker is not a regular file";
    else if (st.st_mode & 022) no = "the marker is writable by others than its owner";
    else if (g_agent_uid != (uid_t)-1 && st.st_uid == g_agent_uid) no = "the marker is the agent's";
    else if (st.st_size > 4096) no = "the marker is over 4 KiB";
    else {
        bool owner_ok = st.st_uid == 0;
        if (!owner_ok && r->su_approvers[0]) {
            struct group gr, *grp = NULL;
            char gb[16384];
            if (getgrnam_r(r->su_approvers, &gr, gb, sizeof gb, &grp) == 0 && grp && st.st_gid == grp->gr_gid)
                owner_ok = true;
        }
        if (!owner_ok) no = "the marker is owned by neither root nor the approvers' group";
        else if ((n = read(fd, buf, sizeof buf - 1)) < 0) no = "the marker cannot be read";
    }
    close(fd);
    if (no) { snprintf(why, wn, "%s", no); return false; }
    buf[n] = '\0';
    if (memchr(buf, '\0', (size_t)n)) { snprintf(why, wn, "the marker holds a NUL byte"); return false; }
    /* the digest of exactly what is checked below (one read: never a second
     * read the file may have changed between) */
    unsigned char h[32];
    if (vfips_sha256(buf, (size_t)n, h) != 0) { snprintf(why, wn, "no digest"); return false; }
    bool first = true, named = false;
    for (char *save = NULL, *ln = strtok_r(buf, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        size_t l = strlen(ln);
        while (l && (ln[l - 1] == '\r' || ln[l - 1] == ' ' || ln[l - 1] == '\t')) ln[--l] = '\0';
        while (*ln == ' ' || *ln == '\t') ln++;
        if (!*ln || *ln == '#') continue;
        if (first) {
            first = false;
            named = !strcmp(ln, "*") || !strcmp(ln, g_run_id);
            if (!named) { snprintf(why, wn, "the marker names another run"); return false; }
            continue;
        }
        struct tm tm;
        memset(&tm, 0, sizeof tm);
        const char *e = !strncmp(ln, "until ", 6) ? strptime(ln + 6, "%Y-%m-%dT%H:%M:%SZ", &tm) : NULL;
        if (!e || *e) { snprintf(why, wn, "the marker has a line other than until YYYY-MM-DDTHH:MM:SSZ"); return false; }
        time_t t = timegm(&tm);
        char back[21];
        gr_utc((int64_t)t, back);
        if (strcmp(back, ln + 6)) { snprintf(why, wn, "the marker's until is not a time"); return false; }
        if (time(NULL) >= t) { snprintf(why, wn, "the marker's until has passed"); return false; }
    }
    if (!named) { snprintf(why, wn, "the marker names no run"); return false; }
    for (int i = 0; i < 32; i++) snprintf(sha + 2 * i, 3, "%02x", h[i]);
    return true;
}

static bool held_room(void) {
    if (g_nheld < g_held_cap) return true;
    size_t nc = g_held_cap ? g_held_cap * 2 : 8;
    struct held_call *nh = realloc(g_held, nc * sizeof *nh);
    if (!nh) return false;
    g_held = nh;
    g_held_cap = nc;
    return true;
}

/* a new held entry (kernel: what 0, the current notification; proxy: its
 * report), the call as decided kept; NULL when it cannot be made */
static struct held_call *held_new(int what, const struct action *a, decision_t d_raw, const char *rule_id,
                                  uint64_t latency_ns, uint64_t conn, const void *msg, size_t len, bool f1, bool f2) {
    if (!held_room()) return NULL;
    struct action *copy = malloc(sizeof *copy);
    void *mcopy = what ? malloc(len) : NULL;
    if (!copy || (what && !mcopy)) { free(copy); free(mcopy); return NULL; }
    *copy = *a;
    if (what) memcpy(mcopy, msg, len);
    struct held_call *h = &g_held[g_nheld++];
    memset(h, 0, sizeof *h);
    h->what = what;
    h->msg = mcopy;
    h->conn = conn;
    h->f1 = f1;
    h->f2 = f2;
    if (!what) h->req = g_cur_req;
    h->act = copy;
    h->d_raw = d_raw;
    snprintf(h->rule_id, sizeof h->rule_id, "%s", rule_id ? rule_id : "none");
    h->df_rule = -1;
    clock_gettime(CLOCK_MONOTONIC, &h->t0);
    long long t0ns = (long long)h->t0.tv_sec * 1000000000LL + h->t0.tv_nsec - (long long)latency_ns;
    h->t0.tv_sec = (time_t)(t0ns / 1000000000LL);
    h->t0.tv_nsec = (long)(t0ns % 1000000000LL);
    return h;
}

static void defer_held_record(const struct held_call *h, const vdp_rule_t *su, bool unknown) {
    uint32_t timeout = su->su_timeout ? su->su_timeout : VDP_SU_TIMEOUT_DEFAULT;
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"defer\",\"run\":\"%s\",\"id\":\"%s\",\"state\":\"held\",%s\"rule_line\":%d,\"until\":\"",
            g_run_id, h->did, unknown ? "\"unknown\":true," : "", su->line);
    json_escape(f, unknown ? "" : su->df_until);
    fprintf(f, "\",\"timeout\":%u,\"scope\":\"%s\",\"escalate\":%s,", timeout, su_scope_run(su) ? "run" : "thread",
            unknown || su->su_escalate ? "true" : "false");
    if (h->what) fprintf(f, "\"proxy_conn\":%llu,", (unsigned long long)h->conn);
    else fprintf(f, "\"agent_pid\":%d,", (int)h->req.pid);
    fprintf(f, "\"action\":\"%s\",\"resolved\":\"", action_kind_name(h->act->kind));
    json_escape(f, h->act->resolved);
    fprintf(f, "\",\"held\":%zu,\"timestamp_ns\":%lld}\n", g_nheld, gr_now_ns());
    rec_end(NULL);
}

static void defer_end_record(const char *did, const char *ending, const char *sha, const char *prop, const char *why) {
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"defer_end\",\"run\":\"%s\",\"id\":\"%s\",\"ending\":\"%s\",", g_run_id, did, ending);
    if (sha && *sha) fprintf(f, "\"marker_sha256\":\"%s\",", sha);
    if (prop && *prop) fprintf(f, "\"step_up\":\"%s\",", prop);
    if (why && *why) { fputs("\"why\":\"", f); json_escape(f, why); fputs("\",", f); }
    fprintf(f, "\"timestamp_ns\":%lld}\n", gr_now_ns());
    rec_end(NULL);
}

/* a held call's step_up record (an escalated deferral's, or `on unknown`'s) */
static void stepup_held_record(const struct held_call *h, const vdp_rule_t *su) {
    int pi = prop_find(h->prop);
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"step_up\",\"run\":\"%s\",\"id\":\"%s\",\"mode\":\"hold\",\"state\":\"held\","
            "\"rule_line\":%d,\"timeout\":%u,\"approvers\":\"%s\",", g_run_id, h->prop, su->line,
            su->su_timeout ? su->su_timeout : VDP_SU_TIMEOUT_DEFAULT, su->su_approvers);
    if (h->what) fprintf(f, "\"proxy_conn\":%llu,", (unsigned long long)h->conn);
    else fprintf(f, "\"agent_pid\":%d,", (int)h->req.pid);
    fprintf(f, "\"action\":\"%s\",\"resolved\":\"", action_kind_name(h->act->kind));
    json_escape(f, h->act->resolved);
    fputs("\",\"proposal\":\"", f);
    json_escape(f, pi >= 0 ? g_prop[pi].text : "");
    fprintf(f, "\",\"held\":%zu,\"scope\":\"%s\",\"defer\":\"%s\",\"timestamp_ns\":%lld}\n", g_nheld,
            h->frz ? "run" : "thread", h->did, gr_now_ns());
    rec_end(NULL);
}

static bool did_make(char out[17]) {
    unsigned char rnd[8];
    if (vfips_rand(rnd, sizeof rnd) != 0) return false;
    for (int i = 0; i < 8; i++) snprintf(out + 2 * i, 3, "%02x", rnd[i]);
    return true;
}

/* A call defer rule su refused (its marker not passing): deferred? True
 * when held (kernel: what 0; proxy: its report). False with g_defer_unheld. */
static bool defer_take(const struct action *a, const vdp_rule_t *su, decision_t d_raw, const char *rule_id,
                       uint64_t latency_ns, int what, uint64_t conn, const void *msg, size_t len, bool f1, bool f2) {
    if (!hold_kind(a)) { g_defer_unheld = "not a call that can be held"; return false; }
    if (!what && (g_grant_notify_fd < 0 || !notif_id_valid(g_grant_notify_fd, g_cur_req.id))) return false;
    if (what && g_proxy.ctl < 0) return false;
    uint32_t maxh = g_gr_p->v.max_held ? g_gr_p->v.max_held : VDP_MAX_HELD_DEFAULT;
    if (g_nheld >= maxh) { g_defer_unheld = "max_held"; return false; }
    char did[17];
    if (!did_make(did)) { g_defer_unheld = "no random id"; return false; }
    bool was_frozen = g_frozen;
    if (su_scope_run(su) && !frz_hold()) {
        snprintf(g_defer_note_buf, sizeof g_defer_note_buf, "scope=run: %s", g_unheld ? g_unheld : "cannot freeze");
        g_defer_unheld = g_defer_note_buf;
        g_unheld = NULL;
        return false;
    }
    struct held_call *h = held_new(what, a, d_raw, rule_id, latency_ns, conn, msg, len, f1, f2);
    if (!h) { if (!was_frozen) (void)frz_set(false); g_defer_unheld = "out of memory"; return false; }
    uint32_t timeout = su->su_timeout ? su->su_timeout : VDP_SU_TIMEOUT_DEFAULT;
    h->dkind = 1;
    memcpy(h->did, did, sizeof h->did);
    h->df_rule = a->rule_index;
    h->df_deadline_ms = gr_now_ms() + (long long)timeout * 1000;
    h->frz = su_scope_run(su);
    if (!what) g_hold_swallow = g_cur_req.id;
    else {
        /* the proxy waits the deferral, and an escalation's hold after it */
        struct wp_heldnote hn = { .type = WP_MSG_HELDNOTE, .ms = timeout * 1000u * (su->su_escalate ? 2u : 1u), .id = conn };
        (void)send(g_proxy.ctl, &hn, sizeof hn, MSG_DONTWAIT | MSG_NOSIGNAL);
    }
    defer_held_record(h, su, false);
    if (su_scope_run(su) && !was_frozen) frz_record(true, h->did, 0);
    return true;
}

/* `on unknown defer escalate`: a ground call no rule holds, escalated at
 * once (its proposal under the `on unknown` line). True when held. */
static bool unk_take(const struct action *a, decision_t d_raw, const char *rule_id, uint64_t latency_ns,
                     int what, uint64_t conn, const void *msg, size_t len, bool f1, bool f2) {
    if (!g_gr_p || !g_gr_p->v.unk_line || !a->why || strcmp(a->why, "no_rule")) return false;
    if (!hold_kind(a) || a->kind == ACT_PROCESS_EXEC) {
        /* a launch no rule names is outside the launch set: no grant could run it */
        g_defer_unheld = "not a call that can be held";
        return false;
    }
    if (g_apv_listen < 0) { g_defer_unheld = "no approvers' socket"; return false; }
    if (!what && (g_grant_notify_fd < 0 || !notif_id_valid(g_grant_notify_fd, g_cur_req.id))) return false;
    if (what && g_proxy.ctl < 0) return false;
    uint32_t maxh = g_gr_p->v.max_held ? g_gr_p->v.max_held : VDP_MAX_HELD_DEFAULT;
    if (g_nheld >= maxh) { g_defer_unheld = "max_held"; return false; }
    char did[17];
    if (!did_make(did)) { g_defer_unheld = "no random id"; return false; }
    struct action ua = *a;
    ua.unk = true;
    const vdp_rule_t *su = act_su(&ua);
    vdp_rule_t sus = *su;                            /* unk_rule_of's buffer is shared */
    bool was_frozen = g_frozen;
    if (su_scope_run(&sus) && !frz_hold()) {
        snprintf(g_defer_note_buf, sizeof g_defer_note_buf, "scope=run: %s", g_unheld ? g_unheld : "cannot freeze");
        g_defer_unheld = g_defer_note_buf;
        g_unheld = NULL;
        return false;
    }
    const char *why;
    int same;
    int k = prop_make(&ua, false, &why, &same);
    if (k < 0) {
        if (!was_frozen) (void)frz_set(false);
        g_defer_unheld = why ? why : "no proposal";
        return false;
    }
    struct held_call *h = held_new(what, &ua, d_raw, rule_id, latency_ns, conn, msg, len, f1, f2);
    if (!h) {
        if (!was_frozen) (void)frz_set(false);
        prop_free((size_t)k);
        g_defer_unheld = "out of memory";
        return false;
    }
    memcpy(h->did, did, sizeof h->did);
    memcpy(h->prop, g_prop[k].id, sizeof h->prop);
    h->frz = su_scope_run(&sus);
    if (!what) g_hold_swallow = g_cur_req.id;
    else {
        uint32_t timeout = sus.su_timeout ? sus.su_timeout : VDP_SU_TIMEOUT_DEFAULT;
        struct wp_heldnote hn = { .type = WP_MSG_HELDNOTE, .ms = timeout * 1000u, .id = conn };
        (void)send(g_proxy.ctl, &hn, sizeof hn, MSG_DONTWAIT | MSG_NOSIGNAL);
    }
    defer_held_record(h, &sus, true);
    if (h->frz && !was_frozen) frz_record(true, h->did, 0);
    defer_end_record(h->did, "escalated", NULL, h->prop, NULL);
    stepup_held_record(h, &sus);
    return true;
}

/* A deferral past its timeout, with escalate: its call held on as a
 * step_up call under the defer rule. False when no proposal can be made. */
static bool defer_escalate(struct held_call *h, const char **why) {
    int same;
    int k = prop_make(h->act, false, why, &same);
    if (k < 0) return false;
    h->dkind = 0;
    memcpy(h->prop, g_prop[k].id, sizeof h->prop);
    defer_end_record(h->did, "escalated", NULL, h->prop, NULL);
    stepup_held_record(h, &g_gr_p->v.rules[h->df_rule]);
    return true;
}

/* emit_pathology, first: hold this call instead of recording its refusal?
 * True when it is held (its record is written when it ends). */
static bool hold_take(pid_t pid, const struct action *a, decision_t d_raw, decision_t d_final,
                      const char *rule_id, uint64_t latency_ns) {
    if (!g_gr_p || !g_cur_set || g_replaying || g_held_end || g_defer_note || d_final == DEC_ALLOW || a->dry ||
        pid != (pid_t)g_cur_req.pid || (a->why && !strcmp(a->why, "revoked")))
        return false;
    /* v1.42 step 5: `on unknown defer escalate` */
    if (d_raw == DEC_UNKNOWN) return unk_take(a, d_raw, rule_id, latency_ns, 0, 0, NULL, 0, false, false);
    if (d_raw != DEC_DENY || a->rule_index < 0 || (size_t)a->rule_index >= g_gr_p->v.n) return false;
    const vdp_rule_t *su = &g_gr_p->v.rules[a->rule_index];
    if (su->verb == VDP_DEFER) return defer_take(a, su, d_raw, rule_id, latency_ns, 0, 0, NULL, 0, false, false);
    if (su->verb != VDP_STEP_UP || su->su_mode != VDP_SU_HOLD || g_apv_listen < 0 || !hold_kind(a) ||
        (a->why && !strcmp(a->why, "revoked")))
        return false;
    /* only a call not yet answered can be held */
    if (g_grant_notify_fd < 0 || !notif_id_valid(g_grant_notify_fd, g_cur_req.id)) return false;
    uint32_t maxh = g_gr_p->v.max_held ? g_gr_p->v.max_held : VDP_MAX_HELD_DEFAULT;
    if (g_nheld >= maxh) return false;           /* refused at once, its record saying so (step_up_note) */
    if (g_nheld == g_held_cap) {
        size_t nc = g_held_cap ? g_held_cap * 2 : 8;
        struct held_call *nh = realloc(g_held, nc * sizeof *nh);
        if (!nh) return false;
        g_held = nh;
        g_held_cap = nc;
    }
    bool was_frozen = g_frozen;
    if (su_scope_run(su) && !frz_hold()) return false;     /* v1.42 step 4: refused at once, with a proposal */
    struct action *copy = malloc(sizeof *copy);
    if (!copy) { if (!was_frozen) (void)frz_set(false); return false; }
    const char *why;
    int same;
    int k = prop_make(a, false, &why, &same);
    if (k < 0) { free(copy); if (!was_frozen) (void)frz_set(false); return false; }
    *copy = *a;
    struct held_call *h = &g_held[g_nheld++];
    memset(h, 0, sizeof *h);
    h->req = g_cur_req;
    h->act = copy;
    h->d_raw = d_raw;
    snprintf(h->rule_id, sizeof h->rule_id, "%s", rule_id ? rule_id : "none");
    memcpy(h->prop, g_prop[k].id, sizeof h->prop);
    h->frz = su_scope_run(su);
    clock_gettime(CLOCK_MONOTONIC, &h->t0);           /* when it was decided: now less its latency */
    long long t0ns = (long long)h->t0.tv_sec * 1000000000LL + h->t0.tv_nsec - (long long)latency_ns;
    h->t0.tv_sec = (time_t)(t0ns / 1000000000LL);
    h->t0.tv_nsec = (long)(t0ns % 1000000000LL);
    g_hold_swallow = g_cur_req.id;
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"step_up\",\"run\":\"%s\",\"id\":\"%s\",\"mode\":\"hold\",\"state\":\"held\","
            "\"rule_line\":%d,\"timeout\":%u,\"approvers\":\"%s\",\"agent_pid\":%d,\"action\":\"%s\",\"resolved\":\"",
            g_run_id, h->prop, su->line, su->su_timeout ? su->su_timeout : VDP_SU_TIMEOUT_DEFAULT, su->su_approvers,
            (int)pid, action_kind_name(a->kind));
    json_escape(f, a->resolved);
    fputs("\",\"proposal\":\"", f);
    json_escape(f, g_prop[k].text);
    fprintf(f, "\",\"held\":%zu,\"scope\":\"%s\",\"timestamp_ns\":%lld}\n", g_nheld,
            su_scope_run(su) ? "run" : "thread", gr_now_ns());
    rec_end(NULL);
    if (su_scope_run(su) && !was_frozen) frz_record(true, h->prop, 0);   /* v1.42 step 4 */
    return true;
}

/* v1.42 step 3b: hold a request or MCP call the proxy reported (what), if
 * a mode=hold rule refuses it: the report kept (msg, len), a grant
 * proposed, the proxy told to wait for the verdict that long. True when
 * held: no verdict and no decision record now. */
static bool px_hold_take(const struct action *a, decision_t d_raw, int what, uint64_t conn, const void *msg,
                         size_t len, bool f1, bool f2) {
    if (!g_gr_p || g_replaying || g_held_end || g_defer_note || a->dry || g_proxy.ctl < 0 ||
        (a->why && !strcmp(a->why, "revoked")))
        return false;
    /* v1.42 step 5: `on unknown defer escalate`, and a defer rule's deferral */
    if (d_raw == DEC_UNKNOWN) return unk_take(a, d_raw, NULL, 0, what, conn, msg, len, f1, f2);
    if (d_raw != DEC_DENY || a->rule_index < 0 || (size_t)a->rule_index >= g_gr_p->v.n) return false;
    if (g_gr_p->v.rules[a->rule_index].verb == VDP_DEFER)
        return defer_take(a, &g_gr_p->v.rules[a->rule_index], d_raw, NULL, 0, what, conn, msg, len, f1, f2);
    if (g_apv_listen < 0) return false;
    const vdp_rule_t *su = &g_gr_p->v.rules[a->rule_index];
    if (su->verb != VDP_STEP_UP || su->su_mode != VDP_SU_HOLD || (a->why && !strcmp(a->why, "revoked"))) return false;
    uint32_t maxh = g_gr_p->v.max_held ? g_gr_p->v.max_held : VDP_MAX_HELD_DEFAULT;
    if (g_nheld >= maxh) return false;                  /* refused now, its record saying max_held */
    if (g_nheld == g_held_cap) {
        size_t nc = g_held_cap ? g_held_cap * 2 : 8;
        struct held_call *nh = realloc(g_held, nc * sizeof *nh);
        if (!nh) return false;
        g_held = nh;
        g_held_cap = nc;
    }
    bool was_frozen = g_frozen;
    if (su_scope_run(su) && !frz_hold()) return false;     /* v1.42 step 4: refused at once, with a proposal */
    void *copy = malloc(len);
    if (!copy) { if (!was_frozen) (void)frz_set(false); return false; }
    const char *why;
    int same;
    int k = prop_make(a, false, &why, &same);
    if (k < 0) { free(copy); if (!was_frozen) (void)frz_set(false); return false; }
    memcpy(copy, msg, len);
    struct held_call *h = &g_held[g_nheld++];
    memset(h, 0, sizeof *h);
    h->what = what;
    h->msg = copy;
    h->conn = conn;
    h->f1 = f1;
    h->f2 = f2;
    memcpy(h->prop, g_prop[k].id, sizeof h->prop);
    h->frz = su_scope_run(su);
    clock_gettime(CLOCK_MONOTONIC, &h->t0);
    uint32_t timeout = su->su_timeout ? su->su_timeout : VDP_SU_TIMEOUT_DEFAULT;
    struct wp_heldnote hn = { .type = WP_MSG_HELDNOTE, .ms = timeout * 1000u, .id = conn };
    (void)send(g_proxy.ctl, &hn, sizeof hn, MSG_DONTWAIT | MSG_NOSIGNAL);
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"step_up\",\"run\":\"%s\",\"id\":\"%s\",\"mode\":\"hold\",\"state\":\"held\","
            "\"rule_line\":%d,\"timeout\":%u,\"approvers\":\"%s\",\"proxy_conn\":%llu,\"action\":\"%s\",\"resolved\":\"",
            g_run_id, h->prop, su->line, timeout, su->su_approvers, (unsigned long long)conn, action_kind_name(a->kind));
    json_escape(f, a->resolved);
    fputs("\",\"proposal\":\"", f);
    json_escape(f, g_prop[k].text);
    fprintf(f, "\",\"held\":%zu,\"scope\":\"%s\",\"timestamp_ns\":%lld}\n", g_nheld,
            su_scope_run(su) ? "run" : "thread", gr_now_ns());
    rec_end(NULL);
    if (su_scope_run(su) && !was_frozen) frz_record(true, h->prop, 0);   /* v1.42 step 4 */
    return true;
}

static int held_find(const char *prop) {
    for (size_t i = 0; i < g_nheld; i++) if (!strcmp(g_held[i].prop, prop)) return (int)i;
    return -1;
}

static void held_drop(size_t i) {
    free(g_held[i].act);
    free(g_held[i].msg);
    memmove(&g_held[i], &g_held[i + 1], (g_nheld - i - 1) * sizeof g_held[0]);
    g_nheld--;
}

/* A held call refused (denied, or past its timeout): answered EACCES and
 * recorded now, its record naming its proposal */
static struct px_open *px_open_of(uint64_t id) {
    for (size_t k = 0; k < g_px_nopen; k++) if (g_px_open[k].id == id) return &g_px_open[k];
    return NULL;
}

/* v1.42 step 3b: a request or MCP call held at the proxy, decided (hold:
 * PXH_AGAIN after its approval, PXH_REFUSE when refused) */
static void px_held_decide(struct held_call *h, int hold) {
    struct px_open *o = px_open_of(h->conn);
    if (!o || !g_gr_p) return;                          /* its connection has gone */
    if (h->what == PXH_HTTP) (void)px_httpreq_decide(g_gr_p, o, h->msg, h->f1, h->f2, hold);
    else (void)px_mcpreq_decide(g_gr_p, o, h->msg, hold);
}

static void held_refuse(size_t i) {
    struct held_call *h = &g_held[i];
    /* v1.42 step 5: a deferral's refusal names it */
    const char *he = h->prop;
    if (h->dkind == 1) {
        snprintf(g_defer_note_buf, sizeof g_defer_note_buf, "\"defer\":\"%s\",\"held\":true,", h->did);
        g_defer_note = g_defer_note_buf;
        he = NULL;
    }
    if (h->what) {                                      /* v1.42 step 3b: at the proxy */
        g_held_end = he;
        px_held_decide(h, PXH_REFUSE);
        g_held_end = NULL;
        g_defer_note = NULL;
        held_drop(i);
        return;
    }
    bool answer = g_grant_notify_fd >= 0 && notif_id_valid(g_grant_notify_fd, h->req.id);
    if (answer || g_grant_notify_fd < 0) {
        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        g_held_end = he;
        emit_pathology(g_report_seq++, (pid_t)h->req.pid, h->act, h->d_raw, DEC_DENY, h->rule_id,
                       (uint64_t)(t1.tv_sec - h->t0.tv_sec) * 1000000000ULL + (uint64_t)(t1.tv_nsec - h->t0.tv_nsec),
                       EACCES);
        g_held_end = NULL;
    }
    g_defer_note = NULL;
    if (answer) send_errno(g_grant_notify_fd, h->req.id, EACCES);
    held_drop(i);
}

/* Each round: a held call whose notification has ended (its caller
 * interrupted, or gone) ends `abandoned` */
static void step_up_end_record(const struct proposal *pp, const char *ending, const char *grant_id,
                               long long uid, const char *who, const char *reason);
static void held_check(void) {
    for (size_t i = g_nheld; i-- > 0;) {
        if (g_held[i].what ? px_open_of(g_held[i].conn) != NULL                /* v1.42 step 3b */
                           : (g_grant_notify_fd < 0 || notif_id_valid(g_grant_notify_fd, g_held[i].req.id)))
            continue;
        if (g_held[i].dkind == 1) defer_end_record(g_held[i].did, "abandoned", NULL, NULL, NULL);   /* v1.42 step 5 */
        int pi = g_held[i].dkind == 1 ? -1 : prop_find(g_held[i].prop);
        if (pi >= 0) {
            step_up_end_record(&g_prop[pi], "abandoned", NULL, -1, NULL, NULL);
            prop_free((size_t)pi);
        }
        held_drop(i);
    }
}

/* After the decision record (seq): the new proposal's own record */
static void step_up_after(uint64_t seq) {
    if (g_new_prop < 0) return;
    const struct proposal *pp = &g_prop[g_new_prop];
    const vdp_rule_t *su = prop_su(pp);
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
    long long now = gr_now_ms(), best = -1;
    for (size_t i = 0; i < g_nprop; i++) {
        long long d = g_prop[i].expires_ms - now;
        if (d < 0) d = 0;
        if (best < 0 || d < best) best = d;
    }
    /* v1.42 step 5: a deferral's marker is checked each second, and its timeout kept */
    for (size_t i = 0; i < g_nheld; i++) {
        if (g_held[i].dkind != 1) continue;
        long long d = g_held[i].df_deadline_ms - now;
        if (d > 1000) d = 1000;
        if (d < 0) d = 0;
        if (best < 0 || d < best) best = d;
    }
    if (best < 0) return -1;
    return best > 3600000 ? 3600000 : (int)best;
}

/* Each round: a proposal past its time ends `timeout` */
static void grant_expire(void) {
    long long now = gr_now_ms();
    for (size_t i = g_nprop; i-- > 0;)
        if (g_prop[i].expires_ms <= now) {
            int hi = held_find(g_prop[i].id);           /* a held call is refused, then the proposal ends */
            if (hi >= 0) held_refuse((size_t)hi);
            step_up_end_record(&g_prop[i], "timeout", NULL, -1, NULL, NULL);
            prop_free(i);
        }
    /* v1.42 step 5: each deferral: its marker passing (decided again), or
     * its timeout (refused, or escalated) */
    for (size_t i = g_nheld; i-- > 0;) {
        struct held_call *h = &g_held[i];
        if (h->dkind != 1 || h->df_rule < 0) continue;
        const vdp_rule_t *su = &g_gr_p->v.rules[h->df_rule];
        char sha[65], mw[160];
        if (df_marker(su, sha, mw, sizeof mw)) {
            defer_end_record(h->did, "resolved", sha, NULL, NULL);
            if (h->what) {                              /* at the proxy: decided again now */
                memcpy(g_replay_cur_did, h->did, sizeof g_replay_cur_did);
                g_replaying = true;
                px_held_decide(h, PXH_AGAIN);
                g_replaying = false;
                g_replay_cur_did[0] = '\0';
                held_drop(i);
            } else if (g_nreplay < sizeof g_replay_q / sizeof g_replay_q[0]) {
                g_replay_frz[g_nreplay] = h->frz;
                memcpy(g_replay_did[g_nreplay], h->did, sizeof g_replay_did[0]);
                g_replay_q[g_nreplay++] = h->req;
                held_drop(i);
            } else held_refuse(i);
            continue;
        }
        if (h->df_deadline_ms > now) continue;
        const char *ew = NULL;
        char did[17];
        memcpy(did, h->did, sizeof did);
        if (su->su_escalate && g_apv_listen >= 0 && defer_escalate(h, &ew)) continue;
        if (su->su_escalate && !ew) ew = g_apv_listen < 0 ? "no approvers' socket" : "no proposal";
        held_refuse(i);
        defer_end_record(did, "timeout", NULL, NULL, su->su_escalate ? ew : NULL);
    }
}

/* At the run's end: each open proposal ends `abandoned` */
static void grant_end_all(void) {
    for (size_t i = 0; i < g_nheld; i++)            /* v1.42 step 5: open deferrals end abandoned */
        if (g_held[i].dkind == 1) defer_end_record(g_held[i].did, "abandoned", NULL, NULL, NULL);
    while (g_nheld) held_drop(g_nheld - 1);        /* the run is ending: its callers are gone */
    g_nreplay = 0;
    while (g_nprop) {
        step_up_end_record(&g_prop[g_nprop - 1], "abandoned", NULL, -1, NULL, NULL);
        prop_free(g_nprop - 1);
    }
    frz_update();                                  /* v1.42 step 4: thawed (recorded) before run_end */
}

/* ---- the approvers' socket ---- */

/* Open /run/varek-approve/<run>.sock (as root). Not fatal: without it no
 * grant can be approved, and every step_up call stays refused. */
static void apv_open(void) {
    if (!g_gr_p || geteuid() != 0) return;
    bool any = false;
    for (size_t i = 0; i < g_gr_p->v.n; i++) any = any || vdp_rule_grantable(&g_gr_p->v.rules[i]);
    any = any || g_gr_p->v.unk_line;               /* v1.42 step 5: escalations are answered there */
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
        const vdp_rule_t *su = prop_su(pp);
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
    const vdp_rule_t *su = prop_su(pp);
    char who[64];
    const char *no = apv_may(cr->uid, cr->gid, su, who);
    if (no) { snprintf(ans, an, "refused: %s", no); return ans; }
    if (!approve) {
        int hi = held_find(pp->id);                     /* a held call is refused first */
        if (hi >= 0) held_refuse((size_t)hi);
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
    int hi = held_find(pp->id);                         /* a held call is decided again, now */
    if (hi >= 0 && g_held[hi].what) {                   /* v1.42 step 3b: at the proxy, at once */
        g_replaying = true;
        px_held_decide(&g_held[hi], PXH_AGAIN);
        g_replaying = false;
        held_drop((size_t)hi);
        hi = -1;
    }
    if (hi >= 0) {
        if (g_nreplay < sizeof g_replay_q / sizeof g_replay_q[0])
            g_replay_frz[g_nreplay] = g_held[hi].frz, g_replay_did[g_nreplay][0] = '\0',
            g_replay_q[g_nreplay++] = g_held[hi].req;
        else held_refuse((size_t)hi), hi = -1;
        if (hi >= 0) held_drop((size_t)hi);
    }
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
        approver = vdp_rule_grantable(&g_gr_p->v.rules[i]) && !apv_may(cr.uid, cr.gid, &g_gr_p->v.rules[i], who);
    }
    if (!ans && !approver && g_gr_p->v.unk_line) {       /* v1.42 step 5: or under the `on unknown` line */
        char who[64];
        approver = !apv_may(cr.uid, cr.gid, &g_unk_rule, who);
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
