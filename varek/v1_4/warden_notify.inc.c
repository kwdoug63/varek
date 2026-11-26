/* SPDX-License-Identifier: MIT
 * warden_notify.inc.c — v1.42 step 7 (docs/security/v1.42-step-up-defer.md,
 * "Notification"): `step_up ... notify=URL` posts each proposed grant to a
 * webhook (Slack, Teams, a ticketing system). Included by warden.c, after
 * warden_grant.inc.c.
 *
 * The post is made by warden-notify (warden_notify_helper.c; the messages
 * are warden_notify.h's), started at the start from a sealed copy, as its
 * own user: the Warden links no TLS code. Its body is JSON: a one-line
 * "text" (what Slack's and Teams' incoming webhooks show) and "varek": the
 * run, the proposal's id, its rule's line, mode and approvers= group, the
 * grant's exact text (so the approver sees what they would authorise), for
 * whom (the user and sub-agent the grant names) and until when. Nothing of
 * the call beyond the grant's object, and not the user's request
 * (--intent), which approvers read with `varek pending`. The webhook only
 * notifies; it can approve nothing.
 *
 * Each post's outcome is recorded once, after its proposal's step_up
 * record: `notify` with the proposal's id, its rule's line, the URL's host
 * and SHA-256 (never the URL: a Slack URL is itself a secret), and
 * `sent` (the 2xx status, attempts), `failed` (why, attempts; a failed
 * attempt is made again once) or `abandoned` (the run ended first). Nothing
 * else depends on it.
 */

static int   g_nt_ctl = -1;                  /* warden-notify's socket */
static char  (*g_nt_host)[256];              /* each rule's notify= host (by rule index) */
static char  (*g_nt_url_sha)[65];            /* ... and the URL's SHA-256 */

struct nt_open { char id[17]; int rule; };
static struct nt_open *g_nt_open;
static size_t g_nt_nopen, g_nt_cap;

static bool nt_policy_wants(const struct policy *p) {
    for (size_t i = 0; i < p->v.n; i++)
        if (p->v.rules[i].verb == VDP_STEP_UP && p->v.rules[i].su_notify[0]) return true;
    return false;
}

/* At start: each notify= URL one warden-notify posts to (the grammar's
 * forms, without user information), its host and SHA-256 kept for the
 * records. 0, or -1 with the reason on stderr. */
static int nt_policy_check(const struct policy *p, const char *path) {
    if (!nt_policy_wants(p)) return 0;
    g_nt_host = calloc(p->v.n, sizeof *g_nt_host);
    g_nt_url_sha = calloc(p->v.n, sizeof *g_nt_url_sha);
    if (!g_nt_host || !g_nt_url_sha) { fprintf(stderr, "[warden] out of memory\n"); return -1; }
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->verb != VDP_STEP_UP || !r->su_notify[0]) continue;
        struct wn_url u;
        if (wn_url_parse(r->su_notify, &u) < 0) {
            fprintf(stderr, "[warden] policy %s:%d: notify= names no host warden-notify posts to (an https:// URL "
                    "without user information, or http:// to 127.0.0.0/8 or [::1]); refusing to start\n", path, r->line);
            return -1;
        }
        memcpy(g_nt_host[i], u.host, strlen(u.host) + 1);
        unsigned char d[32];
        if (vfips_sha256(r->su_notify, strlen(r->su_notify), d) != 0) {
            fprintf(stderr, "[warden] SHA-256 via the host crypto provider failed\n");
            return -1;
        }
        vfips_bin2hex(g_nt_url_sha[i], sizeof g_nt_url_sha[i], d, sizeof d);
    }
    return 0;
}

/* Start warden-notify (from the sealed copy exe_fd) as uid:gid, as
 * warden-secrets is started: an intermediate starts it and exits, so it is
 * not the Warden's child. It is given SSL_CERT_FILE and SSL_CERT_DIR when
 * the Warden has them, and nothing else of the environment. 0, or -1. */
static int nt_start(int exe_fd, uid_t uid, gid_t gid) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) return -1;
    int big = WN_BODY_MAX * 4;
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    char ids[32];
    snprintf(ids, sizeof ids, "%u:%u", (unsigned)uid, (unsigned)gid);
    static char ef[PATH_MAX + 16], ed[PATH_MAX + 16];
    char *env[3] = { NULL, NULL, NULL };
    int ne = 0;
    const char *cf = getenv("SSL_CERT_FILE"), *cd = getenv("SSL_CERT_DIR");
    if (cf && strlen(cf) < PATH_MAX) { snprintf(ef, sizeof ef, "SSL_CERT_FILE=%s", cf); env[ne++] = ef; }
    if (cd && strlen(cd) < PATH_MAX) { snprintf(ed, sizeof ed, "SSL_CERT_DIR=%s", cd); env[ne++] = ed; }
    pid_t mid = fork();
    if (mid < 0) { close(sv[0]); close(sv[1]); return -1; }
    if (mid == 0) {
        close(sv[0]);
        pid_t h = fork();
        if (h != 0) _exit(h < 0 ? 1 : 0);
        int ex = fcntl(exe_fd, F_DUPFD_CLOEXEC, 10);
        if (ex < 0) _exit(1);
        if (dup2(sv[1], 3) < 0) _exit(1);
        if (dup2(ex, 4) < 0 || fcntl(4, F_SETFD, FD_CLOEXEC) < 0) _exit(1);
        int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        if (syscall(SYS_close_range, 5U, ~0U, 0U) < 0)
            for (int fd = 5; fd < 65536; fd++) close(fd);
        char *const av[] = { (char *)"warden-notify", ids, NULL };
        fexecve(4, av, env);
        _exit(127);
    }
    close(sv[1]);
    int st = 0;
    while (waitpid(mid, &st, 0) < 0 && errno == EINTR) { }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { close(sv[0]); errno = ECHILD; return -1; }
    g_nt_ctl = sv[0];
    g_nt_uid = uid;
    g_nt_gid = gid;
    return 0;
}

static void nt_record(const char *id, int rule, const char *outcome, int status, int attempts, const char *why) {
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"notify\",\"run\":\"%s\",\"id\":\"%s\",\"rule_line\":%d,\"outcome\":\"%s\",\"host\":\"",
            g_run_id, id, g_gr_p->v.rules[rule].line, outcome);
    json_escape(f, g_nt_host[rule]);
    fprintf(f, "\",\"url_sha256\":\"%s\",", g_nt_url_sha[rule]);
    if (status > 0) fprintf(f, "\"status\":%d,", status);
    if (attempts > 0) fprintf(f, "\"attempts\":%d,", attempts);
    if (why && *why) { fputs("\"why\":\"", f); json_escape(f, why); fputs("\",", f); }
    fprintf(f, "\"timestamp_ns\":%lld}\n", gr_now_ns());
    rec_end(NULL);
}

/* The post's body for proposal pp under rule su (mode: as its step_up
 * record says). Its length, or 0 when it does not fit. */
static size_t nt_body(char *b, size_t n, const struct proposal *pp, const vdp_rule_t *su, const char *mode) {
    /* the grant's own line: the proposal's third ("allow ...") */
    char rule[PATH_LIMIT + 200] = "";
    const char *l1 = strchr(pp->text, '\n'), *l2 = l1 ? strchr(l1 + 1, '\n') : NULL;
    const char *l3 = l2 ? strchr(l2 + 1, '\n') : NULL;
    if (l2 && l3 && (size_t)(l3 - l2 - 1) < sizeof rule) {
        memcpy(rule, l2 + 1, (size_t)(l3 - l2 - 1));
        rule[l3 - l2 - 1] = '\0';
    }
    char ut[21], ex[21];
    gr_utc(pp->until, ut);
    gr_utc((int64_t)(pp->expires_ms / 1000), ex);
    size_t k = 0;
    apv_cat(b, n, &k, "{\"text\":\"VAREK run %s asks for approval: ", g_run_id);
    apv_cat_json(b, n, &k, rule);
    apv_cat(b, n, &k, " (proposal %s, policy line %d, ", pp->id, su->line);
    if (su->su_approvers[0]) apv_cat(b, n, &k, "approvers %s", su->su_approvers);
    else apv_cat(b, n, &k, "root approves");
    apv_cat(b, n, &k, "; answer by %s with `varek pending %s`)\",", ex, g_run_id);
    apv_cat(b, n, &k, "\"varek\":{\"event\":\"step_up\",\"run\":\"%s\",\"id\":\"%s\",\"rule_line\":%d,\"mode\":\"%s\","
            "\"approvers\":\"%s\",\"grant\":\"", g_run_id, pp->id, su->line, mode, su->su_approvers);
    apv_cat_json(b, n, &k, pp->text);
    apv_cat(b, n, &k, "\",\"user\":");
    if (pp->user[0]) { apv_cat(b, n, &k, "\""); apv_cat_json(b, n, &k, pp->user); apv_cat(b, n, &k, "\""); }
    else apv_cat(b, n, &k, "null");
    apv_cat(b, n, &k, ",\"subagent\":");
    if (pp->subagent[0]) { apv_cat(b, n, &k, "\""); apv_cat_json(b, n, &k, pp->subagent); apv_cat(b, n, &k, "\""); }
    else apv_cat(b, n, &k, "null");
    apv_cat(b, n, &k, ",\"until\":\"%s\",\"expires\":\"%s\"}}", ut, ex);
    return k >= n - 1 ? 0 : k;
}

/* After proposal pp's step_up record (and its run_frozen, if any): its
 * post, when its rule has notify= */
static void notify_post(const struct proposal *pp, const char *mode) {
    if (!g_gr_p || !g_nt_host || pp->su_rule < 0 || (size_t)pp->su_rule >= g_gr_p->v.n) return;
    const vdp_rule_t *su = &g_gr_p->v.rules[pp->su_rule];
    if (su->verb != VDP_STEP_UP || !su->su_notify[0]) return;
    if (g_nt_ctl < 0) { nt_record(pp->id, pp->su_rule, "failed", 0, 0, "no notification helper is running"); return; }
    if (g_nt_nopen == g_nt_cap) {
        size_t nc = g_nt_cap ? g_nt_cap * 2 : 16;
        struct nt_open *no = realloc(g_nt_open, nc * sizeof *no);
        if (!no) { nt_record(pp->id, pp->su_rule, "failed", 0, 0, "out of memory"); return; }
        g_nt_open = no;
        g_nt_cap = nc;
    }
    static char msg[sizeof(struct wn_post) + WN_URL_MAX + WN_BODY_MAX];
    struct wn_post m = { .type = WN_MSG_POST };
    memcpy(m.id, pp->id, sizeof m.id);
    size_t ul = strlen(su->su_notify);
    size_t bl = nt_body(msg + sizeof m + ul, WN_BODY_MAX, pp, su, mode);
    if (!bl || ul > WN_URL_MAX) { nt_record(pp->id, pp->su_rule, "failed", 0, 0, "the post would be too long"); return; }
    m.url_len = (uint32_t)ul;
    m.body_len = (uint32_t)bl;
    memcpy(msg, &m, sizeof m);
    memcpy(msg + sizeof m, su->su_notify, ul);
    ssize_t w = send(g_nt_ctl, msg, sizeof m + ul + bl, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (w != (ssize_t)(sizeof m + ul + bl)) {
        char why[120];
        snprintf(why, sizeof why, "the notification helper did not take the post (%s)", w < 0 ? strerror(errno) : "short");
        nt_record(pp->id, pp->su_rule, "failed", 0, 0, why);
        return;
    }
    struct nt_open *o = &g_nt_open[g_nt_nopen++];
    memcpy(o->id, pp->id, sizeof o->id);
    o->rule = pp->su_rule;
}

/* warden-notify gone: the posts open fail */
static void nt_gone(void) {
    for (size_t i = 0; i < g_nt_nopen; i++)
        nt_record(g_nt_open[i].id, g_nt_open[i].rule, "failed", 0, 0, "the notification helper has gone");
    g_nt_nopen = 0;
    if (g_nt_ctl >= 0) close(g_nt_ctl);
    g_nt_ctl = -1;
}

/* The poll loop: warden-notify's outcomes, each recorded once */
static void notify_service(void) {
    while (g_nt_ctl >= 0) {
        struct wn_result r;
        ssize_t n = recv(g_nt_ctl, &r, sizeof r, MSG_DONTWAIT | MSG_TRUNC);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { nt_gone(); return; }
        if ((size_t)n != sizeof r || r.type != WN_MSG_RESULT || !memchr(r.id, '\0', sizeof r.id) ||
            !memchr(r.why, '\0', sizeof r.why) || r.attempts < 0 || r.attempts > 2 || r.status < 0 || r.status > 599 ||
            (r.sent && (r.status < 200 || r.status > 299 || r.attempts < 1))) {
            log_line_start();
            fprintf(g_log, "[warden] warden-notify sent a malformed message; its posts are not followed further\n");
            nt_gone();
            return;
        }
        for (size_t i = 0; i < g_nt_nopen; i++) {
            if (strcmp(g_nt_open[i].id, r.id)) continue;
            for (char *c = r.why; *c; c++)
                if ((unsigned char)*c < 0x20 || (unsigned char)*c > 0x7e) *c = '?';
            nt_record(r.id, g_nt_open[i].rule, r.sent ? "sent" : "failed", r.status, r.attempts,
                      r.sent ? NULL : (r.why[0] ? r.why : "the post failed"));
            g_nt_open[i] = g_nt_open[--g_nt_nopen];
            break;
        }
    }
}

/* At the run's end: the outcomes already sent are recorded, the rest end
 * `abandoned`, and warden-notify ends its posts (the socket closed) */
static void notify_end_all(void) {
    notify_service();
    for (size_t i = 0; i < g_nt_nopen; i++)
        nt_record(g_nt_open[i].id, g_nt_open[i].rule, "abandoned", 0, 0, "the run ended before the post's outcome");
    g_nt_nopen = 0;
    if (g_nt_ctl >= 0) close(g_nt_ctl);
    g_nt_ctl = -1;
}
