/* SPDX-License-Identifier: MIT
 * warden_signed.inc.c — v1.42 step 6: signed approvals (included by warden.c
 * after warden_grant.inc.c). docs/security/v1.42-step-up-defer.md, "Grants"
 * (Signing) and step 6.
 *
 * The policy pins its approvers' keys by value (`approver key=HEX group=G
 * [name=N]`). Three things are signed with them, each as a detached
 * signature file (varek_approval.h has the format):
 *
 *   - Standing grants (`--grants DIR`): each DIR/NAME.grant with its
 *     DIR/NAME.grant.sig, read at the start. Each must be read by both
 *     parsers, be signed (kind grant) by a pinned key whose group is the
 *     approvers= group of the rule it falls under (a rule without approvers=
 *     takes none), name no run (a standing grant is for any run) and be
 *     within its until. Any that fails refuses the start (fail closed). They
 *     are then live grants as an approved runtime grant is, each recorded
 *     after run_start ("standing":true, "signed_by", "sig").
 *   - Plans (`--require-approved-plan`): the plan given with --plan must
 *     have PLAN.sig (kind plan) by any pinned key, over the very bytes the
 *     gate reads (its snapshot); else the start is refused. Without the
 *     flag a PLAN.sig present is still checked and recorded when it holds.
 *     run_start carries "plan_approved_by".
 *   - Runtime grants (`varek approve --sign-key`): the approve request may
 *     carry `sig SIGHEX key HEX`, verified over the grant's exact text
 *     against a pinned key of the rule's approvers= group (any pinned key
 *     when the rule names none: root alone approves it); a signature that
 *     fails refuses the approval. The peer-credential checks apply as ever.
 */

#include "varek_approval.h"

/* a pinned approver's index whose key is hex, or -1 */
static int apv_pinned(const struct policy *p, const char *hex) {
    for (size_t i = 0; i < p->v.napprovers; i++) if (!strcmp(p->v.approvers[i].key, hex)) return (int)i;
    return -1;
}

/* ---- plans ---- */

/* Before run_start (the plan's snapshot read): PLAN.sig. 0, or -1 printed
 * (with require: missing or failing; without: only reading errors). */
static int plan_approval_check(const struct policy *p, const char *plan_path, bool require) {
    if (!plan_path) {
        if (require) { fprintf(stderr, "[warden] --require-approved-plan needs --plan PLAN\n"); return -1; }
        return 0;
    }
    if (plan_snapshot(plan_path) < 0) {
        fprintf(stderr, "[warden] cannot read the plan %s (%s)\n", plan_path, strerror(errno));
        return -1;
    }
    char sp[PATH_MAX + 8];
    snprintf(sp, sizeof sp, "%s.sig", plan_path);
    char why[200] = "";
    int fd = open(sp, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (!require) return 0;
        fprintf(stderr, "[warden] --require-approved-plan: the plan %s has no approval (%s: %s); refusing to start\n",
                plan_path, sp, strerror(errno));
        return -1;
    }
    char buf[VAPPR_SIG_MAX + 1];
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    vappr_sig_t sg;
    int ki = -1;
    if (n < 0 || n > VAPPR_SIG_MAX) snprintf(why, sizeof why, "cannot read %.150s", sp);
    else if (vappr_parse(buf, (size_t)n, &sg, why, sizeof why) < 0) { }
    else if ((ki = apv_pinned(p, sg.key)) < 0) snprintf(why, sizeof why, "signed by a key the policy pins as no approver's");
    else if (!vappr_verify(&sg, "plan", g_plan_snap, g_plan_snap_len, why, sizeof why)) ki = -1;
    if (ki < 0) {
        if (require) {
            fprintf(stderr, "[warden] --require-approved-plan: the plan %s's approval %s fails: %s; refusing to start\n",
                    plan_path, sp, why);
            return -1;
        }
        snprintf(g_plan_apv_note, sizeof g_plan_apv_note, "%.150s: %.200s", sp, why);
        fprintf(stderr, "[warden] note: the plan's approval %s does not hold (%s); the plan is not approved\n", sp, why);
        return 0;
    }
    const vdp_approver_t *a = &p->v.approvers[ki];
    snprintf(g_plan_apv_key, sizeof g_plan_apv_key, "%s", a->key);
    snprintf(g_plan_apv_name, sizeof g_plan_apv_name, "%s", a->name);
    snprintf(g_plan_apv_group, sizeof g_plan_apv_group, "%s", a->group);
    snprintf(g_plan_apv_sig, sizeof g_plan_apv_sig, "%s", sg.sig);
    g_plan_apv = true;
    fprintf(stderr, "[warden] the plan is approved by %s (group %s)\n", a->name[0] ? a->name : "a pinned key", a->group);
    return 0;
}

/* ---- standing grants ---- */

struct standing {
    struct live_grant *g;
    char  *text;
    char   file[NAME_MAX + 1];
    int    ki;                      /* the signer's pinned index */
    char   sig[VFIPS_SIG_HEX_MAX + 1];
};
static struct standing g_standing[GRANT_MAX];
static size_t g_nstanding;

/* a whole regular file (at most max bytes), malloc'd and NUL-terminated */
static char *read_small(int dfd, const char *name, size_t max, size_t *n, char *why, size_t wn) {
    int fd = openat(dfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { snprintf(why, wn, "%s: %s", name, strerror(errno)); return NULL; }
    struct stat st;
    char *b = NULL;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) snprintf(why, wn, "%s: not a regular file", name);
    else if ((size_t)st.st_size > max) snprintf(why, wn, "%s: over %zu bytes", name, max);
    else if ((b = malloc((size_t)st.st_size + 1)) != NULL) {
        size_t got = 0;
        ssize_t r;
        while (got < (size_t)st.st_size && (r = read(fd, b + got, (size_t)st.st_size - got)) > 0) got += (size_t)r;
        b[got] = '\0';
        *n = got;
    }
    close(fd);
    return b;
}

/* At the start: every DIR/NAME.grant, checked. 0, or -1 printed. */
static int standing_load(const struct policy *p, const char *dir) {
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) { fprintf(stderr, "[warden] --grants %s: %s\n", dir, strerror(errno)); return -1; }
    DIR *d = fdopendir(dup(dfd));
    if (!d) { close(dfd); fprintf(stderr, "[warden] --grants %s: %s\n", dir, strerror(errno)); return -1; }
    char names[GRANT_MAX + 1][NAME_MAX + 1];
    size_t nn = 0;
    int rc = 0;
    for (struct dirent *e; (e = readdir(d)) != NULL;) {
        size_t l = strlen(e->d_name);
        if (l < 7 || strcmp(e->d_name + l - 6, ".grant")) continue;
        if (nn >= GRANT_MAX) {
            fprintf(stderr, "[warden] --grants %s: more than %d grants; refusing to start\n", dir, GRANT_MAX);
            rc = -1;
            break;
        }
        snprintf(names[nn++], sizeof names[0], "%s", e->d_name);
    }
    closedir(d);
    qsort(names, nn, sizeof names[0], (int (*)(const void *, const void *))strcmp);
    time_t now = time(NULL);
    for (size_t i = 0; rc == 0 && i < nn; i++) {
        char why[400] = "", e[300] = "";
        size_t tl = 0, sl = 0;
        char signame[NAME_MAX + 8];
        snprintf(signame, sizeof signame, "%s.sig", names[i]);
        char *text = read_small(dfd, names[i], VDP_GRANT_TEXT_MAX, &tl, why, sizeof why);
        char *st = text ? read_small(dfd, signame, VAPPR_SIG_MAX, &sl, why, sizeof why) : NULL;
        struct live_grant *g = calloc(1, sizeof *g);
        vappr_sig_t sg;
        int ki = -1;
        bool vok = false, cok = false;
        if (!text || !st) { }
        else if (!g) snprintf(why, sizeof why, "out of memory");
        else if (memchr(text, '\0', tl)) snprintf(why, sizeof why, "a NUL in the grant");
        else if (vappr_parse(st, sl, &sg, e, sizeof e) < 0) snprintf(why, sizeof why, "%s: %s", signame, e);
        else if ((ki = apv_pinned(p, sg.key)) < 0) snprintf(why, sizeof why, "signed by a key the policy pins as no approver's");
        else if (!vappr_verify(&sg, "grant", text, tl, e, sizeof e)) snprintf(why, sizeof why, "%s: %s", signame, e);
        else if (!(vok = vdp_grant_parse(&p->v, text, tl, &g->v, e, sizeof e) == 0)) snprintf(why, sizeof why, "%s", e);
        else if (!(cok = vdpc_grant_load(&p->c, text, tl, &g->c, e, sizeof e) == 0))
            snprintf(why, sizeof why, "the checker: %s", e);
        else {
            const char *grp = g->v.su_unknown ? p->v.unk_approvers : p->v.rules[g->v.su_rule].su_approvers;
            if (!grp[0])
                snprintf(why, sizeof why, "it falls under a rule (line %d) that names no approvers= group: such a rule "
                         "takes no standing grant (root alone approves it, at the socket)", g->v.su_line);
            else if (strcmp(grp, p->v.approvers[ki].group))
                snprintf(why, sizeof why, "signed by a key of group %s, and its rule (line %d) is approved by group %s",
                         p->v.approvers[ki].group, g->v.su_line, grp);
            else if (g->v.run[0]) snprintf(why, sizeof why, "a standing grant names no run (for run=): it is for any run");
            else if (g->v.until && (long long)now >= (long long)g->v.until) snprintf(why, sizeof why, "its until has passed");
        }
        unsigned char h[32];
        if (!why[0] && vfips_sha256(text, tl, h) != 0) snprintf(why, sizeof why, "no digest");
        if (why[0]) {
            fprintf(stderr, "[warden] --grants %s: %s: %s; refusing to start\n", dir, names[i], why);
            if (vok) vdp_grant_free(&g->v);
            if (cok) vdpc_grant_free(&g->c);
            free(g);
            free(text);
            free(st);
            rc = -1;
            break;
        }
        for (int j = 0; j < 32; j++) snprintf(g->id + 2 * j, 3, "%02x", h[j]);
        struct standing *s = &g_standing[g_nstanding++];
        s->g = g;
        s->text = text;
        s->ki = ki;
        snprintf(s->file, sizeof s->file, "%s", names[i]);
        snprintf(s->sig, sizeof s->sig, "%s", sg.sig);
        free(st);
    }
    close(dfd);
    if (rc < 0) return -1;
    if (g_nstanding)
        fprintf(stderr, "[warden] %zu standing grant(s) from %s, each signed by an approver of its rule\n",
                g_nstanding, dir);
    return 0;
}

static void signed_by_json(FILE *f, int ki, const char *sig) {
    const vdp_approver_t *a = &g_gr_p->v.approvers[ki];
    fprintf(f, "\"signed_by\":{\"key\":\"%s\",\"name\":\"%s\",\"group\":\"%s\"},\"sig\":\"%s\",", a->key, a->name,
            a->group, sig);
}

/* After run_start: each standing grant live, and recorded */
static void standing_start(void) {
    for (size_t i = 0; i < g_nstanding && g_nlive < GRANT_MAX; i++) {
        struct standing *s = &g_standing[i];
        g_live[g_nlive++] = s->g;
        FILE *f = rec_begin();
        fprintf(f, "{\"event\":\"grant\",\"run\":\"%s\",\"id\":\"%s\",\"standing\":true,\"file\":\"", g_run_id, s->g->id);
        json_escape(f, s->file);
        fputs("\",", f);
        signed_by_json(f, s->ki, s->sig);
        fputs("\"text\":\"", f);
        json_escape(f, s->text);
        fprintf(f, "\",\"timestamp_ns\":%lld}\n", gr_now_ns());
        rec_end(NULL);
        free(s->text);
        s->text = NULL;
    }
}

/* ---- runtime grants, signed (varek approve --sign-key) ---- */

/* The approve request's signature over text, under rule su (its approvers=
 * group). *ki the signer's pinned index; NULL, or why the approval is refused. */
static const char *apv_sig_check(const vdp_rule_t *su, const char *text, const char *key, const char *sig,
                                 int *ki, char *why, size_t wn) {
    *ki = -1;
    if (strlen(key) != VAPPR_KEY_HEX || !vappr_hex_ok(key, VAPPR_KEY_HEX, VAPPR_KEY_HEX) ||
        !vappr_hex_ok(sig, 16, VFIPS_SIG_HEX_MAX)) {
        snprintf(why, wn, "refused: a malformed signature");
        return why;
    }
    int k = apv_pinned(g_gr_p, key);
    if (k < 0) { snprintf(why, wn, "refused: signed by a key the policy pins as no approver's"); return why; }
    if (su->su_approvers[0] && strcmp(su->su_approvers, g_gr_p->v.approvers[k].group)) {
        snprintf(why, wn, "refused: signed by a key of group %s; the rule is approved by group %s",
                 g_gr_p->v.approvers[k].group, su->su_approvers);
        return why;
    }
    vappr_sig_t sg;
    memset(&sg, 0, sizeof sg);
    snprintf(sg.kind, sizeof sg.kind, "grant");
    snprintf(sg.key, sizeof sg.key, "%s", key);
    snprintf(sg.sig, sizeof sg.sig, "%s", sig);
    char e[120];
    if (!vappr_verify(&sg, "grant", text, strlen(text), e, sizeof e)) {
        snprintf(why, wn, "refused: %s", e);
        return why;
    }
    *ki = k;
    return NULL;
}
