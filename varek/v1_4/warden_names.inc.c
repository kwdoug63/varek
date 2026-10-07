/* ---------------- v1.24: host names (sections 3 and 4) ----------------
 *
 * docs/security/v1.21-stage2-host-names.md. Included by warden.c before
 * warden_net.inc.c. The resolution table (g_names, warden_resolve.c) holds
 * what each allowed name resolved to; this file uses it in two places.
 *
 * Section 3, the views. While the policy has a host name rule, a read-only
 * open of /etc/hosts, /etc/resolv.conf, /etc/nsswitch.conf or /etc/host.conf
 * is answered with a read-only descriptor on a sealed memfd the Warden wrote, never the host's
 * file:
 *   /etc/hosts          localhost, then each allowed name's current addresses
 *   /etc/resolv.conf    a nameserver no one answers (192.0.2.1, reserved for
 *                       documentation), attempts:1 timeout:0 (musl, which
 *                       queries it, then gives up at once)
 *   /etc/nsswitch.conf  hosts: files (and files for passwd, group)
 *   /etc/host.conf      multi on: without it (no file, or one the policy does
 *                       not let the agent read) glibc returns only the first
 *                       /etc/hosts line for a name, so the agent got a single
 *                       address, possibly of a family it has no route for
 * The open is matched by the path the agent gave (when it is exactly one of
 * the four) or by the canonical path it resolves to (the four, or what each
 * resolved to on the host when the Warden started: /etc/resolv.conf is often
 * a symlink). It needs no allow rule; a deny rule that covers the path wins
 * (the agent then resolves nothing). Each open is a record (rule hosts_view,
 * resolv_view, nsswitch_view or hostconf_view) with the hosts view's
 * generation, so an audit can tie what the agent could resolve to the
 * resolution records. While the
 * policy has a name rule every connect to port 53 is refused (rule
 * dns_refused), whatever the numeric rules say.
 *
 * Section 4, deciding a connect. The destination is looked up in the table
 * (current and grace addresses) for the names that resolved to it. The
 * connect is decided on every candidate string: the numeric destination and
 * name:port for each such name. The first rule (in policy order) that holds on
 * ANY candidate decides, so a deny rule on a name wins over a later numeric
 * allow of its address and an earlier numeric deny wins over a name allow.
 * The record carries the candidate it was decided on ("resolved"), the
 * address dialed, every candidate and the table generation; an ALLOW's
 * certificate is over the deciding candidate, and the checker also confirms
 * that no earlier host rule holds on any other candidate. */

/* Defined in warden_net.inc.c, which is included after this file. */
static uint64_t g_report_seq;
static uint64_t ns_between(const struct timespec *a, const struct timespec *b);

#define NAMES_MAX_CAND 16                 /* candidates per connect: the address + 15 names */

/* ---- section 3: the views ---- */

enum { VIEW_HOSTS = 0, VIEW_RESOLV = 1, VIEW_NSSWITCH = 2, VIEW_HOSTCONF = 3, VIEW_N = 4 };
static const char *const kViewPath[VIEW_N] = { "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
                                               "/etc/host.conf" };
static const char *const kViewRule[VIEW_N] = { "hosts_view", "resolv_view", "nsswitch_view",
                                               "hostconf_view" };
static char     g_view_canon[VIEW_N][PATH_LIMIT];  /* realpath on the host at startup, or "" */
static int      g_view_fd[VIEW_N] = { -1, -1, -1, -1 };
static uint64_t g_view_gen = UINT64_MAX;          /* g_names.generation the hosts memfd holds */

/* At startup: what each view path resolves to on the host. */
static void views_setup(void) {
    for (int v = 0; v < VIEW_N; v++) {
        char *rp = realpath(kViewPath[v], NULL);
        g_view_canon[v][0] = '\0';
        if (rp && strlen(rp) < PATH_LIMIT) snprintf(g_view_canon[v], PATH_LIMIT, "%s", rp);
        free(rp);
    }
}

static int view_by_target(const char *target) {
    for (int v = 0; v < VIEW_N; v++) if (!strcmp(target, kViewPath[v])) return v;
    return -1;
}

static int view_by_canonical(const char *resolved) {
    for (int v = 0; v < VIEW_N; v++)
        if (!strcmp(resolved, kViewPath[v]) || (g_view_canon[v][0] && !strcmp(resolved, g_view_canon[v])))
            return v;
    return -1;
}

/* A view is served for an open that only reads. */
static bool view_open_readonly(const struct action *a) {
    return a->flags_known && (a->open_flags & O_ACCMODE) == O_RDONLY &&
           !(a->open_flags & (O_CREAT | O_TRUNC | O_TMPFILE));
}

/* A sealed memfd holding the view's bytes. -1 on failure. */
static int view_memfd(int v) {
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (!f) return -1;
    if (v == VIEW_HOSTS) wr_hosts_view(&g_names, f);
    else if (v == VIEW_RESOLV) fputs("nameserver 192.0.2.1\noptions attempts:1 timeout:0\n", f);
    else if (v == VIEW_NSSWITCH) fputs("passwd: files\ngroup: files\nhosts: files\n", f);
    else fputs("multi on\n", f);
    if (fclose(f) != 0) { free(buf); return -1; }
    int fd = memfd_create(kViewRule[v], MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) { free(buf); return -1; }
    bool ok = write_all(fd, buf, len) == 0 &&
              fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0;
    free(buf);
    if (!ok) { close(fd); return -1; }
    return fd;
}

/* A new read-only descriptor on view v (its own file offset), -1 on failure. */
static int view_open(int v) {
    if (v == VIEW_HOSTS && g_view_gen != g_names.generation && g_view_fd[v] >= 0) {
        close(g_view_fd[v]);
        g_view_fd[v] = -1;
    }
    if (g_view_fd[v] < 0) {
        g_view_fd[v] = view_memfd(v);
        if (g_view_fd[v] < 0) return -1;
        if (v == VIEW_HOSTS) g_view_gen = g_names.generation;
    }
    char p[64];
    snprintf(p, sizeof p, "/proc/self/fd/%d", g_view_fd[v]);
    return open(p, O_RDONLY | O_CLOEXEC);
}

/* Answer a read-only open of view v. The policy is asked about the view's
 * path: an explicit deny wins; otherwise the view is served. */
static void view_serve(int notify_fd, const struct seccomp_notif *req, struct action *a,
                       const struct policy *p, int v, const struct timespec *t0) {
    snprintf(a->resolved, sizeof a->resolved, "%s", kViewPath[v]);
    decision_t d_raw = policy_decide(p, a);
    struct timespec t1;
    if (d_raw == DEC_DENY) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        emit_pathology(g_report_seq++, req->pid, a, d_raw, DEC_DENY, decision_rule_id(a, d_raw),
                       ns_between(t0, &t1), EACCES);
        send_simple(notify_fd, req->id, DEC_DENY);
        return;
    }
    snprintf(a->extra, sizeof a->extra, "\"view_generation\":%llu,",
             (unsigned long long)g_names.generation);
    int fd = view_open(v);
    int err = 0;
    if (fd < 0) err = EACCES;
    else if (!notif_id_valid(notify_fd, req->id) || inject_fd(notify_fd, req->id, fd) != 0) err = EACCES;
    if (fd >= 0) close(fd);
    if (err) send_errno(notify_fd, req->id, err);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    emit_pathology(g_report_seq++, req->pid, a, d_raw, DEC_ALLOW,
                   err ? "view_failed" : kViewRule[v], ns_between(t0, &t1), err);
}

/* ---- section 4: candidates for a connect ---- */

/* v1.24 review: addresses a name may not lead to. Whoever controls an
 * allowed name's DNS could answer with one of these, and the Warden dials
 * from the host's network namespace: loopback would reach the host's own
 * services, link-local the cloud metadata service (169.254.169.254). A
 * connect to one is decided on its address alone, so only a numeric rule can
 * allow it. Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7) are not
 * here: internal APIs are reached by name there. */
static bool special_address(const wr_ip_t *ip) { return wr_special_address(ip); }

/* Fill a->cand with the numeric destination (a->resolved, "addr:port") and
 * name:port for each name the address belongs to. 0, or -1 when the address
 * belongs to more names than a connect can carry (refused: a name left out
 * could hold an earlier deny rule). */
static int names_candidates(struct action *a, int fam, const void *addr, unsigned port) {
    a->ncand = 0;
    a->special_addr = false;
    /* a numeric destination is at most 47 bytes ("[IPv6]:65535") */
    snprintf(a->cand[a->ncand++], sizeof a->cand[0], "%.63s", a->resolved);
    snprintf(a->dialed, sizeof a->dialed, "%.63s", a->resolved);
    if (!g_names_on) return 0;
    wr_ip_t ip;
    memset(&ip, 0, sizeof ip);
    if (fam == AF_INET6 && IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)addr)) {
        ip.fam = 4;
        memcpy(ip.a, (const unsigned char *)addr + 12, 4);
    } else if (fam == AF_INET6) {
        ip.fam = 6;
        memcpy(ip.a, addr, 16);
    } else {
        ip.fam = 4;
        memcpy(ip.a, addr, 4);
    }
    if (special_address(&ip)) {
        a->special_addr = true;          /* decided as a number (special_address) */
        return 0;
    }
    size_t idx[NAMES_MAX_CAND];
    size_t n = wr_names_for(&g_names, &ip, wr_now_ms(), idx, NAMES_MAX_CAND - 1);
    if (n > NAMES_MAX_CAND - 1) return -1;
    for (size_t k = 0; k < n; k++)
        snprintf(a->cand[a->ncand++], sizeof a->cand[0], "%s:%u", g_names.e[idx[k]].name, port);
    return 0;
}

/* Decide a connect over its candidates: the first rule (policy order) that
 * holds on any candidate decides; a->resolved becomes that candidate. With
 * one candidate this is policy_decide. */
static decision_t names_decide(const struct policy *p, struct action *a) {
    if (a->ncand <= 1) return policy_decide(p, a);
    int best = -1, best_ri = -1;
    decision_t best_d = DEC_UNKNOWN;
    const char *best_why = NULL;
    for (int c = 0; c < a->ncand; c++) {
        snprintf(a->resolved, sizeof a->resolved, "%s", a->cand[c]);
        decision_t d = policy_decide(p, a);
        if (a->rule_index >= 0 && (best_ri < 0 || a->rule_index < best_ri)) {
            best = c;
            best_ri = a->rule_index;
            best_d = d;
            best_why = a->why;
        }
    }
    if (best < 0) {                       /* no rule holds on any candidate */
        snprintf(a->resolved, sizeof a->resolved, "%s", a->cand[0]);
        return policy_decide(p, a);
    }
    snprintf(a->resolved, sizeof a->resolved, "%s", a->cand[best]);
    a->rule_index = best_ri;
    a->policy_line = p->v.rules[best_ri].line;
    a->why = best_why;
    return best_d;
}

/* The record fields for a connect decided with names. */
static void names_record_fields(struct action *a) {
    if (!g_names_on || a->ncand == 0) return;     /* a Unix connect has no candidates */
    size_t w = 0;
    int k = snprintf(a->extra, sizeof a->extra, "\"dialed\":\"%s\",\"candidates\":[", a->dialed);
    if (k > 0) w = (size_t)k;
    for (int c = 0; c < a->ncand && w < sizeof a->extra; c++) {
        k = snprintf(a->extra + w, sizeof a->extra - w, "%s\"%s\"", c ? "," : "", a->cand[c]);
        if (k > 0) w += (size_t)k;
    }
    if (w < sizeof a->extra)
        snprintf(a->extra + w, sizeof a->extra - w, "],%s\"resolution_generation\":%llu,",
                 a->special_addr ? "\"special_address\":true," : "",
                 (unsigned long long)g_names.generation);
}
