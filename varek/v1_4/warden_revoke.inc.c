/* SPDX-License-Identifier: MIT
 * warden_revoke.inc.c — v1.28 step 4 (docs/security/v1.28-credential-release.md,
 * section 4): revoking a run. Included by warden.c.
 *
 * When the Warden runs as root it opens a control socket for the run,
 * /run/varek/<run>.ctl (the directory 0700, the socket 0600, both root's),
 * and `varek revoke <run>` writes "revoke" to it. Only a peer the kernel
 * says is root (SO_PEERCRED) may revoke. Then:
 *   - the run is recorded `revoked` (who asked: uid and pid);
 *   - every later mediated call is answered UNSATISFIED, recorded with rule
 *     "revoked" (policy_decide, and the supervision loop before anything
 *     else), the proxy's name and request decisions included;
 *   - warden-proxy clears every value and placeholder and closes every
 *     connection (`revocation_proxy`: the values it still holds, 0);
 *   - warden-secrets revokes the run's Vault leases (`revocation_leases`).
 * What was sent before stays sent; the run is not ended (decision D6).
 *
 * The helper's reports on leased secrets it renewed (or could not) are
 * recorded here too: `lease_renewed`, `lease_renewal_failed`.
 *
 * v1.28.1 step 4 (docs/security/v1.28.1-delegation-chain.md, section 4, D5):
 * when the user's token (--on-behalf-of) expires during the run, the Warden
 * records `on_behalf_of_expired` and, by default, revokes the run as above,
 * the revocation recorded `"by":"on_behalf_of_expiry"`;
 * `--on-behalf-of-expiry record` records it and lets the run go on. */

static bool g_revoked;
static int  g_ctl_listen = -1;
static char g_ctl_path[100];
/* /run/varek, held: the socket is removed through it, so in the node
 * agent's supervisor, in the container's mount namespace by then, the
 * node's is (review) */
static int  g_ctl_dir = -1;
static pid_t g_ctl_owner;               /* only the Warden removes it, never a child */

static void ctl_close(void);
static void ctl_atexit(void) { if (getpid() == g_ctl_owner) ctl_close(); }

/* Open the run's control socket (as root). Not fatal: without it the run
 * cannot be revoked, and the Warden says so. */
static void ctl_open(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "[warden] note: not running as root: this run cannot be revoked (varek revoke)\n");
        return;
    }
    if (mkdir("/run/varek", 0700) < 0 && errno != EEXIST) goto fail;
    struct stat st;
    if (lstat("/run/varek", &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 077)) {
        errno = EPERM;
        goto fail;
    }
    if (g_ctl_dir < 0 && (g_ctl_dir = open("/run/varek", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0) goto fail;
    snprintf(g_ctl_path, sizeof g_ctl_path, "/run/varek/%s.ctl", g_run_id);
    (void)unlink(g_ctl_path);
    int s = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s < 0) goto fail;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%.100s", g_ctl_path);
    mode_t old = umask(077);
    int b = bind(s, (struct sockaddr *)&sa, sizeof sa);
    umask(old);
    if (b < 0 || chmod(g_ctl_path, 0600) < 0 || listen(s, 4) < 0) {
        int e = errno;
        close(s);
        (void)unlink(g_ctl_path);
        errno = e;
        goto fail;
    }
    g_ctl_listen = s;
    g_ctl_owner = getpid();
    (void)atexit(ctl_atexit);              /* a start refused after this point */
    fprintf(stderr, "[warden] revocation: varek revoke %s (%s)\n", g_run_id, g_ctl_path);
    return;
fail:
    g_ctl_path[0] = '\0';
    fprintf(stderr, "[warden] note: cannot open /run/varek/ for this run's control socket (%s): it cannot "
            "be revoked\n", strerror(errno));
}

static void ctl_close(void) {
    if (g_ctl_owner && getpid() != g_ctl_owner) return;
    if (g_ctl_listen >= 0) close(g_ctl_listen);
    g_ctl_listen = -1;
    if (g_ctl_path[0]) {
        const char *base = strrchr(g_ctl_path, '/');
        if (g_ctl_dir >= 0 && base) (void)unlinkat(g_ctl_dir, base + 1, 0);
        else (void)unlink(g_ctl_path);
    }
    g_ctl_path[0] = '\0';
}

/* What was decided before the revocation and is not yet answered (a connect
 * the Warden is still dialing, for the agent or for the proxy) is refused
 * now, recorded with rule `revoked`: no decision is recorded as allowed
 * after `revoked`. A send on a connection already allowed goes on. */
static void revoke_pending(int notify_fd) {
    for (int i = g_npend - 1; i >= 0; i--) {
        struct pending_op *op = g_pend[i];
        if (op->kind == PEND_SEND) continue;
        if (op->kind == PEND_STUB) {
            /* review: a connect to the stub is made on the agent's own
             * socket; dissolve it, so the socket is not left connected after
             * the agent is told EACCES (the stub refuses every question now
             * in any case) */
            struct sockaddr un = { .sa_family = AF_UNSPEC };
            (void)connect(op->sock, &un, sizeof un);
            stub_pend_restore(op);
        }
        send_errno(notify_fd, op->id, EACCES);
        net_record(op->tid, op->act, op->d_raw, DEC_DENY, "revoked", &op->t0, EACCES);
        pend_free(i);
    }
    for (int k = 0; k < PX_MAX_DIAL; k++)
        if (g_px[k].used) px_refuse(&g_px[k], DEC_ALLOW, "revoked", EACCES);
}

/* by: NULL for `varek revoke` (the peer's uid and pid), else what revoked it */
static void revoke_run_by(const char *by, uid_t uid, pid_t pid, int notify_fd) {
    g_revoked = true;
    FILE *f = rec_begin();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (by)
        fprintf(f, "{\"event\":\"revoked\",\"run\":\"%s\",\"by\":\"%s\",\"timestamp_ns\":%lld}\n",
                g_run_id, by, (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    else
        fprintf(f, "{\"event\":\"revoked\",\"run\":\"%s\",\"by_uid\":%u,\"by_pid\":%d,\"timestamp_ns\":%lld}\n",
                g_run_id, (unsigned)uid, (int)pid, (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    rec_end(NULL);
    revoke_pending(notify_fd);
    log_line_start();
    if (by) fprintf(g_log, "[warden] the run is revoked (%s): every later call is refused\n", by);
    else fprintf(g_log, "[warden] the run is revoked (by uid %u, pid %d): every later call is refused\n",
                 (unsigned)uid, (int)pid);
    if (g_proxy.ctl >= 0) {
        struct wp_msg m = { .type = WP_MSG_REVOKE, .port = 0 };
        if (send(g_proxy.ctl, &m, sizeof m, MSG_DONTWAIT | MSG_NOSIGNAL) != (ssize_t)sizeof m) {
            log_line_start();
            fprintf(g_log, "[warden] could not tell the proxy to clear its values (%s); its requests are "
                    "refused all the same, and no revocation_proxy is recorded\n", strerror(errno));
        }
    }
    if (g_secrets.ctl >= 0 && ws_revoke(&g_secrets) < 0) {
        log_line_start();
        fprintf(g_log, "[warden] could not tell warden-secrets to revoke the run's leases (%s)\n", strerror(errno));
    }
}

static void revoke_run(uid_t uid, pid_t pid, int notify_fd) { revoke_run_by(NULL, uid, pid, notify_fd); }

/* v1.28.1 step 4: the user's token's expiry */
static bool g_obo_expired;

static long long realtime_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* How long until the token expires (poll's timeout): -1 for no token, or
 * once it has */
static int obo_timeout_ms(void) {
    if (!g_identity.has_user || g_obo_expired) return -1;
    long long d = (long long)g_identity.exp * 1000 - realtime_ms();
    return d <= 0 ? 0 : d > 3600000 ? 3600000 : (int)d;
}

/* Before anything else each round: the token has expired (its `exp`, no
 * leeway) */
static void obo_check(int notify_fd) {
    if (!g_identity.has_user || g_obo_expired || realtime_ms() < (long long)g_identity.exp * 1000) return;
    g_obo_expired = true;
    FILE *f = rec_begin();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(f, "{\"event\":\"on_behalf_of_expired\",\"run\":\"%s\",\"subject\":\"", g_run_id);
    json_escape(f, g_identity.sub);
    fprintf(f, "\",\"expires\":%lld,\"action\":\"%s\",\"timestamp_ns\":%lld}\n", (long long)g_identity.exp,
            g_obo_on_expiry ? "record" : "revoke", (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    rec_end(NULL);
    log_line_start();
    fprintf(g_log, "[warden] the user's token (%s) has expired%s\n", g_identity.sub,
            g_obo_on_expiry ? "; the run goes on (--on-behalf-of-expiry record)" :
            g_revoked ? "; the run was already revoked" : "; revoking the run");
    if (!g_obo_on_expiry && !g_revoked) revoke_run_by("on_behalf_of_expiry", 0, 0, notify_fd);
}

/* A peer on the control socket: one request, one answer. */
static void ctl_service(int notify_fd) {
    int c = accept4(g_ctl_listen, NULL, NULL, SOCK_CLOEXEC);
    if (c < 0) return;
    struct ucred cr;
    socklen_t cl = sizeof cr;
    char req[32] = "";
    const char *ans;
    struct pollfd pf = { .fd = c, .events = POLLIN };
    ssize_t n = -1;
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0) ans = "refused: the peer cannot be named";
    else if (cr.uid != 0) ans = "refused: only root may revoke a run";
    else if (poll(&pf, 1, 1000) != 1 || (n = recv(c, req, sizeof req - 1, MSG_DONTWAIT)) <= 0)
        ans = "refused: no request";
    else {
        req[n] = '\0';
        if (strcmp(req, "revoke")) ans = "refused: unknown request";
        else if (g_revoked) ans = "already revoked";
        else { revoke_run(cr.uid, cr.pid, notify_fd); ans = "revoked"; }
    }
    (void)send(c, ans, strlen(ans), MSG_DONTWAIT | MSG_NOSIGNAL);
    close(c);
}

/* warden-secrets' reports after the start: renewals, and its answer to a
 * revocation. -1 when it has gone. */
static int secrets_service(const struct policy *p) {
    for (;;) {
        union { struct ws_revoked r; struct ws_renewed n; uint32_t type; } m;
        ssize_t k = recv(g_secrets.ctl, &m, sizeof m, MSG_DONTWAIT);
        if (k < 0 && errno == EINTR) continue;
        if (k < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
        if (k == 0) return -1;
        FILE *f;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        long long now = (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
        if (k == (ssize_t)sizeof m.r && m.type == WS_MSG_REVOKED) {
            f = rec_begin();
            fprintf(f, "{\"event\":\"revocation_leases\",\"run\":\"%s\",\"revoked\":%u,\"failed\":%u,"
                    "\"timestamp_ns\":%lld}\n", g_run_id, m.r.revoked, m.r.failed, now);
            rec_end(NULL);
        } else if (k == (ssize_t)sizeof m.n && m.type == WS_MSG_RENEWED && m.n.index < p->v.ncreds &&
                   memchr(m.n.why, 0, sizeof m.n.why)) {
            for (char *c = m.n.why; *c; c++) if (*c < ' ' || *c > '~' || *c == '"' || *c == '\\') *c = '?';
            f = rec_begin();
            if (m.n.ok)
                fprintf(f, "{\"event\":\"lease_renewed\",\"run\":\"%s\",\"credential\":\"%s\",\"ttl\":%u,"
                        "\"timestamp_ns\":%lld}\n", g_run_id, p->v.creds[m.n.index].name, m.n.ttl, now);
            else
                fprintf(f, "{\"event\":\"lease_renewal_failed\",\"run\":\"%s\",\"credential\":\"%s\",\"why\":\"%s\","
                        "\"timestamp_ns\":%lld}\n", g_run_id, p->v.creds[m.n.index].name, m.n.why, now);
            rec_end(NULL);
        } else {
            return -1;                                  /* not the helper's */
        }
    }
}

/* The proxy's answer to a revocation (from proxy_service). */
static void revoked_proxy_record(uint32_t held) {
    FILE *f = rec_begin();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(f, "{\"event\":\"revocation_proxy\",\"run\":\"%s\",\"values_held\":%u,\"timestamp_ns\":%lld}\n",
            g_run_id, held, (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    rec_end(NULL);
}
