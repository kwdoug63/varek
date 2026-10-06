// SPDX-License-Identifier: MIT
// warden_resolve.c — the Warden's resolution table (v1.24). See
// warden_resolve.h for what it does and the design document for why.

#include "warden_resolve.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void wr_config_default(wr_config_t *c) {
    memset(c, 0, sizeof *c);
    c->ttl_min = 30;
    c->ttl_max = 3600;
    c->grace_max = 300;
    c->timeout_s = 2;
    c->attempts = 2;
}

int64_t wr_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* "a.b.c.d:port" -> sockaddr_in. */
static int parse_server(const char *s, struct sockaddr_in *sa) {
    char host[32];
    const char *colon = strrchr(s, ':');
    size_t hl = colon ? (size_t)(colon - s) : strlen(s);
    if (hl == 0 || hl >= sizeof host) return -1;
    memcpy(host, s, hl);
    host[hl] = '\0';
    unsigned long port = 53;
    if (colon) {
        char *end;
        errno = 0;
        port = strtoul(colon + 1, &end, 10);
        if (errno || *end || end == colon + 1 || port == 0 || port > 65535) return -1;
    }
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port = htons((uint16_t)port);
    return inet_pton(AF_INET, host, &sa->sin_addr) == 1 ? 0 : -1;
}

int wr_table_init(wr_table_t *t, const wr_config_t *cfg, char *why, size_t wn) {
    memset(t, 0, sizeof *t);
    t->cfg = *cfg;
    if (cfg->ttl_min == 0 || cfg->ttl_max < cfg->ttl_min) {
        snprintf(why, wn, "the TTL clamp needs 0 < min <= max (got %u, %u)", cfg->ttl_min, cfg->ttl_max);
        return -1;
    }
    if (cfg->timeout_s == 0 || cfg->attempts == 0) {
        snprintf(why, wn, "the resolver timeout and attempts must be at least 1");
        return -1;
    }
    if (cfg->server) {
        struct sockaddr_in sa;
        if (parse_server(cfg->server, &sa) < 0) {
            snprintf(why, wn, "resolver %s: need a.b.c.d[:port]", cfg->server);
            return -1;
        }
        char a[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sa.sin_addr, a, sizeof a);
        snprintf(t->resolver, sizeof t->resolver, "%s:%u", a, (unsigned)ntohs(sa.sin_port));
    } else {
        snprintf(t->resolver, sizeof t->resolver, "resolv.conf");
    }
    return 0;
}

int wr_table_add(wr_table_t *t, const char *name) {
    size_t nl = strlen(name);
    if (nl == 0 || nl > WR_NAME_MAX) return -1;
    for (size_t i = 0; i < t->n; i++)
        if (!strcmp(t->e[i].name, name)) return (int)i;
    wr_entry_t *ne = realloc(t->e, (t->n + 1) * sizeof *ne);
    if (!ne) return -1;
    t->e = ne;
    wr_entry_t *e = &t->e[t->n];
    memset(e, 0, sizeof *e);
    memcpy(e->name, name, nl + 1);
    e->ttl_eff = t->cfg.ttl_min;
    return (int)t->n++;
}

void wr_table_free(wr_table_t *t) {
    if (t->async) wr_async_stop(t);
    for (size_t i = 0; i < t->n; i++) free(t->e[i].addrs);
    free(t->e);
    t->e = NULL;
    t->n = 0;
}

/* ------------------------------------------------------------------ lookup */

/* One query (A or AAAA) on an initialized resolver state. */
static void query_one(res_state rs, const char *name, int type, wr_status_t *st, uint32_t *ttl,
                      wr_ip_t *out, size_t *nout) {
    unsigned char ans[8192];
    *nout = 0;
    *ttl = 0;
    int len = res_nquery(rs, name, ns_c_in, type, ans, sizeof ans);
    if (len < 0) {
        switch (rs->res_h_errno) {
            case HOST_NOT_FOUND: *st = WR_ST_NXDOMAIN; break;
            case NO_DATA:        *st = WR_ST_NODATA; break;
            default:             *st = WR_ST_FAIL; break;    /* TRY_AGAIN, NO_RECOVERY, NETDB_INTERNAL */
        }
        return;
    }
    ns_msg msg;
    if (ns_initparse(ans, len, &msg) < 0) { *st = WR_ST_FAIL; return; }
    if (ns_msg_getflag(msg, ns_f_rcode) == ns_r_nxdomain) { *st = WR_ST_NXDOMAIN; return; }
    if (ns_msg_getflag(msg, ns_f_rcode) != ns_r_noerror) { *st = WR_ST_FAIL; return; }
    /* Follow the CNAME chain from the queried name: the records that count
     * are those owned by a name in the chain. */
    char chain[WR_MAX_CNAME + 1][NS_MAXDNAME];
    size_t nchain = 1;
    snprintf(chain[0], sizeof chain[0], "%s", name);
    size_t cl0 = strlen(chain[0]);
    if (cl0 && chain[0][cl0 - 1] == '.') chain[0][cl0 - 1] = '\0';   /* owners come without the dot */
    int count = ns_msg_count(msg, ns_s_an);
    uint32_t minttl = UINT32_MAX;
    bool grew = true;
    /* Records may come in any order: repeat until the chain stops growing
     * (at most WR_MAX_CNAME + 1 passes). */
    bool used[512] = { false };
    if (count > 512) count = 512;
    for (size_t pass = 0; grew && pass <= WR_MAX_CNAME; pass++) {
        grew = false;
        for (int k = 0; k < count; k++) {
            if (used[k]) continue;
            ns_rr rr;
            if (ns_parserr(&msg, ns_s_an, k, &rr) < 0) { *st = WR_ST_FAIL; *nout = 0; return; }
            if (ns_rr_class(rr) != ns_c_in) { used[k] = true; continue; }
            bool owned = false;
            for (size_t c = 0; c < nchain; c++)
                if (!strcasecmp(ns_rr_name(rr), chain[c])) { owned = true; break; }
            if (!owned) continue;
            used[k] = true;
            if (ns_rr_type(rr) == ns_t_cname) {
                if (nchain > WR_MAX_CNAME) { *st = WR_ST_FAIL; *nout = 0; return; }
                if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), ns_rr_rdata(rr),
                                       chain[nchain], sizeof chain[nchain]) < 0) {
                    *st = WR_ST_FAIL; *nout = 0; return;
                }
                nchain++;
                grew = true;
                if (ns_rr_ttl(rr) < minttl) minttl = ns_rr_ttl(rr);
            } else if ((int)ns_rr_type(rr) == type) {
                size_t al = type == ns_t_a ? 4 : 16;
                if (ns_rr_rdlen(rr) != al) { *st = WR_ST_FAIL; *nout = 0; return; }
                if (ns_rr_ttl(rr) < minttl) minttl = ns_rr_ttl(rr);
                bool dup = false;
                for (size_t j = 0; j < *nout; j++)
                    if (!memcmp(out[j].a, ns_rr_rdata(rr), al)) { dup = true; break; }
                if (!dup && *nout < WR_MAX_ADDRS) {
                    wr_ip_t *ip = &out[(*nout)++];
                    memset(ip, 0, sizeof *ip);
                    ip->fam = type == ns_t_a ? 4 : 6;
                    memcpy(ip->a, ns_rr_rdata(rr), al);
                }
            }
        }
    }
    if (*nout == 0) { *st = WR_ST_NODATA; return; }
    *st = WR_ST_OK;
    *ttl = minttl;
}

void wr_lookup(const wr_table_t *t, const char *name, wr_result_t *r) {
    memset(r, 0, sizeof *r);
    struct __res_state rs;
    memset(&rs, 0, sizeof rs);
    if (res_ninit(&rs) < 0) {
        r->st[0] = r->st[1] = WR_ST_FAIL;
        return;
    }
    rs.retrans = (int)t->cfg.timeout_s;
    rs.retry = (int)t->cfg.attempts;
    /* The name as given, nothing appended: no search list, no ndots games. */
    rs.options &= ~(RES_DEFNAMES | RES_DNSRCH);
    if (t->cfg.server) {
        struct sockaddr_in sa;
        if (parse_server(t->cfg.server, &sa) == 0) {
            rs.nsaddr_list[0] = sa;
            rs.nscount = 1;
        }
    }
    /* "name." so res_nquery never applies a search domain. */
    char fq[WR_NAME_MAX + 2];
    snprintf(fq, sizeof fq, "%s.", name);
    query_one(&rs, fq, ns_t_a, &r->st[0], &r->ttl[0], r->ip[0], &r->n[0]);
    query_one(&rs, fq, ns_t_aaaa, &r->st[1], &r->ttl[1], r->ip[1], &r->n[1]);
    res_nclose(&rs);
}

/* ------------------------------------------------------------------- table */

static bool ip_eq(const wr_ip_t *x, const wr_ip_t *y) {
    return x->fam == y->fam && !memcmp(x->a, y->a, x->fam == 4 ? 4 : 16);
}

static int addr_push(wr_entry_t *e, const wr_ip_t *ip, int64_t until) {
    if (e->n == e->cap) {
        size_t nc = e->cap ? 2 * e->cap : 8;
        wr_addr_t *na = realloc(e->addrs, nc * sizeof *na);
        if (!na) return -1;
        e->addrs = na;
        e->cap = nc;
    }
    e->addrs[e->n].ip = *ip;
    e->addrs[e->n].until_ms = until;
    e->n++;
    return 0;
}

static uint32_t clamp_ttl(const wr_config_t *c, uint32_t ttl) {
    if (ttl < c->ttl_min) return c->ttl_min;
    if (ttl > c->ttl_max) return c->ttl_max;
    return ttl;
}

bool wr_apply(wr_table_t *t, size_t i, const wr_result_t *r, int64_t now) {
    wr_entry_t *e = &t->e[i];
    e->pending = false;
    e->lookups++;
    wr_expire(t, now);
    uint32_t old_ttl = e->ttl_eff;
    int64_t grace_until = now + (int64_t)(old_ttl < t->cfg.grace_max ? old_ttl : t->cfg.grace_max) * 1000;
    bool changed = false;
    bool any_answer = false;
    uint32_t minttl = UINT32_MAX;
    for (int f = 0; f < 2; f++) {
        uint8_t fam = f == 0 ? 4 : 6;
        if (r->st[f] == WR_ST_FAIL) continue;          /* keep this family's current set */
        any_answer = true;
        if (r->st[f] == WR_ST_OK && r->ttl[f] < minttl) minttl = r->ttl[f];
        /* Current addresses of this family that are no longer in the answer
         * go into grace. */
        for (size_t k = 0; k < e->n; k++) {
            wr_addr_t *a = &e->addrs[k];
            if (a->ip.fam != fam || a->until_ms != 0) continue;
            bool kept = false;
            for (size_t j = 0; j < r->n[f]; j++)
                if (ip_eq(&a->ip, &r->ip[f][j])) { kept = true; break; }
            if (!kept) { a->until_ms = grace_until; changed = true; }
        }
        /* Every address in the answer is current (back from grace, or new). */
        for (size_t j = 0; j < r->n[f]; j++) {
            bool found = false;
            for (size_t k = 0; k < e->n; k++) {
                wr_addr_t *a = &e->addrs[k];
                if (!ip_eq(&a->ip, &r->ip[f][j])) continue;
                found = true;
                if (a->until_ms != 0) { a->until_ms = 0; changed = true; }
                break;
            }
            if (!found) {
                if (addr_push(e, &r->ip[f][j], 0) < 0) continue;   /* out of memory: not added */
                changed = true;
            }
        }
    }
    bool have = false;
    for (size_t k = 0; k < e->n; k++) if (e->addrs[k].until_ms == 0) { have = true; break; }
    if (have) e->ever_ok = true;
    /* The next refresh: at the clamped TTL of what answered, or after ttl_min
     * when nothing answered (a failure, or a negative answer). */
    e->ttl_eff = (any_answer && minttl != UINT32_MAX) ? clamp_ttl(&t->cfg, minttl) : t->cfg.ttl_min;
    e->next_ms = now + (int64_t)e->ttl_eff * 1000;
    if (changed) t->generation++;
    return changed;
}

void wr_expire(wr_table_t *t, int64_t now) {
    for (size_t i = 0; i < t->n; i++) {
        wr_entry_t *e = &t->e[i];
        size_t w = 0;
        for (size_t k = 0; k < e->n; k++) {
            if (e->addrs[k].until_ms != 0 && e->addrs[k].until_ms <= now) continue;
            e->addrs[w++] = e->addrs[k];
        }
        e->n = w;
    }
}

int wr_next_due_ms(const wr_table_t *t, int64_t now) {
    int64_t best = -1;
    for (size_t i = 0; i < t->n; i++) {
        if (t->e[i].pending) continue;
        int64_t d = t->e[i].next_ms - now;
        if (d < 0) d = 0;
        if (best < 0 || d < best) best = d;
    }
    if (best > INT32_MAX) best = INT32_MAX;
    return (int)best;
}

bool wr_entry_has(const wr_entry_t *e, const wr_ip_t *ip, int64_t now) {
    for (size_t k = 0; k < e->n; k++) {
        const wr_addr_t *a = &e->addrs[k];
        if (a->until_ms != 0 && a->until_ms <= now) continue;
        if (ip_eq(&a->ip, ip)) return true;
    }
    return false;
}

size_t wr_names_for(const wr_table_t *t, const wr_ip_t *ip, int64_t now, size_t *out, size_t max) {
    size_t k = 0;
    for (size_t i = 0; i < t->n; i++) {
        if (!wr_entry_has(&t->e[i], ip, now)) continue;
        if (k < max) out[k] = i;
        k++;
    }
    return k;
}

void wr_ip_str(const wr_ip_t *ip, char *out, size_t n) {
    if (!inet_ntop(ip->fam == 4 ? AF_INET : AF_INET6, ip->a, out, (socklen_t)n) && n) out[0] = '\0';
}

int wr_ip_parse(const char *s, wr_ip_t *ip) {
    memset(ip, 0, sizeof *ip);
    if (inet_pton(AF_INET, s, ip->a) == 1) { ip->fam = 4; return 0; }
    if (inet_pton(AF_INET6, s, ip->a) == 1) { ip->fam = 6; return 0; }
    return -1;
}

void wr_hosts_view(const wr_table_t *t, FILE *f) {
    fputs("127.0.0.1 localhost\n::1 localhost\n", f);
    char a[INET6_ADDRSTRLEN];
    for (size_t i = 0; i < t->n; i++) {
        const wr_entry_t *e = &t->e[i];
        /* IPv4 before IPv6, whatever order the table holds them in. The
         * table appends a new address after those it keeps, so after a
         * rotation an IPv6 address could come first, and a client that takes
         * only the first line (glibc without "multi on") would get an address
         * the host may have no route for. */
        for (int fam = 4; fam <= 6; fam += 2)
            for (size_t k = 0; k < e->n; k++) {
                if (e->addrs[k].until_ms != 0 || e->addrs[k].ip.fam != fam) continue;
                wr_ip_str(&e->addrs[k].ip, a, sizeof a);
                fprintf(f, "%s %s\n", a, e->name);
            }
    }
}

static const char *st_name(wr_status_t s) {
    switch (s) {
        case WR_ST_OK:       return "ok";
        case WR_ST_NODATA:   return "nodata";
        case WR_ST_NXDOMAIN: return "nxdomain";
        default:             return "fail";
    }
}

void wr_format_record(FILE *f, const char *run, const wr_table_t *t, size_t i,
                      const wr_result_t *r, int64_t now) {
    const wr_entry_t *e = &t->e[i];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    /* Names are lowercase LDH (validated by both policy parsers), so they
     * need no escaping; addresses are inet_ntop output. */
    fprintf(f, "{\"event\":\"resolution\",\"run\":\"%s\",\"name\":\"%s\",\"a\":\"%s\","
               "\"aaaa\":\"%s\",\"addresses\":[", run, e->name, st_name(r->st[0]), st_name(r->st[1]));
    char a[INET6_ADDRSTRLEN];
    bool first = true;
    for (size_t k = 0; k < e->n; k++) {
        if (e->addrs[k].until_ms != 0) continue;
        wr_ip_str(&e->addrs[k].ip, a, sizeof a);
        fprintf(f, "%s\"%s\"", first ? "" : ",", a);
        first = false;
    }
    fputs("],\"grace\":[", f);
    first = true;
    for (size_t k = 0; k < e->n; k++) {
        if (e->addrs[k].until_ms == 0 || e->addrs[k].until_ms <= now) continue;
        wr_ip_str(&e->addrs[k].ip, a, sizeof a);
        fprintf(f, "%s{\"address\":\"%s\",\"until_s\":%lld}", first ? "" : ",", a,
                (long long)((e->addrs[k].until_ms - now + 999) / 1000));
        first = false;
    }
    fputs("],", f);
    uint32_t ttl = UINT32_MAX;
    for (int k = 0; k < 2; k++)
        if (r->st[k] == WR_ST_OK && r->ttl[k] < ttl) ttl = r->ttl[k];
    if (ttl != UINT32_MAX) fprintf(f, "\"ttl\":%u,", ttl);
    fprintf(f, "\"refresh_s\":%u,\"resolver\":\"%s\",\"generation\":%llu,\"timestamp_ns\":%lld}\n",
            e->ttl_eff, t->resolver, (unsigned long long)t->generation,
            (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
}

/* --------------------------------------------------------- resolver helper */

/* The lookups run in a helper process, not a thread: the Warden creates the
 * agent's PID namespace with unshare(CLONE_NEWPID), after which the kernel
 * refuses new threads (clone(CLONE_THREAD) fails with EINVAL), and a thread
 * started before the agent is forked would make that fork unsafe. A process
 * also keeps the resolver library, which parses data from the network, out of
 * the Warden's address space (which holds the log signing key). The helper is
 * a grandchild, so its exit is not the Warden's SIGCHLD; it exits when the
 * Warden's end of the socket closes. */

struct wr_req { uint32_t idx; char name[WR_NAME_MAX + 1]; };
struct wr_rsp { uint32_t idx; wr_result_t r; };

struct wr_async {
    int  fd;                       /* SOCK_SEQPACKET to the helper */
    bool dead;
};

int wr_helper_main(int fd, const wr_config_t *cfg) {
    wr_table_t view;               /* config and resolver label only */
    memset(&view, 0, sizeof view);
    view.cfg = *cfg;
    for (;;) {
        struct wr_req q;
        ssize_t n = recv(fd, &q, sizeof q, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;                       /* the Warden is gone */
        if ((size_t)n != sizeof q) return 1;
        q.name[WR_NAME_MAX] = '\0';
        struct wr_rsp a;
        memset(&a, 0, sizeof a);
        a.idx = q.idx;
        wr_lookup(&view, q.name, &a.r);
        while (send(fd, &a, sizeof a, MSG_NOSIGNAL) < 0)
            if (errno != EINTR) return 1;
    }
}

int wr_helper_exec_main(int argc, char **argv) {
    if (argc != 5) return 2;
    wr_config_t cfg;
    wr_config_default(&cfg);
    cfg.server = strcmp(argv[2], "-") ? argv[2] : NULL;
    cfg.timeout_s = (uint32_t)strtoul(argv[3], NULL, 10);
    cfg.attempts = (uint32_t)strtoul(argv[4], NULL, 10);
    if (cfg.timeout_s == 0 || cfg.attempts == 0 || cfg.timeout_s > 60 || cfg.attempts > 10) return 2;
    return wr_helper_main(3, &cfg);
}

int wr_async_start(wr_table_t *t, const char *helper_exe) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) return -1;
    wr_async_t *as = calloc(1, sizeof *as);
    if (!as) { close(sv[0]); close(sv[1]); return -1; }
    char tmo[16], att[16];
    snprintf(tmo, sizeof tmo, "%u", t->cfg.timeout_s);
    snprintf(att, sizeof att, "%u", t->cfg.attempts);
    pid_t mid = fork();
    if (mid < 0) { close(sv[0]); close(sv[1]); free(as); return -1; }
    if (mid == 0) {
        /* The intermediate: start the helper and exit at once. */
        close(sv[0]);
        pid_t h = fork();
        if (h != 0) _exit(h < 0 ? 1 : 0);
        if (helper_exe) {
            if (dup2(sv[1], 3) < 0) _exit(1);       /* dup2 clears close-on-exec */
            int nul = open("/dev/null", O_RDWR);
            if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
            /* every other descriptor (the verdict stream, the anchor) */
            if (syscall(SYS_close_range, 4U, ~0U, 0U) < 0)
                for (int fd = 4; fd < 65536; fd++) close(fd);
            char *const av[] = { (char *)helper_exe, (char *)"--resolver-helper",
                                 (char *)(t->cfg.server ? t->cfg.server : "-"), tmo, att, NULL };
            execv(helper_exe, av);
            _exit(127);
        }
        _exit(wr_helper_main(sv[1], &t->cfg));
    }
    close(sv[1]);
    int st = 0;
    while (waitpid(mid, &st, 0) < 0 && errno == EINTR) { }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { close(sv[0]); free(as); errno = ECHILD; return -1; }
    int fl = fcntl(sv[0], F_GETFL);
    if (fl < 0 || fcntl(sv[0], F_SETFL, fl | O_NONBLOCK) < 0) { close(sv[0]); free(as); return -1; }
    as->fd = sv[0];
    t->async = as;
    return 0;
}

int wr_async_fd(const wr_table_t *t) { return t->async && !t->async->dead ? t->async->fd : -1; }

bool wr_async_alive(const wr_table_t *t) { return t->async && !t->async->dead; }

void wr_async_schedule(wr_table_t *t, int64_t now) {
    wr_async_t *as = t->async;
    if (!as || as->dead) return;
    for (size_t i = 0; i < t->n; i++) {
        if (t->e[i].pending || t->e[i].next_ms > now) continue;
        struct wr_req q;
        memset(&q, 0, sizeof q);
        q.idx = (uint32_t)i;
        memcpy(q.name, t->e[i].name, sizeof q.name);
        if (send(as->fd, &q, sizeof q, MSG_NOSIGNAL | MSG_DONTWAIT) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;   /* next time */
            as->dead = true;
            return;
        }
        t->e[i].pending = true;
    }
}

void wr_async_collect(wr_table_t *t, int64_t now,
                      void (*done)(void *ctx, size_t i, const wr_result_t *r), void *ctx) {
    wr_async_t *as = t->async;
    if (!as || as->dead) return;
    for (;;) {
        struct wr_rsp a;
        ssize_t n = recv(as->fd, &a, sizeof a, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) as->dead = true;
            return;
        }
        if (n == 0) { as->dead = true; return; }               /* the helper exited */
        /* Only an answer to a lookup that is outstanding counts. */
        if ((size_t)n != sizeof a || a.idx >= t->n || !t->e[a.idx].pending) continue;
        for (int f = 0; f < 2; f++) if (a.r.n[f] > WR_MAX_ADDRS) a.r.n[f] = WR_MAX_ADDRS;
        wr_apply(t, a.idx, &a.r, now);
        if (done) done(ctx, a.idx, &a.r);
    }
}

void wr_async_stop(wr_table_t *t) {
    wr_async_t *as = t->async;
    if (!as) return;
    close(as->fd);                 /* the helper sees EOF and exits */
    free(as);
    t->async = NULL;
}
