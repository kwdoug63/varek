// SPDX-License-Identifier: MIT
// warden_resolve.h — the Warden's resolution table (v1.24; design:
// docs/security/v1.21-stage2-host-names.md, section 2).
//
// A policy with host name rules (`require warden 1.24`, `allow host
// api.example.com:443`) is decided on names, but the agent never sends a DNS
// query. The Warden resolves every name an allow rule names, itself, through
// the host's resolver, and keeps what each name resolved to:
//
//   - At startup, before the agent runs, every name is resolved, A and AAAA
//     (res_nquery, so each answer's TTL is known). A name that does not resolve
//     is reported and retried; it does not stop the Warden.
//   - Each entry is refreshed at its TTL, clamped to [ttl_min, ttl_max]
//     (default [30 s, 1 h]). Refreshes run in a resolver helper process, so
//     the supervisor never waits on a lookup while an agent thread waits on
//     an answer; the supervisor applies each result between notifications.
//   - An address that drops out of a name's answer stays valid for a grace
//     period (the old TTL, at most grace_max, default 5 min), because the agent
//     may have read it just before. After that it is gone.
//   - A refresh that fails (timeout, SERVFAIL) keeps the family's current
//     addresses and is retried after ttl_min; an authoritative empty answer
//     (NXDOMAIN, or no record of the type) replaces them.
//   - Every result is a record in the verdict stream (event "resolution"),
//     chained and signed like any record; wr_format_record writes it.
//   - The Warden trusts the host's resolver. DNSSEC validation is not done
//     here; a host that needs it points the Warden at a validating resolver.
//
// The table is owned by the supervisor. The resolver helper only performs
// lookups and hands results back (wr_async_*); it never sees the table.

#ifndef VAREK_WARDEN_RESOLVE_H
#define VAREK_WARDEN_RESOLVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define WR_NAME_MAX   253          /* a DNS name, without a trailing dot */
#define WR_MAX_ADDRS  64           /* addresses kept per family per answer */
#define WR_MAX_CNAME  8            /* CNAME links followed in one answer */

typedef struct {
    uint32_t    ttl_min;           /* seconds; default 30 */
    uint32_t    ttl_max;           /* seconds; default 3600 */
    uint32_t    grace_max;         /* seconds; default 300 */
    uint32_t    timeout_s;         /* per query attempt; default 2 */
    uint32_t    attempts;          /* per query; default 2 */
    /* Testing and preflight: resolve through this server ("a.b.c.d:port")
     * instead of the host's resolv.conf. NULL: the host's resolver. */
    const char *server;
} wr_config_t;

typedef enum {
    WR_ST_OK = 0,                  /* records of this type */
    WR_ST_NODATA,                  /* the name exists, no record of this type */
    WR_ST_NXDOMAIN,                /* the name does not exist */
    WR_ST_FAIL,                    /* timeout, SERVFAIL, refused, malformed */
} wr_status_t;

typedef struct {
    uint8_t  fam;                  /* 4 or 6 */
    uint8_t  a[16];                /* network order; IPv4 in the first 4 bytes */
} wr_ip_t;

/* One lookup of one name: both families. */
typedef struct {
    wr_status_t st[2];             /* [0] A, [1] AAAA */
    uint32_t    ttl[2];            /* the answer's TTL (minimum over the chain) */
    wr_ip_t     ip[2][WR_MAX_ADDRS];
    size_t      n[2];
} wr_result_t;

typedef struct {
    wr_ip_t  ip;
    int64_t  until_ms;             /* 0: in the current answer; else valid until (monotonic) */
} wr_addr_t;

typedef struct {
    char       name[WR_NAME_MAX + 1];
    wr_addr_t *addrs;
    size_t     n, cap;
    uint32_t   ttl_eff;            /* the clamped TTL now in force (seconds) */
    int64_t    next_ms;            /* next refresh due (monotonic ms) */
    bool       pending;            /* a lookup is with the resolver helper */
    bool       ever_ok;            /* resolved to at least one address once */
    uint64_t   lookups;
    /* v1.25: a name a wildcard rule matched, added when the agent asked for
     * it (warden_stub.inc.c). It is looked up only when asked, never
     * refreshed on its own: when its TTL passes with no new question, its
     * addresses go into grace (wr_retire_due). Not in the hosts view. */
    bool        dynamic;
    wr_status_t st[2];             /* the last lookup's status, A and AAAA */
} wr_entry_t;

typedef struct wr_async wr_async_t;

typedef struct {
    wr_entry_t  *e;
    size_t       n;
    wr_config_t  cfg;
    uint64_t     generation;       /* bumped whenever some current set changes */
    char         resolver[64];     /* "a.b.c.d:53" or "resolv.conf", for records */
    wr_async_t  *async;
} wr_table_t;

/* Defaults for a config. */
void wr_config_default(wr_config_t *c);

/* An empty table with this config. 0, or -1 (bad config: the reason in why). */
int  wr_table_init(wr_table_t *t, const wr_config_t *cfg, char *why, size_t wn);

/* Add a name (lowercase, no trailing dot; the policy parsers validated it).
 * A name already present is not added twice. Returns its index, or -1. */
int  wr_table_add(wr_table_t *t, const char *name);

/* v1.25: the index of name, or -1. */
int  wr_table_find(const wr_table_t *t, const char *name);

/* v1.25: add a dynamic entry (see wr_entry_t.dynamic), not yet looked up.
 * A name already present is returned as it is. Its index, or -1. */
int  wr_table_add_dynamic(wr_table_t *t, const char *name);

/* v1.25: dynamic entries whose TTL has passed (and that no lookup is pending
 * for): their current addresses go into grace (the TTL, at most grace_max)
 * and they wait for the next question. Returns how many were retired; the
 * generation is bumped if any address moved. */
size_t wr_retire_due(wr_table_t *t, int64_t now);

/* v1.25: is entry i's last answer still in force (looked up, TTL not past)? */
bool wr_entry_fresh(const wr_entry_t *e, int64_t now);

void wr_table_free(wr_table_t *t);

/* CLOCK_MONOTONIC in milliseconds. */
int64_t wr_now_ms(void);

/* Resolve one name now, A and AAAA, through the table's resolver. Blocking:
 * call it before the agent runs, or in the resolver helper. */
void wr_lookup(const wr_table_t *t, const char *name, wr_result_t *r);

/* Apply a lookup's result to entry i at time now: the new current set, grace
 * for addresses that dropped out, the next refresh. Returns true if the
 * entry's current set changed (the generation was bumped). */
bool wr_apply(wr_table_t *t, size_t i, const wr_result_t *r, int64_t now);

/* Milliseconds until the next refresh is due (0: one is due now), or -1 if
 * none is scheduled (an empty table, or every due entry already pending). */
int  wr_next_due_ms(const wr_table_t *t, int64_t now);

/* Is ip (current or in grace at now) an address of entry i? */
bool wr_entry_has(const wr_entry_t *e, const wr_ip_t *ip, int64_t now);

/* The entries ip belongs to at now (current or in grace), in table order: up
 * to max indices in out. Returns how many there are (may exceed max). */
size_t wr_names_for(const wr_table_t *t, const wr_ip_t *ip, int64_t now, size_t *out, size_t max);

/* Drop grace addresses whose time is up. */
void wr_expire(wr_table_t *t, int64_t now);

/* v1.24 (section 3): the hosts view the agent reads as /etc/hosts:
 *   127.0.0.1 localhost
 *   ::1 localhost
 * then one line per current address of each name ("<address> <name>"), names
 * in table order, each name's IPv4 addresses before its IPv6 ones. Dynamic
 * entries (v1.25) are left out: the agent asks the stub for them. Addresses in grace are left out (the agent may still connect
 * to one it read before; it cannot look it up again). */
void wr_hosts_view(const wr_table_t *t, FILE *f);

/* An address as text ("192.0.2.1", "2001:db8::1"). */
void wr_ip_str(const wr_ip_t *ip, char *out, size_t n);

/* Parse "a.b.c.d" or an IPv6 address (no brackets). 0 or -1. */
int  wr_ip_parse(const char *s, wr_ip_t *ip);

/* The "resolution" record for entry i after applying r, as one JSON object
 * and a newline (the Warden chains it):
 *   {"event":"resolution","run":RUN,"name":N,"a":ST,"aaaa":ST,
 *    "addresses":[...],"grace":[...],"ttl":T,"refresh_s":R,
 *    "resolver":"...","generation":G,"timestamp_ns":TS}
 * and, for a dynamic entry (v1.25), "dynamic":true before "timestamp_ns".
 * where ST is ok|nodata|nxdomain|fail, ttl the answer's smallest TTL (absent
 * when nothing answered), refresh_s the clamped TTL in force. */
void wr_format_record(FILE *f, const char *run, const wr_table_t *t, size_t i,
                      const wr_result_t *r, int64_t now);

/* ---- the resolver helper ----
 * A process (a grandchild of the caller, so its exit raises no SIGCHLD there)
 * that performs lookups and sends the results back over a socket. Start it
 * while the caller is still single-threaded and before the agent's PID
 * namespace exists. With helper_exe it re-executes that program as
 *   <helper_exe> --resolver-helper <server|-> <timeout_s> <attempts>
 * with the socket on descriptor 3, which must call wr_helper_main (a clean
 * address space); with NULL the forked child runs wr_helper_main directly
 * (tests). The supervisor polls wr_async_fd(); when it is readable,
 * wr_async_collect applies every finished lookup and calls done for each (to
 * write its record). wr_async_schedule hands every due entry to the helper. */
int  wr_async_start(wr_table_t *t, const char *helper_exe);
int  wr_helper_main(int fd, const wr_config_t *cfg);
/* The helper's entry point for a program re-executed as above: argv[1] is
 * "--resolver-helper". Returns the exit status. */
int  wr_helper_exec_main(int argc, char **argv);
int  wr_async_fd(const wr_table_t *t);
/* False once the helper has exited or its socket failed: refreshes stopped. */
bool wr_async_alive(const wr_table_t *t);
void wr_async_schedule(wr_table_t *t, int64_t now);
/* v1.25: hand entry i to the helper now (a dynamic entry the agent asked
 * for). 0, or -1 (the helper is gone, or its socket is full). */
int  wr_async_request(wr_table_t *t, size_t i);
void wr_async_collect(wr_table_t *t, int64_t now,
                      void (*done)(void *ctx, size_t i, const wr_result_t *r), void *ctx);
/* Close the socket; the helper exits after its current lookup. */
void wr_async_stop(wr_table_t *t);

#endif /* VAREK_WARDEN_RESOLVE_H */
