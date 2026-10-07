// SPDX-License-Identifier: MIT
// test_v1240_resolve.c — the v1.24 resolution table (warden_resolve.c)
// against tests/dns_test_server.py. Run by tests/test_v1240.sh; needs no root.
//
//   test_v1240_resolve <port> <zone.json> <queries.log>

#include "../warden_resolve.h"

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, ...) do { if (cond) g_pass++; else { g_fail++; \
    fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); fprintf(stderr, __VA_ARGS__); \
    fputc('\n', stderr); } } while (0)

static const char *g_zone;

static void zone(const char *json) {
    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s.tmp", g_zone);
    FILE *f = fopen(tmp, "w");
    if (!f) { perror(tmp); exit(2); }
    fputs(json, f);
    fclose(f);
    if (rename(tmp, g_zone) < 0) { perror("rename"); exit(2); }
}

static wr_ip_t ip(const char *s) {
    wr_ip_t a;
    if (wr_ip_parse(s, &a) < 0) { fprintf(stderr, "bad test address %s\n", s); exit(2); }
    return a;
}

static size_t current(const wr_entry_t *e) {
    size_t k = 0;
    for (size_t i = 0; i < e->n; i++) if (e->addrs[i].until_ms == 0) k++;
    return k;
}

static int g_done_calls = 0;
static char g_last_record[4096];
static wr_table_t *g_tab;
static void on_done(void *ctx, size_t i, const wr_result_t *r) {
    g_done_calls++;
    FILE *f = fmemopen(g_last_record, sizeof g_last_record, "w");
    wr_format_record(f, "00112233445566778899aabbccddeeff", g_tab, i, r, wr_now_ms());
    fclose(f);
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "--resolver-helper")) return wr_helper_exec_main(argc, argv);
    if (argc != 4) { fprintf(stderr, "usage: %s <port> <zone.json> <queries.log>\n", argv[0]); return 2; }
    g_zone = argv[2];
    const char *qlog = argv[3];
    char server[64];
    snprintf(server, sizeof server, "127.0.0.1:%s", argv[1]);

    wr_config_t cfg;
    wr_config_default(&cfg);
    char why[160];
    wr_table_t t;

    /* config checks */
    cfg.ttl_min = 0;
    CHECK(wr_table_init(&t, &cfg, why, sizeof why) < 0, "ttl_min 0 accepted");
    wr_config_default(&cfg);
    cfg.ttl_min = 10; cfg.ttl_max = 5;
    CHECK(wr_table_init(&t, &cfg, why, sizeof why) < 0, "min > max accepted");
    wr_config_default(&cfg);
    cfg.server = "localhost:53";
    CHECK(wr_table_init(&t, &cfg, why, sizeof why) < 0, "a server name accepted");

    wr_config_default(&cfg);
    cfg.ttl_min = 5;
    cfg.ttl_max = 60;
    cfg.grace_max = 20;
    cfg.timeout_s = 1;
    cfg.attempts = 1;
    cfg.server = server;
    CHECK(wr_table_init(&t, &cfg, why, sizeof why) == 0, "init: %s", why);
    g_tab = &t;
    CHECK(!strcmp(t.resolver, server), "resolver label %s", t.resolver);

    zone("{\"api.example.test\": {\"ttl\": 30, \"a\": [\"192.0.2.10\", \"192.0.2.11\"],"
         "                        \"aaaa\": [\"2001:db8::10\"]},"
         " \"www.example.test\": {\"ttl\": 7, \"cname\": \"edge.example.test\"},"
         " \"edge.example.test\": {\"ttl\": 40, \"a\": [\"192.0.2.10\"]},"
         " \"short.example.test\": {\"ttl\": 1, \"a\": [\"192.0.2.20\"]},"
         " \"long.example.test\": {\"ttl\": 86400, \"a\": [\"192.0.2.21\"]},"
         " \"v4only.example.test\": {\"ttl\": 30, \"a\": [\"192.0.2.30\"]},"
         " \"flaky.example.test\": {\"rcode\": \"servfail\"},"
         " \"slow.example.test\": {\"drop\": true}}");
    int api = wr_table_add(&t, "api.example.test");
    int www = wr_table_add(&t, "www.example.test");
    int sh = wr_table_add(&t, "short.example.test");
    int lg = wr_table_add(&t, "long.example.test");
    int v4 = wr_table_add(&t, "v4only.example.test");
    int nx = wr_table_add(&t, "missing.example.test");
    int fl = wr_table_add(&t, "flaky.example.test");
    int sl = wr_table_add(&t, "slow.example.test");
    CHECK(wr_table_add(&t, "api.example.test") == api, "duplicate name added twice");
    CHECK(t.n == 8, "table has %zu entries", t.n);

    /* 1. startup resolution of every name */
    int64_t now = 1000000;
    wr_result_t r;
    wr_lookup(&t, "api.example.test", &r);
    CHECK(r.st[0] == WR_ST_OK && r.n[0] == 2 && r.st[1] == WR_ST_OK && r.n[1] == 1,
          "api: A %d/%zu AAAA %d/%zu", r.st[0], r.n[0], r.st[1], r.n[1]);
    CHECK(r.ttl[0] == 30, "api ttl %u", r.ttl[0]);
    CHECK(wr_apply(&t, (size_t)api, &r, now), "api: first answer is a change");
    CHECK(current(&t.e[api]) == 3 && t.e[api].ttl_eff == 30, "api: %zu current, ttl %u",
          current(&t.e[api]), t.e[api].ttl_eff);
    CHECK(t.e[api].next_ms == now + 30000, "api: refresh at the TTL");
    wr_ip_t a10 = ip("192.0.2.10"), a11 = ip("192.0.2.11"), a6 = ip("2001:db8::10");
    CHECK(wr_entry_has(&t.e[api], &a10, now) && wr_entry_has(&t.e[api], &a6, now), "api addresses");
    {
        char hv[1024];
        FILE *f = fmemopen(hv, sizeof hv, "w");
        wr_hosts_view(&t, f);
        fclose(f);
        CHECK(!strcmp(hv, "127.0.0.1 localhost\n::1 localhost\n192.0.2.10 api.example.test\n"
                          "192.0.2.11 api.example.test\n2001:db8::10 api.example.test\n"),
              "hosts view: %s", hv);
    }

    /* 2. a CNAME chain: the target's addresses, the chain's smallest TTL */
    wr_lookup(&t, "www.example.test", &r);
    CHECK(r.st[0] == WR_ST_OK && r.n[0] == 1 && r.ttl[0] == 7, "www via CNAME: %d %zu ttl %u",
          r.st[0], r.n[0], r.ttl[0]);
    CHECK(r.st[1] == WR_ST_NODATA, "www AAAA: %d", r.st[1]);
    wr_apply(&t, (size_t)www, &r, now);
    CHECK(t.e[www].ttl_eff == 7, "www ttl %u", t.e[www].ttl_eff);

    /* 3. the TTL clamp */
    wr_lookup(&t, "short.example.test", &r);
    wr_apply(&t, (size_t)sh, &r, now);
    CHECK(t.e[sh].ttl_eff == 5, "a 1 s TTL is clamped up to 5 (got %u)", t.e[sh].ttl_eff);
    wr_lookup(&t, "long.example.test", &r);
    wr_apply(&t, (size_t)lg, &r, now);
    CHECK(t.e[lg].ttl_eff == 60, "a 1 day TTL is clamped down to 60 (got %u)", t.e[lg].ttl_eff);

    /* 4. a name only one family answers */
    wr_lookup(&t, "v4only.example.test", &r);
    CHECK(r.st[0] == WR_ST_OK && r.st[1] == WR_ST_NODATA, "v4only: %d %d", r.st[0], r.st[1]);
    wr_apply(&t, (size_t)v4, &r, now);

    /* 5. a name that does not exist: reported, retried after ttl_min */
    wr_lookup(&t, "missing.example.test", &r);
    CHECK(r.st[0] == WR_ST_NXDOMAIN && r.st[1] == WR_ST_NXDOMAIN, "missing: %d %d", r.st[0], r.st[1]);
    CHECK(!wr_apply(&t, (size_t)nx, &r, now), "missing: no change");
    CHECK(t.e[nx].n == 0 && !t.e[nx].ever_ok && t.e[nx].next_ms == now + 5000, "missing: retry at ttl_min");

    /* 6. SERVFAIL and a dropped query: failures, retried after ttl_min */
    wr_lookup(&t, "flaky.example.test", &r);
    CHECK(r.st[0] == WR_ST_FAIL && r.st[1] == WR_ST_FAIL, "flaky: %d %d", r.st[0], r.st[1]);
    wr_apply(&t, (size_t)fl, &r, now);
    CHECK(t.e[fl].next_ms == now + 5000, "flaky: retry at ttl_min");
    int64_t t0 = wr_now_ms();
    wr_lookup(&t, "slow.example.test", &r);
    int64_t took = wr_now_ms() - t0;
    CHECK(r.st[0] == WR_ST_FAIL && r.st[1] == WR_ST_FAIL, "slow: %d %d", r.st[0], r.st[1]);
    CHECK(took < 6000, "a dropped query gave up after %lld ms", (long long)took);
    wr_apply(&t, (size_t)sl, &r, now);

    /* 7. rotation: a dropped address is kept for the grace period */
    zone("{\"api.example.test\": {\"ttl\": 30, \"a\": [\"192.0.2.11\", \"192.0.2.12\"],"
         "                        \"aaaa\": [\"2001:db8::10\"]},"
         " \"flaky.example.test\": {\"rcode\": \"servfail\"}}");
    now += 30000;
    uint64_t gen = t.generation;
    wr_lookup(&t, "api.example.test", &r);
    CHECK(wr_apply(&t, (size_t)api, &r, now), "rotation is a change");
    CHECK(t.generation == gen + 1, "generation bumped once");
    wr_ip_t a12 = ip("192.0.2.12");
    CHECK(wr_entry_has(&t.e[api], &a12, now) && wr_entry_has(&t.e[api], &a11, now), "new set current");
    CHECK(wr_entry_has(&t.e[api], &a10, now + 19999), "dropped address valid in grace (min(ttl 30, grace 20))");
    CHECK(!wr_entry_has(&t.e[api], &a10, now + 20000), "dropped address gone after grace");
    {
        size_t idx[4];
        size_t k = wr_names_for(&t, &a10, now + 1000, idx, 4);
        CHECK(k == 2 && idx[0] == (size_t)api && idx[1] == (size_t)www,
              "192.0.2.10 belongs to api (grace) and www (current): %zu", k);
        k = wr_names_for(&t, &a10, now + 20000, idx, 4);
        CHECK(k == 1 && idx[0] == (size_t)www, "after grace only www: %zu", k);
        wr_ip_t none = ip("198.51.100.1");
        CHECK(wr_names_for(&t, &none, now, idx, 4) == 0, "an unknown address has no name");
    }
    /* back from grace */
    zone("{\"api.example.test\": {\"ttl\": 30, \"a\": [\"192.0.2.10\"], \"aaaa\": [\"2001:db8::10\"]}}");
    wr_lookup(&t, "api.example.test", &r);
    wr_apply(&t, (size_t)api, &r, now + 5000);
    CHECK(wr_entry_has(&t.e[api], &a10, now + 60000), "an address back in the answer is current again");
    CHECK(wr_entry_has(&t.e[api], &a11, now + 5000 + 19999) &&
          !wr_entry_has(&t.e[api], &a11, now + 5000 + 20000), "11 and 12 now in grace");
    wr_expire(&t, now + 5000 + 20000);
    CHECK(t.e[api].n == 2, "expired grace addresses removed (%zu left)", t.e[api].n);

    /* 8. a failed refresh keeps the current set */
    zone("{\"api.example.test\": {\"rcode\": \"servfail\"}}");
    wr_lookup(&t, "api.example.test", &r);
    CHECK(!wr_apply(&t, (size_t)api, &r, now + 30000), "a failure changes nothing");
    CHECK(wr_entry_has(&t.e[api], &a10, now + 30000) && t.e[api].next_ms == now + 30000 + 5000,
          "current kept, retried at ttl_min");
    /* an authoritative NXDOMAIN does replace it (into grace) */
    zone("{}");
    wr_lookup(&t, "api.example.test", &r);
    CHECK(wr_apply(&t, (size_t)api, &r, now + 40000), "NXDOMAIN after an answer is a change");
    CHECK(current(&t.e[api]) == 0 && wr_entry_has(&t.e[api], &a10, now + 40000 + 4999),
          "old addresses in grace (old TTL 5 s)");

    /* 9. the record */
    {
        char buf[4096];
        FILE *f = fmemopen(buf, sizeof buf, "w");
        wr_lookup(&t, "missing.example.test", &r);
        wr_apply(&t, (size_t)nx, &r, now);
        wr_format_record(f, "00112233445566778899aabbccddeeff", &t, (size_t)nx, &r, now);
        fclose(f);
        CHECK(strstr(buf, "{\"event\":\"resolution\",\"run\":\"00112233445566778899aabbccddeeff\","
                          "\"name\":\"missing.example.test\",\"a\":\"nxdomain\",\"aaaa\":\"nxdomain\","
                          "\"addresses\":[],\"grace\":[],\"refresh_s\":5,") == buf, "record: %s", buf);
        CHECK(buf[strlen(buf) - 1] == '\n' && buf[strlen(buf) - 2] == '}', "record ends with }\\n");
    }

    /* 10. names are queried as given: no search domain is appended */
    {
        FILE *f = fopen(qlog, "r");
        char line[512];
        int bad = 0, seen = 0;
        while (f && fgets(line, sizeof line, f)) {
            seen++;
            if (!strstr(line, ".example.test\n")) bad++;
        }
        if (f) fclose(f);
        CHECK(seen > 0 && bad == 0, "%d of %d queries were for other names", bad, seen);
    }

    /* 11. the resolver helper: refreshes happen off the supervisor, in a
     * forked helper and in a re-executed one (as the Warden runs it) */
    for (int mode = 0; mode < 2; mode++) {
        const char *how = mode ? "re-executed helper" : "forked helper";
        zone(mode ? "{\"api.example.test\": {\"ttl\": 30, \"a\": [\"192.0.2.98\"]},"
                    " \"slow.example.test\": {\"drop\": true}}"
                  : "{\"api.example.test\": {\"ttl\": 30, \"a\": [\"192.0.2.99\"]},"
                    " \"slow.example.test\": {\"drop\": true}}");
        for (size_t i = 0; i < t.n; i++) t.e[i].next_ms = 0;          /* everything due */
        CHECK(wr_next_due_ms(&t, 1) == 0, "%s: due now", how);
        CHECK(wr_async_start(&t, mode ? "/proc/self/exe" : NULL) == 0, "%s started", how);
        CHECK(wr_async_alive(&t), "%s alive", how);
        g_done_calls = 0;
        t0 = wr_now_ms();
        wr_async_schedule(&t, wr_now_ms());
        CHECK(wr_now_ms() - t0 < 100, "%s: scheduling does not wait on a lookup", how);
        CHECK(wr_next_due_ms(&t, wr_now_ms()) == -1, "%s: nothing more due while all are pending", how);
        wr_ip_t want = ip(mode ? "192.0.2.98" : "192.0.2.99");
        int64_t deadline = wr_now_ms() + 15000;
        while (g_done_calls < (int)t.n && wr_now_ms() < deadline) {
            struct pollfd pf = { .fd = wr_async_fd(&t), .events = POLLIN };
            poll(&pf, 1, 500);
            if (pf.revents & POLLIN) wr_async_collect(&t, wr_now_ms(), on_done, NULL);
        }
        CHECK(g_done_calls == (int)t.n, "%s: %d of %zu refreshes came back", how, g_done_calls, t.n);
        CHECK(wr_entry_has(&t.e[api], &want, wr_now_ms()), "%s: api refreshed", how);
        CHECK(strstr(g_last_record, "\"event\":\"resolution\"") != NULL, "records written: %s", g_last_record);
        for (size_t i = 0; i < t.n; i++) CHECK(!t.e[i].pending, "%s: entry %zu still pending", how, i);
        wr_async_stop(&t);
        CHECK(!wr_async_alive(&t) && wr_async_fd(&t) == -1, "%s stopped", how);
    }
    /* v1.24 review: an answer longer than the lookup's buffer (glibc retries
     * a truncated UDP answer over TCP and reports the full length) is a
     * failure, not parsed past the buffer */
    {
        zone("{\"big.example.test\": {\"big\": 1900}}");
        wr_result_t r;
        wr_lookup(&t, "big.example.test", &r);
        CHECK(r.st[0] == WR_ST_FAIL && r.n[0] == 0, "an oversized answer is a failure (st %d, %zu addresses)",
              (int)r.st[0], r.n[0]);
    }
    /* v1.24 review: the table, fed results directly */
    {
        wr_table_t u;
        wr_config_t c;
        wr_config_default(&c);
        char why[160];
        CHECK(wr_table_init(&u, &c, why, sizeof why) == 0, "table: %s", why);
        int a = wr_table_add(&u, "grace.example.test"), m = wr_table_add(&u, "mapped.example.test"),
            d = wr_table_add(&u, "denied.example.test");
        wr_result_t r;
        memset(&r, 0, sizeof r);
        r.st[0] = WR_ST_OK; r.ttl[0] = 300; r.n[0] = 1; r.ip[0][0] = ip("192.0.2.70");
        r.st[1] = WR_ST_NODATA;
        int64_t now = wr_now_ms();
        wr_apply(&u, (size_t)a, &r, now);
        wr_result_t f;
        memset(&f, 0, sizeof f);
        f.st[0] = f.st[1] = WR_ST_FAIL;
        wr_apply(&u, (size_t)a, &f, now + 1000);           /* a failed refresh */
        r.ip[0][0] = ip("192.0.2.71");                     /* then the answer moves */
        wr_apply(&u, (size_t)a, &r, now + 2000);
        int64_t until = 0;
        wr_ip_t old = ip("192.0.2.70");
        for (size_t k = 0; k < u.e[a].n; k++)
            if (!memcmp(u.e[a].addrs[k].ip.a, old.a, 4) && u.e[a].addrs[k].ip.fam == 4) until = u.e[a].addrs[k].until_ms;
        CHECK(until - (now + 2000) >= 299000, "grace after a failed refresh is the last answer's TTL "
              "(300 s), got %lld ms", (long long)(until - (now + 2000)));
        memset(&r, 0, sizeof r);
        r.st[0] = WR_ST_NODATA; r.st[1] = WR_ST_OK; r.ttl[1] = 60; r.n[1] = 1;
        r.ip[1][0] = ip("::ffff:192.0.2.77");
        wr_apply(&u, (size_t)m, &r, now);
        wr_ip_t v4 = ip("192.0.2.77");
        CHECK(wr_entry_has(&u.e[m], &v4, now), "an AAAA answer ::ffff:a.b.c.d binds a.b.c.d");
        memset(&r, 0, sizeof r);
        r.st[0] = WR_ST_OK; r.ttl[0] = 60; r.n[0] = 1; r.ip[0][0] = ip("192.0.2.88"); r.st[1] = WR_ST_NODATA;
        wr_apply(&u, (size_t)d, &r, now);
        u.e[d].unlisted = true;
        char hv[1024];
        FILE *hf = fmemopen(hv, sizeof hv, "w");
        wr_hosts_view(&u, hf);
        fclose(hf);
        CHECK(!strstr(hv, "denied.example.test") && strstr(hv, "grace.example.test"),
              "a name only a deny rule names is not in the hosts view: %s", hv);
        wr_table_free(&u);
    }
    /* a helper that dies is noticed (the Warden then stops the run) */
    {
        wr_config_t bad = t.cfg;
        bad.timeout_s = 99;                     /* refused by the helper's argument check */
        wr_config_t keep = t.cfg;
        t.cfg = bad;
        CHECK(wr_async_start(&t, "/proc/self/exe") == 0, "helper with bad arguments started");
        t.cfg = keep;
        int64_t deadline = wr_now_ms() + 5000;
        while (wr_async_alive(&t) && wr_now_ms() < deadline) {
            struct pollfd pf = { .fd = wr_async_fd(&t), .events = POLLIN };
            poll(&pf, 1, 200);
            wr_async_collect(&t, wr_now_ms(), NULL, NULL);
        }
        CHECK(!wr_async_alive(&t), "a helper that exited is reported dead");
        wr_async_stop(&t);
    }
    wr_table_free(&t);

    printf("test_v1240_resolve: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
