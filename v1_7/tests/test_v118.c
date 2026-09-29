// SPDX-License-Identifier: MIT
/*
 * test_v118.c — VAREK v1.18.0 checks for the v1.7 layer.
 *
 *   1. URL component match keys (url.host, url.scheme, url.port,
 *      url.path): an "internal hosts only" rule written on url.host is not
 *      fooled by a host name hidden in the path, query, fragment or
 *      userinfo, where the v1.7.4 whole-URL glob was.
 *   2. Breaker persistence: the refusal count and the latch survive a
 *      save/load round trip, so the bound holds across Warden runs; a
 *      malformed state file is refused; a latched terminal action that the
 *      policy no longer names loads as a plain terminal deny.
 */

#define _POSIX_C_SOURCE 200809L

#include "plan_breaker.h"
#include "plan_label_policy.h"
#include "plan_policy_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_pass;

#define CHECK(cond, msg) do {                                       \
    if (cond) { g_pass++; printf("  ok:   %s\n", msg); }             \
    else      { g_fail++; printf("  FAIL: %s\n", msg); }             \
} while (0)

static plan_label_policy_config_t *load(const char *text)
{
    FILE *f = fmemopen((void *)text, strlen(text), "r");
    if (!f) return NULL;
    plan_label_policy_config_t *cfg = NULL;
    int line = 0;
    const char *msg = NULL;
    if (plan_label_policy_config_load_stream(f, &cfg, &line, &msg) != 0) {
        printf("  config error line %d: %s\n", line, msg ? msg : "?");
        cfg = NULL;
    }
    fclose(f);
    return cfg;
}

/* Does send_http(url=<url>) get the permissive rule (permit_in SECRET)? */
static int permitted(const plan_label_policy_config_t *cfg, const char *url)
{
    plan_action_arg_t arg = { .key = "url", .value = url };
    plan_action_desc_t a = { .name = "send_http", .named_args = &arg, .n_named_args = 1 };
    plan_label_class_t cls;
    memset(&cls, 0, sizeof cls);
    const plan_label_policy_t *pol = plan_label_policy_config_policy(cfg);
    if (pol->classify(&a, &cls, pol->ctx) != 0) return -1;
    return plan_label_set_test(&cls.permit_in, 0) ? 1 : 0;
}

static const char *kHostPolicy =
    "varek_policy 1\n"
    "label SECRET 0\n"
    "sticky SECRET\n"
    "rule send_http\n"
    "  match url.scheme https\n"
    "  match url.host *.internal.acme.com\n"
    "  permit_in SECRET\n"
    "rule send_http\n"
    "  deny_in SECRET\n";

static const char *kGlobPolicy =
    "varek_policy 1\n"
    "label SECRET 0\n"
    "sticky SECRET\n"
    "rule send_http\n"
    "  match url https://*.internal.acme.com/*\n"
    "  permit_in SECRET\n"
    "rule send_http\n"
    "  deny_in SECRET\n";

static const char *kPortPolicy =
    "varek_policy 1\n"
    "label SECRET 0\n"
    "rule send_http\n"
    "  match url.host api.internal.acme.com\n"
    "  match url.port 8443\n"
    "  match url.path /v1/*\n"
    "  permit_in SECRET\n";

static const char *kDenyFirst =
    "varek_policy 1\n"
    "label SECRET 0\n"
    "sticky SECRET\n"
    "rule send_http\n"
    "  match url.host 127.0.0.1\n"
    "  deny_in SECRET\n"
    "rule send_http\n"
    "  match url.host *.EVIL.example\n"
    "  deny_in SECRET\n"
    "rule send_http\n"
    "  match url.port 443\n"
    "  match url.path /admin*\n"
    "  deny_in SECRET\n"
    "rule send_http\n"
    "  permit_in SECRET\n";

/* Deny rules must not be stepped around by another spelling of the same
 * host, port or path: each such spelling is either matched by the deny rule
 * or refused outright (-1), never given the permissive rule (1). */
static void test_deny_spellings(void)
{
    printf("-- 1b. other spellings do not step around a deny rule\n");
    plan_label_policy_config_t *d = load(kDenyFirst);
    CHECK(d != NULL, "deny-first policy loads");
    if (!d) return;
    static const char *urls[] = {
        "https://127.1/", "https://2130706433/", "https://0x7f.0.0.1/", "https://127.000.0.1/",
        "https://a.evil.example/", "https://A.Evil.Example/",
        "https://h.example:0443/admin", "https://h.example:443//admin",
        "https://h.example:443/;/admin",
        "https://[::ffff:127.0.0.1]/", "https://[0:0:0:0:0:ffff:7f00:1]/", "https://[::7f00:1]/",
    };
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        char msg[200];
        snprintf(msg, sizeof msg, "%s is not given the permissive rule", urls[i]);
        CHECK(permitted(d, urls[i]) != 1, msg);
    }
    CHECK(permitted(d, "https://127.0.0.1/") == 0, "the canonical address hits the deny rule");
    CHECK(permitted(d, "https://ok.example/") == 1, "an unrelated host gets the permissive rule");
    CHECK(permitted(d, "https://[2001:db8::1]/") == 1, "an ordinary IPv6 literal is readable");
    {
        plan_action_arg_t args[2] = { { "url", "https://ok.example/" }, { "url", "https://127.0.0.1/" } };
        plan_action_desc_t a = { .name = "send_http", .named_args = args, .n_named_args = 2 };
        plan_label_class_t cls;
        const plan_label_policy_t *pol = plan_label_policy_config_policy(d);
        CHECK(pol->classify(&a, &cls, pol->ctx) == -1, "a repeated url argument fails the classification");
    }
    plan_label_policy_config_free(d);
}

static void test_url_components(void)
{
    printf("-- 1. URL component match keys\n");
    plan_label_policy_config_t *host = load(kHostPolicy);
    plan_label_policy_config_t *glob = load(kGlobPolicy);
    plan_label_policy_config_t *port = load(kPortPolicy);
    CHECK(host && glob && port, "policies with url.host / url.port / url.path load");
    if (!host || !glob || !port) return;

    static const char *evil[] = {
        "https://evil.example/x.internal.acme.com/",
        "https://evil.example#.internal.acme.com/",
        "https://evil.example?.internal.acme.com/",
    };
    for (size_t i = 0; i < sizeof evil / sizeof evil[0]; i++) {
        char msg[200];
        snprintf(msg, sizeof msg, "whole-URL glob WAS fooled by %s", evil[i]);
        CHECK(permitted(glob, evil[i]) == 1, msg);
        snprintf(msg, sizeof msg, "url.host is not fooled by %s", evil[i]);
        CHECK(permitted(host, evil[i]) == 0, msg);
    }
    CHECK(permitted(host, "https://api.internal.acme.com/v1/sync") == 1,
          "url.host allows a real internal host");
    CHECK(permitted(host, "https://API.Internal.ACME.com./v1") == 1,
          "host is compared lower-cased, one trailing dot dropped");
    CHECK(permitted(host, "https://api.internal.acme.com@evil.example/") == -1,
          "userinfo ('@') fails the classification");
    CHECK(permitted(host, "https://evil.example\\.internal.acme.com/") == -1,
          "a backslash in the authority fails the classification");
    CHECK(permitted(host, "https://evil%2einternal.acme.com/") == -1,
          "a percent-encoded host fails the classification");
    CHECK(permitted(host, "http://api.internal.acme.com/") == 0,
          "url.scheme https refuses http");
    CHECK(permitted(host, "not a url") == -1, "an unparseable URL fails the classification");
    CHECK(permitted(host, "https://api.internal.acme.com:0/") == -1, "port 0 fails the classification");
    CHECK(permitted(host, "https://api.internal.acme.com:99999/") == -1,
          "an out-of-range port fails the classification");

    CHECK(permitted(port, "https://api.internal.acme.com:8443/v1/x") == 1,
          "url.port and url.path match their components");
    CHECK(permitted(port, "https://api.internal.acme.com/v1/x") == 0,
          "an absent port is empty, not 8443");
    CHECK(permitted(port, "https://api.internal.acme.com:8443/v2/x") == 0,
          "url.path is the path only");
    CHECK(permitted(port, "https://api.internal.acme.com:8443/v2/x?q=/v1/") == 0,
          "url.path stops at the query");

    /* A literal argument named "url.host" is never consulted. */
    {
        plan_action_arg_t args[2] = { { "url", "https://evil.example/" },
                                      { "url.host", "x.internal.acme.com" } };
        plan_action_desc_t a = { .name = "send_http", .named_args = args, .n_named_args = 2 };
        plan_label_class_t cls;
        memset(&cls, 0, sizeof cls);
        const plan_label_policy_t *pol = plan_label_policy_config_policy(host);
        int rc = pol->classify(&a, &cls, pol->ctx);
        CHECK(rc == 0 && !plan_label_set_test(&cls.permit_in, 0),
              "a literal \"url.host\" argument cannot stand in for the URL's host");
    }
    CHECK(permitted(host, "https://.internal.acme.com/") == -1, "a host with a leading dot is refused");
    CHECK(permitted(host, "https://a..internal.acme.com/") == -1, "a host with an empty label is refused");
    CHECK(permitted(port, "https://api.internal.acme.com:8443/v1/..%2f..%2fadmin") == -1,
          "an encoded path is refused, not matched as written");
    CHECK(permitted(port, "https://api.internal.acme.com:8443/v1/../admin") == -1,
          "a dot segment in the path is refused");
    CHECK(permitted(host, "https://u@api.internal.acme.com/") == -1,
          "a URL a component rule cannot read fails the classification (plan refused)");

    plan_label_policy_config_free(host);
    plan_label_policy_config_free(glob);
    plan_label_policy_config_free(port);
}

static const char *kBreakerPolicy =
    "varek_policy 1\n"
    "label SECRET 0\n"
    "sticky SECRET\n"
    "refusal_budget 2\n"
    "on_exhaustion terminal abort_txn\n"
    "unknown_disposition deny\n"
    "rule read_balance\n"
    "  origin SECRET\n"
    "rule write_check\n"
    "  deny_in SECRET\n"
    "rule abort_txn\n";

static const char *kRenamedPolicy =
    "varek_policy 1\n"
    "label SECRET 0\n"
    "sticky SECRET\n"
    "refusal_budget 2\n"
    "on_exhaustion terminal rollback\n"
    "unknown_disposition deny\n"
    "rule rollback\n";

/* Save b to a memory buffer and load it into a fresh breaker. */
static plan_breaker_t *round_trip(const plan_breaker_t *b,
                                  const plan_label_policy_config_t *cfg,
                                  char **text_out)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (!f) return NULL;
    int rc = plan_breaker_save(b, f);
    fclose(f);
    if (rc != 0) { free(buf); return NULL; }
    FILE *in = fmemopen(buf, len, "r");
    plan_breaker_t *nb = plan_breaker_new();
    if (!in || !nb || plan_breaker_load(nb, in, cfg) != 0) {
        if (in) fclose(in);
        plan_breaker_free(nb);
        free(buf);
        return NULL;
    }
    fclose(in);
    if (text_out) *text_out = buf; else free(buf);
    return nb;
}

static int load_text(const char *text, const plan_label_policy_config_t *cfg)
{
    FILE *in = fmemopen((void *)text, strlen(text), "r");
    plan_breaker_t *b = plan_breaker_new();
    int rc = (in && b) ? plan_breaker_load(b, in, cfg) : -2;
    if (in) fclose(in);
    plan_breaker_free(b);
    return rc;
}

static void test_breaker_persistence(void)
{
    printf("-- 2. breaker state survives a save/load round trip\n");
    plan_label_policy_config_t *cfg = load(kBreakerPolicy);
    CHECK(cfg != NULL, "breaker policy loads");
    if (!cfg) return;
    const uint64_t sig = 0x1234abcd5678ef00ULL;

    plan_breaker_t *b1 = plan_breaker_new();
    plan_breaker_result_t r = plan_breaker_step(b1, "session one", sig, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.refusals == 1,
          "first refusal is retryable (1 of 2)");

    char *text = NULL;
    plan_breaker_t *b2 = round_trip(b1, cfg, &text);
    CHECK(b2 != NULL, "state saves and loads");
    if (!b2) { plan_breaker_free(b1); plan_label_policy_config_free(cfg); return; }
    CHECK(text && strstr(text, "varek-breaker 1\n") == text, "state file starts with its header");
    free(text);

    r = plan_breaker_step(b2, "session one", sig, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.refusals == 2 &&
          r.terminal_action && strcmp(r.terminal_action, "abort_txn") == 0,
          "second refusal, in a new breaker, spends the budget: terminal abort_txn");

    r = plan_breaker_step(b2, "session two", sig, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.refusals == 1,
          "another session keeps its own count");

    plan_breaker_t *b3 = round_trip(b2, cfg, NULL);
    CHECK(b3 != NULL, "latched state saves and loads");
    if (b3) {
        r = plan_breaker_step(b3, "session one", sig, PLAN_DEC_UNSATISFIED, cfg);
        CHECK(r.latched && r.outcome == PLAN_BREAKER_TERMINAL_ACTION &&
              r.terminal_action && strcmp(r.terminal_action, "abort_txn") == 0,
              "the latch survives: the same terminal outcome, without re-counting");
        r = plan_breaker_step(b3, "session one", sig, PLAN_DEC_SATISFIED, cfg);
        CHECK(r.outcome == PLAN_BREAKER_PASS, "an authorized plan still passes and clears the latch");
    }

    plan_label_policy_config_t *renamed = load(kRenamedPolicy);
    CHECK(renamed != NULL, "renamed-terminal policy loads");
    if (renamed) {
        plan_breaker_t *b4 = round_trip(b2, renamed, NULL);
        CHECK(b4 != NULL, "state loads under a policy that renamed the terminal action");
        if (b4) {
            r = plan_breaker_step(b4, "session one", sig, PLAN_DEC_UNSATISFIED, renamed);
            CHECK(r.latched && r.outcome == PLAN_BREAKER_TERMINAL_DENY && !r.terminal_action,
                  "a latched action the policy no longer names becomes a terminal deny");
        }
        plan_breaker_free(b4);
        plan_label_policy_config_free(renamed);
    }

    CHECK(load_text("", cfg) == -1, "an empty state file is refused");
    CHECK(load_text("varek-breaker 2\n", cfg) == -1, "a wrong header is refused");
    CHECK(load_text("varek-breaker 1\n- 00000000000000zz 1 0 2 -\n", cfg) == -1,
          "a bad signature is refused");
    CHECK(load_text("varek-breaker 1\n- 0000000000000001 1 0 2 -\n- 0000000000000001 2 0 2 -\nend 2\n", cfg) == -1,
          "a duplicate entry is refused");
    CHECK(load_text("varek-breaker 1\n- 0000000000000001 1 0 2 -", cfg) == -1,
          "a cut-off last line is refused");
    CHECK(load_text("varek-breaker 1\n- 0000000000000001 1 0 2 -\n", cfg) == -1,
          "a file cut at a line boundary (no trailer) is refused");
    CHECK(load_text("varek-breaker 1\n", cfg) == -1, "a header alone is refused");
    CHECK(load_text("varek-breaker 1\n- 0000000000000001 1 0 2 -\nend 2\n", cfg) == -1,
          "a trailer that miscounts is refused");
    CHECK(load_text("varek-breaker 1\n- 0000000000000001 1 0 2 -\nend 1\n- 0000000000000002 1 0 2 -\n", cfg) == -1,
          "data after the trailer is refused");
    CHECK(load_text("varek-breaker 1\n- 0000000000000001 1 0 2 - extra\nend 1\n", cfg) == -1,
          "trailing fields are refused");
    CHECK(load_text("varek-breaker 1\n6100 0000000000000001 1 1 3 abort_txn\nend 1\n", cfg) == -1,
          "a NUL byte in a session is refused");
    CHECK(load_text("varek-breaker 1\n- 0000000000000001 1 0 2 -\nend 1\n", cfg) == 0,
          "a well-formed file loads");
    CHECK(load_text("varek-breaker 1\nend 0\n", cfg) == 0, "an empty table loads");

    plan_breaker_free(b1);
    plan_breaker_free(b2);
    plan_breaker_free(b3);
    plan_label_policy_config_free(cfg);
}

static void test_graph_signature(void)
{
    printf("-- 3. the graph signature is canonical\n");
    plan_action_arg_t ta = { "target", "/srv/secret/k" }, tb = { "target", "/srv/public/out" },
                      tc = { "target", "/srv/log" };
    plan_action_desc_t a[3] = {
        { .name = "file_open", .named_args = &ta, .n_named_args = 1 },
        { .name = "file_open", .named_args = &tb, .n_named_args = 1 },
        { .name = "file_open", .named_args = &tc, .n_named_args = 1 },
    };
    /* the same steps, listed in another order: b, c, a */
    plan_action_desc_t r[3] = { a[1], a[2], a[0] };
    uint32_t f1[] = { 0, 0 }, t1[] = { 1, 2 };              /* a->b, a->c */
    uint32_t f2[] = { 0, 0 }, t2[] = { 2, 1 };              /* a->c, a->b */
    uint32_t f3[] = { 0, 0, 0 }, t3[] = { 1, 2, 1 };        /* a->b, a->c, a->b */
    uint32_t f4[] = { 2, 2 }, t4[] = { 0, 1 };              /* renumbered: a->b, a->c */
    uint32_t f5[] = { 0 }, t5[] = { 2 };                    /* a->c only */
    uint64_t s1 = plan_breaker_signature_graph(a, 3, f1, t1, 2);
    CHECK(s1 == plan_breaker_signature_graph(a, 3, f2, t2, 2), "edges in another order: same signature");
    CHECK(s1 == plan_breaker_signature_graph(a, 3, f3, t3, 3), "a repeated edge: same signature");
    CHECK(s1 == plan_breaker_signature_graph(r, 3, f4, t4, 2), "steps renumbered: same signature");
    CHECK(s1 != plan_breaker_signature_graph(a, 3, f5, t5, 1), "a different edge set: different signature");
    CHECK(s1 != plan_breaker_signature_graph(a, 3, NULL, NULL, 0), "no edges: different signature");

    /* Identical steps are not merged: S->M1->P (a leak through the middle)
     * and S->M1, M2->P (no path from S to P) must not share a count. */
    plan_action_arg_t ms = { "target", "/srv/secret/k" }, mm = { "target", "/srv/mid" },
                      mp = { "target", "/srv/public/out" };
    plan_action_desc_t g[4] = {
        { .name = "file_open", .named_args = &ms, .n_named_args = 1 },
        { .name = "file_open", .named_args = &mm, .n_named_args = 1 },
        { .name = "file_open", .named_args = &mm, .n_named_args = 1 },
        { .name = "file_open", .named_args = &mp, .n_named_args = 1 },
    };
    uint32_t lf[] = { 0, 1 }, lt[] = { 1, 3 };               /* S->M1, M1->P */
    uint32_t sf[] = { 0, 2 }, stt[] = { 1, 3 };              /* S->M1, M2->P */
    CHECK(plan_breaker_signature_graph(g, 4, lf, lt, 2) != plan_breaker_signature_graph(g, 4, sf, stt, 2),
          "graphs differing only in which identical step an edge uses differ");
}

int main(void)
{
    printf("VAREK v1.18.0 — v1.7 layer\n");
    test_url_components();
    test_deny_spellings();
    test_breaker_persistence();
    test_graph_signature();
    printf("\n%d/%d checks passed\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}
