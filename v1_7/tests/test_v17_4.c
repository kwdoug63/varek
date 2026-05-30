// SPDX-License-Identifier: MIT
/*
 * test_v17_4.c — VAREK v1.7.4 tests.
 *
 * Covers:
 *   - Argument-pattern matching: glob semantics, multi-constraint AND,
 *     first-match-wins ordering, missing-arg handling, named-args-NULL
 *     backward compatibility.
 *   - Lineage tracing in pathology: single-hop, multi-hop, multiple
 *     originators, sticky_unclassified case, non-contributing
 *     originators correctly excluded.
 *   - Integrated end-to-end: config file with match clauses + lineage
 *     through plan_warden_verify.
 *
 * Clean under -fsanitize=address,undefined.
 */

#define _GNU_SOURCE
#include "execution_plan.h"
#include "plan_dataflow.h"
#include "plan_label.h"
#include "plan_label_policy.h"
#include "plan_policy_config.h"
#include "plan_warden_binding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++;                                  \
        printf("  FAIL: %s  (%s:%d)\n", (msg), __FILE__, __LINE__); \
    } else {                                                    \
        printf("  ok:   %s\n", (msg));                          \
    }                                                           \
} while (0)

enum { L_SECRET = 0, L_PII = 1 };

static const char *label_namer(plan_label_t t, void *ctx)
{
    (void)ctx;
    switch (t) {
        case L_SECRET: return "SECRET";
        case L_PII:    return "PII";
    }
    return NULL;
}

static bool contains(const char *json, size_t n, const char *needle)
{
    size_t nlen = strlen(needle);
    if (n < nlen) return false;
    for (size_t i = 0; i + nlen <= n; i++)
        if (memcmp(json + i, needle, nlen) == 0) return true;
    return false;
}

static plan_label_policy_config_t *load_str(const char *text)
{
    FILE *f = fmemopen((void *)text, strlen(text), "r");
    if (!f) return NULL;
    plan_label_policy_config_t *cfg = NULL;
    int el; const char *em;
    plan_label_policy_config_load_stream(f, &cfg, &el, &em);
    fclose(f);
    return cfg;
}

/* ---------- Argument matching: rule ordering and glob semantics ---------- */

/* The canonical case: send_http to internal endpoints is permitted
 * for sensitive labels; everything else is denied. First-match-wins
 * means the permissive rule must precede the deny rule. */
static void test_arg_match_internal_vs_external(void)
{
    printf("test_arg_match_internal_vs_external\n");
    const char *cfg_text =
        "label SECRET 0\n"
        "sticky SECRET\n"
        "rule read_secret\n"
        "  origin SECRET\n"
        "rule send_http\n"
        "  match url https://*.internal.acme.com/*\n"
        "  permit_in SECRET\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    plan_label_policy_config_t *cfg = load_str(cfg_text);
    CHECK(cfg != NULL, "config loads with match clause");

    /* Plan: read_secret -> send_http to internal endpoint. */
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, 0, 1);

    plan_action_arg_t internal_args[1] = {
        { .key = "url", .value = "https://api.internal.acme.com/v1/foo" },
    };
    plan_action_desc_t actions[2] = {
        { .name = "read_secret" },
        { .name = "send_http",
          .named_args = internal_args, .n_named_args = 1 },
    };

    plan_warden_request_t req = {
        .plan = p, .actions = actions, .n_actions = 2,
        .policy = plan_label_policy_config_policy(cfg),
    };
    plan_warden_response_t resp;
    plan_warden_verify(&req, &resp);
    CHECK(resp.verdict == PLAN_DEC_SATISFIED,
          "internal endpoint: permit rule matches first; SATISFIED");

    /* Same plan, external endpoint. Permissive rule should NOT match;
     * fallback deny rule fires. */
    plan_action_arg_t external_args[1] = {
        { .key = "url", .value = "https://attacker.example.com/exfil" },
    };
    actions[1].named_args = external_args;
    plan_warden_verify(&req, &resp);
    CHECK(resp.verdict == PLAN_DEC_UNSATISFIED,
          "external endpoint: falls through to deny rule");

    exec_plan_free(p);
    plan_label_policy_config_free(cfg);
}

/* Multi-constraint match: ALL `match` clauses on a rule must hold (AND). */
static void test_arg_match_multi_constraint_and(void)
{
    printf("test_arg_match_multi_constraint_and\n");
    const char *cfg_text =
        "label SECRET 0\n"
        "sticky SECRET\n"
        "rule read_secret\n"
        "  origin SECRET\n"
        "rule send_http\n"
        "  match url https://*.internal.acme.com/*\n"
        "  match method GET\n"
        "  permit_in SECRET\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    plan_label_policy_config_t *cfg = load_str(cfg_text);
    CHECK(cfg != NULL, "multi-constraint config loads");

    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, 0, 1);

    /* Both constraints match: internal URL AND method=GET. */
    plan_action_arg_t both_ok[2] = {
        { "url", "https://api.internal.acme.com/v1/foo" },
        { "method", "GET" },
    };
    plan_action_desc_t actions[2] = {
        { .name = "read_secret" },
        { .name = "send_http",
          .named_args = both_ok, .n_named_args = 2 },
    };
    plan_warden_request_t req = {
        .plan = p, .actions = actions, .n_actions = 2,
        .policy = plan_label_policy_config_policy(cfg),
    };
    plan_warden_response_t resp;
    plan_warden_verify(&req, &resp);
    CHECK(resp.verdict == PLAN_DEC_SATISFIED, "both constraints match");

    /* URL matches, method does not — fall through to deny. */
    plan_action_arg_t method_wrong[2] = {
        { "url", "https://api.internal.acme.com/v1/foo" },
        { "method", "POST" },
    };
    actions[1].named_args = method_wrong;
    plan_warden_verify(&req, &resp);
    CHECK(resp.verdict == PLAN_DEC_UNSATISFIED,
          "AND semantics: any constraint fails -> rule does not match");

    exec_plan_free(p);
    plan_label_policy_config_free(cfg);
}

/* Missing named arg means the constraint cannot be satisfied — the
 * rule does NOT match (it falls through to the next rule). */
static void test_arg_match_missing_named_arg(void)
{
    printf("test_arg_match_missing_named_arg\n");
    const char *cfg_text =
        "label SECRET 0\n"
        "sticky SECRET\n"
        "rule read_secret\n"
        "  origin SECRET\n"
        "rule send_http\n"
        "  match url https://*.internal.acme.com/*\n"
        "  permit_in SECRET\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    plan_label_policy_config_t *cfg = load_str(cfg_text);

    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, 0, 1);

    /* No 'url' named arg at all. */
    plan_action_desc_t actions[2] = {
        { .name = "read_secret" },
        { .name = "send_http" },
    };
    plan_warden_request_t req = {
        .plan = p, .actions = actions, .n_actions = 2,
        .policy = plan_label_policy_config_policy(cfg),
    };
    plan_warden_response_t resp;
    plan_warden_verify(&req, &resp);
    CHECK(resp.verdict == PLAN_DEC_UNSATISFIED,
          "missing named arg -> rule does not match -> fallback deny");

    exec_plan_free(p);
    plan_label_policy_config_free(cfg);
}

/* No named args at all on the action: v1.7.3-compatible behavior
 * (rules with no match clause apply by name only). */
static void test_arg_match_backward_compat(void)
{
    printf("test_arg_match_backward_compat\n");
    const char *cfg_text =
        "label SECRET 0\n"
        "sticky SECRET\n"
        "rule read_secret\n"
        "  origin SECRET\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    plan_label_policy_config_t *cfg = load_str(cfg_text);

    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, 0, 1);

    /* No named_args fields populated — v1.7.3 shape. */
    plan_action_desc_t actions[2] = {
        { .name = "read_secret" },
        { .name = "send_http"   },
    };
    plan_warden_request_t req = {
        .plan = p, .actions = actions, .n_actions = 2,
        .policy = plan_label_policy_config_policy(cfg),
    };
    plan_warden_response_t resp;
    plan_warden_verify(&req, &resp);
    CHECK(resp.verdict == PLAN_DEC_UNSATISFIED,
          "v1.7.3-shape actions still trigger name-only rules");

    exec_plan_free(p);
    plan_label_policy_config_free(cfg);
}

/* Glob edge cases — '?' single-char match, multiple '*' wildcards. */
static void test_glob_edge_cases(void)
{
    printf("test_glob_edge_cases\n");
    const char *cfg_text =
        "label SECRET 0\n"
        "sticky SECRET\n"
        "rule emit_token\n"
        "  origin SECRET\n"
        "rule write\n"
        "  match path /tmp/cache-?.dat\n"
        "  permit_in SECRET\n"
        "rule write\n"
        "  match path *.log\n"
        "  permit_in SECRET\n"
        "rule write\n"
        "  deny_in SECRET\n";
    plan_label_policy_config_t *cfg = load_str(cfg_text);
    CHECK(cfg != NULL, "glob config loads");

    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "emit_token", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "write",      PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, 0, 1);

    plan_action_arg_t args[1] = {{ .key = "path", .value = NULL }};
    plan_action_desc_t actions[2] = {
        { .name = "emit_token" },
        { .name = "write", .named_args = args, .n_named_args = 1 },
    };
    plan_warden_request_t req = {
        .plan = p, .actions = actions, .n_actions = 2,
        .policy = plan_label_policy_config_policy(cfg),
    };
    plan_warden_response_t resp;

    /* '?' matches exactly one char: /tmp/cache-1.dat matches the
     * first rule -> permit -> SATISFIED. */
    args[0].value = "/tmp/cache-1.dat";
    plan_warden_verify(&req, &resp);
    CHECK(resp.verdict == PLAN_DEC_SATISFIED, "'?' matches single char");

    /* '?' does NOT match two chars: /tmp/cache-12.dat fails the
     * first rule ('?' is one char), fails the second ('.dat' is not
     * '*.log'), and falls through to the catch-all deny -> UNSAT. */
    args[0].value = "/tmp/cache-12.dat";
    plan_warden_verify(&req, &resp);
    CHECK(resp.verdict == PLAN_DEC_UNSATISFIED,
          "'?' matches one char only; two-char tail falls through to deny");

    /* '*' matches across the path: /var/log/app.log matches *.log. */
    args[0].value = "/var/log/app.log";
    plan_warden_verify(&req, &resp);
    CHECK(resp.verdict == PLAN_DEC_SATISFIED,
          "*.log matches via '*' wildcard");

    /* No glob matches -> deny fallback. */
    args[0].value = "/etc/passwd";
    plan_warden_verify(&req, &resp);
    CHECK(resp.verdict == PLAN_DEC_UNSATISFIED,
          "no glob matches -> deny fallback");

    exec_plan_free(p);
    plan_label_policy_config_free(cfg);
}

/* ---------- Lineage tracing ---------- */

/* Multi-hop lineage: src -> mid1 -> mid2 -> sink. Originator is src,
 * not mid1 or mid2. */
static void test_lineage_multi_hop(void)
{
    printf("test_lineage_multi_hop\n");
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);  /* 0 */
    exec_plan_add_node(p, "transform",   PLAN_DEC_SATISFIED);  /* 1 */
    exec_plan_add_node(p, "enrich",      PLAN_DEC_SATISFIED);  /* 2 */
    exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);  /* 3 */
    exec_plan_add_edge(p, 0, 1);
    exec_plan_add_edge(p, 1, 2);
    exec_plan_add_edge(p, 2, 3);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, 0, L_SECRET);
    plan_dataflow_add_deny_in(df, 3, L_SECRET);

    plan_pathology_opts_t opts = { .label_name = label_namer };
    char buf[4096];
    ssize_t n = plan_dataflow_emit_pathology_buf(df, &opts, buf, sizeof buf);
    CHECK(n > 0, "pathology emitted");

    /* Sources is immediate predecessor (enrich, node 2). */
    CHECK(contains(buf, n, "\"from_label\":\"enrich\""),
          "sources lists immediate predecessor (enrich)");
    /* Originators is the read_secret node — root of the leak. */
    CHECK(contains(buf, n, "\"originators\":"),
          "originators array present");
    CHECK(contains(buf, n, "\"node_label\":\"read_secret\""),
          "originators names the originating action by name");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Multiple originators of the same label converging on one sink. */
static void test_lineage_multiple_originators(void)
{
    printf("test_lineage_multiple_originators\n");
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_db",   PLAN_DEC_SATISFIED);  /* 0 */
    exec_plan_add_node(p, "read_file", PLAN_DEC_SATISFIED);  /* 1 */
    exec_plan_add_node(p, "merge",     PLAN_DEC_SATISFIED);  /* 2 */
    exec_plan_add_node(p, "send_http", PLAN_DEC_SATISFIED);  /* 3 */
    exec_plan_add_edge(p, 0, 2);
    exec_plan_add_edge(p, 1, 2);
    exec_plan_add_edge(p, 2, 3);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, 0, L_SECRET);
    plan_dataflow_add_origin(df, 1, L_SECRET);
    plan_dataflow_add_deny_in(df, 3, L_SECRET);

    plan_pathology_opts_t opts = { .label_name = label_namer };
    char buf[4096];
    ssize_t n = plan_dataflow_emit_pathology_buf(df, &opts, buf, sizeof buf);
    CHECK(n > 0, "pathology emitted");
    CHECK(contains(buf, n, "\"node_label\":\"read_db\""),
          "originator read_db reported");
    CHECK(contains(buf, n, "\"node_label\":\"read_file\""),
          "originator read_file reported");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* An originator that does NOT have a path-carrying-the-label to the
 * sink must NOT be reported. Verifies the backward BFS prunes
 * correctly through the outbound check. */
static void test_lineage_excludes_non_contributing_originator(void)
{
    printf("test_lineage_excludes_non_contributing_originator\n");
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret_A", PLAN_DEC_SATISFIED);  /* 0 contributes */
    exec_plan_add_node(p, "read_secret_B", PLAN_DEC_SATISFIED);  /* 1 dead-end */
    exec_plan_add_node(p, "dead_end_log",  PLAN_DEC_SATISFIED);  /* 2: receives B */
    exec_plan_add_node(p, "send_http",     PLAN_DEC_SATISFIED);  /* 3 */
    exec_plan_add_edge(p, 0, 3);   /* A -> sink */
    exec_plan_add_edge(p, 1, 2);   /* B -> dead_end_log (not to sink) */

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, 0, L_SECRET);
    plan_dataflow_add_origin(df, 1, L_SECRET);
    plan_dataflow_add_deny_in(df, 3, L_SECRET);
    /* Node 2 (dead_end_log) has no classification of SECRET; it would
     * fail-safe to UNKNOWN on the sticky rule. To isolate the lineage
     * test, give it a permit_in. */
    plan_dataflow_add_permit_in(df, 2, L_SECRET);

    plan_pathology_opts_t opts = { .label_name = label_namer };
    char buf[4096];
    ssize_t n = plan_dataflow_emit_pathology_buf(df, &opts, buf, sizeof buf);
    CHECK(n > 0, "pathology emitted");

    /* The send_http suppression must list read_secret_A as originator
     * (it's on the path) but NOT read_secret_B (it's not on any
     * label-carrying path to send_http). We search the send_http
     * block specifically. */
    const char *send_http_marker = strstr(buf, "\"node_label\":\"send_http\"");
    CHECK(send_http_marker != NULL, "send_http block present");
    /* Within the send_http block, look for originators list. */
    if (send_http_marker) {
        /* Find the closing of this suppression block. The next
         * suppression entry (if any) starts after a "},{". For this
         * test the send_http suppression is the only one, so the
         * whole tail after the marker is fair game. */
        const size_t off = (size_t)(send_http_marker - buf);
        const size_t tail = (size_t)n - off;
        CHECK(contains(send_http_marker, tail, "\"read_secret_A\""),
              "send_http originator includes A (path contributor)");
        CHECK(!contains(send_http_marker, tail, "\"read_secret_B\""),
              "send_http originator excludes B (no path to sink)");
    }

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Lineage on a sticky_unclassified UNKNOWN refusal. */
static void test_lineage_sticky_unclassified(void)
{
    printf("test_lineage_sticky_unclassified\n");
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);  /* 0 */
    exec_plan_add_node(p, "mid",         PLAN_DEC_SATISFIED);  /* 1, permit */
    exec_plan_add_node(p, "unclassified",PLAN_DEC_SATISFIED);  /* 2, no class */
    exec_plan_add_edge(p, 0, 1);
    exec_plan_add_edge(p, 1, 2);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, 0, L_SECRET);
    plan_dataflow_add_permit_in(df, 1, L_SECRET);
    /* Node 2 has no classification — UNKNOWN refusal. */

    plan_pathology_opts_t opts = { .label_name = label_namer };
    char buf[4096];
    ssize_t n = plan_dataflow_emit_pathology_buf(df, &opts, buf, sizeof buf);
    CHECK(n > 0, "pathology emitted");
    CHECK(contains(buf, n, "\"kind\":\"sticky_unclassified\""),
          "sticky_unclassified offense reported");
    CHECK(contains(buf, n, "\"node_label\":\"read_secret\""),
          "originator named even for UNKNOWN refusal");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* ---------- Integrated end-to-end with config + lineage ---------- */

static void test_integrated_config_arg_match_lineage(void)
{
    printf("test_integrated_config_arg_match_lineage\n");
    const char *cfg_text =
        "label SECRET 0\n"
        "sticky SECRET\n"
        "rule read_secret\n"
        "  origin SECRET\n"
        "rule transform\n"
        "  permit_in SECRET\n"
        "rule send_http\n"
        "  match url https://*.internal.acme.com/*\n"
        "  permit_in SECRET\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    plan_label_policy_config_t *cfg = load_str(cfg_text);
    CHECK(cfg != NULL, "integrated config loads");

    /* Plan: read_secret -> transform -> send_http to EXTERNAL host. */
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "transform",   PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, 0, 1);
    exec_plan_add_edge(p, 1, 2);

    plan_action_arg_t external[1] = {
        { "url", "https://leak.attacker.example/exfil" },
    };
    plan_action_desc_t actions[3] = {
        { .name = "read_secret" },
        { .name = "transform"   },
        { .name = "send_http",
          .named_args = external, .n_named_args = 1 },
    };
    plan_pathology_opts_t opts =
        plan_label_policy_config_pathology_opts(cfg);
    char pbuf[4096];
    plan_warden_request_t req = {
        .plan = p, .actions = actions, .n_actions = 3,
        .policy = plan_label_policy_config_policy(cfg),
        .path_opts = &opts,
        .pathology_buf = pbuf, .pathology_buf_sz = sizeof pbuf,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);
    CHECK(rc == 0, "binding returns 0");
    CHECK(resp.verdict == PLAN_DEC_UNSATISFIED,
          "external endpoint denied");
    CHECK(resp.pathology_emitted, "pathology written");
    CHECK(contains(pbuf, resp.pathology_len, "\"node_label\":\"send_http\""),
          "pathology names offending action");
    CHECK(contains(pbuf, resp.pathology_len, "\"originators\":"),
          "originators array present");
    CHECK(contains(pbuf, resp.pathology_len, "\"node_label\":\"read_secret\""),
          "originator names read_secret as the root");

    exec_plan_free(p);
    plan_label_policy_config_free(cfg);
}

/* ---------- Parse error for malformed match ---------- */

static void test_match_parse_error(void)
{
    printf("test_match_parse_error\n");
    int el = -1; const char *em = NULL;
    FILE *f = fmemopen((void *)"rule r\n  match onlyone\n",
                       strlen("rule r\n  match onlyone\n"), "r");
    plan_label_policy_config_t *cfg = NULL;
    plan_label_policy_config_load_stream(f, &cfg, &el, &em);
    fclose(f);
    CHECK(cfg == NULL, "incomplete match -> load fails");
    CHECK(el == 2, "error reported on line 2");
    CHECK(em != NULL && strstr(em, "KEY and PATTERN") != NULL,
          "error message names KEY and PATTERN");
}

int main(void)
{
    test_arg_match_internal_vs_external();
    test_arg_match_multi_constraint_and();
    test_arg_match_missing_named_arg();
    test_arg_match_backward_compat();
    test_glob_edge_cases();

    test_lineage_multi_hop();
    test_lineage_multiple_originators();
    test_lineage_excludes_non_contributing_originator();
    test_lineage_sticky_unclassified();

    test_integrated_config_arg_match_lineage();
    test_match_parse_error();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
