// SPDX-License-Identifier: MIT
/*
 * test_v17_2.c — VAREK v1.7.2 Warden-binding integration tests.
 *
 * End-to-end tests of plan_warden_verify(): the full pipeline from
 * an exec_plan_t + action array + label policy through to the
 * two-axis verdict and (on refusal) pathology JSON. These tests
 * exercise the binding as the Warden's `--plan` handler will.
 *
 * Clean under -fsanitize=address,undefined.
 */

#include "execution_plan.h"
#include "plan_dataflow.h"
#include "plan_label.h"
#include "plan_label_policy.h"
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

/* ---------- Shared fixture builders ---------- */

/* Build a simple 3-node plan: read_secret -> process -> send_http.
 * Caller owns the returned plan. */
static exec_plan_t *make_3node_plan(plan_decision_t per_node_decision)
{
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret", per_node_decision);
    exec_plan_add_node(p, "process",     per_node_decision);
    exec_plan_add_node(p, "send_http",   per_node_decision);
    exec_plan_add_edge(p, 0, 1);
    exec_plan_add_edge(p, 1, 2);
    return p;
}

/* Policy rules covering the 3-node plan: read originates SECRET,
 * process is unmatched (intentional, to exercise sticky fail-safe),
 * send_http denies SECRET. */
static void make_3node_policy(plan_label_rule_t rules[2],
                              plan_label_table_t *tbl,
                              plan_label_policy_t *pol)
{
    memset(rules, 0, sizeof(plan_label_rule_t) * 2);
    rules[0].action_name = "read_secret";
    plan_label_set_add(&rules[0].classify.origin, L_SECRET);
    rules[1].action_name = "send_http";
    plan_label_set_add(&rules[1].classify.deny_in, L_SECRET);

    tbl->rules   = rules;
    tbl->n_rules = 2;
    tbl->strict  = false;

    pol->classify = plan_label_policy_from_table;
    pol->ctx      = tbl;
    plan_label_set_clear(&pol->sticky);
    plan_label_set_add(&pol->sticky, L_SECRET);
}

/* ---------- Tests ---------- */

/* Canonical exfil case end-to-end: node-axis SATISFIED, flow-axis
 * UNSATISFIED (send_http denies inbound SECRET), joined UNSATISFIED,
 * pathology JSON populated. */
static void test_canonical_exfil(void)
{
    printf("test_canonical_exfil\n");
    exec_plan_t *plan = make_3node_plan(PLAN_DEC_SATISFIED);
    plan_label_rule_t rules[2];
    plan_label_table_t tbl;
    plan_label_policy_t pol;
    make_3node_policy(rules, &tbl, &pol);

    plan_action_desc_t actions[3] = {
        { .name = "read_secret" },
        { .name = "process"     },
        { .name = "send_http"   },
    };
    plan_pathology_opts_t opts = { .label_name = label_namer };
    char pbuf[4096];

    plan_warden_request_t req = {
        .plan = plan, .actions = actions, .n_actions = 3,
        .policy = &pol, .path_opts = &opts,
        .pathology_buf = pbuf, .pathology_buf_sz = sizeof pbuf,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);

    CHECK(rc == 0, "binding returns 0 (success path)");
    CHECK(resp.verdict   == PLAN_DEC_UNSATISFIED, "joined verdict UNSATISFIED");
    CHECK(resp.node_axis == PLAN_DEC_SATISFIED,   "node axis SATISFIED");
    CHECK(resp.flow_axis == PLAN_DEC_UNSATISFIED, "flow axis UNSATISFIED");
    CHECK(!plan_warden_authorized(&resp), "binding refuses authorization");
    CHECK(resp.pathology_emitted, "pathology written on refusal");
    CHECK(!resp.pathology_overflow, "pathology fit the buffer");
    CHECK(resp.pathology_len > 0, "pathology length positive");
    CHECK(contains(pbuf, resp.pathology_len, "\"verdict\":\"UNSATISFIED\""),
          "pathology reports joined verdict");
    CHECK(contains(pbuf, resp.pathology_len, "\"node_label\":\"send_http\""),
          "pathology names the offending node");
    CHECK(contains(pbuf, resp.pathology_len, "\"SECRET\""),
          "pathology names the offending label");

    exec_plan_free(plan);
}

/* Clean plan: SATISFIED end-to-end; binding authorizes; pathology
 * is NOT written even though a buffer was supplied (no refusal). */
static void test_clean_plan_authorizes(void)
{
    printf("test_clean_plan_authorizes\n");
    exec_plan_t *plan = exec_plan_new();
    exec_plan_add_node(plan, "noop_a", PLAN_DEC_SATISFIED);
    exec_plan_add_node(plan, "noop_b", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(plan, 0, 1);

    /* Empty rule table, no sticky labels: nothing to police. */
    plan_label_table_t tbl = { .rules = NULL, .n_rules = 0, .strict = false };
    plan_label_policy_t pol = {
        .classify = plan_label_policy_from_table,
        .ctx      = &tbl,
    };
    plan_label_set_clear(&pol.sticky);

    plan_action_desc_t actions[2] = {
        { .name = "noop_a" }, { .name = "noop_b" },
    };
    char pbuf[4096];
    plan_warden_request_t req = {
        .plan = plan, .actions = actions, .n_actions = 2,
        .policy = &pol, .path_opts = NULL,
        .pathology_buf = pbuf, .pathology_buf_sz = sizeof pbuf,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);

    CHECK(rc == 0, "success");
    CHECK(resp.verdict == PLAN_DEC_SATISFIED, "joined verdict SATISFIED");
    CHECK(plan_warden_authorized(&resp), "binding authorizes");
    CHECK(!resp.pathology_emitted, "no pathology on SATISFIED");
    CHECK(resp.pathology_len == 0, "pathology_len zero");

    exec_plan_free(plan);
}

/* Sticky-unclassified UNKNOWN end-to-end: an action with no rule
 * receives a sticky label, kernel fail-safes to UNKNOWN, binding
 * refuses, pathology names sticky_unclassified. */
static void test_sticky_unclassified_unknown(void)
{
    printf("test_sticky_unclassified_unknown\n");
    exec_plan_t *plan = exec_plan_new();
    exec_plan_add_node(plan, "read_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(plan, "mystery",     PLAN_DEC_SATISFIED);
    exec_plan_add_edge(plan, 0, 1);

    plan_label_rule_t rules[1];
    memset(rules, 0, sizeof rules);
    rules[0].action_name = "read_secret";
    plan_label_set_add(&rules[0].classify.origin, L_SECRET);

    plan_label_table_t tbl = { .rules = rules, .n_rules = 1, .strict = false };
    plan_label_policy_t pol = {
        .classify = plan_label_policy_from_table, .ctx = &tbl,
    };
    plan_label_set_clear(&pol.sticky);
    plan_label_set_add(&pol.sticky, L_SECRET);

    plan_action_desc_t actions[2] = {
        { .name = "read_secret" }, { .name = "mystery" },
    };
    plan_pathology_opts_t opts = { .label_name = label_namer };
    char pbuf[4096];
    plan_warden_request_t req = {
        .plan = plan, .actions = actions, .n_actions = 2,
        .policy = &pol, .path_opts = &opts,
        .pathology_buf = pbuf, .pathology_buf_sz = sizeof pbuf,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);

    CHECK(rc == 0, "success");
    CHECK(resp.verdict   == PLAN_DEC_UNKNOWN, "joined verdict UNKNOWN");
    CHECK(resp.flow_axis == PLAN_DEC_UNKNOWN, "flow axis UNKNOWN");
    CHECK(!plan_warden_authorized(&resp), "UNKNOWN refuses authorization");
    CHECK(resp.pathology_emitted, "pathology written on UNKNOWN refusal");
    CHECK(contains(pbuf, resp.pathology_len,
                   "\"kind\":\"sticky_unclassified\""),
          "pathology names sticky_unclassified offense");
    CHECK(contains(pbuf, resp.pathology_len, "\"node_label\":\"mystery\""),
          "pathology names unclassified sink");

    exec_plan_free(plan);
}

/* Node-axis UNSATISFIED: a node's per-node decision is UNSATISFIED.
 * The binding must report UNSATISFIED on the node axis and the
 * joined verdict, even when the flow axis is clean. */
static void test_node_axis_refuses_alone(void)
{
    printf("test_node_axis_refuses_alone\n");
    exec_plan_t *plan = exec_plan_new();
    exec_plan_add_node(plan, "ok",       PLAN_DEC_SATISFIED);
    exec_plan_add_node(plan, "forbidden", PLAN_DEC_UNSATISFIED);
    exec_plan_add_edge(plan, 0, 1);

    plan_label_table_t tbl = { .rules = NULL, .n_rules = 0, .strict = false };
    plan_label_policy_t pol = {
        .classify = plan_label_policy_from_table, .ctx = &tbl,
    };
    plan_label_set_clear(&pol.sticky);

    plan_action_desc_t actions[2] = {
        { .name = "ok" }, { .name = "forbidden" },
    };
    plan_warden_request_t req = {
        .plan = plan, .actions = actions, .n_actions = 2,
        .policy = &pol,
        .pathology_buf = NULL, .pathology_buf_sz = 0,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);

    CHECK(rc == 0, "success");
    CHECK(resp.node_axis == PLAN_DEC_UNSATISFIED, "node axis UNSAT");
    CHECK(resp.flow_axis == PLAN_DEC_SATISFIED,   "flow axis clean");
    CHECK(resp.verdict   == PLAN_DEC_UNSATISFIED, "joined UNSAT (node alone)");
    CHECK(!resp.pathology_emitted, "no pathology when no buffer supplied");

    exec_plan_free(plan);
}

/* NULL request: -1 with response safely refused. */
static void test_null_request_safely_refuses(void)
{
    printf("test_null_request_safely_refuses\n");
    plan_warden_response_t resp;
    int rc = plan_warden_verify(NULL, &resp);
    CHECK(rc == -1, "NULL request returns -1");
    CHECK(resp.verdict   == PLAN_DEC_UNKNOWN, "verdict defaulted to UNKNOWN");
    CHECK(resp.node_axis == PLAN_DEC_UNKNOWN, "node axis UNKNOWN");
    CHECK(resp.flow_axis == PLAN_DEC_UNKNOWN, "flow axis UNKNOWN");
    CHECK(!plan_warden_authorized(&resp), "safe-refuse on internal error");
}

/* Missing required field: NULL plan in a non-NULL request. */
static void test_missing_plan_safely_refuses(void)
{
    printf("test_missing_plan_safely_refuses\n");
    plan_action_desc_t a = { .name = "x" };
    plan_label_table_t tbl = { .rules = NULL, .n_rules = 0, .strict = false };
    plan_label_policy_t pol = {
        .classify = plan_label_policy_from_table, .ctx = &tbl };
    plan_label_set_clear(&pol.sticky);

    plan_warden_request_t req = {
        .plan = NULL, .actions = &a, .n_actions = 1, .policy = &pol,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);
    CHECK(rc == -1, "NULL plan returns -1");
    CHECK(resp.verdict == PLAN_DEC_UNKNOWN, "safe default");
}

/* Populate failure (strict + unmatched) propagates as -1, response
 * safely refused. */
static void test_populate_failure_safely_refuses(void)
{
    printf("test_populate_failure_safely_refuses\n");
    exec_plan_t *plan = exec_plan_new();
    exec_plan_add_node(plan, "unrecognized", PLAN_DEC_SATISFIED);

    plan_label_table_t tbl = { .rules = NULL, .n_rules = 0, .strict = true };
    plan_label_policy_t pol = {
        .classify = plan_label_policy_from_table, .ctx = &tbl };
    plan_label_set_clear(&pol.sticky);

    plan_action_desc_t actions[1] = { { .name = "unrecognized" } };
    plan_warden_request_t req = {
        .plan = plan, .actions = actions, .n_actions = 1, .policy = &pol,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);
    CHECK(rc == -1, "strict policy + unmatched action -> -1");
    CHECK(resp.verdict == PLAN_DEC_UNKNOWN, "safe default on populate failure");

    exec_plan_free(plan);
}

/* Pathology buffer too small: overflow flag set, verdict still
 * computed correctly. */
static void test_pathology_overflow_preserves_verdict(void)
{
    printf("test_pathology_overflow_preserves_verdict\n");
    exec_plan_t *plan = make_3node_plan(PLAN_DEC_SATISFIED);
    plan_label_rule_t rules[2];
    plan_label_table_t tbl;
    plan_label_policy_t pol;
    make_3node_policy(rules, &tbl, &pol);

    plan_action_desc_t actions[3] = {
        { .name = "read_secret" },
        { .name = "process"     },
        { .name = "send_http"   },
    };
    char tiny[4];   /* too small for any record */
    plan_warden_request_t req = {
        .plan = plan, .actions = actions, .n_actions = 3, .policy = &pol,
        .pathology_buf = tiny, .pathology_buf_sz = sizeof tiny,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);

    CHECK(rc == 0, "binding still returns 0");
    CHECK(resp.verdict == PLAN_DEC_UNSATISFIED, "verdict computed correctly");
    CHECK(resp.pathology_overflow, "overflow flagged");
    CHECK(!resp.pathology_emitted, "no record claimed on overflow");
    CHECK(resp.pathology_len == 0, "no bytes claimed on overflow");

    exec_plan_free(plan);
}

/* No pathology buffer at all: verdict computed; no emission attempted. */
static void test_no_pathology_buffer(void)
{
    printf("test_no_pathology_buffer\n");
    exec_plan_t *plan = make_3node_plan(PLAN_DEC_SATISFIED);
    plan_label_rule_t rules[2];
    plan_label_table_t tbl;
    plan_label_policy_t pol;
    make_3node_policy(rules, &tbl, &pol);

    plan_action_desc_t actions[3] = {
        { .name = "read_secret" }, { .name = "process" }, { .name = "send_http" },
    };
    plan_warden_request_t req = {
        .plan = plan, .actions = actions, .n_actions = 3, .policy = &pol,
        .pathology_buf = NULL, .pathology_buf_sz = 0,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);

    CHECK(rc == 0, "success");
    CHECK(resp.verdict == PLAN_DEC_UNSATISFIED, "refusal computed");
    CHECK(!resp.pathology_emitted, "no pathology when no buffer");
    CHECK(!resp.pathology_overflow, "no overflow flag when no buffer");

    exec_plan_free(plan);
}

/* Determinism across calls: same plan + policy yields byte-identical
 * pathology output. */
static void test_determinism(void)
{
    printf("test_determinism\n");
    exec_plan_t *plan = make_3node_plan(PLAN_DEC_SATISFIED);
    plan_label_rule_t rules[2];
    plan_label_table_t tbl;
    plan_label_policy_t pol;
    make_3node_policy(rules, &tbl, &pol);

    plan_action_desc_t actions[3] = {
        { .name = "read_secret" }, { .name = "process" }, { .name = "send_http" },
    };
    plan_pathology_opts_t opts = { .label_name = label_namer };
    char buf1[4096], buf2[4096];

    plan_warden_request_t req1 = {
        .plan = plan, .actions = actions, .n_actions = 3, .policy = &pol,
        .path_opts = &opts,
        .pathology_buf = buf1, .pathology_buf_sz = sizeof buf1,
    };
    plan_warden_response_t resp1, resp2;
    int rc1 = plan_warden_verify(&req1, &resp1);

    plan_warden_request_t req2 = req1;
    req2.pathology_buf = buf2;
    int rc2 = plan_warden_verify(&req2, &resp2);

    CHECK(rc1 == 0 && rc2 == 0, "both calls succeed");
    CHECK(resp1.verdict == resp2.verdict, "verdicts match");
    CHECK(resp1.pathology_len == resp2.pathology_len,
          "pathology lengths match");
    CHECK(memcmp(buf1, buf2, resp1.pathology_len) == 0,
          "pathology bytes match exactly");

    exec_plan_free(plan);
}

int main(void)
{
    test_canonical_exfil();
    test_clean_plan_authorizes();
    test_sticky_unclassified_unknown();
    test_node_axis_refuses_alone();
    test_null_request_safely_refuses();
    test_missing_plan_safely_refuses();
    test_populate_failure_safely_refuses();
    test_pathology_overflow_preserves_verdict();
    test_no_pathology_buffer();
    test_determinism();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
