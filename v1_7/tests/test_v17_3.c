// SPDX-License-Identifier: MIT
/*
 * test_v17_3.c — VAREK v1.7.3 config-loader tests.
 *
 * Covers:
 *   - parse of a full valid config (including the canonical exfil case)
 *   - blank lines, comments, indentation handling
 *   - every documented error path with correct line numbers
 *   - end-to-end through plan_warden_verify() proving the loaded policy
 *     produces the same verdicts as a hand-built policy
 *   - posture toggles (strict vs default)
 *   - label-name callback used in pathology
 *
 * Uses fmemopen() so configs are written inline as strings.
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

/* ---------- Helpers ---------- */

static plan_label_policy_config_t *
load_str(const char *text, int *err_line, const char **err_msg)
{
    FILE *f = fmemopen((void *)text, strlen(text), "r");
    if (!f) return NULL;
    plan_label_policy_config_t *cfg = NULL;
    plan_label_policy_config_load_stream(f, &cfg, err_line, err_msg);
    fclose(f);
    return cfg;
}

static bool contains(const char *json, size_t n, const char *needle)
{
    size_t nlen = strlen(needle);
    if (n < nlen) return false;
    for (size_t i = 0; i + nlen <= n; i++)
        if (memcmp(json + i, needle, nlen) == 0) return true;
    return false;
}

/* ---------- Positive parses ---------- */

static void test_parse_minimal(void)
{
    printf("test_parse_minimal\n");
    const char *cfg_text =
        "label SECRET 0\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    int err_line = -1;
    const char *err = NULL;
    plan_label_policy_config_t *cfg = load_str(cfg_text, &err_line, &err);
    CHECK(cfg != NULL, "minimal config loads");
    CHECK(plan_label_policy_config_n_labels(cfg) == 1, "one label");
    CHECK(plan_label_policy_config_n_rules(cfg) == 1, "one rule");
    plan_label_policy_config_free(cfg);
}

static void test_parse_full_with_comments_and_blanks(void)
{
    printf("test_parse_full_with_comments_and_blanks\n");
    const char *cfg_text =
        "# leading comment\n"
        "\n"
        "varek_policy 1\n"
        "\n"
        "# posture omitted -> non-strict\n"
        "\n"
        "label SECRET 0\n"
        "label PII    1\n"
        "label PUBLIC 2\n"
        "\n"
        "sticky SECRET\n"
        "sticky PII\n"
        "\n"
        "rule read_secret\n"
        "  origin SECRET\n"
        "\n"
        "rule log_event\n"
        "  permit_in SECRET\n"
        "  permit_in PII\n"
        "\n"
        "rule send_http\n"
        "  deny_in SECRET\n"
        "  deny_in PII\n";
    int err_line = -1;
    const char *err = NULL;
    plan_label_policy_config_t *cfg = load_str(cfg_text, &err_line, &err);
    CHECK(cfg != NULL, "full config loads");
    CHECK(plan_label_policy_config_n_labels(cfg) == 3, "three labels");
    CHECK(plan_label_policy_config_n_rules(cfg) == 3, "three rules");

    /* Label-name callback returns the right strings. */
    const char *n0 = plan_label_policy_config_label_name(0, cfg);
    const char *n1 = plan_label_policy_config_label_name(1, cfg);
    const char *n9 = plan_label_policy_config_label_name(9, cfg);
    CHECK(n0 && strcmp(n0, "SECRET") == 0, "label 0 named SECRET");
    CHECK(n1 && strcmp(n1, "PII")    == 0, "label 1 named PII");
    CHECK(n9 == NULL, "undeclared label id -> NULL");

    plan_label_policy_config_free(cfg);
}

static void test_strict_toggle(void)
{
    printf("test_strict_toggle\n");
    const char *with_strict =
        "strict\n"
        "label SECRET 0\n";
    int el; const char *em;
    plan_label_policy_config_t *cfg = load_str(with_strict, &el, &em);
    CHECK(cfg != NULL, "strict-bearing config loads");
    const plan_label_policy_t *pol = plan_label_policy_config_policy(cfg);
    const plan_label_table_t *tbl  = (const plan_label_table_t *)pol->ctx;
    CHECK(tbl->strict == true, "strict propagated to table");
    plan_label_policy_config_free(cfg);

    const char *no_strict =
        "label SECRET 0\n";
    cfg = load_str(no_strict, &el, &em);
    CHECK(cfg != NULL, "non-strict default loads");
    pol = plan_label_policy_config_policy(cfg);
    tbl = (const plan_label_table_t *)pol->ctx;
    CHECK(tbl->strict == false, "default is non-strict");
    plan_label_policy_config_free(cfg);
}

/* ---------- Error paths ---------- */

static void expect_error(const char *cfg_text, int want_line, const char *snippet,
                         const char *msg)
{
    int el = -1;
    const char *em = NULL;
    plan_label_policy_config_t *cfg = load_str(cfg_text, &el, &em);
    bool ok = (cfg == NULL) && (el == want_line) && em && strstr(em, snippet);
    checks++;
    if (!ok) {
        failures++;
        printf("  FAIL: %s  (got line=%d, msg=\"%s\")\n",
               msg, el, em ? em : "(null)");
    } else {
        printf("  ok:   %s\n", msg);
    }
    plan_label_policy_config_free(cfg);
}

static void test_error_unknown_statement(void)
{
    printf("test_error_unknown_statement\n");
    expect_error("frobnicate foo\n", 1, "unknown",
                 "unknown top-level statement -> line 1");
}

static void test_error_indented_outside_rule(void)
{
    printf("test_error_indented_outside_rule\n");
    expect_error("  origin SECRET\n", 1, "indented",
                 "indented before any rule -> line 1");
}

static void test_error_label_bad_id(void)
{
    printf("test_error_label_bad_id\n");
    expect_error("label SECRET abc\n", 1, "not a non-negative integer",
                 "non-numeric id -> error");
    expect_error("label SECRET -1\n",  1, "not a non-negative integer",
                 "negative id -> error");
}

static void test_error_label_out_of_range(void)
{
    printf("test_error_label_out_of_range\n");
    /* PLAN_MAX_LABELS is 128 by default. */
    expect_error("label TOO_BIG 128\n", 1, "out of range",
                 "id >= PLAN_MAX_LABELS -> error");
}

static void test_error_label_redeclared_name(void)
{
    printf("test_error_label_redeclared_name\n");
    expect_error("label A 0\nlabel A 1\n", 2, "name already declared",
                 "duplicate name -> line 2");
}

static void test_error_label_redeclared_id(void)
{
    printf("test_error_label_redeclared_id\n");
    expect_error("label A 0\nlabel B 0\n", 2, "id already in use",
                 "duplicate id -> line 2");
}

static void test_error_sticky_undeclared(void)
{
    printf("test_error_sticky_undeclared\n");
    expect_error("sticky NOPE\n", 1, "undeclared label",
                 "sticky NOPE before declaration -> line 1");
}

static void test_error_body_undeclared_label(void)
{
    printf("test_error_body_undeclared_label\n");
    expect_error("rule r\n  origin NOPE\n", 2, "undeclared label",
                 "rule body undeclared label -> line 2");
}

static void test_error_unknown_body_stmt(void)
{
    printf("test_error_unknown_body_stmt\n");
    expect_error("label A 0\nrule r\n  bogus A\n", 3, "unknown rule-body",
                 "unknown body statement -> line 3");
}

static void test_error_duplicate_rule(void)
{
    printf("test_duplicate_rule_allowed\n");
    /* v1.7.4 change: duplicate action_name rules are INTENTIONALLY
     * allowed — they express first-match-wins ordering with different
     * `match` clauses (see test_v17_4). What was a v1.7.3 error is now
     * a feature. Confirm the loader accepts it. */
    int el = -1;
    const char *em = NULL;
    plan_label_policy_config_t *cfg = load_str("rule r\nrule r\n", &el, &em);
    CHECK(cfg != NULL, "duplicate rule action names accepted (v1.7.4)");
    CHECK(cfg && plan_label_policy_config_n_rules(cfg) == 2,
          "both duplicate rules retained in order");
    plan_label_policy_config_free(cfg);
}

static void test_error_version_late(void)
{
    printf("test_error_version_late\n");
    expect_error("label A 0\nvarek_policy 1\n", 2, "must precede",
                 "varek_policy after decl -> line 2");
}

static void test_error_version_value(void)
{
    printf("test_error_version_value\n");
    expect_error("varek_policy 9\n", 1, "version must be 1",
                 "bad version -> line 1");
}

static void test_error_strict_extra_args(void)
{
    printf("test_error_strict_extra_args\n");
    expect_error("strict please\n", 1, "no arguments",
                 "strict with extra tokens -> line 1");
}

/* ---------- End-to-end through plan_warden_verify ---------- */

/* The full pipeline: load a config from text, build a plan + actions,
 * call the binding, verify the verdict and the pathology JSON name
 * the labels by their declared human-readable names. */
static void test_end_to_end_with_binding(void)
{
    printf("test_end_to_end_with_binding\n");
    const char *cfg_text =
        "varek_policy 1\n"
        "label SECRET 0\n"
        "label PII    1\n"
        "sticky SECRET\n"
        "rule read_secret\n"
        "  origin SECRET\n"
        "rule log_event\n"
        "  permit_in SECRET\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    int el; const char *em;
    plan_label_policy_config_t *cfg = load_str(cfg_text, &el, &em);
    CHECK(cfg != NULL, "config loads for binding test");

    /* Build a plan whose action shape matches the rules. */
    exec_plan_t *plan = exec_plan_new();
    exec_plan_add_node(plan, "read_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(plan, "log_event",   PLAN_DEC_SATISFIED);
    exec_plan_add_node(plan, "send_http",   PLAN_DEC_SATISFIED);
    exec_plan_add_edge(plan, 0, 1);
    exec_plan_add_edge(plan, 1, 2);

    plan_action_desc_t actions[3] = {
        { .name = "read_secret" },
        { .name = "log_event"   },
        { .name = "send_http"   },
    };
    plan_pathology_opts_t opts = plan_label_policy_config_pathology_opts(cfg);
    char pbuf[4096];

    plan_warden_request_t req = {
        .plan = plan, .actions = actions, .n_actions = 3,
        .policy = plan_label_policy_config_policy(cfg),
        .path_opts = &opts,
        .pathology_buf = pbuf, .pathology_buf_sz = sizeof pbuf,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);
    CHECK(rc == 0, "binding returns 0");
    CHECK(resp.verdict   == PLAN_DEC_UNSATISFIED, "joined UNSAT (deny at egress)");
    CHECK(resp.flow_axis == PLAN_DEC_UNSATISFIED, "flow axis UNSAT");
    CHECK(resp.node_axis == PLAN_DEC_SATISFIED,   "node axis clean");
    CHECK(resp.pathology_emitted, "pathology written");
    CHECK(contains(pbuf, resp.pathology_len, "\"SECRET\""),
          "pathology names SECRET by its declared name");
    CHECK(contains(pbuf, resp.pathology_len, "\"node_label\":\"send_http\""),
          "pathology names offending action");

    exec_plan_free(plan);
    plan_label_policy_config_free(cfg);
}

/* Round-trip equivalence: a hand-built policy and a loaded-config
 * policy produce identical verdicts on the same plan. */
static void test_round_trip_equivalence(void)
{
    printf("test_round_trip_equivalence\n");

    /* Hand-built policy. */
    plan_label_rule_t rules[2];
    memset(rules, 0, sizeof rules);
    rules[0].action_name = "read_secret";
    plan_label_set_add(&rules[0].classify.origin, 0);   /* SECRET = 0 */
    rules[1].action_name = "send_http";
    plan_label_set_add(&rules[1].classify.deny_in, 0);
    plan_label_table_t handbuilt_tbl = {
        .rules = rules, .n_rules = 2, .strict = false };
    plan_label_policy_t handbuilt_pol = {
        .classify = plan_label_policy_from_table,
        .ctx      = &handbuilt_tbl,
    };
    plan_label_set_clear(&handbuilt_pol.sticky);
    plan_label_set_add(&handbuilt_pol.sticky, 0);

    /* Config-loaded equivalent. */
    const char *cfg_text =
        "label SECRET 0\n"
        "sticky SECRET\n"
        "rule read_secret\n"
        "  origin SECRET\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    int el; const char *em;
    plan_label_policy_config_t *cfg = load_str(cfg_text, &el, &em);
    CHECK(cfg != NULL, "config loads");

    /* Identical plan for both. */
    exec_plan_t *plan = exec_plan_new();
    exec_plan_add_node(plan, "read_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(plan, "send_http",   PLAN_DEC_SATISFIED);
    exec_plan_add_edge(plan, 0, 1);

    plan_action_desc_t actions[2] = {
        { .name = "read_secret" }, { .name = "send_http" },
    };

    plan_warden_request_t req_a = {
        .plan = plan, .actions = actions, .n_actions = 2,
        .policy = &handbuilt_pol,
    };
    plan_warden_request_t req_b = req_a;
    req_b.policy = plan_label_policy_config_policy(cfg);

    plan_warden_response_t r_a, r_b;
    plan_warden_verify(&req_a, &r_a);
    plan_warden_verify(&req_b, &r_b);

    CHECK(r_a.verdict   == r_b.verdict,   "verdicts match");
    CHECK(r_a.flow_axis == r_b.flow_axis, "flow axes match");
    CHECK(r_a.node_axis == r_b.node_axis, "node axes match");

    exec_plan_free(plan);
    plan_label_policy_config_free(cfg);
}

/* The shipped example_policy.cfg parses cleanly. Tries to open the
 * file relative to the working directory; ignores cleanly if not
 * present (e.g. when tests are run from a different cwd). */
static void test_example_policy_file_parses(void)
{
    printf("test_example_policy_file_parses\n");
    FILE *f = fopen("example_policy.cfg", "r");
    if (!f) {
        printf("  ok:   (skipped — example_policy.cfg not in cwd)\n");
        checks++;
        return;
    }
    int el; const char *em;
    plan_label_policy_config_t *cfg = NULL;
    int rc = plan_label_policy_config_load_stream(f, &cfg, &el, &em);
    fclose(f);
    CHECK(rc == 0 && cfg != NULL,
          "shipped example_policy.cfg parses cleanly");
    if (cfg) {
        CHECK(plan_label_policy_config_n_rules(cfg) >= 3,
              "example has at least three rules");
        plan_label_policy_config_free(cfg);
    }
}

int main(void)
{
    test_parse_minimal();
    test_parse_full_with_comments_and_blanks();
    test_strict_toggle();

    test_error_unknown_statement();
    test_error_indented_outside_rule();
    test_error_label_bad_id();
    test_error_label_out_of_range();
    test_error_label_redeclared_name();
    test_error_label_redeclared_id();
    test_error_sticky_undeclared();
    test_error_body_undeclared_label();
    test_error_unknown_body_stmt();
    test_error_duplicate_rule();
    test_error_version_late();
    test_error_version_value();
    test_error_strict_extra_args();

    test_end_to_end_with_binding();
    test_round_trip_equivalence();
    test_example_policy_file_parses();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
