// SPDX-License-Identifier: MIT
/*
 * test_v17_1.c — VAREK v1.7.1 tests.
 *
 * Covers:
 *   - sticky/permit_in kernel semantics (fail-safe, deny-dominates,
 *     permit overrides sticky)
 *   - backward compatibility with v1.7.0 deny-list when no labels
 *     are marked sticky
 *   - adapter populate from a declarative table policy
 *   - pathology JSON shape, content, and determinism
 *
 * Clean under -fsanitize=address,undefined.
 */

#include "execution_plan.h"
#include "plan_dataflow.h"
#include "plan_dataflow_adapter.h"
#include "plan_dataflow_pathology.h"
#include "plan_label.h"
#include "plan_label_policy.h"

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

enum { L_SECRET = 0, L_PII = 1, L_PUBLIC = 2, L_TRACE = 3 };

/* ---------- Sticky kernel semantics ---------- */

/* Sticky label arriving at a node with NO classification at all
 * yields UNKNOWN (the fail-safe v1.7.1 default). */
static void test_sticky_unclassified_is_unknown(void)
{
    printf("test_sticky_unclassified_is_unknown\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "read",   PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "consume", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, a, L_SECRET);
    /* b has NO classification of SECRET at all. */

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNKNOWN,
          "sticky label at unclassified sink -> UNKNOWN");
    CHECK(plan_dataflow_node_decision(df, b) == PLAN_DEC_UNKNOWN,
          "consume node UNKNOWN");
    CHECK(!exec_plan_authorized_with_dataflow(p, df),
          "fail-safe: UNKNOWN suppresses authorization");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Sticky label with explicit permit_in at the sink yields SATISFIED. */
static void test_sticky_permit_in_authorizes(void)
{
    printf("test_sticky_permit_in_authorizes\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "read",   PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "consume", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, a, L_SECRET);
    plan_dataflow_add_permit_in(df, b, L_SECRET);  /* explicitly OK */

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_SATISFIED,
          "sticky label with permit_in -> SATISFIED");
    CHECK(exec_plan_authorized_with_dataflow(p, df),
          "explicit permission authorizes");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Deny still dominates even when sticky and permit_in are also set —
 * the lattice's UNSAT-on-top invariant is preserved. */
static void test_sticky_deny_dominates(void)
{
    printf("test_sticky_deny_dominates\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "read",   PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "egress", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, a, L_SECRET);
    plan_dataflow_add_deny_in(df, b, L_SECRET);
    plan_dataflow_add_permit_in(df, b, L_SECRET); /* contradictory; deny wins */

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNSATISFIED,
          "deny dominates even with permit_in present");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* A FREE (non-sticky) label that is unclassified at the sink stays
 * SATISFIED — the v1.7.0 deny-list semantics for free labels are
 * preserved. */
static void test_free_label_default_satisfied(void)
{
    printf("test_free_label_default_satisfied\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "tagger",  PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "consume", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);

    plan_dataflow_t *df = plan_dataflow_new(p);
    /* L_TRACE is NOT marked sticky. */
    plan_dataflow_add_origin(df, a, L_TRACE);

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_SATISFIED,
          "free label unclassified at sink -> SATISFIED (v1.7.0 compat)");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Sticky takes plan-wide effect: marking a label sticky after
 * setting up origins still triggers the fail-safe at sinks. */
static void test_sticky_marked_after_origins(void)
{
    printf("test_sticky_marked_after_origins\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "read",   PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "consume", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_add_origin(df, a, L_SECRET);
    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_SATISFIED,
          "before mark_sticky: SATISFIED (deny-list)");
    plan_dataflow_mark_sticky(df, L_SECRET);
    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNKNOWN,
          "after mark_sticky: UNKNOWN (fail-safe)");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* ---------- Adapter ---------- */

static void test_adapter_populates_from_table(void)
{
    printf("test_adapter_populates_from_table\n");

    /* Plan: read_secret -> log -> send_http. Three actions. */
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "log",         PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, 0, 1);
    exec_plan_add_edge(p, 1, 2);

    /* Rule table: read_secret originates SECRET, send_http denies it.
     * log is unmatched (and non-strict): with SECRET sticky, log will
     * fail-safe to UNKNOWN — which is the correct, principled refusal. */
    plan_label_rule_t rules[2];
    memset(rules, 0, sizeof rules);
    rules[0].action_name = "read_secret";
    plan_label_set_add(&rules[0].classify.origin, L_SECRET);
    rules[1].action_name = "send_http";
    plan_label_set_add(&rules[1].classify.deny_in, L_SECRET);

    plan_label_table_t tbl = { .rules = rules, .n_rules = 2, .strict = false };

    plan_label_policy_t pol = {
        .classify = plan_label_policy_from_table,
        .ctx      = &tbl,
    };
    plan_label_set_clear(&pol.sticky);
    plan_label_set_add(&pol.sticky, L_SECRET);

    plan_action_desc_t acts[3] = {
        { .name = "read_secret" },
        { .name = "log"         },
        { .name = "send_http"   },
    };

    plan_dataflow_t *df = plan_dataflow_new(p);
    int rc = plan_dataflow_populate(df, acts, 3, &pol);
    CHECK(rc == 0, "populate returns 0");

    plan_decision_t v = plan_dataflow_flow_verdict(df);
    /* The log node (unclassified, sticky SECRET) yields UNKNOWN.
     * The send_http node (deny_in matches) yields UNSATISFIED.
     * UNSATISFIED dominates the fold. */
    CHECK(v == PLAN_DEC_UNSATISFIED, "downstream deny dominates");
    CHECK(plan_dataflow_node_decision(df, 1) == PLAN_DEC_UNKNOWN,
          "log (unclassified, sticky) is UNKNOWN — fail-safe");
    CHECK(plan_dataflow_node_decision(df, 2) == PLAN_DEC_UNSATISFIED,
          "send_http denies SECRET");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

static void test_adapter_strict_rejects_unmatched(void)
{
    printf("test_adapter_strict_rejects_unmatched\n");

    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "frobnicate", PLAN_DEC_SATISFIED);

    plan_label_table_t tbl = { .rules = NULL, .n_rules = 0, .strict = true };
    plan_label_policy_t pol = { .classify = plan_label_policy_from_table,
                                .ctx = &tbl };
    plan_label_set_clear(&pol.sticky);
    plan_action_desc_t acts[1] = { { .name = "frobnicate" } };

    plan_dataflow_t *df = plan_dataflow_new(p);
    int rc = plan_dataflow_populate(df, acts, 1, &pol);
    CHECK(rc == -1, "strict + unmatched -> populate fails");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

static void test_adapter_length_mismatch(void)
{
    printf("test_adapter_length_mismatch\n");

    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "b", PLAN_DEC_SATISFIED);

    plan_label_table_t tbl = { .rules = NULL, .n_rules = 0, .strict = false };
    plan_label_policy_t pol = { .classify = plan_label_policy_from_table,
                                .ctx = &tbl };
    plan_label_set_clear(&pol.sticky);
    plan_action_desc_t acts[1] = { { .name = "a" } };

    plan_dataflow_t *df = plan_dataflow_new(p);
    int rc = plan_dataflow_populate(df, acts, 1, &pol);
    CHECK(rc == -1, "n_actions != plan node count -> populate fails");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* ---------- Pathology JSON ---------- */

static const char *label_namer(plan_label_t t, void *ctx)
{
    (void)ctx;
    switch (t) {
        case L_SECRET: return "SECRET";
        case L_PII:    return "PII";
        case L_PUBLIC: return "PUBLIC";
        case L_TRACE:  return "TRACE";
    }
    return NULL;
}

static bool contains(const char *json, ssize_t n, const char *needle)
{
    /* Substring check on a non-null-terminated json buffer. */
    size_t nlen = strlen(needle);
    if (n < 0 || (size_t)n < nlen) return false;
    for (size_t i = 0; i + nlen <= (size_t)n; i++)
        if (memcmp(json + i, needle, nlen) == 0) return true;
    return false;
}

static void test_pathology_canonical_exfil(void)
{
    printf("test_pathology_canonical_exfil\n");

    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "egress_send", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, 0, 1);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, 0, L_SECRET);
    plan_dataflow_add_deny_in(df, 1, L_SECRET);

    plan_pathology_opts_t opts = { .label_name = label_namer };
    char buf[4096];
    ssize_t n = plan_dataflow_emit_pathology_buf(df, &opts, buf, sizeof buf);

    CHECK(n > 0, "emitter returns positive byte count");
    CHECK(contains(buf, n, "\"verdict\":\"UNSATISFIED\""),
          "verdict UNSATISFIED");
    CHECK(contains(buf, n, "\"flow_axis\":\"UNSATISFIED\""),
          "flow_axis UNSATISFIED");
    CHECK(contains(buf, n, "\"node_axis\":\"SATISFIED\""),
          "node_axis SATISFIED");
    CHECK(contains(buf, n, "\"node_label\":\"egress_send\""),
          "names offending node");
    CHECK(contains(buf, n, "\"kind\":\"deny_in\""),
          "deny_in offense");
    CHECK(contains(buf, n, "\"SECRET\""),
          "names the offending label by human-readable name");
    CHECK(contains(buf, n, "\"from_label\":\"read_secret\""),
          "names the source edge endpoint");

    /* Determinism: re-emit and compare byte for byte. */
    char buf2[4096];
    ssize_t n2 = plan_dataflow_emit_pathology_buf(df, &opts, buf2, sizeof buf2);
    CHECK(n == n2 && memcmp(buf, buf2, (size_t)n) == 0,
          "emission is byte-for-byte deterministic");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

static void test_pathology_sticky_unclassified(void)
{
    printf("test_pathology_sticky_unclassified\n");

    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "read",    PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "unknown_sink", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, 0, 1);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, 0, L_SECRET);
    /* sink has no classification of SECRET */

    plan_pathology_opts_t opts = { .label_name = label_namer };
    char buf[4096];
    ssize_t n = plan_dataflow_emit_pathology_buf(df, &opts, buf, sizeof buf);

    CHECK(n > 0, "emitter returns positive byte count");
    CHECK(contains(buf, n, "\"flow_axis\":\"UNKNOWN\""),
          "flow_axis UNKNOWN");
    CHECK(contains(buf, n, "\"kind\":\"sticky_unclassified\""),
          "names sticky_unclassified offense");
    CHECK(contains(buf, n, "\"node_label\":\"unknown_sink\""),
          "names the unclassified sink");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

static void test_pathology_clean_plan(void)
{
    printf("test_pathology_clean_plan\n");

    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "b", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, 0, 1);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_pathology_opts_t opts = { .label_name = label_namer };
    char buf[1024];
    ssize_t n = plan_dataflow_emit_pathology_buf(df, &opts, buf, sizeof buf);

    CHECK(n > 0, "clean plan emits a record");
    CHECK(contains(buf, n, "\"verdict\":\"SATISFIED\""), "verdict SATISFIED");
    CHECK(contains(buf, n, "\"suppressions\":[]"), "suppressions array empty");
    /* Buffer must be a valid C string on success: NUL at [n], and the
     * reported length must equal strlen (no stray trailing bytes
     * inside the record). This guards the printf("%s", buf) usage. */
    CHECK(buf[n] == '\0', "buffer NUL-terminated at returned length");
    CHECK((size_t)n == strlen(buf), "returned length matches strlen (no stray bytes)");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

static void test_pathology_buffer_overflow(void)
{
    printf("test_pathology_buffer_overflow\n");

    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);

    plan_dataflow_t *df = plan_dataflow_new(p);
    char tiny[4];   /* not enough for any record */
    ssize_t n = plan_dataflow_emit_pathology_buf(df, NULL, tiny, sizeof tiny);
    CHECK(n == -1, "overflow signals -1 (no truncated JSON returned)");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

int main(void)
{
    test_sticky_unclassified_is_unknown();
    test_sticky_permit_in_authorizes();
    test_sticky_deny_dominates();
    test_free_label_default_satisfied();
    test_sticky_marked_after_origins();

    test_adapter_populates_from_table();
    test_adapter_strict_rejects_unmatched();
    test_adapter_length_mismatch();

    test_pathology_canonical_exfil();
    test_pathology_sticky_unclassified();
    test_pathology_clean_plan();
    test_pathology_buffer_overflow();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
