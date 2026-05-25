// SPDX-License-Identifier: MIT
/*
 * tests/test_pathology.c — validate the plan-level pathology JSON
 * output produced by the v1.6.1 sink and adapter.
 *
 * Strategy: open an in-memory FILE* via fmemopen(), point the sink
 * at it, run the adapter under various conditions, then assert on
 * the captured bytes. We do substring assertions rather than pull
 * in a JSON parser; the format is single-line and stable.
 */

#define _POSIX_C_SOURCE 200809L

#include "../pathology.h"
#include "../plan_spec.h"
#include "../warden_adapter.h"

#include <stdio.h>
#include <string.h>

#define EXPECT_CONTAINS(buf, needle) do {                             \
    if (strstr((buf), (needle)) == NULL) {                            \
        fprintf(stderr, "FAIL %s:%d: missing substring '%s' in:\n%s", \
                __FILE__, __LINE__, (needle), (buf));                 \
        return 1;                                                     \
    }                                                                 \
} while (0)

#define EXPECT_NOT_CONTAINS(buf, needle) do {                         \
    if (strstr((buf), (needle)) != NULL) {                            \
        fprintf(stderr, "FAIL %s:%d: unexpected substring '%s' in:\n%s",\
                __FILE__, __LINE__, (needle), (buf));                 \
        return 1;                                                     \
    }                                                                 \
} while (0)

static plan_decision_t all_sat(const plan_spec_action_t *a, void *ud)
{
    (void)a; (void)ud;
    return PLAN_DEC_SATISFIED;
}

static plan_decision_t deny_net(const plan_spec_action_t *a, void *ud)
{
    (void)ud;
    if (a->kind && strcmp(a->kind, "net_connect") == 0) {
        return PLAN_DEC_UNSATISFIED;
    }
    return PLAN_DEC_SATISFIED;
}

static plan_decision_t unknown_one(const plan_spec_action_t *a, void *ud)
{
    (void)ud;
    if (a->label && strcmp(a->label, "post") == 0) {
        return PLAN_DEC_UNKNOWN;
    }
    return PLAN_DEC_SATISFIED;
}

static plan_spec_action_t k_actions[] = {
    { "file_open",   "/in",  NULL, "load" },
    { "process_exec","/bin", NULL, "exec" },
    { "net_connect", "h:80", NULL, "post" },
};
static plan_spec_edge_t k_edges[] = { { 0, 1 }, { 1, 2 } };
static const plan_spec_t k_spec = {
    .actions = k_actions, .n_actions = 3,
    .edges   = k_edges,   .n_edges   = 2,
};

static int test_satisfied_record(void)
{
    char buf[2048] = {0};
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    pathology_sink_t *sink = pathology_sink_new(fp);

    plan_decision_t d = warden_adapter_verify(&k_spec, all_sat, NULL, sink);
    fflush(fp);
    fclose(fp);

    if (d != PLAN_DEC_SATISFIED) {
        fprintf(stderr, "FAIL: expected SATISFIED, got %s\n",
                plan_decision_name(d));
        pathology_sink_free(sink);
        return 1;
    }
    EXPECT_CONTAINS(buf, "\"decision\":\"SATISFIED\"");
    EXPECT_CONTAINS(buf, "\"authorized\":true");
    EXPECT_CONTAINS(buf, "\"n_nodes\":3");
    EXPECT_CONTAINS(buf, "\"n_edges\":2");
    EXPECT_CONTAINS(buf, "\"suppression_reason\":\"none\"");
    EXPECT_CONTAINS(buf, "\"suppressed_node\":null");
    EXPECT_CONTAINS(buf, "\"suppressed_decision\":\"SATISFIED\"");
    EXPECT_CONTAINS(buf, "\"report_id\":\"pp-");

    pathology_sink_free(sink);
    return 0;
}

static int test_unsat_node_record(void)
{
    char buf[2048] = {0};
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    pathology_sink_t *sink = pathology_sink_new(fp);

    plan_decision_t d = warden_adapter_verify(&k_spec, deny_net, NULL, sink);
    fflush(fp);
    fclose(fp);

    if (d != PLAN_DEC_UNSATISFIED) {
        fprintf(stderr, "FAIL: expected UNSATISFIED, got %s\n",
                plan_decision_name(d));
        pathology_sink_free(sink);
        return 1;
    }
    EXPECT_CONTAINS(buf, "\"decision\":\"UNSATISFIED\"");
    EXPECT_CONTAINS(buf, "\"authorized\":false");
    EXPECT_CONTAINS(buf, "\"suppression_reason\":\"node\"");
    EXPECT_CONTAINS(buf, "\"suppressed_node\":\"post\"");
    EXPECT_CONTAINS(buf, "\"suppressed_decision\":\"UNSATISFIED\"");

    pathology_sink_free(sink);
    return 0;
}

static int test_unknown_node_record(void)
{
    char buf[2048] = {0};
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    pathology_sink_t *sink = pathology_sink_new(fp);

    plan_decision_t d = warden_adapter_verify(&k_spec, unknown_one, NULL, sink);
    fflush(fp);
    fclose(fp);

    if (d != PLAN_DEC_UNKNOWN) {
        fprintf(stderr, "FAIL: expected UNKNOWN, got %s\n",
                plan_decision_name(d));
        pathology_sink_free(sink);
        return 1;
    }
    EXPECT_CONTAINS(buf, "\"decision\":\"UNKNOWN\"");
    EXPECT_CONTAINS(buf, "\"authorized\":false");
    EXPECT_CONTAINS(buf, "\"suppression_reason\":\"node\"");
    EXPECT_CONTAINS(buf, "\"suppressed_node\":\"post\"");
    EXPECT_CONTAINS(buf, "\"suppressed_decision\":\"UNKNOWN\"");

    pathology_sink_free(sink);
    return 0;
}

static int test_empty_spec_record(void)
{
    char buf[2048] = {0};
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    pathology_sink_t *sink = pathology_sink_new(fp);

    plan_spec_t empty = { NULL, 0, NULL, 0 };
    plan_decision_t d = warden_adapter_verify(&empty, all_sat, NULL, sink);
    fflush(fp);
    fclose(fp);

    if (d != PLAN_DEC_UNKNOWN) {
        fprintf(stderr, "FAIL: expected UNKNOWN, got %s\n",
                plan_decision_name(d));
        pathology_sink_free(sink);
        return 1;
    }
    EXPECT_CONTAINS(buf, "\"decision\":\"UNKNOWN\"");
    EXPECT_CONTAINS(buf, "\"suppression_reason\":\"empty\"");
    EXPECT_CONTAINS(buf, "\"n_nodes\":0");

    pathology_sink_free(sink);
    return 0;
}

static int test_invalid_edge_record(void)
{
    char buf[2048] = {0};
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    pathology_sink_t *sink = pathology_sink_new(fp);

    plan_spec_edge_t bad[] = { { 0, 99 } };
    plan_spec_t spec = {
        .actions = k_actions, .n_actions = 3,
        .edges   = bad,       .n_edges   = 1,
    };
    plan_decision_t d = warden_adapter_verify(&spec, all_sat, NULL, sink);
    fflush(fp);
    fclose(fp);

    if (d != PLAN_DEC_UNKNOWN) {
        fprintf(stderr, "FAIL: expected UNKNOWN, got %s\n",
                plan_decision_name(d));
        pathology_sink_free(sink);
        return 1;
    }
    EXPECT_CONTAINS(buf, "\"suppression_reason\":\"edge_index\"");

    pathology_sink_free(sink);
    return 0;
}

static int test_cycle_record(void)
{
    /* Spec with a 3-cycle. The adapter accepts the spec edges (all
     * indices are valid); exec_plan_verify detects the cycle and
     * returns UNKNOWN. No node was non-SAT, so suppression_reason
     * must be 'cycle'. */
    char buf[2048] = {0};
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    pathology_sink_t *sink = pathology_sink_new(fp);

    plan_spec_action_t cyc_actions[] = {
        { "k", "t", NULL, "a" },
        { "k", "t", NULL, "b" },
        { "k", "t", NULL, "c" },
    };
    plan_spec_edge_t cyc_edges[] = { { 0, 1 }, { 1, 2 }, { 2, 0 } };
    plan_spec_t cyc = {
        .actions = cyc_actions, .n_actions = 3,
        .edges   = cyc_edges,   .n_edges   = 3,
    };

    plan_decision_t d = warden_adapter_verify(&cyc, all_sat, NULL, sink);
    fflush(fp);
    fclose(fp);

    if (d != PLAN_DEC_UNKNOWN) {
        fprintf(stderr, "FAIL: expected UNKNOWN, got %s\n",
                plan_decision_name(d));
        pathology_sink_free(sink);
        return 1;
    }
    EXPECT_CONTAINS(buf, "\"suppression_reason\":\"cycle\"");
    EXPECT_CONTAINS(buf, "\"suppressed_node\":null");

    pathology_sink_free(sink);
    return 0;
}

/* Forced-UNSAT decider for the escaping test. Forward-declared so the
 * test can reference it before the definition below. */
static plan_decision_t force_unsat(const plan_spec_action_t *a, void *ud);

static int test_label_json_escaping(void)
{
    /* Label contains a double quote and a backslash. Both must be
     * escaped in the JSON output, and the resulting JSON must
     * remain syntactically valid (no stray unescaped characters). */
    char buf[2048] = {0};
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    pathology_sink_t *sink = pathology_sink_new(fp);

    plan_spec_action_t actions[] = {
        { "k", "t", NULL, "name with \"quote\" and \\slash" },
    };
    plan_spec_t spec = { actions, 1, NULL, 0 };

    /* Force suppression so the label surfaces in the record. */
    plan_decision_t d = warden_adapter_verify(&spec, force_unsat, NULL, sink);
    (void)d;
    fflush(fp);
    fclose(fp);

    /* The JSON output must contain the escaped sequences. */
    EXPECT_CONTAINS(buf, "\\\"quote\\\"");
    EXPECT_CONTAINS(buf, "\\\\slash");

    pathology_sink_free(sink);
    return 0;
}

static plan_decision_t force_unsat(const plan_spec_action_t *a, void *ud)
{
    (void)a; (void)ud;
    return PLAN_DEC_UNSATISFIED;
}

static int test_sink_emits_one_record_per_call(void)
{
    char buf[4096] = {0};
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    pathology_sink_t *sink = pathology_sink_new(fp);

    warden_adapter_verify(&k_spec, all_sat, NULL, sink);
    warden_adapter_verify(&k_spec, deny_net, NULL, sink);
    fflush(fp);
    fclose(fp);

    /* Two newline-terminated records expected. */
    size_t newlines = 0;
    for (const char *p = buf; *p; p++) if (*p == '\n') newlines++;
    if (newlines != 2) {
        fprintf(stderr, "FAIL: expected 2 records, found %zu newlines\nbuffer:\n%s",
                newlines, buf);
        pathology_sink_free(sink);
        return 1;
    }
    /* First record SATISFIED, second UNSATISFIED. */
    EXPECT_CONTAINS(buf, "\"decision\":\"SATISFIED\"");
    EXPECT_CONTAINS(buf, "\"decision\":\"UNSATISFIED\"");
    /* Sequence numbers in report_ids must differ. */
    EXPECT_CONTAINS(buf, "-0\"");
    EXPECT_CONTAINS(buf, "-1\"");
    EXPECT_NOT_CONTAINS(buf, "-2\"");

    pathology_sink_free(sink);
    return 0;
}

int main(void)
{
    int fails = 0;
    fails += test_satisfied_record();
    fails += test_unsat_node_record();
    fails += test_unknown_node_record();
    fails += test_empty_spec_record();
    fails += test_invalid_edge_record();
    fails += test_cycle_record();
    fails += test_label_json_escaping();
    fails += test_sink_emits_one_record_per_call();
    printf("test_pathology: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
