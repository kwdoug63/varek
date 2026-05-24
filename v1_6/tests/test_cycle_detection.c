// SPDX-License-Identifier: MIT
/*
 * tests/test_cycle_detection.c
 *
 * Structural verification of the plan graph. A cyclic edge set is
 * structurally unverifiable; verify() returns UNKNOWN, which the
 * caller suppresses. Self-edges are rejected at insertion; longer
 * cycles are caught by the DFS in plan_evaluator.c.
 */

#include "../execution_plan.h"

#include <stdio.h>

#define EXPECT_EQ(actual, expected) do {                              \
    plan_decision_t _a = (actual);                                    \
    plan_decision_t _e = (expected);                                  \
    if (_a != _e) {                                                   \
        fprintf(stderr, "FAIL %s:%d: expected %s, got %s\n",          \
                __FILE__, __LINE__,                                   \
                plan_decision_name(_e), plan_decision_name(_a));      \
        return 1;                                                     \
    }                                                                 \
} while (0)

static int test_two_cycle(void)
{
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "b", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);
    exec_plan_add_edge(p, b, a);
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNKNOWN);
    exec_plan_free(p);
    return 0;
}

static int test_three_cycle(void)
{
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "b", PLAN_DEC_SATISFIED);
    plan_node_id_t c = exec_plan_add_node(p, "c", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);
    exec_plan_add_edge(p, b, c);
    exec_plan_add_edge(p, c, a);
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNKNOWN);
    exec_plan_free(p);
    return 0;
}

static int test_self_edge_rejected_at_insertion(void)
{
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    int rc = exec_plan_add_edge(p, a, a);
    if (rc == 0) {
        fprintf(stderr, "FAIL: self-edge should be rejected\n");
        exec_plan_free(p);
        return 1;
    }
    /* Plan still verifies as a single SATISFIED node. */
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_SATISFIED);
    exec_plan_free(p);
    return 0;
}

static int test_diamond_is_acyclic(void)
{
    /* a -> {b, c}; {b, c} -> d. No cycle. */
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "b", PLAN_DEC_SATISFIED);
    plan_node_id_t c = exec_plan_add_node(p, "c", PLAN_DEC_SATISFIED);
    plan_node_id_t d = exec_plan_add_node(p, "d", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);
    exec_plan_add_edge(p, a, c);
    exec_plan_add_edge(p, b, d);
    exec_plan_add_edge(p, c, d);
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_SATISFIED);
    exec_plan_free(p);
    return 0;
}

static int test_cycle_in_otherwise_unsat_plan_is_unknown(void)
{
    /* Cycle takes precedence over node decisions because the plan
     * is structurally unverifiable — the verifier could not form
     * a meaningful opinion about the action set. */
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "a", PLAN_DEC_UNSATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "b", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);
    exec_plan_add_edge(p, b, a);
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNKNOWN);
    exec_plan_free(p);
    return 0;
}

static int test_disjoint_components_one_cyclic(void)
{
    /* Two disjoint components: one acyclic, one cyclic. The whole
     * plan is unverifiable. */
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "b", PLAN_DEC_SATISFIED);
    plan_node_id_t c = exec_plan_add_node(p, "c", PLAN_DEC_SATISFIED);
    plan_node_id_t d = exec_plan_add_node(p, "d", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);     /* acyclic component */
    exec_plan_add_edge(p, c, d);     /* cyclic component */
    exec_plan_add_edge(p, d, c);
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNKNOWN);
    exec_plan_free(p);
    return 0;
}

int main(void)
{
    int fails = 0;
    fails += test_two_cycle();
    fails += test_three_cycle();
    fails += test_self_edge_rejected_at_insertion();
    fails += test_diamond_is_acyclic();
    fails += test_cycle_in_otherwise_unsat_plan_is_unknown();
    fails += test_disjoint_components_one_cyclic();
    printf("test_cycle_detection: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
