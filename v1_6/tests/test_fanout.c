// SPDX-License-Identifier: MIT
/*
 * tests/test_fanout.c
 *
 * Compositional analog of the per-action symmetric-suppression
 * invariant under graph composition: a single UNSAT leaf poisons
 * a wide fanout regardless of its position. The complement holds:
 * a clean fanout authorizes.
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

/* Build root -> { leaf_0, ..., leaf_{fanout-1} } with leaf bad_idx
 * marked UNSAT and the rest SATISFIED. */
static plan_decision_t fanout_with_bad(size_t fanout, size_t bad_idx)
{
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t root = exec_plan_add_node(p, "root", PLAN_DEC_SATISFIED);
    for (size_t i = 0; i < fanout; i++) {
        plan_decision_t d = (i == bad_idx) ? PLAN_DEC_UNSATISFIED
                                           : PLAN_DEC_SATISFIED;
        plan_node_id_t leaf = exec_plan_add_node(p, "leaf", d);
        exec_plan_add_edge(p, root, leaf);
    }
    plan_decision_t r = exec_plan_verify(p);
    exec_plan_free(p);
    return r;
}

static int test_fanout_poisoned_at_every_position(void)
{
    const size_t fanout = 64;
    for (size_t i = 0; i < fanout; i++) {
        EXPECT_EQ(fanout_with_bad(fanout, i), PLAN_DEC_UNSATISFIED);
    }
    return 0;
}

static int test_clean_fanout_is_satisfied(void)
{
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t root = exec_plan_add_node(p, "root", PLAN_DEC_SATISFIED);
    for (size_t i = 0; i < 64; i++) {
        plan_node_id_t leaf = exec_plan_add_node(p, "leaf", PLAN_DEC_SATISFIED);
        exec_plan_add_edge(p, root, leaf);
    }
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_SATISFIED);
    exec_plan_free(p);
    return 0;
}

static int test_unknown_leaf_poisons_fanout(void)
{
    /* Same shape, one UNKNOWN leaf, no UNSAT. Must yield UNKNOWN. */
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t root = exec_plan_add_node(p, "root", PLAN_DEC_SATISFIED);
    for (size_t i = 0; i < 32; i++) {
        plan_decision_t d = (i == 17) ? PLAN_DEC_UNKNOWN : PLAN_DEC_SATISFIED;
        plan_node_id_t leaf = exec_plan_add_node(p, "leaf", d);
        exec_plan_add_edge(p, root, leaf);
    }
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNKNOWN);
    exec_plan_free(p);
    return 0;
}

int main(void)
{
    int fails = 0;
    fails += test_fanout_poisoned_at_every_position();
    fails += test_clean_fanout_is_satisfied();
    fails += test_unknown_leaf_poisons_fanout();
    printf("test_fanout: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
