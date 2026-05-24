// SPDX-License-Identifier: MIT
/*
 * tests/test_symmetric_suppression.c
 *
 * The core patent invariant: UNSATISFIED and UNKNOWN both suppress
 * execution. The per-action property lifts compositionally to the
 * plan level. The join preserves the more informative of the two
 * for pathology output (UNSATISFIED dominates UNKNOWN), but both
 * block authorization equally.
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

static int test_single_unsat_suppresses(void)
{
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "ok_a", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "ok_b", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "bad",  PLAN_DEC_UNSATISFIED);
    exec_plan_add_node(p, "ok_c", PLAN_DEC_SATISFIED);
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNSATISFIED);
    if (exec_plan_authorized(p)) {
        fprintf(stderr, "FAIL: UNSAT plan must not be authorized\n");
        exec_plan_free(p);
        return 1;
    }
    exec_plan_free(p);
    return 0;
}

static int test_single_unknown_suppresses(void)
{
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "ok_a", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "ok_b", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "huh",  PLAN_DEC_UNKNOWN);
    exec_plan_add_node(p, "ok_c", PLAN_DEC_SATISFIED);
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNKNOWN);
    if (exec_plan_authorized(p)) {
        fprintf(stderr, "FAIL: UNKNOWN plan must not be authorized\n");
        exec_plan_free(p);
        return 1;
    }
    exec_plan_free(p);
    return 0;
}

/* Mixed UNSAT + UNKNOWN: the join must surface UNSAT (strongest
 * negative signal) while still suppressing the plan. */
static int test_unsat_dominates_unknown(void)
{
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "ok",  PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "huh", PLAN_DEC_UNKNOWN);
    exec_plan_add_node(p, "bad", PLAN_DEC_UNSATISFIED);
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNSATISFIED);
    exec_plan_free(p);
    return 0;
}

static int test_all_unknown_is_unknown(void)
{
    exec_plan_t *p = exec_plan_new();
    for (int i = 0; i < 8; i++) {
        exec_plan_add_node(p, "huh", PLAN_DEC_UNKNOWN);
    }
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNKNOWN);
    exec_plan_free(p);
    return 0;
}

static int test_all_unsat_is_unsat(void)
{
    exec_plan_t *p = exec_plan_new();
    for (int i = 0; i < 8; i++) {
        exec_plan_add_node(p, "bad", PLAN_DEC_UNSATISFIED);
    }
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNSATISFIED);
    exec_plan_free(p);
    return 0;
}

int main(void)
{
    int fails = 0;
    fails += test_single_unsat_suppresses();
    fails += test_single_unknown_suppresses();
    fails += test_unsat_dominates_unknown();
    fails += test_all_unknown_is_unknown();
    fails += test_all_unsat_is_unsat();
    printf("test_symmetric_suppression: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
