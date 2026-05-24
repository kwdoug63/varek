// SPDX-License-Identifier: MIT
/* tests/test_evaluator.c — baseline plan-verification behaviors. */

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

#define EXPECT_TRUE(cond) do {                                        \
    if (!(cond)) {                                                    \
        fprintf(stderr, "FAIL %s:%d: '%s' was false\n",               \
                __FILE__, __LINE__, #cond);                           \
        return 1;                                                     \
    }                                                                 \
} while (0)

static int test_empty_plan_is_unknown(void)
{
    exec_plan_t *p = exec_plan_new();
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_UNKNOWN);
    EXPECT_TRUE(!exec_plan_authorized(p));
    exec_plan_free(p);
    return 0;
}

static int test_single_satisfied_node(void)
{
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_SATISFIED);
    EXPECT_TRUE(exec_plan_authorized(p));
    exec_plan_free(p);
    return 0;
}

static int test_all_satisfied(void)
{
    exec_plan_t *p = exec_plan_new();
    for (int i = 0; i < 32; i++) {
        exec_plan_add_node(p, "ok", PLAN_DEC_SATISFIED);
    }
    EXPECT_EQ(exec_plan_verify(p), PLAN_DEC_SATISFIED);
    EXPECT_TRUE(exec_plan_authorized(p));
    exec_plan_free(p);
    return 0;
}

static int test_null_plan(void)
{
    EXPECT_EQ(exec_plan_verify(NULL), PLAN_DEC_UNKNOWN);
    EXPECT_TRUE(!exec_plan_authorized(NULL));
    return 0;
}

static int test_invalid_decision_rejected(void)
{
    exec_plan_t *p = exec_plan_new();
    /* 99 is not a valid plan_decision_t value. */
    plan_node_id_t id = exec_plan_add_node(p, "bogus", (plan_decision_t)99);
    EXPECT_TRUE(id == PLAN_NODE_ID_INVALID);
    EXPECT_TRUE(exec_plan_node_count(p) == 0);
    exec_plan_free(p);
    return 0;
}

int main(void)
{
    int fails = 0;
    fails += test_empty_plan_is_unknown();
    fails += test_single_satisfied_node();
    fails += test_all_satisfied();
    fails += test_null_plan();
    fails += test_invalid_decision_rejected();
    printf("test_evaluator: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
