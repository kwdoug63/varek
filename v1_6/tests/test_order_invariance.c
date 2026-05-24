// SPDX-License-Identifier: MIT
/*
 * tests/test_order_invariance.c
 *
 * The compositional aggregator is associative, commutative, and
 * idempotent, so permuting node-insertion order must not change
 * the plan decision. Verified exhaustively (Heap's algorithm) over
 * small mixed-decision sets; the algebraic property generalizes
 * the guarantee beyond the tested sizes.
 */

#include "../execution_plan.h"

#include <stdio.h>

static plan_decision_t verify_perm(const plan_decision_t *d, size_t n)
{
    exec_plan_t *p = exec_plan_new();
    for (size_t i = 0; i < n; i++) {
        exec_plan_add_node(p, NULL, d[i]);
    }
    plan_decision_t r = exec_plan_verify(p);
    exec_plan_free(p);
    return r;
}

static int permute_check(plan_decision_t *d, size_t n, size_t k,
                         plan_decision_t expected, size_t *count)
{
    if (k == 1) {
        (*count)++;
        plan_decision_t got = verify_perm(d, n);
        if (got != expected) {
            fprintf(stderr,
                    "FAIL: permutation #%zu yielded %s, expected %s\n",
                    *count, plan_decision_name(got),
                    plan_decision_name(expected));
            return 1;
        }
        return 0;
    }
    for (size_t i = 0; i < k; i++) {
        int rc = permute_check(d, n, k - 1, expected, count);
        if (rc != 0) return rc;
        size_t swap_with = (k % 2 == 0) ? i : 0;
        plan_decision_t t = d[swap_with];
        d[swap_with]      = d[k - 1];
        d[k - 1]          = t;
    }
    return 0;
}

static int test_perm_unsat_expected(void)
{
    /* 5! = 120 permutations. Any ordering containing one UNSAT must
     * yield UNSAT regardless of where UNKNOWN sits. */
    plan_decision_t d[] = {
        PLAN_DEC_SATISFIED, PLAN_DEC_SATISFIED,
        PLAN_DEC_UNKNOWN,   PLAN_DEC_UNSATISFIED,
        PLAN_DEC_SATISFIED,
    };
    size_t n = sizeof(d) / sizeof(d[0]);
    size_t count = 0;
    return permute_check(d, n, n, PLAN_DEC_UNSATISFIED, &count);
}

static int test_perm_unknown_expected(void)
{
    /* 5! = 120 permutations. Exactly one UNKNOWN, no UNSAT, must
     * yield UNKNOWN at every position. */
    plan_decision_t d[] = {
        PLAN_DEC_SATISFIED, PLAN_DEC_UNKNOWN,
        PLAN_DEC_SATISFIED, PLAN_DEC_SATISFIED,
        PLAN_DEC_SATISFIED,
    };
    size_t n = sizeof(d) / sizeof(d[0]);
    size_t count = 0;
    return permute_check(d, n, n, PLAN_DEC_UNKNOWN, &count);
}

static int test_perm_sat_expected(void)
{
    /* 6! = 720 permutations. All-SAT must remain SAT under any
     * order. Idempotence of the join makes duplicates irrelevant. */
    plan_decision_t d[] = {
        PLAN_DEC_SATISFIED, PLAN_DEC_SATISFIED,
        PLAN_DEC_SATISFIED, PLAN_DEC_SATISFIED,
        PLAN_DEC_SATISFIED, PLAN_DEC_SATISFIED,
    };
    size_t n = sizeof(d) / sizeof(d[0]);
    size_t count = 0;
    return permute_check(d, n, n, PLAN_DEC_SATISFIED, &count);
}

int main(void)
{
    int fails = 0;
    fails += test_perm_unsat_expected();
    fails += test_perm_unknown_expected();
    fails += test_perm_sat_expected();
    printf("test_order_invariance: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
