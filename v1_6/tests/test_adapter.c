// SPDX-License-Identifier: MIT
/*
 * tests/test_adapter.c — Warden adapter behavior.
 *
 * Covers happy path (all SATISFIED), node-level suppression
 * (decider returns UNSAT / UNKNOWN), structural failures
 * (capacity overflow, invalid edge index, empty spec, NULL args),
 * and defensive coercion (decider returns invalid value).
 */

#include "../pathology.h"
#include "../plan_spec.h"
#include "../warden_adapter.h"

#include <stdio.h>
#include <string.h>

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

/* ---- deciders ---- */

static plan_decision_t all_sat(const plan_spec_action_t *a, void *ud)
{
    (void)a; (void)ud;
    return PLAN_DEC_SATISFIED;
}

static plan_decision_t all_unsat(const plan_spec_action_t *a, void *ud)
{
    (void)a; (void)ud;
    return PLAN_DEC_UNSATISFIED;
}

static plan_decision_t all_unknown(const plan_spec_action_t *a, void *ud)
{
    (void)a; (void)ud;
    return PLAN_DEC_UNKNOWN;
}

static plan_decision_t deny_net(const plan_spec_action_t *a, void *ud)
{
    (void)ud;
    if (a->kind && strcmp(a->kind, "net_connect") == 0) {
        return PLAN_DEC_UNSATISFIED;
    }
    return PLAN_DEC_SATISFIED;
}

static plan_decision_t bogus_decider(const plan_spec_action_t *a, void *ud)
{
    (void)a; (void)ud;
    /* Invalid value -- adapter must defensively coerce to UNKNOWN. */
    return (plan_decision_t)42;
}

/* ---- helpers ---- */

static plan_spec_action_t k_actions[] = {
    { "file_open",   "/in",  NULL, "load"   },
    { "process_exec","/bin", NULL, "exec"   },
    { "net_connect", "h:80", NULL, "post"   },
};
static plan_spec_edge_t k_edges[] = {
    { 0, 1 }, { 1, 2 },
};
static const plan_spec_t k_spec = {
    .actions   = k_actions,
    .n_actions = sizeof(k_actions) / sizeof(k_actions[0]),
    .edges     = k_edges,
    .n_edges   = sizeof(k_edges)   / sizeof(k_edges[0]),
};

/* ---- tests ---- */

static int test_happy_path(void)
{
    EXPECT_EQ(warden_adapter_verify(&k_spec, all_sat, NULL, NULL),
              PLAN_DEC_SATISFIED);
    return 0;
}

static int test_all_unsat_suppresses(void)
{
    EXPECT_EQ(warden_adapter_verify(&k_spec, all_unsat, NULL, NULL),
              PLAN_DEC_UNSATISFIED);
    return 0;
}

static int test_all_unknown_suppresses(void)
{
    EXPECT_EQ(warden_adapter_verify(&k_spec, all_unknown, NULL, NULL),
              PLAN_DEC_UNKNOWN);
    return 0;
}

static int test_targeted_denial(void)
{
    /* deny_net rejects the net_connect action; the plan must
     * suppress as UNSAT regardless of the other approvals. */
    EXPECT_EQ(warden_adapter_verify(&k_spec, deny_net, NULL, NULL),
              PLAN_DEC_UNSATISFIED);
    return 0;
}

static int test_null_spec(void)
{
    EXPECT_EQ(warden_adapter_verify(NULL, all_sat, NULL, NULL),
              PLAN_DEC_UNKNOWN);
    return 0;
}

static int test_null_decider(void)
{
    EXPECT_EQ(warden_adapter_verify(&k_spec, NULL, NULL, NULL),
              PLAN_DEC_UNKNOWN);
    return 0;
}

static int test_empty_spec(void)
{
    plan_spec_t empty = { .actions = NULL, .n_actions = 0,
                          .edges = NULL,   .n_edges   = 0 };
    EXPECT_EQ(warden_adapter_verify(&empty, all_sat, NULL, NULL),
              PLAN_DEC_UNKNOWN);
    return 0;
}

static int test_invalid_edge_index(void)
{
    plan_spec_edge_t bad_edges[] = { { 0, 99 } };  /* 99 does not exist */
    plan_spec_t bad = {
        .actions   = k_actions,
        .n_actions = 3,
        .edges     = bad_edges,
        .n_edges   = 1,
    };
    EXPECT_EQ(warden_adapter_verify(&bad, all_sat, NULL, NULL),
              PLAN_DEC_UNKNOWN);
    return 0;
}

static int test_capacity_overflow(void)
{
    plan_spec_t big = { .actions = k_actions,
                        .n_actions = (size_t)PLAN_MAX_NODES + 1,
                        .edges   = NULL,
                        .n_edges = 0 };
    EXPECT_EQ(warden_adapter_verify(&big, all_sat, NULL, NULL),
              PLAN_DEC_UNKNOWN);
    return 0;
}

static int test_bogus_decider_coerced_to_unknown(void)
{
    /* If the decider returns a value outside the tri-state, the
     * adapter must defensively coerce it to UNKNOWN rather than
     * trusting it. The plan therefore comes out UNKNOWN, not SAT. */
    EXPECT_EQ(warden_adapter_verify(&k_spec, bogus_decider, NULL, NULL),
              PLAN_DEC_UNKNOWN);
    return 0;
}

/* Decider that records a touch count via userdata, so we can verify
 * the adapter forwards userdata to the callback unchanged. */
struct counter_state { int touched; };

static plan_decision_t counter_decider(const plan_spec_action_t *a, void *ud)
{
    (void)a;
    struct counter_state *s = (struct counter_state *)ud;
    if (s) s->touched++;
    return PLAN_DEC_SATISFIED;
}

static int test_userdata_threaded_through(void)
{
    struct counter_state st = { .touched = 0 };
    plan_decision_t r = warden_adapter_verify(&k_spec, counter_decider, &st, NULL);
    EXPECT_EQ(r, PLAN_DEC_SATISFIED);
    if (st.touched != (int)k_spec.n_actions) {
        fprintf(stderr, "FAIL: expected %zu decider calls, got %d\n",
                k_spec.n_actions, st.touched);
        return 1;
    }
    return 0;
}

int main(void)
{
    int fails = 0;
    fails += test_happy_path();
    fails += test_all_unsat_suppresses();
    fails += test_all_unknown_suppresses();
    fails += test_targeted_denial();
    fails += test_null_spec();
    fails += test_null_decider();
    fails += test_empty_spec();
    fails += test_invalid_edge_index();
    fails += test_capacity_overflow();
    fails += test_bogus_decider_coerced_to_unknown();
    fails += test_userdata_threaded_through();
    printf("test_adapter: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
