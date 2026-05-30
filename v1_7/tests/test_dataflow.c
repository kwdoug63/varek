// SPDX-License-Identifier: MIT
/*
 * test_dataflow.c — VAREK v1.7.0 data-flow kernel invariant tests.
 *
 * Covers the canonical compositional-leak case, fanout poisoning,
 * suppression precedence (deny over unknown), cycle handling, the
 * inbound-only policing semantics, two-axis join with the v1.6 node
 * axis, and determinism. Build clean under -fsanitize=address,undefined.
 */

#include "execution_plan.h"
#include "plan_dataflow.h"
#include "plan_label.h"

#include <stdio.h>
#include <stdlib.h>

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

/* Two example labels for the tests. */
enum { L_SECRET = 0, L_PII = 1, L_UNRESOLVED = 2 };

/* Canonical case: read-secret -> transform -> egress, every node's
 * v1.6 decision SATISFIED. Without flow policy the plan authorizes;
 * with SECRET originated at the reader and denied at the egress the
 * plan is refused on the path between them. */
static void test_canonical_exfil(void)
{
    printf("test_canonical_exfil\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t rd = exec_plan_add_node(p, "read_secret",  PLAN_DEC_SATISFIED);
    plan_node_id_t tf = exec_plan_add_node(p, "transform",    PLAN_DEC_SATISFIED);
    plan_node_id_t eg = exec_plan_add_node(p, "egress_send",  PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, rd, tf);
    exec_plan_add_edge(p, tf, eg);

    /* No labels yet: node axis SATISFIED, flow axis SATISFIED. */
    plan_dataflow_t *df = plan_dataflow_new(p);
    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_SATISFIED,
          "no-label flow axis is SATISFIED");
    CHECK(exec_plan_authorized_with_dataflow(p, df),
          "clean plan authorizes");

    /* SECRET originates at the reader, denied at the egress. */
    CHECK(plan_dataflow_add_origin(df, rd, L_SECRET) == 0, "origin add ok");
    CHECK(plan_dataflow_add_deny_in(df, eg, L_SECRET) == 0, "deny-in add ok");

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNSATISFIED,
          "secret reaching egress is UNSATISFIED on flow axis");
    CHECK(exec_plan_verify_with_dataflow(p, df) == PLAN_DEC_UNSATISFIED,
          "joined verdict UNSATISFIED");
    CHECK(!exec_plan_authorized_with_dataflow(p, df),
          "leaking plan is refused");
    CHECK(plan_dataflow_node_decision(df, eg) == PLAN_DEC_UNSATISFIED,
          "egress node flagged UNSATISFIED");
    CHECK(plan_dataflow_node_decision(df, tf) == PLAN_DEC_SATISFIED,
          "transform node clean (deny only at egress)");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Inbound-only policing: a node that ORIGINATES a denied label but
 * does not RECEIVE it is not self-suppressed. The reader originates
 * SECRET and (perversely) also denies SECRET inbound — since SECRET
 * is not on its inbound set, the reader stays SATISFIED. */
static void test_inbound_only_semantics(void)
{
    printf("test_inbound_only_semantics\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t rd = exec_plan_add_node(p, "read", PLAN_DEC_SATISFIED);
    plan_node_id_t sink = exec_plan_add_node(p, "sink", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, rd, sink);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_add_origin(df, rd, L_SECRET);
    plan_dataflow_add_deny_in(df, rd, L_SECRET);   /* policing own origin */

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_SATISFIED,
          "originator not suppressed by its own label");
    CHECK(plan_dataflow_node_decision(df, rd) == PLAN_DEC_SATISFIED,
          "reader stays SATISFIED");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Fanout: one tainted source fans out to two sinks; one denies, one
 * does not. The denying sink poisons the whole plan; the other sink
 * stays clean. */
static void test_fanout_poisoning(void)
{
    printf("test_fanout_poisoning\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t src  = exec_plan_add_node(p, "src",  PLAN_DEC_SATISFIED);
    plan_node_id_t safe = exec_plan_add_node(p, "log",  PLAN_DEC_SATISFIED);
    plan_node_id_t bad  = exec_plan_add_node(p, "send", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, src, safe);
    exec_plan_add_edge(p, src, bad);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_add_origin(df, src, L_PII);
    plan_dataflow_add_deny_in(df, bad, L_PII);

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNSATISFIED,
          "one denying sink poisons the plan");
    CHECK(plan_dataflow_node_decision(df, safe) == PLAN_DEC_SATISFIED,
          "non-denying sink stays SATISFIED");
    CHECK(plan_dataflow_node_decision(df, bad) == PLAN_DEC_UNSATISFIED,
          "denying sink UNSATISFIED");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Suppression precedence: a node whose inbound set hits BOTH a
 * deny-in and an unknown-in label resolves to UNSATISFIED (deny
 * dominates unknown), matching the lattice. */
static void test_suppression_precedence(void)
{
    printf("test_suppression_precedence\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "b", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_add_origin(df, a, L_SECRET);
    plan_dataflow_add_origin(df, a, L_UNRESOLVED);
    plan_dataflow_add_deny_in(df, b, L_SECRET);
    plan_dataflow_add_unknown_in(df, b, L_UNRESOLVED);

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNSATISFIED,
          "deny dominates unknown at the same node");

    plan_dataflow_free(df);
    exec_plan_free(p);

    /* unknown-in alone yields UNKNOWN. */
    exec_plan_t *p2 = exec_plan_new();
    plan_node_id_t c = exec_plan_add_node(p2, "c", PLAN_DEC_SATISFIED);
    plan_node_id_t d = exec_plan_add_node(p2, "d", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p2, c, d);
    plan_dataflow_t *df2 = plan_dataflow_new(p2);
    plan_dataflow_add_origin(df2, c, L_UNRESOLVED);
    plan_dataflow_add_unknown_in(df2, d, L_UNRESOLVED);
    CHECK(plan_dataflow_flow_verdict(df2) == PLAN_DEC_UNKNOWN,
          "unknown-in alone yields UNKNOWN (suppresses)");
    CHECK(!exec_plan_authorized_with_dataflow(p2, df2),
          "UNKNOWN flow suppresses authorization");
    plan_dataflow_free(df2);
    exec_plan_free(p2);
}

/* Cycle on the flow axis yields UNKNOWN (structurally unverifiable),
 * matching the v1.6 node axis treatment. add_edge rejects self-edges,
 * so build a 2-cycle. */
static void test_cycle_unknown(void)
{
    printf("test_cycle_unknown\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "b", PLAN_DEC_SATISFIED);
    CHECK(exec_plan_add_edge(p, a, b) == 0, "edge a->b ok");
    CHECK(exec_plan_add_edge(p, b, a) == 0, "edge b->a ok (cycle formed)");

    plan_dataflow_t *df = plan_dataflow_new(p);
    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNKNOWN,
          "cyclic plan is UNKNOWN on flow axis");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Two-axis join: a node-axis UNSATISFIED must suppress even when the
 * flow axis is clean, and vice versa. */
static void test_two_axis_join(void)
{
    printf("test_two_axis_join\n");

    /* node UNSAT, flow clean -> UNSAT */
    exec_plan_t *p = exec_plan_new();
    exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p, "b", PLAN_DEC_UNSATISFIED);
    exec_plan_add_edge(p, 0, 1);
    plan_dataflow_t *df = plan_dataflow_new(p);
    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_SATISFIED,
          "flow axis clean");
    CHECK(exec_plan_verify_with_dataflow(p, df) == PLAN_DEC_UNSATISFIED,
          "node-axis UNSAT suppresses despite clean flow");
    plan_dataflow_free(df);
    exec_plan_free(p);

    /* node clean, flow UNSAT -> UNSAT */
    exec_plan_t *p2 = exec_plan_new();
    exec_plan_add_node(p2, "a", PLAN_DEC_SATISFIED);
    exec_plan_add_node(p2, "b", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p2, 0, 1);
    plan_dataflow_t *df2 = plan_dataflow_new(p2);
    plan_dataflow_add_origin(df2, 0, L_SECRET);
    plan_dataflow_add_deny_in(df2, 1, L_SECRET);
    CHECK(exec_plan_verify(p2) == PLAN_DEC_SATISFIED, "node axis clean");
    CHECK(exec_plan_verify_with_dataflow(p2, df2) == PLAN_DEC_UNSATISFIED,
          "flow-axis UNSAT suppresses despite clean nodes");
    plan_dataflow_free(df2);
    exec_plan_free(p2);
}

/* Determinism / order invariance: the same plan and inputs yield the
 * same verdict and per-node decisions across repeated runs and across
 * a re-add that changes edge insertion order. */
static void test_determinism(void)
{
    printf("test_determinism\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t s = exec_plan_add_node(p, "s", PLAN_DEC_SATISFIED);
    plan_node_id_t m = exec_plan_add_node(p, "m", PLAN_DEC_SATISFIED);
    plan_node_id_t e = exec_plan_add_node(p, "e", PLAN_DEC_SATISFIED);
    /* insert edges in a non-source-first order */
    exec_plan_add_edge(p, m, e);
    exec_plan_add_edge(p, s, m);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_add_origin(df, s, L_SECRET);
    plan_dataflow_add_deny_in(df, e, L_SECRET);

    plan_decision_t v1 = plan_dataflow_flow_verdict(df);
    plan_decision_t v2 = plan_dataflow_flow_verdict(df); /* cached */
    CHECK(v1 == PLAN_DEC_UNSATISFIED, "edge-order independent: UNSAT");
    CHECK(v1 == v2, "verdict is stable across calls");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Empty plan: flow axis SATISFIED, joined verdict UNKNOWN (node axis). */
static void test_empty_plan(void)
{
    printf("test_empty_plan\n");
    exec_plan_t *p = exec_plan_new();
    plan_dataflow_t *df = plan_dataflow_new(p);
    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_SATISFIED,
          "empty plan: flow axis SATISFIED");
    CHECK(exec_plan_verify_with_dataflow(p, df) == PLAN_DEC_UNKNOWN,
          "empty plan: joined verdict UNKNOWN");
    plan_dataflow_free(df);
    exec_plan_free(p);
}

int main(void)
{
    test_canonical_exfil();
    test_inbound_only_semantics();
    test_fanout_poisoning();
    test_suppression_precedence();
    test_cycle_unknown();
    test_two_axis_join();
    test_determinism();
    test_empty_plan();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
