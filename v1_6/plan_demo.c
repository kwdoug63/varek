// SPDX-License-Identifier: MIT
/*
 * plan_demo.c — minimal exerciser for the v1.6 ExecutionPlan API.
 *
 * Builds two small plans:
 *   1. A clean fetch -> transform -> write diamond. All nodes
 *      SATISFIED. Plan authorizes.
 *   2. The same shape with one poisoned node. Plan is UNSATISFIED.
 */

#include "execution_plan.h"

#include <stdio.h>

int main(void)
{
    /* ---- clean plan ---- */
    exec_plan_t *p = exec_plan_new();
    if (!p) { fprintf(stderr, "alloc failed\n"); return 1; }

    plan_node_id_t fetch     = exec_plan_add_node(p, "fetch_data",     PLAN_DEC_SATISFIED);
    plan_node_id_t transform = exec_plan_add_node(p, "transform_data", PLAN_DEC_SATISFIED);
    plan_node_id_t write_out = exec_plan_add_node(p, "write_output",   PLAN_DEC_SATISFIED);

    exec_plan_add_edge(p, fetch,     transform);
    exec_plan_add_edge(p, transform, write_out);
    exec_plan_add_edge(p, fetch,     write_out);   /* audit edge */

    plan_decision_t d = exec_plan_verify(p);
    printf("clean_plan: decision=%s authorized=%s nodes=%zu edges=%zu\n",
           plan_decision_name(d),
           exec_plan_authorized(p) ? "true" : "false",
           exec_plan_node_count(p),
           exec_plan_edge_count(p));
    exec_plan_free(p);

    /* ---- poisoned plan ---- */
    exec_plan_t *q = exec_plan_new();
    if (!q) { fprintf(stderr, "alloc failed\n"); return 1; }

    exec_plan_add_node(q, "ok_a",     PLAN_DEC_SATISFIED);
    exec_plan_add_node(q, "ok_b",     PLAN_DEC_SATISFIED);
    exec_plan_add_node(q, "bad_node", PLAN_DEC_UNSATISFIED);
    exec_plan_add_node(q, "ok_c",     PLAN_DEC_SATISFIED);

    plan_decision_t dq = exec_plan_verify(q);
    printf("poisoned_plan: decision=%s authorized=%s\n",
           plan_decision_name(dq),
           exec_plan_authorized(q) ? "true" : "false");
    exec_plan_free(q);

    return 0;
}
