// SPDX-License-Identifier: MIT
/*
 * execution_plan.c — ExecutionPlan construction and storage.
 *
 * All verification logic lives in plan_evaluator.c. This file is
 * concerned only with allocation, node/edge append, and accessors.
 */

#include "execution_plan.h"
#include "execution_plan_internal.h"

#include <stdlib.h>

const char *plan_decision_name(plan_decision_t d)
{
    switch (d) {
        case PLAN_DEC_SATISFIED:   return "SATISFIED";
        case PLAN_DEC_UNSATISFIED: return "UNSATISFIED";
        case PLAN_DEC_UNKNOWN:     return "UNKNOWN";
    }
    return "INVALID";
}

exec_plan_t *exec_plan_new(void)
{
    /* calloc zeroes node/edge counts and clears storage. */
    return calloc(1, sizeof(struct exec_plan));
}

void exec_plan_free(exec_plan_t *plan)
{
    free(plan);
}

plan_node_id_t exec_plan_add_node(exec_plan_t *plan,
                                  const char *label,
                                  plan_decision_t decision)
{
    if (!plan)                              return PLAN_NODE_ID_INVALID;
    if (plan->n_nodes >= PLAN_MAX_NODES)    return PLAN_NODE_ID_INVALID;
    if (decision != PLAN_DEC_SATISFIED &&
        decision != PLAN_DEC_UNSATISFIED &&
        decision != PLAN_DEC_UNKNOWN) {
        return PLAN_NODE_ID_INVALID;
    }

    plan_node_id_t id = (plan_node_id_t)plan->n_nodes;
    plan->nodes[plan->n_nodes].id       = id;
    plan->nodes[plan->n_nodes].label    = label;
    plan->nodes[plan->n_nodes].decision = decision;
    plan->n_nodes++;
    return id;
}

int exec_plan_add_edge(exec_plan_t *plan,
                       plan_node_id_t from,
                       plan_node_id_t to)
{
    if (!plan)                              return -1;
    if (plan->n_edges >= PLAN_MAX_EDGES)    return -1;
    if (from >= plan->n_nodes)              return -1;
    if (to   >= plan->n_nodes)              return -1;
    if (from == to)                         return -1;   /* self-edge */

    plan->edges[plan->n_edges].from = from;
    plan->edges[plan->n_edges].to   = to;
    plan->n_edges++;
    return 0;
}

size_t exec_plan_node_count(const exec_plan_t *plan)
{
    return plan ? plan->n_nodes : 0;
}

size_t exec_plan_edge_count(const exec_plan_t *plan)
{
    return plan ? plan->n_edges : 0;
}
