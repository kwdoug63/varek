// SPDX-License-Identifier: MIT
/*
 * execution_plan_internal.h — layout shared between execution_plan.c
 * and plan_evaluator.c. Not part of the public API; do not include
 * outside this directory.
 */

#ifndef VAREK_V1_6_EXECUTION_PLAN_INTERNAL_H
#define VAREK_V1_6_EXECUTION_PLAN_INTERNAL_H

#include "execution_plan.h"

struct exec_plan {
    plan_node_t nodes[PLAN_MAX_NODES];
    plan_edge_t edges[PLAN_MAX_EDGES];
    size_t      n_nodes;
    size_t      n_edges;
};

#endif /* VAREK_V1_6_EXECUTION_PLAN_INTERNAL_H */
