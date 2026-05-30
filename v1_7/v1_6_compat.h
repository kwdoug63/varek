// SPDX-License-Identifier: MIT
/*
 * v1_6_compat.h — v1.7 layer's read-only accessors over v1.6
 * exec_plan_t internals.
 *
 * v1.6's public API exposes counts but not per-edge endpoints or
 * per-node labels by index. The v1.7 propagation kernel and pathology
 * emitter need both for refusal evidence. Reading v1.6 internals
 * directly is the minimum-coupling option:
 *
 *   - v1.6 source files are unchanged; tagged v1.6.x releases stay
 *     byte-identical.
 *   - The coupling is one-way and read-only: v1.7 reads v1.6 state;
 *     v1.6 does not depend on v1.7.
 *   - v1.6's own plan_evaluator.c already shares
 *     execution_plan_internal.h within the v1.6 layer, so the
 *     internal layout is established repo precedent for cross-TU use.
 *
 * These helpers are intentionally not part of v1.7's public surface.
 * Include this header only from v1.7 implementation files (.c), never
 * from v1.7 public headers — the public surface must depend on v1.6's
 * public API only.
 */

#ifndef VAREK_V1_7_V1_6_COMPAT_H
#define VAREK_V1_7_V1_6_COMPAT_H

#include "execution_plan.h"
#include "execution_plan_internal.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Copy the endpoints of the i-th edge into *from and *to.
 * Returns 0 on success; -1 if plan is NULL, an endpoint pointer is
 * NULL, or i is out of range. The edge index is the insertion order
 * established by exec_plan_add_edge().
 */
static inline int dataflow_plan_get_edge(const exec_plan_t *plan,
                                         size_t i,
                                         plan_node_id_t *from,
                                         plan_node_id_t *to)
{
    if (!plan || !from || !to) return -1;
    if (i >= plan->n_edges) return -1;
    *from = plan->edges[i].from;
    *to   = plan->edges[i].to;
    return 0;
}

/*
 * Return the borrowed label for the given node id, or NULL if the id
 * is out of range or the node has no label. The returned pointer is
 * valid for the lifetime of the plan; callers must not free it.
 */
static inline const char *dataflow_plan_get_node_label(const exec_plan_t *plan,
                                                       plan_node_id_t id)
{
    if (!plan) return NULL;
    if ((size_t)id >= plan->n_nodes) return NULL;
    return plan->nodes[id].label;
}

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_7_V1_6_COMPAT_H */
