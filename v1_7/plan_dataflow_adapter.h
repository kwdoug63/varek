// SPDX-License-Identifier: MIT
/*
 * plan_dataflow_adapter.h — VAREK v1.7.1 dataflow adapter.
 *
 * Wires a label policy (plan_label_policy_t) to a dataflow companion
 * (plan_dataflow_t): for each planned action, calls the policy
 * callback to obtain the action's label sets and writes them onto the
 * companion at the corresponding node id. Also applies the policy's
 * sticky set plan-wide.
 *
 * The action array is expected to be in plan node-id order — i.e.
 * actions[i] is the action that became node id i when the v1.6.1
 * adapter called exec_plan_add_node(). The number of actions must
 * match the plan's node count.
 *
 * Layered above the v1.6.1 adapter that calls policy_decide() for
 * the node-axis tri-state. The two layers run side by side on the
 * same action array; this adapter does not call policy_decide() and
 * does not touch the v1.6 node decisions.
 */

#ifndef VAREK_V1_7_PLAN_DATAFLOW_ADAPTER_H
#define VAREK_V1_7_PLAN_DATAFLOW_ADAPTER_H

#include <stddef.h>

#include "plan_dataflow.h"
#include "plan_label_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Populate 'df' by classifying each action in 'actions[0..n_actions)'
 * via 'policy'. The actions array length must equal the plan's node
 * count; otherwise -1 is returned with df partially-populated and
 * the caller should discard it.
 *
 * Returns:
 *    0  on full success.
 *   -1  on NULL argument, length mismatch, a policy callback failure
 *       (the callback returned non-zero), or an internal set-write
 *       failure. On any non-zero return the verdict cache is
 *       invalidated; the caller may inspect partial state but should
 *       not authorize execution.
 */
int plan_dataflow_populate(plan_dataflow_t *df,
                           const plan_action_desc_t *actions,
                           size_t n_actions,
                           const plan_label_policy_t *policy);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_7_PLAN_DATAFLOW_ADAPTER_H */
