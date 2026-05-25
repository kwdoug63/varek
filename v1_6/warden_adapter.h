// SPDX-License-Identifier: MIT
/*
 * warden_adapter.h — turn a plan_spec_t into a verified ExecutionPlan.
 *
 * The adapter is the bridge from a caller-supplied declarative plan
 * to the v1.6 compositional evaluator. For each Action in the spec
 * it invokes a caller-supplied decider callback to obtain a per-node
 * decision (the v1.4 Warden binds this to policy_decide()), assembles
 * an exec_plan_t, runs exec_plan_verify(), and optionally emits a
 * plan-level pathology record.
 *
 * The decider is a callback rather than a direct dependency on the
 * v1.4 policy module so the adapter is independently testable and
 * the actual Warden wiring is a one-line glue in the supervisor TU.
 */

#ifndef VAREK_V1_6_WARDEN_ADAPTER_H
#define VAREK_V1_6_WARDEN_ADAPTER_H

#include "execution_plan.h"
#include "pathology.h"
#include "plan_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Caller-supplied per-action decision function. userdata is the
 * opaque pointer passed to warden_adapter_verify(). Must return
 * one of PLAN_DEC_SATISFIED / PLAN_DEC_UNSATISFIED / PLAN_DEC_UNKNOWN;
 * any other value is treated as UNKNOWN. */
typedef plan_decision_t (*plan_action_decider_fn)(const plan_spec_action_t *action,
                                                  void *userdata);

/* Verify a plan spec.
 *
 * Flow:
 *   1. Validate spec capacity against PLAN_MAX_NODES / PLAN_MAX_EDGES.
 *   2. For each action, call decider() to obtain a per-node decision.
 *   3. Build an exec_plan_t with the resulting nodes and the spec's edges.
 *   4. Run exec_plan_verify().
 *   5. If sink != NULL, emit a plan-level pathology record.
 *   6. Return the plan decision.
 *
 * Returns PLAN_DEC_UNKNOWN on any structural failure (NULL spec,
 * NULL decider, capacity overflow, invalid edge index). All such
 * failures are reflected in the pathology record's reason field
 * when a sink is provided.
 *
 * sink may be NULL to suppress pathology emission entirely (useful
 * for hot-path callers that emit their own telemetry). */
plan_decision_t warden_adapter_verify(const plan_spec_t      *spec,
                                      plan_action_decider_fn  decider,
                                      void                   *userdata,
                                      pathology_sink_t       *sink);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_6_WARDEN_ADAPTER_H */
