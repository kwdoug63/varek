// SPDX-License-Identifier: MIT
/*
 * plan_dataflow.h — VAREK v1.7 cross-action data-flow verification.
 *
 * v1.6 verifies an ExecutionPlan as a compositional decision over
 * each node, treating edges as ordering only. v1.7 adds a second
 * axis: what flows along the edges. Each node may originate labels
 * (taint / capability tags); labels propagate forward by set union
 * over the dependency edges. A node may declare inbound labels that
 * suppress it:
 *
 *   - a label in the node's deny-in set, if present on the inbound
 *     (propagated) set, forces that node's flow decision to
 *     UNSATISFIED;
 *   - a label in the node's unknown-in set, if present and not
 *     already denied, forces UNKNOWN.
 *
 * The flow axis folds to a plan-level tri-state under the same
 * lattice as v1.6 (SATISFIED < UNKNOWN < UNSATISFIED). The plan
 * verdict is the join of the v1.6 node axis and this flow axis.
 *
 * Symmetric suppression is preserved on BOTH axes: execution is
 * authorized only when the plan is SATISFIED on every node AND on
 * every flow. Any UNSATISFIED or UNKNOWN on either axis suppresses
 * the plan; the distinction is retained in the return for pathology
 * output. This is the v1.6 three-state contract lifted to two axes;
 * the decision procedure is not narrowed.
 *
 * SEMANTICS NOTE: the flow policy is evaluated against a node's
 * INBOUND (propagated) label set — the labels that reached it via
 * the plan's edges. A node's own originated labels are added to its
 * OUTBOUND set for downstream propagation but are not policed at the
 * originating node. This is deliberate: v1.7 polices the path
 * BETWEEN actions (the compositional leak), not a single action in
 * isolation, which is already the v1.6 node axis.
 *
 * POSTURE NOTE (load-bearing): v1.7.1 introduces per-label POSTURE.
 * A label is either STICKY (operator-declared sensitive) or FREE
 * (default). For a sticky label arriving at a node: deny-in -> UNSAT;
 * unknown-in -> UNKNOWN; permit-in -> SATISFIED for that label;
 * UNCLASSIFIED at this node -> UNKNOWN (fail-safe). For a free label
 * arriving: existing v1.7.0 semantics — SATISFIED unless deny/unknown.
 *
 * The posture scales with the number of declared sensitive labels in
 * the deployment, not (label x sink) pairs. With no labels marked
 * sticky, behavior is identical to v1.7.0 (deny-list, backward
 * compatible). Marking a label sticky is the operator's signal that
 * every node receiving it must have an explicit disposition. This
 * preserves v1.6's UNKNOWN-suppresses discipline on the flow axis:
 * unclassified-at-the-boundary becomes UNKNOWN, and UNKNOWN refuses.
 *
 * IP NOTE: compositional cross-action data-flow verification is a
 * v1.7 extension beyond USPTO Provisional 64/062,549. Treat the
 * design as confidential pending IP review prior to any public
 * disclosure.
 */

#ifndef VAREK_V1_7_PLAN_DATAFLOW_H
#define VAREK_V1_7_PLAN_DATAFLOW_H

#include <stdbool.h>
#include <stddef.h>

#include "execution_plan.h"
#include "plan_label.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque companion to an exec_plan_t carrying the data-flow inputs
 * and computed results. It borrows the plan pointer for topology
 * and node count; the plan must outlive the companion. */
typedef struct plan_dataflow plan_dataflow_t;

/* ---------- Construction ---------- */

/* Allocate a data-flow companion for 'plan'. All label sets start
 * empty (no taint, no suppression). Returns NULL on allocation
 * failure or if plan is NULL. */
plan_dataflow_t *plan_dataflow_new(const exec_plan_t *plan);

/* Free a companion. NULL-safe. Does not free the plan. */
void plan_dataflow_free(plan_dataflow_t *df);

/* ---------- Inputs (caller-populated, typically by the adapter) ---------- */

/* Add 'tag' to node's set of originated labels (labels this action
 * introduces into the flow). Returns 0 on success, -1 on NULL df,
 * out-of-range node, or out-of-range tag. Invalidates any prior
 * computed verdict. */
int plan_dataflow_add_origin(plan_dataflow_t *df,
                             plan_node_id_t node, plan_label_t tag);

/* Add 'tag' to node's deny-in set: presence on the inbound set
 * forces this node's flow decision to UNSATISFIED. Same return
 * contract as add_origin. */
int plan_dataflow_add_deny_in(plan_dataflow_t *df,
                              plan_node_id_t node, plan_label_t tag);

/* Add 'tag' to node's unknown-in set: presence on the inbound set
 * forces UNKNOWN (unless also denied). Same return contract. */
int plan_dataflow_add_unknown_in(plan_dataflow_t *df,
                                 plan_node_id_t node, plan_label_t tag);

/* Add 'tag' to node's permit-in set: presence on the inbound set is
 * SATISFIED for that label even when the label is sticky. For free
 * labels this is a no-op (free labels are SATISFIED by default).
 * Same return contract as add_origin. Added in v1.7.1. */
int plan_dataflow_add_permit_in(plan_dataflow_t *df,
                                plan_node_id_t node, plan_label_t tag);

/* Add 'tag' to node's declassify set: the label is REMOVED from the
 * node's outbound set, so it does not propagate to successors. The
 * node is still policed on its full inbound set (declassification
 * affects only downstream flow, not the node's own decision), so a
 * declassifier of a sticky label must ALSO be permitted to receive it
 * (permit_in), or it fails closed to UNKNOWN. The declassify set is
 * operator-policy only and is never plan- or agent-supplied: an
 * attacker cannot introduce a declassifying node. Declassification is
 * audited (see plan_dataflow_node_declassified) but not verified —
 * VAREK trusts the operator's assertion that the node sanitizes.
 * Same return contract as add_origin. Added in v1.8.0. */
int plan_dataflow_add_declassify(plan_dataflow_t *df,
                                 plan_node_id_t node, plan_label_t tag);

/* Mark 'tag' as sticky: any node receiving this label must have an
 * explicit disposition (deny-in, unknown-in, or permit-in), otherwise
 * the node's flow decision becomes UNKNOWN (fail-safe). Sticky is a
 * plan-wide property of the label, not a per-node property. Returns
 * 0 on success, -1 on NULL df or out-of-range tag. Invalidates any
 * prior computed verdict. Added in v1.7.1. */
int plan_dataflow_mark_sticky(plan_dataflow_t *df, plan_label_t tag);

/* ---------- Verification ---------- */

/*
 * Compute the flow-axis verdict over the plan:
 *
 *   1. Propagate labels forward in topological order: inbound[n] is
 *      the union of outbound[p] over edges p->n; outbound[n] is
 *      inbound[n] U origin[n].
 *   2. Per node: deny-in hit -> UNSATISFIED; else unknown-in hit ->
 *      UNKNOWN; else SATISFIED.
 *   3. Fold under the lattice (join). Any UNSATISFIED -> UNSATISFIED;
 *      else any UNKNOWN -> UNKNOWN; else SATISFIED.
 *
 * A cycle (the graph is not a DAG) yields UNKNOWN — structurally
 * unverifiable, matching the v1.6 treatment. An empty plan has no
 * flows and yields SATISFIED on this axis; the v1.6 node axis still
 * returns UNKNOWN for an empty plan, so the joined verdict is
 * UNKNOWN.
 *
 * The result and all intermediate per-node sets/decisions are cached
 * on the companion for pathology emission (v1.7.1). Idempotent.
 */
plan_decision_t plan_dataflow_flow_verdict(plan_dataflow_t *df);

/*
 * Joined two-axis verdict: join(exec_plan_verify(plan),
 * plan_dataflow_flow_verdict(df)). This is the v1.7 plan-level
 * decision.
 */
plan_decision_t exec_plan_verify_with_dataflow(const exec_plan_t *plan,
                                               plan_dataflow_t *df);

/* Authorization predicate. True iff exec_plan_verify_with_dataflow()
 * returns SATISFIED. The only API that authorizes execution under
 * v1.7. */
bool exec_plan_authorized_with_dataflow(const exec_plan_t *plan,
                                        plan_dataflow_t *df);

/* ---------- Introspection (post-verdict; for pathology output) ---------- */

/* Per-node flow decision from the last flow_verdict(). Returns
 * UNKNOWN for NULL df, out-of-range node, or if no verdict has been
 * computed. */
plan_decision_t plan_dataflow_node_decision(const plan_dataflow_t *df,
                                            plan_node_id_t node);

/* Copy node's computed inbound (propagated) label set into *out.
 * Returns 0 on success, -1 on NULL arg, out-of-range node, or if no
 * verdict has been computed. */
int plan_dataflow_node_inbound(const plan_dataflow_t *df,
                               plan_node_id_t node,
                               plan_label_set_t *out);

/* Copy node's computed outbound (inbound U origin) label set into
 * *out. Same return contract as node_inbound. Added in v1.7.1 for
 * pathology emission — used to determine which predecessor edge
 * carried a given offending label into a suppressed sink. */
int plan_dataflow_node_outbound(const plan_dataflow_t *df,
                                plan_node_id_t node,
                                plan_label_set_t *out);

/* Copy node's deny-in / unknown-in / permit-in input sets into *out.
 * Same return contract. Added in v1.7.1 for pathology emission. */
int plan_dataflow_node_deny_in(const plan_dataflow_t *df,
                               plan_node_id_t node,
                               plan_label_set_t *out);
int plan_dataflow_node_unknown_in(const plan_dataflow_t *df,
                                  plan_node_id_t node,
                                  plan_label_set_t *out);
int plan_dataflow_node_permit_in(const plan_dataflow_t *df,
                                 plan_node_id_t node,
                                 plan_label_set_t *out);

/* Copy the set of labels this node actually declassified (inbound ∩
 * declassify) into *out. Requires a computed verdict. Same return
 * contract as node_inbound. This is the audit surface: it answers
 * "which sensitive labels were dropped here, and therefore did not
 * reach downstream sinks." Added in v1.8.0. */
int plan_dataflow_node_declassified(const plan_dataflow_t *df,
                                    plan_node_id_t node,
                                    plan_label_set_t *out);

/* Copy node's origin (caller-supplied) label set into *out. Same
 * return contract as the other input accessors. Added in v1.7.4
 * for lineage tracing in pathology. */
int plan_dataflow_node_origin(const plan_dataflow_t *df,
                              plan_node_id_t node,
                              plan_label_set_t *out);

/* Copy the plan-wide sticky-label set into *out. Same return contract,
 * minus the node check. Added in v1.7.1. */
int plan_dataflow_sticky(const plan_dataflow_t *df, plan_label_set_t *out);

/* Return the plan pointer the companion borrows. NULL if df is NULL.
 * Added in v1.7.1 so the adapter and pathology layers don't need the
 * caller to pass the plan separately. */
const exec_plan_t *plan_dataflow_get_plan(const plan_dataflow_t *df);

/* ---------- Lattice utility ---------- */

/* Lattice join over the decision lattice
 * (SATISFIED < UNKNOWN < UNSATISFIED). Associative, commutative,
 * idempotent. The enum's numeric values do NOT match this order
 * (UNSATISFIED=1, UNKNOWN=2), so callers MUST use this function
 * rather than max() over the raw enum. Exposed in v1.7.2 for the
 * Warden binding and any other caller composing multiple axes. */
plan_decision_t plan_decision_join(plan_decision_t a, plan_decision_t b);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_7_PLAN_DATAFLOW_H */
