// SPDX-License-Identifier: MIT
/*
 * execution_plan.h — VAREK v1.6 plan-graph verification API.
 *
 * Pre-execution verification of an ExecutionPlan as a single
 * compositional decision over a directed acyclic graph of Actions.
 * Implements USPTO Provisional 64/062,549 (May 2026) covering
 * pre-execution verification of action graphs as compositional
 * policy decisions.
 *
 * Symmetric-suppression invariant: callers MUST refuse execution on
 * both UNSATISFIED and UNKNOWN. Only SATISFIED authorizes execution.
 * The exec_plan_authorized() predicate encodes this at the API.
 */

#ifndef VAREK_V1_6_EXECUTION_PLAN_H
#define VAREK_V1_6_EXECUTION_PLAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tri-state decision for a plan node and for the plan as a whole.
 * Names track the verification-layer terminology in the patent;
 * the Warden's per-syscall ALLOW / DENY / UNKNOWN is the same
 * algebraic shape on the kernel hot path.
 */
typedef enum {
    PLAN_DEC_SATISFIED   = 0,
    PLAN_DEC_UNSATISFIED = 1,
    PLAN_DEC_UNKNOWN     = 2,
} plan_decision_t;

const char *plan_decision_name(plan_decision_t d);

/* Node id type. PLAN_NODE_ID_INVALID is returned on failure. */
typedef uint32_t plan_node_id_t;
#define PLAN_NODE_ID_INVALID UINT32_MAX

/* Compile-time bounds. Verification stays deterministic and
 * allocation-free past the plan struct. */
#define PLAN_MAX_NODES 1024u
#define PLAN_MAX_EDGES 4096u

/* Per-node record. The decision is supplied by the caller before
 * exec_plan_verify(). v1.6.0 evaluates supplied decisions; the
 * adapter that calls the v1.4 Warden policy_decide() per node and
 * assembles a plan is a separate wiring layer (v1.6.1). */
typedef struct {
    plan_node_id_t  id;
    const char     *label;    /* not copied; caller-owned */
    plan_decision_t decision;
} plan_node_t;

/* Dependency edge: 'to' depends on 'from' (data or ordering). */
typedef struct {
    plan_node_id_t from;
    plan_node_id_t to;
} plan_edge_t;

/* Opaque plan handle. */
typedef struct exec_plan exec_plan_t;

/* ---------- Construction ---------- */

/* Allocate a new plan. Returns NULL on allocation failure. */
exec_plan_t *exec_plan_new(void);

/* Free a plan. NULL-safe. */
void exec_plan_free(exec_plan_t *plan);

/* Append a node. Returns the assigned id, or PLAN_NODE_ID_INVALID on
 * capacity exhaustion, invalid decision value, or NULL plan.
 * 'label' is borrowed, not copied; callers must keep it alive for
 * the lifetime of the plan. NULL labels are permitted. */
plan_node_id_t exec_plan_add_node(exec_plan_t *plan,
                                  const char *label,
                                  plan_decision_t decision);

/* Append an edge from 'from' to 'to'. Returns 0 on success, -1 on
 * invalid ids, capacity exhaustion, or a self-edge. Self-edges are
 * rejected at insertion; longer cycles are caught in verify(). */
int exec_plan_add_edge(exec_plan_t *plan,
                       plan_node_id_t from,
                       plan_node_id_t to);

/* ---------- Introspection ---------- */

size_t exec_plan_node_count(const exec_plan_t *plan);
size_t exec_plan_edge_count(const exec_plan_t *plan);

/* ---------- Verification ---------- */

/*
 * Verify the plan. Three phases:
 *
 *   1. Structural — the edge set must be acyclic. A cycle yields
 *      UNKNOWN (structurally unverifiable).
 *   2. Compositional — fold per-node decisions under the join
 *      over the lattice SATISFIED < UNKNOWN < UNSATISFIED. The
 *      join is associative, commutative, and idempotent, so the
 *      fold order is observably irrelevant.
 *   3. Emission — plan-level tri-state.
 *
 * Decision rule:
 *   cycle present                  -> UNKNOWN
 *   empty plan                     -> UNKNOWN
 *   any node UNSATISFIED           -> UNSATISFIED
 *   else any node UNKNOWN          -> UNKNOWN
 *   else (all nodes SATISFIED)     -> SATISFIED
 *
 * Both UNSATISFIED and UNKNOWN suppress the plan; the distinction
 * is preserved in the return for pathology output.
 */
plan_decision_t exec_plan_verify(const exec_plan_t *plan);

/* Authorization predicate. Returns true iff exec_plan_verify(plan)
 * returns SATISFIED. This is the only API that authorizes
 * execution and is the recommended entry point. */
bool exec_plan_authorized(const exec_plan_t *plan);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_6_EXECUTION_PLAN_H */
