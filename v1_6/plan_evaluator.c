// SPDX-License-Identifier: MIT
/*
 * plan_evaluator.c — compositional verification over an ExecutionPlan.
 *
 * Three phases, in order:
 *
 *   1. Structural verification. Iterative DFS over the edge set
 *      detects any cycle. A cyclic plan is structurally
 *      unverifiable and is reported as UNKNOWN. This matches the
 *      patent's symmetric-suppression semantics: the verifier
 *      could not form an opinion, so the caller suppresses.
 *
 *   2. Compositional aggregation. The per-node decisions are folded
 *      under the information-preserving join over the lattice
 *
 *          SATISFIED < UNKNOWN < UNSATISFIED
 *
 *      The join is associative, commutative, and idempotent. Fold
 *      order is therefore observably irrelevant; the structural
 *      DFS in phase 1 imposes an order for soundness only.
 *
 *   3. Plan-level decision emission.
 *
 * No allocation on the verification path. All cycle-detection
 * storage is in fixed-size thread-local arrays sized to the
 * compile-time maxima. Recursion is avoided; the DFS uses an
 * explicit stack.
 */

#include "execution_plan.h"
#include "execution_plan_internal.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ---------------- cycle detection ---------------- */

enum { COLOR_WHITE = 0, COLOR_GRAY = 1, COLOR_BLACK = 2 };

static bool has_cycle(const exec_plan_t *plan)
{
    if (plan->n_nodes == 0) return false;

    /* Fixed-size scratch sized to the compile-time maxima. Marked
     * thread-local so the evaluator may be called from any
     * supervisor thread without sharing scratch state. */
    static _Thread_local uint8_t        color[PLAN_MAX_NODES];
    static _Thread_local uint32_t       out_head[PLAN_MAX_NODES + 1u];
    static _Thread_local plan_node_id_t out_dst[PLAN_MAX_EDGES];
    static _Thread_local uint32_t       counts[PLAN_MAX_NODES];
    static _Thread_local uint32_t       cursor[PLAN_MAX_NODES];
    static _Thread_local plan_node_id_t stack[PLAN_MAX_NODES];
    static _Thread_local uint32_t       stack_iter[PLAN_MAX_NODES];

    /* Clear only the portions we'll touch. */
    memset(color,  COLOR_WHITE, plan->n_nodes);
    memset(counts, 0, plan->n_nodes * sizeof(counts[0]));
    memset(cursor, 0, plan->n_nodes * sizeof(cursor[0]));

    /* Build CSR adjacency: count out-edges, prefix-sum, then fill. */
    for (size_t i = 0; i < plan->n_edges; i++) {
        counts[plan->edges[i].from]++;
    }
    out_head[0] = 0;
    for (size_t i = 0; i < plan->n_nodes; i++) {
        out_head[i + 1u] = out_head[i] + counts[i];
    }
    for (size_t i = 0; i < plan->n_edges; i++) {
        plan_node_id_t f = plan->edges[i].from;
        out_dst[out_head[f] + cursor[f]++] = plan->edges[i].to;
    }

    /* Iterative DFS. Each unvisited root drives a walk. A gray
     * successor signals a back-edge, i.e. a cycle. */
    for (size_t root = 0; root < plan->n_nodes; root++) {
        if (color[root] != COLOR_WHITE) continue;

        size_t top = 0;
        stack[top]      = (plan_node_id_t)root;
        stack_iter[top] = 0;
        color[root]     = COLOR_GRAY;

        for (;;) {
            plan_node_id_t u  = stack[top];
            uint32_t       it = stack_iter[top];
            uint32_t       beg = out_head[u];
            uint32_t       end = out_head[u + 1u];

            if (it < (end - beg)) {
                stack_iter[top]++;
                plan_node_id_t v = out_dst[beg + it];

                if (color[v] == COLOR_GRAY) {
                    return true;            /* back-edge */
                }
                if (color[v] == COLOR_WHITE) {
                    top++;
                    stack[top]      = v;
                    stack_iter[top] = 0;
                    color[v]        = COLOR_GRAY;
                }
                /* COLOR_BLACK: cross/forward edge, skip. */
            } else {
                color[u] = COLOR_BLACK;
                if (top == 0) break;
                top--;
            }
        }
    }
    return false;
}

/* ---------------- compositional aggregation ---------------- */

/* Information-preserving join over the decision lattice:
 *   SATISFIED < UNKNOWN < UNSATISFIED
 * Associative, commutative, idempotent. */
static plan_decision_t join_decisions(plan_decision_t a, plan_decision_t b)
{
    if (a == PLAN_DEC_UNSATISFIED || b == PLAN_DEC_UNSATISFIED)
        return PLAN_DEC_UNSATISFIED;
    if (a == PLAN_DEC_UNKNOWN || b == PLAN_DEC_UNKNOWN)
        return PLAN_DEC_UNKNOWN;
    return PLAN_DEC_SATISFIED;
}

/* ---------------- public entry points ---------------- */

plan_decision_t exec_plan_verify(const exec_plan_t *plan)
{
    if (!plan)              return PLAN_DEC_UNKNOWN;
    if (plan->n_nodes == 0) return PLAN_DEC_UNKNOWN;
    if (has_cycle(plan))    return PLAN_DEC_UNKNOWN;

    /* Identity for the join is SATISFIED. Fold linearly with a
     * short-circuit at the top of the lattice. */
    plan_decision_t acc = PLAN_DEC_SATISFIED;
    for (size_t i = 0; i < plan->n_nodes; i++) {
        acc = join_decisions(acc, plan->nodes[i].decision);
        if (acc == PLAN_DEC_UNSATISFIED) return PLAN_DEC_UNSATISFIED;
    }
    return acc;
}

bool exec_plan_authorized(const exec_plan_t *plan)
{
    return exec_plan_verify(plan) == PLAN_DEC_SATISFIED;
}
