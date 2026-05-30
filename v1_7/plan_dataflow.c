// SPDX-License-Identifier: MIT
/*
 * plan_dataflow.c — VAREK v1.7 cross-action data-flow verification.
 *
 * Propagation, per-node flow decision, fold, and the two-axis join
 * with the v1.6 node verdict. Reads plan topology through the public
 * exec_plan_* API only; does not include the v1.6 internal header.
 *
 * All working storage is fixed-capacity (PLAN_MAX_NODES). No dynamic
 * allocation past the companion struct itself, matching the v1.6
 * verification discipline.
 */

#include "plan_dataflow.h"
#include "execution_plan.h"
#include "v1_6_compat.h"
#include "plan_label.h"

#include <stdlib.h>

struct plan_dataflow {
    const exec_plan_t *plan;

    /* Inputs (caller-populated). */
    plan_label_set_t origin[PLAN_MAX_NODES];
    plan_label_set_t deny_in[PLAN_MAX_NODES];
    plan_label_set_t unknown_in[PLAN_MAX_NODES];
    plan_label_set_t permit_in[PLAN_MAX_NODES];   /* v1.7.1 */
    plan_label_set_t declassify[PLAN_MAX_NODES];  /* v1.8.0 */
    plan_label_set_t sticky;                       /* v1.7.1 — plan-wide */

    /* Computed by flow_verdict(). */
    plan_label_set_t inbound[PLAN_MAX_NODES];
    plan_label_set_t outbound[PLAN_MAX_NODES];
    plan_label_set_t declassified[PLAN_MAX_NODES]; /* v1.8.0 audit: inbound ∩ declassify */
    plan_decision_t  node_dec[PLAN_MAX_NODES];
    plan_decision_t  flow_verdict;
    bool             computed;
};

/* ---------- Lattice ---------- */
/*
 * Lattice order: SATISFIED < UNKNOWN < UNSATISFIED. The enum's
 * numeric values do NOT match this order (UNSATISFIED=1, UNKNOWN=2),
 * so join is computed over an explicit rank, never over the raw
 * enum value.
 */
static int dec_rank(plan_decision_t d)
{
    switch (d) {
        case PLAN_DEC_SATISFIED:   return 0;
        case PLAN_DEC_UNKNOWN:     return 1;
        case PLAN_DEC_UNSATISFIED: return 2;
    }
    return 2; /* unreachable for valid input; fail safe to the top */
}

static plan_decision_t dec_join(plan_decision_t a, plan_decision_t b)
{
    return dec_rank(a) >= dec_rank(b) ? a : b;
}

/* Public alias for the lattice join. Same shape as dec_join; exposed
 * in v1.7.2 so the Warden binding and other axis-composing callers
 * don't redefine the rank table. */
plan_decision_t plan_decision_join(plan_decision_t a, plan_decision_t b)
{
    return dec_join(a, b);
}

/* ---------- Construction ---------- */

plan_dataflow_t *plan_dataflow_new(const exec_plan_t *plan)
{
    if (!plan)
        return NULL;
    /* calloc zeroes every label set (empty) and clears flags. */
    plan_dataflow_t *df = calloc(1, sizeof(struct plan_dataflow));
    if (!df)
        return NULL;
    df->plan         = plan;
    df->flow_verdict = PLAN_DEC_UNKNOWN;
    df->computed     = false;
    return df;
}

void plan_dataflow_free(plan_dataflow_t *df)
{
    free(df);
}

/* ---------- Inputs ---------- */

static int add_to(plan_dataflow_t *df, plan_label_set_t *arr,
                  plan_node_id_t node, plan_label_t tag)
{
    if (!df)
        return -1;
    if (node >= exec_plan_node_count(df->plan))
        return -1;
    if (plan_label_set_add(&arr[node], tag) != 0)
        return -1;
    df->computed = false; /* inputs changed; stale any prior verdict */
    return 0;
}

int plan_dataflow_add_origin(plan_dataflow_t *df,
                             plan_node_id_t node, plan_label_t tag)
{
    return add_to(df, df ? df->origin : NULL, node, tag);
}

int plan_dataflow_add_deny_in(plan_dataflow_t *df,
                              plan_node_id_t node, plan_label_t tag)
{
    return add_to(df, df ? df->deny_in : NULL, node, tag);
}

int plan_dataflow_add_unknown_in(plan_dataflow_t *df,
                                 plan_node_id_t node, plan_label_t tag)
{
    return add_to(df, df ? df->unknown_in : NULL, node, tag);
}

int plan_dataflow_add_permit_in(plan_dataflow_t *df,
                                plan_node_id_t node, plan_label_t tag)
{
    return add_to(df, df ? df->permit_in : NULL, node, tag);
}

int plan_dataflow_add_declassify(plan_dataflow_t *df,
                                 plan_node_id_t node, plan_label_t tag)
{
    return add_to(df, df ? df->declassify : NULL, node, tag);
}

int plan_dataflow_mark_sticky(plan_dataflow_t *df, plan_label_t tag)
{
    if (!df)
        return -1;
    if (plan_label_set_add(&df->sticky, tag) != 0)
        return -1;
    df->computed = false;
    return 0;
}

/* ---------- Verification ---------- */

/* Per-node flow decision against the finalized inbound set.
 *
 * Order of evaluation (lattice-consistent: deny dominates unknown):
 *   1. Inbound hits deny_in           -> UNSATISFIED.
 *   2. Inbound hits unknown_in        -> UNKNOWN.
 *   3. Sticky inbound label that this node has NOT classified at all
 *      (not in deny_in, unknown_in, or permit_in)
 *                                     -> UNKNOWN (fail-safe; v1.7.1).
 *   4. Otherwise                       -> SATISFIED.
 *
 * Free labels (not in df->sticky) skip step 3 entirely — they retain
 * the v1.7.0 deny-list semantics. With no labels marked sticky, the
 * function is byte-for-byte identical to the v1.7.0 behavior. */
static plan_decision_t node_flow_decision(const plan_dataflow_t *df,
                                          plan_node_id_t n)
{
    if (plan_label_set_intersects(&df->inbound[n], &df->deny_in[n]))
        return PLAN_DEC_UNSATISFIED;
    if (plan_label_set_intersects(&df->inbound[n], &df->unknown_in[n]))
        return PLAN_DEC_UNKNOWN;

    /* Sticky check: any inbound label that is sticky AND not in any of
     * this node's three classified sets (deny / unknown / permit)
     * yields UNKNOWN. Computed as
     *   (inbound & sticky) \ (deny_in | unknown_in | permit_in)
     * non-empty. Done without allocating: build the classified union
     * inline and ask whether (inbound & sticky) has a bit outside it. */
    plan_label_set_t sticky_inbound;
    plan_label_set_clear(&sticky_inbound);
    /* sticky_inbound = inbound & sticky */
    for (size_t i = 0; i < PLAN_LABEL_WORDS; i++)
        sticky_inbound.bits[i] = df->inbound[n].bits[i] & df->sticky.bits[i];

    plan_label_set_t classified;
    plan_label_set_clear(&classified);
    /* classified = deny_in | unknown_in | permit_in */
    for (size_t i = 0; i < PLAN_LABEL_WORDS; i++)
        classified.bits[i] = df->deny_in[n].bits[i]
                           | df->unknown_in[n].bits[i]
                           | df->permit_in[n].bits[i];

    if (plan_label_set_minus_nonempty(&sticky_inbound, &classified))
        return PLAN_DEC_UNKNOWN;

    return PLAN_DEC_SATISFIED;
}

plan_decision_t plan_dataflow_flow_verdict(plan_dataflow_t *df)
{
    if (!df)
        return PLAN_DEC_UNKNOWN;
    if (df->computed)
        return df->flow_verdict;

    const size_t n = exec_plan_node_count(df->plan);
    const size_t m = exec_plan_edge_count(df->plan);

    /* Empty plan: no flows. SATISFIED on this axis; the v1.6 node
     * axis still returns UNKNOWN for an empty plan, so the joined
     * verdict will be UNKNOWN. */
    if (n == 0) {
        df->flow_verdict = PLAN_DEC_SATISFIED;
        df->computed     = true;
        return df->flow_verdict;
    }

    /* Reset computed state. */
    for (size_t i = 0; i < n; i++) {
        plan_label_set_clear(&df->inbound[i]);
        plan_label_set_clear(&df->outbound[i]);
        plan_label_set_clear(&df->declassified[i]);
        df->node_dec[i] = PLAN_DEC_UNKNOWN;
    }

    /* Kahn's algorithm: topological order + acyclicity in one pass.
     * Indegree and queue are fixed-capacity stack arrays. */
    static const size_t CAP = PLAN_MAX_NODES;
    size_t indeg[PLAN_MAX_NODES];
    size_t queue[PLAN_MAX_NODES];
    for (size_t i = 0; i < n; i++)
        indeg[i] = 0;

    for (size_t e = 0; e < m; e++) {
        plan_node_id_t from, to;
        if (dataflow_plan_get_edge(df->plan, e, &from, &to) != 0)
            continue;            /* defensive; should not occur */
        if (to < n)
            indeg[to]++;
    }

    size_t qh = 0, qt = 0;
    for (size_t i = 0; i < n; i++)
        if (indeg[i] == 0)
            queue[qt++] = i;

    size_t processed = 0;
    plan_decision_t verdict = PLAN_DEC_SATISFIED;

    while (qh < qt) {
        size_t u = queue[qh++];
        processed++;

        /* inbound[u] is finalized (all predecessors precede u in the
         * topological order). The node is policed on its FULL inbound
         * set — declassification does not change what the node itself
         * sees, only what it emits downstream. */
        df->node_dec[u] = node_flow_decision(df, (plan_node_id_t)u);
        verdict = dec_join(verdict, df->node_dec[u]);

        /* Audit: record which inbound labels this node declassifies
         * (inbound ∩ declassify). A declassify entry for a label not
         * present on inbound is a harmless no-op and is not recorded. */
        plan_label_set_intersect_into(&df->declassified[u],
                                      &df->inbound[u], &df->declassify[u]);

        /* outbound = (inbound \ declassify) ∪ origin.  v1.8.0: this is
         * the first non-monotone step in the kernel. Declassified
         * labels do not propagate to successors; the declassify set is
         * operator-policy only (never plan/agent-supplied), so an
         * attacker cannot introduce a declassifying node. */
        df->outbound[u] = df->inbound[u];
        plan_label_set_minus_into(&df->outbound[u], &df->declassify[u]);
        plan_label_set_union_into(&df->outbound[u], &df->origin[u]);

        /* Relax successors. */
        for (size_t e = 0; e < m; e++) {
            plan_node_id_t from, to;
            if (dataflow_plan_get_edge(df->plan, e, &from, &to) != 0)
                continue;
            if (from != u || to >= n)
                continue;
            plan_label_set_union_into(&df->inbound[to], &df->outbound[u]);
            if (indeg[to] > 0 && --indeg[to] == 0) {
                if (qt < CAP)
                    queue[qt++] = to;
            }
        }
    }

    /* Not every node ordered => a cycle exists => structurally
     * unverifiable on this axis. UNKNOWN suppresses. */
    if (processed != n)
        verdict = PLAN_DEC_UNKNOWN;

    df->flow_verdict = verdict;
    df->computed     = true;
    return verdict;
}

plan_decision_t exec_plan_verify_with_dataflow(const exec_plan_t *plan,
                                               plan_dataflow_t *df)
{
    plan_decision_t node_axis = exec_plan_verify(plan);
    plan_decision_t flow_axis = plan_dataflow_flow_verdict(df);
    return dec_join(node_axis, flow_axis);
}

bool exec_plan_authorized_with_dataflow(const exec_plan_t *plan,
                                        plan_dataflow_t *df)
{
    return exec_plan_verify_with_dataflow(plan, df) == PLAN_DEC_SATISFIED;
}

/* ---------- Introspection ---------- */

plan_decision_t plan_dataflow_node_decision(const plan_dataflow_t *df,
                                            plan_node_id_t node)
{
    if (!df || !df->computed)
        return PLAN_DEC_UNKNOWN;
    if (node >= exec_plan_node_count(df->plan))
        return PLAN_DEC_UNKNOWN;
    return df->node_dec[node];
}

int plan_dataflow_node_inbound(const plan_dataflow_t *df,
                               plan_node_id_t node,
                               plan_label_set_t *out)
{
    if (!df || !out || !df->computed)
        return -1;
    if (node >= exec_plan_node_count(df->plan))
        return -1;
    *out = df->inbound[node];
    return 0;
}

int plan_dataflow_node_outbound(const plan_dataflow_t *df,
                                plan_node_id_t node,
                                plan_label_set_t *out)
{
    if (!df || !out || !df->computed)
        return -1;
    if (node >= exec_plan_node_count(df->plan))
        return -1;
    *out = df->outbound[node];
    return 0;
}

int plan_dataflow_node_deny_in(const plan_dataflow_t *df,
                               plan_node_id_t node,
                               plan_label_set_t *out)
{
    if (!df || !out) return -1;
    if (node >= exec_plan_node_count(df->plan)) return -1;
    *out = df->deny_in[node];
    return 0;
}

int plan_dataflow_node_unknown_in(const plan_dataflow_t *df,
                                  plan_node_id_t node,
                                  plan_label_set_t *out)
{
    if (!df || !out) return -1;
    if (node >= exec_plan_node_count(df->plan)) return -1;
    *out = df->unknown_in[node];
    return 0;
}

int plan_dataflow_node_permit_in(const plan_dataflow_t *df,
                                 plan_node_id_t node,
                                 plan_label_set_t *out)
{
    if (!df || !out) return -1;
    if (node >= exec_plan_node_count(df->plan)) return -1;
    *out = df->permit_in[node];
    return 0;
}

int plan_dataflow_node_declassified(const plan_dataflow_t *df,
                                    plan_node_id_t node,
                                    plan_label_set_t *out)
{
    if (!df || !out || !df->computed) return -1;
    if (node >= exec_plan_node_count(df->plan)) return -1;
    *out = df->declassified[node];
    return 0;
}

int plan_dataflow_node_origin(const plan_dataflow_t *df,
                              plan_node_id_t node,
                              plan_label_set_t *out)
{
    if (!df || !out) return -1;
    if (node >= exec_plan_node_count(df->plan)) return -1;
    *out = df->origin[node];
    return 0;
}

int plan_dataflow_sticky(const plan_dataflow_t *df, plan_label_set_t *out)
{
    if (!df || !out) return -1;
    *out = df->sticky;
    return 0;
}

const exec_plan_t *plan_dataflow_get_plan(const plan_dataflow_t *df)
{
    return df ? df->plan : NULL;
}
