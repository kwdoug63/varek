// SPDX-License-Identifier: MIT
/*
 * warden_adapter.c — plan_spec -> ExecutionPlan verification.
 *
 * Responsibilities:
 *   - Validate spec against compile-time capacity limits.
 *   - Dispatch each Action through the caller-supplied decider.
 *   - Build the exec_plan_t and run verification.
 *   - Compute the pathology suppression_reason and surface the
 *     first negative node's label for operator telemetry.
 *
 * No allocation past the exec_plan_new() inside this TU. The
 * per-node decision cache uses a stack array sized to PLAN_MAX_NODES.
 */

#define _POSIX_C_SOURCE 200809L

#include "warden_adapter.h"

#include "execution_plan.h"
#include "pathology.h"
#include "plan_spec.h"

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

static uint64_t monotonic_us_since(const struct timespec *t0)
{
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int64_t sec  = (int64_t)t1.tv_sec  - (int64_t)t0->tv_sec;
    int64_t nsec = (int64_t)t1.tv_nsec - (int64_t)t0->tv_nsec;
    int64_t total_ns = sec * 1000000000LL + nsec;
    if (total_ns < 0) total_ns = 0;
    return (uint64_t)(total_ns / 1000LL);
}

/* Find the first action whose cached decision is target_decision.
 * Returns its index, or SIZE_MAX if none. */
static size_t find_first_with_decision(const plan_decision_t *decisions,
                                       size_t n,
                                       plan_decision_t target)
{
    for (size_t i = 0; i < n; i++) {
        if (decisions[i] == target) return i;
    }
    return (size_t)-1;
}

plan_decision_t warden_adapter_verify(const plan_spec_t      *spec,
                                      plan_action_decider_fn  decider,
                                      void                   *userdata,
                                      pathology_sink_t       *sink)
{
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* ---- structural pre-checks ---- */
    if (!spec || !decider) {
        if (sink) {
            pathology_emit_plan_decision(sink, PLAN_DEC_UNKNOWN,
                                         0, 0, monotonic_us_since(&t0),
                                         NULL, PLAN_DEC_UNKNOWN,
                                         PATH_REASON_CAPACITY);
        }
        return PLAN_DEC_UNKNOWN;
    }

    if (spec->n_actions == 0) {
        if (sink) {
            pathology_emit_plan_decision(sink, PLAN_DEC_UNKNOWN,
                                         0, spec->n_edges,
                                         monotonic_us_since(&t0),
                                         NULL, PLAN_DEC_UNKNOWN,
                                         PATH_REASON_EMPTY);
        }
        return PLAN_DEC_UNKNOWN;
    }

    if (spec->n_actions > PLAN_MAX_NODES || spec->n_edges > PLAN_MAX_EDGES) {
        if (sink) {
            pathology_emit_plan_decision(sink, PLAN_DEC_UNKNOWN,
                                         spec->n_actions, spec->n_edges,
                                         monotonic_us_since(&t0),
                                         NULL, PLAN_DEC_UNKNOWN,
                                         PATH_REASON_CAPACITY);
        }
        return PLAN_DEC_UNKNOWN;
    }

    /* ---- build the plan ---- */
    exec_plan_t *plan = exec_plan_new();
    if (!plan) {
        if (sink) {
            pathology_emit_plan_decision(sink, PLAN_DEC_UNKNOWN,
                                         spec->n_actions, spec->n_edges,
                                         monotonic_us_since(&t0),
                                         NULL, PLAN_DEC_UNKNOWN,
                                         PATH_REASON_CAPACITY);
        }
        return PLAN_DEC_UNKNOWN;
    }

    /* Cache per-node decisions for pathology suppressed-node lookup. */
    plan_decision_t node_decisions[PLAN_MAX_NODES];

    for (size_t i = 0; i < spec->n_actions; i++) {
        plan_decision_t d = decider(&spec->actions[i], userdata);
        if (d != PLAN_DEC_SATISFIED &&
            d != PLAN_DEC_UNSATISFIED &&
            d != PLAN_DEC_UNKNOWN) {
            d = PLAN_DEC_UNKNOWN;   /* defensively coerce */
        }
        node_decisions[i] = d;

        plan_node_id_t id = exec_plan_add_node(plan, spec->actions[i].label, d);
        if (id == PLAN_NODE_ID_INVALID) {
            exec_plan_free(plan);
            if (sink) {
                pathology_emit_plan_decision(sink, PLAN_DEC_UNKNOWN,
                                             spec->n_actions, spec->n_edges,
                                             monotonic_us_since(&t0),
                                             NULL, PLAN_DEC_UNKNOWN,
                                             PATH_REASON_CAPACITY);
            }
            return PLAN_DEC_UNKNOWN;
        }
    }

    for (size_t i = 0; i < spec->n_edges; i++) {
        int rc = exec_plan_add_edge(plan,
                                    spec->edges[i].from_idx,
                                    spec->edges[i].to_idx);
        if (rc != 0) {
            exec_plan_free(plan);
            if (sink) {
                pathology_emit_plan_decision(sink, PLAN_DEC_UNKNOWN,
                                             spec->n_actions, spec->n_edges,
                                             monotonic_us_since(&t0),
                                             NULL, PLAN_DEC_UNKNOWN,
                                             PATH_REASON_EDGE_INDEX);
            }
            return PLAN_DEC_UNKNOWN;
        }
    }

    /* ---- verify ---- */
    plan_decision_t result = exec_plan_verify(plan);
    uint64_t latency_us = monotonic_us_since(&t0);

    /* ---- classify suppression for pathology ---- */
    pathology_reason_t  reason          = PATH_REASON_NONE;
    const char         *suppressed_lbl  = NULL;
    plan_decision_t     suppressed_dec  = PLAN_DEC_SATISFIED;

    if (result == PLAN_DEC_UNSATISFIED) {
        size_t k = find_first_with_decision(node_decisions, spec->n_actions,
                                            PLAN_DEC_UNSATISFIED);
        if (k != (size_t)-1) {
            reason         = PATH_REASON_NODE;
            suppressed_lbl = spec->actions[k].label;
            suppressed_dec = PLAN_DEC_UNSATISFIED;
        } else {
            reason         = PATH_REASON_NODE;   /* defensive */
            suppressed_dec = PLAN_DEC_UNSATISFIED;
        }
    } else if (result == PLAN_DEC_UNKNOWN) {
        size_t k = find_first_with_decision(node_decisions, spec->n_actions,
                                            PLAN_DEC_UNKNOWN);
        if (k != (size_t)-1) {
            reason         = PATH_REASON_NODE;
            suppressed_lbl = spec->actions[k].label;
            suppressed_dec = PLAN_DEC_UNKNOWN;
        } else {
            /* No node-level UNKNOWN — must be structural (cycle).
             * Empty plan was rejected upstream. */
            reason         = PATH_REASON_CYCLE;
            suppressed_dec = PLAN_DEC_UNKNOWN;
        }
    }

    if (sink) {
        pathology_emit_plan_decision(sink, result,
                                     spec->n_actions, spec->n_edges,
                                     latency_us,
                                     suppressed_lbl, suppressed_dec,
                                     reason);
    }

    exec_plan_free(plan);
    return result;
}
