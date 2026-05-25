// SPDX-License-Identifier: MIT
/*
 * plan_spec.h — declarative ExecutionPlan input for the Warden adapter.
 *
 * A plan_spec_t is what an agent submits before execution: an ordered
 * list of intended Actions plus the dependency edges between them.
 * The Warden adapter turns this declaration into per-node policy
 * decisions and feeds it to exec_plan_verify().
 *
 * plan_spec_t is a borrow type: all pointers are caller-owned and
 * must outlive the verify call. No deep copies are made.
 */

#ifndef VAREK_V1_6_PLAN_SPEC_H
#define VAREK_V1_6_PLAN_SPEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A single Action the agent intends to execute. Mirrors the v1.4
 * Warden's Semantic Derivation output {kind, target, parameters}
 * with an extra label for pathology output. */
typedef struct {
    const char *kind;        /* "file_open", "net_connect", "process_exec", ... */
    const char *target;      /* path, "host:port", absolute exec path, ... */
    const char *parameters;  /* free-form caller-defined parameter blob; may be NULL */
    const char *label;       /* optional, surfaces in pathology records */
} plan_spec_action_t;

/* A dependency edge between two actions by index into the actions
 * array. 'to_idx' depends on 'from_idx'. */
typedef struct {
    uint32_t from_idx;
    uint32_t to_idx;
} plan_spec_edge_t;

/* The full plan declaration. */
typedef struct {
    const plan_spec_action_t *actions;
    size_t                    n_actions;
    const plan_spec_edge_t   *edges;
    size_t                    n_edges;
} plan_spec_t;

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_6_PLAN_SPEC_H */
