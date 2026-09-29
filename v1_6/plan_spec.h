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

/* v1.20.0: a field declared on a plan step (key=value after its target in a
 * plan file; see plan_parser.h). Kept apart from plan_spec_action_t so that
 * struct, and callers' initializers of it, are unchanged. */
#define PLAN_FIELDS_MAX        16u
#define PLAN_FIELD_KEY_MAX     32u
#define PLAN_FIELD_VALUE_MAX 4096u
/* v1.20.0: the longest target a plan file may declare. The Warden decides a
 * target in a 4096-byte buffer; a longer one (possible once a line may be
 * 16 KB) would be cut short and decided as a different path. */
#define PLAN_TARGET_MAX      4095u

typedef struct {
    const char *key;
    const char *value;
} plan_spec_field_t;

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
