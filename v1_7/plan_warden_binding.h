// SPDX-License-Identifier: MIT
/*
 * plan_warden_binding.h — VAREK v1.7.2 Warden integration.
 *
 * Single entry point for the Warden's `--plan` gate to run the full
 * v1.7 pipeline:
 *   1. plan_dataflow_new       (companion allocation)
 *   2. plan_dataflow_populate  (label policy classifies each action)
 *   3. exec_plan_verify        (v1.6 node-axis verdict)
 *   4. plan_dataflow_flow_verdict  (v1.7 flow-axis verdict)
 *   5. plan_decision_join      (two-axis verdict)
 *   6. plan_dataflow_emit_pathology_buf  (only on refusal, only if
 *                              the caller supplied a buffer)
 *   7. plan_dataflow_free      (companion lifetime ends with the call)
 *
 * The companion's lifetime is entirely inside this call. The Warden
 * does not own it, does not need to free it, and cannot leak it.
 *
 * The two-axis verdict is the value the Warden must consult to gate
 * execution. The per-axis verdicts are returned alongside so the
 * refusal log can record which axis fired.
 *
 * This is NOT on the per-syscall hot path. It runs once at plan
 * submission. Allocation of the companion (~150 KB) is acceptable
 * here; the per-syscall path remains the v1.4 Warden's existing
 * policy_decide().
 *
 * Layered above the v1.6.1 adapter (which calls policy_decide() to
 * stamp node-axis decisions on the plan before this binding sees it).
 * The action array passed here MUST be the same one — in node-id
 * order — that the v1.6.1 adapter used.
 */

#ifndef VAREK_V1_7_PLAN_WARDEN_BINDING_H
#define VAREK_V1_7_PLAN_WARDEN_BINDING_H

#include <stdbool.h>
#include <stddef.h>

#include "execution_plan.h"
#include "plan_dataflow.h"
#include "plan_dataflow_pathology.h"
#include "plan_label_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Inputs to the verification call. All const pointers are borrowed;
 * the binding does not retain any of them past the call. */
typedef struct plan_warden_request {
    const exec_plan_t            *plan;          /* required */
    const plan_action_desc_t     *actions;       /* required, len == plan node count */
    size_t                        n_actions;
    const plan_label_policy_t    *policy;        /* required */
    const plan_pathology_opts_t  *path_opts;     /* optional; may be NULL */

    /* Optional pathology buffer. NULL or zero size means the binding
     * computes the verdict but emits no pathology JSON. A non-NULL
     * buffer is filled ONLY when the verdict is not SATISFIED. */
    char   *pathology_buf;
    size_t  pathology_buf_sz;
} plan_warden_request_t;

/* Outputs. Always fully populated on a successful call (return 0).
 * On failure (return -1), the verdict fields are set to UNKNOWN and
 * must not be trusted — the Warden MUST refuse execution. */
typedef struct plan_warden_response {
    plan_decision_t verdict;        /* two-axis joined verdict */
    plan_decision_t node_axis;      /* v1.6 verdict alone */
    plan_decision_t flow_axis;      /* v1.7 verdict alone */

    /* Pathology emission state. pathology_len is the number of bytes
     * written to the caller's buffer (0 if none). pathology_overflow
     * is true iff the buffer was too small for the full JSON — in
     * that case pathology_len is 0 and the buffer contents are
     * undefined. */
    size_t  pathology_len;
    bool    pathology_overflow;
    bool    pathology_emitted;      /* true iff a record was written */
} plan_warden_response_t;

/*
 * Run the full v1.7.2 verification pipeline.
 *
 * Returns:
 *    0  on success — verdict/axis fields populated; pathology_buf
 *       contains a complete JSON record iff verdict != SATISFIED
 *       AND a buffer was supplied AND it was large enough.
 *   -1  on internal error — NULL request/response, missing required
 *       fields, populate failure, or companion allocation failure.
 *       Response verdict fields are all set to PLAN_DEC_UNKNOWN as
 *       a safe default; the Warden MUST refuse on -1 just as it
 *       refuses on UNSATISFIED.
 *
 * 'Internal error' is distinct from 'verdict UNSATISFIED'. A refused
 * plan returns 0 with verdict UNSATISFIED (or UNKNOWN); only a broken
 * verification machinery returns -1. Both cases require the Warden
 * to refuse; -1 is the stronger signal that something is wrong with
 * the verifier itself, not the plan.
 */
int plan_warden_verify(const plan_warden_request_t *req,
                       plan_warden_response_t *resp);

/* Convenience predicate: true iff resp->verdict == PLAN_DEC_SATISFIED.
 * The Warden's authorization gate. */
bool plan_warden_authorized(const plan_warden_response_t *resp);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_7_PLAN_WARDEN_BINDING_H */
