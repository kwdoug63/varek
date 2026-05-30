// SPDX-License-Identifier: MIT
/*
 * plan_warden_binding.c — VAREK v1.7.2 Warden integration.
 *
 * Implementation of plan_warden_verify(). All companion lifetime is
 * contained in this call.
 */

#include "plan_warden_binding.h"
#include "execution_plan.h"
#include "plan_dataflow.h"
#include "plan_dataflow_adapter.h"
#include "plan_dataflow_pathology.h"
#include "plan_label_policy.h"

#include <sys/types.h>

/* Set response to a safe-refuse default. The Warden refuses on
 * PLAN_DEC_UNKNOWN, so this is the correct value for any failure
 * path. */
static void response_init_refuse(plan_warden_response_t *resp)
{
    resp->verdict            = PLAN_DEC_UNKNOWN;
    resp->node_axis          = PLAN_DEC_UNKNOWN;
    resp->flow_axis          = PLAN_DEC_UNKNOWN;
    resp->pathology_len      = 0;
    resp->pathology_overflow = false;
    resp->pathology_emitted  = false;
}

int plan_warden_verify(const plan_warden_request_t *req,
                       plan_warden_response_t *resp)
{
    if (!resp)
        return -1;
    response_init_refuse(resp);

    if (!req || !req->plan || !req->actions || !req->policy)
        return -1;

    plan_dataflow_t *df = plan_dataflow_new(req->plan);
    if (!df)
        return -1;

    if (plan_dataflow_populate(df, req->actions, req->n_actions,
                               req->policy) != 0) {
        plan_dataflow_free(df);
        return -1;
    }

    /* Compute both axes independently for reporting, then join. We
     * deliberately don't call exec_plan_verify_with_dataflow() here
     * because it discards the per-axis values we need to surface. */
    resp->node_axis = exec_plan_verify(req->plan);
    resp->flow_axis = plan_dataflow_flow_verdict(df);
    resp->verdict   = plan_decision_join(resp->node_axis, resp->flow_axis);

    /* Emit pathology iff the plan was refused AND the caller supplied
     * a buffer. A SATISFIED plan needs no refusal log; a NULL buffer
     * means the caller didn't want pathology this call. */
    if (resp->verdict != PLAN_DEC_SATISFIED &&
        req->pathology_buf && req->pathology_buf_sz > 0) {
        ssize_t n = plan_dataflow_emit_pathology_buf(df,
                                                     req->path_opts,
                                                     req->pathology_buf,
                                                     req->pathology_buf_sz);
        if (n < 0) {
            resp->pathology_overflow = true;
            resp->pathology_len      = 0;
            resp->pathology_emitted  = false;
        } else {
            resp->pathology_len      = (size_t)n;
            resp->pathology_overflow = false;
            resp->pathology_emitted  = true;
        }
    }

    plan_dataflow_free(df);
    return 0;
}

bool plan_warden_authorized(const plan_warden_response_t *resp)
{
    return resp && resp->verdict == PLAN_DEC_SATISFIED;
}
