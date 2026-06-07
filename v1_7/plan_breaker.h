// SPDX-License-Identifier: MIT
/*
 * plan_breaker.h — VAREK v1.8.2 bounded-refusal breaker.
 *
 * The decision procedure (plan_warden_verify) answers, purely and
 * statelessly, "may THIS submission run?" It has no memory and no
 * control loop: a refused plan simply returns UNSATISFIED, and what the
 * agent does next is the host's business. Left unbounded, a stuck or
 * adversarial planner can resubmit the same refused action-graph
 * forever — a self-inflicted denial of service and, in a fully
 * automated deployment, a hang that only a human could break.
 *
 * The breaker closes that loop WITHOUT putting state into the decision
 * procedure. It sits in the enforcement layer (the Warden), keyed by
 * (session, action-signature). Each individual verdict stays a pure
 * function of (plan, policy); the breaker only interprets the SEQUENCE
 * of verdicts for one signature and, once the policy's refusal budget
 * is spent, latches to a deterministic terminal disposition declared in
 * the policy. Resolution is bounded — at most 'budget' retryable
 * refusals per signature — and no outcome ever requires human
 * intervention. That is the v1.8.2 contribution: a non-bypassable loop
 * bound that lives in the trusted boundary, not in vendor harness code.
 *
 * The breaker never authors a corrected action. It returns one of four
 * outcomes; producing an alternative plan (PASS path) or executing the
 * declared safe action (TERMINAL_ACTION path) remains the host's job.
 */

#ifndef VAREK_V1_8_2_PLAN_BREAKER_H
#define VAREK_V1_8_2_PLAN_BREAKER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "execution_plan.h"      /* plan_decision_t */
#include "plan_label_policy.h"   /* plan_action_desc_t */
#include "plan_policy_config.h"  /* plan_disposition_t + breaker accessors */

#ifdef __cplusplus
extern "C" {
#endif

/* The four outcomes of advancing the breaker by one verdict. */
typedef enum {
    PLAN_BREAKER_PASS              = 0,  /* SATISFIED: authorize; counter reset */
    PLAN_BREAKER_REFUSED_RETRYABLE = 1,  /* refused, budget remains: host may re-plan */
    PLAN_BREAKER_TERMINAL_DENY     = 2,  /* terminal: permanent automated refusal */
    PLAN_BREAKER_TERMINAL_ACTION   = 3,  /* terminal: host must run .terminal_action */
} plan_breaker_outcome_t;

typedef struct plan_breaker_result {
    plan_breaker_outcome_t outcome;
    unsigned    refusals;          /* refusal count for this signature now */
    unsigned    budget;            /* effective budget (0 == breaker disabled) */
    const char *terminal_action;   /* non-NULL iff outcome == TERMINAL_ACTION */
    bool        latched;           /* signature is now in a terminal state */
} plan_breaker_result_t;

/* Opaque per-Warden breaker state. Holds the (session, signature) ->
 * refusal-count / latch table. Not internally synchronized: the Warden
 * serializes plan submissions, or guards the breaker with its own lock. */
typedef struct plan_breaker plan_breaker_t;

plan_breaker_t *plan_breaker_new(void);
void            plan_breaker_free(plan_breaker_t *b);

/* Deterministic signature of an action-graph submission: FNV-1a over
 * each node's action name and its named args, in node-id order. The
 * identical graph yields the identical signature; any change to the
 * action set, ordering, or arguments changes it. This is how "the same
 * refused thing" is identified across retries. */
uint64_t plan_breaker_signature(const plan_action_desc_t *actions,
                                size_t n_actions);

/*
 * Advance the breaker for one submission.
 *
 *   'verdict'  is exactly the value plan_warden_verify() produced
 *              (PLAN_DEC_SATISFIED / UNSATISFIED / UNKNOWN). A verifier
 *              internal error (-1 from the binding) MUST be passed here
 *              as PLAN_DEC_UNKNOWN — the binding already sets that.
 *
 *   SATISFIED      -> PASS; the signature's counter and latch are cleared
 *                     (authorization always wins; a now-authorized action
 *                     is never blocked by past refusals).
 *
 *   UNSATISFIED    -> increment the signature's counter.
 *                       counter < budget (breaker enabled) -> REFUSED_RETRYABLE
 *                       counter >= budget OR breaker disabled, see below.
 *
 *   UNKNOWN        -> routes IMMEDIATELY to unknown_disposition and latches.
 *                     (Re-running an UNKNOWN input deterministically
 *                     reproduces UNKNOWN, so retrying it would only burn
 *                     the budget to reach the same place.)
 *
 * When the budget is spent the on_exhaustion disposition fires and the
 * signature latches: every later non-SATISFIED submission of the same
 * signature returns the same terminal outcome without re-counting.
 *
 * If the breaker is DISABLED (no refusal_budget in the policy), an
 * UNSATISFIED verdict always returns REFUSED_RETRYABLE and never
 * latches — exactly the pre-v1.8.2 pass-through. The v1.9 progress
 * verifier refuses to certify such a policy when it can refuse, because
 * an unbounded refusal is not human-out-of-the-loop safe.
 *
 * Returns a fully-populated result. The call cannot fail for a non-NULL
 * breaker; under memory pressure a new table entry may not be recorded,
 * in which case the breaker fails CLOSED (treats the signature as if the
 * budget were already spent and returns the exhaustion disposition).
 */
plan_breaker_result_t plan_breaker_step(plan_breaker_t *b,
                                        const char *session_id,
                                        uint64_t signature,
                                        plan_decision_t verdict,
                                        const plan_label_policy_config_t *cfg);

/* Human-readable name for an outcome (for the refusal/decision log). */
const char *plan_breaker_outcome_name(plan_breaker_outcome_t o);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_8_2_PLAN_BREAKER_H */
