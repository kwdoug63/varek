// SPDX-License-Identifier: MIT
/*
 * plan_progress.h — VAREK v1.9 progress-safety verifier.
 *
 * v1.6-v1.8 prove SAFETY: nothing unauthorized executes. They do not
 * prove LIVENESS: that the system always has a legal, automated next
 * move. A human-out-of-the-loop deployment needs both. Without a
 * liveness proof, "never requires a human" is a hope — the policy could
 * admit a reachable state in which an action is refused and no
 * authorized fallback exists, a deadlock only a human could break.
 *
 * The progress verifier discharges that obligation at policy load time,
 * once, before anything runs. It certifies the theorem:
 *
 *   For every non-authorizing verdict (UNSATISFIED or UNKNOWN) the
 *   policy can produce, the v1.8.2 breaker's deterministic resolution
 *   reaches an automated terminal outcome in finitely many steps, with
 *   no point requiring human intervention.
 *
 * It decomposes into four obligations:
 *
 *   P1  Bounded refusal. If the policy can refuse at all, a
 *       refusal_budget >= 1 must be declared. An unbounded refusal is a
 *       potential infinite retry loop.
 *
 *   P2  Disposed UNKNOWN. unknown_disposition must be terminal (deny, or
 *       a terminal action that satisfies P4). 'deny' is always terminal.
 *
 *   P3  Disposed exhaustion. on_exhaustion must be terminal (same).
 *
 *   P4  Authorized fallback (the reachability proof). Every terminal
 *       disposition that names a safe action must (a) name a declared
 *       rule and (b) have that action PROVABLY AUTHORIZE under this same
 *       policy. If a fallback could itself be refused, the resolution
 *       cycles (refuse -> fallback -> refuse -> ...) and never
 *       terminates without a human. P4 is discharged by submitting the
 *       fallback as a singleton plan to the pure decision procedure
 *       (plan_warden_verify) and requiring SATISFIED — the progress
 *       verifier composes the verifier it sits above as its oracle.
 *
 * A 'deny' disposition is always a valid automated terminal sink (the
 * host aborts the task). Whether abort is operationally acceptable is
 * the author's call; the verifier guarantees only that SOME automated
 * terminal always exists, never a hang.
 *
 * The result is itself three-state, matching VAREK semantics:
 *   SATISFIED   - certified progress-safe (human-out-of-the-loop).
 *   UNSATISFIED - a concrete gap was found; 'detail' names it.
 *   UNKNOWN     - the verifier could not decide (e.g. allocation
 *                 failure); fail closed, treat as NOT certified.
 */

#ifndef VAREK_V1_9_PLAN_PROGRESS_H
#define VAREK_V1_9_PLAN_PROGRESS_H

#include <stdbool.h>

#include "execution_plan.h"      /* plan_decision_t */
#include "plan_policy_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct plan_progress_finding {
    plan_decision_t verdict;      /* SATISFIED / UNSATISFIED / UNKNOWN */
    const char     *reason;       /* static summary string */
    char            detail[256];  /* concrete gap (action name, etc.) */
    int             obligation;   /* which of P1..P4 fired (0 if certified) */
} plan_progress_finding_t;

/* Verify the policy is progress-safe. Returns 0 with *out populated
 * (consult out->verdict), or -1 on bad arguments (NULL cfg/out). */
int plan_progress_verify(const plan_label_policy_config_t *cfg,
                         plan_progress_finding_t *out);

/* Convenience: true iff out->verdict == PLAN_DEC_SATISFIED. */
bool plan_progress_certified(const plan_progress_finding_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_9_PLAN_PROGRESS_H */
