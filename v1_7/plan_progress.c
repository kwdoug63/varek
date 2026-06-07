// SPDX-License-Identifier: MIT
/*
 * plan_progress.c — VAREK v1.9 progress-safety verifier.
 *
 * Static, decidable check over a finite policy. The only non-trivial
 * obligation (P4) is discharged by calling the pure decision procedure
 * on a singleton plan, so the verifier inherits exactly the
 * authorization semantics the Warden will enforce at run time.
 */

#include "plan_progress.h"

#include "execution_plan.h"
#include "plan_label_policy.h"
#include "plan_warden_binding.h"

#include <stdio.h>
#include <string.h>

static void set_finding(plan_progress_finding_t *o, plan_decision_t v,
                        const char *reason, int obligation, const char *detail)
{
    o->verdict    = v;
    o->reason     = reason;
    o->obligation = obligation;
    o->detail[0]  = '\0';
    if (detail) {
        strncpy(o->detail, detail, sizeof o->detail - 1);
        o->detail[sizeof o->detail - 1] = '\0';
    }
}

/*
 * P4 oracle. Does 'action_name' authorize as a singleton plan under
 * cfg's flow policy?
 *
 *   PLAN_DEC_SATISFIED   -> safe to use as a terminal fallback
 *   PLAN_DEC_UNSATISFIED -> the fallback is itself refused (deadlock)
 *   PLAN_DEC_UNKNOWN     -> verifier machinery failed; caller fails closed
 *
 * The node-axis decision is stamped SATISFIED: P4 verifies the FLOW
 * policy does not refuse the fallback. The node-axis permit for the
 * fallback is the deployment's responsibility and is enforced by the
 * Warden's policy_decide() at submission, exactly as for any action.
 */
static plan_decision_t fallback_authorizes(const plan_label_policy_config_t *cfg,
                                           const char *action_name)
{
    exec_plan_t *p = exec_plan_new();
    if (!p) return PLAN_DEC_UNKNOWN;

    if (exec_plan_add_node(p, action_name, PLAN_DEC_SATISFIED)
            == PLAN_NODE_ID_INVALID) {
        exec_plan_free(p);
        return PLAN_DEC_UNKNOWN;
    }

    plan_action_desc_t action = { 0 };
    action.name = action_name;

    plan_pathology_opts_t opts = plan_label_policy_config_pathology_opts(cfg);
    plan_warden_request_t req = {
        .plan             = p,
        .actions          = &action,
        .n_actions        = 1,
        .policy           = plan_label_policy_config_policy(cfg),
        .path_opts        = &opts,
        .pathology_buf    = NULL,
        .pathology_buf_sz = 0,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);
    exec_plan_free(p);

    if (rc != 0) return PLAN_DEC_UNKNOWN;
    return resp.verdict;
}

/* Check one terminal disposition against P2/P3 + P4. 'where' names the
 * directive for diagnostics. Returns the obligation number that failed
 * (0 == ok), and writes verdict/reason/detail into *o on failure. */
static int check_disposition(const plan_label_policy_config_t *cfg,
                             plan_disposition_t disp,
                             const char *where, int obligation,
                             plan_progress_finding_t *o)
{
    /* 'deny' is always a valid automated terminal. */
    if (disp.kind == PLAN_DISP_DENY)
        return 0;

    /* TERMINAL must name something. */
    if (!disp.action_name) {
        char d[256];
        snprintf(d, sizeof d, "%s: terminal disposition has no action name", where);
        set_finding(o, PLAN_DEC_UNSATISFIED,
                    "terminal disposition missing a safe action", obligation, d);
        return obligation;
    }

    /* P4(a): the safe action must be declared. */
    if (!plan_label_policy_config_has_action(cfg, disp.action_name)) {
        char d[256];
        snprintf(d, sizeof d, "%s: safe action '%s' is not a declared rule",
                 where, disp.action_name);
        set_finding(o, PLAN_DEC_UNSATISFIED,
                    "terminal disposition names an undeclared action", obligation, d);
        return obligation;
    }

    /* P4(b) static: a fallback that denies/unknowns a sticky label is
     * refused the moment that label reaches it — it cannot absorb the
     * refused flow it terminates. Sound over-approximation of deadlock. */
    if (plan_label_policy_config_action_denies_sticky(cfg, disp.action_name)) {
        char d[256];
        snprintf(d, sizeof d,
                 "%s: safe action '%s' denies a sticky label it may receive "
                 "(refuse->fallback->refuse)", where, disp.action_name);
        set_finding(o, PLAN_DEC_UNSATISFIED,
                    "fallback action is deadlock-prone (denies a sticky label)",
                    obligation, d);
        return obligation;
    }

    /* P4(b) dynamic: the safe action must authorize as a standalone
     * terminal under the flow policy (also catches verifier-machinery
     * failure as UNKNOWN -> fail closed). */
    plan_decision_t v = fallback_authorizes(cfg, disp.action_name);
    if (v == PLAN_DEC_SATISFIED)
        return 0;

    if (v == PLAN_DEC_UNKNOWN) {
        char d[256];
        snprintf(d, sizeof d, "%s: could not decide whether '%s' authorizes",
                 where, disp.action_name);
        set_finding(o, PLAN_DEC_UNKNOWN,
                    "fallback authorization undecidable; fail closed", obligation, d);
        return obligation;
    }

    /* UNSATISFIED: the fallback is itself refused -> deadlock. */
    char d[256];
    snprintf(d, sizeof d,
             "%s: safe action '%s' is itself refused (refuse->fallback->refuse)",
             where, disp.action_name);
    set_finding(o, PLAN_DEC_UNSATISFIED,
                "fallback action does not authorize (deadlock)", obligation, d);
    return obligation;
}

int plan_progress_verify(const plan_label_policy_config_t *cfg,
                         plan_progress_finding_t *out)
{
    if (!cfg || !out) return -1;

    set_finding(out, PLAN_DEC_SATISFIED,
                "policy is progress-safe (human-out-of-the-loop certified)", 0, NULL);

    const bool can_refuse = plan_label_policy_config_can_refuse(cfg);

    /* A policy that cannot refuse is trivially progress-safe: there is
     * no non-authorizing verdict to resolve. We still validate any
     * dispositions the author declared, but P1 does not apply. */
    if (can_refuse) {
        /* P1: bounded refusal. */
        if (!plan_label_policy_config_breaker_enabled(cfg)) {
            set_finding(out, PLAN_DEC_UNSATISFIED,
                        "policy can refuse but declares no refusal_budget "
                        "(unbounded retry is not human-out-of-the-loop safe)",
                        1, "add: refusal_budget N");
            return 0;
        }
    }

    /* P2: UNKNOWN disposition. UNKNOWN is reachable whenever the policy
     * has a sticky posture or any unknown_in classification; checking it
     * unconditionally is the conservative, safe choice. */
    plan_disposition_t unk = plan_label_policy_config_unknown_disposition(cfg);
    if (check_disposition(cfg, unk, "unknown_disposition", 2, out) != 0)
        return 0;

    /* P3 + P4: exhaustion disposition. Only meaningful when the breaker
     * is enabled; if it is not and the policy cannot refuse, there is no
     * exhaustion path to resolve. */
    if (plan_label_policy_config_breaker_enabled(cfg)) {
        plan_disposition_t exh = plan_label_policy_config_on_exhaustion(cfg);
        if (check_disposition(cfg, exh, "on_exhaustion", 3, out) != 0)
            return 0;
    }

    return 0;
}

bool plan_progress_certified(const plan_progress_finding_t *out)
{
    return out && out->verdict == PLAN_DEC_SATISFIED;
}
