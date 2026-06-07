// SPDX-License-Identifier: MIT
/*
 * warden_hotl_example.c — human-out-of-the-loop reference loop.
 *
 * Shows the two new layers working together:
 *
 *   STARTUP   plan_progress_verify() gates boot. A policy that is not
 *             progress-safe must not run unattended — refuse to start.
 *             This is what makes "no human at run time" provable rather
 *             than hoped: if no automated terminal is guaranteed, the
 *             system never reaches run time.
 *
 *   RUN TIME  for each submission: the (pure) decision procedure returns
 *             a verdict; plan_breaker_step() bounds the retry loop and,
 *             once the budget is spent, resolves to the policy's
 *             terminal disposition. No path waits for a person.
 *
 * The verdict here is supplied by a stub standing in for the Warden's
 * decision (over-limit check). The point of the example is the breaker
 * loop, not the check: an over-limit write is refused; a stuck planner
 * that keeps resubmitting it is bounded to an automated abort; a
 * re-planning harness reaches an authorized action instead.
 *
 * Build (standalone, links the real v1.6 kernel):
 *   see Makefile target 'hotl_example'.
 */

#define _GNU_SOURCE
#include "plan_breaker.h"
#include "plan_progress.h"
#include "plan_policy_config.h"
#include "execution_plan.h"

#include <stdio.h>
#include <string.h>

/* Stand-in for the Warden's decision on a check: refuse over the limit. */
static plan_decision_t decide_check(long amount, long authorized_limit)
{
    return (amount <= authorized_limit) ? PLAN_DEC_SATISFIED
                                        : PLAN_DEC_UNSATISFIED;
}

/* One automated agent run. 'replans' chooses the harness behavior: a
 * stuck planner resubmits the same over-limit amount; a re-planner
 * corrects toward the limit after a refusal. Returns 0 if the run
 * reached an automated terminal with no human; never blocks. */
static int run_agent(plan_breaker_t *b, const plan_label_policy_config_t *cfg,
                     const char *session, long limit, bool replans)
{
    long amount = 284;                 /* first proposal: over the limit */
    const uint64_t SIG = 0xC4EC4ULL;   /* signature for "write_check" class */

    for (int step = 1; step <= 10; step++) {
        plan_decision_t verdict = decide_check(amount, limit);

        plan_breaker_result_t r =
            plan_breaker_step(b, session, SIG, verdict, cfg);

        printf("  step %d: write_check($%ld) -> verdict=%s breaker=%s",
               step, amount, plan_decision_name(verdict),
               plan_breaker_outcome_name(r.outcome));
        if (r.outcome == PLAN_BREAKER_TERMINAL_ACTION)
            printf(" (run safe action: %s)", r.terminal_action);
        printf("\n");

        switch (r.outcome) {
        case PLAN_BREAKER_PASS:
            printf("  -> authorized; check written. Done, no human.\n");
            return 0;
        case PLAN_BREAKER_REFUSED_RETRYABLE:
            if (replans) amount = 200;   /* re-plan within the limit */
            /* else: stuck planner resubmits the same over-limit amount */
            break;
        case PLAN_BREAKER_TERMINAL_DENY:
            printf("  -> automated abort (permanent refusal). Done, no human.\n");
            return 0;
        case PLAN_BREAKER_TERMINAL_ACTION:
            printf("  -> automated fallback executed. Done, no human.\n");
            return 0;
        }
    }
    printf("  -> ERROR: loop did not terminate (should be impossible)\n");
    return 1;
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "hotl_policy.cfg";

    plan_label_policy_config_t *cfg = NULL;
    int line = 0; const char *msg = NULL;
    if (plan_label_policy_config_load(path, &cfg, &line, &msg) != 0) {
        fprintf(stderr, "policy load failed at line %d: %s\n", line, msg ? msg : "?");
        return 2;
    }

    /* STARTUP GATE: refuse to boot unattended unless certified. */
    plan_progress_finding_t f;
    plan_progress_verify(cfg, &f);
    printf("[startup] progress-safety: %s\n", plan_decision_name(f.verdict));
    printf("[startup] %s\n", f.reason);
    if (!plan_progress_certified(&f)) {
        printf("[startup] policy is NOT human-out-of-the-loop safe: %s\n", f.detail);
        printf("[startup] refusing to start unattended.\n");
        plan_label_policy_config_free(cfg);
        return 3;
    }
    printf("[startup] certified; starting unattended.\n\n");

    plan_breaker_t *b = plan_breaker_new();

    printf("Scenario A — re-planning harness:\n");
    run_agent(b, cfg, "agentA", 250, /*replans=*/true);

    printf("\nScenario B — stuck planner (same over-limit resubmit):\n");
    run_agent(b, cfg, "agentB", 250, /*replans=*/false);

    plan_breaker_free(b);
    plan_label_policy_config_free(cfg);
    return 0;
}
