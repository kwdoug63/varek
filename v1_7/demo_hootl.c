// SPDX-License-Identifier: MIT
/*
 * demo_hootl.c — VAREK v1.9 human-out-of-the-loop demonstration.
 *
 * Shows the v1.8.2 breaker and the v1.9 progress verifier resolving every
 * possible verdict path with no human at run time, and refusing to boot a
 * policy that could not.
 *
 * What is REAL here, and what is modeled:
 *   - The progress verifier (v1.9) runs for real at startup. Its P4 check
 *     submits each declared fallback to the pure decision procedure
 *     (plan_warden_verify) and requires SATISFIED, so the certificate this
 *     demo prints is produced by the real VAREK kernel, not asserted.
 *   - The breaker (v1.8.2) runs for real, keyed by real
 *     plan_breaker_signature() values over real action descriptors.
 *   - The run-time verdict for an over-limit write models the Warden's
 *     node-axis decision (policy_decide, e.g. a numeric limit). Per the
 *     documented v1.9 scope boundary, that node-axis permit is the
 *     deployment's responsibility; the flow axis and the progress proof
 *     are VAREK's. The UNKNOWN scenario injects the verdict the binding
 *     emits on an indeterminate result (-1 -> PLAN_DEC_UNKNOWN).
 *
 * The invariant the demo asserts at the end: human_interventions == 0.
 *
 * Build: see the 'demo_hootl' target in the Makefile fragment
 * (INTEGRATION-hotl.md), or:
 *   cc -std=c11 -O2 -I. -I../v1_6 demo_hootl.c \
 *      plan_dataflow.c plan_dataflow_adapter.c plan_dataflow_pathology.c \
 *      plan_warden_binding.c plan_policy_config.c plan_breaker.c \
 *      plan_progress.c ../v1_6/execution_plan.c ../v1_6/plan_evaluator.c \
 *      -o demo_hootl
 */

#define _GNU_SOURCE
#include "plan_breaker.h"
#include "plan_progress.h"
#include "plan_policy_config.h"
#include "plan_label_policy.h"
#include "execution_plan.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/* ---- presentation -------------------------------------------------- */

static bool USE_COLOR = false;

#define DIM   (USE_COLOR ? "\033[2m"  : "")
#define BOLD  (USE_COLOR ? "\033[1m"  : "")
#define RED   (USE_COLOR ? "\033[31m" : "")
#define GRN   (USE_COLOR ? "\033[32m" : "")
#define YEL   (USE_COLOR ? "\033[33m" : "")
#define CYN   (USE_COLOR ? "\033[36m" : "")
#define RST   (USE_COLOR ? "\033[0m"  : "")

static void rule(const char *title)
{
    printf("\n%s%s== %s ==%s\n", BOLD, CYN, title, RST);
}

/* ---- tallies ------------------------------------------------------- */

static struct {
    int sessions;            /* unattended agent runs started */
    int submissions;         /* total breaker steps */
    int retryable;           /* bounded intermediate refusals (expected) */
    int authorized;          /* PASS */
    int auto_terminals;      /* TERMINAL_DENY + TERMINAL_ACTION */
    int human_interventions; /* must remain 0 */
} score;

/* ---- one submission through the real breaker ----------------------- */

/* Submit one action-graph and advance the breaker. 'verdict' is what the
 * decision procedure produced for this submission. Prints the step and
 * updates the tallies. Returns the breaker outcome. */
static plan_breaker_outcome_t
submit(plan_breaker_t *b, const plan_label_policy_config_t *cfg,
       const char *session, const char *action,
       const char *arg_key, const char *arg_val,
       plan_decision_t verdict, int step)
{
    plan_action_arg_t args[1];
    size_t n_args = 0;
    if (arg_key) { args[0].key = arg_key; args[0].value = arg_val; n_args = 1; }

    plan_action_desc_t desc = {
        .name = action, .named_args = n_args ? args : NULL, .n_named_args = n_args,
    };
    uint64_t sig = plan_breaker_signature(&desc, 1);

    plan_breaker_result_t r = plan_breaker_step(b, session, sig, verdict, cfg);
    score.submissions++;

    const char *vc = (verdict == PLAN_DEC_SATISFIED) ? GRN
                   : (verdict == PLAN_DEC_UNKNOWN)    ? YEL : RED;

    printf("    step %d  %s(", step, action);
    if (n_args) printf("%s=%s", arg_key, arg_val);
    printf(")  verdict=%s%s%s  breaker=%s%s%s",
           vc, plan_decision_name(verdict), RST,
           BOLD, plan_breaker_outcome_name(r.outcome), RST);
    if (r.outcome == PLAN_BREAKER_TERMINAL_ACTION)
        printf("  -> run %s%s%s", BOLD, r.terminal_action, RST);
    printf("\n");

    if (r.outcome == PLAN_BREAKER_PASS)            score.authorized++;
    else if (r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE) score.retryable++;
    else if (r.outcome == PLAN_BREAKER_TERMINAL_DENY ||
             r.outcome == PLAN_BREAKER_TERMINAL_ACTION) score.auto_terminals++;
    return r.outcome;
}

static void resolved(const char *how)
{
    printf("    %s-> %s. No human.%s\n", GRN, how, RST);
}

/* ---- the node-axis limit decision (deployment's policy_decide) ------ */

#define LIMIT 250
static plan_decision_t decide_amount(long amount)
{
    return amount <= LIMIT ? PLAN_DEC_SATISFIED : PLAN_DEC_UNSATISFIED;
}

/* ---- startup gate -------------------------------------------------- */

/* Load 'path' and certify it. Returns the loaded cfg on certify, or NULL
 * (after freeing) if it is not progress-safe. 'expect_certified' only
 * shapes the narration. */
static plan_label_policy_config_t *
boot(const char *path, bool expect_certified)
{
    plan_label_policy_config_t *cfg = NULL;
    int line = 0; const char *msg = NULL;
    if (plan_label_policy_config_load(path, &cfg, &line, &msg) != 0) {
        printf("    load failed at line %d: %s\n", line, msg ? msg : "?");
        return NULL;
    }

    plan_progress_finding_t f;
    plan_progress_verify(cfg, &f);

    const char *vc = plan_progress_certified(&f) ? GRN : RED;
    printf("    policy: %s%s%s\n", DIM, path, RST);
    printf("    progress-safety: %s%s%s  (%s)\n",
           vc, plan_decision_name(f.verdict), RST, f.reason);

    if (!plan_progress_certified(&f)) {
        printf("    %sobligation P%d failed: %s%s\n",
               RED, f.obligation, f.detail, RST);
        printf("    %s-> refusing to start unattended (exit 3).%s\n", RED, RST);
        plan_label_policy_config_free(cfg);
        (void)expect_certified;
        return NULL;
    }
    printf("    %s-> certified human-out-of-the-loop; starting unattended.%s\n",
           GRN, RST);
    return cfg;
}

/* ---- main ---------------------------------------------------------- */

int main(int argc, char **argv)
{
    USE_COLOR = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");

    const char *good = (argc > 1) ? argv[1] : "hotl_policy.cfg";
    const char *bad  = (argc > 2) ? argv[2] : "uncertified_policy.cfg";

    printf("%s%sVAREK v1.9 — human-out-of-the-loop demonstration%s\n",
           BOLD, CYN, RST);
    printf("%sCertify the policy can always resolve without a human, then run "
           "unattended.%s\n", DIM, RST);

    /* 1. The negative case first: a policy that can refuse but cannot
     *    prove it always resolves is refused at boot. */
    rule("STARTUP 1/2  reject a policy that is not progress-safe");
    if (boot(bad, false) != NULL) {
        fprintf(stderr, "demo error: uncertified policy was certified\n");
        return 1;
    }

    /* 2. The certified policy boots. P4 ran the real decision procedure. */
    rule("STARTUP 2/2  certify and boot the real policy");
    plan_label_policy_config_t *cfg = boot(good, true);
    if (!cfg) {
        fprintf(stderr, "demo error: expected '%s' to certify\n", good);
        return 1;
    }

    plan_breaker_t *b = plan_breaker_new();

    /* Each scenario is one unattended agent session. Every path ends in an
     * automated outcome; none increments human_interventions. */

    rule("RUN  scenario 1/4  in-policy action authorizes");
    score.sessions++;
    printf("  %sagent writes a check within its limit.%s\n", DIM, RST);
    if (submit(b, cfg, "s1", "write_check", "amount", "200",
               decide_amount(200), 1) == PLAN_BREAKER_PASS)
        resolved("authorized; check written");

    rule("RUN  scenario 2/4  refusal, re-planning harness resolves in-budget");
    score.sessions++;
    printf("  %sfirst proposal is over the limit; the harness re-plans "
           "monotonically (clamps toward the limit).%s\n", DIM, RST);
    {
        long amount = 284; int step = 1;
        for (;;) {
            plan_breaker_outcome_t o =
                submit(b, cfg, "s2", "write_check", "amount",
                       amount == 284 ? "284" : "200",
                       decide_amount(amount), step++);
            if (o == PLAN_BREAKER_PASS) { resolved("authorized; check written"); break; }
            if (o == PLAN_BREAKER_REFUSED_RETRYABLE) { amount = 200; continue; }
            resolved("automated terminal"); break;
        }
    }

    rule("RUN  scenario 3/4  stuck planner bounded to an automated fallback");
    score.sessions++;
    printf("  %sa stuck or adversarial planner resubmits the identical "
           "over-limit action; the budget (3) is spent, then the "
           "pre-authorized fallback fires.%s\n", DIM, RST);
    {
        int step = 1;
        for (;;) {
            plan_breaker_outcome_t o =
                submit(b, cfg, "s3", "write_check", "amount", "284",
                       decide_amount(284), step++);
            if (o == PLAN_BREAKER_REFUSED_RETRYABLE) continue;       /* same input again */
            if (o == PLAN_BREAKER_TERMINAL_ACTION) { resolved("pre-authorized abort_txn executed"); break; }
            if (o == PLAN_BREAKER_TERMINAL_DENY)   { resolved("automated abort"); break; }
            resolved("authorized"); break;
        }
    }

    rule("RUN  scenario 4/4  indeterminate verdict disposed without a human");
    score.sessions++;
    printf("  %sthe decision procedure returns UNKNOWN (the binding's "
           "-1 maps here). UNKNOWN is never retried — a re-run reproduces "
           "it — so it goes straight to the policy's unknown_disposition.%s\n",
           DIM, RST);
    {
        plan_breaker_outcome_t o =
            submit(b, cfg, "s4", "write_check", "amount", "999",
                   PLAN_DEC_UNKNOWN, 1);
        if (o == PLAN_BREAKER_TERMINAL_DENY) resolved("automated deny (task aborted)");
        else if (o == PLAN_BREAKER_TERMINAL_ACTION) resolved("automated fallback executed");
    }

    /* ---- scoreboard ---- */
    rule("RESULT");
    printf("    unattended sessions ....... %d\n", score.sessions);
    printf("    submissions ............... %d  (= %d resolved + %d bounded retries)\n",
           score.submissions, score.authorized + score.auto_terminals, score.retryable);
    printf("    authorized (executed) ..... %d\n", score.authorized);
    printf("    automated terminals ....... %d\n", score.auto_terminals);
    printf("    %shuman interventions ....... %d%s\n",
           score.human_interventions == 0 ? GRN : RED,
           score.human_interventions, RST);

    bool ok = (score.human_interventions == 0) &&
              (score.authorized + score.auto_terminals == score.sessions);
    printf("\n    %s%s%s\n", ok ? GRN : RED, BOLD,
           ok ? "every session resolved automatically; no human in the loop"
              : "INVARIANT VIOLATED");
    printf("%s", RST);

    plan_breaker_free(b);
    plan_label_policy_config_free(cfg);
    return ok ? 0 : 1;
}
