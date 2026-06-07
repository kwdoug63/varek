// SPDX-License-Identifier: MIT
/*
 * test_v19_progress.c — VAREK v1.9 progress-safety verifier tests.
 *
 * Pins the liveness contract that makes human-out-of-the-loop provable:
 *   - a complete HOTL policy (budget + terminal fallback that authorizes
 *     + unknown disposition) certifies
 *   - a refusable policy with no budget fails P1
 *   - a terminal fallback that names an undeclared action fails P4(a)
 *   - a terminal fallback that is itself refused fails P4(b) (deadlock)
 *   - on_exhaustion deny / unknown deny always certify (deny is terminal)
 *   - a policy that cannot refuse is trivially progress-safe
 *
 * Clean under -fsanitize=address,undefined.
 */

#define _GNU_SOURCE
#include "plan_progress.h"
#include "plan_policy_config.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, msg) do {                                       \
    checks++;                                                       \
    if (!(cond)) { failures++;                                      \
        printf("  FAIL: %s  (%s:%d)\n", (msg), __FILE__, __LINE__); \
    } else { printf("  ok:   %s\n", (msg)); }                       \
} while (0)

static plan_label_policy_config_t *load(const char *text)
{
    FILE *f = fmemopen((void *)text, strlen(text), "r");
    plan_label_policy_config_t *cfg = NULL;
    int line = 0; const char *msg = NULL;
    int rc = plan_label_policy_config_load_stream(f, &cfg, &line, &msg);
    if (f) fclose(f);
    if (rc != 0) { printf("  load failed line %d: %s\n", line, msg ? msg : "?"); return NULL; }
    return cfg;
}

static plan_decision_t verify(const char *text, plan_progress_finding_t *f)
{
    plan_label_policy_config_t *cfg = load(text);
    if (!cfg) { f->verdict = PLAN_DEC_UNKNOWN; return PLAN_DEC_UNKNOWN; }
    int rc = plan_progress_verify(cfg, f);
    plan_label_policy_config_free(cfg);
    if (rc != 0) { f->verdict = PLAN_DEC_UNKNOWN; }
    return f->verdict;
}

int main(void)
{
    printf("VAREK v1.9 progress-safety tests\n");
    plan_progress_finding_t f;

    /* Complete HOTL policy. abort_txn carries no SECRET and is not denied
     * anywhere, so as a singleton it authorizes -> P4 holds. */
    const char *GOOD =
        "varek_policy 1\n"
        "label SECRET 0\n"
        "sticky SECRET\n"
        "refusal_budget 3\n"
        "on_exhaustion terminal abort_txn\n"
        "unknown_disposition deny\n"
        "rule read_secret\n"
        "  origin SECRET\n"
        "rule send_http\n"
        "  deny_in SECRET\n"
        "rule abort_txn\n";
    CHECK(verify(GOOD, &f) == PLAN_DEC_SATISFIED, "complete HOTL policy certifies");
    CHECK(f.obligation == 0, "  no obligation flagged");

    /* Refusable, no budget -> P1 fails. */
    const char *NOBUDGET =
        "varek_policy 1\n"
        "label SECRET 0\n"
        "sticky SECRET\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    CHECK(verify(NOBUDGET, &f) == PLAN_DEC_UNSATISFIED, "no budget -> not certified");
    CHECK(f.obligation == 1, "  P1 (bounded refusal) flagged");

    /* Terminal fallback names an undeclared action -> P4(a). */
    const char *MISSING =
        "varek_policy 1\n"
        "label SECRET 0\n"
        "sticky SECRET\n"
        "refusal_budget 2\n"
        "on_exhaustion terminal does_not_exist\n"
        "unknown_disposition deny\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    CHECK(verify(MISSING, &f) == PLAN_DEC_UNSATISFIED, "undeclared fallback -> not certified");
    CHECK(f.obligation == 3, "  P4 flagged for undeclared fallback");

    /* Terminal fallback is itself refused -> P4(b) deadlock. The
     * fallback bad_fallback both originates and is denied SECRET, so as a
     * singleton its own egress refuses it. */
    const char *DEADLOCK =
        "varek_policy 1\n"
        "label SECRET 0\n"
        "sticky SECRET\n"
        "refusal_budget 2\n"
        "on_exhaustion terminal bad_fallback\n"
        "unknown_disposition deny\n"
        "rule bad_fallback\n"
        "  origin SECRET\n"
        "  deny_in SECRET\n";
    CHECK(verify(DEADLOCK, &f) == PLAN_DEC_UNSATISFIED, "self-refusing fallback -> not certified");
    CHECK(f.obligation == 3, "  P4 flagged for deadlock fallback");

    /* on_exhaustion deny + unknown deny: deny is always terminal. */
    const char *DENYALL =
        "varek_policy 1\n"
        "label SECRET 0\n"
        "sticky SECRET\n"
        "refusal_budget 1\n"
        "on_exhaustion deny\n"
        "unknown_disposition deny\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    CHECK(verify(DENYALL, &f) == PLAN_DEC_SATISFIED, "deny dispositions certify (abort is terminal)");

    /* Policy that cannot refuse: trivially progress-safe, no budget needed. */
    const char *PERMITALL =
        "varek_policy 1\n"
        "label PUBLIC 0\n"
        "rule anything\n"
        "  origin PUBLIC\n";
    CHECK(verify(PERMITALL, &f) == PLAN_DEC_SATISFIED, "non-refusing policy is trivially safe");

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
