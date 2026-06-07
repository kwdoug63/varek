// SPDX-License-Identifier: MIT
/*
 * test_v18_2_breaker.c — VAREK v1.8.2 bounded-refusal breaker tests.
 *
 * Pins the loop-bound contract:
 *   - SATISFIED passes and clears history
 *   - UNSATISFIED is retryable until the budget, then latches terminal
 *   - latched signatures replay the terminal outcome idempotently
 *   - UNKNOWN routes immediately to its disposition (no retries)
 *   - terminal-action vs deny dispositions surface correctly
 *   - distinct signatures and sessions keep independent counters
 *   - a now-SATISFIED verdict clears a latched signature
 *   - disabled breaker never latches (pre-v1.8.2 pass-through)
 *   - signatures are deterministic and argument-sensitive
 *
 * Clean under -fsanitize=address,undefined.
 */

#define _GNU_SOURCE
#include "plan_breaker.h"
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
    if (rc != 0) {
        printf("  policy load failed line %d: %s\n", line, msg ? msg : "?");
        return NULL;
    }
    return cfg;
}

int main(void)
{
    printf("VAREK v1.8.2 breaker tests\n");

    /* Policy: budget 3, exhaustion fires a safe action, unknown denies. */
    const char *POL =
        "varek_policy 1\n"
        "label SECRET 0\n"
        "sticky SECRET\n"
        "refusal_budget 3\n"
        "on_exhaustion terminal abort_txn\n"
        "unknown_disposition deny\n"
        "rule abort_txn\n";
    plan_label_policy_config_t *cfg = load(POL);
    CHECK(cfg != NULL, "policy with breaker directives loads");
    if (!cfg) return 1;

    CHECK(plan_label_policy_config_breaker_enabled(cfg), "breaker enabled");
    CHECK(plan_label_policy_config_refusal_budget(cfg) == 3, "budget parsed = 3");
    plan_disposition_t exh = plan_label_policy_config_on_exhaustion(cfg);
    CHECK(exh.kind == PLAN_DISP_TERMINAL &&
          exh.action_name && strcmp(exh.action_name, "abort_txn") == 0,
          "on_exhaustion = terminal abort_txn");
    plan_disposition_t unk = plan_label_policy_config_unknown_disposition(cfg);
    CHECK(unk.kind == PLAN_DISP_DENY, "unknown_disposition = deny");

    plan_breaker_t *b = plan_breaker_new();
    CHECK(b != NULL, "breaker allocates");

    uint64_t sig = 0xABCDEF12u;  /* stand-in signature for this test */

    /* Three retryable refusals, then latch to terminal action. */
    plan_breaker_result_t r;
    r = plan_breaker_step(b, "sess-1", sig, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.refusals == 1,
          "refusal 1 retryable");
    r = plan_breaker_step(b, "sess-1", sig, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.refusals == 2,
          "refusal 2 retryable");
    r = plan_breaker_step(b, "sess-1", sig, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.refusals == 3 &&
          r.terminal_action && strcmp(r.terminal_action, "abort_txn") == 0 &&
          r.latched,
          "refusal 3 == budget -> terminal action abort_txn, latched");

    /* Latched: further non-SATISFIED replays terminal idempotently. */
    r = plan_breaker_step(b, "sess-1", sig, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.latched,
          "latched signature replays terminal action");

    /* A different signature in the same session is independent. */
    r = plan_breaker_step(b, "sess-1", 0x999u, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.refusals == 1,
          "distinct signature has its own counter");

    /* A different session with the same signature is independent. */
    r = plan_breaker_step(b, "sess-2", sig, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.refusals == 1,
          "distinct session has its own counter");

    /* SATISFIED clears the latched signature. */
    r = plan_breaker_step(b, "sess-1", sig, PLAN_DEC_SATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_PASS, "SATISFIED passes");
    r = plan_breaker_step(b, "sess-1", sig, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.refusals == 1,
          "counter reset after SATISFIED");

    /* UNKNOWN routes immediately to deny, no retries consumed. */
    r = plan_breaker_step(b, "sess-3", 0x1234u, PLAN_DEC_UNKNOWN, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_DENY && r.latched,
          "UNKNOWN -> immediate terminal deny");

    plan_breaker_free(b);
    plan_label_policy_config_free(cfg);

    /* Disabled breaker (no refusal_budget): never latches. */
    const char *POL2 =
        "varek_policy 1\n"
        "label SECRET 0\n"
        "sticky SECRET\n"
        "rule noop\n";
    plan_label_policy_config_t *cfg2 = load(POL2);
    CHECK(cfg2 && !plan_label_policy_config_breaker_enabled(cfg2),
          "no budget -> breaker disabled");
    plan_breaker_t *b2 = plan_breaker_new();
    for (int i = 0; i < 100; i++)
        r = plan_breaker_step(b2, "s", 0x42u, PLAN_DEC_UNSATISFIED, cfg2);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && !r.latched,
          "disabled breaker stays retryable forever (pre-v1.8.2 behavior)");
    plan_breaker_free(b2);
    plan_label_policy_config_free(cfg2);

    /* Signature determinism + argument sensitivity. */
    plan_action_arg_t a1[] = { { "amount", "200" } };
    plan_action_arg_t a2[] = { { "amount", "284" } };
    plan_action_desc_t p200 = { .name = "write_check", .named_args = a1, .n_named_args = 1 };
    plan_action_desc_t p284 = { .name = "write_check", .named_args = a2, .n_named_args = 1 };
    uint64_t s200a = plan_breaker_signature(&p200, 1);
    uint64_t s200b = plan_breaker_signature(&p200, 1);
    uint64_t s284  = plan_breaker_signature(&p284, 1);
    CHECK(s200a == s200b, "signature is deterministic");
    CHECK(s200a != s284,  "signature is argument-sensitive ($200 != $284)");

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
