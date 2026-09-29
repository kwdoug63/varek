// SPDX-License-Identifier: MIT
/*
 * test_v119.c — VAREK v1.19.0: the session's refusal limit.
 *
 * refusal_budget bounds resubmissions of ONE plan (one signature). Through
 * v1.18.0 a planner that changed one step each time got a fresh count every
 * time. session_refusal_budget bounds the refused submissions of a whole
 * session, whatever plans they are.
 *
 *   1. The directive parses, and bad forms are refused.
 *   2. A planner that changes the plan each time is stopped at the limit.
 *   3. An authorized plan still passes, and does not reset the count.
 *   4. UNKNOWN counts; replays of a latched plan do not; sessions are separate.
 *   5. With no session limit declared, the count is kept but never latches.
 *   6. The count and the latch survive a save/load round trip; a v1.18.0
 *      (version 1) table loads; malformed session lines are refused.
 */

#define _POSIX_C_SOURCE 200809L

#include "plan_breaker.h"
#include "plan_label_policy.h"
#include "plan_policy_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_pass;

#define CHECK(cond, msg) do {                                       \
    if (cond) { g_pass++; printf("  ok:   %s\n", msg); }             \
    else      { g_fail++; printf("  FAIL: %s\n", msg); }             \
} while (0)

static plan_label_policy_config_t *load_cfg(const char *text, int *line, const char **msg)
{
    FILE *f = fmemopen((void *)text, strlen(text), "r");
    if (!f) return NULL;
    plan_label_policy_config_t *cfg = NULL;
    int l = 0;
    const char *m = NULL;
    if (plan_label_policy_config_load_stream(f, &cfg, &l, &m) != 0) cfg = NULL;
    fclose(f);
    if (line) *line = l;
    if (msg) *msg = m;
    return cfg;
}

#define POLICY_HEAD            \
    "varek_policy 1\n"         \
    "label SECRET 0\n"         \
    "sticky SECRET\n"

#define POLICY_RULES           \
    "rule read_balance\n"      \
    "  origin SECRET\n"        \
    "rule write_check\n"       \
    "  deny_in SECRET\n"       \
    "rule abort_txn\n"

/* Per plan 3, per session 4, a terminal action on exhaustion. */
static const char *kSessionPolicy =
    POLICY_HEAD
    "refusal_budget 3\n"
    "session_refusal_budget 4\n"
    "on_exhaustion terminal abort_txn\n"
    "unknown_disposition deny\n"
    POLICY_RULES;

/* Same, no session limit. */
static const char *kPlanOnlyPolicy =
    POLICY_HEAD
    "refusal_budget 3\n"
    "on_exhaustion deny\n"
    POLICY_RULES;

/* Session limit 2, deny on exhaustion. */
static const char *kSmallPolicy =
    POLICY_HEAD
    "refusal_budget 5\n"
    "session_refusal_budget 2\n"
    "on_exhaustion deny\n"
    "unknown_disposition deny\n"
    POLICY_RULES;

static void test_parse(void)
{
    printf("-- 1. the directive parses; bad forms are refused\n");
    plan_label_policy_config_t *cfg = load_cfg(kSessionPolicy, NULL, NULL);
    CHECK(cfg && plan_label_policy_config_session_refusal_budget(cfg) == 4,
          "session_refusal_budget 4 is read");
    plan_label_policy_config_free(cfg);
    cfg = load_cfg(kPlanOnlyPolicy, NULL, NULL);
    CHECK(cfg && plan_label_policy_config_session_refusal_budget(cfg) == 0,
          "absent means no session limit (0)");
    plan_label_policy_config_free(cfg);

    struct { const char *text, *why; } bad[] = {
        { POLICY_HEAD "refusal_budget 3\nsession_refusal_budget 0\n" POLICY_RULES, "0 is refused" },
        { POLICY_HEAD "refusal_budget 3\nsession_refusal_budget -1\n" POLICY_RULES, "a negative number is refused" },
        { POLICY_HEAD "refusal_budget 3\nsession_refusal_budget 4x\n" POLICY_RULES, "a non-number is refused" },
        { POLICY_HEAD "refusal_budget 3\nsession_refusal_budget\n" POLICY_RULES, "a missing number is refused" },
        { POLICY_HEAD "refusal_budget 3\nsession_refusal_budget 4 5\n" POLICY_RULES, "an extra token is refused" },
        { POLICY_HEAD "refusal_budget 3\nsession_refusal_budget 1000001\n" POLICY_RULES, "more than 1000000 is refused" },
        { POLICY_HEAD "refusal_budget 3\nsession_refusal_budget 4\nsession_refusal_budget 5\n" POLICY_RULES,
          "a duplicate is refused" },
        { POLICY_HEAD "session_refusal_budget 4\n" POLICY_RULES, "without refusal_budget it is refused" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        const char *msg = NULL;
        cfg = load_cfg(bad[i].text, NULL, &msg);
        CHECK(cfg == NULL && msg && strstr(msg, "session_refusal_budget"), bad[i].why);
        plan_label_policy_config_free(cfg);
    }
}

static void test_changing_plans(void)
{
    printf("-- 2. a planner that changes the plan each time is stopped\n");
    plan_label_policy_config_t *cfg = load_cfg(kSessionPolicy, NULL, NULL);
    if (!cfg) { CHECK(0, "policy loads"); return; }
    plan_breaker_t *b = plan_breaker_new();
    plan_breaker_result_t r;
    for (uint64_t sig = 1; sig <= 3; sig++) {
        r = plan_breaker_step(b, "s", sig, PLAN_DEC_UNSATISFIED, cfg);
        char m[96];
        snprintf(m, sizeof m, "plan %llu: retryable (session %u of 4)", (unsigned long long)sig,
                 (unsigned)sig);
        CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.refusals == 1 &&
              r.session_refusals == sig && r.session_budget == 4 && !r.session_exhausted, m);
    }
    r = plan_breaker_step(b, "s", 4, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.terminal_action &&
          strcmp(r.terminal_action, "abort_txn") == 0 && r.session_exhausted &&
          r.session_refusals == 4 && r.refusals == 1,
          "the 4th different plan is terminal (on_exhaustion), though it was refused once");
    r = plan_breaker_step(b, "s", 5, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.session_exhausted && r.latched &&
          r.session_refusals == 4,
          "a 5th, new plan is terminal at once and not counted again");
    r = plan_breaker_step(b, "s", 1, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.session_exhausted,
          "an earlier plan with budget left is now terminal too");

    printf("-- 3. an authorized plan passes and does not reset the count\n");
    r = plan_breaker_step(b, "s", 6, PLAN_DEC_SATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_PASS && r.session_refusals == 4,
          "a SATISFIED plan passes after the limit");
    r = plan_breaker_step(b, "s", 7, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.session_exhausted,
          "the next refused plan is still terminal");
    plan_breaker_free(b);

    /* Interleaving authorized plans does not buy more retries either. */
    b = plan_breaker_new();
    unsigned retryable = 0;
    for (uint64_t i = 0; i < 20; i++) {
        (void)plan_breaker_step(b, "t", 1000 + i, PLAN_DEC_SATISFIED, cfg);
        r = plan_breaker_step(b, "t", 2000 + i, PLAN_DEC_UNSATISFIED, cfg);
        if (r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE) retryable++;
    }
    CHECK(retryable == 3, "with an authorized plan between each, still 3 retryable refusals in all");

    /* The per-plan limit still applies while the session has room. */
    r = plan_breaker_step(b, "u", 42, PLAN_DEC_UNSATISFIED, cfg);
    r = plan_breaker_step(b, "u", 42, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.refusals == 2, "same plan twice: retryable");
    r = plan_breaker_step(b, "u", 42, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && !r.session_exhausted && r.session_refusals == 3,
          "the same plan a 3rd time is terminal by its own budget; the session is not spent");
    r = plan_breaker_step(b, "u", 43, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.session_exhausted && r.session_refusals == 4,
          "a different plan then spends the session's 4th");
    plan_breaker_free(b);
    plan_label_policy_config_free(cfg);
}

static void test_unknown_replay_sessions(void)
{
    printf("-- 4. UNKNOWN counts; replays do not; sessions are separate\n");
    plan_label_policy_config_t *cfg = load_cfg(kSmallPolicy, NULL, NULL);
    if (!cfg) { CHECK(0, "policy loads"); return; }
    plan_breaker_t *b = plan_breaker_new();
    plan_breaker_result_t r = plan_breaker_step(b, "a", 1, PLAN_DEC_UNKNOWN, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_DENY && r.session_refusals == 1 && !r.session_exhausted,
          "UNKNOWN is terminal for its plan and counts 1 for the session");
    for (int i = 0; i < 5; i++) r = plan_breaker_step(b, "a", 1, PLAN_DEC_UNKNOWN, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_DENY && r.session_refusals == 1,
          "replaying the latched plan does not count again");
    r = plan_breaker_step(b, "b", 9, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.session_refusals == 1,
          "another session has its own count");
    r = plan_breaker_step(b, "a", 2, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_DENY && r.session_exhausted && r.session_refusals == 2,
          "after an UNKNOWN, one more refusal spends a limit of 2");
    r = plan_breaker_step(b, "b", 10, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_DENY && r.session_exhausted && r.session_refusals == 2,
          "session b reaches its own limit independently");
    r = plan_breaker_step(b, "c", 1, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE, "a new session starts at zero");
    r = plan_breaker_step(b, "c", 2, PLAN_DEC_UNKNOWN, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_DENY && r.session_exhausted && r.session_refusals == 2,
          "an UNKNOWN that is the session's 2nd refusal latches the session");
    r = plan_breaker_step(b, "c", 3, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_TERMINAL_DENY && r.session_exhausted && r.session_refusals == 2,
          "the next new plan is terminal at once, not counted");
    r = plan_breaker_step(b, "c", 4, PLAN_DEC_SATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_PASS && r.session_exhausted && r.session_refusals == 2,
          "an authorized plan in it passes, and reports the session as exhausted");
    r = plan_breaker_step(b, NULL, 1, PLAN_DEC_UNSATISFIED, cfg);
    CHECK(r.outcome == PLAN_BREAKER_REFUSED_RETRYABLE && r.session_refusals == 1,
          "the unnamed session is counted too");
    plan_breaker_free(b);
    plan_label_policy_config_free(cfg);
}

static void test_no_session_limit(void)
{
    printf("-- 5. no session limit: counted, never latched\n");
    plan_label_policy_config_t *cfg = load_cfg(kPlanOnlyPolicy, NULL, NULL);
    if (!cfg) { CHECK(0, "policy loads"); return; }
    plan_breaker_t *b = plan_breaker_new();
    plan_breaker_result_t r;
    bool all_retryable = true;
    for (uint64_t sig = 1; sig <= 50; sig++) {
        r = plan_breaker_step(b, "s", sig, PLAN_DEC_UNSATISFIED, cfg);
        if (r.outcome != PLAN_BREAKER_REFUSED_RETRYABLE || r.session_exhausted) all_retryable = false;
    }
    CHECK(all_retryable && r.session_refusals == 50 && r.session_budget == 0,
          "50 different refused plans are all retryable (the v1.18.0 behavior); the count is 50");
    plan_breaker_free(b);
    plan_label_policy_config_free(cfg);
}

static plan_breaker_t *round_trip(const plan_breaker_t *b, const plan_label_policy_config_t *cfg,
                                  char **text_out)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (!f) return NULL;
    int rc = plan_breaker_save(b, f);
    fclose(f);
    if (rc != 0) { free(buf); return NULL; }
    FILE *in = fmemopen(buf, len, "r");
    plan_breaker_t *nb = plan_breaker_new();
    if (!in || !nb || plan_breaker_load(nb, in, cfg) != 0) {
        if (in) fclose(in);
        plan_breaker_free(nb);
        free(buf);
        return NULL;
    }
    fclose(in);
    if (text_out) *text_out = buf; else free(buf);
    return nb;
}

static plan_breaker_t *load_text(const char *text, const plan_label_policy_config_t *cfg)
{
    FILE *in = fmemopen((void *)text, strlen(text), "r");
    plan_breaker_t *b = plan_breaker_new();
    if (!in || !b || plan_breaker_load(b, in, cfg) != 0) {
        if (in) fclose(in);
        plan_breaker_free(b);
        return NULL;
    }
    fclose(in);
    return b;
}

static void test_persistence(void)
{
    printf("-- 6. the session's count and latch persist\n");
    plan_label_policy_config_t *cfg = load_cfg(kSessionPolicy, NULL, NULL);
    if (!cfg) { CHECK(0, "policy loads"); return; }
    plan_breaker_t *b = plan_breaker_new();
    plan_breaker_result_t r;
    for (uint64_t sig = 1; sig <= 3; sig++) r = plan_breaker_step(b, "run 7", sig, PLAN_DEC_UNSATISFIED, cfg);
    char *text = NULL;
    plan_breaker_t *b2 = round_trip(b, cfg, &text);
    CHECK(b2 != NULL, "a table with sessions saves and loads");
    CHECK(text && strstr(text, "varek-breaker 2\n") == text &&
          strstr(text, "\nsession 72756e2037 3 0 2 -\n") && strstr(text, "\nend 4\n"),
          "the file holds a session line and counts it in the trailer");
    free(text);
    if (b2) {
        r = plan_breaker_step(b2, "run 7", 99, PLAN_DEC_UNSATISFIED, cfg);
        CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.session_exhausted && r.session_refusals == 4,
              "after a reload, a new plan spends the session's 4th: terminal");
        plan_breaker_t *b3 = round_trip(b2, cfg, NULL);
        CHECK(b3 != NULL, "the latched session saves and loads");
        if (b3) {
            r = plan_breaker_step(b3, "run 7", 100, PLAN_DEC_UNSATISFIED, cfg);
            CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.terminal_action &&
                  strcmp(r.terminal_action, "abort_txn") == 0 && r.session_exhausted,
                  "after another reload the session is still latched");
            plan_breaker_free(b3);
        }
        plan_breaker_free(b2);
    }
    plan_breaker_free(b);

    /* A v1.18.0 table: each session starts from its entries' refusals. */
    plan_breaker_t *v1 = load_text("varek-breaker 1\n"
                                   "72756e2037 0000000000000001 2 0 2 -\n"
                                   "72756e2037 0000000000000002 1 0 2 -\n"
                                   "end 2\n", cfg);
    CHECK(v1 != NULL, "a version 1 table loads");
    if (v1) {
        r = plan_breaker_step(v1, "run 7", 3, PLAN_DEC_UNSATISFIED, cfg);
        CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.session_refusals == 4 && r.session_exhausted,
              "its session starts at 3 (the refusals its plans hold), so the next is the 4th");
        plan_breaker_free(v1);
    }

    struct { const char *text, *why; } bad[] = {
        { "varek-breaker 1\nsession - 1 0 2 -\nend 1\n", "a session line in a version 1 table is refused" },
        { "varek-breaker 2\nsession - 1 0 2 -\nsession - 2 0 2 -\nend 2\n", "a duplicate session is refused" },
        { "varek-breaker 2\nsession - 1 0 2 -\nend 0\n", "a trailer that does not count the session is refused" },
        { "varek-breaker 2\nsession - x 0 2 -\nend 1\n", "a non-numeric count is refused" },
        { "varek-breaker 2\nsession - 1 2 2 -\nend 1\n", "a bad latch flag is refused" },
        { "varek-breaker 2\nsession - 1 0 0 -\nend 1\n", "a bad outcome is refused" },
        { "varek-breaker 2\nsession 7a 1 0 2 - extra\nend 1\n", "an extra token is refused" },
        { "varek-breaker 2\nsession 7 1 0 2 -\nend 1\n", "an odd-length session is refused" },
        { "varek-breaker 2\nsession 00 1 0 2 -\nend 1\n", "a NUL in the session is refused" },
        { "varek-breaker 2\nsession\nend 1\n", "a bare session line is refused" },
        { "varek-breaker 3\nend 0\n", "an unknown version is refused" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        plan_breaker_t *x = load_text(bad[i].text, cfg);
        CHECK(x == NULL, bad[i].why);
        plan_breaker_free(x);
    }

    /* A count that is not plain decimal digits, or past UINT_MAX, is
     * refused: sscanf's %u read "-1" as UINT_MAX and wrapped the next
     * increment to 0, resetting the limit. */
    struct { const char *text, *why; } counts[] = {
        { "varek-breaker 2\nsession 41 -1 0 2 -\nend 1\n", "a session count of -1 is refused" },
        { "varek-breaker 2\nsession 41 +3 0 2 -\nend 1\n", "a session count of +3 is refused" },
        { "varek-breaker 2\nsession 41 4294967296 0 2 -\nend 1\n", "a session count past UINT_MAX is refused" },
        { "varek-breaker 2\n41 0000000000000001 -1 0 2 -\nsession 41 0 0 2 -\nend 2\n", "an entry count of -1 is refused" },
        { "varek-breaker 1\n41 0000000000000001 -1 0 2 -\nend 1\n", "an entry count of -1 in a version 1 table is refused" },
        { "varek-breaker 2\n41 0000000000000001 3 0 2 -\nsession 41 2 0 2 -\nend 2\n",
          "a session count below its entries' refusals is refused" },
    };
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        plan_breaker_t *x = load_text(counts[i].text, cfg);
        CHECK(x == NULL, counts[i].why);
        plan_breaker_free(x);
    }
    plan_breaker_t *top = load_text("varek-breaker 2\nsession 41 4294967295 0 2 -\nend 1\n", cfg);
    CHECK(top != NULL, "a session count of UINT_MAX loads");
    if (top) {
        r = plan_breaker_step(top, "A", 1, PLAN_DEC_UNSATISFIED, cfg);
        CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.session_exhausted &&
              r.session_refusals == 4294967295u, "and the next refusal stays at UINT_MAX: terminal, no wrap");
        plan_breaker_free(top);
    }
    /* A version 2 table with entries but no session line: the session starts
     * from its entries, not at 0. */
    plan_breaker_t *noline = load_text("varek-breaker 2\n"
                                       "61 0000000000000001 2 0 2 -\n"
                                       "61 0000000000000002 1 0 2 -\n"
                                       "end 2\n", cfg);
    CHECK(noline != NULL, "a version 2 table with no session line loads");
    if (noline) {
        r = plan_breaker_step(noline, "a", 3, PLAN_DEC_UNSATISFIED, cfg);
        CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.session_refusals == 4 && r.session_exhausted,
              "its session starts from the 3 refusals its entries hold");
        plan_breaker_free(noline);
    }
    /* A version 1 entry latched by an UNKNOWN (0 refusals) counts 1. */
    plan_breaker_t *unk = load_text("varek-breaker 1\n"
                                    "61 0000000000000001 0 1 2 -\n"
                                    "61 0000000000000002 2 0 2 -\n"
                                    "end 2\n", cfg);
    CHECK(unk != NULL, "a version 1 table with an UNKNOWN latch loads");
    if (unk) {
        r = plan_breaker_step(unk, "a", 3, PLAN_DEC_UNSATISFIED, cfg);
        CHECK(r.outcome == PLAN_BREAKER_TERMINAL_ACTION && r.session_refusals == 4,
              "the UNKNOWN latch counts 1, so the session starts at 3 and the next is the 4th");
        plan_breaker_free(unk);
    }

    /* A latched session whose terminal action the policy no longer names
     * loads as a plain deny. */
    plan_breaker_t *ren = load_text("varek-breaker 2\nsession 61 4 1 3 old_action\nend 1\n", cfg);
    CHECK(ren != NULL, "a latched session loads");
    if (ren) {
        r = plan_breaker_step(ren, "a", 1, PLAN_DEC_UNSATISFIED, cfg);
        CHECK(r.outcome == PLAN_BREAKER_TERMINAL_DENY && r.session_exhausted && !r.terminal_action,
              "its unknown terminal action loads as TERMINAL_DENY");
        plan_breaker_free(ren);
    }
    plan_label_policy_config_free(cfg);
}

int main(void)
{
    test_parse();
    test_changing_plans();
    test_unknown_replay_sessions();
    test_no_session_limit();
    test_persistence();
    printf("%d/%d checks passed\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}
