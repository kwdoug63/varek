// SPDX-License-Identifier: MIT
/*
 * plan_breaker.c — VAREK v1.8.2 bounded-refusal breaker.
 *
 * Reference implementation. The (session, signature) table is a flat
 * vector walked linearly; correct and easy to audit, O(n) per step.
 * A production Warden with many concurrent sessions should swap the
 * lookup for a hash map — the semantics below are the contract, not
 * the data structure.
 */

#include "plan_breaker.h"

#include <stdlib.h>
#include <string.h>

/* ---------- Signature ---------- */

/* FNV-1a 64-bit. Deterministic, no allocation, stable across runs. */
static uint64_t fnv1a(uint64_t h, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)p[i];
        h *= 0x00000100000001B3ULL;
    }
    return h;
}

static uint64_t fnv1a_str(uint64_t h, const char *s)
{
    /* Length-delimited so "ab"+"c" != "a"+"bc". */
    size_t n = s ? strlen(s) : 0;
    uint64_t nn = (uint64_t)n;
    h = fnv1a(h, &nn, sizeof nn);
    return s ? fnv1a(h, s, n) : h;
}

uint64_t plan_breaker_signature(const plan_action_desc_t *actions,
                                size_t n_actions)
{
    uint64_t h = 0xCBF29CE484222325ULL;            /* FNV offset basis */
    uint64_t na = (uint64_t)n_actions;
    h = fnv1a(h, &na, sizeof na);
    if (!actions) return h;

    for (size_t i = 0; i < n_actions; i++) {
        const plan_action_desc_t *a = &actions[i];
        h = fnv1a_str(h, a->name);
        uint64_t nn = (uint64_t)a->n_named_args;
        h = fnv1a(h, &nn, sizeof nn);
        for (size_t j = 0; j < a->n_named_args; j++) {
            h = fnv1a_str(h, a->named_args[j].key);
            h = fnv1a_str(h, a->named_args[j].value);
        }
    }
    return h;
}

/* ---------- State table ---------- */

typedef struct {
    char    *session;            /* owned strdup; "" for NULL session */
    uint64_t signature;
    unsigned refusals;
    bool     latched;
    plan_breaker_outcome_t latched_outcome;
    const char *latched_action;  /* borrowed from cfg disposition */
} entry_t;

struct plan_breaker {
    entry_t *entries;
    size_t   n;
    size_t   cap;
};

plan_breaker_t *plan_breaker_new(void)
{
    return (plan_breaker_t *)calloc(1, sizeof(struct plan_breaker));
}

void plan_breaker_free(plan_breaker_t *b)
{
    if (!b) return;
    for (size_t i = 0; i < b->n; i++)
        free(b->entries[i].session);
    free(b->entries);
    free(b);
}

static entry_t *find_entry(plan_breaker_t *b, const char *sid, uint64_t sig)
{
    const char *key = sid ? sid : "";
    for (size_t i = 0; i < b->n; i++) {
        if (b->entries[i].signature == sig &&
            strcmp(b->entries[i].session, key) == 0)
            return &b->entries[i];
    }
    return NULL;
}

/* Returns NULL only on allocation failure. */
static entry_t *intern_entry(plan_breaker_t *b, const char *sid, uint64_t sig)
{
    entry_t *e = find_entry(b, sid, sig);
    if (e) return e;

    if (b->n == b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 16;
        entry_t *grown = (entry_t *)realloc(b->entries, nc * sizeof(entry_t));
        if (!grown) return NULL;
        b->entries = grown;
        b->cap     = nc;
    }
    const char *key = sid ? sid : "";
    char *dup = (char *)malloc(strlen(key) + 1);
    if (!dup) return NULL;
    strcpy(dup, key);

    e = &b->entries[b->n++];
    e->session         = dup;
    e->signature       = sig;
    e->refusals        = 0;
    e->latched         = false;
    e->latched_outcome = PLAN_BREAKER_TERMINAL_DENY;
    e->latched_action  = NULL;
    return e;
}

/* ---------- Disposition -> outcome ---------- */

static void terminalize(plan_disposition_t disp,
                        plan_breaker_outcome_t *outcome,
                        const char **action)
{
    if (disp.kind == PLAN_DISP_TERMINAL && disp.action_name) {
        *outcome = PLAN_BREAKER_TERMINAL_ACTION;
        *action  = disp.action_name;
    } else {
        *outcome = PLAN_BREAKER_TERMINAL_DENY;
        *action  = NULL;
    }
}

/* ---------- Step ---------- */

plan_breaker_result_t plan_breaker_step(plan_breaker_t *b,
                                        const char *session_id,
                                        uint64_t signature,
                                        plan_decision_t verdict,
                                        const plan_label_policy_config_t *cfg)
{
    plan_breaker_result_t r;
    r.outcome         = PLAN_BREAKER_TERMINAL_DENY;
    r.refusals        = 0;
    r.budget          = plan_label_policy_config_refusal_budget(cfg);
    r.terminal_action = NULL;
    r.latched         = false;

    const bool enabled = plan_label_policy_config_breaker_enabled(cfg);

    /* SATISFIED authorizes unconditionally and clears any history. */
    if (verdict == PLAN_DEC_SATISFIED) {
        entry_t *e = b ? find_entry(b, session_id, signature) : NULL;
        if (e) { e->refusals = 0; e->latched = false; e->latched_action = NULL; }
        r.outcome = PLAN_BREAKER_PASS;
        return r;
    }

    /* No breaker object, or table full and entry could not be interned:
     * fail closed to the policy's exhaustion disposition. */
    entry_t *e = b ? intern_entry(b, session_id, signature) : NULL;
    if (!e) {
        terminalize(plan_label_policy_config_on_exhaustion(cfg),
                    &r.outcome, &r.terminal_action);
        r.latched = true;
        return r;
    }

    /* Already terminal for this signature: idempotent replay. */
    if (e->latched) {
        r.outcome         = e->latched_outcome;
        r.terminal_action = e->latched_action;
        r.refusals        = e->refusals;
        r.latched         = true;
        return r;
    }

    /* UNKNOWN never retries — route straight to its disposition. */
    if (verdict == PLAN_DEC_UNKNOWN) {
        terminalize(plan_label_policy_config_unknown_disposition(cfg),
                    &r.outcome, &r.terminal_action);
        e->latched         = true;
        e->latched_outcome = r.outcome;
        e->latched_action  = r.terminal_action;
        r.refusals = e->refusals;
        r.latched  = true;
        return r;
    }

    /* UNSATISFIED: count it. */
    e->refusals++;
    r.refusals = e->refusals;

    /* Breaker disabled: pre-v1.8.2 behavior — surface, never latch. */
    if (!enabled) {
        r.outcome = PLAN_BREAKER_REFUSED_RETRYABLE;
        return r;
    }

    if (e->refusals < r.budget) {
        r.outcome = PLAN_BREAKER_REFUSED_RETRYABLE;
        return r;
    }

    /* Budget spent: fire on_exhaustion and latch. */
    terminalize(plan_label_policy_config_on_exhaustion(cfg),
                &r.outcome, &r.terminal_action);
    e->latched         = true;
    e->latched_outcome = r.outcome;
    e->latched_action  = r.terminal_action;
    r.latched          = true;
    return r;
}

const char *plan_breaker_outcome_name(plan_breaker_outcome_t o)
{
    switch (o) {
    case PLAN_BREAKER_PASS:              return "PASS";
    case PLAN_BREAKER_REFUSED_RETRYABLE: return "REFUSED_RETRYABLE";
    case PLAN_BREAKER_TERMINAL_DENY:     return "TERMINAL_DENY";
    case PLAN_BREAKER_TERMINAL_ACTION:   return "TERMINAL_ACTION";
    default:                             return "?";
    }
}
