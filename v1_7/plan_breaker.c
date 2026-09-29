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

#include <inttypes.h>
#include <stdio.h>
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

static uint64_t step_hash(const plan_action_desc_t *a)
{
    uint64_t h = 0xCBF29CE484222325ULL;
    h = fnv1a_str(h, a->name);
    uint64_t nn = (uint64_t)a->n_named_args;
    h = fnv1a(h, &nn, sizeof nn);
    for (size_t j = 0; j < a->n_named_args; j++) {
        h = fnv1a_str(h, a->named_args[j].key);
        h = fnv1a_str(h, a->named_args[j].value);
    }
    return h;
}

static int cmp_pair(const void *x, const void *y)
{
    const uint64_t *a = x, *b = y;
    if (a[0] != b[0]) return (a[0] > b[0]) - (a[0] < b[0]);
    return (a[1] > b[1]) - (a[1] < b[1]);
}

/* Sort context for ordering step indices by (hash, index). */
static const uint64_t *g_sort_hash;
static int cmp_step(const void *x, const void *y)
{
    size_t i = *(const size_t *)x, j = *(const size_t *)y;
    if (g_sort_hash[i] != g_sort_hash[j]) return g_sort_hash[i] < g_sort_hash[j] ? -1 : 1;
    return (i > j) - (i < j);
}

uint64_t plan_breaker_signature_graph(const plan_action_desc_t *actions,
                                      size_t n_actions,
                                      const uint32_t *edge_from,
                                      const uint32_t *edge_to,
                                      size_t n_edges)
{
    /* The steps are put in a canonical order: by their hash (name and
     * arguments), identical steps keeping their order in the plan. Each edge
     * is written as (position, position) in that order, and the edges are
     * sorted with repeats dropped. So listing distinct steps or the edges in
     * another order, or repeating an edge, gives the same signature, while
     * different edge sets always give different ones. Identical steps are
     * never merged: merging would let an authorized graph clear the count of a
     * refused one that differs only in which copy an edge uses. Reordering
     * identical steps can give a new signature (a new count). If allocation
     * fails, the signature is derived from the steps alone. */
    uint64_t *st = calloc(n_actions ? n_actions : 1, sizeof *st);
    size_t *ord = calloc(n_actions ? n_actions : 1, sizeof *ord);
    size_t *pos = calloc(n_actions ? n_actions : 1, sizeof *pos);
    uint64_t *ed = calloc(2 * (n_edges ? n_edges : 1), sizeof *ed);
    if (!st || !ord || !pos || !ed) {
        free(st); free(ord); free(pos); free(ed);
        return plan_breaker_signature(actions, n_actions) ^ 1;
    }
    for (size_t i = 0; i < n_actions; i++) { st[i] = step_hash(&actions[i]); ord[i] = i; }
    g_sort_hash = st;
    qsort(ord, n_actions, sizeof *ord, cmp_step);
    g_sort_hash = NULL;
    for (size_t k = 0; k < n_actions; k++) pos[ord[k]] = k;
    size_t ne = 0;
    for (size_t i = 0; edge_from && edge_to && i < n_edges; i++) {
        if (edge_from[i] >= n_actions || edge_to[i] >= n_actions) continue;
        ed[2 * ne]     = (uint64_t)pos[edge_from[i]];
        ed[2 * ne + 1] = (uint64_t)pos[edge_to[i]];
        ne++;
    }
    qsort(ed, ne, 2 * sizeof *ed, cmp_pair);
    uint64_t h = 0xCBF29CE484222325ULL;
    h = fnv1a(h, "graph-2", 7);
    uint64_t na = (uint64_t)n_actions;
    h = fnv1a(h, &na, sizeof na);
    for (size_t k = 0; k < n_actions; k++) h = fnv1a(h, &st[ord[k]], sizeof st[0]);
    uint64_t nu = 0;
    for (size_t i = 0; i < ne; i++) {
        if (i && ed[2 * i] == ed[2 * i - 2] && ed[2 * i + 1] == ed[2 * i - 1]) continue;
        h = fnv1a(h, &ed[2 * i], 2 * sizeof *ed);
        nu++;
    }
    h = fnv1a(h, &nu, sizeof nu);
    free(st); free(ord); free(pos); free(ed);
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

/* ---------- Persistence (v1.18.0) ---------- */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int plan_breaker_save(const plan_breaker_t *b, FILE *out)
{
    if (!b || !out) return -1;
    if (fprintf(out, "varek-breaker 1\n") < 0) return -1;
    for (size_t i = 0; i < b->n; i++) {
        const entry_t *e = &b->entries[i];
        if (!e->session[0]) {
            if (fputc('-', out) == EOF) return -1;
        } else {
            for (const unsigned char *c = (const unsigned char *)e->session; *c; c++)
                if (fprintf(out, "%02x", *c) < 0) return -1;
        }
        if (fprintf(out, " %016" PRIx64 " %u %d %d %s\n",
                    e->signature, e->refusals, e->latched ? 1 : 0,
                    (int)e->latched_outcome,
                    e->latched_action ? e->latched_action : "-") < 0)
            return -1;
    }
    /* The trailer: a file cut short, even at a line boundary, does not read
     * back as a smaller table. */
    if (fprintf(out, "end %zu\n", b->n) < 0) return -1;
    return fflush(out) == 0 ? 0 : -1;
}

static const char *known_action(const plan_label_policy_config_t *cfg, const char *name)
{
    plan_disposition_t d[2] = {
        plan_label_policy_config_on_exhaustion(cfg),
        plan_label_policy_config_unknown_disposition(cfg),
    };
    for (int i = 0; i < 2; i++)
        if (d[i].kind == PLAN_DISP_TERMINAL && d[i].action_name &&
            strcmp(d[i].action_name, name) == 0)
            return d[i].action_name;
    return NULL;
}

int plan_breaker_load(plan_breaker_t *b, FILE *in,
                      const plan_label_policy_config_t *cfg)
{
    if (!b || !in || !cfg || b->n != 0) return -1;
    char line[1024];
    if (!fgets(line, sizeof line, in) || strcmp(line, "varek-breaker 1\n") != 0)
        return -1;
    bool ended = false;
    while (fgets(line, sizeof line, in)) {
        size_t len = strlen(line);
        if (ended) return -1;                                /* data after the trailer */
        if (len == 0 || line[len - 1] != '\n') return -1;   /* over-long or cut */
        line[len - 1] = '\0';
        if (strncmp(line, "end ", 4) == 0) {
            char *endp = NULL;
            unsigned long long n = strtoull(line + 4, &endp, 10);
            if (!endp || *endp || line[4] < '0' || line[4] > '9' || n != b->n) return -1;
            ended = true;
            continue;
        }
        char sess_hex[520], action[256];
        char sig_hex[17];
        unsigned refusals;
        int latched, outcome;
        char tail;
        if (sscanf(line, "%519s %16s %u %d %d %255s %c", sess_hex, sig_hex,
                   &refusals, &latched, &outcome, action, &tail) != 6)
            return -1;
        if (strlen(sig_hex) != 16 || (latched != 0 && latched != 1) ||
            (outcome != PLAN_BREAKER_TERMINAL_DENY && outcome != PLAN_BREAKER_TERMINAL_ACTION))
            return -1;
        uint64_t sig = 0;
        for (int i = 0; i < 16; i++) {
            int v = hexval(sig_hex[i]);
            if (v < 0) return -1;
            sig = (sig << 4) | (uint64_t)v;
        }
        char session[260];
        if (strcmp(sess_hex, "-") == 0) {
            session[0] = '\0';
        } else {
            size_t hl = strlen(sess_hex);
            if (hl % 2 || hl / 2 >= sizeof session) return -1;
            for (size_t i = 0; i < hl / 2; i++) {
                int hi = hexval(sess_hex[2 * i]), lo = hexval(sess_hex[2 * i + 1]);
                if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) return -1;
                session[i] = (char)(hi * 16 + lo);
            }
            session[hl / 2] = '\0';
        }
        if (find_entry(b, session, sig)) return -1;          /* duplicate */
        entry_t *e = intern_entry(b, session, sig);
        if (!e) return -1;
        e->refusals = refusals;
        e->latched  = latched == 1;
        e->latched_outcome = (plan_breaker_outcome_t)outcome;
        e->latched_action  = NULL;
        if (e->latched && outcome == PLAN_BREAKER_TERMINAL_ACTION) {
            e->latched_action = strcmp(action, "-") ? known_action(cfg, action) : NULL;
            if (!e->latched_action) e->latched_outcome = PLAN_BREAKER_TERMINAL_DENY;
        }
    }
    return (ferror(in) || !ended) ? -1 : 0;
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
