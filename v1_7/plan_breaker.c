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
#include <limits.h>
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

/* v1.19.0: one per session, counting its refused submissions whatever plans
 * they were. */
typedef struct {
    char    *session;            /* owned strdup; "" for NULL session */
    unsigned refusals;
    bool     latched;
    plan_breaker_outcome_t latched_outcome;
    const char *latched_action;  /* borrowed from cfg disposition */
} session_t;

struct plan_breaker {
    entry_t   *entries;
    size_t     n;
    size_t     cap;
    session_t *sessions;
    size_t     ns;
    size_t     scap;
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
    for (size_t i = 0; i < b->ns; i++)
        free(b->sessions[i].session);
    free(b->sessions);
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

static session_t *find_session(plan_breaker_t *b, const char *sid)
{
    const char *key = sid ? sid : "";
    for (size_t i = 0; i < b->ns; i++)
        if (strcmp(b->sessions[i].session, key) == 0)
            return &b->sessions[i];
    return NULL;
}

/* Returns NULL only on allocation failure. */
static session_t *intern_session(plan_breaker_t *b, const char *sid)
{
    session_t *s = find_session(b, sid);
    if (s) return s;
    if (b->ns == b->scap) {
        size_t nc = b->scap ? b->scap * 2 : 8;
        session_t *grown = (session_t *)realloc(b->sessions, nc * sizeof(session_t));
        if (!grown) return NULL;
        b->sessions = grown;
        b->scap     = nc;
    }
    const char *key = sid ? sid : "";
    char *dup = (char *)malloc(strlen(key) + 1);
    if (!dup) return NULL;
    strcpy(dup, key);
    s = &b->sessions[b->ns++];
    s->session         = dup;
    s->refusals        = 0;
    s->latched         = false;
    s->latched_outcome = PLAN_BREAKER_TERMINAL_DENY;
    s->latched_action  = NULL;
    return s;
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
    memset(&r, 0, sizeof r);
    r.outcome        = PLAN_BREAKER_TERMINAL_DENY;
    r.budget         = plan_label_policy_config_refusal_budget(cfg);
    r.session_budget = plan_label_policy_config_session_refusal_budget(cfg);

    const bool enabled = plan_label_policy_config_breaker_enabled(cfg);

    /* SATISFIED authorizes unconditionally and clears the plan's history.
     * The session's count is not cleared: an authorized plan in between
     * would otherwise reset the bound on the refused ones. */
    if (verdict == PLAN_DEC_SATISFIED) {
        entry_t *e = b ? find_entry(b, session_id, signature) : NULL;
        if (e) { e->refusals = 0; e->latched = false; e->latched_action = NULL; }
        session_t *s = b ? find_session(b, session_id) : NULL;
        if (s) { r.session_refusals = s->refusals; r.session_exhausted = s->latched; }
        r.outcome = PLAN_BREAKER_PASS;
        return r;
    }

    /* No breaker object, or an entry that could not be recorded: fail
     * closed to the policy's exhaustion disposition. */
    /* The session first: a table is never saved with an entry whose session
     * has no count. */
    session_t *s = b ? intern_session(b, session_id) : NULL;
    entry_t   *e = s ? intern_entry(b, session_id, signature) : NULL;
    if (!e || !s) {
        terminalize(plan_label_policy_config_on_exhaustion(cfg),
                    &r.outcome, &r.terminal_action);
        r.latched = true;
        return r;
    }

    /* Already terminal for this signature: idempotent replay. */
    if (e->latched) {
        r.outcome          = e->latched_outcome;
        r.terminal_action  = e->latched_action;
        r.refusals         = e->refusals;
        r.session_refusals = s->refusals;
        r.latched          = true;
        r.session_exhausted = s->latched;
        return r;
    }

    /* The session's limit is spent: every refused plan in it is terminal,
     * whatever plan it is. Not counted again. */
    if (s->latched) {
        r.outcome          = s->latched_outcome;
        r.terminal_action  = s->latched_action;
        e->latched         = true;
        e->latched_outcome = r.outcome;
        e->latched_action  = r.terminal_action;
        r.refusals         = e->refusals;
        r.session_refusals = s->refusals;
        r.latched          = true;
        r.session_exhausted = true;
        return r;
    }

    if (s->refusals < UINT_MAX) s->refusals++;
    r.session_refusals = s->refusals;
    const bool session_spent = r.session_budget && s->refusals >= r.session_budget;

    /* UNKNOWN never retries — route straight to its disposition. It counts
     * toward the session's limit like any refusal. */
    if (verdict == PLAN_DEC_UNKNOWN) {
        terminalize(plan_label_policy_config_unknown_disposition(cfg),
                    &r.outcome, &r.terminal_action);
        e->latched         = true;
        e->latched_outcome = r.outcome;
        e->latched_action  = r.terminal_action;
        r.refusals = e->refusals;
        r.latched  = true;
        if (session_spent) {
            s->latched = true;
            terminalize(plan_label_policy_config_on_exhaustion(cfg),
                        &s->latched_outcome, &s->latched_action);
            r.session_exhausted = true;
        }
        return r;
    }

    /* UNSATISFIED: count it. */
    if (e->refusals < UINT_MAX) e->refusals++;
    r.refusals = e->refusals;

    /* Breaker disabled: pre-v1.8.2 behavior — surface, never latch. (A
     * session limit requires the breaker, so there is none here.) */
    if (!enabled) {
        r.outcome = PLAN_BREAKER_REFUSED_RETRYABLE;
        return r;
    }

    if (e->refusals < r.budget && !session_spent) {
        r.outcome = PLAN_BREAKER_REFUSED_RETRYABLE;
        return r;
    }

    /* A budget spent (this plan's, the session's, or both): fire
     * on_exhaustion and latch. */
    terminalize(plan_label_policy_config_on_exhaustion(cfg),
                &r.outcome, &r.terminal_action);
    e->latched         = true;
    e->latched_outcome = r.outcome;
    e->latched_action  = r.terminal_action;
    r.latched          = true;
    if (session_spent) {
        s->latched         = true;
        s->latched_outcome = r.outcome;
        s->latched_action  = r.terminal_action;
        r.session_exhausted = true;
    }
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
    if (fprintf(out, "varek-breaker 2\n") < 0) return -1;
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
    for (size_t i = 0; i < b->ns; i++) {
        const session_t *ss = &b->sessions[i];
        if (fputs("session ", out) == EOF) return -1;
        if (!ss->session[0]) {
            if (fputc('-', out) == EOF) return -1;
        } else {
            for (const unsigned char *c = (const unsigned char *)ss->session; *c; c++)
                if (fprintf(out, "%02x", *c) < 0) return -1;
        }
        if (fprintf(out, " %u %d %d %s\n", ss->refusals, ss->latched ? 1 : 0,
                    (int)ss->latched_outcome,
                    ss->latched_action ? ss->latched_action : "-") < 0)
            return -1;
    }
    /* The trailer: a file cut short, even at a line boundary, does not read
     * back as a smaller table. */
    if (fprintf(out, "end %zu\n", b->n + b->ns) < 0) return -1;
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

/* A count: decimal digits only (no sign, no space), at most UINT_MAX.
 * sscanf's %u accepts "-1" and wraps values past UINT_MAX, which would turn
 * a damaged count into a small one. Returns 0 or -1. */
static int parse_count(const char *t, unsigned *out)
{
    if (!t[0] || strlen(t) > 10) return -1;
    unsigned long long v = 0;
    for (const char *c = t; *c; c++) {
        if (*c < '0' || *c > '9') return -1;
        v = v * 10 + (unsigned long long)(*c - '0');
    }
    if (v > UINT_MAX) return -1;
    *out = (unsigned)v;
    return 0;
}

/* Decode a session written as hex (or "-" for the empty session) into
 * out[outsz]. Returns 0 or -1. */
static int decode_session(const char *hex, char *out, size_t outsz)
{
    if (strcmp(hex, "-") == 0) { out[0] = '\0'; return 0; }
    size_t hl = strlen(hex);
    if (hl == 0 || hl % 2 || hl / 2 >= outsz) return -1;
    for (size_t i = 0; i < hl / 2; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) return -1;
        out[i] = (char)(hi * 16 + lo);
    }
    out[hl / 2] = '\0';
    return 0;
}

/* The latched outcome and action as read from a line. A TERMINAL_ACTION
 * whose action the config no longer names becomes TERMINAL_DENY. */
static void restore_latch(const plan_label_policy_config_t *cfg, int latched, int outcome,
                          const char *action, plan_breaker_outcome_t *o, const char **act)
{
    *o   = (plan_breaker_outcome_t)outcome;
    *act = NULL;
    if (latched == 1 && outcome == PLAN_BREAKER_TERMINAL_ACTION) {
        *act = strcmp(action, "-") ? known_action(cfg, action) : NULL;
        if (!*act) *o = PLAN_BREAKER_TERMINAL_DENY;
    }
}

int plan_breaker_load(plan_breaker_t *b, FILE *in,
                      const plan_label_policy_config_t *cfg)
{
    if (!b || !in || !cfg || b->n != 0 || b->ns != 0) return -1;
    char line[1024];
    if (!fgets(line, sizeof line, in)) return -1;
    int version;
    if (strcmp(line, "varek-breaker 1\n") == 0)      version = 1;
    else if (strcmp(line, "varek-breaker 2\n") == 0) version = 2;
    else return -1;
    bool ended = false;
    while (fgets(line, sizeof line, in)) {
        size_t len = strlen(line);
        if (ended) return -1;                                /* data after the trailer */
        if (len == 0 || line[len - 1] != '\n') return -1;   /* over-long or cut */
        line[len - 1] = '\0';
        if (strncmp(line, "end ", 4) == 0) {
            char *endp = NULL;
            unsigned long long n = strtoull(line + 4, &endp, 10);
            if (!endp || *endp || line[4] < '0' || line[4] > '9' || n != b->n + b->ns)
                return -1;
            ended = true;
            continue;
        }
        char sess_hex[520], action[256], session[260], count[32];
        unsigned refusals;
        int latched, outcome;
        char tail;
        if (strncmp(line, "session ", 8) == 0) {
            /* v2: session <session> <refusals> <latched> <outcome> <action> */
            if (version < 2) return -1;
            if (sscanf(line + 8, "%519s %31s %d %d %255s %c", sess_hex, count,
                       &latched, &outcome, action, &tail) != 5 ||
                parse_count(count, &refusals) != 0)
                return -1;
            if ((latched != 0 && latched != 1) ||
                (outcome != PLAN_BREAKER_TERMINAL_DENY && outcome != PLAN_BREAKER_TERMINAL_ACTION) ||
                decode_session(sess_hex, session, sizeof session) != 0 ||
                find_session(b, session))                     /* duplicate */
                return -1;
            session_t *ss = intern_session(b, session);
            if (!ss) return -1;
            ss->refusals = refusals;
            ss->latched  = latched == 1;
            restore_latch(cfg, latched, outcome, action, &ss->latched_outcome, &ss->latched_action);
            continue;
        }
        char sig_hex[17];
        if (sscanf(line, "%519s %16s %31s %d %d %255s %c", sess_hex, sig_hex,
                   count, &latched, &outcome, action, &tail) != 6 ||
            parse_count(count, &refusals) != 0)
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
        if (decode_session(sess_hex, session, sizeof session) != 0) return -1;
        if (find_entry(b, session, sig)) return -1;          /* duplicate */
        entry_t *e = intern_entry(b, session, sig);
        if (!e) return -1;
        e->refusals = refusals;
        e->latched  = latched == 1;
        restore_latch(cfg, latched, outcome, action, &e->latched_outcome, &e->latched_action);
    }
    if (ferror(in) || !ended) return -1;

    /* Each session's count against the refusals its entries hold. Every
     * counted refusal of an entry was also counted for its session, and only
     * an authorized plan lowers an entry's count, so a session's count is at
     * least the sum. A v1.18.0 table has no session counts: each session starts
     * from that sum, with an entry latched by an UNKNOWN (which held 0) counted
     * as 1 — fewer than the session made, never more. In a version 2 table a
     * session line with less than the sum is refused, and a session with
     * entries but no line starts from the sum. */
    size_t ns_read = b->ns;
    for (size_t i = 0; i < b->n; i++) {
        const entry_t *en = &b->entries[i];
        unsigned add = en->refusals;
        if (version == 1 && en->latched && add == 0) add = 1;
        session_t *ss = find_session(b, en->session);
        bool from_file = ss && (size_t)(ss - b->sessions) < ns_read;
        if (!ss) ss = intern_session(b, en->session);
        if (!ss) return -1;
        if (from_file) {
            /* checked below, once the sum is known */
            continue;
        }
        ss->refusals = ss->refusals > UINT_MAX - add ? UINT_MAX : ss->refusals + add;
    }
    for (size_t k = 0; k < ns_read; k++) {
        unsigned long long sum = 0;
        for (size_t i = 0; i < b->n; i++)
            if (strcmp(b->entries[i].session, b->sessions[k].session) == 0)
                sum += b->entries[i].refusals;
        if (sum > b->sessions[k].refusals) return -1;
    }
    return 0;
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
