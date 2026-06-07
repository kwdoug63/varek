// SPDX-License-Identifier: MIT
/*
 * plan_policy_config.c — VAREK v1.7.3 label-policy config loader.
 *
 * Line-oriented parser with strict error reporting. Dependency-free
 * (libc only). All storage is owned by the config and freed on
 * plan_label_policy_config_free(). The parser is single-pass with a
 * doubling rules vector; allocation happens only here, not on the
 * Warden's hot path.
 */

#include "plan_policy_config.h"
#include "plan_label.h"
#include "plan_label_policy.h"
#include "plan_dataflow_pathology.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- Storage ---------- */

struct plan_label_policy_config {
    /* Public faces — pointers in 'policy' and 'table' must remain
     * stable for the config's lifetime; we finalize them after the
     * rules vector stops growing. */
    plan_label_policy_t policy;
    plan_label_table_t  table;

    /* Owned storage. */
    plan_label_rule_t *rules;
    size_t             n_rules;
    size_t             cap_rules;

    /* Label names indexed by id; NULL for undeclared ids. Owned
     * (strdup'd) strings. */
    char *label_names[PLAN_MAX_LABELS];
    size_t n_labels;

    /* v1.8.2 bounded-refusal breaker config. calloc() gives the safe
     * defaults: breaker disabled, both dispositions = deny. */
    bool               budget_set;
    unsigned           refusal_budget;
    bool               on_exhaustion_set;
    bool               unknown_disp_set;
    plan_disposition_t on_exhaustion;   /* .action_name owned (strdup) or NULL */
    plan_disposition_t unknown_disp;    /* .action_name owned (strdup) or NULL */

    /* Each rule's action_name is strdup'd; we walk rules[] on free
     * to release them. */
};

/* ---------- Static error strings ---------- */

static const char *ERR_NONE                 = "";
static const char *ERR_IO                   = "I/O error reading config";
static const char *ERR_OOM                  = "out of memory";
static const char *ERR_LINE_TOO_LONG        = "line exceeds 1024 bytes";
static const char *ERR_UNKNOWN_STMT         = "unknown top-level statement";
static const char *ERR_UNKNOWN_BODY_STMT    = "unknown rule-body statement";
static const char *ERR_INDENTED_OUTSIDE     = "indented statement outside any rule";
static const char *ERR_LABEL_MISSING_ARGS   = "'label' requires NAME and ID";
static const char *ERR_LABEL_BAD_ID         = "label id is not a non-negative integer";
static const char *ERR_LABEL_OUT_OF_RANGE   = "label id out of range";
static const char *ERR_LABEL_REDECL_NAME    = "label name already declared";
static const char *ERR_LABEL_REDECL_ID      = "label id already in use";
static const char *ERR_STICKY_MISSING_NAME  = "'sticky' requires a label name";
static const char *ERR_STICKY_UNKNOWN_NAME  = "'sticky' references undeclared label";
static const char *ERR_RULE_MISSING_NAME    = "'rule' requires an action name";
static const char *ERR_BODY_MISSING_LABEL   = "rule-body statement requires a label name";
static const char *ERR_BODY_UNKNOWN_LABEL   = "rule-body statement references undeclared label";
static const char *ERR_VERSION_BAD          = "varek_policy version must be 1";
static const char *ERR_VERSION_LATE         = "varek_policy pragma must precede other statements";
static const char *ERR_STRICT_EXTRA_ARGS    = "'strict' takes no arguments";
static const char *ERR_EXTRA_TOKENS         = "unexpected extra tokens on line";
static const char *ERR_MATCH_BAD_ARGS       = "'match' requires KEY and PATTERN";
static const char *ERR_BUDGET_BAD           = "'refusal_budget' requires a positive integer";
static const char *ERR_BUDGET_DUP           = "duplicate 'refusal_budget' directive";
static const char *ERR_DISP_BAD             = "disposition must be 'deny' or 'terminal NAME'";
static const char *ERR_DISP_DUP_EXH         = "duplicate 'on_exhaustion' directive";
static const char *ERR_DISP_DUP_UNK         = "duplicate 'unknown_disposition' directive";

/* ---------- Helpers ---------- */

static char *xstrdup(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

static plan_label_t lookup_label(const plan_label_policy_config_t *cfg,
                                 const char *name)
{
    for (size_t i = 0; i < PLAN_MAX_LABELS; i++) {
        if (cfg->label_names[i] && strcmp(cfg->label_names[i], name) == 0)
            return (plan_label_t)i;
    }
    return PLAN_LABEL_INVALID;
}

static int ensure_rule_capacity(plan_label_policy_config_t *cfg)
{
    if (cfg->n_rules < cfg->cap_rules) return 0;
    size_t new_cap = cfg->cap_rules ? cfg->cap_rules * 2 : 16;
    plan_label_rule_t *r = (plan_label_rule_t *)realloc(
        cfg->rules, new_cap * sizeof(plan_label_rule_t));
    if (!r) return -1;
    /* Zero the newly added slots; calloc semantics for the tail. */
    memset(&r[cfg->cap_rules], 0,
           (new_cap - cfg->cap_rules) * sizeof(plan_label_rule_t));
    cfg->rules     = r;
    cfg->cap_rules = new_cap;
    return 0;
}

/* Tokenize a line in place. Returns number of tokens; tokens[] are
 * pointers into the (modified) line. Whitespace runs are separators. */
static int tokenize(char *line, char **tokens, int max_tokens)
{
    int n = 0;
    char *p = line;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (n >= max_tokens) {
            /* Excess tokens stay attached to the last one; callers
             * that count > expected detect the overflow. */
            return n + 1;
        }
        tokens[n++] = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p) { *p = '\0'; p++; }
    }
    return n;
}

/* ---------- Parser state ---------- */

typedef struct {
    plan_label_policy_config_t *cfg;
    int  line_no;
    bool version_seen;
    bool any_decl_seen;
    plan_label_rule_t *current_rule;   /* NULL outside rule block */
} parse_state_t;

/* Add label tag to a class slot (origin/deny_in/unknown_in/permit_in)
 * by name lookup. Returns NULL on success or static error string. */
static const char *body_add_label(plan_label_set_t *set,
                                  const parse_state_t *st,
                                  const char *name)
{
    plan_label_t t = lookup_label(st->cfg, name);
    if (t == PLAN_LABEL_INVALID) return ERR_BODY_UNKNOWN_LABEL;
    if (plan_label_set_add(set, t) != 0) return ERR_LABEL_OUT_OF_RANGE;
    return NULL;
}

/* ---------- Top-level statement handlers ---------- */

static const char *handle_varek_policy(parse_state_t *st, int n_tokens,
                                       char **tokens)
{
    if (st->any_decl_seen) return ERR_VERSION_LATE;
    if (n_tokens != 2)     return ERR_VERSION_BAD;
    if (strcmp(tokens[1], "1") != 0) return ERR_VERSION_BAD;
    st->version_seen = true;
    return NULL;
}

static const char *handle_strict(parse_state_t *st, int n_tokens, char **tokens)
{
    (void)tokens;
    if (n_tokens != 1) return ERR_STRICT_EXTRA_ARGS;
    st->cfg->table.strict = true;
    return NULL;
}

static const char *handle_label(parse_state_t *st, int n_tokens, char **tokens)
{
    if (n_tokens != 3) return ERR_LABEL_MISSING_ARGS;
    const char *name = tokens[1];
    const char *id_s = tokens[2];

    /* Parse id. */
    char *end = NULL;
    long id = strtol(id_s, &end, 10);
    if (!end || *end != '\0' || id < 0) return ERR_LABEL_BAD_ID;
    if (id >= (long)PLAN_MAX_LABELS)    return ERR_LABEL_OUT_OF_RANGE;

    /* Reject name reuse. */
    if (lookup_label(st->cfg, name) != PLAN_LABEL_INVALID)
        return ERR_LABEL_REDECL_NAME;
    if (st->cfg->label_names[id] != NULL)
        return ERR_LABEL_REDECL_ID;

    char *dup = xstrdup(name);
    if (!dup) return ERR_OOM;
    st->cfg->label_names[id] = dup;
    st->cfg->n_labels++;
    return NULL;
}

static const char *handle_sticky(parse_state_t *st, int n_tokens, char **tokens)
{
    if (n_tokens != 2) return ERR_STICKY_MISSING_NAME;
    plan_label_t t = lookup_label(st->cfg, tokens[1]);
    if (t == PLAN_LABEL_INVALID) return ERR_STICKY_UNKNOWN_NAME;
    if (plan_label_set_add(&st->cfg->policy.sticky, t) != 0)
        return ERR_LABEL_OUT_OF_RANGE;
    return NULL;
}

static const char *handle_rule(parse_state_t *st, int n_tokens, char **tokens)
{
    if (n_tokens != 2) return ERR_RULE_MISSING_NAME;
    /* v1.7.4: multiple rules with the same action name are explicitly
     * allowed — they are how first-match-wins ordering with different
     * argument constraints (match clauses) is expressed. The v1.7.3
     * duplicate-rule-name check is removed. */

    if (ensure_rule_capacity(st->cfg) != 0) return ERR_OOM;
    plan_label_rule_t *r = &st->cfg->rules[st->cfg->n_rules++];
    memset(r, 0, sizeof *r);
    r->action_name = xstrdup(tokens[1]);
    if (!r->action_name) {
        st->cfg->n_rules--;
        return ERR_OOM;
    }
    st->current_rule = r;
    return NULL;
}

/* Append a match constraint to the current rule. The match storage
 * is grown one entry at a time via realloc; entries are tiny and
 * counts are typically small. Returns NULL on success or a static
 * error string on allocation/strdup failure. */
static const char *add_match_to_rule(plan_label_rule_t *rule,
                                     const char *key, const char *pattern)
{
    size_t new_n = rule->n_matches + 1;
    plan_label_rule_match_t *grown = (plan_label_rule_match_t *)realloc(
        (void *)rule->matches,
        new_n * sizeof(plan_label_rule_match_t));
    if (!grown) return ERR_OOM;

    char *key_dup = xstrdup(key);
    char *pat_dup = xstrdup(pattern);
    if (!key_dup || !pat_dup) {
        free(key_dup); free(pat_dup);
        rule->matches = grown;   /* still owned for cleanup */
        return ERR_OOM;
    }

    grown[new_n - 1].key     = key_dup;
    grown[new_n - 1].pattern = pat_dup;
    rule->matches   = grown;
    rule->n_matches = new_n;
    return NULL;
}

/* ---------- v1.8.2 breaker directive handlers ---------- */

static const char *handle_refusal_budget(parse_state_t *st, int n_tokens,
                                         char **tokens)
{
    if (st->cfg->budget_set) return ERR_BUDGET_DUP;
    if (n_tokens != 2)       return ERR_BUDGET_BAD;
    char *end = NULL;
    long n = strtol(tokens[1], &end, 10);
    if (!end || *end != '\0' || n < 1) return ERR_BUDGET_BAD;
    st->cfg->refusal_budget = (unsigned)n;
    st->cfg->budget_set     = true;
    return NULL;
}

/* Parse 'deny' | 'terminal NAME' from tokens[1..]. On TERMINAL the
 * action name is strdup'd into out->action_name (owned by cfg). */
static const char *parse_disposition(int n_tokens, char **tokens,
                                     plan_disposition_t *out)
{
    if (n_tokens == 2 && strcmp(tokens[1], "deny") == 0) {
        out->kind        = PLAN_DISP_DENY;
        out->action_name = NULL;
        return NULL;
    }
    if (n_tokens == 3 && strcmp(tokens[1], "terminal") == 0) {
        char *dup = xstrdup(tokens[2]);
        if (!dup) return ERR_OOM;
        out->kind        = PLAN_DISP_TERMINAL;
        out->action_name = dup;          /* owned; freed in config_free */
        return NULL;
    }
    return ERR_DISP_BAD;
}

static const char *handle_on_exhaustion(parse_state_t *st, int n_tokens,
                                        char **tokens)
{
    if (st->cfg->on_exhaustion_set) return ERR_DISP_DUP_EXH;
    const char *e = parse_disposition(n_tokens, tokens, &st->cfg->on_exhaustion);
    if (e) return e;
    st->cfg->on_exhaustion_set = true;
    return NULL;
}

static const char *handle_unknown_disposition(parse_state_t *st, int n_tokens,
                                              char **tokens)
{
    if (st->cfg->unknown_disp_set) return ERR_DISP_DUP_UNK;
    const char *e = parse_disposition(n_tokens, tokens, &st->cfg->unknown_disp);
    if (e) return e;
    st->cfg->unknown_disp_set = true;
    return NULL;
}

/* ---------- Rule-body statement handler ---------- */

static const char *handle_body(parse_state_t *st, int n_tokens, char **tokens)
{
    const char *kw = tokens[0];

    /* v1.7.4: match clause. Three tokens: 'match' KEY PATTERN. */
    if (strcmp(kw, "match") == 0) {
        if (n_tokens != 3) return ERR_MATCH_BAD_ARGS;
        return add_match_to_rule(st->current_rule, tokens[1], tokens[2]);
    }

    if (n_tokens != 2) return ERR_BODY_MISSING_LABEL;
    const char *name = tokens[1];
    plan_label_class_t *c = &st->current_rule->classify;

    if      (strcmp(kw, "origin")     == 0) return body_add_label(&c->origin,     st, name);
    else if (strcmp(kw, "deny_in")    == 0) return body_add_label(&c->deny_in,    st, name);
    else if (strcmp(kw, "unknown_in") == 0) return body_add_label(&c->unknown_in, st, name);
    else if (strcmp(kw, "permit_in")  == 0) return body_add_label(&c->permit_in,  st, name);
    else if (strcmp(kw, "declassify") == 0) return body_add_label(&c->declassify, st, name);
    return ERR_UNKNOWN_BODY_STMT;
}

/* ---------- Main parse loop ---------- */

static void cfg_zero(plan_label_policy_config_t *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    cfg->policy.classify = plan_label_policy_from_table;
    cfg->policy.ctx      = &cfg->table;
    plan_label_set_clear(&cfg->policy.sticky);
    cfg->table.strict = false;
}

int plan_label_policy_config_load_stream(FILE *stream,
                                         plan_label_policy_config_t **out,
                                         int *err_line,
                                         const char **err_msg)
{
    if (out) *out = NULL;
    if (err_line) *err_line = 0;
    if (err_msg)  *err_msg  = ERR_NONE;

    if (!stream || !out) { if (err_msg) *err_msg = ERR_IO; return -1; }

    plan_label_policy_config_t *cfg =
        (plan_label_policy_config_t *)calloc(1, sizeof *cfg);
    if (!cfg) { if (err_msg) *err_msg = ERR_OOM; return -1; }
    cfg_zero(cfg);

    parse_state_t st = { .cfg = cfg, .line_no = 0,
                         .version_seen = false, .any_decl_seen = false,
                         .current_rule = NULL };

    char line[1024];
    const char *err = NULL;

    while (fgets(line, sizeof line, stream)) {
        st.line_no++;

        /* Detect unterminated long lines (no '\n' AND buffer is full
         * AND there is more to read). */
        size_t len = strlen(line);
        if (len == sizeof(line) - 1 && line[len - 1] != '\n' &&
            !feof(stream)) {
            err = ERR_LINE_TOO_LONG;
            break;
        }

        /* Strip CR / NL. */
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        /* Decide indentation BEFORE we mutate the buffer. */
        bool indented = len > 0 && isspace((unsigned char)line[0]);

        /* Skip blank or comment-only lines. */
        {
            size_t i = 0;
            while (i < len && isspace((unsigned char)line[i])) i++;
            if (i == len) continue;             /* all whitespace */
            if (line[i] == '#') continue;       /* comment */
        }

        /* Tokenize (mutates line). Expect <= 4 tokens for any
         * statement; tokenize returns n_tokens+1 if more. */
        char *tokens[5] = {0};
        int n_tokens = tokenize(line, tokens, 4);
        if (n_tokens == 0) continue;
        if (n_tokens > 4) { err = ERR_EXTRA_TOKENS; break; }

        if (indented) {
            if (!st.current_rule) { err = ERR_INDENTED_OUTSIDE; break; }
            err = handle_body(&st, n_tokens, tokens);
            if (err) break;
        } else {
            /* Top-level closes any current rule. */
            st.current_rule = NULL;

            const char *kw = tokens[0];
            if      (strcmp(kw, "varek_policy") == 0) err = handle_varek_policy(&st, n_tokens, tokens);
            else if (strcmp(kw, "strict")       == 0) err = handle_strict(&st, n_tokens, tokens);
            else if (strcmp(kw, "label")        == 0) err = handle_label(&st, n_tokens, tokens);
            else if (strcmp(kw, "sticky")       == 0) err = handle_sticky(&st, n_tokens, tokens);
            else if (strcmp(kw, "rule")         == 0) err = handle_rule(&st, n_tokens, tokens);
            else if (strcmp(kw, "refusal_budget") == 0) err = handle_refusal_budget(&st, n_tokens, tokens);
            else if (strcmp(kw, "on_exhaustion")  == 0) err = handle_on_exhaustion(&st, n_tokens, tokens);
            else if (strcmp(kw, "unknown_disposition") == 0) err = handle_unknown_disposition(&st, n_tokens, tokens);
            else                                       err = ERR_UNKNOWN_STMT;
            if (err) break;

            if (strcmp(kw, "varek_policy") != 0)
                st.any_decl_seen = true;
        }
    }

    if (!err && ferror(stream)) err = ERR_IO;

    if (err) {
        if (err_line) *err_line = st.line_no;
        if (err_msg)  *err_msg  = err;
        plan_label_policy_config_free(cfg);
        return -1;
    }

    /* Finalize the table to point at the (now stable) rules array. */
    cfg->table.rules   = cfg->rules;
    cfg->table.n_rules = cfg->n_rules;
    /* policy.ctx already points at table; policy.classify already set. */

    *out = cfg;
    return 0;
}

int plan_label_policy_config_load(const char *path,
                                  plan_label_policy_config_t **out,
                                  int *err_line,
                                  const char **err_msg)
{
    if (out) *out = NULL;
    if (err_line) *err_line = 0;
    if (err_msg)  *err_msg  = ERR_NONE;

    if (!path || !out) { if (err_msg) *err_msg = ERR_IO; return -1; }

    FILE *f = fopen(path, "r");
    if (!f) { if (err_msg) *err_msg = ERR_IO; return -1; }

    int rc = plan_label_policy_config_load_stream(f, out, err_line, err_msg);
    fclose(f);
    return rc;
}

void plan_label_policy_config_free(plan_label_policy_config_t *cfg)
{
    if (!cfg) return;
    for (size_t i = 0; i < PLAN_MAX_LABELS; i++)
        free(cfg->label_names[i]);
    if (cfg->rules) {
        for (size_t i = 0; i < cfg->n_rules; i++) {
            free((void *)cfg->rules[i].action_name);
            /* v1.7.4: free match clauses if any. */
            if (cfg->rules[i].matches) {
                for (size_t j = 0; j < cfg->rules[i].n_matches; j++) {
                    free((void *)cfg->rules[i].matches[j].key);
                    free((void *)cfg->rules[i].matches[j].pattern);
                }
                free((void *)cfg->rules[i].matches);
            }
        }
        free(cfg->rules);
    }
    free((void *)cfg->on_exhaustion.action_name);
    free((void *)cfg->unknown_disp.action_name);
    free(cfg);
}

/* ---------- Accessors ---------- */

const plan_label_policy_t *
plan_label_policy_config_policy(const plan_label_policy_config_t *cfg)
{
    return cfg ? &cfg->policy : NULL;
}

const char *plan_label_policy_config_label_name(plan_label_t tag, void *ctx)
{
    const plan_label_policy_config_t *cfg = (const plan_label_policy_config_t *)ctx;
    if (!cfg || tag >= PLAN_MAX_LABELS) return NULL;
    return cfg->label_names[tag];
}

plan_pathology_opts_t
plan_label_policy_config_pathology_opts(const plan_label_policy_config_t *cfg)
{
    plan_pathology_opts_t opts;
    opts.label_name     = plan_label_policy_config_label_name;
    opts.label_name_ctx = (void *)cfg;
    return opts;
}

size_t plan_label_policy_config_n_rules(const plan_label_policy_config_t *cfg)
{
    return cfg ? cfg->n_rules : 0;
}

size_t plan_label_policy_config_n_labels(const plan_label_policy_config_t *cfg)
{
    return cfg ? cfg->n_labels : 0;
}

/* ---------- v1.8.2 / v1.9 accessors ---------- */

bool plan_label_policy_config_breaker_enabled(const plan_label_policy_config_t *cfg)
{
    return cfg && cfg->budget_set;
}

unsigned plan_label_policy_config_refusal_budget(const plan_label_policy_config_t *cfg)
{
    return cfg ? cfg->refusal_budget : 0u;
}

plan_disposition_t
plan_label_policy_config_on_exhaustion(const plan_label_policy_config_t *cfg)
{
    plan_disposition_t deny = { PLAN_DISP_DENY, NULL };
    return cfg ? cfg->on_exhaustion : deny;
}

plan_disposition_t
plan_label_policy_config_unknown_disposition(const plan_label_policy_config_t *cfg)
{
    plan_disposition_t deny = { PLAN_DISP_DENY, NULL };
    return cfg ? cfg->unknown_disp : deny;
}

bool plan_label_policy_config_has_action(const plan_label_policy_config_t *cfg,
                                         const char *action_name)
{
    if (!cfg || !action_name) return false;
    for (size_t i = 0; i < cfg->n_rules; i++) {
        if (cfg->rules[i].action_name &&
            strcmp(cfg->rules[i].action_name, action_name) == 0)
            return true;
    }
    return false;
}

bool plan_label_policy_config_can_refuse(const plan_label_policy_config_t *cfg)
{
    if (!cfg) return false;
    if (!plan_label_set_empty(&cfg->policy.sticky)) return true;
    for (size_t i = 0; i < cfg->n_rules; i++) {
        const plan_label_class_t *c = &cfg->rules[i].classify;
        if (!plan_label_set_empty(&c->deny_in))    return true;
        if (!plan_label_set_empty(&c->unknown_in)) return true;
    }
    return false;
}

bool plan_label_policy_config_action_denies_sticky(
        const plan_label_policy_config_t *cfg, const char *action_name)
{
    if (!cfg || !action_name) return false;
    const plan_label_set_t *sticky = &cfg->policy.sticky;
    if (plan_label_set_empty(sticky)) return false;
    for (size_t i = 0; i < cfg->n_rules; i++) {
        if (!cfg->rules[i].action_name ||
            strcmp(cfg->rules[i].action_name, action_name) != 0)
            continue;
        const plan_label_class_t *c = &cfg->rules[i].classify;
        if (plan_label_set_intersects(&c->deny_in, sticky))    return true;
        if (plan_label_set_intersects(&c->unknown_in, sticky)) return true;
    }
    return false;
}
