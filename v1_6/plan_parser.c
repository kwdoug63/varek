// SPDX-License-Identifier: MIT
/*
 * plan_parser.c — text-format plan file parser implementation.
 *
 * The handle owns all string storage. We strdup() each token into
 * the handle's allocation list so the plan_spec_t view can safely
 * borrow those pointers for the lifetime of the handle.
 *
 * Design notes:
 *   - Two-pass on labels: actions parsed first build a label table;
 *     edge labels are resolved by linear lookup. Action counts are
 *     small so linear search is fine.
 *   - Tokenization is whitespace-only (space and tab). No quoting,
 *     no escape sequences. Tokens with internal whitespace must
 *     wait for a richer format.
 *   - Line length is capped at PLAN_LINE_MAX. Longer lines are an
 *     error rather than silent truncation.
 */

#define _POSIX_C_SOURCE 200809L

#include "plan_parser.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PLAN_PARSE_MAX_ACTIONS  256u
#define PLAN_PARSE_MAX_EDGES   1024u
#define PLAN_LABEL_MAX          64u
#define PLAN_LINE_MAX         1024u
#define PLAN_OWNED_STRINGS_MAX (PLAN_PARSE_MAX_ACTIONS * 4u)

struct plan_parsed {
    /* Owned string storage. Every const char * inside actions[]
     * points into one of these slots. */
    char  *owned[PLAN_OWNED_STRINGS_MAX];
    size_t n_owned;

    /* Action label table — parallel to actions[] for edge lookup. */
    char   labels[PLAN_PARSE_MAX_ACTIONS][PLAN_LABEL_MAX];

    plan_spec_action_t actions[PLAN_PARSE_MAX_ACTIONS];
    size_t             n_actions;

    plan_spec_edge_t   edges[PLAN_PARSE_MAX_EDGES];
    size_t             n_edges;

    plan_spec_t        spec;
};

static void set_err(char *buf, size_t len, const char *path, size_t line,
                    const char *msg)
{
    if (!buf || len == 0) return;
    if (path) {
        snprintf(buf, len, "%s:%zu: %s", path, line, msg);
    } else {
        snprintf(buf, len, "(plan):%zu: %s", line, msg);
    }
}

/* Strdup into the handle's owned-strings table. Returns NULL and
 * sets err on table overflow. */
static const char *intern(plan_parsed_t *h, const char *s,
                          char *err, size_t err_len)
{
    if (h->n_owned >= PLAN_OWNED_STRINGS_MAX) {
        if (err) snprintf(err, err_len, "intern table exhausted");
        return NULL;
    }
    char *dup = strdup(s);
    if (!dup) {
        if (err) snprintf(err, err_len, "out of memory");
        return NULL;
    }
    h->owned[h->n_owned++] = dup;
    return dup;
}

static int is_label_char(int c, int leading)
{
    if (isalpha(c) || c == '_') return 1;
    if (!leading && (isdigit(c) || c == '-')) return 1;
    return 0;
}

static int valid_label(const char *s)
{
    if (!s || !*s) return 0;
    if (!is_label_char((unsigned char)s[0], 1)) return 0;
    for (const char *p = s + 1; *p; p++) {
        if (!is_label_char((unsigned char)*p, 0)) return 0;
    }
    return strlen(s) < PLAN_LABEL_MAX;
}

/* Find a label's action index. Returns SIZE_MAX if not present. */
static size_t find_label(const plan_parsed_t *h, const char *label)
{
    for (size_t i = 0; i < h->n_actions; i++) {
        if (strcmp(h->labels[i], label) == 0) return i;
    }
    return (size_t)-1;
}

/* Trim trailing CR/LF/whitespace and return pointer to first
 * non-whitespace char. Mutates the buffer. */
static char *trim_inplace(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    return s;
}

/* strtok_r over whitespace. */
static char *next_token(char **saveptr)
{
    return strtok_r(NULL, " \t", saveptr);
}

static int parse_line(plan_parsed_t *h, const char *path, size_t lineno,
                      char *line, char *err, size_t err_len)
{
    char *trimmed = trim_inplace(line);
    if (*trimmed == '\0' || *trimmed == '#') return 0;   /* blank/comment */

    char *saveptr = NULL;
    char *directive = strtok_r(trimmed, " \t", &saveptr);
    if (!directive) return 0;

    if (strcmp(directive, "action") == 0) {
        if (h->n_actions >= PLAN_PARSE_MAX_ACTIONS) {
            set_err(err, err_len, path, lineno, "too many actions");
            return -1;
        }
        char *label  = next_token(&saveptr);
        char *kind   = next_token(&saveptr);
        char *target = next_token(&saveptr);
        char *extra  = next_token(&saveptr);

        if (!label || !kind || !target) {
            set_err(err, err_len, path, lineno,
                    "action requires: action <label> <kind> <target>");
            return -1;
        }
        if (extra) {
            set_err(err, err_len, path, lineno,
                    "action accepts only three fields; quote-bearing targets unsupported");
            return -1;
        }
        if (!valid_label(label)) {
            set_err(err, err_len, path, lineno,
                    "invalid label (use [A-Za-z_][A-Za-z0-9_-]*)");
            return -1;
        }
        if (find_label(h, label) != (size_t)-1) {
            set_err(err, err_len, path, lineno, "duplicate action label");
            return -1;
        }

        const char *kind_s   = intern(h, kind,   err, err_len);
        const char *target_s = intern(h, target, err, err_len);
        const char *label_s  = intern(h, label,  err, err_len);
        if (!kind_s || !target_s || !label_s) return -1;

        size_t idx = h->n_actions;
        h->actions[idx].kind       = kind_s;
        h->actions[idx].target     = target_s;
        h->actions[idx].parameters = NULL;
        h->actions[idx].label      = label_s;
        snprintf(h->labels[idx], PLAN_LABEL_MAX, "%s", label);
        h->n_actions++;
        return 0;
    }

    if (strcmp(directive, "edge") == 0) {
        if (h->n_edges >= PLAN_PARSE_MAX_EDGES) {
            set_err(err, err_len, path, lineno, "too many edges");
            return -1;
        }
        char *from = next_token(&saveptr);
        char *to   = next_token(&saveptr);
        char *extra = next_token(&saveptr);

        if (!from || !to) {
            set_err(err, err_len, path, lineno,
                    "edge requires: edge <from_label> <to_label>");
            return -1;
        }
        if (extra) {
            set_err(err, err_len, path, lineno, "edge accepts only two labels");
            return -1;
        }

        size_t fi = find_label(h, from);
        size_t ti = find_label(h, to);
        if (fi == (size_t)-1) {
            set_err(err, err_len, path, lineno, "edge 'from' label undefined");
            return -1;
        }
        if (ti == (size_t)-1) {
            set_err(err, err_len, path, lineno, "edge 'to' label undefined");
            return -1;
        }
        if (fi == ti) {
            set_err(err, err_len, path, lineno, "self-edge rejected");
            return -1;
        }
        if (fi > UINT32_MAX || ti > UINT32_MAX) {
            set_err(err, err_len, path, lineno, "label index overflow");
            return -1;
        }

        h->edges[h->n_edges].from_idx = (uint32_t)fi;
        h->edges[h->n_edges].to_idx   = (uint32_t)ti;
        h->n_edges++;
        return 0;
    }

    set_err(err, err_len, path, lineno,
            "unknown directive (expected 'action' or 'edge')");
    return -1;
}

plan_parsed_t *plan_parser_load(const char *path,
                                char       *err_buf,
                                size_t      err_buf_len)
{
    if (!path) {
        if (err_buf && err_buf_len) snprintf(err_buf, err_buf_len, "null path");
        return NULL;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (err_buf && err_buf_len) {
            snprintf(err_buf, err_buf_len, "%s: cannot open", path);
        }
        return NULL;
    }

    plan_parsed_t *h = calloc(1, sizeof(*h));
    if (!h) {
        fclose(fp);
        if (err_buf && err_buf_len) snprintf(err_buf, err_buf_len, "out of memory");
        return NULL;
    }

    char line[PLAN_LINE_MAX];
    size_t lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        size_t n = strlen(line);
        if (n > 0 && line[n - 1] != '\n' && !feof(fp)) {
            set_err(err_buf, err_buf_len, path, lineno, "line too long");
            plan_parser_free(h);
            fclose(fp);
            return NULL;
        }
        if (parse_line(h, path, lineno, line, err_buf, err_buf_len) != 0) {
            plan_parser_free(h);
            fclose(fp);
            return NULL;
        }
    }
    fclose(fp);

    if (h->n_actions == 0) {
        set_err(err_buf, err_buf_len, path, lineno, "no actions declared");
        plan_parser_free(h);
        return NULL;
    }

    h->spec.actions   = h->actions;
    h->spec.n_actions = h->n_actions;
    h->spec.edges     = h->edges;
    h->spec.n_edges   = h->n_edges;
    return h;
}

const plan_spec_t *plan_parser_spec(const plan_parsed_t *parsed)
{
    return parsed ? &parsed->spec : NULL;
}

size_t plan_parser_action_count(const plan_parsed_t *parsed)
{
    return parsed ? parsed->n_actions : 0;
}

size_t plan_parser_edge_count(const plan_parsed_t *parsed)
{
    return parsed ? parsed->n_edges : 0;
}

void plan_parser_free(plan_parsed_t *parsed)
{
    if (!parsed) return;
    for (size_t i = 0; i < parsed->n_owned; i++) free(parsed->owned[i]);
    free(parsed);
}
