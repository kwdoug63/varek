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
 *   - Tokenization is whitespace-only (space and tab) for the
 *     directive, label, kind and target. v1.20.0: after the target an
 *     action may carry fields, key=value, whose value may be quoted
 *     ("...", with \" \\ \n \r \t and \xHH escapes) so it can hold
 *     spaces. See plan_parser.h.
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
#define PLAN_LINE_MAX        16384u   /* v1.20.0: was 1024; a line may carry fields */
#define PLAN_OWNED_STRINGS_MAX (PLAN_PARSE_MAX_ACTIONS * (4u + 2u * PLAN_FIELDS_MAX))

struct plan_parsed {
    /* Owned string storage. Every const char * inside actions[]
     * points into one of these slots. */
    char  *owned[PLAN_OWNED_STRINGS_MAX];
    size_t n_owned;

    /* Action label table — parallel to actions[] for edge lookup. */
    char   labels[PLAN_PARSE_MAX_ACTIONS][PLAN_LABEL_MAX];

    plan_spec_action_t actions[PLAN_PARSE_MAX_ACTIONS];
    size_t             n_actions;

    /* v1.20.0: each action's fields, in file order. */
    plan_spec_field_t  fields[PLAN_PARSE_MAX_ACTIONS][PLAN_FIELDS_MAX];
    size_t             n_fields[PLAN_PARSE_MAX_ACTIONS];

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

/* v1.20.0: a field key, [a-z][a-z0-9_]{0,31}. No '.', so a key cannot
 * collide with a flow rule's URL component keys (url.host and so on). */
static int valid_field_key(const char *s, size_t n)
{
    if (n == 0 || n > PLAN_FIELD_KEY_MAX) return 0;
    if (!(s[0] >= 'a' && s[0] <= 'z')) return 0;
    for (size_t i = 1; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return 0;
    }
    return 1;
}

static int hexdig(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse the fields that follow an action's target: key=value separated by
 * spaces or tabs. A bare value runs to the next space or tab and holds no
 * '"' and no control character. A quoted value is "...": the escapes \"
 * \\ \n \r \t and \xHH (not \x00) are decoded, any other backslash is
 * an error, a raw control character other than tab is an error, and the
 * closing quote must end the token. Returns 0, or -1 with err set. */
static int parse_fields(plan_parsed_t *h, size_t idx, char *p, const char *path,
                        size_t lineno, char *err, size_t err_len)
{
    char value[PLAN_FIELD_VALUE_MAX + 1];
    for (;;) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) return 0;
        const char *key = p;
        while (*p && *p != '=' && *p != ' ' && *p != '\t') p++;
        size_t kl = (size_t)(p - key);
        if (*p != '=') {
            set_err(err, err_len, path, lineno,
                    "after the target an action takes only key=value fields");
            return -1;
        }
        if (!valid_field_key(key, kl)) {
            set_err(err, err_len, path, lineno,
                    "invalid field name (use [a-z][a-z0-9_]*, at most 32 characters)");
            return -1;
        }
        *p++ = '\0';                                       /* terminate the key */
        if (strcmp(key, "target") == 0) {
            set_err(err, err_len, path, lineno,
                    "field 'target' is reserved (the target is the third field)");
            return -1;
        }
        for (size_t i = 0; i < h->n_fields[idx]; i++)
            if (strcmp(h->fields[idx][i].key, key) == 0) {
                set_err(err, err_len, path, lineno, "duplicate field in one action");
                return -1;
            }
        if (h->n_fields[idx] >= PLAN_FIELDS_MAX) {
            set_err(err, err_len, path, lineno, "too many fields in one action (at most 16)");
            return -1;
        }
        size_t vl = 0;
        if (*p == '"') {
            p++;
            for (;;) {
                unsigned char c = (unsigned char)*p;
                if (c == '\0') {
                    set_err(err, err_len, path, lineno, "unterminated quoted field value");
                    return -1;
                }
                if (c == '"') { p++; break; }
                if (c == '\\') {
                    char e = p[1];
                    int hi, lo;
                    if (e == '"' || e == '\\') { c = (unsigned char)e; p += 2; }
                    else if (e == 'n') { c = '\n'; p += 2; }
                    else if (e == 'r') { c = '\r'; p += 2; }
                    else if (e == 't') { c = '\t'; p += 2; }
                    else if (e == 'x' && (hi = hexdig(p[2])) >= 0 && (lo = hexdig(p[3])) >= 0 &&
                             (hi | lo) != 0) {
                        c = (unsigned char)(hi * 16 + lo);
                        p += 4;
                    } else {
                        set_err(err, err_len, path, lineno,
                                "bad escape in a quoted field value (use \\\" \\\\ \\n \\r \\t or \\xHH, not \\x00)");
                        return -1;
                    }
                } else {
                    if ((c < 0x20 && c != '\t') || c == 0x7f) {
                        set_err(err, err_len, path, lineno, "control character in a field value");
                        return -1;
                    }
                    p++;
                }
                if (vl >= PLAN_FIELD_VALUE_MAX) {
                    set_err(err, err_len, path, lineno, "field value too long (at most 4096 bytes)");
                    return -1;
                }
                value[vl++] = (char)c;
            }
            if (*p && *p != ' ' && *p != '\t') {
                set_err(err, err_len, path, lineno, "text after a closing quote");
                return -1;
            }
        } else {
            while (*p && *p != ' ' && *p != '\t') {
                unsigned char c = (unsigned char)*p;
                if (c == '"' || c < 0x20 || c == 0x7f) {
                    set_err(err, err_len, path, lineno,
                            "a bare field value holds no '\"' or control character (quote it)");
                    return -1;
                }
                if (vl >= PLAN_FIELD_VALUE_MAX) {
                    set_err(err, err_len, path, lineno, "field value too long (at most 4096 bytes)");
                    return -1;
                }
                value[vl++] = (char)c;
                p++;
            }
        }
        value[vl] = '\0';
        const char *k = intern(h, key, err, err_len);
        const char *v = k ? intern(h, value, err, err_len) : NULL;
        if (!k || !v) return -1;
        h->fields[idx][h->n_fields[idx]].key   = k;
        h->fields[idx][h->n_fields[idx]].value = v;
        h->n_fields[idx]++;
    }
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
        /* The target is a whitespace token; the rest of the line holds the
         * fields, which need their own scanner (a quoted value may hold
         * spaces), so strtok stops here. */
        char *target = NULL, *rest = NULL;
        if (kind && saveptr) {
            char *q = saveptr;
            while (*q == ' ' || *q == '\t') q++;
            if (*q) {
                target = q;
                while (*q && *q != ' ' && *q != '\t') q++;
                if (*q) *q++ = '\0';
                rest = q;
            }
        }

        if (!label || !kind || !target) {
            set_err(err, err_len, path, lineno,
                    "action requires: action <label> <kind> <target> [key=value ...]");
            return -1;
        }
        if (strlen(target) > PLAN_TARGET_MAX) {
            set_err(err, err_len, path, lineno, "target too long (at most 4095 bytes)");
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
        h->n_fields[idx] = 0;
        if (rest && parse_fields(h, idx, rest, path, lineno, err, err_len) != 0) return -1;
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

    /* v1.20.0: getline, so a NUL byte is seen (fgets would stop the string
     * there and drop the rest of the line unseen) and the limit is exact: a
     * line holds fewer than PLAN_LINE_MAX bytes, not counting its newline. */
    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    size_t lineno = 0;
    while ((got = getline(&line, &cap, fp)) >= 0) {
        lineno++;
        size_t n = (size_t)got;
        if (n > 0 && line[n - 1] == '\n') n--;
        const char *why = NULL;
        if (n >= PLAN_LINE_MAX)             why = "line too long (at most 16383 bytes)";
        else if (memchr(line, '\0', n))     why = "NUL byte in line";
        if (why) set_err(err_buf, err_buf_len, path, lineno, why);
        if (why || parse_line(h, path, lineno, line, err_buf, err_buf_len) != 0) {
            free(line);
            plan_parser_free(h);
            fclose(fp);
            return NULL;
        }
    }
    free(line);
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

const plan_spec_field_t *plan_parser_fields(const plan_parsed_t *parsed, size_t action_idx,
                                            size_t *n_out)
{
    if (n_out) *n_out = 0;
    if (!parsed || action_idx >= parsed->n_actions) return NULL;
    if (n_out) *n_out = parsed->n_fields[action_idx];
    return parsed->n_fields[action_idx] ? parsed->fields[action_idx] : NULL;
}

void plan_parser_free(plan_parsed_t *parsed)
{
    if (!parsed) return;
    for (size_t i = 0; i < parsed->n_owned; i++) free(parsed->owned[i]);
    free(parsed);
}
