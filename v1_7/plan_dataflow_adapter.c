// SPDX-License-Identifier: MIT
/*
 * plan_dataflow_adapter.c — VAREK v1.7.1 adapter implementation and
 * reference table-driven label policy.
 */

#include "plan_dataflow_adapter.h"
#include "plan_label_policy.h"
#include "plan_dataflow.h"
#include "execution_plan.h"

#include <string.h>

/* ---------- Reference table-driven policy ---------- */

/* Shell-style glob matcher (v1.7.4). Supports '*' (any chars including
 * none) and '?' (exactly one char); every other byte is literal.
 * Standard greedy-with-backtrack implementation; O(n*m) worst case,
 * linear in practice. Returns true iff pattern matches the whole
 * string. */
static bool glob_match(const char *pattern, const char *s)
{
    if (!pattern || !s) return false;
    const char *star_p = NULL;
    const char *star_s = NULL;
    while (*s) {
        if (*pattern == '?' || *pattern == *s) {
            pattern++; s++;
        } else if (*pattern == '*') {
            star_p = pattern++;     /* remember position after '*' */
            star_s = s;             /* remember string position at '*' */
        } else if (star_p) {
            pattern = star_p + 1;   /* backtrack: extend the '*' match by one char */
            s = ++star_s;
        } else {
            return false;
        }
    }
    while (*pattern == '*') pattern++;
    return *pattern == '\0';
}

/* Look up a named arg by key on an action descriptor. Returns the
 * value string, or NULL if the action has no such named arg. v1.7.4. */
static const char *find_named_arg(const plan_action_desc_t *action,
                                  const char *key)
{
    if (!action || !key || !action->named_args) return NULL;
    for (size_t i = 0; i < action->n_named_args; i++) {
        const plan_action_arg_t *a = &action->named_args[i];
        if (a->key && strcmp(a->key, key) == 0)
            return a->value;
    }
    return NULL;
}

/* v1.18.0: URL components as match keys.
 *
 * A glob over a whole URL cannot say "this host". In the v1.7.4 example rule
 * `match url https://<star>.internal.acme.com/<star>` (<star> = '*') the first
 * star also matches '/', '?', '#' and '@', so https://evil.example/x.internal.acme.com/
 * and https://evil.example#.internal.acme.com/ matched the "internal only" rule.
 * A key of the form <arg>.scheme, <arg>.host, <arg>.port or <arg>.path parses
 * the named arg <arg> as an absolute URL and matches the pattern against that
 * one component: `match url.host *.internal.acme.com`.
 *
 * The parse is strict, and a URL it rejects matches no component rule (the
 * permissive rule does not apply, so a later name-only rule decides):
 *   scheme  [A-Za-z][A-Za-z0-9+.-]* then "://", lower-cased;
 *   authority up to the first '/', '?' or '#'; any '@' (userinfo) or '\\'
 *           rejects the URL, since readers disagree about which host it names;
 *   host    [A-Za-z0-9.-] only (no percent-encoding), lower-cased, one
 *           trailing '.' dropped, not empty; or a bracketed IPv6 literal;
 *   port    digits after ':', 1 to 65535; empty when absent;
 *   path    the rest up to '?' or '#', "/" when empty. */
#define URL_PART_MAX 512

static int url_component(const char *url, const char *part, char *out, size_t outsz)
{
    if (!url || !part || outsz < 2) return -1;
    const char *p = url;
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))) return -1;
    while ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
           (*p >= '0' && *p <= '9') || *p == '+' || *p == '.' || *p == '-') p++;
    if (strncmp(p, "://", 3) != 0) return -1;
    size_t scheme_len = (size_t)(p - url);
    const char *auth = p + 3;
    size_t auth_len = strcspn(auth, "/?#");
    if (auth_len == 0) return -1;
    for (size_t i = 0; i < auth_len; i++)
        if (auth[i] == '@' || auth[i] == '\\') return -1;

    const char *host = auth, *host_end, *port = NULL;
    const char *auth_end = auth + auth_len;
    if (*host == '[') {
        host_end = memchr(host, ']', auth_len);
        if (!host_end) return -1;
        for (const char *q = host + 1; q < host_end; q++)
            if (!((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') ||
                  (*q >= 'A' && *q <= 'F') || *q == ':' || *q == '.')) return -1;
        host_end++;
        if (host_end < auth_end) {
            if (*host_end != ':') return -1;
            port = host_end + 1;
        }
    } else {
        host_end = memchr(host, ':', auth_len);
        if (host_end) port = host_end + 1; else host_end = auth_end;
        if (host_end == host) return -1;
        for (const char *q = host; q < host_end; q++)
            if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
                  (*q >= '0' && *q <= '9') || *q == '.' || *q == '-')) return -1;
    }
    unsigned long portnum = 0;
    if (port) {
        if (port == auth_end) return -1;
        for (const char *q = port; q < auth_end; q++) {
            if (*q < '0' || *q > '9') return -1;
            portnum = portnum * 10 + (unsigned long)(*q - '0');
            if (portnum > 65535) return -1;
        }
        if (portnum == 0) return -1;
    }

    const char *src; size_t len;
    bool lower = false;
    if (strcmp(part, "scheme") == 0) {
        src = url; len = scheme_len; lower = true;
    } else if (strcmp(part, "host") == 0) {
        src = host; len = (size_t)(host_end - host); lower = true;
        if (len > 1 && src[len - 1] == '.' && src[0] != '[') len--;
        if (len == 0 || src[len - 1] == '.' || src[0] == '.') return -1;
        for (size_t i = 1; i < len; i++)
            if (src[i] == '.' && src[i - 1] == '.') return -1;   /* empty label */
    } else if (strcmp(part, "port") == 0) {
        src = port ? port : ""; len = port ? (size_t)(auth_end - port) : 0;
    } else if (strcmp(part, "path") == 0) {
        src = auth_end; len = strcspn(auth_end, "?#");
        if (len == 0) { src = "/"; len = 1; }
        /* Matched as written, so refuse what a server would rewrite: an
         * encoded byte ("%2f", "%2e"), a backslash, a "." or ".." segment. */
        for (size_t i = 0; i < len; i++) {
            if (src[i] == '%' || src[i] == '\\') return -1;
            if (src[i] == '.' && (i == 0 || src[i - 1] == '/')) {
                size_t k = i + 1;
                if (k < len && src[k] == '.') k++;
                if (k == len || src[k] == '/') return -1;
            }
        }
    } else {
        return -1;
    }
    if (len >= outsz) return -1;
    for (size_t i = 0; i < len; i++) {
        char c = src[i];
        out[i] = (lower && c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    out[len] = '\0';
    return 0;
}

/* The value a match constraint tests: the named arg itself, or (v1.18.0) one
 * URL component of it for a key "<arg>.<part>". NULL when the action has no
 * such arg or its URL does not parse. */
/* If key is a URL component key "<arg>.<part>", write <arg> to base and
 * return the part name; else NULL. */
static const char *component_key(const char *key, char *base, size_t basesz)
{
    const char *dot = key ? strrchr(key, '.') : NULL;
    if (!dot || dot == key) return NULL;
    const char *part = dot + 1;
    if (strcmp(part, "scheme") && strcmp(part, "host") &&
        strcmp(part, "port") && strcmp(part, "path")) return NULL;
    size_t bl = (size_t)(dot - key);
    if (bl >= basesz) return NULL;
    memcpy(base, key, bl);
    base[bl] = '\0';
    return part;
}

/* A component key is always derived from the URL in <arg>: an argument that is
 * literally named "url.host" is never consulted, or a caller could pass
 * url=https://evil.example/ with "url.host"=x.internal.acme.com. */
static const char *match_value(const plan_action_desc_t *action, const char *key,
                               char *buf, size_t bufsz)
{
    char base[128];
    const char *part = component_key(key, base, sizeof base);
    if (!part) return find_named_arg(action, key);
    const char *url = find_named_arg(action, base);
    if (!url || url_component(url, part, buf, bufsz) != 0) return NULL;
    return buf;
}

/* True if some rule for this action tests a component of a URL argument the
 * action carries, and that URL does not parse for that component. The
 * classification then fails (the plan is refused) instead of the rule simply
 * not matching: with first-match-wins, a deny rule on url.host that skipped an
 * unparseable URL would let it fall through to a later, more permissive rule
 * (https://u@a.evil.example/ past `match url.host *.evil.example`). */
static bool unparseable_component(const plan_label_table_t *tbl,
                                  const plan_action_desc_t *action)
{
    char base[128], buf[URL_PART_MAX];
    for (size_t i = 0; i < tbl->n_rules; i++) {
        const plan_label_rule_t *r = &tbl->rules[i];
        if (!r->action_name || strcmp(r->action_name, action->name) != 0) continue;
        for (size_t j = 0; j < r->n_matches; j++) {
            const char *part = component_key(r->matches[j].key, base, sizeof base);
            if (!part) continue;
            const char *url = find_named_arg(action, base);
            if (url && url_component(url, part, buf, sizeof buf) != 0) return true;
        }
    }
    return false;
}

/* All match constraints on a rule must hold. A rule with no matches
 * (n_matches == 0) is name-only and always passes this check. */
static bool rule_matches_action(const plan_label_rule_t *r,
                                const plan_action_desc_t *action)
{
    char buf[URL_PART_MAX];
    for (size_t i = 0; i < r->n_matches; i++) {
        const plan_label_rule_match_t *m = &r->matches[i];
        const char *val = match_value(action, m->key, buf, sizeof buf);
        if (!val) return false;
        if (!glob_match(m->pattern, val)) return false;
    }
    return true;
}

int plan_label_policy_from_table(const plan_action_desc_t *action,
                                 plan_label_class_t *out,
                                 void *ctx)
{
    if (!action || !out || !ctx)
        return -1;

    const plan_label_table_t *tbl = (const plan_label_table_t *)ctx;

    /* v1.18.0: fail closed on a URL a component rule cannot read. */
    if (action->name && unparseable_component(tbl, action))
        return -1;

    for (size_t i = 0; i < tbl->n_rules; i++) {
        const plan_label_rule_t *r = &tbl->rules[i];
        if (!r->action_name || !action->name)
            continue;
        if (strcmp(r->action_name, action->name) != 0)
            continue;
        /* v1.7.4: argument constraints must also hold. */
        if (!rule_matches_action(r, action))
            continue;
        *out = r->classify;
        return 0;
    }

    /* No match. */
    if (tbl->strict)
        return -1;

    /* Non-strict: empty classification. The kernel's sticky check
     * still catches any sticky inbound label at this node (it will
     * be unclassified here, hence UNKNOWN). That is the principled
     * fail-safe default and the reason non-strict is acceptable. */
    plan_label_set_clear(&out->origin);
    plan_label_set_clear(&out->deny_in);
    plan_label_set_clear(&out->unknown_in);
    plan_label_set_clear(&out->permit_in);
    plan_label_set_clear(&out->declassify);
    return 0;
}

/* ---------- Adapter ---------- */

/* Apply a label set to the data-flow companion via a per-tag setter.
 * Returns 0 on success, -1 on the first setter failure. */
typedef int (*per_tag_setter_t)(plan_dataflow_t *, plan_node_id_t, plan_label_t);

static int apply_set(plan_dataflow_t *df, plan_node_id_t node,
                     const plan_label_set_t *set, per_tag_setter_t setter)
{
    for (plan_label_t t = 0; t < PLAN_MAX_LABELS; t++) {
        if (plan_label_set_test(set, t)) {
            if (setter(df, node, t) != 0)
                return -1;
        }
    }
    return 0;
}

int plan_dataflow_populate(plan_dataflow_t *df,
                           const plan_action_desc_t *actions,
                           size_t n_actions,
                           const plan_label_policy_t *policy)
{
    if (!df || !actions || !policy || !policy->classify)
        return -1;

    /* The plan's node count must match the action array length. The
     * v1.6.1 adapter assigns node ids in insertion order, so this
     * indexing is the convention. */
    const exec_plan_t *plan = plan_dataflow_get_plan(df);
    if (!plan)
        return -1;
    const size_t plan_n = exec_plan_node_count(plan);

    if (plan_n != n_actions)
        return -1;

    /* Apply the policy's sticky set plan-wide. */
    for (plan_label_t t = 0; t < PLAN_MAX_LABELS; t++) {
        if (plan_label_set_test(&policy->sticky, t)) {
            if (plan_dataflow_mark_sticky(df, t) != 0)
                return -1;
        }
    }

    /* Classify each action and write its label sets onto its node. */
    for (size_t i = 0; i < n_actions; i++) {
        plan_label_class_t cls;
        plan_label_set_clear(&cls.origin);
        plan_label_set_clear(&cls.deny_in);
        plan_label_set_clear(&cls.unknown_in);
        plan_label_set_clear(&cls.permit_in);
        plan_label_set_clear(&cls.declassify);

        if (policy->classify(&actions[i], &cls, policy->ctx) != 0)
            return -1;

        const plan_node_id_t node = (plan_node_id_t)i;
        if (apply_set(df, node, &cls.origin,     plan_dataflow_add_origin)     != 0)
            return -1;
        if (apply_set(df, node, &cls.deny_in,    plan_dataflow_add_deny_in)    != 0)
            return -1;
        if (apply_set(df, node, &cls.unknown_in, plan_dataflow_add_unknown_in) != 0)
            return -1;
        if (apply_set(df, node, &cls.permit_in,  plan_dataflow_add_permit_in)  != 0)
            return -1;
        if (apply_set(df, node, &cls.declassify, plan_dataflow_add_declassify) != 0)
            return -1;
    }

    return 0;
}
