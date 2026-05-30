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

/* All match constraints on a rule must hold. A rule with no matches
 * (n_matches == 0) is name-only and always passes this check. */
static bool rule_matches_action(const plan_label_rule_t *r,
                                const plan_action_desc_t *action)
{
    for (size_t i = 0; i < r->n_matches; i++) {
        const plan_label_rule_match_t *m = &r->matches[i];
        const char *val = find_named_arg(action, m->key);
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
