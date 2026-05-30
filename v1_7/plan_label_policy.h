// SPDX-License-Identifier: MIT
/*
 * plan_label_policy.h — VAREK v1.7.1 label-policy adapter surface.
 *
 * The v1.7.0 kernel evaluates supplied label sets and a supplied
 * sticky set; it does not classify actions. v1.7.1 introduces the
 * adapter surface that classifies — turning a planned action into
 * its origin / deny-in / unknown-in / permit-in label sets — and
 * leaves the kernel unaware of action semantics.
 *
 * This mirrors v1.6's split: the v1.6.0 kernel evaluates supplied
 * per-node decisions; the v1.6.1 adapter calls the Warden's
 * policy_decide() to produce them. The v1.7.1 label policy is the
 * analogous surface on the flow axis, layered alongside (not
 * replacing) policy_decide().
 *
 * The interface is a callback. A reference implementation that
 * matches actions by name against a declarative rule table is
 * provided (plan_label_policy_from_table). Deployments with richer
 * matching (environment context, dynamic classification) supply
 * their own callback.
 *
 * v1.7.4: the reference table policy gains ARGUMENT MATCHING. An
 * action descriptor may carry structured key/value arguments, and a
 * rule may carry argument predicates (key + glob pattern, matched
 * via POSIX fnmatch). A rule matches an action iff its action_name
 * matches AND every argument predicate matches. Predicates are
 * AND-combined; rules are tried in order and the FIRST fully-matching
 * rule wins. Order rules specific-to-general, with a name-only rule
 * last as the safe default. Glob (not regex) is used deliberately:
 * bounded, auditable, no catastrophic backtracking. Argument matching
 * can only grant explicit permits; anything an arg-matched rule does
 * not classify still hits the kernel's sticky fail-safe (UNKNOWN).
 */

#ifndef VAREK_V1_7_PLAN_LABEL_POLICY_H
#define VAREK_V1_7_PLAN_LABEL_POLICY_H

#include <stdbool.h>
#include <stddef.h>

#include "plan_label.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A named argument carried alongside an action descriptor. The
 * adapter stringifies non-string args at the boundary so the policy
 * surface stays simple. Added in v1.7.4. */
typedef struct plan_action_arg {
    const char *key;        /* e.g. "url", "path", "method" */
    const char *value;      /* string form; e.g. "https://api.example.com/v1" */
} plan_action_arg_t;

/* Action descriptor handed to the policy callback. Fields are
 * borrowed; the callback must not retain pointers. */
typedef struct plan_action_desc {
    const char *name;       /* e.g. "read_file", "send_http" */
    const void *args;       /* opaque, deployment-specific; may be NULL */
    size_t      args_len;
    /* v1.7.4: named arguments for pattern matching in the reference
     * table-driven policy. NULL / 0 = no named args (v1.7.3-compatible
     * behavior; name-only matching). Custom callbacks may also inspect
     * these. */
    const plan_action_arg_t *named_args;
    size_t                   n_named_args;
} plan_action_desc_t;

/* Output of a classification: the label-set slots populated by
 * the policy. Slots not relevant to the action stay empty. */
typedef struct plan_label_class {
    plan_label_set_t origin;
    plan_label_set_t deny_in;
    plan_label_set_t unknown_in;
    plan_label_set_t permit_in;
    plan_label_set_t declassify;   /* v1.8.0 */
} plan_label_class_t;

/* Policy callback. Returns 0 on success, -1 on policy error (e.g.
 * unrecognized action and the policy chose strict matching). On
 * success, '*out' contains the action's label sets. */
typedef int (*plan_label_policy_fn)(const plan_action_desc_t *action,
                                    plan_label_class_t *out,
                                    void *ctx);

/* Policy bundle: callback plus its context plus the plan-wide sticky
 * set the policy wants enforced. The adapter applies 'sticky' to the
 * data-flow companion once and uses 'classify' once per action. */
typedef struct plan_label_policy {
    plan_label_policy_fn classify;
    void                *ctx;
    plan_label_set_t     sticky;
} plan_label_policy_t;

/* ---------- Reference table-driven policy ---------- */

/* A single argument-match constraint on a rule (v1.7.4). The rule
 * applies only if the action carries a named arg with this key and
 * the arg's value matches the glob pattern. All constraints on a
 * rule must hold (AND). Pointers are borrowed from the policy
 * owner. */
typedef struct plan_label_rule_match {
    const char *key;        /* named-arg key the action must carry */
    const char *pattern;    /* shell-style glob: * = any chars, ? = one char */
} plan_label_rule_match_t;

/* A single rule: match an action by exact name (and optional argument
 * constraints) and emit fixed label sets. Pointers are borrowed;
 * the rule table must outlive the policy that references it.
 *
 * v1.7.4: 'matches' / 'n_matches' are optional. If n_matches == 0,
 * matching is name-only (v1.7.3-compatible). Otherwise, the rule
 * matches only when the action's name equals action_name AND every
 * match constraint holds. Rules are walked in declaration order;
 * first match wins. */
typedef struct plan_label_rule {
    const char        *action_name;
    plan_label_class_t classify;
    const plan_label_rule_match_t *matches;     /* optional, NULL ok */
    size_t                         n_matches;
} plan_label_rule_t;

typedef struct plan_label_table {
    const plan_label_rule_t *rules;
    size_t                   n_rules;
    /* If true, an action not matched by any rule yields -1 from the
     * callback (the adapter propagates this and the plan fails to
     * populate). If false, unmatched actions classify to empty sets
     * (and any sticky inbound labels at that node will fail-safe to
     * UNKNOWN in the kernel — which is the principled default). */
    bool                     strict;
} plan_label_table_t;

/* Reference callback that looks up an action by name in the table
 * supplied as 'ctx' (a const plan_label_table_t *). */
int plan_label_policy_from_table(const plan_action_desc_t *action,
                                 plan_label_class_t *out,
                                 void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_7_PLAN_LABEL_POLICY_H */
