// SPDX-License-Identifier: MIT
/*
 * plan_policy_config.h — VAREK v1.7.3 label-policy config loader.
 *
 * Loads a text policy file into a plan_label_policy_t suitable for
 * plan_warden_verify(). The file declares: labels by name and id,
 * the plan-wide sticky set, per-action rules (origin / deny_in /
 * unknown_in / permit_in), and an optional strict toggle. A
 * label-name callback is also produced for pathology rendering.
 *
 * GRAMMAR (line-oriented).
 *
 *   varek_policy 1               # optional version pragma; must be
 *                                # first non-comment line if present.
 *   strict                       # optional; default is non-strict.
 *   label NAME ID                # NAME -> ID; ID in [0, PLAN_MAX_LABELS).
 *   sticky NAME                  # plan-wide sticky.
 *   rule ACTION_NAME             # opens a rule block until the next
 *                                # non-indented line.
 *     match KEY PATTERN          # v1.7.4: argument constraint; ALL
 *                                # matches on a rule must hold. PATTERN
 *                                # is a shell glob (* and ?). Multiple
 *                                # rules with the same action name are
 *                                # walked in declaration order;
 *                                # first match wins.
 *     origin NAME                # rule-body statements; must be
 *     deny_in NAME               # indented (any leading whitespace).
 *     unknown_in NAME
 *     permit_in NAME
 *
 *   # comments run to end of line; only at start of line.
 *   blank lines are ignored.
 *   labels must be declared (label NAME ID) before any use.
 *
 * On success, the loader returns a config object owning:
 *   - the policy + table for plan_warden_request_t.policy
 *   - the label_name callback + ctx for plan_pathology_opts_t
 *   - all strdup'd strings the above point into
 *
 * The Warden builds the request once at plan submission against the
 * pointers exposed on the config; the config outlives all requests
 * built from it. Free with plan_label_policy_config_free() at
 * Warden shutdown.
 */

#ifndef VAREK_V1_7_PLAN_POLICY_CONFIG_H
#define VAREK_V1_7_PLAN_POLICY_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "plan_label.h"
#include "plan_label_policy.h"
#include "plan_dataflow_pathology.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------
 * v1.8.2 / v1.9 additions — bounded-refusal breaker + progress safety.
 *
 * Three optional top-level directives extend the grammar:
 *
 *   refusal_budget N             # v1.8.2. N >= 1. Max retryable
 *                                # UNSATISFIED verdicts the breaker
 *                                # tolerates for one (session,signature)
 *                                # before latching to the exhaustion
 *                                # disposition. Absent => breaker
 *                                # disabled (pre-v1.8.2 pass-through).
 *
 *   on_exhaustion deny           # v1.8.2. Terminal disposition once the
 *   on_exhaustion terminal NAME  # refusal budget is spent. 'deny' is a
 *                                # permanent automated refusal (abort).
 *                                # 'terminal NAME' fires the pre-
 *                                # authorized safe action NAME (which
 *                                # must itself be a declared rule and,
 *                                # per v1.9, must authorize). Absent =>
 *                                # deny (fail-closed terminal).
 *
 *   unknown_disposition deny           # v1.8.2. Terminal disposition for
 *   unknown_disposition terminal NAME  # an UNKNOWN verdict. UNKNOWN is
 *                                # never retried (a re-run reproduces it),
 *                                # so it routes here immediately. Absent
 *                                # => deny.
 *
 * None of these touch the decision procedure. The verdict for any single
 * submission remains a pure function of (plan, policy). The breaker only
 * interprets the SEQUENCE of verdicts for one (session, signature) and
 * picks a deterministic terminal disposition; the resolution is bounded
 * and never requires human intervention.
 * -------------------------------------------------------------------- */

/* A terminal disposition: what the breaker does once retries are spent
 * (on_exhaustion) or for an UNKNOWN verdict (unknown_disposition). */
typedef enum {
    PLAN_DISP_DENY     = 0,   /* permanent automated refusal / abort */
    PLAN_DISP_TERMINAL = 1,   /* fire the named pre-authorized safe action */
} plan_disposition_kind_t;

typedef struct plan_disposition {
    plan_disposition_kind_t kind;
    const char             *action_name;  /* borrowed; non-NULL iff TERMINAL */
} plan_disposition_t;

/* Opaque config handle. */
typedef struct plan_label_policy_config plan_label_policy_config_t;

/* ---------- Load / free ---------- */

/* Load a policy from a file path. On success returns 0 and writes
 * the new config to *out. On failure returns -1, writes the line
 * number of the offending statement (1-based; 0 if not line-bound)
 * to *err_line if non-NULL, and writes a static error description
 * pointer to *err_msg if non-NULL (do not free). On failure *out
 * is set to NULL. */
int plan_label_policy_config_load(const char *path,
                                  plan_label_policy_config_t **out,
                                  int *err_line,
                                  const char **err_msg);

/* Same, reading from an already-open stream. The loader does not
 * close the stream. Useful for fmemopen() in tests. */
int plan_label_policy_config_load_stream(FILE *stream,
                                         plan_label_policy_config_t **out,
                                         int *err_line,
                                         const char **err_msg);

/* Free a config and all storage it owns. NULL-safe. After this call,
 * any pointers obtained through the accessors below are invalid. */
void plan_label_policy_config_free(plan_label_policy_config_t *cfg);

/* ---------- Accessors ---------- */

/* Borrowed pointer to the policy bundle. Use as
 * plan_warden_request_t.policy. Valid for the lifetime of cfg. */
const plan_label_policy_t *
plan_label_policy_config_policy(const plan_label_policy_config_t *cfg);

/* Label-name callback for pathology output. The cfg is the ctx. */
const char *plan_label_policy_config_label_name(plan_label_t tag, void *ctx);

/* Convenience: build a plan_pathology_opts_t pointing at the
 * label-name callback. */
plan_pathology_opts_t
plan_label_policy_config_pathology_opts(const plan_label_policy_config_t *cfg);

/* Diagnostics: number of rules and labels loaded. */
size_t plan_label_policy_config_n_rules(const plan_label_policy_config_t *cfg);
size_t plan_label_policy_config_n_labels(const plan_label_policy_config_t *cfg);

/* ---------- v1.8.2 / v1.9 accessors ---------- */

/* True iff a refusal_budget >= 1 was declared (breaker enabled). */
bool plan_label_policy_config_breaker_enabled(const plan_label_policy_config_t *cfg);

/* The declared refusal budget (0 iff the breaker is disabled). */
unsigned plan_label_policy_config_refusal_budget(const plan_label_policy_config_t *cfg);

/* Terminal disposition once the refusal budget is spent. Defaults to
 * {PLAN_DISP_DENY, NULL} when no on_exhaustion directive is present. */
plan_disposition_t
plan_label_policy_config_on_exhaustion(const plan_label_policy_config_t *cfg);

/* Terminal disposition for an UNKNOWN verdict. Defaults to
 * {PLAN_DISP_DENY, NULL} when no unknown_disposition directive is present. */
plan_disposition_t
plan_label_policy_config_unknown_disposition(const plan_label_policy_config_t *cfg);

/* True iff some rule names this action. Used by the v1.9 progress
 * verifier to confirm a terminal disposition's safe action exists. */
bool plan_label_policy_config_has_action(const plan_label_policy_config_t *cfg,
                                         const char *action_name);

/* True iff the policy can produce a refusal at all: a non-empty sticky
 * set, or any rule with a non-empty deny_in / unknown_in set. A policy
 * that cannot refuse is trivially progress-safe. */
bool plan_label_policy_config_can_refuse(const plan_label_policy_config_t *cfg);

/* True iff some rule for 'action_name' classifies a sticky label into
 * its deny_in or unknown_in set — meaning the action is refused the
 * moment that label reaches it. A terminal fallback for which this
 * holds is deadlock-prone (it cannot safely absorb the refused flow it
 * is meant to terminate), so the v1.9 progress verifier rejects it.
 * Conservative: checks every rule that names the action. */
bool plan_label_policy_config_action_denies_sticky(
        const plan_label_policy_config_t *cfg, const char *action_name);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_7_PLAN_POLICY_CONFIG_H */
