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

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_7_PLAN_POLICY_CONFIG_H */
