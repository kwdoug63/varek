// SPDX-License-Identifier: MIT
/*
 * adapter_demo.c — exercises the v1.6.1 Warden adapter end-to-end.
 *
 * Two scenarios:
 *   1. A small fetch -> transform -> write plan where the decider
 *      approves all actions. Plan authorizes.
 *   2. The same plan where the decider denies any "net_connect"
 *      action. Plan suppresses, pathology record names the
 *      suppressed action.
 */

#include "pathology.h"
#include "plan_spec.h"
#include "warden_adapter.h"

#include <stdio.h>
#include <string.h>

/* Toy decider: deny network connects, allow everything else.
 * In a real adapter integration this wraps the v1.4 policy_decide(). */
static plan_decision_t toy_decider(const plan_spec_action_t *action, void *ud)
{
    (void)ud;
    if (action->kind && strcmp(action->kind, "net_connect") == 0) {
        return PLAN_DEC_UNSATISFIED;
    }
    return PLAN_DEC_SATISFIED;
}

/* Permissive decider: allow everything. */
static plan_decision_t allow_all(const plan_spec_action_t *action, void *ud)
{
    (void)action; (void)ud;
    return PLAN_DEC_SATISFIED;
}

int main(void)
{
    pathology_sink_t *sink = pathology_sink_new(stderr);
    if (!sink) { fprintf(stderr, "sink alloc failed\n"); return 1; }

    plan_spec_action_t actions[] = {
        { "file_open",   "/var/data/input.json", NULL, "load_input"   },
        { "process_exec","/usr/bin/python3",     NULL, "run_transform"},
        { "net_connect", "api.example.com:443",  NULL, "post_results" },
        { "file_open",   "/var/data/audit.log",  NULL, "audit_write"  },
    };
    plan_spec_edge_t edges[] = {
        { 0, 1 },  /* transform depends on input */
        { 1, 2 },  /* post depends on transform */
        { 1, 3 },  /* audit depends on transform */
    };
    plan_spec_t spec = {
        .actions    = actions,
        .n_actions  = sizeof(actions) / sizeof(actions[0]),
        .edges      = edges,
        .n_edges    = sizeof(edges) / sizeof(edges[0]),
    };

    printf("scenario_1 (permissive decider)\n");
    plan_decision_t d1 = warden_adapter_verify(&spec, allow_all, NULL, sink);
    printf("  result: %s\n", plan_decision_name(d1));

    printf("scenario_2 (toy decider denies net_connect)\n");
    plan_decision_t d2 = warden_adapter_verify(&spec, toy_decider, NULL, sink);
    printf("  result: %s\n", plan_decision_name(d2));

    pathology_sink_free(sink);
    return 0;
}
