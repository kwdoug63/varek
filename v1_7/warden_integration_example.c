// SPDX-License-Identifier: MIT
/*
 * warden_integration_example.c — reference integration of the VAREK
 * data-flow subsystem into a Warden-style `--plan` gate.
 *
 * This is NOT a test (no asserts) and NOT for shipping. It is the
 * worked template the Warden's `--plan` handler follows: load a policy
 * once at startup, then for each submitted plan build the plan + action
 * array, call plan_warden_verify(), gate on the verdict, and emit
 * pathology on refusal. It compiles and runs standalone against the
 * test shim; in the real tree it links the host's plan_evaluator.c
 * instead (see INTEGRATION.md).
 *
 * Build (standalone):
 *   cc -std=c11 execution_plan.c plan_dataflow.c plan_dataflow_adapter.c \
 *      plan_dataflow_pathology.c plan_warden_binding.c plan_policy_config.c \
 *      plan_evaluator_shim.c warden_integration_example.c -o warden_example
 *
 * Run:
 *   ./warden_example                 # uses the built-in inline policy
 *   ./warden_example my_policy.cfg   # loads a policy file
 */

#define _GNU_SOURCE
#include "varek_dataflow.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A self-contained policy used when no config path is given. In a real
 * deployment this lives in a file loaded at Warden startup. */
static const char *INLINE_POLICY =
    "varek_policy 1\n"
    "label SECRET 0\n"
    "sticky SECRET\n"
    "rule read_secret\n"
    "  origin SECRET\n"
    "rule redact\n"
    "  permit_in SECRET\n"     /* trusted to see the secret ... */
    "  declassify SECRET\n"    /* ... and to cleanse it */
    "rule send_http\n"
    "  deny_in SECRET\n";

/* The Warden's gate. Returns true iff the plan is authorized. Mirrors
 * exactly what the real `--plan` handler does per submission. */
static bool warden_gate(const char *plan_name,
                        const exec_plan_t *plan,
                        const plan_action_desc_t *actions, size_t n_actions,
                        const plan_label_policy_config_t *cfg)
{
    /* Pathology buffer. Size for the deployment's largest expected
     * plan; 64 KiB is generous for hundreds of nodes. */
    char pbuf[64 * 1024];
    plan_pathology_opts_t opts = plan_label_policy_config_pathology_opts(cfg);

    plan_warden_request_t req = {
        .plan             = plan,
        .actions          = actions,
        .n_actions        = n_actions,
        .policy           = plan_label_policy_config_policy(cfg),
        .path_opts        = &opts,
        .pathology_buf    = pbuf,
        .pathology_buf_sz = sizeof pbuf,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);

    /* rc != 0 means the verifier itself failed; treat as refusal. */
    if (rc != 0) {
        fprintf(stderr,
                "[varek] plan \"%s\": verifier error -> REFUSED (fail-safe)\n",
                plan_name);
        return false;
    }

    const bool authorized = plan_warden_authorized(&resp);
    fprintf(stderr,
            "[varek] plan \"%s\": verdict=%s (node=%s flow=%s) -> %s\n",
            plan_name,
            plan_decision_name(resp.verdict),
            plan_decision_name(resp.node_axis),
            plan_decision_name(resp.flow_axis),
            authorized ? "AUTHORIZED" : "REFUSED");

    if (!authorized && resp.pathology_emitted) {
        fprintf(stderr, "[varek] refusal pathology: ");
        fwrite(pbuf, 1, resp.pathology_len, stderr);
        fputc('\n', stderr);
    }
    return authorized;
}

int main(int argc, char **argv)
{
    /* ----- Warden startup: load policy once ----- */
    plan_label_policy_config_t *cfg = NULL;
    int err_line = 0;
    const char *err_msg = NULL;

    if (argc > 1) {
        if (plan_label_policy_config_load(argv[1], &cfg,
                                          &err_line, &err_msg) != 0) {
            fprintf(stderr, "[varek] policy load failed at %s line %d: %s\n",
                    argv[1], err_line, err_msg ? err_msg : "(unknown)");
            return 2;
        }
        fprintf(stderr, "[varek] loaded policy from %s (%zu rules, %zu labels)\n",
                argv[1],
                plan_label_policy_config_n_rules(cfg),
                plan_label_policy_config_n_labels(cfg));
    } else {
        FILE *f = fmemopen((void *)INLINE_POLICY, strlen(INLINE_POLICY), "r");
        if (!f || plan_label_policy_config_load_stream(f, &cfg,
                                                       &err_line, &err_msg) != 0) {
            fprintf(stderr, "[varek] inline policy load failed at line %d: %s\n",
                    err_line, err_msg ? err_msg : "(unknown)");
            if (f) fclose(f);
            return 2;
        }
        fclose(f);
        fprintf(stderr, "[varek] loaded built-in inline policy\n");
    }

    /* ----- Per-submission: plan A — sanitize-then-send -----
     * read_secret -> redact -> send_http. The redactor is trusted to
     * see and cleanse SECRET, so the egress (which denies SECRET) never
     * receives it. Expected: AUTHORIZED. */
    {
        exec_plan_t *p = exec_plan_new();
        exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
        exec_plan_add_node(p, "redact",      PLAN_DEC_SATISFIED);
        exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
        exec_plan_add_edge(p, 0, 1);
        exec_plan_add_edge(p, 1, 2);
        plan_action_desc_t actions[3] = {
            { .name = "read_secret" },
            { .name = "redact"      },
            { .name = "send_http"   },
        };
        warden_gate("sanitize-then-send", p, actions, 3, cfg);
        exec_plan_free(p);
    }

    /* ----- Per-submission: plan B — direct exfil -----
     * read_secret -> send_http, no redaction. The raw secret reaches
     * the denying egress. Expected: REFUSED, with pathology naming the
     * leak and its originator. */
    {
        exec_plan_t *p = exec_plan_new();
        exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
        exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
        exec_plan_add_edge(p, 0, 1);
        plan_action_desc_t actions[2] = {
            { .name = "read_secret" },
            { .name = "send_http"   },
        };
        warden_gate("direct-exfil", p, actions, 2, cfg);
        exec_plan_free(p);
    }

    /* ----- Warden shutdown ----- */
    plan_label_policy_config_free(cfg);
    return 0;
}
