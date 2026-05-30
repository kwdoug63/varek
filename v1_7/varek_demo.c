// SPDX-License-Identifier: MIT
/*
 * varek_demo.c — VAREK v1.8.1 demonstration.
 *
 * A narrated tour of the cross-action data-flow verifier. Every verdict
 * below is produced by the real verifier (the same plan_warden_verify
 * the Warden calls), against the real policy in demo_policy.cfg. No
 * output is staged or hardcoded.
 *
 * Build/run:  make demo
 *   or:       cc -std=c11 execution_plan.c plan_dataflow.c \
 *               plan_dataflow_adapter.c plan_dataflow_pathology.c \
 *               plan_warden_binding.c plan_policy_config.c \
 *               plan_evaluator_shim.c varek_demo.c -o varek_demo
 *             ./varek_demo            # loads demo_policy.cfg
 */

#define _GNU_SOURCE
#include "varek_dataflow.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- presentation helpers ---------- */

static void rule(void)
{
    puts("--------------------------------------------------------------------");
}
static void banner(const char *s)
{
    puts("====================================================================");
    printf("  %s\n", s);
    puts("====================================================================");
}

/* Summary bookkeeping. */
static const char *g_names[16];
static plan_decision_t g_got[16];
static plan_decision_t g_exp[16];
static size_t g_n = 0;

/* Run one scenario end-to-end through the real gate. */
static void scenario(const plan_label_policy_config_t *cfg,
                     const char *title,
                     const char *plan_picture,
                     const char *story,
                     const exec_plan_t *plan,
                     const plan_action_desc_t *actions, size_t n,
                     plan_decision_t expected)
{
    banner(title);
    printf("  plan:  %s\n", plan_picture);
    printf("  story: %s\n", story);
    rule();

    char pbuf[64 * 1024];
    plan_pathology_opts_t opts = plan_label_policy_config_pathology_opts(cfg);
    plan_warden_request_t req = {
        .plan = plan, .actions = actions, .n_actions = n,
        .policy = plan_label_policy_config_policy(cfg),
        .path_opts = &opts,
        .pathology_buf = pbuf, .pathology_buf_sz = sizeof pbuf,
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);

    if (rc != 0) {
        printf("  RESULT: verifier error -> REFUSED (fail-safe)\n\n");
        resp.verdict = PLAN_DEC_UNKNOWN;
    } else {
        printf("  RESULT: %s   (node=%s  flow=%s)  ->  %s\n",
               plan_decision_name(resp.verdict),
               plan_decision_name(resp.node_axis),
               plan_decision_name(resp.flow_axis),
               resp.verdict == PLAN_DEC_SATISFIED ? "AUTHORIZED" : "REFUSED");
        if (resp.verdict != PLAN_DEC_SATISFIED && resp.pathology_emitted) {
            printf("  evidence: ");
            fwrite(pbuf, 1, resp.pathology_len, stdout);
            printf("\n");
        }
        putchar('\n');
    }

    if (g_n < 16) {
        g_names[g_n] = title;
        g_got[g_n]   = resp.verdict;
        g_exp[g_n]   = expected;
        g_n++;
    }
}

/* All demo nodes pass the node axis; the demo isolates the DATA-FLOW
 * axis, which is what this subsystem adds over per-action checks. */
#define SAT PLAN_DEC_SATISFIED

int main(int argc, char **argv)
{
    const char *policy_path = (argc > 1) ? argv[1] : "demo_policy.cfg";

    plan_label_policy_config_t *cfg = NULL;
    int line = 0; const char *msg = NULL;
    if (plan_label_policy_config_load(policy_path, &cfg, &line, &msg) != 0) {
        fprintf(stderr, "could not load %s (line %d: %s)\n",
                policy_path, line, msg ? msg : "?");
        return 2;
    }

    puts("");
    puts("  VAREK — cross-action data-flow verification (v1.8.1)");
    printf("  policy: %s  (%zu rules, %zu labels)\n",
           policy_path,
           plan_label_policy_config_n_rules(cfg),
           plan_label_policy_config_n_labels(cfg));
    puts("  Every action below passes its own per-action policy check.");
    puts("  What VAREK adds is the verdict over how data flows BETWEEN them,");
    puts("  decided before any action runs.");
    puts("");

    /* 1. Clean plan — VAREK stays out of the way. */
    {
        exec_plan_t *p = exec_plan_new();
        exec_plan_add_node(p, "fetch_public_data", SAT);
        exec_plan_add_node(p, "format_report",     SAT);
        exec_plan_add_node(p, "display",           SAT);
        exec_plan_add_edge(p, 0, 1);
        exec_plan_add_edge(p, 1, 2);
        plan_action_desc_t a[3] = {
            { .name = "fetch_public_data" },
            { .name = "format_report" },
            { .name = "display" },
        };
        scenario(cfg, "1. Clean plan",
                 "fetch_public_data -> format_report -> display",
                 "No sensitive data anywhere. A safe plan must not be "
                 "obstructed.",
                 p, a, 3, PLAN_DEC_SATISFIED);
        exec_plan_free(p);
    }

    /* 2. Direct exfiltration. */
    {
        exec_plan_t *p = exec_plan_new();
        exec_plan_add_node(p, "read_secret", SAT);
        exec_plan_add_node(p, "send_http",   SAT);
        exec_plan_add_edge(p, 0, 1);
        plan_action_desc_t a[2] = {
            { .name = "read_secret" },
            { .name = "send_http" },
        };
        scenario(cfg, "2. Direct exfiltration",
                 "read_secret -> send_http",
                 "Read a secret, send it out. The obvious leak.",
                 p, a, 2, PLAN_DEC_UNSATISFIED);
        exec_plan_free(p);
    }

    /* 3. Compositional exfiltration — the headline case. */
    {
        exec_plan_t *p = exec_plan_new();
        exec_plan_add_node(p, "read_secret", SAT);
        exec_plan_add_node(p, "transform",   SAT);
        exec_plan_add_node(p, "enrich",      SAT);
        exec_plan_add_node(p, "send_http",   SAT);
        exec_plan_add_edge(p, 0, 1);
        exec_plan_add_edge(p, 1, 2);
        exec_plan_add_edge(p, 2, 3);
        plan_action_desc_t a[4] = {
            { .name = "read_secret" },
            { .name = "transform" },
            { .name = "enrich" },
            { .name = "send_http" },
        };
        scenario(cfg, "3. Compositional exfiltration (the case per-action checks miss)",
                 "read_secret -> transform -> enrich -> send_http",
                 "Every step is individually permitted. No single action "
                 "violates policy. The leak lives in the composition -- and "
                 "the evidence traces the secret back to its origin.",
                 p, a, 4, PLAN_DEC_UNSATISFIED);
        exec_plan_free(p);
    }

    /* 4. Sanitize-then-send — declassification (v1.8.0). */
    {
        exec_plan_t *p = exec_plan_new();
        exec_plan_add_node(p, "read_secret", SAT);
        exec_plan_add_node(p, "redact",      SAT);
        exec_plan_add_node(p, "send_http",   SAT);
        exec_plan_add_edge(p, 0, 1);
        exec_plan_add_edge(p, 1, 2);
        plan_action_desc_t a[3] = {
            { .name = "read_secret" },
            { .name = "redact" },
            { .name = "send_http" },
        };
        scenario(cfg, "4. Sanitize-then-send (declassification)",
                 "read_secret -> redact -> send_http",
                 "A redactor is trusted to observe the secret AND cleanse "
                 "it. The cleansed data may flow onward. VAREK permits the "
                 "legitimate workflow, not just denies.",
                 p, a, 3, PLAN_DEC_SATISFIED);
        exec_plan_free(p);
    }

    /* 5. Bypass the redactor — can't route around declassification. */
    {
        exec_plan_t *p = exec_plan_new();
        exec_plan_add_node(p, "read_secret", SAT);
        exec_plan_add_node(p, "redact",      SAT);
        exec_plan_add_node(p, "send_http",   SAT);
        exec_plan_add_edge(p, 0, 1);   /* read -> redact */
        exec_plan_add_edge(p, 1, 2);   /* redact -> send */
        exec_plan_add_edge(p, 0, 2);   /* read -> send  (bypass!) */
        plan_action_desc_t a[3] = {
            { .name = "read_secret" },
            { .name = "redact" },
            { .name = "send_http" },
        };
        scenario(cfg, "5. Bypass attempt",
                 "read_secret -> redact -> send_http,  plus read_secret -> send_http",
                 "A plan that routes the raw secret around the redactor "
                 "straight to egress. The bypass edge still carries the "
                 "uncleansed secret, so it is refused.",
                 p, a, 3, PLAN_DEC_UNSATISFIED);
        exec_plan_free(p);
    }

    /* 6a. Argument-sensitive egress: internal endpoint authorized. */
    {
        exec_plan_t *p = exec_plan_new();
        exec_plan_add_node(p, "read_secret", SAT);
        exec_plan_add_node(p, "send_http",   SAT);
        exec_plan_add_edge(p, 0, 1);
        plan_action_arg_t args[1] = {
            { .key = "url", .value = "https://api.internal.acme.com/v1/sync" },
        };
        plan_action_desc_t a[2] = {
            { .name = "read_secret" },
            { .name = "send_http", .named_args = args, .n_named_args = 1 },
        };
        scenario(cfg, "6a. Egress to an internal endpoint",
                 "read_secret -> send_http(url=https://api.internal.acme.com/...)",
                 "Policy permits sensitive data to a trusted internal host. "
                 "Argument-sensitive: the destination decides the verdict.",
                 p, a, 2, PLAN_DEC_SATISFIED);
        exec_plan_free(p);
    }

    /* 6b. Same action, external endpoint: refused. */
    {
        exec_plan_t *p = exec_plan_new();
        exec_plan_add_node(p, "read_secret", SAT);
        exec_plan_add_node(p, "send_http",   SAT);
        exec_plan_add_edge(p, 0, 1);
        plan_action_arg_t args[1] = {
            { .key = "url", .value = "https://paste.evil.example/upload" },
        };
        plan_action_desc_t a[2] = {
            { .name = "read_secret" },
            { .name = "send_http", .named_args = args, .n_named_args = 1 },
        };
        scenario(cfg, "6b. Same action, external endpoint",
                 "read_secret -> send_http(url=https://paste.evil.example/...)",
                 "Identical plan shape; only the destination differs. The "
                 "external host is not permitted, so it is refused.",
                 p, a, 2, PLAN_DEC_UNSATISFIED);
        exec_plan_free(p);
    }

    /* 7. Sticky fail-safe: unclassified handler receiving a secret. */
    {
        exec_plan_t *p = exec_plan_new();
        exec_plan_add_node(p, "read_secret",    SAT);
        exec_plan_add_node(p, "mystery_plugin", SAT);
        exec_plan_add_edge(p, 0, 1);
        plan_action_desc_t a[2] = {
            { .name = "read_secret" },
            { .name = "mystery_plugin" },   /* not in the policy at all */
        };
        scenario(cfg, "7. Fail-safe on the unknown",
                 "read_secret -> mystery_plugin",
                 "A handler the policy has never classified receives a "
                 "secret. VAREK does not guess: it returns UNKNOWN, which "
                 "suppresses. Unclassified is not the same as allowed.",
                 p, a, 2, PLAN_DEC_UNKNOWN);
        exec_plan_free(p);
    }

    /* ---------- summary ---------- */
    banner("Summary");
    int pass = 0;
    for (size_t i = 0; i < g_n; i++) {
        bool ok = (g_got[i] == g_exp[i]);
        pass += ok;
        printf("  [%s] %-12s  %s\n",
               ok ? "ok" : "XX",
               plan_decision_name(g_got[i]),
               g_names[i]);
    }
    rule();
    printf("  %d / %zu scenarios behaved as described.\n\n", pass, g_n);

    plan_label_policy_config_free(cfg);
    return (pass == (int)g_n) ? 0 : 1;
}
