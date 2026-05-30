// SPDX-License-Identifier: MIT
/*
 * test_v18_0.c — VAREK v1.8.0 declassification tests.
 *
 * Declassification is the escape hatch that lets a sanitize-then-send
 * workflow authorize. These tests pin the SAFETY properties that keep
 * it from becoming a laundering hole:
 *
 *   - a redactor that declassifies a sticky label it is permitted to
 *     see lets sanitized data flow onward (the legitimate case)
 *   - declassify WITHOUT permit on a sticky label still fails closed
 *     (the two-assertion requirement)
 *   - the declassifier is policed on its own inbound (declassification
 *     affects only downstream flow)
 *   - an attacker cannot route around the declassifier: the raw label
 *     reaching egress directly is still denied
 *   - declassification is audited (node_declassified reports it)
 *   - empty declassify set => pure v1.7.x behavior (backward compat)
 *   - end-to-end through the binding and the config grammar
 *
 * Clean under -fsanitize=address,undefined.
 */

#define _GNU_SOURCE
#include "execution_plan.h"
#include "plan_dataflow.h"
#include "plan_label.h"
#include "plan_label_policy.h"
#include "plan_policy_config.h"
#include "plan_warden_binding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++;                                  \
        printf("  FAIL: %s  (%s:%d)\n", (msg), __FILE__, __LINE__); \
    } else {                                                    \
        printf("  ok:   %s\n", (msg));                          \
    }                                                           \
} while (0)

enum { L_SECRET = 0, L_PII = 1 };

/* Legitimate sanitize-then-send: read_secret -> redact -> send_http.
 * The redactor is permitted to see SECRET and declassifies it; the
 * egress denies SECRET but never receives it. Plan authorizes. */
static void test_sanitize_then_send_authorizes(void)
{
    printf("test_sanitize_then_send_authorizes\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t rd = exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
    plan_node_id_t rx = exec_plan_add_node(p, "redact",      PLAN_DEC_SATISFIED);
    plan_node_id_t eg = exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, rd, rx);
    exec_plan_add_edge(p, rx, eg);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, rd, L_SECRET);
    plan_dataflow_add_permit_in(df, rx, L_SECRET);    /* redactor may see it */
    plan_dataflow_add_declassify(df, rx, L_SECRET);   /* redactor cleanses it */
    plan_dataflow_add_deny_in(df, eg, L_SECRET);      /* egress denies it */

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_SATISFIED,
          "sanitized secret reaches egress cleansed -> SATISFIED");
    CHECK(exec_plan_authorized_with_dataflow(p, df),
          "sanitize-then-send authorizes");

    /* Audit: the redactor declassified SECRET. */
    plan_label_set_t dz;
    CHECK(plan_dataflow_node_declassified(df, rx, &dz) == 0,
          "declassified set readable after verdict");
    CHECK(plan_label_set_test(&dz, L_SECRET),
          "audit records SECRET declassified at redactor");

    /* And it did NOT reach the egress inbound. */
    plan_label_set_t eg_in;
    plan_dataflow_node_inbound(df, eg, &eg_in);
    CHECK(!plan_label_set_test(&eg_in, L_SECRET),
          "declassified label absent from egress inbound");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* declassify WITHOUT permit on a sticky label still fails closed: the
 * redactor receives sticky SECRET with no permit/deny/unknown
 * disposition, so its own inbound decision is UNKNOWN. The two-
 * assertion requirement holds. */
static void test_declassify_without_permit_fails_closed(void)
{
    printf("test_declassify_without_permit_fails_closed\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t rd = exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
    plan_node_id_t rx = exec_plan_add_node(p, "redact",      PLAN_DEC_SATISFIED);
    plan_node_id_t eg = exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, rd, rx);
    exec_plan_add_edge(p, rx, eg);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, rd, L_SECRET);
    plan_dataflow_add_declassify(df, rx, L_SECRET);   /* declassify but NO permit */
    plan_dataflow_add_deny_in(df, eg, L_SECRET);

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNKNOWN,
          "declassify without permit on sticky -> UNKNOWN (fail closed)");
    CHECK(plan_dataflow_node_decision(df, rx) == PLAN_DEC_UNKNOWN,
          "redactor itself is UNKNOWN (policed on full inbound)");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* The declassifier is policed on its own inbound: if the egress (not
 * the redactor) denies SECRET, declassification downstream doesn't
 * rescue a node that itself fails. Here the redactor DENIES SECRET
 * inbound while also declassifying it -> the node is UNSAT regardless,
 * because policing happens before declassification. */
static void test_declassifier_policed_on_inbound(void)
{
    printf("test_declassifier_policed_on_inbound\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t rd = exec_plan_add_node(p, "read", PLAN_DEC_SATISFIED);
    plan_node_id_t rx = exec_plan_add_node(p, "node", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, rd, rx);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_add_origin(df, rd, L_SECRET);
    plan_dataflow_add_deny_in(df, rx, L_SECRET);      /* node denies inbound SECRET */
    plan_dataflow_add_declassify(df, rx, L_SECRET);   /* and would declassify it */

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNSATISFIED,
          "node policed on inbound before declassification -> UNSAT");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Attacker cannot route around the declassifier: a direct edge from
 * the secret source to the egress (bypassing the redactor) still
 * carries the raw label, which the egress denies. */
static void test_cannot_route_around_declassifier(void)
{
    printf("test_cannot_route_around_declassifier\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t rd = exec_plan_add_node(p, "read_secret", PLAN_DEC_SATISFIED);
    plan_node_id_t rx = exec_plan_add_node(p, "redact",      PLAN_DEC_SATISFIED);
    plan_node_id_t eg = exec_plan_add_node(p, "send_http",   PLAN_DEC_SATISFIED);
    /* Legit path rd->rx->eg AND a bypass edge rd->eg. */
    exec_plan_add_edge(p, rd, rx);
    exec_plan_add_edge(p, rx, eg);
    exec_plan_add_edge(p, rd, eg);   /* bypass! */

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_mark_sticky(df, L_SECRET);
    plan_dataflow_add_origin(df, rd, L_SECRET);
    plan_dataflow_add_permit_in(df, rx, L_SECRET);
    plan_dataflow_add_declassify(df, rx, L_SECRET);
    plan_dataflow_add_deny_in(df, eg, L_SECRET);

    /* The bypass edge delivers raw SECRET to egress -> denied. */
    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNSATISFIED,
          "bypass of declassifier still denied at egress");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Backward compatibility: with no declassify set, behavior is exactly
 * v1.7.x — the canonical exfil refuses. */
static void test_no_declassify_is_v17_behavior(void)
{
    printf("test_no_declassify_is_v17_behavior\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t rd = exec_plan_add_node(p, "read", PLAN_DEC_SATISFIED);
    plan_node_id_t eg = exec_plan_add_node(p, "send", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, rd, eg);

    plan_dataflow_t *df = plan_dataflow_new(p);
    plan_dataflow_add_origin(df, rd, L_SECRET);
    plan_dataflow_add_deny_in(df, eg, L_SECRET);
    /* No declassify anywhere. */

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_UNSATISFIED,
          "no declassify -> canonical exfil still refused");

    plan_label_set_t dz;
    /* Audit set exists but is empty. */
    CHECK(plan_dataflow_node_declassified(df, eg, &dz) == 0 &&
          plan_label_set_empty(&dz),
          "no declassification recorded");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* Declassify of a label not on inbound is a harmless no-op, not
 * recorded in the audit set. */
static void test_declassify_noop_not_audited(void)
{
    printf("test_declassify_noop_not_audited\n");
    exec_plan_t *p = exec_plan_new();
    plan_node_id_t a = exec_plan_add_node(p, "a", PLAN_DEC_SATISFIED);
    plan_node_id_t b = exec_plan_add_node(p, "b", PLAN_DEC_SATISFIED);
    exec_plan_add_edge(p, a, b);

    plan_dataflow_t *df = plan_dataflow_new(p);
    /* b declassifies SECRET but never receives it. */
    plan_dataflow_add_declassify(df, b, L_SECRET);

    CHECK(plan_dataflow_flow_verdict(df) == PLAN_DEC_SATISFIED,
          "no-op declassify doesn't change verdict");
    plan_label_set_t dz;
    plan_dataflow_node_declassified(df, b, &dz);
    CHECK(plan_label_set_empty(&dz),
          "no-op declassify not recorded in audit set");

    plan_dataflow_free(df);
    exec_plan_free(p);
}

/* End-to-end through the binding and config grammar: the example's
 * redactor pattern loaded from a config string authorizes a
 * sanitize-then-send plan. */
static void test_end_to_end_config_declassify(void)
{
    printf("test_end_to_end_config_declassify\n");
    const char *cfg_text =
        "label SECRET 0\n"
        "sticky SECRET\n"
        "rule read_secret\n"
        "  origin SECRET\n"
        "rule redact_secret\n"
        "  permit_in SECRET\n"
        "  declassify SECRET\n"
        "rule send_http\n"
        "  deny_in SECRET\n";
    FILE *f = fmemopen((void *)cfg_text, strlen(cfg_text), "r");
    plan_label_policy_config_t *cfg = NULL;
    int el; const char *em;
    plan_label_policy_config_load_stream(f, &cfg, &el, &em);
    fclose(f);
    CHECK(cfg != NULL, "config with declassify loads");

    exec_plan_t *plan = exec_plan_new();
    exec_plan_add_node(plan, "read_secret",  PLAN_DEC_SATISFIED);
    exec_plan_add_node(plan, "redact_secret", PLAN_DEC_SATISFIED);
    exec_plan_add_node(plan, "send_http",    PLAN_DEC_SATISFIED);
    exec_plan_add_edge(plan, 0, 1);
    exec_plan_add_edge(plan, 1, 2);

    plan_action_desc_t actions[3] = {
        { .name = "read_secret" },
        { .name = "redact_secret" },
        { .name = "send_http" },
    };
    plan_warden_request_t req = {
        .plan = plan, .actions = actions, .n_actions = 3,
        .policy = plan_label_policy_config_policy(cfg),
    };
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);

    CHECK(rc == 0, "binding returns 0");
    CHECK(resp.verdict == PLAN_DEC_SATISFIED,
          "config-driven sanitize-then-send authorizes");

    exec_plan_free(plan);
    plan_label_policy_config_free(cfg);
}

int main(void)
{
    test_sanitize_then_send_authorizes();
    test_declassify_without_permit_fails_closed();
    test_declassifier_policed_on_inbound();
    test_cannot_route_around_declassifier();
    test_no_declassify_is_v17_behavior();
    test_declassify_noop_not_audited();
    test_end_to_end_config_declassify();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
