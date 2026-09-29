// SPDX-License-Identifier: MIT
/*
 * test_v120.c — VAREK v1.20.0: rules on declared fields.
 *
 * A plan step may now declare fields (key=value) besides its target, and the
 * Warden hands them to the flow policy as named arguments. The agent writes
 * its plan, so a rule that matches a field can be switched on or off by
 * declaring or omitting it. The Warden refuses such a policy unless it says
 * trust_declared_fields.
 *
 *   1. trust_declared_fields parses; bad forms are refused.
 *   2. plan_label_policy_config_field_rule() finds a rule on any key but
 *      target (or a component of target), and names it.
 *   3. A rule on a field classifies an action carrying that field, including
 *      a value with spaces, and a URL field's components.
 */

#define _POSIX_C_SOURCE 200809L

#include "plan_label_policy.h"
#include "plan_policy_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_pass;

#define CHECK(cond, msg) do {                                       \
    if (cond) { g_pass++; printf("  ok:   %s\n", msg); }             \
    else      { g_fail++; printf("  FAIL: %s\n", msg); }             \
} while (0)

static plan_label_policy_config_t *load(const char *text, const char **msg)
{
    FILE *f = fmemopen((void *)text, strlen(text), "r");
    if (!f) return NULL;
    plan_label_policy_config_t *cfg = NULL;
    int line = 0;
    const char *m = NULL;
    if (plan_label_policy_config_load_stream(f, &cfg, &line, &m) != 0) cfg = NULL;
    fclose(f);
    if (msg) *msg = m;
    return cfg;
}

#define HEAD "varek_policy 1\nlabel SECRET 0\n"

static void test_directive(void)
{
    printf("-- 1. trust_declared_fields\n");
    plan_label_policy_config_t *cfg = load(HEAD "trust_declared_fields\nrule a\n", NULL);
    CHECK(cfg && plan_label_policy_config_trusts_declared_fields(cfg), "the directive is read");
    plan_label_policy_config_free(cfg);
    cfg = load(HEAD "rule a\n", NULL);
    CHECK(cfg && !plan_label_policy_config_trusts_declared_fields(cfg), "absent means no");
    plan_label_policy_config_free(cfg);
    const char *msg = NULL;
    cfg = load(HEAD "trust_declared_fields yes\nrule a\n", &msg);
    CHECK(!cfg && msg && strstr(msg, "no arguments"), "an argument is refused");
    plan_label_policy_config_free(cfg);
    cfg = load(HEAD "trust_declared_fields\ntrust_declared_fields\nrule a\n", &msg);
    CHECK(!cfg && msg && strstr(msg, "duplicate"), "a duplicate is refused");
    plan_label_policy_config_free(cfg);
}

static void test_field_rule(void)
{
    printf("-- 2. which rules match a declared field\n");
    struct { const char *rules; int want; const char *key, *why; } t[] = {
        { "rule file_open\n  origin SECRET\n", 0, NULL, "a name-only rule: no" },
        { "rule file_open\n  match target /srv/*\n  origin SECRET\n", 0, NULL, "a rule on target: no" },
        { "rule file_open\n  match target.path /srv/*\n  origin SECRET\n", 0, NULL, "a rule on a component of target: no" },
        { "rule file_open\n  match target /srv/*\n  match contains *pii*\n  origin SECRET\n", 1, "contains",
          "a rule on target and a field: yes, and it names the field" },
        { "rule send_http\n  match url.host *.internal\n  permit_in SECRET\n", 1, "url.host",
          "a rule on a URL field's host: yes" },
        { "rule a\nrule b\n  match mode write\n  deny_in SECRET\n", 1, "mode",
          "a later rule that refuses on a field: yes (leaving the field out avoids it)" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char text[512];
        snprintf(text, sizeof text, "%s%s", HEAD, t[i].rules);
        plan_label_policy_config_t *cfg = load(text, NULL);
        const char *action = NULL, *key = NULL;
        bool got = cfg && plan_label_policy_config_field_rule(cfg, &action, &key);
        bool ok = cfg && got == (t[i].want == 1) &&
                  (!t[i].key || (key && strcmp(key, t[i].key) == 0 && action));
        CHECK(ok, t[i].why);
        plan_label_policy_config_free(cfg);
    }
}

static int origin_secret(const plan_label_policy_config_t *cfg, const char *name,
                         const plan_action_arg_t *args, size_t n)
{
    plan_action_desc_t a = { .name = name, .named_args = args, .n_named_args = n };
    plan_label_class_t cls;
    memset(&cls, 0, sizeof cls);
    const plan_label_policy_t *pol = plan_label_policy_config_policy(cfg);
    if (pol->classify(&a, &cls, pol->ctx) != 0) return -1;
    return plan_label_set_test(&cls.origin, 0) ? 1 : 0;
}

static void test_classify(void)
{
    printf("-- 3. a rule on a field classifies an action that declares it\n");
    plan_label_policy_config_t *cfg = load(HEAD
        "trust_declared_fields\n"
        "rule http_request\n"
        "  match url.host *.internal.example\n"
        "  match body *BEGIN?PRIVATE?KEY*\n"
        "  origin SECRET\n"
        "rule http_request\n", NULL);
    CHECK(cfg != NULL, "policy loads");
    if (!cfg) return;
    plan_action_arg_t with[] = {
        { .key = "target", .value = "https://api.internal.example/v1" },
        { .key = "body",   .value = "-----BEGIN PRIVATE KEY-----\nMII..." },
        { .key = "url",    .value = "https://api.internal.example/v1" },
    };
    CHECK(origin_secret(cfg, "http_request", with, 3) == 1,
          "a body with a key in it, to an internal host: SECRET (the value's spaces and newline match)");
    plan_action_arg_t nobody[] = {
        { .key = "target", .value = "https://api.internal.example/v1" },
        { .key = "url",    .value = "https://api.internal.example/v1" },
    };
    CHECK(origin_secret(cfg, "http_request", nobody, 2) == 0,
          "the same step without the body field: the rule does not apply (what trust_declared_fields accepts)");
    plan_action_arg_t outside[] = {
        { .key = "body", .value = "-----BEGIN PRIVATE KEY-----" },
        { .key = "url",  .value = "https://evil.example/x.internal.example/" },
    };
    CHECK(origin_secret(cfg, "http_request", outside, 2) == 0,
          "an outside host with the internal name in its path: not the internal rule");
    plan_label_policy_config_free(cfg);
}

int main(void)
{
    test_directive();
    test_field_rule();
    test_classify();
    printf("%d/%d checks passed\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}
