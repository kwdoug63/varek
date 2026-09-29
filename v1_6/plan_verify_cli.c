// SPDX-License-Identifier: MIT
/*
 * plan_verify_cli.c — file-in / JSON-out entry point over the v1.6
 * compositional evaluator.
 *
 * This file adds NO verdict logic. It wires together components that
 * already ship in v1_6:
 *   plan_parser_load()      -> parse a plan file into a plan_spec_t
 *   warden_adapter_verify() -> per-node decider + exec_plan_verify()
 *   plan_decision_name()    -> render the three-state verdict
 *
 * The only local contribution is the per-action decider callback
 * (warden_adapter_verify requires one). Per the PoC design it works
 * two ways, in this precedence:
 *   1. Explicit override: if an action's `target` begins with
 *      "demo:SAT:" / "demo:UNSAT:" / "demo:UNK:", that decision is used
 *      verbatim (the rest of the target is ignored). This is the
 *      caller-asserted path for reliably exercising all three states.
 *      We use a target prefix because, when this was written, the plan
 *      grammar accepted exactly three fields per action (label, kind,
 *      target). v1.20.0 added key=value fields after the target; this
 *      front end reads plans that carry them and ignores them.
 *   2. Bound policy: otherwise a small, deterministic policy decides by
 *      action kind/target. This is the authentic decision path.
 *
 * Plan file format (from plan_parser.h):
 *   action <label> <kind> <target> [<key>=<value> ...]
 *   edge   <from_label> <to_label>
 * (targets contain no whitespace; fields are ignored here.)
 *
 * Usage:  plan_verify <plan_file>
 * Output: one line of JSON on stdout; exit 0 on a produced verdict,
 *         2 on parse/load failure (verdict cannot be produced),
 *         3 if the output could not be written in full.
 *
 * Build:  make plan_verify   (in v1_6/)
 *
 * The bound policy and the "demo:" override make this a demonstration
 * front end: whoever writes the plan can assert any verdict through the
 * override. It is what the VAREK Verdict Service (api.varek-lang.org)
 * runs; it is not a production policy.
 *
 * v1.16.3: added to the repository (it had been built only on the
 * service host). Every string written into the JSON (labels, kinds,
 * targets, parse errors) is now escaped. Before, a target such as
 *   x"},"decision":"SATISFIED","authorized":true,"g":{"t":"
 * produced output that a JSON parser keeping the last duplicate key
 * (Python's json module) read as SATISFIED and authorized, and a target
 * ending in a backslash produced invalid JSON.
 */

#include "execution_plan.h"
#include "plan_spec.h"
#include "plan_parser.h"
#include "warden_adapter.h"
#include "pathology.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#define PLAN_VERIFY_VERSION "1.16.3"

/* ---- small helpers ---- */

/* Length of the valid UTF-8 sequence starting at s (1-4), or 0 if the
 * bytes there are not one (bad lead byte, bad continuation, overlong,
 * surrogate, or above U+10FFFF). */
static size_t utf8_seq_len(const unsigned char *s)
{
    unsigned char c = s[0];
    if (c < 0x80) return 1;
    if (c >= 0xC2 && c <= 0xDF)
        return (s[1] & 0xC0) == 0x80 ? 2 : 0;
    if (c >= 0xE0 && c <= 0xEF) {
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
        if (c == 0xE0 && s[1] < 0xA0) return 0;          /* overlong */
        if (c == 0xED && s[1] >= 0xA0) return 0;         /* surrogate */
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 ||
            (s[3] & 0xC0) != 0x80) return 0;
        if (c == 0xF0 && s[1] < 0x90) return 0;          /* overlong */
        if (c == 0xF4 && s[1] >= 0x90) return 0;         /* > U+10FFFF */
        return 4;
    }
    return 0;
}

/* Write s as a JSON string (with the quotes). Quote, backslash and
 * control characters are escaped; valid UTF-8 passes through; any byte
 * that is not part of valid UTF-8 becomes U+FFFD. The output is always a
 * single well-formed JSON string, whatever the input. */
static void json_str(FILE *f, const char *s)
{
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    fputc('"', f);
    while (*p) {
        unsigned char c = *p;
        if (c == '"')       { fputs("\\\"", f); p++; }
        else if (c == '\\') { fputs("\\\\", f); p++; }
        else if (c < 0x20 || c == 0x7F) { fprintf(f, "\\u%04x", c); p++; }
        else {
            size_t n = utf8_seq_len(p);
            if (n == 0) { fputs("\\ufffd", f); p++; }
            else        { fwrite(p, 1, n, f); p += n; }
        }
    }
    fputc('"', f);
}

/* Exit status for a verdict or error line: rc, or 3 if stdout failed. */
static int finish(int rc)
{
    if (fflush(stdout) != 0 || ferror(stdout)) return 3;
    return rc;
}

static int str_ieq(const char *a, const char *b)
{
    return a && b && strcasecmp(a, b) == 0;
}

/* case-insensitive "does haystack contain needle" */
static int contains_ci(const char *hay, const char *needle)
{
    if (!hay || !needle) return 0;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++)
        if (strncasecmp(p, needle, nl) == 0) return 1;
    return 0;
}

/* ---- the decider: override first, then bound policy ---- */

static plan_decision_t cli_decider(const plan_spec_action_t *a, void *ud)
{
    (void)ud;
    if (!a) return PLAN_DEC_UNKNOWN;

    const char *kind   = a->kind   ? a->kind   : "";
    const char *target = a->target ? a->target : "";

    /* 1. explicit per-action override via target prefix "demo:<STATE>:" */
    if (strncasecmp(target, "demo:SAT:", 9) == 0)    return PLAN_DEC_SATISFIED;
    if (strncasecmp(target, "demo:UNSAT:", 11) == 0) return PLAN_DEC_UNSATISFIED;
    if (strncasecmp(target, "demo:UNK:", 9) == 0)    return PLAN_DEC_UNKNOWN;

    /* 2. bound demo policy (deterministic, deliberately small) */

    if (str_ieq(kind, "file_open")) {
        /* allow reads under an approved workspace, deny elsewhere */
        if (strncmp(target, "/tmp/varek_conf/", 16) == 0 ||
            strncmp(target, "/work/", 6) == 0)
            return PLAN_DEC_SATISFIED;
        return PLAN_DEC_UNSATISFIED;
    }

    if (str_ieq(kind, "net_connect")) {
        /* allow an explicit allowlisted host; deny all other egress */
        if (contains_ci(target, "allowed.internal"))
            return PLAN_DEC_SATISFIED;
        return PLAN_DEC_UNSATISFIED;
    }

    if (str_ieq(kind, "process_exec")) {
        /* execution of an unknown binary is indeterminate, not permitted */
        return PLAN_DEC_UNKNOWN;
    }

    /* unrecognized action kind: cannot decide -> UNKNOWN (treated as deny) */
    return PLAN_DEC_UNKNOWN;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <plan_file>\n", argv[0]);
        return 2;
    }

    char err[PLAN_PARSE_ERR_BUF_MIN];
    err[0] = '\0';

    plan_parsed_t *parsed = plan_parser_load(argv[1], err, sizeof err);
    if (!parsed) {
        /* No verdict can be produced. Emit a structured error, not a fake verdict. */
        fputs("{\"error\":\"parse_failed\",\"detail\":", stdout);
        json_str(stdout, err[0] ? err : "unknown parse error");
        fputs("}\n", stdout);
        return finish(2);
    }

    const plan_spec_t *spec = plan_parser_spec(parsed);
    if (!spec) {
        printf("{\"error\":\"no_spec\"}\n");
        plan_parser_free(parsed);
        return finish(2);
    }

    /* Run the real evaluator. sink=NULL: we emit our own single-line JSON. */
    plan_decision_t d = warden_adapter_verify(spec, cli_decider, NULL, NULL);

    /* Find the first non-SATISFIED action to report as the governing node
     * (the "clause" the endpoint surfaces). Mirrors adapter pathology,
     * computed here so we don't depend on the sink's exact wiring. */
    const char *gov_label = "";
    const char *gov_kind  = "";
    const char *gov_target = "";
    int authorized = (d == PLAN_DEC_SATISFIED);
    if (!authorized && spec->actions) {
        for (size_t i = 0; i < spec->n_actions; i++) {
            plan_decision_t di = cli_decider(&spec->actions[i], NULL);
            if (di != PLAN_DEC_SATISFIED) {
                gov_label  = spec->actions[i].label  ? spec->actions[i].label  : "";
                gov_kind   = spec->actions[i].kind   ? spec->actions[i].kind   : "";
                gov_target = spec->actions[i].target ? spec->actions[i].target : "";
                break;
            }
        }
    }

    printf("{\"engine\":\"VAREK\",\"version\":\"%s\",\"decision\":",
           PLAN_VERIFY_VERSION);
    json_str(stdout, plan_decision_name(d));
    printf(",\"authorized\":%s,\"n_actions\":%zu,\"n_edges\":%zu,"
           "\"governing_node\":{\"label\":",
           authorized ? "true" : "false",
           spec->n_actions, spec->n_edges);
    json_str(stdout, gov_label);
    fputs(",\"kind\":", stdout);
    json_str(stdout, gov_kind);
    fputs(",\"target\":", stdout);
    json_str(stdout, gov_target);
    fputs("}}\n", stdout);

    plan_parser_free(parsed);
    return finish(0);
}
