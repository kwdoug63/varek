// SPDX-License-Identifier: MIT
// vdp_check.c — command-line front end to the Warden's SMT decision procedure
// (smt_decide.c), linked from the same source the Warden runs. Used by the
// solver cross-check (tools/smt_crosscheck.py) and the verdict-distribution
// harness (tools/verdict_harness.py), and by operators to lint a policy.
//
//   vdp_check <policy> lint
//       Human-readable: parse errors, and every rule that can never fire.
//       Exit 0 if the policy parses and no rule is DEAD, 1 if some rule is
//       DEAD, 2 on a parse error.
//   vdp_check <policy> analyze
//       One JSON line per rule: {"index","line","kind","verb","reach"}.
//   vdp_check <policy> batch
//       Reads queries from stdin, one per line:
//           <path|host|exec> <flags|-> <hex-encoded string>
//       flags is a decimal or 0x-hex 32-bit value, or '-' for symbolic flags.
//       Writes one JSON line per query: {"verdict","rule","line","why"}.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../smt_decide.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static vdp_policy_t g_pol;

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_kind(const char *k, vdp_kind_t *out) {
    if (!strcmp(k, "path")) { *out = VDP_KIND_PATH; return 0; }
    if (!strcmp(k, "host")) { *out = VDP_KIND_HOST; return 0; }
    if (!strcmp(k, "exec")) { *out = VDP_KIND_EXEC; return 0; }
    return -1;
}

static int do_batch(void) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    static char s[VDP_STR_MAX + 64];
    while ((n = getline(&line, &cap, stdin)) >= 0) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (n == 0) continue;
        char *save = NULL;
        char *k = strtok_r(line, " ", &save);
        char *fl = strtok_r(NULL, " ", &save);
        char *hx = strtok_r(NULL, " ", &save);
        if (!hx) hx = "";          /* empty string */
        vdp_kind_t kind;
        if (!k || !fl || parse_kind(k, &kind) < 0) {
            printf("{\"error\":\"bad query\"}\n");
            continue;
        }
        bool has_flags = strcmp(fl, "-") != 0;
        uint32_t flags = has_flags ? (uint32_t)strtoul(fl, NULL, 0) : 0;
        size_t hl = strlen(hx);
        if (hl % 2 || hl / 2 > sizeof s - 1) {
            printf("{\"error\":\"bad hex\"}\n");
            continue;
        }
        size_t sl = 0;
        int bad = 0;
        for (size_t i = 0; i < hl; i += 2) {
            int a = hexval(hx[i]), b = hexval(hx[i + 1]);
            if (a < 0 || b < 0) { bad = 1; break; }
            s[sl++] = (char)(a * 16 + b);
        }
        s[sl] = '\0';
        if (bad || memchr(s, '\0', sl)) { printf("{\"error\":\"bad hex\"}\n"); continue; }
        int ri;
        vdp_why_t why;
        vdp_verdict_t v = vdp_decide(&g_pol, kind, s, flags, has_flags, &ri, &why);
        printf("{\"verdict\":\"%s\",\"rule\":%d,\"line\":%d,\"why\":\"%s\"}\n",
               vdp_verdict_name(v), ri, ri >= 0 ? g_pol.rules[ri].line : -1,
               vdp_why_name(why));
    }
    free(line);
    fflush(stdout);
    return 0;
}

static const char *reach_name(vdp_reach_t r) {
    return r == VDP_REACHABLE ? "REACHABLE" : r == VDP_DEAD ? "DEAD" : "UNKNOWN";
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <policy> lint|analyze|batch\n", argv[0]);
        return 2;
    }
    char err[512];
    if (vdp_policy_load(argv[1], &g_pol, err, sizeof err) < 0) {
        if (!strcmp(argv[2], "lint")) fprintf(stderr, "policy error: %s\n", err);
        else printf("{\"error\":\"policy\",\"detail\":\"%s\"}\n", "parse");
        if (strcmp(argv[2], "lint")) fprintf(stderr, "policy error: %s\n", err);
        return 2;
    }
    if (!strcmp(argv[2], "batch")) return do_batch();
    if (!strcmp(argv[2], "analyze")) {
        for (size_t i = 0; i < g_pol.n; i++) {
            const vdp_rule_t *r = &g_pol.rules[i];
            printf("{\"index\":%zu,\"line\":%d,\"kind\":\"%s\",\"verb\":\"%s\",\"reach\":\"%s\"}\n",
                   i, r->line, vdp_kind_name(r->kind),
                   r->verb == VDP_ALLOW ? "allow" : "deny",
                   reach_name(vdp_rule_reachable(&g_pol, i)));
        }
        return 0;
    }
    if (!strcmp(argv[2], "lint")) {
        int dead = 0;
        for (size_t i = 0; i < g_pol.n; i++) {
            char adv[512];
            if (vdp_rule_advisory(&g_pol.rules[i], adv, sizeof adv))
                printf("%s:%d: note: %s\n", argv[1], g_pol.rules[i].line, adv);
            vdp_reach_t rr = vdp_rule_reachable(&g_pol, i);
            if (rr == VDP_DEAD) {
                const vdp_rule_t *r = &g_pol.rules[i];
                printf("%s:%d: %s %s %s can never fire (every action it matches is "
                       "decided by an earlier rule)\n", argv[1], r->line,
                       r->verb == VDP_ALLOW ? "allow" : "deny", vdp_kind_name(r->kind), r->s.c);
                dead++;
            } else if (rr == VDP_REACH_UNKNOWN) {
                printf("%s:%d: reachability not decided (outside the enumeration bound)\n",
                       argv[1], g_pol.rules[i].line);
            }
        }
        printf("%s: %zu rules, %d can never fire\n", argv[1], g_pol.n, dead);
        return dead ? 1 : 0;
    }
    fprintf(stderr, "unknown mode %s\n", argv[2]);
    return 2;
}
