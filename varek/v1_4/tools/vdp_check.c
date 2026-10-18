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
//   vdp_check <policy> analyze [automaton]
//       One JSON line per rule: {"index","line","kind","verb","reach"}, plus
//       for a REACHABLE rule a witness: "witness" (hex string) and "flags"
//       (the rule is the first to hold on that pair), and for UNKNOWN the
//       budget that was hit ("why"). With `automaton`, every path and exec
//       rule is decided by the automaton search (testing: the cross-check
//       runs both methods on the same policies).
//   vdp_check <policy> batch
//       Reads queries from stdin, one per line:
//           <path|host|exec|request|mcp> <flags|-> <hex-encoded string, or '=' if empty> [@<subject>]
//       flags is a decimal or 0x-hex 32-bit value, or '-' for symbolic flags.
//       Writes one JSON line per query: {"verdict","rule","line","why"}, and
//       for a SATISFIED verdict (v1.15) its certificate's witness "w" in the
//       vdp_cert_check input form ('-', 'c:<offset>' or 'g:<a>-<b>,...';
//       "!" if no witness could be built).

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../smt_decide.h"
#include "../shared_domains.h"
#include <fcntl.h>

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
    if (!strcmp(k, "request")) { *out = VDP_KIND_REQUEST; return 0; }     /* v1.26.1 */
    if (!strcmp(k, "mcp")) { *out = VDP_KIND_MCP; return 0; }             /* v1.31 */
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
        char *sj = strtok_r(NULL, " ", &save);  /* v1.31: @N, the calling subject (default @0) */
        if (!hx || !strcmp(hx, "=")) hx = "";   /* empty string (absent, or '=') */
        char *send = NULL;
        long subj = sj ? (sj[0] == '@' ? strtol(sj + 1, &send, 10) : -1) : 0;
        if (sj && (subj < 0 || subj > 1000 || !send || *send || send == sj + 1)) {
            printf("{\"error\":\"bad subject\"}\n");
            continue;
        }
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
        vdp_verdict_t v = vdp_decide_subj(&g_pol, (int)subj, kind, s, flags, has_flags, &ri, &why);
        printf("{\"verdict\":\"%s\",\"rule\":%d,\"line\":%d,\"why\":\"%s\"",
               vdp_verdict_name(v), ri, ri >= 0 ? g_pol.rules[ri].line : -1,
               vdp_why_name(why));
        if (v == VDP_SATISFIED) {
            vdp_cert_t c;
            if (vdp_certificate(&g_pol, ri, s, &c) < 0) printf(",\"w\":\"!\"");
            else if (c.wkind == VDP_WIT_OFFSET) printf(",\"w\":\"c:%u\"", c.off);
            else if (c.wkind == VDP_WIT_SPANS) {
                printf(",\"w\":\"g:");
                for (uint32_t k = 0; k < c.nspan; k++)
                    printf("%s%u-%u", k ? "," : "", c.span[k][0], c.span[k][1]);
                printf("\"");
            } else printf(",\"w\":\"-\"");
        }
        printf("}\n");
    }
    free(line);
    fflush(stdout);
    return 0;
}

static const char *reach_name(vdp_reach_t r) {
    return r == VDP_REACHABLE ? "REACHABLE" : r == VDP_DEAD ? "DEAD" : "UNKNOWN";
}

int main(int argc, char **argv) {
    if (argc != 3 && !(argc == 4 && !strcmp(argv[2], "analyze") && !strcmp(argv[3], "automaton"))) {
        fprintf(stderr, "usage: %s <policy> lint|analyze [automaton]|batch|launches|mounts|openas|credentials|identity\n", argv[0]);
        return 2;
    }
    if (argc == 4) vdp_reach_force_automaton = true;
    char err[512];
    if (vdp_policy_load(argv[1], &g_pol, err, sizeof err) < 0) {
        if (!strcmp(argv[2], "lint")) fprintf(stderr, "policy error: %s\n", err);
        else printf("{\"error\":\"policy\",\"detail\":\"%s\"}\n", "parse");
        if (strcmp(argv[2], "lint")) fprintf(stderr, "policy error: %s\n", err);
        return 2;
    }
    if (!strcmp(argv[2], "batch")) return do_batch();
    /* v1.27: are launches after the first decided (require warden 1.27)? */
    if (!strcmp(argv[2], "launches")) {
        printf("%s\n", g_pol.launches ? "on" : "off");
        return 0;
    }
    /* v1.32: will the Warden mount anything (launches decided and a path
     * rule that writes somewhere absolute: the noexec mounts, as
     * noexec_build lists them; a rule no directory bounds makes the Warden
     * refuse, counted as mounting)? varek run's container check */
    if (!strcmp(argv[2], "mounts")) {
        bool w = false;
        for (size_t i = 0; g_pol.launches && i < g_pol.n; i++) {
            char t[4096];
            bool exact;
            if (vdp_rule_may_write(&g_pol.rules[i]) &&
                (vdp_rule_noexec_target(&g_pol.rules[i], t, sizeof t, &exact) < 0 || t[0])) w = true;
        }
        printf("%s\n", w ? "on" : "off");
        return 0;
    }
    /* v1.29: are files opened with the agent's credentials (require warden 1.29)? */
    if (!strcmp(argv[2], "openas")) {
        printf("%s\n", g_pol.open_as_agent ? "on" : "off");
        return 0;
    }
    /* v1.28: the credentials and the rules that carry them, as this parser
     * read them (the certificate checker and the cross-check oracle print the
     * same lines; the cross-check compares them) */
    if (!strcmp(argv[2], "credentials")) {
        static const char *const kStore[] = { "", "file", "vault", "aws-sm" };
        for (size_t k = 0; k < g_pol.ncreds; k++)
            printf("credential %s %s %s\n", g_pol.creds[k].name, kStore[g_pol.creds[k].store], g_pol.creds[k].ref);
        for (size_t i = 0; i < g_pol.n; i++) {
            const vdp_rule_t *r = &g_pol.rules[i];
            if (r->cred)
                printf("rule %d %s %s %s\n", r->line, g_pol.creds[r->cred - 1].name, r->cred_hdr,
                       r->cred_scheme[0] ? r->cred_scheme : "-");
        }
        /* v1.31: an MCP access token's audience */
        for (size_t k = 0; k < g_pol.ncreds; k++)
            if (g_pol.creds[k].audience[0])
                printf("audience %s %s %s\n", g_pol.creds[k].name, g_pol.creds[k].audience,
                       g_pol.creds[k].opaque ? "opaque" : "-");
        return 0;
    }
    /* v1.28.1: the identities the run trusts and the sub-agents, as this
     * parser read them (vdp_cert_check and the oracle print the same) */
    if (!strcmp(argv[2], "identity")) {
        for (size_t k = 0; k < g_pol.nissuers; k++)
            printf("issuer %s %s %s\n", g_pol.issuers[k].iss, g_pol.issuers[k].aud,
                   g_pol.issuers[k].jwks[0] ? g_pol.issuers[k].jwks : "-");
        for (size_t k = 0; k < g_pol.nspiffe; k++)
            printf("spiffe %s %s\n", g_pol.spiffe[k].domain, g_pol.spiffe[k].bundle);
        for (size_t i = 0; i < g_pol.n; i++)
            if (g_pol.rules[i].subagent[0]) printf("subagent %d %s\n", g_pol.rules[i].line, g_pol.rules[i].subagent);
        if (g_pol.require_obo) printf("require on-behalf-of\n");
        /* v1.31: the confined subjects, the rules for each, the MCP resources */
        for (size_t k = 0; k < g_pol.nsubjects; k++) {
            const vdp_rule_t *r = &g_pol.rules[g_pol.subjects[k].rule];
            printf("confined %zu %s %s %d %s\n", k + 1, g_pol.subjects[k].name,
                   g_pol.subjects[k].mcp ? "mcp" : "subagent", r->line, r->sha256[0] ? r->sha256 : "-");
        }
        for (size_t i = 0; i < g_pol.n; i++)
            if (g_pol.rules[i].subj) printf("for %d %d\n", g_pol.rules[i].line, g_pol.rules[i].subj);
        for (size_t k = 0; k < g_pol.nmcpres; k++)
            printf("mcp-resource %s %s\n", g_pol.mcpres[k].url, g_pol.mcpres[k].aud[0] ? g_pol.mcpres[k].aud : "-");
        return 0;
    }
    if (!strcmp(argv[2], "analyze")) {
        static char wit[VDP_STR_MAX + 1];
        for (size_t i = 0; i < g_pol.n; i++) {
            const vdp_rule_t *r = &g_pol.rules[i];
            size_t wl = 0;
            uint32_t wf = 0;
            vdp_reach_t rr = vdp_rule_reachable_witness(&g_pol, i, wit, sizeof wit, &wl, &wf);
            printf("{\"index\":%zu,\"line\":%d,\"kind\":\"%s\",\"verb\":\"%s\",\"reach\":\"%s\"",
                   i, r->line, vdp_kind_name(r->kind),
                   r->verb == VDP_ALLOW ? "allow" : "deny", reach_name(rr));
            if (rr == VDP_REACHABLE) {
                printf(",\"witness\":\"");
                for (size_t k = 0; k < wl; k++) printf("%02x", (unsigned char)wit[k]);
                printf("\",\"flags\":\"0x%x\"", wf);
            } else if (rr == VDP_REACH_UNKNOWN) {
                printf(",\"why\":\"%s\"", vdp_reach_unknown_reason());
            }
            printf("}\n");
        }
        return 0;
    }
    if (!strcmp(argv[2], "lint")) {
        int dead = 0, hostnever = 0;
        for (size_t i = 0; i < g_pol.n; i++) {
            char adv[512], hw[160];
            if (vdp_rule_advisory(&g_pol.rules[i], adv, sizeof adv))
                printf("%s:%d: note: %s\n", argv[1], g_pol.rules[i].line, adv);
            /* v1.27: an interpreter or shell allowed to launch, or a file both
             * launched and written */
            if (vdp_exec_advisory(&g_pol, i, adv, sizeof adv))
                printf("%s:%d: note: %s\n", argv[1], g_pol.rules[i].line, adv);
            /* v1.21: a host rule whose constant no connect can produce (a
             * non-canonical spelling, or a v1.24 host name without `require
             * warden 1.24`) matches nothing: counted, and
             * lint fails, as for a rule that can never fire. */
            if (g_pol.rules[i].kind == VDP_KIND_HOST &&
                !vdp_host_rule_ok(&g_pol.rules[i], hw, sizeof hw))
                hostnever++;
            /* v1.26.1: a request rule whose exact host no host rule allows on
             * its port is never reached: the connection is refused first */
            if ((g_pol.rules[i].kind == VDP_KIND_REQUEST || g_pol.rules[i].kind == VDP_KIND_MCP) &&
                vdp_request_host_refused(&g_pol, i, hw, sizeof hw)) {
                printf("%s:%d: %s rule can never fire: %s\n", argv[1], g_pol.rules[i].line,
                       vdp_kind_name(g_pol.rules[i].kind), hw);
                dead++;
                continue;
            }
            vdp_reach_t rr = vdp_rule_reachable(&g_pol, i);
            if (rr == VDP_DEAD) {
                const vdp_rule_t *r = &g_pol.rules[i];
                printf("%s:%d: %s %s %s%s can never fire (every action it matches is decided "
                       "by an earlier rule, or it matches no string within the length bound)\n",
                       argv[1], r->line, r->verb == VDP_ALLOW ? "allow" : "deny",
                       vdp_kind_name(r->kind), vdp_matcher_prefix(r), r->s.c);
                dead++;
            } else if (rr == VDP_REACH_UNKNOWN) {
                printf("%s:%d: reachability not decided (%s)\n", argv[1], g_pol.rules[i].line,
                    vdp_reach_unknown_text());
            }
        }
        /* v1.31: a confined subject no rule is written for: every call it makes
         * is refused (a note; a server needs at least its loader and libraries) */
        for (size_t k = 0; k < g_pol.nsubjects; k++) {
            bool any = false;
            for (size_t i = 0; i < g_pol.n && !any; i++) any = g_pol.rules[i].subj == (int)k + 1;
            if (!any)
                printf("%s:%d: note: no rule is written for %s (for=%s): every call it makes is refused\n",
                       argv[1], g_pol.subjects[k].line, g_pol.subjects[k].name, g_pol.subjects[k].name);
        }
        /* v1.31 review: a confined subject's file, or a directory above it, that
         * any subject's rules let be written: the Warden refuses to start (the
         * file could be replaced); say so here, and fail */
        int replaceable = 0;
        for (size_t i = 0; i < g_pol.n; i++) {
            const vdp_rule_t *r = &g_pol.rules[i];
            if (!r->confined_subj || r->kind != VDP_KIND_EXEC || r->s.c[0] != '/') continue;
            char d[VDP_STR_MAX + 1];
            snprintf(d, sizeof d, "%s", r->s.c);
            bool hit = false;
            for (;;) {
                static const uint32_t kW[] = { O_WRONLY, O_RDWR, O_WRONLY | O_CREAT | O_TRUNC, O_RDWR | O_CREAT };
                for (size_t j = 0; j <= g_pol.nsubjects && !hit; j++)
                    for (size_t f = 0; f < sizeof kW / sizeof kW[0] && !hit; f++) {
                        int ri = -1;
                        vdp_why_t wy;
                        hit = vdp_decide_subj(&g_pol, (int)j, VDP_KIND_PATH, d, kW[f], true, &ri, &wy) == VDP_SATISFIED;
                    }
                if (hit) break;
                char *sl = strrchr(d, '/');
                if (!sl) break;
                if (sl == d) { if (!d[1]) break; d[1] = '\0'; continue; }
                *sl = '\0';
            }
            if (hit) {
                printf("%s:%d: %s's file %s could be replaced: the policy lets %s be written; the Warden "
                       "refuses to start\n", argv[1], r->line, r->subagent, r->s.c, d);
                replaceable++;
            }
        }
        /* v1.31 review: an mcp rule's METHOD is a path glob, so '*' does not
         * match '/': `deny mcp URL * NAME` misses tools/call (a note) */
        for (size_t i = 0; i < g_pol.n; i++) {
            const vdp_rule_t *r = &g_pol.rules[i];
            if (r->kind != VDP_KIND_MCP) continue;
            const char *m = strchr(r->s.c, '#');
            const char *e = m ? strchr(m + 1, '#') : NULL;
            if (!m || !e) continue;
            bool star = false, slash = false, dstar = false;
            for (const char *q = m + 1; q < e; q++) {
                star |= *q == '*';
                slash |= *q == '/';
                dstar |= q[0] == '*' && q + 1 < e && q[1] == '*';
            }
            if (star && !slash && !dstar)
                printf("%s:%d: note: the method %.*s matches no method with a '/' (tools/call, resources/read): "
                       "'*' does not match '/'; write ** or the method\n", argv[1], r->line, (int)(e - m - 1), m + 1);
        }
        /* v1.25: an allow wildcard over a shared domain is refused at load
         * (shared_domains.h), as the Warden refuses it; lint names the entry. */
        int shared = 0;
        for (size_t i = 0; i < g_pol.n; i++) {
            const vdp_rule_t *r = &g_pol.rules[i];
            if (r->kind != VDP_KIND_HOST || !r->s.wild || r->verb != VDP_ALLOW) continue;
            static sd_lists_t *lists;
            static int tried;
            char why[512], psl[4096], var[4096], suf[512];
            if (!tried) {
                tried = 1;
                if (sd_default_path("public_suffix_list.dat", psl, sizeof psl) < 0 ||
                    sd_default_path("varek_shared_domains.txt", var, sizeof var) < 0)
                    snprintf(why, sizeof why, "the shared-domain lists (data/) were not found");
                else
                    lists = sd_load(psl, var, why, sizeof why);
                if (!lists) printf("%s: %s; wildcard host rules cannot be checked\n", argv[1], why);
            }
            if (!lists) { shared++; continue; }
            if (sd_wildcard_suffix(r->s.c, suf, sizeof suf) == 0 &&
                sd_refuses(lists, suf, why, sizeof why)) {
                printf("%s:%d: allow host *.%s is refused: %s\n", argv[1], r->line, suf, why);
                shared++;
            }
        }
        /* v1.27 review: with launches on, an allow exec rule the Warden cannot
         * expand to a set of files refuses its start; say so here, and fail */
        int noexpand = 0;
        for (size_t i = 0; g_pol.launches && i < g_pol.n; i++) {
            const vdp_rule_t *r = &g_pol.rules[i];
            if (r->kind != VDP_KIND_EXEC || r->verb != VDP_ALLOW) continue;
            const char *c = r->s.c, *why = NULL;
            size_t cl = strlen(c);
            if (r->s.op != VDP_STR_EQ && r->s.op != VDP_STR_PREFIX && r->s.op != VDP_STR_GLOB)
                why = "a suffix or contains rule cannot be expanded to the files it admits";
            else if (r->s.op == VDP_STR_GLOB && c[0] != '/')
                why = "a glob must start with a directory (\"/...\") to be expanded";
            else if (c[0] == '/' && (strstr(c, "/./") || strstr(c, "/../") || strstr(c, "//") ||
                     (cl >= 2 && !strcmp(c + cl - 2, "/.")) || (cl >= 3 && !strcmp(c + cl - 3, "/.."))))
                why = "its path holds a \".\" or \"..\" segment or \"//\"; launches are decided on names "
                      "without them";
            if (why) {
                printf("%s:%d: allow exec is refused by the Warden at start: %s\n", argv[1], r->line, why);
                noexpand++;
            }
        }
        /* v1.27: exec rules without the opt-in decide only the first launch */
        for (size_t i = 0; !g_pol.launches && i < g_pol.n; i++)
            if (g_pol.rules[i].kind == VDP_KIND_EXEC && g_pol.rules[i].verb == VDP_ALLOW) {
                printf("%s:%d: note: exec rules take effect for launches after the first only with "
                       "`require warden 1.27`; without it every later launch is refused\n",
                       argv[1], g_pol.rules[i].line);
                break;
            }
        /* v1.28: a credential no request rule carries is fetched for nothing */
        for (size_t k = 0; k < g_pol.ncreds; k++) {
            bool used = false;
            for (size_t i = 0; !used && i < g_pol.n; i++) used = g_pol.rules[i].cred == (int)k + 1;
            if (!used)
                printf("%s:%d: note: credential %s is named, but no request or mcp rule carries it\n",
                       argv[1], g_pol.creds[k].line, g_pol.creds[k].name);
        }
        /* v1.28.1: `require on-behalf-of` with no trusted issuer: no token can
         * be verified, so no run can start; and a `trust issuer` line without
         * `require on-behalf-of` is used only when the operator gives a token */
        if (g_pol.require_obo && !g_pol.nissuers && !g_pol.nmcpres)       /* v1.31: or an MCP resource */
            printf("%s: note: require on-behalf-of, but no issuer is trusted (trust issuer ...): no run can "
                   "start\n", argv[1]);
        /* v1.16: the policy's glob size against the cap that bounds the work
         * of one decision (4,096 tokens x a 4,095-byte string). */
        printf("%s: glob tokens %zu of %d\n", argv[1], vdp_policy_glob_tokens(&g_pol),
               VDP_GLOB_MAX_TOTAL);
        if (hostnever)
            printf("%s: %zu rules, %d can never fire, %d host rules can never match a connect\n",
                   argv[1], g_pol.n, dead, hostnever);
        else
            printf("%s: %zu rules, %d can never fire\n", argv[1], g_pol.n, dead);
        if (shared)
            printf("%s: %d wildcard host rules refused (shared domains)\n", argv[1], shared);
        return dead || hostnever || shared || noexpand || replaceable ? 1 : 0;
    }
    fprintf(stderr, "unknown mode %s\n", argv[2]);
    return 2;
}
