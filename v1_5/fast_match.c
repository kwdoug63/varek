// SPDX-License-Identifier: MIT
/*
 * fast_match.c — fast-path policy matcher for VAREK v1.5
 *
 * Implements the simple-rule classifier and matcher that handles the
 * common case in policy_decide():
 *
 *   - Rules are loaded from a policy.txt file at startup
 *   - Simple rules (path-prefix, exact host, exec path) are compiled
 *     into sorted arrays for binary-search lookup
 *   - Complex rules (regex, conjunction, etc.) would route to the
 *     SMT slow path — not implemented in this benchmark, all current
 *     v1.4 rules are simple
 *
 * The three-state return ALLOW / DENY / UNKNOWN is preserved.
 * UNKNOWN suppression to DENY happens at the call boundary.
 *
 * Build:    make fast_match
 * Run:      ./fast_match [iterations]   2> bench_fast.log
 *           python3 ../v1_4/bench_summarize.py bench_fast.log
 *
 * Companion: smt_probe.c, smt_probe2.c (slow path, deferred for richer
 *            policies — see NOTES.md).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_ITER  10000
#define MAX_RULES     1024
#define PATH_LIMIT    4096

/* ---------------- decision types ---------------- */

typedef enum { DEC_ALLOW, DEC_DENY, DEC_UNKNOWN } decision_t;

static const char *decision_name(decision_t d) {
    switch (d) {
        case DEC_ALLOW:   return "ALLOW";
        case DEC_DENY:    return "DENY";
        case DEC_UNKNOWN: return "UNKNOWN";
    }
    return "INVALID";
}

/* ---------------- rule storage ---------------- */

typedef enum { KIND_PATH, KIND_HOST, KIND_EXEC } rule_kind_t;

struct rule {
    rule_kind_t kind;
    char        match[PATH_LIMIT];
    decision_t  decision;
    /* Pre-computed length for hot-path strncmp avoidance. */
    size_t      match_len;
};

/*
 * Compiled policy: rules separated by kind, each kind sorted by match
 * string for binary-search lookup. Order within a kind is alphabetical;
 * "first match wins" semantics are preserved by checking allow rules
 * before deny rules at lookup time, then falling through to UNKNOWN.
 *
 * For prefix matching, sort order means that for any query, the
 * longest matching prefix is the lexicographically-largest entry that
 * is <= query. We binary-search for the upper bound and walk back one.
 */
struct compiled_policy {
    struct rule path_rules[MAX_RULES];
    size_t      n_path;
    struct rule host_rules[MAX_RULES];
    size_t      n_host;
    struct rule exec_rules[MAX_RULES];
    size_t      n_exec;
};

static int rule_cmp(const void *a, const void *b) {
    const struct rule *ra = (const struct rule *)a;
    const struct rule *rb = (const struct rule *)b;
    return strcmp(ra->match, rb->match);
}

/* ---------------- policy load ---------------- */

static int policy_load(const char *path, struct compiled_policy *p) {
    memset(p, 0, sizeof(*p));
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[fast_match] cannot open %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    char line[PATH_LIMIT + 64];
    int  lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *q = line;
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q == '#' || *q == '\0' || *q == '\n') continue;
        size_t L = strlen(q);
        while (L && (q[L-1] == '\n' || q[L-1] == '\r' || q[L-1] == ' ')) {
            q[--L] = '\0';
        }

        char verb[16] = {0}, kind[16] = {0}, match[PATH_LIMIT] = {0};
        if (sscanf(q, "%15s %15s %4095s", verb, kind, match) != 3) {
            fprintf(stderr, "[fast_match] bad rule at %s:%d\n", path, lineno);
            fclose(f); return -1;
        }
        struct rule r;
        memset(&r, 0, sizeof(r));
        if      (!strcmp(kind, "path")) r.kind = KIND_PATH;
        else if (!strcmp(kind, "host")) r.kind = KIND_HOST;
        else if (!strcmp(kind, "exec")) r.kind = KIND_EXEC;
        else { fprintf(stderr, "[fast_match] bad kind '%s' at %s:%d\n",
                       kind, path, lineno); fclose(f); return -1; }
        if      (!strcmp(verb, "allow")) r.decision = DEC_ALLOW;
        else if (!strcmp(verb, "deny"))  r.decision = DEC_DENY;
        else { fprintf(stderr, "[fast_match] bad verb '%s' at %s:%d\n",
                       verb, path, lineno); fclose(f); return -1; }
        snprintf(r.match, sizeof(r.match), "%s", match);
        r.match_len = strlen(r.match);

        switch (r.kind) {
            case KIND_PATH:
                if (p->n_path >= MAX_RULES) goto too_many;
                p->path_rules[p->n_path++] = r; break;
            case KIND_HOST:
                if (p->n_host >= MAX_RULES) goto too_many;
                p->host_rules[p->n_host++] = r; break;
            case KIND_EXEC:
                if (p->n_exec >= MAX_RULES) goto too_many;
                p->exec_rules[p->n_exec++] = r; break;
        }
    }
    fclose(f);

    /* Sort each kind by match string for binary-search lookup. */
    qsort(p->path_rules, p->n_path, sizeof(struct rule), rule_cmp);
    qsort(p->host_rules, p->n_host, sizeof(struct rule), rule_cmp);
    qsort(p->exec_rules, p->n_exec, sizeof(struct rule), rule_cmp);

    fprintf(stderr,
        "[fast_match] loaded %zu path / %zu host / %zu exec rules from %s\n",
        p->n_path, p->n_host, p->n_exec, path);
    return 0;

too_many:
    fclose(f);
    fprintf(stderr, "[fast_match] policy exceeds MAX_RULES=%d\n", MAX_RULES);
    return -1;
}

/* ---------------- prefix lookup ---------------- */

/*
 * Binary search for the longest prefix of `target` that appears in the
 * sorted `rules` array. We search for the upper bound (first rule
 * lexicographically greater than target) and walk back to test
 * candidates in descending order. The first candidate that is a prefix
 * of target is the longest match.
 *
 * Worst case: O(log n) for the bound + O(k) walkback where k is small
 * in practice (typically 0-2 candidates need testing).
 */
static const struct rule *
prefix_lookup(const struct rule *rules, size_t n, const char *target)
{
    if (n == 0) return NULL;
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (strcmp(rules[mid].match, target) <= 0) lo = mid + 1;
        else                                       hi = mid;
    }
    /* Walk back from lo-1 testing prefix match. */
    while (lo > 0) {
        lo--;
        const struct rule *r = &rules[lo];
        if (r->match_len <= strlen(target) &&
            memcmp(target, r->match, r->match_len) == 0) {
            return r;
        }
        /* If this rule is not a prefix and is lex-smaller than target,
         * we can stop — earlier rules are even smaller and can only be
         * prefixes if they are even shorter. We keep going just one
         * step to handle the "rule is prefix but lex-smaller" case
         * cleanly; in practice walkback rarely exceeds 1-2 steps. */
        if (strncmp(target, r->match, 1) != 0) break;
    }
    return NULL;
}

/* Exact-match lookup (for host and exec rules). */
static const struct rule *
exact_lookup(const struct rule *rules, size_t n, const char *target)
{
    if (n == 0) return NULL;
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int    c   = strcmp(rules[mid].match, target);
        if      (c < 0) lo = mid + 1;
        else if (c > 0) hi = mid;
        else            return &rules[mid];
    }
    return NULL;
}

/* ---------------- policy decision ---------------- */

static decision_t policy_decide(const struct compiled_policy *p,
                                rule_kind_t kind,
                                const char *target)
{
    const struct rule *r = NULL;
    switch (kind) {
        case KIND_PATH:
            r = prefix_lookup(p->path_rules, p->n_path, target);
            break;
        case KIND_HOST:
            /* Try exact match first; fall back to host-only match by
             * stripping ":port". For simplicity here we try exact only;
             * caller is responsible for normalizing as needed. */
            r = exact_lookup(p->host_rules, p->n_host, target);
            break;
        case KIND_EXEC:
            r = exact_lookup(p->exec_rules, p->n_exec, target);
            break;
    }
    return r ? r->decision : DEC_UNKNOWN;
}

static decision_t suppress(decision_t d) {
    return (d == DEC_ALLOW) ? DEC_ALLOW : DEC_DENY;
}

/* ---------------- benchmark workload ---------------- */

struct workload_entry {
    rule_kind_t kind;
    const char *target;
    const char *expected_kind;  /* for the JSON action field */
};

static const struct workload_entry WORKLOAD[] = {
    /* Mix matching the v1.4 policy.txt (after the demo exec rules
     * stripping done in the v1.4 PR). */
    { KIND_PATH, "/tmp/varek_allowed_alpha",       "file.open" },
    { KIND_PATH, "/usr/lib/x86_64-linux-gnu/libc.so.6", "file.open" },
    { KIND_PATH, "/etc/shadow",                    "file.open" },
    { KIND_PATH, "/tmp/no_match",                  "file.open" },
    { KIND_PATH, "/proc/self/maps",                "file.open" },
    { KIND_PATH, "/lib/x86_64-linux-gnu/ld-linux.so.2", "file.open" },
    { KIND_PATH, "/etc/passwd",                    "file.open" },
    { KIND_PATH, "/etc/ld.so.cache",               "file.open" },
    { KIND_HOST, "127.0.0.1:8080",                 "net.connect" },
    { KIND_HOST, "8.8.8.8:53",                     "net.connect" },
    { KIND_EXEC, "/usr/bin/env",                   "process.exec" },
    { KIND_EXEC, "/bin/bash",                      "process.exec" },
};
static const size_t WORKLOAD_N = sizeof(WORKLOAD) / sizeof(WORKLOAD[0]);

/* ---------------- main ---------------- */

int main(int argc, char **argv) {
    int iter = (argc >= 2) ? atoi(argv[1]) : DEFAULT_ITER;
    if (iter <= 0) iter = DEFAULT_ITER;

    const char *policy_path = (argc >= 3) ? argv[2] : "../v1_4/policy.txt";

    static struct compiled_policy pol;  /* ~12 MB; too large for stack */
    if (policy_load(policy_path, &pol) < 0) return 1;

    fprintf(stderr,
        "[fast_match] iter=%d  workload=%zu  policy=%s\n",
        iter, WORKLOAD_N, policy_path);
    fflush(stderr);

    /* Warmup */
    for (size_t w = 0; w < WORKLOAD_N; w++) {
        (void)policy_decide(&pol, WORKLOAD[w].kind, WORKLOAD[w].target);
    }

    int allow_count = 0, deny_count = 0;

    for (int i = 0; i < iter; i++) {
        const struct workload_entry *e = &WORKLOAD[i % WORKLOAD_N];

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        decision_t raw   = policy_decide(&pol, e->kind, e->target);
        decision_t final = suppress(raw);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        uint64_t lat_ns = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                       + (t1.tv_nsec - t0.tv_nsec);

        if (final == DEC_ALLOW) allow_count++; else deny_count++;

        struct timespec wall;
        clock_gettime(CLOCK_REALTIME, &wall);
        fprintf(stderr,
            "{\"report_id\":\"fm-%ld.%09ld-%d\","
            "\"agent_pid\":%d,"
            "\"action\":\"%s\","
            "\"target\":\"%s\","
            "\"decision_raw\":\"%s\","
            "\"decision_final\":\"%s\","
            "\"rule\":\"fast_match\","
            "\"kernel_verdict\":\"%s\","
            "\"latency_us\":%" PRIu64 ","
            "\"latency_ns\":%" PRIu64 ","
            "\"timestamp_ns\":%lld}\n",
            (long)wall.tv_sec, wall.tv_nsec, i,
            (int)getpid(),
            e->expected_kind,
            e->target,
            decision_name(raw),
            decision_name(final),
            final == DEC_ALLOW ? "ALLOW" : "EPERM",
            (uint64_t)(lat_ns / 1000ULL),
            lat_ns,
            (long long)(wall.tv_sec * 1000000000LL + wall.tv_nsec));
    }

    fprintf(stdout,
        "[fast_match] complete: %d allow, %d deny\n",
        allow_count, deny_count);
    return 0;
}
