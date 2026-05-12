// SPDX-License-Identifier: MIT
/*
 * smt_probe.c — feasibility benchmark for SMT-discharged policy decisions
 *
 * Goal: measure end-to-end latency of a single SMT decision using Z3's
 *       string theory, to determine whether the architecture can support
 *       SMT-based policy_decide() within the deck's stated latency budget.
 *
 * Encoding under test:
 *
 *     (declare-const action_path String)
 *     (assert (= action_path "<input>"))
 *     (assert (str.prefixof "<rule_prefix>" action_path))
 *     (check-sat)
 *
 *   sat   → ALLOW   (action satisfies the policy rule)
 *   unsat → DENY    (action does not satisfy)
 *   unkn  → UNKNOWN (suppressed to DENY by symmetric-suppression invariant)
 *
 * Each iteration:
 *   - Picks an input from a varied workload (matching, non-matching, edge case)
 *   - Builds Z3 AST from scratch (worst-case; no caching)
 *   - Calls Z3_solver_check
 *   - Records CLOCK_MONOTONIC latency in microseconds
 *   - Emits a JSON pathology record compatible with bench_summarize.py
 *
 * NOT under test (deferred to later slices):
 *   - Multi-rule policies (disjunction, ordering, first-match-wins)
 *   - Caching of compiled assertions or solver state
 *   - Integration with the Warden's hot path
 *   - Bitvector encoding (if string theory turns out to be too slow)
 *
 * Build:    make
 * Run:      ./smt_probe [iterations]   2> bench.log
 *           python3 bench_summarize.py bench.log
 *
 * Requires: libz3-dev (Z3 C API), Linux >= 5.14, Ubuntu 24.04 or similar.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <z3.h>

#define DEFAULT_ITER 10000

/* The single rule under test. Policy says: action_path must have this prefix. */
static const char *RULE_PREFIX = "/tmp/varek_allowed_";

/* Workload: a mix of inputs that exercise ALLOW, DENY, and edge cases.
 * This is not adversarial, just varied — a benchmark of the encoding cost,
 * not of policy expressiveness. */
static const char *WORKLOAD[] = {
    "/tmp/varek_allowed_alpha",       /* ALLOW: matches prefix exactly */
    "/tmp/varek_allowed_beta_42",     /* ALLOW: longer suffix */
    "/tmp/varek_allowed_",            /* ALLOW: minimum match */
    "/etc/shadow",                    /* DENY:  no match */
    "/tmp/varek_other_path",          /* DENY:  partial overlap with prefix */
    "/var/log/syslog",                /* DENY:  unrelated */
    "/tmp/varek_allowed",             /* DENY:  missing trailing underscore */
    "/tmp/varek_allowed_x/sub/file",  /* ALLOW: prefix + nested path */
    "/usr/bin/env",                   /* DENY:  unrelated */
    "/proc/self/maps",                /* DENY:  unrelated */
};
static const size_t WORKLOAD_N = sizeof(WORKLOAD) / sizeof(WORKLOAD[0]);

typedef enum { DEC_ALLOW, DEC_DENY, DEC_UNKNOWN } decision_t;

static const char *decision_name(decision_t d) {
    switch (d) {
        case DEC_ALLOW:   return "ALLOW";
        case DEC_DENY:    return "DENY";
        case DEC_UNKNOWN: return "UNKNOWN";
    }
    return "INVALID";
}

/*
 * Build the Z3 AST and check satisfiability.
 *
 * One context per call (worst case; no reuse). This measures the floor cost
 * of a single decision with zero caching. Real production code would reuse
 * the context across many decisions, which should be strictly faster.
 */
static decision_t smt_decide(const char *action_path, const char *rule_prefix) {
    Z3_config  cfg = Z3_mk_config();
    Z3_set_param_value(cfg, "model", "false");      /* we only need sat/unsat */
    Z3_context ctx = Z3_mk_context(cfg);
    Z3_del_config(cfg);

    Z3_sort   string_sort   = Z3_mk_string_sort(ctx);
    Z3_symbol path_sym      = Z3_mk_string_symbol(ctx, "action_path");
    Z3_ast    path_var      = Z3_mk_const(ctx, path_sym, string_sort);

    /* assert: action_path == "<input>"  */
    Z3_ast    input_str     = Z3_mk_string(ctx, action_path);
    Z3_ast    eq_input      = Z3_mk_eq(ctx, path_var, input_str);

    /* assert: str.prefixof "<rule_prefix>" action_path */
    Z3_ast    prefix_str    = Z3_mk_string(ctx, rule_prefix);
    Z3_ast    prefixof      = Z3_mk_seq_prefix(ctx, prefix_str, path_var);

    Z3_solver solver = Z3_mk_solver(ctx);
    Z3_solver_inc_ref(ctx, solver);

    Z3_solver_assert(ctx, solver, eq_input);
    Z3_solver_assert(ctx, solver, prefixof);

    Z3_lbool result = Z3_solver_check(ctx, solver);

    Z3_solver_dec_ref(ctx, solver);
    Z3_del_context(ctx);

    switch (result) {
        case Z3_L_TRUE:  return DEC_ALLOW;    /* sat   → action matches rule */
        case Z3_L_FALSE: return DEC_DENY;     /* unsat → action does not match */
        default:         return DEC_UNKNOWN;  /* unkn  → suppressed by caller */
    }
}

/* Apply symmetric suppression: UNKNOWN collapses to DENY at the boundary. */
static decision_t suppress(decision_t d) {
    return (d == DEC_ALLOW) ? DEC_ALLOW : DEC_DENY;
}

int main(int argc, char **argv) {
    int iter = (argc >= 2) ? atoi(argv[1]) : DEFAULT_ITER;
    if (iter <= 0) iter = DEFAULT_ITER;

    fprintf(stderr,
        "[smt_probe] rule_prefix=%s  iterations=%d  workload_size=%zu\n",
        RULE_PREFIX, iter, WORKLOAD_N);
    fprintf(stderr, "[smt_probe] Z3 version: ");
    {
        unsigned major, minor, build, rev;
        Z3_get_version(&major, &minor, &build, &rev);
        fprintf(stderr, "%u.%u.%u (build %u)\n", major, minor, build, rev);
    }
    fflush(stderr);

    /* Warmup: Z3's first call pays library-init cost we don't want to count. */
    (void)smt_decide("/warmup", RULE_PREFIX);
    (void)smt_decide("/tmp/varek_allowed_warmup", RULE_PREFIX);

    int allow_count = 0, deny_count = 0, unknown_count = 0;

    for (int i = 0; i < iter; i++) {
        const char *input = WORKLOAD[i % WORKLOAD_N];

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        decision_t raw = smt_decide(input, RULE_PREFIX);
        decision_t final = suppress(raw);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        uint64_t lat_ns = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                       + (t1.tv_nsec - t0.tv_nsec);

        switch (final) {
            case DEC_ALLOW:   allow_count++; break;
            case DEC_DENY:    deny_count++; break;
            case DEC_UNKNOWN: unknown_count++; break;
        }

        struct timespec wall;
        clock_gettime(CLOCK_REALTIME, &wall);
        fprintf(stderr,
            "{\"report_id\":\"smt-%ld.%09ld-%d\","
            "\"agent_pid\":%d,"
            "\"action\":\"smt.policy_decide\","
            "\"target\":\"%s\","
            "\"decision_raw\":\"%s\","
            "\"decision_final\":\"%s\","
            "\"rule\":\"prefixof:%s\","
            "\"kernel_verdict\":\"%s\","
            "\"latency_us\":%" PRIu64 ","
            "\"timestamp_ns\":%lld}\n",
            (long)wall.tv_sec, wall.tv_nsec, i,
            (int)getpid(),
            input,
            decision_name(raw),
            decision_name(final),
            RULE_PREFIX,
            final == DEC_ALLOW ? "ALLOW" : "EPERM",
            (uint64_t)(lat_ns / 1000ULL),
            (long long)(wall.tv_sec * 1000000000LL + wall.tv_nsec));
    }
    fflush(stderr);

    fprintf(stdout,
        "[smt_probe] complete: %d allow, %d deny, %d unknown (suppressed)\n",
        allow_count, deny_count, unknown_count);
    fprintf(stdout,
        "[smt_probe] see stderr / log for pathology records\n");
    return 0;
}
