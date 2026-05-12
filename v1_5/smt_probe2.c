// SPDX-License-Identifier: MIT
/*
 * smt_probe2.c — context-reuse benchmark for SMT-discharged policy decisions
 *
 * Same encoding as smt_probe.c but with the realistic production pattern:
 * one Z3 context and one solver are created at startup and reused across
 * all decisions via Z3_solver_push / Z3_solver_pop. This measures the
 * per-decision cost as it would be in the Warden's hot path, not the
 * worst-case create-and-tear-down cost from probe v1.
 *
 * Build:    make probe2
 * Run:      ./smt_probe2 [iterations] 2> bench.log
 *           python3 bench_summarize.py bench.log
 *
 * What this measures:
 *   - Per-decision encoding cost (mk_string for input, mk_eq, push/pop)
 *   - SAT check cost
 *   - Result extraction
 *
 * What this does NOT measure (still future work):
 *   - Multi-rule policies
 *   - Pre-compiled rule ASTs (further optimization beyond reuse)
 *   - Integration with the Warden's seccomp-unotify pipeline
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

static const char *RULE_PREFIX = "/tmp/varek_allowed_";

static const char *WORKLOAD[] = {
    "/tmp/varek_allowed_alpha",
    "/tmp/varek_allowed_beta_42",
    "/tmp/varek_allowed_",
    "/etc/shadow",
    "/tmp/varek_other_path",
    "/var/log/syslog",
    "/tmp/varek_allowed",
    "/tmp/varek_allowed_x/sub/file",
    "/usr/bin/env",
    "/proc/self/maps",
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
 * Persistent state set up once at startup and reused across all decisions.
 *
 * Strategy: build the rule's prefix-of constraint AST once; on each decision
 * push a fresh frame, add the input-equality assertion, check, pop.
 *
 * This pattern matches how the Warden would integrate SMT: one context per
 * supervisor process, rules compiled at policy load time, per-action work
 * scoped to push/check/pop.
 */
struct smt_state {
    Z3_context ctx;
    Z3_solver  solver;
    Z3_sort    string_sort;
    Z3_ast     path_var;     /* the action_path String constant */
    Z3_ast     prefixof_ast; /* str.prefixof(<rule>, action_path) */
};

static void smt_state_init(struct smt_state *s, const char *rule_prefix) {
    Z3_config cfg = Z3_mk_config();
    Z3_set_param_value(cfg, "model", "false");
    s->ctx = Z3_mk_context(cfg);
    Z3_del_config(cfg);

    s->string_sort = Z3_mk_string_sort(s->ctx);
    Z3_symbol path_sym = Z3_mk_string_symbol(s->ctx, "action_path");
    s->path_var = Z3_mk_const(s->ctx, path_sym, s->string_sort);

    Z3_ast prefix_str = Z3_mk_string(s->ctx, rule_prefix);
    s->prefixof_ast = Z3_mk_seq_prefix(s->ctx, prefix_str, s->path_var);

    s->solver = Z3_mk_solver(s->ctx);
    Z3_solver_inc_ref(s->ctx, s->solver);

    /* The rule constraint is a permanent assertion. */
    Z3_solver_assert(s->ctx, s->solver, s->prefixof_ast);
}

static void smt_state_destroy(struct smt_state *s) {
    Z3_solver_dec_ref(s->ctx, s->solver);
    Z3_del_context(s->ctx);
}

/*
 * Per-decision: push a fresh frame, assert path equality, check, pop.
 * Pop discards the per-call assertion; the rule assertion stays live.
 */
static decision_t smt_decide(struct smt_state *s, const char *action_path) {
    Z3_solver_push(s->ctx, s->solver);

    Z3_ast input_str = Z3_mk_string(s->ctx, action_path);
    Z3_ast eq_input  = Z3_mk_eq(s->ctx, s->path_var, input_str);
    Z3_solver_assert(s->ctx, s->solver, eq_input);

    Z3_lbool result = Z3_solver_check(s->ctx, s->solver);

    Z3_solver_pop(s->ctx, s->solver, 1);

    switch (result) {
        case Z3_L_TRUE:  return DEC_ALLOW;
        case Z3_L_FALSE: return DEC_DENY;
        default:         return DEC_UNKNOWN;
    }
}

static decision_t suppress(decision_t d) {
    return (d == DEC_ALLOW) ? DEC_ALLOW : DEC_DENY;
}

int main(int argc, char **argv) {
    int iter = (argc >= 2) ? atoi(argv[1]) : DEFAULT_ITER;
    if (iter <= 0) iter = DEFAULT_ITER;

    fprintf(stderr,
        "[smt_probe2] context-reuse mode  rule_prefix=%s  iter=%d  workload=%zu\n",
        RULE_PREFIX, iter, WORKLOAD_N);
    {
        unsigned major, minor, build, rev;
        Z3_get_version(&major, &minor, &build, &rev);
        fprintf(stderr, "[smt_probe2] Z3 version: %u.%u.%u (build %u)\n",
                major, minor, build, rev);
    }
    fflush(stderr);

    struct smt_state state;
    smt_state_init(&state, RULE_PREFIX);

    /* Warmup: amortize first-call solver-init cost. */
    for (size_t w = 0; w < WORKLOAD_N; w++) {
        (void)smt_decide(&state, WORKLOAD[w]);
    }

    int allow_count = 0, deny_count = 0, unknown_count = 0;

    for (int i = 0; i < iter; i++) {
        const char *input = WORKLOAD[i % WORKLOAD_N];

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        decision_t raw   = smt_decide(&state, input);
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
            "{\"report_id\":\"smt2-%ld.%09ld-%d\","
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

    smt_state_destroy(&state);

    fprintf(stdout,
        "[smt_probe2] complete: %d allow, %d deny, %d unknown\n",
        allow_count, deny_count, unknown_count);
    return 0;
}
