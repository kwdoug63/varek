// SPDX-License-Identifier: MIT
/*
 * plan_dataflow_pathology.c — VAREK v1.7.1 deterministic JSON
 * pathology over flow-axis state.
 *
 * Dependency-free. Hand-written JSON writer streaming into a caller
 * buffer (or a stack buffer routed to FILE*).
 */

#include "plan_dataflow_pathology.h"
#include "plan_dataflow.h"
#include "plan_label.h"
#include "execution_plan.h"
#include "v1_6_compat.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ---------- Internal: bounded buffer writer ---------- */

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    bool   ovf;
} bw_t;

static void bw_init(bw_t *w, char *buf, size_t cap)
{
    w->buf = buf; w->cap = cap; w->len = 0; w->ovf = false;
}

static void bw_putc(bw_t *w, char c)
{
    if (w->ovf) return;
    if (w->len >= w->cap) { w->ovf = true; return; }
    w->buf[w->len++] = c;
}

static void bw_puts(bw_t *w, const char *s)
{
    while (*s) bw_putc(w, *s++);
}

static void bw_putu(bw_t *w, unsigned long long v)
{
    char tmp[32]; int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n--) bw_putc(w, tmp[n]);
}

/* JSON string emission with the small set of escapes the spec
 * requires. Labels in plan node strings are typically ASCII
 * identifiers in this codebase; the conservative escape set covers
 * the rest safely. */
static void bw_putstr(bw_t *w, const char *s)
{
    bw_putc(w, '"');
    if (!s) { bw_puts(w, "null"); bw_putc(w, '"'); return; }
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  bw_puts(w, "\\\""); break;
            case '\\': bw_puts(w, "\\\\"); break;
            case '\b': bw_puts(w, "\\b");  break;
            case '\f': bw_puts(w, "\\f");  break;
            case '\n': bw_puts(w, "\\n");  break;
            case '\r': bw_puts(w, "\\r");  break;
            case '\t': bw_puts(w, "\\t");  break;
            default:
                if (c < 0x20) {
                    char hex[7];
                    snprintf(hex, sizeof hex, "\\u%04x", c);
                    bw_puts(w, hex);
                } else {
                    bw_putc(w, (char)c);
                }
        }
    }
    bw_putc(w, '"');
}

/* ---------- Decision rendering ---------- */

static const char *dec_name(plan_decision_t d)
{
    switch (d) {
        case PLAN_DEC_SATISFIED:   return "SATISFIED";
        case PLAN_DEC_UNSATISFIED: return "UNSATISFIED";
        case PLAN_DEC_UNKNOWN:     return "UNKNOWN";
    }
    return "INVALID";
}

/* ---------- Label emission ---------- */

static void emit_label(bw_t *w, plan_label_t t,
                       const plan_pathology_opts_t *opts)
{
    if (opts && opts->label_name) {
        const char *name = opts->label_name(t, opts->label_name_ctx);
        if (name) {
            bw_putstr(w, name);
            return;
        }
    }
    /* Fallback: numeric. */
    bw_putc(w, '"');
    bw_putu(w, (unsigned long long)t);
    bw_putc(w, '"');
}

/* ---------- Suppression analysis ---------- */

/* Per-node finalized inbound, outbound, and decision are cached on
 * the companion after flow_verdict(). For a suppressed node we
 * compute:
 *   - deny_hits      = inbound & deny_in       (UNSAT contributors)
 *   - unknown_hits   = inbound & unknown_in    (UNKNOWN contributors)
 *   - sticky_unclass = (inbound & sticky) \ (deny|unknown|permit)
 *                                              (UNKNOWN fail-safe)
 * For each offending label, the immediate predecessor edges that
 * carry it are p such that an edge p->n exists and outbound[p]
 * contains the label. */

/* Sources: predecessors of 'n' whose outbound carries 'label'. */
static void emit_sources_for_label(bw_t *w, plan_dataflow_t *df,
                                   plan_node_id_t n, plan_label_t label,
                                   const plan_pathology_opts_t *opts)
{
    const exec_plan_t *plan = plan_dataflow_get_plan(df);
    const size_t m = exec_plan_edge_count(plan);

    bw_putc(w, '[');
    bool first = true;
    for (size_t e = 0; e < m; e++) {
        plan_node_id_t from, to;
        if (dataflow_plan_get_edge(plan, e, &from, &to) != 0) continue;
        if (to != n) continue;

        plan_label_set_t outb;
        if (plan_dataflow_node_outbound(df, from, &outb) != 0) continue;
        if (!plan_label_set_test(&outb, label)) continue;

        if (!first) bw_putc(w, ',');
        first = false;
        bw_putc(w, '{');
        bw_putstr(w, "from"); bw_putc(w, ':');
        bw_putu(w, (unsigned long long)from);
        bw_putc(w, ',');
        bw_putstr(w, "from_label"); bw_putc(w, ':');
        bw_putstr(w, dataflow_plan_get_node_label(plan, from));
        bw_putc(w, ',');
        bw_putstr(w, "label"); bw_putc(w, ':');
        emit_label(w, label, opts);
        bw_putc(w, '}');
    }
    bw_putc(w, ']');
}

/* Lineage (v1.7.4): originators are nodes whose origin set contains
 * 'label' AND which have a directed path to 'sink' along which every
 * node's outbound carries 'label'. Computed by backward BFS from sink
 * through predecessors whose outbound carries the label. The sink
 * itself is never reported as its own originator (a sink's own origin
 * is irrelevant — v1.7 polices inbound, not origin, at a node).
 *
 * Output is in node-id ascending order for determinism. */
static void emit_originators_for_label(bw_t *w, plan_dataflow_t *df,
                                       plan_node_id_t sink,
                                       plan_label_t label,
                                       const plan_pathology_opts_t *opts)
{
    const exec_plan_t *plan = plan_dataflow_get_plan(df);
    const size_t n = exec_plan_node_count(plan);
    const size_t m = exec_plan_edge_count(plan);

    bool visited[PLAN_MAX_NODES] = {false};
    plan_node_id_t queue[PLAN_MAX_NODES];
    bool is_orig[PLAN_MAX_NODES] = {false};
    size_t qh = 0, qt = 0;

    if (sink >= n) { bw_putc(w, '['); bw_putc(w, ']'); return; }
    visited[sink] = true;
    queue[qt++] = sink;

    while (qh < qt) {
        plan_node_id_t u = queue[qh++];

        /* If u (other than the sink) originates the label, it's a
         * lineage source. */
        if (u != sink) {
            plan_label_set_t origin;
            if (plan_dataflow_node_origin(df, u, &origin) == 0 &&
                plan_label_set_test(&origin, label)) {
                is_orig[u] = true;
            }
        }

        /* Walk predecessors p of u where outbound[p] carries label. */
        for (size_t e = 0; e < m; e++) {
            plan_node_id_t from, to;
            if (dataflow_plan_get_edge(plan, e, &from, &to) != 0) continue;
            if (to != u) continue;
            if (from >= n || visited[from]) continue;
            plan_label_set_t outb;
            if (plan_dataflow_node_outbound(df, from, &outb) != 0) continue;
            if (!plan_label_set_test(&outb, label)) continue;
            visited[from] = true;
            queue[qt++] = from;
        }
    }

    bw_putc(w, '[');
    bool first = true;
    for (size_t i = 0; i < n; i++) {
        if (!is_orig[i]) continue;
        if (!first) bw_putc(w, ',');
        first = false;
        bw_putc(w, '{');
        bw_putstr(w, "node"); bw_putc(w, ':');
        bw_putu(w, (unsigned long long)i);
        bw_putc(w, ',');
        bw_putstr(w, "node_label"); bw_putc(w, ':');
        bw_putstr(w, dataflow_plan_get_node_label(plan, (plan_node_id_t)i));
        bw_putc(w, ',');
        bw_putstr(w, "label"); bw_putc(w, ':');
        emit_label(w, label, opts);
        bw_putc(w, '}');
    }
    bw_putc(w, ']');
}

/* Emit one offending-label group: kind, labels[], sources[].
 * 'set' is the label set for this kind (deny / unknown / sticky_unclass).
 * Sources are unioned over every offending label in the set, so the
 * consumer sees "node X was suppressed; here are the offending labels
 * and the edges that brought them." */
static void emit_offense_group(bw_t *w, plan_dataflow_t *df,
                               plan_node_id_t n,
                               const plan_label_set_t *set,
                               const char *kind,
                               const plan_pathology_opts_t *opts)
{
    if (plan_label_set_empty(set)) return;

    bw_putc(w, '{');
    bw_putstr(w, "kind"); bw_putc(w, ':'); bw_putstr(w, kind);

    /* Labels. */
    bw_putc(w, ',');
    bw_putstr(w, "labels"); bw_putc(w, ':'); bw_putc(w, '[');
    bool first_label = true;
    for (plan_label_t t = 0; t < PLAN_MAX_LABELS; t++) {
        if (!plan_label_set_test(set, t)) continue;
        if (!first_label) bw_putc(w, ',');
        first_label = false;
        emit_label(w, t, opts);
    }
    bw_putc(w, ']');

    /* Sources: array per label. */
    bw_putc(w, ',');
    bw_putstr(w, "sources"); bw_putc(w, ':'); bw_putc(w, '[');
    bool first_src_label = true;
    for (plan_label_t t = 0; t < PLAN_MAX_LABELS; t++) {
        if (!plan_label_set_test(set, t)) continue;
        if (!first_src_label) bw_putc(w, ',');
        first_src_label = false;
        emit_sources_for_label(w, df, n, t, opts);
    }
    bw_putc(w, ']');

    /* Originators (v1.7.4): array per label, parallel to sources. */
    bw_putc(w, ',');
    bw_putstr(w, "originators"); bw_putc(w, ':'); bw_putc(w, '[');
    bool first_orig_label = true;
    for (plan_label_t t = 0; t < PLAN_MAX_LABELS; t++) {
        if (!plan_label_set_test(set, t)) continue;
        if (!first_orig_label) bw_putc(w, ',');
        first_orig_label = false;
        emit_originators_for_label(w, df, n, t, opts);
    }
    bw_putc(w, ']');

    bw_putc(w, '}');
}

/* ---------- Emitter ---------- */

ssize_t plan_dataflow_emit_pathology_buf(plan_dataflow_t *df,
                                         const plan_pathology_opts_t *opts,
                                         char *buf, size_t bufsz)
{
    if (!df || !buf || bufsz == 0)
        return -1;

    /* Force verdict computation if not done. */
    plan_decision_t flow = plan_dataflow_flow_verdict(df);
    const exec_plan_t *plan = plan_dataflow_get_plan(df);
    plan_decision_t node = exec_plan_verify(plan);
    plan_decision_t total = plan_decision_join(node, flow);

    /* Reserve one byte for a NUL terminator so the buffer is always a
     * valid C string on success (snprintf semantics). The returned
     * length excludes the NUL; the FILE* wrapper and length-based
     * callers are unaffected. This removes the printf("%s", buf)
     * footgun. */
    bw_t w; bw_init(&w, buf, bufsz - 1);

    bw_putc(&w, '{');
    bw_putstr(&w, "verdict");   bw_putc(&w, ':'); bw_putstr(&w, dec_name(total));
    bw_putc(&w, ',');
    bw_putstr(&w, "node_axis"); bw_putc(&w, ':'); bw_putstr(&w, dec_name(node));
    bw_putc(&w, ',');
    bw_putstr(&w, "flow_axis"); bw_putc(&w, ':'); bw_putstr(&w, dec_name(flow));

    /* Suppressions array: per-node, in id order. */
    bw_putc(&w, ',');
    bw_putstr(&w, "suppressions"); bw_putc(&w, ':'); bw_putc(&w, '[');

    plan_label_set_t sticky;
    plan_dataflow_sticky(df, &sticky);

    const size_t n = exec_plan_node_count(plan);
    bool first_node = true;
    for (size_t i = 0; i < n; i++) {
        plan_node_id_t node_id = (plan_node_id_t)i;
        plan_decision_t d = plan_dataflow_node_decision(df, node_id);
        if (d == PLAN_DEC_SATISFIED) continue;

        plan_label_set_t inbound, deny_in, unknown_in, permit_in;
        if (plan_dataflow_node_inbound(df, node_id, &inbound)   != 0) continue;
        if (plan_dataflow_node_deny_in(df, node_id, &deny_in)   != 0) continue;
        if (plan_dataflow_node_unknown_in(df, node_id, &unknown_in) != 0) continue;
        if (plan_dataflow_node_permit_in(df, node_id, &permit_in)   != 0) continue;

        /* Compute the three offense sets. */
        plan_label_set_t deny_hits, unknown_hits, sticky_unclass, classified;
        plan_label_set_clear(&deny_hits);
        plan_label_set_clear(&unknown_hits);
        plan_label_set_clear(&sticky_unclass);
        plan_label_set_clear(&classified);
        for (size_t k = 0; k < PLAN_LABEL_WORDS; k++) {
            deny_hits.bits[k]      = inbound.bits[k] & deny_in.bits[k];
            unknown_hits.bits[k]   = inbound.bits[k] & unknown_in.bits[k];
            classified.bits[k]     = deny_in.bits[k] | unknown_in.bits[k] | permit_in.bits[k];
            sticky_unclass.bits[k] = (inbound.bits[k] & sticky.bits[k]) & ~classified.bits[k];
        }

        if (!first_node) bw_putc(&w, ',');
        first_node = false;

        bw_putc(&w, '{');
        bw_putstr(&w, "node"); bw_putc(&w, ':');
        bw_putu(&w, (unsigned long long)node_id);
        bw_putc(&w, ',');
        bw_putstr(&w, "node_label"); bw_putc(&w, ':');
        bw_putstr(&w, dataflow_plan_get_node_label(plan, node_id));
        bw_putc(&w, ',');
        bw_putstr(&w, "decision"); bw_putc(&w, ':');
        bw_putstr(&w, dec_name(d));
        bw_putc(&w, ',');
        bw_putstr(&w, "offenses"); bw_putc(&w, ':'); bw_putc(&w, '[');

        bool inner_first = true;
        /* deny first (it dominates the lattice) */
        if (!plan_label_set_empty(&deny_hits)) {
            if (!inner_first) bw_putc(&w, ',');
            inner_first = false;
            emit_offense_group(&w, df, node_id, &deny_hits, "deny_in", opts);
        }
        if (!plan_label_set_empty(&unknown_hits)) {
            if (!inner_first) bw_putc(&w, ',');
            inner_first = false;
            emit_offense_group(&w, df, node_id, &unknown_hits, "unknown_in", opts);
        }
        if (!plan_label_set_empty(&sticky_unclass)) {
            if (!inner_first) bw_putc(&w, ',');
            inner_first = false;
            emit_offense_group(&w, df, node_id, &sticky_unclass, "sticky_unclassified", opts);
        }

        bw_putc(&w, ']');
        bw_putc(&w, '}');
    }

    bw_putc(&w, ']');
    bw_putc(&w, '}');

    if (w.ovf) return -1;
    buf[w.len] = '\0';   /* always room: capacity was bufsz - 1 */
    return (ssize_t)w.len;
}

int plan_dataflow_emit_pathology(plan_dataflow_t *df,
                                 const plan_pathology_opts_t *opts,
                                 FILE *out)
{
    if (!df || !out) return -1;

    /* Stack buffer sized for typical plans. PLAN_MAX_NODES=1024;
     * worst case a few hundred bytes per suppression; cap at 256 KB. */
    enum { BUFSZ = 256 * 1024 };
    static __thread char stack_buf[BUFSZ];

    ssize_t n = plan_dataflow_emit_pathology_buf(df, opts, stack_buf, BUFSZ);
    if (n < 0) return -1;
    if (fwrite(stack_buf, 1, (size_t)n, out) != (size_t)n) return -1;
    return 0;
}
