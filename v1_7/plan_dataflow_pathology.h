// SPDX-License-Identifier: MIT
/*
 * plan_dataflow_pathology.h — VAREK v1.7.1 flow-axis pathology output.
 *
 * After plan_dataflow_flow_verdict() has run, the dataflow companion
 * holds per-node inbound, outbound, and decision state. This module
 * turns that state into a structured, deterministic record of what
 * suppressed the plan on the flow axis: which nodes were suppressed,
 * which inbound labels triggered the suppression, and which immediate
 * predecessor edges carried those labels into the suppressed node.
 *
 * SCOPE. v1.7.1 pathology covers the FLOW axis only. The v1.6 node
 * axis's per-node suppressions are out of scope and are reported by
 * the v1.6 layer separately. The emitter always names both axis
 * verdicts so a consumer can correlate.
 *
 * DETERMINISM. Nodes are reported in id order; labels in tag order;
 * sources in node-id order. JSON has stable shape and key ordering.
 *
 * IMMEDIATE PREDECESSORS AND ORIGINATORS. For each offending label at
 * a sink, the emitter reports two arrays:
 *   - sources: predecessors whose outbound directly carries the label
 *     (the cut points one hop away from the sink);
 *   - originators (v1.7.4): nodes that originate the label and have a
 *     directed label-carrying path to the sink (the root sources of
 *     the leak).
 * Both are computed from the cached propagation state; no extra
 * traversal of the kernel.
 *
 * NO DYNAMIC ALLOCATION past the caller's buffer. All work is done
 * over fixed-capacity stack arrays and the caller-supplied char buffer
 * or FILE*.
 */

#ifndef VAREK_V1_7_PLAN_DATAFLOW_PATHOLOGY_H
#define VAREK_V1_7_PLAN_DATAFLOW_PATHOLOGY_H

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>      /* ssize_t */

#include "plan_dataflow.h"
#include "plan_label.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Optional rendering options. NULL-safe (defaults apply). */
typedef struct plan_pathology_opts {
    /* Map a label tag to a human-readable name. If NULL, labels are
     * emitted as their numeric tag. Returned string is borrowed by
     * the emitter for the duration of the call. */
    const char *(*label_name)(plan_label_t tag, void *ctx);
    void        *label_name_ctx;
} plan_pathology_opts_t;

/* Emit a JSON pathology record to a caller-supplied buffer. Returns
 * the number of bytes written on success (the content length, NOT
 * counting the NUL terminator). On success the buffer is NUL-
 * terminated (snprintf semantics), so it is safe to use as a C
 * string; the effective content capacity is therefore bufsz - 1.
 * Returns -1 on argument error or if the buffer is too small to hold
 * the full record plus terminator (the buffer contents are then
 * undefined and must be discarded). Verdict must already be computed;
 * if it has not been, the emitter computes it. */
ssize_t plan_dataflow_emit_pathology_buf(plan_dataflow_t *df,
                                         const plan_pathology_opts_t *opts,
                                         char *buf, size_t bufsz);

/* Emit to a FILE*. Returns 0 on success, -1 on I/O or argument
 * error. Uses an internal buffer sized for typical plans
 * (PLAN_MAX_NODES x a few hundred bytes); falls back to -1 if the
 * record exceeds it. */
int plan_dataflow_emit_pathology(plan_dataflow_t *df,
                                 const plan_pathology_opts_t *opts,
                                 FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_7_PLAN_DATAFLOW_PATHOLOGY_H */
