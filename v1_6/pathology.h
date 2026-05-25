// SPDX-License-Identifier: MIT
/*
 * pathology.h — plan-level pathology record emission.
 *
 * Matches the JSON-to-stderr style of the v1.4 Warden's
 * emit_pathology(): single-line, no whitespace, monotonic
 * latency in microseconds, wall-clock report_id. Plan-level
 * records use the "pp-" prefix to distinguish from the v1.4
 * per-action "pr-" prefix.
 *
 * The sink is single-threaded by contract, matching the v1.4
 * Warden's supervisor-thread invariant. The sequence counter is
 * not atomic.
 */

#ifndef VAREK_V1_6_PATHOLOGY_H
#define VAREK_V1_6_PATHOLOGY_H

#include "execution_plan.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Why the plan was suppressed, for operator telemetry. */
typedef enum {
    PATH_REASON_NONE        = 0,   /* plan SATISFIED */
    PATH_REASON_NODE        = 1,   /* a node decision was non-SATISFIED */
    PATH_REASON_CYCLE       = 2,   /* cyclic edge set */
    PATH_REASON_EMPTY       = 3,   /* zero actions in spec */
    PATH_REASON_CAPACITY    = 4,   /* spec exceeded PLAN_MAX_NODES / PLAN_MAX_EDGES */
    PATH_REASON_EDGE_INDEX  = 5,   /* spec edge referenced an invalid node index */
} pathology_reason_t;

const char *pathology_reason_name(pathology_reason_t r);

typedef struct pathology_sink pathology_sink_t;

/* Open a sink writing to fp. The sink does not take ownership of
 * fp and will not close it. Returns NULL on allocation failure. */
pathology_sink_t *pathology_sink_new(FILE *fp);

/* Close the sink. NULL-safe. Does not close the underlying FILE*. */
void pathology_sink_free(pathology_sink_t *sink);

/* Emit a plan-level pathology record.
 *
 * suppressed_label may be NULL; suppressed_decision is the cached
 * per-node decision that triggered suppression, or SATISFIED when
 * none applies. reason classifies the cause for the operator. */
void pathology_emit_plan_decision(pathology_sink_t   *sink,
                                  plan_decision_t     plan_decision,
                                  size_t              n_nodes,
                                  size_t              n_edges,
                                  uint64_t            latency_us,
                                  const char         *suppressed_label,
                                  plan_decision_t     suppressed_decision,
                                  pathology_reason_t  reason);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_6_PATHOLOGY_H */
