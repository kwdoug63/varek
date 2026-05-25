// SPDX-License-Identifier: MIT
/*
 * pathology.c — plan-level pathology record emission.
 */

#define _POSIX_C_SOURCE 200809L

#include "pathology.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct pathology_sink {
    FILE    *fp;
    uint64_t seq;
};

const char *pathology_reason_name(pathology_reason_t r)
{
    switch (r) {
        case PATH_REASON_NONE:       return "none";
        case PATH_REASON_NODE:       return "node";
        case PATH_REASON_CYCLE:      return "cycle";
        case PATH_REASON_EMPTY:      return "empty";
        case PATH_REASON_CAPACITY:   return "capacity";
        case PATH_REASON_EDGE_INDEX: return "edge_index";
    }
    return "invalid";
}

pathology_sink_t *pathology_sink_new(FILE *fp)
{
    if (!fp) return NULL;
    pathology_sink_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->fp  = fp;
    s->seq = 0;
    return s;
}

void pathology_sink_free(pathology_sink_t *sink)
{
    free(sink);
}

/* Emit a JSON-safe representation of s wrapped in quotes. Handles
 * the JSON minimum-escape set: \, ", and control characters below
 * 0x20. Bytes >= 0x20 pass through (valid UTF-8 strings remain
 * valid JSON strings without further escaping). */
static void emit_json_string(FILE *fp, const char *s)
{
    fputc('"', fp);
    if (!s) { fputc('"', fp); return; }
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '"':  fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\b': fputs("\\b",  fp); break;
            case '\f': fputs("\\f",  fp); break;
            case '\n': fputs("\\n",  fp); break;
            case '\r': fputs("\\r",  fp); break;
            case '\t': fputs("\\t",  fp); break;
            default:
                if (c < 0x20) {
                    fprintf(fp, "\\u%04x", (unsigned)c);
                } else {
                    fputc((int)c, fp);
                }
                break;
        }
    }
    fputc('"', fp);
}

void pathology_emit_plan_decision(pathology_sink_t   *sink,
                                  plan_decision_t     plan_decision,
                                  size_t              n_nodes,
                                  size_t              n_edges,
                                  uint64_t            latency_us,
                                  const char         *suppressed_label,
                                  plan_decision_t     suppressed_decision,
                                  pathology_reason_t  reason)
{
    if (!sink || !sink->fp) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    bool authorized = (plan_decision == PLAN_DEC_SATISFIED);

    fprintf(sink->fp,
        "{\"report_id\":\"pp-%ld.%09ld-%" PRIu64 "\","
        "\"type\":\"plan_verify\","
        "\"decision\":\"%s\","
        "\"authorized\":%s,"
        "\"n_nodes\":%zu,"
        "\"n_edges\":%zu,"
        "\"latency_us\":%" PRIu64 ","
        "\"suppression_reason\":\"%s\","
        "\"suppressed_node\":",
        (long)ts.tv_sec, ts.tv_nsec, sink->seq,
        plan_decision_name(plan_decision),
        authorized ? "true" : "false",
        n_nodes,
        n_edges,
        latency_us,
        pathology_reason_name(reason));

    if (suppressed_label) {
        emit_json_string(sink->fp, suppressed_label);
    } else {
        fputs("null", sink->fp);
    }

    fprintf(sink->fp,
        ",\"suppressed_decision\":\"%s\","
        "\"timestamp_ns\":%lld}\n",
        plan_decision_name(suppressed_decision),
        (long long)((long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec));

    fflush(sink->fp);
    sink->seq++;
}
