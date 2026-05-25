// SPDX-License-Identifier: MIT
/*
 * plan_parser.h — text-format plan file parser.
 *
 * Reads a plan declaration file into an owning plan_parsed_t handle
 * that exposes a plan_spec_t view. Plans are loaded once at startup
 * and the parsed result lives until plan_parser_free().
 *
 * File format (line-oriented, # comments, blank lines ignored):
 *
 *   action <label> <kind> <target>
 *   edge   <from_label> <to_label>
 *
 *   - <label> is a unique identifier matching [A-Za-z_][A-Za-z0-9_-]{0,63}.
 *   - <kind> is a free-form token; the decider interprets it
 *     (typical values match the v1.4 Warden: "file_open",
 *     "net_connect", "process_exec").
 *   - <target> is a single token. Paths, hosts, and exec strings
 *     are supported as long as they contain no whitespace.
 *   - <from_label> / <to_label> must reference action lines already
 *     declared above the edge line.
 *
 * The parser does not validate the kind string against any
 * particular set; that is the decider's job. Acyclicity is checked
 * during exec_plan_verify(), not at parse time.
 */

#ifndef VAREK_V1_6_PLAN_PARSER_H
#define VAREK_V1_6_PLAN_PARSER_H

#include "plan_spec.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAN_PARSE_ERR_BUF_MIN 256u

typedef struct plan_parsed plan_parsed_t;

/* Load and parse a plan file.
 *
 * On success returns a non-NULL handle; the caller frees with
 * plan_parser_free(). On failure returns NULL and writes a
 * human-readable error message into err_buf (truncated at
 * err_buf_len-1; err_buf must be at least PLAN_PARSE_ERR_BUF_MIN
 * bytes for sensible messages).
 *
 * Errors include: file unreadable, malformed line, unknown
 * directive, duplicate action label, edge references undefined
 * label, action/edge count exceeded. */
plan_parsed_t *plan_parser_load(const char *path,
                                char       *err_buf,
                                size_t      err_buf_len);

/* Borrow the parsed spec. Pointer is valid until plan_parser_free()
 * is called on the parent handle. Returns NULL on a NULL handle. */
const plan_spec_t *plan_parser_spec(const plan_parsed_t *parsed);

/* Number of actions / edges that were parsed (introspection). */
size_t plan_parser_action_count(const plan_parsed_t *parsed);
size_t plan_parser_edge_count  (const plan_parsed_t *parsed);

/* Release all storage owned by the handle. NULL-safe. */
void plan_parser_free(plan_parsed_t *parsed);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_6_PLAN_PARSER_H */
