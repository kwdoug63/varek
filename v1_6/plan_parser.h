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
 *   action <label> <kind> <target> [<key>=<value> ...]
 *   edge   <from_label> <to_label>
 *
 *   - <label> is a unique identifier matching [A-Za-z_][A-Za-z0-9_-]{0,63}.
 *   - <kind> is a free-form token; the decider interprets it
 *     (typical values match the v1.4 Warden: "file_open",
 *     "net_connect", "process_exec").
 *   - <target> is a single token. Paths, hosts, and exec strings
 *     are supported as long as they contain no whitespace.
 *   - v1.20.0: fields. After the target an action may carry up to 16
 *     fields, key=value, so a step can declare more than its target (a
 *     request's body or headers, say). A key is [a-z][a-z0-9_]*, at most
 *     32 characters, unique within the action, and not "target". A value
 *     is either bare (up to the next space or tab; no '"' or control
 *     character) or quoted: "..." with the escapes \" \\ \n \r \t and
 *     \xHH (not \x00); a raw control character other than tab is an
 *     error. A value is at most 4096 bytes after decoding, a target at
 *     most 4095 bytes, and a line at most 16383 bytes (not counting its
 *     newline; it was 1022 through v1.19.0). A NUL byte refuses the file. Fields are what the agent DECLARES, like the rest
 *     of the plan; nothing checks the agent's later traffic against them.
 *     plan_parser_fields() returns them; plan_spec_action_t is unchanged.
 *     v1.21.1: the Warden's node check reads one field, a file_open
 *     step's `open` (open=read, or an access mode then O_ flags joined
 *     by '|'), and decides the step with those open flags.
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

/* v1.20.0: the fields declared on action 'action_idx', in file order, and
 * their count in *n_out. NULL (and 0) when it has none or the index is out
 * of range. Valid until plan_parser_free(). */
const plan_spec_field_t *plan_parser_fields(const plan_parsed_t *parsed, size_t action_idx,
                                            size_t *n_out);

/* Release all storage owned by the handle. NULL-safe. */
void plan_parser_free(plan_parsed_t *parsed);

#ifdef __cplusplus
}
#endif

#endif /* VAREK_V1_6_PLAN_PARSER_H */
