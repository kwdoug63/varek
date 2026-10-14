// SPDX-License-Identifier: MIT
// mcp_json.h — v1.31 (docs/security/v1.31-standards.md, section 3): what an
// MCP call over HTTP asks for, read from the request body the server will act
// on, by a strict JSON parser (warden-proxy links it; the Warden never parses
// a body).
//
// The body must be one JSON-RPC 2.0 request or notification:
//   - JSON as RFC 8259 defines it, with nothing extra: UTF-8 only (no
//     overlong forms, surrogates or code points past U+10FFFF), no byte-order
//     mark, no comments, no trailing commas, no leading zeros, strings
//     without raw control characters and with each \u escape a whole
//     character (a surrogate pair together, never a lone half);
//   - no object holds the same member name twice, at any depth (a server
//     that reads the last of two "method"s would act on another call than the
//     one decided); names are compared after their escapes are decoded;
//   - nesting at most MJ_MAX_DEPTH deep, strings at most MJ_MAX_STR bytes;
//   - an object (a batch, an array, is refused), with "jsonrpc": "2.0", a
//     string "method", an "id" that is a string or a number (absent: a
//     notification; null, or anything else, refused), and "params", if
//     present, an object. In params, "name" and "uri", if present, are
//     strings, and not both (the name the call is decided on is the one the
//     server acts on); "_meta"."traceparent", if a string, is reported.
// Every value is checked whether or not it is used.

#ifndef VAREK_MCP_JSON_H
#define VAREK_MCP_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MJ_MAX_DEPTH  64
#define MJ_MAX_STR    (1u << 20)
#define MJ_METHOD_MAX 256
#define MJ_NAME_MAX   4096
#define MJ_ID_MAX     160
#define MJ_TP_MAX     64

typedef struct {
    char   method[MJ_METHOD_MAX];   /* decoded; NUL-terminated (refused if longer, or if it holds a NUL) */
    char   name[MJ_NAME_MAX];       /* params.name or params.uri, decoded ("" with has_name false: neither) */
    bool   has_name;
    bool   notification;            /* no "id" */
    char   id[MJ_ID_MAX];           /* the id's JSON text as written (a string with its quotes, or a number) */
    char   traceparent[MJ_TP_MAX];  /* params._meta.traceparent, if a string of 1 to 63 bytes 0x21-0x7e */
} mj_call_t;

/* Read the call in body[0, n). 0, or -1 with the reason in why (a short
 * phrase, printable ASCII). */
int mj_call(const uint8_t *body, size_t n, mj_call_t *out, char *why, size_t wn);

/* v1.31 step 5: a bearer token's claims, read without checking its
 * signature (what they say can only refuse a call) */
#define MJ_AUD_MAX 8
#define MJ_AUD_LEN 512
typedef struct {
    uint32_t naud;                  /* the audiences read ("aud" a string: 1) */
    bool     aud_over;              /* more than MJ_AUD_MAX, one of MJ_AUD_LEN bytes or more, or not a string */
    size_t   signing_len;           /* v1.31 review: the length of header.payload (the signing input) */
    bool     has_exp;
    int64_t  exp;
    char     aud[MJ_AUD_MAX][MJ_AUD_LEN];
} mj_jwt_t;

/* Read token tok[0, n) as a JWT. 1: it is one (three base64url parts, the
 * first decoding to a JSON object), and its header (naming "alg") and
 * claims are each one JSON object, read as strictly as a call: no
 * duplicate members, UTF-8 only, at most 64 deep; "exp", if given, a whole
 * number. 0: it is not in a JWT's form (an opaque token, an RFC 6750
 * b64token). -1: it is in a JWT's form (its first segment decodes to '{')
 * but is not a strict compact JWS, or cannot be read so, or it is neither
 * (a byte a bearer token may not hold) (why). v1.31 review: padding, a
 * byte outside base64url, or a segment not canonically encoded is -1, not
 * opaque, so a lenient reader cannot be handed a token these checks passed
 * over. */
int mj_jwt(const char *tok, size_t n, mj_jwt_t *out, char *why, size_t wn);

/* Decode an Mcp-Name or Mcp-Method header value as the transport says:
 * "=?base64?B64?=" is the Base64 of the value (padding required, no other
 * bytes); anything else is the value itself. The value written to out is
 * NUL-terminated. 0, or -1 (malformed, or does not fit, or holds a NUL). */
int mj_header_value(const char *v, size_t vn, char *out, size_t outn);

#endif
