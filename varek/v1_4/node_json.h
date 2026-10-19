// SPDX-License-Identifier: MIT
// node_json.h — v1.34 (docs/security/v1.34-kubernetes.md, step 2): reading
// the values the node agent needs from the container's state, which the
// runtime sends with the seccomp descriptor (OCI's container process state),
// and from the bundle's config.json.
//
// A strict reader of RFC 8259 JSON: the whole document is checked (UTF-8
// only, no trailing data, nesting at most NJ_MAX_DEPTH), and an object that
// holds the same member name twice, at any depth, is refused: the runtime's
// own reader takes the last of two, so the Warden must never read another
// value than the one the runtime acts on. Names are compared as Go's
// encoding/json matches them to fields (ASCII case folded, U+017F as s and
// U+212A as k), so "args" and "Args" are the same name; nj_find matches
// exactly, so a lone name in another case is not found.
#ifndef VAREK_NODE_JSON_H
#define VAREK_NODE_JSON_H
#include <stdbool.h>
#include <stddef.h>

#define NJ_MAX_DEPTH 32

// Checks the document. 0, or -1 with the reason in why.
int nj_check(const char *doc, size_t n, char *why, size_t wn);

// The value at path in a checked document: each element an object's member
// name, or "#N" for an array's element N (from 0). 0 and the value's span in
// *v, *vn; -1 if there is none.
int nj_find(const char *doc, size_t n, const char *const *path, size_t depth,
            const char **v, size_t *vn);

// A string value, decoded, NUL-terminated: 0, or -1 (not a string, too long,
// or holding a NUL).
int nj_string(const char *v, size_t vn, char *out, size_t outn);

// An integer value (no fraction or exponent): 0, or -1.
int nj_int(const char *v, size_t vn, long long *out);

#endif
