// SPDX-License-Identifier: MIT
// vdp_checker.h — VAREK certificate checker (v1.15).
//
// The SMT decision procedure (smt_decide.c) decides every Warden action. From
// v1.15 each SATISFIED verdict carries a certificate, and this checker must
// accept the certificate before the Warden authorizes the action. The checker
// is written separately from the procedure and shares no code with it: it has
// its own policy parser and its own matchers, and none of the procedure's
// optimizations (fast rejection, word-parallel automata, reachability search,
// enumeration pruning). An authorization therefore needs two independent
// implementations to agree, and a logic bug confined to the procedure cannot
// authorize an action. The trusted base for "no action is authorized that the
// policy does not allow" is this checker (and the kernel mechanisms around it),
// not the procedure. (Both run in the Warden's process, so this separation does
// not extend to memory corruption.) The checker is independent in code, not in
// design: it follows the same grammar, its glob parser mirrors the procedure's
// structure, and its matcher runs the same automaton one step at a time.
//
// ---------------------------------------------------------------------------
// The claim a certificate proves
// ---------------------------------------------------------------------------
//
// An action is (kind, s, f): kind is path, host or exec; s is the string the
// policy is matched against (the resolved canonical path, "host:port", or the
// exec path); f is the open flags for a path, or "any" for a symbolic query
// (the --plan gate), and ignored for host and exec.
//
// Ground claim (f given): rule r is the first rule of this kind that holds on
// (s, f), and r is an allow rule. A rule holds when its string atom holds on
// s and its flag atom (f & mask) == value holds on f. The action must lie in
// the fragment: |s| <= 4095 and, for a path, f has no bit outside the x86_64
// open(2) set and access mode is not 3.
//
// Symbolic claim (path, f = any): for EVERY admissible f (no bit outside the
// open(2) set, access mode not 3) the first rule that holds on (s, f) exists
// and is an allow rule.
//
// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------
//
//   r   the index (0-based, in file order, counting rules only) of the rule
//       that decides a ground claim; -1 is allowed for a symbolic claim, where
//       several rules may decide for different f.
//   w   a witness that rule r's string atom holds on s:
//         prefix / exact / suffix / host   none (the checker compares bytes)
//         contains c                       an offset k with s[k .. k+|c|) == c
//         glob                             one span [a, b) of s per stretch
//                                          token, in pattern order
//
// Stretch tokens of a glob are `*`, `**`, and the `/**/` unit. A glob is read
// as a sequence of tokens: a literal byte (also `\x`), a one-byte set (`?`,
// `[...]`), `*` (zero or more bytes, none '/'), `**` (zero or more bytes), and
// the `/**/` unit, which is the literal '/' followed by a SEGS token: zero
// bytes, or one or more bytes of which the last is '/'. The span of a `/**/`
// unit covers its SEGS part only (the bytes after the leading '/').
//
// Checking a ground certificate:
//   1. the action is in the fragment;
//   2. rule r exists, is an allow rule of this kind, and its flag atom holds;
//   3. the witness shows r's string atom holds (for a glob: walking the tokens
//      left to right, each literal and set token takes the next byte, each
//      stretch token takes exactly its span, which must start where the walk
//      is and satisfy the token, and the walk ends at |s|);
//   4. no earlier rule of this kind holds on (s, f) — decided here, with the
//      checker's own matchers.
// Checking a symbolic certificate: the checker computes which path rules'
// string atoms hold on s and enumerates every admissible value of the flag bits
// those rules test. A symbolic certificate that names one deciding rule (r >= 0)
// carries that rule's witness, which is checked too; r = -1 carries none.
//
// v1.26.1: a request is (request, s) with s the request object
// "METHOD scheme://host:port/path?query"; request rules are globs over it.
//
// The checker implements the policy grammar of VAREK 1.26.1 (smt_decide.h). A
// policy it cannot parse is refused, so the Warden does not start.

#ifndef VAREK_VDP_CHECKER_H
#define VAREK_VDP_CHECKER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VDPC_GRAMMAR_MAJOR 1
#define VDPC_GRAMMAR_MINOR 27

#define VDPC_MAX_S        4095
#define VDPC_MAX_RULES    256
#define VDPC_MAX_STRETCH  32          /* a glob has at most 32 wildcards */
#define VDPC_GLOB_MAX_TOTAL 4096      /* glob tokens per policy (v1.16; was 65536) */

enum { VDPC_PATH = 0, VDPC_HOST = 1, VDPC_EXEC = 2, VDPC_REQUEST = 3 /* v1.26.1 */ };

typedef struct vdpc_rule vdpc_rule_t;

typedef struct {
    vdpc_rule_t  *rules;
    size_t        n;
    unsigned char sha256[32];         /* of the policy bytes as loaded */
    int           proxy;              /* v1.26: `proxy on` */
    unsigned      proxy_ports[16];    /* v1.26: `proxy ports`, in order; none: the default */
    size_t        proxy_nports;
    char          proxy_up_host[254]; /* v1.26 section 5: `proxy upstream http://HOST:PORT` */
    unsigned      proxy_up_port;      /* 0: none */
    int           proxy_inspect;      /* v1.26.1: `proxy inspect` (proxy is then 1 too) */
    char          proxy_pass[64][254];/* v1.26.1: `proxy passthrough host NAME`, in order */
    size_t        proxy_npass;
    int           launches;           /* v1.27: `require warden 1.27` (launches decided) */
} vdpc_policy_t;

typedef struct {
    int      r;                       /* deciding rule, or -1 (symbolic only) */
    int      wkind;                   /* 0 none, 1 contains offset, 2 glob spans */
    uint32_t off;                     /* contains: offset */
    uint32_t nspan;                   /* glob: number of spans */
    uint32_t span[VDPC_MAX_STRETCH][2];
} vdpc_cert_t;

/* Parse a policy from memory (the exact bytes the Warden loaded). 0, or -1
 * with a message. */
int  vdpc_load(const char *name, const char *buf, size_t len, vdpc_policy_t *p,
               char *err, size_t errlen);
void vdpc_free(vdpc_policy_t *p);

/* Check a certificate for a SATISFIED claim. has_flags false means the
 * symbolic claim (path only). Returns 1 if the certificate is accepted, 0 if
 * not (the reason in why). */
int vdpc_check(const vdpc_policy_t *p, int kind, const char *s, size_t sl,
               uint32_t flags, bool has_flags, const vdpc_cert_t *c,
               char *why, size_t whylen);

/* A parsed rule, for comparison with another parser (the Warden compares the
 * decision procedure's parse with this one at load). */
enum { VDPC_M_PREFIX, VDPC_M_EXACT, VDPC_M_SUFFIX, VDPC_M_CONTAINS, VDPC_M_GLOB, VDPC_M_HOST };
typedef struct {
    bool        allow;
    int         kind, match, line;
    const char *c;
    size_t      clen;
    uint32_t    mask, value;
    bool        portless;             /* host: no port, so every port matches */
    bool        name;                 /* host (v1.24): a host name rule */
    bool        wild;                 /* host (v1.25): a wildcard rule, held as a glob */
    uint32_t    names, rate;          /* host (v1.25): a wildcard allow rule's budgets, 0: not set */
    uint32_t    max_body;             /* request (v1.26.1): max_body=, 0: not set */
} vdpc_rule_info_t;
int vdpc_rule_info(const vdpc_policy_t *p, size_t i, vdpc_rule_info_t *out);

/* Does rule i's string atom hold on s? (Testing and audit: which rules match
 * a path, by the checker's own matchers.) 1, 0, or -1 if there is no rule i. */
int vdpc_holds(const vdpc_policy_t *p, size_t i, const char *s, size_t sl);

/* v1.16: 1 if some admissible open(2) flags value of an open of path s is
 * decided by an allow rule (the agent could open s), 0 if none is. */
int vdpc_path_openable(const vdpc_policy_t *p, const char *s, size_t sl);

/* Hex form of the policy digest (65 bytes with the NUL). */
void vdpc_digest_hex(const vdpc_policy_t *p, char out[65]);

/* SHA-256 (FIPS 180-4), used for the policy digest. */
void vdpc_sha256(const void *data, size_t len, unsigned char out[32]);

#endif /* VAREK_VDP_CHECKER_H */
