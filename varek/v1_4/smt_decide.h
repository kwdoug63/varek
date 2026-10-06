// SPDX-License-Identifier: MIT
// smt_decide.h — VAREK SMT decision procedure for the Warden (v1.14; the v1.10
// verification program: v1.13 added the flag fragment, v1.14 the bounded
// string fragment).
//
// A policy is compiled into a quantifier-free formula over two variables per
// action:
//
//   s : a bounded string (the canonical path, "host:port", or exec path),
//       length 0..VDP_STR_MAX over bytes 1..255;
//   f : a 32-bit bitvector (the open flags; the kernel's `int flags`, so the
//       width is ABI-faithful: openat() ignores the upper 32 bits of the
//       register, and so does this model).
//
// Each rule r_i is  verb_i  S_i(s) AND B_i(f)  where
//
//   S_i is one string atom:
//        prefix(c, s) | s == c | host(c, s)                         (v1.13)
//        suffix(c, s) | contains(c, s) | s in glob(c)               (v1.14)
//        host(c, s) := s == c  OR  (portless(c) AND prefix(c ++ ":", s))
//          portless(c): c names an address or (v1.24) a host name without a
//          port; decided once at load (see vdp_policy_load).
//        glob(c) is the regular language of a path glob (see the grammar
//        below): literal bytes, ?, [...] classes, * (no '/'), ** (any bytes)
//        and the unit /**/ (zero or more whole path segments).
//   B_i is one bitvector atom:  (f & m_i) == v_i   (m_i == 0 means true)
//
// Rules of one action kind are ordered; the first rule whose formula holds
// decides (first match wins). The verdict is
//
//   SATISFIED    the first rule that holds is an allow rule
//   UNSATISFIED  the first rule that holds is a deny rule
//   UNKNOWN      no rule holds, or the action lies outside the fragment
//
// and UNKNOWN is suppressed to DENY by the caller (symmetric suppression).
//
// Fragment boundary (soundness obligations). An action outside the fragment
// is UNKNOWN, never a guessed SATISFIED:
//
//   - length guard: a string longer than VDP_STR_MAX is UNKNOWN (the caller
//     also refuses to truncate; see xproc_read_str);
//   - conservative mask: a flags value with any bit outside the ABI-defined
//     open(2) flag set (VDP_KNOWN_OFLAGS) is UNKNOWN, whatever the rules say;
//   - access mode 3 (O_WRONLY|O_RDWR, the kernel's "ioctl-only" mode, which
//     still honours O_TRUNC and O_CREAT) matches none of access=ro|wo|rw and
//     is UNKNOWN;
//   - bounded enumeration: a non-ground query whose relevant flag bits
//     exceed VDP_MAX_ENUM_BITS returns UNKNOWN rather than an unproved answer.
//
// Two query forms use the same procedure:
//
//   vdp_decide()          a concrete action (s and, for paths, f given). The
//                         satisfiability check of  policy AND s = v AND f = w
//                         reduces to evaluating the formula.
//   vdp_decide()          with has_flags == false: f is symbolic. SATISFIED
//                         only if EVERY admissible f is SATISFIED, UNSATISFIED
//                         only if every f is UNSATISFIED, else UNKNOWN. Used by
//                         the --plan gate, whose file_open actions carry no
//                         flags.
//   vdp_rule_reachable()  is there ANY (s, f) for which rule i is the first
//                         rule that holds? Decided exactly over the abstract
//                         domain (any byte string up to the bound, any in-
//                         fragment flags value). For prefix / exact / host
//                         atoms, by a finite witness set over the constants'
//                         trie; once a kind has a suffix, contains or glob
//                         rule, by a breadth-first search of the product of
//                         the rules' automata (shortest witness first, so the
//                         length bound is exact). Both use a bounded bitvector
//                         enumeration for the flags; past the enumeration or
//                         state budget the answer is UNKNOWN. Over the actions
//                         that really occur it errs toward REACHABLE (the safe
//                         direction for a warning). Used at policy load to
//                         report rules that can never fire.
//
// What a flag clause constrains. A clause constrains the flags the agent passes
// to openat(), checked when the Warden opens the object. That is sound for
// readonly: the access mode, O_TRUNC and O_CREAT take effect at open and cannot
// be changed afterwards. It is NOT a persistent property for bits fcntl(F_SETFL)
// can change later (O_APPEND, O_NONBLOCK, O_ASYNC, O_DIRECT, O_NOATIME) or bits
// the kernel adjusts (O_LARGEFILE is forced on 64-bit; the __O_SYNC bit alone
// gains O_DSYNC). vdp_rule_advisory() reports such clauses.
//
// Every answer this procedure gives is cross-checked against an SMT solver by
// tools/smt_crosscheck.py (differential, zero-disagreement gate).

#ifndef VAREK_SMT_DECIDE_H
#define VAREK_SMT_DECIDE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VDP_STR_MAX        4095     /* bound on s, bytes (PATH_LIMIT - 1) */
#define VDP_MAX_RULES      256
#define VDP_MAX_ENUM_BITS  16       /* bounded bitvector enumeration */
#define VDP_GLOB_MAX_WILD  32       // wildcards per glob (* ** ? [...] and the /**/ unit)
#define VDP_GLOB_MAX_TOTAL 4096     // glob tokens per policy: bounds the work per decision (v1.16: was 65536)

/* The x86_64 open(2) flag bits (uapi asm-generic/fcntl.h). Anything outside
 * this set is outside the fragment. */
#define VDP_KNOWN_OFLAGS   0x007fffc3u  /* checked against <fcntl.h> in smt_decide.c */

typedef enum { VDP_KIND_PATH = 0, VDP_KIND_HOST = 1, VDP_KIND_EXEC = 2 } vdp_kind_t;
typedef enum { VDP_ALLOW = 0, VDP_DENY = 1 } vdp_verb_t;
typedef enum {
    VDP_STR_PREFIX = 0, VDP_STR_EQ = 1, VDP_STR_HOST = 2,          /* v1.13 */
    VDP_STR_SUFFIX = 3, VDP_STR_CONTAINS = 4, VDP_STR_GLOB = 5,    /* v1.14 */
} vdp_str_op_t;

struct vdp_prog;    /* a compiled glob (smt_decide.c) */

typedef enum {
    VDP_UNKNOWN = 0,
    VDP_SATISFIED = 1,
    VDP_UNSATISFIED = 2,
} vdp_verdict_t;

typedef enum {
    VDP_REACH_UNKNOWN = 0,
    VDP_REACHABLE = 1,
    VDP_DEAD = 2,
} vdp_reach_t;

typedef struct {
    vdp_str_op_t      op;
    size_t            len;
    char              c[VDP_STR_MAX + 1];  /* the constant; for glob, the pattern */
    struct vdp_prog  *prog;                /* glob only: compiled at load */
    bool              portless;            /* host only: no port, so every port matches */
    bool              name;                /* host only (v1.24): a host name rule */
    bool              wild;                /* host only (v1.25): a wildcard *.suffix rule, held as a glob */
} vdp_str_atom_t;

typedef struct {
    uint32_t mask;      /* 0 = no constraint */
    uint32_t value;     /* value & ~mask == 0 */
} vdp_bv_atom_t;

typedef struct {
    vdp_verb_t     verb;
    vdp_kind_t     kind;
    vdp_str_atom_t s;
    vdp_bv_atom_t  b;
    int            line;   /* policy file line, for diagnostics and records */
} vdp_rule_t;

typedef struct {
    vdp_rule_t rules[VDP_MAX_RULES];
    size_t     n;
} vdp_policy_t;

/* Why a verdict was reached (for records). */
typedef enum {
    VDP_WHY_RULE = 0,          /* a rule decided; see *rule_index */
    VDP_WHY_NO_RULE,           /* no rule holds -> UNKNOWN */
    VDP_WHY_LENGTH_GUARD,      /* string over VDP_STR_MAX -> UNKNOWN */
    VDP_WHY_UNKNOWN_FLAGS,     /* flag bits outside the ABI set -> UNKNOWN */
    VDP_WHY_SYMBOLIC_MIXED,    /* symbolic f: outcomes differ -> UNKNOWN */
    VDP_WHY_ENUM_BOUND,        /* too many relevant bits -> UNKNOWN */
    VDP_WHY_ACCESS_MODE_3,     /* O_ACCMODE == 3: outside the fragment -> UNKNOWN */
} vdp_why_t;

const char *vdp_verdict_name(vdp_verdict_t v);
const char *vdp_why_name(vdp_why_t w);
const char *vdp_kind_name(vdp_kind_t k);

// Parse a policy file. Returns 0, or -1 with a message in err. Refuses (never
// silently drops) a policy with more than VDP_MAX_RULES rules, a line of more
// than 64 tokens, an empty constant, an unknown token, a malformed glob, glob
// patterns over VDP_GLOB_MAX_TOTAL tokens in all, or a contradictory flag
// clause. Release with vdp_policy_free().
//
// Line format:
//   <allow|deny> <path|host|exec> [matcher] <constant> [flag-clause...]
// matcher (v1.14; path and exec rules only):
//   exact      s == constant
//   prefix     s starts with constant    (the default for path)
//   suffix     s ends with constant
//   contains   constant occurs in s
//   glob       s matches the glob constant, anchored at both ends:
//                ?        one byte other than '/'
//                [...]    one byte from a set: a, a-z, [!...] or [^...] to
//                         negate; never matches '/' (a '/' inside is refused).
//                         A ']' first in the set and a '-' last are literal;
//                         \x inside a set is the byte x.
//                *        zero or more bytes, none of them '/'
//                **       zero or more bytes of any value
//                /**/     a '/', then zero or more whole segments each ending
//                         in '/' (so /a/**/b matches /a/b and /a/x/y/b); only
//                         with an unescaped '/' before the ** (\/**/ is a
//                         '/' then ** then '/')
//                \x       the byte x literally
//              at most VDP_GLOB_MAX_WILD wildcards; *** is refused.
// Without a matcher, path is prefix, exec is exact, and host is host[:port] (a
// bare host matches any port). A matcher keyword is read as a matcher only
// when a constant follows it that is not itself a flag clause, so every v1.13
// policy keeps its meaning (write `prefix glob` for a constant named glob).
// After `require warden 1.14` (or later) a matcher keyword with no constant
// after it is an error, not a prefix rule for the word. Tokens are separated
// by ASCII whitespace and a token starting with '#' starts a comment, so a
// constant can contain neither whitespace nor a leading '#'.
// flag-clause (path rules only):
//   readonly                              (access=ro -O_CREAT -O_TRUNC)
//   access=ro | access=wo | access=rw     (the O_ACCMODE bits only; note that
//                                          O_RDONLY|O_TRUNC truncates and
//                                          O_RDONLY|O_CREAT creates on Linux)
//   +O_NAME                               (bit must be set)
//   -O_NAME                               (bit must be clear)
// A constant (glob patterns included) may not contain control bytes
// (0x00-0x1f, 0x7f).
//
// Directive:
//   require warden <major>.<minor>
// refuses to load on an older procedure. Put it first in any policy that uses
// flag clauses: a v1.12 Warden fails to load it (unknown verb) instead of
// silently ignoring the clauses, which v1.12's parser did. A policy that uses
// matchers should say `require warden 1.14`; a v1.13 Warden refuses matcher
// lines in any case (it reads the constant as an unknown flag clause), and the
// directive makes the reason explicit.
// v1.24: a host rule names a host (`allow host api.example.com:443`) only
// after `require warden 1.24` (or later); a Warden before 1.24 then refuses
// the policy instead of loading name rules it cannot match. After the
// directive a host constant in name form that is not a valid name is refused
// (see vdp_host_name_form). Without it, such a constant keeps its v1.21
// meaning (an exact string no connect produces; a load-time note says so), and
// a `require warden 1.24` that follows such a rule is refused, so that one
// policy cannot hold host names under both meanings.
int vdp_policy_load(const char *path, vdp_policy_t *p, char *err, size_t errlen);

/* Decide a single action. s must be a NUL-terminated string. flags is used only
 * for VDP_KIND_PATH when has_flags is true; with has_flags false the flags are
 * treated as symbolic (see header comment). rule_index (optional) receives the
 * deciding rule's index, or -1. why (optional) receives the reason. */
vdp_verdict_t vdp_decide(const vdp_policy_t *p, vdp_kind_t kind, const char *s,
                         uint32_t flags, bool has_flags,
                         int *rule_index, vdp_why_t *why);

/* The rule's matcher as written ("glob ", "suffix ", ...), or "" when it is the
 * kind's default (prefix for path, exact for exec, host for host). */
const char *vdp_matcher_prefix(const vdp_rule_t *r);

/* As vdp_policy_load, from a buffer (v1.15: the Warden reads the policy file
 * once, and both this procedure and the certificate checker parse those same
 * bytes, whose SHA-256 it records). */
int vdp_policy_load_mem(const char *name, const char *buf, size_t len, vdp_policy_t *p,
                        char *err, size_t errlen);

/* v1.15: the certificate of a SATISFIED verdict (see checker/vdp_checker.h for
 * what it proves and how it is checked). rule is the deciding rule's index, or
 * -1 for a symbolic verdict several rules decide; the witness shows that
 * rule's string atom holds on s: none (prefix, exact, suffix, host), an offset
 * (contains), or one span of s per STAR / SEGS token of a glob, in order. */
enum { VDP_WIT_NONE = 0, VDP_WIT_OFFSET = 1, VDP_WIT_SPANS = 2 };
typedef struct {
    int      rule;
    int      wkind;
    uint32_t off;
    uint32_t nspan;
    uint32_t span[VDP_GLOB_MAX_WILD][2];
} vdp_cert_t;

/* Fill the certificate for a SATISFIED verdict that vdp_decide reached with
 * rule_index on s. 0, or -1 if no witness could be built (which the checker
 * then refuses: the action is not authorized). */
int vdp_certificate(const vdp_policy_t *p, int rule_index, const char *s, vdp_cert_t *c);

/* Release what vdp_policy_load allocated (compiled globs). */
void vdp_policy_free(vdp_policy_t *p);

/* v1.16: total glob tokens in the policy (<= VDP_GLOB_MAX_TOTAL). */
size_t vdp_policy_glob_tokens(const vdp_policy_t *p);

/* Can rule i ever be the first rule (of its kind) that holds? */
vdp_reach_t vdp_rule_reachable(const vdp_policy_t *p, size_t i);

/* As vdp_rule_reachable, and on VDP_REACHABLE also a witness: a string (at
 * most wcap - 1 bytes, NUL-terminated, length in *wlen) and a flags value for
 * which rule i is the first rule that holds. wit may be NULL. */
vdp_reach_t vdp_rule_reachable_witness(const vdp_policy_t *p, size_t i,
                                       char *wit, size_t wcap, size_t *wlen,
                                       uint32_t *wflags);

/* Testing only: decide every reachability query with the automaton search,
 * also for kinds the trie method covers (the cross-check runs both). */
extern bool vdp_reach_force_automaton;

/* Why the last reachability query in this thread returned VDP_REACH_UNKNOWN:
 * "enumeration_bound" (more than VDP_MAX_ENUM_BITS free flag bits),
 * "state_budget" (the automaton search's state or work budget), or
 * "witness_alphabet" (the trie method found a constant prefix followed by all
 * 255 byte values, so its witness set may be incomplete); "" if it did not. */
const char *vdp_reach_unknown_reason(void);

/* The same, as text for a load-time note. */
const char *vdp_reach_unknown_text(void);

/* Name <-> bit for flag clauses; returns 0 if unknown. */
uint32_t vdp_flag_bit(const char *name);

/* Advisory text for a rule (flag clauses that constrain only the open() call,
 * non-ASCII bytes in the constant). Writes a NUL-terminated message and returns
 * its length, or 0 if there is nothing to report. */
size_t vdp_rule_advisory(const vdp_rule_t *r, char *buf, size_t n);

/* v1.21: does a host rule's constant name an address without a port (so it
 * matches that address on every port)? See smt_decide.c. */
bool vdp_host_portless(const char *c, size_t cl);
bool vdp_host_is_ipv4(const char *c, size_t cl);

/* v1.21: can a connect produce this host constant (numeric address in the
 * Warden's spelling, optional decimal port, or unix:<absolute path)? When not,
 * writes the reason to why and returns false. Used for a load-time note. */
bool vdp_host_constant_ok(const char *c, size_t cl, char *why, size_t wn);

/* v1.24: host names. A host constant is in name form unless it starts with
 * '[' or "unix:", or the part before its first ':' is empty or only digits and
 * dots (those are numeric forms, as in v1.21). A constant in name form is
 *   <name>  or  <name>:<port>
 * where <name> is lowercase letters, digits, '-' and '.', labels of 1 to 63
 * bytes that neither start nor end with '-', at most 253 bytes, no trailing
 * dot, a last label that is not all digits, internationalized names as
 * A-labels (xn--...) only, and not the word "unix" (unix:/path names a Unix
 * socket); <port> is decimal, 0 to 65535, without leading zeros. Wildcards
 * (*.example.com) are not names (planned for v1.25).
 * Returns 0 if c is not in name form, 1 if it is a valid name constant, -1 if
 * it is in name form but invalid (the reason in why). */
int vdp_host_name_form(const char *c, size_t cl, char *why, size_t wn);

/* v1.25: a wildcard host constant, *.<suffix> or *.<suffix>:<port>, where
 * <suffix> is a valid v1.24 name of at least two labels and <port> as for a
 * name. *.example.com matches a name with one or more labels before
 * .example.com, never example.com itself. It is held as the glob
 *   ?*.<suffix>:<port>    or, without a port,    ?*.<suffix>:*
 * (names hold no glob metacharacters, and the strings a connect is decided on
 * are valid names, so the glob is exact), and decided, certified and analysed
 * as any glob. Returns 1 and writes the glob to out (outn bytes), 0 if c does
 * not start with "*.", or -1 if it is an invalid wildcard (the reason in why). */
int vdp_host_wildcard_glob(const char *c, size_t cl, char *out, size_t outn, char *why, size_t wn);

/* v1.24: can a connect ever match this host rule? A name rule (`require
 * warden 1.24` before it) can; a constant in name form without the directive
 * cannot, nor can a numeric constant vdp_host_constant_ok refuses. When not,
 * writes the reason to why and returns false. */
bool vdp_host_rule_ok(const vdp_rule_t *r, char *why, size_t wn);

/* The Warden version this procedure implements, for `require warden X.Y`.
 * v1.21: host rules take effect (decided connections), and a bracketed IPv6
 * constant without a port ("[::1]") matches every port.
 * v1.24: host names (`allow host api.example.com:443`); a name without a port
 * matches every port. Name rules need `require warden 1.24` before them.
 * v1.25: wildcard host names (`allow host *.example.com:443`), after
 * `require warden 1.25`; see vdp_host_wildcard_glob. */
#define VDP_WARDEN_MAJOR 1
#define VDP_WARDEN_MINOR 25

#endif /* VAREK_SMT_DECIDE_H */
