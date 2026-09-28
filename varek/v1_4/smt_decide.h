// SPDX-License-Identifier: MIT
// smt_decide.h — VAREK SMT decision procedure for the Warden (v1.13; the first
// release of the v1.10 verification program).
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
//   S_i is one string atom:  prefix(c, s) | s == c | host(c, s)
//        host(c, s) := s == c  OR  (c has no ':' AND prefix(c ++ ":", s))
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
//                         rule that holds? Decided exactly for this fragment
//                         (finite witness set over the constants' trie plus a
//                         bounded bitvector enumeration). Used at policy load
//                         to report rules that can never fire.
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

/* The x86_64 open(2) flag bits (uapi asm-generic/fcntl.h). Anything outside
 * this set is outside the fragment. */
#define VDP_KNOWN_OFLAGS   0x007fffc3u  /* checked against <fcntl.h> in smt_decide.c */

typedef enum { VDP_KIND_PATH = 0, VDP_KIND_HOST = 1, VDP_KIND_EXEC = 2 } vdp_kind_t;
typedef enum { VDP_ALLOW = 0, VDP_DENY = 1 } vdp_verb_t;
typedef enum { VDP_STR_PREFIX = 0, VDP_STR_EQ = 1, VDP_STR_HOST = 2 } vdp_str_op_t;

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
    vdp_str_op_t op;
    size_t       len;
    char         c[VDP_STR_MAX + 1];
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
} vdp_why_t;

const char *vdp_verdict_name(vdp_verdict_t v);
const char *vdp_why_name(vdp_why_t w);
const char *vdp_kind_name(vdp_kind_t k);

/* Parse a policy file. Returns 0, or -1 with a message in err. Refuses (never
 * silently drops) a policy with more than VDP_MAX_RULES rules, an over-long
 * line, an empty constant, an unknown token, or a contradictory flag clause.
 *
 * Line format:
 *   <allow|deny> <path|host|exec> <constant> [flag-clause...]
 * flag-clause (path rules only):
 *   readonly                              (access=ro -O_CREAT -O_TRUNC)
 *   access=ro | access=wo | access=rw     (the O_ACCMODE bits only; note that
 *                                          O_RDONLY|O_TRUNC truncates and
 *                                          O_RDONLY|O_CREAT creates on Linux)
 *   +O_NAME                               (bit must be set)
 *   -O_NAME                               (bit must be clear)
 * A path rule's constant is a prefix; host is host[:port] (a bare host matches
 * any port); exec is an exact path. */
int vdp_policy_load(const char *path, vdp_policy_t *p, char *err, size_t errlen);

/* Decide a single action. s must be a NUL-terminated string. flags is used only
 * for VDP_KIND_PATH when has_flags is true; with has_flags false the flags are
 * treated as symbolic (see header comment). rule_index (optional) receives the
 * deciding rule's index, or -1. why (optional) receives the reason. */
vdp_verdict_t vdp_decide(const vdp_policy_t *p, vdp_kind_t kind, const char *s,
                         uint32_t flags, bool has_flags,
                         int *rule_index, vdp_why_t *why);

/* Can rule i ever be the first rule (of its kind) that holds? */
vdp_reach_t vdp_rule_reachable(const vdp_policy_t *p, size_t i);

/* Name <-> bit for flag clauses; returns 0 if unknown. */
uint32_t vdp_flag_bit(const char *name);

#endif /* VAREK_SMT_DECIDE_H */
