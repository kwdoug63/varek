// SPDX-License-Identifier: MIT
// smt_decide.c — VAREK SMT decision procedure (v1.14; the v1.10 verification
// program). See smt_decide.h for the fragment, the verdict semantics and the
// soundness obligations.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "smt_decide.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Flag bits: x86_64 kernel uapi values (asm-generic/fcntl.h). Hard-coded     */
/* because glibc defines some as 0 in userspace (O_LARGEFILE on 64-bit) or as */
/* composites (O_SYNC, O_TMPFILE); checked against <fcntl.h> where possible.  */
/* ------------------------------------------------------------------------ */

#define K_O_ACCMODE    00000003u
#define K_O_CREAT      00000100u
#define K_O_EXCL       00000200u
#define K_O_NOCTTY     00000400u
#define K_O_TRUNC      00001000u
#define K_O_APPEND     00002000u
#define K_O_NONBLOCK   00004000u
#define K_O_DSYNC      00010000u
#define K_FASYNC       00020000u
#define K_O_DIRECT     00040000u
#define K_O_LARGEFILE  00100000u
#define K_O_DIRECTORY  00200000u
#define K_O_NOFOLLOW   00400000u
#define K_O_NOATIME    01000000u
#define K_O_CLOEXEC    02000000u
#define K___O_SYNC     04000000u
#define K_O_PATH      010000000u
#define K___O_TMPFILE 020000000u

#if !defined(__x86_64__)
#error "VAREK Warden supports x86_64 only (flag bit values are x86_64 uapi)"
#endif

_Static_assert(K_O_CREAT     == (unsigned)O_CREAT,     "O_CREAT");
_Static_assert(K_O_EXCL      == (unsigned)O_EXCL,      "O_EXCL");
_Static_assert(K_O_NOCTTY    == (unsigned)O_NOCTTY,    "O_NOCTTY");
_Static_assert(K_O_TRUNC     == (unsigned)O_TRUNC,     "O_TRUNC");
_Static_assert(K_O_APPEND    == (unsigned)O_APPEND,    "O_APPEND");
_Static_assert(K_O_NONBLOCK  == (unsigned)O_NONBLOCK,  "O_NONBLOCK");
_Static_assert(K_O_DSYNC     == (unsigned)O_DSYNC,     "O_DSYNC");
_Static_assert(K_FASYNC      == (unsigned)O_ASYNC,     "O_ASYNC");
_Static_assert(K_O_DIRECT    == (unsigned)O_DIRECT,    "O_DIRECT");
_Static_assert(K_O_DIRECTORY == (unsigned)O_DIRECTORY, "O_DIRECTORY");
_Static_assert(K_O_NOFOLLOW  == (unsigned)O_NOFOLLOW,  "O_NOFOLLOW");
_Static_assert(K_O_NOATIME   == (unsigned)O_NOATIME,   "O_NOATIME");
_Static_assert(K_O_CLOEXEC   == (unsigned)O_CLOEXEC,   "O_CLOEXEC");
_Static_assert((K___O_SYNC | K_O_DSYNC) == (unsigned)O_SYNC, "O_SYNC");
_Static_assert(K_O_PATH      == (unsigned)O_PATH,      "O_PATH");
_Static_assert((K___O_TMPFILE | K_O_DIRECTORY) == (unsigned)O_TMPFILE, "O_TMPFILE");
_Static_assert((K_O_ACCMODE | K_O_CREAT | K_O_EXCL | K_O_NOCTTY | K_O_TRUNC |
                K_O_APPEND | K_O_NONBLOCK | K_O_DSYNC | K_FASYNC | K_O_DIRECT |
                K_O_LARGEFILE | K_O_DIRECTORY | K_O_NOFOLLOW | K_O_NOATIME |
                K_O_CLOEXEC | K___O_SYNC | K_O_PATH | K___O_TMPFILE)
               == VDP_KNOWN_OFLAGS, "VDP_KNOWN_OFLAGS");

/* Names for +/- flag clauses. Each maps to its distinguishing bit: O_SYNC is
 * the __O_SYNC bit (glibc's O_SYNC sets it together with O_DSYNC) and
 * O_TMPFILE the __O_TMPFILE bit (O_TMPFILE also sets O_DIRECTORY). The access
 * mode is not a single bit; use access=ro|wo|rw. */
static const struct { const char *name; uint32_t bit; } kFlagNames[] = {
    { "O_CREAT",     K_O_CREAT     }, { "O_EXCL",      K_O_EXCL      },
    { "O_NOCTTY",    K_O_NOCTTY    }, { "O_TRUNC",     K_O_TRUNC     },
    { "O_APPEND",    K_O_APPEND    }, { "O_NONBLOCK",  K_O_NONBLOCK  },
    { "O_DSYNC",     K_O_DSYNC     }, { "O_ASYNC",     K_FASYNC      },
    { "O_DIRECT",    K_O_DIRECT    }, { "O_LARGEFILE", K_O_LARGEFILE },
    { "O_DIRECTORY", K_O_DIRECTORY }, { "O_NOFOLLOW",  K_O_NOFOLLOW  },
    { "O_NOATIME",   K_O_NOATIME   }, { "O_CLOEXEC",   K_O_CLOEXEC   },
    { "O_SYNC",      K___O_SYNC    }, { "O_PATH",      K_O_PATH      },
    { "O_TMPFILE",   K___O_TMPFILE },
};

uint32_t vdp_flag_bit(const char *name) {
    for (size_t i = 0; i < sizeof kFlagNames / sizeof kFlagNames[0]; i++)
        if (!strcmp(name, kFlagNames[i].name)) return kFlagNames[i].bit;
    return 0;
}

const char *vdp_verdict_name(vdp_verdict_t v) {
    switch (v) {
        case VDP_SATISFIED:   return "SATISFIED";
        case VDP_UNSATISFIED: return "UNSATISFIED";
        default:              return "UNKNOWN";
    }
}

const char *vdp_why_name(vdp_why_t w) {
    switch (w) {
        case VDP_WHY_RULE:           return "rule";
        case VDP_WHY_NO_RULE:        return "no_rule";
        case VDP_WHY_LENGTH_GUARD:   return "length_guard";
        case VDP_WHY_UNKNOWN_FLAGS:  return "unknown_flag_bits";
        case VDP_WHY_SYMBOLIC_MIXED: return "symbolic_flags_mixed";
        case VDP_WHY_ENUM_BOUND:     return "enumeration_bound";
        case VDP_WHY_ACCESS_MODE_3:  return "access_mode_3";
    }
    return "unknown";
}

const char *vdp_kind_name(vdp_kind_t k) {
    switch (k) {
        case VDP_KIND_PATH: return "path";
        case VDP_KIND_HOST: return "host";
        case VDP_KIND_EXEC: return "exec";
    }
    return "?";
}

/* ------------------------------------------------------------------------ */
/* String programs (v1.14)                                                   */
/* ------------------------------------------------------------------------ */
/*
 * Every string atom of the bounded string fragment compiles to a program: a
 * sequence of tokens, each one of
 *
 *   ONE(S)   exactly one byte from the set S
 *   STAR(S)  zero or more bytes from S
 *   SEGS     the regular expression (.*\/)? : empty, or any bytes ending in
 *            '/'. The glob unit slash-star-star-slash compiles to ONE('/')
 *            followed by SEGS.
 *
 * Sets never contain byte 0. A program with tokens t_0..t_{n-1} defines a
 * nondeterministic automaton without epsilon moves except the forward skip over
 * STAR and SEGS tokens:
 *
 *   position state k (0 <= k <= n)   the first k tokens are matched; n accepts
 *   inner state k                    inside SEGS token k (read some bytes, want '/')
 *
 * Glob patterns compile to programs at load and are matched by simulating the
 * automaton on a bitset of states (vdp_decide). prefix / exact / suffix /
 * contains compile to programs only for the reachability search; vdp_decide
 * matches them with memcmp / memmem.
 */

enum { T_ONE = 0, T_STAR = 1, T_SEGS = 2 };
#define TYPE_IS_STRETCH(t) ((t) == T_STAR || (t) == T_SEGS)

struct vdp_tok { uint8_t type; uint16_t set; };
typedef struct { uint64_t w[4]; } bset_t;

struct vdp_prog {
    size_t          ntok;
    struct vdp_tok *tok;
    size_t          nsets;
    bset_t         *sets;
    size_t          w1;         /* words per half of a state set (bits 0..ntok) */
    /* Necessary conditions, checked before the automaton runs (vdp_decide's
     * hot path): every match starts with pre[0..npre), ends with
     * suf[0..nsuf), contains mid[0..nmid) (the longest run of single-byte
     * tokens), has at least minlen bytes, and exactly minlen if exact. */
    size_t          npre, nsuf, nmid, minlen;
    bool            exact;
    unsigned char  *pre, *suf, *mid;
    /* Word-parallel step tables (bit k = token k): bm[b * w1 ..] the tokens
     * whose set holds byte b; the tokens that are ONE, STAR, SEGS, and
     * STAR or SEGS (the forward skips). */
    uint64_t       *bm, *onem, *starm, *segsm, *skipm;
};

static inline bool bs_has(const bset_t *s, unsigned b) { return (s->w[b >> 6] >> (b & 63)) & 1; }
static inline void bs_add(bset_t *s, unsigned b) { s->w[b >> 6] |= 1ull << (b & 63); }

static bset_t bs_any(void) {            /* 1..255 */
    bset_t s = { { ~0ull, ~0ull, ~0ull, ~0ull } };
    s.w[0] &= ~1ull;
    return s;
}
static bset_t bs_notslash(void) {       /* 1..255 minus '/' */
    bset_t s = bs_any();
    s.w['/' >> 6] &= ~(1ull << ('/' & 63));
    return s;
}
static bset_t bs_one(unsigned char b) { bset_t s = { { 0, 0, 0, 0 } }; bs_add(&s, b); return s; }
static bool bs_eq(const bset_t *a, const bset_t *b) { return !memcmp(a, b, sizeof *a); }

struct pbuild { struct vdp_prog *p; size_t tcap, scap; };

static int pb_set(struct pbuild *b, const bset_t *s) {
    for (size_t i = 0; i < b->p->nsets; i++)
        if (bs_eq(&b->p->sets[i], s)) return (int)i;
    if (b->p->nsets == b->scap) {
        size_t nc = b->scap ? b->scap * 2 : 8;
        bset_t *ns = realloc(b->p->sets, nc * sizeof *ns);
        if (!ns) return -1;
        b->p->sets = ns;
        b->scap = nc;
    }
    b->p->sets[b->p->nsets] = *s;
    return (int)b->p->nsets++;
}

static int pb_tok(struct pbuild *b, int type, const bset_t *s) {
    int si = 0;
    if (s && (si = pb_set(b, s)) < 0) return -1;
    if (b->p->ntok == b->tcap) {
        size_t nc = b->tcap ? b->tcap * 2 : 16;
        struct vdp_tok *nt = realloc(b->p->tok, nc * sizeof *nt);
        if (!nt) return -1;
        b->p->tok = nt;
        b->tcap = nc;
    }
    b->p->tok[b->p->ntok].type = (uint8_t)type;
    b->p->tok[b->p->ntok].set = (uint16_t)si;
    b->p->ntok++;
    return 0;
}

static void prog_free(struct vdp_prog *p) {
    if (!p) return;
    free(p->tok);
    free(p->sets);
    free(p->pre);
    free(p->suf);
    free(p->mid);
    free(p->bm);
    free(p->onem);
    free(p);
}

/* The byte of a singleton set, or -1. */
static int bs_single(const bset_t *s) {
    int n = 0, b = -1;
    for (int w = 0; w < 4; w++) {
        n += __builtin_popcountll(s->w[w]);
        if (s->w[w]) b = w * 64 + __builtin_ctzll(s->w[w]);
    }
    return n == 1 ? b : -1;
}

static struct vdp_prog *prog_new(struct pbuild *b) {
    memset(b, 0, sizeof *b);
    b->p = calloc(1, sizeof *b->p);
    return b->p;
}

static struct vdp_prog *prog_done(struct pbuild *b) {
    struct vdp_prog *p = b->p;
    p->w1 = (p->ntok + 1 + 63) / 64;
    /* Literal prefix and suffix, minimum length (fast rejection). */
    p->exact = true;
    for (size_t k = 0; k < p->ntok; k++) {
        if (p->tok[k].type == T_ONE) p->minlen++;
        else p->exact = false;
    }
    size_t k = 0;
    while (k < p->ntok && p->tok[k].type == T_ONE && bs_single(&p->sets[p->tok[k].set]) >= 0) k++;
    p->npre = k;
    k = p->ntok;
    while (k > 0 && p->tok[k - 1].type == T_ONE && bs_single(&p->sets[p->tok[k - 1].set]) >= 0) k--;
    p->nsuf = p->ntok - k;
    p->pre = malloc(p->npre + 1);
    p->suf = malloc(p->nsuf + 1);
    /* Longest run of single-byte tokens: any match holds it as a substring. */
    size_t best = 0, bstart = 0, run = 0;
    for (size_t i = 0; i < p->ntok; i++) {
        if (p->tok[i].type == T_ONE && bs_single(&p->sets[p->tok[i].set]) >= 0) {
            if (++run > best) { best = run; bstart = i + 1 - run; }
        } else run = 0;
    }
    p->nmid = best;
    p->mid = malloc(best + 1);
    if (!p->mid) { prog_free(p); return NULL; }
    for (size_t i = 0; i < best; i++) p->mid[i] = (unsigned char)bs_single(&p->sets[p->tok[bstart + i].set]);
    size_t W = p->w1;
    p->bm = calloc(256 * W, sizeof *p->bm);
    p->onem = calloc(4 * W, sizeof *p->onem);
    if (!p->pre || !p->suf || !p->bm || !p->onem) { prog_free(p); return NULL; }
    p->starm = p->onem + W;
    p->segsm = p->onem + 2 * W;
    p->skipm = p->onem + 3 * W;
    for (size_t i = 0; i < p->ntok; i++) {
        uint64_t bit = 1ull << (i & 63);
        size_t w = i >> 6;
        const struct vdp_tok *tk = &p->tok[i];
        if (tk->type == T_ONE) p->onem[w] |= bit;
        else if (tk->type == T_STAR) p->starm[w] |= bit;
        else p->segsm[w] |= bit;
        if (tk->type != T_ONE) p->skipm[w] |= bit;
        if (tk->type != T_SEGS)
            for (unsigned c = 1; c < 256; c++)
                if (bs_has(&p->sets[tk->set], c)) p->bm[c * W + w] |= bit;
    }
    for (size_t i = 0; i < p->npre; i++) p->pre[i] = (unsigned char)bs_single(&p->sets[p->tok[i].set]);
    for (size_t i = 0; i < p->nsuf; i++)
        p->suf[i] = (unsigned char)bs_single(&p->sets[p->tok[p->ntok - p->nsuf + i].set]);
    return p;
}

/* Literal-based atoms as programs (for the reachability search). */
static struct vdp_prog *prog_from_atom(vdp_str_op_t op, const char *c, size_t len) {
    struct pbuild b;
    if (!prog_new(&b)) return NULL;
    bset_t any = bs_any();
    int rc = 0;
    if (op == VDP_STR_SUFFIX || op == VDP_STR_CONTAINS) rc |= pb_tok(&b, T_STAR, &any);
    for (size_t i = 0; i < len && !rc; i++) {
        bset_t one = bs_one((unsigned char)c[i]);
        rc |= pb_tok(&b, T_ONE, &one);
    }
    if (op == VDP_STR_PREFIX || op == VDP_STR_CONTAINS) rc |= pb_tok(&b, T_STAR, &any);
    if (rc) { prog_free(b.p); return NULL; }
    return prog_done(&b);
}

/* Compile a glob. Returns NULL with a message in emsg on a malformed pattern
 * (or out of memory). */
static struct vdp_prog *prog_glob(const char *c, size_t len, char *emsg, size_t en) {
    struct pbuild b;
    if (!prog_new(&b)) { snprintf(emsg, en, "out of memory"); return NULL; }
    bset_t any = bs_any(), ns = bs_notslash();
    bool after_slash = false;     /* previous token is an unescaped '/' (or SEGS) */
    int wild = 0;
    size_t i = 0;
#define FAIL(...) do { snprintf(emsg, en, __VA_ARGS__); prog_free(b.p); return NULL; } while (0)
#define TOK(ty, s) do { if (pb_tok(&b, (ty), (s)) < 0) FAIL("out of memory"); } while (0)
    while (i < len) {
        unsigned char ch = (unsigned char)c[i];
        if (ch == '\\') {
            if (i + 1 >= len) FAIL("glob ends in a lone backslash");
            bset_t one = bs_one((unsigned char)c[i + 1]);
            TOK(T_ONE, &one);
            after_slash = false;
            i += 2;
        } else if (ch == '*') {
            if (i + 1 < len && c[i + 1] == '*') {
                if (i + 2 < len && c[i + 2] == '*') FAIL("'***' in a glob is ambiguous");
                if (after_slash && i + 2 < len && c[i + 2] == '/') {
                    TOK(T_SEGS, NULL);          /* the '/' before is already a token */
                    i += 3;
                    after_slash = true;
                } else {
                    TOK(T_STAR, &any);
                    i += 2;
                    after_slash = false;
                }
            } else {
                TOK(T_STAR, &ns);
                i += 1;
                after_slash = false;
            }
            wild++;
        } else if (ch == '?') {
            TOK(T_ONE, &ns);
            wild++;
            after_slash = false;
            i++;
        } else if (ch == '[') {
            size_t j = i + 1;
            bool neg = false;
            if (j < len && (c[j] == '!' || c[j] == '^')) { neg = true; j++; }
            bset_t m = { { 0, 0, 0, 0 } };
            bool first = true, closed = false;
            while (j < len) {
                unsigned char x = (unsigned char)c[j];
                if (x == ']' && !first) { closed = true; j++; break; }
                first = false;
                if (x == '\\') {
                    if (j + 1 >= len) FAIL("glob ends in a lone backslash");
                    x = (unsigned char)c[++j];
                }
                j++;
                unsigned char y = x;
                if (j + 1 < len && c[j] == '-' && c[j + 1] != ']') {
                    j++;
                    y = (unsigned char)c[j];
                    if (y == '\\') {
                        if (j + 1 >= len) FAIL("glob ends in a lone backslash");
                        y = (unsigned char)c[++j];
                    }
                    j++;
                    if (y < x) FAIL("bad range %c-%c in a glob class", x, y);
                }
                for (unsigned v = x; v <= y; v++) {
                    if (v == '/') FAIL("'/' in a glob class never matches; write it outside the class");
                    bs_add(&m, v);
                }
            }
            if (!closed) FAIL("unterminated '[' in a glob");
            if (neg) {
                for (int w = 0; w < 4; w++) m.w[w] = ns.w[w] & ~m.w[w];
            }
            TOK(T_ONE, &m);
            wild++;
            after_slash = false;
            i = j;
        } else {
            bset_t one = bs_one(ch);
            TOK(T_ONE, &one);
            after_slash = (ch == '/');
            i++;
        }
        if (wild > VDP_GLOB_MAX_WILD) FAIL("more than %d wildcards in a glob", VDP_GLOB_MAX_WILD);
    }
#undef TOK
#undef FAIL
    return prog_done(&b);
}

/* Automaton state sets. A set is 2 * w1 words: bits 0..ntok of the first half
 * are the position states, bit k of the second half is "inside SEGS token k".
 * Every step is word-parallel over the tables built in prog_done, so a step
 * costs O(ntok / 64) whatever the number of active states. */
#define PW(p) (2 * (p)->w1)
#define ST_MAXW (2 * ((VDP_STR_MAX + 3 + 63) / 64))   /* ntok <= VDP_STR_MAX + 2 */

static inline bool st_has(const uint64_t *S, size_t q) { return (S[q >> 6] >> (q & 63)) & 1; }

/* Forward skips: a position state k whose token is STAR or SEGS also puts
 * k + 1 in the set, transitively along a run of such tokens. With K the skip
 * mask and Y = P & K, the sum Y + K carries from each bit of Y to the end of
 * its run of K (runs are separated by a 0 bit, which stops the carry), and
 * (Y + K) ^ K holds exactly the bits from the lowest bit of Y in each run to
 * one past the run's end. */
static void prog_close(const struct vdp_prog *p, uint64_t *S) {
    size_t W = p->w1;
    uint64_t c = 0;
    for (size_t w = 0; w < W; w++) {
        uint64_t k = p->skipm[w], y = S[w] & k;
        uint64_t s = y + k;
        uint64_t c1 = s < y;
        uint64_t s2 = s + c;
        uint64_t c2 = s2 < s;
        S[w] |= s2 ^ k;
        c = c1 | c2;
    }
}

static void prog_start(const struct vdp_prog *p, uint64_t *S) {
    memset(S, 0, PW(p) * sizeof *S);
    S[0] = 1;
    prog_close(p, S);
}

/* T := step(S, b); returns true if T is non-empty. */
static bool prog_step(const struct vdp_prog *p, const uint64_t *S, unsigned b, uint64_t *T) {
    size_t W = p->w1;
    const uint64_t *P = S, *I = S + W, *m = p->bm + (size_t)b * W;
    uint64_t *TP = T, *TI = T + W;
    uint64_t carry = 0, carry2 = 0;
    bool slash = (b == '/');
    for (size_t w = 0; w < W; w++) {
        uint64_t aw = P[w] & m[w];
        uint64_t one = aw & p->onem[w];
        uint64_t segs = P[w] & p->segsm[w];
        uint64_t in = I[w] | segs;                 /* SEGS: any byte stays inside */
        TI[w] = in;
        TP[w] = (one << 1) | carry | (aw & p->starm[w]);
        carry = one >> 63;
        if (slash) {                               /* '/' ends the segment run */
            TP[w] |= (in << 1) | carry2;
            carry2 = in >> 63;
        }
    }
    prog_close(p, TP);
    for (size_t w = 0; w < 2 * W; w++) if (T[w]) return true;
    return false;
}

static bool prog_match(const struct vdp_prog *p, const char *s, size_t sl) {
    if (sl < p->minlen || (p->exact && sl != p->minlen)) return false;
    if (memcmp(s, p->pre, p->npre) || memcmp(s + sl - p->nsuf, p->suf, p->nsuf)) return false;
    if (p->nmid > p->npre && p->nmid > p->nsuf && !memmem(s, sl, p->mid, p->nmid)) return false;
    uint64_t A[ST_MAXW], B[ST_MAXW];
    uint64_t *S = A, *T = B;
    /* The literal prefix matched above; the only way through it is one token
     * per byte, so the automaton resumes in state npre. */
    memset(S, 0, PW(p) * sizeof *S);
    S[p->npre >> 6] |= 1ull << (p->npre & 63);
    prog_close(p, S);
    for (size_t i = p->npre; i < sl; i++) {
        unsigned b = (unsigned char)s[i];
        if (!b || !prog_step(p, S, b, T)) return false;
        uint64_t *x = S; S = T; T = x;
    }
    return st_has(S, p->ntok);
}

const char *vdp_matcher_prefix(const vdp_rule_t *r) {
    switch (r->s.op) {
        case VDP_STR_PREFIX:   return r->kind == VDP_KIND_PATH ? "" : "prefix ";
        case VDP_STR_EQ:       return r->kind == VDP_KIND_EXEC ? "" : "exact ";
        case VDP_STR_HOST:     return "";
        case VDP_STR_SUFFIX:   return "suffix ";
        case VDP_STR_CONTAINS: return "contains ";
        case VDP_STR_GLOB:     return "glob ";
    }
    return "";
}

/* v1.15: a witness that a glob matches, for the certificate. Runs the
 * automaton from the start (no fast path), keeps every state set, and walks
 * back from the accepting state to the start, recording for each STAR and
 * SEGS token the span of s it took. Returns 1 with the spans, 0 if s does not
 * match, -1 on allocation failure. */
static int prog_witness(const struct vdp_prog *p, const char *s, size_t sl,
                        uint32_t (*span)[2], size_t maxspan, size_t *nspan) {
    size_t W = PW(p), w1 = p->w1, n = p->ntok;
    uint64_t *S = malloc((sl + 1) * W * sizeof *S);
    long *start = malloc((n + 1) * sizeof *start), *end = malloc((n + 1) * sizeof *end);
    if (!S || !start || !end) { free(S); free(start); free(end); return -1; }
    int rc = 0;
    prog_start(p, S);
    for (size_t i = 0; i < sl; i++) {
        unsigned b = (unsigned char)s[i];
        if (!b || !prog_step(p, S + i * W, b, S + (i + 1) * W)) goto out;
    }
    if (!st_has(S + sl * W, n)) goto out;
    for (size_t k = 0; k <= n; k++) start[k] = end[k] = -1;

    /* Backward walk. (pos, q, in): position state q, or inside SEGS token q. */
    size_t pos = sl, q = n;
    bool in = false;
#define POS(P, Q) st_has(S + (P) * W, (Q))
#define INS(P, Q) st_has(S + (P) * W + w1, (Q))
#define TYPE(K) (p->tok[K].type)
#define TAKES(K, B) bs_has(&p->sets[p->tok[K].set], (B))
    while (pos > 0 || q > 0 || in) {
        if (in) {                                  /* inside SEGS token q, pos > 0 */
            if (POS(pos - 1, q)) { in = false; pos--; start[q] = (long)pos; }
            else if (INS(pos - 1, q)) pos--;
            else { rc = -1; goto out; }
            continue;
        }
        if (q < n && (TYPE(q) == T_STAR || TYPE(q) == T_SEGS)) start[q] = (long)pos;
        unsigned b = pos ? (unsigned char)s[pos - 1] : 0;
        if (q > 0 && TYPE(q - 1) != T_ONE && POS(pos, q - 1)) {
            /* the skip over token q-1 (STAR ends, or SEGS is empty) */
            end[q - 1] = (long)pos;
            q--;
        } else if (pos > 0 && q > 0 && TYPE(q - 1) == T_ONE && TAKES(q - 1, b) && POS(pos - 1, q - 1)) {
            pos--; q--;
        } else if (pos > 0 && q < n && TYPE(q) == T_STAR && TAKES(q, b) && POS(pos - 1, q)) {
            pos--;                                 /* the star took one more byte */
        } else if (pos > 0 && q > 0 && TYPE(q - 1) == T_SEGS && b == '/' &&
                   (POS(pos - 1, q - 1) || INS(pos - 1, q - 1))) {
            end[q - 1] = (long)pos;                /* SEGS ends with this '/' */
            if (POS(pos - 1, q - 1)) { pos--; q--; start[q] = (long)pos; }
            else { pos--; q--; in = true; }
        } else { rc = -1; goto out; }              /* cannot happen: S is exact */
    }
    /* The walk ends in the start state, which may be inside a first STAR. */
    if (n > 0 && TYPE(0) == T_STAR) start[0] = 0;
#undef POS
#undef INS
#undef TYPE
#undef TAKES
    *nspan = 0;
    for (size_t k = 0; k < n; k++) {
        if (TYPE_IS_STRETCH(p->tok[k].type)) {
            if (*nspan >= maxspan || start[k] < 0 || end[k] < start[k]) { rc = -1; goto out; }
            span[*nspan][0] = (uint32_t)start[k];
            span[*nspan][1] = (uint32_t)end[k];
            (*nspan)++;
        }
    }
    rc = 1;
out:
    free(S); free(start); free(end);
    return rc;
}

int vdp_certificate(const vdp_policy_t *p, int rule_index, const char *s, vdp_cert_t *c) {
    memset(c, 0, sizeof *c);
    c->rule = rule_index;
    if (rule_index < 0) return 0;                  /* symbolic, several rules */
    if ((size_t)rule_index >= p->n) return -1;
    const vdp_str_atom_t *a = &p->rules[rule_index].s;
    size_t sl = strnlen(s, VDP_STR_MAX + 1);
    if (a->op == VDP_STR_CONTAINS) {
        const char *hit = memmem(s, sl, a->c, a->len);
        if (!hit) return -1;
        c->wkind = VDP_WIT_OFFSET;
        c->off = (uint32_t)(hit - s);
        return 0;
    }
    if (a->op == VDP_STR_GLOB) {
        size_t ns = 0;
        if (prog_witness(a->prog, s, sl, c->span, VDP_GLOB_MAX_WILD, &ns) != 1) return -1;
        c->wkind = VDP_WIT_SPANS;
        c->nspan = (uint32_t)ns;
        return 0;
    }
    return 0;
}

/* v1.16: the policy's glob size, in tokens (at most VDP_GLOB_MAX_TOTAL). With
 * the length bound it bounds the matching work of one decision. */
size_t vdp_policy_glob_tokens(const vdp_policy_t *p) {
    size_t t = 0;
    for (size_t i = 0; i < p->n; i++)
        if (p->rules[i].s.prog) t += p->rules[i].s.prog->ntok;
    return t;
}

void vdp_policy_free(vdp_policy_t *p) {
    if (!p) return;
    for (size_t i = 0; i < p->n; i++) {
        prog_free(p->rules[i].s.prog);
        p->rules[i].s.prog = NULL;
    }
}

/* ------------------------------------------------------------------------ */
/* Policy parsing                                                            */
/* ------------------------------------------------------------------------ */

static int vdp_policy_load_inner(const char *path, FILE *f, vdp_policy_t *p, char *err, size_t errlen);

static int perr(char *err, size_t errlen, const char *path, int line,
                const char *fmt, ...) {
    if (err && errlen) {
        int n = snprintf(err, errlen, "%s:%d: ", path, line);
        if (n < 0) n = 0;
        if ((size_t)n < errlen) {
            va_list ap;
            va_start(ap, fmt);
            vsnprintf(err + n, errlen - (size_t)n, fmt, ap);
            va_end(ap);
        }
    }
    return -1;
}

/* "<digits>.<digits>", nothing else (sscanf would also take signs and
 * spaces); -1 otherwise. */
static int parse_version(const char *s, int *maj, int *mn) {
    int *out[2] = { maj, mn };
    for (int part = 0; part < 2; part++) {
        long v = 0;
        int nd = 0;
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (*s++ - '0');
            if (++nd > 6) return -1;
        }
        if (!nd) return -1;
        *out[part] = (int)v;
        if (part == 0 && *s++ != '.') return -1;
    }
    return *s ? -1 : 0;
}

/* Is t a flag clause (syntactically)? Used to tell a matcher keyword from a
 * v1.13 constant that happens to be spelt like one. */
static bool is_flag_clause(const char *t) {
    return !strcmp(t, "readonly") || !strcmp(t, "access=ro") || !strcmp(t, "access=wo") ||
           !strcmp(t, "access=rw") || ((t[0] == '+' || t[0] == '-') && vdp_flag_bit(t + 1));
}

static const struct { const char *name; vdp_str_op_t op; } kMatchers[] = {
    { "exact", VDP_STR_EQ }, { "prefix", VDP_STR_PREFIX }, { "suffix", VDP_STR_SUFFIX },
    { "contains", VDP_STR_CONTAINS }, { "glob", VDP_STR_GLOB },
};

/* Merge (mask, value) into a rule's bitvector atom; -1 on contradiction. */
static int bv_add(vdp_bv_atom_t *b, uint32_t mask, uint32_t value) {
    uint32_t overlap = b->mask & mask;
    if ((b->value & overlap) != (value & overlap)) return -1;
    b->mask  |= mask;
    b->value |= value & mask;
    return 0;
}

int vdp_policy_load(const char *path, vdp_policy_t *p, char *err, size_t errlen) {
    memset(p, 0, sizeof(*p));
    FILE *f = fopen(path, "re");
    if (!f) return perr(err, errlen, path, 0, "cannot open: %s", strerror(errno));
    int rc = vdp_policy_load_inner(path, f, p, err, errlen);
    if (rc < 0) { vdp_policy_free(p); p->n = 0; }
    return rc;
}

int vdp_policy_load_mem(const char *name, const char *buf, size_t len, vdp_policy_t *p,
                        char *err, size_t errlen) {
    memset(p, 0, sizeof(*p));
    if (len == 0) return 0;                        /* an empty policy: no rules */
    FILE *f = fmemopen((void *)buf, len, "r");
    if (!f) return perr(err, errlen, name, 0, "cannot read policy: %s", strerror(errno));
    int rc = vdp_policy_load_inner(name, f, p, err, errlen);
    if (rc < 0) { vdp_policy_free(p); p->n = 0; }
    return rc;
}

static int vdp_policy_load_inner(const char *path, FILE *f, vdp_policy_t *p, char *err, size_t errlen) {

    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    int lineno = 0;
    int rc = 0;
    int req_maj = 0, req_min = 0;       /* highest `require warden` seen so far */
    int legacy_name_line = 0;           /* v1.24: a host name read before `require warden 1.24` */
    size_t glob_tokens = 0;
    while ((got = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (memchr(line, '\0', (size_t)got)) {
            rc = perr(err, errlen, path, lineno, "NUL byte in line"); break;
        }
        /* Tokenize on whitespace. */
        char *tok[64];
        int nt = 0;
        char *save = NULL;
        for (char *t = strtok_r(line, " \t\r\n\v\f", &save); t;
             t = strtok_r(NULL, " \t\r\n\v\f", &save)) {
            if (nt == 0 && t[0] == '#') break;          /* comment line */
            if (nt > 0 && t[0] == '#') break;           /* trailing comment */
            if (nt >= (int)(sizeof tok / sizeof tok[0])) {
                rc = perr(err, errlen, path, lineno, "too many tokens"); goto out;
            }
            tok[nt++] = t;
        }
        if (nt == 0) continue;
        if (!strcmp(tok[0], "require")) {
            int maj = -1, mn = -1;
            if (nt != 3 || strcmp(tok[1], "warden") || parse_version(tok[2], &maj, &mn) < 0) {
                rc = perr(err, errlen, path, lineno, "bad directive (need: require warden <major>.<minor>)");
                break;
            }
            if (maj > VDP_WARDEN_MAJOR || (maj == VDP_WARDEN_MAJOR && mn > VDP_WARDEN_MINOR)) {
                rc = perr(err, errlen, path, lineno, "policy requires Warden %d.%d; this is %d.%d",
                          maj, mn, VDP_WARDEN_MAJOR, VDP_WARDEN_MINOR);
                break;
            }
            if (legacy_name_line && (maj > 1 || (maj == 1 && mn >= 24))) {
                rc = perr(err, errlen, path, lineno,
                          "require warden %d.%d after a host name (line %d) that it would give "
                          "a new meaning; put the directive before the host rules",
                          maj, mn, legacy_name_line);
                break;
            }
            if (maj > req_maj || (maj == req_maj && mn > req_min)) { req_maj = maj; req_min = mn; }
            continue;
        }
        if (nt < 3) { rc = perr(err, errlen, path, lineno, "bad rule (need: verb kind constant)"); break; }
        if (p->n >= VDP_MAX_RULES) {
            rc = perr(err, errlen, path, lineno,
                      "more than %d rules; refusing to drop any", VDP_MAX_RULES);
            break;
        }
        vdp_rule_t *r = &p->rules[p->n];
        memset(r, 0, sizeof(*r));
        r->line = lineno;

        if      (!strcmp(tok[0], "allow")) r->verb = VDP_ALLOW;
        else if (!strcmp(tok[0], "deny"))  r->verb = VDP_DENY;
        else { rc = perr(err, errlen, path, lineno, "unknown verb %s", tok[0]); break; }

        if      (!strcmp(tok[1], "path")) { r->kind = VDP_KIND_PATH; r->s.op = VDP_STR_PREFIX; }
        else if (!strcmp(tok[1], "host")) { r->kind = VDP_KIND_HOST; r->s.op = VDP_STR_HOST; }
        else if (!strcmp(tok[1], "exec")) { r->kind = VDP_KIND_EXEC; r->s.op = VDP_STR_EQ; }
        else { rc = perr(err, errlen, path, lineno, "unknown kind %s", tok[1]); break; }

        /* v1.14 matcher: a keyword followed by a constant that is not itself a
         * flag clause (so `allow path glob readonly`, a v1.13 prefix rule for
         * the constant "glob", keeps its meaning). */
        int ci = 2;
        for (size_t m = 0; m < sizeof kMatchers / sizeof kMatchers[0]; m++) {
            if (strcmp(tok[2], kMatchers[m].name)) continue;
            if (nt < 4 || is_flag_clause(tok[3])) {
                /* A v1.13 constant spelt like a keyword keeps its meaning, but a
                 * policy that requires 1.14 or later means a matcher here, so a
                 * missing constant (or one a '#' turned into a comment) is an
                 * error rather than a prefix rule for the word. */
                if (req_maj > 1 || (req_maj == 1 && req_min >= 14)) {
                    rc = perr(err, errlen, path, lineno,
                              "matcher '%s' without a constant (a constant may not start "
                              "with '#'; write `prefix %s` for a constant named %s)",
                              tok[2], tok[2], tok[2]);
                    goto out;
                }
                continue;
            }
            if (r->kind == VDP_KIND_HOST) {
                rc = perr(err, errlen, path, lineno,
                          "matcher '%s' on a host rule (matchers apply to path and exec rules)",
                          tok[2]);
                goto out;
            }
            r->s.op = kMatchers[m].op;
            ci = 3;
            break;
        }
        const char *cs = tok[ci];
        size_t cl = strlen(cs);
        if (cl == 0 || cl > VDP_STR_MAX) {
            rc = perr(err, errlen, path, lineno, "constant length %zu out of range", cl); break;
        }
        for (size_t k = 0; k < cl; k++) {
            unsigned char ch = (unsigned char)cs[k];
            if (ch < 0x20 || ch == 0x7f) {
                rc = perr(err, errlen, path, lineno, "control byte 0x%02x in constant", ch);
                goto out;
            }
        }
        memcpy(r->s.c, cs, cl + 1);
        r->s.len = cl;
        if (r->kind == VDP_KIND_HOST) {
            /* v1.24: a constant in name form is a host name after `require
             * warden 1.24`, and must then be a valid one; before it, it keeps
             * its v1.21 meaning (an exact string, which no connect produces). */
            char why[160];
            int nf = vdp_host_name_form(cs, cl, why, sizeof why);
            /* v1.25: *.<suffix>[:port], after `require warden 1.25`. */
            if (cl >= 2 && cs[0] == '*' && cs[1] == '.' && (req_maj > 1 || (req_maj == 1 && req_min >= 24))) {
                if (!(req_maj > 1 || (req_maj == 1 && req_min >= 25))) {
                    rc = perr(err, errlen, path, lineno, "a wildcard host name needs `require warden 1.25`");
                    break;
                }
                char g[VDP_STR_MAX + 1];
                if (vdp_host_wildcard_glob(cs, cl, g, sizeof g, why, sizeof why) < 0) {
                    rc = perr(err, errlen, path, lineno, "bad wildcard host name: %s", why);
                    break;
                }
                size_t gl = strlen(g);
                memcpy(r->s.c, g, gl + 1);
                r->s.len = gl;
                r->s.op = VDP_STR_GLOB;
                r->s.name = r->s.wild = true;
                r->s.portless = false;
            } else if (nf != 0 && (req_maj > 1 || (req_maj == 1 && req_min >= 24))) {
                if (nf < 0) { rc = perr(err, errlen, path, lineno, "bad host name: %s", why); break; }
                r->s.name = true;
                r->s.portless = !memchr(cs, ':', cl);
            } else {
                if (nf != 0 && !legacy_name_line) legacy_name_line = lineno;
                r->s.portless = vdp_host_portless(cs, cl);
            }
        }
        if (r->s.op == VDP_STR_GLOB) {
            char gm[160] = "out of memory";
            r->s.prog = prog_glob(r->s.c, r->s.len, gm, sizeof gm);
            if (!r->s.prog) { rc = perr(err, errlen, path, lineno, "%s", gm); break; }
            glob_tokens += r->s.prog->ntok;
            if (glob_tokens > VDP_GLOB_MAX_TOTAL) {
                p->n++;
                rc = perr(err, errlen, path, lineno,
                          "glob patterns total more than %d tokens (bounds the work per decision)",
                          VDP_GLOB_MAX_TOTAL);
                break;
            }
        }
        p->n++;             /* counted now so vdp_policy_free releases the glob */

        for (int i = ci + 1; i < nt; i++) {
            const char *t = tok[i];
            if (r->kind != VDP_KIND_PATH) {
                rc = perr(err, errlen, path, lineno, "flag clause '%s' on a non-path rule", t); goto out;
            }
            uint32_t mask, value;
            if (!strcmp(t, "readonly")) {
                /* access=ro alone is NOT read-only on Linux: O_RDONLY|O_TRUNC
                 * truncates and O_RDONLY|O_CREAT creates. readonly also
                 * requires O_CREAT and O_TRUNC clear. */
                mask  = K_O_ACCMODE | K_O_CREAT | K_O_TRUNC;
                value = 0;
            }
            else if (!strcmp(t, "access=ro")) { mask = K_O_ACCMODE; value = 0; }
            else if (!strcmp(t, "access=wo")) { mask = K_O_ACCMODE; value = 1; }
            else if (!strcmp(t, "access=rw")) { mask = K_O_ACCMODE; value = 2; }
            else if ((t[0] == '+' || t[0] == '-') && vdp_flag_bit(t + 1)) {
                mask  = vdp_flag_bit(t + 1);
                value = (t[0] == '+') ? mask : 0;
            } else {
                rc = perr(err, errlen, path, lineno, "unknown flag clause '%s'", t); goto out;
            }
            if (bv_add(&r->b, mask, value) < 0) {
                rc = perr(err, errlen, path, lineno, "contradictory flag clause '%s'", t); goto out;
            }
        }
    }
out:
    free(line);
    fclose(f);
    return rc;
}

/* ------------------------------------------------------------------------ */
/* Atoms                                                                     */
/* ------------------------------------------------------------------------ */

/* v1.21: a dotted-quad IPv4 address as a connect spells it: four decimal
 * parts of 1 to 3 digits, each at most 255, no leading zero. */
bool vdp_host_is_ipv4(const char *c, size_t cl) {
    size_t i = 0;
    for (int part = 0; part < 4; part++) {
        if (part && (i >= cl || c[i++] != '.')) return false;
        size_t st = i;
        unsigned v = 0;
        while (i < cl && c[i] >= '0' && c[i] <= '9' && i - st < 3) v = v * 10 + (unsigned)(c[i++] - '0');
        if (i == st || v > 255 || (i - st > 1 && c[st] == '0')) return false;
    }
    return i == cl;
}

/* v1.21: a host constant without a port matches that address on any port: an
 * IPv4 address ("127.0.0.1"), or a bracketed IPv6 address ("[::1]"), whose
 * colons are inside the brackets. Any other constant matches only itself.
 * Through v1.20 every colon-free constant matched "<constant>:<anything>", so
 * `allow host unix` matched every Unix socket (unix:<path>) once v1.21 began
 * deciding them; and "[::1]" matched only the string "[::1]", which no connect
 * produces. The certificate checker (vdp_checker.c) and the cross-check oracle
 * (tools/smt_crosscheck.py) have the same rule. */
bool vdp_host_portless(const char *c, size_t cl) {
    if (!memchr(c, ':', cl)) return vdp_host_is_ipv4(c, cl);
    return cl >= 2 && c[0] == '[' && c[cl - 1] == ']' && !memchr(c + 1, ']', cl - 2);
}

/* v1.24: is c a host constant in name form, and a valid one? See smt_decide.h
 * for the form. 0: not in name form (a numeric form: '[', "unix:", or digits
 * and dots before the first ':'); 1: a valid name constant; -1: in name form
 * but invalid, the reason in why. */
int vdp_host_name_form(const char *c, size_t cl, char *why, size_t wn) {
    if ((cl >= 1 && c[0] == '[') || (cl >= 5 && !memcmp(c, "unix:", 5))) return 0;
    const char *colon = memchr(c, ':', cl);
    size_t hl = colon ? (size_t)(colon - c) : cl;
    bool numeric = true;
    for (size_t i = 0; i < hl; i++)
        if (!((c[i] >= '0' && c[i] <= '9') || c[i] == '.')) { numeric = false; break; }
    if (numeric) return 0;
#define BAD(...) do { snprintf(why, wn, __VA_ARGS__); return -1; } while (0)
    if (memchr(c, '*', hl))
        BAD("a '*' may only be the whole leftmost label of a wildcard (*.example.com), which "
            "needs `require warden 1.25`");
    if (c[hl - 1] == '.') BAD("a trailing dot is not allowed (write the name without it)");
    for (size_t i = 0; i < hl; i++) {
        unsigned char ch = (unsigned char)c[i];
        if (ch >= 'A' && ch <= 'Z') BAD("host names are written in lowercase");
        if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.'))
            BAD("a host name has only a-z, 0-9, '-' and '.' (an internationalized name is "
                "written as its A-labels, xn--...)");
    }
    if (hl > 253) BAD("a host name is at most 253 bytes");
    size_t st = 0;
    bool digits = true;
    for (size_t i = 0; i <= hl; i++) {
        if (i < hl && c[i] != '.') continue;
        size_t ll = i - st;
        if (ll == 0) BAD("empty label");
        if (ll > 63) BAD("a label is at most 63 bytes");
        if (c[st] == '-' || c[i - 1] == '-') BAD("a label cannot start or end with '-'");
        digits = true;
        for (size_t k = st; k < i; k++) if (c[k] < '0' || c[k] > '9') { digits = false; break; }
        st = i + 1;
    }
    if (digits) BAD("the last label is all digits (an address is written a.b.c.d)");
    if (hl == 4 && !memcmp(c, "unix", 4)) BAD("unix is reserved (unix:/path names a Unix socket)");
    if (colon) {
        const char *port = colon + 1;
        size_t pl = cl - hl - 1, k = 0;
        unsigned long v = 0;
        for (; k < pl && k < 6 && port[k] >= '0' && port[k] <= '9'; k++) v = v * 10 + (unsigned)(port[k] - '0');
        if (pl == 0 || k != pl || v > 65535 || (pl > 1 && port[0] == '0'))
            BAD("the port must be a decimal number from 0 to 65535 without leading zeros");
    }
#undef BAD
    return 1;
}

static bool str_holds(const vdp_str_atom_t *a, const char *s, size_t sl) {
    switch (a->op) {
        case VDP_STR_PREFIX:
            return sl >= a->len && memcmp(s, a->c, a->len) == 0;
        case VDP_STR_EQ:
            return sl == a->len && memcmp(s, a->c, a->len) == 0;
        case VDP_STR_HOST:
            if (sl == a->len && memcmp(s, a->c, a->len) == 0) return true;
            if (!a->portless) return false;
            return sl > a->len && memcmp(s, a->c, a->len) == 0 && s[a->len] == ':';
        case VDP_STR_SUFFIX:
            return sl >= a->len && memcmp(s + sl - a->len, a->c, a->len) == 0;
        case VDP_STR_CONTAINS:
            return memmem(s, sl, a->c, a->len) != NULL;
        case VDP_STR_GLOB:
            return a->prog && prog_match(a->prog, s, sl);
    }
    return false;
}

static inline bool bv_holds(const vdp_bv_atom_t *b, uint32_t f) {
    return (f & b->mask) == b->value;
}

static int popcount32(uint32_t x) { return __builtin_popcount(x); }

/* Enumerate every subset of `bits` (as values of f). cb returns false to stop.
 * Caller guarantees popcount(bits) <= VDP_MAX_ENUM_BITS. */
static void enum_subsets(uint32_t bits, bool (*cb)(uint32_t f, void *ud), void *ud) {
    uint32_t sub = 0;
    for (;;) {
        if (!cb(sub, ud)) return;
        if (sub == bits) return;
        sub = (sub - bits) & bits;     /* next subset (Gray-free standard trick) */
    }
}

/* ------------------------------------------------------------------------ */
/* Decide                                                                    */
/* ------------------------------------------------------------------------ */

struct sym_ctx {
    const vdp_policy_t *p;
    const int *cand;          /* indices of rules whose string atom holds */
    size_t n;
    int outcome;              /* -2 unset, -1 none, else verb */
    int first_rule;
    bool mixed;
    bool multi_rule;          /* same outcome reached through different rules */
};

static bool sym_cb(uint32_t f, void *ud) {
    struct sym_ctx *c = ud;
    if ((f & K_O_ACCMODE) == K_O_ACCMODE) return true;   /* outside the fragment */
    int oc = -1, ri = -1;
    for (size_t k = 0; k < c->n; k++) {
        const vdp_rule_t *r = &c->p->rules[c->cand[k]];
        if (bv_holds(&r->b, f)) { oc = (int)r->verb; ri = c->cand[k]; break; }
    }
    if (c->outcome == -2) { c->outcome = oc; c->first_rule = ri; }
    else if (c->outcome != oc) { c->mixed = true; return false; }
    else if (c->first_rule != ri) c->multi_rule = true;
    return true;
}

vdp_verdict_t vdp_decide(const vdp_policy_t *p, vdp_kind_t kind, const char *s,
                         uint32_t flags, bool has_flags,
                         int *rule_index, vdp_why_t *why) {
    int dummy_idx; vdp_why_t dummy_why;
    if (!rule_index) rule_index = &dummy_idx;
    if (!why) why = &dummy_why;
    *rule_index = -1;

    size_t sl = strnlen(s, VDP_STR_MAX + 1);
    if (sl > VDP_STR_MAX) { *why = VDP_WHY_LENGTH_GUARD; return VDP_UNKNOWN; }

#ifdef VDP_FAULT_INJECT
    /* TEST BUILDS ONLY (make warden_faultinject, tests/test_v1150.sh): a
     * planted bug. A path ending in "/.inject" is decided SATISFIED by the last
     * allow path rule, whatever the policy says, so the test can show that the
     * certificate checker, not the procedure, has the last word. */
    if (kind == VDP_KIND_PATH && sl >= 8 && !memcmp(s + sl - 8, "/.inject", 8)) {
        for (size_t i = p->n; i-- > 0;) {
            if (p->rules[i].kind == VDP_KIND_PATH && p->rules[i].verb == VDP_ALLOW) {
                *rule_index = (int)i;
                *why = VDP_WHY_RULE;
                return VDP_SATISFIED;
            }
        }
    }
#endif

    bool ground = (kind != VDP_KIND_PATH) || has_flags;
    if (kind == VDP_KIND_PATH && has_flags && (flags & ~VDP_KNOWN_OFLAGS)) {
        *why = VDP_WHY_UNKNOWN_FLAGS;
        return VDP_UNKNOWN;
    }
    if (kind == VDP_KIND_PATH && has_flags && (flags & K_O_ACCMODE) == K_O_ACCMODE) {
        *why = VDP_WHY_ACCESS_MODE_3;
        return VDP_UNKNOWN;
    }
    if (kind != VDP_KIND_PATH) flags = 0;   /* non-path rules carry no bv atom */

    if (ground) {
        for (size_t i = 0; i < p->n; i++) {
            const vdp_rule_t *r = &p->rules[i];
            if (r->kind != kind) continue;
            if (str_holds(&r->s, s, sl) && bv_holds(&r->b, flags)) {
                *rule_index = (int)i;
                *why = VDP_WHY_RULE;
                return r->verb == VDP_ALLOW ? VDP_SATISFIED : VDP_UNSATISFIED;
            }
        }
        *why = VDP_WHY_NO_RULE;
        return VDP_UNKNOWN;
    }

    /* Symbolic flags (path, has_flags false). */
    int cand[VDP_MAX_RULES];
    size_t n = 0;
    uint32_t bits = 0;
    for (size_t i = 0; i < p->n; i++) {
        const vdp_rule_t *r = &p->rules[i];
        if (r->kind != kind || !str_holds(&r->s, s, sl)) continue;
        cand[n++] = (int)i;
        bits |= r->b.mask;
        if (r->b.mask == 0) break;          /* holds for every f: later rules unreachable */
    }
    if (n == 0) { *why = VDP_WHY_NO_RULE; return VDP_UNKNOWN; }
    if (popcount32(bits) > VDP_MAX_ENUM_BITS) { *why = VDP_WHY_ENUM_BOUND; return VDP_UNKNOWN; }

    struct sym_ctx c = { .p = p, .cand = cand, .n = n, .outcome = -2, .first_rule = -1 };
    enum_subsets(bits, sym_cb, &c);
    if (c.mixed) { *why = VDP_WHY_SYMBOLIC_MIXED; return VDP_UNKNOWN; }
    if (c.outcome < 0) { *why = VDP_WHY_NO_RULE; return VDP_UNKNOWN; }
    *rule_index = c.multi_rule ? -1 : c.first_rule;   /* -1: several rules agree */
    *why = VDP_WHY_RULE;
    return c.outcome == (int)VDP_ALLOW ? VDP_SATISFIED : VDP_UNSATISFIED;
}

/* ------------------------------------------------------------------------ */
/* Reachability: is there (s, f) with rule i the first holding rule?         */
/* ------------------------------------------------------------------------ */
/*
 * Truth of every string atom on s depends only on (a) which elements of D are
 * prefixes of s, and (b) whether s equals a constant, where D is the set of all
 * constants of this kind (plus c ++ ":" for portless host constants). Every
 * such class that contains a string of length <= VDP_STR_MAX contains one of:
 *
 *   - an element of D (covers s equal to a constant, and s == d in D);
 *   - d ++ x for d in D or d == "", where x is a byte such that d ++ x is a
 *     prefix of no element of D (covers every other s: take d = the longest
 *     element of D that is a prefix of s);
 *   - "" (the empty string).
 *
 * If some d has no such byte x (all 255 continuations used), the class may be
 * missed, so the answer degrades to UNKNOWN rather than DEAD.
 *
 * For a candidate s, J = { j < i of this kind : S_j(s) }. Rule i fires first
 * on (s, f) iff B_i(f) and no j in J has B_j(f). That is decided by
 * enumerating the free bits of the masks in J (bounded; beyond the bound the
 * answer degrades to UNKNOWN).
 */

struct dset { char **v; size_t *len; size_t n, cap; };

static int dset_add(struct dset *d, const char *s, size_t l) {
    for (size_t i = 0; i < d->n; i++)
        if (d->len[i] == l && memcmp(d->v[i], s, l) == 0) return 0;
    if (d->n == d->cap) {
        size_t nc = d->cap ? d->cap * 2 : 16;
        char **nv = realloc(d->v, nc * sizeof *nv);
        if (!nv) return -1;
        d->v = nv;
        size_t *nl = realloc(d->len, nc * sizeof *nl);
        if (!nl) return -1;
        d->len = nl;
        d->cap = nc;
    }
    char *c = malloc(l + 2);
    if (!c) return -1;
    memcpy(c, s, l);
    c[l] = '\0';
    d->v[d->n] = c;
    d->len[d->n] = l;
    d->n++;
    return 0;
}

static void dset_free(struct dset *d) {
    for (size_t i = 0; i < d->n; i++) free(d->v[i]);
    free(d->v);
    free(d->len);
    memset(d, 0, sizeof *d);
}

/* A byte x such that (prefix ++ x) is a prefix of no element of D; 0 if none. */
static unsigned char fresh_byte(const struct dset *D, const char *pre, size_t pl) {
    bool used[256] = { false };
    used[0] = true;
    for (size_t i = 0; i < D->n; i++)
        if (D->len[i] > pl && memcmp(D->v[i], pre, pl) == 0)
            used[(unsigned char)D->v[i][pl]] = true;
    /* Prefer readable witnesses. */
    for (int c = 'a'; c <= 'z'; c++) if (!used[c]) return (unsigned char)c;
    for (int c = 1; c < 256; c++) if (!used[c]) return (unsigned char)c;
    return 0;
}

/* Exists f ⊆ KNOWN: B_i(f) and no j in J has B_j(f)?  1 yes (f in *fout),
 * 0 no, -1 bound. */
static int bv_first_possible(const vdp_policy_t *p, size_t i, const int *J, size_t nj,
                             uint32_t *fout) {
    const vdp_bv_atom_t *bi = &p->rules[i].b;
    uint32_t free_bits = 0;
    for (size_t k = 0; k < nj; k++) {
        const vdp_bv_atom_t *bj = &p->rules[J[k]].b;
        if (bj->mask == 0) return 0;                     /* B_j always holds */
        /* If B_i's fixed bits already contradict B_j, B_j can never hold. */
        uint32_t ov = bi->mask & bj->mask;
        if ((bi->value & ov) != (bj->value & ov)) continue;
        free_bits |= bj->mask & ~bi->mask;
    }
    if (popcount32(free_bits) > VDP_MAX_ENUM_BITS) return -1;
    uint32_t sub = 0;
    for (;;) {
        uint32_t f = bi->value | sub;
        bool ok = (f & K_O_ACCMODE) != K_O_ACCMODE;       /* in the fragment */
        for (size_t k = 0; k < nj && ok; k++)
            if (bv_holds(&p->rules[J[k]].b, f)) ok = false;
        if (ok) { *fout = f; return 1; }
        if (sub == free_bits) break;
        sub = (sub - free_bits) & free_bits;
    }
    return 0;
}

static __thread const char *g_reach_why = "";
const char *vdp_reach_unknown_reason(void) { return g_reach_why; }
const char *vdp_reach_unknown_text(void) {
    if (!strcmp(g_reach_why, "state_budget")) return "the automaton search hit its state budget";
    if (!strcmp(g_reach_why, "witness_alphabet"))
        return "a constant is followed by every byte value in other constants";
    return "outside the enumeration bound";
}
bool vdp_reach_force_automaton = false;

static void put_witness(char *wit, size_t wcap, size_t *wlen, const char *s, size_t sl) {
    if (wlen) *wlen = sl;
    if (!wit || !wcap) return;
    size_t k = sl < wcap - 1 ? sl : wcap - 1;
    memcpy(wit, s, k);
    wit[k] = '\0';
}

static vdp_reach_t reach_trie(const vdp_policy_t *p, size_t i, char *wit, size_t wcap,
                              size_t *wlen, uint32_t *wflags) {
    const vdp_rule_t *ri = &p->rules[i];
    vdp_kind_t kind = ri->kind;

    struct dset D = {0};
    for (size_t j = 0; j <= i; j++) {
        const vdp_rule_t *r = &p->rules[j];
        if (r->kind != kind) continue;
        if (dset_add(&D, r->s.c, r->s.len) < 0) { dset_free(&D); return VDP_REACH_UNKNOWN; }
        if (r->s.op == VDP_STR_HOST && r->s.portless) {
            char tmp[VDP_STR_MAX + 2];
            memcpy(tmp, r->s.c, r->s.len);
            tmp[r->s.len] = ':';
            if (dset_add(&D, tmp, r->s.len + 1) < 0) { dset_free(&D); return VDP_REACH_UNKNOWN; }
        }
    }

    /* Candidate witnesses. */
    struct dset W = {0};
    bool incomplete = false;
    int rc_oom = 0;
    rc_oom |= dset_add(&W, "", 0);
    for (size_t k = 0; k < D.n; k++) rc_oom |= dset_add(&W, D.v[k], D.len[k]);
    {
        unsigned char x = fresh_byte(&D, "", 0);
        if (!x) incomplete = true;
        else { char t[2] = { (char)x, 0 }; rc_oom |= dset_add(&W, t, 1); }
    }
    for (size_t k = 0; k < D.n; k++) {
        if (D.len[k] + 1 > VDP_STR_MAX) continue;      /* any longer s is out of bound */
        unsigned char x = fresh_byte(&D, D.v[k], D.len[k]);
        if (!x) { incomplete = true; continue; }
        char *t = malloc(D.len[k] + 2);
        if (!t) { rc_oom = -1; break; }
        memcpy(t, D.v[k], D.len[k]);
        t[D.len[k]] = (char)x;
        t[D.len[k] + 1] = '\0';
        rc_oom |= dset_add(&W, t, D.len[k] + 1);
        free(t);
    }
    if (rc_oom) { dset_free(&D); dset_free(&W); return VDP_REACH_UNKNOWN; }

    vdp_reach_t res = VDP_DEAD;
    bool bound = false;
    int J[VDP_MAX_RULES];
    for (size_t w = 0; w < W.n && res != VDP_REACHABLE; w++) {
        const char *s = W.v[w];
        size_t sl = W.len[w];
        if (sl > VDP_STR_MAX || !str_holds(&ri->s, s, sl)) continue;
        size_t nj = 0;
        for (size_t j = 0; j < i; j++) {
            const vdp_rule_t *r = &p->rules[j];
            if (r->kind == kind && str_holds(&r->s, s, sl)) J[nj++] = (int)j;
        }
        uint32_t f = 0;
        int b = bv_first_possible(p, i, J, nj, &f);
        if (b == 1) {
            res = VDP_REACHABLE;
            put_witness(wit, wcap, wlen, s, sl);
            if (wflags) *wflags = f;
        }
        else if (b < 0) bound = true;
    }
    if (res == VDP_DEAD && (incomplete || bound)) {
        res = VDP_REACH_UNKNOWN;
        g_reach_why = bound ? "enumeration_bound" : "witness_alphabet";
    }
    dset_free(&D);
    dset_free(&W);
    return res;
}

/* ------------------------------------------------------------------------ */
/* Reachability by automaton product search (v1.14)                          */
/* ------------------------------------------------------------------------ */
/*
 * Once a kind has a suffix, contains or glob rule, the witness set above no
 * longer covers every class of strings, so reachability is decided on the
 * rules' automata instead. Every string atom of the kind is a program (above).
 *
 * Bytes are grouped into classes on which every set of every program involved
 * (and the test b == '/') agrees; one representative per class suffices.
 *
 * For a set S of earlier rules, "rule i fires first on some s" (flags aside)
 * is  L_i \ U_{j in S} L_j  containing a string of length <= VDP_STR_MAX. A
 * breadth-first search over tuples of per-rule DFA states (built lazily by
 * subset construction) finds the shortest such string, so the length bound is
 * decided exactly: the search does not expand past depth VDP_STR_MAX.
 *
 * Flags: S depends on f. With J the earlier rules whose flag atom is
 * compatible with B_i and whose language meets L_i, S(f) = { j in J : B_j(f) }.
 * Reachability is monotone (S subset of S' and Reach(S') imply Reach(S)), so
 * only the inclusion-minimal S(f) over the enumerated f need a search; first
 * the rules whose B_j holds whenever B_i does (S_always, a subset of every
 * S(f)) are tried, and if that search is DEAD so is the rule.
 *
 * With no competing rule the search is not needed: a program's shortest string
 * takes one byte per ONE token and none for STAR / SEGS (prog_shortest).
 *
 * Budgets: VDP_MAX_ENUM_BITS free flag bits, LD_MAX_STATES DFA states per rule,
 * PROD_MAX_INTS for one product search and REACH_WORK for the whole query.
 * Past a budget the answer is UNKNOWN (never a guessed DEAD or REACHABLE).
 */

#define LD_MAX_STATES  (1u << 14)
#define PROD_MAX_INTS  (1u << 22)
#define REACH_WORK     (1ull << 23)   /* per query: DFA words stepped + tuple components */

static __thread unsigned long long g_work;

enum { LF_ACC = 1, LF_UNIV = 2, LF_EMPTY = 4 };

struct ldfa {
    const struct vdp_prog *pg;
    size_t    W;          /* words per state set */
    uint64_t *st;         /* n * W */
    uint8_t  *fl;         /* LF_* per state */
    int      *tr;         /* n * ncls, -1 = not computed */
    size_t    n, cap, ncls;
    int      *ht;         /* open addressing, -1 empty */
    size_t    htcap;
    int       any_set;    /* index of the ANY set in pg, or -1 */
};

static uint64_t hash_words(const uint64_t *w, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) { h ^= w[i]; h *= 1099511628211ull; h ^= h >> 29; }
    return h;
}

static void ld_free(struct ldfa *L) {
    free(L->st); free(L->fl); free(L->tr); free(L->ht);
    memset(L, 0, sizeof *L);
}

static int ld_rehash(struct ldfa *L, size_t nc) {
    int *nh = malloc(nc * sizeof *nh);
    if (!nh) return -1;
    for (size_t k = 0; k < nc; k++) nh[k] = -1;
    for (size_t id = 0; id < L->n; id++) {
        size_t h = (size_t)hash_words(L->st + id * L->W, L->W) & (nc - 1);
        while (nh[h] >= 0) h = (h + 1) & (nc - 1);
        nh[h] = (int)id;
    }
    free(L->ht);
    L->ht = nh;
    L->htcap = nc;
    return 0;
}

/* Intern a state set; returns its id, or -1 (budget / memory). */
static int ld_intern(struct ldfa *L, const uint64_t *S) {
    size_t h = (size_t)hash_words(S, L->W) & (L->htcap - 1);
    while (L->ht[h] >= 0) {
        int id = L->ht[h];
        if (!memcmp(L->st + (size_t)id * L->W, S, L->W * sizeof *S)) return id;
        h = (h + 1) & (L->htcap - 1);
    }
    if (L->n >= LD_MAX_STATES) return -1;
    if (L->n == L->cap) {
        size_t nc = L->cap * 2;
        uint64_t *ns = realloc(L->st, nc * L->W * sizeof *ns);
        if (!ns) return -1;
        L->st = ns;
        uint8_t *nf = realloc(L->fl, nc);
        if (!nf) return -1;
        L->fl = nf;
        int *nt = realloc(L->tr, nc * L->ncls * sizeof *nt);
        if (!nt) return -1;
        L->tr = nt;
        L->cap = nc;
    }
    size_t id = L->n++;
    memcpy(L->st + id * L->W, S, L->W * sizeof *S);
    for (size_t c = 0; c < L->ncls; c++) L->tr[id * L->ncls + c] = -1;
    const struct vdp_prog *p = L->pg;
    uint8_t f = 0;
    bool empty = true;
    for (size_t w = 0; w < L->W; w++) if (S[w]) { empty = false; break; }
    if (empty) f |= LF_EMPTY;
    if (st_has(S, p->ntok)) f |= LF_ACC;
    /* Universal: the last token is STAR(any byte) and we are at it, so every
     * continuation stays accepted. (A sufficient test; used only to prune.) */
    if (p->ntok && p->tok[p->ntok - 1].type == T_STAR &&
        (int)p->tok[p->ntok - 1].set == L->any_set && st_has(S, p->ntok - 1))
        f |= LF_UNIV;
    L->fl[id] = f;
    if (2 * L->n > L->htcap && ld_rehash(L, L->htcap * 2) < 0) return -1;
    h = (size_t)hash_words(S, L->W) & (L->htcap - 1);
    while (L->ht[h] >= 0) h = (h + 1) & (L->htcap - 1);
    L->ht[h] = (int)id;
    return (int)id;
}

static int ld_init(struct ldfa *L, const struct vdp_prog *pg, size_t ncls) {
    memset(L, 0, sizeof *L);
    L->pg = pg;
    L->W = PW(pg);
    L->ncls = ncls;
    L->cap = 16;
    L->st = malloc(L->cap * L->W * sizeof *L->st);
    L->fl = malloc(L->cap);
    L->tr = malloc(L->cap * ncls * sizeof *L->tr);
    L->htcap = 64;
    L->ht = malloc(L->htcap * sizeof *L->ht);
    if (!L->st || !L->fl || !L->tr || !L->ht) return -1;
    for (size_t k = 0; k < L->htcap; k++) L->ht[k] = -1;
    bset_t any = bs_any();
    L->any_set = -1;
    for (size_t k = 0; k < pg->nsets; k++) if (bs_eq(&pg->sets[k], &any)) L->any_set = (int)k;
    uint64_t S[ST_MAXW];
    prog_start(pg, S);
    return ld_intern(L, S) == 0 ? 0 : -1;       /* the start state is id 0 */
}

static int ld_next(struct ldfa *L, int id, size_t cls, unsigned rep) {
    int *slot = &L->tr[(size_t)id * L->ncls + cls];
    if (*slot >= 0) return *slot;
    uint64_t T[ST_MAXW];
    g_work += L->W;
    prog_step(L->pg, L->st + (size_t)id * L->W, rep, T);
    int nid = ld_intern(L, T);           /* may move L->tr */
    if (nid >= 0) L->tr[(size_t)id * L->ncls + cls] = nid;
    return nid;
}

/* Shortest string of a program alone: a byte from each ONE token's set, nothing
 * for STAR and SEGS. 1 (written to buf, length in *len) or 0 (a set is empty
 * or the string would pass the bound). */
static int prog_shortest(const struct vdp_prog *p, char *buf, size_t *len) {
    size_t n = 0;
    for (size_t k = 0; k < p->ntok; k++) {
        if (p->tok[k].type != T_ONE) continue;
        const bset_t *s = &p->sets[p->tok[k].set];
        int b = -1;
        for (unsigned c = 'a'; c <= 'z' && b < 0; c++) if (bs_has(s, c)) b = (int)c;
        for (unsigned c = 1; c < 256 && b < 0; c++) if (bs_has(s, c)) b = (int)c;
        if (b < 0 || n >= VDP_STR_MAX) return 0;
        buf[n++] = (char)b;
    }
    *len = n;
    return 1;
}

static size_t tup_hash(const int *t, size_t m) {
    uint64_t h = 1469598103934665603ull;
    for (size_t q = 0; q < m; q++) { h ^= (uint64_t)(uint32_t)t[q]; h *= 1099511628211ull; h ^= h >> 31; }
    return (size_t)h;
}

/* Product search. comp[0] is rule i's automaton; comp[1..m-1] are others.
 * inter == false: accept when comp[0] accepts and no other does (rule i
 *                 fires first); others that reach the empty set drop out.
 * inter == true:  m == 2, accept when both accept (the languages meet).
 * Returns 1 (witness written), 0 (no string of length <= VDP_STR_MAX), or -1
 * (budget). */
static int prod_search(struct ldfa **comp, size_t m, bool inter, const unsigned char *rep,
                       size_t ncls, char *wit, size_t wcap, size_t *wlen) {
    size_t cap = 256, n = 0;
    int *tup = malloc(cap * m * sizeof *tup);
    int *par = malloc(cap * sizeof *par);
    uint8_t *via = malloc(cap);
    uint16_t *dep = malloc(cap * sizeof *dep);
    size_t htcap = 1024;
    int *ht = malloc(htcap * sizeof *ht);
    int *cur = malloc(m * sizeof *cur);
    int res = -1;
    if (m == 1 && !inter) {
        char buf[VDP_STR_MAX + 1];
        size_t len = 0;
        res = prog_shortest(comp[0]->pg, buf, &len);
        if (res == 1) put_witness(wit, wcap, wlen, buf, len);
        goto done;
    }
    if (!tup || !par || !via || !dep || !ht || !cur) goto done;
    for (size_t k = 0; k < htcap; k++) ht[k] = -1;

    /* start tuple */
    for (size_t k = 0; k < m; k++) {
        uint8_t f = comp[k]->fl[0];
        if (k == 0 || inter) {
            if (f & LF_EMPTY) { res = 0; goto done; }
            cur[k] = 0;
        } else {
            if (f & LF_UNIV) { res = 0; goto done; }
            cur[k] = (f & LF_EMPTY) ? -1 : 0;
        }
    }
    memcpy(tup, cur, m * sizeof *cur);
    par[0] = -1; via[0] = 0; dep[0] = 0; n = 1;
    {
        size_t h = tup_hash(cur, m) & (htcap - 1);
        ht[h] = 0;
    }
    for (size_t head = 0; head < n; head++) {
        const int *t = tup + head * m;
        bool acc = comp[0]->fl[t[0]] & LF_ACC;
        for (size_t k = 1; k < m && acc; k++) {
            if (inter) acc = comp[k]->fl[t[k]] & LF_ACC;
            else if (t[k] >= 0 && (comp[k]->fl[t[k]] & LF_ACC)) acc = false;
        }
        if (acc) {
            size_t len = dep[head];
            char buf[VDP_STR_MAX + 1];
            size_t pos = len;
            for (int x = (int)head; par[x] >= 0; x = par[x]) buf[--pos] = (char)rep[via[x]];
            put_witness(wit, wcap, wlen, buf, len);
            res = 1;
            goto done;
        }
        if (dep[head] >= VDP_STR_MAX) continue;
        g_work += m * ncls;
        if (g_work > REACH_WORK) { res = -1; goto done; }
        for (size_t c = 0; c < ncls; c++) {
            const int *tt = tup + head * m;        /* tup may move below */
            bool dead = false;
            for (size_t k = 0; k < m && !dead; k++) {
                if (tt[k] < 0) { cur[k] = -1; continue; }
                int nx = ld_next(comp[k], tt[k], c, rep[c]);
                if (nx < 0) { res = -1; goto done; }
                tt = tup + head * m;
                uint8_t f = comp[k]->fl[nx];
                if (k == 0 || inter) { if (f & LF_EMPTY) dead = true; cur[k] = nx; }
                else if (f & LF_UNIV) dead = true;
                else cur[k] = (f & LF_EMPTY) ? -1 : nx;
            }
            if (dead) continue;
            size_t h = tup_hash(cur, m) & (htcap - 1);
            bool seen = false;
            while (ht[h] >= 0) {
                if (!memcmp(tup + (size_t)ht[h] * m, cur, m * sizeof *cur)) { seen = true; break; }
                h = (h + 1) & (htcap - 1);
            }
            if (seen) continue;
            if ((n + 1) * m > PROD_MAX_INTS) { res = -1; goto done; }
            if (n == cap) {
                size_t nc = cap * 2;
                int *a = realloc(tup, nc * m * sizeof *a); if (!a) goto done; tup = a;
                int *b = realloc(par, nc * sizeof *b); if (!b) goto done; par = b;
                uint8_t *v = realloc(via, nc); if (!v) goto done; via = v;
                uint16_t *d = realloc(dep, nc * sizeof *d); if (!d) goto done; dep = d;
                cap = nc;
            }
            memcpy(tup + n * m, cur, m * sizeof *cur);
            par[n] = (int)head; via[n] = (uint8_t)c; dep[n] = (uint16_t)(dep[head] + 1);
            ht[h] = (int)n;
            n++;
            if (2 * n > htcap) {
                size_t nc = htcap * 2;
                int *nh = malloc(nc * sizeof *nh);
                if (!nh) goto done;
                for (size_t k = 0; k < nc; k++) nh[k] = -1;
                for (size_t x = 0; x < n; x++) {
                    size_t hh = tup_hash(tup + x * m, m) & (nc - 1);
                    while (nh[hh] >= 0) hh = (hh + 1) & (nc - 1);
                    nh[hh] = (int)x;
                }
                free(ht); ht = nh; htcap = nc;
            }
        }
    }
    res = 0;
done:
    free(tup); free(par); free(via); free(dep); free(ht); free(cur);
    return res;
}

/* Refine the byte classes by one set. */
static void refine(unsigned char *cls, size_t *ncls, const bset_t *s) {
    int map[256][2];
    for (size_t k = 0; k < *ncls; k++) map[k][0] = map[k][1] = -1;
    size_t nn = 0;
    unsigned char out[256];
    for (unsigned b = 1; b < 256; b++) {
        int in = bs_has(s, b);
        int *slot = &map[cls[b]][in];
        if (*slot < 0) *slot = (int)nn++;
        out[b] = (unsigned char)*slot;
    }
    memcpy(cls + 1, out + 1, 255);
    *ncls = nn;
}

static vdp_reach_t reach_automaton(const vdp_policy_t *p, size_t i, char *wit, size_t wcap,
                                   size_t *wlen, uint32_t *wflags) {
    const vdp_rule_t *ri = &p->rules[i];
    vdp_kind_t kind = ri->kind;
    const vdp_bv_atom_t *bi = &ri->b;

    /* Candidates: rule i, then earlier same-kind rules whose flag atom can hold
     * together with B_i. */
    int cand[VDP_MAX_RULES];
    size_t nc = 0;
    cand[nc++] = (int)i;
    for (size_t j = 0; j < i; j++) {
        const vdp_rule_t *r = &p->rules[j];
        if (r->kind != kind) continue;
        uint32_t ov = bi->mask & r->b.mask;
        if ((bi->value & ov) != (r->b.value & ov)) continue;
        cand[nc++] = (int)j;
    }

    struct vdp_prog *owned[VDP_MAX_RULES] = { 0 };
    const struct vdp_prog *pg[VDP_MAX_RULES];
    struct ldfa L[VDP_MAX_RULES];
    size_t nld = 0;
    vdp_reach_t res = VDP_REACH_UNKNOWN;
    const char *why = "state_budget";
    g_work = 0;
    uint64_t (*sets)[4] = NULL;
    uint32_t *setf = NULL;
    size_t nsets = 0;

    for (size_t k = 0; k < nc; k++) {
        const vdp_str_atom_t *a = &p->rules[cand[k]].s;
        if (a->op == VDP_STR_GLOB) pg[k] = a->prog;
        else pg[k] = owned[k] = prog_from_atom(a->op, a->c, a->len);
        if (!pg[k]) goto out;
    }

    /* Byte classes. */
    unsigned char cls[256] = { 0 };
    size_t ncls = 1;
    bset_t slash = bs_one('/');
    refine(cls, &ncls, &slash);
    for (size_t k = 0; k < nc; k++)
        for (size_t s = 0; s < pg[k]->nsets; s++) refine(cls, &ncls, &pg[k]->sets[s]);
    unsigned char rep[256];
    bool have[256] = { false };
    /* Prefer readable representatives. */
    for (unsigned b = 'a'; b <= 'z'; b++) if (!have[cls[b]]) { have[cls[b]] = true; rep[cls[b]] = (unsigned char)b; }
    for (unsigned b = 1; b < 256; b++) if (!have[cls[b]]) { have[cls[b]] = true; rep[cls[b]] = (unsigned char)b; }

    for (nld = 0; nld < nc; nld++)
        if (ld_init(&L[nld], pg[nld], ncls) < 0) { nld++; goto out; }

    /* J: candidates whose language meets L_i. A rule that never meets L_i is
     * left out of every search: its automaton may never reach the empty set
     * (a contains rule does not), so it would only multiply the product. */
    int J[VDP_MAX_RULES];
    size_t nj = 0;
    for (size_t k = 1; k < nc; k++) {
        struct ldfa *two[2] = { &L[0], &L[k] };
        int r = prod_search(two, 2, true, rep, ncls, NULL, 0, NULL);
        if (r != 0) J[nj++] = (int)k;       /* budget: keep it (conservative) */
    }

    /* S_always: B_j holds whenever B_i does. */
    struct ldfa *comp[VDP_MAX_RULES];
    size_t m = 0;
    comp[m++] = &L[0];
    uint32_t free_bits = 0;
    for (size_t x = 0; x < nj; x++) {
        const vdp_bv_atom_t *bj = &p->rules[cand[J[x]]].b;
        if ((bj->mask & ~bi->mask) == 0) comp[m++] = &L[J[x]];
        else free_bits |= bj->mask & ~bi->mask;
    }
    char wb[VDP_STR_MAX + 1];
    size_t wl = 0;
    int r = prod_search(comp, m, false, rep, ncls, wb, sizeof wb, &wl);
    if (r == 0) { res = VDP_DEAD; goto out; }
    if (r < 0) goto out;
    if (free_bits == 0) {
        res = VDP_REACHABLE;
        put_witness(wit, wcap, wlen, wb, wl);
        if (wflags) *wflags = bi->value;     /* access mode of B_i is 0..2 or free (0) */
        goto out;
    }
    if (popcount32(free_bits) > VDP_MAX_ENUM_BITS) { why = "enumeration_bound"; goto out; }

    /* Enumerate f; collect the distinct S(f) (as bitsets over J positions). */
    size_t scap = 64;
    sets = malloc(scap * sizeof *sets);
    setf = malloc(scap * sizeof *setf);
    if (!sets || !setf) goto out;
    uint32_t sub = 0;
    for (;;) {
        uint32_t f = bi->value | sub;
        if ((f & K_O_ACCMODE) != K_O_ACCMODE) {
            uint64_t s[4] = { 0, 0, 0, 0 };
            for (size_t x = 0; x < nj; x++)
                if (bv_holds(&p->rules[cand[J[x]]].b, f)) s[x >> 6] |= 1ull << (x & 63);
            bool dup = false;
            for (size_t q = 0; q < nsets && !dup; q++) dup = !memcmp(sets[q], s, sizeof s);
            if (!dup) {
                if (nsets == scap) {
                    scap *= 2;
                    uint64_t (*ns)[4] = realloc(sets, scap * sizeof *ns);
                    if (!ns) goto out;
                    sets = ns;
                    uint32_t *nf = realloc(setf, scap * sizeof *nf);
                    if (!nf) goto out;
                    setf = nf;
                }
                memcpy(sets[nsets], s, sizeof s);
                setf[nsets++] = f;
            }
        }
        if (sub == free_bits) break;
        sub = (sub - free_bits) & free_bits;
    }

    bool budget = false;
    res = VDP_DEAD;
    for (size_t q = 0; q < nsets; q++) {
        bool minimal = true;              /* no other distinct set strictly inside */
        for (size_t o = 0; o < nsets && minimal; o++) {
            if (o == q) continue;
            bool sub_o = true;
            for (int w = 0; w < 4; w++) if (sets[o][w] & ~sets[q][w]) sub_o = false;
            if (sub_o) minimal = false;
        }
        if (!minimal) continue;
        m = 0;
        comp[m++] = &L[0];
        for (size_t x = 0; x < nj; x++)
            if ((sets[q][x >> 6] >> (x & 63)) & 1) comp[m++] = &L[J[x]];
        r = prod_search(comp, m, false, rep, ncls, wb, sizeof wb, &wl);
        if (r == 1) {
            res = VDP_REACHABLE;
            put_witness(wit, wcap, wlen, wb, wl);
            if (wflags) *wflags = setf[q];
            break;
        }
        if (r < 0) budget = true;
    }
    if (res == VDP_DEAD && budget) res = VDP_REACH_UNKNOWN;

out:
    if (res == VDP_REACH_UNKNOWN) g_reach_why = why;
    free(sets);
    free(setf);
    for (size_t k = 0; k < nld; k++) ld_free(&L[k]);
    for (size_t k = 0; k < nc; k++) prog_free(owned[k]);
    return res;
}

vdp_reach_t vdp_rule_reachable_witness(const vdp_policy_t *p, size_t i,
                                       char *wit, size_t wcap, size_t *wlen,
                                       uint32_t *wflags) {
    g_reach_why = "";
    if (wlen) *wlen = 0;
    if (wit && wcap) wit[0] = '\0';
    if (i >= p->n) return VDP_REACH_UNKNOWN;
    vdp_kind_t kind = p->rules[i].kind;
    bool automaton = false;
    if (kind != VDP_KIND_HOST) {
        automaton = vdp_reach_force_automaton;
        for (size_t j = 0; j <= i && !automaton; j++) {
            const vdp_rule_t *r = &p->rules[j];
            if (r->kind == kind && (r->s.op == VDP_STR_SUFFIX || r->s.op == VDP_STR_CONTAINS ||
                                    r->s.op == VDP_STR_GLOB))
                automaton = true;
        }
    }
    return automaton ? reach_automaton(p, i, wit, wcap, wlen, wflags)
                     : reach_trie(p, i, wit, wcap, wlen, wflags);
}

vdp_reach_t vdp_rule_reachable(const vdp_policy_t *p, size_t i) {
    return vdp_rule_reachable_witness(p, i, NULL, 0, NULL, NULL);
}

/* ------------------------------------------------------------------------ */
/* Advisories                                                                */
/* ------------------------------------------------------------------------ */

#define K_FCNTL_MUTABLE (K_O_APPEND | K_O_NONBLOCK | K_FASYNC | K_O_DIRECT | K_O_NOATIME)

/* v1.21: is c a host constant a connect can produce? Fills why when not. */
bool vdp_host_constant_ok(const char *c, size_t cl, char *why, size_t wn) {
    char buf[VDP_STR_MAX + 1];
    if (cl > VDP_STR_MAX) cl = VDP_STR_MAX;
    memcpy(buf, c, cl);
    buf[cl] = '\0';
    if (!strncmp(buf, "unix:", 5)) {
        if (buf[5] != '/') {
            snprintf(why, wn, "a unix: constant must name an absolute path (the Warden decides on "
                     "the socket's canonical path)");
            return false;
        }
        return true;
    }
    char addr[VDP_STR_MAX + 1];
    const char *port = NULL;
    int fam;
    if (buf[0] == '[') {
        char *rb = strchr(buf, ']');
        if (!rb) goto name;
        size_t al = (size_t)(rb - buf - 1);
        memcpy(addr, buf + 1, al);
        addr[al] = '\0';
        if (rb[1] == ':') port = rb + 2;
        else if (rb[1] != '\0') goto name;
        fam = AF_INET6;
    } else {
        char *colon = strchr(buf, ':');
        size_t al = colon ? (size_t)(colon - buf) : cl;
        memcpy(addr, buf, al);
        addr[al] = '\0';
        if (colon) port = colon + 1;
        fam = AF_INET;
    }
    unsigned char bin[16];
    char canon[INET6_ADDRSTRLEN];
    if (inet_pton(fam, addr, bin) != 1) goto name;
    if (fam == AF_INET6 && !memcmp(bin, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12)) {
        inet_ntop(AF_INET, bin + 12, canon, sizeof canon);
        snprintf(why, wn, "an IPv4-mapped address is decided as its IPv4 form, %s", canon);
        return false;
    }
    inet_ntop(fam, bin, canon, sizeof canon);
    if (strcmp(canon, addr) != 0) {
        snprintf(why, wn, "the Warden spells this address %s%s%s", fam == AF_INET6 ? "[" : "",
                 canon, fam == AF_INET6 ? "]" : "");
        return false;
    }
    if (port) {
        unsigned long v = 0;
        size_t k = 0;
        for (; port[k] >= '0' && port[k] <= '9' && k < 6; k++) v = v * 10 + (unsigned)(port[k] - '0');
        if (k == 0 || port[k] || v > 65535 || (k > 1 && port[0] == '0')) {
            snprintf(why, wn, "the port must be a decimal number from 0 to 65535 without leading "
                     "zeros");
            return false;
        }
    }
    return true;
name:
    snprintf(why, wn, "not a numeric address: host rules match a.b.c.d[:port], [IPv6][:port], "
             "unix:/path, or a host name after `require warden 1.24`");
    return false;
}

int vdp_host_wildcard_glob(const char *c, size_t cl, char *out, size_t outn, char *why, size_t wn) {
    if (cl < 2 || c[0] != '*' || c[1] != '.') return 0;
    const char *rest = c + 2;
    size_t rl = cl - 2;
    if (vdp_host_name_form(rest, rl, why, wn) != 1) {
        if (vdp_host_name_form(rest, rl, why, wn) == 0)
            snprintf(why, wn, "the part after *. must be a host name");
        return -1;
    }
    const char *colon = memchr(rest, ':', rl);
    size_t hl = colon ? (size_t)(colon - rest) : rl;
    if (!memchr(rest, '.', hl)) {
        snprintf(why, wn, "*. must be followed by at least two labels (*.example.com, not *.com)");
        return -1;
    }
    int n = colon ? snprintf(out, outn, "?*.%.*s:%s", (int)hl, rest, colon + 1)
                  : snprintf(out, outn, "?*.%.*s:*", (int)hl, rest);
    if (n < 0 || (size_t)n >= outn) { snprintf(why, wn, "too long"); return -1; }
    return 1;
}

/* v1.24: can a connect ever match host rule r? Fills why when not. */
bool vdp_host_rule_ok(const vdp_rule_t *r, char *why, size_t wn) {
    if (r->kind != VDP_KIND_HOST || r->s.name) return true;
    char nw[160];
    if (vdp_host_name_form(r->s.c, r->s.len, nw, sizeof nw) != 0) {
        snprintf(why, wn, "a host name is matched only after `require warden 1.24` (before this "
                 "rule)");
        return false;
    }
    return vdp_host_constant_ok(r->s.c, r->s.len, why, wn);
}

size_t vdp_rule_advisory(const vdp_rule_t *r, char *buf, size_t n) {
    if (!n) return 0;
    buf[0] = '\0';
    size_t w = 0;
#define ADD(...) do { int k_ = snprintf(buf + w, n - w, __VA_ARGS__); \
                      if (k_ > 0) w = (w + (size_t)k_ < n) ? w + (size_t)k_ : n - 1; } while (0)
    uint32_t m = r->b.mask;
    if (m & K_FCNTL_MUTABLE) {
        ADD("%sclause on", w ? "; " : "");
        for (size_t i = 0; i < sizeof kFlagNames / sizeof kFlagNames[0]; i++)
            if (m & K_FCNTL_MUTABLE & kFlagNames[i].bit) ADD(" %s", kFlagNames[i].name);
        ADD(" constrains only the open() call: fcntl(F_SETFL) can change it afterwards");
    }
    if (m & K_O_LARGEFILE)
        ADD("%sO_LARGEFILE is set by the kernel on every 64-bit open; the clause "
            "constrains only what the agent passes", w ? "; " : "");
    if (m & (K_O_DSYNC | K___O_SYNC))
        ADD("%sclauses on O_DSYNC/O_SYNC constrain the flags as passed; the kernel "
            "adds O_DSYNC to an open that sets the O_SYNC bit alone", w ? "; " : "");
    if (r->kind != VDP_KIND_HOST) {
        const char *c = r->s.c;
        bool rel = false;
        if (r->s.op == VDP_STR_PREFIX || r->s.op == VDP_STR_EQ) rel = c[0] != '/';
        else if (r->s.op == VDP_STR_GLOB)
            rel = c[0] != '/' && c[0] != '*' && !(c[0] == '\\' && c[1] == '/');
        if (rel)
            ADD("%sthe constant does not start with '/', but the Warden decides on "
                "absolute resolved paths, so this rule matches no real action", w ? "; " : "");
    }
    /* v1.21: the Warden decides a connect on the numeric destination it will
     * dial, spelt as inet_ntop writes it: a.b.c.d:port, [IPv6]:port (an
     * IPv4-mapped IPv6 address as its IPv4 form), or unix:<canonical path>;
     * v1.24: or on name:port for the allowed names that resolved to it. A
     * constant in any other form can never match (a host name without
     * `require warden 1.24`: `deny host evil.example.com` never fired through
     * v1.20), so say so. */
    if (r->kind == VDP_KIND_HOST) {
        char why[160];
        if (!vdp_host_rule_ok(r, why, sizeof why))
            ADD("%s%s, so this rule can never match", w ? "; " : "", why);
    }
    for (size_t i = 0; i < r->s.len; i++) {
        if ((unsigned char)r->s.c[i] >= 0x80) {
            ADD("%sconstant contains non-ASCII bytes: check it is not a mistyped "
                "space or other invisible character", w ? "; " : "");
            break;
        }
    }
#undef ADD
    return w;
}
