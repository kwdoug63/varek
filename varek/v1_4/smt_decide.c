// SPDX-License-Identifier: MIT
// smt_decide.c — VAREK SMT decision procedure (v1.13; the v1.10 verification
// program). See smt_decide.h for the fragment, the verdict semantics and the
// soundness obligations.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "smt_decide.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
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
/* Policy parsing                                                            */
/* ------------------------------------------------------------------------ */

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

    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    int lineno = 0;
    int rc = 0;
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
            char tail = 0;
            if (nt != 3 || strcmp(tok[1], "warden") ||
                sscanf(tok[2], "%d.%d%c", &maj, &mn, &tail) != 2 || maj < 0 || mn < 0) {
                rc = perr(err, errlen, path, lineno, "bad directive (need: require warden <major>.<minor>)");
                break;
            }
            if (maj > VDP_WARDEN_MAJOR || (maj == VDP_WARDEN_MAJOR && mn > VDP_WARDEN_MINOR)) {
                rc = perr(err, errlen, path, lineno, "policy requires Warden %d.%d; this is %d.%d",
                          maj, mn, VDP_WARDEN_MAJOR, VDP_WARDEN_MINOR);
                break;
            }
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

        size_t cl = strlen(tok[2]);
        if (cl == 0 || cl > VDP_STR_MAX) {
            rc = perr(err, errlen, path, lineno, "constant length %zu out of range", cl); break;
        }
        for (size_t k = 0; k < cl; k++) {
            unsigned char ch = (unsigned char)tok[2][k];
            if (ch < 0x20 || ch == 0x7f) {
                rc = perr(err, errlen, path, lineno, "control byte 0x%02x in constant", ch);
                goto out;
            }
        }
        memcpy(r->s.c, tok[2], cl + 1);
        r->s.len = cl;

        for (int i = 3; i < nt; i++) {
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
        p->n++;
    }
out:
    free(line);
    fclose(f);
    return rc;
}

/* ------------------------------------------------------------------------ */
/* Atoms                                                                     */
/* ------------------------------------------------------------------------ */

static bool str_holds(const vdp_str_atom_t *a, const char *s, size_t sl) {
    switch (a->op) {
        case VDP_STR_PREFIX:
            return sl >= a->len && memcmp(s, a->c, a->len) == 0;
        case VDP_STR_EQ:
            return sl == a->len && memcmp(s, a->c, a->len) == 0;
        case VDP_STR_HOST:
            if (sl == a->len && memcmp(s, a->c, a->len) == 0) return true;
            if (memchr(a->c, ':', a->len)) return false;
            return sl > a->len && memcmp(s, a->c, a->len) == 0 && s[a->len] == ':';
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
 * constants of this kind (plus c ++ ":" for colon-free host constants). Every
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

/* Exists f ⊆ KNOWN: B_i(f) and no j in J has B_j(f)?  1 yes, 0 no, -1 bound. */
static int bv_first_possible(const vdp_policy_t *p, size_t i, const int *J, size_t nj) {
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
        if (ok) return 1;
        if (sub == free_bits) break;
        sub = (sub - free_bits) & free_bits;
    }
    return 0;
}

vdp_reach_t vdp_rule_reachable(const vdp_policy_t *p, size_t i) {
    if (i >= p->n) return VDP_REACH_UNKNOWN;
    const vdp_rule_t *ri = &p->rules[i];
    vdp_kind_t kind = ri->kind;

    struct dset D = {0};
    for (size_t j = 0; j <= i; j++) {
        const vdp_rule_t *r = &p->rules[j];
        if (r->kind != kind) continue;
        if (dset_add(&D, r->s.c, r->s.len) < 0) { dset_free(&D); return VDP_REACH_UNKNOWN; }
        if (r->s.op == VDP_STR_HOST && !memchr(r->s.c, ':', r->s.len)) {
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
        int b = bv_first_possible(p, i, J, nj);
        if (b == 1) res = VDP_REACHABLE;
        else if (b < 0) incomplete = true;
    }
    if (res == VDP_DEAD && incomplete) res = VDP_REACH_UNKNOWN;
    dset_free(&D);
    dset_free(&W);
    return res;
}

/* ------------------------------------------------------------------------ */
/* Advisories                                                                */
/* ------------------------------------------------------------------------ */

#define K_FCNTL_MUTABLE (K_O_APPEND | K_O_NONBLOCK | K_FASYNC | K_O_DIRECT | K_O_NOATIME)

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
