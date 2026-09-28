#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
smt_crosscheck.py — differential check of the Warden's SMT decision procedure
(smt_decide.c, driven through tools/vdp_check) against an SMT solver (Z3).

The policy is re-parsed here independently of the C parser and encoded in the
solver's string and bitvector theories:

    s : String, length <= L, every character in 1..255
    f : BitVec(32), no bit outside the ABI open(2) flag set K
    rule_i  :=  S_i(s) AND (f & m_i) == v_i
    S_i     :=  prefix(c, s) | s == c | s == c OR prefix(c ++ ":", s)

For every checked item the solver's answer must match the procedure's:

  ground     concrete (kind, s, f): the verdict of the first rule that holds.
  symbolic   concrete s, symbolic f (the --plan gate's file_open): SATISFIED iff
             no admissible f yields anything but SATISFIED (a universally
             quantified check), likewise UNSATISFIED, else UNKNOWN.
  reach      is there any (s, f) for which rule i is the first rule to hold?

Agreement rules (the gate):
  - a definite verdict (SATISFIED / UNSATISFIED / REACHABLE / DEAD) from the
    procedure must equal the solver's; any difference is a soundness failure;
  - an UNKNOWN from the procedure must equal the solver's UNKNOWN, except when
    the procedure reports its documented enumeration bound (conservative).

Usage:
  smt_crosscheck.py --vdp tools/vdp_check [--fuzz N] [--seed S] POLICY...
Exit 0 iff there are zero disagreements.
"""

import argparse
import json
import os
import random
import re
import subprocess
import sys
import tempfile

import z3

L = 4095
KNOWN = 0x007FFFC3
ACC = 0o3
FLAG_BITS = {
    "O_CREAT": 0o100, "O_EXCL": 0o200, "O_NOCTTY": 0o400, "O_TRUNC": 0o1000,
    "O_APPEND": 0o2000, "O_NONBLOCK": 0o4000, "O_DSYNC": 0o10000,
    "O_ASYNC": 0o20000, "O_DIRECT": 0o40000, "O_LARGEFILE": 0o100000,
    "O_DIRECTORY": 0o200000, "O_NOFOLLOW": 0o400000, "O_NOATIME": 0o1000000,
    "O_CLOEXEC": 0o2000000, "O_SYNC": 0o4000000, "O_PATH": 0o10000000,
    "O_TMPFILE": 0o20000000,
}


class PolicyError(Exception):
    pass


WS = re.compile(r"[ \t\r\n\v\f]+")        # ASCII whitespace only, as C strtok_r


def parse_policy(path):
    """Independent re-implementation of the policy grammar (smt_decide.h)."""
    rules = []
    with open(path, "rb") as fh:
        for lineno, raw in enumerate(fh, 1):
            if b"\0" in raw:
                raise PolicyError(f"{path}:{lineno}: NUL byte")
            text = raw.decode("latin-1")
            toks = []
            for t in WS.split(text):
                if not t:
                    continue
                if t.startswith("#"):
                    break
                toks.append(t)
            if not toks:
                continue
            if toks[0] == "require":
                m = re.fullmatch(r"(\d+)\.(\d+)", toks[2]) if len(toks) == 3 else None
                if len(toks) != 3 or toks[1] != "warden" or not m:
                    raise PolicyError(f"{path}:{lineno}: bad directive")
                if (int(m.group(1)), int(m.group(2))) > (1, 13):
                    raise PolicyError(f"{path}:{lineno}: requires newer Warden")
                continue
            if len(toks) < 3:
                raise PolicyError(f"{path}:{lineno}: bad rule")
            verb, kind, const = toks[0], toks[1], toks[2]
            if verb not in ("allow", "deny"):
                raise PolicyError(f"{path}:{lineno}: verb")
            if kind not in ("path", "host", "exec"):
                raise PolicyError(f"{path}:{lineno}: kind")
            if not (1 <= len(const) <= L):
                raise PolicyError(f"{path}:{lineno}: constant length")
            if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in const):
                raise PolicyError(f"{path}:{lineno}: control byte in constant")
            mask = value = 0
            for t in toks[3:]:
                if kind != "path":
                    raise PolicyError(f"{path}:{lineno}: flag clause on {kind}")
                if t == "readonly":
                    m, v = ACC | FLAG_BITS["O_CREAT"] | FLAG_BITS["O_TRUNC"], 0
                elif t in ("access=ro", "access=wo", "access=rw"):
                    m, v = ACC, {"access=ro": 0, "access=wo": 1, "access=rw": 2}[t]
                elif t[:1] in "+-" and t[1:] in FLAG_BITS:
                    m = FLAG_BITS[t[1:]]
                    v = m if t[0] == "+" else 0
                else:
                    raise PolicyError(f"{path}:{lineno}: flag clause {t}")
                ov = mask & m
                if (value & ov) != (v & ov):
                    raise PolicyError(f"{path}:{lineno}: contradictory")
                mask |= m
                value |= v & m
            rules.append({"verb": verb, "kind": kind, "c": const,
                          "mask": mask, "value": value, "line": lineno})
            if len(rules) > 256:
                raise PolicyError(f"{path}: more than 256 rules")
    return rules


# ---------------------------------------------------------------- encoding --

# Every solver object of one policy lives in its own Z3 context, dropped when
# the policy is done: a single global context accumulates every term of every
# query (gigabytes with near-bound constants).
CTX = None


def new_context():
    global CTX
    CTX = z3.Context()


def _byte_re():
    return z3.Range(chr(1), chr(255), ctx=CTX)


def fdomain(f):
    """Admissible flags: ABI bits only, and not access mode 3."""
    return z3.And((f & z3.BitVecVal(~KNOWN & 0xFFFFFFFF, 32, ctx=CTX)) == 0,
                  (f & z3.BitVecVal(ACC, 32, ctx=CTX)) != z3.BitVecVal(ACC, 32, ctx=CTX))


def domain(s, f):
    return z3.And(z3.Length(s) <= L, z3.InRe(s, z3.Star(_byte_re())), fdomain(f))


def str_atom(r, s):
    c = z3.StringVal(r["c"], ctx=CTX)
    if r["kind"] == "path":
        return z3.PrefixOf(c, s)
    if r["kind"] == "exec":
        return s == c
    if ":" in r["c"]:
        return s == c
    return z3.Or(s == c, z3.PrefixOf(z3.StringVal(r["c"] + ":", ctx=CTX), s))


def bv_atom(r, f):
    if r["mask"] == 0:
        return z3.BoolVal(True, ctx=CTX)
    return (f & z3.BitVecVal(r["mask"], 32, ctx=CTX)) == z3.BitVecVal(r["value"], 32, ctx=CTX)


def fires_first(rules, idx, s, f):
    """Rule idx holds and no earlier rule of its kind holds."""
    k = rules[idx]["kind"]
    here = z3.And(str_atom(rules[idx], s), bv_atom(rules[idx], f))
    before = [z3.Not(z3.And(str_atom(r, s), bv_atom(r, f)))
              for r in rules[:idx] if r["kind"] == k]
    return z3.And(here, *before)


def sat(*fs):
    so = z3.Solver(ctx=CTX)
    so.set("timeout", 20000)
    so.add(*fs)
    r = so.check()
    if r == z3.unknown:
        raise RuntimeError("solver returned unknown (timeout)")
    return r == z3.sat


def oracle_ground(rules, kind, sval, fval):
    s, f = z3.String("s", ctx=CTX), z3.BitVec("f", 32, ctx=CTX)
    fv = fval if (kind == "path" and fval is not None) else 0
    pin = [s == z3.StringVal(sval, ctx=CTX), f == z3.BitVecVal(fv, 32, ctx=CTX)]
    if not sat(domain(s, f), *pin):
        return "UNKNOWN"                      # outside the fragment
    for i, r in enumerate(rules):
        if r["kind"] != kind:
            continue
        if sat(domain(s, f), *pin, fires_first(rules, i, s, f)):
            return "SATISFIED" if r["verb"] == "allow" else "UNSATISFIED"
    return "UNKNOWN"


def oracle_symbolic(rules, sval):
    """path, concrete s, symbolic f. SATISFIED iff every admissible f is."""
    s, f = z3.String("s", ctx=CTX), z3.BitVec("f", 32, ctx=CTX)
    pin = s == z3.StringVal(sval, ctx=CTX)
    if not sat(domain(s, f), pin):
        return "UNKNOWN"
    idx = [i for i, r in enumerate(rules) if r["kind"] == "path"]
    allow_first = z3.Or([fires_first(rules, i, s, f) for i in idx
                         if rules[i]["verb"] == "allow"] or [z3.BoolVal(False, ctx=CTX)])
    deny_first = z3.Or([fires_first(rules, i, s, f) for i in idx
                        if rules[i]["verb"] == "deny"] or [z3.BoolVal(False, ctx=CTX)])
    if not sat(domain(s, f), pin, z3.Not(allow_first)):
        return "SATISFIED"
    if not sat(domain(s, f), pin, z3.Not(deny_first)):
        return "UNSATISFIED"
    return "UNKNOWN"


# Reachability uses a second, equivalent encoding of s: a length n and one
# 8-bit vector per character position. Z3's string theory does not finish on
# conjunctions of many negated prefixof constraints (the same tail pathology
# v1.5 measured), while this encoding is plain QF_BV + linear integer
# arithmetic. It is exact: every atom reads only positions below
# M = (longest constant) + 2, and positions >= M are unconstrained bytes, so
# any model extends to a string in the domain (length <= L, bytes 1..255).

class ByteStr:
    def __init__(self, rules):
        m = max([len(r["c"]) + 1 for r in rules] + [1]) + 1
        self.n = z3.Int("n", ctx=CTX)
        self.b = [z3.BitVec(f"b{k}", 8, ctx=CTX) for k in range(m)]

    def domain(self):
        # Length bound only. The byte range 1..255 needs no constraint: atoms
        # only compare positions with constant bytes, and the grammar forbids
        # bytes 0x00-0x20 and 0x7f in constants, so a 0 byte in a model acts
        # exactly like an unused byte in 1..255, which always exists at every
        # position (at most 222 values can occur). Dropping the ~4,100
        # implications a near-bound constant needed keeps the query fast; the
        # encoding stays exact.
        return z3.And(self.n >= 0, self.n <= L)

    def prefix(self, c):
        return z3.And(self.n >= len(c),
                      *[self.b[k] == ord(ch) for k, ch in enumerate(c)])

    def eq(self, c):
        return z3.And(self.n == len(c), self.prefix(c))


def str_atom_bytes(r, bs):
    c = r["c"]
    if r["kind"] == "path":
        return bs.prefix(c)
    if r["kind"] == "exec" or ":" in c:
        return bs.eq(c)
    # host(c, s) = s == c OR prefix(c ++ ":", s), written with the shared prefix
    # factored out: prefix(c, s) AND (|s| == |c| OR s[|c|] == ':'). Logically
    # identical; the solver times out on the unfactored disjunction of two long
    # conjunctions (a 4 KB constant) and answers the factored form instantly.
    k = len(c)
    at_k = bs.b[k] == ord(":") if k < len(bs.b) else z3.BoolVal(False, ctx=CTX)
    return z3.And(bs.prefix(c), z3.Or(bs.n == k, z3.And(bs.n >= k + 1, at_k)))


def oracle_reach(rules, i):
    bs = ByteStr(rules)
    f = z3.BitVec("f", 32, ctx=CTX)
    k = rules[i]["kind"]
    here = z3.And(str_atom_bytes(rules[i], bs), bv_atom(rules[i], f))
    before = [z3.Not(z3.And(str_atom_bytes(r, bs), bv_atom(r, f)))
              for r in rules[:i] if r["kind"] == k]
    return "REACHABLE" if sat(bs.domain(), fdomain(f), here, *before) else "DEAD"


# ------------------------------------------------------------ procedure IO --

def run_vdp(vdp, policy, mode, stdin=None):
    p = subprocess.run([vdp, policy, mode], input=stdin, capture_output=True,
                       text=True, timeout=600)
    return p.returncode, p.stdout, p.stderr


# ------------------------------------------------------------- query gen --

def rand_const_bytes(rng):
    """Occasionally non-ASCII bytes, never whitespace/control (as the grammar)."""
    return rng.choice(["\xa0", "\x85", "\xe9", "\xff", "\x80"])


def gen_queries(rules, rng, n):
    consts = {"path": [], "host": [], "exec": []}
    for r in rules:
        consts[r["kind"]].append(r["c"])
    out = []
    alphabet = "/ab:.x"
    for _ in range(n):
        kind = rng.choice(["path", "path", "path", "host", "exec"])
        base = rng.choice(consts[kind]) if consts[kind] and rng.random() < 0.85 else ""
        choice = rng.random()
        if choice < 0.25:
            sval = base
        elif choice < 0.55:
            sval = base + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 4)))
        elif choice < 0.75 and base:
            sval = base[: rng.randint(0, len(base))]
        elif choice < 0.8:
            sval = "/" * (L + rng.randint(1, 3))            # over the length bound
        else:
            sval = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
        if kind == "host" and base and ":" not in base and rng.random() < 0.4:
            sval = base + ":" + str(rng.choice([80, 443, 8080]))
        if kind == "path":
            r = rng.random()
            if r < 0.2:
                fval = None                                   # symbolic
            elif r < 0.25:
                fval = rng.choice([0x80000000, 0x01000000, 0x0800000,       # unknown bits
                                   0x3, 0x203, 0x43])                        # access mode 3
            else:
                fval = rng.getrandbits(32) & KNOWN & rng.choice(
                    [0x3, 0x243, 0x7FFFC3, 0x40 | 0x200 | 0x3, 0x400 | 0x3])
        else:
            fval = 0
        out.append((kind, sval, fval))
    return out


FLAG_CLAUSES = ["readonly", "access=ro", "access=wo", "access=rw"] + \
    [sign + name for name in FLAG_BITS for sign in "+-"]


def fuzz_policy(rng, path):
    frags = ["/a", "/a/", "/a/b", "/ab", "/b/", "/a/b/c", "x", "x:1", "/"]
    lines = []
    if rng.random() < 0.3:
        lines.append(rng.choice(["require warden 1.13", "require warden 1.12",
                                 "require warden 1.14", "require warden x"]))
    wide = rng.random() < 0.2           # many distinct flag bits: reach the bound
    for _ in range(rng.randint(1, 9)):
        kind = rng.choice(["path", "path", "path", "host", "exec"])
        c = rng.choice(frags) + rng.choice(["", "", "a", "/", ":2"])
        r = rng.random()
        if r < 0.05:
            c = "/" + "d" * rng.randint(L - 8, L + 2)     # near / over the length bound
        elif r < 0.12:
            c = c + rand_const_bytes(rng)                  # non-ASCII byte in a constant
        verb = rng.choice(["allow", "deny"])
        clauses = []
        if kind == "path":
            if wide:
                # distinct flag names, random signs: up to 19 relevant bits,
                # enough to reach the procedure's 16-bit enumeration bound
                names = rng.sample(sorted(FLAG_BITS), rng.randint(8, len(FLAG_BITS)))
                clauses += [rng.choice("+-") + n for n in names]
                if rng.random() < 0.5:
                    clauses.append(rng.choice(["access=ro", "access=wo", "access=rw"]))
            else:
                for _ in range(rng.randint(0, 3)):
                    clauses.append(rng.choice(FLAG_CLAUSES))
        elif rng.random() < 0.05:
            clauses.append("readonly")                     # must be refused on host/exec
        line = " ".join([verb, kind, c] + clauses)
        if rng.random() < 0.05:
            line += "\r"                                   # CRLF
        if rng.random() < 0.05:
            line += "  # trailing comment"
        lines.append(line)
    with open(path, "w", encoding="latin-1", newline="") as fh:
        fh.write("\n".join(lines) + "\n")


# ------------------------------------------------------------------ check --

def check_policy(vdp, policy, rng, nq, stats, verbose):
    new_context()
    fails = []
    try:
        rules = parse_policy(policy)
        py_ok = True
    except PolicyError as e:
        rules, py_ok = None, False
        py_err = str(e)
    rc, out, err = run_vdp(vdp, policy, "analyze")
    c_ok = rc == 0
    if py_ok != c_ok:
        fails.append(f"{policy}: parse disagreement (python ok={py_ok}, C ok={c_ok}; {err.strip() or ''} {'' if py_ok else py_err})")
        return fails
    if not py_ok:
        stats["rejected_policies"] += 1
        return fails
    stats["policies"] += 1

    # Reachability of every rule.
    reach = [json.loads(l) for l in out.splitlines() if l.strip()]
    if len(reach) != len(rules):
        fails.append(f"{policy}: rule count mismatch ({len(reach)} vs {len(rules)})")
        return fails
    for i, rr in enumerate(reach):
        want = oracle_reach(rules, i)
        got = rr["reach"]
        stats["reach"] += 1
        if got == "UNKNOWN":
            stats["reach_unknown"] += 1   # enumeration bound (never DEAD/REACHABLE guessed)
            continue
        if got != want:
            fails.append(f"{policy}: rule {i} (line {rules[i]['line']}) reach C={got} solver={want}")

    # Ground and symbolic queries.
    qs = gen_queries(rules, rng, nq)
    lines = []
    for kind, sval, fval in qs:
        fl = "-" if fval is None else hex(fval)
        lines.append(f"{kind} {fl} {sval.encode('latin-1').hex()}")
    rc, out, err = run_vdp(vdp, policy, "batch", "\n".join(lines) + "\n")
    res = [json.loads(l) for l in out.splitlines() if l.strip()]
    if len(res) != len(qs):
        fails.append(f"{policy}: batch answered {len(res)} of {len(qs)}")
        return fails
    for (kind, sval, fval), r in zip(qs, res):
        if kind == "path" and fval is None:
            want = oracle_symbolic(rules, sval)
            stats["symbolic"] += 1
        else:
            want = oracle_ground(rules, kind, sval, fval)
            stats["ground"] += 1
        got = r["verdict"]
        if r.get("why") == "enumeration_bound":
            stats["bound_seen"] += 1
        if got == want:
            continue
        if got == "UNKNOWN" and r.get("why") == "enumeration_bound":
            stats["bound_unknown"] += 1
            continue
        shown = sval if len(sval) < 60 else sval[:30] + f"...({len(sval)} bytes)"
        fails.append(f"{policy}: {kind} {shown!r} flags={fval}: C={got} ({r.get('why')}) solver={want}")
    return fails


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--vdp", required=True)
    ap.add_argument("--fuzz", type=int, default=0, help="random policies to generate")
    ap.add_argument("--seed", type=int, default=1010)
    ap.add_argument("--queries", type=int, default=60)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("policies", nargs="*")
    a = ap.parse_args()

    rng = random.Random(a.seed)
    stats = {k: 0 for k in ("policies", "rejected_policies", "reach", "reach_unknown",
                            "ground", "symbolic", "bound_unknown", "bound_seen")}
    fails = []
    for p in a.policies:
        fails += check_policy(a.vdp, p, rng, a.queries, stats, a.verbose)
    with tempfile.TemporaryDirectory() as td:
        for k in range(a.fuzz):
            p = os.path.join(td, f"fuzz{k}.txt")
            fuzz_policy(rng, p)
            fails += check_policy(a.vdp, p, rng, a.queries, stats, a.verbose)
            if fails and not a.verbose:
                shutil_copy = os.path.join(tempfile.gettempdir(), f"vdp_fail_{k}.txt")
                with open(p) as src, open(shutil_copy, "w") as dst:
                    dst.write(src.read())
                fails.append(f"(failing fuzz policy saved to {shutil_copy})")
                break
    total = stats["reach"] + stats["ground"] + stats["symbolic"]
    print(f"smt_crosscheck: {stats['policies']} policies ({stats['rejected_policies']} "
          f"rejected by both parsers), {total} checks: {stats['reach']} reachability, "
          f"{stats['ground']} ground, {stats['symbolic']} symbolic-flag; "
          f"procedure hit its enumeration bound {stats['bound_seen']} times "
          f"(verdicts) and {stats['reach_unknown']} times (reachability); "
          f"of these, conservative UNKNOWN where the solver was definite: "
          f"{stats['reach_unknown'] + stats['bound_unknown']}")
    for fl in fails[:40]:
        print("  DISAGREE", fl)
    print(f"smt_crosscheck: {'PASS' if not fails else 'FAIL'} "
          f"({len(fails)} disagreement{'s' if len(fails) != 1 else ''})")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
