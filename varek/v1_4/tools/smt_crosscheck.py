#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
smt_crosscheck.py — differential check of the Warden's SMT decision procedure
(smt_decide.c, driven through tools/vdp_check) against an off-the-shelf SMT
solver (the reference solver: its Python package is listed in
tools/requirements-crosscheck.txt and imported below as `smt`).

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
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import tempfile

import z3 as smt  # the reference SMT solver; see tools/requirements-crosscheck.txt

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
MATCHERS = {"exact": "eq", "prefix": "prefix", "suffix": "suffix",
            "contains": "contains", "glob": "glob"}
GLOB_MAX_WILD = 32
GLOB_MAX_TOTAL = 4096
MAX_TOKENS = 64
ANY = frozenset(range(1, 256))
NOTSLASH = ANY - {ord("/")}


def is_flag_clause(t):
    return (t in ("readonly", "access=ro", "access=wo", "access=rw")
            or (t[:1] in ("+", "-") and t[1:] in FLAG_BITS))


# ------------------------------------------------------------ regex terms --
# A small regular-expression algebra over bytes 1..255, used three ways: as the
# meaning of a glob (written from the grammar in smt_decide.h, independently of
# the C token machine), translated to the solver's regex theory, and decided directly by
# Brzozowski derivatives (the bounded-length reachability fallback below).
# Terms are interned integers so hashing and equality are O(1).

class RX:
    def __init__(self):
        self.node = []          # id -> tuple
        self.ids = {}           # tuple -> id
        self.nullable = []
        self.dcache = {}
        self.EMPTY = self._mk(("0",), False)
        self.EPS = self._mk(("e",), True)
        self.TOP = self.star(self.cset(ANY))    # every string (all bytes 1..255)

    def _mk(self, key, nul):
        i = self.ids.get(key)
        if i is None:
            i = len(self.node)
            self.node.append(key)
            self.ids[key] = i
            self.nullable.append(nul)
        return i

    def cset(self, s):
        s = frozenset(s)
        return self.EMPTY if not s else self._mk(("c", s), False)

    def lit(self, c, i=0):
        """c[i:] as a literal (c a str of latin-1 chars)."""
        if i >= len(c):
            return self.EPS
        return self._mk(("l", c, i), False)

    def cat(self, a, b):
        if a == self.EMPTY or b == self.EMPTY:
            return self.EMPTY
        if a == self.EPS:
            return b
        if b == self.EPS:
            return a
        na = self.node[a]
        if na[0] == ".":                      # right-associate
            return self.cat(na[1], self.cat(na[2], b))
        return self._mk((".", a, b), self.nullable[a] and self.nullable[b])

    def cats(self, *xs):
        r = self.EPS
        for x in reversed(xs):
            r = self.cat(x, r)
        return r

    def star(self, a):
        if a in (self.EMPTY, self.EPS):
            return self.EPS
        if self.node[a][0] == "*":
            return a
        return self._mk(("*", a), True)

    def alt(self, *xs):
        items = set()
        for x in xs:
            n = self.node[x]
            if n[0] == "|":
                items |= n[1]
            elif x != self.EMPTY:
                items.add(x)
        if self.TOP in items:
            return self.TOP
        if not items:
            return self.EMPTY
        if len(items) == 1:
            return next(iter(items))
        fs = frozenset(items)
        return self._mk(("|", fs), any(self.nullable[x] for x in fs))

    def conj(self, *xs):
        items = set()
        for x in xs:
            n = self.node[x]
            if n[0] == "&":
                items |= n[1]
            elif x == self.EMPTY:
                return self.EMPTY
            elif x != self.TOP:
                items.add(x)
        if not items:
            return self.TOP
        if len(items) == 1:
            return next(iter(items))
        fs = frozenset(items)
        return self._mk(("&", fs), all(self.nullable[x] for x in fs))

    def neg(self, a):
        n = self.node[a]
        if n[0] == "~":
            return n[1]
        return self._mk(("~", a), not self.nullable[a])

    def sets(self, a, acc=None, seen=None):
        """Every byte set a term distinguishes (for byte classes)."""
        acc = set() if acc is None else acc
        seen = set() if seen is None else seen
        stack = [a]
        while stack:
            x = stack.pop()
            if x in seen:
                continue
            seen.add(x)
            n = self.node[x]
            if n[0] == "c":
                acc.add(n[1])
            elif n[0] == "l":
                for ch in n[1][n[2]:]:
                    acc.add(frozenset([ord(ch)]))
            elif n[0] in (".",):
                stack += [n[1], n[2]]
            elif n[0] in ("*", "~"):
                stack.append(n[1])
            elif n[0] in ("|", "&"):
                stack += list(n[1])
        return acc

    def deriv(self, a, b):
        key = (a, b)
        r = self.dcache.get(key)
        if r is not None:
            return r
        n = self.node[a]
        k = n[0]
        if k in ("0", "e"):
            r = self.EMPTY
        elif k == "c":
            r = self.EPS if b in n[1] else self.EMPTY
        elif k == "l":
            r = self.lit(n[1], n[2] + 1) if ord(n[1][n[2]]) == b else self.EMPTY
        elif k == ".":
            first = self.cat(self.deriv(n[1], b), n[2])
            r = self.alt(first, self.deriv(n[2], b)) if self.nullable[n[1]] else first
        elif k == "*":
            r = self.cat(self.deriv(n[1], b), a)
        elif k == "|":
            r = self.alt(*[self.deriv(x, b) for x in n[1]])
        elif k == "&":
            r = self.conj(*[self.deriv(x, b) for x in n[1]])
        else:
            r = self.neg(self.deriv(n[1], b))
        self.dcache[key] = r
        return r

    def matches(self, a, s):
        for ch in s:
            b = ord(ch)
            if not 1 <= b <= 255:
                return False
            a = self.deriv(a, b)
            if a == self.EMPTY:
                return False
        return self.nullable[a]

    def shortest(self, a, limit, budget=400000):
        """Shortest string in a (length <= limit): the string, None if there is
        none within the limit, or raises RuntimeError past the state budget."""
        sets = self.sets(a)
        classes = {}
        for b in range(1, 256):
            sig = tuple(b in s for s in sets)
            classes.setdefault(sig, b)
        reps = sorted(classes.values())
        par = {a: None}
        frontier = [a]
        depth = 0
        while frontier:
            for x in frontier:
                if self.nullable[x]:
                    out = []
                    while par[x] is not None:
                        x, b = par[x]
                        out.append(chr(b))
                    return "".join(reversed(out))
            if depth == limit:
                return None
            nxt = []
            for x in frontier:
                for b in reps:
                    y = self.deriv(x, b)
                    if y == self.EMPTY or y in par:
                        continue
                    par[y] = (x, b)
                    nxt.append(y)
            if len(par) > budget:
                raise RuntimeError("derivative search budget")
            frontier = nxt
            depth += 1
        return None


def parse_glob(rx, pat, where):
    """The glob grammar of smt_decide.h, as a regular expression."""
    parts, run = [], []            # run: pending literal bytes (one lit term)

    class Parts(list):
        def append(self, x):
            if run:
                super().append(rx.lit("".join(run)))
                run.clear()
            super().append(x)
    parts = Parts()
    i, n, wild, after_slash = 0, len(pat), 0, False
    ntok = 0                       # tokens as the C program counts them
    gtoks = []                     # the token sequence (certificate witnesses)
    while i < n:
        ch = pat[i]
        if ch == "\\":
            if i + 1 >= n:
                raise PolicyError(f"{where}: lone backslash")
            run.append(pat[i + 1])
            gtoks.append(("lit", ord(pat[i + 1])))
            ntok += 1
            after_slash = False
            i += 2
        elif ch == "*":
            if pat[i + 1:i + 2] == "*":
                if pat[i + 2:i + 3] == "*":
                    raise PolicyError(f"{where}: ***")
                if after_slash and pat[i + 2:i + 3] == "/":
                    # "/**/": the '/' is already in the literal run; (.*/)? follows
                    parts.append(rx.alt(rx.EPS, rx.cat(rx.TOP, rx.cset([ord("/")]))))
                    gtoks.append(("segs",))
                    i += 3
                    after_slash = True
                else:
                    parts.append(rx.TOP)
                    gtoks.append(("dstar",))
                    i += 2
                    after_slash = False
            else:
                parts.append(rx.star(rx.cset(NOTSLASH)))
                gtoks.append(("star",))
                i += 1
                after_slash = False
            wild += 1
            ntok += 1
        elif ch == "?":
            parts.append(rx.cset(NOTSLASH))
            gtoks.append(("set", NOTSLASH))
            wild += 1
            ntok += 1
            after_slash = False
            i += 1
        elif ch == "[":
            j = i + 1
            neg = False
            if j < n and pat[j] in "!^":
                neg, j = True, j + 1
            members, first, closed = set(), True, False
            while j < n:
                x = pat[j]
                if x == "]" and not first:
                    closed, j = True, j + 1
                    break
                first = False
                if x == "\\":
                    if j + 1 >= n:
                        raise PolicyError(f"{where}: lone backslash")
                    j += 1
                    x = pat[j]
                j += 1
                y = x
                if j + 1 < n and pat[j] == "-" and pat[j + 1] != "]":
                    j += 1
                    y = pat[j]
                    if y == "\\":
                        if j + 1 >= n:
                            raise PolicyError(f"{where}: lone backslash")
                        j += 1
                        y = pat[j]
                    j += 1
                    if ord(y) < ord(x):
                        raise PolicyError(f"{where}: bad range")
                rng = set(range(ord(x), ord(y) + 1))
                if ord("/") in rng:
                    raise PolicyError(f"{where}: '/' in class")
                members |= rng
            if not closed:
                raise PolicyError(f"{where}: unterminated class")
            parts.append(rx.cset(NOTSLASH - members if neg else members))
            gtoks.append(("set", frozenset(NOTSLASH - members if neg else members)))
            wild += 1
            ntok += 1
            after_slash = False
            i = j
        else:
            run.append(ch)
            gtoks.append(("lit", ord(ch)))
            ntok += 1
            after_slash = ch == "/"
            i += 1
        if wild > GLOB_MAX_WILD:
            raise PolicyError(f"{where}: too many wildcards")
    parts.append(rx.EPS)                        # flush the last literal run
    return rx.cats(*parts), ntok, gtoks


def host_portless(c):
    """v1.21: a host constant without a port matches every port: a dotted-quad
    IPv4 address, or a bracketed IPv6 address such as [::1] (colons only inside
    the brackets). Any other constant matches only itself."""
    if ":" not in c:
        parts = c.split(".")
        return len(parts) == 4 and all(
            1 <= len(p) <= 3 and p.isdigit() and p.isascii() and int(p) <= 255
            and not (len(p) > 1 and p[0] == "0") for p in parts)
    return len(c) >= 2 and c[0] == "[" and c[-1] == "]" and "]" not in c[1:-1]


NAME_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def host_name_form(c):
    """v1.24: 0 if c is a numeric host form ('[', 'unix:', or only digits and
    dots before the first ':'), 1 if it is a valid host name constant
    (name or name:port), -1 if it is in name form but invalid. Written from the
    grammar in smt_decide.h, independently of both C parsers."""
    if c.startswith("[") or c.startswith("unix:"):
        return 0
    host, sep, port = c.partition(":")
    if all(ch in "0123456789." for ch in host):
        return 0
    if len(host) > 253 or host == "unix":
        return -1
    labels = host.split(".")
    if not all(NAME_LABEL.fullmatch(l) for l in labels) or labels[-1].isdigit():
        return -1
    if sep and not re.fullmatch(r"0|[1-9][0-9]{0,4}", port) or (sep and int(port) > 65535):
        return -1
    return 1


def atom_rx(rx, r):
    """The language of a rule's string atom."""
    c, op = r["c"], r["op"]
    if op == "prefix":
        return rx.cat(rx.lit(c), rx.TOP)
    if op == "eq":
        return rx.lit(c)
    if op == "suffix":
        return rx.cat(rx.TOP, rx.lit(c))
    if op == "contains":
        return rx.cats(rx.TOP, rx.lit(c), rx.TOP)
    if op == "glob":
        return r["rx"]
    # host
    if not r["portless"]:
        return rx.lit(c)
    return rx.alt(rx.lit(c), rx.cat(rx.lit(c + ":"), rx.TOP))


def parse_policy(path):
    """Independent re-implementation of the policy grammar (smt_decide.h)."""
    with open(path, "rb") as fh:
        return parse_lines(fh.read().split(b"\n"), path)


def parse_lines(raw_lines, path):
    rules = []
    rx = RX()
    req = (0, 0)                   # highest `require warden` so far
    legacy_name = False            # v1.24: a host name read before `require warden 1.24`
    glob_tokens = 0
    if True:
        for lineno, raw in enumerate(raw_lines, 1):
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
            if len(toks) > MAX_TOKENS:
                raise PolicyError(f"{path}:{lineno}: too many tokens")
            if toks[0] == "require":
                m = re.fullmatch(r"([0-9]{1,6})\.([0-9]{1,6})", toks[2]) if len(toks) == 3 else None
                if len(toks) != 3 or toks[1] != "warden" or not m:
                    raise PolicyError(f"{path}:{lineno}: bad directive")
                v = (int(m.group(1)), int(m.group(2)))
                if v > (1, 25):
                    raise PolicyError(f"{path}:{lineno}: requires newer Warden")
                if legacy_name and v >= (1, 24):
                    raise PolicyError(f"{path}:{lineno}: require warden 1.24 after a host name")
                req = max(req, v)
                continue
            if len(toks) < 3:
                raise PolicyError(f"{path}:{lineno}: bad rule")
            verb, kind = toks[0], toks[1]
            if verb not in ("allow", "deny"):
                raise PolicyError(f"{path}:{lineno}: verb")
            if kind not in ("path", "host", "exec"):
                raise PolicyError(f"{path}:{lineno}: kind")
            op = {"path": "prefix", "host": "host", "exec": "eq"}[kind]
            ci = 2
            if toks[2] in MATCHERS and len(toks) >= 4 and not is_flag_clause(toks[3]):
                if kind == "host":
                    raise PolicyError(f"{path}:{lineno}: matcher on host")
                op, ci = MATCHERS[toks[2]], 3
            elif toks[2] in MATCHERS and req >= (1, 14):
                raise PolicyError(f"{path}:{lineno}: matcher without a constant")
            const = toks[ci]
            if not (1 <= len(const) <= L):
                raise PolicyError(f"{path}:{lineno}: constant length")
            if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in const):
                raise PolicyError(f"{path}:{lineno}: control byte in constant")
            if len(rules) >= 256:
                raise PolicyError(f"{path}: more than 256 rules")
            wild = False
            if kind == "host" and const.startswith("*.") and req >= (1, 24):
                # v1.25: *.<suffix>[:port] -> the glob ?*.<suffix>:<port> (or :*)
                if req < (1, 25):
                    raise PolicyError(f"{path}:{lineno}: wildcard before 1.25")
                if host_name_form(const[2:]) != 1:
                    raise PolicyError(f"{path}:{lineno}: bad wildcard")
                host, sep, port = const[2:].partition(":")
                if "." not in host:
                    raise PolicyError(f"{path}:{lineno}: wildcard over one label")
                const = "?*." + host + ":" + (port if sep else "*")
                op, wild = "glob", True
            grx, gtoks = None, None
            if op == "glob":
                grx, nt, gtoks = parse_glob(rx, const, f"{path}:{lineno}")
                glob_tokens += nt
                if glob_tokens > GLOB_MAX_TOTAL:
                    raise PolicyError(f"{path}:{lineno}: glob tokens over the policy total")
            mask = value = 0
            budgets = {}
            for t in toks[ci + 1:]:
                bk, _, bv = t.partition("=")
                if kind == "host" and bk in ("names", "rate") and _:
                    # v1.25: a wildcard allow rule's budgets (no part of a decision)
                    if not (wild and verb == "allow"):
                        raise PolicyError(f"{path}:{lineno}: budget on a non-wildcard rule")
                    if not re.fullmatch(r"[1-9][0-9]*", bv) or int(bv) > (100000 if bk == "names" else 10000):
                        raise PolicyError(f"{path}:{lineno}: bad budget {t}")
                    if bk in budgets:
                        raise PolicyError(f"{path}:{lineno}: budget twice")
                    budgets[bk] = int(bv)
                    continue
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
            portless = name = False
            if wild:
                name = True
            elif kind == "host":
                nf = host_name_form(const)
                if nf and req >= (1, 24):
                    if nf < 0:
                        raise PolicyError(f"{path}:{lineno}: bad host name")
                    name, portless = True, ":" not in const
                else:
                    legacy_name = legacy_name or nf != 0
                    portless = host_portless(const)
            r = {"verb": verb, "kind": kind, "op": op, "c": const, "rx": grx, "gtoks": gtoks,
                 "mask": mask, "value": value, "line": lineno, "portless": portless, "name": name,
                 "wild": wild}
            r["lang"] = atom_rx(rx, r)
            rules.append(r)
    return rules, rx


# ---------------------------------------------------------------- encoding --

# Every solver object of one policy lives in its own solver context, dropped when
# the policy is done: a single global context accumulates every term of every
# query (gigabytes with near-bound constants).
CTX = None


def new_context():
    global CTX
    CTX = smt.Context()


def zstr(s):
    """A solver string literal for s. smt.StringVal decodes \\u{..} escape sequences;
    escaping every backslash as \\u{5c} makes it take s byte for byte."""
    return smt.StringVal(s.replace("\\", "\\u{5c}"), ctx=CTX)


def _byte_re():
    return smt.Range(chr(1), chr(255), ctx=CTX)


def fdomain(f):
    """Admissible flags: ABI bits only, and not access mode 3."""
    return smt.And((f & smt.BitVecVal(~KNOWN & 0xFFFFFFFF, 32, ctx=CTX)) == 0,
                  (f & smt.BitVecVal(ACC, 32, ctx=CTX)) != smt.BitVecVal(ACC, 32, ctx=CTX))


def domain(s, f):
    return smt.And(smt.Length(s) <= L, smt.InRe(s, smt.Star(_byte_re())), fdomain(f))


def set_to_smt(s):
    """A byte set as a union of the solver's character ranges."""
    b = sorted(s)
    runs, lo = [], b[0]
    for x, y in zip(b, b[1:] + [None]):
        if y != x + 1:
            runs.append(smt.Range(chr(lo), chr(x), ctx=CTX))
            if y is not None:
                lo = y
    return runs[0] if len(runs) == 1 else smt.Union(*runs)


def rx_to_smt(rx, a, memo=None):
    memo = {} if memo is None else memo
    if a in memo:
        return memo[a]
    n = rx.node[a]
    k = n[0]
    if k == "0":
        r = smt.Empty(smt.ReSort(smt.StringSort(ctx=CTX)))
    elif k == "e":
        r = smt.Re(zstr(""))
    elif k == "c":
        r = set_to_smt(n[1])
    elif k == "l":
        r = smt.Re(zstr(n[1][n[2]:]))
    elif k == ".":
        r = smt.Concat(rx_to_smt(rx, n[1], memo), rx_to_smt(rx, n[2], memo))
    elif k == "*":
        r = smt.Star(rx_to_smt(rx, n[1], memo))
    elif k == "|":
        r = smt.Union(*[rx_to_smt(rx, x, memo) for x in n[1]])
    elif k == "&":
        r = smt.Intersect(*[rx_to_smt(rx, x, memo) for x in n[1]])
    else:
        r = smt.Complement(rx_to_smt(rx, n[1], memo))
    memo[a] = r
    return r


def str_atom(rx, r, s):
    """Ground / symbolic-flag encoding: the solver's string functions, and its regex
    membership for globs."""
    c = zstr(r["c"])
    op = r["op"]
    if op == "prefix":
        return smt.PrefixOf(c, s)
    if op == "eq":
        return s == c
    if op == "suffix":
        return smt.SuffixOf(c, s)
    if op == "contains":
        return smt.Contains(s, c)
    if op == "glob":
        return smt.InRe(s, rx_to_smt(rx, r["rx"]))
    if not r["portless"]:
        return s == c
    return smt.Or(s == c, smt.PrefixOf(zstr(r["c"] + ":"), s))


def bv_atom(r, f):
    if r["mask"] == 0:
        return smt.BoolVal(True, ctx=CTX)
    return (f & smt.BitVecVal(r["mask"], 32, ctx=CTX)) == smt.BitVecVal(r["value"], 32, ctx=CTX)


def fires_first(rx, rules, idx, s, f):
    """Rule idx holds and no earlier rule of its kind holds."""
    k = rules[idx]["kind"]
    here = smt.And(str_atom(rx, rules[idx], s), bv_atom(rules[idx], f))
    before = [smt.Not(smt.And(str_atom(rx, r, s), bv_atom(r, f)))
              for r in rules[:idx] if r["kind"] == k]
    return smt.And(here, *before)


def check(*fs, timeout=20000):
    so = smt.Solver(ctx=CTX)
    so.set("timeout", timeout)
    so.add(*fs)
    return so.check(), so


def sat(*fs):
    r, _ = check(*fs)
    if r == smt.unknown:
        raise RuntimeError("solver returned unknown (timeout)")
    return r == smt.sat


def oracle_first(rx, rules, kind, sval, fval):
    """Index of the first rule that holds on the concrete action, None if no
    rule holds, or 'OUT' if the action is outside the fragment."""
    s, f = smt.String("s", ctx=CTX), smt.BitVec("f", 32, ctx=CTX)
    fv = fval if (kind == "path" and fval is not None) else 0
    pin = [s == zstr(sval), f == smt.BitVecVal(fv, 32, ctx=CTX)]
    if not sat(domain(s, f), *pin):
        return "OUT"
    for i, r in enumerate(rules):
        if r["kind"] != kind:
            continue
        if sat(domain(s, f), *pin, fires_first(rx, rules, i, s, f)):
            return i
    return None


def oracle_ground(rx, rules, kind, sval, fval):
    i = oracle_first(rx, rules, kind, sval, fval)
    if i is None or i == "OUT":
        return "UNKNOWN"
    return "SATISFIED" if rules[i]["verb"] == "allow" else "UNSATISFIED"


def oracle_symbolic(rx, rules, sval):
    """path, concrete s, symbolic f. SATISFIED iff every admissible f is."""
    s, f = smt.String("s", ctx=CTX), smt.BitVec("f", 32, ctx=CTX)
    pin = s == zstr(sval)
    if not sat(domain(s, f), pin):
        return "UNKNOWN"
    idx = [i for i, r in enumerate(rules) if r["kind"] == "path"]
    allow_first = smt.Or([fires_first(rx, rules, i, s, f) for i in idx
                         if rules[i]["verb"] == "allow"] or [smt.BoolVal(False, ctx=CTX)])
    deny_first = smt.Or([fires_first(rx, rules, i, s, f) for i in idx
                        if rules[i]["verb"] == "deny"] or [smt.BoolVal(False, ctx=CTX)])
    if not sat(domain(s, f), pin, smt.Not(allow_first)):
        return "SATISFIED"
    if not sat(domain(s, f), pin, smt.Not(deny_first)):
        return "UNSATISFIED"
    return "UNKNOWN"


# Reachability, legacy atoms (prefix / exact / host): a length n and one 8-bit
# vector per character position. The solver's string theory does not finish on
# conjunctions of many negated prefixof constraints (the same tail pathology
# v1.5 measured), while this encoding is plain QF_BV + linear integer
# arithmetic. It is exact: every atom reads only positions below
# M = (longest constant) + 2, and positions >= M are unconstrained bytes, so
# any model extends to a string in the domain (length <= L, bytes 1..255).

class ByteStr:
    def __init__(self, rules):
        m = max([len(r["c"]) + 1 for r in rules] + [1]) + 1
        self.n = smt.Int("n", ctx=CTX)
        self.b = [smt.BitVec(f"b{k}", 8, ctx=CTX) for k in range(m)]

    def domain(self):
        # Length bound only. The byte range 1..255 needs no constraint: atoms
        # only compare positions with constant bytes, and the grammar forbids
        # bytes 0x00-0x20 and 0x7f in constants, so a 0 byte in a model acts
        # exactly like an unused byte in 1..255, which always exists at every
        # position (at most 222 values can occur). Dropping the ~4,100
        # implications a near-bound constant needed keeps the query fast; the
        # encoding stays exact.
        return smt.And(self.n >= 0, self.n <= L)

    def prefix(self, c):
        return smt.And(self.n >= len(c),
                      *[self.b[k] == ord(ch) for k, ch in enumerate(c)])

    def eq(self, c):
        return smt.And(self.n == len(c), self.prefix(c))


def str_atom_bytes(r, bs):
    c = r["c"]
    if r["op"] == "prefix":
        return bs.prefix(c)
    if r["op"] == "eq" or not r["portless"]:
        return bs.eq(c)
    # host(c, s) = s == c OR prefix(c ++ ":", s), written with the shared prefix
    # factored out: prefix(c, s) AND (|s| == |c| OR s[|c|] == ':'). Logically
    # identical; the solver times out on the unfactored disjunction of two long
    # conjunctions (a 4 KB constant) and answers the factored form instantly.
    k = len(c)
    at_k = bs.b[k] == ord(":") if k < len(bs.b) else smt.BoolVal(False, ctx=CTX)
    return smt.And(bs.prefix(c), smt.Or(bs.n == k, smt.And(bs.n >= k + 1, at_k)))


LEGACY_OPS = ("prefix", "eq", "host")


def oracle_reach_bytes(rules, i):
    k = rules[i]["kind"]
    rs = [r for r in rules[:i + 1] if r["kind"] == k]
    bs = ByteStr(rs)
    f = smt.BitVec("f", 32, ctx=CTX)
    here = smt.And(str_atom_bytes(rules[i], bs), bv_atom(rules[i], f))
    before = [smt.Not(smt.And(str_atom_bytes(r, bs), bv_atom(r, f)))
              for r in rules[:i] if r["kind"] == k]
    return "REACHABLE" if sat(bs.domain(), fdomain(f), here, *before) else "DEAD"


# Reachability with suffix / contains / glob atoms. Two independent deciders:
#
#  (1) the solver's regex theory, WITHOUT the length bound (with it, the solver unrolls to the
#      bound and does not finish on near-bound constants). UNSAT means DEAD at
#      any length. SAT with a model of length <= L means REACHABLE. SAT with a
#      longer model, or a timeout, is inconclusive for the bounded question.
#  (2) Brzozowski derivatives over the terms above: breadth-first to depth L,
#      so the bound is exact. The flags are handled by the solver: every satisfiable
#      signature (which earlier rules' flag atoms hold, given B_i) is
#      enumerated, and the string question is asked for each one.
#
# The procedure's answer must equal (2), and must agree with (1) whenever (1)
# is conclusive.

def flag_signatures(rules, i, earlier):
    f = smt.BitVec("f", 32, ctx=CTX)
    so = smt.Solver(ctx=CTX)
    so.add(fdomain(f), bv_atom(rules[i], f))
    atoms = [bv_atom(rules[j], f) for j in earlier]
    out = []
    while so.check() == smt.sat:
        m = so.model()
        sig = tuple(smt.is_true(m.eval(a, model_completion=True)) for a in atoms)
        fv = m.eval(f, model_completion=True).as_long()
        out.append((sig, fv))
        so.add(smt.Or([a if not v else smt.Not(a) for a, v in zip(atoms, sig)] or
                     [smt.BoolVal(False, ctx=CTX)]))
    return out


def oracle_reach_rx(rx, rules, i, stats):
    k = rules[i]["kind"]
    earlier = [j for j in range(i) if rules[j]["kind"] == k]
    # (2) derivatives, per flag signature
    deriv = "DEAD"
    for sig, fv in flag_signatures(rules, i, earlier):
        shadow = [rules[j]["lang"] for j, on in zip(earlier, sig) if on]
        q = rx.conj(rules[i]["lang"], *[rx.neg(x) for x in shadow])
        if rx.shortest(q, L) is not None:
            deriv = "REACHABLE"
            break
    # (1) the solver's regex theory, unbounded
    s, f = smt.String("s", ctx=CTX), smt.BitVec("f", 32, ctx=CTX)
    memo = {}
    here = smt.And(smt.InRe(s, rx_to_smt(rx, rules[i]["lang"], memo)), bv_atom(rules[i], f))
    before = [smt.Not(smt.And(smt.InRe(s, rx_to_smt(rx, rules[j]["lang"], memo)), bv_atom(rules[j], f)))
              for j in earlier]
    r, so = check(smt.InRe(s, smt.Star(_byte_re())), fdomain(f), here, *before, timeout=10000)
    if r == smt.unsat:
        solver = "DEAD"
    elif r == smt.sat and len(so.model()[s].as_string()) <= L:
        solver = "REACHABLE"
    else:
        solver = None
    if solver is None:
        stats["reach_solver_inconclusive"] += 1
    elif solver != deriv:
        raise RuntimeError(f"oracles disagree on rule {i}: solver {solver}, derivatives {deriv}")
    return deriv


def oracle_reach(rx, rules, i, stats):
    k = rules[i]["kind"]
    if all(r["op"] in LEGACY_OPS for r in rules[:i + 1] if r["kind"] == k):
        return oracle_reach_bytes(rules, i)
    stats["reach_regex"] += 1
    return oracle_reach_rx(rx, rules, i, stats)


# ------------------------------------------------------------ procedure IO --

def run_vdp(vdp, policy, *mode, stdin=None):
    p = subprocess.run([vdp, policy, *mode], input=stdin, capture_output=True,
                       text=True, timeout=600)
    return p.returncode, p.stdout, p.stderr


# ------------------------------------------------------------- query gen --

def rand_const_bytes(rng):
    """Occasionally non-ASCII bytes, never whitespace/control (as the grammar)."""
    return rng.choice(["\xa0", "\x85", "\xe9", "\xff", "\x80"])


PREFERRED = [ord(c) for c in "/ab.x:"]


def sample(rx, a, rng, depth=0):
    """A random string of the language of term a (for query generation)."""
    n = rx.node[a]
    k = n[0]
    if k in ("0", "e"):
        return ""
    if k == "c":
        pref = [b for b in PREFERRED if b in n[1]]
        if pref and rng.random() < 0.8:
            return chr(rng.choice(pref))
        return chr(rng.choice(sorted(n[1])))
    if k == "l":
        return n[1][n[2]:]
    if k == ".":
        out = []
        while rx.node[a][0] == ".":             # right-nested: iterate, don't recurse
            out.append(sample(rx, rx.node[a][1], rng, depth + 1))
            a = rx.node[a][2]
        return "".join(out) + sample(rx, a, rng, depth + 1)
    if k == "*":
        return "".join(sample(rx, n[1], rng, depth + 1) for _ in range(rng.randint(0, 3)))
    if k == "|":
        return sample(rx, rng.choice(sorted(n[1])), rng, depth + 1)
    return ""


def gen_queries(rules, rx, rng, n):
    by_kind = {"path": [], "host": [], "exec": []}
    for r in rules:
        by_kind[r["kind"]].append(r)
    out = []
    alphabet = "/ab:.x"
    for _ in range(n):
        kind = rng.choice(["path", "path", "path", "host", "exec"])
        base = sample(rx, rng.choice(by_kind[kind])["lang"], rng) \
            if by_kind[kind] and rng.random() < 0.85 else ""
        choice = rng.random()
        if rng.random() < 0.03:
            base = base + "\\u{" + rng.choice(["62", "2f", "5c", "41"]) + "}"   # the solver's escape text
        if choice < 0.35:
            sval = base
        elif choice < 0.55:
            sval = base + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 4)))
        elif choice < 0.65:
            sval = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 4))) + base
        elif choice < 0.75 and base:
            sval = base[: rng.randint(0, len(base))]
        elif choice < 0.8:
            sval = "/" * (L + rng.randint(1, 3))            # over the length bound
        else:
            sval = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
        if len(sval) > L + 3:
            sval = sval[: L + rng.randint(-2, 3)]
        if kind == "host" and rng.random() < 0.25:
            # v1.25: the strings a connect is decided on: names with ports
            sval = rng.choice(["a.example.com", "x.a.example.com", "example.com", "a.b.example.com",
                               "x.a.b.example.com", "a.example.org", "1.2.3.4"]) + \
                rng.choice([":443", ":80", ":8080"])
        elif kind == "host" and base and (host_portless(base) or (host_name_form(base) == 1 and ":" not in base)) \
                and rng.random() < 0.4:
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

GLOB_PIECES = ["/a", "/b", "/", "*", "**", "?", "[ab]", "[!a]", "[a-c]", "[]a]", ".x",
               "/**/", "\\*", "\\[", "\\/", "\\/**/", "x", ":", "\xe9", "[^b]"]
GLOB_TAILS = ["/*", "/**", "*", "/**/b", "/?", "[ab]*", "/*/b", "**/", "/[!a]", ".x", "/"]
GLOB_BAD = ["[", "\\", "***", "[/]", "[b-a]", "[!]", "[a-/]", "?" * 33]
AMBIGUOUS = ["allow path glob readonly", "deny path suffix -O_CREAT", "allow path exact",
             "deny path suffix #.pem backups", "deny path glob", "allow path contains \\u{2f}x",
             "allow path " + " ".join(["/x"] + ["readonly"] * 61), "allow path " + " ".join(["/x"] + ["readonly"] * 62),
             "allow host suffix .com", "deny exec contains", "allow host glob",
             "deny path prefix glob", "allow path glob access=rw", "deny path contains +O_EXCL x"]


def fuzz_line(rng, prior, strings, wide):
    frags = ["/a", "/a/", "/a/b", "/ab", "/b/", "/a/b/c", "x", "x:1", "/", "[::1]", "[a]", "[:]",
             "1.2.3.4", "1.2.3.4:5", "01.2.3.4", "256.1.1.1", "unix", "unix:/a"]
    # v1.24 host names, valid and not
    names = ["api.example.com", "api.example.com:443",
             # v1.25 wildcards, valid and not
             "*.example.com", "*.example.com:443", "*.b.example.com", "*.com", "*.example.com:0",
             "**.example.com", "a.*.example.com", "*.Example.com", "*", "*.example.com.", "a.b", "a-b.c0", "xn--bcher-kva.example",
             "localhost", "x", "a.b:0", "a.b:65535", "Api.example.com", "a.b.", "*.example.com",
             "a..b", "-a.b", "a-.b", "a.123", "1a.2", "a.b:65536", "a.b:080", "a.b:", "unix:80",
             "a_b.c", "a.b:1:2", "\xe9.example", "a" * 63 + ".b", "a" * 64 + ".b",
             ".".join(["a" * 63] * 4)[:253], ".".join(["a" * 63] * 4)[:252] + "aa"]
    if rng.random() < 0.03:
        return rng.choice(AMBIGUOUS)
    matcher = None
    if prior and rng.random() < 0.35:
        # a rule that overlaps an earlier one: same kind, the earlier
        # constant's literal stem, a broader or narrower matcher
        kind, c0 = rng.choice(prior)
        # (at most 64 bytes of it: copying a near-bound constant into several
        # rules adds nothing the dedicated near-bound rules do not, and only
        # slows the oracle's derivative search)
        stem = re.split(r"[*?\[\\]", c0, maxsplit=1)[0][:64] or "/"
        if kind == "host":
            c = stem
        else:
            matcher, c = rng.choice([(None, stem), ("prefix", stem), ("exact", stem),
                                     ("glob", stem + "**"), ("glob", stem + "*"),
                                     ("glob", stem + "/**/b"), ("suffix", stem[-2:] or stem),
                                     ("contains", stem[1:3] or stem)])
    else:
        kind = rng.choice(["path", "path", "path", "host", "host", "exec"])
        c = rng.choice(frags) + rng.choice(["", "", "a", "/", ":2"])
        if kind == "host" and rng.random() < 0.6:
            c = rng.choice(names) + rng.choice(["", "", "", ":443", "a"])
            if rng.random() < 0.6:
                c = rng.choice(["api.example.com", "api.example.com:443", "a.b", "a-b.c0",
                                "xn--bcher-kva.example", "localhost", "*.example.com",
                                "*.example.com:443", "*.b.example.com", "a.b.example.com"])
        if strings and kind != "host" and rng.random() < 0.7:
            matcher = rng.choice(["exact", "prefix", "suffix", "contains", "glob", "glob"])
        elif strings and kind == "host" and rng.random() < 0.03:
            matcher = "suffix"                             # must be refused
        if matcher in ("suffix", "contains"):
            c = rng.choice([".pem", "/.ssh/", "b", "a/", ".x", "/a", "x:1", "ab"] + frags)
        elif matcher == "glob":
            if rng.random() < 0.5:
                # overlap with the prefix rules: a shared stem, then wildcards
                c = rng.choice(frags) + "".join(rng.choice(GLOB_TAILS)
                                                for _ in range(rng.randint(1, 2)))
            else:
                c = "".join(rng.choice(GLOB_PIECES) for _ in range(rng.randint(1, 5)))
            if rng.random() < 0.06:
                c += rng.choice(GLOB_BAD)
        r = rng.random()
        if r < 0.05:
            d = "d" * rng.randint(L - 8, L + 2)
            c = ("/" + d) if matcher not in ("suffix", "contains", "glob") else \
                rng.choice(["/" + d, d + ".pem", "/" + d[:-4] + "*"])   # near / over the bound
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
            for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
                clauses.append(rng.choice(FLAG_CLAUSES))
    elif rng.random() < 0.05:
        clauses.append("readonly")                     # must be refused on host/exec
    line = " ".join([verb, kind] + ([matcher] if matcher else []) + [c] + clauses)
    if rng.random() < 0.05:
        line += "\r"                                   # CRLF
    if rng.random() < 0.05:
        line += "  # trailing comment"
    return line, kind, c


def fuzz_policy(rng, path):
    """A random policy. Seven in ten are kept valid (each line is regenerated
    until this file's parser accepts it; the C parser must agree, which the
    check verifies), so most policies reach the reachability and query checks;
    the rest may carry any number of malformed lines, for the parsers."""
    valid = rng.random() < 0.7
    lines = []
    if rng.random() < 0.15:
        # v1.25: a host-name policy: wildcards over and beside exact names and
        # addresses, allow and deny, with and without ports, so first-match
        # order between the forms is exercised.
        hosts = ["*.example.com", "*.example.com:443", "*.b.example.com", "*.a.b.example.com:80",
                 "a.example.com", "a.example.com:443", "b.example.com", "x.a.b.example.com",
                 "example.com", "*.example.org", "1.2.3.4", "1.2.3.4:443"]
        bad = ["*.com", "*.example.com:0443", "a.*.example.com", "*.Example.com", "*"]
        lines.append("require warden 1.25")
        # v1.25 section 4: budgets on wildcard allow rules (and, when the
        # policy may be invalid, where they do not belong or out of range)
        good_b = ["names=1", "names=64", "names=100000", "rate=1", "rate=10", "rate=10000"]
        bad_b = ["names=0", "names=100001", "rate=10001", "names=05", "names=", "rate=x", "nams=5"]
        for _ in range(rng.randint(1, 8)):
            c = rng.choice(hosts + (bad if not valid and rng.random() < 0.3 else []))
            verb = rng.choice(['allow', 'deny'])
            tail = ""
            if rng.random() < 0.4 and (valid is False or (verb == "allow" and c.startswith("*."))):
                opts = rng.sample(good_b, rng.randint(1, 2))
                if not valid and rng.random() < 0.4:
                    opts.append(rng.choice(bad_b + good_b))       # bad, or given twice
                tail = " " + " ".join(opts)
            lines.append(f"{verb} host {c}{tail}")
        with open(path, "w", encoding="latin-1", newline="") as fh:
            fh.write("\n".join(lines) + "\n")
        return
    if rng.random() < 0.3:
        lines.append(rng.choice(["require warden 1.14", "require warden 1.13", "require warden 01.14",
                                 "require warden 1.15", "require warden 1.16", "require warden 1.21",
                                 "require warden 1.24", "require warden 1.24", "require warden 1.25"] +
                                ([] if valid else ["require warden 1.26", "require warden x",
                                                   "require warden +1.14", "require warden 1.+14",
                                                   "require warden 1.1400000"])))
    elif rng.random() < 0.35:
        lines.append(rng.choice(["require warden 1.24", "require warden 1.25"]))   # host names, wildcards
    wide = rng.random() < 0.15          # many distinct flag bits: reach the bound
    strings = rng.random() < 0.65       # use v1.14 matchers in this policy
    prior = []
    late_require = not valid and rng.random() < 0.1
    for _ in range(rng.randint(1, 12)):
        if late_require and rng.random() < 0.3:
            lines.append("require warden 1.24")    # after a host name: refused
        for _try in range(30):
            got = fuzz_line(rng, prior, strings, wide)
            line = got if isinstance(got, str) else got[0]
            if not valid:
                break
            try:
                parse_lines([line.encode("latin-1")], "line")
                break
            except PolicyError:
                continue
        else:
            continue
        if not isinstance(got, str):
            prior.append((got[1], got[2]))
        lines.append(line)
    with open(path, "w", encoding="latin-1", newline="") as fh:
        fh.write("\n".join(lines) + "\n")


# ------------------------------------------------------------------ check --

# ------------------------------------------------------------ certificates --
# v1.15: every SATISFIED verdict carries a certificate (rule index + witness)
# that the independent checker (tools/vdp_cert_check, checker/vdp_checker.c)
# must accept. The cross-check requires: every certificate the procedure emits
# is accepted and its witness is valid by the definition below (written from
# checker/vdp_checker.h); every forged certificate whose claim is false is
# rejected; and a mutated witness is accepted exactly when it is still valid.

def trace_valid(gtoks, s, spans):
    """Does the span list prove that the glob (token list) matches s?"""
    pos, k = 0, 0
    for tk in gtoks:
        if tk[0] in ("lit", "set"):
            if pos >= len(s):
                return False
            b = ord(s[pos])
            if (tk[0] == "lit" and b != tk[1]) or (tk[0] == "set" and b not in tk[1]):
                return False
            pos += 1
            continue
        if k >= len(spans):
            return False
        a, b = spans[k]
        k += 1
        if a != pos or b < a or b > len(s):
            return False
        seg = s[a:b]
        if tk[0] == "star" and "/" in seg:
            return False
        if tk[0] == "segs" and seg and seg[-1] != "/":
            return False
        pos = b
    return k == len(spans) and pos == len(s)


def find_spans(gtoks, s, relax=None):
    """Some valid span list for s, or None (small patterns only). relax drops
    one rule of the definition ("star": '/' allowed in a * span; "segs": a
    /**/ span need not end in '/'), to build witnesses that are wrong in
    exactly that way."""
    if len(gtoks) > 200 or len(s) > 400:
        return None
    sys.setrecursionlimit(max(sys.getrecursionlimit(), 5000))
    memo = {}

    def go(ti, pos):
        key = (ti, pos)
        if key in memo:
            return memo[key]
        res = None
        if ti == len(gtoks):
            res = [] if pos == len(s) else None
        else:
            tk = gtoks[ti]
            if tk[0] in ("lit", "set"):
                if pos < len(s):
                    b = ord(s[pos])
                    if (tk[0] == "lit" and b == tk[1]) or (tk[0] == "set" and b in tk[1]):
                        res = go(ti + 1, pos + 1)
            else:
                for e in range(pos, len(s) + 1):
                    seg = s[pos:e]
                    if tk[0] == "star" and "/" in seg and relax != "star":
                        break
                    if tk[0] == "segs" and seg and seg[-1] != "/" and relax != "segs":
                        continue
                    rest = go(ti + 1, e)
                    if rest is not None:
                        res = [(pos, e)] + rest
                        break
        memo[key] = res
        return res
    return go(0, 0)


def wit_str(spans):
    return "g:" + ",".join(f"{a}-{b}" for a, b in spans)


def parse_wit(w):
    if w.startswith("g:"):
        return [tuple(int(x) for x in p.split("-")) for p in w[2:].split(",") if p]
    return None


def cert_checks(checker, policy, rules, rx, qs, res, wants, rng, stats, fails):
    lines, expect, labels = [], [], []

    def add(kind, sval, fval, r, w, want, label):
        fl = "-" if fval is None else hex(fval)
        hx = sval.encode("latin-1").hex() or "="
        lines.append(f"{kind} {fl} {hx} {r} {w}")
        expect.append(want)
        labels.append(label)

    for (kind, sval, fval), r, want in zip(qs, res, wants):
        allow_idx = [i for i, x in enumerate(rules) if x["kind"] == kind and x["verb"] == "allow"]
        sym = kind == "path" and fval is None
        if r["verdict"] != want:
            continue       # the procedure's conservative UNKNOWN (enumeration bound)
        if r["verdict"] == "SATISFIED":
            w = r.get("w", "!")
            ri = r["rule"]
            if w == "!":
                fails.append(f"{policy}: {kind} {sval[:40]!r}: SATISFIED without a witness")
                continue
            if w.startswith("g:") and not trace_valid(rules[ri]["gtoks"], sval, parse_wit(w)):
                fails.append(f"{policy}: {kind} {sval[:40]!r}: the procedure's glob witness {w} is invalid")
            add(kind, sval, fval, ri, w, "ok", "procedure certificate")
            stats["certs_emitted"] += 1
            # a mutated witness is accepted exactly when it is still valid
            spans = parse_wit(w)
            if spans:
                m = [list(x) for x in spans]
                k = rng.randrange(len(m))
                m[k][rng.randrange(2)] += rng.choice([-1, 1, 2])
                m = [tuple(x) for x in m]
                if all(0 <= a and 0 <= b for a, b in m):
                    add(kind, sval, fval, ri, wit_str(m),
                        "ok" if trace_valid(rules[ri]["gtoks"], sval, m) else "reject", "mutated witness")
                    stats["certs_mutated"] += 1
        # forged claims: another allow rule, or any rule when not SATISFIED
        if sym:
            truth_first = None
        else:
            truth_first = r["rule"] if r["verdict"] == "SATISFIED" else None
        # (-1 claims "every flags value is decided by some allow rule": a
        # forgery only when the verdict is not SATISFIED)
        for fr in rng.sample(allow_idx, min(3, len(allow_idx))) + \
                ([-1] if sym and r["verdict"] != "SATISFIED" else []):
            if fr == truth_first:
                continue
            if sym and r["verdict"] == "SATISFIED" and fr == r["rule"]:
                continue
            rr = rules[fr] if fr >= 0 else None
            w = "-"
            if rr and rr["op"] == "contains":
                k = sval.find(rr["c"])
                w = f"c:{k if k >= 0 else 0}"
            elif rr and rr["op"] == "glob":
                sp = find_spans(rr["gtoks"], sval)
                w = wit_str(sp) if sp is not None else wit_str([(0, 0)] * sum(
                    1 for t in rr["gtoks"] if t[0] in ("star", "dstar", "segs")))
            add(kind, sval, fval, fr, w, "reject", "forged claim")
            stats["certs_forged"] += 1
    # Strings that a glob matches only if one rule of the definition is
    # relaxed (a '/' inside '*', a /**/ unit not ending in '/'): claims on them
    # with the relaxed witness must be refused.
    for fr, rr in enumerate(rules):
        if rr["op"] != "glob" or rr["verb"] != "allow":
            continue
        for _ in range(3):
            out = []
            for tk in rr["gtoks"]:
                if tk[0] == "lit":
                    out.append(chr(tk[1]))
                elif tk[0] == "set":
                    out.append(chr(rng.choice(sorted(tk[1]))))
                elif tk[0] == "star":
                    out.append(rng.choice(["", "a", "a/b", "/"]))
                elif tk[0] == "dstar":
                    out.append(rng.choice(["", "a", "a/"]))
                else:
                    out.append(rng.choice(["", "x", "a/x"]))
            sval = "".join(out)
            if len(sval) > L or rx.matches(rr["lang"], sval):
                continue
            for relax in ("star", "segs"):
                sp = find_spans(rr["gtoks"], sval, relax)
                if sp is not None:
                    fv = 0 if rr["kind"] != "path" else rr["value"]
                    add(rr["kind"], sval, fv, fr, wit_str(sp), "reject", f"witness wrong ({relax})")
                    stats["certs_forged"] += 1
    # Deny claims, kind confusion, and witnesses wrong in one specific way.
    for (kind, sval, fval), r, want in zip(qs, res, wants):
        if len(sval) > L:
            continue
        for fr, rr in enumerate(rules):
            if rr["kind"] == kind and rr["verb"] == "deny" and rng.random() < 0.3:
                add(kind, sval, fval, fr, "-", "reject", "deny-rule claim")
                stats["certs_forged"] += 1
            elif rr["kind"] != kind and rr["verb"] == "allow" and rng.random() < 0.2:
                add(kind, sval, fval, fr, "-", "reject", "claim with a rule of another kind")
                stats["certs_forged"] += 1
            elif rr["kind"] == kind and rr["op"] == "glob" and not rx.matches(rr["lang"], sval):
                for relax in ("star", "segs"):
                    sp = find_spans(rr["gtoks"], sval, relax)
                    if sp is not None:
                        add(kind, sval, fval, fr, wit_str(sp), "reject", f"witness wrong ({relax})")
                        stats["certs_forged"] += 1
    # The checker's own matchers against the oracle's languages, rule by rule
    # and string by string (both directions: a missed match would let a forged
    # claim past an earlier deny rule; an extra one would refuse a true one).
    # Besides the queries: strings drawn from every rule's language, and some
    # padded to exactly the 4095-byte bound.
    probes = []
    for rr in rules:
        for _ in range(4):
            probes.append(sample(rx, rr["lang"], rng))
    for x in list(probes[:6]):
        if 0 < len(x) < L:
            probes.append((x + "/" + "a" * L)[:L])
            probes.append(("/" + "a" * L)[: L - len(x)] + x)
    strs = [sval for _, sval, _ in qs if len(sval) <= L + 3] + [x for x in probes if len(x) <= L]
    hp = subprocess.run([checker, policy, "holds"],
                        input="\n".join(x.encode("latin-1").hex() or "=" for x in strs) + "\n",
                        capture_output=True, text=True, timeout=600)
    hl = hp.stdout.splitlines()
    if len(hl) != len(strs):
        fails.append(f"{policy}: checker 'holds' answered {len(hl)} of {len(strs)}")
    else:
        for sval, row in zip(strs, hl):
            for i, rr in enumerate(rules):
                want = rx.matches(rr["lang"], sval)
                stats["cert_holds"] += 1
                if (row[i] == "1") != want:
                    fails.append(f"{policy}: checker says rule {i} (line {rr['line']}) "
                                 f"{'holds' if row[i] == '1' else 'does not hold'} on {sval[:60]!r}; "
                                 f"the oracle says {'it does' if want else 'it does not'}")
                    break
        # targeted forgeries: an allow rule that holds, after the first rule
        # that holds (so only the earlier-rule check can refuse the claim)
        extra = [(k, x, rng.choice([0, 0x1, 0x2, 0x241])) for x in probes for k in ("path", "exec")]
        for (kind, sval, fval), r, want in list(zip(qs, res, wants)) + [(e, None, None) for e in extra]:
            if (kind == "path" and fval is None) or len(sval) > L:
                continue
            fv = fval if kind == "path" else 0
            hold = [i for i, rr in enumerate(rules) if rr["kind"] == kind
                    and (fv & rr["mask"]) == rr["value"] and rx.matches(rr["lang"], sval)]
            if len(hold) < 2 or (kind == "path" and ((fv & ~KNOWN) or (fv & ACC) == ACC)):
                continue
            for fr in hold[1:]:
                rr = rules[fr]
                if rr["verb"] != "allow":
                    continue
                w = "-"
                if rr["op"] == "contains":
                    w = f"c:{sval.find(rr['c'])}"
                elif rr["op"] == "glob":
                    sp = find_spans(rr["gtoks"], sval)
                    if sp is None:
                        continue
                    w = wit_str(sp)
                add(kind, sval, fval, fr, w, "reject", "shadowed claim")
                stats["certs_shadowed"] += 1
    if not lines:
        return
    p = subprocess.run([checker, policy, "batch"], input="\n".join(lines) + "\n",
                       capture_output=True, text=True, timeout=600)
    got = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
    if len(got) != len(lines):
        fails.append(f"{policy}: checker answered {len(got)} of {len(lines)} ({p.stderr.strip()[:200]})")
        return
    for ln, want, lab, g in zip(lines, expect, labels, got):
        if g["check"] != want:
            fails.append(f"{policy}: checker {g['check']} ({g.get('why')}) on {lab}, expected {want}: {ln[:160]}")


def check_policy(vdp, policy, rng, nq, stats, verbose, checker=None):
    new_context()
    fails = []
    try:
        rules, rx = parse_policy(policy)
        py_ok = True
    except PolicyError as e:
        rules, rx, py_ok = None, None, False
        py_err = str(e)
    rc, out, err = run_vdp(vdp, policy, "analyze")
    c_ok = rc == 0
    if py_ok != c_ok:
        fails.append(f"{policy}: parse disagreement (python ok={py_ok}, C ok={c_ok}; {err.strip() or ''} {'' if py_ok else py_err})")
        return fails
    if checker:
        # the certificate checker parses the policy independently too
        k = subprocess.run([checker, policy, "digest"], capture_output=True, text=True)
        if (k.returncode == 0) != c_ok:
            fails.append(f"{policy}: parse disagreement (checker ok={k.returncode == 0}, "
                         f"procedure ok={c_ok}; {k.stderr.strip()[:200]})")
            return fails
        if c_ok:
            with open(policy, "rb") as fh:
                if k.stdout.strip() != hashlib.sha256(fh.read()).hexdigest():
                    fails.append(f"{policy}: checker's policy digest differs from SHA-256")
    if not py_ok:
        stats["rejected_policies"] += 1
        return fails
    stats["policies"] += 1
    if any(r["op"] in ("suffix", "contains", "glob") for r in rules):
        stats["string_policies"] += 1

    # Reachability of every rule, and the witness of every REACHABLE answer.
    reach = [json.loads(l) for l in out.splitlines() if l.strip()]
    if len(reach) != len(rules):
        fails.append(f"{policy}: rule count mismatch ({len(reach)} vs {len(rules)})")
        return fails
    # The automaton search on every path/exec rule too (the trie method decides
    # those rules in normal use): both methods must match the oracle.
    rc2, out2, _ = run_vdp(vdp, policy, "analyze", "automaton")
    forced = [json.loads(l) for l in out2.splitlines() if l.strip()]
    for i, rr in enumerate(reach):
        want = None
        stats["reach"] += 1
        for label, res in (("", rr), (" [automaton]", forced[i] if i < len(forced) else {})):
            if label and rules[i]["kind"] == "host":
                continue
            if label:
                stats["reach_forced_checked"] += 1
                if res == rr:
                    continue            # same answer and witness as above: checked
            got = res.get("reach")
            if got == "UNKNOWN":
                # Only a documented budget may give UNKNOWN; the answer is
                # then conservative whatever the oracle would say.
                why = res.get("why")
                if why not in ("enumeration_bound", "state_budget", "witness_alphabet"):
                    fails.append(f"{policy}: rule {i} (line {rules[i]['line']}){label} UNKNOWN "
                                 f"without a budget reason ({why!r})")
                else:
                    stats["reach_unknown"] += 1
                    stats[f"reach_unknown_{why}"] = stats.get(f"reach_unknown_{why}", 0) + 1
                continue
            if want is None:
                try:
                    want = oracle_reach(rx, rules, i, stats)
                except RuntimeError as e:
                    fails.append(f"{policy}: rule {i} (line {rules[i]['line']}): {e}")
                    break
            if got != want:
                fails.append(f"{policy}: rule {i} (line {rules[i]['line']}) reach{label} C={got} oracle={want}")
                continue
            if got == "REACHABLE":
                w = bytes.fromhex(res["witness"]).decode("latin-1")
                fv = int(res["flags"], 16)
                stats["witnesses"] += 1
                first = oracle_first(rx, rules, rules[i]["kind"], w, fv) if len(w) <= L else "OUT"
                if first != i:
                    fails.append(f"{policy}: rule {i} (line {rules[i]['line']}){label} witness "
                                 f"{w[:40]!r} flags={fv:#x} does not make it fire first (solver: {first})")

    # Ground and symbolic queries.
    qs = gen_queries(rules, rx, rng, nq)
    lines = []
    for kind, sval, fval in qs:
        fl = "-" if fval is None else hex(fval)
        lines.append(f"{kind} {fl} {sval.encode('latin-1').hex()}")
    rc, out, err = run_vdp(vdp, policy, "batch", stdin="\n".join(lines) + "\n")
    res = [json.loads(l) for l in out.splitlines() if l.strip()]
    if len(res) != len(qs):
        fails.append(f"{policy}: batch answered {len(res)} of {len(qs)}")
        return fails
    wants = []
    for (kind, sval, fval), r in zip(qs, res):
        if kind == "path" and fval is None:
            want = oracle_symbolic(rx, rules, sval)
            stats["symbolic"] += 1
        else:
            want = oracle_ground(rx, rules, kind, sval, fval)
            stats["ground"] += 1
        got = r["verdict"]
        wants.append(want)
        if r.get("why") == "enumeration_bound":
            stats["bound_seen"] += 1
        if got == want:
            continue
        if got == "UNKNOWN" and r.get("why") == "enumeration_bound":
            stats["bound_unknown"] += 1
            continue
        shown = sval if len(sval) < 60 else sval[:30] + f"...({len(sval)} bytes)"
        fails.append(f"{policy}: {kind} {shown!r} flags={fval}: C={got} ({r.get('why')}) solver={want}")
    if checker:
        cert_checks(checker, policy, rules, rx, qs, res, wants, rng, stats, fails)
    return fails


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--vdp", required=True)
    ap.add_argument("--cert", help="certificate checker (tools/vdp_cert_check): check every "
                    "certificate the procedure emits, and forged and mutated ones")
    ap.add_argument("--fuzz", type=int, default=0, help="random policies to generate")
    ap.add_argument("--seed", type=int, default=1010)
    ap.add_argument("--queries", type=int, default=60)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("policies", nargs="*")
    a = ap.parse_args()

    rng = random.Random(a.seed)
    stats = {k: 0 for k in ("policies", "rejected_policies", "string_policies", "reach",
                            "reach_regex", "reach_solver_inconclusive", "reach_forced_checked",
                            "reach_unknown", "witnesses", "ground", "symbolic",
                            "bound_unknown", "bound_seen", "certs_emitted", "certs_forged",
                            "certs_mutated", "certs_shadowed", "cert_holds")}
    fails = []
    for p in a.policies:
        fails += check_policy(a.vdp, p, rng, a.queries, stats, a.verbose, a.cert)
    with tempfile.TemporaryDirectory() as td:
        for k in range(a.fuzz):
            p = os.path.join(td, f"fuzz{k}.txt")
            fuzz_policy(rng, p)
            fails += check_policy(a.vdp, p, rng, a.queries, stats, a.verbose, a.cert)
            if fails and not a.verbose:
                keep = os.path.join(tempfile.gettempdir(), f"vdp_fail_{k}.txt")
                with open(p, encoding="latin-1") as src, open(keep, "w", encoding="latin-1") as dst:
                    dst.write(src.read())
                fails.append(f"(failing fuzz policy saved to {keep})")
                break
    total = stats["reach"] + stats["reach_forced_checked"] + stats["ground"] + stats["symbolic"]
    print(f"smt_crosscheck: {stats['policies']} policies ({stats['string_policies']} with "
          f"suffix/contains/glob rules; {stats['rejected_policies']} rejected by both parsers), "
          f"{total} checks: {stats['reach']} reachability (+{stats['reach_forced_checked']} "
          f"automaton-search re-checks), {stats['ground']} ground, {stats['symbolic']} "
          f"symbolic-flag; {stats['witnesses']} witnesses confirmed by the solver")
    reasons = ", ".join(f"{k[len('reach_unknown_'):]} {v}" for k, v in sorted(stats.items())
                        if k.startswith("reach_unknown_")) or "none"
    print(f"smt_crosscheck: reachability UNKNOWN by reason: {reasons}")
    print(f"smt_crosscheck: string reachability decided by derivatives {stats['reach_regex']} "
          f"times, solver regex conclusive on {stats['reach_regex'] - stats['reach_solver_inconclusive']} "
          f"(inconclusive {stats['reach_solver_inconclusive']}: model past the length bound or "
          f"timeout); procedure bound hits {stats['bound_seen']} (verdicts), "
          f"{stats['reach_unknown']} (reachability); conservative UNKNOWN answers at a "
          f"budget: {stats['reach_unknown'] + stats['bound_unknown']}")
    if a.cert:
        print(f"smt_crosscheck: certificates: {stats['certs_emitted']} emitted by the procedure "
              f"and accepted, {stats['certs_forged']} forged claims and "
              f"{stats['certs_shadowed']} claims shadowed by an earlier rule rejected, "
              f"{stats['certs_mutated']} mutated witnesses judged as the definition says; "
              f"{stats['cert_holds']} rule/string matches agree with the oracle")
    for fl in fails[:40]:
        print("  DISAGREE", fl)
    print(f"smt_crosscheck: {'PASS' if not fails else 'FAIL'} "
          f"({len(fails)} disagreement{'s' if len(fails) != 1 else ''})")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
