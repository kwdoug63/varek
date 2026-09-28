#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
verdict_harness.py — verdict-distribution harness for the VAREK SMT decision
procedure (v1.13, v1.14; the v1.10 verification program).

Each corpus case names a policy and a list of concrete actions labelled with a
ground truth, SAFE or UNSAFE. Every action is decided by the Warden's decision
procedure (through tools/vdp_check, the same smt_decide.c the Warden runs), and
the harness reports:

  - the outcome table: verdict (SATISFIED / UNSATISFIED / UNKNOWN) by ground
    truth (SAFE / UNSAFE);
  - clear rate: SAFE actions proved SATISFIED / all SAFE actions;
  - over-refusal: SAFE actions not SATISFIED (UNKNOWN or UNSATISFIED);
  - the GATE: unsafe_satisfied == 0. Any UNSAFE action proved SATISFIED fails
    the run (exit 1). This is the soundness obligation every v1.10/v1.11-program
    extension is admitted under.

To measure what each fragment buys, the same actions are also decided under:

  v1.13.0 shipped   the policy file as v1.13.0 shipped it (a verbatim copy in
                    harness/baseline-v1.13.0/, named by "v1130_policy_file"):
                    flag clauses, no string matchers;
  v1.12.4 shipped   the policy file as v1.12.4 shipped it (harness/baseline-
                    v1.12.4/, "v1124_policy_file"): prefix rules only;
  flags ignored     the current file with every flag clause removed (what a
                    Warden without the flag fragment would enforce from it: a
                    "(read)" rule admits writes);
  flag rules dropped the current file with every flag-constrained rule removed
                    (the only way to keep those writes out without the flag
                    fragment, which also turns the reads into UNKNOWN).

Two caveats the report states rather than hides. A SATISFIED verdict on an exec
or connect is still refused at run time (those are deny-only since v1.9.1), so
the report gives file-open figures separately. And the same action appears in
several cases (the loader actions are in all five), so the report gives the
number of distinct actions.

PROVENANCE. The seed corpus shipped in harness/corpus/ is synthetic: its
policies are SAI's example sector policies and its SAFE/UNSAFE labels were
written by SAI. The CHANGELOG requires ground truth from customer-authored
policies and adversarial labels from an independent oracle; until such a
corpus exists, numbers from this harness are a regression gate and a
demonstration, not a measured baseline, and are reported as synthetic.

Usage:
  verdict_harness.py --vdp tools/vdp_check [--json out.json] CORPUS_DIR_OR_FILES...
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import tempfile

ACC = {"O_RDONLY": 0, "O_WRONLY": 1, "O_RDWR": 2}
BITS = {
    "O_CREAT": 0o100, "O_EXCL": 0o200, "O_NOCTTY": 0o400, "O_TRUNC": 0o1000,
    "O_APPEND": 0o2000, "O_NONBLOCK": 0o4000, "O_DSYNC": 0o10000,
    "O_ASYNC": 0o20000, "O_DIRECT": 0o40000, "O_LARGEFILE": 0o100000,
    "O_DIRECTORY": 0o200000, "O_NOFOLLOW": 0o400000, "O_NOATIME": 0o1000000,
    "O_CLOEXEC": 0o2000000, "O_SYNC": 0o4010000, "O_PATH": 0o10000000,
    "O_TMPFILE": 0o20200000,
}
VERDICTS = ("SATISFIED", "UNSATISFIED", "UNKNOWN")


def flags_value(spec):
    if spec is None:
        return None
    if isinstance(spec, int):
        return spec
    v = 0
    for name in spec:
        if name in ACC:
            v |= ACC[name]
        elif name in BITS:
            v |= BITS[name]
        else:
            raise ValueError(f"unknown flag {name}")
    return v


_WS = re.compile(r"[ \t\r\n\v\f]+")


MATCHERS = ("exact", "prefix", "suffix", "contains", "glob")


def is_flag_clause(t):
    return t in ("readonly", "access=ro", "access=wo", "access=rw") or \
        (t[:1] in ("+", "-") and t[1:] in BITS)


def strip_policy(text, mode):
    """Flag-free views of the current policy (string matchers kept). Tokenizes
    as the C parser does: ASCII whitespace only, and '#' starts a comment only
    at the start of a token."""
    out = []
    for ln in text.splitlines():
        body = []
        for t in _WS.split(ln):
            if not t:
                continue
            if t.startswith("#"):
                break
            body.append(t)
        if len(body) < 3 or body[0] == "require":
            if body and body[0] == "require":
                continue                                  # v1.12 had no directives
            out.append(ln)
            continue
        core = 4 if (body[2] in MATCHERS and len(body) >= 4
                     and not is_flag_clause(body[3])) else 3
        if len(body) > core:
            if mode == "strict":
                continue                                  # rule dropped
            ln = " ".join(body[:core])                    # clauses dropped
        out.append(ln)
    return "\n".join(out) + "\n"


def decide(vdp, policy_text, actions):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write(policy_text)
        path = fh.name
    try:
        q = []
        for a in actions:
            fv = flags_value(a.get("flags")) if a["kind"] == "path" else 0
            fl = "-" if fv is None else hex(fv)
            q.append(f"{a['kind']} {fl} {a['target'].encode('latin-1').hex()}")
        p = subprocess.run([vdp, path, "batch"], input="\n".join(q) + "\n",
                           capture_output=True, text=True, timeout=120)
        if p.returncode != 0:
            raise RuntimeError(f"vdp_check failed: {p.stderr.strip()}")
        res = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
        if len(res) != len(actions):
            raise RuntimeError("vdp_check answered a different number of queries")
        return res
    finally:
        os.unlink(path)


def load_cases(args, base):
    files = []
    for a in args:
        files += sorted(glob.glob(os.path.join(a, "*.json"))) if os.path.isdir(a) else [a]
    cases = []
    for f in files:
        with open(f) as fh:
            c = json.load(fh)
        c["_file"] = f
        pf = c["policy_file"]
        with open(pf if os.path.isabs(pf) else os.path.join(base, pf)) as fh:
            c["_policy"] = fh.read()
        for key, slot in (("v1124_policy_file", "_policy_v1124"),
                          ("v1130_policy_file", "_policy_v1130")):
            bf = c.get(key)
            if bf:
                with open(bf if os.path.isabs(bf) else os.path.join(base, bf)) as fh:
                    c[slot] = fh.read()
        cases.append(c)
    return cases


def table():
    return {t: {v: 0 for v in VERDICTS} for t in ("SAFE", "UNSAFE")}


def summarize(tab):
    safe = sum(tab["SAFE"].values())
    unsafe = sum(tab["UNSAFE"].values())
    return {
        "table": tab,
        "safe": safe,
        "unsafe": unsafe,
        "clear_rate": tab["SAFE"]["SATISFIED"] / safe if safe else None,
        "over_refusal": (safe - tab["SAFE"]["SATISFIED"]) / safe if safe else None,
        "unsafe_satisfied": tab["UNSAFE"]["SATISFIED"],
        "unsafe_refused_rate": (unsafe - tab["UNSAFE"]["SATISFIED"]) / unsafe if unsafe else None,
    }


def fmt_row(name, s, f):
    t = s["table"]
    return (f"  {name:18s} SAFE: {t['SAFE']['SATISFIED']:3d} SAT {t['SAFE']['UNSATISFIED']:3d} UNSAT "
            f"{t['SAFE']['UNKNOWN']:3d} UNK | UNSAFE: {t['UNSAFE']['SATISFIED']:3d} SAT "
            f"{t['UNSAFE']['UNSATISFIED']:3d} UNSAT {t['UNSAFE']['UNKNOWN']:3d} UNK | "
            f"clear {100 * s['clear_rate']:5.1f}% (file opens {100 * f['clear_rate']:5.1f}%)  "
            f"unsafe_satisfied {s['unsafe_satisfied']} (file opens {f['unsafe_satisfied']}; "
            f"{s.get('unsafe_satisfied_distinct', 0)} distinct)")


def main():
    ap = argparse.ArgumentParser(description="VAREK verdict-distribution harness")
    ap.add_argument("--vdp", required=True)
    ap.add_argument("--base", default=".", help="directory policy_file paths are relative to")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("corpus", nargs="+")
    a = ap.parse_args()

    cases = load_cases(a.corpus, a.base)
    views = {"v1.14": None, "v1.13.0 shipped": "v1130", "v1.12.4 shipped": "v1124",
             "flags ignored": "permissive", "flag rules dropped": "strict"}
    tabs = {v: table() for v in views}
    ftabs = {v: table() for v in views}      # file opens only
    unsafe_sat = {v: set() for v in views}   # distinct UNSAFE actions proved SATISFIED
    details = []
    synthetic = False
    for c in cases:
        synthetic |= c.get("provenance", "").startswith("synthetic")
        for view, mode in views.items():
            if mode is None:
                pol = c["_policy"]
            elif mode in ("v1124", "v1130"):
                if f"_policy_{mode}" not in c:
                    continue
                pol = c[f"_policy_{mode}"]
            else:
                pol = strip_policy(c["_policy"], mode)
            res = decide(a.vdp, pol, c["actions"])
            for act, r in zip(c["actions"], res):
                tabs[view][act["truth"]][r["verdict"]] += 1
                if act["truth"] == "UNSAFE" and r["verdict"] == "SATISFIED":
                    unsafe_sat[view].add((act["kind"], act["target"], json.dumps(act.get("flags"))))
                if act["kind"] == "path":
                    ftabs[view][act["truth"]][r["verdict"]] += 1
                if view == "v1.14":
                    details.append({"case": c["id"], "label": act["label"], "kind": act["kind"],
                                    "target": act["target"], "flags": act.get("flags"),
                                    "truth": act["truth"], "verdict": r["verdict"],
                                    "why": r["why"], "policy_line": r["line"]})

    report = {v: summarize(t) for v, t in tabs.items()}
    for v in views:
        report[v]["unsafe_satisfied_distinct"] = len(unsafe_sat[v])
    freport = {v: summarize(t) for v, t in ftabs.items()}
    report["file_opens"] = freport
    report["cases"] = len(cases)
    report["actions"] = report["v1.14"]["safe"] + report["v1.14"]["unsafe"]
    distinct = {(d["kind"], d["target"], json.dumps(d["flags"]), d["truth"]) for d in details}
    report["distinct_actions"] = len(distinct)
    report["provenance"] = ("synthetic: SAI-authored policies and labels; a regression gate "
                            "and demonstration, not a measured baseline") if synthetic else "as supplied"

    print(f"verdict_harness: {report['cases']} cases, {report['actions']} actions "
          f"({report['distinct_actions']} distinct) [{report['provenance']}]")
    for v in views:
        print(fmt_row(v, report[v], freport[v]))
    print("  note: exec/connect SATISFIED verdicts are still refused at run time "
          "(deny-only since v1.9.1); file-open figures are the runtime outcome")
    bad = [d for d in details if d["truth"] == "UNSAFE" and d["verdict"] == "SATISFIED"]
    over = [d for d in details if d["truth"] == "SAFE" and d["verdict"] != "SATISFIED"]
    for d in bad:
        print(f"  GATE VIOLATION: {d['case']}/{d['label']}: UNSAFE {d['kind']} {d['target']} "
              f"flags={d['flags']} proved SATISFIED (policy line {d['policy_line']})")
    for d in over:
        print(f"  over-refusal:   {d['case']}/{d['label']}: SAFE {d['kind']} {d['target']} "
              f"flags={d['flags']} -> {d['verdict']} ({d['why']})")
    if a.json:
        report["details"] = details
        with open(a.json, "w") as fh:
            json.dump(report, fh, indent=2)
    ok = report["v1.14"]["unsafe_satisfied"] == 0
    print(f"verdict_harness: gate unsafe_satisfied == 0: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
