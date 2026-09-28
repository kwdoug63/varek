#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
verdict_harness.py — verdict-distribution harness for the VAREK SMT decision
procedure (v1.13; the v1.10 verification program).

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

To measure what the new fragment buys, the same actions are also decided under
two policies v1.12 could have enforced from the same file:

  v1.12-permissive  every flag clause removed (v1.12 ignored open flags, so a
                    "(read)" rule also admitted writes);
  v1.12-strict      every rule that carries a flag clause removed (the only way
                    to keep writes out under v1.12, which also turns the reads
                    into UNKNOWN).

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


def strip_policy(text, mode):
    """v1.12 views of a v1.13 policy."""
    out = []
    for ln in text.splitlines():
        body = ln.split("#", 1)[0].split()
        if len(body) < 3:
            out.append(ln)
            continue
        if len(body) > 3:
            if mode == "strict":
                continue                                  # rule dropped
            ln = " ".join(body[:3])                       # clauses dropped
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


def fmt_row(name, s):
    t = s["table"]
    return (f"  {name:18s} SAFE: {t['SAFE']['SATISFIED']:3d} SAT {t['SAFE']['UNSATISFIED']:3d} UNSAT "
            f"{t['SAFE']['UNKNOWN']:3d} UNK | UNSAFE: {t['UNSAFE']['SATISFIED']:3d} SAT "
            f"{t['UNSAFE']['UNSATISFIED']:3d} UNSAT {t['UNSAFE']['UNKNOWN']:3d} UNK | "
            f"clear {100 * s['clear_rate']:5.1f}%  unsafe_satisfied {s['unsafe_satisfied']}")


def main():
    ap = argparse.ArgumentParser(description="VAREK verdict-distribution harness")
    ap.add_argument("--vdp", required=True)
    ap.add_argument("--base", default=".", help="directory policy_file paths are relative to")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("corpus", nargs="+")
    a = ap.parse_args()

    cases = load_cases(a.corpus, a.base)
    views = {"v1.13": None, "v1.12-permissive": "permissive", "v1.12-strict": "strict"}
    tabs = {v: table() for v in views}
    details = []
    synthetic = False
    for c in cases:
        synthetic |= c.get("provenance", "").startswith("synthetic")
        for view, mode in views.items():
            pol = c["_policy"] if mode is None else strip_policy(c["_policy"], mode)
            res = decide(a.vdp, pol, c["actions"])
            for act, r in zip(c["actions"], res):
                tabs[view][act["truth"]][r["verdict"]] += 1
                if view == "v1.13":
                    details.append({"case": c["id"], "label": act["label"], "kind": act["kind"],
                                    "target": act["target"], "flags": act.get("flags"),
                                    "truth": act["truth"], "verdict": r["verdict"],
                                    "why": r["why"], "policy_line": r["line"]})

    report = {v: summarize(t) for v, t in tabs.items()}
    report["cases"] = len(cases)
    report["actions"] = report["v1.13"]["safe"] + report["v1.13"]["unsafe"]
    report["provenance"] = ("synthetic: SAI-authored policies and labels; a regression gate "
                            "and demonstration, not a measured baseline") if synthetic else "as supplied"

    print(f"verdict_harness: {report['cases']} cases, {report['actions']} actions "
          f"[{report['provenance']}]")
    for v in views:
        print(fmt_row(v, report[v]))
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
    ok = report["v1.13"]["unsafe_satisfied"] == 0
    print(f"verdict_harness: gate unsafe_satisfied == 0: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
