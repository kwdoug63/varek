#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_check.py — judge a v1.25 soak run (soak.sh) against section 5 of
docs/security/v1.25-wildcard-host-names.md: a real API reached through many
names under one suffix, for 24 hours, with a wildcard rule at the default
budgets, shows

  1. the run lasted the time asked, with a fetch every interval;
  2. no refused connect from a stale table: no connect to the soak port was
     refused, and no fetch failed because a name did not resolve or a connect
     was refused (failures the Warden did not cause, such as a server error
     or a timeout, are listed and may be up to --max-other-failures);
  3. every question recorded: each fetch's name was asked of the stub (a
     dns_question record) shortly before the fetch;
  4. no budget hit in normal use: no wildcard_budget record;
  5. every peer the agent reached was the name's address (current, or in
     grace) by the latest resolution record before the fetch;
  6. tools/varek_audit.py passes (certificates, chain, the stub's records and
     budgets, connects decided over many names).

It also reports what the run says about the defaults: distinct names, the
most new names in any minute, lookups, retirements, and the most names on
one address (connects recorded with hashed candidates).

  soak_check.py --dir OUT --policy OUT/policy.txt --checker tools/vdp_cert_check \\
      [--hours 24] [--interval 60] [--port 443] [--pubkey K.pub]

Prints a report (also written to OUT/report.txt) and exits 0 on PASS.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "..", "tools")


def load_stream(path):
    recs = []
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh:
            if line.startswith("{"):
                try:
                    recs.append(json.loads(line))
                except ValueError:
                    pass
    return recs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--checker", required=True)
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--max-other-failures", type=float, default=0.01,
                    help="fraction of fetches that may fail for reasons outside the Warden")
    ap.add_argument("--pubkey")
    a = ap.parse_args()

    out, problems = [], []
    say = out.append
    recs = load_stream(os.path.join(a.dir, "verdicts.log"))
    fetches = []
    with open(os.path.join(a.dir, "agent.jsonl")) as fh:
        for line in fh:
            try:
                fetches.append(json.loads(line))
            except ValueError:
                pass

    # 1. duration and cadence
    start = next((r for r in recs if r.get("event") == "run_start"), None)
    end = next((r for r in recs if r.get("event") == "run_end"), None)
    if not start or not end:
        problems.append("the stream has no run_start or no run_end (the run did not finish)")
        dur = 0.0
    else:
        dur = (end["timestamp_ns"] - start["timestamp_ns"]) / 1e9
    ok = [f for f in fetches if f.get("ok")]
    names = sorted({f["name"] for f in fetches})
    say(f"run: {dur / 3600:.2f} h (asked {a.hours:g} h); {len(fetches)} fetches over {len(names)} "
        f"names, {len(ok)} ok, {len(fetches) - len(ok)} failed; {len(recs)} records")
    if dur < a.hours * 3600 * 0.99:
        problems.append(f"the run lasted {dur / 3600:.2f} h, less than {a.hours:g} h")
    want = a.hours * 3600 / a.interval
    if len(fetches) < want * 0.98:
        problems.append(f"{len(fetches)} fetches, fewer than the {want:.0f} expected")

    # 2. refused connects and failed fetches
    refused = [r for r in recs if r.get("action") == "net.connect" and r.get("decision_final") == "DENY"
               and str(r.get("target", "")).endswith(f":{a.port}")]
    say(f"refused connects to port {a.port}: {len(refused)}")
    for r in refused[:20]:
        problems.append(f"seq {r.get('seq')}: connect to {r.get('target')} refused (rule {r.get('rule')}, "
                        f"decided on {r.get('resolved')!r})")
    failed = [f for f in fetches if not f.get("ok")]
    warden = [f for f in failed if "PermissionError" in f.get("error", "") or "gaierror" in f.get("error", "")]
    for f in warden[:20]:
        problems.append(f"{f['name']} at {f['t']}: {f.get('error')} (refused or not resolved)")
    other = [f for f in failed if f not in warden]
    if other:
        kinds = {}
        for f in other:
            k = f.get("error", f"HTTP {f.get('status')}")[:80]
            kinds[k] = kinds.get(k, 0) + 1
        say(f"failures outside the Warden: {len(other)} (" +
            ", ".join(f"{k} x{v}" for k, v in kinds.items()) + ")")
        if fetches and len(other) / len(fetches) > a.max_other_failures:
            problems.append(f"{len(other)} of {len(fetches)} fetches failed for other reasons")

    # 3. every fetch's name asked of the stub just before
    qs = [r for r in recs if r.get("event") == "dns_question"]
    asked = {}
    for q in qs:
        asked.setdefault(q.get("name"), []).append(q["timestamp_ns"])
    unasked = 0
    for f in ok:
        t = int(f["t"] * 1e9)
        if not any(t - 30 * 10**9 <= x <= t + 5 * 10**9 for x in asked.get(f["name"], [])):
            unasked += 1
            if unasked <= 10:
                problems.append(f"{f['name']} at {f['t']}: fetched with no question to the stub recorded")
    answers = {}
    for q in qs:
        answers[q.get("answer")] = answers.get(q.get("answer"), 0) + 1
    say(f"stub questions: {len(qs)} (" + ", ".join(f"{k} {v}" for k, v in sorted(answers.items())) +
        f"); fetches with no recorded question: {unasked}")

    # 4. budgets, and what the run says about the defaults
    hits = [q for q in qs if q.get("rule") == "wildcard_budget"]
    say(f"budget refusals: {len(hits)}")
    for q in hits[:10]:
        problems.append(f"{q.get('name')}: refused by the {q.get('budget')} budget in normal use")
    new = sorted(q["timestamp_ns"] for q in qs if q.get("new"))
    peak = max((sum(1 for y in new if x - 60 * 10**9 < y <= x) for x in new), default=0)
    if start and isinstance(start.get("wildcard_budgets"), list) and start["wildcard_budgets"]:
        b = start["wildcard_budgets"][0]
        say(f"names charged: {len(new)} of {b.get('names')}; most in any minute: {peak} of {b.get('rate')}")

    # 5. peers bound by the resolution records
    res = [r for r in recs if r.get("event") == "resolution"]
    # (v1.25 review: grace_end and unanswered records are not lookups either)
    lookups = sum(1 for r in res if r.get("dynamic") and r.get("a") not in ("retired", "grace_end", "unanswered"))
    retired = sum(1 for r in res if r.get("a") == "retired")
    ended = sum(1 for r in res if r.get("a") == "grace_end")
    say(f"resolution records: {lookups} lookups on demand, {retired} retirements, {ended} ends of grace")

    def bound(name, addr, t_ns):
        latest = None
        for r in res:
            if r.get("name") == name and r["timestamp_ns"] <= t_ns:
                latest = r
        if latest is None:
            return False
        if addr in (latest.get("addresses") or []):
            return True
        return any(g.get("address") == addr and t_ns <= latest["timestamp_ns"] + g.get("until_s", 0) * 1e9
                   for g in latest.get("grace") or [])
    unbound = 0
    for f in fetches:
        if f.get("peer") and not bound(f["name"], f["peer"], int(f["t"] * 1e9) + 2 * 10**9):
            unbound += 1
            if unbound <= 10:
                problems.append(f"{f['name']} at {f['t']}: reached {f['peer']}, which no resolution "
                                f"record of it gave")
    say(f"peers the agent reached: all in the resolution records: {'yes' if not unbound else 'NO'}")
    conns = [r for r in recs if r.get("action") == "net.connect" and r.get("decision_final") == "ALLOW"
             and str(r.get("target", "")).endswith(f":{a.port}")]
    most = max([r.get("candidates_n", len(r.get("candidates") or [])) for r in conns] or [0])
    hashed = sum(1 for r in conns if "candidates_sha256" in r)
    say(f"connects decided: {len(conns)}; most candidates on one connect: {most} "
        f"({max(most - 1, 0)} names on one address); recorded hashed: {hashed}")

    # 6. the audit
    cmd = [sys.executable, os.path.join(TOOLS, "varek_audit.py"), "--policy", a.policy,
           "--checker", a.checker, os.path.join(a.dir, "verdicts.log")]
    if a.pubkey:
        cmd[2:2] = ["--pubkey", a.pubkey]
    p = subprocess.run(cmd, capture_output=True, text=True)
    say("audit: " + (p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr.strip()))
    if p.returncode != 0:
        problems.append("varek_audit.py failed: " + "; ".join(
            l.strip() for l in p.stdout.splitlines() if "PROBLEM" in l)[:600])

    say("")
    for pr in problems[:60]:
        say(f"  PROBLEM {pr}")
    say(f"soak_check: {'PASS' if not problems else 'FAIL'}")
    text = "\n".join(out) + "\n"
    print(text, end="")
    with open(os.path.join(a.dir, "report.txt"), "w") as fh:
        fh.write(text)
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
