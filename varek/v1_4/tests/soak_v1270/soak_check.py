#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_check.py — judge a v1.27 soak run (soak.sh) against section 7 of
docs/security/v1.27-program-launches.md: an agent under the Warden with
`require warden 1.27`, launching git, python3 and a compiler for 24 hours,
shows

  1. the run lasted the time asked, with a task every interval, Landlock
     holding the agent and a launch set in run_start;
  2. every task succeeded: each of its launches allowed, certified and seen
     running (exec_result launched or gone), none refused, none killed; a task
     that failed after its launches were allowed is listed, and may be up to
     --max-other-failures;
  3. every probe refused where it must be: an unlisted program by no rule
     (default_deny_unknown), a denied one by the deny rule (policy_match), a
     program written during the run by the launch set (exec_not_in_ruleset),
     each with EACCES to the agent;
  4. no process was killed by the identity check, and tools/varek_audit.py
     passes.

It also reports the Warden's time to decide each program's launches.

  soak_check.py --dir OUT --policy OUT/policy.txt --checker tools/vdp_cert_check \\
      [--hours 24] [--interval 60] [--pubkey K.pub]

Prints a report (also written to OUT/report.txt) and exits 0 on PASS.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "..", "tools")
PROBE_RULE = {"unlisted": "default_deny_unknown", "denied": "policy_match", "written": "exec_not_in_ruleset"}


def load(path):
    out = []
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh:
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def pct(v, q):
    v = sorted(v)
    return v[min(len(v) - 1, int(len(v) * q))] if v else -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--checker", required=True)
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--max-other-failures", type=float, default=0.01)
    ap.add_argument("--pubkey")
    a = ap.parse_args()
    out, problems = [], []
    say = out.append
    recs = load(os.path.join(a.dir, "verdicts.log"))
    turns = load(os.path.join(a.dir, "agent.jsonl"))

    # 1. duration, cadence, Landlock and the launch set
    start = next((r for r in recs if r.get("event") == "run_start"), None)
    end = next((r for r in recs if r.get("event") == "run_end"), None)
    dur = (end["timestamp_ns"] - start["timestamp_ns"]) / 1e9 if start and end else 0.0
    if not start or not end:
        problems.append("the stream has no run_start or no run_end (the run did not finish)")
    tasks = [t for t in turns if "task" in t]
    probes = [t for t in turns if "probe" in t]
    say(f"run: {dur / 3600:.2f} h (asked {a.hours:g} h); {len(tasks)} tasks ({sum(1 for t in tasks if t.get('ok'))} ok) "
        f"and {len(probes)} probes; {len(recs)} records")
    if start:
        ll, ex = start.get("landlock"), start.get("exec_ruleset")
        if not isinstance(ll, dict) or not isinstance(ex, list):
            problems.append(f"run_start has no Landlock ({ll!r}) or no launch set")
        else:
            whys = {}
            for e in ex:
                whys[e.get("why")] = whys.get(e.get("why"), 0) + 1
            say(f"Landlock ABI {ll.get('abi')}; launch set: {len(ex)} files ("
                + ", ".join(f"{v} {k}" for k, v in sorted(whys.items())) + f"); Warden {start.get('warden')}")
    if dur < a.hours * 3600 * 0.99:
        problems.append(f"the run lasted {dur / 3600:.2f} h, less than {a.hours:g} h")
    want = a.hours * 3600 / a.interval
    if len(turns) < want * 0.98:
        problems.append(f"{len(turns)} turns, fewer than the {want:.0f} expected")

    launches = [r for r in recs if r.get("action") == "process.exec" and r.get("rule") != "bootstrap_exec_allow"]
    results = {}
    for r in recs:
        if r.get("event") == "exec_result":
            results[r.get("decision_seq")] = r.get("result")

    # 2. tasks: each of their launches allowed and seen; probes are judged below
    probe_paths = {t["path"] for t in probes}
    task_launches = [r for r in launches if r.get("resolved") not in probe_paths]
    refused = [r for r in task_launches if r.get("decision_final") != "ALLOW"]
    say(f"launches: {len(launches)} decided, {sum(1 for r in launches if r.get('rule') == 'exec_allowed')} allowed; "
        f"task launches refused: {len(refused)}")
    for r in refused[:20]:
        problems.append(f"seq {r.get('seq')}: a task's launch of {r.get('resolved')!r} was refused ({r.get('rule')})")
    unseen = [r for r in task_launches if r.get("rule") == "exec_allowed"
              and results.get(r.get("seq")) not in ("launched", "gone")]
    if unseen:
        problems.append(f"{len(unseen)} allowed launches without exec_result launched or gone "
                        f"(first: seq {unseen[0].get('seq')}, {results.get(unseen[0].get('seq'))!r})")
    out_r = {}
    for v in results.values():
        out_r[v] = out_r.get(v, 0) + 1
    say("exec_result: " + ", ".join(f"{k} {v}" for k, v in sorted(out_r.items(), key=str)))
    failed = [t for t in tasks if not t.get("ok")]
    if failed:
        kinds = {}
        for t in failed:
            k = f"{t['task']}: rc {t.get('rc')} errno {t.get('errno')} {str(t.get('out'))[:60]}"
            kinds[k] = kinds.get(k, 0) + 1
        say(f"tasks that failed: {len(failed)} (" + "; ".join(f"{k} x{v}" for k, v in sorted(kinds.items())) + ")")
        if tasks and len(failed) / len(tasks) > a.max_other_failures:
            problems.append(f"{len(failed)} of {len(tasks)} tasks failed")
    per = {}
    for t in tasks:
        per.setdefault(t["task"], []).append(t)
    say("per task: " + "; ".join(f"{k} {sum(1 for t in v if t.get('ok'))}/{len(v)} ok, "
                                  f"p50 {pct([t['ms'] for t in v], .5):.0f} ms p99 {pct([t['ms'] for t in v], .99):.0f} ms"
                                  for k, v in sorted(per.items())))

    # 3. probes
    bad = []
    pk = {}
    for t in probes:
        pk[t["probe"]] = pk.get(t["probe"], 0) + 1
        mine = [r for r in launches if r.get("resolved") == t["path"]
                and abs(r.get("timestamp_ns", 0) / 1e9 - t["t"]) < 60]
        rule = PROBE_RULE[t["probe"]]
        if not t.get("refused") or not mine or any(r.get("decision_final") == "ALLOW" for r in mine) or \
                any(r.get("rule") != rule for r in mine):
            bad.append((t, f"not refused as {rule} ({[(r.get('rule'), r.get('decision_final')) for r in mine]}, "
                           f"agent errno {t.get('errno')})"))
    say(f"probes: {len(probes)} (" + ", ".join(f"{k} {v}" for k, v in sorted(pk.items())) +
        f"), refused and recorded: {len(probes) - len(bad)}")
    for t, why in bad[:20]:
        problems.append(f"probe {t['probe']} at {t['t']}: {why}")
    if not probes and len(turns) >= 3:
        problems.append("no probes ran")

    # 4. no kill, and the Warden's time per program
    killed = [r for r in recs if r.get("rule") == "exec_identity_mismatch"]
    if killed:
        problems.append(f"{len(killed)} process(es) killed by the identity check (first: {killed[0].get('exe')!r})")
    lat = {}
    for r in launches:
        if r.get("rule") == "exec_allowed":
            lat.setdefault(r.get("resolved"), []).append(r.get("latency_us", 0))
    say("the Warden's time to decide an allowed launch, p50/p99 us:")
    for k in sorted(lat):
        say(f"  {k:52s} n={len(lat[k]):5d}  {pct(lat[k], .5):5d} / {pct(lat[k], .99):6d}")
    cmd = [sys.executable, os.path.join(TOOLS, "varek_audit.py"), "--policy", a.policy,
           "--checker", a.checker, os.path.join(a.dir, "verdicts.log")]
    if a.pubkey:
        cmd[2:2] = ["--pubkey", a.pubkey]
    p = subprocess.run(cmd, capture_output=True, text=True)
    say("audit: " + (p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr.strip()))
    if p.returncode != 0:
        problems.append("varek_audit.py failed: " + "; ".join(
            ln.strip() for ln in p.stdout.splitlines() if "PROBLEM" in ln)[:600])
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
