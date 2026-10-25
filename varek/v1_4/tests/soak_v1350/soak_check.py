#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_check.py — judges the v1.35 soak (soak.sh) from what its run left in
DIR/d/:

  - the run: the Warden and the agent exited 0; a turn each interval, about
    as many as the hours give (at least 95%), each done by the SDK's loop
    with its tools (the scripted model's answer);
  - the plan: decided SATISFIED at the gate, by the SHA-256 of the plan
    `varek plan generate` wrote, and the run held to it (run_start's hold);
  - the probes, every tenth turn: each refused, as the agent saw it, and
    in the stream as outside the plan (rule outside_plan), each of the three
    the same number of times as the probes ran; no other call refused;
  - the docs server: tools/call of search_docs and get_doc about once a turn,
    never get_secret (the probe's call must not reach it);
  - the audit (varek_audit.py --plan) PASS; the OCSF export valid OCSF 1.9.0,
    and the plan gate's event in it;
  - each process's memory over the run (rss.tsv): a note above 16 MB of growth.

  soak_check.py --dir DIR --v14 DIR [--hours 24] [--interval 60] [--pubkey K.pub]
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys


def load(path):
    out = []
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            for line in fh:
                if line.startswith("{"):
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--v14", required=True)
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--pubkey")
    ap.add_argument("--sign-key")
    a = ap.parse_args()
    if a.sign_key and not a.pubkey and os.path.exists(a.sign_key + ".pub"):
        a.pubkey = a.sign_key + ".pub"
    D = os.path.join(a.dir, "d")
    tools = os.path.join(a.v14, "tools")
    out, problems = [], []
    say = out.append
    say(f"soak_check: the v1.35 soak in {a.dir}: {a.hours} h, a turn every {a.interval} s")
    for f in ("verdicts.log", "agent.jsonl", "agent.plan", "policy.txt", "server.jsonl", "exit"):
        if not os.path.exists(os.path.join(D, f)):
            problems.append(f"no d/{f}")
    try:
        rc = open(os.path.join(D, "exit")).read().strip()
    except OSError:
        rc = "?"
    say(f"  the Warden exited {rc}")
    if rc != "0":
        problems.append(f"the Warden exited {rc}, not 0")

    # the turns and the probes, as the agent saw them
    turns = [r for r in load(os.path.join(D, "agent.jsonl")) if "turn" in r]
    want = int(a.hours * 3600 / a.interval)
    bad = [r for r in turns if not r.get("ok")]
    probed = [r for r in turns if "probes" in r]
    say(f"  turns: {len(turns)} (about {want} expected), {len(bad)} not done, {len(probed)} with probes")
    if len(turns) < 0.95 * want:
        problems.append(f"{len(turns)} turns, fewer than 95% of the {want} the run's length gives")
    for r in bad[:5]:
        problems.append(f"turn {r.get('turn')} not done: {r.get('error') or r.get('output')}")
    let = [(r["turn"], k, v.get("detail")) for r in probed for k, v in r["probes"].items() if not v.get("refused")]
    for t, k, d in let[:5]:
        problems.append(f"turn {t}: the {k} probe was let through ({d})")
    if not probed:
        problems.append("no probe ran")

    # the stream: the gate, the hold, every refusal
    recs = load(os.path.join(D, "verdicts.log"))
    rs = next((r for r in recs if r.get("event") == "run_start"), {})
    gate = next((r for r in recs if r.get("event") == "plan_gate"), {})
    try:
        sha = hashlib.sha256(open(os.path.join(D, "agent.plan"), "rb").read()).hexdigest()
    except OSError:
        sha = None
    say(f"  the plan gate: {gate.get('verdict')}, {gate.get('actions')} steps; held: {bool(rs.get('hold'))}")
    if gate.get("verdict") != "SATISFIED" or gate.get("plan_sha256") != sha:
        problems.append(f"the plan gate decided {gate.get('verdict')} on {gate.get('plan_sha256')}, not SATISFIED on "
                        f"the plan written ({sha})")
    if not isinstance(rs.get("hold"), dict) or rs["hold"].get("plan_sha256") != sha:
        problems.append("run_start does not hold the run to the plan written")
    conf = json.load(open(os.path.join(D, "agent", "soak.json")))
    denied = [r for r in recs if r.get("decision_final") == "DENY"]
    outside = [r for r in denied if r.get("rule") == "outside_plan"]
    # refused as every run refuses them, plan or not: glibc's nscd (names go to the Warden's stub), and
    # the MCP client's GET to open the server's stream and DELETE to end its session (no mcp rule
    # decides them and no step kind names them: the client goes on without either; for v1.36)
    def expected(r):
        t = str(r.get("resolved") or r.get("target") or "")
        return (r.get("action") == "net.connect" and t == "unix:/var/run/nscd/socket") or \
            (r.get("action") == "net.request" and t in ("GET " + conf["mcp_url"], "DELETE " + conf["mcp_url"]))
    known = [r for r in denied if r.get("rule") != "outside_plan" and expected(r)]
    other = [r for r in denied if r.get("rule") != "outside_plan" and not expected(r)]
    by = {"file": 0, "host": 0, "mcp": 0}
    for r in outside:
        t = str(r.get("resolved") or r.get("target") or "")
        if r.get("action") == "net.mcp" and r.get("mcp_name") == "get_secret":
            by["mcp"] += 1
        elif t == conf["outside"]:
            by["file"] += 1
        elif "status.example.com" in t or r.get("action") in ("net.connect", "net.proxy"):
            by["host"] += 1
        else:
            problems.append(f"seq {r.get('seq')}: refused outside the plan, and not a probe's: {r.get('action')} {t}")
    say(f"  refused outside the plan: {len(outside)} (file {by['file']}, host {by['host']}, mcp {by['mcp']}); "
        f"refused as every run is (nscd, the MCP transport's GET and DELETE): {len(known)}; refused otherwise: {len(other)}")
    for k, n in by.items():
        if n < len(probed):
            problems.append(f"the {k} probe ran {len(probed)} times, and {n} of its calls are refused outside the plan")
    for r in other[:5]:
        problems.append(f"seq {r.get('seq')}: refused ({r.get('rule')}), a call no probe makes: {r.get('action')} "
                        f"{r.get('resolved') or r.get('target')}")

    # the docs server
    srv = load(os.path.join(D, "server.jsonl"))
    calls = {}
    for r in srv:
        if r.get("rpc") == "tools/call":
            calls[r.get("tool")] = calls.get(r.get("tool"), 0) + 1
    say(f"  the docs server: {sum(calls.values())} tools/call ({', '.join(f'{k} {v}' for k, v in sorted(calls.items()))})")
    if calls.get("get_secret"):
        problems.append(f"get_secret reached the docs server {calls['get_secret']} time(s)")
    for t in ("search_docs", "get_doc"):
        if calls.get(t, 0) < 0.95 * len(turns):
            problems.append(f"{t} reached the server {calls.get(t, 0)} times in {len(turns)} turns")

    # the audit, and the OCSF export
    cmd = [sys.executable, os.path.join(tools, "varek_audit.py"), "--policy", os.path.join(D, "policy.txt"),
           "--checker", os.path.join(tools, "vdp_cert_check"), "--plan", os.path.join(D, "agent.plan"),
           os.path.join(D, "verdicts.log")]
    if a.pubkey:
        cmd[2:2] = ["--pubkey", a.pubkey]
    p = subprocess.run(cmd, capture_output=True, text=True)
    for ln in p.stdout.splitlines():
        if ln.startswith(("varek_audit: plan:", "varek_audit: integrity:")):
            say("  " + ln)
    say("  audit: " + (p.stdout.strip().splitlines() or ["?"])[-1] + f" (exit {p.returncode})")
    if p.returncode != 0:
        problems.append("the audit: " + "; ".join(l.strip() for l in p.stdout.splitlines() if "PROBLEM" in l)[:600])
    ev = os.path.join(D, "events.ocsf")
    cmd = [sys.executable, os.path.join(tools, "varek_ocsf.py"), "--log", os.path.join(D, "verdicts.log"), "--policy",
           os.path.join(D, "policy.txt"), "--checker", os.path.join(tools, "vdp_cert_check"), "--output", ev]
    if a.pubkey:
        cmd += ["--pubkey", a.pubkey]
    p = subprocess.run(cmd, capture_output=True, text=True)
    v = subprocess.run([sys.executable, os.path.join(a.v14, "tests", "ocsf_validate.py"), ev], capture_output=True,
                       text=True)
    gates = [e for e in load(ev) if e.get("unmapped", {}).get("varek", {}).get("event") == "plan_gate"]
    say(f"  OCSF: {(v.stdout.strip().splitlines() or ['?'])[-1]}; the plan gate's event: {len(gates)}")
    if p.returncode != 0 or v.returncode != 0 or len(gates) != 1 or gates[0].get("action") != "Allowed":
        problems.append(f"the OCSF export (exit {p.returncode}, validation exit {v.returncode}, {len(gates)} gate event(s))")

    try:
        lines = open(os.path.join(D, "rss.tsv")).read().splitlines()
        head = lines[0].split("\t")
        rows = [l.split("\t") for l in lines[1:]]
        for i, name in enumerate(head[1:], 1):
            xs = [int(r[i]) for r in rows if len(r) > i and r[i].isdigit()]
            if xs:
                say(f"  memory, {name}: {xs[0]} kB at the start, {max(xs)} kB at most, {xs[-1]} kB at the end "
                    f"({len(xs)} samples)")
                if xs[-1] > xs[0] + 16384:
                    say(f"    note: {name} grew by {xs[-1] - xs[0]} kB over the run")
    except (OSError, IndexError):
        say("  memory: no rss.tsv")
    say("")
    for pr in problems[:80]:
        say(f"  PROBLEM {pr}")
    say(f"soak_check: {'PASS' if not problems else 'FAIL'}")
    print("\n".join(out))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
