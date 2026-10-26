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
    in the stream as outside the plan (rule outside_plan) by its exact
    target, during a probe turn's probes, each of the three once per probe
    turn; no other call refused; reconnects to the docs server few;
  - the docs server: tools/call of search_docs and get_doc about once a turn,
    never get_secret (the probe's call must not reach it);
  - the audit (varek_audit.py --plan) PASS; the OCSF export valid OCSF 1.9.0,
    and the plan gate's event in it;
  - each process's memory over the run (rss.tsv): the last quarter's median
    at most 16 MB (or a fifth) above the second quarter's.

  soak_check.py --dir DIR --v14 DIR [--hours 24] [--interval 60] [--pubkey K.pub]
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from urllib.parse import urlsplit


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
    # step 9 (review): a lost session is reconnected; more than a few means the run did not hold up
    recon = [r for r in turns if r.get("reconnected") or r.get("reconnect_error")]
    say(f"  reconnects to the docs server: {len(recon)}")
    if len(recon) > max(3, len(turns) // 500):
        problems.append(f"{len(recon)} reconnects to the docs server in {len(turns)} turns")
    for r in [r for r in turns if r.get("reconnect_error")][:3]:
        problems.append(f"turn {r.get('turn')}: the reconnect failed: {r['reconnect_error']}")

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
    # step 9 (review): each probe's call by its exact target, and within a probe turn's probes (2 s either side)
    su = urlsplit(conf["status_url"])
    status_hp = f"{su.hostname}:{su.port or 443}"
    windows = [(r["probe_t"] - 2, r["probe_end"] + 2) for r in probed if "probe_t" in r and "probe_end" in r]
    by = {"file": 0, "host": 0, "mcp": 0}
    for r in outside:
        t = str(r.get("resolved") or r.get("target") or "")
        if r.get("action") == "net.mcp" and r.get("mcp_name") == "get_secret":
            k = "mcp"
        elif r.get("action") == "file.open" and t == conf["outside"]:
            k = "file"
        elif r.get("action") in ("net.connect", "net.proxy") and str(r.get("target") or "") == status_hp:
            k = "host"
        else:
            problems.append(f"seq {r.get('seq')}: refused outside the plan, and not a probe's: {r.get('action')} {t}")
            continue
        by[k] += 1
        ts = r.get("timestamp_ns")
        if windows and isinstance(ts, int) and not any(a <= ts / 1e9 <= b for a, b in windows):
            problems.append(f"seq {r.get('seq')}: the {k} probe's refusal, at no probe turn's probes")
    say(f"  refused outside the plan: {len(outside)} (file {by['file']}, host {by['host']}, mcp {by['mcp']}); "
        f"refused as every run is (nscd, the MCP transport's GET and DELETE): {len(known)}; refused otherwise: {len(other)}")
    for k, n in by.items():
        if n != len(probed):
            problems.append(f"the {k} probe ran {len(probed)} times, and {n} of its calls are refused outside the plan "
                            f"(one each)")
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
                # step 9 (review): a judgement, not a note: the last quarter's median against the second's
                # (the first quarter is the run settling), over an hour's samples or more
                if len(xs) >= 12:
                    q = len(xs) // 4
                    early, late = sorted(xs[q:2 * q])[q // 2], sorted(xs[-q:])[q // 2]
                    grew = late - early
                    say(f"    the last quarter's median {late} kB, the second's {early} kB")
                    if grew > max(16384, early // 5):
                        problems.append(f"{name}'s memory grew by {grew} kB over the run (median of the last "
                                        f"quarter's samples against the second's)")
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
