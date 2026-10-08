#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_check.py — judge a v1.26 soak run (soak.sh) against section 6 of
docs/security/v1.26-egress-proxy.md: an agent under the Warden with the
egress proxy on (SNI mode), fetching real APIs behind several CDNs for 24
hours, shows

  1. the run lasted the time asked, with a fetch every interval;
  2. no refused request that the policy allows: every fetch of an allowed
     URL was decided ALLOW by the Warden (a net.proxy record); a fetch that
     failed after the Warden passed it on (a server error, a timeout, a dial
     the network refused) is listed, and may be up to --max-other-failures;
  3. every request recorded: each fetch has its net.proxy record, each
     connection passed on its proxy_close, and each probe (an allowed name's
     address with an SNI no rule allows) was refused, with a DENY record for
     the name it sent;
  4. tools/varek_audit.py passes (hand-offs, decisions and certificates,
     closes, the chain).

It also reports the time the proxy adds, as the Warden records it (the
report of the name to the socket passed back) and as the agent saw it, per
name, and the bytes relayed.

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
    ap.add_argument("--max-other-failures", type=float, default=0.01,
                    help="fraction of fetches that may fail for reasons outside the Warden")
    ap.add_argument("--pubkey")
    a = ap.parse_args()

    out, problems = [], []
    say = out.append
    recs = load(os.path.join(a.dir, "verdicts.log"))
    fetches = load(os.path.join(a.dir, "agent.jsonl"))

    # 1. duration and cadence
    start = next((r for r in recs if r.get("event") == "run_start"), None)
    end = next((r for r in recs if r.get("event") == "run_end"), None)
    dur = (end["timestamp_ns"] - start["timestamp_ns"]) / 1e9 if start and end else 0.0
    if not start or not end:
        problems.append("the stream has no run_start or no run_end (the run did not finish)")
    reqs = [f for f in fetches if not f.get("probe")]
    probes = [f for f in fetches if f.get("probe")]
    ok = [f for f in reqs if f.get("ok")]
    say(f"run: {dur / 3600:.2f} h (asked {a.hours:g} h); {len(reqs)} fetches ({len(ok)} ok) and "
        f"{len(probes)} probes; {len(recs)} records")
    if start and not isinstance(start.get("proxy"), dict):
        problems.append("run_start names no proxy: the run was not in SNI mode")
    elif start:
        say(f"proxy: {json.dumps(start['proxy'])}")
    if dur < a.hours * 3600 * 0.99:
        problems.append(f"the run lasted {dur / 3600:.2f} h, less than {a.hours:g} h")
    want = a.hours * 3600 / a.interval
    if len(fetches) < want * 0.98:
        problems.append(f"{len(fetches)} fetches and probes, fewer than the {want:.0f} expected")

    # 2 and 3. each fetch and probe against the Warden's records of it: the
    # net.proxy records of name:port, in time order, matched to the fetches
    # of that name:port in time order (one request each)
    px = [r for r in recs if r.get("action") == "net.proxy"]
    by_target = {}
    for r in px:
        by_target.setdefault(r.get("target"), []).append(r)
    closes = {r.get("proxy_conn"): r for r in recs if r.get("event") == "proxy_close"}
    refused_allowed, unrecorded, other, probe_bad = [], [], [], []
    warden_us, agent_ms = {}, {}
    used = set()
    for f in sorted(fetches, key=lambda f: f["t"]):
        tgt = f"{f['sni'] if f.get('probe') else f['name']}:{f['port']}"
        t0, t1 = int(f["t"] * 1e9) - 2 * 10**9, int((f["t"] + f.get("ms", 0) / 1000) * 1e9) + 5 * 10**9
        rec = next((r for r in by_target.get(tgt, []) if id(r) not in used and t0 <= r["timestamp_ns"] <= t1), None)
        if rec is not None:
            used.add(id(rec))
        if f.get("probe"):
            if f.get("ok") or rec is None or rec.get("decision_final") != "DENY":
                probe_bad.append((f, rec))
            continue
        if rec is None:
            unrecorded.append(f)
            continue
        if rec.get("decision_final") != "ALLOW":
            refused_allowed.append((f, rec))
            continue
        if rec.get("rule") == "proxy_dialed" and rec.get("proxy_conn") not in closes:
            unrecorded.append(f)
        if f.get("ok"):
            warden_us.setdefault(tgt, []).append(rec.get("latency_us", 0))
            agent_ms.setdefault(tgt, []).append(f.get("ms", 0))
        else:
            other.append((f, rec))
    say(f"fetches the policy allows that the Warden refused: {len(refused_allowed)}")
    for f, r in refused_allowed[:20]:
        problems.append(f"{f['url']} at {f['t']}: refused (rule {r.get('rule')}, seq {r.get('seq')})")
    say(f"fetches with no record of the request (or of its close): {len(unrecorded)}")
    for f in unrecorded[:20]:
        problems.append(f"{f['url']} at {f['t']}: no net.proxy record, or no proxy_close ({f.get('error', 'ok')})")
    if other:
        kinds = {}
        for f, r in other:
            k = (f.get("error") or f"HTTP {f.get('status')}")[:70] + f" [{r.get('rule')}]"
            kinds[k] = kinds.get(k, 0) + 1
        say(f"failures after the Warden passed the request on: {len(other)} (" +
            ", ".join(f"{k} x{v}" for k, v in sorted(kinds.items())) + ")")
        if reqs and len(other) / len(reqs) > a.max_other_failures:
            problems.append(f"{len(other)} of {len(reqs)} fetches failed after the Warden passed them on")
    say(f"probes (an allowed name's address, SNI {probes[0]['sni'] if probes else '-'}): {len(probes)}, "
        f"refused and recorded: {len(probes) - len(probe_bad)}")
    for f, r in probe_bad[:20]:
        problems.append(f"probe at {f['t']}: {'reached the server' if f.get('ok') else 'no DENY record of ' + f['sni']}")
    if not probes and a.hours >= 0.05:
        problems.append("no probes ran")

    # what the proxy costs, and what it relayed
    say("per name (allowed fetches that succeeded): Warden decision and dial, p50/p99 us; agent's request, p50/p99 ms")
    for tgt in sorted(warden_us):
        w, m = warden_us[tgt], agent_ms[tgt]
        say(f"  {tgt:<34s} n={len(w):5d}  warden {pct(w, .5):6d}/{pct(w, .99):7d} us   "
            f"request {pct(m, .5):5d}/{pct(m, .99):6d} ms")
    why = {}
    up = down = 0
    for c in closes.values():
        why[c.get("why")] = why.get(c.get("why"), 0) + 1
        up += c.get("bytes_up") or 0
        down += c.get("bytes_down") or 0
    say(f"closes: {len(closes)} (" + ", ".join(f"{k} {v}" for k, v in sorted(why.items(), key=str)) +
        f"); relayed {up} bytes up, {down} down")
    handoffs = sum(1 for r in recs if r.get("proxy_handoff") is True)
    say(f"hand-offs: {handoffs}; proxied decisions: {len(px)}")

    # 4. the audit
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
