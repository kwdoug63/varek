#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_check.py — judge a v1.26.1 soak run (soak.sh) against section 6 of
docs/security/v1.26.1-inspecting-mode.md: an agent under the Warden with the
egress proxy in inspecting mode, fetching real APIs behind several CDNs for
24 hours, shows

  1. the run lasted the time asked, with a fetch every interval, in
     inspecting mode;
  2. no refused request that the policy allows: every fetch of an allowed
     URL was passed on to be inspected (a net.proxy record) and its request
     allowed (a net.request record of its object, certified); a fetch that
     failed after the Warden allowed it (a server error, a timeout) is
     listed, and may be up to --max-other-failures;
  3. every request recorded: each fetch has its records, each connection
     passed on its proxy_close counting its requests, and each probe was
     refused where it must be:
       sni       the name it sent refused (net.proxy DENY);
       host      a different Host: the proxy's parser refused it (403, the
                 close refused_request with request_error), nothing decided;
       path      the allowed path with a "/./" segment: the same;
       denied    a deny rule refused it (net.request policy_match, 403);
       unlisted  no rule allows it (net.request default_deny_unknown, 403);
  4. tools/varek_audit.py passes (connections, requests, bodies, closes,
     certificates, the trust records, the chain).

It also reports, per name, the Warden's time on a connection (decided and
dialed) and on a request (decided and certified), the agent's time for the
whole fetch, and the closes by reason.

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

    # 1. duration, cadence and mode
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
    if start and (not isinstance(start.get("proxy"), dict) or start["proxy"].get("mode") != "inspect"):
        problems.append("run_start's proxy is not in inspecting mode")
    elif start:
        tr = start.get("trust") or {}
        say(f"proxy: {json.dumps(start['proxy'])}; warden-proxy {start.get('proxy_binary_sha256', '?')[:16]}; "
            f"run CA {str(tr.get('ca_sha256', '?'))[:16]} for {tr.get('ca_names', '?')} name(s), "
            f"{tr.get('host_roots', '?')} host roots, key locked {tr.get('ca_key_locked')}")
    if dur < a.hours * 3600 * 0.99:
        problems.append(f"the run lasted {dur / 3600:.2f} h, less than {a.hours:g} h")
    want = a.hours * 3600 / a.interval
    if len(fetches) < want * 0.98:
        problems.append(f"{len(fetches)} fetches and probes, fewer than the {want:.0f} expected")

    # 2 and 3. each fetch and probe against the Warden's records of it: the
    # net.proxy records of name:port, in time order, matched to the fetches
    # of that name:port in time order (one connection each); then the
    # connection's requests and its close
    px = [r for r in recs if r.get("action") == "net.proxy"]
    by_target = {}
    for r in px:
        by_target.setdefault(r.get("target"), []).append(r)
    rq_by_conn = {}
    for r in recs:
        if r.get("action") == "net.request":
            rq_by_conn.setdefault(r.get("proxy_conn"), []).append(r)
    closes = {r.get("proxy_conn"): r for r in recs if r.get("event") == "proxy_close"}
    refused_allowed, unrecorded, other, probe_bad = [], [], [], []
    conn_us, req_us, agent_ms = {}, {}, {}
    probe_kinds = {}
    used = set()
    for f in sorted(fetches, key=lambda f: f["t"]):
        kind = f.get("probe")
        tgt = f"{f['sni'] if kind == 'sni' else f['name']}:{f['port']}"
        t0, t1 = int(f["t"] * 1e9) - 2 * 10**9, int((f["t"] + f.get("ms", 0) / 1000) * 1e9) + 5 * 10**9
        rec = next((r for r in by_target.get(tgt, []) if id(r) not in used and t0 <= r["timestamp_ns"] <= t1), None)
        if rec is not None:
            used.add(id(rec))
        cid = rec.get("proxy_conn") if rec else None
        rq = rq_by_conn.get(cid, []) if rec else []
        close = closes.get(cid) if rec else None
        if kind:
            probe_kinds[kind] = probe_kinds.get(kind, 0) + 1
            if f.get("ok") or rec is None:
                why = "it got through" if f.get("ok") else f"no record of {tgt}"
            elif kind == "sni":
                why = None if rec.get("decision_final") == "DENY" else "the name it sent was not refused"
            elif kind in ("host", "path"):
                why = None if (f.get("status") == 403 and rec.get("decision_final") == "ALLOW" and not rq and
                               close and close.get("why") == "refused_request" and close.get("request_error")) \
                    else "not refused by the proxy's parser (403, refused_request, nothing decided)"
            else:
                rule = "policy_match" if kind == "denied" else "default_deny_unknown"
                obj = f"GET https://{f['name']}:{f['port']}{f.get('path')}"
                why = None if (f.get("status") == 403 and len(rq) == 1 and rq[0].get("decision_final") == "DENY"
                               and rq[0].get("rule") == rule and rq[0].get("target") == obj) \
                    else f"not refused as {rule} ({[(r.get('rule'), r.get('target')) for r in rq]})"
            if why:
                probe_bad.append((f, why))
            continue
        if rec is None:
            unrecorded.append(f)
            continue
        obj = f"GET {f.get('scheme', 'https')}://{f['name']}:{f['port']}{f.get('path', '/')}"
        mine = [r for r in rq if r.get("target") == obj]
        if rec.get("decision_final") != "ALLOW" or rec.get("inspected") is not True or \
                any(r.get("decision_final") != "ALLOW" for r in mine):
            refused_allowed.append((f, rec if rec.get("decision_final") != "ALLOW" else
                                    next((r for r in mine if r.get("decision_final") != "ALLOW"), rec)))
            continue
        if rec.get("rule") == "proxy_dialed" and (close is None or close.get("requests") != len(rq)):
            unrecorded.append(f)
            continue
        if f.get("ok"):
            if len(mine) != 1 or mine[0].get("check") != "ok":
                unrecorded.append(f)
                continue
            conn_us.setdefault(tgt, []).append(rec.get("latency_us", 0))
            req_us.setdefault(tgt, []).append(mine[0].get("latency_us", 0))
            agent_ms.setdefault(tgt, []).append(f.get("ms", 0))
        else:
            other.append((f, mine[0] if mine else rec))
    say(f"fetches the policy allows that the Warden refused: {len(refused_allowed)}")
    for f, r in refused_allowed[:20]:
        problems.append(f"{f['url']} at {f['t']}: refused (rule {r.get('rule')}, seq {r.get('seq')})")
    say(f"fetches with no record of the connection, the request, or the close and its count: {len(unrecorded)}")
    for f in unrecorded[:20]:
        problems.append(f"{f['url']} at {f['t']}: a record is missing ({f.get('error', 'ok')})")
    if other:
        kinds = {}
        for f, r in other:
            k = (f.get("error") or f"HTTP {f.get('status')}")[:70] + f" [{r.get('rule')}]"
            kinds[k] = kinds.get(k, 0) + 1
        say(f"failures after the Warden allowed the request: {len(other)} (" +
            ", ".join(f"{k} x{v}" for k, v in sorted(kinds.items())) + ")")
        if reqs and len(other) / len(reqs) > a.max_other_failures:
            problems.append(f"{len(other)} of {len(reqs)} fetches failed after the Warden allowed them")
    say(f"probes: {len(probes)} (" + ", ".join(f"{k} {v}" for k, v in sorted(probe_kinds.items())) +
        f"), refused and recorded: {len(probes) - len(probe_bad)}")
    for f, why in probe_bad[:20]:
        problems.append(f"probe {f['probe']} at {f['t']}: {why}")
    if not probes and len(fetches) >= 3:
        problems.append("no probes ran")

    # what the proxy costs, and what it relayed
    say("per name (allowed fetches that succeeded), p50/p99: the Warden on the connection (decided and "
        "dialed) and on the request (decided and certified), us; the agent's fetch, ms")
    for tgt in sorted(conn_us):
        c, q, m = conn_us[tgt], req_us[tgt], agent_ms[tgt]
        say(f"  {tgt:<34s} n={len(c):5d}  connection {pct(c, .5):6d}/{pct(c, .99):7d} us  "
            f"request {pct(q, .5):4d}/{pct(q, .99):5d} us   fetch {pct(m, .5):5d}/{pct(m, .99):6d} ms")
    why = {}
    up = down = nreq = 0
    for c in closes.values():
        why[c.get("why")] = why.get(c.get("why"), 0) + 1
        up += c.get("bytes_up") or 0
        down += c.get("bytes_down") or 0
        nreq += c.get("requests") or 0
    say(f"closes: {len(closes)} (" + ", ".join(f"{k} {v}" for k, v in sorted(why.items(), key=str)) +
        f"); {nreq} requests counted; relayed {up} bytes up, {down} down")
    say(f"proxied decisions: {len(px)}; request decisions: {sum(len(v) for v in rq_by_conn.values())}; "
        f"request bodies: {sum(1 for r in recs if r.get('event') == 'request_body')}")

    # 4. the audit
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
