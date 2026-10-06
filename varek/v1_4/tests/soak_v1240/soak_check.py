#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_check.py — judge a v1.24 soak run (soak.sh) against section 5 of
docs/security/v1.21-stage2-host-names.md:

  1. it ran the time asked (run_start to run_end), with the agent fetching
     each URL every interval;
  2. no refused connect caused by a stale table: no connect to a soak name's
     port was refused, and every fetch that failed is accounted for (a failure
     the Warden did not cause, such as a server error or a timeout, is listed
     but does not fail the run, up to --max-other-failures);
  3. every refresh recorded: each name has resolution records at least as
     often as its own refresh_s says (with --slack seconds of tolerance);
  4. every address the agent used is in the resolution records: each peer the
     agent reached was the name's address (current, or in grace) by the latest
     resolution record before the connect;
  5. each URL was served by the CDN it is meant to test (from response
     headers), when --expect gives one;
  6. tools/varek_audit.py passes on the stream (certificates, chain, signatures
     with --pubkey, name-to-address bindings).

  soak_check.py --dir OUT --policy OUT/policy.txt --checker tools/vdp_cert_check \
      [--hours 24] [--interval 60] [--expect URL=fastly ...] [--pubkey K.pub]

Prints a report (also written to OUT/report.txt) and exits 0 on PASS.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.parse

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
    ap.add_argument("--slack", type=float, default=30)
    ap.add_argument("--max-other-failures", type=float, default=0.01,
                    help="fraction of fetches that may fail for reasons outside the Warden")
    ap.add_argument("--expect", action="append", default=[], help="URL=fastly|cloudflare|cloudfront")
    ap.add_argument("--pubkey")
    a = ap.parse_args()

    out = []
    problems = []
    say = out.append
    recs = load_stream(os.path.join(a.dir, "verdicts.log"))
    fetches = []
    with open(os.path.join(a.dir, "agent.jsonl")) as fh:
        for line in fh:
            try:
                fetches.append(json.loads(line))
            except ValueError:
                pass
    start = next((r for r in recs if r.get("event") == "run_start"), None)
    end = next((r for r in recs if r.get("event") == "run_end"), None)
    if not start or not end:
        problems.append("the stream has no run_start or no run_end (the run did not finish)")
        dur = 0.0
    else:
        dur = (end["timestamp_ns"] - start["timestamp_ns"]) / 1e9
    say(f"run: {dur / 3600:.2f} h (asked {a.hours:g} h); {len(fetches)} fetches; "
        f"{len(recs)} records")
    if dur < a.hours * 3600 * 0.99:
        problems.append(f"the run lasted {dur / 3600:.2f} h, less than {a.hours:g} h")

    # 1. fetch cadence, per URL
    urls = sorted({f["url"] for f in fetches})
    want = a.hours * 3600 / a.interval
    hosts = {}
    for u in urls:
        fs = [f for f in fetches if f["url"] == u]
        ok = [f for f in fs if f.get("ok")]
        hosts[u] = urllib.parse.urlsplit(u)
        say(f"{u}: {len(fs)} fetches, {len(ok)} ok, {len(fs) - len(ok)} failed")
        if len(fs) < want * 0.98:
            problems.append(f"{u}: {len(fs)} fetches, fewer than the {want:.0f} expected")

    # 2. refused connects to a soak name, and failed fetches
    names = {h.hostname for h in hosts.values()}
    ports = {h.port or (443 if h.scheme == "https" else 80) for h in hosts.values()}
    refused = [r for r in recs if r.get("action") == "net.connect" and r.get("decision_final") == "DENY"
               and any(str(r.get("target", "")).endswith(f":{p}") for p in ports)]
    say(f"refused connects to the soak ports: {len(refused)}")
    for r in refused[:20]:
        problems.append(f"seq {r.get('seq')}: connect to {r.get('target')} refused "
                        f"(rule {r.get('rule')}, decided on {r.get('resolved')!r}): a stale table?")
    failed = [f for f in fetches if not f.get("ok")]
    warden_caused = [f for f in failed if "PermissionError" in f.get("error", "")
                     or "gaierror" in f.get("error", "")]
    for f in warden_caused[:20]:
        problems.append(f"{f['url']} at {f['t']}: {f.get('error')} (refused or not resolved: "
                        f"the Warden's table or views)")
    other = [f for f in failed if f not in warden_caused]
    if other:
        kinds = {}
        for f in other:
            # the whole message, not only the type: four "OSError: [Errno 101]
            # Network is unreachable" in the first 24-hour run were the Warden's
            # (an IPv6-only hosts view on an IPv4-only host), not the network's
            k = f.get("error", f"HTTP {f.get('status')}")[:80]
            kinds[k] = kinds.get(k, 0) + 1
        say(f"failures outside the Warden: {len(other)} ({', '.join(f'{k} x{v}' for k, v in kinds.items())})")
        if fetches and len(other) / len(fetches) > a.max_other_failures:
            problems.append(f"{len(other)} of {len(fetches)} fetches failed for other reasons "
                            f"(more than {a.max_other_failures:.1%}): look at the network before trusting the run")

    # 3. refresh cadence, per name
    res = [r for r in recs if r.get("event") == "resolution"]
    for n in sorted(names):
        rs = [r for r in res if r.get("name") == n]
        changes = 0
        prev_set = None
        worst = 0.0
        for x, y in zip(rs, rs[1:]):
            gap = (y["timestamp_ns"] - x["timestamp_ns"]) / 1e9
            allowed = x.get("refresh_s", 30) + a.slack
            worst = max(worst, gap - x.get("refresh_s", 30))
            if gap > allowed:
                problems.append(f"{n}: {gap:.0f} s between resolution records, its refresh was "
                                f"{x.get('refresh_s')} s (a refresh not made or not recorded)")
        for r in rs:
            s = tuple(sorted(r.get("addresses") or []))
            if prev_set is not None and s != prev_set:
                changes += 1
            prev_set = s
        ttls = sorted({r.get("refresh_s") for r in rs})
        say(f"{n}: {len(rs)} resolution records, refresh {ttls[0] if ttls else '-'}..{ttls[-1] if ttls else '-'} s, "
            f"{changes} answer changes, worst lateness {worst:.1f} s")
        if not rs:
            problems.append(f"{n}: no resolution records")

    # 4. every peer the agent reached was the name's address by the records
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
    graced = 0
    for f in fetches:
        if not f.get("peer"):
            continue
        n = hosts[f["url"]].hostname
        t_ns = int(f["t"] * 1e9)
        if not bound(n, f["peer"], t_ns + 2 * 10**9):     # the connect precedes the agent's timestamp
            unbound += 1
            if unbound <= 20:
                problems.append(f"{f['url']} at {f['t']}: reached {f['peer']}, which no resolution "
                                f"record of {n} gave")
        else:
            latest = [r for r in res if r.get("name") == n and r["timestamp_ns"] <= t_ns + 2 * 10**9][-1]
            if f["peer"] not in (latest.get("addresses") or []):
                graced += 1
    say(f"peers the agent reached: all in the resolution records: {'yes' if not unbound else 'NO'}; "
        f"{graced} fetch(es) used an address in its grace period")

    # 5. the CDN each URL is meant to test
    for e in a.expect:
        u, _, cdn = e.partition("=")
        seen = {f.get("cdn") for f in fetches if f["url"] == u and f.get("ok")}
        say(f"{u}: served by {', '.join(sorted(x for x in seen if x)) or 'nothing'} (expected {cdn})")
        if cdn not in seen:
            problems.append(f"{u}: no response showed {cdn}'s headers: it does not test {cdn}")

    # 6. the audit
    cmd = [sys.executable, os.path.join(TOOLS, "varek_audit.py"), "--policy", a.policy,
           "--checker", a.checker, os.path.join(a.dir, "verdicts.log")]
    if a.pubkey:
        cmd[2:2] = ["--pubkey", a.pubkey]
    p = subprocess.run(cmd, capture_output=True, text=True)
    say("audit: " + (p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr.strip()))
    for line in p.stdout.splitlines():
        if line.startswith("varek_audit: integrity"):
            say(line.replace("varek_audit: ", "audit "))
    if p.returncode != 0:
        problems.append("varek_audit.py failed: " + "; ".join(
            l.strip() for l in p.stdout.splitlines() if "PROBLEM" in l)[:600])

    say("")
    for pr in problems[:60]:
        say(f"  PROBLEM {pr}")
    verdict = "PASS" if not problems else "FAIL"
    say(f"soak_check: {verdict}")
    text = "\n".join(out) + "\n"
    print(text, end="")
    with open(os.path.join(a.dir, "report.txt"), "w") as fh:
        fh.write(text)
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
