#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_check.py — judge a v1.28 soak run (soak.sh) against step 7 of
docs/security/v1.28-credential-release.md: an agent holding only
placeholders for four credentials calls an API for 24 hours, and the run is
revoked near the end. The run shows

  1. it lasted the time asked, with a call every interval, the agent holding
     a placeholder for each credential and run_start listing all four;
  2. before the revocation every call succeeded, and the API found the value
     in the header its rule names, nowhere else, for each (the body intact);
  3. every probe held: a missing header and another credential's placeholder
     refused by the proxy (each a credential_refused), a placeholder where no
     rule names one sent as it is, the file store unreadable to the agent;
  4. the Vault lease renewed by warden-secrets all run long (every 40 s of
     its 60), none failing;
  5. the revocation: recorded once by root, the proxy holding no value after
     it, the lease revoked at the stand-in, no call reaching the API after
     it, every call after it refused;
  6. no value in the verdict stream, the agent's output or the API's log,
     and tools/varek_audit.py passes.

It also reports the time each call took, the Warden's time to decide a
request with a credential, and each process's memory over the run.

  soak_check.py --dir OUT --policy OUT/policy.txt --checker tools/vdp_cert_check \\
      --values /etc/varek-soak1280/values.json [--hours 24] [--interval 60] [--pubkey K.pub]

Prints a report (also written to OUT/report.txt) and exits 0 on PASS.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "..", "tools")
NAMES = ("api", "db", "st", "gh")


def load(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh:
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def load_verdicts(path):
    """The Warden's stream, a line at a time, keeping what is judged."""
    v = {"start": None, "end": None, "events": [], "after": [], "req_lat": [], "n": 0, "revoked_seen": False}
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh:
            if not line.startswith("{"):
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            v["n"] += 1
            ev = r.get("event")
            if ev == "run_start" and v["start"] is None:
                v["start"] = r
            elif ev == "run_end":
                v["end"] = r
            elif ev in ("credential_refused", "revoked", "revocation_proxy", "revocation_leases",
                        "lease_renewed", "lease_renewal_failed"):
                v["events"].append(r)
                if ev == "revoked":
                    v["revoked_seen"] = True
            elif "decision_final" in r:
                if v["revoked_seen"] and r.get("decision_final") != "DENY":
                    v["after"].append(r)
                if r.get("action") == "net.request" and r.get("credential") and r.get("decision_final") == "ALLOW":
                    v["req_lat"].append(r.get("latency_us", 0))
    return v


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--checker", required=True)
    ap.add_argument("--values", required=True)
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--pubkey")
    a = ap.parse_args()
    out, problems = [], []
    say = out.append
    D = a.dir
    values = json.load(open(a.values))
    agent = load(os.path.join(D, "agent.jsonl"))
    api = load(os.path.join(D, "api.jsonl"))
    vd = load_verdicts(os.path.join(D, "verdicts.log"))
    rs = vd["start"] or {}

    # 1. the run
    say(f"soak_check: v1.28 credential release soak in {D}")
    say(f"Warden {rs.get('warden', '?')}, run {rs.get('run', '?')}, {vd['n']} records"
        + ("" if vd["end"] else " (no run_end: the run did not end cleanly)"))
    if not vd["end"]:
        problems.append("the stream has no run_end")
    creds = rs.get("credentials") if isinstance(rs.get("credentials"), list) else []
    if sorted(c.get("name") for c in creds) != sorted(NAMES) or not rs.get("secrets_binary_sha256"):
        problems.append(f"run_start lists credentials {[c.get('name') for c in creds]}, not the four, "
                        f"or not warden-secrets' SHA-256")
    for c in creds:
        say(f"  credential {c.get('name')}: {c.get('store')}:{c.get('ref')}, version {c.get('version')}, "
            f"{c.get('length')} bytes")
    start = next((r for r in agent if r.get("start")), None)
    if not start or start.get("placeholders") is not True:
        problems.append("the agent did not hold a placeholder for each credential")
    turns = [r for r in agent if "task" in r or "probe" in r]
    want = int(a.hours * 3600 / a.interval)
    say(f"turns: {len(turns)} (about {want} expected)")
    if len(turns) < 0.9 * want:
        problems.append(f"only {len(turns)} turns of about {want}: the run stopped early or stalled")

    # the revocation's time
    # (varek revoke's start and end: a turn between them is judged neither way)
    t_rev = t_rev_end = None
    rev_out = ""
    try:
        t, t1, rev_out = open(os.path.join(D, "revoke.txt")).read().strip().split("\t", 2)
        t_rev, t_rev_end = float(t), float(t1)
    except (OSError, ValueError):
        problems.append("no revoke.txt: the run was not revoked")
    if t_rev is not None and "revoked" not in rev_out:
        problems.append(f"varek revoke said: {rev_out!r}")
    before = [r for r in turns if t_rev is None or r["t"] < t_rev]
    after = [r for r in turns if t_rev_end is not None and r["t"] > t_rev_end]

    # 2. calls before the revocation, and what the API found
    tasks = [r for r in before if "task" in r]
    failed = [r for r in tasks if not r.get("ok")]
    by = {n: sum(1 for r in tasks if r["task"] == n) for n in NAMES}
    say(f"calls before the revocation: {len(tasks)} (" + ", ".join(f"{n} {by[n]}" for n in NAMES) +
        f"), succeeded: {len(tasks) - len(failed)}")
    for r in failed[:10]:
        problems.append(f"call {r['task']} at {r['t']}: {r.get('status', r.get('error'))}")
    api_cred = [r for r in api if r.get("credential")]
    api_bad = [r for r in api_cred if not r.get("value_ok") or r.get("value_elsewhere")
               or (r.get("path") == "/v1/c" and not r.get("body_ok"))]
    say(f"the API: {len(api_cred)} calls with a credential, the value where its rule names it in "
        f"{len(api_cred) - len(api_bad)}")
    for r in api_bad[:10]:
        problems.append(f"the API at {r['t']}: {r.get('path')} {r.get('credential')}: value "
                        f"{'right' if r.get('value_ok') else 'wrong or missing'}"
                        f"{', and a value elsewhere in the request' if r.get('value_elsewhere') else ''}"
                        f"{', body changed' if r.get('path') == '/v1/c' and not r.get('body_ok') else ''}")
    ok_all = sum(1 for r in turns if "task" in r and r.get("ok"))
    if len(api_cred) != ok_all:
        problems.append(f"the API saw {len(api_cred)} calls with a credential, the agent made {ok_all} "
                        f"that succeeded")
    # (soak.sh's own check that the API is listening, before the run, is no error)
    t_start = (rs.get("timestamp_ns") or 0) / 1e9
    errs = [r for r in api if r.get("error") and r.get("t", 0) >= t_start]
    if errs:
        problems.append(f"the API logged {len(errs)} error(s) (first: {errs[0]['error']})")

    # 3. probes
    probes = [r for r in before if "probe" in r]
    pk = {}
    for r in probes:
        pk[r["probe"]] = pk.get(r["probe"], 0) + 1
        if not r.get("held"):
            problems.append(f"probe {r['probe']} at {r['t']} did not hold: {r.get('status', r.get('error', r.get('result')))}")
    say(f"probes before the revocation: {len(probes)} (" + ", ".join(f"{k} {v}" for k, v in sorted(pk.items())) +
        f"), held: {sum(1 for r in probes if r.get('held'))}")
    if len(turns) >= 3 and not probes:
        problems.append("no probes ran")
    cf = [e for e in vd["events"] if e.get("event") == "credential_refused"]
    want_cf = pk.get("missing", 0) + pk.get("other", 0)
    say(f"swaps refused by the proxy (credential_refused): {len(cf)} (the missing and other probes: {want_cf})")
    if len(cf) != want_cf:
        problems.append(f"{len(cf)} credential_refused records, for {want_cf} probes that must each make one")

    # 4. the lease
    ren = [e for e in vd["events"] if e.get("event") == "lease_renewed"]
    renf = [e for e in vd["events"] if e.get("event") == "lease_renewal_failed"]
    t0 = (rs.get("timestamp_ns") or 0) / 1e9
    span = ((t_rev or (agent[-1]["t"] if agent else t0)) - t0) if t0 else 0
    want_ren = int(span / 40)
    say(f"lease renewals: {len(ren)} (about {want_ren} in {span / 3600:.2f} h), failed: {len(renf)}")
    if renf:
        problems.append(f"{len(renf)} lease renewal(s) failed (first: {renf[0].get('why')})")
    if want_ren >= 3 and len(ren) < 0.9 * want_ren:
        problems.append(f"only {len(ren)} lease renewals of about {want_ren}")
    if any(e.get("credential") != "db" or e.get("ttl") != 60 for e in ren):
        problems.append("a renewal that is not the db lease's, or not for 60 s")
    sreq = open(os.path.join(D, "stores", "requests.log")).read().splitlines() \
        if os.path.exists(os.path.join(D, "stores", "requests.log")) else []
    say(f"the stand-in got {sum(1 for l in sreq if 'PUT renew database/creds/soak/Sk1 token=ok' in l)} renewals")

    # 5. the revocation
    rv = [e for e in vd["events"] if e.get("event") == "revoked"]
    rp = [e for e in vd["events"] if e.get("event") == "revocation_proxy"]
    rl = [e for e in vd["events"] if e.get("event") == "revocation_leases"]
    if t_rev is not None:
        say(f"revoked at {t_rev:.0f} ({len(after)} turns after it): proxy values held "
            f"{rp[0].get('values_held') if rp else '?'}, leases revoked {rl[0].get('revoked') if rl else '?'} "
            f"(failed {rl[0].get('failed') if rl else '?'})")
        if len(rv) != 1 or rv[0].get("by_uid") != 0:
            problems.append(f"the revocation is recorded {len(rv)} time(s), or not by root")
        if not rp or rp[0].get("values_held") != 0:
            problems.append("the proxy did not report holding no value after the revocation")
        if not rl or rl[0].get("revoked") != 1 or rl[0].get("failed") != 0:
            problems.append("the Vault lease was not revoked (revocation_leases)")
        if not any("PUT revoke database/creds/soak/Sk1 token=ok" in l for l in sreq):
            problems.append("the stand-in got no revoke for the lease")
        if not after:
            problems.append("no turn ran after the revocation")
        through = [r for r in after if r.get("ok") or r.get("status") == 200]
        if through:
            problems.append(f"{len(through)} call(s) after the revocation succeeded (first: {through[0]})")
        late = [r for r in api if r.get("t", 0) > t_rev_end]
        if late:
            problems.append(f"{len(late)} call(s) reached the API after the revocation")
        if vd["after"]:
            r = vd["after"][0]
            problems.append(f"{len(vd['after'])} decision(s) allowed after the revocation (first: seq "
                            f"{r.get('seq')} {r.get('action')} {r.get('target')})")
        late_ren = [e for e in ren if e.get("timestamp_ns", 0) / 1e9 > t_rev_end]
        if late_ren:
            problems.append(f"{len(late_ren)} renewal(s) after the revocation")

    # 6. no value anywhere, and the audit
    for f in ("verdicts.log", "agent.jsonl", "api.jsonl", "stores/requests.log", "rss.tsv"):
        p = os.path.join(D, f)
        if os.path.exists(p):
            data = open(p, encoding="utf-8", errors="surrogateescape").read()
            leaked = [n for n, v in values.items() if v in data]
            if leaked:
                problems.append(f"{f} holds the value of {', '.join(leaked)}")
    ms = [r.get("ms", 0) for r in tasks if r.get("ok")]
    say(f"a call with a credential, at the agent: p50 {pct(ms, .5)} ms, p99 {pct(ms, .99)} ms; the Warden's "
        f"decision on it: p50 {pct(vd['req_lat'], .5)} us, p99 {pct(vd['req_lat'], .99)} us")
    try:
        rows = [l.split("\t") for l in open(os.path.join(D, "rss.tsv")).read().splitlines()[1:]]
        rows = [r for r in rows if len(r) == 4]
        for i, name in ((1, "warden"), (2, "warden-proxy"), (3, "warden-secrets")):
            xs = [int(r[i]) for r in rows if r[i].isdigit()]
            if xs:
                say(f"memory, {name}: {xs[0]} kB at the start, {max(xs)} kB at most, {xs[-1]} kB at the end "
                    f"({len(xs)} samples)")
                if xs[-1] > xs[0] + 16384:
                    say(f"  note: {name} grew by {xs[-1] - xs[0]} kB over the run")
    except OSError:
        say("memory: no rss.tsv")
    cmd = [sys.executable, os.path.join(TOOLS, "varek_audit.py"), "--policy", a.policy,
           "--checker", a.checker, os.path.join(D, "verdicts.log")]
    if a.pubkey:
        cmd[2:2] = ["--pubkey", a.pubkey]
    p = subprocess.run(cmd, capture_output=True, text=True)
    for ln in p.stdout.splitlines():
        if ln.startswith("varek_audit: credentials:") or ln.startswith("varek_audit: note:"):
            say(ln)
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
    with open(os.path.join(D, "report.txt"), "w") as fh:
        fh.write(text)
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
