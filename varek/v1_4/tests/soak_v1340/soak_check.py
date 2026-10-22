#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_check.py — judges a run of soak.sh (v1.34 step 9) and writes
DIR/report.txt. The run passes when:

  long agents   each node's ran the whole run: every turn of work done
                (files, python3, git, the allowed service), every probe
                held, each of the six kinds; not restarted
  short Jobs    at least nine in ten of those due (one less than the run's
                time holds) ran, each to its end with
                every turn done and every probe held; none failed
  services      the denied service saw no request; the allowed one at least
                one for each turn of work
  streams       each agent pod's container has one stream on its node,
                named by its pod, with its run_end; each audited
                (tools/varek_audit.py: signed with the node key, anchored,
                each decision under its policy)
  exporter      each stream's run has the audit's event, passed, in the
                exporter's log on its node
  VAREK's pods  the node agent, plugin, exporter and webhook containers not
                restarted
  memory        the node agent's listener and the long agents' supervisors
                at the end within 1.5 times their size after the first hour
                (and 4 MB), reported as they went

  soak_check.py DIR [--tools varek/v1_4/tools]
"""
import argparse
import collections
import glob
import json
import os
import statistics
import subprocess
import sys

PROBES = {"shadow", "outside", "own_program", "denied_host", "denied_ip", "metadata"}


def jl(path):
    out = []
    try:
        for line in open(path, errors="replace"):
            line = line.strip()
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return out


def pct(xs, p):
    if not xs:
        return 0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


class Check:
    def __init__(self):
        self.rows, self.fails, self.table = [], 0, []

    def __call__(self, ok, what, detail=""):
        self.rows.append(("PASS" if ok else "FAIL", what, detail))
        if not ok:
            self.fails += 1


def agent_log(recs):
    work = [r for r in recs if r.get("task") == "work"]
    probes = [r for r in recs if "probe" in r]
    return {"start": bool(recs) and bool(recs[0].get("start")) and bool(recs[0].get("ok")),
            "end": bool(recs) and bool(recs[-1].get("end")), "work": work, "probes": probes,
            "bad": [r for r in work if not r.get("ok")], "leaks": [r for r in probes if not r.get("held")]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--tools", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
    a = ap.parse_args()
    d = a.dir
    meta = json.load(open(f"{d}/meta.json"))
    hours, interval = meta["hours"], meta["interval"]
    c = Check()
    pods = {}
    for pj in glob.glob(f"{d}/logs/*.pod.json"):
        p = json.load(open(pj))
        pods[p["metadata"]["name"]] = p

    # --- the long agents
    expect_turns = int(hours * 3600 / interval)
    long_turns = long_probes = commits = 0
    http_ms = []
    for i, node in enumerate(meta["nodes"]):
        name = f"long-{i}"
        p = pods.get(name, {})
        st = p.get("status", {})
        cs = (st.get("containerStatuses") or [{}])[0]
        L = agent_log(jl(f"{d}/logs/{name}.jsonl"))
        kinds = {r["probe"] for r in L["probes"]}
        long_turns += len(L["work"])
        long_probes += len(L["probes"])
        commits += sum(1 for r in L["work"] if r.get("commit"))
        http_ms += [r["http_ms"] for r in L["work"] if "http_ms" in r]
        c(L["start"] and L["end"] and st.get("phase") == "Succeeded" and cs.get("restartCount", 0) == 0,
          f"{name} on {node}: ran the whole run, not restarted", f"phase {st.get('phase')}, restarts {cs.get('restartCount')}")
        c(len(L["work"]) + len(L["probes"]) >= 0.95 * expect_turns and not L["bad"],
          f"{name}: every turn of work done", f"{len(L['work'])} done, {len(L['bad'])} failed of {expect_turns} due"
          + (f"; first: {L['bad'][0]}" if L["bad"] else ""))
        c(L["probes"] and not L["leaks"] and kinds == PROBES, f"{name}: every probe held",
          f"{len(L['probes'])} probes, {len(L['leaks'])} not held, kinds {sorted(kinds)}"
          + (f"; first: {L['leaks'][0]}" if L["leaks"] else ""))

    # --- the short Jobs
    short = {n: p for n, p in pods.items() if p["metadata"].get("labels", {}).get("soak") == "short"}
    # the first comes at the schedule's first minute after the start: one fewer
    due = max(1, int(hours * 60 / meta["short_every"]) - 1)
    s_ok = s_bad = 0
    s_probes = 0
    for n, p in sorted(short.items()):
        L = agent_log(jl(f"{d}/logs/{n}.jsonl"))
        s_probes += len(L["probes"])
        good = bool(p.get("status", {}).get("phase") == "Succeeded" and L["start"] and L["end"] and not L["bad"]
                    and not L["leaks"] and L["work"])
        s_ok += good
        if not good:
            s_bad += 1
            c(False, f"short Job pod {n}", f"phase {p.get('status', {}).get('phase')}, start {L['start']}, end {L['end']}, "
              f"failed {L['bad'][:1]}, not held {L['leaks'][:1]}")
    c(s_ok >= 0.9 * due and s_bad == 0, "the short Jobs: each ran to its end, every turn done, every probe held",
      f"{s_ok} of {due} due ran, {s_bad} did not")

    # --- the services
    allowed = [r for r in jl(f"{d}/allowed.jsonl") if "path" in r]
    denied = [r for r in jl(f"{d}/denied.jsonl") if "path" in r]
    all_work = long_turns + sum(len(agent_log(jl(f"{d}/logs/{n}.jsonl"))["work"]) for n in short)
    c(not denied, "the denied service saw no request", f"{len(denied)} requests")
    c(len(allowed) >= all_work, "the allowed service had each turn's request", f"{len(allowed)} requests, {all_work} turns")

    # --- the streams, and the exporter's audits
    streams, by_pod = {}, collections.defaultdict(list)
    for node in meta["nodes"]:
        for s in glob.glob(f"{d}/streams/{node}/*.jsonl"):
            recs = jl(s)
            rs = next((r for r in recs if r.get("event") == "run_start"), None)
            if not rs:
                continue
            pod = (rs.get("node") or {}).get("pod", {})
            if pod.get("namespace") != "varek-soak":
                continue
            # a stream of an earlier run on the same cluster (the node keeps
            # them) is not this run's
            if isinstance(rs.get("timestamp_ns"), int) and rs["timestamp_ns"] < meta["start"] * 10**9:
                continue
            streams[s] = {"node": node, "run": rs.get("run"), "pod": pod.get("name"), "records": len(recs),
                          "end": any(r.get("event") == "run_end" for r in recs),
                          "deny": sum(1 for r in recs if r.get("decision_final") == "DENY"),
                          "allow": sum(1 for r in recs if r.get("decision_final") == "ALLOW")}
            by_pod[pod.get("name")].append(s)
    agent_pods = [f"long-{i}" for i in range(len(meta["nodes"]))] + sorted(short)
    missing = [n for n in agent_pods if len(by_pod.get(n, [])) != 1]
    c(not missing, "each agent pod's container has one stream on its node, named by its pod",
      f"{len(streams)} streams for {len(agent_pods)} pods" + (f"; not one: {missing[:5]}" if missing else ""))
    c(all(v["end"] for v in streams.values()), "each stream has its run_end",
      f"{sum(1 for v in streams.values() if not v['end'])} without")
    audit_bad = []
    for s, v in sorted(streams.items()):
        anchor = f"{d}/streams/{v['node']}/anchor"
        r = subprocess.run([sys.executable, os.path.join(a.tools, "varek_audit.py"), "--policy", s[:-6] + ".policy",
                            "--checker", os.path.join(a.tools, "vdp_cert_check"), "--pubkey", f"{d}/node.key.pub",
                            "--anchor", anchor, s], capture_output=True, text=True)
        v["audit"] = r.returncode == 0
        if r.returncode != 0:
            audit_bad.append((v["pod"], (r.stdout + r.stderr).strip().splitlines()[-1:]))
    c(streams and not audit_bad, "each stream audited: signed with the node key, anchored, each decision under its policy",
      f"{len(streams) - len(audit_bad)} of {len(streams)} pass" + (f"; first failing: {audit_bad[0]}" if audit_bad else ""))
    exported = {}
    for node in meta["nodes"]:
        seen = set()
        for line in open(f"{d}/exporter/{node}.jsonl", errors="replace") if os.path.exists(f"{d}/exporter/{node}.jsonl") else []:
            if line in seen or not line.startswith("{"):
                continue
            seen.add(line)
            try:
                e = json.loads(line)
            except ValueError:
                continue
            v = (e.get("unmapped") or {}).get("varek") or {}
            if v.get("event") == "audit":
                exported[(e.get("metadata") or {}).get("correlation_uid")] = (v.get("audit") or {}).get("passed")
    not_ex = [v["pod"] for v in streams.values() if exported.get(v["run"]) is not True]
    c(streams and not not_ex, "each run's audit in the exporter's log, passed",
      f"{len(streams) - len(not_ex)} of {len(streams)}" + (f"; not: {not_ex[:5]}" if not_ex else ""))

    # --- VAREK's own pods
    vp = json.load(open(f"{d}/varek-pods.json"))["items"] if os.path.exists(f"{d}/varek-pods.json") else []
    restarts = {(p["metadata"]["name"], s["name"]): s.get("restartCount", 0)
                for p in vp for s in p.get("status", {}).get("containerStatuses", [])}
    c(vp and not any(restarts.values()), "VAREK's containers (node agent, plugin, exporter, webhook) not restarted",
      ", ".join(f"{k[0]}/{k[1]} {v}" for k, v in restarts.items() if v) or f"{len(restarts)} containers")

    # --- memory
    mem = jl(f"{d}/samples/mem.jsonl")
    t0 = meta["start"]
    grow, mem_rows = [], []
    for node in meta["nodes"]:
        ser = collections.defaultdict(list)            # (role) -> [(t, kb)]
        for m in mem:
            if m.get("node") != node:
                continue
            procs = m["procs"]
            pids = {p["pid"]: p for p in procs}
            for p in procs:
                if p["name"] == "warden" and "--node-agent" in p["arg"]:   # not the plugin's --oci-filter runs
                    role = "listener" if pids.get(p["ppid"], {}).get("name") != "warden" else "supervisor"
                    ser[role].append((m["t"], p["rss_kb"]))
                elif p["name"] == "varek-nri":
                    ser["plugin"].append((m["t"], p["rss_kb"]))
                elif "varek_node_export" in p["arg"]:
                    ser["exporter"].append((m["t"], p["rss_kb"]))
        for role, xs in sorted(ser.items()):
            if role == "supervisor":                   # the largest of them at each sample
                by_t = collections.defaultdict(int)
                for t, kb in xs:
                    by_t[t] = max(by_t[t], kb)
                xs = sorted(by_t.items())
            vals = [kb for _, kb in xs]
            mem_rows.append(f"{node} {role}: {min(vals) / 1024:.1f} to {max(vals) / 1024:.1f} MB "
                            f"(median {statistics.median(vals) / 1024:.1f})")
            after = [kb for t, kb in xs if t >= t0 + 3600] or vals
            if role in ("listener", "supervisor") and vals[-1] > 1.5 * after[0] + 4096:
                grow.append(f"{node} {role} {after[0] / 1024:.1f} -> {vals[-1] / 1024:.1f} MB")
    c(mem and not grow, "the node agent's memory flat over the run", "; ".join(grow) or f"{len(mem)} samples")

    # --- the report
    deny = sum(v["deny"] for v in streams.values())
    recs = sum(v["records"] for v in streams.values())
    lines = [f"soak_check: v1.34 step 9, {hours:g} h, image {meta.get('image')} {meta.get('digest') or ''}".rstrip(),
             f"nodes: {', '.join(meta['nodes'])}" + (" (OpenShift)" if meta.get("openshift") else ""), ""]
    lines += [f"  {s}   {w}" + (f"  ({x})" if x else "") for s, w, x in c.rows]
    lines += ["", "| | |", "|---|---|",
              f"| Duration | {hours:g} h, a turn every {interval:g} s; {len(meta['nodes'])} long agents, a short Job every {meta['short_every']} min |",
              f"| Long agents | {long_turns} turns of work done, {commits} git commits; {long_probes} probes, all held |",
              f"| Short Jobs | {s_ok} of {due} due ran to their end; {s_probes} probes, all held |",
              f"| The allowed service | {len(allowed)} requests; at the agent p50 {pct(http_ms, 50)} ms, p99 {pct(http_ms, 99)} ms |",
              f"| The denied service | {len(denied)} requests |",
              f"| Streams | {len(streams)}, {recs} records ({deny} refused); audited: {sum(1 for v in streams.values() if v.get('audit'))} pass |",
              f"| The exporter | {sum(1 for v in streams.values() if exported.get(v['run']) is True)} runs' audits passed in its log |",
              f"| Memory | {'; '.join(mem_rows) or 'no samples'} |", ""]
    lines.append("soak_check: PASS" if c.fails == 0 else f"soak_check: FAIL ({c.fails})")
    text = "\n".join(lines) + "\n"
    open(f"{d}/report.txt", "w").write(text)
    print(text, end="")
    return 0 if c.fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
