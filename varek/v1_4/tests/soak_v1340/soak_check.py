#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_check.py — judges a run of soak.sh (v1.34 step 9; v1.36 step 12,
the ship gate's runs) and writes DIR/report.txt. The run passes when:

  long agents   each node's ran the whole run: every turn of work done
                (files, python3, git, the allowed service), every probe
                held, each of its kinds; not restarted
  short Jobs    at least nine in ten of those due (one less than the run's
                time holds) ran, each to its end with
                every turn done and every probe held; none failed
  services      the denied service saw no request; the allowed one at least
                one for each turn of work
  streams       each agent pod's container has one stream on its node,
                named by its pod, with its run_end; each audited
                (tools/varek_audit.py: signed with the node's own key as
                the cluster's VarekNodeKey list holds it, v1.36 D10, or the
                one key of a run before it; anchored; each decision under
                its policy)
  exporter      each stream's run has the audit's event, passed, in the
                exporter's log on its node
  VAREK's pods  the node agent, plugin, exporter and webhook containers not
                restarted
  memory        the node agent's listener and the long agents' supervisors
                at the end within 1.5 times their size after the first hour
                (and 4 MB), reported as they went

and, for the ship gate's runs (meta.json's ship_gate, v1.36 step 12):

  the token     every request for a turn reached the allowed service with
                the soak's token (the egress proxy swapped the agent's
                placeholder for it), none other with it; each agent stream's
                run_start names the credential; the token in no stream, log
                or export
  the plan      each agent stream held to its plan (run_start's hold, the
                audit given the plan's copy beside it: its SHA-256 the
                gate's); refused outside the plan only the probes' reads of
                /etc/hostname, by the agent and by its sub-agent; refused
                otherwise only the probes' calls and glibc's nscd; the
                metadata probe's connections, which the egress proxy
                refuses, each in the stream (proxy_unreadable)
  sub-agents    each long agent's build sub-agent and MCP server launched
                and settled, the server's own rules holding it
  volume pods   each node's ran the whole run, every read done; the largest
                stream over 1,000,000 records in a run of 24 hours (half the
                reads asked for in a shorter one), and audited in fixed
                memory: the audit's resident memory at the last tenth of
                the stream read within 16 MB of the first tenth (measured
                as d9_flat_memory.py does, across the stream's segments)

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
import tempfile
import time

PROBES = {"shadow", "outside", "own_program", "denied_host", "denied_ip", "metadata"}
GATE_PROBES = PROBES | {"outside_plan", "builder_outside_plan", "server_outside", "placeholder_elsewhere"}
SAMPLE_S = 0.05                 # the audit's memory, sampled (d9_flat_memory.py: 0.2 s, for a stream of 1M)
SLACK_KB = 16 * 1024            # as d9_flat_memory.py
GATE_RECORDS = 1_000_000        # the ship gate's large stream, in a run of 24 hours


def jl(path):
    """the JSON objects of a log, a line each; objects run together on one
    line (two writers at once, as servers.py's threads before its lock) are
    each read"""
    out, dec = [], json.JSONDecoder()
    try:
        for line in open(path, errors="replace"):
            line, pos = line.strip(), 0
            while pos < len(line) and line[pos] == "{":
                try:
                    obj, pos = dec.raw_decode(line, pos)
                except ValueError:
                    break
                out.append(obj)
                while pos < len(line) and line[pos].isspace():
                    pos += 1
    except OSError:
        pass
    return out


def segments(path):
    """v1.36 (D9): a stream and the segments it went on in (the node agent
    rotates a stream at the chart's streams.rotateBytes): NAME.jsonl,
    NAME.jsonl.2, ..."""
    out, n = [path], 2
    while os.path.exists(f"{path}.{n}"):
        out.append(f"{path}.{n}")
        n += 1
    return out


def records(path):
    """a stream's records, its segments in order, one at a time (the volume
    pods' streams are over a million records: none is held whole here)"""
    for g in segments(path):
        try:
            with open(g, errors="replace") as f:
                for line in f:
                    if line.startswith("{"):
                        try:
                            yield json.loads(line)
                        except ValueError:
                            continue
        except OSError:
            continue


def subject(r):
    """the sub-agent a record is attributed to (its name, without #N), or
    None for the agent's own: a launch names it (subagent), and every record
    of it ends its chain (obo: [..., "subagent:NAME#N"])"""
    sub = r.get("subagent")
    if not sub:
        obo = r.get("obo")
        last = obo[-1] if isinstance(obo, list) and obo else ""
        sub = last[len("subagent:"):] if isinstance(last, str) and last.startswith("subagent:") else None
    return str(sub).split("#")[0] if sub else None


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


def status_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def read_pos(pid, segs, sizes):
    """how far the audit has read a stream of segments: the bytes of the
    segments before the one it has open, and its offset in that one"""
    reals = [os.path.realpath(s) for s in segs]
    try:
        fds = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return None
    for fd in fds:
        try:
            k = reals.index(os.readlink(f"/proc/{pid}/fd/{fd}"))
            with open(f"/proc/{pid}/fdinfo/{fd}") as f:
                for line in f:
                    if line.startswith("pos:"):
                        return sum(sizes[:k]) + int(line.split()[1])
        except (OSError, ValueError):
            continue
    return None


def audit(cmd, segs, sample):
    """the audit, its exit and output; with sample, its resident memory by
    how far it has read (samples of (position, kB))"""
    with tempfile.TemporaryFile(mode="w+") as out:
        p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, text=True)
        samples = []
        sizes = [os.path.getsize(s) for s in segs] if sample else []
        while p.poll() is None:
            if sample:
                kb, pos = status_kb(p.pid), read_pos(p.pid, segs, sizes)
                if kb is not None and pos is not None:
                    samples.append((pos, kb))
            time.sleep(SAMPLE_S if sample else 0.2)
        out.seek(0)
        return p.returncode, out.read(), samples, sum(sizes)


def flat(samples, size):
    """d9_flat_memory.py's measure: the memory while the stream is read, at
    its first tenth and its last"""
    read = [(pos, kb) for pos, kb in samples if pos < size]
    first = [kb for pos, kb in read if pos <= size * 0.1]
    last = [kb for pos, kb in read if pos >= size * 0.9]
    if not first or not last:
        return False, f"too few samples while the stream was read ({len(read)})"
    grow = max(last) - min(first)
    return grow <= SLACK_KB, (f"{max(last)} kB at the last tenth, {min(first)} kB at the first ({grow:+d} kB, at "
                              f"most {SLACK_KB} kB); {len(read)} samples")


def has_bytes(paths, needle):
    """is needle in any of these files (read in chunks, overlapping)"""
    for p in paths:
        try:
            with open(p, "rb") as f:
                tail = b""
                while True:
                    b = f.read(1 << 20)
                    if not b:
                        break
                    if needle in tail + b:
                        return p
                    tail = b[-len(needle):]
        except OSError:
            continue
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--tools", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
    a = ap.parse_args()
    d = a.dir
    meta = json.load(open(f"{d}/meta.json"))
    hours, interval = meta["hours"], meta["interval"]
    gate = bool(meta.get("ship_gate"))
    probe_kinds = GATE_PROBES if gate else PROBES
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
        c(L["probes"] and not L["leaks"] and kinds == probe_kinds, f"{name}: every probe held",
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

    # --- the volume pods (v1.36 step 12)
    vol_opens = {}
    if gate:
        rate = meta.get("volume_rate", 0)
        for i, node in enumerate(meta["nodes"]):
            name = f"volume-{i}"
            p = pods.get(name, {})
            st = p.get("status", {})
            cs = (st.get("containerStatuses") or [{}])[0]
            recs = jl(f"{d}/logs/{name}.jsonl")
            end = recs[-1] if recs and recs[-1].get("end") else {}
            vol_opens[name] = end.get("opens", 0)
            c(bool(recs) and recs[0].get("start") and recs[0].get("ok") and end and st.get("phase") == "Succeeded"
              and cs.get("restartCount", 0) == 0 and end.get("failed") == 0
              and end.get("opens", 0) >= 0.9 * rate * hours * 3600,
              f"{name} on {node}: ran the whole run, every read done",
              f"phase {st.get('phase')}, restarts {cs.get('restartCount')}, {end.get('opens')} reads "
              f"({end.get('failed')} failed) of {int(rate * hours * 3600)} asked for")

    # --- the services
    allowed = [r for r in jl(f"{d}/allowed.jsonl") if "path" in r]
    denied = [r for r in jl(f"{d}/denied.jsonl") if "path" in r]
    all_work = long_turns + sum(len(agent_log(jl(f"{d}/logs/{n}.jsonl"))["work"]) for n in short)
    c(not denied, "the denied service saw no request", f"{len(denied)} requests")
    if gate:
        turns = [r for r in allowed if r["path"].startswith("/turn/")]
        plain = [r for r in allowed if r["path"].startswith("/plain/")]
        c(len(turns) >= all_work, "the allowed service had each turn's request", f"{len(turns)} requests, {all_work} turns")
        c(turns and all(r.get("cred") == "value" for r in turns),
          "... each with the soak's token (the agent's placeholder swapped by the egress proxy)",
          f"{sum(1 for r in turns if r.get('cred') == 'value')} of {len(turns)}")
        c(plain and not any(r.get("cred") == "value" for r in plain) and all(r.get("cred") == "other" for r in plain),
          "the requests the policy gives no credential reached it with the placeholder, never the token",
          f"{len(plain)} requests: {dict(collections.Counter(r.get('cred') for r in plain))}")
        others = [r for r in allowed if not r["path"].startswith(("/turn/", "/plain/"))]
        c(not others, "no other request reached the allowed service", f"{len(others)}" + (f"; first {others[0]}" if others else ""))
    else:
        c(len(allowed) >= all_work, "the allowed service had each turn's request", f"{len(allowed)} requests, {all_work} turns")

    # --- the streams, and the exporter's audits
    streams, by_pod = {}, collections.defaultdict(list)
    for node in meta["nodes"]:
        for s in glob.glob(f"{d}/streams/{node}/*.jsonl"):
            v = {"node": node, "records": 0, "end": False, "deny": 0, "allow": 0, "denied": [], "subs": set(),
                 "settled": collections.Counter(), "sub_recs": collections.Counter(), "unreadable": 0}
            rs = None
            for r in records(s):
                if rs is None:
                    if r.get("event") != "run_start":
                        break
                    rs = r
                v["records"] += 1
                if r.get("event") == "run_end":
                    v["end"] = True
                elif r.get("event") == "proxy_unreadable":
                    v["unreadable"] += 1
                elif r.get("event") == "subagent_settled":
                    v["settled"][(str(r.get("subagent", "")).split("#")[0], r.get("result"))] += 1
                f = r.get("decision_final")
                if f == "ALLOW":
                    v["allow"] += 1
                elif f == "DENY":
                    v["deny"] += 1
                    if len(v["denied"]) < 10000:
                        v["denied"].append(dict({k: r.get(k) for k in ("seq", "action", "target", "resolved", "rule",
                                                                       "decision_raw")}, sub=subject(r)))
                if r.get("action") == "process.exec" and r.get("subagent"):
                    v["subs"].add(str(r["subagent"]).split("#")[0])
                if r.get("action") and subject(r):
                    v["sub_recs"][subject(r)] += 1
            if not rs:
                continue
            pod = (rs.get("node") or {}).get("pod", {})
            if pod.get("namespace") != "varek-soak":
                continue
            # a stream of an earlier run on the same cluster (the node keeps
            # them) is not this run's
            if isinstance(rs.get("timestamp_ns"), int) and rs["timestamp_ns"] < meta["start"] * 10**9:
                continue
            v.update(run=rs.get("run"), pod=pod.get("name"), rs={k: rs.get(k) for k in ("hold", "credentials")})
            streams[s] = v
            by_pod[pod.get("name")].append(s)
    agent_pods = [f"long-{i}" for i in range(len(meta["nodes"]))] + sorted(short)
    if gate:
        agent_pods += [f"volume-{i}" for i in range(len(meta["nodes"]))]
    missing = [n for n in agent_pods if len(by_pod.get(n, [])) != 1]
    c(not missing, "each agent pod's container has one stream on its node, named by its pod",
      f"{len(streams)} streams for {len(agent_pods)} pods" + (f"; not one: {missing[:5]}" if missing else ""))
    c(all(v["end"] for v in streams.values()), "each stream has its run_end",
      f"{sum(1 for v in streams.values() if not v['end'])} without")
    audit_bad = []
    # v1.36 step 9 (D10): each node's own key, from the cluster's list; a run
    # before it signed every node's streams with one key (node.key.pub)
    nk = f"{d}/node-keys.json"
    key = ["--node-keys", nk] if os.path.exists(nk) else ["--pubkey", f"{d}/node.key.pub"]
    if os.path.exists(nk):
        # v1.36 step 11 (review): an empty or malformed list (soak.sh leaves an
        # empty file when kubectl fails) is a failed check, not a traceback
        try:
            with open(nk) as f:
                listed = collections.Counter(i["spec"]["node"] for i in json.load(f).get("items") or [])
        except (OSError, ValueError, AttributeError, KeyError, TypeError) as e:
            listed = collections.Counter()
            c(False, "the cluster's VarekNodeKey list read (node-keys.json)", f"{type(e).__name__}: {e}")
        unkeyed = [n for n in meta["nodes"] if not listed.get(n)]
        c(not unkeyed, "each node's key published (a VarekNodeKey for each node)",
          f"{len(meta['nodes']) - len(unkeyed)} of {len(meta['nodes'])}" + (f"; none for {unkeyed}" if unkeyed else ""))
    big = max((s for s, v in streams.items() if str(v.get("pod", "")).startswith("volume-")),
              key=lambda s: streams[s]["records"], default=None) if gate else None
    for s, v in sorted(streams.items()):
        anchor = f"{d}/streams/{v['node']}/anchor"
        plan = s[:-6] + ".plan"
        cmd = [sys.executable, os.path.join(a.tools, "varek_audit.py"), "--policy", s[:-6] + ".policy",
               "--checker", os.path.join(a.tools, "vdp_cert_check")] + key + ["--anchor", anchor]
        # v1.36 step 12: a held run's plan, the node agent's copy beside its stream
        if gate and os.path.exists(plan):
            cmd += ["--plan", plan]
        rc, out, samples, size = audit(cmd + segments(s), segments(s), s == big)
        v["audit"] = rc == 0
        if s == big:
            v["flat"] = flat(samples, size)
        if rc != 0:
            audit_bad.append((v["pod"], out.strip().splitlines()[-1:]))
    c(streams and not audit_bad, "each stream audited: signed with the node key, anchored, each decision under its policy"
      + (" and its plan" if gate else ""),
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

    # --- the ship gate's (v1.36 step 12): the token, the plan, the sub-agents, the large stream
    outside_n = sub_n = 0
    if gate:
        agents = {s: v for s, v in streams.items() if not str(v.get("pod", "")).startswith("volume-")}
        c(streams and all((v["rs"].get("credentials") or [{}])[0].get("name") == "soak_token"
                          and len(v["rs"].get("credentials") or []) == 1 for v in streams.values()),
          "each stream's run_start names the credential (soak_token), fetched on the node",
          f"{sum(1 for v in streams.values() if (v['rs'].get('credentials') or [{}])[0].get('name') == 'soak_token')} "
          f"of {len(streams)}")
        token = open(f"{d}/secret/token", "rb").read() if os.path.exists(f"{d}/secret/token") else b""
        where = [p for p in glob.glob(f"{d}/streams/**/*", recursive=True) + glob.glob(f"{d}/logs/*") +
                 glob.glob(f"{d}/exporter/*") + glob.glob(f"{d}/*.jsonl") if os.path.isfile(p)]
        found = has_bytes(where, token) if token else "no token kept (DIR/secret/token)"
        c(not found, "the token in no stream, pod log, export or service log", f"{len(where)} files" +
          (f"; found in {found}" if found else ""))
        c(streams and all(isinstance(v["rs"].get("hold"), dict) and str(v["rs"]["hold"].get("plan", "")).endswith(".plan")
                          for v in streams.values()),
          "each stream held to its plan (run_start's hold)",
          f"{sum(1 for v in streams.values() if isinstance(v['rs'].get('hold'), dict))} of {len(streams)}")
        # refused outside the plan: the probes' reads of /etc/hostname alone;
        # refused otherwise: the probes' calls, and glibc's nscd (names go to the
        # Warden's stub), refused in every run
        denied_ip = meta.get("denied_ip", "")
        def probe_call(r):
            t = str(r.get("resolved") or r.get("target") or "")
            return (t in ("/etc/shadow", "/outside/w", "/etc/passwd", "169.254.169.254:80", f"{denied_ip}:8080")
                    or t.endswith("/mytrue") or "denied.varek-soak-svc" in t
                    or (r.get("action") == "net.connect" and t == "unix:/var/run/nscd/socket"))
        bad_out, bad_other = [], []
        for v in streams.values():
            for r in v["denied"]:
                t = str(r.get("resolved") or r.get("target") or "")
                if r.get("rule") == "outside_plan":
                    outside_n += 1
                    if not (t == "/etc/hostname" and r.get("action") == "file.open"):
                        bad_out.append((v["pod"], r))
                elif not probe_call(r):
                    bad_other.append((v["pod"], r))
        c(not bad_out and outside_n > 0, "refused outside the plan: the probes' reads of /etc/hostname alone",
          f"{outside_n} refused, {len(bad_out)} not a probe's" + (f"; first: {bad_out[0]}" if bad_out else ""))
        c(not bad_other, "refused otherwise: the probes' calls alone (and glibc's nscd)",
          f"{len(bad_other)} other" + (f"; first: {bad_other[0]}" if bad_other else ""))
        held_sub = sum(1 for v in streams.values() for r in v["denied"]
                       if r.get("rule") == "outside_plan" and r.get("sub") == "builder")
        c(held_sub > 0, "... the sub-agent's among them, its records its own (subagent:builder#N)", f"{held_sub}")
        longs = {s: v for s, v in agents.items() if str(v.get("pod", "")).startswith("long-")}
        sub_ok = [v["pod"] for v in longs.values()
                  if {"builder", "files"} <= v["subs"] and v["settled"][("builder", "launched")] > 0
                  and v["settled"][("files", "launched")] > 0
                  and not any(k[1] != "launched" for k in v["settled"])]
        sub_n = sum(sum(v["settled"].values()) for v in longs.values())
        c(longs and len(sub_ok) == len(longs), "each long agent's sub-agent and MCP server launched and settled, every launch",
          f"{len(sub_ok)} of {len(longs)}; " + "; ".join(
              f"{v['pod']}: {dict(v['settled'])}" for v in longs.values()))
        srv = sum(1 for v in streams.values() for r in v["denied"]
                  if r.get("sub") == "files" and str(r.get("resolved") or r.get("target") or "") == "/etc/passwd")
        c(srv > 0, "the MCP server held to its own rules: its read of /etc/passwd (the agent's to read) refused", f"{srv}")
        # the metadata probe's connection, refused by the egress proxy (its
        # Host an address): a proxy_unreadable record for each
        meta_probes = {f"long-{i}": sum(1 for r in agent_log(jl(f"{d}/logs/long-{i}.jsonl"))["probes"]
                                        if r["probe"] == "metadata") for i in range(len(meta["nodes"]))}
        unrec = [(v["pod"], v["unreadable"], meta_probes[v["pod"]]) for v in longs.values()
                 if v["unreadable"] < meta_probes.get(v["pod"], 0)]
        c(longs and not unrec, "the metadata probe's connections, refused by the egress proxy, each in the stream "
          "(proxy_unreadable)", "; ".join(f"{p}: {n} of {m}" for p, n, m in unrec) or
          f"{sum(v['unreadable'] for v in longs.values())} records, {sum(meta_probes.values())} probes")
        need = GATE_RECORDS if hours >= 24 else int(0.5 * meta.get("volume_rate", 0) * hours * 3600)
        bv = streams.get(big, {})
        c(big is not None and bv.get("records", 0) > need,
          f"the largest stream over {need:,} records" + (" (the ship gate's)" if need == GATE_RECORDS else
                                                         " (a run under 24 hours: half the reads asked for)"),
          f"{bv.get('pod')} on {bv.get('node')}: {bv.get('records', 0):,} records in {len(segments(big)) if big else 0} "
          f"segment(s)")
        ok, why = bv.get("flat", (False, "not audited"))
        c(big is not None and ok and bv.get("audit"), "... audited in fixed memory", why)

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
    step = "v1.36 step 12, the ship gate" if gate else "v1.34 step 9"
    lines = [f"soak_check: {step}, {hours:g} h, image {meta.get('image')} {meta.get('digest') or ''}".rstrip(),
             f"nodes: {', '.join(meta['nodes'])}" + (" (OpenShift)" if meta.get("openshift") else ""), ""]
    lines += [f"  {s}   {w}" + (f"  ({x})" if x else "") for s, w, x in c.rows]
    lines += ["", "| | |", "|---|---|",
              f"| Duration | {hours:g} h, a turn every {interval:g} s; {len(meta['nodes'])} long agents, a short Job every {meta['short_every']} min"
              + (f", {len(meta['nodes'])} volume pods ({meta.get('volume_rate')} reads a second)" if gate else "") + " |",
              f"| Long agents | {long_turns} turns of work done, {commits} git commits; {long_probes} probes, all held |",
              f"| Short Jobs | {s_ok} of {due} due ran to their end; {s_probes} probes, all held |",
              f"| The allowed service | {len(allowed)} requests; at the agent p50 {pct(http_ms, 50)} ms, p99 {pct(http_ms, 99)} ms |",
              f"| The denied service | {len(denied)} requests |",
              f"| Streams | {len(streams)}, {recs} records ({deny} refused); audited: {sum(1 for v in streams.values() if v.get('audit'))} pass |",
              f"| The exporter | {sum(1 for v in streams.values() if exported.get(v['run']) is True)} runs' audits passed in its log |"]
    if gate:
        bv = streams.get(big, {}) if big else {}
        lines += [f"| The plan | {outside_n} calls refused outside it, each a probe's; sub-agent and server launches settled: {sub_n} |",
                  f"| The large stream | {bv.get('records', 0):,} records ({bv.get('pod')}, {bv.get('node')}); "
                  f"{(bv.get('flat') or (False, 'not audited'))[1]} |",
                  f"| Volume pods | {', '.join(f'{k} {n:,} reads' for k, n in sorted(vol_opens.items()))} |"]
    lines += [f"| Memory | {'; '.join(mem_rows) or 'no samples'} |", ""]
    lines.append("soak_check: PASS" if c.fails == 0 else f"soak_check: FAIL ({c.fails})")
    text = "\n".join(lines) + "\n"
    open(f"{d}/report.txt", "w").write(text)
    print(text, end="")
    return 0 if c.fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
