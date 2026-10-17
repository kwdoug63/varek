#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_check.py — judge a shared soak (soak.sh) of v1.28.1, v1.29.0 and
v1.31.0. Three runs side by side:

  A  (v1.28.1, v1.31.0) the agent on behalf of a verified user, two confined
     MCP servers kept for the run, MCP calls of its own, sub-agents. Shown:
     1. it lasted the time asked, a turn every interval; run_start names the
        user (verified, revoke on expiry) and the MCP token (its server);
     2. before the user's token expired, every task worked and every probe
        held: each call decided for its own subject (the agent, fs, gh, the
        sub-agents), with the chain user, agent, sub-agent... on every
        record and each confined server's certificate subject;
     3. the remote MCP server got the MCP token in gh's allowed calls only,
        as their bearer token, and nothing refused, no placeholder, no
        user's token;
     4. the expiry: recorded once, the run revoked by it, every decision
        after it refused and nothing reaching the remote server;
     5. no token in the stream, the agent's output or the OCSF events; the
        audit passes; the OCSF export (followed the whole run) matches the
        stream (--verify) and is valid OCSF 1.9.0.
  B  (v1.29.0) varek run with nothing set up (the baseline and the python
     profile): every turn of work done (files, python3, git), every probe
     refused; the audit passes.
  C  (v1.29.0) the same work as a dry run of a narrower policy: every turn
     done, the policy's refusals recorded and let through (enforced:
     false), the audit says DRY RUN, NOT ENFORCED (exit 3); varek policy
     suggest's draft lints and loads in the checker, and a dry run under it
     lets through only the system calls the draft notes it cannot admit.

It also reports the time each task took, the Warden's time per decision for
each subject, and each process's memory over the run (rss.tsv).

  soak_check.py --dir OUT --checker tools/vdp_cert_check --vdp tools/vdp_check \\
      --values /etc/varek-soak-shared/values.json --dir-ag /opt/varek-soak-shared \\
      [--hours 24] [--interval 60] [--lead 300] [--pubkey K.pub]

Prints a report (also written to OUT/report.txt) and exits 0 on PASS.
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
V14 = os.path.abspath(os.path.join(HERE, "..", ".."))
TOOLS = os.path.join(V14, "tools")
TASKS_A = ("mcp_list", "mcp_search", "fs_read", "gh_get", "subagents")
PROBES_A = ("mcp_delete", "mcp_unlisted", "agent_get", "fs_outside", "fs_store", "gh_delete", "agent_srvfile",
            "env_launch")
PROBES_B = ("shadow", "outside", "own_program")


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


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def audit(say, problems, label, policy, checker, log, pubkey, want):
    cmd = [sys.executable, os.path.join(TOOLS, "varek_audit.py"), "--policy", policy, "--checker", checker, log]
    if pubkey:
        cmd[2:2] = ["--pubkey", pubkey]
    rc, out, err = run(cmd)
    for ln in out.splitlines():
        if ln.startswith(("varek_audit: chain:", "varek_audit: credentials:", "varek_audit: integrity:")):
            say("  " + ln)
    say(f"  audit: " + (out.strip().splitlines()[-1] if out.strip() else err.strip()[:300]) + f" (exit {rc})")
    if rc != want:
        problems.append(f"{label}: the audit exited {rc}, not {want}: " +
                        "; ".join(ln.strip() for ln in out.splitlines() if "PROBLEM" in ln)[:600])
    return out


def turns_of(agent):
    return [r for r in agent if "task" in r or "probe" in r]


def check_a(a, say, problems, values, D):
    A = os.path.join(D, "a")
    pol = os.path.join(A, "policy.txt")
    agent = load(os.path.join(A, "agent.jsonl"))
    remote = load(os.path.join(A, "remote.jsonl"))
    recs = load(os.path.join(A, "verdicts.log"))
    rs = next((r for r in recs if r.get("event") == "run_start"), {})
    say(f"A (v1.28.1, v1.31.0): Warden {rs.get('warden', '?')}, run {rs.get('run', '?')}, {len(recs)} records"
        + ("" if any(r.get("event") == "run_end" for r in recs) else " (no run_end: the run did not end cleanly)"))
    if not any(r.get("event") == "run_end" for r in recs):
        problems.append("A: the stream has no run_end")
    # 1. the run
    ob = rs.get("on_behalf_of") if isinstance(rs.get("on_behalf_of"), dict) else {}
    u = ob.get("user") if isinstance(ob.get("user"), dict) else {}
    say(f"  on behalf of {u.get('subject')} ({u.get('issuer')}, {u.get('algorithm')}), verified "
        f"{u.get('verified')}, on expiry {u.get('on_expiry')}")
    if u.get("verified") is not True or u.get("subject") != "alice@example.test" or u.get("on_expiry") != "revoke":
        problems.append("A: run_start does not name the verified user, with revoke on expiry")
    creds = rs.get("credentials") if isinstance(rs.get("credentials"), list) else []
    mt = [c for c in creds if isinstance(c, dict) and c.get("name") == "mt"]
    if len(mt) != 1 or not str(mt[0].get("audience", "")).startswith("https://mcp.example.com:") \
            or not isinstance(mt[0].get("expires"), int):
        problems.append(f"A: run_start does not list credential mt with its server and its expiry ({creds})")
    start = next((r for r in agent if r.get("start")), {})
    if start.get("placeholder") is not True or start.get("fs") is not True or start.get("gh") is not True:
        problems.append(f"A: the agent's start: {start}")
    turns = turns_of(agent)
    want = int(a.hours * 3600 / a.interval)
    say(f"  turns: {len(turns)} (about {want} expected)")
    if len(turns) < 0.9 * want:
        problems.append(f"A: only {len(turns)} turns of about {want}: the run stopped early or stalled")

    # the expiry and the revocation
    exp = [r for r in recs if r.get("event") == "on_behalf_of_expired"]
    rv = [r for r in recs if r.get("event") == "revoked"]
    t_exp = u.get("expires") if isinstance(u.get("expires"), int) else None
    t_rev = rv[0]["timestamp_ns"] / 1e9 if rv and isinstance(rv[0].get("timestamp_ns"), int) else None
    if len(exp) != 1 or exp[0].get("action") != "revoke" or exp[0].get("expires") != t_exp:
        problems.append(f"A: the user's token's expiry is recorded {len(exp)} time(s), or not as a revocation")
    if len(rv) != 1 or rv[0].get("by") != "on_behalf_of_expiry":
        problems.append(f"A: the run is revoked {len(rv)} time(s), or not by the expiry ({rv[:1]})")
    if t_exp and t_rev:
        say(f"  the user's token expired at {t_exp}; the run revoked {t_rev - t_exp:.2f} s after")
    before = [r for r in turns if t_exp is None or r["t"] + r.get("ms", 0) / 1000 < t_exp]
    after = [r for r in turns if t_rev is not None and r["t"] > t_rev + 1]

    # 2. before: tasks and probes
    tasks = [r for r in before if "task" in r]
    by = {k: [r for r in tasks if r["task"] == k] for k in TASKS_A}
    say("  tasks before the expiry: " + ", ".join(f"{k} {sum(1 for r in v if r.get('ok'))}/{len(v)}"
                                                  for k, v in by.items()))
    for r in [r for r in tasks if not r.get("ok")][:10]:
        problems.append(f"A: task {r['task']} at {r['t']}: {r.get('status', r.get('error', r.get('result')))}")
    if tasks and any(not v for v in by.values()):
        problems.append("A: a kind of task never ran before the expiry")
    probes = [r for r in before if "probe" in r]
    pk = {k: [r for r in probes if r["probe"] == k] for k in PROBES_A}
    say("  probes before the expiry: " + ", ".join(f"{k} {sum(1 for r in v if r.get('held'))}/{len(v)}"
                                                   for k, v in pk.items() if v))
    for r in [r for r in probes if not r.get("held")][:10]:
        problems.append(f"A: probe {r['probe']} at {r['t']} did not hold: "
                        f"{r.get('status', r.get('error', r.get('result')))}")
    if len(turns) > 3 * len(PROBES_A) * 10 and any(not v for v in pk.values()):
        problems.append("A: a kind of probe never ran before the expiry")

    # each call decided for its own subject
    dec = [r for r in recs if "report_id" in r]
    t_exp_ns = (t_exp or 1 << 62) * 10**9
    pre = [r for r in dec if r.get("timestamp_ns", 0) < t_exp_ns]
    ag = a.dir_ag
    U = mt[0].get("audience") if mt else ""
    launches = [r for r in dec if r.get("action") == "process.exec" and r.get("mcp_server") is True]
    srv = {r["subagent"].split("#")[0]: r for r in launches if r.get("decision_final") == "ALLOW"}
    say(f"  MCP servers launched: " + ", ".join(f"{n} ({r['subagent']}, confined {r.get('confined')})"
                                               for n, r in sorted(srv.items())))
    if sorted(srv) != ["fs", "gh"] or any(r.get("confined") is not True for r in srv.values()) or \
            len([r for r in launches if r.get("decision_final") == "ALLOW"]) != 2:
        problems.append("A: fs and gh were not each launched once, confined")
    chain = {n: ["user", "agent", "subagent:" + r["subagent"]] for n, r in srv.items()}

    def of(subject, action=None, target=None, final=None, rule=None):
        return [r for r in pre if r.get("obo") == subject and (action is None or r.get("action") == action)
                and (target is None or r.get("target") == target)
                and (final is None or r.get("decision_final") == final) and (rule is None or r.get("rule") == rule)]

    subj = {}
    if "fs" in chain:
        fa = of(chain["fs"], "file.open", ag + "/proj/a", "ALLOW")
        subj["fs"] = {r.get("cert_subject") for r in fa}
        if len(fa) < len([r for r in by["fs_read"] if r.get("ok")]) or len(subj["fs"]) != 1 or \
                not all(isinstance(s, int) and s > 0 for s in subj["fs"]):
            problems.append(f"A: fs's reads of the project are not each its own (certificate subjects {subj['fs']})")
        n_out = len(of(chain["fs"], "file.open", ag + "/agent_only", "DENY"))
        n_st = len([r for r in pre if r.get("obo") == chain["fs"] and r.get("target") == a.store
                    and r.get("decision_final") == "DENY"])
        if n_out < len(pk["fs_outside"]) or n_st < len(pk["fs_store"]):
            problems.append(f"A: fs's refused reads are not recorded as its own ({n_out}, {n_st})")
    if "gh" in chain:
        gg = of(chain["gh"], "net.mcp", None, "ALLOW")
        gg = [r for r in gg if r.get("mcp_name") == "get_issue"]
        subj["gh"] = {r.get("cert_subject") for r in gg}
        if len(gg) != len([r for r in by["gh_get"] if r.get("ok")]) or any(r.get("credential") != "mt" for r in gg) \
                or len(subj["gh"]) != 1 or subj["gh"] == subj.get("fs"):
            problems.append(f"A: gh's calls are not each its own, with credential mt ({len(gg)}, subjects {subj['gh']})")
        gd = [r for r in of(chain["gh"], "net.mcp", None, "DENY") if r.get("mcp_name") == "delete_repo"]
        if len(gd) < len(pk["gh_delete"]):
            problems.append("A: gh's delete_repo calls are not refused as its own")
    say(f"  certificate subjects: " + ", ".join(f"{n} {sorted(s)}" for n, s in sorted(subj.items())))
    me = ["user", "agent"]
    al = [r for r in of(me, "net.mcp", None, "ALLOW")]
    if len(al) != len([r for r in by["mcp_list"] + by["mcp_search"] if r.get("ok")]) or \
            any(r.get("cert_subject", 0) != 0 or r.get("credential") for r in al):
        problems.append(f"A: the agent's own MCP calls are not each the agent's, without a credential ({len(al)})")
    ad = [r for r in of(me, "net.mcp", None, "DENY")]
    names = sorted({r.get("mcp_name") for r in ad})
    if len(ad) < len(pk["mcp_delete"]) + len(pk["mcp_unlisted"]) + len(pk["agent_get"]):
        problems.append(f"A: the agent's refused MCP calls are not all recorded ({len(ad)}: {names})")
    if len(of(me, "file.open", ag + "/srv_only", "DENY")) < len(pk["agent_srvfile"]):
        problems.append("A: the agent's open of fs's own file is not recorded refused")
    ev = [r for r in pre if r.get("action") == "process.exec" and r.get("rule") == "subagent_env"]
    if len(ev) < len(pk["env_launch"]) or any(r.get("env") != "PYTHONPATH" for r in ev):
        problems.append(f"A: the launches with PYTHONPATH are not refused as subagent_env ({len(ev)})")
    sb = [r for r in pre if r.get("action") == "file.open" and r.get("target") == ag + "/proj/b"
          and r.get("decision_final") == "ALLOW"]
    shapes = {tuple(re.sub(r"#\d+$", "#n", x) for x in r.get("obo", [])) for r in sb}
    say(f"  sub-agents: {len(sb)} opens by tester, chains {sorted(shapes)}")
    if len(sb) < len([r for r in by["subagents"] if r.get("ok")]) or \
            shapes - {("user", "agent", "subagent:coder#n", "subagent:tester#n")}:
        problems.append(f"A: tester's opens are not attributed user, agent, coder, tester ({shapes})")
    nosub = [r for r in dec if not isinstance(r.get("obo"), list) or r["obo"][:2] != ["user", "agent"]]
    if nosub:
        problems.append(f"A: {len(nosub)} decision(s) not on behalf of the user (first: {nosub[0].get('seq')})")

    # 3. the remote MCP server
    errs = [r for r in remote if r.get("error")]
    gets = [r for r in remote if r.get("name") == "get_issue"]
    say(f"  the remote MCP server: {len(remote)} requests, {sum(1 for r in remote if r.get('bearer') == 'mt')} "
        f"with the MCP token, {len(errs)} errors")
    if errs:
        problems.append(f"A: the remote server logged {len(errs)} error(s) (first: {errs[0]['error']})")
    if len(gets) != len([r for r in by["gh_get"] if r.get("ok")]) or any(r.get("bearer") != "mt" for r in gets):
        problems.append(f"A: the remote server's get_issue calls ({len(gets)}) are not gh's, each with the MCP token")
    bad = [r for r in remote if r.get("values") or r.get("bearer") in ("placeholder", "other")
           or (r.get("bearer") == "mt" and r.get("name") != "get_issue")
           or str(r.get("name", "")).startswith("delete_") or r.get("name") == "other_tool"]
    if bad:
        problems.append(f"A: {len(bad)} request(s) at the remote server that must not be there (first: {bad[0]})")

    # 4. after the expiry
    if t_rev is not None:
        say(f"  turns after the revocation: {len(after)}, any of them working: "
            f"{sum(1 for r in after if r.get('ok') or r.get('status') == 200)}")
        if not after:
            problems.append("A: no turn ran after the revocation")
        if any(r.get("ok") or r.get("status") == 200 for r in after):
            problems.append("A: a task worked after the revocation")
        late = [r for r in remote if r.get("t", 0) > t_rev]
        if late:
            problems.append(f"A: {len(late)} request(s) reached the remote server after the revocation")
        allowed = [r for r in dec if r.get("timestamp_ns", 0) > rv[0]["timestamp_ns"] and r.get("decision_final") != "DENY"]
        if allowed:
            problems.append(f"A: {len(allowed)} decision(s) allowed after the revocation (first: seq "
                            f"{allowed[0].get('seq')} {allowed[0].get('action')} {allowed[0].get('target')})")

    # 5. no token anywhere; the audit; OCSF
    tok = [values["mt"], values["user"], values["user"].split(".")[-1], values["user"].split(".")[1],
           values["mt"].split(".")[-1]]
    for f in ("a/verdicts.log", "a/agent.jsonl", "a/events.jsonl", "a/remote.jsonl", "rss.tsv", "a/ocsf.out"):
        p = os.path.join(D, f)
        if os.path.exists(p):
            data = open(p, encoding="utf-8", errors="surrogateescape").read()
            if any(t and t in data for t in tok):
                problems.append(f"A: {f} holds a token (or its signature or claims)")
    audit(say, problems, "A", pol, a.checker, os.path.join(A, "verdicts.log"), a.pubkey, 0)
    ev_path = os.path.join(A, "events.jsonl")
    if not os.path.exists(ev_path) or os.path.getsize(ev_path) == 0:
        problems.append("A: the OCSF export wrote no events")
    else:
        n_ev = sum(1 for _ in open(ev_path))
        cmd = [sys.executable, os.path.join(TOOLS, "varek_ocsf.py"), "--log", os.path.join(A, "verdicts.log"),
               "--verify", ev_path, "--policy", pol, "--checker", a.checker]
        if a.pubkey:
            cmd += ["--pubkey", a.pubkey]
        rc, out, err = run(cmd)
        say(f"  OCSF: {n_ev} events followed; --verify exit {rc}: {(out.strip() or err.strip()).splitlines()[-1:]}")
        if rc != 0:
            problems.append(f"A: the OCSF events do not match the stream: {(out + err).strip()[-400:]}")
        rc, out, err = run([sys.executable, os.path.join(V14, "tests", "ocsf_validate.py"), ev_path])
        say(f"  OCSF 1.9.0 schema: exit {rc}: {(out.strip() or err.strip()).splitlines()[-1:]}")
        if rc != 0:
            problems.append(f"A: the OCSF events are not valid OCSF 1.9.0: {(out + err).strip()[:400]}")

    # the cost
    for k in TASKS_A:
        ms = [r.get("ms", 0) for r in by[k] if r.get("ok")]
        say(f"  {k:<11} at the agent: p50 {pct(ms, .5)} ms, p99 {pct(ms, .99)} ms ({len(ms)})")
    for label, rows in (("the agent's MCP calls", al),
                        ("gh's MCP calls", [r for r in pre if r.get("action") == "net.mcp" and r.get("obo") == chain.get("gh")]),
                        ("the agent's opens", of(me, "file.open")),
                        ("fs's opens", of(chain.get("fs", []), "file.open"))):
        lat = [r.get("latency_us", 0) for r in rows]
        say(f"  the Warden's decision, {label}: p50 {pct(lat, .5)} us, p99 {pct(lat, .99)} us ({len(lat)})")


def check_work(a, say, problems, D, name, dry):
    W = os.path.join(D, name)
    agent = load(os.path.join(W, "agent.jsonl"))
    recs = load(os.path.join(W, "verdicts.log"))
    rs = next((r for r in recs if r.get("event") == "run_start"), {})
    label = name.upper()
    say(f"{label} (v1.29.0): Warden {rs.get('warden', '?')}, run {rs.get('run', '?')}, mode {rs.get('mode', 'enforce')}, "
        f"{len(recs)} records" + ("" if any(r.get("event") == "run_end" for r in recs) else " (no run_end)"))
    if not any(r.get("event") == "run_end" for r in recs):
        problems.append(f"{label}: the stream has no run_end")
    if (rs.get("mode") == "dry_run") != dry:
        problems.append(f"{label}: run_start's mode is {rs.get('mode')}")
    start = next((r for r in agent if r.get("start")), {})
    if start.get("ok") is not True or start.get("uid") != 65534:
        problems.append(f"{label}: the agent's start: {start}")
    turns = turns_of(agent)
    want = int(a.hours * 3600 / a.interval)
    work = [r for r in turns if "task" in r]
    say(f"  turns: {len(turns)} (about {want} expected); work done {sum(1 for r in work if r.get('ok'))}/{len(work)}")
    if len(turns) < 0.9 * want:
        problems.append(f"{label}: only {len(turns)} turns of about {want}")
    for r in [r for r in work if not r.get("ok")][:10]:
        problems.append(f"{label}: work at {r['t']} failed at {r.get('step')}: {r.get('error')}")
    policy = rs.get("policy_path") or ""
    pub = os.path.join(W, "etc", "log.key.pub")
    if not rs:
        problems.append(f"{label}: no run_start (see {name}/varek.err)")
        return
    dec = [r for r in recs if "report_id" in r]
    if not dry:
        probes = [r for r in turns if "probe" in r]
        say("  probes: " + ", ".join(f"{k} {sum(1 for r in probes if r['probe'] == k and r.get('held'))}/"
                                     f"{sum(1 for r in probes if r['probe'] == k)}" for k in PROBES_B))
        for r in [r for r in probes if not r.get("held")][:10]:
            problems.append(f"{label}: probe {r['probe']} at {r['t']} did not hold: {r.get('result')}")
        if len(turns) > 40 and len({r["probe"] for r in probes}) != len(PROBES_B):
            problems.append(f"{label}: a kind of probe never ran")
        n = {k: sum(1 for r in probes if r["probe"] == k) for k in PROBES_B}
        got = {"shadow": sum(1 for r in dec if r.get("target") == "/etc/shadow" and r.get("decision_final") == "DENY"),
               "outside": sum(1 for r in dec if r.get("target") == os.path.join(W, "outside", "w")
                              and r.get("decision_final") == "DENY"),
               "own_program": sum(1 for r in dec if r.get("action") == "process.exec"
                                  and str(r.get("target", "")).endswith("mytrue") and r.get("decision_final") == "DENY")}
        if any(got[k] < n[k] for k in PROBES_B):
            problems.append(f"{label}: the probes' refusals are not all recorded ({got} for {n})")
        if not os.path.exists(policy) or not open(policy).readline().startswith("#@ varek baseline"):
            problems.append(f"{label}: the run's policy ({policy}) is not a baseline varek run wrote")
        rc, out, _ = run(["git", "-c", "safe.directory=*", "-C", os.path.join(W, "work"), "rev-list", "--count", "HEAD"])
        commits = int(out.strip()) if rc == 0 and out.strip().isdigit() else 0
        say(f"  git commits in the project: {commits}")
        if commits < 0.8 * len(work) / 5:
            problems.append(f"{label}: only {commits} git commits for {len(work)} turns of work")
        audit(say, problems, label, policy, a.checker, os.path.join(W, "verdicts.log"), pub, 0)
    else:
        let = [r for r in dec if r.get("enforced") is False]
        kinds = {}
        for r in let:
            t = r.get("resolved") or r.get("target") or "?"
            k = t if not t.startswith("/") else os.path.relpath(t, os.path.join(W, "work")).split("/")[0]
            kinds[k] = kinds.get(k, 0) + 1
        say(f"  let through (enforced: false): {len(let)} (" + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items())[:8]) + ")")
        if not any(k == "src" for k in kinds) or not any(k == "scratch" for k in kinds):
            problems.append(f"{label}: the narrower policy's refusals of src/ and scratch/ were not recorded")
        out = audit(say, problems, label, policy, a.checker, os.path.join(W, "verdicts.log"), pub, 3)
        if "VERIFIED: DRY RUN, NOT ENFORCED" not in out:
            problems.append(f"{label}: the audit does not say DRY RUN, NOT ENFORCED")
        # the draft
        draft = os.path.join(W, "draft.txt")
        if not os.path.exists(draft):
            problems.append(f"{label}: varek policy suggest wrote no draft ({open(os.path.join(W, 'suggest.err')).read()[-300:] if os.path.exists(os.path.join(W, 'suggest.err')) else ''})")
            return
        text = open(draft).read()
        exact = re.findall(r"^allow path exact (\S+)", text, re.M)
        say(f"  varek policy suggest: {len(exact)} exact rule(s)")
        if not any(p.endswith("/src/mod_0.py") for p in exact):
            problems.append(f"{label}: the draft has no exact rule for the files written under src/")
        rc, out, err = run([a.vdp, draft, "lint"])
        if rc != 0:
            problems.append(f"{label}: the draft does not lint: {(out + err).strip()[-300:]}")
        rc, out, err = run([a.checker, draft, "digest"])
        if rc != 0:
            problems.append(f"{label}: the certificate checker refuses the draft: {(out + err).strip()[-300:]}")
        noted = set(re.findall(r"^# system call (\d+) ", text, re.M))
        rer = load(os.path.join(W, "draft.log"))
        rwork = [r for r in load(os.path.join(W, "draft.jsonl")) if "task" in r]
        rlet = [r for r in rer if "report_id" in r and r.get("enforced") is False]
        other = [r for r in rlet if not (r.get("action") == "other" and str(r.get("target", "")).startswith("syscall:")
                                          and str(r["target"]).split(":")[1] in noted)]
        say(f"  a dry run under the draft: work done {sum(1 for r in rwork if r.get('ok'))}/{len(rwork)}, let through "
            f"{len(rlet)} (system calls the draft notes: {len(rlet) - len(other)})")
        if not rwork or any(not r.get("ok") for r in rwork):
            problems.append(f"{label}: the work under the draft did not all get done")
        if other:
            problems.append(f"{label}: under the draft, {len(other)} call(s) still refused (first: "
                            f"{other[0].get('action')} {other[0].get('target')})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--checker", required=True)
    ap.add_argument("--vdp", required=True)
    ap.add_argument("--values", required=True)
    ap.add_argument("--dir-ag", required=True)
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--lead", type=float, default=300)
    ap.add_argument("--pubkey")
    a = ap.parse_args()
    a.store = "/etc/varek-soak-shared/mt"
    out, problems = [], []
    say = out.append
    D = a.dir
    values = json.load(open(a.values))
    say(f"soak_check: the shared soak (v1.28.1, v1.29.0, v1.31.0) in {D}: {a.hours} h, a turn every {a.interval} s")
    check_a(a, say, problems, values, D)
    check_work(a, say, problems, D, "b", False)
    check_work(a, say, problems, D, "c", True)
    try:
        lines = open(os.path.join(D, "rss.tsv")).read().splitlines()
        head = lines[0].split("\t")
        rows = [l.split("\t") for l in lines[1:]]
        for i, name in enumerate(head[1:], 1):
            xs = [int(r[i]) for r in rows if len(r) > i and r[i].isdigit()]
            if xs:
                say(f"memory, {name}: {xs[0]} kB at the start, {max(xs)} kB at most, {xs[-1]} kB at the end "
                    f"({len(xs)} samples)")
                if xs[-1] > xs[0] + 16384:
                    say(f"  note: {name} grew by {xs[-1] - xs[0]} kB over the run")
    except (OSError, IndexError):
        say("memory: no rss.tsv")
    say("")
    for pr in problems[:80]:
        say(f"  PROBLEM {pr}")
    say(f"soak_check: {'PASS' if not problems else 'FAIL'}")
    text = "\n".join(out) + "\n"
    print(text, end="")
    with open(os.path.join(D, "report.txt"), "w") as fh:
        fh.write(text)
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
