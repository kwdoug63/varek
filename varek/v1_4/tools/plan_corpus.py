#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
plan_corpus.py — v1.35 step 8 (docs/security/v1.35-frameworks.md): plans the
adapters generate from a corpus of agents, each decided under a policy, and
v1.11's condition measured (docs/roadmap/v1.36-v1.37.md): the share of plans
refused only for steps UNKNOWN on the collection stratum, that is, plans
v1.11 could let start. Counted per plan.

The corpus (harness/plans/manifest.json) names each agent by its public
repository, commit and path, the framework, and the adapter's options; an
agent built inside a function (the OpenAI Agents SDK's MCP examples) is
read through a shim beside it (harness/plans/shims/), the example's own
constructors at module level.

Each plan is decided under the policy an operator would write who names
everything the plan names, the "named" rule, the same for every agent:

  file_open PATH [open=read]       allow path [exact] PATH [readonly]
  net_connect HOST:PORT            allow host HOST:PORT
  process_exec PROGRAM             allow exec PROGRAM
  mcp_call URL method=M [name=N]   allow host (the URL's), allow mcp URL M [N]
                                   (an mcp rule names its server by host
                                   name: none for a server at an address)
  subagent NAME exec=PROGRAM       allow exec PROGRAM subagent=NAME

and never grants a server whole: a tools/call step naming no tool gets no
rule. So a plan is refused only for what no rule naming one object can
allow: those steps are what the figure is about.

Each step not SATISFIED is put on a stratum (docs/verification/corpus-v1-
schema.md) by what it names:

  file_open                       string-path
  net_connect                     string-host
  mcp_call with name=, or another method than tools/call   string-host
  mcp_call tools/call, no name    unlisted-tools: every tool of the server,
                                  which the plan does not list
  process_exec, subagent          launch
  credential                      credential
  (a step refused for its certificate)   certificate

classified from the plan's own step (its kind, method= and name=), not the
decision's object, which for a server at an address is its URL alone (step
9, review). No step of plan 1.35 is on the collection stratum
(docs/verification/corpus-v1-schema.md: an element of a payload crossing a
boundary): a step names one object, or a server's tools as a set the plan
does not list, which a policy granting the server, or an adapter listing
its tools, allows without v1.11. So with plan 1.35 the plan gate cannot
meet v1.11's condition at all, whatever the corpus: the column is kept,
and is 0 by construction (v111_clears), not by measurement.

  plan_corpus.py fetch  --manifest M --src DIR
  plan_corpus.py run    --manifest M --src DIR --out DIR [--python PY] [--varek-home DIR]
  plan_corpus.py report --out DIR

run writes OUT/plans/, OUT/policies/, OUT/decisions/, OUT/results.json and
OUT/summary.md; report prints the summary again from results.json.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
VAREK = os.path.join(HERE, "varek")
DATA_ADAPTERS = ("agentcore", "watsonx", "claude")
STEP = re.compile(r'^\s*(\w+) step "(.*)" is (SATISFIED|UNSATISFIED|UNKNOWN): (.*)$')
CERT = re.compile(r'^\s*(?:\[warden\] plan: )?certificate refused for "(.*)": (.*)$')   # step 9 (review)


class CorpusError(Exception):
    pass


def load_manifest(path):
    with open(path) as fh:
        m = json.load(fh)
    if not isinstance(m.get("agents"), list) or not isinstance(m.get("repos"), dict):
        raise CorpusError(f"{path}: not a manifest (repos, agents)")
    ids = [a["id"] for a in m["agents"]]
    if len(ids) != len(set(ids)):
        raise CorpusError(f"{path}: an id is named twice")
    return m


def cmd_fetch(a):
    m = load_manifest(a.manifest)
    os.makedirs(a.src, exist_ok=True)
    for name, r in m["repos"].items():
        d = os.path.join(a.src, name)
        if os.path.isdir(os.path.join(d, ".git")):
            have = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            if have == r["commit"]:
                print(f"{name}: at {r['commit']}")
                continue
        else:
            subprocess.run(["git", "init", "-q", d], check=True)
            subprocess.run(["git", "-C", d, "remote", "add", "origin", r["url"]], check=True)
        subprocess.run(["git", "-C", d, "fetch", "-q", "--depth", "1", "origin", r["commit"]], check=True)
        subprocess.run(["git", "-C", d, "checkout", "-q", "FETCH_HEAD"], check=True)
        print(f"{name}: fetched {r['commit']}")
    return 0


def plan_steps(path):
    out = []
    with open(path) as fh:
        for line in fh:
            f = line.split()
            if len(f) >= 4 and f[0] == "action":
                kv = dict(x.split("=", 1) for x in f[4:] if "=" in x)
                out.append({"label": f[1], "kind": f[2], "target": f[3], **kv})
    return out


def hostport(url):
    """HOST:PORT of a server's URL, an IPv6 address bracketed (step 9, review)"""
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise CorpusError(f"{url!r} is not an http:// or https:// URL")
    h = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
    return f"{h}:{u.port or (443 if u.scheme == 'https' else 80)}"


def named_policy(steps):
    """the "named" rule (the module's docstring)"""
    L = ["# plan_corpus.py: the \"named\" policy, from the plan's own steps", "require warden 1.35", "proxy inspect"]
    for s in steps:
        k, t = s["kind"], s["target"]
        if k == "file_open":
            L.append(f"allow path {'' if t.endswith('/') else 'exact '}{t}{' readonly' if s.get('open') == 'read' else ''}")
        elif k == "net_connect":
            L.append(f"allow host {t}")
        elif k == "process_exec":
            L.append(f"allow exec {t}")
        elif k == "mcp_call":
            L.append(f"allow host {hostport(t)}")
            m, n = s.get("method", ""), s.get("name")
            if m == "tools/call" and not n:
                continue                     # a server is never granted whole
            host = urlsplit(t).hostname or ""
            if re.fullmatch(r"[0-9.]+", host) or ":" in host:
                continue                     # an mcp rule names its server by host name (v1.31), not an address
            L.append(f"allow mcp {t} {m}" + (f" {n}" if n else ""))
        elif k == "subagent" and s.get("exec"):
            L.append(f"allow exec {s['exec']} subagent={t}")
    ports = sorted({int(hostport(s["target"]).rsplit(":", 1)[1]) for s in steps if s["kind"] == "mcp_call"} | {80, 443})
    if ports != [80, 443]:                   # an MCP server on another port: the proxy takes it too
        L.insert(3, "proxy ports " + " ".join(map(str, ports)))
    return "\n".join(dict.fromkeys(L)) + "\n"


def stratum(kind, step):
    """a step not SATISFIED, by what the plan's own step names"""
    if kind == "file_open":
        return "string-path"
    if kind == "net_connect":
        return "string-host"
    if kind == "mcp_call":
        if step and step.get("method", "tools/call") == "tools/call" and not step.get("name"):
            return "unlisted-tools"
        return "string-host"
    if kind in ("process_exec", "subagent"):
        return "launch"
    return kind


def match_steps(steps, refused):
    """each refused line's step of the plan: the Warden decides the steps in
    the plan's order and says each refused one in that order, so the next
    step of the same kind whose target the object names"""
    def norm(url):                       # the canonical URL names the default port; the plan may not
        try:
            u = urlsplit(url)
            return (u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80), u.path.rstrip("/"))
        except ValueError:
            return url

    def same(kind, obj, s):
        if s["kind"] != kind:
            return False
        if kind != "mcp_call":
            return True
        parts = obj.split("#")
        if norm(parts[0]) != norm(s["target"]):
            return False
        # an object URL#METHOD#NAME is the step's method and name; the URL alone (a server at an
        # address, refused before its object is made) is any step of that server, in order
        return len(parts) != 3 or (parts[1] == s.get("method", "tools/call") and parts[2] == s.get("name", ""))
    i, out = 0, []
    for kind, obj in refused:
        j = i
        while j < len(steps) and not same(kind, obj, steps[j]):
            j += 1
        if j < len(steps):
            out.append(steps[j])
            i = j + 1
        else:
            out.append(None)
    return out


def v111_clears(kind, obj):
    """whether v1.11's fragment could clear the step: it decides over the
    elements of a payload given at decision time
    (docs/verification/bounded-sequence-fragment.md, 2); a plan 1.35 step
    gives it none, so this is False by construction, not a measurement"""
    return False


def generate(a, ent, m, project, plan):
    fw = ent["framework"]
    argv = [sys.executable, VAREK, "plan", "generate", "-o", plan, "--force", "--from", fw, project]
    argv[4:4] = ["--no-confine"] if fw in DATA_ADAPTERS else ["--python", a.python]
    argv += ent.get("args", [])
    env = dict(os.environ)
    if a.varek_home:
        env["VAREK_HOME"] = a.varek_home
    try:
        r = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=600)
    except subprocess.TimeoutExpired:                    # step 9 (review): that agent's, not the run's end
        return False, ["varek plan generate took more than 600 s"]
    why = [x for x in (r.stderr + r.stdout).splitlines() if not x.startswith("{")]
    return r.returncode == 0 and os.path.isfile(plan), why


def cmd_run(a):
    m = load_manifest(a.manifest)
    for sub in ("plans", "policies", "decisions", "work"):
        os.makedirs(os.path.join(a.out, sub), exist_ok=True)
    results = []

    def save():                          # step 9 (review): after each agent, so a run cut short keeps them
        with open(os.path.join(a.out, "results.json"), "w") as fh:
            json.dump({"manifest": a.manifest, "results": results}, fh, indent=1)
    for ent in m["agents"]:
        safe = ent["id"].replace("/", "__")
        repo = m["repos"][ent["repo"]]
        project = os.path.join(a.src, ent["repo"], ent["path"])
        if not os.path.isdir(project):
            raise CorpusError(f"{ent['id']}: no {project} (plan_corpus.py fetch)")
        if ent.get("shim"):                       # the example's directory, the shim beside it
            work = os.path.join(a.out, "work", safe)
            shutil.rmtree(work, ignore_errors=True)
            shutil.copytree(project, work, symlinks=True)
            shutil.copy(os.path.join(os.path.dirname(os.path.abspath(a.manifest)), ent["shim"]),
                        os.path.join(work, "varek_shim.py"))
            subprocess.run(["chmod", "-R", "a+rX", work], check=True)
            project = work
        plan = os.path.join(a.out, "plans", safe + ".plan")
        ok, why = generate(a, ent, m, project, plan)
        res = {"id": ent["id"], "framework": ent["framework"], "source": f"{repo['url']}@{repo['commit']}:{ent['path']}",
               "shim": ent.get("shim")}
        if not ok:
            res.update({"generated": False, "why": why[-3:]})
            results.append(res)
            save()
            print(f"{ent['id']}: no plan ({(why or ['?'])[-1][:120]})")
            continue
        steps = plan_steps(plan)
        pol = os.path.join(a.out, "policies", safe + ".policy")
        try:
            text = named_policy(steps)
        except CorpusError as e:
            res.update({"generated": True, "policy_error": [str(e)]})
            results.append(res)
            save()
            print(f"{ent['id']}: no named policy ({e})")
            continue
        with open(pol, "w") as fh:
            fh.write(text)
        try:
            d = subprocess.run([sys.executable, VAREK, "policy", "check", pol, "--plan", plan],
                               capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            res.update({"generated": True, "policy_error": ["varek policy check took more than 300 s"]})
            results.append(res)
            save()
            continue
        with open(os.path.join(a.out, "decisions", safe + ".txt"), "w") as fh:
            fh.write(d.stdout + d.stderr)
        out = d.stdout + d.stderr
        if "policy error:" in out or "plan load failed" in out:
            res.update({"generated": True, "policy_error": [x for x in out.splitlines()
                                                            if "policy error" in x or "plan load failed" in x][:2]})
            results.append(res)
            save()
            print(f"{ent['id']}: the named policy or the plan does not load ({res['policy_error'][0][:120]})")
            continue
        lines, certs = [], []
        for line in out.splitlines():
            mm, mc = STEP.match(line), CERT.match(line)
            if mm and mm.group(3) != "SATISFIED":
                lines.append((mm.group(1), mm.group(2), mm.group(3), mm.group(4)))
            elif mc:
                certs.append({"kind": "?", "object": mc.group(1), "decision": "UNKNOWN", "why": mc.group(2),
                              "stratum": "certificate", "v111_clears": False})
        refused = []
        for (k, obj, dec, why_), st in zip(lines, match_steps(steps, [(x[0], x[1]) for x in lines])):
            refused.append({"kind": k, "object": obj, "decision": dec, "why": why_,
                            "step": st and st["label"], "stratum": stratum(k, st), "v111_clears": v111_clears(k, obj)})
        refused += certs
        authorized = bool(re.search(r": authorized under \S+ \(\d+ actions\)", out))
        if not authorized and not refused:
            res.update({"generated": True, "policy_error": ["refused, and no step's reason was read: " + out[-300:]]})
            results.append(res)
            save()
            print(f"{ent['id']}: refused, no step's reason read")
            continue
        kinds = {}
        for s in steps:
            kinds[s["kind"]] = kinds.get(s["kind"], 0) + 1
        res.update({"generated": True, "steps": len(steps), "kinds": kinds,
                    "names_a_server": any(s["kind"] in ("mcp_call", "subagent") for s in steps),
                    "authorized": authorized, "refused_steps": refused,
                    "refused_only_collection": bool(refused) and all(r["stratum"] == "collection" for r in refused),
                    "refused_only_unlisted": bool(refused) and all(r["stratum"] == "unlisted-tools" for r in refused),
                    "v111_could_start": bool(refused) and all(r["v111_clears"] for r in refused)})
        results.append(res)
        save()
        print(f"{ent['id']}: {len(steps)} steps, {'authorized' if authorized else 'refused (' + ', '.join(sorted({r['stratum'] for r in refused})) + ')'}")
    save()
    text = summary(results)
    with open(os.path.join(a.out, "summary.md"), "w") as fh:
        fh.write(text)
    print(text)
    return 0


def pct(n, d):
    return f"{n}/{d} ({100.0 * n / d:.1f}%)" if d else "0/0"


def summary(results):
    gen = [r for r in results if r.get("generated") and "policy_error" not in r]
    fws = sorted({r["framework"] for r in results})
    rows = ["| framework | agents | plans | authorized | refused | refused only for unlisted tools | "
            "refused only for collection steps | v1.11 could let start (0 by construction) |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |"]

    def row(name, rs, g):
        ref = [r for r in g if not r["authorized"]]
        return (f"| {name} | {len(rs)} | {len(g)} | {sum(r['authorized'] for r in g)} | {len(ref)} | "
                f"{pct(sum(r.get('refused_only_unlisted', False) for r in g), len(g))} | "
                f"{pct(sum(r['refused_only_collection'] for r in g), len(g))} | "
                f"{pct(sum(r['v111_could_start'] for r in g), len(g))} |")
    for fw in fws:
        rs = [r for r in results if r["framework"] == fw]
        rows.append(row(fw, rs, [r for r in rs if r.get("generated") and "policy_error" not in r]))
    rows.append(row("**all**", results, gen))
    srv = [r for r in gen if r["names_a_server"]]
    rows.append(row("plans naming a tool server", srv, srv))
    strata = {}
    for r in gen:
        for s in r["refused_steps"]:
            strata[s["stratum"]] = strata.get(s["stratum"], 0) + 1
    share = [sum(r.get("refused_only_unlisted", False) for r in gen if r["framework"] == fw) /
             max(1, len([r for r in gen if r["framework"] == fw])) for fw in fws]
    lines = ["# v1.35 step 8: the plan corpus, v1.11's condition", "",
             f"{len(results)} agents, {len(fws)} frameworks ({', '.join(fws)}); {len(gen)} plans generated.", ""]
    lines += rows
    lines += ["", "Steps not SATISFIED, by stratum: " +
              (", ".join(f"{k} {v}" for k, v in sorted(strata.items())) or "none") + ".", "",
              f"Per framework (each framework's share, averaged): {100.0 * sum(share) / max(1, len(share)):.1f}% "
              f"refused only for unlisted tools.", "",
              "No step of plan 1.35 is on the collection stratum, so the collection column and v1.11's are 0 by "
              "construction: with plan 1.35 the plan gate cannot meet v1.11's condition. The agents are the "
              "frameworks' published examples, not deployed agents.", ""]
    nogen = [r for r in results if not r.get("generated")]
    if nogen:
        def reason(r):                           # the adapter's own line, else the last
            w = r.get("why") or ["?"]
            return next((x.strip() for x in w if "failed" in x or "refused" in x), w[-1].strip())[:220]
        lines.append(f"No plan for {len(nogen)}: " + "; ".join(f"{r['id']} ({reason(r)})" for r in nogen) + ".")
    perr = [r for r in results if "policy_error" in r]          # step 9 (review): left out of the plans, said
    if perr:
        lines.append(f"Left out, the named policy or the plan not loading: {len(perr)}: " +
                     "; ".join(f"{r['id']} ({r['policy_error'][0][:160]})" for r in perr) + ".")
    return "\n".join(lines) + "\n"


def cmd_report(a):
    with open(os.path.join(a.out, "results.json")) as fh:
        print(summary(json.load(fh)["results"]))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="plan_corpus.py", description="v1.35 step 8: the plan corpus and v1.11's condition")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--manifest", required=True)
    f.add_argument("--src", required=True)
    f.set_defaults(fn=cmd_fetch)
    r = sub.add_parser("run")
    r.add_argument("--manifest", required=True)
    r.add_argument("--src", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--python", default=sys.executable, help="the agents' Python, for the code adapters")
    r.add_argument("--varek-home", help="VAREK_HOME for varek plan generate (its adapters/, warden)")
    r.set_defaults(fn=cmd_run)
    p = sub.add_parser("report")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_report)
    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except (CorpusError, OSError, subprocess.CalledProcessError) as e:
        print(f"plan_corpus: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
