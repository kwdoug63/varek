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
  mcp_call tools/call, no name    collection: the server's tools, an
                                  element each, listed by the live server
  process_exec, subagent          launch
  credential                      credential

and asked whether v1.11's fragment could clear it: it decides predicates
over the elements of a payload given at decision time, at most N long
(docs/verification/bounded-sequence-fragment.md, 2). A collection step
clears only if the plan gives its elements; a plan 1.35 step gives none (it
names one object, or a server whose tools the plan does not list).

  plan_corpus.py fetch  --manifest M --src DIR
  plan_corpus.py run    --manifest M --src DIR --out DIR [--python PY]
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
    u = urlsplit(url)
    return f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"


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


def stratum(kind, obj):
    """a step not SATISFIED, by what it names (the decision's object)"""
    if kind == "file_open":
        return "string-path"
    if kind == "net_connect":
        return "string-host"
    if kind == "mcp_call":
        parts = obj.split("#")
        if len(parts) == 3 and parts[1] == "tools/call" and parts[2] == "":
            return "collection"
        return "string-host"
    if kind in ("process_exec", "subagent"):
        return "launch"
    return kind


def v111_clears(kind, obj):
    """whether v1.11's fragment could clear the step: it decides over the
    elements of a payload given at decision time; a plan 1.35 step gives
    none (the server's tools are listed by the live server)"""
    return False


def generate(a, ent, m, project, plan):
    fw = ent["framework"]
    argv = [sys.executable, VAREK, "plan", "generate", "-o", plan, "--force", "--from", fw, project]
    argv[4:4] = ["--no-confine"] if fw in DATA_ADAPTERS else ["--python", a.python]
    argv += ent.get("args", [])
    env = dict(os.environ)
    if a.varek_home:
        env["VAREK_HOME"] = a.varek_home
    r = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=600)
    why = [x for x in (r.stderr + r.stdout).splitlines() if not x.startswith("{")]
    return r.returncode == 0 and os.path.isfile(plan), why


def cmd_run(a):
    m = load_manifest(a.manifest)
    for sub in ("plans", "policies", "decisions", "work"):
        os.makedirs(os.path.join(a.out, sub), exist_ok=True)
    results = []
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
            print(f"{ent['id']}: no plan ({(why or ['?'])[-1][:120]})")
            continue
        steps = plan_steps(plan)
        pol = os.path.join(a.out, "policies", safe + ".policy")
        with open(pol, "w") as fh:
            fh.write(named_policy(steps))
        d = subprocess.run([sys.executable, VAREK, "policy", "check", pol, "--plan", plan],
                           capture_output=True, text=True, timeout=300)
        with open(os.path.join(a.out, "decisions", safe + ".txt"), "w") as fh:
            fh.write(d.stdout + d.stderr)
        out = d.stdout + d.stderr
        if "policy error:" in out:
            res.update({"generated": True, "policy_error": [x for x in out.splitlines() if "policy error" in x][:2]})
            results.append(res)
            print(f"{ent['id']}: the named policy does not load ({res['policy_error'][0][:120]})")
            continue
        refused = []
        for line in out.splitlines():
            mm = STEP.match(line)
            if mm and mm.group(3) != "SATISFIED":
                k, obj = mm.group(1), mm.group(2)
                refused.append({"kind": k, "object": obj, "decision": mm.group(3), "why": mm.group(4),
                                "stratum": stratum(k, obj), "v111_clears": v111_clears(k, obj)})
        authorized = bool(re.search(r": authorized under \S+ \(\d+ actions\)", out))
        if not authorized and not refused:
            raise CorpusError(f"{ent['id']}: the plan was refused and no step's reason was read:\n{out[-800:]}")
        kinds = {}
        for s in steps:
            kinds[s["kind"]] = kinds.get(s["kind"], 0) + 1
        res.update({"generated": True, "steps": len(steps), "kinds": kinds,
                    "names_a_server": any(s["kind"] in ("mcp_call", "subagent") for s in steps),
                    "authorized": authorized, "refused_steps": refused,
                    "refused_only_collection": bool(refused) and all(r["stratum"] == "collection" for r in refused),
                    "v111_could_start": bool(refused) and all(r["v111_clears"] for r in refused)})
        results.append(res)
        print(f"{ent['id']}: {len(steps)} steps, {'authorized' if authorized else 'refused (' + ', '.join(sorted({r['stratum'] for r in refused})) + ')'}")
    with open(os.path.join(a.out, "results.json"), "w") as fh:
        json.dump({"manifest": a.manifest, "results": results}, fh, indent=1)
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
    rows = ["| framework | agents | plans | authorized | refused | refused only for collection steps | v1.11 could let start |",
            "| --- | --- | --- | --- | --- | --- | --- |"]

    def row(name, rs, g):
        ref = [r for r in g if not r["authorized"]]
        return (f"| {name} | {len(rs)} | {len(g)} | {sum(r['authorized'] for r in g)} | {len(ref)} | "
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
    share = [sum(r["refused_only_collection"] for r in gen if r["framework"] == fw) /
             max(1, len([r for r in gen if r["framework"] == fw])) for fw in fws]
    lines = ["# v1.35 step 8: the plan corpus, v1.11's condition", "",
             f"{len(results)} agents, {len(fws)} frameworks ({', '.join(fws)}); {len(gen)} plans generated.", ""]
    lines += rows
    lines += ["", "Steps not SATISFIED, by stratum: " +
              (", ".join(f"{k} {v}" for k, v in sorted(strata.items())) or "none") + ".", "",
              f"Per framework (each framework's share, averaged): {100.0 * sum(share) / max(1, len(share)):.1f}% "
              f"refused only for collection steps.", ""]
    nogen = [r for r in results if not r.get("generated")]
    if nogen:
        def reason(r):                           # the adapter's own line, else the last
            w = r.get("why") or ["?"]
            return next((x.strip() for x in w if "failed" in x or "refused" in x), w[-1].strip())[:220]
        lines.append(f"No plan for {len(nogen)}: " + "; ".join(f"{r['id']} ({reason(r)})" for r in nogen) + ".")
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
