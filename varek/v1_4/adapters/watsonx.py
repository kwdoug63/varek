#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
watsonx.py — VAREK's adapter for IBM watsonx Orchestrate (v1.35 step 6,
docs/security/v1.35-frameworks.md, D5).

Writes an agent's plan (plan 1.35) from an Agent Development Kit project's
files, read as data (ADK 2.19): the agent's spec (`kind: native`, YAML or
JSON) and the toolkits it names (`kind: mcp`), found anywhere in the
project. Nothing of the agent's code is imported.

  - each toolkit over HTTP (`url`, `transport`): its MCP calls (initialize,
    notifications/initialized, tools/list) and tools/call of each tool it
    allows (`tools`); `tools: ["*"]` or none listed (the agent finds them
    when it connects) makes one step naming no tool, said so;
  - each toolkit the agent's platform launches (`command`): a sub-agent
    step naming the toolkit (its calls over stdio are not decided; its
    launch is);
  - its model (`llm: PROVIDER/MODEL`): the provider's host (watsonx.ai's in
    --watsonx-region for `watsonx/...`, or --model-host);
  - its collaborators, as the agents of this project they are: their own
    toolkits and models, each said so.
Its tools that run on the platform (Python and OpenAPI tools, flows) are
named in comments: the platform runs them, not the agent's process.

Where it runs: a native agent runs on watsonx Orchestrate. Its plan can be
checked against a policy (varek plan generate --policy) wherever; a run is
held to it only where the agent runs beside the Warden (the Developer
Edition, or an agent served by the team).

  watsonx.py PROJECT [--agent NAME] [--watsonx-region REGION]
             [--model-host HOST:PORT ...] [--no-runtime] [--app-dir DIR]

It reads YAML with PyYAML where it is installed (the system's), and JSON
always. The plan goes to standard output; exit 0 with a plan, 1 without.
"""

import argparse
import json
import os
import re
import sys

import importlib.util as _ilu
_vp_spec = _ilu.spec_from_file_location("varek_plan", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                    "varek_plan.py"))
vp = _ilu.module_from_spec(_vp_spec)
_vp_spec.loader.exec_module(vp)   # by its path: the adapter's directory is not put on sys.path, where an
                                  # adapter's name could hide the framework's package

ADAPTER = "watsonx"
SPEC_SUFFIXES = (".yaml", ".yml", ".json")
REGION = re.compile(r"[a-z]{2}-[a-z]+(-[0-9])?")
# watsonx.ai's regions (its documented ML endpoints)
WATSONX_HOST = "{}.ml.cloud.ibm.com:443"

try:
    import yaml  # the system's PyYAML, where installed
except ImportError:                                  # pragma: no cover - depends on the host
    yaml = None


def warn(msg):
    vp.warn(ADAPTER, msg)


def load_spec(path):
    data = vp.read_bytes(path, "spec")
    if path.endswith(".json"):
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise vp.AdapterError(f"{path} is not JSON: {e}")
    if yaml is None:
        raise vp.AdapterError(f"{path} is YAML, and this Python has no PyYAML (install python3-yaml, or "
                              f"export the spec as JSON)")
    try:
        docs = [d for d in yaml.safe_load_all(data.decode("utf-8")) if d is not None]
    except (UnicodeDecodeError, yaml.YAMLError) as e:
        raise vp.AdapterError(f"{path} is not YAML: {e}")
    return docs[0] if len(docs) == 1 else {"__docs__": docs}


def scan(root, depth=4):
    """every spec under the project: {'agents': {name: (path, spec)}, 'toolkits': {...}}"""
    found = {"agents": {}, "toolkits": {}}
    root_depth = root.rstrip("/").count("/")
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if not x.startswith(".") and x not in ("node_modules", "__pycache__", "venv"))
        if d.count("/") - root_depth >= depth:
            dirs[:] = []
        for f in sorted(files):
            if not f.endswith(SPEC_SUFFIXES):
                continue
            p = os.path.join(d, f)
            try:
                spec = load_spec(p)
            except vp.AdapterError as e:
                if yaml is None and not f.endswith(".json"):
                    raise
                warn(f"{os.path.relpath(p, root)}: not read ({e}); left out")
                continue
            for s in spec.get("__docs__", [spec]) if isinstance(spec, dict) else []:
                if not isinstance(s, dict) or not isinstance(s.get("name"), str):
                    continue
                kind = s.get("kind")
                if kind == "mcp":
                    found["toolkits"][s["name"]] = (p, s)
                elif kind in ("native", "agent", "external") or (
                        kind is None and s.get("spec_version") and any(k in s for k in ("toolkits", "tools",
                                                                                       "collaborators", "llm"))):
                    found["agents"][s["name"]] = (p, s)
    return found


def model_hosts(llm, region, given):
    out = []
    if isinstance(llm, str) and "/" in llm:
        provider = llm.split("/", 1)[0].lower()
        if provider == "watsonx":
            out.append(("model", WATSONX_HOST.format(region), f"watsonx.ai in {region} ({llm})"))
        elif provider in vp.MODEL_HOSTS:
            out.append(("model", vp.MODEL_HOSTS[provider], f"the model provider ({llm})"))
        else:
            warn(f"model {llm}: no host known for provider {provider!r}: name it with --model-host")
    for h in given:
        out.append(("model", h, "the model provider (--model-host)"))
    return out


def toolkit_steps(P, name, tk, notes):
    url, cmd = tk.get("url"), tk.get("command")
    tools = tk.get("tools")
    P.comment()
    if url:
        P.comment(f"toolkit {name}: {url} ({tk.get('transport', 'streamable_http')})")
        allow = [t for t in tools or [] if isinstance(t, str) and t != "*"]
        if not allow:
            why = "it allows every tool (tools: [\"*\"])" if tools and "*" in tools else \
                  "it lists no tool (the agent finds them when it connects)"
            vp.mcp_server_steps(P, url, name, None, why)
        else:
            vp.mcp_server_steps(P, url, name, allow)
    elif cmd:
        P.comment(f"toolkit {name}: launched by the agent's platform")
        vp.stdio_server_step(P, name, cmd.split()[0])
    else:
        notes.append(f"toolkit {name}: no url and no command (not imported yet?): left out")


def agent_steps(P, name, spec, specs, region, model_given, seen, notes, depth=0):
    seen.add(name)
    kind = spec.get("kind")
    if kind == "external" or (kind == "agent" and spec.get("deployment")):
        notes.append(f"agent {name} is {'an external agent' if kind == 'external' else 'a custom agent (a code bundle)'}: "
                     f"its plan is its own framework's (varek plan generate --from langgraph, ...)")
    hosts = model_hosts(spec.get("llm"), region, model_given if depth == 0 else ())
    if hosts:
        vp.host_steps(P, hosts)
    for tk in spec.get("toolkits") or []:
        if not isinstance(tk, str):
            continue
        if tk not in specs["toolkits"]:
            raise vp.AdapterError(f"agent {name} names toolkit {tk!r}, and no toolkit spec of that name is in the "
                                  f"project (kind: mcp, name: {tk})")
        toolkit_steps(P, tk, specs["toolkits"][tk][1], notes)
    tools = [t if isinstance(t, str) else (t or {}).get("name") for t in spec.get("tools") or []]
    if tools:
        notes.append(f"agent {name}'s tools (run by the platform, not the agent's process): "
                     f"{', '.join(str(t) for t in tools)}")
    for c in spec.get("collaborators") or []:
        cname = c if isinstance(c, str) else (c or {}).get("name")
        if cname in seen:
            continue
        if cname in specs["agents"]:
            P.comment()
            P.comment(f"collaborator {cname} (of {name}): its toolkits and model")
            agent_steps(P, cname, specs["agents"][cname][1], specs, region, (), seen, notes, depth + 1)
        else:
            notes.append(f"collaborator {cname} of agent {name}: not in this project (its plan is its own)")


def generate(a):
    root = os.path.abspath(a.project)
    if not os.path.isdir(root):
        raise vp.AdapterError(f"no project directory at {a.project}")
    if a.watsonx_region and not REGION.fullmatch(a.watsonx_region):
        raise vp.AdapterError(f"--watsonx-region {a.watsonx_region!r} is not a region")
    specs = scan(root)
    agents = specs["agents"]
    if a.agent:
        if a.agent not in agents:
            raise vp.AdapterError(f"no agent named {a.agent!r} in the project (it has: {', '.join(agents) or 'none'})")
        name = a.agent
    elif len(agents) == 1:
        name = next(iter(agents))
    elif not agents:
        raise vp.AdapterError("no agent spec in the project (kind: native, with a name)")
    else:
        raise vp.AdapterError(f"the project has {len(agents)} agents ({', '.join(agents)}): name one with --agent")
    path, spec = agents[name]
    P = vp.Plan()
    vp.header(P, ADAPTER, f"{os.path.relpath(path, root)} (agent {name})",
              f"agent {name}, model {spec.get('llm', '(the platform default)')}",
              ("A native agent runs on watsonx Orchestrate: its plan can be checked against a policy",
               "anywhere; a run is held to it only where the agent runs beside the Warden."))
    if not a.no_runtime:
        vp.runtime_steps(P, a.app_dir)
    notes = []
    agent_steps(P, name, spec, specs, a.watsonx_region or "us-south", a.model_host, set(), notes)
    if notes:
        P.comment()
        for n in notes:
            P.comment(n)
    if P.n == 0:
        raise vp.AdapterError(f"agent {name}: nothing to write")
    return P.text()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="watsonx.py", description="VAREK's plan adapter for IBM watsonx Orchestrate")
    ap.add_argument("project", help="the Agent Development Kit project (its agent and toolkit specs)")
    ap.add_argument("--agent", help="the agent to write the plan of, if the project has more than one")
    ap.add_argument("--watsonx-region", help="watsonx.ai's region for a watsonx/ model (default us-south)")
    ap.add_argument("--model-host", action="append", default=[], metavar="HOST:PORT",
                    help="the model provider's host, where the agent's llm does not say it")
    ap.add_argument("--app-dir", help="the agent's code directory, where it runs beside the Warden")
    ap.add_argument("--no-runtime", action="store_true", help="leave out the language runtime's own reads")
    a = ap.parse_args(argv)
    try:
        sys.stdout.write(generate(a))
    except vp.AdapterError as e:
        warn(str(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
