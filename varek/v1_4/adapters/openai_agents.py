#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
openai_agents.py — VAREK's adapter for the OpenAI Agents SDK (v1.35 step 6,
docs/security/v1.35-frameworks.md, D5).

An Agents SDK agent exists only as Python objects, so this adapter imports
it (`--entry FILE.py:ATTR`, an Agent), in the agent's own Python (`varek plan
generate --python`), under the Warden: the project and its packages
read-only, no network, each provider's key a placeholder.

From the agent, and each agent it hands off to (a handoff runs in the same
process: its tools and servers are the run's too), it writes:
  - the model's host: OpenAI's API for a model named by a string, or the
    client's base URL (OpenAIResponsesModel, OpenAIChatCompletionsModel), or
    the provider of a LiteLLM model (`anthropic/...`); OpenAI's API is also
    where the SDK sends its traces, unless they are off;
  - each MCP server: over HTTP (MCPServerStreamableHttp, MCPServerSse), its
    MCP calls and tools/call of each tool its static filter allows
    (allowed_tool_names), or one step naming no tool (no filter, a blocked
    list only, or a callable filter), said so; over stdio (MCPServerStdio),
    a sub-agent step for its program.
Hosted tools (WebSearchTool, FileSearchTool, CodeInterpreterTool,
ImageGenerationTool, HostedMCPTool) run at OpenAI, inside the model's
request: they are comments, not steps. A function tool runs in the agent's
process: what it opens and dials is decided by the policy as any call, and
is not in the plan unless named (--host, --file).

  openai_agents.py PROJECT --entry FILE.py:ATTR [--host HOST:PORT ...]
                   [--file PATH[:ro] ...] [--app-dir DIR] [--no-runtime] [--no-traces]

The plan goes to standard output; exit 0 with a plan, 1 without.
"""

import argparse
import os
import sys

import importlib.util as _ilu
_vp_spec = _ilu.spec_from_file_location("varek_plan", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                    "varek_plan.py"))
vp = _ilu.module_from_spec(_vp_spec)
_vp_spec.loader.exec_module(vp)   # by its path (see varek_plan.py)

ADAPTER = "openai-agents"
HOSTED = {"WebSearchTool", "FileSearchTool", "CodeInterpreterTool", "ImageGenerationTool", "HostedMCPTool",
          "ToolSearchTool"}
LOCAL_SHELL = {"LocalShellTool", "ShellTool", "ComputerTool", "ApplyPatchTool"}


def warn(msg):
    vp.warn(ADAPTER, msg)


def agents_of(root_agent):
    """the agent and every agent its handoffs reach, in order"""
    def kind(obj, names):
        return "agents" if "Agent" in names and hasattr(obj, "handoffs") and hasattr(obj, "mcp_servers") else None
    found = vp.walk_objects([root_agent], kind, ("agents",), warn)["agents"]
    out, ids = [], set()
    for x in [root_agent] + found:
        if id(x) not in ids:
            ids.add(id(x))
            out.append(x)
    return out


def model_host(model):
    """(host:port, why) of an agent's model, or (None, why)"""
    if model is None or isinstance(model, str):
        name = model or "the SDK's default model"
        if isinstance(model, str) and model.startswith("litellm/"):
            provider = model.split("/")[1]
            h = vp.MODEL_HOSTS.get(provider)
            return h, f"LiteLLM's {provider} ({model})"
        return vp.MODEL_HOSTS["openai"], f"OpenAI's API ({name})"
    cls = type(model).__name__
    if cls == "LitellmModel":
        m = getattr(model, "model", "") or ""
        base = getattr(model, "base_url", None)
        if base:
            return vp.hostport_of_url(base), f"{cls} ({base})"
        provider = m.split("/")[0] if "/" in m else "openai"
        return vp.MODEL_HOSTS.get(provider), f"{cls} ({m})"
    for attr in ("_client", "client", "openai_client"):
        c = getattr(model, attr, None)
        bu = getattr(c, "base_url", None)
        if bu is not None and "://" in str(bu):
            return vp.hostport_of_url(str(bu)), f"{cls} (its client's base URL {bu})"
    return None, cls


def server_steps(P, srv, notes):
    cls, name = type(srv).__name__, getattr(srv, "name", None) or getattr(srv, "_name", "server")
    params = getattr(srv, "params", None)
    P.comment()
    if cls in ("MCPServerStreamableHttp", "MCPServerSse"):
        url = params.get("url") if isinstance(params, dict) else getattr(params, "url", None)
        P.comment(f"MCP server {name} ({cls}): {url}")
        flt = getattr(srv, "tool_filter", None)
        allowed = flt.get("allowed_tool_names") if isinstance(flt, dict) else None
        if allowed:
            blocked = set(flt.get("blocked_tool_names") or ())
            vp.mcp_server_steps(P, url, name, [t for t in allowed if t not in blocked])
        else:
            why = ("its tool filter is a callable" if callable(flt) else
                   "its filter blocks names only" if isinstance(flt, dict) else "it has no tool filter")
            vp.mcp_server_steps(P, url, name, None, f"{why}, so it may call every tool the server lists")
    elif cls == "MCPServerStdio":
        cmd = getattr(params, "command", None) or (params.get("command") if isinstance(params, dict) else None)
        P.comment(f"MCP server {name} ({cls})")
        if cmd:
            vp.stdio_server_step(P, name, cmd)
        else:
            notes.append(f"MCP server {name}: no command")
    else:
        notes.append(f"MCP server {name} ({cls}): not a kind this adapter reads: name its steps in the plan")


def generate(a):
    root = os.path.abspath(a.project)
    vp.placeholder_keys()
    if not a.entry:
        raise vp.AdapterError("name the agent with --entry FILE.py:ATTR (the Agents SDK has no project file)")
    mod, agent = vp.import_attr(root, a.entry, "agent")
    if callable(agent) and not hasattr(agent, "handoffs"):
        try:
            agent = agent()
        except Exception as e:
            raise vp.AdapterError(f"the agent factory failed: {type(e).__name__}: {e}")
    if not (hasattr(agent, "handoffs") and hasattr(agent, "mcp_servers")):
        raise vp.AdapterError(f"{a.entry} is not an Agents SDK Agent (a {type(agent).__name__})")
    agents = agents_of(agent)
    P = vp.Plan()
    vp.header(P, ADAPTER, a.entry, f"agent {agent.name}: {len(agents)} agent(s) with its handoffs")
    extra = []
    for f in a.file:
        path, _, ro = f.partition(":")
        if not path.startswith("/"):
            raise vp.AdapterError(f"--file {f!r}: an absolute path")
        extra.append((path, ro == "ro"))
    if not a.no_runtime:
        vp.runtime_steps(P, a.app_dir or root, extra=extra, python_env=True)
    else:
        for path, ro in extra:
            P.step("file_open", path, "file", os.path.basename(path.rstrip("/")), **({"open": "read"} if ro else {}))
    hosts, notes = [], []
    tracing = not os.environ.get("VAREK_PLAN_NO_TRACES") and not a.no_traces
    for ag in agents:
        h, why = model_host(getattr(ag, "model", None))
        if h:
            hosts.append(("model", h, f"agent {ag.name}'s model: {why}"))
        else:
            notes.append(f"agent {ag.name}'s model {why}: its host is not known: name it with --host")
        for t in getattr(ag, "tools", None) or []:
            cls, name = type(t).__name__, getattr(t, "name", type(t).__name__)
            if cls in HOSTED:
                where = f" ({getattr(t, 'tool_config', {}).get('server_url')})" if cls == "HostedMCPTool" else ""
                notes.append(f"agent {ag.name}'s tool {name} ({cls}{where}) runs at OpenAI, in the model's request")
            elif cls in LOCAL_SHELL:
                notes.append(f"agent {ag.name}'s tool {name} ({cls}) runs commands or changes files in the agent's "
                             f"process: each is decided by the policy, and is not in the plan unless named")
            else:
                notes.append(f"agent {ag.name}'s tool {name} runs in the agent's process: what it opens and dials "
                             f"is decided by the policy, and is not in the plan (--host, --file name it)")
    if tracing:
        hosts.append(("traces", vp.MODEL_HOSTS["openai"], "the SDK's traces (off with --no-traces where the agent "
                                                          "turns them off)"))
    for h in a.host:
        hosts.append(("host", h, "--host"))
    vp.host_steps(P, hosts)
    seen = set()
    for ag in agents:
        for srv in getattr(ag, "mcp_servers", None) or []:
            if id(srv) in seen:
                continue
            seen.add(id(srv))
            server_steps(P, srv, notes)
    if notes:
        P.comment()
        for n in dict.fromkeys(notes):
            P.comment(n)
    return P.text()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="openai_agents.py", description="VAREK's plan adapter for the OpenAI Agents SDK")
    ap.add_argument("project", help="the agent's project directory (put on the import path)")
    ap.add_argument("--entry", help="FILE.py:ATTR, the Agent (or a function returning it), relative to PROJECT")
    ap.add_argument("--host", action="append", default=[], metavar="HOST:PORT",
                    help="a host the agent's own tools dial, as a step")
    ap.add_argument("--file", action="append", default=[], metavar="PATH[:ro]",
                    help="a file or directory (ending in /) the agent's own tools open, as a step (:ro read only)")
    ap.add_argument("--no-traces", action="store_true", help="the agent turns the SDK's traces off: no step for them")
    ap.add_argument("--app-dir", help="the agent's code directory where it runs (default: the project's)")
    ap.add_argument("--no-runtime", action="store_true", help="leave out the language runtime's own reads")
    a = ap.parse_args(argv)
    out = vp.claim_stdout()
    try:
        text = generate(a)
    except vp.AdapterError as e:
        warn(str(e))
        sys.stderr.flush()
        os._exit(1)
    except Exception as e:                       # the agent's code may raise anything
        warn(f"the adapter failed: {type(e).__name__}: {e}")
        sys.stderr.flush()
        os._exit(1)
    out.write(text)
    out.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    sys.exit(main())
