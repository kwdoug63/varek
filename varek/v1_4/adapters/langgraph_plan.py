#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
langgraph_plan.py — VAREK's adapter for LangGraph (v1.35 step 6,
docs/security/v1.35-frameworks.md, D5).

A LangGraph agent exists only as Python objects (langgraph.json points at
code; a graph may be built per run by a factory), so this adapter imports
the graph, in the agent's own Python (`varek plan generate --python`), under
the Warden: the project and its packages read-only, no network. Before it
imports anything it sets each model provider's key to a placeholder: the
agent's clients are made, and never with a real key.

From the compiled graph (its nodes, and the module-level objects their
code uses), and the MCP clients its module defines, it writes:
  - each chat model's provider host (its base URL where set: ChatOpenAI,
    AzureChatOpenAI, ChatAnthropic, ChatBedrock(Converse), ChatGoogle*,
    ChatVertexAI, ChatOllama, ...);
  - each MCP server a MultiServerMCPClient connects to: over HTTP, its MCP
    calls (tools/call naming no tool: the client lists them when it
    connects); over stdio, a sub-agent step for its program;
  - the hosts and directories of the tools it knows (Tavily, Wikipedia,
    DuckDuckGo, the file management tools' root directory);
  - each subgraph's, the same way.
A tool that is a Python function runs in the agent's process: what it opens
and dials is decided by the policy as any call, and is not in the plan
unless named (--host, --file). The plan names what may happen, not how
often: a graph that loops is written once.

  langgraph_plan.py PROJECT [--graph NAME | --entry FILE.py:ATTR] [--region REGION]
               [--host HOST:PORT ...] [--file PATH[:ro] ...] [--app-dir DIR] [--no-runtime]

The plan goes to standard output; exit 0 with a plan, 1 without.
"""

import argparse
import asyncio
import inspect
import os
import sys

import importlib.util as _ilu
_vp_spec = _ilu.spec_from_file_location("varek_plan", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                    "varek_plan.py"))
vp = _ilu.module_from_spec(_vp_spec)
_vp_spec.loader.exec_module(vp)   # by its path: the adapter's directory is not put on sys.path, where an
                                  # adapter's name could hide the framework's package

ADAPTER = "langgraph"
# tools whose hosts are known (by class name)
TOOL_HOSTS = {
    "TavilySearch": ("api.tavily.com:443",), "TavilySearchResults": ("api.tavily.com:443",),
    "TavilyExtract": ("api.tavily.com:443",),
    "WikipediaQueryRun": ("en.wikipedia.org:443",),
    "DuckDuckGoSearchRun": ("duckduckgo.com:443", "html.duckduckgo.com:443"),
    "DuckDuckGoSearchResults": ("duckduckgo.com:443", "html.duckduckgo.com:443"),
}
FILE_TOOLS_WRITE = {"WriteFileTool", "CopyFileTool", "DeleteFileTool", "MoveFileTool"}
FILE_TOOLS_READ = {"ReadFileTool", "ListDirectoryTool", "FileSearchTool"}


def warn(msg):
    vp.warn(ADAPTER, msg)


mro_names = vp.mro_names


def walk(roots):
    """every model, tool, MCP client and graph the roots reach"""
    def kind(obj, names):
        if "BaseChatModel" in names or ("BaseLanguageModel" in names and
                                        type(obj).__name__.startswith(("Chat", "Azure", "Ollama"))):
            return "models"
        if "BaseTool" in names:
            return "tools"
        if "MultiServerMCPClient" in names:
            return "mcp"
        if "Pregel" in names:
            return "graphs"
        return None
    return vp.walk_objects(roots, kind, ("models", "tools", "mcp", "graphs"), lambda m: warn(m))


def url_hostport(u):
    try:
        return vp.hostport_of_url(str(u))
    except ValueError:
        return None


def model_host(m, region):
    """(host:port, why) of a chat model"""
    cls = type(m).__name__
    for attr in ("openai_api_base", "base_url", "anthropic_api_url", "azure_endpoint", "endpoint_url", "api_base"):
        v = getattr(m, attr, None)
        if v and isinstance(v, (str,)) and "://" in v:
            return url_hostport(v), f"{cls} ({attr} {v})"
    for client_attr in ("root_client", "client"):
        c = getattr(m, client_attr, None)
        bu = getattr(c, "base_url", None)
        if bu is not None and "://" in str(bu):
            return url_hostport(bu), f"{cls} (its client's base URL)"
    if "Bedrock" in cls:
        r = getattr(m, "region_name", None) or region
        h = vp.bedrock_host(r)
        return h, f"{cls} in {r}"
    if "Vertex" in cls:
        loc = getattr(m, "location", None) or "us-central1"
        return f"{loc}-aiplatform.googleapis.com:443", f"{cls} in {loc}"
    if "Ollama" in cls:
        return "localhost:11434", f"{cls} (its default base URL)"
    for key, host in (("OpenAI", "openai"), ("Anthropic", "anthropic"), ("Google", "google"),
                      ("Gemini", "gemini"), ("Mistral", "mistral"), ("Groq", "groq"), ("Cohere", "cohere"),
                      ("DeepSeek", "deepseek"), ("XAI", "xai"), ("Together", "together"),
                      ("Fireworks", "fireworks"), ("Perplexity", "perplexity")):
        if key.lower() in cls.lower():
            return vp.MODEL_HOSTS[host], f"{cls} (its provider's API host)"
    return None, cls


def import_entry(root, entry):
    mod, obj = vp.import_attr(root, entry, "graph")
    attr = entry.rpartition(":")[2]
    if "Pregel" not in mro_names(obj) and callable(obj):
        try:
            params = inspect.signature(obj).parameters
            obj = obj({}) if params else obj()
            if inspect.iscoroutine(obj):
                obj = asyncio.run(obj)
        except Exception as e:
            raise vp.AdapterError(f"the graph factory {attr} failed: {type(e).__name__}: {e}")
    if "Pregel" not in mro_names(obj):
        raise vp.AdapterError(f"{entry} is not a compiled graph (a {type(obj).__name__})")
    return mod, obj


def generate(a):
    root = os.path.abspath(a.project)
    vp.placeholder_keys(a.region)
    if a.entry:
        entry, gname = a.entry, a.entry
    else:
        cfg, _ = vp.read_json(os.path.join(root, "langgraph.json"), "langgraph.json")
        graphs = cfg.get("graphs") if isinstance(cfg, dict) else None
        if not isinstance(graphs, dict) or not graphs:
            raise vp.AdapterError("langgraph.json names no graph (graphs)")
        if a.graph:
            if a.graph not in graphs:
                raise vp.AdapterError(f"langgraph.json has no graph {a.graph!r} (it has: {', '.join(graphs)})")
            gname = a.graph
        elif len(graphs) == 1:
            gname = next(iter(graphs))
        else:
            raise vp.AdapterError(f"langgraph.json has {len(graphs)} graphs ({', '.join(graphs)}): name one with --graph")
        entry = graphs[gname]
        if isinstance(entry, dict):
            entry = entry.get("path", "")
    mod, graph = import_entry(root, entry)
    # step 9 (review): what the graph reaches (its nodes, and the module's names their code uses), not
    # everything the module defines: a model the file builds and no node uses is not the agent's. The
    # one exception, said in the plan: the module's own MCP clients (MultiServerMCPClient), whose tools
    # the agent gets when it runs (await client.get_tools()), so no graph built before then holds them
    found = walk([graph])
    module_mcp = [v for v in vars(mod).values()
                  if "MultiServerMCPClient" in mro_names(v) and all(v is not c for c in found["mcp"])]
    found["mcp"] += module_mcp
    P = vp.Plan()
    vp.header(P, ADAPTER, f"{entry} (graph {gname})", f"graph {gname}: {len(found['graphs'])} graph(s), "
              f"{len(found['models'])} model(s), {len(found['tools'])} tool(s), {len(found['mcp'])} MCP client(s)")
    extra = []
    for f in a.file:
        path, _, ro = f.partition(":")
        if not path.startswith("/"):
            raise vp.AdapterError(f"--file {f!r}: an absolute path")
        extra.append((path, ro == "ro"))
    tool_notes, hosts = [], []
    for t in found["tools"]:
        cls, name = type(t).__name__, getattr(t, "name", "?")
        if cls in TOOL_HOSTS:
            for h in TOOL_HOSTS[cls]:
                hosts.append(("tool_" + name, h, f"tool {name} ({cls})"))
        elif cls in FILE_TOOLS_READ | FILE_TOOLS_WRITE:
            rd = getattr(t, "root_dir", None)
            if rd:
                # step 9 (review): a relative root_dir is the agent's working directory's, where it runs
                # (--app-dir, else the project), not this adapter's
                rd = os.path.normpath(os.path.join(a.app_dir or root, str(rd)))
                extra.append((rd.rstrip("/") + "/", cls in FILE_TOOLS_READ))
            else:
                tool_notes.append(f"tool {name} ({cls}): no root_dir, so any file; name its files with --file")
        elif "MCP" in cls or getattr(t, "metadata", None) and "mcp" in str(getattr(t, "metadata", "")).lower():
            continue
        else:
            tool_notes.append(f"tool {name} runs in the agent's process: what it opens and dials is decided by the "
                              f"policy, and is not in the plan (--host, --file name it)")
    if not a.no_runtime:
        vp.runtime_steps(P, a.app_dir or root, extra=extra, python_env=True)
    elif extra:
        for path, ro in extra:
            P.step("file_open", path, "file", os.path.basename(path.rstrip("/")), **({"open": "read"} if ro else {}))
    for m in found["models"]:
        h, why = model_host(m, a.region)
        if h:
            hosts.append(("model", h, why))
        else:
            tool_notes.append(f"model {why}: its host is not known: name it with --host")
    for h in a.host:
        hosts.append(("host", h, "--host"))
    vp.host_steps(P, hosts)
    if module_mcp:
        P.comment()
        P.comment(f"{len(module_mcp)} MCP client(s) the module defines and the graph does not hold: the agent gets")
        P.comment("their tools when it runs, so their servers are in the plan")
    for c in found["mcp"]:
        conns = getattr(c, "connections", None) or {}
        for sname, conn in conns.items() if isinstance(conns, dict) else []:
            P.comment()
            transport = (conn or {}).get("transport", "stdio" if (conn or {}).get("command") else "streamable_http")
            P.comment(f"MCP server {sname} ({transport})")
            if conn.get("url"):
                vp.mcp_server_steps(P, conn["url"], sname, None,
                                    "MultiServerMCPClient lists its tools when it connects (it has no allow-list)")
            elif conn.get("command"):
                vp.stdio_server_step(P, sname, conn["command"])
    if tool_notes:
        P.comment()
        for n in dict.fromkeys(tool_notes):
            P.comment(n)
    if P.n == 0:
        raise vp.AdapterError(f"graph {gname}: nothing to write")
    return P.text()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="langgraph_plan.py", description="VAREK's plan adapter for LangGraph")
    ap.add_argument("project", help="the LangGraph project (the directory holding langgraph.json)")
    ap.add_argument("--graph", help="the graph (langgraph.json's graphs), if it has more than one")
    ap.add_argument("--entry", help="FILE.py:ATTR, the compiled graph or its factory, instead of langgraph.json")
    ap.add_argument("--region", help="the AWS region of a Bedrock model that names none")
    ap.add_argument("--host", action="append", default=[], metavar="HOST:PORT",
                    help="a host the agent's own tools dial, as a step")
    ap.add_argument("--file", action="append", default=[], metavar="PATH[:ro]",
                    help="a file or directory (ending in /) the agent's own tools open, as a step (:ro read only)")
    ap.add_argument("--app-dir", help="the agent's code directory where it runs (default: the project's)")
    ap.add_argument("--no-runtime", action="store_true", help="leave out the language runtime's own reads")
    a = ap.parse_args(argv)
    out = vp.claim_stdout()      # what the agent's code prints goes to standard error, not into the plan
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
    os._exit(0)          # the agent's imports may leave threads behind (clients, loops): end now


if __name__ == "__main__":
    sys.exit(main())
