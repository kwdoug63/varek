#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
agentcore.py — VAREK's adapter for Amazon Bedrock AgentCore (v1.35 step 5,
docs/security/v1.35-frameworks.md, D5).

Writes the plan (plan 1.35) of one runtime of an AgentCore CLI project from
the project's own files, read as data; nothing of the agent's code is
imported or run:

  agentcore/agentcore.json            the project (AgentCore CLI 0.31)
  agentcore/aws-targets.json          its deployment targets (account, region)
  agentcore/.cli/deployed-state.json  what was deployed (each gateway's URL)
  the files a gateway target names    (a Lambda target's tool schema, an
                                       inline OpenAPI schema), and the
                                       runtime's Dockerfile (its WORKDIR)

One step for each thing the project gives the agent:
  - each gateway's MCP calls: initialize, notifications/initialized,
    tools/list, and tools/call of each tool the project lists (as AgentCore
    Gateway names them, TARGET___TOOL, and its search tool when semantic
    search is on); a target whose tools the gateway lists from the live
    server (an MCP server, a Smithy model, an API Gateway stage, a
    connector) makes the step for the gateway's tools/call name no tool,
    and the plan says so;
  - an MCP server the project hosts on AgentCore Runtime and binds to this
    runtime, and its tool;
  - the AWS hosts the runtime's features reach in the target's region:
    AgentCore's data plane (Identity's credentials, Memory, the browser and
    code interpreter, other runtimes) and, with OpenTelemetry on (the
    default), X-Ray and CloudWatch Logs;
  - its session storage and file systems (each mount, read and written);
  - its language runtime's own reads (the system read-only, its code
    directory, /tmp), which a run held to its plan needs as the agent starts.

Not in the project's files, so not written: the agent's own tools and its
model provider, which are its framework's (Strands, LangGraph, the OpenAI
Agents SDK, ...). --model-host names the model's host; the framework's own
adapter (v1.35 step 6) writes the rest.

  agentcore.py PROJECT [--runtime NAME] [--target NAME] [--region REGION]
               [--gateway-url NAME=URL ...] [--model-host HOST:PORT ...]
               [--app-dir DIR] [--no-runtime]

The plan goes to standard output; what the adapter could not read, or did
not write, to standard error. Exit 0 with a plan, 1 without one, 2 on usage.
It needs only Python's standard library, and is run by `varek plan
generate`, under the Warden, with the project read-only and no network.
"""

import argparse
import os
import re
import sys

import importlib.util as _ilu
_vp_spec = _ilu.spec_from_file_location("varek_plan", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                    "varek_plan.py"))
vp = _ilu.module_from_spec(_vp_spec)
_vp_spec.loader.exec_module(vp)   # by its path: the adapter's directory is not put on sys.path, where an
                                  # adapter's name could hide the framework's package

ADAPTER = "agentcore"
ADAPTER_VERSION = vp.VERSION
REGION = re.compile(r"[a-z]{2}(-gov)?-[a-z]+-[0-9]")
HOSTPORT = vp.HOSTPORT
SEARCH_TOOL = "x_amz_bedrock_agentcore_search"      # the gateway's own tool, with semantic search on
LIVE_KINDS = {"mcpServer": "an MCP server", "smithyModel": "a Smithy model", "apiGateway": "an API Gateway stage",
              "connector": "a connector", "passthrough": "a passthrough endpoint", "httpRuntime": "a runtime"}


AdapterError, Plan, field, read_json = vp.AdapterError, vp.Plan, vp.field, vp.read_json


def warn(msg):
    vp.warn(ADAPTER, msg)


def find_project(root):
    for d in (os.path.join(root, "agentcore"), root):
        if os.path.isfile(os.path.join(d, "agentcore.json")):
            return d
    raise AdapterError(f"no agentcore/agentcore.json under {root} (an AgentCore CLI project's)")


def one(items, name, what, flag):
    items = [i for i in items if isinstance(i, dict)]
    if name:
        found = [i for i in items if i.get("name") == name]
        if not found:
            raise AdapterError(f"no {what} named {name!r} (the project has: "
                               f"{', '.join(str(i.get('name')) for i in items) or 'none'})")
        return found[0]
    if len(items) == 1:
        return items[0]
    if not items:
        raise AdapterError(f"the project has no {what}")
    raise AdapterError(f"the project has {len(items)} {what}s ({', '.join(str(i.get('name')) for i in items)}): "
                       f"name one with {flag}")


def deployed_gateways(state, target):
    """{gateway name: url} for the deployment target, from deployed-state.json"""
    out = {}
    res = ((state or {}).get("targets") or {}).get(target, {}).get("resources") or {}
    for src in ((res.get("mcp") or {}).get("gateways") or {}, res.get("gateways") or {}):
        for name, g in src.items():
            if isinstance(g, dict) and isinstance(g.get("gatewayUrl"), str) and name not in out:
                out[name] = g["gatewayUrl"]
    return out, res


def target_tools(t, root):
    """(tool names, why the gateway lists them live or None) of a gateway target"""
    kind = t.get("targetType")
    names = [d.get("name") for d in t.get("toolDefinitions") or [] if isinstance(d, dict) and d.get("name")]
    if names:
        return names, None
    lf = t.get("lambdaFunctionArn")
    if kind == "lambdaFunctionArn" and isinstance(lf, dict) and isinstance(lf.get("toolSchemaFile"), str):
        p = lf["toolSchemaFile"]
        data, _ = read_json(p if os.path.isabs(p) else os.path.join(root, p), f"target {t.get('name')}'s tool schema")
        if not isinstance(data, list) or not all(isinstance(d, dict) and isinstance(d.get("name"), str) for d in data):
            raise AdapterError(f"target {t.get('name')}'s tool schema is not a list of tools with names")
        return [d["name"] for d in data], None
    src = t.get("schemaSource")
    if kind == "openApiSchema" and isinstance(src, dict) and isinstance(src.get("inline"), dict):
        p = src["inline"].get("path", "")
        if p.endswith(".json"):
            data, _ = read_json(p if os.path.isabs(p) else os.path.join(root, p), f"target {t.get('name')}'s OpenAPI schema")
            ops = []
            for path_item in (data.get("paths") or {}).values() if isinstance(data, dict) else []:
                for op in (path_item or {}).values() if isinstance(path_item, dict) else []:
                    if isinstance(op, dict) and isinstance(op.get("operationId"), str):
                        ops.append(op["operationId"])
            if ops:
                return ops, None
            return [], "its OpenAPI schema names no operationId"
        return [], "its OpenAPI schema is not JSON (the adapter reads JSON only)"
    if kind == "openApiSchema":
        return [], "its OpenAPI schema is in S3"
    return [], f"its tools are {LIVE_KINDS.get(kind, kind or 'unknown')}'s, listed by the live gateway"


def workdir(rt, root):
    """the agent's code directory in its container"""
    if rt.get("build") == "CodeZip":
        return "/var/task"
    ctx = rt.get("buildContextPath") or rt.get("codeLocation") or "."
    df = os.path.join(root, ctx, rt.get("dockerfile") or "Dockerfile")
    wd = None
    try:
        with open(df, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r"\s*WORKDIR\s+(\S+)\s*$", line, re.I)
                if m and m.group(1).startswith("/"):
                    wd = m.group(1)
    except OSError:
        return None
    return wd


def generate(a):
    adir = find_project(os.path.abspath(a.project))
    root = os.path.dirname(adir) if os.path.basename(adir) == "agentcore" else adir
    spec, spec_sha = read_json(os.path.join(adir, "agentcore.json"), "project file")
    if not isinstance(spec, dict) or not isinstance(spec.get("runtimes"), list):
        raise AdapterError("agentcore.json is not an AgentCore CLI project (no runtimes)")
    targets, _ = read_json(os.path.join(adir, "aws-targets.json"), "deployment targets", required=False)
    state, _ = read_json(os.path.join(adir, ".cli", "deployed-state.json"), "deployed state", required=False)
    rt = one(spec["runtimes"], a.runtime, "runtime", "--runtime")
    rname = rt.get("name")
    tgt = one(targets or [], a.target, "deployment target", "--target") if (targets or a.target) else {}
    region = a.region or tgt.get("region")
    if not region or not REGION.fullmatch(region):
        raise AdapterError(f"no region for the AWS hosts (aws-targets.json, or --region): {region!r}")
    urls, res = deployed_gateways(state, tgt.get("name", "default"))
    for kv in a.gateway_url:
        name, _, url = kv.partition("=")
        if not url:
            raise AdapterError(f"--gateway-url {kv!r} is not NAME=URL")
        urls[name] = url
    if rt.get("protocol", "HTTP") != "HTTP":
        warn(f"runtime {rname} serves {rt.get('protocol')}: its plan names what it calls, as for HTTP")

    P = Plan()
    P.comment(f"Written by `varek plan generate --from {ADAPTER}` (VAREK {ADAPTER_VERSION}, adapters/agentcore.py)")
    P.comment(f"from {os.path.relpath(os.path.join(adir, 'agentcore.json'), root)} (SHA-256 {spec_sha})")
    P.comment(f"project {spec.get('name')}, runtime {rname}, target {tgt.get('name', '-')} "
              f"(account {tgt.get('account', '-')}, region {region})")
    P.comment("Each step names something the project gives the agent. Held to this plan (varek run")
    P.comment("--hold-to-plan, or a policy's `require plan`), the run is refused a call the policy")
    P.comment("allows that no step covers. Not here, as agentcore.json does not say them: the agent's")
    P.comment("own tools and its model provider, which are its framework's (--model-host names the")
    P.comment("model's host).")
    P.start()

    if not a.no_runtime:
        app = a.app_dir or workdir(rt, root)
        vp.runtime_steps(P, app)                 # step 10: the shared runtime reads, the machine's too
        if not app:
            warn(f"runtime {rname}: its code directory in the container is not known (no WORKDIR): give --app-dir")

    said = False
    for i, fs in enumerate(rt.get("filesystemConfigurations") or []):
        for kind in ("sessionStorage", "efsAccessPoint", "s3FilesAccessPoint", "capacityProviderVolume"):
            mp = (fs.get(kind) or {}).get("mountPath") if isinstance(fs, dict) else None
            if mp:
                if not said:
                    P.comment()
                    P.comment("the runtime's file systems, read and written")
                    said = True
                P.step("file_open", mp.rstrip("/") + "/", "fs", kind, str(i + 1))

    hosts = []                                      # (label, host:port, why)
    conns = [c.get("to", {}) for c in rt.get("connections") or [] if isinstance(c, dict)]
    data_plane = []
    if spec.get("credentials"):
        data_plane.append("Identity's credentials")
    if spec.get("memories") or any(c.get("type") == "memory" for c in conns):
        data_plane.append("Memory")
    for t, what in (("browser", "the browser"), ("codeInterpreter", "the code interpreter"),
                    ("runtime", "another runtime")):
        if any(c.get("type") == t for c in conns):
            data_plane.append(what)
    if data_plane:
        hosts.append(("agentcore_data", f"bedrock-agentcore.{region}.amazonaws.com:443", ", ".join(data_plane)))
    if (rt.get("instrumentation") or {}).get("enableOtel", True) is not False:
        hosts.append(("otel_traces", f"xray.{region}.amazonaws.com:443", "OpenTelemetry's traces (X-Ray)"))
        hosts.append(("otel_logs", f"logs.{region}.amazonaws.com:443", "OpenTelemetry's logs (CloudWatch)"))
    for h in a.model_host:
        if not HOSTPORT.fullmatch(h):
            raise AdapterError(f"--model-host {h!r} is not HOST:PORT")
        hosts.append(("model", h, "the model provider (--model-host)"))
    if hosts:
        P.comment()
        P.comment("the hosts the runtime's features reach")
        for lab, hp, why in hosts:
            P.comment(f"  {hp}: {why}")
            P.step("net_connect", hp, lab)

    for gw in spec.get("agentCoreGateways") or []:
        if not isinstance(gw, dict) or gw.get("protocolType", "MCP") != "MCP":
            continue
        name = gw.get("name")
        url = urls.get(name)
        if not url:
            raise AdapterError(f"gateway {name} has no URL: not deployed to target {tgt.get('name', 'default')} "
                               f"(deployed-state.json), and no --gateway-url {name}=URL")
        P.comment()
        P.comment(f"gateway {name}: {url} (authorizer {gw.get('authorizerType', 'NONE')})")
        for m in ("initialize", "notifications/initialized", "tools/list"):
            P.step("mcp_call", url, "gw", name, m.split("/")[-1], method=m)
        tools, live = [], []
        for t in gw.get("targets") or []:
            if not isinstance(t, dict):
                continue
            names, why = target_tools(t, root)
            if why:
                live.append((t.get("name"), why))
            tools += [f"{t.get('name')}___{n}" for n in names]
        if gw.get("enableSemanticSearch", True):
            tools.append(SEARCH_TOOL)
        if live:
            for tn, why in live:
                P.comment(f"  target {tn}: {why}, so the step for its tools names none: it covers every")
                P.comment("  tool of this gateway")
            P.step("mcp_call", url, "gw", name, "tools", method="tools/call")
        else:
            for tool in tools:
                P.step("mcp_call", url, "gw", name, tool, method="tools/call", name=tool)

    mcp_rt = (res.get("mcp") or {}).get("runtimes") or {}
    for tool in spec.get("mcpRuntimeTools") or []:
        if not isinstance(tool, dict) or not any(b.get("runtimeName") == rname for b in tool.get("bindings") or []):
            continue
        ep = (mcp_rt.get(tool.get("name")) or {}).get("runtimeEndpoint", "")
        if not ep.startswith("https://"):
            raise AdapterError(f"MCP runtime tool {tool.get('name')} is bound to runtime {rname} and not deployed "
                               f"(no runtimeEndpoint URL in deployed-state.json)")
        tn = (tool.get("toolDefinition") or {}).get("name")
        P.comment()
        P.comment(f"MCP server {tool.get('name')} on AgentCore Runtime, bound to this runtime")
        for m in ("initialize", "notifications/initialized", "tools/list"):
            P.step("mcp_call", ep, "mcprt", tool.get("name"), m.split("/")[-1], method=m)
        P.step("mcp_call", ep, "mcprt", tool.get("name"), tn, method="tools/call", **({"name": tn} if tn else {}))

    creds = [c for c in spec.get("credentials") or [] if isinstance(c, dict)]
    if creds:
        P.comment()
        P.comment("credentials (AgentCore Identity): AWS releases them to the agent from AgentCore's data")
        P.comment("plane (its host above), not the Warden, so they are not credential steps:")
        for c in creds:
            P.comment(f"  {c.get('name')} ({c.get('authorizerType')})")
    if P.n == 0:
        raise AdapterError(f"runtime {rname}: nothing to write (--no-runtime, and no host, file system or gateway)")
    return P.text()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agentcore.py", description="VAREK's plan adapter for Amazon Bedrock AgentCore")
    ap.add_argument("project", help="the AgentCore CLI project (the directory holding agentcore/)")
    ap.add_argument("--runtime", help="the runtime (agent) to write the plan of, if the project has more than one")
    ap.add_argument("--target", help="the deployment target (aws-targets.json), if more than one")
    ap.add_argument("--region", help="the AWS region, if aws-targets.json does not give it")
    ap.add_argument("--gateway-url", action="append", default=[], metavar="NAME=URL",
                    help="a gateway's URL, where deployed-state.json does not hold it")
    ap.add_argument("--model-host", action="append", default=[], metavar="HOST:PORT",
                    help="the model provider's host (the agent's framework's, not in agentcore.json)")
    ap.add_argument("--app-dir", help="the agent's code directory in its container (default: the Dockerfile's "
                                      "WORKDIR, or /var/task for CodeZip)")
    ap.add_argument("--no-runtime", action="store_true", help="leave out the language runtime's own reads")
    a = ap.parse_args(argv)
    try:
        sys.stdout.write(generate(a))
    except AdapterError as e:
        warn(str(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
