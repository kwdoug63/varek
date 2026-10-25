#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
claude_agent.py — VAREK's adapter for the Claude Agent SDK (v1.35 step 6,
docs/security/v1.35-frameworks.md, D5).

Writes an agent's plan (plan 1.35) from its project's Claude settings, read
as data (the files the SDK loads with setting_sources=["project"]; the
options an agent passes in code are not data, and are named with --allow
instead):

  .claude/settings.json, .claude/settings.local.json  permission rules, env
  .mcp.json                                           MCP servers
  .claude/agents/*.md                                 sub-agents

The steps:
  - each permission an allow rule grants: Read(PATH) a file or directory
    read, Edit(PATH) and Write(PATH) written, WebFetch(domain:HOST) the host,
    Bash(PROGRAM ...) the program launched (its path as the launch would be
    decided), mcp__SERVER__TOOL the server's tool;
  - each MCP server: over HTTP, its MCP calls and tools/call of each tool an
    allow rule names (mcp__SERVER alone, or none named: one step naming no
    tool, said so); over stdio, a sub-agent step for its program;
  - the model's host: Anthropic's API, or ANTHROPIC_BASE_URL, Bedrock
    (CLAUDE_CODE_USE_BEDROCK) or Vertex AI (CLAUDE_CODE_USE_VERTEX) as the
    settings' env says; and the CLI's own traffic, unless the env turns it off;
  - the Claude Code CLI the SDK launches (--cli, or `claude` on the PATH),
    and its state under the user's home (~/.claude/, ~/.claude.json).
WebSearch runs at Anthropic, inside the model's request: a comment. A rule
the plan cannot name (Bash alone, a path under ~ with no --home) is said in
a comment. A sub-agent of .claude/agents runs in the agent's process: its
tools are the agent's.

  claude_agent.py PROJECT [--cli PATH] [--home DIR] [--allow RULE ...]
                  [--app-dir DIR] [--no-runtime]

The plan goes to standard output; exit 0 with a plan, 1 without.
"""

import argparse
import os
import pwd
import re
import sys

import importlib.util as _ilu
_vp_spec = _ilu.spec_from_file_location("varek_plan", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                    "varek_plan.py"))
vp = _ilu.module_from_spec(_vp_spec)
_vp_spec.loader.exec_module(vp)   # by its path (see varek_plan.py)

ADAPTER = "claude"
RULE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:\((.*)\))?$")
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def warn(msg):
    vp.warn(ADAPTER, msg)


def frontmatter(path):
    """a sub-agent file's front matter (key: value lines between --- and ---)"""
    text = vp.read_bytes(path, "sub-agent").decode("utf-8", "replace").splitlines()
    out = {}
    if not text or text[0].strip() != "---":
        return out
    for line in text[1:]:
        if line.strip() == "---":
            break
        k, _, v = line.partition(":")
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def path_prefix(spec, root, home):
    """a permission rule's path pattern (gitignore-like) as a step's target:
    the directory before its first wildcard (ending in /), or the file"""
    if spec.startswith("//"):
        p = spec[1:]
    elif spec.startswith("~/"):
        if not home:
            return None
        p = os.path.join(home, spec[2:])
    elif spec.startswith("/"):
        p = os.path.join(root, spec[1:])              # settings-relative: the project's, where it runs
    else:
        p = os.path.join(root, spec[2:] if spec.startswith("./") else spec)
    cut = re.search(r"[*?\[{]", p)
    if cut:
        p = p[:cut.start()]
        p = p if p.endswith("/") else os.path.dirname(p) + "/"
    return os.path.normpath(p) + ("/" if p.endswith("/") and p != "/" else "") if p else None


def generate(a):
    root = os.path.abspath(a.project)
    if not os.path.isdir(root):
        raise vp.AdapterError(f"no project directory at {a.project}")
    if a.app_dir and not a.app_dir.startswith("/"):
        raise vp.AdapterError(f"--app-dir {a.app_dir!r}: an absolute path")
    base = os.path.normpath(a.app_dir) if a.app_dir else root    # a rule's relative path is the project's, there
    home = a.home
    if not home and os.getuid() == 0:            # step 9 (review): root's home is not the agent's
        home = None
    elif not home:
        try:
            home = pwd.getpwuid(os.getuid()).pw_dir
        except KeyError:
            home = None
    if home in ("/nonexistent", "/"):
        home = None
    settings, allow, env, sources = {}, list(a.allow), {}, []
    for name in ("settings.json", "settings.local.json"):
        d, _ = vp.read_json(os.path.join(root, ".claude", name), f".claude/{name}", required=False)
        if isinstance(d, dict):
            sources.append(f".claude/{name}")
            # step 9 (review): a value of another type is read as none, not a traceback
            perms = d.get("permissions") if isinstance(d.get("permissions"), dict) else {}
            rules = perms.get("allow") if isinstance(perms.get("allow"), list) else []
            allow += [r for r in rules if isinstance(r, str)]
            denv = d.get("env") if isinstance(d.get("env"), dict) else {}
            env.update({str(k): str(v) for k, v in denv.items()})
            settings = d if name == "settings.json" else settings
    mcp, _ = vp.read_json(os.path.join(root, ".mcp.json"), ".mcp.json", required=False)
    servers = mcp.get("mcpServers") if isinstance(mcp, dict) else None
    servers = servers if isinstance(servers, dict) else {}
    if mcp is not None:
        sources.append(".mcp.json")
    enabled = settings.get("enabledMcpjsonServers")
    if isinstance(enabled, list):
        servers = {k: v for k, v in servers.items() if k in enabled}
    subagents = []
    adir = os.path.join(root, ".claude", "agents")
    if os.path.isdir(adir):
        for f in sorted(os.listdir(adir)):
            if f.endswith(".md"):
                subagents.append(frontmatter(os.path.join(adir, f)) | {"file": f})
    if not sources and not allow:
        raise vp.AdapterError("no .claude/settings.json, .mcp.json or --allow: nothing says what the agent is given")
    P = vp.Plan()
    vp.header(P, ADAPTER, ", ".join(sources) or "--allow", f"{len(allow)} allow rule(s), {len(servers)} MCP "
              f"server(s), {len(subagents)} sub-agent(s)")
    files, hosts, launches, notes, mcp_tools = [], [], [], [], {}
    for rule in allow:
        m = RULE.match(rule.strip())
        if not m:
            notes.append(f"allow rule {rule!r}: not a rule this adapter reads")
            continue
        tool, spec = m.group(1), m.group(2)
        if tool.startswith("mcp__"):
            parts = tool.split("__", 2)
            # step 9 (review): mcp__SERVER is every tool of SERVER; an empty server or tool name is not
            if not parts[1] or (len(parts) > 2 and not parts[2]):
                notes.append(f"allow rule {rule!r}: an empty server or tool name: left out")
                continue
            mcp_tools.setdefault(parts[1], set()).add(parts[2] if len(parts) > 2 else "*")
        elif tool in ("Read", "Glob", "Grep", "LS", "NotebookRead") and spec:
            p = path_prefix(spec, base, home)
            files.append((p, True)) if p else notes.append(f"allow rule {rule}: a path under ~ (give --home)")
        elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit") and spec:
            p = path_prefix(spec, base, home)
            files.append((p, False)) if p else notes.append(f"allow rule {rule}: a path under ~ (give --home)")
        elif tool == "WebFetch" and spec and spec.startswith("domain:"):
            hosts.append(("web", spec[7:] + ":443", f"WebFetch ({rule})"))
        elif tool == "Bash" and spec:
            prog = spec.split()[0].split(":")[0]
            path = vp.find_program(prog, SYSTEM_PATH)
            if path:
                launches.append((os.path.realpath(path), rule))
            else:
                notes.append(f"allow rule {rule}: {prog} is not on the system's PATH here")
        elif tool == "WebSearch":
            notes.append("WebSearch runs at Anthropic, inside the model's request")
        elif tool in ("Bash", "Read", "Edit", "Write", "WebFetch"):
            notes.append(f"allow rule {rule}: every {tool} call, which no step can name: the policy decides each")
        else:
            notes.append(f"allow rule {rule}: a tool in the agent's process (decided by the policy as its calls)")
    cfg = [(os.path.join(home, ".claude") + "/", False), (os.path.join(home, ".claude.json"), False)] if home \
        else []
    if not a.no_runtime:
        vp.runtime_steps(P, base, extra=files + cfg)
    else:
        for p, ro in files + cfg:
            P.step("file_open", p, "file", os.path.basename(p.rstrip("/")), **({"open": "read"} if ro else {}))
    if not home:
        notes.append("the CLI keeps its state in the user's home (~/.claude/): give --home to name it")
    # the model and the CLI's own traffic
    if env.get("CLAUDE_CODE_USE_BEDROCK") in ("1", "true"):
        h = vp.bedrock_host(env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or "us-east-1")
        hosts.append(("model", h, "Bedrock (CLAUDE_CODE_USE_BEDROCK)"))
    elif env.get("CLAUDE_CODE_USE_VERTEX") in ("1", "true"):
        r = env.get("CLOUD_ML_REGION", "us-east5")
        hosts.append(("model", f"{r}-aiplatform.googleapis.com:443", "Vertex AI (CLAUDE_CODE_USE_VERTEX)"))
    elif env.get("ANTHROPIC_BASE_URL"):
        h = vp.hostport_of_url(env["ANTHROPIC_BASE_URL"])
        if not h:
            raise vp.AdapterError(f"ANTHROPIC_BASE_URL {str(env['ANTHROPIC_BASE_URL'])[:200]!r} is not a URL with a host")
        hosts.append(("model", h, "ANTHROPIC_BASE_URL"))
    else:
        hosts.append(("model", vp.MODEL_HOSTS["anthropic"], "Anthropic's API"))
    quiet = env.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC") in ("1", "true") or \
        (env.get("DISABLE_TELEMETRY") in ("1", "true") and env.get("DISABLE_ERROR_REPORTING") in ("1", "true"))
    if not quiet:
        hosts.append(("cli_telemetry", "statsig.anthropic.com:443", "the CLI's telemetry (off with the settings' "
                                                                     "env CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1)"))
        notes.append("the CLI also reports errors to Sentry unless DISABLE_ERROR_REPORTING=1: refused unless named")
    vp.host_steps(P, hosts)
    cli = a.cli or vp.find_program("claude", SYSTEM_PATH)
    if cli or launches:
        P.comment()
        P.comment("the programs the agent launches")
    if cli:
        P.comment("  the Claude Code CLI the SDK runs")
        P.step("process_exec", os.path.realpath(cli), "claude_cli")
    else:
        notes.append("the Claude Code CLI the SDK runs: not found (--cli PATH names it; the SDK's bundled one is "
                     "in its package)")
    for path, rule in launches:
        P.comment(f"  {path}: {rule}")
        P.step("process_exec", path, "bash", os.path.basename(path))
    for name, srv in servers.items():
        if not isinstance(srv, dict):
            continue
        P.comment()
        P.comment(f"MCP server {name} (.mcp.json)")
        tools = mcp_tools.get(name, set())
        if srv.get("url") or srv.get("type") in ("http", "sse"):
            if not tools or "*" in tools:
                why = "an allow rule grants it whole (mcp__" + name + ")" if "*" in tools else \
                      "no allow rule names its tools (each is asked for, or the SDK's options allow it)"
                vp.mcp_server_steps(P, srv.get("url", ""), name, None, why)
            else:
                vp.mcp_server_steps(P, srv.get("url", ""), name, sorted(tools))
        elif srv.get("command"):
            vp.stdio_server_step(P, name, srv["command"], SYSTEM_PATH)
    for name in sorted(set(mcp_tools) - set(servers)):
        notes.append(f"allow rules name MCP server {name}, which .mcp.json does not: an SDK server in the agent's "
                     f"process (create_sdk_mcp_server) or one its options give; its tools run in the agent's process "
                     f"or reach what the plan does not name")
    for sa in subagents:
        notes.append(f"sub-agent {sa.get('name', sa['file'])} (.claude/agents/{sa['file']}) runs in the agent's "
                     f"process, with tools {sa.get('tools', 'its own')}: the plan's steps are its too")
    if notes:
        P.comment()
        for n in dict.fromkeys(notes):
            P.comment(n)
    return P.text()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="claude_agent.py", description="VAREK's plan adapter for the Claude Agent SDK")
    ap.add_argument("project", help="the agent's project (the directory holding .claude/ and .mcp.json)")
    ap.add_argument("--cli", help="the Claude Code CLI the SDK runs (default: claude on the PATH)")
    ap.add_argument("--home", help="the agent user's home, where the CLI keeps its state (default: this user's)")
    ap.add_argument("--allow", action="append", default=[], metavar="RULE",
                    help="an allow rule the agent's options give in code (allowed_tools), as the settings' are read")
    ap.add_argument("--app-dir", help="the agent's code directory where it runs (default: the project's)")
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
