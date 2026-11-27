# SPDX-License-Identifier: MIT
"""varek_mcp_tools.py: `varek mcp tools`, v1.43 step 3
(docs/security/v1.43-palantir-ontology-mcp.md, D2).

Writes the `mcp` rules for one MCP server from the server's own tool list,
one exact rule per tool, no globs over tool names:

  - a tool whose annotations say readOnlyHint true, and not destructiveHint
    true, is allowed;
  - every other tool, unannotated included, is held for an approver
    (v1.42's `step_up ... mode=hold`);
  - a tool whose name a rule cannot name exactly (a space, '#', a glob
    character, anything outside printable ASCII, or too long) gets no rule,
    so it is refused, and the file says why.

An annotation is the server's claim about itself: it can move a tool to a
person, never past one. A person reviews the file before it is used.

The file's header records the tool list's SHA-256 (each tool's name,
annotations, argument names and required arguments, canonical JSON), and
`--check FILE` fails when the server's list differs, naming the tools
added, removed and changed.

The list comes from the server (initialize, notifications/initialized and
tools/list, every page; no tool is called) or from a file: a tools/list
result, a list of tools, or omcp_measure.py's output. The bearer token, if
any, is read from a file or the environment and is never printed or
written. In this step the list is fetched directly; fetching it through a
run with only those methods allowed (D2) comes with gateway mode (step 4).
"""

import datetime as _dt
import hashlib
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request

PROTOCOLS = ("2026-07-28", "2025-06-18")
MAX_NAME = 4095
BAD_NAME = re.compile(r"[\s#*?\[\]\\]")
HEADER_HASH = re.compile(r"^# tools-sha256 ([0-9a-f]{64})$", re.M)
HEADER_URL = re.compile(r"^# varek mcp tools: (\S+)$", re.M)
RULE_TOOL = re.compile(r"^(?:allow|step_up) mcp (\S+) tools/call (\S+)", re.M)


class McpToolsError(Exception):
    pass


# ------------------------------------------------------------------ fetch --

def _post(url, msg, token, proto, session, timeout):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": proto, "Mcp-Method": msg["method"]}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(msg).encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
    except urllib.error.URLError as e:
        raise McpToolsError(f"cannot reach {url}: {e.reason}") from None


def _reply(hd, body, rid):
    if "text/event-stream" in hd.get("content-type", ""):
        msgs, data = [], []
        for line in body.decode("utf-8", "replace").splitlines() + [""]:
            if line.startswith("data:"):
                data.append(line[5:].lstrip())
            elif not line and data:
                try:
                    msgs.append(json.loads("\n".join(data)))
                except json.JSONDecodeError:
                    pass
                data = []
    else:
        try:
            msgs = [json.loads(body)]
        except json.JSONDecodeError:
            msgs = []
    return next((m for m in msgs if isinstance(m, dict) and m.get("id") == rid), None)


def fetch_tools(url, token=None, timeout=30):
    """The server's tools, every page. Raises McpToolsError."""
    init = session = proto = None
    for pv in PROTOCOLS:
        st, hd, body = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": pv, "capabilities": {},
            "clientInfo": {"name": "varek-mcp-tools", "version": "1.43.0"}}}, token, pv, None, timeout)
        if st == 401:
            raise McpToolsError(f"{url} refused the token (HTTP 401); give one with --token-file")
        r = _reply(hd, body, 1) if st == 200 else None
        if r and "result" in r:
            init, session, proto = r["result"], hd.get("mcp-session-id"), r["result"].get("protocolVersion", pv)
            break
    if init is None:
        raise McpToolsError(f"{url} did not answer initialize (tried {', '.join(PROTOCOLS)})")
    _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token, proto, session, timeout)
    tools, cursor, rid = [], None, 2
    while True:
        st, hd, body = _post(url, {"jsonrpc": "2.0", "id": rid, "method": "tools/list",
                                   "params": {"cursor": cursor} if cursor else {}},
                             token, proto, session, timeout)
        r = _reply(hd, body, rid) if st == 200 else None
        if not r or "result" not in r:
            raise McpToolsError(f"{url}: tools/list failed (HTTP {st})")
        tools.extend(r["result"].get("tools") or [])
        cursor, rid = r["result"].get("nextCursor"), rid + 1
        if not cursor:
            break
        if rid > 1000:
            raise McpToolsError(f"{url}: tools/list did not end after 1,000 pages")
    return {"server": init.get("serverInfo"), "protocol": proto, "tools": tools}


def load_tools(path):
    """Tools from a file: a tools/list result, a list, or omcp_measure.py's output."""
    with open(path, encoding="utf-8") as f:
        try:
            d = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise McpToolsError(f"{path}: not JSON (a tools/list result, a list of tools, or "
                                "omcp_measure.py's output)") from None
    if isinstance(d, list):
        return d
    if not isinstance(d, dict):
        raise McpToolsError(f"{path}: no tool list in it")
    if isinstance(d.get("tools"), list):
        return d["tools"]
    if isinstance(d.get("result"), dict) and isinstance(d["result"].get("tools"), list):
        return d["result"]["tools"]
    if isinstance(d.get("mcp"), dict) and isinstance(d["mcp"].get("tools"), list):
        return d["mcp"]["tools"]
    raise McpToolsError(f"{path}: no tool list in it")


# ---------------------------------------------------------------- classify --

def _shape(t):
    """What the fingerprint covers, from either a full tool or omcp_measure.py's summary."""
    if "inputSchema" in t:
        schema = t.get("inputSchema") or {}
        args, req = sorted((schema.get("properties") or {}).keys()), sorted(schema.get("required") or [])
    else:
        args, req = sorted(t.get("arguments") or []), sorted(t.get("required") or [])
    return {"name": t.get("name"), "annotations": t.get("annotations") or {}, "arguments": args,
            "required": req}


def fingerprint(tools):
    shapes = sorted((_shape(t) for t in tools), key=lambda s: str(s["name"]))
    return hashlib.sha256(json.dumps(shapes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def name_problem(name):
    if not isinstance(name, str) or not name:
        return "no name"
    if len(name.encode()) > MAX_NAME:
        return "longer than 4,095 bytes"
    if any(ord(c) < 0x21 or ord(c) > 0x7e for c in name):
        return "a character outside printable ASCII, or a space"
    m = BAD_NAME.search(name)
    if m:
        return f"the character {m.group(0)!r}, which a rule cannot name exactly"
    return None


def classify(t):
    """('allow'|'step_up'|'refuse', reason)."""
    p = name_problem(t.get("name"))
    if p:
        return "refuse", p
    ann = t.get("annotations") or {}
    if ann.get("readOnlyHint") is True and ann.get("destructiveHint") is not True:
        return "allow", "the server marks it read-only"
    if ann.get("destructiveHint") is True:
        return "step_up", "the server marks it destructive"
    if ann.get("readOnlyHint") is False:
        return "step_up", "the server marks it as writing"
    return "step_up", "no read-only annotation"


# ------------------------------------------------------------------- write --

def _host_port(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise McpToolsError(f"{url}: not an http(s) URL")
    if u.query or u.fragment:
        raise McpToolsError(f"{url}: an MCP server URL has no query or fragment")
    try:
        ipaddress.ip_address(u.hostname)
    except ValueError:
        pass
    else:
        raise McpToolsError(f"{url}: an MCP server's host is a host name, not an address (as the policy grammar "
                            "requires)")
    return u.hostname, u.port or (443 if u.scheme == "https" else 80)


CRED_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
CRED_STORE = re.compile(r"^(?:file:/\S+|vault:\S+|awssm:\S+)$")


def write_policy(url, tools, approvers=None, timeout=300, now=None, gateway=False, credential=None):
    """The policy text. gateway: v1.43's gateway mode (`mcp gateway URL`, no
    TLS interception) in place of inspecting mode. credential: (NAME,
    STORE:REF, opaque) for a v1.31 MCP token the run holds, released into
    the allowed calls; the agent holds only its placeholder."""
    host, port = _host_port(url)
    if gateway and not url.startswith("https://"):
        raise McpToolsError(f"{url}: a gateway's server is reached over https://")
    cred_line, cred_opt = None, ""
    if credential:
        name, store, opaque = credential
        if not CRED_NAME.match(name or ""):
            raise McpToolsError(f"--credential {name!r}: a credential's name is [a-z][a-z0-9_]{{0,31}}")
        if not CRED_STORE.match(store or ""):
            raise McpToolsError("--credential-from: file:/PATH, vault:PATH#KEY or awssm:NAME")
        if not url.startswith("https://"):
            raise McpToolsError(f"{url}: a credential goes only to an https:// server")
        cred_line = f"credential {name} from {store} audience={url}" + (" opaque" if opaque else "")
        cred_opt = f" credential={name}"
    now = now or _dt.datetime.now(_dt.timezone.utc)
    rows = sorted(((t, *classify(t)) for t in tools), key=lambda x: str(x[0].get("name")))
    n = {"allow": 0, "step_up": 0, "refuse": 0}
    for _, v, _ in rows:
        n[v] += 1
    hold = f" mode=hold timeout={int(timeout)}" + (f" approvers={approvers}" if approvers else "")
    out = [
        f"# varek mcp tools: {url}",
        f"# written {now.strftime('%Y-%m-%dT%H:%M:%SZ')} from the server's own tool list",
        f"# tools-sha256 {fingerprint(tools)}",
        f"# {len(rows)} tools: {n['allow']} allowed (the server marks them read-only), "
        f"{n['step_up']} held for an approver, {n['refuse']} refused (no exact rule possible)",
        "# A person reviews this file before it is used. `varek mcp tools --check FILE` fails",
        "# when the server's tool list changes.",
    ]
    if not approvers:
        out.append("# No --approvers group: root alone approves each held call (v1.42).")
    if gateway:
        gw_url = f"http://{host}{urllib.parse.urlsplit(url).path or '/'}"
        out += [
            f"# Gateway mode: the agent's MCP client uses {gw_url} (port 80); the proxy",
            f"# decides each call against {url} and speaks verified TLS to the server.",
            "",
            "require warden 1.43",
            "proxy on",
            "proxy ports 80 443" + ("" if port == 443 else f" {port}"),
            f"mcp gateway {url}",
        ]
    else:
        out += ["", "require warden 1.43" if credential else "require warden 1.42", "proxy inspect",
                *([] if port in (80, 443) else [f"proxy ports {port}"])]
    if cred_line:
        out += [f"# The agent holds only the placeholder ($VAREK_CRED_{credential[0].upper()}); the proxy",
                "# releases the token into the calls a rule below allows, and into a held call",
                "# only once a person approves it (v1.43, D10).", cred_line]
    out += [
        f"allow host {host}:{port}",
        f"allow mcp {url} initialize{cred_opt}",
        f"allow mcp {url} notifications/initialized{cred_opt}",
        f"allow mcp {url} tools/list{cred_opt}",
        "",
    ]
    for t, verdict, why in rows:
        title = (t.get("title") or "").replace("\n", " ")[:80]
        label = f"{t.get('name')!r}" if verdict == "refuse" else t["name"]
        out.append(f"# {label}: {why}" + (f" ({title})" if title else ""))
        if verdict == "allow":
            out.append(f"allow mcp {url} tools/call {t['name']}{cred_opt}")
        elif verdict == "step_up":
            out.append(f"step_up mcp {url} tools/call {t['name']}{cred_opt}{hold}")
        else:
            out.append("#   no rule: refused, as every call no rule names is")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------- check --

def check_policy(text, tools):
    """(ok, report lines). Compares the file's recorded list with `tools`."""
    m = HEADER_HASH.search(text)
    if not m:
        raise McpToolsError("the file has no '# tools-sha256' line: not written by `varek mcp tools`")
    now = fingerprint(tools)
    if m.group(1) == now:
        return True, [f"unchanged: tools-sha256 {now}"]
    named = {name for _, name in RULE_TOOL.findall(text)}
    current = {t.get("name"): t for t in tools}
    lines = [f"changed: the file records {m.group(1)}, the server's list is {now}"]
    added = sorted(n for n in current if n not in named and classify(current[n])[0] != "refuse")
    removed = sorted(n for n in named if n not in current)
    if added:
        lines.append("  new tools (no rule; refused until the file is rewritten): " + ", ".join(added))
    if removed:
        lines.append("  tools the server no longer lists: " + ", ".join(removed))
    if not added and not removed:
        lines.append("  the same names: a tool's annotations or arguments changed")
    return False, lines


def recorded_url(text):
    m = HEADER_URL.search(text)
    return m.group(1) if m else None
