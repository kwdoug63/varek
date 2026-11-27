#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""omcp_agent.py: a headless MCP client for a Palantir Ontology MCP server reached through
VAREK's gateway (v1.43 step 5, integrations/palantir/README.md).

It stands in for an agent's MCP client, for scripts and for the recorded run:

  omcp_agent.py list                      the tools the server lists
  omcp_agent.py call NAME ['{"k": "v"}']  call one tool with JSON arguments

Each invocation initializes a session (initialize, notifications/initialized)
and then lists or calls. The URL is the gateway's, http://HOST/PATH (port
80), from --url or OMCP_GATEWAY_URL. The bearer token it sends is
$VAREK_CRED_OMCP, which under VAREK holds only the credential's placeholder:
the proxy releases the real token into the calls the policy allows.

Exit status: 0 the call's result; 3 a JSON-RPC error (VAREK's refusals are
these); 4 an HTTP error (a 502 when the server's TLS cannot be verified);
2 usage. Standard library only. VAREK is not affiliated with Palantir.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

PROTOCOLS = ("2026-07-28", "2025-06-18")


class HttpFail(Exception):
    pass


def _post(url, msg, token, proto, session, timeout):
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if proto:
        h["MCP-Protocol-Version"] = proto
    if session:
        h["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(msg).encode(), method="POST", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.headers, r.read()
    except urllib.error.HTTPError as e:
        raise HttpFail(f"HTTP {e.code}: {e.read(300).decode('utf-8', 'replace').strip()}")
    except urllib.error.URLError as e:
        raise HttpFail(str(e.reason))


def _reply(headers, body, rid):
    if (headers.get("Content-Type") or "").startswith("text/event-stream"):
        data = []
        for line in body.decode("utf-8", "replace").splitlines() + [""]:
            if line.startswith("data:"):
                data.append(line[5:].lstrip())
            elif not line and data:
                m = json.loads("\n".join(data))
                data = []
                if m.get("id") == rid:
                    return m
        raise HttpFail("no reply in the event stream")
    return json.loads(body) if body else {}


class Session:
    def __init__(self, url, token, timeout):
        self.url, self.token, self.timeout = url, token, timeout
        self.proto, self.session, self.rid = None, None, 0
        for proto in PROTOCOLS:
            hd, body = _post(url, self._msg("initialize", {
                "protocolVersion": proto, "capabilities": {},
                "clientInfo": {"name": "varek-omcp-agent", "version": "1.43"}}), token, None, None, timeout)
            m = _reply(hd, body, self.rid)
            if "result" in m:
                self.proto = m["result"].get("protocolVersion", proto)
                self.session = hd.get("Mcp-Session-Id")
                break
        else:
            raise HttpFail("the server initialized with neither protocol revision")
        _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token, self.proto,
              self.session, timeout)

    def _msg(self, method, params):
        self.rid += 1
        return {"jsonrpc": "2.0", "id": self.rid, "method": method, "params": params}

    def request(self, method, params):
        msg = self._msg(method, params)
        hd, body = _post(self.url, msg, self.token, self.proto, self.session, self.timeout)
        return _reply(hd, body, msg["id"])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="omcp_agent.py", description="A headless MCP client through VAREK's gateway.")
    ap.add_argument("--url", default=os.environ.get("OMCP_GATEWAY_URL"),
                    help="the gateway URL, http://HOST/PATH (or OMCP_GATEWAY_URL)")
    ap.add_argument("--timeout", type=int, default=660,
                    help="seconds to wait for a reply; a held call waits for its approver (default 660)")
    sub = ap.add_subparsers(dest="op", required=True)
    sub.add_parser("list")
    c = sub.add_parser("call")
    c.add_argument("name")
    c.add_argument("arguments", nargs="?", default="{}")
    a = ap.parse_args(argv)
    if not a.url:
        ap.error("no --url (or OMCP_GATEWAY_URL)")
    try:
        args = json.loads(a.arguments) if a.op == "call" else None
    except ValueError:
        ap.error("the arguments are one JSON object")
    try:
        s = Session(a.url, os.environ.get("VAREK_CRED_OMCP", ""), a.timeout)
        if a.op == "list":
            tools, cursor = [], None
            while True:
                m = s.request("tools/list", {"cursor": cursor} if cursor else {})
                if "error" in m:
                    break
                tools += m["result"].get("tools", [])
                cursor = m["result"].get("nextCursor")
                if not cursor:
                    break
            if "error" not in m:
                m = {"result": {"tools": tools}}
        else:
            m = s.request("tools/call", {"name": a.name, "arguments": args})
    except HttpFail as e:
        print(f"omcp_agent: {e}", file=sys.stderr)
        return 4
    print(json.dumps(m.get("result", m.get("error")), indent=2))
    return 3 if "error" in m else 0


if __name__ == "__main__":
    sys.exit(main())
