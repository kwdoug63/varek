#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""gh_server.py — the shared soak's remote-tools server (run A): a stdio MCP
server the agent launches once and keeps for the whole run, confined by the
Warden (`mcp server gh exec ...`). For each tools/call it makes the same call
to the remote MCP server (mcp.example.com, the soak's stand-in) over HTTPS,
through the Warden's inspecting proxy, with credential mt's placeholder as
its bearer token: the proxy puts the token in only where a rule written
for=gh names it.

  initialize                     {"name": "gh"}
  tools/call NAME                {"status": <the remote's HTTP status>} or {"error": ...}

  gh_server.py PORT

Standard library only.
"""
import http.client
import json
import os
import ssl
import sys

H = "mcp.example.com"


def answer(i, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "result": result}) + "\n")
    sys.stdout.flush()


def remote(port, ctx, rid, name):
    body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                       "params": {"name": name, "arguments": {"n": rid}}}).encode()
    conn = http.client.HTTPSConnection(H, port, timeout=20, context=ctx)
    try:
        conn.putrequest("POST", "/mcp", skip_accept_encoding=True)
        for k, v in (("Content-Type", "application/json"), ("Accept", "application/json, text/event-stream"),
                     ("MCP-Protocol-Version", "2025-06-18"),
                     ("Authorization", "Bearer " + os.environ.get("VAREK_CRED_MT", "")),
                     ("Content-Length", str(len(body)))):
            conn.putheader(k, v)
        conn.endheaders(body)
        r = conn.getresponse()
        r.read(65536)
        return r.status
    finally:
        conn.close()


def main():
    port = int(sys.argv[1])
    ctx = ssl.create_default_context()
    rid = 0
    for line in sys.stdin:
        try:
            m = json.loads(line)
        except ValueError:
            continue
        i, method, p = m.get("id"), m.get("method"), m.get("params") or {}
        if method == "initialize":
            answer(i, {"name": "gh"})
        elif method == "tools/call":
            rid += 1
            try:
                answer(i, {"status": remote(port, ctx, rid, str(p.get("name", "")))})
            except Exception as e:              # noqa: BLE001 - every failure is answered
                answer(i, {"error": f"{type(e).__name__}: {e}"[:200]})
        else:
            answer(i, {"error": "unknown"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
