# SPDX-License-Identifier: MIT
# v1430_gw_agent.py: the agent of test_v1430.sh (v1.43, an `mcp gateway`).
# It speaks to the Ontology MCP stand-in as an MCP client configured with the
# gateway's address does: plain HTTP to http://omcp.example.com/mcp/app1 (port
# 80), every call with the credential's placeholder as its bearer token; the
# Warden's proxy decides each call and speaks TLS to the server. Each call is
# on its own connection (a refusal ends one). Then the ways around the gateway:
# TLS straight to the server's port, plain HTTP there, and a Host naming
# another port. For each it prints
#   CALL TAG STATUS-LINE | BODY        or        CALL TAG ERR <exception>
#   v1430_gw_agent.py PORT             PORT: the server's own port
import json, os, socket, ssl, sys, time

P = int(sys.argv[1])
H = "omcp.example.com"
TOK = os.environ.get("VAREK_CRED_TOK", "")
print("ENV", TOK.startswith("varek_ph_tok_"), flush=True)
SESSION = [""]


def response(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        x = s.recv(65536)
        if not x:
            return buf.decode("latin-1"), {}
        buf += x
    head, buf = buf.split(b"\r\n\r\n", 1)
    hd = {}
    for h in head.split(b"\r\n")[1:]:
        k, _, v = h.decode("latin-1").partition(":")
        hd[k.strip().lower()] = v.strip()
    ln = int(hd.get("content-length", "0"))
    while len(buf) < ln:
        x = s.recv(65536)
        if not x:
            break
        buf += x
    return head.split(b"\r\n")[0].decode() + " | " + buf[:ln].decode("latin-1"), hd


def call(tag, method, params=None, rid=None, path="/mcp/app1", host=H, port=80, tls=False):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if rid is not None:
        msg["id"] = rid
    body = json.dumps(msg).encode()
    head = ("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n"
            "Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2025-06-18\r\n"
            "Authorization: Bearer %s\r\n" % (path, host, TOK))
    if SESSION[0]:
        head += "Mcp-Session-Id: %s\r\n" % SESSION[0]
    head += "Content-Length: %d\r\n\r\n" % len(body)
    t0 = time.monotonic()
    try:
        s = socket.create_connection((H, port), 15)
        if tls:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=H)
        s.sendall(head.encode() + body)
        line, hd = response(s)
        s.close()
        print("CALL", tag, line, "| %.1fs" % (time.monotonic() - t0), flush=True)
        return hd
    except (OSError, ssl.SSLError) as e:
        print("CALL", tag, "ERR", type(e).__name__, flush=True)
        return {}


hd = call("init", "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "gw-agent", "version": "1"}}, 1)
SESSION[0] = hd.get("mcp-session-id", "")
call("notify", "notifications/initialized")
call("list", "tools/list", {}, 2)
call("search", "tools/call", {"name": "search-osdk-todo-task", "arguments": {"project_id": "p1"}}, 3)
call("query", "tools/call", {"name": "get-overdue-osdk-todo-tasks", "arguments": {}}, 4)
call("create", "tools/call", {"name": "create-osdk-todo-task", "arguments": {"title": "x", "project_id": "p1"}}, 5)
call("delete", "tools/call", {"name": "delete-osdk-todo-task", "arguments": {"task_id": "t1"}}, 6)
call("unlisted", "tools/call", {"name": "archive-osdk-todo-task", "arguments": {"task_id": "t2"}}, 7)
call("otherpath", "tools/list", {}, 8, path="/mcp/other")
call("hostport", "tools/list", {}, 9, host="%s:80" % H)
call("direct_tls", "tools/list", {}, 10, port=P, tls=True)
call("direct_plain", "tools/list", {}, 11, port=P)
call("search2", "tools/call", {"name": "search-osdk-todo-task", "arguments": {}}, 12)
