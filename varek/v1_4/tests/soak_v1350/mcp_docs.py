#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""mcp_docs.py — the MCP server of the v1.35 soak (soak.sh starts it, as
root, outside the Warden): Streamable HTTP over HTTPS, answered with JSON
(no event stream), enough for the OpenAI Agents SDK's MCP client:
initialize (with a session id), notifications/initialized, tools/list and
tools/call of

  search_docs   the documents whose text holds the query
  get_doc       one document
  get_secret    a value the agent's plan does not name (the soak's probe
                calls it: the run held to its plan must refuse the call
                before it reaches here)

Each request is logged to LOG as one JSON line: time, HTTP method, the
JSON-RPC method and tool name. A GET is 405 (no event stream), a DELETE
(the session's end) 200.

  mcp_docs.py IP PORT CERT KEY LOG
"""
import json
import socket
import ssl
import sys
import threading
import time
import uuid

ip, port, cert, key, log_path = sys.argv[1], int(sys.argv[2]), *sys.argv[3:6]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
lock = threading.Lock()
log = open(log_path, "a", buffering=1)
DOCS = {"plans": "A plan names what an agent is given.", "holds": "A run held to its plan is refused the rest.",
        "audit": "The audit checks the chain, the certificates and the plan's records."}
TOOLS = [
    {"name": "search_docs", "description": "Find documents", "inputSchema": {
        "type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}},
    {"name": "get_doc", "description": "One document", "inputSchema": {
        "type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
    {"name": "get_secret", "description": "A value", "inputSchema": {"type": "object", "properties": {}}},
]


def call(name, args):
    if name == "search_docs":
        q = str(args.get("query", "")).lower()
        return ", ".join(k for k, v in DOCS.items() if q in v.lower() or q in k) or "none"
    if name == "get_doc":
        return DOCS.get(str(args.get("id")), "no such document")
    if name == "get_secret":
        return "the soak's secret"
    return None


def answer(req):
    m, rid = req.get("method"), req.get("id")
    if m == "initialize":
        pv = (req.get("params") or {}).get("protocolVersion", "2025-06-18")
        return {"protocolVersion": pv, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "varek-soak-docs", "version": "1.35.0"}}, rid
    if m == "tools/list":
        return {"tools": TOOLS}, rid
    if m == "tools/call":
        p = req.get("params") or {}
        out = call(p.get("name"), p.get("arguments") or {})
        if out is None:
            return {"content": [{"type": "text", "text": "no such tool"}], "isError": True}, rid
        return {"content": [{"type": "text", "text": out}], "isError": False}, rid
    if m == "ping":
        return {}, rid
    return None, rid


def respond(c, status, body=b"", ctype="application/json", extra=()):
    head = [f"HTTP/1.1 {status}", f"Content-Type: {ctype}", f"Content-Length: {len(body)}", "Connection: keep-alive"]
    head += list(extra)
    c.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + body)


def serve(c):
    try:
        c = ctx.wrap_socket(c, server_side=True)
        f = c.makefile("rb")
        while True:
            line = f.readline()
            if not line:
                return
            meth = line.split(b" ")[0].decode("ascii", "replace")
            hdr = {}
            while True:
                h = f.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
                k, _, v = h.decode("latin-1").partition(":")
                hdr[k.strip().lower()] = v.strip()
            body = f.read(int(hdr.get("content-length", "0") or 0))
            rec = {"t": time.time(), "http": meth}
            if meth == "POST":
                try:
                    req = json.loads(body)
                except ValueError:
                    req = {}
                rec["rpc"] = req.get("method")
                if req.get("method") == "tools/call":
                    rec["tool"] = (req.get("params") or {}).get("name")
                result, rid = answer(req)
                if rid is None or result is None:
                    respond(c, "202 Accepted", b"")
                else:
                    extra = [f"Mcp-Session-Id: {uuid.uuid4().hex}"] if req.get("method") == "initialize" else []
                    respond(c, "200 OK", json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}).encode(),
                            extra=extra)
            elif meth == "DELETE":
                respond(c, "200 OK", b"")
            else:
                respond(c, "405 Method Not Allowed", b"")
            with lock:
                log.write(json.dumps(rec) + "\n")
    except (OSError, ssl.SSLError, ValueError):
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port))
s.listen(64)
while True:
    conn, _ = s.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
