#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1430_omcp_server.py: a stand-in for a Palantir Ontology MCP (OMCP) server,
for v1.43's tests (docs/security/v1.43-palantir-ontology-mcp.md, step 2).

Streamable HTTP on one URL path (POST only): enough of the 2025-06-18 and
2026-07-28 revisions to initialize, list tools a page at a time and call
them. It exposes a small to-do ontology the way OMCP exposes object types,
action types and query functions, with tool names in the style Palantir's
documentation shows (search-osdk-todo-task, create-osdk-todo-task):

  search-osdk-todo-task          object type search    readOnlyHint
  get-overdue-osdk-todo-tasks    query function        readOnlyHint
  create-osdk-todo-task          action type           (no annotations)
  modify-osdk-todo-task-status   action type           readOnlyHint false
  delete-osdk-todo-task          action type           destructiveHint

Until step 1 measures a real enrollment, the names and annotations are a
model, not Palantir's behaviour. VAREK is not affiliated with Palantir.

A request without "Authorization: Bearer <token>" gets 401 with a
WWW-Authenticate header. Replies are text/event-stream when the request
accepts it and --sse is given, JSON otherwise. Every request is logged as a
JSON line (method, tool name, headers but never the Authorization value).

  v1430_omcp_server.py --port N [--host 127.0.0.1] [--path /mcp/app1]
      [--token T] [--sse] [--page-size N] [--variant base|changed|unnamable]
      [--log FILE] [--tls CERT KEY]

--variant changed adds an argument to create-osdk-todo-task and a new tool,
so a written policy's --check fails; --variant unnamable adds a tool whose
name a policy cannot name exactly. Prints "ready PORT" when listening.
"""

import argparse
import json
import ssl
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOLS = ("2025-06-18", "2026-07-28")


def tool_defs(variant):
    t = [
        {"name": "search-osdk-todo-task", "title": "Search Todo Task",
         "description": "Search Todo Task objects, optionally by project_id.",
         "annotations": {"readOnlyHint": True},
         "inputSchema": {"type": "object", "properties": {"project_id": {"type": "string"}}}},
        {"name": "get-overdue-osdk-todo-tasks", "title": "Overdue tasks",
         "description": "Query function: tasks past their due date.",
         "annotations": {"readOnlyHint": True},
         "inputSchema": {"type": "object", "properties": {"as_of": {"type": "string"}}}},
        {"name": "create-osdk-todo-task", "title": "Create Todo Task",
         "description": "Action: create a Todo Task.",
         "inputSchema": {"type": "object",
                         "properties": {"title": {"type": "string"}, "project_id": {"type": "string"},
                                        "status": {"type": "string"}, "due_date": {"type": "string"}},
                         "required": ["title", "project_id"]}},
        {"name": "modify-osdk-todo-task-status", "title": "Modify Todo Task Status",
         "description": "Action: set a task's status.",
         "annotations": {"readOnlyHint": False},
         "inputSchema": {"type": "object",
                         "properties": {"task_id": {"type": "string"}, "status": {"type": "string"}},
                         "required": ["task_id", "status"]}},
        {"name": "delete-osdk-todo-task", "title": "Delete Todo Task",
         "description": "Action: delete a task.",
         "annotations": {"readOnlyHint": False, "destructiveHint": True},
         "inputSchema": {"type": "object", "properties": {"task_id": {"type": "string"}},
                         "required": ["task_id"]}},
    ]
    if variant == "changed":
        t[2]["inputSchema"]["properties"]["assigned_to"] = {"type": "string"}
        t.append({"name": "archive-osdk-todo-task", "title": "Archive Todo Task",
                  "description": "Action: archive a task.",
                  "inputSchema": {"type": "object", "properties": {"task_id": {"type": "string"}}}})
    if variant == "unnamable":
        t.append({"name": "export tasks*", "description": "A name a policy cannot name exactly.",
                  "annotations": {"readOnlyHint": True},
                  "inputSchema": {"type": "object", "properties": {}}})
    return t


class State:
    def __init__(self, a):
        self.a = a
        self.tools = tool_defs(a.variant)
        self.tasks = {"t1": {"task_id": "t1", "title": "Draft runbook", "project_id": "p1", "status": "open",
                             "due_date": "2026-11-20"},
                      "t2": {"task_id": "t2", "title": "Review policy", "project_id": "p2", "status": "open",
                             "due_date": "2026-12-31"}}
        self.sessions = set()
        self.lock = threading.Lock()

    def call(self, name, args):
        with self.lock:
            if name == "search-osdk-todo-task":
                rows = [t for t in self.tasks.values() if args.get("project_id") in (None, t["project_id"])]
            elif name == "get-overdue-osdk-todo-tasks":
                rows = [t for t in self.tasks.values() if t["due_date"] < args.get("as_of", "2026-11-27")]
            elif name == "create-osdk-todo-task":
                tid = f"t{len(self.tasks) + 1}"
                self.tasks[tid] = {"task_id": tid, "status": "open", "due_date": "", **args}
                rows = [self.tasks[tid]]
            elif name == "modify-osdk-todo-task-status":
                self.tasks[args["task_id"]]["status"] = args["status"]
                rows = [self.tasks[args["task_id"]]]
            elif name == "delete-osdk-todo-task":
                rows = [self.tasks.pop(args["task_id"])]
            else:
                return None
        return {"content": [{"type": "text", "text": json.dumps(rows)}], "isError": False}


def make_handler(st):
    a = st.a

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def _log(self, rec):
            if a.log:
                with st.lock, open(a.log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")

        def _send(self, code, obj=None, headers=None, sse=False):
            body = b""
            if obj is not None:
                raw = json.dumps(obj).encode()
                body = b"event: message\ndata: " + raw + b"\n\n" if sse else raw
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if obj is not None:
                self.send_header("Content-Type", "text/event-stream" if sse else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._send(405, {"error": "POST only"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n)
            hdrs = {k: v for k, v in self.headers.items() if k.lower() != "authorization"}
            if self.path != a.path:
                self._log({"path": self.path, "status": 404})
                return self._send(404, {"error": "not found"})
            if self.headers.get("Authorization") != f"Bearer {a.token}":
                self._log({"status": 401, "headers": hdrs})
                return self._send(401, {"error": "unauthorized"}, {
                    "WWW-Authenticate": 'Bearer realm="omcp-standin"'})
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                return self._send(400, {"jsonrpc": "2.0", "id": None,
                                        "error": {"code": -32700, "message": "parse error"}})
            method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
            self._log({"method": method, "name": params.get("name"), "headers": hdrs})
            sse = a.sse and "text/event-stream" in (self.headers.get("Accept") or "")
            sess = self.headers.get("Mcp-Session-Id")

            def ok(result, extra=None):
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": result}, extra, sse)

            def err(code, text, http=200):
                return self._send(http, {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": text}},
                                  None, sse)

            if method == "initialize":
                pv = params.get("protocolVersion")
                if pv not in PROTOCOLS:
                    return err(-32602, f"unsupported protocol version {pv}", 400)
                sid = uuid.uuid4().hex
                st.sessions.add(sid)
                return ok({"protocolVersion": pv, "capabilities": {"tools": {"listChanged": False}},
                           "serverInfo": {"name": "omcp-standin", "version": "1.43.0-test"}},
                          {"Mcp-Session-Id": sid})
            if sess not in st.sessions:
                return err(-32600, "no session", 400)
            if rid is None:                       # a notification
                return self._send(202)
            if method == "tools/list":
                start = int(params.get("cursor") or 0)
                page = st.tools[start:start + a.page_size]
                res = {"tools": page}
                if start + a.page_size < len(st.tools):
                    res["nextCursor"] = str(start + a.page_size)
                return ok(res)
            if method == "tools/call":
                r = st.call(params.get("name"), params.get("arguments") or {})
                return ok(r) if r is not None else err(-32602, "unknown tool")
            if method == "ping":
                return ok({})
            return err(-32601, "method not found")

    return H


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--path", default="/mcp/app1")
    p.add_argument("--token", default="standin-token")
    p.add_argument("--sse", action="store_true")
    p.add_argument("--page-size", type=int, default=2)
    p.add_argument("--variant", choices=("base", "changed", "unnamable"), default="base")
    p.add_argument("--log")
    p.add_argument("--tls", nargs=2, metavar=("CERT", "KEY"))
    a = p.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(State(a)))
    if a.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*a.tls)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"ready {srv.server_address[1]}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
