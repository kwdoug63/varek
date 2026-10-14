#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""agent_a.py — run A of the shared soak (soak.sh): an agent under the
Warden, on behalf of a user whose token the Warden verified, with two
confined MCP servers it launches once and keeps (fs, gh), MCP calls of its
own over HTTPS, and sub-agents. Every <interval> seconds it does one task,
in turn:

  mcp_list    tools/list to the remote MCP server        (the agent's rule: 200)
  mcp_search  tools/call search_code                     (the agent's rule: 200)
  fs_read     fs reads a project file                    (fs's rule: the file's text)
  gh_get      gh calls get_issue with credential mt      (gh's rule: 200, the token
                                                          put in by the proxy)
  subagents   coder (a sub-agent) launches tester (a sub-agent of it); each
              opens a project file                       (exit 0)

and prints one JSON line: {"t", "task", "ok", "ms", ...}. The third turn,
and every <probe-every>-th after it, is a probe instead, the kinds in turn
({"t", "probe", "held"}: held when it came out as it must):

  mcp_delete     tools/call delete_repo                  a deny rule: 403
  mcp_unlisted   tools/call other_tool                   no rule: 403
  agent_get      tools/call get_issue, by the agent      only gh's rule allows it: 403
  fs_outside     fs reads the agent's own file           not fs's: EACCES
  fs_store       fs reads the MCP token's file           EACCES
  gh_delete      gh calls delete_repo                    deny for=gh: 403
  agent_srvfile  the agent opens a file only fs may      EACCES
  env_launch     a second fs, launched with PYTHONPATH   refused at the launch (subagent_env)

  agent_a.py --interval 60 --seconds 86400 --port P --dir D

D holds bin/coder, bin/tester, srv/fs_server.py, srv/gh_server.py,
proj/{a,b}, agent_only and srv_only. Standard library only.
"""
import argparse
import http.client
import json
import os
import select
import ssl
import subprocess
import time

H = "mcp.example.com"
TASKS = ("mcp_list", "mcp_search", "fs_read", "gh_get", "subagents")
PROBES = ("mcp_delete", "mcp_unlisted", "agent_get", "fs_outside", "fs_store", "gh_delete", "agent_srvfile",
          "env_launch")


class Server:
    """A stdio MCP server, kept for the run."""

    def __init__(self, argv):
        self.argv, self.p, self.n = argv, None, 0

    def start(self):
        self.p = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        return self.call("initialize", {})

    def call(self, method, params, timeout=30):
        if self.p is None or self.p.poll() is not None:
            raise RuntimeError("the server is not running" + (f" (exit {self.p.returncode})" if self.p else ""))
        self.n += 1
        self.p.stdin.write((json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
                            + "\n").encode())
        buf = b""
        end = time.time() + timeout
        while not buf.endswith(b"\n"):
            r, _, _ = select.select([self.p.stdout], [], [], max(0.0, end - time.time()))
            if not r:
                raise TimeoutError("no answer")
            x = os.read(self.p.stdout.fileno(), 65536)
            if not x:
                raise RuntimeError("the server closed its output")
            buf += x
        return json.loads(buf)["result"]


def mcp(a, ctx, rid, method, params=None):
    """The agent's own MCP call: the HTTP status."""
    m = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        m["params"] = params
    body = json.dumps(m).encode()
    conn = http.client.HTTPSConnection(H, a.port, timeout=20, context=ctx)
    try:
        conn.putrequest("POST", "/mcp", skip_accept_encoding=True)
        for k, v in (("Content-Type", "application/json"), ("Accept", "application/json, text/event-stream"),
                     ("MCP-Protocol-Version", "2025-06-18"), ("Content-Length", str(len(body)))):
            conn.putheader(k, v)
        conn.endheaders(body)
        r = conn.getresponse()
        r.read(65536)
        return r.status
    finally:
        conn.close()


def task(a, ctx, srv, i, kind):
    rec = {"t": round(time.time(), 3), "task": kind}
    t0 = time.time()
    try:
        if kind == "mcp_list":
            st = mcp(a, ctx, i, "tools/list")
            rec.update(status=st, ok=st == 200)
        elif kind == "mcp_search":
            st = mcp(a, ctx, i, "tools/call", {"name": "search_code", "arguments": {"q": "soak"}})
            rec.update(status=st, ok=st == 200)
        elif kind == "fs_read":
            r = srv["fs"].call("tools/call", {"name": "read_file", "arguments": {"path": a.dir + "/proj/a"}})
            rec.update(ok=r.get("text") == "project file a\n", result=r.get("error", "text"))
        elif kind == "gh_get":
            r = srv["gh"].call("tools/call", {"name": "get_issue"})
            rec.update(status=r.get("status"), ok=r.get("status") == 200, error=r.get("error"))
        else:
            p = subprocess.run([a.dir + "/bin/coder", "spawn", a.dir + "/proj/a", a.dir + "/bin/tester", "open",
                                a.dir + "/proj/b"], capture_output=True, timeout=60)
            rec.update(exit=p.returncode, ok=p.returncode == 0)
    except Exception as e:                      # noqa: BLE001 - every failure is recorded
        rec.update(ok=False, error=f"{type(e).__name__}: {e}"[:200])
    if rec.get("error") is None:
        rec.pop("error", None)
    rec["ms"] = int((time.time() - t0) * 1000)
    return rec


def probe(a, ctx, srv, i, kind):
    rec = {"t": round(time.time(), 3), "probe": kind}
    t0 = time.time()
    try:
        if kind in ("mcp_delete", "mcp_unlisted", "agent_get"):
            name = {"mcp_delete": "delete_repo", "mcp_unlisted": "other_tool", "agent_get": "get_issue"}[kind]
            st = mcp(a, ctx, i, "tools/call", {"name": name})
            rec.update(status=st, held=st == 403)
        elif kind in ("fs_outside", "fs_store"):
            path = a.dir + "/agent_only" if kind == "fs_outside" else a.store
            r = srv["fs"].call("tools/call", {"name": "read_file", "arguments": {"path": path}})
            rec.update(result=r.get("error", "text"), held=r.get("error") == "EACCES")
        elif kind == "gh_delete":
            r = srv["gh"].call("tools/call", {"name": "delete_repo"})
            rec.update(status=r.get("status"), held=r.get("status") == 403)
        elif kind == "agent_srvfile":
            try:
                open(a.dir + "/srv_only", "rb").close()
                rec.update(held=False, result="opened")
            except PermissionError:
                rec.update(held=True, result="EACCES")
        else:
            env = dict(os.environ, PYTHONPATH=a.dir + "/proj")
            try:
                p = subprocess.run([a.dir + "/srv/fs_server.py"], input=b"", capture_output=True, env=env, timeout=30)
                rec.update(held=False, result=f"ran (exit {p.returncode})")
            except PermissionError:
                rec.update(held=True, result="EACCES")
    except Exception as e:                      # noqa: BLE001
        rec.update(held=False, error=f"{type(e).__name__}: {e}"[:200])
    rec["ms"] = int((time.time() - t0) * 1000)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--seconds", type=float, default=86400)
    ap.add_argument("--probe-every", type=int, default=10)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--store", required=True)
    a = ap.parse_args()
    ctx = ssl.create_default_context()          # the host's bundle and the run's CA
    srv = {"fs": Server([a.dir + "/srv/fs_server.py"]), "gh": Server([a.dir + "/srv/gh_server.py", str(a.port)])}
    start = {"t": round(time.time(), 3), "start": True,
             "placeholder": os.environ.get("VAREK_CRED_MT", "").startswith("varek_ph_mt_")}
    for n, s in srv.items():
        try:
            start[n] = s.start().get("name") == n
        except Exception as e:                  # noqa: BLE001
            start[n] = f"{type(e).__name__}: {e}"[:200]
    print(json.dumps(start), flush=True)
    end = time.time() + a.seconds
    nxt = time.time()
    i = j = p = 0
    while time.time() < end:
        i += 1
        if a.probe_every and i >= 3 and (i - 3) % a.probe_every == 0:
            rec = probe(a, ctx, srv, i, PROBES[p % len(PROBES)])
            p += 1
        else:
            rec = task(a, ctx, srv, i, TASKS[j % len(TASKS)])
            j += 1
        print(json.dumps(rec), flush=True)
        nxt += a.interval
        time.sleep(max(0.0, min(nxt, end) - time.time()))
    for s in srv.values():
        if s.p is not None:
            s.p.stdin.close()
            try:
                s.p.wait(10)
            except subprocess.TimeoutExpired:
                s.p.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
