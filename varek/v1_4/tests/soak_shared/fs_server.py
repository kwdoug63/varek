#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""fs_server.py — the shared soak's file server (run A): a stdio MCP server
the agent launches once and keeps for the whole run. The Warden confines it
(`mcp server fs exec ...`): its calls are decided by the rules written
for=fs, not the agent's. One JSON-RPC message a line on stdin, one answer a
line on stdout:

  initialize                    {"name": "fs"}
  tools/list                    {"tools": [{"name": "read_file"}]}
  tools/call read_file {path}   {"text": <the file>} or {"error": "EACCES"|...}

Standard library only.
"""
import errno
import json
import sys


def answer(i, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "result": result}) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        try:
            m = json.loads(line)
        except ValueError:
            continue
        i, method, p = m.get("id"), m.get("method"), m.get("params") or {}
        if method == "initialize":
            answer(i, {"name": "fs"})
        elif method == "tools/list":
            answer(i, {"tools": [{"name": "read_file"}]})
        elif method == "tools/call" and p.get("name") == "read_file":
            try:
                with open(p.get("arguments", {}).get("path", ""), encoding="utf-8", errors="replace") as fh:
                    answer(i, {"text": fh.read(65536)})
            except OSError as e:
                answer(i, {"error": errno.errorcode.get(e.errno, str(e.errno))})
        else:
            answer(i, {"error": "unknown"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
