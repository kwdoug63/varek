#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""demo_d5.py: the recorded run's agent (v1.43 step 6, docs/security/v1.43-palantir-ontology-mcp.md, D5).

Five calls to an Ontology MCP server through VAREK's gateway, one after another,
each printed with what happened and how long it took:

  1. read            search-osdk-todo-task           the policy allows it
  2. write approved  create-osdk-todo-task           held; a person approves (varek approve)
  3. write denied    modify-osdk-todo-task-status    held; a person refuses (varek deny)
  4. write timed out delete-osdk-todo-task           held; nobody answers before timeout=
  5. unnamed tool    archive-osdk-todo-task          no rule names it: refused at once

Run it under VAREK with the server's gateway URL in OMCP_GATEWAY_URL (README.md,
section 6), and answer steps 2 to 4 from another terminal with `varek pending`,
`varek approve` and `varek deny`. One process, so a policy needs no rule for
another launch. The tool names are the stand-in's and Palantir's OSDK to-do
example's; pass --tools to name an enrollment's own (five comma-separated names,
in the order above). VAREK is not affiliated with Palantir Technologies Inc.
"""
import argparse
import contextlib
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "clients"))
import omcp_agent  # noqa: E402

DEFAULT = ["search-osdk-todo-task", "create-osdk-todo-task", "modify-osdk-todo-task-status",
           "delete-osdk-todo-task", "archive-osdk-todo-task"]
LABELS = ["read", "write-approved", "write-denied", "write-timed-out", "unnamed-tool"]
ARGS = [{"project_id": "varek-demo"}, {"title": "Filed by an agent under VAREK", "project_id": "varek-demo"},
        {"task_id": "varek-demo-1", "status": "DONE"}, {"task_id": "varek-demo-1"}, {"task_id": "varek-demo-1"}]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="demo_d5.py", description="The five calls of the recorded run (D5).")
    ap.add_argument("--tools", help="five tool names, comma-separated, in the order of the steps")
    a = ap.parse_args(argv)
    names = a.tools.split(",") if a.tools else DEFAULT
    if len(names) != 5:
        ap.error("--tools names five tools")
    for i, (label, name, args) in enumerate(zip(LABELS, names, ARGS), 1):
        print(f"[{i}/5] {label}: {name} ...", flush=True)
        buf, t0 = io.StringIO(), time.monotonic()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = omcp_agent.main(["call", name, json.dumps(args)])
        dt = time.monotonic() - t0
        what = {0: "ran", 3: "refused", 4: "failed"}.get(rc, f"exit {rc}")
        detail = " ".join(buf.getvalue().split())[:200]
        print(f"STEP {label} {what} {dt:.1f}s {detail}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
