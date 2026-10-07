#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1240_tamper.py — test_v1240.sh: the forgeries the v1.24 independent review
found the audit accepting, made the way someone who holds the log (but not
the signing key) could: edit records, then recompute the hash chain.
varek_audit.py must refuse each.

  v1240_tamper.py <in.log> <out.log> <mode> [args]

  nocands <target>        the first allowed connect to <target>: drop
                          dialed, candidates and resolution_generation
  port0 <target>          the first allowed connect to <target>: spell its
                          port with a leading zero everywhere
  dropname <target> <n> <name>
                          the n-th allowed connect to <target> (from 1):
                          leave <name> out of its candidates
  droprecord <text>       delete the first record whose text contains <text>
  view <path> <rule>      the first refused open of <path>: turn it into a
                          view served (rule <rule>)
  unstart <key>           delete <key> from run_start
  badaddrs                the first resolution record: "addresses": 5
"""
import hashlib
import json
import sys

src, dst, mode, args = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
lines = open(src, encoding="utf-8", errors="surrogateescape").read().splitlines(keepends=True)
done = False
seen = 0


def edit(d):
    """Edit record d in place; return False to delete it. Sets done."""
    global done, seen
    if done:
        return True
    allowed_conn = d.get("action") == "net.connect" and d.get("decision_final") == "ALLOW"
    if mode == "nocands" and allowed_conn and d.get("target") == args[0] and "candidates" in d:
        for k in ("dialed", "candidates", "resolution_generation"):
            d.pop(k, None)
        done = True
    elif mode == "port0" and allowed_conn and d.get("target") == args[0]:
        h, _, p = args[0].rpartition(":")
        new = f"{h}:0{p}"
        fix = lambda s: s[: -len(p)] + "0" + p if isinstance(s, str) and s.endswith(":" + p) else s
        d["target"], d["dialed"], d["resolved"] = new, new, fix(d.get("resolved"))
        d["candidates"] = [fix(c) for c in d.get("candidates", [])]
        done = True
    elif mode == "dropname" and allowed_conn and d.get("target") == args[0]:
        seen += 1
        if seen == int(args[1]):
            d["candidates"] = [c for c in d.get("candidates", []) if not c.startswith(args[2] + ":")]
            if str(d.get("resolved", "")).startswith(args[2] + ":"):
                d["resolved"] = d.get("dialed")
            done = True
    elif mode == "view" and d.get("action") == "file.open" and d.get("target") == args[0] \
            and d.get("decision_final") == "DENY":
        d.update(decision_raw="UNKNOWN", decision_final="ALLOW", rule=args[1], policy_line=-1,
                 kernel_verdict="ALLOW", errno=0, view_generation=1)
        done = True
    elif mode == "unstart" and d.get("event") == "run_start":
        d.pop(args[0], None)
        done = True
    elif mode == "badaddrs" and d.get("event") == "resolution":
        d["addresses"] = 5
        done = True
    return True


head = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
out = []
for line in lines:
    if line.startswith("{") and ',"chain":"' in line:
        cut = line.index(',"chain":"')
        body = line[:cut]
        if mode == "droprecord" and not done and args[0] in body:
            done = True
            continue
        if mode != "droprecord":
            d = json.loads(body + "}")
            before = json.dumps(d, separators=(",", ":"), ensure_ascii=False)
            edit(d)
            after = json.dumps(d, separators=(",", ":"), ensure_ascii=False)
            if after != before:
                body = after[:-1]
        head = hashlib.sha256(head + body.encode("utf-8", "surrogateescape")).digest()
        line = body + ',"chain":"' + head.hex() + line[cut + 10 + 64:]
    out.append(line)
if not done:
    sys.exit(f"v1240_tamper: nothing to edit for {mode} {args}")
open(dst, "w", encoding="utf-8", errors="surrogateescape").write("".join(out))
