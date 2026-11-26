#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_approver.py — run D's approver in the shared soak (v1.42.0).

As root, it finds run D's approvers' socket in the Warden's stream (the
line `approvals: /run/varek-approve/RUN.sock`), then approves every
proposal the socket lists, as proposed, with the reason "soak". Each answer
is a line of JSON in OUT. It ends when the Warden (PID) has ended.

  soak_approver.py --log D/verdicts.log --pid WARDEN_PID --out D/approvals.jsonl
"""
import argparse
import json
import os
import re
import socket
import sys
import time


def ask(path, req):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(path)
    s.sendall(req.encode())
    s.shutdown(socket.SHUT_WR)
    out = b""
    while True:
        b = s.recv(65536)
        if not b:
            return out.decode(errors="replace")
        out += b


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    sock = None
    with open(a.out, "a") as out:
        while alive(a.pid):
            if sock is None:
                try:
                    m = re.search(r"approvals: (/run/varek-approve/[0-9a-f]+\.sock)", open(a.log, errors="replace").read(1 << 20))
                except OSError:
                    m = None
                if not m:
                    time.sleep(0.5)
                    continue
                sock = m.group(1)
                out.write(json.dumps({"t": round(time.time(), 3), "socket": sock}) + "\n")
                out.flush()
            try:
                ids = [json.loads(ln).get("id") for ln in ask(sock, "pending").splitlines() if ln.startswith("{")]
                for i in ids:
                    if not i:
                        continue
                    ans = ask(sock, f"approve {i}\nreason soak").strip()
                    out.write(json.dumps({"t": round(time.time(), 3), "id": i, "answer": ans[:120]}) + "\n")
                    out.flush()
            except (OSError, ValueError) as e:
                if alive(a.pid):
                    out.write(json.dumps({"t": round(time.time(), 3), "error": str(e)[:200]}) + "\n")
                    out.flush()
                    time.sleep(1)
            time.sleep(0.2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
