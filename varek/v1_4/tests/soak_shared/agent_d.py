#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""agent_d.py — run D's agent in the shared soak (v1.42.0): approvals.

Each turn, one line of JSON on stdout:
  held      reads DIR/d/held, which a step_up rule (mode=hold) holds until
            soak_approver.py approves the runtime grant it proposes;
  standing  reads DIR/d/standing, which a step_up rule allows under the
            run's standing grant (signed, --grants), with no one asked;
  defer     every tenth turn, reads DIR/d/defer, which a defer rule holds
            until its marker (never written) or its timeout: refused.
The time each read took is recorded (ms). It runs for SECONDS, a turn every
INTERVAL.

  agent_d.py --interval 60 --seconds 86400 --dir /opt/varek-soak-shared
"""
import argparse
import json
import os
import sys
import time


def read(path):
    t = time.monotonic()
    try:
        with open(path) as fh:
            fh.read()
        ok = True
    except OSError as e:
        ok = e.errno
    return ok, round((time.monotonic() - t) * 1000, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--seconds", type=float, default=86400)
    ap.add_argument("--dir", required=True)
    a = ap.parse_args()
    d = os.path.join(a.dir, "d")
    print(json.dumps({"start": True, "ok": True, "uid": os.getuid()}), flush=True)
    end = time.time() + a.seconds
    n = 0
    while time.time() < end:
        t0 = time.time()
        r = {"t": round(t0, 3), "turn": n, "task": "approvals"}
        r["held"], r["held_ms"] = read(os.path.join(d, "held"))
        r["standing"], r["standing_ms"] = read(os.path.join(d, "standing"))
        if n % 10 == 9:
            r["defer"], r["defer_ms"] = read(os.path.join(d, "defer"))
        r["ok"] = r["held"] is True and r["standing"] is True and r.get("defer", 13) == 13
        print(json.dumps(r), flush=True)
        n += 1
        left = a.interval - (time.time() - t0)
        if left > 0 and time.time() + left < end:
            time.sleep(left)
        elif left > 0:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
