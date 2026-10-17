#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""build_agent.py — runs B and C of the shared soak (soak.sh): a coding
agent's work in its project directory, under `varek run` with nothing set
up first (the baseline policy, B) or a dry run of a narrower policy (C).
Every <interval> seconds, one turn of work, the same few file names over and
over:

  writes src/mod_<i % 8>.py
  runs `python3 -B build.py`, which reads src/ and writes build/out.txt
  writes and removes scratch/s_<i % 4>
  reads README
  every fifth turn: git add -A and git commit

and prints one JSON line: {"t", "task": "work", "ok", "ms", "step"}. With
--probe-every N, the third turn and every N-th after it is a probe instead
({"t", "probe", "held"}):

  shadow       reads /etc/shadow                         EACCES
  outside      writes a file outside the project         EACCES
  own_program  launches a program it wrote (a copy of true)  EACCES

  build_agent.py --interval 60 --seconds 86400 [--probe-every 10] --outside DIR

It runs in the project directory (made by soak.sh, the agent's own).
Standard library only.
"""
import argparse
import json
import os
import shutil
import subprocess
import time

PROBES = ("shadow", "outside", "own_program")
GIT = ["git", "-c", "user.name=VAREK soak", "-c", "user.email=soak@example.test", "-c", "init.defaultBranch=main",
       "-c", "commit.gpgsign=false"]
BUILD = """import glob
out = []
for f in sorted(glob.glob("src/*.py")):
    out.append(f + " " + str(len(open(f).read())))
open("build/out.txt", "w").write("\\n".join(out) + "\\n")
"""


def work(i):
    rec = {"t": round(time.time(), 3), "task": "work"}
    t0 = time.time()
    step = "src"
    try:
        with open(f"src/mod_{i % 8}.py", "w") as fh:
            fh.write(f"# turn {i}\nVALUE = {i}\n")
        step = "build"
        subprocess.run(["python3", "-B", "build.py"], check=True, capture_output=True, timeout=60)
        if f"src/mod_{i % 8}.py" not in open("build/out.txt").read():
            raise RuntimeError("build/out.txt does not list the file written")
        step = "scratch"
        with open(f"scratch/s_{i % 4}", "w") as fh:
            fh.write("x" * 256)
        os.unlink(f"scratch/s_{i % 4}")
        step = "read"
        open("README").read()
        if i % 5 == 0:
            step = "git"
            subprocess.run(GIT + ["add", "-A"], check=True, capture_output=True, timeout=60)
            subprocess.run(GIT + ["commit", "-q", "-m", f"turn {i}"], check=True, capture_output=True, timeout=60)
        rec.update(ok=True)
    except Exception as e:                      # noqa: BLE001 - every failure is recorded
        err = getattr(e, "stderr", b"") or b""
        rec.update(ok=False, step=step, error=(f"{type(e).__name__}: {e} " + err.decode("utf-8", "replace"))[:300])
    rec["ms"] = int((time.time() - t0) * 1000)
    return rec


def probe(a, kind):
    rec = {"t": round(time.time(), 3), "probe": kind}
    try:
        if kind == "shadow":
            open("/etc/shadow").read()
        elif kind == "outside":
            with open(os.path.join(a.outside, "w"), "w") as fh:
                fh.write("x")
        else:
            shutil.copy("/usr/bin/true", "mytrue")
            os.chmod("mytrue", 0o755)
            try:
                subprocess.run(["./mytrue"], check=True, timeout=30)
            finally:
                os.unlink("mytrue")
        rec.update(held=False, result="done")
    except PermissionError:
        rec.update(held=True, result="EACCES")
    except Exception as e:                      # noqa: BLE001
        rec.update(held=False, result=f"{type(e).__name__}: {e}"[:200])
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--seconds", type=float, default=86400)
    ap.add_argument("--probe-every", type=int, default=0)
    ap.add_argument("--outside", required=True)
    a = ap.parse_args()
    start = {"t": round(time.time(), 3), "start": True, "cwd": os.getcwd(), "uid": os.getuid()}
    try:
        for d in ("src", "build", "scratch"):
            os.makedirs(d, exist_ok=True)
        if not os.path.exists("build.py"):
            open("build.py", "w").write(BUILD)
        if not os.path.isdir(".git"):
            subprocess.run(GIT + ["init", "-q"], check=True, capture_output=True, timeout=60)
        start["ok"] = True
    except Exception as e:                      # noqa: BLE001
        start.update(ok=False, error=f"{type(e).__name__}: {e}"[:200])
    print(json.dumps(start), flush=True)
    end = time.time() + a.seconds
    nxt = time.time()
    i = p = 0
    while time.time() < end:
        i += 1
        if a.probe_every and i >= 3 and (i - 3) % a.probe_every == 0:
            rec = probe(a, PROBES[p % len(PROBES)])
            p += 1
        else:
            rec = work(i)
        print(json.dumps(rec), flush=True)
        nxt += a.interval
        time.sleep(max(0.0, min(nxt, end) - time.time()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
