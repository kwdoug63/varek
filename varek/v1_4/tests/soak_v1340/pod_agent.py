#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""pod_agent.py — the agent of v1.34's 24-hour runs (soak.sh): a coding
agent's work in its project, as run B of the shared soak does it
(tests/soak_shared/build_agent.py), in a pod's container under the node
agent, with the pod's network (D5). Every <interval> seconds, one turn of
work, the same few file names over and over:

  writes src/mod_<i % 8>.py
  runs `python3 -B build.py`, which reads src/ and writes build/out.txt
  writes and removes scratch/s_<i % 4>
  reads README
  GET <allowed>, a service of the cluster the policy names (by its name)
  every fifth turn: git add -A and git commit

and prints one JSON line: {"t", "task": "work", "ok", "ms", "step"}. With
--probe-every N, the third turn and every N-th after it is a probe instead
({"t", "probe", "held", "result"}), in turn:

  shadow       reads /etc/shadow                              refused
  outside      writes a file in a volume the policy names not  refused
  own_program  launches a program it wrote (a copy of true)   refused
  denied_host  GET <denied>, a service the policy names not   not reached
  denied_ip    the same service by its address                not reached
  metadata     the cloud's instance metadata (169.254.169.254) not reached

A probe holds when the call is refused (EACCES, EPERM) or the name does not
resolve; the servers' own logs (servers.py) show whether anything reached
them.

  pod_agent.py --interval 60 --seconds 86400 --probe-every 10 --outside DIR
               --allowed URL --denied URL --denied-ip URL

It runs in its project directory (--project, default the working
directory), made on its first turn. Git and Python are run by their
absolute paths (no lookups the policy would refuse on PATH), and git's
configuration read from $HOME (the pod gives the project). Standard library
only.
"""
import argparse
import errno
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

PROBES = ("shadow", "outside", "own_program", "denied_host", "denied_ip", "metadata")
GIT = ["/usr/bin/git", "-c", "user.name=VAREK soak", "-c", "user.email=soak@example.test", "-c", "init.defaultBranch=main",
       "-c", "commit.gpgsign=false", "-c", "gc.auto=0"]
BUILD = """import glob
out = []
for f in sorted(glob.glob("src/*.py")):
    out.append(f + " " + str(len(open(f).read())))
open("build/out.txt", "w").write("\\n".join(out) + "\\n")
"""
REFUSED = (errno.EACCES, errno.EPERM)


def get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read(4096)


def work(a, i):
    rec = {"t": round(time.time(), 3), "task": "work"}
    t0 = time.time()
    step = "src"
    try:
        with open(f"src/mod_{i % 8}.py", "w") as fh:
            fh.write(f"# turn {i}\nVALUE = {i}\n")
        step = "build"
        subprocess.run([sys.executable, "-B", "build.py"], check=True, capture_output=True, timeout=60)
        if f"src/mod_{i % 8}.py" not in open("build/out.txt").read():
            raise RuntimeError("build/out.txt does not list the file written")
        step = "scratch"
        with open(f"scratch/s_{i % 4}", "w") as fh:
            fh.write("x" * 256)
        os.unlink(f"scratch/s_{i % 4}")
        step = "read"
        open("README").read()
        step = "http"
        t1 = time.time()
        status, body = get(f"{a.allowed}?turn={i}")
        if status != 200 or not body.startswith(b"allowed"):
            raise RuntimeError(f"the allowed service answered {status} {body[:40]!r}")
        rec["http_ms"] = int((time.time() - t1) * 1000)
        if i % 5 == 0:
            step = "git"
            subprocess.run(GIT + ["add", "-A"], check=True, capture_output=True, timeout=60)
            subprocess.run(GIT + ["commit", "-q", "-m", f"turn {i}"], check=True, capture_output=True, timeout=60)
            rec["commit"] = True
        rec.update(ok=True)
    except Exception as e:                      # noqa: BLE001 - every failure is recorded
        err = getattr(e, "stderr", b"") or b""
        rec.update(ok=False, step=step, error=(f"{type(e).__name__}: {e} " + err.decode("utf-8", "replace"))[:300])
    rec["ms"] = int((time.time() - t0) * 1000)
    return rec


def reached(url):
    """a GET that must not reach its server: held when refused or unresolved"""
    try:
        status, _ = get(url, timeout=5)
        return False, f"answered {status}"
    except urllib.error.HTTPError as e:
        return False, f"answered {e.code}"
    except urllib.error.URLError as e:
        r = e.reason
        if isinstance(r, socket.gaierror):
            return True, f"unresolved ({r.strerror})"
        if isinstance(r, OSError) and r.errno in REFUSED:
            return True, errno.errorcode[r.errno]
        return False, f"{type(r).__name__}: {r}"[:200]
    except OSError as e:
        if e.errno in REFUSED:
            return True, errno.errorcode[e.errno]
        return False, f"{type(e).__name__}: {e}"[:200]


def probe(a, kind):
    rec = {"t": round(time.time(), 3), "probe": kind}
    try:
        if kind == "shadow":
            open("/etc/shadow").read()
        elif kind == "outside":
            with open(os.path.join(a.outside, "w"), "w") as fh:
                fh.write("x")
        elif kind == "own_program":
            shutil.copy("/usr/bin/true", "mytrue")
            os.chmod("mytrue", 0o755)
            try:
                subprocess.run(["./mytrue"], check=True, timeout=30)
            finally:
                os.unlink("mytrue")
        else:
            url = {"denied_host": a.denied, "denied_ip": a.denied_ip,
                   "metadata": "http://169.254.169.254/latest/meta-data/"}[kind]
            held, why = reached(url)
            rec.update(held=held, result=why)
            return rec
        rec.update(held=False, result="done")
    except OSError as e:
        rec.update(held=e.errno in REFUSED, result=errno.errorcode.get(e.errno, str(e.errno)))
    except Exception as e:                      # noqa: BLE001
        rec.update(held=False, result=f"{type(e).__name__}: {e}"[:200])
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--seconds", type=float, default=86400)
    ap.add_argument("--probe-every", type=int, default=0)
    ap.add_argument("--outside", required=True)
    ap.add_argument("--allowed", required=True)
    ap.add_argument("--denied", required=True)
    ap.add_argument("--denied-ip", required=True)
    ap.add_argument("--project", default=".")
    a = ap.parse_args()
    start = {"t": round(time.time(), 3), "start": True, "uid": os.getuid(), "gid": os.getgid(),
             "host": socket.gethostname()}
    try:
        os.makedirs(a.project, exist_ok=True)
        os.chdir(a.project)
        for d in ("src", "build", "scratch"):
            os.makedirs(d, exist_ok=True)
        if not os.path.exists("build.py"):
            open("build.py", "w").write(BUILD)
        if not os.path.exists("README"):
            open("README", "w").write("the soak's project\n")
        if not os.path.isdir(".git"):
            subprocess.run(GIT + ["init", "-q"], check=True, capture_output=True, timeout=60)
        start["ok"] = True
    except Exception as e:                      # noqa: BLE001
        err = getattr(e, "stderr", b"") or b""
        start.update(ok=False, error=(f"{type(e).__name__}: {e} " + err.decode("utf-8", "replace"))[:300])
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
            rec = work(a, i)
        print(json.dumps(rec), flush=True)
        nxt += a.interval
        time.sleep(max(0.0, min(nxt, end) - time.time()))
    print(json.dumps({"t": round(time.time(), 3), "end": True, "turns": i}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
