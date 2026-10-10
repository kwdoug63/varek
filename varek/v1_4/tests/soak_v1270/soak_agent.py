# SPDX-License-Identifier: MIT
"""soak_agent.py — the agent of the v1.27 soak (soak.sh). Once every
--interval seconds, for --seconds, it runs one task in turn, timing each and
printing one JSON line on stdout:

  git      git --version, then git hash-object of a file
  python   python3 -c 'print(sum(range(1000)))'
  compile  cc -o <work>/t <work>/t.c (only with --cc): cc, cc1, as, collect2, ld

and every tenth turn, from the third, a probe the policy must refuse, three
kinds in turn:

  unlisted  /usr/bin/false, which no rule allows (default_deny_unknown)
  denied    /usr/bin/env, which a deny rule refuses (policy_match)
  written   a program the agent writes now into <work>/run/, whose names a
            rule allows but which is not in the launch set (exec_not_in_ruleset)
"""
import argparse
import json
import os
import subprocess
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("--interval", type=float, default=60)
ap.add_argument("--seconds", type=float, required=True)
ap.add_argument("--work", required=True)
ap.add_argument("--cc", action="store_true")
a = ap.parse_args()

tasks = ["git", "python"] + (["compile"] if a.cc else [])
probes = ["unlisted", "denied", "written"]


def run(argv):
    t0 = time.monotonic()
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=60, env={"PATH": "/usr/bin:/bin"})
        return r.returncode, (r.stdout + r.stderr).strip()[:160], None, (time.monotonic() - t0) * 1000
    except OSError as e:
        return None, "", e.errno, (time.monotonic() - t0) * 1000
    except subprocess.TimeoutExpired:
        return None, "timeout", None, (time.monotonic() - t0) * 1000


def task(kind):
    if kind == "git":
        rc, out, err, ms = run(["/usr/bin/git", "--version"])
        if rc == 0:
            rc2, out2, err2, ms2 = run(["/usr/bin/git", "hash-object", a.work + "/t.c"])
            rc, out, err, ms = (rc2, out + " " + out2, err2, ms + ms2)
        return rc, out, err, ms
    if kind == "python":
        return run(["/usr/bin/python3", "-c", "print(sum(range(1000)))"])
    return run(["/usr/bin/cc", "-o", a.work + "/t", a.work + "/t.c"])


def probe(kind, n):
    if kind == "unlisted":
        return "/usr/bin/false", run(["/usr/bin/false"])
    if kind == "denied":
        return "/usr/bin/env", run(["/usr/bin/env"])
    p = f"{a.work}/run/w{n}"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o755)
    with open("/usr/bin/true", "rb") as src:
        os.write(fd, src.read())
    os.close(fd)
    return p, run([p])


end = time.time() + a.seconds
i = nt = npb = 0
while True:
    start = time.time()
    if start >= end:
        break
    rec = {"t": round(start, 3), "i": i}
    if i >= 2 and (i - 2) % 10 == 0:
        kind = probes[npb % len(probes)]
        path, (rc, out, err, ms) = probe(kind, npb)
        npb += 1
        rec.update(probe=kind, path=path, rc=rc, errno=err, ms=round(ms, 1), refused=err == 13)
    else:
        kind = tasks[nt % len(tasks)]
        nt += 1
        rc, out, err, ms = task(kind)
        rec.update(task=kind, rc=rc, errno=err, out=out, ms=round(ms, 1), ok=rc == 0)
    print(json.dumps(rec), flush=True)
    i += 1
    time.sleep(max(0.0, a.interval - (time.time() - start)))
