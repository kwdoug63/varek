#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""pod_agent.py — the agent of the 24-hour runs (soak.sh): a coding agent's
work in its project, as run B of the shared soak does it
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
               (with --ship-gate, port 80 the egress proxy's: its own
               refusal, a 403 with no body, holds too)

A probe holds when the call is refused (EACCES, EPERM) or the name does not
resolve; the servers' own logs (servers.py) show whether anything reached
them.

--ship-gate (v1.36 step 12, policy.txt and plan.txt): the run is held to
its plan, and a turn also
  runs the build as the policy's sub-agent `builder` (/usr/local/bin/python3,
    a launch of its own group; the agent runs as python3.12)
  writes notes/n_<i % 4> and has the confined MCP server `files`
    (/usr/bin/head, launched with an environment of its own) read it back
  GETs <allowed>turn/<i> over HTTPS with the soak's token's placeholder
    ($VAREK_CRED_SOAK_TOKEN) in X-Varek-Soak, which the egress proxy swaps
    for the token: the server answers whether it got the token
and four more probes, in turn after the six:

  outside_plan          reads /etc/hostname, which the policy allows and
                        the plan does not name                      refused
  builder_outside_plan  the sub-agent reads it                      refused
  server_outside        the MCP server reads /etc/passwd, the
                        agent's to read, not the server's            refused
  placeholder_elsewhere GET <allowed>plain/<i> with the placeholder,
                        on a request rule naming no credential: the
                        server gets the placeholder, not the token  held

The container's first process cannot launch a sub-agent under the node
agent (subagent_first_process): with --ship-gate it forks at once, works in
the child and waits for it. --volume RATE, the ship gate's large stream:
no turns; RATE reads of a file of its project a second (each a record),
and a line a minute ({"t", "task": "volume", "opens", "ok"}).

  pod_agent.py --interval 60 --seconds 86400 --probe-every 10 --outside DIR
               --allowed URL --denied URL --denied-ip URL [--ship-gate]
               [--volume RATE]

It runs in its project directory (--project, default the working
directory), made on its first turn. Git and Python are run by their
absolute paths (no lookups the policy would refuse on PATH), and git's
configuration read from $HOME (the pod gives the project). Standard library
only.
"""
import argparse
import errno
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

PROBES = ("shadow", "outside", "own_program", "denied_host", "denied_ip", "metadata")
GATE_PROBES = PROBES + ("outside_plan", "builder_outside_plan", "server_outside", "placeholder_elsewhere")
GIT = ["/usr/bin/git", "-c", "user.name=VAREK soak", "-c", "user.email=soak@example.test", "-c", "init.defaultBranch=main",
       "-c", "commit.gpgsign=false", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
BUILDER = "/usr/local/bin/python3"           # the sub-agent's name (policy.txt: subagent=builder)
SERVER = "/usr/bin/head"                     # the confined MCP server (mcp server files)
CRED_ENV = "VAREK_CRED_SOAK_TOKEN"           # the plugin's placeholder for soak_token
CRED_HEADER = "X-Varek-Soak"
# the MCP server's environment: a confined subject launched with a variable
# that can name code (GIT_*, PYTHON*, LD_*, ...) is refused (subagent_env), and
# the agent's has several (the image's PYTHON_VERSION, the pod's
# GIT_CONFIG_NOSYSTEM): it is launched with this alone
SERVER_ENV = {"PATH": "/usr/bin:/bin"}
BUILD = """import glob, sys
if sys.argv[1:] == ["--probe"]:              # the sub-agent's probe: a file outside the plan
    try:
        open("/etc/hostname").read()
        print("read")
        sys.exit(3)
    except OSError as e:
        print("refused", e.errno)
        sys.exit(0)
out = []
for f in sorted(glob.glob("src/*.py")):
    out.append(f + " " + str(len(open(f).read())))
open("build/out.txt", "w").write("\\n".join(out) + "\\n")
"""
REFUSED = (errno.EACCES, errno.EPERM)


def get(url, timeout=10, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(4096)


def placeholder():
    ph = os.environ.get(CRED_ENV, "")
    if not ph:
        raise RuntimeError(f"no {CRED_ENV} in the environment (the plugin's placeholder)")
    return ph


def work(a, i):
    rec = {"t": round(time.time(), 3), "task": "work"}
    t0 = time.time()
    step = "src"
    try:
        with open(f"src/mod_{i % 8}.py", "w") as fh:
            fh.write(f"# turn {i}\nVALUE = {i}\n")
        step = "build"
        py = BUILDER if a.ship_gate else sys.executable
        subprocess.run([py, "-B", "build.py"], check=True, capture_output=True, timeout=60)
        if f"src/mod_{i % 8}.py" not in open("build/out.txt").read():
            raise RuntimeError("build/out.txt does not list the file written")
        step = "scratch"
        with open(f"scratch/s_{i % 4}", "w") as fh:
            fh.write("x" * 256)
        os.unlink(f"scratch/s_{i % 4}")
        step = "read"
        open("README").read()
        if a.ship_gate:
            step = "server"
            with open(f"notes/n_{i % 4}", "w") as fh:
                fh.write(f"turn {i}\n")
            r = subprocess.run([SERVER, "-n", "1", f"notes/n_{i % 4}"], check=True, capture_output=True, timeout=60,
                               env=SERVER_ENV)
            if r.stdout != f"turn {i}\n".encode():
                raise RuntimeError(f"the MCP server read {r.stdout[:40]!r}, not the note written")
        step = "http"
        t1 = time.time()
        if a.ship_gate:
            status, body = get(f"{a.allowed}turn/{i}", headers={CRED_HEADER: placeholder()})
            if status != 200 or not body.startswith(b"allowed") or b" cred=value" not in body:
                raise RuntimeError(f"the allowed service answered {status} {body[:80]!r} (not the token)")
        else:
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


def reached(url, proxied=False):
    """a GET that must not reach its server: held when refused or unresolved,
    or (proxied: on a port the egress proxy takes, in inspecting mode) when
    the proxy itself answers no, a 403 with no body and the connection closed"""
    try:
        status, _ = get(url, timeout=5)
        return False, f"answered {status}"
    except urllib.error.HTTPError as e:
        body = e.read(64)
        if proxied and e.code == 403 and not body and (e.headers.get("Connection") or "").lower() == "close":
            return True, "refused by the egress proxy (403, no body)"
        return False, f"answered {e.code} {body[:40]!r}"
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


def probe(a, kind, i):
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
        elif kind == "outside_plan":
            open("/etc/hostname").read()
        elif kind == "builder_outside_plan":
            r = subprocess.run([BUILDER, "-B", "build.py", "--probe"], capture_output=True, timeout=60)
            out = r.stdout.decode("utf-8", "replace").split()
            refused = r.returncode == 0 and out[:1] == ["refused"] and len(out) > 1 and out[1].isdigit()
            code = int(out[1]) if refused else None
            rec.update(held=refused and code in REFUSED,
                       result=errno.errorcode.get(code, str(code)) if refused else
                       f"exit {r.returncode} {r.stdout[:60]!r} {r.stderr[-120:]!r}")
            return rec
        elif kind == "server_outside":
            r = subprocess.run([SERVER, "-n", "1", "/etc/passwd"], capture_output=True, timeout=60, env=SERVER_ENV)
            held = r.returncode != 0 and not r.stdout and (b"Permission denied" in r.stderr or
                                                           b"Operation not permitted" in r.stderr)
            rec.update(held=held, result=f"exit {r.returncode} {r.stderr.decode('utf-8', 'replace').strip()[-120:]}")
            return rec
        elif kind == "placeholder_elsewhere":
            ph = placeholder()
            status, body = get(f"{a.allowed}plain/{i}", headers={CRED_HEADER: ph})
            want = "sha=" + hashlib.sha256(ph.encode()).hexdigest()
            words = body.decode("utf-8", "replace").split()
            rec.update(held=status == 200 and "cred=other" in words and want in words,
                       result=f"answered {status} {' '.join(words[:2])}" + (" (the placeholder)" if want in words else ""))
            return rec
        else:
            url = {"denied_host": a.denied, "denied_ip": a.denied_ip,
                   "metadata": "http://169.254.169.254/latest/meta-data/"}[kind]
            # v1.36 step 12: under inspecting mode port 80 is the proxy's (the metadata service's)
            held, why = reached(url, proxied=a.ship_gate and kind == "metadata")
            rec.update(held=held, result=why)
            return rec
        rec.update(held=False, result="done")
    except OSError as e:
        rec.update(held=e.errno in REFUSED, result=errno.errorcode.get(e.errno, str(e.errno)))
    except Exception as e:                      # noqa: BLE001
        rec.update(held=False, result=f"{type(e).__name__}: {e}"[:200])
    return rec


def volume(a, end):
    """--volume: RATE reads a second of one file of the project, a line a minute"""
    path = "volume.txt"
    with open(path, "w") as fh:
        fh.write("the ship gate's large stream\n")
    total = bad = n = 0
    last = time.time()
    nxt = time.time()
    while time.time() < end:
        for _ in range(a.volume):
            try:
                with open(path) as fh:
                    fh.read()
                n += 1
            except OSError:
                bad += 1
        nxt += 1.0
        if time.time() - last >= 60:
            print(json.dumps({"t": round(time.time(), 3), "task": "volume", "opens": n, "ok": bad == 0}), flush=True)
            total += n
            n, last = 0, time.time()
        time.sleep(max(0.0, min(nxt, end) - time.time()))
    total += n
    if n:
        print(json.dumps({"t": round(time.time(), 3), "task": "volume", "opens": n, "ok": bad == 0}), flush=True)
    return total, bad


def forked():
    """--ship-gate: the work in a child, the container's first process
    waiting for it (and passing it the signals the kubelet sends)"""
    pid = os.fork()
    if pid == 0:
        return
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, lambda n, _f: os.kill(pid, n))
    while True:
        try:
            _, st = os.waitpid(pid, 0)
            break
        except InterruptedError:
            continue
    os._exit(os.waitstatus_to_exitcode(st) & 0xff)


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
    ap.add_argument("--ship-gate", action="store_true")
    ap.add_argument("--volume", type=int, default=0)
    a = ap.parse_args()
    if a.ship_gate:
        forked()
    start = {"t": round(time.time(), 3), "start": True, "uid": os.getuid(), "gid": os.getgid(),
             "host": socket.gethostname(), "pid": os.getpid()}
    try:
        os.makedirs(a.project, exist_ok=True)
        os.chdir(a.project)
        for d in ("src", "build", "scratch") + (("notes",) if a.ship_gate else ()):
            os.makedirs(d, exist_ok=True)
        if not os.path.exists("build.py"):
            open("build.py", "w").write(BUILD)
        if not os.path.exists("README"):
            open("README", "w").write("the soak's project\n")
        if not a.volume and not os.path.isdir(".git"):
            subprocess.run(GIT + ["init", "-q"], check=True, capture_output=True, timeout=60)
        start["ok"] = True
    except Exception as e:                      # noqa: BLE001
        err = getattr(e, "stderr", b"") or b""
        start.update(ok=False, error=(f"{type(e).__name__}: {e} " + err.decode("utf-8", "replace"))[:300])
    print(json.dumps(start), flush=True)
    end = time.time() + a.seconds
    if a.volume:
        total, bad = volume(a, end)
        print(json.dumps({"t": round(time.time(), 3), "end": True, "opens": total, "failed": bad}), flush=True)
        return 0
    probes = GATE_PROBES if a.ship_gate else PROBES
    nxt = time.time()
    i = p = 0
    while time.time() < end:
        i += 1
        if a.probe_every and i >= 3 and (i - 3) % a.probe_every == 0:
            rec = probe(a, probes[p % len(probes)], i)
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
