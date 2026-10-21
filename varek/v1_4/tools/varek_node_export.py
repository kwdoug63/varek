#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""varek_node_export.py — v1.34 step 5 (docs/security/v1.34-kubernetes.md, D8):
a node's evidence as OCSF, for the cluster's collector.

The node agent writes each container's verdict stream to its directory
(--node-streams DIR: DIR/<container>.<supervisor>.jsonl), with the policy the
container ran under beside it (DIR/<container>.<supervisor>.policy). This
follows every stream there, those already present and each new one, and
exports each with tools/varek_ocsf.py --follow under its own policy copy (the
audit runs on each record as it comes, with the node's public key and anchor
if given); the events of all of them go to one output, a JSON object a line
(standard output by default: a DaemonSet's log, which the cluster's log
collector already takes).

A stream whose supervisor has gone without its run_end (a container refused
at its start, or a supervisor killed) is left once it stops growing.

  varek_node_export.py --streams DIR [--output FILE] [--checker VDP_CERT_CHECK]
                       [--pubkey KEY.pub] [--anchor ANCHOR] [--device NODE]
                       [--once]

--once exports the streams present and returns when each is done (for a test,
or a node's last pass)."""
import argparse
import os
import re
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STREAM = re.compile(r"^(?P<base>[^/]+\.(?P<pid>\d+))\.jsonl$")
QUIET_S = 5.0                     # a stream not growing this long, its supervisor gone: left


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class Exporter:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.out = open(args.output, "a", encoding="utf-8") if args.output else sys.stdout
        self.seen = set()
        self.running = {}            # path -> (process, thread)
        self.failed = 0

    def emit(self, line):
        with self.lock:
            self.out.write(line if line.endswith("\n") else line + "\n")
            self.out.flush()

    def start(self, name):
        a = self.args
        m = STREAM.match(name)
        path = os.path.join(a.streams, name)
        policy = os.path.join(a.streams, m.group("base") + ".policy")
        if not os.path.isfile(policy):
            print(f"varek_node_export: {name}: no policy beside it ({policy}); not exported", file=sys.stderr)
            return
        cmd = [sys.executable, os.path.join(HERE, "varek_ocsf.py"), "--follow", path, "--policy", policy]
        for flag, val in (("--checker", a.checker), ("--pubkey", a.pubkey), ("--anchor", a.anchor),
                          ("--device", a.device)):
            if val:
                cmd += [flag, val]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def pump():
            for line in p.stdout:
                if line.strip():
                    self.emit(line)
            err = p.stderr.read()
            if p.wait() != 0:
                self.failed += 1
                print(f"varek_node_export: {name}: {err.strip().splitlines()[-1] if err.strip() else 'failed'}",
                      file=sys.stderr)
        t = threading.Thread(target=pump, daemon=True)
        t.start()
        self.running[path] = (p, t, int(m.group("pid")))

    def scan(self):
        try:
            names = sorted(os.listdir(self.args.streams))
        except OSError as e:
            print(f"varek_node_export: {self.args.streams}: {e}", file=sys.stderr)
            return
        for name in names:
            if STREAM.match(name) and name not in self.seen:
                self.seen.add(name)
                self.start(name)

    def reap(self):
        now = time.time()
        for path, (p, t, pid) in list(self.running.items()):
            if p.poll() is not None:
                t.join()
                del self.running[path]
                continue
            try:
                quiet = now - os.stat(path).st_mtime
            except OSError:
                quiet = QUIET_S
            if not alive(pid) and quiet >= QUIET_S:
                p.terminate()                # no run_end will come: its supervisor is gone
                p.wait()
                t.join()
                del self.running[path]
                print(f"varek_node_export: {os.path.basename(path)}: its supervisor ended without run_end; left",
                      file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--streams", required=True, help="the node agent's --node-streams directory")
    ap.add_argument("--output", "-o", help="where the events go (default: standard output)")
    ap.add_argument("--checker", help="tools/vdp_cert_check (for the audit)")
    ap.add_argument("--pubkey", help="the node's public key (the streams are signed)")
    ap.add_argument("--anchor", help="the node's anchor")
    ap.add_argument("--device", help="the node's name in each event's device")
    ap.add_argument("--once", action="store_true", help="the streams present only, then return")
    args = ap.parse_args(argv)
    ex = Exporter(args)
    ex.scan()
    while True:
        ex.reap()
        if args.once and not ex.running:
            break
        time.sleep(1)
        if not args.once:
            ex.scan()
    return 1 if ex.failed else 0


if __name__ == "__main__":
    sys.exit(main())
