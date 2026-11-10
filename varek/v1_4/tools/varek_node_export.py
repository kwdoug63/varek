#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""varek_node_export.py — v1.34 step 5 (docs/security/v1.34-kubernetes.md, D8):
a node's evidence as OCSF, for the cluster's collector.

The node agent writes each container's verdict stream to its directory
(--node-streams DIR: DIR/<container>.<supervisor>.jsonl), with the policy the
container ran under beside it (DIR/<container>.<supervisor>.policy); v1.36
(D9): past the chart's streams.rotateBytes the stream goes on in segments
beside it (.jsonl.2, .jsonl.3, ...), which its follower reads in turn. This
follows every stream there, those already present and each new one, and
exports each with tools/varek_ocsf.py --follow under its own policy copy (the
audit runs on each record as it comes, with the node's public key and anchor
if given); the events of all of them go to one output, a JSON object a line
(standard output by default: a DaemonSet's log, which the cluster's log
collector already takes).

A stream whose supervisor has gone without its run_end (a container refused
at its start, or a supervisor killed) is left once it stops growing and its
follower has had GRACE seconds to finish on its own. A stream that ends with
its run_end has its follower in the whole-stream audit, minutes for a day's
(step 9): it is given AUDIT_GRACE seconds.

Step 8 review: at most --max-followers streams are followed at once, the
others waiting their turn; a stream is taken once its policy copy is beside
it; with --state FILE, the streams done are written there, and not exported
again when the exporter starts again (a pod restarted, its node's streams
still there).

  varek_node_export.py --streams DIR [--output FILE] [--checker VDP_CERT_CHECK]
                       [--pubkey KEY.pub] [--anchor ANCHOR] [--device NODE]
                       [--state FILE] [--max-followers N] [--once]

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
QUIET_S = 5.0                     # a stream not growing this long, its supervisor gone: left ...
GRACE_S = 120.0                   # ... after its follower has had this long to end on its own
AUDIT_GRACE_S = 3600.0            # ... or this long, its run_end written: its follower is in the audit


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def last_segment(path):
    """v1.36 (D9): the stream's last segment (the node agent rotates a stream
    at the chart's streams.rotateBytes: NAME.jsonl, NAME.jsonl.2, ...)"""
    n = 1
    while os.path.exists(f"{path}.{n + 1}"):
        n += 1
    return path if n == 1 else f"{path}.{n}"


def ends_with_run_end(path):
    """True when the stream's last record is its run_end (in its last segment)"""
    path = last_segment(path)
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 65536))
            tail = f.read()
    except OSError:
        return False
    lines = tail.rstrip(b"\n").rsplit(b"\n", 1)
    return b'"event":"run_end"' in lines[-1]


class Exporter:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.out = open(args.output, "a", encoding="utf-8") if args.output else sys.stdout
        self.seen = set()            # taken: following, waiting, or done
        self.waiting = []            # names, in the order seen
        self.running = {}            # path -> (process, thread, supervisor's pid)
        self.gone_at = {}            # path -> when its supervisor was found gone, the stream quiet
        self.failed = 0
        self.state = None
        if args.state:
            self.load_state()

    def load_state(self):
        """the streams done before, those still in the directory kept"""
        try:
            done = [l.strip() for l in open(self.args.state, encoding="utf-8") if l.strip()]
        except FileNotFoundError:
            done = []
        try:
            present = set(os.listdir(self.args.streams))
        except OSError:
            present = set()
        keep = [n for n in done if n in present]
        self.seen.update(keep)
        tmp = self.args.state + ".new"
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(n + "\n" for n in keep)
        os.replace(tmp, self.args.state)
        self.state = open(self.args.state, "a", encoding="utf-8")

    def done(self, path):
        if self.state:
            with self.lock:
                self.state.write(os.path.basename(path) + "\n")
                self.state.flush()

    def emit(self, line):
        with self.lock:
            self.out.write(line if line.endswith("\n") else line + "\n")
            self.out.flush()

    def start(self, name):
        a = self.args
        m = STREAM.match(name)
        path = os.path.join(a.streams, name)
        policy = os.path.join(a.streams, m.group("base") + ".policy")
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
        present = set(names)
        for name in names:
            m = STREAM.match(name)
            # review (T3): taken once its policy is beside it (the node
            # agent copies it there as the stream starts)
            if m and name not in self.seen and m.group("base") + ".policy" in present:
                self.seen.add(name)
                self.waiting.append(name)
        while self.waiting and len(self.running) < self.args.max_followers:
            self.start(self.waiting.pop(0))

    def scan_waiting(self):
        while self.waiting and len(self.running) < self.args.max_followers:
            self.start(self.waiting.pop(0))

    def reap(self):
        now = time.time()
        for path, (p, t, pid) in list(self.running.items()):
            if p.poll() is not None:
                t.join()
                del self.running[path]
                self.gone_at.pop(path, None)
                self.done(path)
                continue
            try:
                quiet = now - os.stat(last_segment(path)).st_mtime
            except OSError:
                quiet = QUIET_S
            if alive(pid) or quiet < QUIET_S:
                self.gone_at.pop(path, None)
                continue
            # review (T2): its follower may be in its last audit (run_end
            # read): it is given time to end on its own first
            since = self.gone_at.setdefault(path, now)
            # step 9: a day's stream takes minutes to audit, past GRACE_S
            ended = ends_with_run_end(path)
            grace = self.args.audit_grace if ended else self.args.grace
            if now - since >= grace:
                p.terminate()                # no run_end will come, or its audit has not ended
                p.wait()
                t.join()
                del self.running[path]
                del self.gone_at[path]
                self.done(path)
                why = f"its audit did not end in {grace:g} s" if ended else "its supervisor ended without run_end"
                print(f"varek_node_export: {os.path.basename(path)}: {why}; left (not verified)", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--streams", required=True, help="the node agent's --node-streams directory")
    ap.add_argument("--output", "-o", help="where the events go (default: standard output)")
    ap.add_argument("--checker", help="tools/vdp_cert_check (for the audit)")
    ap.add_argument("--pubkey", help="the node's public key (the streams are signed)")
    ap.add_argument("--anchor", help="the node's anchor")
    ap.add_argument("--device", help="the node's name in each event's device")
    ap.add_argument("--state", help="the streams done are written here, and not exported again")
    ap.add_argument("--max-followers", type=int, default=64, help="streams followed at once (the others wait)")
    ap.add_argument("--grace", type=float, default=GRACE_S, help=argparse.SUPPRESS)
    ap.add_argument("--audit-grace", type=float, default=AUDIT_GRACE_S, help=argparse.SUPPRESS)
    ap.add_argument("--once", action="store_true", help="the streams present only, then return")
    args = ap.parse_args(argv)
    if args.max_followers < 1:
        ap.error("--max-followers takes 1 or more")
    ex = Exporter(args)
    ex.scan()
    while True:
        ex.reap()
        if args.once:
            ex.scan_waiting()
            if not ex.running and not ex.waiting:
                break
        time.sleep(1)
        if not args.once:
            ex.scan()
    return 1 if ex.failed else 0


if __name__ == "__main__":
    sys.exit(main())
