#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_anchor_forward.py — send the Warden's anchor records off this host
(v1.16.2).

The Warden's --anchor writes one line per signed record (run_start, each
checkpoint, run_end). An anchor protects the verdict stream against whoever
holds it only if it lives where they cannot rewrite it; a file on the Warden's
own host does not protect against that host's root. This forwarder closes the
gap:

    warden --sign-key K --anchor /run/varek/anchor.fifo -- agent 2> verdicts.log
                                 │
            varek_anchor_forward.py --fifo /run/varek/anchor.fifo \\
                --spool /var/lib/varek/anchor-spool --ssh varek-anchor@anchor-host
                                 │  (each line within about a second)
            anchor host: an append-only file (tools/varek_anchor_receiver.sh)

  * It creates the FIFO (mode 600) and holds it open, so the Warden always
    finds a reader (the Warden refuses a FIFO anchor with none, and never
    blocks on it).
  * Every line it reads is first appended to a local spool, then sent. Sending
    is retried with backoff until it succeeds, so an outage of the anchor host
    delays anchoring but loses nothing; after a restart, whatever was not yet
    sent is sent. Delivery is at least once: a line may arrive twice, which the
    audit ignores.
  * Only well-formed anchor lines are forwarded (a JSON object with a 32-hex
    run id, a known event and a 64-hex chain value).

Destinations:
  --ssh USER@HOST   appends through SSH to an account that can only append
                    (set it up on the anchor host with
                    tools/varek_anchor_receiver.sh); use --ssh-key and
                    --known-hosts for a dedicated key and a pinned host key.
  --exec COMMAND    pipes each batch of lines to COMMAND (run with sh -c): any
                    sink that is not writable by this host's root, e.g. a
                    remote syslog or an object store with a retention lock.
                    COMMAND must exit 0 only once the lines are stored.

Run it as a service (tools/systemd/varek-anchor-forward.service). It logs to
stderr. SIGTERM: one last attempt to send, then exit.
"""

import argparse
import errno
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time

LINE = re.compile(rb'^\{"run":"[0-9a-f]{32}","event":"(run_start|checkpoint|run_end)",'
                  rb'"records":[0-9]+,"chain":"[0-9a-f]{64}"(,"sig":"[0-9a-f]{128}")?,'
                  rb'"timestamp_ns":[0-9]+\}$')
MAX_LINE = 1024
ROTATE_AT = 16 << 20            # rotate the spool once fully sent and this large
BATCH_MAX = 1 << 20


def log(msg):
    print(f"[anchor-forward] {msg}", file=sys.stderr, flush=True)


class Spool:
    """An append-only local copy of every accepted line, and the offset up to
    which it has been delivered (written atomically)."""

    def __init__(self, d):
        self.d = d
        os.makedirs(d, mode=0o700, exist_ok=True)
        st = os.stat(d)
        if st.st_mode & 0o022:
            raise SystemExit(f"varek_anchor_forward: spool {d} is writable by group or others")
        self.path = os.path.join(d, "anchor.spool")
        self.offp = os.path.join(d, "sent.offset")
        self.f = open(self.path, "ab")
        os.chmod(self.path, 0o600)

    def append(self, lines):
        self.f.write(b"".join(l + b"\n" for l in lines))
        self.f.flush()
        os.fsync(self.f.fileno())

    def sent(self):
        try:
            with open(self.offp) as fh:
                return int(fh.read().strip() or 0)
        except (OSError, ValueError):
            return 0

    def mark(self, off):
        tmp = self.offp + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(f"{off}\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.offp)

    def pending(self):
        off, size = self.sent(), os.path.getsize(self.path)
        if size <= off:
            return off, b""
        with open(self.path, "rb") as fh:
            fh.seek(off)
            data = fh.read(min(size - off, BATCH_MAX))
        cut = data.rfind(b"\n") + 1          # whole lines only
        return off, data[:cut]

    def maybe_rotate(self):
        size = os.path.getsize(self.path)
        if size >= ROTATE_AT and self.sent() >= size:
            self.f.close()
            os.replace(self.path, self.path + ".1")
            self.f = open(self.path, "ab")
            os.chmod(self.path, 0o600)
            self.mark(0)
            log(f"spool rotated ({size} bytes kept as anchor.spool.1)")


def open_fifo(path):
    try:
        st = os.lstat(path)
        if not stat.S_ISFIFO(st.st_mode):
            raise SystemExit(f"varek_anchor_forward: {path} exists and is not a FIFO")
    except FileNotFoundError:
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
        os.mkfifo(path, 0o600)
        log(f"created FIFO {path}")
    os.chmod(path, 0o600)
    # Read-write: the forwarder is always a reader and never sees EOF when a
    # Warden run ends.
    return os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)


def sender(a):
    if a.ssh:
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
               "-o", "ServerAliveInterval=15", "-T"]
        if a.ssh_key:
            cmd += ["-i", a.ssh_key, "-o", "IdentitiesOnly=yes"]
        if a.known_hosts:
            cmd += ["-o", f"UserKnownHostsFile={a.known_hosts}", "-o", "StrictHostKeyChecking=yes"]
        if a.ssh_port:
            cmd += ["-p", str(a.ssh_port)]
        cmd += [a.ssh]
        return cmd, a.ssh
    return ["sh", "-c", a.exec], "exec"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Send the Warden's anchor records off this host.")
    ap.add_argument("--fifo", required=True, help="the FIFO the Warden's --anchor names")
    ap.add_argument("--spool", required=True, help="local spool directory (root-only)")
    dest = ap.add_mutually_exclusive_group(required=True)
    dest.add_argument("--ssh", help="USER@HOST of an append-only receiver")
    dest.add_argument("--exec", help="command that stores lines read from stdin")
    ap.add_argument("--ssh-key", help="SSH private key for the receiver")
    ap.add_argument("--known-hosts", help="known_hosts file pinning the receiver's host key")
    ap.add_argument("--ssh-port", type=int)
    ap.add_argument("--interval", type=float, default=1.0, help="seconds between send attempts")
    ap.add_argument("--drain", action="store_true",
                    help="send what the spool holds, then exit (no FIFO; testing and catch-up)")
    a = ap.parse_args(argv)

    spool = Spool(a.spool)
    cmd, name = sender(a)
    stop = {"now": False}

    def on_term(sig, frm):
        stop["now"] = True
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    def try_send():
        off, data = spool.pending()
        if not data:
            return True
        try:
            p = subprocess.run(cmd, input=data, capture_output=True, timeout=60)
            ok = p.returncode == 0
            err = p.stderr.decode(errors="replace").strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            ok, err = False, str(e)
        if ok:
            spool.mark(off + len(data))
            n = data.count(b"\n")
            log(f"sent {n} line(s) to {name}")
            spool.maybe_rotate()
            return True
        log(f"send to {name} failed ({err[:200] or 'no message'}); "
            f"{os.path.getsize(spool.path) - off} byte(s) waiting, will retry")
        return False

    if a.drain:
        while True:
            ok = try_send()
            if not ok:
                return 1
            if not spool.pending()[1]:
                return 0

    fd = open_fifo(a.fifo)
    log(f"reading {a.fifo}, spooling to {spool.path}, sending to {name}")
    buf = b""
    backoff = a.interval
    next_try = 0.0
    while not stop["now"]:
        r, _, _ = select.select([fd], [], [], a.interval)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                chunk = b""
            buf += chunk
            *lines, buf = buf.split(b"\n")
            if len(buf) > MAX_LINE:
                log("discarding an over-long partial line")
                buf = b""
            good = []
            for l in lines:
                if LINE.match(l):
                    good.append(l)
                elif l.strip():
                    log(f"ignoring a line that is not an anchor record ({l[:60]!r})")
            if good:
                spool.append(good)
        now = time.monotonic()
        if now >= next_try:
            if try_send():
                backoff = a.interval
                next_try = now + a.interval
            else:
                backoff = min(backoff * 2, 60.0)
                next_try = now + backoff
    try_send()
    log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
