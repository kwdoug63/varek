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
    blocks on it), and holds an exclusive lock on FIFO.lock while it runs,
    which the Warden and the preflight test to know it is alive.
  * Every line it reads is first appended to a local spool, then sent. Sending
    is retried with backoff until it succeeds, so an outage of the anchor host
    delays anchoring but loses nothing already read; after a restart, whatever was not yet
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
import fcntl
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
                  rb'"records":(0|[1-9][0-9]{0,19}),"chain":"[0-9a-f]{64}"(,"sig":"[0-9a-f]{128}")?,'
                  rb'"timestamp_ns":(0|[1-9][0-9]{0,18})\}$')
MAX_LINE = 1024
ROTATE_AT = 16 << 20            # rotate the spool once fully sent and this large
BATCH_MAX = 1 << 20


def log(msg):
    print(f"[anchor-forward] {msg}", file=sys.stderr, flush=True)


def _own_dir(d):
    """d is a real directory (not a symlink) owned by this user, not writable
    by group or others; created 0700 if missing."""
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        os.makedirs(d, mode=0o700, exist_ok=True)
        st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode):
        raise SystemExit(f"varek_anchor_forward: {d} is not a directory (or is a symlink)")
    if st.st_uid != os.geteuid():
        raise SystemExit(f"varek_anchor_forward: {d} belongs to uid {st.st_uid}, not to this user")
    if st.st_mode & 0o022:
        raise SystemExit(f"varek_anchor_forward: {d} is writable by group or others")


def _open_nofollow(path, flags, mode=0o600):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
        os.close(fd)
        raise SystemExit(f"varek_anchor_forward: {path} is not a regular file owned by this user")
    os.fchmod(fd, 0o600)
    return fd


class Spool:
    """An append-only local copy of every accepted line, and the offset up to
    which it has been delivered (written atomically). Files are opened without
    following symlinks, in a directory only this user can write."""

    def __init__(self, d):
        self.d = d
        _own_dir(d)
        self.path = os.path.join(d, "anchor.spool")
        self.offp = os.path.join(d, "sent.offset")
        self.fd = _open_nofollow(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        self.held = []                   # lines read but not yet written (disk full)

    def append(self, lines):
        """Write lines (plus any held back earlier). On a write error (disk
        full), cut the spool back to where it was, so no torn line remains,
        keep the lines in memory, and report False; the caller retries and
        stops reading the FIFO meanwhile (the Warden's hold keeps the rest in
        the pipe)."""
        self.held.extend(lines)
        if not self.held:
            return True
        data = b"".join(l + b"\n" for l in self.held)
        start = os.fstat(self.fd).st_size
        try:
            n = 0
            while n < len(data):
                n += os.write(self.fd, data[n:])
            os.fsync(self.fd)
        except OSError as e:
            try:
                os.ftruncate(self.fd, start)
            except OSError:
                pass
            log(f"cannot write the spool ({e.strerror}); {len(self.held)} line(s) held in memory, "
                f"FIFO reads paused")
            return False
        self.held = []
        return True

    def sent(self):
        try:
            fd = _open_nofollow(self.offp, os.O_RDONLY)
            with os.fdopen(fd) as fh:
                off = int(fh.read().strip() or 0)
        except (OSError, ValueError):
            return 0
        size = os.path.getsize(self.path)
        if off > size:
            log(f"sent.offset {off} is past the spool's end ({size}): resending from the start")
            return 0
        return off

    def mark(self, off):
        tmp = self.offp + ".tmp"
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        fd = _open_nofollow(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(fd, "w") as fh:
            fh.write(f"{off}\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.offp)

    def pending(self):
        off, size = self.sent(), os.path.getsize(self.path)
        if size <= off:
            return off, b""
        fd = _open_nofollow(self.path, os.O_RDONLY)
        with os.fdopen(fd, "rb") as fh:
            fh.seek(off)
            data = fh.read(min(size - off, BATCH_MAX))
        cut = data.rfind(b"\n") + 1          # whole lines only
        return off, data[:cut]

    def maybe_rotate(self):
        size = os.path.getsize(self.path)
        if size >= ROTATE_AT and self.sent() >= size and not self.held:
            # Offset first: a crash after it resends (duplicates), never skips.
            self.mark(0)
            os.close(self.fd)
            os.replace(self.path, self.path + ".1")
            self.fd = _open_nofollow(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
            log(f"spool rotated ({size} bytes kept as anchor.spool.1)")


def open_fifo(path):
    _own_dir(os.path.dirname(os.path.abspath(path)))
    try:
        st = os.lstat(path)
        if not stat.S_ISFIFO(st.st_mode):
            raise SystemExit(f"varek_anchor_forward: {path} exists and is not a FIFO")
    except FileNotFoundError:
        os.mkfifo(path, 0o600)
        log(f"created FIFO {path}")
    # Read-write: the forwarder is always a reader and never sees EOF when a
    # Warden run ends. The FIFO must be this user's own.
    fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISFIFO(st.st_mode) or st.st_uid != os.geteuid():
        os.close(fd)
        raise SystemExit(f"varek_anchor_forward: {path} is not a FIFO owned by this user")
    os.fchmod(fd, 0o600)
    # A lock held for the forwarder's lifetime: the Warden and the preflight
    # test it to tell a live forwarder from a FIFO merely held open (another
    # Warden holds its anchor FIFO read-write).
    lk = os.open(path + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit(f"varek_anchor_forward: another forwarder holds {path}.lock")
    return fd, lk


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

    fd, _lock = open_fifo(a.fifo)
    log(f"reading {a.fifo}, spooling to {spool.path}, sending to {name}")
    buf = b""
    backoff = a.interval
    next_try = 0.0
    while not stop["now"]:
        # While lines are held back by a full disk, leave the rest in the pipe.
        r, _, _ = select.select([] if spool.held else [fd], [], [], a.interval)
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
        elif spool.held:
            spool.append([])             # retry lines held back by a full disk
        now = time.monotonic()
        if now >= next_try:
            if try_send():
                backoff = a.interval
                next_try = now + a.interval
            else:
                backoff = min(backoff * 2, 60.0)
                next_try = now + backoff
    if spool.held:
        spool.append([])
    if spool.held:
        log(f"stopping with {len(spool.held)} line(s) that could not be written to the spool: "
            f"they are lost; the audit will report them as never anchored")
    try_send()
    log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
