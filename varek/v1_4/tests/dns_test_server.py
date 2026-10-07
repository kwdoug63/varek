#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""dns_test_server.py — a small authoritative DNS server for the v1.24 tests.

It answers A, AAAA and CNAME from a zone file it re-reads on every query, so a
test can rotate answers while the Warden runs. UDP and TCP on 127.0.0.1.

  dns_test_server.py --port N --zone zone.json [--log queries.log] [--ready FILE]

zone.json maps a name (lowercase, no trailing dot) to its records:

  {"api.example.test": {"ttl": 30, "a": ["192.0.2.10"], "aaaa": ["2001:db8::10"]},
   "www.example.test": {"ttl": 60, "cname": "api.example.test"},
   "flaky.example.test": {"rcode": "servfail"},
   "slow.example.test": {"drop": true},
   "big.example.test": {"big": 1900}}

"big": N answers A over UDP with the truncation bit and nothing else, and over
TCP with N addresses (1900: about 61 KB, as one TCP message allows): the v1.24 review's oversized answer.

A name not in the zone is NXDOMAIN. Each query is appended to the log as
"<type> <name>" (the tests check which names reached the server).
"""

import argparse
import json
import os
import socket
import socketserver
import struct
import threading

T_A, T_CNAME, T_AAAA = 1, 5, 28
RCODES = {"noerror": 0, "servfail": 2, "nxdomain": 3, "refused": 5}


def read_name(msg, off):
    labels = []
    jumps = 0
    end = None
    while True:
        n = msg[off]
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | msg[off + 1]
            jumps += 1
            if jumps > 16:
                raise ValueError("loop")
            continue
        off += 1
        if n == 0:
            break
        labels.append(msg[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels), (end if end is not None else off)


def enc_name(name):
    out = b""
    for lab in name.split("."):
        if lab:
            out += bytes([len(lab)]) + lab.encode("ascii")
    return out + b"\0"


def rr(name, rtype, ttl, rdata):
    return enc_name(name) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


class State:
    def __init__(self, zone, log):
        self.zone_path = zone
        self.log_path = log
        self.lock = threading.Lock()

    def zone(self):
        try:
            with open(self.zone_path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def note(self, qtype, name):
        if not self.log_path:
            return
        with self.lock, open(self.log_path, "a") as fh:
            fh.write(f"{qtype} {name}\n")


def answer(state, msg, tcp=False):
    """The response bytes for one query, or None to drop it."""
    if len(msg) < 12:
        return None
    qid, flags, qd = struct.unpack("!HHH", msg[:6])
    if qd != 1:
        return None
    qname, off = read_name(msg, 12)
    qtype, _qclass = struct.unpack("!HH", msg[off:off + 4])
    question = msg[12:off + 4]
    key = qname.lower().rstrip(".")
    state.note(qtype, key)
    zone = state.zone()
    rcode = 0
    answers = []
    name = key
    seen = set()
    while True:
        ent = zone.get(name)
        if ent is None:
            if name == key:
                rcode = 3
            break
        if ent.get("drop"):
            return None
        if ent.get("rcode"):
            rcode = RCODES[ent["rcode"]]
            break
        if ent.get("big") and qtype == T_A:
            if not tcp:
                rflags = 0x8000 | 0x0400 | 0x0200 | (flags & 0x0100)     # TC: ask over TCP
                return struct.pack("!HHHHHH", qid, rflags, 1, 0, 0, 0) + question
            answers = [rr(name, T_A, 30, bytes([10, (i >> 16) & 255, (i >> 8) & 255, i & 255]))
                       for i in range(int(ent["big"]))]
            break
        ttl = int(ent.get("ttl", 30))
        if "cname" in ent and qtype != T_CNAME:
            if name in seen:
                break
            seen.add(name)
            answers.append(rr(name, T_CNAME, ttl, enc_name(ent["cname"])))
            name = ent["cname"]
            continue
        if qtype == T_A:
            answers += [rr(name, T_A, ttl, socket.inet_pton(socket.AF_INET, a)) for a in ent.get("a", [])]
        elif qtype == T_AAAA:
            answers += [rr(name, T_AAAA, ttl, socket.inet_pton(socket.AF_INET6, a))
                        for a in ent.get("aaaa", [])]
        break
    rflags = 0x8000 | 0x0400 | (flags & 0x0100) | rcode     # QR, AA, RD copied
    return struct.pack("!HHHHHH", qid, rflags, 1, len(answers), 0, 0) + question + b"".join(answers)


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            out = answer(self.server.state, data)
        except (ValueError, IndexError, struct.error):
            return
        if out is not None:
            sock.sendto(out, self.client_address)


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            hdr = self.request.recv(2)
            if len(hdr) < 2:
                return
            (n,) = struct.unpack("!H", hdr)
            data = b""
            while len(data) < n:
                chunk = self.request.recv(n - len(data))
                if not chunk:
                    return
                data += chunk
            out = answer(self.server.state, data, tcp=True)
            if out is not None and len(out) <= 65535:
                self.request.sendall(struct.pack("!H", len(out)) + out)
        except (OSError, ValueError, IndexError, struct.error):
            return


class ThreadedUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--zone", required=True)
    ap.add_argument("--log")
    ap.add_argument("--ready", help="file to create once the server is listening")
    a = ap.parse_args()
    state = State(a.zone, a.log)
    u = ThreadedUDP(("127.0.0.1", a.port), UDP)
    t = ThreadedTCP(("127.0.0.1", a.port), TCP)
    u.state = t.state = state
    threading.Thread(target=t.serve_forever, daemon=True).start()
    if a.ready:
        with open(a.ready, "w") as fh:
            fh.write(str(os.getpid()))
    u.serve_forever()


if __name__ == "__main__":
    main()
