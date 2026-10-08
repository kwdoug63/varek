#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1250_latency.py — the client of tests/latency_v1250.sh.

  v1250_latency.py gai <name-format> <n>
      n getaddrinfo calls (IPv4, TCP), the name formatted with {i}
  v1250_latency.py raw <server> <port> <name-format> <n>
      n A questions over one connected UDP socket, without the C library
  v1250_latency.py connect <addr> <port> <n> [<name-format> <k>]
      resolve k names first (so the address carries them), then n blocking
      TCP connects one after another

Prints one line: "LAT n=<n> p50=<us> p90=<us> p99=<us>".
"""

import os
import socket
import struct
import sys
import time


def pct(v, q):
    v = sorted(v)
    return v[min(len(v) - 1, int(len(v) * q))]


def report(lat):
    us = [x // 1000 for x in lat]
    print(f"LAT n={len(us)} p50={pct(us, .5)} p90={pct(us, .9)} p99={pct(us, .99)}", flush=True)


def query(name, qid):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\0" + struct.pack(">HH", 1, 1)


def main():
    mode = sys.argv[1]
    lat = []
    if mode == "gai":
        fmt, n = sys.argv[2], int(sys.argv[3])
        for i in range(n):
            t = time.perf_counter_ns()
            socket.getaddrinfo(fmt.format(i=i), 443, socket.AF_INET, socket.SOCK_STREAM)
            lat.append(time.perf_counter_ns() - t)
    elif mode == "raw":
        server, port, fmt, n = sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.connect((server, port))
        for i in range(n):
            qid = i & 0xffff
            t = time.perf_counter_ns()
            s.send(query(fmt.format(i=i), qid))
            while True:
                r = s.recv(4096)
                if r[:2] == struct.pack(">H", qid):
                    break
            lat.append(time.perf_counter_ns() - t)
            if r[3] & 0x0f:
                sys.exit(f"v1250_latency: {fmt.format(i=i)}: rcode {r[3] & 0x0f}")
    elif mode == "connect":
        addr, port, n = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
        if len(sys.argv) > 6:
            fmt, k = sys.argv[5], int(sys.argv[6])
            for i in range(k):
                socket.getaddrinfo(fmt.format(i=i), port, socket.AF_INET, socket.SOCK_STREAM)
        for _ in range(n):
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t = time.perf_counter_ns()
            c.connect((addr, port))
            lat.append(time.perf_counter_ns() - t)
            c.close()
    else:
        sys.exit(__doc__)
    report(lat)


if __name__ == "__main__":
    main()
