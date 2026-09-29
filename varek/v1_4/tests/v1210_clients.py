#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real Python clients for test_v1210.sh (run as the agent, under the Warden,
and natively for the latency comparison). One mode per invocation:

  requests-get URL [CAFILE]        requests.get; prints status and length
  raw-tls IP PORT SNI PATH [CAFILE] TLS to an address with SNI and a verified
                                   certificate for SNI; HTTP/1.1 GET
  unix PATH                        stream echo over a Unix socket
  udp IP PORT                      connected UDP echo (send, and sendmsg)
  bench-connect IP PORT N          socket.create_connection N times; prints
                                   BENCH python-connect ... percentiles (us)
  bench-requests URL N             requests.get N times on new connections
"""
import os
import socket
import ssl
import sys
import time


def pct(v):
    v = sorted(v)
    n = len(v)
    return (f"n={n} p50={v[n // 2]:.0f} p90={v[n * 9 // 10]:.0f} p99={v[min(n - 1, n * 99 // 100)]:.0f} "
            f"max={v[-1]:.0f} mean={sum(v) / n:.0f} (us)")


def main():
    mode, args = sys.argv[1], sys.argv[2:]
    if mode == "requests-get":
        import requests
        verify = args[1] if len(args) > 1 else True
        r = requests.get(args[0], timeout=10, verify=verify)
        print(f"CLIENT python-requests {args[0]} status={r.status_code} bytes={len(r.content)}")
    elif mode == "raw-tls":
        ip, port, sni, path = args[0], int(args[1]), args[2], args[3]
        ctx = ssl.create_default_context(cafile=args[4] if len(args) > 4 else None)
        with socket.create_connection((ip, port), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=sni) as t:
                t.sendall(f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n"
                          f"User-Agent: varek-test\r\n\r\n".encode())
                head = t.recv(64).split(b"\r\n", 1)[0].decode()
                print(f"CLIENT python-tls {sni}@{ip} {head} cert={t.getpeercert()['subject'][-1][0][1]}")
    elif mode == "unix":
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(args[0])
            s.sendall(b"ping")
            print(f"CLIENT python-unix {args[0]} echo={s.recv(16).decode()}")
    elif mode == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.connect((args[0], int(args[1])))
            s.send(b"one")
            a = s.recv(16)
            s.sendmsg([b"t", b"wo"])
            b = s.recv(16)
            print(f"CLIENT python-udp {args[0]}:{args[1]} echo={a.decode()},{b.decode()}")
    elif mode == "bench-connect":
        ip, port, n = args[0], int(args[1]), int(args[2])
        t = []
        for _ in range(n):
            a = time.perf_counter()
            s = socket.create_connection((ip, port), timeout=5)
            t.append((time.perf_counter() - a) * 1e6)
            s.close()
        print(f"BENCH python-connect {pct(t)}")
    elif mode == "bench-requests":
        import requests
        url, n = args[0], int(args[1])
        t = []
        for _ in range(n):
            a = time.perf_counter()
            requests.get(url, timeout=5, headers={"Connection": "close"}).content
            t.append((time.perf_counter() - a) * 1e6)
        print(f"BENCH python-requests {pct(t)}")
    else:
        sys.exit(f"unknown mode {mode}")


if __name__ == "__main__":
    main()
