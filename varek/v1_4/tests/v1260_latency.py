#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1260_latency.py — the client of tests/latency_v1260.sh.

  v1260_latency.py tls <where> <port> <sni> <n>
      n HTTPS requests one after another: connect, TLS handshake with that
      SNI, GET, read the reply to its end
  v1260_latency.py http <where> <port> <host> <n>
      n HTTP/1.1 requests one after another (Host as given)
  v1260_latency.py connect <where> <port> <n>
      n TCP connects one after another, closed at once

<where> is resolved once, before the timing (a name through the C library:
under the Warden with the proxy on, its synthetic address). Prints one line:
"LAT n=<n> p50=<us> p90=<us> p99=<us> failed=<k>".
"""

import socket
import ssl
import sys
import time


def pct(v, q):
    v = sorted(v)
    return v[min(len(v) - 1, int(len(v) * q))] if v else -1


def main():
    mode, where, port, n = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[-1])
    addr = socket.getaddrinfo(where, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    lat, failed = [], 0
    for _ in range(n):
        t0 = time.perf_counter_ns()
        try:
            s = socket.create_connection((addr, port), 10)
            if mode == "tls":
                s = ctx.wrap_socket(s, server_hostname=sys.argv[4])
                s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % sys.argv[4].encode())
            elif mode == "http":
                s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % sys.argv[4].encode())
            if mode != "connect":
                got = b""
                while True:
                    d = s.recv(65536)
                    if not d:
                        break
                    got += d
                if not got.startswith(b"HTTP/1.1 200"):
                    raise OSError("no 200")
            s.close()
            lat.append(time.perf_counter_ns() - t0)
        except (OSError, ssl.SSLError):
            failed += 1
    us = [x // 1000 for x in lat]
    print(f"LAT n={len(us)} p50={pct(us, .5)} p90={pct(us, .9)} p99={pct(us, .99)} failed={failed}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
