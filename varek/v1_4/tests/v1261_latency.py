#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1261_latency.py — the client of tests/latency_v1261.sh.

  v1261_latency.py tls <where> <port> <sni> <n>
      n HTTPS requests one after another, each on a new connection: connect,
      TLS handshake with that SNI, GET /, the reply read to its end
  v1261_latency.py tlska <where> <port> <sni> <n>
      n HTTPS requests on one kept-alive connection (made before the timing)
  v1261_latency.py http <where> <port> <host> <n>
      n HTTP/1.1 requests, each on a new connection (Host as given)
  v1261_latency.py httpka <where> <port> <host> <n>
      n HTTP/1.1 requests on one kept-alive connection
  v1261_latency.py connect <where> <port> <n>
      n TCP connects one after another, closed at once

As tests/v1260_latency.py, which it extends with the kept-alive modes. <where>
is resolved once, before the timing. The server is not verified (the run's
CA or the server's own certificate: the cost is the same). Prints one line:
"LAT n=<n> p50=<us> p90=<us> p99=<us> failed=<k>".
"""

import socket
import ssl
import sys
import time


def pct(v, q):
    v = sorted(v)
    return v[min(len(v) - 1, int(len(v) * q))] if v else -1


def reply(s):
    """One response, Content-Length framed: True for a 200."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            return False
        buf += d
    head, _, body = buf.partition(b"\r\n\r\n")
    cl = 0
    for ln in head.split(b"\r\n")[1:]:
        if ln.lower().startswith(b"content-length:"):
            cl = int(ln.split(b":", 1)[1])
    while len(body) < cl:
        d = s.recv(65536)
        if not d:
            return False
        body += d
    return head.startswith(b"HTTP/1.1 200")


def main():
    mode, where, port, n = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[-1])
    addr = socket.getaddrinfo(where, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    host = sys.argv[4].encode() if mode != "connect" else b""
    tls = mode in ("tls", "tlska")

    def connect():
        s = socket.create_connection((addr, port), 10)
        return ctx.wrap_socket(s, server_hostname=sys.argv[4]) if tls else s

    lat, failed, ka = [], 0, None
    for _ in range(n):
        try:
            if mode in ("tlska", "httpka") and ka is None:
                ka = connect()
            t0 = time.perf_counter_ns()
            if mode == "connect":
                socket.create_connection((addr, port), 10).close()
            elif ka is not None:
                ka.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host)
                if not reply(ka):
                    ka.close()
                    ka = None
                    raise OSError("no 200")
            else:
                s = connect()
                s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host)
                ok = reply(s)
                s.close()
                if not ok:
                    raise OSError("no 200")
            lat.append(time.perf_counter_ns() - t0)
        except (OSError, ssl.SSLError):
            failed += 1
    us = [x // 1000 for x in lat]
    print(f"LAT n={len(us)} p50={pct(us, .5)} p90={pct(us, .9)} p99={pct(us, .99)} failed={failed}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
