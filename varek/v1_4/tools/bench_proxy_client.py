#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""bench_proxy_client.py — the agent of `varek bench --proxy` (v1.26.1).

  bench_proxy_client.py <name>[=<addr>] <port> <cafile|default> <n> <warmup> <kind>...

Each kind is timed n times, after `warmup` untimed calls, one after another,
over HTTPS to <name>:<port> (the name resolved once, before the timing: under
the Warden with the proxy on, its synthetic address; natively, <addr>):

  https      a new connection each time: connect, TLS handshake (verifying
             the server as api clients do, against <cafile>, or the default
             trust store with "default"), GET /ok, the reply read to its end
  request    GET /ok on one kept-alive connection, made before the timing:
             the cost of one request once a connection is open
  denied     a new connection each time, GET /denied: under the Warden in
             inspecting mode a deny rule refuses it (403); natively the
             server answers it

Prints, for each kind, "CLASS <kind> ok=<k> fail=<k> status=<code>:<count>,..."
and "SAMPLES <kind> <us> ..." (the timed calls, microseconds), then "END".
"""

import socket
import ssl
import sys
import time

REPLY_END = b"\r\n\r\n"


def read_reply(s):
    """One response (Content-Length framed): its status code, or 0."""
    buf = b""
    while REPLY_END not in buf:
        d = s.recv(65536)
        if not d:
            return 0
        buf += d
    head, _, body = buf.partition(REPLY_END)
    lines = head.split(b"\r\n")
    try:
        code = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return 0
    cl = 0
    for ln in lines[1:]:
        if ln.lower().startswith(b"content-length:"):
            cl = int(ln.split(b":", 1)[1])
    while len(body) < cl:
        d = s.recv(65536)
        if not d:
            return 0
        body += d
    return code


def main():
    name, _, addr = sys.argv[1].partition("=")
    port, cafile = int(sys.argv[2]), sys.argv[3]
    n, warmup, kinds = int(sys.argv[4]), int(sys.argv[5]), sys.argv[6:]
    addr = socket.getaddrinfo(addr or name, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    ctx = ssl.create_default_context(cafile=None if cafile == "default" else cafile)

    def connect():
        s = socket.create_connection((addr, port), 10)
        return ctx.wrap_socket(s, server_hostname=name)

    def get(s, path, keep):
        s.sendall(b"GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\n" %
                  (path, name.encode(), b"" if keep else b"Connection: close\r\n"))
        return read_reply(s)

    for kind in kinds:
        samples, status, ok, fail = [], {}, 0, 0
        ka = None
        for i in range(warmup + n):
            t0 = time.perf_counter_ns()
            try:
                if kind == "request":
                    if ka is None:
                        ka = connect()
                        t0 = time.perf_counter_ns()
                    code = get(ka, b"/ok", True)
                    if code != 200:
                        ka.close()
                        ka = None
                else:
                    s = connect()
                    code = get(s, b"/ok" if kind == "https" else b"/denied", False)
                    s.close()
            except (OSError, ssl.SSLError):
                code = 0
                if kind == "request" and ka is not None:
                    ka.close()
                    ka = None
            dt = time.perf_counter_ns() - t0
            status[code] = status.get(code, 0) + 1
            if code == 200:
                ok += 1
            else:
                fail += 1
            if i >= warmup:
                samples.append(dt / 1000.0)
        if ka is not None:
            ka.close()
        print(f"CLASS {kind} ok={ok} fail={fail} status=" +
              ",".join(f"{k}:{v}" for k, v in sorted(status.items())), flush=True)
        print(f"SAMPLES {kind} " + " ".join(f"{x:.1f}" for x in samples), flush=True)
    print("END", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
