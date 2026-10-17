#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""bench_mcp_client.py — the agent of `varek bench --mcp` (v1.31).

  bench_mcp_client.py <name>[=<addr>] <port> <cafile|default> <n> <warmup> <size>...

For each size (bytes), n timed calls after `warmup` untimed ones, one after
another on one kept-alive HTTPS connection to <name>:<port> (made before the
timing; the name resolved once): a POST of a JSON-RPC tools/call of `echo`
to /mcp whose body is exactly <size> bytes (its one argument padded), and
the reply read to its end. Natively <addr> is dialed; under the Warden the
name's synthetic address. Each call's id is its own, and the reply must
carry it.

Prints, for each size, "CLASS s<size> ok=<k> fail=<k> status=<code>:<count>,..."
and "SAMPLES s<size> <us> ..." (the timed calls, microseconds), then "END".
"""

import json
import socket
import ssl
import sys
import time

REPLY_END = b"\r\n\r\n"


def body(i, size):
    """A tools/call of echo, exactly size bytes."""
    head = {"jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": ""}}}
    b = json.dumps(head, separators=(",", ":")).encode()
    pad = size - len(b)
    if pad < 0:
        raise SystemExit(f"bench_mcp_client: a call cannot be {size} bytes")
    return b.replace(b'"text":""', b'"text":"' + b"a" * pad + b'"')


def read_reply(s):
    """One response (Content-Length framed): (status code, body), or (0, b"")."""
    buf = b""
    while REPLY_END not in buf:
        d = s.recv(65536)
        if not d:
            return 0, b""
        buf += d
    head, _, rest = buf.partition(REPLY_END)
    lines = head.split(b"\r\n")
    try:
        code = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return 0, b""
    cl = 0
    for ln in lines[1:]:
        if ln.lower().startswith(b"content-length:"):
            cl = int(ln.split(b":", 1)[1])
    while len(rest) < cl:
        d = s.recv(65536)
        if not d:
            return 0, b""
        rest += d
    return code, rest[:cl]


def main():
    name, _, addr = sys.argv[1].partition("=")
    port, cafile = int(sys.argv[2]), sys.argv[3]
    n, warmup, sizes = int(sys.argv[4]), int(sys.argv[5]), [int(x) for x in sys.argv[6:]]
    addr = socket.getaddrinfo(addr or name, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    ctx = ssl.create_default_context(cafile=None if cafile == "default" else cafile)

    def connect():
        s = socket.create_connection((addr, port), 30)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)    # no Nagle stall on a body's last segment
        return ctx.wrap_socket(s, server_hostname=name)

    head = (b"POST /mcp HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\n"
            b"Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2025-06-18\r\n"
            b"Content-Length: %%d\r\n\r\n" % (name.encode(), port))
    i = 0
    for size in sizes:
        samples, status, ok, fail = [], {}, 0, 0
        ka = None
        for j in range(warmup + n):
            i += 1
            b = body(i, size)
            msg = head % len(b) + b
            t0 = time.perf_counter_ns()
            try:
                if ka is None:
                    ka = connect()
                    t0 = time.perf_counter_ns()
                ka.sendall(msg)
                code, rb = read_reply(ka)
                if code == 200 and json.loads(rb).get("id") != i:
                    code = 1                                  # an answer to another call
                if code != 200:
                    ka.close()
                    ka = None
            except (OSError, ssl.SSLError, ValueError):
                code = 0
                if ka is not None:
                    ka.close()
                    ka = None
            dt = time.perf_counter_ns() - t0
            status[code] = status.get(code, 0) + 1
            if code == 200:
                ok += 1
            else:
                fail += 1
            if j >= warmup:
                samples.append(dt / 1000.0)
        if ka is not None:
            ka.close()
        print(f"CLASS s{size} ok={ok} fail={fail} status=" +
              ",".join(f"{k}:{v}" for k, v in sorted(status.items())), flush=True)
        print(f"SAMPLES s{size} " + " ".join(f"{x:.1f}" for x in samples), flush=True)
    print("END", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
