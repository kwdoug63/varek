#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_remote.py — the remote MCP server of the shared soak's run A
(soak.sh starts it, as root, outside the Warden): Streamable HTTP over
HTTPS, enough to answer a call. It checks, at the receiving end, what the
egress proxy let through and put in:

  bearer   "mt" when the Authorization header is exactly "Bearer <mt>" (the
           run's MCP token, put in by the proxy where a rule written for=gh
           names it), "placeholder" when it holds a VAREK placeholder (the
           swap did not happen), "none" without one, "other" otherwise
  values   whether the request holds any of the values anywhere else (it
           must not: neither the MCP token outside its header nor the
           user's token)

Each request is logged to LOG as one JSON line: time, HTTP method, the
JSON-RPC method and tool name, bearer, values; never a value. A POST with
an id gets a JSON-RPC result; a notification 202; a GET "ok".

  soak_remote.py IP PORT CERT KEY VALUES.json LOG

VALUES.json: {"mt": <the MCP token>, "user": <the user's token>} (root's, 0600).
"""
import json
import socket
import ssl
import sys
import threading
import time

ip, port, cert, key, values_path, log_path = sys.argv[1], int(sys.argv[2]), *sys.argv[3:7]
V = json.load(open(values_path))
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
lock = threading.Lock()
log = open(log_path, "a", buffering=1)


def serve(c):
    try:
        s = ctx.wrap_socket(c, server_side=True)
        s.settimeout(60)
        buf = b""

        def more():
            nonlocal buf
            x = s.recv(65536)
            if not x:
                raise EOFError
            buf += x

        while True:
            while b"\r\n\r\n" not in buf:
                more()
            head, buf = buf.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")
            hs = []
            for h in lines[1:]:
                k, _, v = h.partition(":")
                hs.append((k.strip().lower(), v.strip()))
            n = int(next((v for k, v in hs if k == "content-length"), "0") or 0)
            while len(buf) < n:
                more()
            body, buf = buf[:n], buf[n:]
            rec = {"t": round(time.time(), 3), "http": lines[0].split(" ")[0]}
            auth = [v for k, v in hs if k == "authorization"]
            if not auth:
                rec["bearer"] = "none"
            elif auth == ["Bearer " + V["mt"]]:
                rec["bearer"] = "mt"
            elif any("varek_ph_" in a for a in auth):
                rec["bearer"] = "placeholder"
            else:
                rec["bearer"] = "other"
            text = head.decode("latin-1") + body.decode("latin-1")
            rest = text.replace("Bearer " + V["mt"], "", 1) if rec["bearer"] == "mt" else text
            rec["values"] = any(v in rest for v in V.values())
            try:
                m = json.loads(body) if body else {}
            except ValueError:
                m = {}
            if isinstance(m, dict):
                rec["method"] = m.get("method")
                if isinstance(m.get("params"), dict) and "name" in m["params"]:
                    rec["name"] = m["params"]["name"]
            with lock:
                log.write(json.dumps(rec) + "\n")
            if rec["http"] == "GET":
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            elif isinstance(m, dict) and "id" in m:
                out = json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"seen": m.get("method")}}).encode()
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                          % len(out) + out)
            else:
                s.sendall(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
    except (EOFError, OSError, ssl.SSLError, ValueError):
        pass
    except Exception as e:                      # noqa: BLE001 - every other failure is logged
        with lock:
            log.write(json.dumps({"t": round(time.time(), 3), "error": f"{type(e).__name__}: {e}"[:200]}) + "\n")
    finally:
        c.close()


ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind((ip, port))
ls.listen(64)
while True:
    c, _ = ls.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
