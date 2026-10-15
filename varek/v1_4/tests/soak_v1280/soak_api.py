#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_api.py — the API the v1.28 soak's agent calls (soak.sh starts it, as
root, outside the Warden). It checks, at the receiving end, what the egress
proxy put in each request:

  /v1/a  Authorization: Bearer <api>     /v1/b  X-Api-Key: <db>
  /v1/c  X-Token: <st> (POST, a body)    /v1/d  Authorization: token <gh>
  /v1/plain?q=...  no credential: what the agent sent, as it sent it

For a credential path it answers 200 when the header holds exactly the
value, 401 when it holds a placeholder (the swap did not happen), 400
otherwise. For /v1/plain it answers 200 and says whether the head holds a
placeholder and whether it holds any value (it must not: no rule names one
there).

  soak_api.py IP PORT CERT KEY VALUES.json LOG

VALUES.json maps each credential's name to its value (root's, 0600). Each
request is logged to LOG as one JSON line: time, path, status, and for a
credential path whether the value was right; never a value.
"""
import json
import socket
import ssl
import sys
import threading
import time

ip, port, cert, key, values_path, log_path = sys.argv[1], int(sys.argv[2]), *sys.argv[3:7]
V = json.load(open(values_path))
ROUTES = {"/v1/a": ("authorization", "Bearer ", "api"), "/v1/b": ("x-api-key", "", "db"),
          "/v1/c": ("x-token", "", "st"), "/v1/d": ("authorization", "token ", "gh")}
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
lock = threading.Lock()
log = open(log_path, "a", buffering=1)


def answer(s, status, obj):
    b = json.dumps(obj).encode()
    reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found"}[status]
    s.sendall(b"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
              b"Connection: close\r\n\r\n%s" % (status, reason.encode(), len(b), b))


def serve(c):
    try:
        s = ctx.wrap_socket(c, server_side=True)
        s.settimeout(30)
        d = b""
        while b"\r\n\r\n" not in d and len(d) < 65536:
            x = s.recv(65536)
            if not x:
                return
            d += x
        head, body = d.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        method, target = lines[0].split(" ")[:2]
        n = 0
        hdrs = []
        for h in lines[1:]:
            k, _, v = h.partition(":")
            hdrs.append((k.strip().lower(), v.strip()))
            if k.strip().lower() == "content-length":
                n = int(v)
        while len(body) < n:
            x = s.recv(65536)
            if not x:
                break
            body += x
        path = target.split("?", 1)[0]
        text = head.decode("latin-1") + body.decode("latin-1")
        rec = {"t": round(time.time(), 3), "method": method, "path": path}
        any_value = any(v in text for v in V.values())
        if path in ROUTES:
            name, scheme, cred = ROUTES[path]
            got = [v for k, v in hdrs if k == name]
            want = scheme + V[cred]
            if len(got) == 1 and got[0] == want:
                status = 200
            elif any("varek_ph_" in g for g in got):
                status = 401
            else:
                status = 400
            # the right value, in its header only: nowhere else in the request
            others = text.replace(want, "", 1)
            rec.update(credential=cred, value_ok=status == 200, value_elsewhere=any(v in others for v in V.values()))
            if path == "/v1/c":
                rec["body_ok"] = body == b"soak body " + b"x" * 64
            answer(s, status, {"ok": status == 200})
        elif path == "/v1/plain":
            status = 200
            rec.update(placeholder_seen="varek_ph_" in text, value_seen=any_value)
            answer(s, status, {"placeholder_seen": rec["placeholder_seen"], "value_seen": any_value})
        else:
            status = 404
            answer(s, status, {})
        rec["status"] = status
        with lock:
            log.write(json.dumps(rec) + "\n")
        s.close()
    except Exception as e:                      # noqa: BLE001 - every failure is logged
        with lock:
            log.write(json.dumps({"t": round(time.time(), 3), "error": f"{type(e).__name__}: {e}"[:200]}) + "\n")


ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind((ip, port))
ls.listen(64)
while True:
    c, _ = ls.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
