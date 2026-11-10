#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""servers.py — the cluster's services the soak's agents call (soak.sh):
one the policy names (`--name allowed`) and one it does not (`--name
denied`). Each answers GET with its name, and logs each request it is sent
as one JSON line on standard output ({"t", "server", "client", "path"}), so
the checker (soak_check.py) can count what reached each: the denied one
must see no request from an agent.

v1.36 step 12 (the ship gate): --tls CERT KEY serves HTTPS, and
--token-sha256 HEX is the SHA-256 of the soak's token. Each request's
X-Varek-Soak header is then told apart, logged ("cred") and answered
(`<name> cred=<kind>`): `value` when it is the token (the egress proxy
swapped the agent's placeholder for it), `none` when there is none,
`other sha=<its SHA-256>` otherwise (a placeholder sent as it is). The
token itself is never logged.

  servers.py --name allowed|denied [--port 8080] [--tls CERT KEY] [--token-sha256 HEX]

Standard library only. Runs unsupervised, in the soak's services' namespace.
"""
import argparse
import hashlib
import json
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--tls", nargs=2, metavar=("CERT", "KEY"))
    ap.add_argument("--token-sha256", default="")
    a = ap.parse_args()
    lock = threading.Lock()

    def log(rec):
        # one write a line, one thread at a time: two requests at once (the
        # server is threaded) printed as one line were each lost to the count
        line = json.dumps(rec) + "\n"
        with lock:
            sys.stdout.write(line)
            sys.stdout.flush()

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - the library's name
            rec = {"t": round(time.time(), 3), "server": a.name, "client": self.client_address[0], "path": self.path}
            body = a.name
            if a.token_sha256:
                h = self.headers.get("X-Varek-Soak")
                sha = hashlib.sha256(h.encode("utf-8", "surrogateescape")).hexdigest() if h is not None else ""
                kind = "none" if h is None else "value" if sha == a.token_sha256 else "other"
                rec["cred"] = kind
                body += f" cred={kind}" + (f" sha={sha}" if kind == "other" else "")
            log(rec)
            body = (body + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    ctx = None
    if a.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.tls[0], a.tls[1])

    class S(ThreadingHTTPServer):
        # the TLS handshake in each request's own thread, not in accept: a
        # client that connects and sends nothing (the readiness probe) holds
        # up no other
        def finish_request(self, request, client_address):
            if ctx:
                try:
                    request = ctx.wrap_socket(request, server_side=True)
                except (OSError, ValueError):
                    return
            super().finish_request(request, client_address)

    srv = S(("", a.port), H)
    log({"t": round(time.time(), 3), "server": a.name, "listening": a.port, "tls": bool(a.tls)})
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
