#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""servers.py — the cluster's services the soak's agents call (soak.sh):
one the policy names (`--name allowed`) and one it does not (`--name
denied`). Each answers GET with its name, and logs each request it is sent
as one JSON line on standard output ({"t", "server", "client", "path"}), so
the checker (soak_check.py) can count what reached each: the denied one
must see no request from an agent.

  servers.py --name allowed|denied [--port 8080]

Standard library only. Runs unsupervised, in the soak's services' namespace.
"""
import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--port", type=int, default=8080)
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
            log({"t": round(time.time(), 3), "server": a.name, "client": self.client_address[0], "path": self.path})
            body = (a.name + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    log({"t": round(time.time(), 3), "server": a.name, "listening": a.port})
    ThreadingHTTPServer(("", a.port), H).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
