#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The servers test_v1210.sh runs its agent against (in the host's network
namespace, outside the Warden). Writes <dir>/ready when all are listening and
runs until killed. Every server logs what it saw to <dir>/servers.log."""
import os, socket, stat, struct, sys, threading

D = sys.argv[1]                         # e.g. /tmp/varek_v1210
S = os.path.join(D, "sock")
LOG = open(os.path.join(D, "servers.log"), "a", buffering=1)
lock = threading.Lock()

def log(msg):
    with lock:
        LOG.write(msg + "\n")

def serve_stream(srv, name, greet=None, creds=False):
    def one(c):
        try:
            if creds:
                pid, uid, gid = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                log(f"{name} peer uid={uid} gid={gid}")
            if greet:
                c.sendall(greet)
            while True:
                b = c.recv(4096)
                if not b:
                    break
                c.sendall(b)
        except OSError:
            pass
        finally:
            c.close()
    def loop():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()

def tcp(port, **kw):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(512)
    serve_stream(s, f"tcp:{port}", **kw)
    if socket.has_ipv6:
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s6.bind(("::1", port)); s6.listen(512)
            serve_stream(s6, f"tcp6:{port}", **kw)
        except OSError:
            pass                       # no IPv6 on this host

def udp(port):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", port))
    def loop():
        while True:
            b, a = u.recvfrom(65536)
            u.sendto(b, a)
    threading.Thread(target=loop, daemon=True).start()

def unix(path, kind, mode=0o777, **kw):
    try: os.unlink(path)
    except FileNotFoundError: pass
    s = socket.socket(socket.AF_UNIX, kind)
    s.bind(path)
    os.chmod(path, mode)
    if kind == socket.SOCK_DGRAM:
        def loop():
            while True:
                b = s.recv(65536)
                log(f"unix-dgram {os.path.basename(path)} got {len(b)} bytes")
        threading.Thread(target=loop, daemon=True).start()
    else:
        s.listen(64)
        serve_stream(s, f"unix:{os.path.basename(path)}", **kw)

os.makedirs(S, exist_ok=True)
os.chmod(D, 0o755); os.chmod(S, 0o755)
tcp(18181)
tcp(18182, greet=b"D")
tcp(18186, greet=b"A")
udp(18183)
# 18184: a listener whose accept queue is full, so new SYNs are dropped and a
# client's connect waits (the slow-destination case).
slow = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
slow.bind(("127.0.0.1", 18184)); slow.listen(0)
fillers = []
for _ in range(3):
    f = socket.socket(); f.setblocking(False)
    try: f.connect(("127.0.0.1", 18184))
    except BlockingIOError: pass
    fillers.append(f)
unix(os.path.join(S, "s.sock"), socket.SOCK_STREAM, creds=True)
unix(os.path.join(S, "d.sock"), socket.SOCK_DGRAM)
unix(os.path.join(S, "q.sock"), socket.SOCK_SEQPACKET)
unix(os.path.join(S, "root.sock"), socket.SOCK_STREAM, mode=0o700)
os.makedirs(os.path.join(D, "outside"), exist_ok=True)
unix(os.path.join(D, "outside", "other.sock"), socket.SOCK_STREAM)
for name, target in (("link-ok.sock", "s.sock"), ("link-bad.sock", "../outside/other.sock"),
                     ("other.sock", "../outside/other.sock")):
    p = os.path.join(S, name)
    try: os.unlink(p)
    except FileNotFoundError: pass
    os.symlink(target, p)
ab = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
ab.bind("\0varek_v1210_abs"); ab.listen(4)
serve_stream(ab, "unix-abstract", greet=b"X")
# Benchmark listeners: accept and close at once, with a deep backlog, so the
# numbers measure the connect and not this script's threads.
def accept_close(srv):
    def loop():
        while True:
            c, _ = srv.accept()
            c.close()
    threading.Thread(target=loop, daemon=True).start()
b4 = socket.socket(); b4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
b4.bind(("127.0.0.1", 18190)); b4.listen(4096); accept_close(b4)
bp = os.path.join(S, "bench.sock")
try: os.unlink(bp)
except FileNotFoundError: pass
bu = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); bu.bind(bp); os.chmod(bp, 0o777)
bu.listen(4096); accept_close(bu)
# HTTP for the real clients: plain on 18187, TLS on 18188 (a certificate for
# 127.0.0.1 the test made in <dir>/tls), and HTTP over a Unix socket.
import http.server, socketserver, ssl
class Quiet(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = b"varek v1.21 decided connection\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 1024
    allow_reuse_address = True
h = TS(("127.0.0.1", 18187), Quiet)
threading.Thread(target=h.serve_forever, daemon=True).start()
tls = os.path.join(D, "tls")
if os.path.exists(os.path.join(tls, "cert.pem")):
    hs = TS(("127.0.0.1", 18188), Quiet)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(tls, "cert.pem"), os.path.join(tls, "key.pem"))
    hs.socket = ctx.wrap_socket(hs.socket, server_side=True)
    threading.Thread(target=hs.serve_forever, daemon=True).start()
class UTS(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
class UQuiet(Quiet):
    def address_string(self):
        return "unix"
hp = os.path.join(S, "http.sock")
try: os.unlink(hp)
except FileNotFoundError: pass
hu = UTS(hp, UQuiet); os.chmod(hp, 0o777)
threading.Thread(target=hu.serve_forever, daemon=True).start()
open(os.path.join(D, "ready"), "w").close()
threading.Event().wait()
