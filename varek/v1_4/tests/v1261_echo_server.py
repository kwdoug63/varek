# SPDX-License-Identifier: MIT
"""v1.26.1 tests: an HTTP/1.1 server, plain or TLS, that keeps connections
alive, reads each request's body (Content-Length or chunked), logs
"GOT METHOD TARGET LEN SHA256" for each whole request, and answers
"ok METHOD TARGET LEN SHA256". Usage: v1261_echo_server.py IP PORT LOG [CERT KEY]"""
import hashlib, socket, ssl, sys, threading

ip, port, log = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ctx = None
if len(sys.argv) > 5:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[4], sys.argv[5])
lock = threading.Lock()


def note(line):
    with lock, open(log, "a") as f:
        f.write(line + "\n")


def serve(c):
    try:
        s = ctx.wrap_socket(c, server_side=True) if ctx else c
        f = s.makefile("rb")
        while True:
            line = f.readline()
            if not line:
                return
            method, target, _ = line.decode().split(" ", 2)
            headers = {}
            while True:
                h = f.readline()
                if h in (b"\r\n", b""):
                    break
                k, v = h.decode().split(":", 1)
                headers[k.strip().lower()] = v.strip()
            body = b""
            if "content-length" in headers:
                body = f.read(int(headers["content-length"]))
            elif headers.get("transfer-encoding", "").lower() == "chunked":
                while True:
                    size = int(f.readline().split(b";")[0], 16)
                    if size == 0:
                        while f.readline() not in (b"\r\n", b""):
                            pass
                        break
                    body += f.read(size)
                    f.readline()
            out = f"ok {method} {target} {len(body)} {hashlib.sha256(body).hexdigest()}"
            note("GOT " + out[3:])
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(out), out.encode()))
    except Exception as e:
        note("ERR " + type(e).__name__)


l = socket.socket()
l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind((ip, port))
l.listen(32)
while True:
    c, _ = l.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
