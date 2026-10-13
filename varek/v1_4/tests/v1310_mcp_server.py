# SPDX-License-Identifier: MIT
# v1310_mcp_server.py — a stand-in MCP server over HTTPS for test_v1310.sh
# (section 3): Streamable HTTP, enough of the 2025-06-18 and 2026-07-28
# revisions to answer a call. Each request's head and body (a chunked one
# without its framing) is logged as a JSON line. A POST with an id gets a
# JSON-RPC result naming the method it read; a notification gets 202; a GET
# gets "ok". Connections are kept open (several requests on one).
#   v1310_mcp_server.py IP PORT CERT KEY LOG
import json, socket, ssl, sys, threading

ip, port, cert, key, log = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
lsn = socket.socket()
lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lsn.bind((ip, port))
lsn.listen(32)
lock = threading.Lock()


def serve(c):
    try:
        s = ctx.wrap_socket(c, server_side=True)
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
            hs = {}
            for h in head.split(b"\r\n")[1:]:
                k, _, v = h.partition(b":")
                hs[k.strip().lower().decode()] = v.strip().decode("latin-1")
            body = b""
            if "content-length" in hs:
                n = int(hs["content-length"])
                while len(buf) < n:
                    more()
                body, buf = buf[:n], buf[n:]
            elif hs.get("transfer-encoding", "").lower() == "chunked":
                while True:
                    while b"\r\n" not in buf:
                        more()
                    ln, buf = buf.split(b"\r\n", 1)
                    n = int(ln.split(b";")[0], 16)
                    while len(buf) < n + 2:
                        more()
                    body += buf[:n]
                    buf = buf[n + 2:]
                    if n == 0:
                        break
            with lock, open(log, "a") as f:
                f.write(json.dumps({"head": head.decode("latin-1"), "body": body.decode("latin-1")}) + "\n")
            if head.startswith(b"GET "):
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                continue
            try:
                m = json.loads(body)
            except ValueError:
                m = {}
            if isinstance(m, dict) and "id" in m:
                out = json.dumps({"jsonrpc": "2.0", "id": m["id"],
                                  "result": {"seen": m.get("method"),
                                             "protocol": hs.get("mcp-protocol-version", "")}}).encode()
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(out) + out)
            else:
                s.sendall(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
    except (EOFError, OSError, ssl.SSLError, ValueError):
        pass
    finally:
        c.close()


while True:
    c, _ = lsn.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
