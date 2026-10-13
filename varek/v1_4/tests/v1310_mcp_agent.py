# SPDX-License-Identifier: MIT
# v1310_mcp_agent.py — the agent of test_v1310.sh (section 3): MCP calls over
# HTTPS through the Warden's inspecting proxy, each on its own connection
# (a refusal ends one) unless it says otherwise. For each it prints
#   CALL TAG STATUS-LINE | BODY
# of each response it got, or CALL TAG ERR <exception>.
#   v1310_mcp_agent.py PORT          every call below
#   v1310_mcp_agent.py PORT TAG      one tools/call get_issue with the
#                                    placeholder as a bearer token
#   v1310_mcp_agent.py PORT tokens F section 4: each token in F (JSON) as a
#                                    bearer token, then credential mt's placeholder
import base64, json, os, socket, ssl, sys

P = int(sys.argv[1])
H = "mcp.example.com"
TOK = os.environ.get("VAREK_CRED_TOK", "")
print("ENV", TOK.startswith("varek_ph_tok_"), flush=True)


def responses(s, n):
    buf, out = b"", []
    while len(out) < n:
        while b"\r\n\r\n" not in buf:
            x = s.recv(65536)
            if not x:
                return out + ([buf.decode("latin-1")] if buf else [])
            buf += x
        head, buf = buf.split(b"\r\n\r\n", 1)
        ln = 0
        for h in head.split(b"\r\n")[1:]:
            if h.lower().startswith(b"content-length:"):
                ln = int(h.split(b":", 1)[1])
        while len(buf) < ln:
            x = s.recv(65536)
            if not x:
                break
            buf += x
        out.append(head.split(b"\r\n")[0].decode() + " | " + buf[:ln].decode("latin-1"))
        buf = buf[ln:]
    return out


def send(tag, raw, n=1):
    try:
        s = ssl.create_default_context().wrap_socket(socket.create_connection((H, P), 15), server_hostname=H)
        s.sendall(raw)
        for r in responses(s, n):
            print("CALL", tag, r, flush=True)
        s.close()
    except (OSError, ssl.SSLError) as e:
        print("CALL", tag, "ERR", type(e).__name__, flush=True)


def post(body, path="/mcp", hdrs=(), chunked=False):
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    b = body.encode() if isinstance(body, str) else body
    h = "POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\n" % (path, H, P)
    h += "Accept: application/json, text/event-stream\r\n"
    for k, v in hdrs:
        h += "%s: %s\r\n" % (k, v)
    if chunked:
        mid = len(b) // 2
        framed = b"%x\r\n" % mid + b[:mid] + b"\r\n" + b"%x;ext=1\r\n" % (len(b) - mid) + b[mid:] + b"\r\n0\r\n\r\n"
        return (h + "Transfer-Encoding: chunked\r\n\r\n").encode() + framed
    return (h + "Content-Length: %d\r\n\r\n" % len(b)).encode() + b


def call(i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        m["params"] = params
    return m


V0618 = [("MCP-Protocol-Version", "2025-06-18")]
V0728 = [("MCP-Protocol-Version", "2026-07-28")]
BEARER = [("Authorization", "Bearer " + TOK)]
if len(sys.argv) > 3 and sys.argv[2] == "tokens":
    # section 4: tools/list with each token of the JSON file {tag: token} as
    # a bearer token; then credential mt's placeholder where its rule names
    # it, on another endpoint, and on a plain request
    for tag, t in json.load(open(sys.argv[3])).items():
        send(tag, post(call(30, "tools/list"), hdrs=V0618 + [("Authorization", "Bearer " + t)]))
    MT = [("Authorization", "Bearer " + os.environ.get("VAREK_CRED_MT", ""))]
    send("ph_get", post(call(31, "tools/call", {"name": "get_issue"}), hdrs=V0618 + MT))
    send("ph_other", post(call(32, "tools/list"), path="/other", hdrs=V0618 + MT))
    send("ph_plain", ("GET /plain HTTP/1.1\r\nHost: %s:%d\r\nAuthorization: %s\r\n\r\n" % (H, P, MT[0][1])).encode())
    sys.exit(0)
if len(sys.argv) > 2:
    send(sys.argv[2], post(call(3, "tools/call", {"name": "get_issue"}), hdrs=V0618 + BEARER))
    sys.exit(0)
send("init", post(call(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                          "clientInfo": {"name": "t", "version": "1"}}), hdrs=V0618))
send("notify", post({"jsonrpc": "2.0", "method": "notifications/initialized"}, hdrs=V0618))
send("list", post(call(2, "tools/list"), hdrs=V0728 + [("Mcp-Method", "tools/list")]))
send("get", post(call(3, "tools/call", {"name": "get_issue", "arguments": {"n": 1}}), hdrs=V0618 + BEARER))
send("getesc", post('{"jsonrpc":"2.0","id":4,"method":"tools\\/call","params":{"name":"get\\u005fissue"}}',
                    hdrs=V0618 + BEARER))
send("delete", post(call(5, "tools/call", {"name": "delete_repo"}), hdrs=V0618))
send("unlisted", post(call("six", "tools/call", {"name": "other_tool"}), hdrs=V0618))
send("dup", post('{"jsonrpc":"2.0","id":7,"method":"tools/list","method":"tools/call","params":{"name":"get_issue"}}'))
send("batch", post([call(8, "tools/list")]))
send("hdrmis", post(call(9, "tools/call", {"name": "get_issue"}), hdrs=V0728 + [("Mcp-Method", "tools/list")] + BEARER))
send("namemis", post(call(10, "tools/call", {"name": "get_issue"}),
                     hdrs=V0728 + [("Mcp-Method", "tools/call"), ("Mcp-Name", "get_other")] + BEARER))
send("b64", post(call(11, "tools/call", {"name": "get_issue"}),
                 hdrs=V0728 + [("Mcp-Method", "tools/call"),
                               ("Mcp-Name", "=?base64?" + base64.b64encode(b"get_issue").decode() + "?=")] + BEARER))
send("small", post(call(12, "resources/read", {"uri": "file:///projects/app/a.txt"}), hdrs=V0618))
send("big", post(call(13, "resources/read", {"uri": "file:///projects/app/a.txt", "_meta": {"pad": "x" * 400}}),
                 hdrs=V0618))
send("huge", post(call(14, "tools/list", {"_meta": {"pad": "x" * 3000}}), path="/mcp2", hdrs=V0618))
send("chunked", post(call(15, "tools/list"), hdrs=V0618, chunked=True))
send("trace", post(call(16, "tools/list", {"_meta": {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}}),
                   hdrs=V0618))
send("query", post(call(17, "tools/list"), path="/mcp?x=1", hdrs=V0618))
send("get_stream", ("GET /mcp HTTP/1.1\r\nHost: %s:%d\r\nAccept: text/event-stream\r\n\r\n" % (H, P)).encode())
send("two", post(call(18, "tools/list"), hdrs=V0618) + post(call(19, "initialize", {}), hdrs=V0618), n=2)
send("nodeep", post('{"jsonrpc":"2.0","id":20,"method":"tools/list","params":{"a":' + "[" * 80 + "]" * 80 + "}}"))
send("badutf8", post(b'{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"get_\xc0\xaf"}}'))
