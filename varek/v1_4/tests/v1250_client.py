# SPDX-License-Identifier: MIT
# v1250_client.py — run as the agent by test_v1250.sh. Prints
# "OK|ERR <case> <detail> <ms>" per case.
#
#   v1250_client.py <port> <wildcard-name> <outside-name>
#       glibc getaddrinfo (hosts: files dns, through the Warden's stub):
#       resolve and fetch a name only a wildcard rule allows; a name outside
#       every rule fails
#   v1250_client.py raw <udp|tcp> <type> <name>
#       one DNS question of its own to the stub (the address in the
#       resolv.conf view): prints the rcode, the answer count and addresses
#   v1250_client.py connect <addr> <port>
#       a plain connect (to some other port-53 server: must be refused)
#   v1250_client.py ask <name> ...
#       getaddrinfo each name in turn, as fast as it can (a DNS-tunnel style
#       client: every name new); prints one line per name
import http.client, os, socket, struct, sys, time


def case(name, f):
    t = time.time()
    try:
        r = "OK %s %s" % (name, f())
    except Exception as e:
        r = "ERR %s %s" % (name, type(e).__name__)
    print("%s %d" % (r, (time.time() - t) * 1000), flush=True)


def stub():
    for line in open("/etc/resolv.conf"):
        if line.startswith("nameserver"):
            return line.split()[1]
    raise OSError("no nameserver")


def question(name, qtype):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for lab in name.split("."):
        q += bytes([len(lab)]) + lab.encode()
    return q + b"\0" + struct.pack(">HH", qtype, 1)


def answer(m):
    rcode, an = m[3] & 15, struct.unpack(">H", m[6:8])[0]
    o = 12
    while m[o]:
        o += 1 + m[o]
    o += 5
    addrs = []
    for _ in range(an):
        o += 2                                   # a pointer to the question's name
        t, _c, _ttl, l = struct.unpack(">HHIH", m[o:o + 10])
        o += 10
        if t in (1, 28):
            addrs.append(socket.inet_ntop(socket.AF_INET if t == 1 else socket.AF_INET6, m[o:o + l]))
        o += l
    return "rcode=%d an=%d %s" % (rcode, an, ",".join(addrs) or "-")


def raw(transport, qtype, name):
    q = question(name, {"A": 1, "AAAA": 28, "TXT": 16, "MX": 15}[qtype])
    if transport == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.connect((stub(), 53))
        s.send(q)
        return answer(s.recv(512))
    s = socket.create_connection((stub(), 53), timeout=3)
    s.sendall(struct.pack(">H", len(q)) + q)
    buf = b""
    while len(buf) < 2 or len(buf) < 2 + struct.unpack(">H", buf[:2])[0]:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    return answer(buf[2:])


if sys.argv[1] == "raw":
    case("raw-%s-%s" % (sys.argv[2], sys.argv[3]), lambda: raw(sys.argv[2], sys.argv[3], sys.argv[4]))
    sys.exit(0)
if sys.argv[1] == "ask":
    for n in sys.argv[2:]:
        case("ask " + n, lambda: ",".join(sorted({a[4][0] for a in socket.getaddrinfo(n, 80, proto=socket.IPPROTO_TCP)})))
    sys.exit(0)
if sys.argv[1] == "connect":
    case("connect %s:%s" % (sys.argv[2], sys.argv[3]),
         lambda: socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=3) and "connected")
    sys.exit(0)
port, name, outside = int(sys.argv[1]), sys.argv[2], sys.argv[3]
case("resolve", lambda: ",".join(sorted({a[4][0] for a in socket.getaddrinfo(name, port, proto=socket.IPPROTO_TCP)})))


def get():
    c = http.client.HTTPConnection(name, port, timeout=3)
    c.request("GET", "/")
    return c.getresponse().status


case("http", get)
case("unlisted", lambda: socket.getaddrinfo(outside, port))
