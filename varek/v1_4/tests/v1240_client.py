# SPDX-License-Identifier: MIT
# v1240_client.py — run as the agent by test_v1240.sh (Python, glibc's
# getaddrinfo). Prints "OK|ERR <case> <detail> <ms>" per case.
import http.client, socket, sys, time
def case(name, f):
    t = time.time()
    try:
        r = "OK %s %s" % (name, f())
    except Exception as e:
        r = "ERR %s %s" % (name, type(e).__name__)
    print("%s %d" % (r, (time.time() - t) * 1000), flush=True)
def get(h, p=None):
    p = port if p is None else p
    c = http.client.HTTPConnection(h, p, timeout=3)
    c.request("GET", "/")
    return c.getresponse().status
if sys.argv[1] == "timed":
    # timed <seconds>@<host>:<port> ...: connect at those times after start
    t0 = time.time()
    for spec in sys.argv[2:]:
        at, dest = spec.split("@", 1)
        time.sleep(max(0, float(at) - (time.time() - t0)))
        h, p = dest.rsplit(":", 1)
        case("at %s %s" % (at, dest), lambda: get(h, int(p)))
    sys.exit(0)
if sys.argv[1] == "late":
    # late <seconds> <port>: after a wait, resolve and fetch api.example.com
    time.sleep(float(sys.argv[2]))
    port = int(sys.argv[3])
    case("resolve", lambda: ",".join(sorted({a[4][0] for a in socket.getaddrinfo("api.example.com", port, proto=socket.IPPROTO_TCP)})))
    case("http", lambda: get("api.example.com"))
    sys.exit(0)
port = int(sys.argv[1])
case("resolve", lambda: ",".join(sorted({a[4][0] for a in socket.getaddrinfo("api.example.com", port, proto=socket.IPPROTO_TCP)})))
case("http", lambda: get("api.example.com"))
case("unlisted", lambda: socket.getaddrinfo("other.example.com", port))
case("denied-name", lambda: socket.getaddrinfo("blocked.example.com", port))
def unix(path):
    u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    u.connect(path)
    return "connected"
for extra in sys.argv[2:]:
    if extra.startswith("unix:"):
        case("connect " + extra, lambda: unix(extra[5:]))
        continue
    h, p = extra.rsplit(":", 1)
    case("connect " + extra, lambda: get(h, int(p)))
