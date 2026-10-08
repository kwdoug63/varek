#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# latency_v1260.sh — what the egress proxy costs (v1.26.0, SNI mode;
# docs/security/v1.26-egress-proxy.md, section 6).
#
# Requests, n each, one after another (tests/v1260_latency.py), to servers on
# this machine's own address (a TLS server and an HTTP server, each replying
# a few bytes and closing):
#   native tls       no Warden: connect, TLS handshake, GET, the reply
#   direct tls       under the Warden, `allow host <addr>:<port>` on a proxied
#                    port: dialed directly, as in v1.21 (no proxy in the path)
#   proxied tls      under the Warden, `allow host api.example.com:<port>`, by
#                    name: the synthetic address, the hand-off, the
#                    ClientHello read, the decision and certificate, the dial,
#                    then every byte relayed by the proxy
#   native http, proxied http   the same for plain HTTP (the Host header)
#   via squid        proxied tls through a Squid upstream (section 5), where
#                    Squid is installed
#   hand-off only    connects to the synthetic address, closed at once: the
#                    hand-off without a request
# For proxied rows it also reads the Warden's records: the time from the
# proxy's report of the name to the socket passed back (decision,
# certificate, and the dial to the server), and the hand-off's own time.
#
#   sudo tests/latency_v1260.sh <warden> [n] [out-file]
#
# Run as root (the proxy runs as its own user).
set -u
WARDEN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
N="${2:-500}"
OUTF="${3:-}"
T="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "latency_v1260.sh: run as root"; exit 2; }
OUT="$(mktemp -d)"
D=/tmp/varek_lat1260.$$
rm -rf "$D"; mkdir -p "$D"; chmod 755 "$D"
cp "$T/v1260_latency.py" "$D/"; chmod 644 "$D/v1260_latency.py"
HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
PORT=$((20000 + RANDOM % 20000))
TP=$((41000 + RANDOM % 2000)); HP=$((TP + 1)); SP=$((TP + 2))
printf '{"api.example.com": {"ttl": 3600, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/zone.json"
python3 "$T/dns_test_server.py" --port "$PORT" --zone "$OUT/zone.json" --ready "$OUT/ready" > /dev/null 2>&1 &
SERVERS="$!"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -days 1 \
    -subj /CN=api.example.com > /dev/null 2>&1
python3 - "$HOSTIP" "$TP" "$HP" "$OUT/cert.pem" "$OUT/key.pem" <<'PY' > /dev/null 2>&1 &
import socket, ssl, sys, threading
ip, tp, hp = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[4], sys.argv[5])
REPLY = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
def serve(c, tls):
    try:
        if tls:
            c = ctx.wrap_socket(c, server_side=True)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(4096)
            if not d: return
            buf += d
        c.sendall(REPLY)
    except Exception:
        pass
    finally:
        c.close()
def listen(port, tls):
    l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind((ip, port)); l.listen(1024)
    while True:
        c, _ = l.accept(); threading.Thread(target=serve, args=(c, tls), daemon=True).start()
threading.Thread(target=listen, args=(hp, False), daemon=True).start()
listen(tp, True)
PY
SERVERS="$SERVERS $!"
SQ=""
if command -v squid > /dev/null || [ -x /usr/sbin/squid ]; then
    SQ=/tmp/varek_lat1260sq.$$; rm -rf "$SQ"; mkdir -p "$SQ"; chmod 777 "$SQ"
    printf '%s api.example.com\n' "$HOSTIP" > "$SQ/hosts"
    printf 'http_port %s:%s\nhttp_access allow all\nhosts_file %s/hosts\naccess_log none\ncache_log %s/cache.log\npid_filename %s/squid.pid\ncache deny all\ncoredump_dir %s\nshutdown_lifetime 1 seconds\n' \
        "$HOSTIP" "$SP" "$SQ" "$SQ" "$SQ" "$SQ" > "$SQ/squid.conf"
    chmod 644 "$SQ"/*
    ( cd "$SQ" && "$(command -v squid || echo /usr/sbin/squid)" -N -f "$SQ/squid.conf" > /dev/null 2>&1 & )
fi
trap 'kill $SERVERS 2>/dev/null; [ -n "$SQ" ] && kill "$(cat "$SQ/squid.pid" 2>/dev/null)" 2>/dev/null; rm -rf "$OUT" "$D" "$SQ"' EXIT
for _ in $(seq 100); do
    [ -e "$OUT/ready" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $TP), 0.2); socket.create_connection(('$HOSTIP', $HP), 0.2)" 2>/dev/null && \
        { [ -z "$SQ" ] || python3 -c "import socket; socket.create_connection(('$HOSTIP', $SP), 0.2)" 2>/dev/null; } && break
    sleep 0.1
done

policy() {   # policy <file> <proxy lines> <host rules...>
    local f="$1" px="$2"; shift 2
    { printf 'require warden 1.26\nproxy on\nproxy ports %s %s\n%b' "$TP" "$HP" "$px"
      for r in "$@"; do printf 'allow host %s\n' "$r"; done
      for d in /usr/ /lib /proc/ /sys/ /etc/ssl/ "$D/"; do printf 'allow path %s readonly\n' "$d"; done
      printf 'allow path /etc/ld.so.cache readonly\n'; } > "$f"
}
policy "$OUT/direct.policy" "" "$HOSTIP:$TP" "$HOSTIP:$HP" "api.example.com:$TP"
policy "$OUT/proxied.policy" "" "api.example.com:$TP" "api.example.com:$HP"
policy "$OUT/squid.policy" "proxy upstream http://$HOSTIP:$SP\n" "api.example.com:$TP" "api.example.com:$HP"

run() {   # run <policy> <log> <client args...>: the client as the agent
    local pol="$1" log="$2"; shift 2
    env -i PATH=/usr/bin:/bin "$WARDEN" "$pol" --dns-server "127.0.0.1:$PORT" \
        -- /usr/bin/python3 "$D/v1260_latency.py" "$@" 2> "$log" | grep '^LAT'
}
row() { printf '%-16s %s\n' "$1" "${2#LAT }"; }
records() {   # records <log> <label>: the Warden's own time on proxied requests
    python3 - "$1" "$2" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith('{"report_id"')]
def p(v, q):
    v = sorted(v); return v[min(len(v) - 1, int(len(v) * q))] if v else -1
px = [r["latency_us"] for r in recs if r.get("action") == "net.proxy" and r.get("rule") == "proxy_dialed"]
ho = [r["latency_us"] for r in recs if r.get("proxy_handoff") is True]
print(f"{sys.argv[2]:<16s} records: decided and dialed n={len(px)} p50={p(px,.5)} p90={p(px,.9)} p99={p(px,.99)}; "
      f"hand-off n={len(ho)} p50={p(ho,.5)} p99={p(ho,.99)} (us)")
PY
}

{
    echo "VAREK v1.26.0 latency of the egress proxy, SNI mode ($(date -u +%Y-%m-%dT%H:%MZ); kernel $(uname -r); $(nproc) vCPU)"
    echo "n=$N requests per row, one after another; percentiles in microseconds, measured by the client;"
    echo "each request is a new connection (TLS: a full handshake, RSA 2048), to servers on this machine's own address."
    row "native tls"     "$(python3 "$D/v1260_latency.py" tls "$HOSTIP" "$TP" api.example.com "$N")"
    row "direct tls"     "$(run "$OUT/direct.policy" "$OUT/r1.log" tls "$HOSTIP" "$TP" api.example.com "$N")"
    row "proxied tls"    "$(run "$OUT/proxied.policy" "$OUT/r2.log" tls api.example.com "$TP" api.example.com "$N")"
    records "$OUT/r2.log" "proxied tls"
    row "native http"    "$(python3 "$D/v1260_latency.py" http "$HOSTIP" "$HP" api.example.com "$N")"
    row "proxied http"   "$(run "$OUT/proxied.policy" "$OUT/r3.log" http api.example.com "$HP" api.example.com "$N")"
    records "$OUT/r3.log" "proxied http"
    if [ -n "$SQ" ]; then
        row "via squid"  "$(run "$OUT/squid.policy" "$OUT/r4.log" tls api.example.com "$TP" api.example.com "$N")"
        records "$OUT/r4.log" "via squid"
    else
        echo "via squid        (Squid is not installed)"
    fi
    row "hand-off only"  "$(run "$OUT/proxied.policy" "$OUT/r5.log" connect api.example.com "$TP" "$N")"
} | tee "$OUT/latency.txt"
[ -n "$OUTF" ] && cp "$OUT/latency.txt" "$OUTF"
exit 0
