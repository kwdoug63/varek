#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# latency_v1261.sh — what the egress proxy costs in inspecting mode (v1.26.1;
# docs/security/v1.26.1-inspecting-mode.md, section 6). The v1.26.0 table
# (tests/latency_v1260.sh) again, each proxied row in SNI mode and in
# inspecting mode, with kept-alive rows: n requests on one connection, the
# per-request cost once a connection is open (in inspecting mode, each
# request decided by the Warden before any of it is sent).
#
# Requests, n each, one after another (tests/v1261_latency.py), to servers on
# this machine's own address (a TLS server and an HTTP server, keep-alive,
# replying a few bytes):
#   native ...       no Warden
#   sni ...          under the Warden, `proxy on`, `allow host
#                    api.example.com:<port>`: decided on the name, relayed
#   inspect ...      `proxy inspect`, the same host rules and a request rule
#                    for GET /: the server verified, the client's TLS
#                    terminated with the run's CA, each request decided
#   ... tls          a new connection each (a full handshake, RSA 2048 at the
#                    server; in inspecting mode a second, P-256, to the client)
#   ... tls ka       requests on one kept-alive connection
#   ... http, http ka   the same for plain HTTP
#   via squid ...    the tls row through a Squid upstream, where installed
#   hand-off only    connects to the synthetic address, closed at once
# For proxied rows it also reads the Warden's records: a connection decided
# and dialed (net.proxy), a request decided (net.request), and the hand-off.
#
#   sudo tests/latency_v1261.sh <warden> [n] [out-file]
#
# Run as root (the proxy runs as its own user).
set -u
WARDEN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
N="${2:-500}"
OUTF="${3:-}"
T="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "latency_v1261.sh: run as root"; exit 2; }
OUT="$(mktemp -d)"
D=/tmp/varek_lat1261.$$
rm -rf "$D"; mkdir -p "$D"; chmod 755 "$D"
cp "$T/v1261_latency.py" "$D/"; chmod 644 "$D/v1261_latency.py"
HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
PORT=$((20000 + RANDOM % 20000))
TP=$((41000 + RANDOM % 2000)); HP=$((TP + 1)); SP=$((TP + 2))
printf '{"api.example.com": {"ttl": 3600, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/zone.json"
python3 "$T/dns_test_server.py" --port "$PORT" --zone "$OUT/zone.json" --ready "$OUT/ready" > /dev/null 2>&1 &
SERVERS="$!"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -days 1 \
    -subj /CN=api.example.com -addext subjectAltName=DNS:api.example.com > /dev/null 2>&1
cp "$OUT/cert.pem" "$D/server.pem"; chmod 644 "$D/server.pem"     # the proxy verifies the server by it
python3 - "$HOSTIP" "$TP" "$HP" "$OUT/cert.pem" "$OUT/key.pem" <<'PY' > /dev/null 2>&1 &
import socket, ssl, sys, threading
ip, tp, hp = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[4], sys.argv[5])
REPLY = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n%s\r\nok"
def serve(c, tls):
    try:
        if tls:
            c = ctx.wrap_socket(c, server_side=True)
        buf = b""
        while True:
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d: return
                buf += d
            head, _, buf = buf.partition(b"\r\n\r\n")
            close = b"\r\nconnection: close" in head.lower()
            c.sendall(REPLY % (b"Connection: close\r\n" if close else b""))
            if close: return
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
    SQ=/tmp/varek_lat1261sq.$$; rm -rf "$SQ"; mkdir -p "$SQ"; chmod 777 "$SQ"
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

policy() {   # policy <file> <mode: on|inspect> <proxy lines>
    local f="$1" mode="$2" px="$3"
    { printf 'require warden 1.26\nproxy %s\nproxy ports %s %s\n%b' "$mode" "$TP" "$HP" "$px"
      printf 'allow host api.example.com:%s\nallow host api.example.com:%s\n' "$TP" "$HP"
      if [ "$mode" = inspect ]; then
          printf 'allow request GET https://api.example.com:%s/\nallow request GET http://api.example.com:%s/\n' "$TP" "$HP"
      fi
      for d in /usr/ /lib /proc/ /sys/ /etc/ssl/ "$D/"; do printf 'allow path %s readonly\n' "$d"; done
      printf 'allow path /etc/ld.so.cache readonly\n'; } > "$f"
}
policy "$OUT/sni.policy" on ""
policy "$OUT/inspect.policy" inspect ""
policy "$OUT/sni_squid.policy" on "proxy upstream http://$HOSTIP:$SP\n"
policy "$OUT/inspect_squid.policy" inspect "proxy upstream http://$HOSTIP:$SP\n"

run() {   # run <policy> <log> <client args...>: the client as the agent
    local pol="$1" log="$2"; shift 2
    env -i PATH=/usr/bin:/bin "$WARDEN" "$pol" --dns-server "127.0.0.1:$PORT" --trust-bundle "$D/server.pem" \
        -- /usr/bin/python3 "$D/v1261_latency.py" "$@" 2> "$log" | grep '^LAT'
}
records() {   # records <log> <label>: the Warden's own time on proxied connections and requests
    python3 - "$1" "$2" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith('{"report_id"')]
def p(v, q):
    v = sorted(v); return v[min(len(v) - 1, int(len(v) * q))] if v else -1
px = [r["latency_us"] for r in recs if r.get("action") == "net.proxy" and r.get("rule") == "proxy_dialed"]
rq = [r["latency_us"] for r in recs if r.get("action") == "net.request" and r.get("rule") == "request_allowed"]
ho = [r["latency_us"] for r in recs if r.get("proxy_handoff") is True]
print(f"{sys.argv[2]:<18s} records: decided and dialed n={len(px)} p50={p(px,.5)} p99={p(px,.99)}"
      + (f"; request decided n={len(rq)} p50={p(rq,.5)} p99={p(rq,.99)}" if rq else "")
      + f"; hand-off p50={p(ho,.5)} p99={p(ho,.99)} (us)")
PY
}
row() { printf '%-18s %s\n' "$1" "${2#LAT }"; }
CL="$D/v1261_latency.py"

{
    echo "VAREK v1.26.1 latency of the egress proxy, SNI and inspecting mode ($(date -u +%Y-%m-%dT%H:%MZ); kernel $(uname -r); $(nproc) vCPU)"
    echo "n=$N requests per row, one after another; percentiles in microseconds, measured by the client;"
    echo "tls/http: a new connection each (TLS: a full handshake, RSA 2048 at the server); ka: on one kept-alive connection;"
    echo "servers on this machine's own address. In inspecting mode every request is decided before any of it is sent."
    row "native tls"       "$(python3 "$CL" tls "$HOSTIP" "$TP" api.example.com "$N")"
    row "sni tls"          "$(run "$OUT/sni.policy" "$OUT/r1.log" tls api.example.com "$TP" api.example.com "$N")"
    records "$OUT/r1.log" "sni tls"
    row "inspect tls"      "$(run "$OUT/inspect.policy" "$OUT/r2.log" tls api.example.com "$TP" api.example.com "$N")"
    records "$OUT/r2.log" "inspect tls"
    row "native tls ka"    "$(python3 "$CL" tlska "$HOSTIP" "$TP" api.example.com "$N")"
    row "sni tls ka"       "$(run "$OUT/sni.policy" "$OUT/r3.log" tlska api.example.com "$TP" api.example.com "$N")"
    row "inspect tls ka"   "$(run "$OUT/inspect.policy" "$OUT/r4.log" tlska api.example.com "$TP" api.example.com "$N")"
    records "$OUT/r4.log" "inspect tls ka"
    row "native http"      "$(python3 "$CL" http "$HOSTIP" "$HP" api.example.com "$N")"
    row "sni http"         "$(run "$OUT/sni.policy" "$OUT/r5.log" http api.example.com "$HP" api.example.com "$N")"
    row "inspect http"     "$(run "$OUT/inspect.policy" "$OUT/r6.log" http api.example.com "$HP" api.example.com "$N")"
    records "$OUT/r6.log" "inspect http"
    row "native http ka"   "$(python3 "$CL" httpka "$HOSTIP" "$HP" api.example.com "$N")"
    row "sni http ka"      "$(run "$OUT/sni.policy" "$OUT/r7.log" httpka api.example.com "$HP" api.example.com "$N")"
    row "inspect http ka"  "$(run "$OUT/inspect.policy" "$OUT/r8.log" httpka api.example.com "$HP" api.example.com "$N")"
    if [ -n "$SQ" ]; then
        row "via squid sni"     "$(run "$OUT/sni_squid.policy" "$OUT/r9.log" tls api.example.com "$TP" api.example.com "$N")"
        row "via squid inspect" "$(run "$OUT/inspect_squid.policy" "$OUT/r10.log" tls api.example.com "$TP" api.example.com "$N")"
        records "$OUT/r10.log" "via squid inspect"
    else
        echo "via squid          (Squid is not installed)"
    fi
    row "hand-off only"    "$(run "$OUT/inspect.policy" "$OUT/r11.log" connect api.example.com "$TP" "$N")"
} | tee "$OUT/latency.txt"
[ -n "$OUTF" ] && cp "$OUT/latency.txt" "$OUTF"
exit 0
