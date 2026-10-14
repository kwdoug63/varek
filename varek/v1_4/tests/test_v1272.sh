#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1272.sh — VAREK v1.27.2: in a signed verdict stream no checkpoint
# seals more than checkpoint_every records (RELEASE-v1.27.2.md).
#
# Checkpoints were written only between notifications, but one pass over the
# egress proxy's reports (a burst of requests) can write several records, so a
# signed stream could hold more than checkpoint_every (64) records between two
# signatures and fail its own audit. An agent under the inspecting proxy makes
# 20 bursts of 32 requests at once, in a signed run:
#   1. the Warden reports 1.27.2;
#   2. every gap between signed records is within checkpoint_every;
#   3. the audit passes the stream, signed.
#
#   test_v1272.sh VDP_CHECK VDP_CERT_CHECK WARDEN
set -u
CERT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
WARDEN="${3:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WP="$HERE/warden-proxy"
OUT="$(mktemp -d)"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
SRV=""
trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT ${W:-}" || rm -rf "$OUT" "${W:-}"' EXIT

echo "== 1. the version =="
check "the Warden reports 1.27.2" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | grep -q 'VAREK Warden  1.27.2'"

echo "== 2. a signed run of requests in bursts =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ] || [ ! -x "$WP" ] || ! command -v openssl > /dev/null; then
    skip "a signed run of requests in bursts (needs root, the warden binary, warden-proxy and openssl)"
else
    W="$(mktemp -d /tmp/varek_v1272.XXXXXX)"; chmod 755 "$W"
    HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
    P1=$((42000 + RANDOM % 5000))
    ( cd "$W" &&
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tca.key -out tca.pem -days 2 \
          -subj "/CN=VAREK test root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" &&
      openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout api.key -out api.csr -subj "/CN=api.example.com" &&
      printf 'subjectAltName=DNS:api.example.com\nextendedKeyUsage=serverAuth\n' > api.ext &&
      openssl x509 -req -in api.csr -CA tca.pem -CAkey tca.key -CAcreateserial -out api.pem -days 1 -extfile api.ext
    ) > "$OUT/certs.log" 2>&1
    BUNDLE="$W/bundle.pem"            # the proxy reads it, as its own user
    cat "$(python3 -c 'import ssl; print(ssl.get_default_verify_paths().openssl_cafile)')" "$W/tca.pem" > "$BUNDLE"
    chmod 644 "$BUNDLE" "$W"/*.pem
    cat > "$OUT/srv.py" <<'PY'
import socket, ssl, sys, threading
ip, port, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind((ip, port)); l.listen(64)
def serve(c):
    try:
        s = ctx.wrap_socket(c, server_side=True)
        if s.recv(1000):
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        s.close()
    except Exception:
        pass
while True:
    c, _ = l.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
    python3 "$OUT/srv.py" "$HOSTIP" "$P1" "$W/api.pem" "$W/api.key" > "$OUT/srv.log" 2>&1 &
    SRV="$SRV $!"
    DPORT=$((20000 + RANDOM % 20000))
    printf '{"api.example.com": {"ttl": 300, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/zone.json"
    python3 "$HERE/tests/dns_test_server.py" --port "$DPORT" --zone "$OUT/zone.json" --log "$OUT/q.log" \
        --ready "$OUT/ready" > /dev/null 2>&1 &
    SRV="$SRV $!"
    for _ in $(seq 50); do
        [ -e "$OUT/ready" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $P1), 0.2)" 2>/dev/null && break
        sleep 0.1
    done
    cat > "$W/burst.py" <<'PY'
import socket, ssl, sys, threading
P = int(sys.argv[1]); ctx = ssl.create_default_context(); ok = []
def one():
    try:
        s = ctx.wrap_socket(socket.create_connection(("api.example.com", P), 15), server_hostname="api.example.com")
        s.sendall(b"GET /v1/burst HTTP/1.1\r\nHost: api.example.com:%d\r\n\r\n" % P); s.recv(100); s.close(); ok.append(1)
    except (OSError, ssl.SSLError):
        pass
for _ in range(20):
    ts = [threading.Thread(target=one) for _ in range(32)]
    [t.start() for t in ts]; [t.join() for t in ts]
print("BURST", len(ok), flush=True)
PY
    chmod 644 "$W/burst.py"
    POL="$OUT/burst.policy"
    printf 'require warden 1.26\nproxy inspect\nproxy ports %s\nallow host api.example.com\nallow request GET https://api.example.com:%s/v1/burst\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path exact %s/burst.py readonly\n' \
        "$P1" "$P1" "$W" > "$POL"
    "$HERE/tools/varek_keygen" "$W/bk" > /dev/null 2>&1
    env -i PATH=/usr/bin:/bin timeout 180 "$WARDEN" "$POL" --sign-key "$W/bk" --dns-server "127.0.0.1:$DPORT" \
        --trust-bundle "$BUNDLE" -- /usr/bin/python3 "$W/burst.py" "$P1" > "$OUT/burst.out" 2> "$OUT/burst.log"
    sed 's/^/     /' "$OUT/burst.out"
    check "the agent's requests went through the proxy" grep -q '^BURST [1-9]' "$OUT/burst.out"
    # the largest number of decision records between two signed records (a
    # checkpoint, or run_start and run_end, which are signed too)
    python3 - "$OUT/burst.log" > "$OUT/gap.txt" <<'PY'
import json, sys
every, gap, worst, signed = 64, 0, 0, 0
for l in open(sys.argv[1], errors="replace"):
    if not l.startswith("{"):
        continue
    r = json.loads(l)
    if r.get("event") == "run_start":
        every = int(r.get("checkpoint_every", every))
    if "sig" in r:
        signed += 1; worst = max(worst, gap); gap = 0
    elif "report_id" in r:
        gap += 1
print(max(worst, gap), every, signed)
PY
    read -r GAP EVERY NSIG < "$OUT/gap.txt"
    echo "     the most decision records between two signatures: $GAP (checkpoint_every $EVERY; $NSIG signed records)"
    check "no checkpoint seals more than checkpoint_every records" sh -c "[ '$NSIG' -gt 2 ] && [ '$GAP' -le '$EVERY' ]"
    python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" --pubkey "$W/bk.pub" "$OUT/burst.log" > "$OUT/burst.aud" 2>&1
    check "the audit passes the stream, signed" sh -c "grep -q 'varek_audit: PASS' '$OUT/burst.aud' && grep -q 'integrity: signed' '$OUT/burst.aud'"
    [ "$fail" = 0 ] || grep -m3 PROBLEM "$OUT/burst.aud" | sed 's/^/     /'
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1272: PASS ($skips skipped)"; else echo "test_v1272: FAIL"; fi
exit "$fail"
