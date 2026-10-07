#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# latency_v1240.sh — what deciding a connect on host names costs (v1.24.0).
#
# One connect after another to a listener on this machine's own address, n
# connects each (tests/v1210_bench, static C, blocking TCP):
#   native     the client outside the Warden
#   numeric    under the Warden, allowed by `allow host <addr>:<port>`
#   1 name     allowed by `allow host api.example.com:<port>`, a name that
#              resolves to the address: decided over 2 candidates
#   15 names   15 allowed names that all resolve to the address (the most a
#              v1.24 connect carries): decided over 16 candidates
# For each run under the Warden it reads the connect records: the Warden's
# latency per connect, the dial, and the Warden's own time (latency minus
# the dial), which is where deciding over candidates shows.
#
#   sudo tests/latency_v1240.sh <warden> <v1210_bench> [n] [out-file]
#
# Names are served by tests/dns_test_server.py. Run as root.
set -u
WARDEN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
BENCH="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
N="${3:-3000}"
OUTF="${4:-}"
T="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "latency_v1240.sh: run as root"; exit 2; }
OUT="$(mktemp -d)"
D=/tmp/varek_lat1240
rm -rf "$D"; mkdir -p "$D"; chmod 755 "$D"
cp "$BENCH" "$D/bench"; chmod 755 "$D/bench"
HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
PORT=$((20000 + RANDOM % 20000))
printf '{"api.example.com": {"ttl": 3600, "a": ["%s"]}' "$HOSTIP" > "$OUT/zone.json"
for i in $(seq 1 14); do printf ', "n%s.example.com": {"ttl": 3600, "a": ["%s"]}' "$i" "$HOSTIP"; done >> "$OUT/zone.json"
echo '}' >> "$OUT/zone.json"
python3 "$T/dns_test_server.py" --port "$PORT" --zone "$OUT/zone.json" --ready "$OUT/ready" > /dev/null 2>&1 &
SERVERS="$!"
# the listener takes a free port from the kernel and writes it down
python3 -c '
import socket, sys
s = socket.socket(); s.bind((sys.argv[1], 0)); s.listen(1024)
open(sys.argv[2], "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept(); c.close()' "$HOSTIP" "$OUT/lport" &
SERVERS="$SERVERS $!"
trap 'kill $SERVERS 2>/dev/null; rm -rf "$OUT" "$D"' EXIT
for _ in $(seq 50); do [ -e "$OUT/ready" ] && [ -s "$OUT/lport" ] && break; sleep 0.1; done
LP=$(cat "$OUT/lport")
[ -n "$LP" ] && [ -e "$OUT/ready" ] || { echo "latency_v1240.sh: the servers did not start"; exit 1; }

policy() {   # policy <file> <host rules...>
    local f="$1"; shift
    { printf 'require warden 1.24\n'; for r in "$@"; do printf 'allow host %s\n' "$r"; done
      printf 'allow path %s/ readonly\n' "$D"; } > "$f"
}
policy "$OUT/numeric.policy" "$HOSTIP:$LP"
policy "$OUT/name1.policy" "api.example.com:$LP"
names=("api.example.com:$LP"); for i in $(seq 1 14); do names+=("n$i.example.com:$LP"); done
policy "$OUT/name15.policy" "${names[@]}"

{
    echo "VAREK v1.24.0 connect latency on host names ($(date -u +%Y-%m-%dT%H:%MZ); kernel $(uname -r); $(nproc) vCPU)"
    echo "One blocking TCP connect after another to a listener on this machine's own address; percentiles in microseconds."
    echo "'warden' is the client as the agent; 'records' are the Warden's connect records (its latency, the dial, its own time)."
    no="$("$D/bench" "$HOSTIP" "$LP" "$N" 2>/dev/null | grep '^BENCH')"
    printf '%-12s native  %s\n' "native" "${no#BENCH }"
    for cfg in numeric name1 name15; do
        wo="$(env -i PATH=/usr/bin:/bin "$WARDEN" "$OUT/$cfg.policy" --dns-server "127.0.0.1:$PORT" \
              -- "$D/bench" "$HOSTIP" "$LP" "$N" 2> "$OUT/$cfg.log" | grep '^BENCH')"
        printf '%-12s warden  %s\n' "$cfg" "${wo#BENCH }"
        python3 - "$OUT/$cfg.log" "$cfg" <<'PY'
import json, sys
c = [json.loads(l) for l in open(sys.argv[1]) if l.startswith('{"report_id"') and '"net.connect"' in l]
c = [r for r in c if r["decision_final"] == "ALLOW"]
if c:
    def p(v, q):
        v = sorted(v); return v[min(len(v) - 1, int(len(v) * q))]
    lat = [r["latency_us"] for r in c]; dial = [r["dial_us"] for r in c]
    own = [a - b for a, b in zip(lat, dial)]
    cands = sorted({len(r.get("candidates", [])) for r in c})
    by = sorted({r.get("resolved", "").split(":")[0] for r in c})
    print(f"{sys.argv[2]:<12s} records n={len(c)} candidates={cands} decided on {by[:2]}{'...' if len(by) > 2 else ''}; "
          f"warden latency p50={p(lat,.5)} p90={p(lat,.9)} p99={p(lat,.99)}; dial p50={p(dial,.5)} p99={p(dial,.99)}; "
          f"Warden's own p50={p(own,.5)} p90={p(own,.9)} p99={p(own,.99)} (us)")
else:
    print(f"{sys.argv[2]:<12s} records: no allowed connect (see the log)")
PY
    done
} | tee "$OUT/latency.txt"
[ -n "$OUTF" ] && cp "$OUT/latency.txt" "$OUTF"
exit 0
