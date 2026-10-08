#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# latency_v1250.sh — what wildcard host names cost (v1.25.0).
#
# Lookups, n each (tests/v1250_latency.py, IPv4, one after another):
#   raw direct     A questions straight to the test DNS server, no Warden:
#                  what one upstream question costs here
#   raw stub new   A questions to the Warden's stub, a new name each time:
#                  the stub, the resolver helper and the upstream question
#   raw stub again the same name again and again: answered from the table
#   gai exact      getaddrinfo of an exact name: the hosts view, as in v1.24
#   gai new        getaddrinfo of a new wildcard name each time
#   gai again      getaddrinfo of the same wildcard name again and again
# Connects, n each, one blocking TCP connect after another to a listener on
# this machine's own address:
#   numeric        allowed by `allow host <addr>:<port>`
#   1 name         by `allow host *.many.example.com:<port>`, one name
#                  resolved to the address: decided over 2 candidates
#   40 names       40 names under the wildcard resolved to the address:
#                  decided over 41 candidates, recorded hashed
# For connects it also reads the Warden's records: its latency per connect,
# the dial, and its own time (latency minus the dial).
#
#   sudo tests/latency_v1250.sh <warden> [n] [out-file]
#
# Names are served by tests/dns_test_server.py. Run as root.
set -u
WARDEN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
N="${2:-1000}"
OUTF="${3:-}"
T="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "latency_v1250.sh: run as root"; exit 2; }
OUT="$(mktemp -d)"
D=/tmp/varek_lat1250
rm -rf "$D"; mkdir -p "$D"; chmod 755 "$D"
cp "$T/v1250_latency.py" "$D/"; chmod 644 "$D/v1250_latency.py"
HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
PORT=$((20000 + RANDOM % 20000))
python3 - "$OUT/zone.json" "$HOSTIP" "$N" <<'PY'
import json, sys
ip, n = sys.argv[2], int(sys.argv[3])
z = {"api.example.com": {"ttl": 3600, "a": [ip]}, "again.wild.example.com": {"ttl": 3600, "a": [ip]}}
for i in range(n):
    z[f"n{i}.new.example.com"] = {"ttl": 3600, "a": [ip]}     # stub, new names
    z[f"g{i}.new.example.com"] = {"ttl": 3600, "a": [ip]}     # getaddrinfo, new names
    z[f"d{i}.direct.example.com"] = {"ttl": 3600, "a": [ip]}  # no Warden
for i in range(40):
    z[f"m{i}.many.example.com"] = {"ttl": 3600, "a": [ip]}
json.dump(z, open(sys.argv[1], "w"))
PY
python3 "$T/dns_test_server.py" --port "$PORT" --zone "$OUT/zone.json" --ready "$OUT/ready" > /dev/null 2>&1 &
SERVERS="$!"
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
[ -n "$LP" ] && [ -e "$OUT/ready" ] || { echo "latency_v1250.sh: the servers did not start"; exit 1; }

policy() {   # policy <file> <host rules...>
    local f="$1"; shift
    { printf 'require warden 1.25\n'; for r in "$@"; do printf 'allow host %s\n' "$r"; done
      for d in /usr/ /lib /proc/ /sys/ "$D/"; do printf 'allow path %s readonly\n' "$d"; done
      printf 'allow path /etc/ld.so.cache readonly\n'; } > "$f"
}
# budgets large enough that the runs measure lookups, not refusals
B="names=100000 rate=10000 acknowledge=dns-channel"
policy "$OUT/lookup.policy" "api.example.com:443" "*.new.example.com:443 $B" "*.wild.example.com:443 $B"
policy "$OUT/numeric.policy" "$HOSTIP:$LP"
policy "$OUT/many.policy" "*.many.example.com:$LP $B"

run() {   # run <policy> <log> <client args...>: the client as the agent
    local pol="$1" log="$2"; shift 2
    env -i PATH=/usr/bin:/bin "$WARDEN" "$pol" --dns-server "127.0.0.1:$PORT" \
        -- /usr/bin/python3 "$D/v1250_latency.py" "$@" 2> "$log" | grep '^LAT'
}
row() { printf '%-16s %s\n' "$1" "${2#LAT }"; }
records() {   # records <log> <label>: the Warden's records of connects to the listener
    python3 - "$1" "$2" "$LP" <<'PY'
import json, sys
c = [json.loads(l) for l in open(sys.argv[1]) if l.startswith('{"report_id"') and '"net.connect"' in l]
c = [r for r in c if r["decision_final"] == "ALLOW" and r.get("dial_us") is not None
     and any(str(r.get(k, "")).endswith(":" + sys.argv[3]) for k in ("dialed", "resolved"))]
if c:
    def p(v, q):
        v = sorted(v); return v[min(len(v) - 1, int(len(v) * q))]
    lat = [r["latency_us"] for r in c]; dial = [r["dial_us"] for r in c]
    own = [a - b for a, b in zip(lat, dial)]
    cands = sorted({r.get("candidates_n", len(r.get("candidates", []))) for r in c})
    hashed = sum(1 for r in c if "candidates_sha256" in r)
    print(f"{sys.argv[2]:<16s} records n={len(c)} candidates={cands} hashed={hashed}; "
          f"warden latency p50={p(lat,.5)} p99={p(lat,.99)}; dial p50={p(dial,.5)} p99={p(dial,.99)}; "
          f"Warden's own p50={p(own,.5)} p90={p(own,.9)} p99={p(own,.99)} (us)")
else:
    print(f"{sys.argv[2]:<16s} records: no allowed connect (see the log)")
PY
}

{
    echo "VAREK v1.25.0 latency of wildcard host names ($(date -u +%Y-%m-%dT%H:%MZ); kernel $(uname -r); $(nproc) vCPU)"
    echo "n=$N per lookup row, $N connects per connect row; percentiles in microseconds, measured by the client."
    echo "Upstream is tests/dns_test_server.py on 127.0.0.1 (it re-reads its zone file on every question)."
    row "raw direct"     "$(python3 "$D/v1250_latency.py" raw 127.0.0.1 "$PORT" 'd{i}.direct.example.com' "$N")"
    row "raw stub new"   "$(run "$OUT/lookup.policy" "$OUT/l1.log" raw 127.53.53.53 53 'n{i}.new.example.com' "$N")"
    row "raw stub again" "$(run "$OUT/lookup.policy" "$OUT/l2.log" raw 127.53.53.53 53 'again.wild.example.com' "$N")"
    row "gai exact"      "$(run "$OUT/lookup.policy" "$OUT/l3.log" gai 'api.example.com' "$N")"
    row "gai new"        "$(run "$OUT/lookup.policy" "$OUT/l4.log" gai 'g{i}.new.example.com' "$N")"
    row "gai again"      "$(run "$OUT/lookup.policy" "$OUT/l5.log" gai 'again.wild.example.com' "$N")"
    row "native connect" "$(python3 "$D/v1250_latency.py" connect "$HOSTIP" "$LP" "$N")"
    row "numeric"        "$(run "$OUT/numeric.policy" "$OUT/c1.log" connect "$HOSTIP" "$LP" "$N")"
    records "$OUT/c1.log" "numeric"
    row "1 name"         "$(run "$OUT/many.policy" "$OUT/c2.log" connect "$HOSTIP" "$LP" "$N" 'm{i}.many.example.com' 1)"
    records "$OUT/c2.log" "1 name"
    row "40 names"       "$(run "$OUT/many.policy" "$OUT/c3.log" connect "$HOSTIP" "$LP" "$N" 'm{i}.many.example.com' 40)"
    records "$OUT/c3.log" "40 names"
} | tee "$OUT/latency.txt"
[ -n "$OUTF" ] && cp "$OUT/latency.txt" "$OUTF"
exit 0
