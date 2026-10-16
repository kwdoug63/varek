#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# latency_v1281.sh — v1.28.1's latency figures (make latency-v1281), written
# to tests/latency_v1.28.1.txt:
#   1. varek bench --subagents: the bench's opens and connects with no
#      sub-agent named and with one named (each call's control group read
#      before it is decided), alternated, and the Warden's own time per
#      decision (1b: the same with the group read from /proc, the fallback
#      before Linux 6.13);
#   2. startup: wall time of `warden POLICY -- /usr/bin/true`, K runs each,
#      with no identity, with a user's token (warden-secrets started, the
#      stand-in issuer's discovery document and keys fetched over HTTPS on
#      this host, the token verified), and with a sub-agent named (the
#      run's control group made and removed).
# Run as root, with python3-cryptography and a cgroup2 mount.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
N="${N:-2000}" K="${K:-20}"
OUT="${OUT:-$HERE/tests/latency_v1.28.1.txt}"
T="$(mktemp -d /tmp/varek_lat1281.XXXXXX)"; chmod 755 "$T"
python3 "$HERE/tests/v1281_idp.py" serve "$T" > "$T/serve.out" 2>&1 &
IDP=$!
trap 'kill $IDP 2>/dev/null; rm -rf "$T"' EXIT
for _ in $(seq 100); do [ -f "$T/port" ] && break; sleep 0.1; done
ISS="https://127.0.0.1:$(cat "$T/port")"
chmod 644 "$T/ca.pem"; printf 'oidc_ca = %s/ca.pem\n' "$T" > "$T/conf"; chmod 600 "$T/conf"
python3 "$HERE/tests/v1281_idp.py" mint "$T" es256 > "$T/tok"; chmod 600 "$T/tok"
L='allow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\n'
printf "require warden 1.28\n$L" > "$T/none.txt"
printf "require warden 1.28\ntrust issuer $ISS audience varek-agent\n$L" > "$T/user.txt"
printf "require warden 1.28\nallow exec /usr/bin/env subagent=x\n$L" > "$T/sub.txt"
chmod 644 "$T"/*.txt
V() { NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" "$@"; }
# ms <policy> [options]: K starts, the p50 and p90 of their wall time in ms
ms() { local pol="$1"; shift
       for _ in $(seq "$K"); do
           s=$(date +%s%N); "$HERE/warden" "$pol" "$@" -- /usr/bin/true > /dev/null 2>&1 || echo "FAILED" >&2
           echo $(( ($(date +%s%N) - s) / 1000 ))
       done | sort -n | awk '{a[NR]=$1} END {printf "p50 %.1f ms, p90 %.1f ms (%d runs)", a[int(NR*0.5)+1]/1000, a[int(NR*0.9)+1]/1000, NR}'; }
{
    echo "# v1.28.1 latency (tests/latency_v1281.sh, N=$N, K=$K), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "## 1. attribution: varek bench --subagents"
    V bench --subagents -n "$N" --warmup 200 --rounds 3 2>/dev/null
    echo
    echo "## 1b. the same, each call's group read from /proc (as on a kernel before 6.13)"
    VAREK_WARDEN_TEST_NO_PIDFD_INFO=1 V bench --subagents -n "$N" --warmup 200 --rounds 3 2>/dev/null
    echo
    echo "## 2. startup: warden POLICY -- /usr/bin/true, wall time"
    echo "no identity, no sub-agent:                   $(ms "$T/none.txt")"
    echo "a user's token (stand-in issuer, this host): $(ms "$T/user.txt" --secrets-conf "$T/conf" --on-behalf-of "$T/tok")"
    echo "a sub-agent named (the run's group):         $(ms "$T/sub.txt")"
} > "$OUT"
echo "latency_v1281: written to $OUT"
