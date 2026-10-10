#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# latency_v1270.sh — v1.27's latency figures (make latency-v1270), written to
# tests/latency_v1.27.0.txt:
#   1. varek bench --launches: a launch the policy allows and one a deny rule
#      refuses (spawn, launch, wait), natively, with launches off (1.26) and on
#      (1.27), and the Warden's own time per decision;
#   2. the identity check alone: varek bench (opens and connects) under a base
#      policy `require warden 1.26` and one `require warden 1.27`, alternated.
# Run as root on a host with Landlock.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
N="${N:-1000}"
OUT="${OUT:-$HERE/tests/latency_v1.27.0.txt}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
chmod 755 "$T"
printf 'require warden 1.26\n' > "$T/b126.txt"; printf 'require warden 1.27\n' > "$T/b127.txt"
chmod 644 "$T"/b12*.txt
V() { NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" "$@"; }
{
    echo "# v1.27.0 latency (tests/latency_v1270.sh, N=$N), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "## 1. launches"
    V bench --launches -n "$N" --warmup 50 --rounds 3 2>/dev/null
    echo
    echo "## 2. the identity check alone (varek bench, p50 us: the agent's call / the Warden's decision)"
    for round in 1 2 3; do
        for b in 126 127; do
            V bench --policy "$T/b$b.txt" -n "$((N * 2))" --rounds 1 --json 2>/dev/null | python3 -c "
import json, sys
r = json.load(sys.stdin)
print('round $round, require warden 1.${b#1}:', 'checks passed' if r['ok'] else 'CHECKS FAILED', '; '.join(
    f\"{k} {v['warden']['p50']} / {v['warden_decision_us']['p50']}\" for k, v in r['kinds'].items()))"
        done
    done
} > "$OUT"
echo "latency_v1270: written to $OUT"
