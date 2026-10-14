#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# latency_v1310.sh — v1.31's latency figures (make latency-v1310), written
# to tests/latency_v1.31.0.txt:
#   1. varek bench --for: the Warden's own time per decision when the calls
#      are the agent's (after the baseline), a confined MCP server's (its
#      rules the bench's only), and a server's with its own copy of the
#      baseline (as varek run --mcp writes it), alternated;
#   2. varek bench --mcp: tools/call over HTTPS with bodies of 1 KiB to
#      1 MiB, natively, under a request rule (the body streamed) and under an
#      MCP rule (the body held, read and parsed, then sent): the time the
#      proxy adds per call, and the Warden's own time per decision;
#   3. startup: wall time of `warden POLICY -- /usr/bin/true`, K runs each,
#      under the baseline and the baseline with one and with four MCP
#      servers (each server's file hashed and checked at the start).
# Run as root.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
N="${N:-2000}" NM="${NM:-100}" K="${K:-20}" R="${R:-5}"
OUT="${OUT:-$HERE/tests/latency_v1.31.0.txt}"
T="$(mktemp -d /tmp/varek_lat1310.XXXXXX)"; chmod 755 "$T"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/proj" "$T/srv"; chmod 755 "$T/proj" "$T/srv"
for i in 1 2 3 4; do cp "$HERE/tools/bench_workload" "$T/srv/s$i"; chmod 755 "$T/srv/s$i"; done
# the policies varek run writes, for nobody in $T/proj (with --mcp sN=...)
PYTHONPATH="$HERE/tools" python3 -c "
import pwd, varek_baseline as b
pw, tmp = pwd.getpwnam('nobody'), '/tmp/varek-65534'
open('$T/base.txt', 'w').write(b.generate('$T/proj', pw, tmp, None))
for k in (1, 4):
    sv = b.mcp_servers(['s%d=$T/srv/s%d' % (i, i) for i in range(1, k + 1)], '$T/proj', tmp)
    open('$T/mcp%d.txt' % k, 'w').write(b.generate('$T/proj', pw, tmp, None, servers=sv))"
chmod 644 "$T"/*.txt
V() { NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" "$@"; }
# ms POLICY: K starts, the p50 and p90 of their wall time in ms
ms() { local pol="$1"
       for _ in $(seq "$K"); do
           s=$(date +%s%N); (cd "$T/proj" && "$HERE/warden" "$pol" --run-as nobody -- /usr/bin/true > /dev/null 2>&1) || echo "FAILED" >&2
           echo $(( ($(date +%s%N) - s) / 1000 ))
       done | sort -n | awk '{a[NR]=$1} END {printf "p50 %.1f ms, p90 %.1f ms (%d runs)", a[int(NR*0.5)+1]/1000, a[int(NR*0.9)+1]/1000, NR}'; }
rules() { grep -cE '^(allow|deny)' "$1"; }
{
    echo "# v1.31.0 latency (tests/latency_v1310.sh, N=$N, NM=$NM, K=$K, R=$R), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "## 1. a confined MCP server's decisions against the agent's: varek bench --for"
    V bench --for -n "$N" --warmup 200 --rounds "$R" 2>/dev/null
    echo
    echo "## 2. MCP calls over HTTP, 1 KiB to 1 MiB: varek bench --mcp"
    V bench --mcp -n "$NM" --warmup 10 --rounds "$R" 2>/dev/null
    echo
    echo "## 3. startup: warden POLICY -- /usr/bin/true, wall time (each server's file hashed and checked at start)"
    echo "the baseline ($(rules "$T/base.txt") rules):                   $(ms "$T/base.txt")"
    echo "the baseline + 1 MCP server ($(rules "$T/mcp1.txt") rules):    $(ms "$T/mcp1.txt")"
    echo "the baseline + 4 MCP servers ($(rules "$T/mcp4.txt") rules):   $(ms "$T/mcp4.txt")"
} > "$OUT"
echo "latency_v1310: written to $OUT"
