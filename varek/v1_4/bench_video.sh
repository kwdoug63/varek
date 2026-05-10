#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# bench_video.sh — VAREK Warden v1.4 live benchmark, video-capture friendly.
#
# This script runs the real benchmark (warden + bench_target) and presents
# the results with deliberate pacing suitable for screen recording.
# Every number displayed comes from a real measurement of a real run.
# There are no random values, no hardcoded summaries, and no synthetic
# outputs anywhere in this script or in the tools it invokes.
#
# Usage:   sudo ./bench_video.sh
#          sudo ./bench_video.sh --no-color   (plain output)
#          sudo ./bench_video.sh --quick      (skip pacing, run as fast as possible)
#
# Requires: warden, bench_target, bench_summarize.py, bench_histogram.py
#           in the current directory; Linux >= 5.14; root.

set -euo pipefail

# ---- options -----------------------------------------------------------
USE_COLOR=1
QUICK=0
for arg in "$@"; do
    case "$arg" in
        --no-color) USE_COLOR=0 ;;
        --quick)    QUICK=1 ;;
        -h|--help)
            sed -n '2,16p' "$0" | sed 's/^# //; s/^#//'
            exit 0 ;;
    esac
done

# ---- styling -----------------------------------------------------------
if [[ $USE_COLOR -eq 1 ]]; then
    T='\033[38;5;51m'   # teal
    W='\033[1;37m'      # white bold
    D='\033[2;37m'      # dim
    G='\033[0;32m'      # green
    R='\033[0;31m'      # red
    Y='\033[1;33m'      # yellow
    B='\033[1m'         # bold
    N='\033[0m'         # reset
else
    T='' W='' D='' G='' R='' Y='' B='' N=''
fi

HLINE='────────────────────────────────────────────────────────────'

banner() {
    echo
    echo -e "  ${T}${B}┌${HLINE}┐${N}"
    printf  "  ${T}${B}│${N}  %-58s${T}${B}│${N}\n" "$1"
    printf  "  ${T}${B}│${N}  ${D}%-58s${N}${T}${B}│${N}\n" "$2"
    echo -e "  ${T}${B}└${HLINE}┘${N}"
    echo
}

section() { echo -e "${W}  ▌ $1${N}"; }

pause() {
    [[ $QUICK -eq 1 ]] && return
    sleep "${1:-1.0}"
}

# ---- preconditions -----------------------------------------------------
if [[ ! -f warden.c ]]; then
    echo "error: run from the v1_4 directory (warden.c not found)"
    exit 1
fi

# Auto-elevate if not root
if [[ $EUID -ne 0 ]]; then
    exec sudo -E "$0" "$@"
fi

# Auto-build if needed
if [[ ! -x warden || ! -x bench_target || warden.c -nt warden ]]; then
    echo -e "${Y}  building binaries...${N}"
    make >/dev/null 2>&1
    echo
fi

clear

# ---- Scene 1: Title ----------------------------------------------------
banner "VAREK Warden v1.4 — Live Benchmark" \
       "Deterministic Safety for Autonomous Systems"
pause 2

# ---- Scene 2: Host -----------------------------------------------------
section "Host"
echo -e "    Kernel:    $(uname -srm)"
CPU=$(grep 'model name' /proc/cpuinfo | head -1 | sed 's/.*: //')
echo -e "    CPU:       ${CPU}"
MEM=$(free -h | awk 'NR==2 {printf "%s total, %s available", $2, $7}')
echo -e "    Memory:    ${MEM}"
echo
pause 2

# ---- Scene 3: Build verification ---------------------------------------
section "Build verification"
WARDEN_SHA=$(sha256sum warden | cut -c1-12)
BENCH_SHA=$(sha256sum bench_target | cut -c1-12)
WARDEN_SZ=$(stat -c '%s' warden)
BENCH_SZ=$(stat -c '%s' bench_target)
echo -e "    ${G}✓${N} warden        ${D}sha256:${WARDEN_SHA}${N}  ${WARDEN_SZ} bytes"
echo -e "    ${G}✓${N} bench_target  ${D}sha256:${BENCH_SHA}${N}  ${BENCH_SZ} bytes"
echo
pause 1.5

# ---- Scene 4: Policy ---------------------------------------------------
section "Active policy"
RULES=$(grep -cE '^\s*(allow|deny)' policy.txt)
echo -e "    File:      ./policy.txt"
echo -e "    Rules:     ${RULES} loaded"
echo -e "    Categories: $(grep -oE '^\s*(allow|deny)\s+(path|host|exec)' policy.txt | awk '{print $2}' | sort -u | tr '\n' ' ')"
echo
pause 1.5

# ---- Scene 5: Run the real benchmark -----------------------------------
section "Running 10,000 supervised syscall decisions"
echo -e "    ${D}full pathology log → bench.log${N}"
echo

START=$(date +%s.%N)
./warden policy.txt -- ./bench_target 10000 2> bench.log >/dev/null
END=$(date +%s.%N)
ELAPSED=$(awk "BEGIN { printf \"%.3f\", $END - $START }")

REC_COUNT=$(grep -c '"report_id"' bench.log || echo 0)
echo -e "    ${G}✓${N} Complete: ${B}${REC_COUNT}${N} pathology records emitted in ${B}${ELAPSED}s${N}"
echo
pause 2

# ---- Scene 6: Replay sample records (paced) ----------------------------
section "Sampled records (every ~1000th decision, paced for video)"
echo

python3 - <<'PY'
import json, re, sys, time, os

with open('bench.log') as f:
    text = f.read()

records = []
for m in re.finditer(r'\{[^{}]*"report_id"[^{}]*\}', text):
    try: records.append(json.loads(m.group(0)))
    except: pass

n = len(records)
if n == 0:
    print("    (no records)")
    sys.exit(0)

# Sample 11 records: first, every ~10%, last
step = max(1, n // 10)
indices = sorted(set([0] + list(range(step, n, step))[:9] + [n - 1]))

quick = os.environ.get('QUICK', '0') == '1'
USE_COLOR = os.environ.get('USE_COLOR', '1') == '1'
G = '\033[0;32m' if USE_COLOR else ''
R = '\033[0;31m' if USE_COLOR else ''
Y = '\033[1;33m' if USE_COLOR else ''
N = '\033[0m'    if USE_COLOR else ''

for i in indices:
    r = records[i]
    a = r.get('action', '?')[:12]
    t = r.get('target', '?')[:34]
    d = r.get('decision_final', '?')
    raw = r.get('decision_raw', '?')
    lat = r.get('latency_us', 0)
    rule = r.get('rule', '?')

    if d == 'ALLOW':
        color = G
    elif raw == 'UNKNOWN':
        color = Y
    else:
        color = R

    print(f"    [#{i+1:>5}/{n}] {a:<12} {t:<34} {color}{d:<5}{N} {lat:>4}µs  {raw}")
    sys.stdout.flush()
    if not quick:
        time.sleep(0.35)
PY
echo
pause 1.5

# ---- Scene 7: Decision Latency Report ---------------------------------
section "Decision Latency Report"
echo
python3 bench_summarize.py bench.log | sed 's/^/    /'
echo
pause 3

# ---- Scene 8: Distribution histogram ----------------------------------
section "Latency distribution (2 µs bins, main range 0–100 µs)"
echo

# Render an ASCII bar chart from the histogram script's output
python3 - <<'PY'
import re, subprocess, os

USE_COLOR = os.environ.get('USE_COLOR', '1') == '1'
T = '\033[38;5;51m' if USE_COLOR else ''
D = '\033[2;37m'    if USE_COLOR else ''
N = '\033[0m'       if USE_COLOR else ''

out = subprocess.check_output(['python3', 'bench_histogram.py', 'bench.log'], text=True)

bins = []
for line in out.splitlines():
    m = re.match(r'\s*(\d+),\s*(\d+),\s*(\d+),', line)
    if m:
        bins.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))

if not bins:
    print("    (no histogram data)")
    raise SystemExit

max_count = max(b[2] for b in bins) or 1
bar_width = 40

for lo, hi, count in bins:
    if count == 0: continue
    fill = int(round(count / max_count * bar_width))
    bar = T + '█' * fill + N + D + '·' * (bar_width - fill) + N
    pct = count / sum(b[2] for b in bins) * 100
    print(f"    {lo:>3}–{hi:<3} µs  {bar}  {count:>5}  ({pct:5.2f}%)")
PY
echo

# Pull percentile markers from summarize for prominent display
P50=$(python3 bench_summarize.py bench.log | awk '/p50/    {print $3}')
P95=$(python3 bench_summarize.py bench.log | awk '/p95/    {print $3}')
P99=$(python3 bench_summarize.py bench.log | awk '/p99 / {print $3}')
P999=$(python3 bench_summarize.py bench.log | awk '/p99.9/ {print $3}')
MAX=$(python3 bench_summarize.py bench.log | awk '/^   max/ {print $3}')

echo -e "    ${W}Percentiles${N}   ${D}|${N}  P50 ${T}${P50}µs${N}  ${D}·${N}  P95 ${T}${P95}µs${N}  ${D}·${N}  ${B}P99 ${T}${P99}µs${N}  ${D}·${N}  P99.9 ${T}${P999}µs${N}  ${D}·${N}  max ${T}${MAX}µs${N}"
echo -e "    ${W}vs budget${N}     ${D}|${N}  50 ms budget = $(awk "BEGIN { printf \"%dx\", 50000 / ${P99} }") our P99"
echo
pause 4

# ---- Scene 9: Provenance ----------------------------------------------
banner "Every number above is from a real measurement." \
       "Reproduce: ./bench_video.sh   ·   log: ./bench.log"

# ---- Final: write a provenance file -----------------------------------
{
    echo "VAREK Warden v1.4 benchmark"
    echo "Run timestamp: $(date -Iseconds)"
    echo "Host: $(uname -srvmo)"
    echo "CPU: ${CPU}"
    echo "Memory: ${MEM}"
    echo "warden  sha256 prefix: ${WARDEN_SHA}"
    echo "bench   sha256 prefix: ${BENCH_SHA}"
    echo "Records: ${REC_COUNT}"
    echo "Wall-clock: ${ELAPSED}s"
    echo
    python3 bench_summarize.py bench.log
} > bench_results_v1_4.txt

echo -e "  ${D}Results written to bench_results_v1_4.txt${N}"
echo
