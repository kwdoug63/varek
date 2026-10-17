#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# latency_v1290.sh — v1.29's latency figures (make latency-v1290), written
# to tests/latency_v1.29.0.txt:
#   1. varek bench --open-as: the bench's opens and connects under `require
#      warden 1.28` (opened as root) and `require warden 1.29` (opened as the
#      agent), alternated, and the Warden's own time per decision;
#   2. varek bench --baseline: the decision time under a sector pack, the
#      baseline, and the baseline with each shipped profile;
#   3. a dry run: a system call outside the allowlist (getpriority), and an
#      allowed open, natively, enforcing (refused in the kernel) and in a dry
#      run (sent to the Warden, recorded, let through), as the agent sees it;
#   4. startup: wall time of `warden POLICY -- /usr/bin/true`, K runs each,
#      under the pack, the baseline, and the baseline with the claude profile.
# Run as root.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
N="${N:-2000}" K="${K:-20}" R="${R:-5}"
OUT="${OUT:-$HERE/tests/latency_v1.29.0.txt}"
T="$(mktemp -d /tmp/varek_lat1290.XXXXXX)"; chmod 755 "$T"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/proj"; chmod 755 "$T/proj"
echo f > "$T/f"; chmod 644 "$T/f"
L='allow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\n'
printf "require warden 1.29\n${L}allow path $T/f readonly\n" > "$T/p129.txt"
# the policies varek run writes, for nobody in $T/proj
PYTHONPATH="$HERE/tools" python3 -c "
import pwd, re, varek_baseline as b
pw = pwd.getpwnam('nobody')
open('$T/base.txt', 'w').write(b.generate('$T/proj', pw, '/tmp/varek-65534', None))
open('$T/claude.txt', 'w').write(b.generate('$T/proj', pw, '/tmp/varek-65534',
     b.load_profile('$HERE/policies/agents/claude.profile.txt')))
pack = re.sub(r'(?m)^require warden \S+\s*$', '', open('$HERE/policies/healthcare.policy.txt').read())
open('$T/pack.txt', 'w').write('require warden 1.29\n' + pack)"
chmod 644 "$T"/*.txt
V() { NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" "$@"; }
# lats KIND [ARGS]: RL rounds of v1290_lat as nobody, natively, enforcing
# and in a dry run, alternated within each round (so drift between them
# cancels), into $T/lat-MODE
RL="${RL:-5}"
lats() {
    rm -f "$T"/lat-native "$T"/lat-enforce "$T"/lat-dry
    for i in $(seq "$RL"); do
        for mode in native enforce dry; do
            case "$mode" in
                native)  runuser -u nobody -- "$HERE/tests/v1290_lat" "$@" ;;
                enforce) "$HERE/warden" "$T/p129.txt" --run-as nobody -- "$HERE/tests/v1290_lat" "$@" 2> /dev/null ;;
                dry)     "$HERE/warden" "$T/p129.txt" --dry-run --run-as nobody -- "$HERE/tests/v1290_lat" "$@" 2> /dev/null ;;
            esac >> "$T/lat-$mode"
        done
    done
}
# lat MODE: the medians of the rounds' p50 and p90
lat() {
    awk '{print $2, $3, $4}' "$T/lat-$1" | sort -n | awk '{p50[NR]=$1; ok=$3} END {printf "p50 %6.1f us", p50[int((NR+1)/2)]}'
    awk '{print $3}' "$T/lat-$1" | sort -n | awk '{a[NR]=$1} END {printf ", p90 %6.1f us", a[int((NR+1)/2)]}'
    awk '{ok=$4} END {printf " (%s of %s calls succeeded)", ok, '"$N"'}' "$T/lat-$1"
}
# ms POLICY: K starts, the p50 and p90 of their wall time in ms
ms() { local pol="$1"
       for _ in $(seq "$K"); do
           s=$(date +%s%N); (cd "$T/proj" && "$HERE/warden" "$pol" --run-as nobody -- /usr/bin/true > /dev/null 2>&1) || echo "FAILED" >&2
           echo $(( ($(date +%s%N) - s) / 1000 ))
       done | sort -n | awk '{a[NR]=$1} END {printf "p50 %.1f ms, p90 %.1f ms (%d runs)", a[int(NR*0.5)+1]/1000, a[int(NR*0.9)+1]/1000, NR}'; }
{
    echo "# v1.29.0 latency (tests/latency_v1290.sh, N=$N, K=$K, R=$R, RL=$RL), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "## 1. opening as the agent: varek bench --open-as"
    V bench --open-as -n "$N" --warmup 200 --rounds "$R" 2>/dev/null
    echo
    echo "## 2. the baseline and the profiles against a pack: varek bench --baseline"
    V bench --baseline -n "$N" --warmup 200 --rounds "$R" 2>/dev/null
    echo
    echo "## 3. a dry run: a call outside the allowlist, and an allowed open (as the agent sees them; medians of $RL rounds, each mode alternated within a round)"
    lats unlisted "$N"
    echo "getpriority, natively:                    $(lat native)"
    echo "getpriority, enforcing (EPERM, kernel):   $(lat enforce)"
    echo "getpriority, dry run (to the Warden):     $(lat dry)"
    lats open "$N" "$T/f"
    echo "open, allowed, natively:                  $(lat native)"
    echo "open, allowed, enforcing:                 $(lat enforce)"
    echo "open, allowed, dry run:                   $(lat dry)"
    echo
    echo "## 4. startup: warden POLICY -- /usr/bin/true, wall time (the launch set read and hashed at start)"
    echo "pack healthcare ($(grep -cE '^(allow|deny)' "$T/pack.txt") rules):           $(ms "$T/pack.txt")"
    echo "the baseline ($(grep -cE '^(allow|deny)' "$T/base.txt") rules):             $(ms "$T/base.txt")"
    echo "the baseline + claude ($(grep -cE '^(allow|deny)' "$T/claude.txt") rules):    $(ms "$T/claude.txt")"
} > "$OUT"
echo "latency_v1290: written to $OUT"
