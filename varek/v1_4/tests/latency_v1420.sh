#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# latency_v1420.sh — v1.42's latency check (make latency-v1420), written to
# tests/latency_v1.42.0.txt: calls not held are decided no slower than in
# v1.41 (docs/security/v1.42-step-up-defer.md, "Tests and ship gate").
#
# Three runs a round, alternated within each round so drift between them
# cancels, RL rounds:
#   v1.41      the v1.41.0 Warden (built from the tag into a scratch
#              directory), a policy of allow and deny rules;
#   v1.42      this Warden, the same policy;
#   v1.42 + su this Warden, the same policy with step_up rules (mode=grant
#              and mode=hold), a defer rule and max_held: none of them names
#              the bench's calls, so no call is held or proposed, but the
#              filter is loaded for holds (SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#              where the kernel has it) and the hold table is looked at each
#              round of the supervision loop.
# Each run makes N opens of one kind (tests/v1290_lat, as nobody): a file an
# allow rule allows, one a deny rule refuses, one no rule names (UNKNOWN,
# refused). Reported: as the agent sees each call (the medians of the rounds'
# p50 and p90), and the Warden's own time per decision (the median of the
# rounds' p50 of the decision records' latency_us).
# Run as root. Without git or the v1.41.0 tag, the v1.41 column is left out.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TOP="$(cd "$HERE/../.." && pwd)"
N="${N:-2000}" RL="${RL:-5}"
OUT="${OUT:-$HERE/tests/latency_v1.42.0.txt}"
T="$(mktemp -d /tmp/varek_lat1420.XXXXXX)"; chmod 755 "$T"
trap 'rm -rf "$T"' EXIT
echo f > "$T/f"; echo d > "$T/d"; echo u > "$T/u"; chmod 644 "$T/f" "$T/d" "$T/u"
mkdir -p "$T/su" "$T/hold" "$T/df"; chmod 755 "$T/su" "$T/hold" "$T/df"
L='allow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\n'
R="allow path $T/f readonly\ndeny path $T/d\n"
printf "require warden 1.29\n${L}${R}" > "$T/p141.txt"
printf "require warden 1.42\n${L}${R}step_up path $T/su/ timeout=60\nstep_up path $T/hold/ mode=hold timeout=60\ndefer path $T/df/ until=/run/varek-lat1420.marker timeout=60\nmax_held 4\n" > "$T/p142.txt"
chmod 644 "$T"/*.txt

W141=""
if command -v git > /dev/null && git -C "$TOP" rev-parse -q --verify "refs/tags/v1.41.0" > /dev/null 2>&1; then
    mkdir -p "$T/v141"
    if git -C "$TOP" archive v1.41.0 varek/v1_4 v1_6 v1_7 | tar -x -C "$T/v141" \
       && make -C "$T/v141/varek/v1_4" warden > "$T/v141.build" 2>&1; then
        W141="$T/v141/varek/v1_4/warden"
    else
        echo "latency_v1420: the v1.41.0 Warden did not build (see below); its column is left out" >&2
        tail -5 "$T/v141.build" >&2 || true
    fi
else
    echo "latency_v1420: no v1.41.0 tag here; the v1.41 column is left out" >&2
fi

# one WARDEN POLICY KIND FILE: N opens; append "p50 p90 ok decide_p50" to $T/lat-KIND-$tag
one() {
    local w="$1" pol="$2" kind="$3" f="$4" tag="$5" o
    o="$("$w" "$pol" --run-as nobody -- "$HERE/tests/v1290_lat" open "$N" "$f" 2> "$T/rec")"
    local d; d="$(python3 -c '
import json, statistics, sys
v = sorted(r["latency_us"] for r in (json.loads(l) for l in open(sys.argv[1], errors="replace") if l.startswith("{"))
           if r.get("resolved") == sys.argv[2] and isinstance(r.get("latency_us"), (int, float)))
print(statistics.median(v) if v else "nan")' "$T/rec" "$f")"
    echo "$(awk '{print $2, $3, $4}' <<<"$o") $d" >> "$T/lat-$kind-$tag"
}
for i in $(seq "$RL"); do
    for kind in allowed denied unknown; do
        case "$kind" in allowed) f="$T/f" ;; denied) f="$T/d" ;; unknown) f="$T/u" ;; esac
        [ -n "$W141" ] && one "$W141" "$T/p141.txt" "$kind" "$f" v141
        one "$HERE/warden" "$T/p141.txt" "$kind" "$f" v142
        one "$HERE/warden" "$T/p142.txt" "$kind" "$f" v142su
    done
done
# col KIND TAG: "p50 / p90 / decide" medians over the rounds
col() {
    [ -s "$T/lat-$1-$2" ] || { printf '%26s' "-"; return; }
    python3 -c '
import statistics, sys
rows = [l.split() for l in open(sys.argv[1])]
m = lambda i: statistics.median(float(r[i]) for r in rows)
print("%7.1f %7.1f %8.1f" % (m(0), m(1), m(3)), end="")' "$T/lat-$1-$2"
    printf '   '
}
okc() { awk '{print $3}' "$T/lat-$1-$2" 2>/dev/null | sort -u | tr '\n' ' '; }
host() { printf '%s, %s CPU(s), kernel %s' "$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')" "$(nproc)" "$(uname -r)"; }
{
    echo "# v1.42.0 latency (tests/latency_v1420.sh, N=$N, RL=$RL), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "host: $(host)"
    echo "Warden $(sed -n 's/.*"warden":"\([0-9.]*\)".*/\1/p' "$T/rec" | head -1) at $(git -C "$TOP" rev-parse --short HEAD 2>/dev/null || echo '?')$(git -C "$TOP" diff --quiet HEAD -- varek/v1_4 2>/dev/null || echo ' (with changes not committed)')$( [ -n "$W141" ] && echo ', against the v1.41.0 tag built here' )"
    echo "${LAT_HOST_NOTE:-the host: where the script ran; the figures, of this host, compared with each other: not a benchmark of the Warden}"
    echo
    echo "## calls not held: v1.41, v1.42, and v1.42 with step_up and defer rules that name none of them"
    echo "each cell: p50 and p90 as the agent sees the call, then the Warden's own time per decision (p50 of latency_us); microseconds, medians of $RL rounds of $N calls"
    echo
    printf '%-24s %-26s %-26s %-26s\n' "open" "v1.41" "v1.42" "v1.42 + step_up/defer"
    printf '%-24s %-26s %-26s %-26s\n' "" "  p50     p90   decide" "  p50     p90   decide" "  p50     p90   decide"
    for kind in allowed denied unknown; do
        case "$kind" in allowed) lab="allowed (read)" ;; denied) lab="denied by a rule" ;; unknown) lab="no rule (UNKNOWN)" ;; esac
        printf '%-24s %s%s%s\n' "$lab" "$(col "$kind" v141)" "$(col "$kind" v142)" "$(col "$kind" v142su)"
    done
    echo
    echo "calls that succeeded each run: allowed $(okc allowed v142su)(of $N), denied $(okc denied v142su), unknown $(okc unknown v142su)"
    echo "v1.41 and v1.42: require warden 1.29, the same allow and deny rules. v1.42 + step_up/defer: require warden 1.42, the same rules, then"
    echo "step_up path (mode=grant), step_up path mode=hold, defer path until=... and max_held 4, none naming the bench's files."
} > "$OUT"
echo "latency_v1420: written to $OUT"
cat "$OUT"
