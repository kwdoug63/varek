#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# lifecycle_video.sh — VAREK v1.9.3 lifecycle crash demo, video-capture friendly.
#
# Runs a real agent (tests/lifecycle_target, which spawns a helper process)
# under a real Warden, crashes the Warden with SIGKILL, and shows which agent
# processes are still alive. Does it twice: once with the pre-fix Warden
# (built from git, default ref v1.9.3^) and once with this Warden.
# Every process and result shown comes from the live system. Nothing is
# simulated or hardcoded.
#
# Usage:   sudo ./lifecycle_video.sh
#          sudo ./lifecycle_video.sh --no-color
#          sudo ./lifecycle_video.sh --quick         (no pacing)
#          sudo BEFORE_REF=<git-ref> ./lifecycle_video.sh
#
# Requires: root, Linux >= 5.14, libseccomp-dev, libsodium-dev (v1.16+), a git checkout.

set -euo pipefail
cd "$(dirname "$0")"

USE_COLOR=1
QUICK=0
for arg in "$@"; do
    case "$arg" in
        --no-color) USE_COLOR=0 ;;
        --quick)    QUICK=1 ;;
        -h|--help)  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    esac
done

if [[ $USE_COLOR -eq 1 ]]; then
    C='\033[38;2;0;216;217m'  # VAREK cyan
    A='\033[38;2;248;193;92m' # signal amber
    W='\033[1;37m'; D='\033[2;37m'; G='\033[0;32m'; R='\033[0;31m'
    B='\033[1m'; N='\033[0m'
else
    C='' A='' W='' D='' G='' R='' B='' N=''
fi

pause() { [[ $QUICK -eq 1 ]] || sleep "${1:-1.5}"; }
say()   { echo -e "  $*"; }
rule()  { echo -e "  ${D}────────────────────────────────────────────────────────────${N}"; }

[[ $(id -u) -eq 0 ]] || { echo "run as root (sudo ./lifecycle_video.sh)"; exit 1; }

BEFORE_REF="${BEFORE_REF:-v1.9.3^}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---- build -------------------------------------------------------------
echo -e "${D}  building...${N}"
make -s warden tests/lifecycle_target >/dev/null
REPO_ROOT="$(git rev-parse --show-toplevel)"
if ! git -C "$REPO_ROOT" rev-parse -q --verify "$BEFORE_REF^{commit}" >/dev/null; then
    echo "git ref '$BEFORE_REF' not found; set BEFORE_REF to the pre-fix commit"; exit 1
fi
git -C "$REPO_ROOT" archive "$BEFORE_REF" varek/v1_4 v1_6 | tar -x -C "$WORK"
make -s -C "$WORK/varek/v1_4" warden >/dev/null
BEFORE_BIN="$WORK/varek/v1_4/warden"
AFTER_BIN="$PWD/warden"
TARGET="$PWD/tests/lifecycle_target"
BEFORE_LABEL="before  (pre-fix Warden, commit $(git -C "$REPO_ROOT" rev-parse --short "$BEFORE_REF"))"
AFTER_LABEL="after   (v1.9.3)"

# ---- helpers -----------------------------------------------------------
descendants() {  # all live descendants of $1
    ps -e -o pid=,ppid= | awk -v root="$1" '
        { parent[$1] = $2 }
        END {
            for (p in parent) {
                q = p
                while (q in parent && q != root && q > 1) q = parent[q]
                if (q == root && p != root) print p
            }
        }' | sort -n
}

alive() {  # running (not a zombie)
    [[ -r /proc/$1/stat ]] || return 1
    local st; st=$(awk '{ s = $0; sub(/.*\) /, "", s); split(s, f, " "); print f[1] }' "/proc/$1/stat" 2>/dev/null) || return 1
    [[ -n "$st" && "$st" != "Z" && "$st" != "X" ]]
}

role() {  # label a process by its place in the tree
    local pid=$1 wpid=$2 pp
    pp=$(awk '{ s = $0; sub(/.*\) /, "", s); split(s, f, " "); print f[2] }' "/proc/$pid/stat")
    if [[ "$pp" == "$wpid" ]]; then echo "agent"; else echo "agent's helper"; fi
}

SURVIVORS=0
run_case() {
    local bin=$1 label=$2 ready=$WORK/ready.$RANDOM
    echo
    rule
    say "${W}${label}${N}"
    rule
    pause 1

    "$bin" policy.txt -- "$TARGET" >"$ready" 2>/dev/null &
    local wpid=$!
    for _ in $(seq 50); do [[ -s "$ready" ]] && break; sleep 0.1; done

    local pids=() roles=()
    for p in $(descendants "$wpid"); do pids+=("$p"); roles+=("$(role "$p" "$wpid")"); done

    say "Warden supervising        ${D}pid $wpid${N}"
    for i in "${!pids[@]}"; do
        say "  └ ${roles[$i]}$(printf '%*s' $((22 - ${#roles[$i]})) '')${D}pid ${pids[$i]}${N}"
    done
    pause 2

    say "${A}${B}kill -9 $wpid${N}   ${D}# crash the supervisor${N}"
    kill -9 "$wpid"; wait "$wpid" 2>/dev/null || true
    sleep 1
    pause 1

    SURVIVORS=0
    for i in "${!pids[@]}"; do
        if alive "${pids[$i]}"; then
            say "  ${R}${B}STILL RUNNING${N}  $(printf '%-16s' "${roles[$i]}")${D}pid ${pids[$i]}${N}"
            SURVIVORS=$((SURVIVORS + 1))
        else
            say "  ${G}${B}stopped${N}        $(printf '%-16s' "${roles[$i]}")${D}pid ${pids[$i]}${N}"
        fi
    done
    for p in "${pids[@]}"; do kill -9 "$p" 2>/dev/null || true; done
    pause 2
}

# ---- show --------------------------------------------------------------
clear || true
echo
say "${C}${B}VAREK Warden — what happens when the supervisor crashes?${N}"
say "${D}An agent runs under the Warden and starts a helper process.${N}"
say "${D}Then the Warden is killed without warning.${N}"
pause 3

run_case "$BEFORE_BIN" "$BEFORE_LABEL"
before=$SURVIVORS
run_case "$AFTER_BIN"  "$AFTER_LABEL"
after=$SURVIVORS

echo
rule
say "${W}Result${N}"
rule
say "before: ${R}${B}$before${N} agent process(es) kept running without oversight"
say "v1.9.3: ${G}${B}$after${N} agent process(es) kept running without oversight"
echo
say "${C}If the supervisor stops, the agent stops, and so does everything it started.${N}"
say "${D}Don't Trust. Verify.   github.com/kwdoug63/varek${N}"
echo
