#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# v1340_sweep.sh — v1.34 step 7 (docs/security/v1.34-kubernetes.md, section
# 4): the suites against a container the node agent supervises, a sweep like
# v1.32's. Each suite (make test-...) runs twice from a copy of this
# checkout:
#   host  as it is, under the Warden;
#   node  with the Warden replaced by tests/v1340_pod.py, which runs each
#         agent the suite starts (POLICY -- PROGRAM) as a pod's container
#         under the node agent, adjusted as VAREK's NRI plugin adjusts it,
#         and every other use of the Warden by the Warden itself;
# then each check is compared (tests/v1340_sweep_compare.py): held on both,
# or different, each difference either listed with its reason in
# tests/v1340_sweep_known.txt or a failure. A suite's check the node run
# passes through to the Warden (an option the node agent does not take) is
# counted apart. The host run is also the branch's regression count.
#
#   sudo varek/v1_4/tests/v1340_sweep.sh [--out DIR] [--runc PATH] [--only host|node] [SUITE...]
#
# Needs root, runc (or RUNC), python3, overlayfs and what the suites need.
# Writes DIR/{host,node}/SUITE.log, DIR/calls.jsonl (each Warden call of the
# node run, carried or passed through, with why) and DIR/summary.txt
# (default /var/tmp/varek-sweep-<time>); VAREK_SWEEP_KEEP=1 keeps each
# container's stream and the node agent's log. Exit status 1 for a difference no
# reason is listed for, or a suite that fails on the host.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="" RUNC="${RUNC:-}" ONLY="" SUITES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --runc) RUNC="$2"; shift 2 ;;
        --only) ONLY="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^set -u/p' "$0" | sed 's/^# \{0,1\}//; /^set -u/d'; exit 0 ;;
        -*) echo "v1340_sweep.sh: unknown option $1" >&2; exit 2 ;;
        *) SUITES+=("$1"); shift ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "v1340_sweep.sh: run as root" >&2; exit 2; }
[ -n "$RUNC" ] || RUNC="$(command -v runc || true)"
[ -n "$RUNC" ] && [ -x "$RUNC" ] || { echo "v1340_sweep.sh: runc is needed (RUNC)" >&2; exit 2; }
command -v python3 > /dev/null || { echo "v1340_sweep.sh: python3 is needed" >&2; exit 2; }
OUT="${OUT:-/var/tmp/varek-sweep-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT/host" "$OUT/node"
# its own directory on the root file system (not /tmp: the container's /tmp
# is noexec, and the suites' programs run from the copy)
W="$(mktemp -d /var/lib/varek-sweep.XXXXXX)"; chmod 755 "$W"
cleanup() {
    umount -l "$W/hostroot" 2>/dev/null; umount -l "$W/ovl" 2>/dev/null
    for r in "$W"/inv/*/state; do [ -d "$r" ] && for c in "$r"/*; do [ -e "$c" ] && "$RUNC" --root "$r" delete -f "${c##*/}" >/dev/null 2>&1; done; done
    if [ -n "${VAREK_SWEEP_KEEP:-}" ]; then echo "kept $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT
say() { echo "$*" | tee -a "$OUT/summary.txt"; }
: > "$OUT/summary.txt"
say "v1340_sweep.sh $(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z'); $(uname -sr); $("$RUNC" --version | head -1); commit $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)"

echo "== the copy, built"
mkdir -p "$W/src" "$W/bin" "$W/inv" "$W/ovl" "$W/hostroot"
tar -C "$ROOT" --exclude=.git -cf - . | tar -C "$W/src" -xf -
S="$W/src/varek/v1_4"
make -s -C "$S" clean > /dev/null 2>&1
make -s -C "$S" all varek-init warden-proxy > "$OUT/build.log" 2>&1 || { tail -20 "$OUT/build.log"; echo "v1340_sweep.sh: the build failed" >&2; exit 1; }
# the Warden itself, beside the stand-in that takes its name: it finds its
# data files and warden-proxy beside its own binary
cp "$S/warden" "$S/warden-sweep-real"; chmod 755 "$S/warden-sweep-real"
if [ ${#SUITES[@]} = 0 ]; then
    mapfile -t SUITES < <(sed -n 's/^\.PHONY:\(.*\)$/\1/p' "$S/Makefile" | tr ' ' '\n' | grep -E '^test-v1[0-9]+$|^test-lifecycle$' | sort -u)
    SUITES+=(test-cli)
fi
LIMIT=1800

suite() {   # MODE SUITE
    local t0 rc
    t0=$(date +%s)
    if [ "$1" = node ]; then
        # the Warden as the suite names it (./warden), not remade (-o)
        timeout "$LIMIT" make -s -o warden -C "$S" "$2" > "$OUT/node/$2.log" 2>&1; rc=$?
    else
        timeout "$LIMIT" make -s -C "$S" "$2" > "$OUT/host/$2.log" 2>&1; rc=$?
    fi
    printf '%-6s %-18s rc=%-3s %5ss\n' "$1" "$2" "$rc" "$(( $(date +%s) - t0 ))" | tee -a "$OUT/runs.txt"
    echo "$rc" > "$OUT/$1/$2.rc"
}

if [ "$ONLY" != node ]; then
    echo "== the host run"
    for t in "${SUITES[@]}"; do suite host "$t"; done
fi
if [ "$ONLY" != host ]; then
    echo "== the node run"
    mount --bind / "$W/hostroot" && mount --make-private "$W/hostroot" && mount -t tmpfs -o mode=755 tmpfs "$W/ovl" ||
        { echo "v1340_sweep.sh: the host root's bind or the overlay's tmpfs did not mount" >&2; exit 1; }
    : > "$OUT/calls.jsonl"; chmod 666 "$OUT/calls.jsonl"   # a suite runs the Warden as other users too
    # the stand-in where any user (or a user namespace's root) can run it
    install -m 755 "$HERE/tests/v1340_pod.py" "$W/bin/v1340_pod.py"
    PY="$(command -v python3)"
    # the version the Warden reports, which tools/varek reads from its binary
    VER="$(grep -ao '"warden":"[0-9.]*"' "$S/warden-sweep-real" | head -1)"
    for t in "${SUITES[@]}"; do
        # the stand-in, its settings written in (sudo, in the suites' targets, clears the environment)
        # v1.36 step 5: in Python, not sh (a shell drops variables whose names
        # are not its own, BASH_FUNC_f%% among them, which the agent is to
        # get), and isolated (-I: a suite's PYTHONPATH is the agent's, not the
        # stand-in's)
        cat > "$S/warden" <<EOF
#!$PY -I
# v1340_sweep.sh's stand-in for the Warden $VER
import os, sys
os.environ.update(VAREK_SWEEP_DIR='$W', VAREK_SWEEP_WARDEN='$S/warden-sweep-real', VAREK_SWEEP_LAUNCHER='$S/varek-init',
                  VAREK_SWEEP_RUNC='$RUNC', VAREK_SWEEP_LOG='$OUT/calls.jsonl', VAREK_SWEEP_SUITE='$t',
                  VAREK_SWEEP_KEEP='${VAREK_SWEEP_KEEP:-}')
os.execv(sys.executable, [sys.executable, "-I", "$W/bin/v1340_pod.py"] + sys.argv[1:])
EOF
        chmod 755 "$S/warden"; touch -r "$S/warden-sweep-real" "$S/warden"
        suite node "$t"
    done
    cp "$S/warden-sweep-real" "$S/warden"
fi

echo
python3 "$HERE/tests/v1340_sweep_compare.py" "$OUT" "$HERE/tests/v1340_sweep_known.txt" "${SUITES[@]}" | tee -a "$OUT/summary.txt"
exit "${PIPESTATUS[0]}"
