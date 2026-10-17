#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# container_sweep.sh — v1.32 step 1 (docs/security/v1.32-containers.md):
# run the suites inside VAREK's test image under the container settings
# the image documents, and find which settings each needs.
#
#   sudo varek/v1_4/tests/container_sweep.sh [--runtime docker|podman]
#        [--build] [--out DIR] [--caps "SYS_ADMIN SYS_PTRACE ..."]
#        [--drop-each] [SUITE...]
#
# --build        build the test image first (packaging/container/Containerfile,
#                --target test) from this checkout
# --caps LIST    the capabilities added after --cap-drop ALL (default: the
#                list measured so far, below)
# --drop-each    after the run with every capability, run a short set of
#                suites (DROP_SUITES) once per capability with that one left
#                out, so each is shown needed (a suite fails without it)
#
# The container gets --cap-drop ALL and the capabilities, the runtime's own
# default seccomp profile and its default AppArmor or SELinux confinement:
# never --privileged, seccomp=unconfined, apparmor=unconfined or
# label=disable. --cgroupns=private gives it a cgroup namespace of its own.
#
# Writes the logs and summary.txt (suite, result, pass, fail, skip, seconds,
# per capability set) to DIR (default /var/tmp/varek-container-sweep-<time>).
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RT="" BUILD=0 OUT="" DROP=0 SUITES=()
CAPS="SYS_ADMIN SYS_PTRACE SETPCAP SETUID SETGID DAC_OVERRIDE KILL NET_ADMIN NET_BIND_SERVICE CHOWN"
# what the suites themselves need to set up their cases, not VAREK: mknod
# (a block device and a /dev/mem twin in the allowed tree)
TEST_CAPS="MKNOD"
# --drop-each runs these, which between them use every capability above,
# rather than every suite once per capability
DROP_SUITES="test-lifecycle test-v1124 test-v1250 test-v1271 test-v1281 test-v1290 test-v1311"
LIMIT=1200                                   # seconds a suite may take
IMAGE=varek-test
while [ $# -gt 0 ]; do
    case "$1" in
        --runtime) RT="$2"; shift 2 ;;
        --build) BUILD=1; shift ;;
        --out) OUT="$2"; shift 2 ;;
        --caps) CAPS="$2"; shift 2 ;;
        --drop-each) DROP=1; shift ;;
        --image) IMAGE="$2"; shift 2 ;;
        -h|--help) sed -n '3,30p' "$0"; exit 0 ;;
        -*) echo "container_sweep.sh: unknown option $1" >&2; exit 2 ;;
        *) SUITES+=("$1"); shift ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "container_sweep.sh: run as root (the runtime starts the containers)" >&2; exit 2; }
if [ -z "$RT" ]; then
    if command -v docker >/dev/null 2>&1; then RT=docker
    elif command -v podman >/dev/null 2>&1; then RT=podman
    else echo "container_sweep.sh: neither docker nor podman is installed" >&2; exit 2; fi
fi
OUT="${OUT:-/var/tmp/varek-container-sweep-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
{
    echo "host: $(uname -srm); $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "commit: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null) ($(git -C "$ROOT" branch --show-current 2>/dev/null))"
    echo "runtime: $RT $($RT --version 2>/dev/null | head -1)"
    echo "cgroup: $(stat -fc %T /sys/fs/cgroup)  (cgroup2fs is v2)"
    echo "AppArmor: $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)  SELinux: $(getenforce 2>/dev/null || echo absent)"
    echo "security options: $($RT info --format '{{.SecurityOptions}}' 2>/dev/null || $RT info 2>/dev/null | grep -A4 -i 'security' | tr '\n' ' ')"
    echo "capabilities: $CAPS"
} | tee "$OUT/host.txt"

if [ "$BUILD" = 1 ]; then
    echo "== build the test image"
    if ! "$RT" build -f "$ROOT/packaging/container/Containerfile" --target test -t "$IMAGE" "$ROOT" > "$OUT/build.log" 2>&1; then
        tail -20 "$OUT/build.log"; echo "container_sweep.sh: the build failed ($OUT/build.log)"; exit 1
    fi
fi

if [ ${#SUITES[@]} = 0 ]; then
    # every suite the Makefile names but the ones that need no privilege or
    # take most of an hour (the cross-check); test-cli last
    mapfile -t SUITES < <(sed -n 's/^\.PHONY:\(.*\)$/\1/p' "$HERE/Makefile" | tr ' ' '\n' | grep -E '^test-v1|^test-lifecycle$' )
    SUITES+=(test-cli)
fi

# run_set LABEL CAPS...: every suite in a container with --cap-drop ALL and
# these capabilities; a row per suite in summary.txt
run_set() {
    local label="$1"; shift
    local args=(--rm --cap-drop ALL --cgroupns=private)
    for c in "$@" $TEST_CAPS; do args+=(--cap-add "$c"); done
    printf '\n== %s: --cap-drop ALL%s (and, for the tests, %s)\n' "$label" "$(printf ' --cap-add %s' "$@")" "$TEST_CAPS" | tee -a "$OUT/summary.txt"
    printf '%-22s %-6s %6s %6s %6s %8s\n' SUITE RESULT PASS FAIL SKIP SECONDS | tee -a "$OUT/summary.txt"
    for s in "${SUITES[@]}"; do
        local t0 log="$OUT/$label.$s.log" rc p f k name="varek-sweep-$$-$s"
        t0=$(date +%s)
        # a suite past its time is stopped by removing its container (a
        # timeout on the client alone leaves the container running)
        timeout "$LIMIT" "$RT" run --name "$name" "${args[@]}" "$IMAGE" make "$s" > "$log" 2>&1; rc=$?
        [ "$rc" = 124 ] && { echo "container_sweep.sh: $s ran past ${LIMIT} s; stopped" >> "$log"; "$RT" rm -f "$name" > /dev/null 2>&1; }
        p=$(grep -c '  PASS' "$log"); f=$(grep -c '  FAIL' "$log"); k=$(grep -c '  SKIP' "$log")
        printf '%-22s %-6s %6s %6s %6s %8s\n' "$s" "$([ $rc = 0 ] && echo ok || echo FAILED)" "$p" "$f" "$k" "$(( $(date +%s) - t0 ))" \
            | tee -a "$OUT/summary.txt"
    done
}

: > "$OUT/summary.txt"
cat "$OUT/host.txt" >> "$OUT/summary.txt"
# shellcheck disable=SC2086
run_set all $CAPS
if [ "$DROP" = 1 ]; then
    # shellcheck disable=SC2206
    SUITES=($DROP_SUITES)
    for c in $CAPS; do
        rest=$(echo " $CAPS " | sed "s/ $c / /")
        # shellcheck disable=SC2086
        run_set "without-$c" $rest
    done
fi
echo "container_sweep.sh: logs and summary.txt in $OUT"
