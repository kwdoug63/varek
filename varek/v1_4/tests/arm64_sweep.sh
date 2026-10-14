#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# arm64_sweep.sh — v1.30 (docs/security/v1.30-macos.md, step 1): build the
# Warden on an arm64 Linux host and run every suite, one after another, each
# logged to OUT/<suite>.log, then a table of each suite's result.
#
# Run as root on the arm64 host (an AWS Graviton instance, Ubuntu 24.04), from
# a checkout of the v1.30 branch:
#
#   sudo varek/v1_4/tests/arm64_sweep.sh [--deps] [--out DIR] [SUITE...]
#
# --deps installs what the suites need first (the packages CI installs,
# pytest for test-cli, and z3 and the CycloneDX validator for the cross-check
# and v1.18's suite). With
# no SUITE, every `make test-*` target and `make crosscheck` run. Nothing else
# under the Warden should run on the host meanwhile (test_v1280.sh revokes
# every run).
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="" DEPS=0 SUITES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --deps) DEPS=1; shift ;;
        --out) OUT="$2"; shift 2 ;;
        -*) echo "unknown option $1"; exit 2 ;;
        *) SUITES+=("$1"); shift ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "arm64_sweep.sh: run as root"; exit 2; }
# the suites run as root itself: a root shell reached by sudo -i would
# otherwise name its user as the operator, and varek run its user as the agent
unset SUDO_UID SUDO_GID SUDO_USER SUDO_COMMAND
[ "$(uname -m)" = aarch64 ] || echo "arm64_sweep.sh: note: this host is $(uname -m), not aarch64"
OUT="${OUT:-/var/tmp/varek-arm64-sweep-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
if [ "$DEPS" = 1 ]; then
    apt-get update -q &&
    apt-get install -y -q build-essential libseccomp-dev libsodium-dev libssl-dev openjdk-21-jdk-headless \
        musl-tools python3-cryptography python3-pip python3-pytest python3-yaml python3-venv git openssl &&
    apt-get install -y -q --no-install-recommends squid || { echo "arm64_sweep.sh: apt-get failed"; exit 1; }
    # --ignore-installed: beside Ubuntu's own copies (its jsonschema cannot be
    # uninstalled by pip, and the CycloneDX validator needs a newer one)
    python3 -m pip install --break-system-packages --ignore-installed -q -r "$HERE/tools/requirements-crosscheck.txt" \
        -r "$HERE/tools/requirements-test.txt" || { echo "arm64_sweep.sh: pip failed"; exit 1; }
fi
{
    echo "host: $(uname -srm); $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "commit: $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null) ($(git -C "$HERE" branch --show-current 2>/dev/null))"
    echo "libseccomp $(dpkg-query -W -f '${Version}' libseccomp-dev 2>/dev/null), $(cc --version | head -1)"
} | tee "$OUT/host.txt"
echo "== build"
if ! make -C "$HERE" all tests/v1281_sub tests/v1290_open tests/v1310_peek tests/v1300_oflags > "$OUT/build.log" 2>&1; then
    tail -20 "$OUT/build.log"; echo "arm64_sweep.sh: the build failed ($OUT/build.log)"; exit 1
fi
if [ ${#SUITES[@]} = 0 ]; then
    mapfile -t SUITES < <(sed -n 's/^\.PHONY:\(.*\)$/\1/p' "$HERE/Makefile" | tr ' ' '\n' | grep -E '^test-' | grep -vx 'test-cli')
    SUITES+=(test-cli crosscheck)
fi
printf '%-22s %-6s %6s %6s %6s %8s\n' SUITE RESULT PASS FAIL SKIP SECONDS > "$OUT/summary.txt"
for s in "${SUITES[@]}"; do
    t0=$(date +%s)
    timeout 3600 make -C "$HERE" "$s" > "$OUT/$s.log" 2>&1; rc=$?
    p=$(grep -c '  PASS' "$OUT/$s.log"); f=$(grep -c '  FAIL' "$OUT/$s.log"); k=$(grep -c '  SKIP' "$OUT/$s.log")
    printf '%-22s %-6s %6s %6s %6s %8s\n' "$s" "$([ $rc = 0 ] && echo ok || echo FAILED)" "$p" "$f" "$k" "$(( $(date +%s) - t0 ))" \
        | tee -a "$OUT/summary.txt"
done
echo "arm64_sweep.sh: logs and summary.txt in $OUT"
grep -q FAILED "$OUT/summary.txt" && exit 1 || exit 0
