#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# arm64_sweep.sh — v1.30 (docs/security/v1.30-macos.md, step 1): build the
# Warden on an arm64 Linux host and run every suite, one after another, each
# logged to OUT/<suite>.log, then a table of each suite's result. Since
# v1.36 also the matrix's host cells (Rocky Linux 9 and Amazon Linux 2023 in
# VMs on x86_64 runners, tests/vm_cell.sh).
#
# Run as root on the arm64 host (an AWS Graviton instance, Ubuntu 24.04), from
# a checkout of the v1.30 branch where the user nobody can read it (/opt, not
# /root):
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
# the bench tests (test-cli) run their workload as nobody, and other checks
# run the tools as nobody: the checkout must be reachable by nobody (not
# under /root, which is 0700)
if ! setpriv --reuid 65534 --regid 65534 --clear-groups test -r "$HERE/tools/varek" 2>/dev/null; then
    echo "arm64_sweep.sh: nobody cannot read $HERE (under a directory closed to other users, such as /root):"
    echo "  clone it where nobody can, e.g. git clone -b $(git -C "$HERE" branch --show-current 2>/dev/null) https://github.com/kwdoug63/varek.git /opt/varek130"
    exit 2
fi
# the suites run as root itself: a root shell reached by sudo -i would
# otherwise name its user as the operator, and varek run its user as the agent
unset SUDO_UID SUDO_GID SUDO_USER SUDO_COMMAND
[ "$(uname -m)" = aarch64 ] || echo "arm64_sweep.sh: note: this host is $(uname -m), not aarch64"
OUT="${OUT:-/var/tmp/varek-arm64-sweep-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
if [ "$DEPS" = 1 ]; then
    if command -v apt-get > /dev/null; then
        apt-get update -q &&
        apt-get install -y -q build-essential libseccomp-dev libsodium-dev libssl-dev openjdk-21-jdk-headless \
            musl-tools python3-cryptography python3-pip python3-pytest python3-yaml python3-venv git openssl &&
        apt-get install -y -q --no-install-recommends squid || { echo "arm64_sweep.sh: apt-get failed"; exit 1; }
    elif command -v dnf > /dev/null; then
        # RHEL 9 or a rebuild: libsodium is EPEL's, glibc-static CodeReady
        # Builder's (tests/vm_cell.sh enables both). Amazon Linux 2023 (v1.36,
        # the matrix's host cells): its own repositories, Java as Corretto.
        # A name the host's repositories do not have is left out (strict=0)
        # and the build's own packages are checked after; --allowerasing:
        # the cloud images' curl-minimal gives way to curl.
        java="java-21-openjdk-headless"
        grep -q '^ID="*amzn' /etc/os-release && java="java-21-amazon-corretto-headless"
        dnf -y --allowerasing --setopt=strict=0 install gcc make git openssl libseccomp-devel openssl-devel \
            libsodium-devel python3 python3-pip python3-cryptography "$java" squid curl util-linux \
            glibc-static libasan libubsan gcc-c++ cmake procps-ng iproute sudo runc || { echo "arm64_sweep.sh: dnf failed"; exit 1; }
        missing="$(rpm -q gcc make libseccomp-devel libsodium-devel openssl-devel python3 | sed -n 's/^package \(.*\) is not installed$/\1/p' | tr '\n' ' ')"
        [ -z "$missing" ] || { echo "arm64_sweep.sh: the build needs $missing(not in this host's repositories)"; exit 1; }
        for p in "$java" squid glibc-static libasan libubsan runc; do
            rpm -q "$p" > /dev/null 2>&1 || echo "arm64_sweep.sh: note: no $p here (the suites that need it skip or fail)"
        done
        # runc (v1.36 step 11): test_v1340's containers under the node
        # agent, which skip without it (vm_cell.sh fails a sweep that skips);
        # glibc-static (from CRB): the suites' static probes; libasan and
        # libubsan: test-mcp-json and the proxy's parsers under the sanitizers;
        # gcc-c++ and cmake: z3 5 built from source (its aarch64 wheels need
        # glibc 2.38; RHEL 9 has 2.34), for the cross-check
        dnf -y install musl-gcc > /dev/null 2>&1 || echo "arm64_sweep.sh: note: no musl-gcc here (the musl checks skip)"
    else
        echo "arm64_sweep.sh: --deps knows apt-get and dnf only"; exit 1
    fi
    # --ignore-installed: beside the system's own copies (Ubuntu's jsonschema
    # cannot be uninstalled by pip, and the CycloneDX validator needs a newer
    # one); --break-system-packages where pip has it (not RHEL 9's)
    BSP=""; python3 -m pip install --help 2>/dev/null | grep -q -- --break-system-packages && BSP=--break-system-packages
    # --prefer-binary: a release with a wheel for this Python and machine where
    # one meets the requirement; z3 5 has none for aarch64 before glibc 2.38,
    # so on RHEL 9 it is built from source (gcc-c++ and cmake, above; about
    # half an hour)
    python3 -m pip install $BSP --ignore-installed --prefer-binary -q -r "$HERE/tools/requirements-test.txt" \
        pytest pyyaml || { echo "arm64_sweep.sh: pip failed"; exit 1; }
    # the cross-check oracle's solver is optional: without it that check skips
    python3 -m pip install $BSP --ignore-installed --prefer-binary -q -r "$HERE/tools/requirements-crosscheck.txt" ||
        echo "arm64_sweep.sh: note: z3-solver did not install; the cross-check oracle skips"
fi
{
    echo "host: $(uname -srm); $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "commit: $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null) ($(git -C "$HERE" branch --show-current 2>/dev/null))"
    echo "libseccomp $(dpkg-query -W -f '${Version}' libseccomp-dev 2>/dev/null || rpm -q --qf '%{VERSION}' libseccomp 2>/dev/null), $(cc --version | head -1)"
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
