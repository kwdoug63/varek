#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Runs on the Packer build instance (Amazon Linux 2023), as root.
# Builds and installs VAREK in /opt/varek, adds the Enterprise packs and the
# Marketplace settings, removes the compiler, then proves the installed image
# works with a real Warden run and audit.
set -euo pipefail

PREFIX=/opt/varek
# AL2023's sudo secure_path is /sbin:/bin:/usr/sbin:/usr/bin, so `sudo varek`
# only works if the command is in /usr/bin.
BINDIR=/usr/bin
SRC=/tmp/varek-src.tar.gz
PACKS=/tmp/varek-packs
MARKET=/tmp/varek-marketplace.json
MARK="Licensed to VAREK Enterprise subscribers"

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
grep -q 'Amazon Linux' /etc/os-release || die "expected Amazon Linux 2023"

say "Patching the base image"
# Move to the newest AL2023 release so the image ships with no known CVEs.
dnf -y upgrade --releasever=latest

say "Build and runtime packages"
# libseccomp and libsodium are installed by name first so dnf records them as
# wanted: removing the -devel packages later must not take the libraries with it.
dnf -y install libseccomp libsodium openssl-libs python3 awscli-2
# glibc-static: `varek bench`'s workload is linked static, so its runs under
# the Warden make no loader opens (v1.22).
dnf -y install gcc make libseccomp-devel libsodium-devel openssl-devel glibc-static tar gzip

say "Building VAREK ${VAREK_VERSION:-}"
BUILD=$(mktemp -d /tmp/varek-build.XXXXXX)
tar -xzf "$SRC" -C "$BUILD"
make -C "$BUILD/varek/v1_4" -j"$(nproc)"
make -C "$BUILD/varek/v1_4" install PREFIX="$PREFIX" BINDIR="$BINDIR"
rm -f "$PREFIX"/policies/*.bak-* 2>/dev/null || true

say "Enterprise policy packs"
shopt -s nullglob
packs=("$PACKS"/*.policy.txt)
[ "${#packs[@]}" -gt 0 ] || die "no *.policy.txt packs were uploaded to $PACKS"
for p in "${packs[@]}"; do
    name=$(basename "$p")
    # Only files marked as Enterprise packs ship, so the license check gates
    # every paid pack and nothing unmarked slips into the image.
    head -n 20 "$p" | grep -q "$MARK" || die "$name lacks the '$MARK' header"
    "$BINDIR/varek" policy check "$p" >/dev/null || die "$name does not lint"
    install -m 0644 "$p" "$PREFIX/policies/$name"
    echo "  $name"
done

say "Marketplace settings"
product_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("product_id",""))' "$MARKET")
if [ -n "$product_id" ]; then
    install -m 0644 "$MARKET" "$PREFIX/marketplace.json"
    echo "  license check for product $product_id"
else
    echo "  no product_id: test image, no license check (Enterprise packs cannot be selected)"
fi

say "Removing the compiler and headers"
dnf -y remove gcc make libseccomp-devel libsodium-devel openssl-devel glibc-static
dnf -y autoremove
if ldd "$PREFIX/warden" "$PREFIX/warden-proxy" "$PREFIX/tools/vdp_check" "$PREFIX/tools/vdp_cert_check" \
        "$PREFIX/tools/varek_keygen" | grep -q 'not found'; then
    die "a runtime library went missing with the build packages"
fi

say "Smoke test: a real Warden run on the installed image"
SMOKE=$(mktemp -d /tmp/varek-smoke.XXXXXX)
export VAREK_CONFIG="$SMOKE/etc/varek.conf"
"$BINDIR/varek" init --pack healthcare --log-dir "$SMOKE/log"
"$BINDIR/varek" doctor || true   # the build instance has no anchor or license role
"$BINDIR/varek" preflight --run
# A Python agent (what buyers run) whose read of /etc/hostname must be refused.
# Not /bin/sh: on AL2023 it is bash, which needs getpgrp() and /dev/tty.
smoke=$("$BINDIR/varek" run -- /usr/bin/python3 -c \
    'exec("try: open(\"/etc/hostname\")\nexcept OSError: print(\"smoke-ok\")")')
grep -q smoke-ok <<<"$smoke" || die "the smoke agent did not run as expected: $smoke"
refused=$("$BINDIR/varek" refusals)
grep -q UNSATISFIED <<<"$refused" || die "the refused read did not show up"
"$BINDIR/varek" audit
"$BINDIR/varek" export >/dev/null
boms=("$SMOKE"/log/*.cdx.json)
[ "${#boms[@]}" -gt 0 ] || die "export wrote no evidence file"
for bom in "${boms[@]}"; do
    "$BINDIR/varek" export --verify "$bom"
done
# varek bench: its workload runs natively and under the Warden and every
# verdict is checked (exit 1 if one is wrong). A short run: this proves the
# installed bench works, it is not a measurement of the image.
"$BINDIR/varek" bench -n 200 --warmup 20 --rounds 1 > "$SMOKE/bench.txt" 2>&1 \
    || { cat "$SMOKE/bench.txt"; die "varek bench failed"; }
"$BINDIR/varek" policy list
"$BINDIR/varek" version
unset VAREK_CONFIG

say "Cleaning up the build"
rm -rf "$SMOKE" "$BUILD" "$SRC" "$PACKS" "$MARKET"
# Nothing under /etc/varek or /var/log/varek may ship: each buyer's signing
# key is made by their own `varek init` on first use.
rm -rf /etc/varek /var/log/varek
echo "VAREK ${VAREK_VERSION:-} installed in $PREFIX"
