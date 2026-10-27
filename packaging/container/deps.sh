#!/bin/sh
# SPDX-License-Identifier: MIT
# deps.sh build|test|runtime — the packages each stage of the VAREK image
# needs, by the package manager the base image has (dnf, microdnf, apt-get).
set -eu
stage="$1"
# an install, tried again with the package manager's metadata dropped: some
# of EPEL's mirrors at times serve a repomd.xml other than the one its
# metalink names ("checksum doesn't match"), until the metalink is fetched
# again and agrees (it has lasted half an hour in CI, other builds passing).
# Each try is held to five minutes: an install that stalls, printing nothing,
# is tried again too (v1.36's matrix: the node image's build sat in this step
# for 20 minutes in four of its runs, the same build taking one in the rest)
# On AlmaLinux, a try that fails moves its repositories from the mirror list
# to AlmaLinux's own server (the baseurl each repository file keeps
# commented out), its packages still checked by AlmaLinux's key: v1.36's
# arm64 runners were handed an aarch64 mirror that served an empty
# repomd.xml at every try, and another that stalled.
almalinux_primary() {
    [ -f /etc/almalinux-release ] && [ ! -e /etc/yum.repos.d/.varek-primary ] || return 0
    echo "deps.sh: AlmaLinux's repositories from repo.almalinux.org, not the mirror list" >&2
    sed -i -e 's|^mirrorlist=|#mirrorlist=|' -e 's|^# *baseurl=|baseurl=|' /etc/yum.repos.d/almalinux-*.repo
    : > /etc/yum.repos.d/.varek-primary
}
retry() {
    n=1
    until timeout 300 "$@"; do
        [ "$n" -lt 6 ] || return 1
        echo "deps.sh: $1 failed or stalled (try $n of 6); again in $((n * 15)) s, its metadata dropped" >&2
        almalinux_primary
        "$1" clean all >/dev/null 2>&1 || true
        sleep $((n * 15))
        n=$((n + 1))
    done
}
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    case "$stage" in
    build)   pkgs="build-essential libseccomp-dev libsodium-dev libssl-dev python3 ca-certificates" ;;
    # what CI installs for the suites (.github/workflows/warden-build.yml)
    test)    pkgs="openjdk-21-jdk-headless musl-tools squid python3-cryptography python3-pytest python3-yaml
                   python3-pip curl openssl git iproute2 procps sudo" ;;
    runtime) pkgs="libseccomp2 libsodium23 libssl3t64 python3 ca-certificates" ;;
    esac
    # shellcheck disable=SC2086
    apt-get install -y -qq --no-install-recommends $pkgs >/dev/null
    rm -rf /var/lib/apt/lists/*
elif command -v dnf >/dev/null 2>&1; then
    case "$stage" in
    build)
        retry dnf -y -q install epel-release dnf-plugins-core
        dnf config-manager --set-enabled crb
        # glibc-static (CodeReady Builder): the launcher, varek-init, is static (v1.34)
        retry dnf -y -q install gcc make libseccomp-devel libsodium-devel openssl-devel python3 glibc-static ;;
    test) echo "deps.sh: the test stage is Ubuntu's (see the Containerfile)" >&2; exit 2 ;;
    runtime) retry dnf -y -q install libseccomp libsodium openssl-libs python3 ;;
    esac
    dnf clean all >/dev/null
elif command -v microdnf >/dev/null 2>&1; then
    [ "$stage" = runtime ] || { echo "deps.sh: microdnf images are for the runtime stage only" >&2; exit 2; }
    # libsodium is not in UBI's repositories; it comes from EPEL 9, as on RHEL.
    # EPEL's key is the one kept with this file (packaging/container/
    # RPM-GPG-KEY-EPEL-9, fingerprint FF8A D134 4597 106E CE81 3B91 8A38 72BF
    # 3228 467C), imported first, so epel-release is installed only signed by
    # it, and every EPEL package microdnf installs after it is checked by it
    if ! rpm -q epel-release >/dev/null 2>&1; then
        key="${VAREK_EPEL_KEY:-/tmp/RPM-GPG-KEY-EPEL-9}"
        rpm --import "$key"
        rpm -q gpg-pubkey-3228467c >/dev/null || { echo "deps.sh: EPEL 9's key did not import" >&2; exit 1; }
        curl -fsSL -o /tmp/epel-release.rpm https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
        rpm -K /tmp/epel-release.rpm | grep -q 'digests signatures OK$' ||
            { echo "deps.sh: epel-release is not signed by EPEL 9's key" >&2; exit 1; }
        rpm -i /tmp/epel-release.rpm
        rm -f /tmp/epel-release.rpm "$key"
    fi
    retry microdnf -y install libseccomp libsodium openssl-libs python3 >/dev/null
    microdnf clean all >/dev/null
else
    echo "deps.sh: no apt-get, dnf or microdnf" >&2; exit 2
fi
