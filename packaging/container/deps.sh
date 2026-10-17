#!/bin/sh
# SPDX-License-Identifier: MIT
# deps.sh build|test|runtime — the packages each stage of the VAREK image
# needs, by the package manager the base image has (dnf, microdnf, apt-get).
set -eu
stage="$1"
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    case "$stage" in
    build)   pkgs="build-essential libseccomp-dev libsodium-dev libssl-dev python3 ca-certificates" ;;
    # what CI installs for the suites (.github/workflows/warden-build.yml)
    test)    pkgs="openjdk-21-jdk-headless musl-tools squid python3-cryptography python3-pytest python3-yaml
                   curl openssl git iproute2 procps sudo" ;;
    runtime) pkgs="libseccomp2 libsodium23 libssl3t64 python3 ca-certificates" ;;
    esac
    # shellcheck disable=SC2086
    apt-get install -y -qq --no-install-recommends $pkgs >/dev/null
    rm -rf /var/lib/apt/lists/*
elif command -v dnf >/dev/null 2>&1; then
    case "$stage" in
    build)
        dnf -y -q install epel-release dnf-plugins-core
        dnf config-manager --set-enabled crb
        dnf -y -q install gcc make libseccomp-devel libsodium-devel openssl-devel python3 ;;
    test) echo "deps.sh: the test stage is Ubuntu's (see the Containerfile)" >&2; exit 2 ;;
    runtime) dnf -y -q install libseccomp libsodium openssl-libs python3 ;;
    esac
    dnf clean all >/dev/null
elif command -v microdnf >/dev/null 2>&1; then
    [ "$stage" = runtime ] || { echo "deps.sh: microdnf images are for the runtime stage only" >&2; exit 2; }
    # libsodium is not in UBI's repositories; it comes from EPEL 9, as on RHEL
    rpm -q epel-release >/dev/null 2>&1 ||
        rpm -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
    microdnf -y install libseccomp libsodium openssl-libs python3 >/dev/null
    microdnf clean all >/dev/null
else
    echo "deps.sh: no apt-get, dnf or microdnf" >&2; exit 2
fi
