#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# provision.sh — v1.30 (docs/security/v1.30-macos.md, step 4): set up the
# guest VAREK runs in on a Mac. Run as root inside the VM by `varek vm init`,
# with the VAREK checkout shared read from SRC:
#
#   provision.sh SRC
#
# The guest: RHEL 9.6 or later on aarch64, registered (subscription-manager),
# or a rebuild of it (AlmaLinux, Rocky Linux) or CentOS Stream 9. It installs
# what the Warden needs to build (libsodium from EPEL), builds it from a copy
# of SRC in /opt/varek-src, installs it (make install: /opt/varek, varek in
# /usr/local/bin), makes sure Landlock is on, and runs varek doctor.
set -euo pipefail
SRC="${1:?usage: provision.sh SRC}"
say() { printf '[provision] %s\n' "$*"; }
die() { printf '[provision] %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
. /etc/os-release
MAJOR="${VERSION_ID%%.*}" MINOR="${VERSION_ID#*.}"; [ "$MINOR" = "$VERSION_ID" ] && MINOR=0
[ "$MAJOR" = 9 ] || die "$PRETTY_NAME: the guest must be RHEL 9 or a rebuild of it"
[ "$(uname -m)" = aarch64 ] || say "note: this guest is $(uname -m), not aarch64"
case "$ID" in
    rhel)
        [ "$MINOR" -ge 6 ] || die "$PRETTY_NAME: RHEL 9.6 or later is needed (Landlock)"
        subscription-manager status > /dev/null 2>&1 || die "the guest is not registered: sudo subscription-manager register"
        subscription-manager repos --enable "codeready-builder-for-rhel-9-$(uname -m)-rpms" ;;
    almalinux|rocky|centos)
        dnf -y install dnf-plugins-core
        dnf config-manager --set-enabled crb ;;
    *) die "$PRETTY_NAME is not RHEL 9 or a rebuild of it" ;;
esac

say "packages"
dnf -y install gcc make git tar python3 libseccomp-devel openssl-devel
# libsodium (the Warden's Ed25519 signatures) is in EPEL, not RHEL
rpm -q epel-release > /dev/null 2>&1 || dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
dnf -y install libsodium-devel

say "the Warden, from $SRC"
rm -rf /opt/varek-src.new
mkdir -p /opt/varek-src.new
tar -C "$SRC" --exclude=./.git -cf - . | tar -C /opt/varek-src.new -xf -
rm -rf /opt/varek-src && mv /opt/varek-src.new /opt/varek-src
make -C /opt/varek-src/varek/v1_4 clean > /dev/null 2>&1 || true
make -C /opt/varek-src/varek/v1_4 all
make -C /opt/varek-src/varek/v1_4 install

# Landlock: on by default from RHEL 9.6; if the kernel's LSM list lacks it,
# add it (takes effect at the next boot)
mkdir -p /var/lib/varek-vm
if ! grep -qw landlock /sys/kernel/security/lsm 2>/dev/null; then
    say "Landlock is not in the kernel's LSM list: adding it (at the next boot)"
    grubby --update-kernel=ALL --args="lsm=$(cat /sys/kernel/security/lsm),landlock"
    touch /var/lib/varek-vm/reboot-needed
fi

say "varek doctor"
varek doctor || say "varek doctor reported a problem (above)"
date -u +%Y-%m-%dT%H:%M:%SZ > /var/lib/varek-vm/provisioned
say "done"
