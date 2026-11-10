#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# m4_kvm.sh — v1.36 step 1, M4c (tests/measure_v1360/README.md; the design
# note's D11): does a hosted runner give KVM, and does a Fedora Cloud VM
# booted in it run with SELinux enforcing? If so, the matrix's SELinux cell
# can run on the runner, not on a cloud instance. As root.
#
#   sudo -E varek/v1_4/tests/measure_v1360/m4_kvm.sh [--out DIR]
set -uo pipefail

OUT=/var/tmp/measure_v1360
[ "${1:-}" = --out ] && OUT="$2"
[ "$(id -u)" = 0 ] || { echo "m4_kvm.sh: run as root" >&2; exit 2; }
# Fedora's release and where its Cloud images are. To be confirmed on the
# first run: the release current then.
FEDORA="${FEDORA:-44}"
IMAGES="https://download.fedoraproject.org/pub/fedora/linux/releases/$FEDORA/Cloud/x86_64/images/"
mkdir -p "$OUT/kvm"
cd "$OUT/kvm" || exit 1
LOG="$OUT/m4_kvm.log"
measure() {
    echo "MEASURE m4.$1: $2" | tee -a "$OUT/measure.txt"
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- \`m4.$1\`: $2" >> "$GITHUB_STEP_SUMMARY"
    return 0
}

# 1. /dev/kvm, present and usable once the runner's user is let in (the
# udev rule GitHub's documentation gives for its larger runners)
measure kvm_present "$([ -e /dev/kvm ] && echo yes || echo no)"
measure cpu_virt "$(grep -cwE 'vmx|svm' /proc/cpuinfo) of $(nproc) CPUs flag vmx or svm"
echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' > /etc/udev/rules.d/99-kvm4all.rules
udevadm control --reload-rules >> "$LOG" 2>&1
udevadm trigger --name-match=kvm >> "$LOG" 2>&1
user="${SUDO_USER:-runner}"
measure kvm_usable "$(su -s /bin/sh "$user" -c 'test -r /dev/kvm && test -w /dev/kvm' 2>> "$LOG" && echo "yes, by $user" || echo no)"
[ -e /dev/kvm ] || { measure selinux_vm "not measured (no /dev/kvm)"; exit 0; }

# 2. A Fedora Cloud VM under KVM: cloud-init prints getenforce and the
# kernel to the serial console, then powers off
apt-get update >> "$LOG" 2>&1
apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils >> "$LOG" 2>&1 || { measure setup "qemu did not install"; exit 1; }
listing="$(curl -fsSL "$IMAGES")" || { measure setup "no listing at $IMAGES"; exit 1; }
img="$(grep -oE 'Fedora-Cloud-Base-Generic-[0-9.-]+\.x86_64\.qcow2' <<< "$listing" | sort -u | tail -1)"
sums="$(grep -oE 'Fedora-Cloud-[0-9.-]+-x86_64-CHECKSUM' <<< "$listing" | sort -u | tail -1)"
[ -n "$img" ] && [ -n "$sums" ] || { measure setup "no Cloud image or CHECKSUM in $IMAGES"; exit 1; }
curl -fsSL -o base.qcow2 "$IMAGES$img" && curl -fsSL -o CHECKSUM "$IMAGES$sums" || { measure setup "the image did not download"; exit 1; }
want="$(sed -n "s/^SHA256 ($img) = \([0-9a-f]*\)$/\1/p" CHECKSUM)"
[ -n "$want" ] && [ "$(sha256sum base.qcow2 | awk '{print $1}')" = "$want" ] || { measure setup "$img does not match its CHECKSUM"; exit 1; }
measure image "$img"
qemu-img create -f qcow2 -F qcow2 -b base.qcow2 disk.qcow2 >> "$LOG" 2>&1
cat > user-data <<'EOF'
#cloud-config
runcmd:
  - [sh, -c, 'echo "VAREK-M4 getenforce=$(getenforce) kernel=$(uname -r)" > /dev/ttyS0']
  - [poweroff]
EOF
printf 'instance-id: varek-m4\nlocal-hostname: varek-m4\n' > meta-data
cloud-localds seed.iso user-data meta-data >> "$LOG" 2>&1 || { measure setup "cloud-localds failed"; exit 1; }
t0=$(date +%s)
timeout 900 qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
    -drive file=disk.qcow2,if=virtio -drive file=seed.iso,if=virtio,format=raw \
    -nic user,model=virtio -display none -monitor none -serial file:serial.log >> "$LOG" 2>&1
rc=$?
secs=$(( $(date +%s) - t0 ))
line="$(grep -a -m1 'VAREK-M4' serial.log 2> /dev/null | tr -d '\r')"
if [ -n "$line" ]; then
    measure selinux_vm "${line#VAREK-M4 }; boot to power-off ${secs} s"
else
    measure selinux_vm "no answer (qemu exit $rc after ${secs} s; the serial log's end: $(tail -c 300 serial.log 2>/dev/null | tr -d '\r' | tr '\n' ' '))"
fi
exit 0
