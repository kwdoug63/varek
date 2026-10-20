#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mac_check.sh — v1.30 step 5 (docs/security/v1.30-macos.md): VAREK on a Mac
# with Apple silicon, through its VM, checked end to end on a real Mac (an
# EC2 Mac). Run as the Mac's user (not root), from a checkout of the v1.30
# branch, after `brew install vfkit qemu python`:
#
#   varek/v1_4/tests/mac_check.sh [--image FILE --sha256 HEX] [--out DIR] [--sweep] [--soak-trial]
#
# --image FILE   the RHEL 9 aarch64 KVM guest image (9.6 or later), for the
#                first run: `varek vm init` makes the VM from it, checked
#                against --sha256 (as Red Hat's download page shows it). A
#                RHEL guest stops there to be registered with your own login;
#                then run this again without --image (it carries on with
#                --resume).
# --sweep        also run every suite inside the VM (tests/arm64_sweep.sh; an
#                hour or more)
# --soak-trial   also the shared soak's 6-minute trial inside the VM
#
# What it checks, each line PASS or FAIL, into DIR/summary.txt (default
# ~/varek-mac-check):
#   1. the Mac: macOS on Apple silicon, vfkit, qemu-img, ssh;
#   2. the VM made and set up (varek vm init), once;
#   3. its start time, cold, with a project shared; varek doctor inside;
#   4. what the VM sees of the Mac: the project share only (one virtio-fs
#      mount; of the Mac's /Users only the path to the project), even to
#      root in the VM (a link or .. out of the share);
#   5. an agent under the Warden in the VM (varek vm run): it reads and
#      writes the project, and the Mac sees its file; it cannot read a file
#      in the Mac's home directory (not in the VM at all), nor write outside
#      the project in the VM, nor connect to the Mac (the VM's gateway) or
#      to the instance metadata service; its verdict stream copied to the
#      project and audited; what root in the VM reaches of the Mac's network
#      is reported (a known limit, docs/security/v1.30-macos.md);
#   6. (--sweep) every suite inside the VM; (--soak-trial) the soak's trial.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VAREK="$HERE/tools/varek"
IMAGE="" SHA="" OUT="$HOME/varek-mac-check" SWEEP=0 SOAK=0
while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --sha256) SHA="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --sweep) SWEEP=1; shift ;;
        --soak-trial) SOAK=1; shift ;;
        -h|--help) sed -n '3,/^set -u$/{/^#/p}' "$0"; exit 0 ;;
        *) echo "mac_check.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" != 0 ] || { echo "mac_check.sh: run as the Mac's user, not root (the VM is the user's)" >&2; exit 2; }
mkdir -p "$OUT"
SUM="$OUT/summary.txt"
fails=0
pass() { printf '  PASS  %s\n' "$1" | tee -a "$SUM"; }
flunk() { printf '  FAIL  %s\n' "$1" | tee -a "$SUM"; fails=$((fails + 1)); }
check() { local d="$1"; shift; if "$@" >> "$OUT/checks.log" 2>&1; then pass "$d"; else flunk "$d"; fi; }
vk() { python3 "$VAREK" "$@"; }
vssh() { python3 "$VAREK" vm ssh "$@"; }
{
    echo "mac_check.sh $(date '+%Y-%m-%d %H:%M %Z')"
    echo "host: $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null), $(uname -m), $(sysctl -n hw.model 2>/dev/null)"
    echo "commit: $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null)"
    echo "vfkit: $(vfkit --version 2>/dev/null | head -1)  qemu-img: $(qemu-img --version 2>/dev/null | head -1)"
} | tee "$SUM"

echo "== 1. the Mac" | tee -a "$SUM"
check "macOS on Apple silicon" sh -c '[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ]'
check "vfkit, qemu-img, ssh and python3 installed" sh -c 'command -v vfkit && command -v qemu-img && command -v ssh && command -v python3'
check "vfkit takes --cloud-init (0.6 or later)" sh -c 'vfkit --help 2>&1 | grep -q -- --cloud-init'
check "the DHCP leases (the VM's address) are readable" sh -c '[ ! -e /var/db/dhcpd_leases ] || [ -r /var/db/dhcpd_leases ]'
[ "$fails" = 0 ] || { echo "mac_check.sh: the Mac is not ready (above)"; exit 1; }

echo "== 2. the VM" | tee -a "$SUM"
VMJ="${VAREK_VM_DIR:-$HOME/.varek/vm}/default/vm.json"
if [ -n "$IMAGE" ] && [ ! -e "$VMJ" ]; then
    t0=$(date +%s)
    [ -n "$SHA" ] || { echo "mac_check.sh: --image needs --sha256 HEX (Red Hat's download page shows it)"; exit 2; }
    vk vm init --image "$IMAGE" --sha256 "$SHA" 2>&1 | tee "$OUT/init.log"; rc=${PIPESTATUS[0]}
    if [ "$rc" = 3 ]; then
        echo "mac_check.sh: register the guest as the lines above say, then run this again without --image"
        exit 3
    fi
    [ "$rc" = 0 ] && pass "varek vm init: the VM made and set up ($(( $(date +%s) - t0 )) s)" || { flunk "varek vm init ($OUT/init.log)"; exit 1; }
elif [ -e "$VMJ" ] && ! python3 -c "import json,sys; sys.exit(0 if json.load(open('$VMJ')).get('provisioned') else 1)"; then
    vk vm init --resume 2>&1 | tee "$OUT/init.log"; rc=${PIPESTATUS[0]}
    [ "$rc" = 0 ] && pass "varek vm init --resume: the VM set up" || { flunk "varek vm init --resume ($OUT/init.log)"; exit 1; }
elif [ -e "$VMJ" ]; then
    pass "the VM exists and is set up ($VMJ)"
else
    echo "mac_check.sh: no VM yet: give --image FILE (the RHEL 9 aarch64 KVM guest image)"; exit 2
fi

echo "== 3. its start, and varek doctor inside" | tee -a "$SUM"
PROJ="$HOME/varek-mac-check-project"
rm -rf "$PROJ"; mkdir -p "$PROJ"; echo "the project's file" > "$PROJ/readme.txt"
SECRET="$HOME/varek-mac-check-secret.txt"
echo "not the VM's to read: $(date +%s)" > "$SECRET"; chmod 600 "$SECRET"
vk vm stop > /dev/null 2>&1
t0=$(python3 -c 'import time; print(time.time())')
if vk vm start "$PROJ" > "$OUT/start.log" 2>&1; then
    secs=$(python3 -c "import time; print(f'{time.time() - $t0:.1f}')")
    pass "varek vm start, cold, the project shared: ${secs} s to ssh"
else
    flunk "varek vm start ($OUT/start.log)"; exit 1
fi
vssh "sudo varek doctor" > "$OUT/doctor.txt" 2>&1
check "varek doctor in the VM: Landlock, seccomp user-notify, cgroup v2" \
    sh -c "grep -Eq 'OK.*Landlock ABI' '$OUT/doctor.txt' && ! grep -E '^ *FAIL' '$OUT/doctor.txt' | grep -qiv 'varek.conf'"
vssh "uname -srm; . /etc/os-release; echo \$PRETTY_NAME; cat /sys/kernel/security/lsm" > "$OUT/guest.txt" 2>&1
echo "  guest: $(tr '\n' ' ' < "$OUT/guest.txt")" | tee -a "$SUM"

echo "== 4. what the VM sees of the Mac" | tee -a "$SUM"
vssh "findmnt -rn -t virtiofs -o TARGET,SOURCE" > "$OUT/mounts.txt" 2>&1
# (macOS's wc pads its count with spaces)
check "one virtio-fs share, the project, at the Mac's path" sh -c "[ \"\$(wc -l < '$OUT/mounts.txt' | tr -d ' ')\" = 1 ] && grep -q '^$PROJ project' '$OUT/mounts.txt'"
# the project's path is made in the VM to mount it at: nothing else of /Users
check "of the Mac's /Users, only the path to the project" vssh \
    "[ -z \"\$(sudo find /Users -path '$PROJ' -prune -o -print | grep -vx -e /Users -e '$HOME' -e '$(dirname "$PROJ")')\" ]"
check "the Mac's file outside the project is not in the VM" vssh "! sudo test -e '$SECRET'"
check "root in the VM: a link out of the share does not reach it" vssh \
    "sudo ln -sfn '$SECRET' '$PROJ/link-out' && ! sudo cat '$PROJ/link-out'; sudo rm -f '$PROJ/link-out'"
check "root in the VM: .. from the share does not reach it" vssh "! sudo cat '$PROJ/../$(basename "$SECRET")'"
GW="$(vssh "ip route show default | awk '{print \$3; exit}'" 2>/dev/null)"

echo "== 5. an agent under the Warden in the VM" | tee -a "$SUM"
cat > "$PROJ/probe.py" <<EOF
import os, json
r = {}
def t(name, f):
    try: f(); r[name] = "ok"
    except OSError as e: r[name] = e.strerror
t("read_project", lambda: open("readme.txt").read())
t("write_project", lambda: open("from-the-vm.txt", "w").write("written by the agent in the VM\n"))
t("read_mac_secret", lambda: open("$SECRET").read())
t("write_outside", lambda: open("/var/tmp/varek-mac-check-outside", "w").write("x"))
t("read_shadow", lambda: open("/etc/shadow").read())
import socket
def conn(host, port):
    s = socket.create_connection((host, port), timeout=5); s.close()
t("connect_mac", lambda: conn("${GW:-192.168.64.1}", 22))
t("connect_imds", lambda: conn("169.254.169.254", 80))
print(json.dumps(r))
EOF
(cd "$PROJ" && vk vm run --profile python -- python3 probe.py) > "$OUT/probe.out" 2> "$OUT/probe.err"
r() { python3 -c "import json,sys; d=[json.loads(l) for l in open('$OUT/probe.out') if l.startswith('{')]; print(d[-1].get(sys.argv[1]) if d else 'no output')" "$1"; }
[ "$(r read_project)" = ok ] && [ "$(r write_project)" = ok ] && pass "the agent reads and writes the project" || flunk "the project ($(r read_project), $(r write_project))"
check "... and the Mac sees what it wrote" grep -q 'written by the agent in the VM' "$PROJ/from-the-vm.txt"
[ "$(r read_mac_secret)" != ok ] && pass "it cannot read the Mac's file outside the project ($(r read_mac_secret))" || flunk "it read the Mac's file outside the project"
[ "$(r write_outside)" != ok ] && pass "it cannot write outside the project in the VM ($(r write_outside))" || flunk "it wrote outside the project"
[ "$(r read_shadow)" != ok ] && pass "it cannot read the VM's /etc/shadow ($(r read_shadow))" || flunk "it read /etc/shadow"
[ "$(r connect_mac)" != ok ] && pass "it cannot connect to the Mac, the VM's gateway ${GW:-192.168.64.1}:22 ($(r connect_mac))" || flunk "it connected to the Mac"
[ "$(r connect_imds)" != ok ] && pass "it cannot connect to the instance metadata service ($(r connect_imds))" || flunk "it connected to 169.254.169.254"
# the stream by the name varek vm run gave it, not the newest file in a directory the agent writes
STREAM="$(sed -n 's/^\[varek\] the run.s verdict stream: //p' "$OUT/probe.err" | tail -1)"
check "its verdict stream copied to the project (.varek/)" test -s "$STREAM"
# audited in the VM, where the run's policy and the certificate checker are
# (the copy on the Mac is the same file: compared by its hash)
SNAME="$(basename "$STREAM")"
vssh "sudo varek audit /var/log/varek/$SNAME" > "$OUT/audit.txt" 2>&1; arc=$?
[ "$arc" = 0 ] && pass "... and the stream audits in the VM (exit 0)" || flunk "the stream's audit in the VM: exit $arc ($OUT/audit.txt)"
check "... and the copy on the Mac is the VM's stream" sh -c \
    "[ \"\$(shasum -a 256 < '$STREAM' | cut -d' ' -f1)\" = \"\$(python3 '$VAREK' vm ssh 'sudo sha256sum /var/log/varek/$SNAME' | cut -d' ' -f1)\" ]"
# root in the VM, unlike the agent, is not under the Warden: what it reaches of the Mac's network
for t in "${GW:-192.168.64.1} 22" "${GW:-192.168.64.1} 5000" "169.254.169.254 80"; do
    set -- $t
    if vssh "timeout 5 bash -c '</dev/tcp/$1/$2'" > /dev/null 2>&1; then w="reaches"; else w="does not reach"; fi
    echo "  INFO  root in the VM $w $1:$2" | tee -a "$SUM"
done

if [ "$SWEEP" = 1 ]; then
    echo "== 6a. every suite inside the VM" | tee -a "$SUM"
    vssh "sudo /opt/varek-src/varek/v1_4/tests/arm64_sweep.sh --deps --out /var/tmp/varek-vm-sweep" > "$OUT/sweep.log" 2>&1
    vssh "cat /var/tmp/varek-vm-sweep/summary.txt 2>/dev/null || ls /var/tmp/varek-vm-sweep" > "$OUT/sweep-summary.txt" 2>&1
    tail -45 "$OUT/sweep-summary.txt" | tee -a "$SUM"
    if grep -q ' FAILED ' "$OUT/sweep-summary.txt" || ! grep -Eq '^test-[a-z0-9-]+ +ok ' "$OUT/sweep-summary.txt"; then
        flunk "every suite inside the VM ($OUT/sweep-summary.txt)"
    else
        pass "every suite inside the VM"
    fi
fi
if [ "$SOAK" = 1 ]; then
    echo "== 6b. the shared soak's 6-minute trial inside the VM" | tee -a "$SUM"
    vssh "sudo dnf -y -q install python3-cryptography openssl git > /dev/null && cd /opt/varek-src && sudo make -s -C varek/v1_4 tests/v1281_sub && sudo varek/v1_4/tests/soak_shared/soak.sh --hours 0.1 --interval 3 --out /var/tmp/varek-vm-soak-trial-\$(date +%s)" > "$OUT/soak-trial.log" 2>&1
    grep -q 'soak_check: PASS' "$OUT/soak-trial.log" && pass "the soak's trial: soak_check: PASS" || flunk "the soak's trial ($OUT/soak-trial.log)"
fi

vk vm stop > /dev/null 2>&1
rm -f "$SECRET"
echo | tee -a "$SUM"
if [ "$fails" = 0 ]; then echo "mac_check.sh: PASS ($SUM)" | tee -a "$SUM"; else echo "mac_check.sh: $fails FAILED ($SUM)" | tee -a "$SUM"; fi
[ "$fails" = 0 ]
