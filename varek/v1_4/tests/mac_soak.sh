#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mac_soak.sh — v1.30 step 7 (docs/security/v1.30-macos.md): the shared soak
# (tests/soak_shared) for 24 hours inside VAREK's VM on a Mac, the one
# mac_check.sh made and set up. Run as the Mac's user (not root), from the
# same checkout, after mac_check.sh has passed:
#
#   varek/v1_4/tests/mac_soak.sh start [--hours 24]
#   varek/v1_4/tests/mac_soak.sh status
#   varek/v1_4/tests/mac_soak.sh check
#
# start   starts the VM (if it is not running) with a project directory of its
#         own shared, installs what the soak needs in the VM, and starts the
#         soak there in the background (setsid nohup, as root in the VM): it
#         keeps running after this script and ssh end. The Mac is kept awake
#         for the soak's length and an hour more (caffeinate). The VM and the
#         soak must not be stopped until it ends: no `varek vm stop`, and no
#         mac_check.sh (it stops the VM at its end).
# status  the soak's process in the VM, its time so far, and its last lines.
# check   after the end: the soak's report (soak_check: PASS or FAIL) and its
#         files copied to the Mac, into ~/varek-mac-soak/.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VAREK="$HERE/tools/varek"
OUT="$HOME/varek-mac-soak"
PROJ="$HOME/varek-mac-soak-project"
VMOUT=/var/tmp/varek-vm-soak-24h            # in the VM
cmd="${1:-}"; [ $# -gt 0 ] && shift
HOURS=24
while [ $# -gt 0 ]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        *) echo "mac_soak.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" != 0 ] || { echo "mac_soak.sh: run as the Mac's user, not root (the VM is the user's)" >&2; exit 2; }
vk() { python3 "$VAREK" "$@"; }
vssh() { python3 "$VAREK" vm ssh "$@"; }
# the VM's copy of the source (/opt/varek-src, made when the VM was set up)
# refreshed from this checkout, so what runs in the VM is this commit
sync_src() { (cd "$HERE/../.." && COPYFILE_DISABLE=1 tar --no-mac-metadata --exclude .git -cf - .) |
             vssh "sudo tar --no-same-owner -C /opt/varek-src -xf -"; }
mkdir -p "$OUT"

case "$cmd" in
start)
    if vk vm status 2>/dev/null | grep -q '^running *yes'; then
        echo "mac_soak.sh: the VM is running; using it as it is"
    else
        mkdir -p "$PROJ"
        vk vm start "$PROJ" || { echo "mac_soak.sh: the VM did not start (mac_check.sh first)"; exit 1; }
    fi
    if vssh "pgrep -f '[s]oak_shared/soak.sh' > /dev/null"; then
        echo "mac_soak.sh: a soak is already running in the VM (mac_soak.sh status)"; exit 1
    fi
    vssh "[ ! -e $VMOUT ]" || { echo "mac_soak.sh: $VMOUT is already in the VM: move it aside first (vm ssh)"; exit 1; }
    echo "== what the soak needs, in the VM"
    sync_src || { echo "mac_soak.sh: the VM's copy of the source could not be refreshed"; exit 1; }
    vssh "sudo dnf -y -q install python3-cryptography openssl git > /dev/null && cd /opt/varek-src && sudo make -s -C varek/v1_4 all tests/v1281_sub" ||
        { echo "mac_soak.sh: the VM's setup for the soak failed (above)"; exit 1; }
    echo "== the soak, $HOURS h, in the background in the VM"
    # only the soak itself in the background, its descriptors none of ssh's
    # (a list put in the background, `cd && ...&`, would hold the session
    # open, and this would wait the soak's whole length)
    vssh "cd /opt/varek-src || exit 1; sudo setsid nohup varek/v1_4/tests/soak_shared/soak.sh --hours $HOURS --out $VMOUT > /var/tmp/varek-vm-soak-24h.out 2>&1 < /dev/null &"
    sleep 20
    vssh "pgrep -f '[s]oak_shared/soak.sh' > /dev/null" || {
        echo "mac_soak.sh: the soak stopped at once:"; vssh "tail -20 /var/tmp/varek-vm-soak-24h.out"; exit 1; }
    # the Mac awake for the soak and an hour more
    secs=$(python3 -c "print(int(float('$HOURS') * 3600) + 3600)")
    # (macOS's nohup refuses to run without a console, as under Session
    # Manager: the hangup is ignored by hand)
    /bin/sh -c 'trap "" HUP; exec caffeinate -i -s -t "$0"' "$secs" > /dev/null 2>&1 < /dev/null &
    {
        echo "mac_soak.sh start: $(date '+%Y-%m-%d %H:%M %Z') ($(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z'))"
        echo "  host: $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null), $(sysctl -n hw.model 2>/dev/null)"
        echo "  commit: $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null)"
        echo "  the VM: $(vssh 'uname -srm; . /etc/os-release; echo $PRETTY_NAME; varek version 2>&1 | head -1' 2>/dev/null | tr '\n' ' ')"
        echo "  ends about $(TZ=America/Chicago date -v+"${HOURS%.*}"H '+%Y-%m-%d %H:%M %Z' 2>/dev/null)"
    } | tee "$OUT/start.txt"
    echo "mac_soak.sh: started. Check it with: varek/v1_4/tests/mac_soak.sh status"
    ;;
status)
    vk vm status | sed -n '3,4p'
    vssh "ps -eo pid,etime,args | grep '[s]oak_shared/soak.sh' | head -1; tail -3 /var/tmp/varek-vm-soak-24h.out; ls $VMOUT 2>/dev/null | tr '\n' ' '; echo" ||
        echo "mac_soak.sh: the VM does not answer"
    ;;
check)
    if vssh "pgrep -f '[s]oak_shared/soak.sh' > /dev/null"; then
        echo "mac_soak.sh: the soak is still running (mac_soak.sh status)"; exit 1
    fi
    vssh "sudo test -s $VMOUT/report.txt" || {
        echo "mac_soak.sh: no report in the VM; its last lines:"; vssh "tail -20 /var/tmp/varek-vm-soak-24h.out"; exit 1; }
    # the report, the run's output and the runs' records, copied here over ssh
    vssh "sudo tar -C /var/tmp -czf - varek-vm-soak-24h varek-vm-soak-24h.out" > "$OUT/varek-vm-soak-24h.tar.gz" &&
        echo "the soak's files: $OUT/varek-vm-soak-24h.tar.gz"
    vssh "sudo cat $VMOUT/report.txt" > "$OUT/report.txt"
    cat "$OUT/report.txt"
    grep -q 'soak_check: PASS' "$OUT/report.txt"
    ;;
*)
    sed -n '3,/^set -u$/{/^#/p}' "$0"; exit 2 ;;
esac
