#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1162.sh — regression test for VAREK v1.16.2: the off-host anchor.
#
# Sets up, on this machine, what a deployment sets up on two:
#   - an anchor receiver (tools/varek_anchor_receiver.sh) behind a private sshd
#     on 127.0.0.1:2222, with its own test account, directory and helper path;
#   - the forwarder (tools/varek_anchor_forward.py) reading the Warden's anchor
#     FIFO and sending over SSH with a dedicated key and a pinned host key.
# Then:
#   1. a signed run is anchored off-host, each line with the receiver's receive
#      time, and audits "signed, anchored" against the receiver's copy;
#   2. the receiver's account can only append well-formed anchor lines: a
#      requested command is not run, malformed lines are dropped, the file is
#      append-only, port forwarding is refused, and a public key carrying a
#      second line is refused at setup;
#   3. nothing is lost: an outage of the anchor host (records wait in the
#      spool), a restart of the forwarder in the middle of a run (the Warden
#      holds the FIFO), a receiver that cannot write (the forwarder retries),
#      and a full spool disk (lines are held in memory);
#   4. the audit is not fooled or blocked by extra anchor lines: unsigned,
#      conflicting or malformed lines are noted and ignored; --list-runs lists
#      every run; --max-anchor-delay uses the receive times;
#   5. preflight: a FIFO anchor without a reader fails; with the forwarder
#      running the trial run is delivered and audited; with the anchor host
#      down, delivery fails; local-file anchor and on-host key are warnings;
#   6. --exec delivers to any command.
# Skipped (not failed) if sshd is not installed.
#
# Usage: ./test_v1162.sh <warden> <varek_keygen> <v1160_probe>
set -u

WARDEN="${1:?usage: test_v1162.sh <warden> <varek_keygen> <probe>}"
KEYGEN="${2:?}"
PROBE="${3:?}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
FWD="$HERE/tools/varek_anchor_forward.py"
RCV="$HERE/tools/varek_anchor_receiver.sh"
PRE="$HERE/tools/varek_preflight.sh"
POL="$HERE/policies/finance.policy.txt"
A=(python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$HERE/tools/vdp_cert_check")

fail=0
pass() { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }

if ! command -v /usr/sbin/sshd >/dev/null 2>&1 || ! command -v ssh >/dev/null 2>&1; then
    echo "test_v1162: SKIP (OpenSSH server and client are needed)"; exit 0
fi

U=varek-anchor-v1162 RD=/srv/varek-anchor-v1162 HELPER=/usr/local/lib/varek-v1162/varek-anchor-append
FIFO=/run/varek-v1162/anchor.fifo SP=/var/lib/varek-v1162/spool LOGD=/var/log/varek-v1162
OUT="$(mktemp -d)" PORT=2222
FWPID="" MNT=""
cleanup() {
    [ -n "$FWPID" ] && kill "$FWPID" 2>/dev/null
    [ -f "$OUT/sshd.pid" ] && kill "$(cat "$OUT/sshd.pid")" 2>/dev/null
    [ -n "$MNT" ] && umount "$MNT" 2>/dev/null
    chattr -a "$RD"/*.anchor.log "$RD"/*.moved 2>/dev/null
    rm -rf "$RD" /run/varek-v1162 /var/lib/varek-v1162 "$LOGD" "$(dirname "$HELPER")" "$OUT" \
           /tmp/varek_v1162_marker
    userdel "$U" 2>/dev/null
}
trap cleanup EXIT
mkdir -p "$LOGD"
"$KEYGEN" "$OUT/log.key" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$OUT/fwkey" -C varek-forwarder
ssh-keygen -q -t ed25519 -N '' -f "$OUT/other" -C other
ssh-keygen -q -t ed25519 -N '' -f "$OUT/hostkey"
mkdir -p /run/sshd
cat > "$OUT/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $OUT/hostkey
PidFile $OUT/sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AuthorizedKeysFile .ssh/authorized_keys
StrictModes yes
EOF
start_sshd() { /usr/sbin/sshd -f "$OUT/sshd_config"; sleep 0.5; }
stop_sshd() { kill "$(cat "$OUT/sshd.pid")" 2>/dev/null; sleep 0.5; }
start_sshd
SSH=(ssh -o BatchMode=yes -o IdentitiesOnly=yes -o UserKnownHostsFile="$OUT/kh" -p "$PORT")
start_fwd() {
    python3 "$FWD" --fifo "$FIFO" --spool "$SP" --ssh "$U@127.0.0.1" --ssh-port "$PORT" \
        --ssh-key "$OUT/fwkey" --known-hosts "$OUT/kh" --interval 0.5 >> "$OUT/fw.log" 2>&1 &
    FWPID=$!
    for _ in $(seq 1 20); do [ -p "$FIFO" ] && break; sleep 0.2; done
    sleep 0.3
}
stop_fwd() { [ -n "$FWPID" ] && { kill "$FWPID"; wait "$FWPID" 2>/dev/null; FWPID=""; }; }
count() { local n; n="$(grep -c "\"run\":\"$2\"" "$1" 2>/dev/null)"; echo "${n:-0}"; }
wait_run() {  # anchor file, run id, expected lines
    for _ in $(seq 1 40); do [ "$(count "$1" "$2")" -ge "$3" ] && return 0; sleep 0.5; done; return 1
}
runid() { grep -o '"event":"run_start","run":"[0-9a-f]*"' "$1" | cut -d'"' -f8; }
nsig() { grep -c '"sig":' "$1"; }
warden_run() {  # log, extra warden args..., -- target...
    local log="$1"; shift
    timeout 60 "$WARDEN" "$POL" --sign-key "$OUT/log.key" --anchor "$FIFO" "$@" > /dev/null 2> "$log"
}

echo "== setup"
o="$(bash "$RCV" --name host1 --pubkey "$(cat "$OUT/fwkey.pub")"$'\n'"$(cat "$OUT/other.pub")" \
      --user "$U" --dir "$RD" --helper "$HELPER" 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && grep -q "single line" <<<"$o" && ! id "$U" >/dev/null 2>&1 \
  && pass "a public key carrying a second line is refused before anything is created" || flunk "multi-line pubkey"
bash "$RCV" --name host1 --pubkey "$(cat "$OUT/fwkey.pub")" --user "$U" --dir "$RD" --helper "$HELPER" > "$OUT/rcv.out"
RF="$RD/host1.anchor.log"
grep -q "append-only (chattr +a)" "$OUT/rcv.out" && [ "$(wc -l < "$RD/.ssh/authorized_keys")" = 1 ] \
  && pass "receiver set up: one restricted key, forced command, append-only file" || { flunk "receiver setup"; cat "$OUT/rcv.out"; }
ssh-keyscan -p "$PORT" -t ed25519 127.0.0.1 2>/dev/null > "$OUT/kh"
start_fwd

echo "== 1. a signed run, anchored off-host"
warden_run "$LOGD/v1.log" --checkpoint-every 2 -- /bin/cat /etc/ld.so.cache
R1="$(runid "$LOGD/v1.log")"; n1=$(nsig "$LOGD/v1.log")
wait_run "$RF" "$R1" "$n1" && pass "all $n1 signed records reached the anchor host" || flunk "records on the anchor host"
grep "\"run\":\"$R1\"" "$RF" | grep -q '"received_ns":[0-9]*}$' && pass "each carries the anchor host's receive time" || flunk "received_ns"
o="$("${A[@]}" --pubkey "$OUT/log.key.pub" --anchor "$RF" --max-anchor-delay 30 "$LOGD/v1.log" 2>&1)"
grep -q "integrity: signed, anchored" <<<"$o" && grep -q "anchoring delay: at most" <<<"$o" && grep -q PASS <<<"$o" \
  && pass "audit against the receiver's copy: signed, anchored; delay reported" || { flunk "audit vs receiver"; echo "$o" | tail -4; }

echo "== 2. the receiver's account can only append anchor lines"
before=$(wc -l < "$RF")
printf '%s\n' '{"run":"not an anchor line"}' hello | "${SSH[@]}" -i "$OUT/fwkey" "$U@127.0.0.1" \
    "touch /tmp/varek_v1162_marker" >/dev/null 2>&1
[ ! -e /tmp/varek_v1162_marker ] && [ "$(wc -l < "$RF")" = "$before" ] \
  && pass "a requested command is not run, and malformed lines are dropped" || flunk "forced command"
su "$U" -s /bin/sh -c ": > $RF" 2>/dev/null
[ "$(wc -l < "$RF")" = "$before" ] && pass "the account cannot truncate the anchor (append-only)" || flunk "append-only"
"${SSH[@]}" -i "$OUT/fwkey" -N -L 127.0.0.1:2299:127.0.0.1:$PORT "$U@127.0.0.1" >/dev/null 2>&1 & fp=$!
sleep 1.5
banner="$(timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2299 && head -c 4 <&3' 2>/dev/null)"
kill "$fp" 2>/dev/null; wait "$fp" 2>/dev/null
[ "$banner" != "SSH-" ] && pass "port forwarding is refused (no connection through the tunnel)" || flunk "port forwarding"

echo "== 3. nothing is lost"
stop_sshd
warden_run "$LOGD/v2.log" --checkpoint-every 2 -- /bin/cat /etc/ld.so.cache
R2="$(runid "$LOGD/v2.log")"; n2=$(nsig "$LOGD/v2.log")
sleep 2
[ "$(count "$RF" "$R2")" = 0 ] && [ "$(count "$SP/anchor.spool" "$R2")" = "$n2" ] \
  && pass "anchor host down: the run's $n2 records wait in the spool" || flunk "outage buffering"
stop_fwd; start_sshd; start_fwd
wait_run "$RF" "$R2" "$n2" && pass "it returns (and the forwarder restarts): they are delivered" || flunk "delivery after outage"
o="$("${A[@]}" --pubkey "$OUT/log.key.pub" --anchor "$RF" "$LOGD/v2.log" 2>&1)"
grep -q "integrity: signed, anchored" <<<"$o" && pass "the run made during the outage audits signed, anchored" || flunk "audit after outage"
o="$("${A[@]}" --pubkey "$OUT/log.key.pub" --anchor "$RF" --max-anchor-delay 0.001 "$LOGD/v2.log" 2>&1)"
grep -q "reached the anchor more than" <<<"$o" && pass "--max-anchor-delay flags records that arrived late" || flunk "late records"
# Forwarder restarted in the middle of a run: the Warden holds the FIFO open.
warden_run "$LOGD/v3.log" --checkpoint-every 1 -- "$PROBE" -s 3000 /etc/ld.so.cache /etc/ld.so.cache &
wp=$!
sleep 1; stop_fwd; sleep 3; start_fwd      # the probe's second open (at ~3 s) finds no forwarder
wait "$wp"
R3="$(runid "$LOGD/v3.log")"; n3=$(nsig "$LOGD/v3.log")
wait_run "$RF" "$R3" "$n3"
o="$("${A[@]}" --pubkey "$OUT/log.key.pub" --anchor "$RF" "$LOGD/v3.log" 2>&1)"
! grep -q anchor_error "$LOGD/v3.log" && grep -q "integrity: signed, anchored" <<<"$o" \
  && pass "the forwarder restarted mid-run: no anchor error, the run audits signed, anchored" \
  || { flunk "forwarder restart mid-run"; grep -c anchor_error "$LOGD/v3.log"; echo "$o" | tail -3; }
# The receiver cannot write (its file moved away): the forwarder keeps retrying.
chattr -a "$RF"; mv "$RF" "$RD/host1.moved"
warden_run "$LOGD/v4.log" -- /bin/true
R4="$(runid "$LOGD/v4.log")"; n4=$(nsig "$LOGD/v4.log")
sleep 2
grep -q "failed" "$OUT/fw.log" && [ ! -e "$RF" ] && pass "a receiver that cannot write makes the forwarder retry" || flunk "helper failure"
mv "$RD/host1.moved" "$RF"; chattr +a "$RF"
wait_run "$RF" "$R4" "$n4" && pass "... and the lines arrive once it can" || flunk "delivery after helper failure"
# A full spool disk: lines are held in memory, then written and sent.
stop_fwd
MNT=/var/lib/varek-v1162/tiny
mkdir -p "$MNT" && chmod 700 "$MNT"
if mount -t tmpfs -o size=16k,mode=0700 tmpfs "$MNT" 2>/dev/null; then
    python3 "$FWD" --fifo "$FIFO" --spool "$MNT/spool" --ssh "$U@127.0.0.1" --ssh-port "$PORT" \
        --ssh-key "$OUT/fwkey" --known-hosts "$OUT/kh" --interval 0.5 >> "$OUT/fw3.log" 2>&1 &
    FWPID=$!; sleep 0.5
    head -c 16384 /dev/zero > "$MNT/filler" 2>/dev/null
    warden_run "$LOGD/v5.log" -- /bin/true
    R5="$(runid "$LOGD/v5.log")"; n5=$(nsig "$LOGD/v5.log")
    sleep 1.5
    alive=0; kill -0 "$FWPID" 2>/dev/null && alive=1
    rm -f "$MNT/filler"
    if [ "$alive" = 1 ] && grep -q "held in memory" "$OUT/fw3.log" && wait_run "$RF" "$R5" "$n5"; then
        pass "a full spool disk: the forwarder keeps running, holds the lines, and sends them once there is room"
    else flunk "full spool disk (alive=$alive)"; tail -3 "$OUT/fw3.log"; fi
    stop_fwd; umount "$MNT"; MNT=""
else
    printf '  %-6s %s\n' SKIP "full spool disk (cannot mount a tmpfs here)"
fi
start_fwd

echo "== 4. extra anchor lines neither fool nor block the audit"
cp "$RF" "$OUT/extra.log"
line="$(grep "\"run\":\"$R1\"" "$RF" | grep '"event":"run_end"' | head -1)"
{ printf '%s\n' "${line/\"records\":/\"records\":9}"         # conflicting, later, still validly signed
  printf '%s\n' "$(sed -E 's/"sig":"[0-9a-f]{128}"/"sig":"'"$(printf '0%.0s' $(seq 1 128))"'"/' <<<"$line")"
  echo 'this is not JSON'
} >> "$OUT/extra.log"
o="$("${A[@]}" --pubkey "$OUT/log.key.pub" --anchor "$OUT/extra.log" "$LOGD/v1.log" 2>&1)"
grep -q "integrity: signed, anchored" <<<"$o" && grep -q "PASS" <<<"$o" && grep -q "no valid signature" <<<"$o" \
  && grep -q "first one received was used" <<<"$o" && grep -q "not JSON" <<<"$o" \
  && pass "unsigned, conflicting and malformed extra lines are noted and ignored" || { flunk "extra lines"; echo "$o" | tail -6; }
o="$(python3 "$HERE/tools/varek_audit.py" --list-runs --anchor "$RF" 2>&1)"
for r in "$R1" "$R2" "$R3" "$R4"; do grep -q "$r" <<<"$o" || { flunk "--list-runs misses $r"; break; }; done
grep -q "run(s) in" <<<"$o" && pass "--list-runs lists every run in the anchor" || flunk "--list-runs"

echo "== 5. preflight"
o="$("$PRE" "$POL" --log "$LOGD/p.log" --sign-key "$OUT/log.key" --anchor "$FIFO" --spool "$SP" --run 2>&1)"
grep -q "has a reader" <<<"$o" && grep -q "delivered the trial run's records off-host" <<<"$o" \
  && grep -q "integrity: signed, anchored" <<<"$o" && grep -q "preflight: PASS (0 warning" <<<"$o" \
  && pass "forwarder running: trial run delivered off-host and audited; no warnings" || { flunk "preflight with forwarder"; echo "$o" | grep -E "FAIL|WARN"; }
stop_sshd
o="$("$PRE" "$POL" --log "$LOGD/p.log" --sign-key "$OUT/log.key" --anchor "$FIFO" --spool "$SP" --run 2>&1)"
grep -q "has not delivered" <<<"$o" && grep -q "preflight: FAIL" <<<"$o" && pass "anchor host down: the trial run's delivery fails" || flunk "preflight delivery failure"
start_sshd
stop_fwd
o="$("$PRE" "$POL" --anchor "$FIFO" 2>&1)"
grep -q "has no reader" <<<"$o" && grep -q "preflight: FAIL" <<<"$o" && pass "a FIFO anchor with no reader fails" || flunk "FIFO without reader"
o="$("$PRE" "$POL" --log "$LOGD/p.log" --sign-key "$OUT/log.key" --anchor "$LOGD/local.anchor" 2>&1)"
grep -q "WARN  the anchor is a file on this host" <<<"$o" && grep -q "WARN  the signing key and the verdict streams are both on this host" <<<"$o" \
  && grep -q "preflight: PASS" <<<"$o" && pass "a local-file anchor and an on-host key are warnings" || flunk "local anchor warnings"
{ cat "$POL"; echo "allow path /var/lib/varek-v1162/"; } > "$OUT/leaky.txt"
o="$("$PRE" "$OUT/leaky.txt" --spool "$SP" 2>&1)"
grep -q "forwarder spool: the policy lets the agent open" <<<"$o" && pass "a spool the agent could open fails" || flunk "spool check"

echo "== 6. --exec"
EX="$OUT/exec_sink"
python3 "$FWD" --fifo "$OUT/exec.fifo" --spool "$OUT/exec_spool" --exec "cat >> $EX" --interval 0.3 >> "$OUT/fw2.log" 2>&1 &
FWPID=$!
for _ in $(seq 1 20); do [ -p "$OUT/exec.fifo" ] && break; sleep 0.2; done
timeout 30 "$WARDEN" "$POL" --sign-key "$OUT/log.key" --anchor "$OUT/exec.fifo" -- /bin/true > /dev/null 2> "$LOGD/v6.log"
R6="$(runid "$LOGD/v6.log")"
wait_run "$EX" "$R6" 2
o="$("${A[@]}" --pubkey "$OUT/log.key.pub" --anchor "$EX" "$LOGD/v6.log" 2>&1)"
grep -q "integrity: signed, anchored" <<<"$o" && pass "--exec delivers to a command (here: a file); the run audits anchored" \
  || { flunk "--exec"; echo "$o" | tail -3; }

echo
if [ "$fail" -eq 0 ]; then echo "test_v1162: PASS"; else echo "test_v1162: FAIL"; fi
exit "$fail"
