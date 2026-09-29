#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1162.sh — regression test for VAREK v1.16.2: the off-host anchor.
#
# Sets up, on this machine, what a deployment sets up on two:
#   - an anchor receiver (tools/varek_anchor_receiver.sh) behind a private sshd
#     on 127.0.0.1:2222, with its own test account and directory;
#   - the forwarder (tools/varek_anchor_forward.py) reading the Warden's anchor
#     FIFO and sending over SSH with a dedicated key and a pinned host key.
# Then:
#   1. a signed run is anchored off-host and audits "signed, anchored" against
#      the receiver's copy;
#   2. the receiver's account can only append well-formed anchor lines: its
#      forced command ignores any requested command, drops malformed lines,
#      and the file is append-only (chattr +a);
#   3. an outage of the anchor host loses nothing: lines wait in the spool and
#      are delivered when it returns, and a restarted forwarder resumes;
#   4. preflight: a FIFO anchor without a reader fails, with the forwarder
#      running it passes and audits the trial run against the spool, and a
#      local-file anchor or a key with no off-host anchor is a warning;
#   5. --exec delivers to any command.
# Skipped (not failed) if sshd is not installed.
#
# Usage: ./test_v1162.sh <warden> <varek_keygen>
set -u

WARDEN="${1:?usage: test_v1162.sh <warden> <varek_keygen>}"
KEYGEN="${2:?}"
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

U=varek-anchor-v1162 RD=/srv/varek-anchor-v1162 FIFO=/run/varek-v1162/anchor.fifo SP=/var/lib/varek-v1162/spool
OUT="$(mktemp -d)" PORT=2222
FWPID="" SSHD_PID=""
cleanup() {
    [ -n "$FWPID" ] && kill "$FWPID" 2>/dev/null
    [ -f "$OUT/sshd.pid" ] && kill "$(cat "$OUT/sshd.pid")" 2>/dev/null
    chattr -a "$RD"/*.anchor.log 2>/dev/null
    rm -rf "$RD" /run/varek-v1162 /var/lib/varek-v1162 /var/log/varek-v1162 "$OUT"
    userdel "$U" 2>/dev/null
}
trap cleanup EXIT
mkdir -p /var/log/varek-v1162 /etc/varek-v1162
"$KEYGEN" "$OUT/log.key" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$OUT/fwkey" -C varek-forwarder
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
bash "$RCV" --name host1 --pubkey "$(cat "$OUT/fwkey.pub")" --user "$U" --dir "$RD" > "$OUT/rcv.out"
RF="$RD/host1.anchor.log"
grep -q "append-only (chattr +a)" "$OUT/rcv.out" && pass "receiver set up: forced-command account, append-only file" \
  || { flunk "receiver setup"; cat "$OUT/rcv.out"; }
ssh-keyscan -p "$PORT" -t ed25519 127.0.0.1 2>/dev/null > "$OUT/kh"
start_fwd() {
    python3 "$FWD" --fifo "$FIFO" --spool "$SP" --ssh "$U@127.0.0.1" --ssh-port "$PORT" \
        --ssh-key "$OUT/fwkey" --known-hosts "$OUT/kh" --interval 0.5 >> "$OUT/fw.log" 2>&1 &
    FWPID=$!
    for _ in $(seq 1 20); do [ -p "$FIFO" ] && break; sleep 0.2; done
}
wait_lines() {  # file, count
    for _ in $(seq 1 40); do [ "$(wc -l < "$1" 2>/dev/null || echo 0)" -ge "$2" ] && return 0; sleep 0.5; done; return 1
}

echo "== 1. a signed run, anchored off-host"
start_fwd
timeout 30 "$WARDEN" "$POL" --sign-key "$OUT/log.key" --anchor "$FIFO" --checkpoint-every 2 \
    -- /bin/cat /etc/ld.so.cache > /dev/null 2> /var/log/varek-v1162/v1.log
n1=$(grep -c '"sig":' /var/log/varek-v1162/v1.log)
wait_lines "$RF" "$n1" && pass "all $n1 signed records reached the anchor host" || flunk "records on the anchor host ($(wc -l < "$RF") of $n1)"
o="$("${A[@]}" --pubkey "$OUT/log.key.pub" --anchor "$RF" /var/log/varek-v1162/v1.log 2>&1)"
grep -q "integrity: signed, anchored" <<<"$o" && grep -q PASS <<<"$o" \
  && pass "audit against the receiver's copy: signed, anchored" || { flunk "audit vs receiver"; echo "$o" | tail -3; }

echo "== 2. the receiver's account can only append anchor lines"
before=$(wc -l < "$RF")
printf '%s\n' '{"run":"not an anchor line"}' 'hello' | ssh -o BatchMode=yes -i "$OUT/fwkey" -o IdentitiesOnly=yes \
    -o UserKnownHostsFile="$OUT/kh" -p "$PORT" "$U@127.0.0.1" "rm -f $RF; touch $RD/pwned" >/dev/null 2>&1
[ -f "$RF" ] && [ ! -e "$RD/pwned" ] && [ "$(wc -l < "$RF")" = "$before" ] \
  && pass "a requested command is ignored, and malformed lines are dropped" || flunk "forced command"
su "$U" -s /bin/sh -c ": > $RF" 2>/dev/null
[ "$(wc -l < "$RF")" = "$before" ] && pass "the account cannot truncate the anchor (append-only)" || flunk "append-only"
ssh -o BatchMode=yes -i "$OUT/fwkey" -o UserKnownHostsFile="$OUT/kh" -p "$PORT" -N -o ExitOnForwardFailure=yes \
    -L 127.0.0.1:0:127.0.0.1:22 "$U@127.0.0.1" >/dev/null 2>&1 & fp=$!
sleep 1.5; if kill -0 "$fp" 2>/dev/null; then kill "$fp"; flunk "port forwarding is refused"; else pass "port forwarding is refused"; fi

echo "== 3. an outage of the anchor host"
stop_sshd
timeout 30 "$WARDEN" "$POL" --sign-key "$OUT/log.key" --anchor "$FIFO" --checkpoint-every 2 \
    -- /bin/cat /etc/ld.so.cache > /dev/null 2> /var/log/varek-v1162/v2.log
n2=$(grep -c '"sig":' /var/log/varek-v1162/v2.log)
sleep 2
grep -q "failed" "$OUT/fw.log" && [ "$(wc -l < "$RF")" = "$before" ] && [ "$(wc -l < "$SP/anchor.spool")" -ge $((n1 + n2)) ] \
  && pass "while it is down, $n2 records wait in the spool" || flunk "outage buffering"
kill "$FWPID"; wait "$FWPID" 2>/dev/null; FWPID=""
start_sshd
start_fwd
wait_lines "$RF" $((before + n2)) && pass "after it returns (and the forwarder restarts), they are delivered" \
  || flunk "delivery after the outage ($(wc -l < "$RF") of $((before + n2)))"
o="$("${A[@]}" --pubkey "$OUT/log.key.pub" --anchor "$RF" /var/log/varek-v1162/v2.log 2>&1)"
grep -q "integrity: signed, anchored" <<<"$o" && pass "the run made during the outage audits signed, anchored" \
  || { flunk "audit after outage"; echo "$o" | tail -3; }

echo "== 4. preflight"
o="$("$PRE" "$POL" --log /var/log/varek-v1162/p.log --sign-key "$OUT/log.key" --anchor "$FIFO" --spool "$SP" --run 2>&1)"
grep -q "has a reader" <<<"$o" && grep -q "integrity: signed, anchored" <<<"$o" && grep -q "preflight: PASS (0 warning" <<<"$o" \
  && pass "with the forwarder running: PASS, no warnings, trial run audited against the spool" || { flunk "preflight with forwarder"; echo "$o" | grep -E "FAIL|WARN|audit"; }
kill "$FWPID"; wait "$FWPID" 2>/dev/null; FWPID=""
o="$("$PRE" "$POL" --anchor "$FIFO" 2>&1)"
grep -q "has no reader" <<<"$o" && grep -q "preflight: FAIL" <<<"$o" && pass "a FIFO anchor with no reader fails" || flunk "FIFO without reader"
o="$("$PRE" "$POL" --log /var/log/varek-v1162/p.log --sign-key "$OUT/log.key" --anchor /var/log/varek-v1162/local.anchor 2>&1)"
grep -q "WARN  the anchor is a file on this host" <<<"$o" && grep -q "WARN  the signing key and the verdict streams are both on this host" <<<"$o" \
  && grep -q "preflight: PASS" <<<"$o" && pass "a local-file anchor and an on-host key are warnings" || flunk "local anchor warnings"
{ cat "$POL"; echo "allow path /var/lib/varek-v1162/"; } > "$OUT/leaky.txt"
o="$("$PRE" "$OUT/leaky.txt" --spool "$SP" 2>&1)"
grep -q "forwarder spool: the policy lets the agent open" <<<"$o" && pass "a spool the agent could open fails" || flunk "spool check"

echo "== 5. --exec"
EX="$OUT/exec_sink"
python3 "$FWD" --fifo "$OUT/exec.fifo" --spool "$OUT/exec_spool" --exec "cat >> $EX" --interval 0.3 >> "$OUT/fw2.log" 2>&1 &
FWPID=$!
for _ in $(seq 1 20); do [ -p "$OUT/exec.fifo" ] && break; sleep 0.2; done
timeout 30 "$WARDEN" "$POL" --sign-key "$OUT/log.key" --anchor "$OUT/exec.fifo" \
    -- /bin/true > /dev/null 2> /var/log/varek-v1162/v3.log
wait_lines "$EX" 2
o="$("${A[@]}" --pubkey "$OUT/log.key.pub" --anchor "$EX" /var/log/varek-v1162/v3.log 2>&1)"
grep -q "integrity: signed, anchored" <<<"$o" && pass "--exec delivers to a command (here: a file); the run audits anchored" \
  || { flunk "--exec"; echo "$o" | tail -3; }

echo
if [ "$fail" -eq 0 ]; then echo "test_v1162: PASS"; else echo "test_v1162: FAIL"; fi
exit "$fail"
