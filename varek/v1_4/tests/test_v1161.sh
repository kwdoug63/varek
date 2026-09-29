#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1161.sh — regression test for VAREK v1.16.1: deployment preflight.
#
#   1. `vdp_cert_check <policy> openable` agrees with the live Warden: for every
#      shipped policy and several verdict-stream locations, the Warden refuses
#      to start exactly when the tool says the agent could open the stream.
#   2. tools/varek_preflight.sh passes a good deployment (signed, anchored,
#      trial run audited) and fails the ones the Warden would refuse: a stream
#      in the agent's scratch space, a key that is group-readable, has a second
#      name or sits under an allowed path, an anchor the agent could open.
#   3. The Makefile's dependency check names the packages to install.
#
# Usage: ./test_v1161.sh <warden> <vdp_cert_check>
set -u

WARDEN="${1:?usage: test_v1161.sh <warden> <vdp_cert_check>}"
CERT="${2:?}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PRE="$HERE/tools/varek_preflight.sh"

fail=0
pass() { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }

D=/tmp/varek_v1161
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT" "$D" /tmp/varek_allowed_v1161' EXIT
rm -rf "$D"; mkdir -p "$D/log" "$D/keys" /tmp/varek /tmp/varek_allowed_v1161

echo "== 1. the openable check agrees with the Warden"
POLS=("$HERE/policy.txt" "$HERE/conformance_policy.txt" "$HERE"/policies/*.txt)
LOCS=("$D/log/verdicts.log" /tmp/varek/v1161.log /tmp/varek_allowed_v1161/verdicts.log)
agree=0 total=0
for p in "${POLS[@]}"; do
    for l in "${LOCS[@]}"; do
        rm -f "$l"
        predicted="$(printf '%s\n' "$l" | "$CERT" "$p" openable | cut -d' ' -f1)"
        timeout 20 "$WARDEN" "$p" -- /bin/true 2> "$l" >/dev/null
        if grep -q "would let the agent open the verdict stream" "$l"; then got=openable; else got=closed; fi
        total=$((total + 1))
        if [ "$predicted" = "$got" ]; then agree=$((agree + 1))
        else echo "    $(basename "$p") $l: tool says $predicted, the Warden $got"; fi
        rm -f "$l"
    done
done
[ "$agree" = "$total" ] && pass "tool and Warden agree on $total policy/location pairs" || flunk "agreement $agree/$total"

echo "== 2. preflight"
"$HERE/tools/varek_keygen" "$D/keys/k" >/dev/null
FIN="$HERE/policies/finance.policy.txt"
o="$("$PRE" "$FIN" --log "$D/log/verdicts.log" --sign-key "$D/keys/k" --anchor "$D/log/anchor" --run 2>&1)"
grep -q "preflight: PASS" <<<"$o" && grep -q "integrity: signed, anchored" <<<"$o" \
  && pass "a good deployment passes, with a signed and anchored trial run" || { flunk "good deployment"; echo "$o" | tail -8; }
[ -z "$(ls -A "$D/log" | grep preflight)" ] && pass "the trial run's stream is removed afterwards" || flunk "trial stream left behind"
check_fail() {  # name, expected text, args...
    local name="$1" msg="$2"; shift 2
    local o; o="$("$PRE" "$@" 2>&1)"; local rc=$?
    if [ "$rc" -ne 0 ] && grep -q -- "$msg" <<<"$o"; then pass "$name"; else flunk "$name"; echo "$o" | grep -E "FAIL|preflight" | head -3; fi
}
check_fail "a stream in the agent's scratch space fails" "the policy lets the agent open it" "$FIN" --log /tmp/varek/v1161.log
cp "$D/keys/k" "$D/keys/open"; chmod 644 "$D/keys/open"
check_fail "a group-readable key fails" "chmod 600" "$FIN" --sign-key "$D/keys/open"
ln "$D/keys/k" "$D/keys/k2"
check_fail "a key with a second name fails" "has 2 names" "$FIN" --sign-key "$D/keys/k"
rm -f "$D/keys/k2"
{ cat "$FIN"; echo "allow path $D/keys/"; } > "$OUT/leaky.txt"
check_fail "a key the agent could open fails" "the policy lets the agent open" "$OUT/leaky.txt" --sign-key "$D/keys/k"
check_fail "an anchor the agent could open fails" "anchor: the policy lets the agent open" "$FIN" --anchor /tmp/varek/anchor
check_fail "a missing key fails" "not found" "$FIN" --sign-key "$D/keys/none"

echo "== 2b. cases the review found (the Warden refuses; the preflight must fail)"
mkdir -p "$D/r" /tmp/varek
ln -sfn /tmp/varek/v1161_dl.log "$D/r/dangling.log"
check_fail "a log that is a dangling symlink into scratch space fails" "the policy lets the agent open it" "$FIN" --log "$D/r/dangling.log"
timeout 20 "$WARDEN" "$FIN" -- /bin/true 2> "$D/r/dangling.log" >/dev/null
grep -q "would let the agent open the verdict stream" /tmp/varek/v1161_dl.log && pass "... and the Warden refuses it too" || flunk "Warden on a dangling-symlink log"
rm -f /tmp/varek/v1161_dl.log
: > "$D/r/t1"; ln "$D/r/t1" "$D/r/t2"; ln -sfn "$D/r/t1" "$D/r/viasym.log"
check_fail "a log reached through a symlink, with two names, fails" "has 2 names" "$FIN" --log "$D/r/viasym.log"
ln -sfn /tmp/varek "$D/r/tlink"
check_fail "a new log under a symlinked ancestor in scratch space fails" "the policy lets the agent open it" "$FIN" --log "$D/r/tlink/v1161sub/v.log"
check_fail "a log whose directory does not exist fails" "does not exist" "$FIN" --log "$D/r/nodir/v.log"
: > "$D/r/safe_anchor"; ln -sfn "$D/r/safe_anchor" "$D/r/anchor_link"
check_fail "an anchor that is a symlink fails" "anchor .* is a symlink" "$FIN" --anchor "$D/r/anchor_link"
mkdir -p "$D/r/anchor_dir"
check_fail "an anchor that is a directory fails" "not a regular file, FIFO or character device" "$FIN" --anchor "$D/r/anchor_dir"
check_fail "an anchor whose directory does not exist fails" "anchor's directory" "$FIN" --anchor "$D/r/nodir/anchor"
: > "$D/r/a1"; ln "$D/r/a1" "$D/r/a2"
check_fail "an anchor with two names fails" "has 2 names" "$FIN" --anchor "$D/r/a1"
hex="$(head -c 64 "$D/keys/k")"
for v in 'nn' 'lead' 'split'; do
    case "$v" in
        nn)    printf '%s\n\n' "$hex" ;;
        lead)  printf '\n%s' "$hex" ;;
        split) printf '%s\n%s' "${hex:0:32}" "${hex:32}" ;;
    esac > "$D/keys/bad_$v"; chmod 600 "$D/keys/bad_$v"
    check_fail "a malformed key ($v) fails" "not exactly 64 hex" "$FIN" --sign-key "$D/keys/bad_$v"
done
mkfifo "$D/r/ff_unused" 2>/dev/null
mkdir -p '/tmp/varek_v1161_$(touch /tmp/varek_v1161_PWNED)'
chmod 755 '/tmp/varek_v1161_$(touch /tmp/varek_v1161_PWNED)'
rm -f /tmp/varek_v1161_PWNED
o="$("$PRE" "$FIN" --log '/tmp/varek_v1161_$(touch /tmp/varek_v1161_PWNED)/v.log' --run 2>&1)"
[ ! -e /tmp/varek_v1161_PWNED ] && grep -q "preflight: PASS" <<<"$o" \
  && pass "a log directory named like a command is used as a name, never run" || { flunk "command in the log path"; echo "$o" | tail -4; }
rm -rf '/tmp/varek_v1161_$(touch /tmp/varek_v1161_PWNED)' /tmp/varek_v1161_PWNED
mkdir -p "$D/shared"; chown nobody "$D/shared" 2>/dev/null || chown 65534 "$D/shared"
check_fail "--run refuses a log directory another user owns" "must belong to root" "$FIN" --log "$D/shared/v.log" --run
mkfifo /tmp/varek/v1161_fifo
o="$("$PRE" "$FIN" --log /tmp/varek/v1161_fifo 2>&1)"
grep -q "WARN  verdict stream /tmp/varek/v1161_fifo is not a regular file" <<<"$o" && grep -q "preflight: PASS" <<<"$o" \
  && pass "a FIFO log in an allowed path is a warning (the Warden refuses only regular files)" || flunk "FIFO log"
rm -f /tmp/varek/v1161_fifo

echo "== 3. build dependency check"
o="$(make -s -C "$HERE" deps-check CC=false 2>&1)"
grep -q "libsodium-dev" <<<"$o" && grep -q "libsodium-devel" <<<"$o" \
  && pass "make names the packages to install when the headers are missing" || flunk "deps-check message"
make -s -C "$HERE" deps-check >/dev/null 2>&1 && pass "make deps-check passes on this host" || flunk "deps-check on this host"

echo
if [ "$fail" -eq 0 ]; then echo "test_v1161: PASS"; else echo "test_v1161: FAIL"; fi
exit "$fail"
