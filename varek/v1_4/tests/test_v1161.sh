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
check_fail "a missing key fails" "does not exist" "$FIN" --sign-key "$D/keys/none"

echo "== 3. build dependency check"
o="$(make -s -C "$HERE" deps-check CC=false 2>&1)"
grep -q "libsodium-dev" <<<"$o" && grep -q "libsodium-devel" <<<"$o" \
  && pass "make names the packages to install when the headers are missing" || flunk "deps-check message"
make -s -C "$HERE" deps-check >/dev/null 2>&1 && pass "make deps-check passes on this host" || flunk "deps-check on this host"

echo
if [ "$fail" -eq 0 ]; then echo "test_v1161: PASS"; else echo "test_v1161: FAIL"; fi
exit "$fail"
