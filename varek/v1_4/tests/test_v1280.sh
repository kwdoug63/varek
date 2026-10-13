#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# test_v1280.sh — VAREK v1.28.0: credential release, the agent holds only
# placeholders (docs/security/v1.28-credential-release.md). The parts built
# so far:
#   1. the grammar: `credential NAME from STORE:REF` and an allow request
#      rule's `credential=NAME header=HEADER[:SCHEME]`, after `require warden
#      1.28`, read the same way by the decision procedure (vdp_check) and the
#      certificate checker (vdp_cert_check), each form and each refusal; lint
#      notes a credential no rule carries; the Warden reports 1.28.0, compares
#      the two readings at load, and (until the swap is built) refuses to
#      start a policy that names a credential.
#
#   test_v1280.sh VDP_CHECK VDP_CERT_CHECK [WARDEN]
set -u

VDP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
CERT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
WARDEN="${3:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
trap '[ -n "${KEEP:-}" ] && echo "kept $OUT" || rm -rf "$OUT"' EXIT

echo "== 1. the grammar =="
# accepted <label> <policy>: both parsers load it and print the same credentials
accepted() {
    printf '%b' "$2" > "$OUT/p.txt"
    if ! "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1; then
        flunk "accepted: $1 ($("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null | head -1))"
    elif ! "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then
        flunk "accepted: $1 (the checker refused it: $("$CERT" "$OUT/p.txt" digest 2>&1 | head -1))"
    elif [ "$("$VDP" "$OUT/p.txt" credentials)" != "$("$CERT" "$OUT/p.txt" credentials)" ]; then
        flunk "accepted: $1 (the parsers read the credentials differently)"
    else pass "accepted: $1"; fi
}
# refused <label> <policy> <words of the procedure's reason>: both parsers refuse it
refused() {
    printf '%b' "$2" > "$OUT/p.txt"
    local e
    e="$("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null)"
    if "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1; then flunk "refused: $1 (the procedure loaded it)"
    elif "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then flunk "refused: $1 (the checker loaded it)"
    elif ! printf '%s' "$e" | grep -qF -- "$3"; then flunk "refused: $1 (message: $e)"
    else pass "refused: $1"; fi
}
R='require warden 1.28\nproxy inspect\nallow host api.example.com:443\n'
C='credential k from file:/etc/varek/creds/k\n'
Q() { printf '%s%sallow request GET https://api.example.com/v1/x %s\n' "$R" "$C" "$1"; }   # one rule, its options

accepted "a credential of each store"   "${R}credential a from file:/etc/varek/creds/a\ncredential b from vault:secret/data/agents/b#token\ncredential c from aws-sm:arn:aws:secretsmanager:us-east-1:111122223333:secret:c-AbCdEf\n"
accepted "a rule carrying one, a scheme" "$(Q 'credential=k header=Authorization:Bearer')"
accepted "the whole header value"       "$(Q 'credential=k header=X-Api-Key')"
accepted "header first, with max_body"  "$(Q 'header=authorization:token max_body=1k credential=k')"
accepted "two rules, one credential"    "${R}${C}allow request GET https://api.example.com/a credential=k header=X-K\nallow request POST https://api.example.com/b credential=k header=Authorization:Bearer\n"
accepted "32 credentials"               "${R}$(for i in $(seq 1 32); do printf 'credential c%d from file:/c/%d\\n' "$i" "$i"; done)"
accepted "a name of 32 bytes"           "${R}credential a2345678901234567890123456789_12 from file:/x\n"
printf '%b' "$(Q 'credential=k header=Authorization:Bearer')" > "$OUT/p.txt"
check "the two parsers print the credential and the rule" \
    sh -c "'$VDP' '$OUT/p.txt' credentials | grep -qx 'credential k file /etc/varek/creds/k' && '$CERT' '$OUT/p.txt' credentials | grep -qx 'rule 5 k Authorization Bearer'"

refused "a credential before 1.28"      'require warden 1.27\ncredential k from file:/x\n'                   "needs \`require warden 1.28\`"
refused "credential= before 1.28"       'require warden 1.27\nproxy inspect\nallow host api.example.com:443\nallow request GET https://api.example.com/x credential=k header=X\n' "needs \`require warden 1.28\`"
refused "an unknown credential"         "$(Q 'credential=nope header=X')"                                   "unknown credential 'nope'"
refused "a credential named after use"  "${R}allow request GET https://api.example.com/x credential=k header=X\n${C}" "unknown credential 'k'"
refused "credential= on a deny rule"    "${R}${C}deny request GET https://api.example.com/x credential=k header=X\n" "only to allow request rules"
refused "credential= without header="   "$(Q 'credential=k')"                                               "go together"
refused "header= without credential="   "$(Q 'header=X-K')"                                                 "go together"
refused "credential= twice"             "$(Q 'credential=k credential=k header=X')"                         "given twice"
refused "header= twice"                 "$(Q 'credential=k header=X header=Y')"                             "given twice"
refused "header=Host"                   "$(Q 'credential=k header=Host')"                                   "frames the request"
refused "header=content-length:x"       "$(Q 'credential=k header=content-length:x')"                       "frames the request"
refused "header=Proxy-Authorization"    "$(Q 'credential=k header=Proxy-Authorization')"                    "frames the request"
refused "an empty scheme"               "$(Q 'credential=k header=X:')"                                     "HTTP token"
refused "a scheme with a colon"         "$(Q 'credential=k header=X:A:B')"                                  "HTTP token"
refused "a header of 65 bytes"          "$(Q "credential=k header=$(printf 'H%.0s' $(seq 1 65))")"          "HTTP token"
refused "a scheme of 33 bytes"          "$(Q "credential=k header=X:$(printf 's%.0s' $(seq 1 33))")"        "HTTP token"
refused "a name with a capital"         "${R}credential Key from file:/x\n"                                 "a credential's name"
refused "a name of 33 bytes"            "${R}credential a23456789012345678901234567890123 from file:/x\n" "a credential's name"
refused "a name given twice"            "${R}${C}credential k from file:/y\n"                               "named twice"
refused "33 credentials"                "${R}$(for i in $(seq 1 33); do printf 'credential c%d from file:/c/%d\\n' "$i" "$i"; done)" "more than 32"
refused "no from"                       "${R}credential k at file:/x\n"                                     "need: credential"
refused "an unknown store"              "${R}credential k from env:K\n"                                     "file:, vault: or aws-sm:"
refused "a relative file path"          "${R}credential k from file:k\n"                                    "absolute path"
refused "a file path with .."           "${R}credential k from file:/a/../k\n"                              "absolute path"
refused "a file path ending in /"       "${R}credential k from file:/a/\n"                                  "absolute path"
refused "a file path with //"           "${R}credential k from file:/a//k\n"                                "absolute path"
refused "a vault reference without #"   "${R}credential k from vault:secret/k\n"                            "PATH#FIELD"
refused "a vault path from /"           "${R}credential k from vault:/secret/k#f\n"                         "PATH#FIELD"
refused "a vault field with !"          "${R}credential k from vault:secret/k#f!\n"                         "a vault field"
refused "an aws-sm reference not an ARN" "${R}credential k from aws-sm:my-secret\n"                         "Secrets Manager ARN"
refused "a reference with a high byte"  "${R}credential k from file:/k\xe9\n"                               "printable ASCII"
refused "require warden 1.29"           'require warden 1.29\n'                                             "this is 1.28"

printf 'require warden 1.28\nproxy inspect\nallow host api.example.com:443\n%bcredential unused from file:/u\nallow request GET https://api.example.com/x credential=k header=X\n' "$C" > "$OUT/l.txt"
check "lint notes a credential no rule carries" sh -c "'$VDP' '$OUT/l.txt' lint | grep -q ':5: note: credential unused is named, but no request rule carries it'"
check "lint is silent on a credential a rule carries" sh -c "! '$VDP' '$OUT/l.txt' lint | grep -q 'credential k is named'"

if [ -z "$WARDEN" ]; then
    skip "the Warden's checks (no warden binary given)"
else
    check "the Warden reports 1.28.0" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | grep -q 'VAREK Warden  1.28.0'"
    printf '%b' "$(Q 'credential=k header=Authorization:Bearer')" > "$OUT/w.txt"
    "$WARDEN" "$OUT/w.txt" --check-startup > "$OUT/w.out" 2>&1; echo $? > "$OUT/w.rc"
    check "the Warden refuses, for now, a policy that names a credential" \
        sh -c "! grep -qx 0 '$OUT/w.rc' && grep -q 'credential release is not built in this Warden yet' '$OUT/w.out'"
    printf 'require warden 1.28\nproxy inspect\nallow host api.example.com:443\nallow request GET https://api.example.com/x\n' > "$OUT/w2.txt"
    check "the Warden starts a 1.28 policy with no credential" "$WARDEN" "$OUT/w2.txt" --check-startup
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1280: PASS ($skips skipped)"; exit 0; fi
echo "test_v1280: FAIL"; exit 1
