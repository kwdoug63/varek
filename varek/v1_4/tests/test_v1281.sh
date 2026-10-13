#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# test_v1281.sh — VAREK v1.28.1: the on-behalf-of chain, who each decision
# was for (docs/security/v1.28.1-delegation-chain.md). The parts built so
# far:
#   1. the grammar: `trust issuer URL audience AUD [jwks URL]`, `trust spiffe
#      DOMAIN bundle PATH`, `require on-behalf-of` and an allow exec rule's
#      `subagent=NAME`, after `require warden 1.28`, read the same way by the
#      decision procedure (vdp_check) and the certificate checker
#      (vdp_cert_check), each form and each refusal; lint; the Warden
#      reports 1.28.1, compares the two readings at load, and refuses what
#      later steps build.
#
#   test_v1281.sh VDP_CHECK VDP_CERT_CHECK [WARDEN]
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
# accepted <label> <policy>: both parsers load it and print the same identities
accepted() {
    printf '%b' "$2" > "$OUT/p.txt"
    if ! "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1; then
        flunk "accepted: $1 ($("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null | head -1))"
    elif ! "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then
        flunk "accepted: $1 (the checker refused it: $("$CERT" "$OUT/p.txt" digest 2>&1 | head -1))"
    elif [ "$("$VDP" "$OUT/p.txt" identity)" != "$("$CERT" "$OUT/p.txt" identity)" ]; then
        flunk "accepted: $1 (the parsers read the identities differently)"
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
R='require warden 1.28\n'
I='trust issuer https://idp.example.com/ audience varek-agent\n'
X() { printf '%sallow exec %s\n' "$R" "$1"; }      # one exec rule

accepted "an issuer, with its keys' URL"     "${R}${I}trust issuer https://login.example.org audience api://varek jwks https://login.example.org/keys\n"
accepted "a SPIFFE trust domain"             "${R}trust spiffe prod.example.org bundle /etc/varek/spiffe.pem\n"
accepted "require on-behalf-of"              "${R}${I}require on-behalf-of\n"
accepted "a sub-agent on an exact exec rule" "$(X '/usr/bin/python3 subagent=helper')"
accepted "a sub-agent on a prefix exec rule" "$(X 'prefix /opt/tools/ subagent=tool_runner')"
accepted "a sub-agent on a glob exec rule"   "$(X 'glob /opt/*/run subagent=a1')"
accepted "one sub-agent on two rules"        "${R}allow exec /usr/bin/a subagent=s\nallow exec /usr/bin/b subagent=s\n"
accepted "8 issuers"                         "${R}$(for i in $(seq 1 8); do printf 'trust issuer https://i%d.example.com audience a\\n' "$i"; done)"
accepted "8 trust domains"                   "${R}$(for i in $(seq 1 8); do printf 'trust spiffe d%d.example.org bundle /b%d\\n' "$i" "$i"; done)"
accepted "a sub-agent's name of 32 bytes"    "$(X '/usr/bin/x subagent=a2345678901234567890123456789_12')"
printf '%b' "${R}${I}trust spiffe example.org bundle /etc/varek/b.pem\nrequire on-behalf-of\nallow exec /usr/bin/python3 subagent=helper\n" > "$OUT/p.txt"
check "the two parsers print the issuer, the trust domain, the sub-agent and require on-behalf-of" \
    sh -c "'$VDP' '$OUT/p.txt' identity | grep -qx 'issuer https://idp.example.com/ varek-agent -' && '$CERT' '$OUT/p.txt' identity | grep -qx 'spiffe example.org /etc/varek/b.pem' && '$CERT' '$OUT/p.txt' identity | grep -qx 'subagent 5 helper' && '$VDP' '$OUT/p.txt' identity | grep -qx 'require on-behalf-of'"

refused "trust before 1.28"                  'require warden 1.27\ntrust issuer https://i.example.com audience a\n' "needs \`require warden 1.28\`"
refused "require on-behalf-of before 1.28"   'require warden 1.27\nrequire on-behalf-of\n'                         "needs \`require warden 1.28\`"
refused "subagent= before 1.28"              'require warden 1.27\nallow exec /usr/bin/x subagent=a\n'              "needs \`require warden 1.28\`"
refused "an http:// issuer"                  "${R}trust issuer http://idp.example.com audience a\n"                   "https:// URLs with a host"
refused "an issuer without a host"           "${R}trust issuer https:///x audience a\n"                               "https:// URLs with a host"
refused "an issuer of 256 bytes"             "${R}trust issuer https://$(printf 'x%.0s' $(seq 1 248)) audience a\n"  "https:// URLs with a host"
refused "an audience of 256 bytes"           "${R}trust issuer https://i.example.com audience $(printf 'a%.0s' $(seq 1 256))\n" "an audience 1 to 255"
refused "an http:// keys URL"                "${R}trust issuer https://i.example.com audience a jwks http://k.example.com\n" "https:// URLs with a host"
refused "no audience"                        "${R}trust issuer https://i.example.com\n"                               "need: trust issuer"
refused "aud for audience"                   "${R}trust issuer https://i.example.com aud a\n"                         "need: trust issuer"
refused "keys for jwks"                      "${R}trust issuer https://i.example.com audience a keys https://k.example.com\n" "need: trust issuer"
refused "jwks without its URL"               "${R}trust issuer https://i.example.com audience a jwks\n"               "need: trust issuer"
refused "an issuer trusted twice"            "${R}${I}${I}"                                                           "trusted twice"
refused "9 issuers"                          "${R}$(for i in $(seq 1 9); do printf 'trust issuer https://i%d.example.com audience a\\n' "$i"; done)" "more than 8"
refused "a trust domain with a capital"      "${R}trust spiffe Example.org bundle /b\n"                               "a trust domain"
refused "a trust domain from '-'"            "${R}trust spiffe -x.org bundle /b\n"                                    "a trust domain"
refused "a relative bundle"                  "${R}trust spiffe example.org bundle b.pem\n"                            "an absolute path"
refused "a bundle path with .."              "${R}trust spiffe example.org bundle /a/../b\n"                          "an absolute path"
refused "pem for bundle"                     "${R}trust spiffe example.org pem /b\n"                                  "need: trust spiffe"
refused "a trust domain twice"               "${R}trust spiffe e.org bundle /a\ntrust spiffe e.org bundle /b\n"       "trusted twice"
refused "9 trust domains"                    "${R}$(for i in $(seq 1 9); do printf 'trust spiffe d%d.org bundle /b\\n' "$i"; done)" "more than 8"
refused "trust something else"               "${R}trust domain example.org\n"                                         "need: trust issuer"
refused "require on-behalf-of twice"         "${R}require on-behalf-of\nrequire on-behalf-of\n"                       "given twice"
refused "require on-behalf-of with a word"   "${R}require on-behalf-of always\n"                                      "need: require on-behalf-of"
refused "subagent= on a deny exec rule"      "${R}deny exec /usr/bin/x subagent=a\n"                                  "only to allow exec rules"
refused "subagent= on a path rule"           "${R}allow path /tmp/ subagent=a\n"                                      "only to allow exec rules"
refused "subagent= on a host rule"           "${R}allow host api.example.com:443 subagent=a\n"                        "only to allow exec rules"
refused "subagent= twice"                    "$(X '/usr/bin/x subagent=a subagent=b')"                                "given twice"
refused "an empty sub-agent name"            "$(X '/usr/bin/x subagent=')"                                            "a sub-agent's name"
refused "a sub-agent name with a capital"    "$(X '/usr/bin/x subagent=Helper')"                                      "a sub-agent's name"
refused "a sub-agent name of 33 bytes"       "$(X '/usr/bin/x subagent=a23456789012345678901234567890123')"           "a sub-agent's name"
refused "require warden 1.29"                'require warden 1.29\n'                                                  "this is 1.28"

printf 'require warden 1.28\nrequire on-behalf-of\nallow path /usr/ readonly\n' > "$OUT/l.txt"
check "lint notes require on-behalf-of with no trusted issuer" sh -c "'$VDP' '$OUT/l.txt' lint | grep -q 'require on-behalf-of, but no issuer is trusted'"
printf '%b' "${R}${I}require on-behalf-of\n" > "$OUT/l2.txt"
check "lint is silent when an issuer is trusted" sh -c "! '$VDP' '$OUT/l2.txt' lint | grep -q 'no issuer is trusted'"

if [ -z "$WARDEN" ]; then
    skip "the Warden's checks (no warden binary given)"
else
    check "the Warden reports 1.28.1" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | grep -q 'VAREK Warden  1.28.1'"
    printf '%b' "${R}${I}trust spiffe example.org bundle /etc/varek/b.pem\nallow path /usr/ readonly\n" > "$OUT/w1.txt"
    check "the Warden starts a policy that trusts an issuer and a trust domain" "$WARDEN" "$OUT/w1.txt" --check-startup
    printf '%b' "${R}${I}require on-behalf-of\nallow path /usr/ readonly\n" > "$OUT/w2.txt"
    "$WARDEN" "$OUT/w2.txt" --check-startup > "$OUT/w2.out" 2>&1; echo $? > "$OUT/w2.rc"
    check "until step 2, require on-behalf-of refuses the start, saying so" \
        sh -c "! grep -qx 0 '$OUT/w2.rc' && grep -q 'not built in this Warden yet (v1.28.1 step 2)' '$OUT/w2.out'"
    printf '%b' "${R}allow exec /usr/bin/true subagent=a\nallow path /usr/ readonly\n" > "$OUT/w3.txt"
    "$WARDEN" "$OUT/w3.txt" --check-startup > "$OUT/w3.out" 2>&1; echo $? > "$OUT/w3.rc"
    check "until step 3, subagent= refuses the start, saying so" \
        sh -c "! grep -qx 0 '$OUT/w3.rc' && grep -q 'not built in this Warden yet (v1.28.1 step 3)' '$OUT/w3.out'"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1281: PASS ($skips skipped)"; exit 0; fi
echo "test_v1281: FAIL"; exit 1
