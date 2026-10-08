#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1261.sh — v1.26.1, the egress proxy's inspecting mode: the parts
# built so far (docs/security/v1.26.1-inspecting-mode.md).
#
#   1. policy grammar: `proxy inspect`, `proxy passthrough host NAME` and
#      request rules (`allow|deny request METHOD URL [max_body=N]`) after
#      `require warden 1.26`; every refused form refused by both the decision
#      procedure and the certificate checker; each rule held as the glob over
#      the request object; requests decided and certified as the rules say
#      (a query only where a rule names one, '?' never a wildcard); a request
#      rule no connection can reach reported; `varek policy show`; and the
#      Warden refusing to run inspecting mode until it is built
#
# Usage: test_v1261.sh <vdp_check> <vdp_cert_check> [<warden>]
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
trap '[ -n "${KEEP:-}" ] && echo "kept $OUT" || rm -rf "$OUT"' EXIT
hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

echo "== 1. policy grammar =="
accepted() {
    printf '%b' "$2" > "$OUT/p.txt"
    if "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1 && "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then
        pass "accepted: $1"
    else flunk "accepted: $1 ($("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null | head -1))"; fi
}
refused() {
    printf '%b' "$2" > "$OUT/p.txt"
    local e
    e="$("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null)"
    if "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1; then flunk "refused: $1 (the procedure loaded it)"
    elif "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then flunk "refused: $1 (the checker loaded it)"
    elif ! printf '%s' "$e" | grep -qF -- "$3"; then flunk "refused: $1 (message: $e)"
    else pass "refused: $1"; fi
}
R='require warden 1.26\nproxy inspect\n'
H='allow host api.example.com:443\n'
Q() { printf '%sallow request %s\n' "$R$H" "$1"; }      # one request rule
accepted "proxy inspect"                     "${R}${H}"
accepted "with ports and an upstream"        "${R}proxy ports 443 8443\nproxy upstream http://p.example:3128\n${H}"
accepted "a passthrough host"                "${R}proxy passthrough host pinned.example.net\n${H}"
accepted "an exact request"                  "$(Q 'GET https://api.example.com/v1/models')"
accepted "any method, a ** path"             "$(Q '* https://api.example.com/v1/**')"
accepted "a port, a wildcard host"           "${R}proxy ports 8443\nallow host *.svc.example.com:8443 acknowledge=dns-channel\nallow request POST https://*.svc.example.com:8443/q/*\n"
accepted "plain http on port 80"             "${R}allow host plain.example.com:80\nallow request GET http://plain.example.com/x\n"
accepted "a query and a set"                 "$(Q 'GET https://api.example.com/v1/[ab]*?limit=*')"
accepted "a trailing slash, an escape"       "$(Q 'GET https://api.example.com/v1/a%20b/')"
accepted "max_body in k, m and bytes"        "${R}${H}allow request POST https://api.example.com/a max_body=256k\nallow request POST https://api.example.com/b max_body=1024m\nallow request PUT https://api.example.com/c max_body=1\n"
accepted "a deny request"                    "$(printf '%sdeny request * https://api.example.com/v1/admin/**\n' "$R$H")"
refused "a request rule before 1.26"         'require warden 1.25\nallow request GET https://a.example.com/x\n' "needs \`require warden 1.26\`"
refused "a request rule with proxy on"       'require warden 1.26\nproxy on\nallow request GET https://a.example.com/x\n' "without \`proxy inspect\`"
refused "a request rule, no proxy"           'require warden 1.26\nallow request GET https://a.example.com/x\n' "without \`proxy inspect\`"
refused "proxy on and inspect"               'require warden 1.26\nproxy on\nproxy inspect\n' "together"
refused "proxy inspect twice"                'require warden 1.26\nproxy inspect\nproxy inspect\n' "given twice"
refused "inspect with more"                  'require warden 1.26\nproxy inspect now\n' "bad directive"
refused "passthrough without inspect"        'require warden 1.26\nproxy on\nproxy passthrough host a.example.com\n' "without \`proxy inspect\`"
refused "a passthrough wildcard"             "${R}proxy passthrough host *.example.com\n" "not a wildcard"
refused "a passthrough port"                 "${R}proxy passthrough host a.example.com:443\n" "without a port"
refused "a passthrough address"              "${R}proxy passthrough host 1.2.3.4\n" "not an address"
refused "a passthrough bad name"             "${R}proxy passthrough host A.example.com\n" "lowercase"
refused "a passthrough twice"                "${R}proxy passthrough host a.example.com\nproxy passthrough host a.example.com\n" "given twice"
refused "passthrough without host"           "${R}proxy passthrough a.example.com\n" "proxy passthrough host"
refused "a lowercase method"                 "$(Q 'get https://api.example.com/x')" "1 to 20 letters A-Z"
refused "a method with a digit"              "$(Q 'G1 https://api.example.com/x')" "1 to 20 letters A-Z"
refused "a 21-letter method"                 "$(Q 'ABCDEFGHIJKLMNOPQRSTU https://api.example.com/x')" "1 to 20 letters A-Z"
refused "no URL"                             "${R}allow request GET\n" "need: allow request"
refused "another scheme"                     "$(Q 'GET ftp://api.example.com/x')" "https:// or http://"
refused "no path"                            "$(Q 'GET https://api.example.com')" "needs a path"
refused "an address"                         "$(Q 'GET https://1.2.3.4/x')" "not an address"
refused "an IPv6 address"                    "$(Q 'GET https://[::1]/x')" "a request URL"
refused "port 0"                             "$(Q 'GET https://api.example.com:0/x')" "port is 1 to 65535"
refused "a leading zero"                     "$(Q 'GET https://api.example.com:0443/x')" "port is 1 to 65535"
refused "port 65536"                         "$(Q 'GET https://api.example.com:65536/x')" "port is 1 to 65535"
refused "an uppercase host"                  "$(Q 'GET https://API.example.com/x')" "lowercase"
refused "a wildcard over one label"          "$(Q 'GET https://*.com/x')" "at least two labels"
refused "a wildcard inside"                  "$(Q 'GET https://a.*.example.com/x')" "leftmost label"
refused "a .. segment"                       "$(Q 'GET https://api.example.com/a/../b')" "'..' segment"
refused "a . segment"                        "$(Q 'GET https://api.example.com/a/./b')" "'..' segment"
refused "an empty segment"                   "$(Q 'GET https://api.example.com/a//b')" "('//')"
refused "a ;"                                "$(Q 'GET https://api.example.com/a;b')" "';'"
refused "a backslash"                        "$(Q 'GET https://api.example.com/a\\\\b')" "';'"
refused "a # in the path"                    "$(Q 'GET https://api.example.com/a#b')" "';'"
refused "a non-ASCII byte"                   "$(Q 'GET https://api.example.com/\xe9')" "0x21 to 0x7e"
refused "%41, an unreserved byte"            "$(Q 'GET https://api.example.com/v1/%61dmin')" "unreserved"
refused "%2F, a slash"                       "$(Q 'GET https://api.example.com/a%2Fb')" "unreserved"
refused "%2f, a slash"                       "$(Q 'GET https://api.example.com/a%2fb')" "unreserved"
refused "a bad escape"                       "$(Q 'GET https://api.example.com/a%4')" "escape %XX"
refused "a bad glob"                         "$(Q 'GET https://api.example.com/[/]')" "glob class"
refused "max_body=0"                         "$(Q 'POST https://api.example.com/x max_body=0')" "max_body is 1 to"
refused "max_body over 1 GiB"                "$(Q 'POST https://api.example.com/x max_body=1025m')" "max_body is 1 to"
refused "max_body=1g"                        "$(Q 'POST https://api.example.com/x max_body=1g')" "max_body is 1 to"
refused "max_body twice"                     "$(Q 'POST https://api.example.com/x max_body=1k max_body=2k')" "given twice"
refused "max_body on a deny"                 "${R}${H}deny request POST https://api.example.com/x max_body=1k\n" "only to allow"
refused "an unknown option"                  "$(Q 'POST https://api.example.com/x limit=5')" "unknown option"
refused "an unproxied port"                  "$(Q 'GET https://api.example.com:8443/x')" "not proxied"
refused "a passthrough host's requests"      "${R}proxy passthrough host api.example.com\n${H}allow request GET https://api.example.com/x\n" "passthrough host"
refused "a wildcard over a passthrough"      "${R}proxy passthrough host a.svc.example.com\nallow request GET https://*.svc.example.com/x\n" "passthrough host"
refused "an object over 4,095 bytes"         "$(Q "GET https://api.example.com/$(printf 'a%.0s' $(seq 1 4080))")" "over 4,095 bytes"

# The glob each rule is held as, as both parsers read it.
printf '%b' "${R}proxy passthrough host pinned.example.net\n${H}allow host *.svc.example.com:443 acknowledge=dns-channel
allow request GET https://api.example.com/v1/models
allow request POST https://api.example.com/v1/chat/completions max_body=256k
allow request GET https://api.example.com/v1/files?limit=*
deny request * https://api.example.com/v1/admin/**
allow request * https://*.svc.example.com/**
" > "$OUT/r.txt"
"$CERT" "$OUT/r.txt" rules > "$OUT/rules.out" 2>&1
want="r a - 0 0 - 8 0 0 0 $(hex 'GET https://api.example.com:443/v1/files\?limit=*')"
if grep -qxF "$want" "$OUT/rules.out"; then pass "a query's '?' is held escaped, the port filled in"
else flunk "a query's '?' is held escaped ($(cat "$OUT/rules.out"))"; fi
want="r a - 0 0 - 10 0 0 0 $(hex '* https://?*.svc.example.com:443/**')"
if grep -qxF "$want" "$OUT/rules.out"; then pass "a wildcard host and method are held as globs"
else flunk "a wildcard host and method are held as globs"; fi
if grep -q '^r a - 0 0 - 7 0 0 262144 ' "$OUT/rules.out"; then pass "max_body=256k is 262,144 bytes"
else flunk "max_body=256k is 262,144 bytes"; fi
p="$("$CERT" "$OUT/r.txt" proxy 2>&1)"
if [ "$p" = "inspect 80 443 passthrough pinned.example.net" ]; then pass "the checker reports inspecting mode and the passthrough host"
else flunk "the checker reports inspecting mode ($p)"; fi

# Requests decided, then each SATISFIED certificate checked by the checker.
decide() {   # decide "<object>" <verdict> <description>
    local o="$1" want="$2" d="$3" got cert
    got="$(printf 'request - %s\n' "$(hex "$o")" | "$VDP" "$OUT/r.txt" batch 2>/dev/null)"
    if ! printf '%s' "$got" | grep -q "\"verdict\":\"$want\""; then flunk "$d ($got)"; return; fi
    if [ "$want" = SATISFIED ]; then
        local ri w
        ri="$(printf '%s' "$got" | sed -n 's/.*"rule":\([0-9-]*\).*/\1/p')"
        w="$(printf '%s' "$got" | sed -n 's/.*"w":"\([^"]*\)".*/\1/p')"
        cert="$(printf 'request - %s %s %s\n' "$(hex "$o")" "$ri" "${w:-=}" | "$CERT" "$OUT/r.txt" batch 2>&1)"
        if ! printf '%s' "$cert" | grep -q '"check":"ok"'; then flunk "$d (the checker: $cert)"; return; fi
    fi
    pass "$d"
}
decide 'GET https://api.example.com:443/v1/models'           SATISFIED   "an exact request allowed, its certificate accepted"
decide 'GET https://api.example.com:443/v1/models?x=1'       UNKNOWN     "an exact rule matches no query"
decide 'POST https://api.example.com:443/v1/models'          UNKNOWN     "another method is not allowed"
decide 'GET https://api.example.com:443/v1/files?limit=10'   SATISFIED   "a query a rule names is allowed"
decide 'GET https://api.example.com:443/v1/filesXlimit=10'   UNKNOWN     "'?' is not a wildcard"
decide 'DELETE https://api.example.com:443/v1/admin/u/1'     UNSATISFIED "a deny over any method holds"
decide 'GET https://api.example.com:80/v1/models'            UNKNOWN     "the port is part of the object"
decide 'PUT https://a.svc.example.com:443/q/r?s=1'           SATISFIED   "a wildcard host's request allowed"
decide 'PUT https://svc.example.com:443/q'                   UNKNOWN     "a wildcard does not match its suffix"
decide 'GET http://api.example.com:443/v1/models'            UNKNOWN     "the scheme is part of the object"

# A request rule whose host no host rule allows is never reached.
printf 'require warden 1.26\nproxy inspect\nallow host a.example.com:443\nallow request GET https://b.example.com/x\n' > "$OUT/n.txt"
if ! "$VDP" "$OUT/n.txt" lint > "$OUT/lint.out" 2>&1 && grep -q "can never fire: no host rule allows b.example.com:443" "$OUT/lint.out"
then pass "lint reports a request rule no host rule reaches"
else flunk "lint reports a request rule no host rule reaches ($(cat "$OUT/lint.out"))"; fi

if python3 "$HERE/tools/varek" policy show "$OUT/r.txt" > "$OUT/show.out" 2>&1 &&
   grep -q '^Proxy    inspecting mode, ports 80, 443:' "$OUT/show.out" &&
   grep -q '^Passthrough pinned.example.net:' "$OUT/show.out" &&
   grep -qF 'Request  allow GET https://api.example.com:443/v1/files?limit=* (line 8)' "$OUT/show.out" &&
   grep -qF 'Request  allow POST https://api.example.com:443/v1/chat/completions (line 7), bodies at most 262,144 bytes' "$OUT/show.out"
then pass "varek policy show names inspecting mode, passthrough hosts and request rules"
else flunk "varek policy show ($(head -c 600 "$OUT/show.out"))"; fi

if [ -n "$WARDEN" ]; then
    "$WARDEN" "$OUT/r.txt" --check-startup > "$OUT/w.out" 2>&1; rc=$?
    if [ "$rc" = 2 ] && grep -q "loaded policy" "$OUT/w.out" && grep -q "inspecting mode is not built into this Warden yet" "$OUT/w.out"
    then pass "the Warden loads the policy (both parsers agree) and refuses to run inspecting mode yet"
    else flunk "the Warden refuses to run inspecting mode yet (rc=$rc; $(tail -2 "$OUT/w.out"))"; fi
    "$WARDEN" "$OUT/n.txt" --check-startup > "$OUT/w2.out" 2>&1
    if grep -q "WARNING: request rule can never fire: no host rule allows b.example.com:443" "$OUT/w2.out"
    then pass "the Warden warns about a request rule no host rule reaches"
    else flunk "the Warden warns about a request rule no host rule reaches"; fi
else skip "the Warden's startup check (no warden binary given)"; skip "the Warden's warning"; fi

echo
if [ "$fail" = 0 ]; then echo "test_v1261: PASS ($skips skipped)"; else echo "test_v1261: FAIL"; fi
exit "$fail"
