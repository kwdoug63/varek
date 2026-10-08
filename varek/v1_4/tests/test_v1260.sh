#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1260.sh — v1.26.0, the egress proxy in SNI mode: the parts built so
# far (docs/security/v1.26-egress-proxy.md).
#
#   1. policy grammar: `proxy on` and `proxy ports P...` after
#      `require warden 1.26`, refused forms (before 1.26, twice, bad or
#      repeated ports, more than 16, ports without `proxy on`, `proxy inspect`
#      until v1.26.1), the same answer from the decision procedure and the
#      certificate checker on every case, and the Warden starting with them
#
# Usage: test_v1260.sh <vdp_check> <vdp_cert_check> [<warden>]
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
trap 'rm -rf "$OUT"' EXIT

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
    elif ! printf '%s' "$e" | grep -qF "$3"; then flunk "refused: $1 (message: $e)"
    else pass "refused: $1"; fi
}
R='require warden 1.26\n'
H='allow host api.example.com:443\n'
accepted "proxy on"                          "${R}proxy on\n${H}"
accepted "proxy on, then ports"              "${R}proxy on\nproxy ports 443 8443\n${H}"
accepted "ports before proxy on"             "${R}proxy ports 80\nproxy on\n${H}"
accepted "the port bounds"                   "${R}proxy on\nproxy ports 1 65535\n${H}"
accepted "16 ports"                          "${R}proxy on\nproxy ports $(seq -s ' ' 1 16)\n${H}"
accepted "a trailing comment"                "${R}proxy on   # SNI mode\n${H}"
accepted "with a wildcard rule"              "${R}proxy on\nallow host *.example.com:443 acknowledge=dns-channel\n"
refused "proxy before 1.26"                  'require warden 1.25\nproxy on\n'          "require warden 1.26"
refused "proxy with no require"              'proxy on\n'                               "require warden 1.26"
refused "proxy on twice"                     "${R}proxy on\nproxy on\n"                 "given twice"
refused "proxy ports twice"                  "${R}proxy on\nproxy ports 443\nproxy ports 80\n" "given twice"
refused "a port given twice"                 "${R}proxy on\nproxy ports 443 443\n"     "given twice"
refused "port 0"                             "${R}proxy on\nproxy ports 0\n"            "a port is 1 to 65535"
refused "port 65536"                         "${R}proxy on\nproxy ports 65536\n"        "a port is 1 to 65535"
refused "a leading zero"                     "${R}proxy on\nproxy ports 0443\n"         "a port is 1 to 65535"
refused "not a number"                       "${R}proxy on\nproxy ports https\n"        "a port is 1 to 65535"
refused "17 ports"                           "${R}proxy on\nproxy ports $(seq -s ' ' 1 17)\n" "more than 16 ports"
refused "ports without proxy on"             "${R}proxy ports 443\n"                    "without \`proxy on\`"
refused "proxy ports with none"              "${R}proxy on\nproxy ports\n"              "bad directive"
refused "proxy alone"                        "${R}proxy\n"                              "bad directive"
refused "proxy off"                          "${R}proxy off\n"                          "bad directive"
refused "proxy on with more"                 "${R}proxy on now\n"                       "bad directive"
refused "proxy inspect (v1.26.1)"            "${R}proxy inspect\n"                      "planned for v1.26.1"
refused "require 1.27"                       'require warden 1.27\n'                    "this is 1.26"

if [ -n "$WARDEN" ]; then
    printf 'require warden 1.26\nproxy on\nproxy ports 443 8443\nallow host api.example.com:443\n' > "$OUT/w.txt"
    check "the Warden starts with the proxy directives" "$WARDEN" "$OUT/w.txt" --check-startup
else skip "the Warden's startup check (no warden binary given)"; fi

echo
if [ "$fail" = 0 ]; then echo "test_v1260: PASS ($skips skipped)"; exit 0; fi
echo "test_v1260: FAIL"; exit 1
