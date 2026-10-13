#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# test_v1310.sh — VAREK v1.31.0: standards (docs/security/v1.31-standards.md).
# The parts built so far:
#   1. the grammar: `mcp server NAME exec PATH [sha256=HEX]`, an allow exec
#      rule's `subagent=NAME confined`, `for=NAME` on every kind of rule,
#      `<allow|deny> mcp URL METHOD [NAME] ...`, a credential's
#      `audience=URL [opaque]` and `trust mcp-resource URL [audience AUD]`,
#      after `require warden 1.31`, read the same way by the decision
#      procedure (vdp_check) and the certificate checker (vdp_cert_check),
#      each form and each refusal; decisions by subject, and certificates
#      checked against the calling subject's rules; lint; the Warden reports
#      1.31.0, compares the two readings at load, and refuses what later
#      steps build.
#
#   test_v1310.sh VDP_CHECK VDP_CERT_CHECK [WARDEN]
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
hx() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

echo "== 1. the grammar =="
# accepted <label> <policy>: both parsers load it and print the same identities and credentials
accepted() {
    printf '%b' "$2" > "$OUT/p.txt"
    if ! "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1; then
        flunk "accepted: $1 ($("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null | head -1))"
    elif ! "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then
        flunk "accepted: $1 (the checker refused it: $("$CERT" "$OUT/p.txt" digest 2>&1 | head -1))"
    elif [ "$("$VDP" "$OUT/p.txt" identity)" != "$("$CERT" "$OUT/p.txt" identity)" ] ||
         [ "$("$VDP" "$OUT/p.txt" credentials)" != "$("$CERT" "$OUT/p.txt" credentials)" ]; then
        flunk "accepted: $1 (the parsers read the subjects or the credentials differently)"
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
R='require warden 1.31\n'
P='require warden 1.31\nproxy inspect\n'
U='https://mcp.example.com/mcp'
S='mcp server files exec /opt/mcp/bin/mcp-server-filesystem\n'
H='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

accepted "an MCP server"                          "${R}${S}"
accepted "an MCP server pinned by SHA-256"        "${R}mcp server gh exec /opt/mcp/bin/github-mcp-server sha256=$H\n"
accepted "a confined sub-agent"                   "${R}allow exec /opt/tools/helper subagent=helper confined\n"
accepted "a confined sub-agent on a glob rule"    "${R}allow exec glob /opt/*/run subagent=h2 confined\n"
accepted "for= on path, host and exec rules"      "${R}${S}allow path /home/u/proj/ for=files\nallow host api.github.com:443 for=files\nallow exec /usr/bin/git for=files\n"
accepted "for= on a path rule with flag clauses"  "${R}${S}allow path /usr/lib/ readonly for=files\n"
accepted "a confined subject's own sub-agent"     "${R}${S}allow exec /opt/n2 subagent=nested confined for=files\n"
accepted "an mcp rule"                            "${P}allow mcp $U tools/list\n"
accepted "an mcp rule with a tool glob"           "${P}allow mcp $U tools/call get_*\ndeny mcp $U tools/call delete_*\n"
accepted "an mcp rule with a method glob"         "${P}allow mcp $U tools/* x\n"
accepted "an mcp rule for a resource"             "${P}allow mcp $U resources/read file:///projects/app/**\n"
accepted "an mcp rule on the root of a host"      "${P}allow mcp https://mcp.example.com server/discover\n"
accepted "an mcp rule on http:// and a port"      "${P}proxy ports 80 8443\nallow mcp http://plain.example.com/mcp tools/list\nallow mcp https://mcp.example.com:8443/m tools/list\n"
accepted "an mcp rule with max_body= and for="    "${P}${S}allow mcp $U tools/call x max_body=1m for=files\n"
accepted "an mcp rule carrying a credential"      "${P}credential k from file:/etc/varek/creds/k\nallow mcp $U tools/call x credential=k\n"
accepted "an MCP access token for its server"     "${P}credential gh from file:/etc/varek/creds/gh audience=$U\nallow mcp $U tools/call credential=gh\n"
accepted "an opaque MCP access token"             "${P}credential gh from vault:kv/gh#t audience=$U opaque\nallow mcp https://mcp.example.com:443/mcp tools/call x credential=gh header=authorization:bearer\n"
accepted "a token's audience with the port"       "${P}credential gh from file:/x audience=https://mcp.example.com:443/mcp\nallow mcp $U tools/call x credential=gh\n"
accepted "trust mcp-resource"                     "${R}trust mcp-resource $U\ntrust mcp-resource https://api.example.com audience api://x\n"
accepted "32 confined subjects"                   "${R}$(for i in $(seq 1 32); do printf 'mcp server s%d exec /opt/m/s%d\\n' "$i" "$i"; done)"
accepted "an mcp server's name of 32 bytes"       "${R}mcp server a2345678901234567890123456789_12 exec /opt/x\n"
accepted "a name starting with an option word, escaped" "${P}allow mcp $U tools/call \\\\for=x\n"

printf '%b' "${P}credential gh from file:/etc/varek/creds/gh audience=$U opaque\ntrust mcp-resource $U audience api://x\n${S}allow exec /opt/tools/helper subagent=helper confined\nallow path /home/u/proj/ for=files\nallow mcp $U tools/call get_* credential=gh for=helper\n" > "$OUT/p.txt"
check "the parsers print the subjects, the rules for each and the MCP resource" \
    sh -c "'$VDP' '$OUT/p.txt' identity | grep -qx 'confined 1 files mcp 5 -' && '$CERT' '$OUT/p.txt' identity | grep -qx 'confined 2 helper subagent 6 -' && '$VDP' '$OUT/p.txt' identity | grep -qx 'for 7 1' && '$CERT' '$OUT/p.txt' identity | grep -qx 'for 8 2' && '$CERT' '$OUT/p.txt' identity | grep -qx 'mcp-resource $U api://x'"
check "the parsers print a token's audience, canonical, and where it goes" \
    sh -c "'$VDP' '$OUT/p.txt' credentials | grep -qx 'audience gh https://mcp.example.com:443/mcp opaque' && '$CERT' '$OUT/p.txt' credentials | grep -qx 'rule 8 gh Authorization Bearer'"

refused "mcp server before require warden 1.31"   'require warden 1.29\nmcp server a exec /opt/x\n'                  "needs \`require warden 1.31\`"
refused "an mcp rule before 1.31"                 'require warden 1.28\nproxy inspect\nallow mcp https://m.example.com/ x\n' "needs \`require warden 1.31\`"
refused "for= before 1.31"                        'require warden 1.29\nallow path /x for=a\n'                          "for= needs"
refused "confined before 1.31"                    'require warden 1.29\nallow exec /x subagent=a confined\n'            "confined needs"
refused "audience= before 1.31"                   'require warden 1.29\ncredential a from file:/x audience=https://m.example.com/\n' "audience= needs"
refused "trust mcp-resource before 1.31"          "require warden 1.29\ntrust mcp-resource $U\n"                       "needs \`require warden 1.31\`"
refused "require warden 1.32"                     'require warden 1.32\n'                                                "requires Warden 1.32"
for launcher in /usr/bin/node /usr/bin/npx /usr/local/bin/uvx /usr/bin/docker /usr/bin/env /usr/bin/python3.12 /bin/sh /lib64/ld-linux-x86-64.so.2; do
    refused "an MCP server that is $(basename "$launcher")" "${R}mcp server a exec $launcher\n" "an interpreter or a launcher"
done
refused "an MCP server's name in capitals"        "${R}mcp server Files exec /opt/x\n"                                  "a server's name"
refused "an MCP server's relative path"           "${R}mcp server a exec opt/x\n"                                       "absolute path"
refused "an MCP server's path ending in /"        "${R}mcp server a exec /opt/x/\n"                                     "absolute path"
refused "an MCP server's path with .."            "${R}mcp server a exec /opt/../x\n"                                   "absolute path"
refused "a bad sha256="                           "${R}mcp server a exec /opt/x sha256=ABC\n"                           "64 lowercase hex"
refused "sha256= of 63 digits"                    "${R}mcp server a exec /opt/x sha256=${H:1}\n"                       "64 lowercase hex"
refused "mcp server without exec"                 "${R}mcp server a run /opt/x\n"                                       "need: mcp server"
refused "an MCP server named twice"               "${R}${S}mcp server files exec /opt/y\n"                              "given once"
refused "33 confined subjects"                    "${R}$(for i in $(seq 1 33); do printf 'mcp server s%d exec /opt/m/s%d\\n' "$i" "$i"; done)" "more than 32"
refused "confined without subagent="              "${R}allow exec /x confined\n"                                        "confined applies only"
refused "confined on a path rule"                 "${R}allow path /x subagent=a confined\n"                             "subagent= applies only"
refused "confined on a deny rule"                 "${R}deny exec /x subagent=a confined\n"                              "subagent= applies only"
refused "confined given twice"                    "${R}allow exec /x subagent=a confined confined\n"                    "confined given twice"
refused "a confined name also unconfined (after)" "${R}allow exec /x subagent=a confined\nallow exec /y subagent=a\n" "confined everywhere or nowhere"
refused "a confined name also unconfined (before)" "${R}allow exec /y subagent=a\nallow exec /x subagent=a confined\n" "confined everywhere or nowhere"
refused "an MCP server named as an unconfined sub-agent" "${R}allow exec /y subagent=files\n${S}"                       "confined everywhere or nowhere"
refused "for= naming no subject"                  "${R}allow path /x for=nobody\n"                                      "no confined subject"
refused "for= naming a subject declared later"    "${R}allow path /x for=files\n${S}"                                   "no confined subject"
refused "for= naming an unconfined sub-agent"     "${R}allow exec /y subagent=u\nallow path /x for=u\n"                "no confined subject"
refused "for= given twice"                        "${R}${S}allow path /x for=files for=files\n"                         "for= given twice"
refused "for= on its own declaration"             "${R}allow exec /x subagent=a confined for=a\n"                       "no confined subject"
refused "an mcp rule without proxy inspect"       "${R}allow mcp $U tools/list\n"                                       "without \`proxy inspect\`"
refused "an mcp rule on an unproxied port"        "${P}allow mcp https://mcp.example.com:8443/m tools/list\n"           "not proxied"
refused "an mcp rule on a passthrough host"       "${P}proxy passthrough host mcp.example.com\nallow mcp $U tools/list\n" "passthrough host"
refused "an mcp rule with a query"                "${P}allow mcp $U?x=1 tools/list\n"                                   "no query"
refused "an mcp rule with a fragment"             "${P}allow mcp $U#f tools/list\n"                                     "no query"
refused "an mcp rule on an address"               "${P}allow mcp https://1.2.3.4/mcp tools/list\n"                      "not an address"
refused "an mcp rule on a wildcard host"          "${P}allow mcp https://*.example.com/mcp tools/list\n"                "not a wildcard"
refused "an mcp rule with user information"       "${P}allow mcp https://u@mcp.example.com/mcp tools/list\n"            "no user information"
refused "an mcp rule with a capital host"         "${P}allow mcp https://MCP.example.com/mcp tools/list\n"              "host name"
refused "an mcp rule with '//'"                   "${P}allow mcp https://mcp.example.com/a//b tools/list\n"             "no empty segment"
refused "an mcp rule with '..'"                   "${P}allow mcp https://mcp.example.com/a/../b tools/list\n"           "'..' segment"
refused "an mcp rule escaping an unreserved byte" "${P}allow mcp https://mcp.example.com/%41 tools/list\n"              "percent-encode"
refused "an mcp rule with a wildcard in the URL"  "${P}allow mcp https://mcp.example.com/a* tools/list\n"               "wildcard"
refused "an mcp rule on ftp://"                   "${P}allow mcp ftp://mcp.example.com/ tools/list\n"                   "https:// or http://"
refused "a method with '#'"                       "${P}allow mcp $U tools#call\n"                                       "a method is"
refused "a method of 129 bytes"                   "${P}allow mcp $U $(printf 'm%.0s' $(seq 1 129))\n"                  "a method is"
refused "a name with a byte over 0x7e"            "${P}allow mcp $U tools/call a\xe9\n"                                 "a name is"
refused "a name with a bad glob"                  "${P}allow mcp $U tools/call [a\n"                                    "glob"
refused "two names"                               "${P}allow mcp $U tools/call a b\n"                                   "unknown option"
refused "max_body= on a deny mcp rule"            "${P}deny mcp $U tools/call x max_body=1k\n"                          "allow mcp rules"
refused "credential= on a deny mcp rule"          "${P}credential k from file:/k\ndeny mcp $U tools/call x credential=k\n" "allow mcp rules"
refused "header= without credential="             "${P}allow mcp $U tools/call x header=Authorization:Bearer\n"         "header= needs credential="
refused "an unknown credential"                   "${P}allow mcp $U tools/call x credential=nope\n"                     "unknown credential"
refused "a credential on an http:// mcp rule"     "${P}credential k from file:/k\nallow mcp http://plain.example.com/mcp x credential=k\n" "only on an https://"
refused "an MCP token for another server"         "${P}credential gh from file:/x audience=$U\nallow mcp https://other.example.com/mcp x credential=gh\n" "not for this server"
refused "an MCP token in another header"          "${P}credential gh from file:/x audience=$U\nallow mcp $U x credential=gh header=X-Api-Key\n" "Authorization:Bearer"
refused "an MCP token on a request rule"          "${P}credential gh from file:/x audience=$U\nallow request GET $U credential=gh header=Authorization:Bearer\n" "only an mcp rule"
refused "an audience on http://"                  "${R}credential gh from file:/x audience=http://mcp.example.com/mcp\n" "starts with https://"
refused "opaque without an audience"              "${R}credential gh from file:/x opaque\n"                             "need: credential"
refused "an audience with a query"                "${R}credential gh from file:/x audience=$U?x\n"                      "no query"
refused "trust mcp-resource on http://"           "${R}trust mcp-resource http://mcp.example.com/mcp\n"                  "starts with https://"
refused "trust mcp-resource twice"                "${R}trust mcp-resource $U\ntrust mcp-resource $U\n"                  "trusted twice"
refused "trust mcp-resource's audience missing"   "${R}trust mcp-resource $U audience\n"                                "need: trust mcp-resource"
refused "9 trusted MCP resources"                 "${R}$(for i in $(seq 1 9); do printf 'trust mcp-resource https://m%d.example.com/\\n' "$i"; done)" "more than 8"

# decisions by subject, through both C tools
printf '%b' "${P}${S}allow exec /opt/tools/helper subagent=helper confined\nallow path /usr/lib/\nallow path /home/u/proj/ for=files\nallow host mcp.example.com:443\nallow host mcp.example.com:443 for=helper\nallow mcp $U tools/list\nallow mcp $U tools/call get_*\ndeny mcp $U tools/call delete_*\nallow mcp $U resources/read file:///projects/app/** for=helper\n" > "$OUT/d.txt"
O1="$(hx 'https://mcp.example.com:443/mcp#tools/call#get_issue')"
O2="$(hx 'https://mcp.example.com:443/mcp#tools/call#delete_repo')"
O3="$(hx 'https://mcp.example.com:443/mcp#resources/read#file:///projects/app/a/b')"
O4="$(hx 'https://mcp.example.com:443/mcp#tools/list#')"
PP="$(hx /home/u/proj/a.c)"; PL="$(hx /usr/lib/libc.so.6)"
printf 'mcp - %s\nmcp - %s\nmcp - %s\nmcp - %s @2\nmcp - %s\npath 0 %s\npath 0 %s @1\npath 0 %s @1\npath 0 %s @3\nmcp - %s @1\n' \
    "$O1" "$O2" "$O3" "$O3" "$O4" "$PP" "$PP" "$PL" "$PP" "$O1" | "$VDP" "$OUT/d.txt" batch > "$OUT/d.out"
v() { sed -n "${1}p" "$OUT/d.out" | grep -q "\"verdict\":\"$2\""; }
check "a tool the agent's mcp rule allows is SATISFIED"            v 1 SATISFIED
check "a tool a deny mcp rule names is UNSATISFIED"                v 2 UNSATISFIED
check "a resource only the helper's rule allows is UNKNOWN for the agent" v 3 UNKNOWN
check "... and SATISFIED for the helper (subject 2)"                v 4 SATISFIED
check "tools/list, a call that names nothing, is SATISFIED"        v 5 SATISFIED
check "the server's path rule does not decide the agent's open"    v 6 UNKNOWN
check "it decides the server's (subject 1)"                        v 7 SATISFIED
check "the agent's path rule does not decide the server's open"    v 8 UNKNOWN
check "a subject that does not exist gets nothing"                 v 9 UNKNOWN
check "the agent's mcp rule does not decide the server's call"     v 10 UNKNOWN
W1="$(sed -n 1p "$OUT/d.out" | sed -n 's/.*"rule":\([0-9]*\).*"w":"\([^"]*\)".*/\1 \2/p')"
W4="$(sed -n 4p "$OUT/d.out" | sed -n 's/.*"rule":\([0-9]*\).*"w":"\([^"]*\)".*/\1 \2/p')"
W7="$(sed -n 7p "$OUT/d.out" | sed -n 's/.*"rule":\([0-9]*\).*"w":"\([^"]*\)".*/\1 \2/p')"
printf 'mcp - %s %s\nmcp - %s %s @1\nmcp - %s %s @2\nmcp - %s %s\npath 0 %s %s @1\npath 0 %s %s\npath 0 %s %s @2\n' \
    "$O1" "$W1" "$O1" "$W1" "$O3" "$W4" "$O3" "$W4" "$PP" "$W7" "$PP" "$W7" "$PP" "$W7" | "$CERT" "$OUT/d.txt" batch > "$OUT/c.out"
c() { sed -n "${1}p" "$OUT/c.out" | grep -q "\"check\":\"$2\""; }
check "the checker accepts the agent's certificate for a tool"     c 1 ok
check "... and refuses it replayed for the server"                 c 2 reject
check "the checker accepts the helper's certificate"               c 3 ok
check "... and refuses it replayed for the agent"                  c 4 reject
check "the checker accepts the server's certificate for its open"  c 5 ok
check "... and refuses it for the agent and for another subject"   sh -c "sed -n 6p '$OUT/c.out' | grep -q reject && sed -n 7p '$OUT/c.out' | grep -q reject"
check "the checker refuses a subject that does not exist" \
    sh -c "printf 'path 0 %s %s @9\n' '$PP' '$W7' | '$CERT' '$OUT/d.txt' batch | grep -q 'no such subject'"

# lint
printf '%b' "${P}${S}allow mcp $U tools/list for=files\n" > "$OUT/l.txt"
check "lint: an mcp rule whose subject has no host rule can never fire" \
    sh -c "'$VDP' '$OUT/l.txt' lint | grep -q ':4: mcp rule can never fire: no host rule allows mcp.example.com:443'"
printf '%b' "${R}${S}allow exec /opt/tools/helper subagent=helper confined\nallow path /x for=helper\n" > "$OUT/l2.txt"
check "lint: a confined subject no rule is written for" \
    sh -c "'$VDP' '$OUT/l2.txt' lint | grep -q ':2: note: no rule is written for files (for=files)' && ! '$VDP' '$OUT/l2.txt' lint | grep -q 'written for helper'"
printf '%b' "${R}${S}allow path /x\nallow path /x for=files\n" > "$OUT/l3.txt"
check "a subject's rule is not shadowed by the agent's same rule (lint finds no dead rule)" "$VDP" "$OUT/l3.txt" lint

# the Warden
if [ -z "$WARDEN" ]; then
    skip "the Warden's checks (no warden binary given)"
else
    check "the Warden reports 1.31.0 or later" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | python3 -c 'import re,sys; m=re.search(r\"VAREK Warden  (\\d+)\\.(\\d+)\\.(\\d+)\", sys.stdin.read()); sys.exit(0 if m and tuple(map(int, m.groups())) >= (1, 31, 0) else 1)'"
    printf '%b' "${R}allow path /usr/\n" > "$OUT/w1.txt"
    check "the Warden starts a require warden 1.31 policy" "$WARDEN" "$OUT/w1.txt" --check-startup
    for form in "${R}${S}" "${R}allow exec /opt/h subagent=h confined\n" "${P}allow mcp $U tools/list\n" \
                "${R}credential gh from file:/x audience=$U\n" "${R}trust mcp-resource $U\n"; do
        printf '%b' "$form" > "$OUT/w2.txt"
        "$WARDEN" "$OUT/w2.txt" --check-startup > "$OUT/w2.out" 2>&1
        rc=$?
        check "the Warden refuses, until a later step builds it: $(printf '%b' "$form" | sed -n 2p | cut -c1-48)" \
            sh -c "[ $rc != 0 ] && grep -q 'read but not yet enforced by this build' '$OUT/w2.out'"
    done
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1310: PASS ($skips skipped)"; exit 0; fi
echo "test_v1310: FAIL"; exit 1
