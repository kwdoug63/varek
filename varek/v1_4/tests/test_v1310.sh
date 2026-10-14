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
#   2. confined subjects in the Warden: an MCP server decided by its own
#      rules and the agent by its own (files, a fork, a program the server
#      launches), records and certificates by subject, the audit (and the
#      forgeries it refuses), the server out of the agent's /proc, and the
#      start refused for a pinned file with another hash or a server file
#      that any subject may write (or a directory above it).
#   3. MCP calls over HTTP: a stand-in server (both revisions), each call
#      decided on the body the server acts on (escaped names, a chunked
#      body, two calls on one connection, a notification), the refusals
#      (a deny rule, no rule, duplicate keys, a batch, deep nesting, invalid
#      UTF-8, headers that disagree with the body, a body over the limit, a
#      query) and their JSON-RPC error, a credential only in the calls its
#      rule allows (and a credential for= an MCP server only in the
#      server's calls), the records, and the audit (and the forgeries it
#      refuses).
#   4. MCP tokens: a credential's audience= checked at fetch (another
#      server, expired, near expiry, no expiry, opaque with and without
#      `opaque`); the agent's own bearer tokens (another audience, expired,
#      malformed, the user's token; a good one and an opaque one allowed);
#      the run's MCP token only in the calls its rule names; the user found
#      through `trust mcp-resource` (RFC 9728, RFC 8414, OpenID discovery, an
#      issuer that is not its identifier, metadata for another resource,
#      another audience, the line's audience); no token in any record.
#   5. the OCSF export: each kind of record as OCSF 1.9.0, checked against
#      the vendored schema; UNKNOWN kept; a dry run never Blocked; the user,
#      the delegation and an MCP server named; every event's link back
#      verified, and an edited, removed, reordered or cut event found; a
#      stream edited or refused by the audit not exported; --follow on a
#      live run and on one that ends early; the CLI.
#   6. audit and tools: forged streams the audit refuses (a server's
#      decision on the agent's rule and the reverse, an MCP call on a
#      passthrough connection, an MCP token released to another server, a
#      token in the stream); policy show, refusals --for, runs, doctor's
#      server checks, policy suggest --for and for MCP calls, the CycloneDX
#      server and endpoint, varek run --mcp.
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
for launcher in /usr/bin/node /usr/bin/npx /usr/local/bin/uvx /usr/bin/docker /usr/bin/env /usr/bin/python3.12 /bin/sh /lib64/ld-linux-x86-64.so.2 \
                /usr/bin/time /usr/bin/strace /usr/bin/bwrap /usr/bin/setpriv /usr/local/bin/tsx; do       # review: more launchers
    refused "an MCP server that is $(basename "$launcher")" "${R}mcp server a exec $launcher\n" "an interpreter or a launcher"
done
refused "an MCP server's name in capitals"        "${R}mcp server Files exec /opt/x\n"                                  "a server's name"
refused "an mcp rule's NAME with a '#' (review: it could never match)" "${P}allow mcp $U tools/call a#b\n"  "never '#'"
refused "an mcp rule's NAME with an escaped '#' (review)" "${P}allow mcp $U tools/call [#]x\n"              "never '#'"
LONGU="https://mcp.example.com/$(head -c 4100 /dev/zero | tr '\0' a)"
refused "an audience= over 4,095 bytes (review: the checker refuses it too)" "${R}credential c from file:/x audience=$LONGU\n" "too long"
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
    printf '%b' "${P}allow mcp $U tools/list\n" > "$OUT/w3.txt"
    check "the Warden starts a policy with mcp rules (step 4)" "$WARDEN" "$OUT/w3.txt" --check-startup
    for form in "${R}credential gh from file:/x audience=$U\n" "${R}trust mcp-resource $U\n"; do
        printf '%b' "$form" > "$OUT/w2.txt"
        check "the Warden starts a policy with it (step 5): $(printf '%b' "$form" | sed -n 2p | cut -c1-48)" \
            "$WARDEN" "$OUT/w2.txt" --check-startup
    done
fi

echo "== 2. confined subjects: each decided by its own rules =="
SUBP="$HERE/tests/v1281_sub"; PEEK="$HERE/tests/v1310_peek"
CGM="$(awk '$3 == "cgroup2" { print $2; exit }' /proc/self/mounts)"
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ ! -x "$SUBP" ] || [ ! -x "$PEEK" ] || [ -z "$CGM" ]; then
    skip "section 2 (needs root, the warden, tests/v1281_sub, tests/v1310_peek and a cgroup2 mount)"
else
    B="$(mktemp -d /tmp/varek_v1310s.XXXXXX)"; chmod 755 "$B"
    trap '[ -n "${KEEP:-}" ] && echo "kept $OUT $B" || rm -rf "$OUT" "$B"' EXIT
    for n in agent srv tool; do cp "$SUBP" "$B/$n"; chmod 755 "$B/$n"; done
    cp "$PEEK" "$B/peek"; chmod 755 "$B/peek"
    for f in fa fs fb; do echo hi > "$B/$f"; chmod 644 "$B/$f"; done
    SL='allow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\n'
    SLF="$(printf '%b' "$SL" | sed 's/$/ for=files/')\n"
    SP="require warden 1.31\nmcp server files exec $B/srv\nallow exec $B/tool for=files\nallow exec $B/peek for=files\n"
    SP="${SP}allow path $B/fa readonly\nallow path $B/fb readonly\nallow path $B/fs readonly for=files\nallow path $B/fb readonly for=files\n"
    printf '%b' "$SP$SL$SLF" > "$B/p.txt"
    # the agent's environment as varek run gives it (v1.31 review: a confined
    # server's environment may name no code, and this host's may)
    sgo() { local n="$1"; shift; env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "${POL:-$B/p.txt}" -- "$B/agent" "$@" > "$OUT/$n.so" 2> "$OUT/$n.out"; echo $? > "$OUT/$n.rc"; }
    # dec <name> <file>: each decision on <file>, as "action obo decision rule", in order
    dec() { python3 -c 'import json,sys
for l in open(sys.argv[1]):
    if l.startswith("{\"report_id\""):
        r = json.loads(l)
        if r["target"] == sys.argv[2]: print(r["action"], "+".join(r["obo"]), r["decision_final"], r.get("cert_subject", 0))' "$OUT/$1.out" "$2"; }
    sgo own spawn "$B/fa" "$B/srv" open "$B/fs"
    check "the server opens what its own rules allow (ALLOW, certificate checked as subject 1)" \
        sh -c "$(declare -f dec); OUT='$OUT' dec own '$B/fs' | grep -qx 'file.open agent+subagent:files#1 ALLOW 1'"
    check "... the agent's own open after it is the agent's (ALLOW, subject 0)" \
        sh -c "$(declare -f dec); OUT='$OUT' dec own '$B/fa' | grep -qx 'file.open agent ALLOW 0'"
    check "the server's launch record says it is an MCP server and confined" \
        grep -q '"subagent":"files#1","mcp_server":true,"confined":true,"cgroup":' "$OUT/own.out"
    check "the audit accepts a run with a confined MCP server" python3 "$HERE/tools/varek_audit.py" --policy "$B/p.txt" --checker "$CERT" "$OUT/own.out"
    sgo notmine spawn "$B/fs" "$B/srv" open "$B/fa"
    check "the server is refused what only the agent's rules allow" \
        sh -c "$(declare -f dec); OUT='$OUT' dec notmine '$B/fa' | grep -qx 'file.open agent+subagent:files#1 DENY 0'"
    check "the agent is refused what only the server's rules allow" \
        sh -c "$(declare -f dec); OUT='$OUT' dec notmine '$B/fs' | grep -qx 'file.open agent DENY 0'"
    sgo both spawn "$B/fb" "$B/srv" open "$B/fb"
    check "a file both sets of rules allow: each allowed by its own rule" \
        sh -c "$(declare -f dec); OUT='$OUT' dec both '$B/fb' | tr '\n' ';' | grep -qx 'file.open agent+subagent:files#1 ALLOW 1;file.open agent ALLOW 0;'"
    sgo fork spawn "$B/fa" "$B/srv" fork "$B/fs"
    check "the server's child (a fork) is decided by the server's rules" \
        sh -c "[ \"\$($(declare -f dec); OUT='$OUT' dec fork '$B/fs' | grep -c 'agent+subagent:files#1 ALLOW 1')\" = 2 ]"
    sgo tool spawn "$B/fa" "$B/srv" spawn "$B/fs" "$B/tool" open "$B/fs"
    check "a program the server launches by its own rule runs, decided as the server" \
        sh -c "$(declare -f dec); OUT='$OUT' dec tool '$B/tool' | grep -qx 'process.exec agent+subagent:files#1 ALLOW 1' && [ \"\$($(declare -f dec); OUT='$OUT' dec tool '$B/fs' | grep -c 'agent+subagent:files#1 ALLOW 1')\" = 2 ]"
    check "the audit accepts it" python3 "$HERE/tools/varek_audit.py" --policy "$B/p.txt" --checker "$CERT" "$OUT/tool.out"
    sgo atool spawn "$B/fa" "$B/tool" open "$B/fs"
    check "the agent may not launch what only the server's rules allow" \
        sh -c "$(declare -f dec); OUT='$OUT' dec atool '$B/tool' | grep -q '^process.exec agent DENY'"
    # review: under rules that let the server read /proc, so it is the
    # Warden's own refusal of another process's entries that is tested
    { cat "$B/p.txt"; printf 'allow path /proc/ readonly for=files\n'; } > "$B/pp.txt"
    POL="$B/pp.txt" sgo peek spawn "$B/fa" "$B/srv" exec "$B/peek" self:status environ mem fd/0 cwd/.
    check "the server cannot open the agent's /proc entries (environ, mem, fd, cwd), though its rules allow /proc" \
        sh -c "grep -qx 'self:status ok' '$OUT/peek.so' && grep -qx 'environ refused EACCES' '$OUT/peek.so' && grep -qx 'mem refused EACCES' '$OUT/peek.so' && grep -qx 'fd/0 refused EACCES' '$OUT/peek.so' && grep -qx 'cwd/. refused EACCES' '$OUT/peek.so'"
    # v1.31 review: the environment the agent launches a confined server with
    # names no code (a #! script's interpreter would load it, under the
    # server's rules); checked at the launch, and in the new image's own copy
    mkdir -p "$B/work"; chmod 777 "$B/work"
    printf '#!/usr/bin/python3\nimport sys\nprint("server ran", flush=True)\n' > "$B/srv.py"; chmod 755 "$B/srv.py"
    printf 'print("INJECTED", flush=True)\n' > "$B/work/sitecustomize.py"; chmod 644 "$B/work/sitecustomize.py"
    EP="require warden 1.31\nmcp server py exec $B/srv.py\nallow path $B/work/\nallow path $B/fa readonly\n"
    EP="${EP}allow path $B/work/ readonly for=py\nallow path exact $B/srv.py readonly for=py\nallow exec /usr/bin/python3 for=py\n"
    printf '%b' "$EP$SL$(printf '%b' "$SL" | sed 's/$/ for=py/')\n" > "$B/pe.txt"
    envgo() { local n="$1"; shift; timeout 60 env -i PATH=/usr/bin:/bin "$@" "$WARDEN" "$B/pe.txt" -- "$B/agent" spawn "$B/fa" "$B/srv.py" > "$OUT/$n.so" 2> "$OUT/$n.out"; echo $? > "$OUT/$n.rc"; }
    envgo eok PYTHONUNBUFFERED=1
    check "a confined Python server starts with a setting that names no code (PYTHONUNBUFFERED)" \
        sh -c "grep -qx 'server ran' '$OUT/eok.so' && ! grep -q INJECTED '$OUT/eok.so'"
    envgo epath PYTHONPATH="$B/work"
    check "launched with PYTHONPATH set, it is refused at the launch (subagent_env), and nothing of it runs" \
        sh -c "grep -q '\"action\":\"process.exec\".*\"rule\":\"subagent_env\"' '$OUT/epath.out' && grep -q '\"env\":\"PYTHONPATH\"' '$OUT/epath.out' && ! grep -q 'INJECTED\|server ran' '$OUT/epath.so'"
    check "... the audit accepts that run (a refusal)" python3 "$HERE/tools/varek_audit.py" --policy "$B/pe.txt" --checker "$CERT" "$OUT/epath.out"
    envgo elate VAREK_WARDEN_TEST_ENV_LATE=1 PYTHONPATH="$B/work"
    check "and when only the new image's copy shows it, the server is killed at its first call, before anything of it runs" \
        sh -c "grep -q '\"rule\":\"subagent_env\"' '$OUT/elate.out' && grep -q 'was launched as a confined subject with PYTHONPATH set' '$OUT/elate.out' && ! grep -q 'INJECTED\|server ran' '$OUT/elate.so'"
    check "... and the audit reports it" sh -c "! python3 '$HERE/tools/varek_audit.py' --policy '$B/pe.txt' --checker '$CERT' '$OUT/elate.out' > '$OUT/elate.aud' 2>&1 && grep -q 'with .PYTHONPATH. set (it names code)' '$OUT/elate.aud'"
    evbad=""
    envgo eopt NODE_OPTIONS="--max-old-space-size=4096 --no-warnings" JAVA_TOOL_OPTIONS="-Djavax.net.ssl.trustStore=/x -Xmx1g" GIT_TERMINAL_PROMPT=0 LD_PRELOAD=
    check "options that load no code (NODE_OPTIONS heap, JAVA_TOOL_OPTIONS trust store, GIT_TERMINAL_PROMPT, an empty LD_PRELOAD) start it" \
        grep -qx 'server ran' "$OUT/eopt.so"
    for v in LD_PRELOAD=/x NODE_OPTIONS=--require=/x "NODE_OPTIONS=--no-warnings -r /x" JAVA_TOOL_OPTIONS=-javaagent:/x BASH_ENV=/x BASH_FUNC_f%%=x GIT_SSH_COMMAND=x GLIBC_TUNABLES=x PERL5LIB=/x; do
        envgo ev "$v"
        grep -q '"rule":"subagent_env"' "$OUT/ev.out" || evbad="$evbad ${v%%=*}"
    done
    check "each of LD_PRELOAD, NODE_OPTIONS (--require, -r), JAVA_TOOL_OPTIONS (-javaagent), BASH_ENV, BASH_FUNC_*, GIT_SSH_COMMAND, GLIBC_TUNABLES, PERL5LIB refused at a confined launch${evbad:+ (not:$evbad)}" \
        test -z "$evbad"
    # forged streams the audit refuses
    F="$HERE/tests/v1270_forge.py"; AUD="$HERE/tools/varek_audit.py"
    refuses() { if python3 "$AUD" --policy "$2" --checker "$CERT" "$3" > "$OUT/f.out" 2>&1; then flunk "the audit refuses $1"
                elif grep -qF -- "$4" "$OUT/f.out"; then pass "the audit refuses $1"
                else flunk "the audit refuses $1 ($(grep -m1 PROBLEM "$OUT/f.out"))"; fi; }
    SV='sv = next(r for r in recs if isinstance(r, dict) and r.get("cert_subject") == 1)'
    python3 "$F" "$OUT/own.out" "$OUT/g1.log" "$SV; sv.pop('cert_subject')"
    refuses "a server's decision whose certificate is recorded as the agent's" "$B/p.txt" "$OUT/g1.log" "but the decision was for subject 1"
    python3 "$F" "$OUT/own.out" "$OUT/g2.log" "$SV; sv['obo'] = ['agent']"
    refuses "a server's decision passed off as the agent's" "$B/p.txt" "$OUT/g2.log" "but the decision was for subject 0"
    AG='ag = next(r for r in recs if isinstance(r, dict) and r.get("target") == "'"$B"'/fa" and r.get("decision_final") == "ALLOW")'
    python3 "$F" "$OUT/own.out" "$OUT/g3.log" "$AG; ag['cert_subject'] = 1; ag['obo'] = ['agent', 'subagent:files#1']"
    refuses "the agent's allowed open passed off as the server's" "$B/p.txt" "$OUT/g3.log" "refused"
    # the start
    H0="$(sha256sum "$B/srv" | cut -d' ' -f1)"
    st() { printf '%b' "$2" > "$B/s.txt"; "$WARDEN" "$B/s.txt" --check-startup > "$OUT/st.out" 2>&1; local rc=$?
           if [ "$1" = ok ]; then [ $rc = 0 ]; else [ $rc != 0 ] && grep -qF -- "$3" "$OUT/st.out"; fi; }
    check "a server pinned by its SHA-256 starts" st ok "require warden 1.31\nmcp server files exec $B/srv sha256=$H0\n$SL"
    check "a server whose file has another SHA-256 is refused at the start" \
        st no "require warden 1.31\nmcp server files exec $B/srv sha256=$(printf '0%.0s' $(seq 1 64))\n$SL" "not the 0000"
    check "a server whose file the agent may write is refused" \
        st no "require warden 1.31\nmcp server files exec $B/srv\nallow path $B/srv access=rw\n$SL" "could be replaced"
    check "a server under a directory the agent may write is refused" \
        st no "require warden 1.31\nmcp server files exec $B/srv\nallow path $B/\n$SL" "could be replaced"
    check "a server whose file another subject may write is refused" \
        st no "require warden 1.31\nmcp server files exec $B/srv\nmcp server two exec $B/tool\nallow path $B/srv access=wo for=two\n$SL" "could be replaced"
    ln -sf /usr/bin/python3 "$B/pyl"
    check "a server file that is a symlink to an interpreter is refused at the start (review)" \
        st no "require warden 1.31\nmcp server files exec $B/pyl\n$SL" "an interpreter or a launcher"
    check "a server an earlier exec rule decides is refused, saying so (review)" \
        st no "require warden 1.31\nallow exec $B/srv\nmcp server files exec $B/srv\n$SL" "launched by an earlier exec rule"
    check "a server that is not there is refused" \
        st no "require warden 1.31\nmcp server files exec $B/nothere\n$SL" "is not a launchable file"
    check "a confined sub-agent is checked the same way" \
        st no "require warden 1.31\nallow exec $B/srv subagent=h confined\nallow path $B/ access=rw\n$SL" "could be replaced"
fi

echo "== 3. MCP calls over HTTP: the body read, its call decided =="
WP="$(dirname "${WARDEN:-.}")/warden-proxy"
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ ! -x "$WP" ] || ! command -v openssl > /dev/null; then
    skip "section 3 (needs root, the warden, warden-proxy and openssl)"
else
    X="$(mktemp -d /tmp/varek_v1310m.XXXXXX)"; chmod 755 "$X"
    trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT ${B:-} $X" || rm -rf "$OUT" "${B:-}" "$X"' EXIT
    HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
    PS=$((43000 + RANDOM % 5000))
    ( cd "$X" &&
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tca.key -out tca.pem -days 2 \
          -subj "/CN=VAREK v1.31 test root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" &&
      openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout s.key -out s.csr -subj "/CN=mcp.example.com" &&
      printf 'subjectAltName=DNS:mcp.example.com\nextendedKeyUsage=serverAuth\n' > s.ext &&
      openssl x509 -req -in s.csr -CA tca.pem -CAkey tca.key -CAcreateserial -out s.pem -days 1 -extfile s.ext ) > "$OUT/certs3.log" 2>&1
    cat "$(python3 -c 'import ssl; print(ssl.get_default_verify_paths().openssl_cafile)')" "$X/tca.pem" > "$X/bundle.pem"
    chmod 644 "$X"/*.pem
    python3 "$HERE/tests/v1310_mcp_server.py" "$HOSTIP" "$PS" "$X/s.pem" "$X/s.key" "$OUT/got.jsonl" > "$OUT/srv.log" 2>&1 &
    SRV=$!
    DP=$((20000 + RANDOM % 20000))
    printf '{"mcp.example.com": {"ttl": 30, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/zone3.json"
    python3 "$HERE/tests/dns_test_server.py" --port "$DP" --zone "$OUT/zone3.json" --log "$OUT/q3.log" --ready "$OUT/ready3" > /dev/null 2>&1 &
    SRV="$SRV $!"
    for _ in $(seq 50); do
        [ -e "$OUT/ready3" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $PS), 0.2)" 2>/dev/null && break
        sleep 0.1
    done
    TOKV="mcp-token-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    printf '%s\n' "$TOKV" > "$X/tok"; chmod 600 "$X/tok"
    cp "$HERE/tests/v1310_mcp_agent.py" "$X/agent.py"; chmod 644 "$X/agent.py"
    U="https://mcp.example.com:$PS/mcp"
    POL="$OUT/mcp.policy"
    { printf 'require warden 1.31\nproxy inspect\nproxy ports %s\ncredential tok from file:%s/tok\n' "$PS" "$X"
      printf 'allow host mcp.example.com\n'
      printf 'allow mcp %s initialize\n' "$U"
      printf 'allow mcp %s notifications/initialized\n' "$U"
      printf 'allow mcp %s tools/list\n' "$U"
      printf 'deny mcp %s tools/call delete_*\n' "$U"
      printf 'allow mcp %s tools/call get_* credential=tok\n' "$U"
      printf 'allow mcp %s resources/read file:///projects/app/** max_body=300\n' "$U"
      printf 'allow mcp %s2 tools/list max_body=1000\n' "$U"
      printf 'allow request GET %s\n' "$U"
      printf 'allow request POST https://mcp.example.com:%s/**\n' "$PS"     # review: not for an endpoint's other spellings
      printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path exact %s/agent.py readonly\n' "$X"
    } > "$POL"
    env -i PATH=/usr/bin:/bin timeout 180 "$WARDEN" "$POL" --dns-server "127.0.0.1:$DP" --trust-bundle "$X/bundle.pem" -- \
        /usr/bin/python3 "$X/agent.py" "$PS" > "$OUT/m.out" 2> "$OUT/m.log"
    cut -c1-150 "$OUT/m.out" | sed 's/^/     /'
    said() { grep -q "^CALL $1 $2" "$OUT/m.out"; }
    said_in() { grep -q "^CALL $2 $3" "$OUT/$1.out"; }
    got() { python3 - "$OUT/got.jsonl" "$1" "${2:-1}" <<'PY'
import json, sys
n = 0
for l in open(sys.argv[1]):
    r = json.loads(l)
    n += bool(eval(sys.argv[2], {"h": r["head"], "b": r["body"], "json": json}))
sys.exit(0 if n == int(sys.argv[3] if len(sys.argv) > 3 else "1") else 1)
PY
    }
    rec() { python3 - "$OUT/m.log" "$1" <<'PY'
import json, sys
recs = [json.loads(l[l.index("{"):]) for l in open(sys.argv[1], errors="replace") if l.startswith("{")]
M = [r for r in recs if r.get("action") == "net.mcp"]
sys.exit(0 if eval(sys.argv[2], {"json": json, "R": recs, "M": M, "by": lambda i: [r for r in M if r.get("rpc_id") == i]}) else 1)
PY
    }
    for t in init list get getesc small chunked trace ctutf8; do
        check "allowed ($t): the server answered it" said "$t" "HTTP/1.1 200 OK"
    done
    check "a notification is allowed (the server's 202)" said notify "HTTP/1.1 202 Accepted"
    check "the 2025-06-18 and 2026-07-28 revisions both reached the server" \
        sh -c "grep -q '\"protocol\": \"2025-06-18\"' '$OUT/m.out' && grep -q '\"protocol\": \"2026-07-28\"' '$OUT/m.out'"
    check "a GET on the endpoint is decided by request rules (allowed)" said get_stream "HTTP/1.1 200 OK | ok"
    check "two calls on one connection: both answered, in order" \
        sh -c "grep -c '^CALL two HTTP/1.1 200 OK' '$OUT/m.out' | grep -qx 2 && grep '^CALL two' '$OUT/m.out' | head -1 | grep -q '\"id\": 18'"
    for t in delete unlisted dup batch hdrmis namemis big huge query nodeep badutf8 charset noctype gzip empty trailer upper slash; do
        check "refused ($t): 403" said "$t" "HTTP/1.1 403 Forbidden"
    done
    check "a refused call gets a JSON-RPC error with its id and code -32000" \
        sh -c "grep '^CALL delete ' '$OUT/m.out' | grep -q '\"id\":5,\"error\":{\"code\":-32000,\"message\":\"VAREK: this call was refused: the policy denies it (line 9)\"' && grep '^CALL unlisted ' '$OUT/m.out' | grep -q '\"id\":\"six\",\"error\":{\"code\":-32000'"
    check "a call that could not be read gets id null" sh -c "grep '^CALL batch ' '$OUT/m.out' | grep -q '\"id\":null,\"error\":{\"code\":-32000'"
    check "nothing refused reached the server" \
        got "'delete_repo' in b or 'other_tool' in b or '\"id\": 7' in b or b.startswith('[') or '\"id\": 9,' in b or '\"id\": 10,' in b or '\"id\": 13,' in b or '\"id\": 14,' in b or '?x=1' in h or '\"id\": 20,' in b or '\"id\": 21,' in b or any('\"id\": %d,' % i in b for i in (22, 24, 25, 26, 27, 28)) or 'Content-Length: 0' in h" 0
    check "the credential reached the server in the calls its rule allows (get, getesc, b64), as Authorization: Bearer" \
        got "'Authorization: Bearer $TOKV' in h and ('tools/call' in b or 'tools\\\\/call' in b)" 3
    check "and nowhere else" got "'$TOKV' in h + b" 3
    check "a body comes after its head intact (a chunked one with its framing)" \
        got "'Transfer-Encoding: chunked' in h and b == json.dumps({'jsonrpc': '2.0', 'id': 15, 'method': 'tools/list'})"
    check "the escaped name was decided as get_issue" \
        rec "[r['resolved'] for r in by('4')] == ['$U#tools/call#get_issue'] and by('4')[0]['decision_final'] == 'ALLOW'"
    check "each call is recorded (net.mcp): method, name, id, body length and SHA-256, protocol version" \
        rec "(lambda r: r['mcp_method'] == 'tools/call' and r['mcp_name'] == 'get_issue' and r['protocol_version'] == '2025-06-18' and r['body_len'] > 0 and len(r['body_sha256']) == 64 and r['rule'] == 'mcp_allowed' and r['credential'] == 'tok' and r['credential_header'] == 'Authorization' and r['max_body'] == 1048576 and r['check'] == 'ok')(by('3')[0])"
    check "the body's SHA-256 is of the body as sent" \
        rec "__import__('hashlib').sha256(json.dumps({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}).encode()).hexdigest() == by('2')[0]['body_sha256']"
    check "a notification is recorded as one, a string id as written" \
        rec "any(r.get('notification') is True and r['mcp_method'] == 'notifications/initialized' for r in M) and by('\"six\"')[0]['rule'] == 'default_deny_unknown'"
    check "the traceparent from _meta is recorded" rec "by('16')[0]['traceparent'] == '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'"
    check "the refusals' rules: policy_match, mcp_unreadable, mcp_header_mismatch, max_body" \
        rec "[r['rule'] for r in by('5')] == ['policy_match'] and sum(r['rule'] == 'mcp_unreadable' for r in M) == 6 and sum(r['rule'] == 'mcp_header_mismatch' for r in M) == 5 and sum(r['rule'] == 'max_body' for r in M) == 2"
    check "a body over the deciding rule's max_body: refused by that rule's limit" \
        rec "[(r['rule'], r['policy_line']) for r in by('13')] == [('max_body', 11)]"
    check "a body sent other than as UTF-8 JSON is refused: a charset, no Content-Type, a Content-Encoding (review)" \
        rec "[r.get('mcp_error') for r in M if r['rule'] == 'mcp_header_mismatch' and r['decision_final'] == 'DENY'].count('the Content-Type is not application/json in UTF-8') == 2 and sum(r.get('mcp_error') == 'the body has a Content-Encoding' for r in M) == 1 and by('23')[0]['rule'] == 'mcp_allowed'"
    check "an empty body is refused at once, and a chunked body with trailers (review)" \
        rec "any(r['rule'] == 'mcp_unreadable' and r.get('mcp_error') == 'not one JSON-RPC call: an empty body' for r in M) and any(r['rule'] == 'mcp_unreadable' and r.get('mcp_error') == 'a chunked body with trailers' for r in M)"
    check "a POST to another spelling of the endpoint (its case, a trailing /) is refused, not decided by a request rule (review)" \
        rec "sorted(r['target'].rsplit('/', 1)[1] if not r['target'].endswith('/') else '/' for r in R if r.get('action') == 'net.request' and r.get('rule') == 'mcp_endpoint_variant' and r['decision_final'] == 'DENY') == ['/', 'MCP']"
    check "a POST with a query to the endpoint is refused (net.request, mcp_query)" \
        rec "any(r.get('action') == 'net.request' and r['rule'] == 'mcp_query' and '?x=1' in r['target'] for r in R)"
    check "no call's value is in the verdict stream" sh -c "! grep -qF -- '$TOKV' '$OUT/m.log'"
    AUD="$HERE/tools/varek_audit.py"
    check "the audit accepts the run" python3 "$AUD" --policy "$POL" --checker "$CERT" "$OUT/m.log"
    F="$HERE/tests/v1270_forge.py"
    refuses() { if python3 "$AUD" --policy "$2" --checker "$CERT" "$3" > "$OUT/f.out" 2>&1; then flunk "the audit refuses $1"
                elif grep -qF -- "$4" "$OUT/f.out"; then pass "the audit refuses $1"
                else flunk "the audit refuses $1 ($(grep -m1 PROBLEM "$OUT/f.out"))"; fi; }
    G='g = next(r for r in recs if isinstance(r, dict) and r.get("action") == "net.mcp" and r.get("rpc_id") == "3")'
    python3 "$F" "$OUT/m.log" "$OUT/g1.log" "$G; g['target'] = g['resolved'] = g['resolved'].replace('get_issue', 'delete_repo')"
    refuses "an allowed call passed off as another" "$POL" "$OUT/g1.log" "refused"
    python3 "$F" "$OUT/m.log" "$OUT/g2.log" "$G; g['max_body'] = 99"
    refuses "an allowed call whose max_body is not its rule's" "$POL" "$OUT/g2.log" "whose max_body is not its rule's"
    python3 "$F" "$OUT/m.log" "$OUT/g3.log" "$G; g['action'] = 'net.request'; g['rule'] = 'request_allowed'; g['target'] = g['resolved'] = 'POST $U'; g['body'] = 'length'; g['body_declared'] = g['body_len']"
    refuses "a POST to the endpoint recorded as a request" "$POL" "$OUT/g3.log" "decided as a request, not as an MCP call"
    python3 "$F" "$OUT/m.log" "$OUT/g4.log" "$G; del g['credential'], g['credential_header']"
    refuses "an allowed call without the credential its rule names" "$POL" "$OUT/g4.log" "recorded without it"
    python3 "$F" "$OUT/m.log" "$OUT/g5.log" "g = next(r for r in recs if isinstance(r, dict) and r.get('action') == 'net.mcp' and r.get('rpc_id') == '5'); g['rule'] = 'default_deny_unknown'"
    refuses "a call refused as matching no rule that a deny rule decides" "$POL" "$OUT/g5.log" "but policy line 9 matches it"
    python3 "$F" "$OUT/m.log" "$OUT/g6.log" "$G; g['mcp_url'] = 'https://mcp.example.com:$PS/other'"
    refuses "a call to a URL that is not an MCP endpoint" "$POL" "$OUT/g6.log" "which is not an MCP endpoint"
    # a credential for= a confined MCP server: released only into its calls
    if [ ! -x "$SUBP" ] || [ -z "$CGM" ]; then
        skip "a credential for= an MCP server (needs tests/v1281_sub and a cgroup2 mount)"
    else
        cp "$SUBP" "$X/srv"; cp "$SUBP" "$X/sagent"; chmod 755 "$X/srv" "$X/sagent"
        PYR="$(readlink -f /usr/bin/python3)"
        SLX='allow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\nallow path exact '"$X"'/agent.py readonly\n'
        POLF="$OUT/mcpf.policy"
        { printf 'require warden 1.31\nproxy inspect\nproxy ports %s\ncredential tok from file:%s/tok\n' "$PS" "$X"
          printf 'mcp server files exec %s/srv\nallow exec %s for=files\n' "$X" "$PYR"
          printf 'allow host mcp.example.com\nallow host mcp.example.com for=files\n'
          printf 'allow mcp %s tools/list\n' "$U"
          printf 'allow mcp %s tools/call get_* credential=tok for=files\n' "$U"
          printf '%b' "$SLX"; printf '%b' "$SLX" | sed 's/$/ for=files/'
        } > "$POLF"
        : > "$OUT/got.jsonl"
        env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$POLF" --dns-server "127.0.0.1:$DP" --trust-bundle "$X/bundle.pem" -- \
            "$PYR" "$X/agent.py" "$PS" server > "$OUT/f1.out" 2> "$OUT/f1.log"
        env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$POLF" --dns-server "127.0.0.1:$DP" --trust-bundle "$X/bundle.pem" -- \
            "$X/sagent" spawn "$X/agent.py" "$X/srv" exec "$PYR" "$X/agent.py" "$PS" server > "$OUT/f2.out" 2> "$OUT/f2.log"
        sed 's/^/     /' "$OUT/f1.out" "$OUT/f2.out"
        check "the agent's own call, which only the server's rule allows, is refused" said_in f1 server "HTTP/1.1 403 Forbidden"
        check "the server's call is allowed, and carries the credential its rule names" \
            sh -c "grep -q '^CALL server HTTP/1.1 200 OK' '$OUT/f2.out' && [ \"\$(grep -c 'Bearer $TOKV' '$OUT/got.jsonl')\" = 1 ]"
        check "the server's call is recorded as its own (its chain, certificate subject 1, the credential)" \
            python3 -c "import json,sys
M = [json.loads(l) for l in open('$OUT/f2.log') if l.startswith('{') and '\"net.mcp\"' in l]
sys.exit(0 if len(M) == 1 and M[0]['obo'] == ['agent', 'subagent:files#1'] and M[0].get('cert_subject') == 1 and M[0]['credential'] == 'tok' else 1)"
        check "the audit accepts both runs" sh -c "python3 '$AUD' --policy '$POLF' --checker '$CERT' '$OUT/f1.log' > /dev/null && python3 '$AUD' --policy '$POLF' --checker '$CERT' '$OUT/f2.log' > /dev/null"
    fi
fi

echo "== 4. MCP tokens: the run's, the agent's, and the user found through MCP =="
SECRETS="$(dirname "${WARDEN:-/nonexistent}")/warden-secrets"
if [ -z "${PS:-}" ] || [ ! -x "$SECRETS" ] || ! python3 -c 'import cryptography' 2>/dev/null; then
    skip "section 4 (needs section 3's servers, warden-secrets and python3-cryptography)"
else
    A="$(mktemp -d /tmp/varek_v1310a.XXXXXX)"; chmod 755 "$A"
    python3 "$HERE/tests/v1310_as.py" serve "$A" > "$A/serve.out" 2>&1 &
    SRV="$SRV $!"
    trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT ${B:-} $X $A" || rm -rf "$OUT" "${B:-}" "$X" "$A"' EXIT
    for _ in $(seq 100); do [ -f "$A/port" ] && break; sleep 0.1; done
    AP="$(cat "$A/port")"; AB="https://localhost:$AP"
    chmod 644 "$A/ca.pem"
    printf 'oidc_ca = %s/ca.pem\n' "$A" > "$A/conf"; chmod 600 "$A/conf"
    tok() { python3 "$HERE/tests/v1310_as.py" mint "$A" "$@"; }
    put() { printf '%s\n' "$2" > "$1"; chmod 600 "$1"; }
    LIBS='allow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\n'
    # g4 <name> <policy text> [warden options]: a run of /usr/bin/true
    g4() { local n="$1"; printf '%b' "$2" > "$OUT/$n.pol"; shift 2
           timeout 90 "$WARDEN" "$OUT/$n.pol" --secrets-conf "$A/conf" --dns-server "127.0.0.1:$DP" \
               --trust-bundle "$X/bundle.pem" "$@" -- /usr/bin/true > "$OUT/$n.out" 2>&1; echo $? > "$OUT/$n.rc"; }
    ok4() { grep -qx 0 "$OUT/$1.rc"; }
    no4() { ! grep -qx 0 "$OUT/$1.rc" && grep -qF -- "$2" "$OUT/$1.out"; }
    rs4() { python3 -c 'import json,sys
for l in open(sys.argv[1]):
    if l.startswith("{\"event\":\"run_start\""): sys.exit(0 if eval(sys.argv[2], {"r": json.loads(l)}) else 1)
sys.exit(1)' "$OUT/$1.out" "$2"; }
    # the run's MCP token (audience=), checked when it is fetched
    FT="require warden 1.31\nproxy inspect\nproxy ports $PS\ncredential mt from file:$X/mt audience=$U\nallow host mcp.example.com\nallow mcp $U tools/call get_* credential=mt\n$LIBS"
    put "$X/mt" "$(tok "$AB/as" "$U" 3600)"
    g4 ft_ok "$FT"
    check "an MCP token for its server, not near expiry: fetched, the run starts" ok4 ft_ok
    check "run_start lists it with its server and its expiry (never its value)" \
        rs4 ft_ok "[(c['audience'], type(c.get('expires'))) for c in r['credentials']] == [('$U', int)]"
    put "$X/mt" "$(tok "$AB/as" "https://mcp.example.com/mcp" 3600)"
    g4 ft_aud "$FT"
    check "an MCP token for another server (the port left out of a URL that needs it) is refused" no4 ft_aud "does not name $U"
    put "$X/mt" "$(tok "$AB/as" "$U" -60)"
    g4 ft_exp "$FT"
    check "an expired MCP token is refused" no4 ft_exp "it expired"
    put "$X/mt" "$(tok "$AB/as" "$U" 30)"
    g4 ft_near "$FT"
    check "an MCP token expiring in under 60 s is refused" no4 ft_near "under 60 s"
    put "$X/mt" "$(tok "$AB/as" "$U" -)"
    g4 ft_noexp "$FT"
    check "an MCP token without an expiry is refused" no4 ft_noexp "without an expiry"
    put "$X/mt" "opaque-mcp-token-0123456789"
    g4 ft_opq "$FT"
    check "an opaque MCP token, its line not saying opaque, is refused" no4 ft_opq "does not say opaque"
    g4 ft_opq2 "$(printf '%s' "$FT" | sed "s|audience=$U|audience=$U opaque|")"
    check "... and with opaque: fetched, listed as opaque, no expiry" \
        sh -c "$(declare -f ok4 rs4); OUT='$OUT'; ok4 ft_opq2 && rs4 ft_opq2 \"r['credentials'][0].get('opaque') is True and 'expires' not in r['credentials'][0]\""
    put "$X/mt" "$(tok "$AB/as" "https://mcp.example.com/mcp" 3600)"
    g4 ft_opq3 "$(printf '%s' "$FT" | sed "s|audience=$U|audience=$U opaque|")"
    check "an opaque line whose value is a JWT for another server: still checked, refused (review)" no4 ft_opq3 "does not name $U"
    # the user, found through an MCP server's metadata
    MR="require warden 1.31\ntrust mcp-resource $AB/mcp\n$LIBS"
    put "$A/utok" "$(tok "$AB/as" "$AB/mcp" 3600)"
    g4 mr_as "$MR" --on-behalf-of "$A/utok"
    check "a user token from an authorization server the resource's metadata names (RFC 9728, RFC 8414): verified" ok4 mr_as
    check "run_start names the issuer found, the resource it was found through, and its URL as the audience" \
        rs4 mr_as "(lambda u: (u['issuer'], u['mcp_resource'], u['audience'], u['policy_line']))(r['on_behalf_of']['user']) == ('$AB/as', '$AB/mcp', '$AB/mcp', 2)"
    check "the audit accepts it" python3 "$HERE/tools/varek_audit.py" --policy "$OUT/mr_as.pol" --checker "$CERT" "$OUT/mr_as.out"
    put "$A/utok" "$(tok "$AB/oidc" "$AB/mcp" 3600)"
    g4 mr_oidc "$MR" --on-behalf-of "$A/utok"
    check "... from one with OpenID discovery only: verified" ok4 mr_oidc
    put "$A/utok" "$(tok "$AB/liar" "$AB/mcp" 3600)"
    g4 mr_liar "$MR" --on-behalf-of "$A/utok"
    check "metadata whose issuer is not the identifier it was fetched for: refused" no4 mr_liar "$AB/liar: its metadata names another issuer"
    put "$A/utok" "$(tok "$AB/as" "$AB/other" 3600)"
    g4 mr_aud "$MR" --on-behalf-of "$A/utok"
    check "a user token for another audience: refused" no4 mr_aud "does not hold $AB/mcp"
    put "$A/utok" "$(tok "$AB/as2" "$AB/bad" 3600)"
    g4 mr_bad "require warden 1.31\ntrust mcp-resource $AB/bad\n$LIBS" --on-behalf-of "$A/utok"
    check "resource metadata naming another resource: its servers are not trusted" no4 mr_bad "names another resource"
    put "$A/utok" "$(tok "$AB/as" "api://mcp-tools" 3600)"
    g4 mr_audline "require warden 1.31\ntrust mcp-resource $AB/mcp audience api://mcp-tools\n$LIBS" --on-behalf-of "$A/utok"
    check "with the line's audience: a token for it is verified" \
        sh -c "$(declare -f ok4 rs4); OUT='$OUT'; ok4 mr_audline && rs4 mr_audline \"r['on_behalf_of']['user']['audience'] == 'api://mcp-tools'\""
    F4="$HERE/tests/v1270_forge.py"; AUD4="$HERE/tools/varek_audit.py"
    python3 "$F4" "$OUT/mr_as.out" "$OUT/g41.log" "u = next(r for r in recs if isinstance(r, dict) and r.get('event') == 'run_start')['on_behalf_of']['user']; u['mcp_resource'] = 'https://localhost:1/x'"
    check "the audit refuses a user found through a resource the policy does not trust" \
        sh -c "! python3 '$AUD4' --policy '$OUT/mr_as.pol' --checker '$CERT' '$OUT/g41.log' > '$OUT/g41.aud' 2>&1 && grep -q 'which the policy does not trust' '$OUT/g41.aud'"
    # the agent's own bearer tokens, and the run's MCP token on its calls only
    MTV="$(tok "$AB/as" "$U" 3600)"; put "$X/mt" "$MTV"
    put "$A/utok" "$(tok "$AB/as" "$AB/mcp" 3600)"
    python3 - "$X/toks.json" "$(tok "$AB/as" "$U" 600)" "$(tok "$AB/as" "https://mcp.example.com:$PS/other" 600)" \
        "$(tok "$AB/as" "$U" -60)" "$(cat "$A/utok")" <<'PY'
import base64, json, sys
b = lambda s: base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()
# v1.31 review: the user's token signed again (ECDSA's other s: n - s, a
# valid signature its server's library accepts), and lenient spellings a
# server would read as the token: padding, a tab after the scheme, DPoP
u = sys.argv[5]
h, p, sg = u.split(".")
raw = base64.urlsafe_b64decode(sg + "=" * (-len(sg) % 4))
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
s2 = (N - int.from_bytes(raw[32:], "big")).to_bytes(32, "big")
u2 = h + "." + p + "." + base64.urlsafe_b64encode(raw[:32] + s2).rstrip(b"=").decode()
json.dump({"t_good": sys.argv[2], "t_other": sys.argv[3], "t_expired": sys.argv[4], "t_opaque": "opaque-abc-123",
           "t_malformed": b('{"alg":"ES256"}') + "." + b('{"aud":"a","aud":"b"}') + ".c2ln", "t_user": u,
           "t_user_s": u2, "t_other_pad": sys.argv[3] + "==", "t_expired_pad": sys.argv[4] + "==", "t_user_pad": u + "==",
           "t_other_tab": "HDR:Bearer\t" + sys.argv[3], "t_other_dpop": "HDR:DPoP " + sys.argv[3]},
          open(sys.argv[1], "w"))
PY
    chmod 644 "$X/toks.json"
    POL4="$OUT/tok.policy"
    { printf 'require warden 1.31\nproxy inspect\nproxy ports %s\ncredential mt from file:%s/mt audience=%s\n' "$PS" "$X" "$U"
      printf 'trust mcp-resource %s/mcp\nallow host mcp.example.com\n' "$AB"
      printf 'allow mcp %s tools/call get_* credential=mt\nallow mcp %s tools/list\n' "$U" "$U"
      printf 'allow mcp https://mcp.example.com:%s/other tools/list\nallow request GET https://mcp.example.com:%s/plain\n' "$PS" "$PS"
      printf '%b' "$LIBS"; printf 'allow path exact %s/agent.py readonly\nallow path exact %s/toks.json readonly\n' "$X" "$X"
    } > "$POL4"
    : > "$OUT/got.jsonl"
    env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$POL4" --secrets-conf "$A/conf" --on-behalf-of "$A/utok" \
        --dns-server "127.0.0.1:$DP" --trust-bundle "$X/bundle.pem" -- \
        /usr/bin/python3 "$X/agent.py" "$PS" tokens "$X/toks.json" > "$OUT/t4.out" 2> "$OUT/t4.log"
    cut -c1-150 "$OUT/t4.out" | sed 's/^/     /'
    for t in t_good t_opaque ph_get ph_other ph_plain; do check "allowed ($t)" said_in t4 "$t" "HTTP/1.1 200 OK"; done
    for t in t_other t_expired t_malformed t_user t_user_s t_other_pad t_expired_pad t_user_pad t_other_tab t_other_dpop; do
        check "refused ($t): 403" said_in t4 "$t" "HTTP/1.1 403 Forbidden"; done
    r4() { python3 -c 'import json,sys
M = {}
for l in open(sys.argv[1], errors="replace"):
    if l.startswith("{") and "\"net.mcp\"" in l:
        r = json.loads(l); M.setdefault(r.get("rpc_id"), []).append(r)
sys.exit(0 if eval(sys.argv[2], {"M": M}) else 1)' "$OUT/t4.log" "$1"; }
    check "the refusals' rules: another audience, expired, malformed, the user's token" \
        r4 "sorted(r['rule'] for r in M['30'] if r['decision_final'] == 'DENY') == ['mcp_token_audience'] * 3 + ['mcp_token_expired'] + ['mcp_token_malformed'] * 4 + ['mcp_token_user'] * 2"
    check "... the user's token signed again is the user's; padding is malformed; a tab or DPoP is still the bearer token (review)" \
        r4 "len(M['30']) == 12"
    check "each call records what kind of token it carried, never the token" \
        r4 "sorted(r['token'] for r in M['30']) == ['jwt'] * 7 + ['malformed'] * 4 + ['opaque'] and all(r['token'] == 'placeholder' for r in M['31'] + M['32'])"
    check "the run's MCP token reached the server once: in the call its rule names" \
        sh -c "[ \"\$(grep -c -- '$MTV' '$OUT/got.jsonl')\" = 1 ] && grep -- '$MTV' '$OUT/got.jsonl' | grep -q 'tools/call'"
    check "... not on another MCP endpoint or a plain request (they got the placeholder)" \
        sh -c "grep '/other' '$OUT/got.jsonl' | grep -q 'Bearer varek_ph_mt_' && grep 'GET /plain' '$OUT/got.jsonl' | grep -q 'Bearer varek_ph_mt_'"
    check "no token value is in the verdict stream (the run's, the user's, the agent's)" \
        python3 -c "import json,sys; log = open('$OUT/t4.log').read(); vals = list(json.load(open('$X/toks.json')).values()) + ['$MTV', open('$A/utok').read().strip()]; sys.exit(1 if any(v in log for v in vals) else 0)"
    check "the audit accepts the run" python3 "$HERE/tools/varek_audit.py" --policy "$POL4" --checker "$CERT" "$OUT/t4.log"
    python3 "$F4" "$OUT/t4.log" "$OUT/g42.log" "g = next(r for r in recs if isinstance(r, dict) and r.get('rule') == 'mcp_token_audience'); g['token'] = 'placeholder'"
    check "the audit refuses a token refusal on a call that carried no token of that kind" \
        sh -c "! python3 '$AUD4' --policy '$POL4' --checker '$CERT' '$OUT/g42.log' > '$OUT/g42.aud' 2>&1 && grep -q 'is not one its rule' '$OUT/g42.aud'"
fi

echo "== 5. the OCSF export =="
OX="$HERE/tools/varek_ocsf.py"; OV="$HERE/tests/ocsf_validate.py"
if [ ! -f "$OUT/m.log" ] || [ ! -f "$HERE/schemas/ocsf-1.9.0/schema.json" ]; then
    skip "section 5 (needs section 3's streams and the vendored schema)"
else
    oex() { python3 "$OX" --policy "$2" --checker "$CERT" --device testhost --log "$1" -o "$3" > "$3.err" 2>&1; }
    # ev <events> <python on E, the events>
    ev() { python3 -c 'import json,sys
E = [json.loads(l) for l in open(sys.argv[1])]
V = [e["unmapped"]["varek"] for e in E]
sys.exit(0 if eval(sys.argv[2], {"E": E, "V": V}) else 1)' "$1" "$2"; }
    check "a stream with files, processes, connections, requests and MCP calls exports" oex "$OUT/m.log" "$POL" "$OUT/m.ev"
    check "every event is valid OCSF 1.9.0 (the vendored schema, no network)" python3 "$OV" "$OUT/m.ev"
    check "each decision record is one event, a rename's second half folded into its first" \
        python3 -c "import json,sys
R = [json.loads(l) for l in open('$OUT/m.log') if l.startswith('{\"report_id\"')]
E = [json.loads(l) for l in open('$OUT/m.ev')]
ids = [e['unmapped']['varek'].get('report_id') for e in E if 'report_id' in e['unmapped']['varek']]
want = [r['report_id'] for r in R if r['action'] != 'file.rename_to']
sys.exit(0 if ids == want else 1)"
    check "each event names its record's seq and chain value, and the run (correlation_uid)" \
        ev "$OUT/m.ev" "all(v['chain'] and len(v['chain']) == 64 for v in V[:-1]) and len({e['metadata']['correlation_uid'] for e in E}) == 1"
    check "the classes: file, process, network, HTTP, API (MCP) and lifecycle" \
        ev "$OUT/m.ev" "{1001, 1007, 4001, 4002, 6003, 6002} <= {e['class_uid'] for e in E}"
    check "an MCP tools/call is API Activity Other, with its tool; a tools/list is Read" \
        ev "$OUT/m.ev" "any(e['class_uid'] == 6003 and e['activity_id'] == 99 and e['api']['operation'] == 'tools/call' and e['resources'][0]['name'] == 'get_issue' for e in E) and any(e['class_uid'] == 6003 and e['activity_id'] == 2 and e['api']['operation'] == 'tools/list' for e in E)"
    check "an HTTP request is HTTP Activity by its method (the GET on the endpoint, the POST with a query)" \
        ev "$OUT/m.ev" "any(e['class_uid'] == 4002 and e['activity_id'] == 3 and e['action_id'] == 1 for e in E) and any(e['class_uid'] == 4002 and e['activity_id'] == 6 and e['disposition_id'] == 2 for e in E)"
    check "UNKNOWN is kept: refused (Denied, Blocked) and unmapped.varek.decision UNKNOWN" \
        ev "$OUT/m.ev" "any(v.get('decision') == 'UNKNOWN' and e['action_id'] == 2 and e['disposition_id'] == 2 for e, v in zip(E, V))"
    check "a refusal by a deny rule is UNSATISFIED, with the deciding line's text as the policy's desc" \
        ev "$OUT/m.ev" "any(v.get('decision') == 'UNSATISFIED' and e['policy']['desc'].startswith('deny mcp') for e, v in zip(E, V))"
    check "the last event is the audit's verdict: passed" ev "$OUT/m.ev" "V[-1]['event'] == 'audit' and V[-1]['audit']['passed'] is True"
    [ -f "$OUT/t4.log" ] && oex "$OUT/t4.log" "$POL4" "$OUT/t4.ev"
    [ -f "$OUT/t4.log" ] && check "a run on behalf of a user: actor.user, actor.idp and the delegation (the token's SHA-256, its issuer)" \
        sh -c "python3 '$OV' '$OUT/t4.ev' > /dev/null && $(declare -f ev); ev '$OUT/t4.ev' \"all(e['actor']['user']['uid'] == 'alice@example.test' and e['actor']['idp']['uid'] == '$AB/as' and e['delegation']['issuer_uid'] == '$AB/as' and len(e['delegation']['uid']) == 64 for e in E if 'actor' in e)\""
    if [ -f "$OUT/f2.log" ]; then
        oex "$OUT/f2.log" "$POLF" "$OUT/f2.ev"
        check "an MCP server's events name it in ai_agent (type mcp_server), the agent's the agent" \
            sh -c "python3 '$OV' '$OUT/f2.ev' > /dev/null && $(declare -f ev); ev '$OUT/f2.ev' \"any(e.get('ai_agent', {}).get('type') == 'mcp_server' and e['ai_agent']['name'] == 'files' for e in E) and any(e.get('ai_agent', {}).get('name') == 'sagent' and e['ai_agent']['type'] == 'Other' for e in E)\""
    fi
    # the link back, checked
    check "--verify: the events are the stream's" python3 "$OX" --verify "$OUT/m.ev" --log "$OUT/m.log" --policy "$POL" --checker "$CERT"
    python3 - "$OUT/m.ev" "$OUT" <<'PY'
import json, sys
L = open(sys.argv[1]).read().splitlines()
d = sys.argv[2]
# an event's decision changed, whatever it was (which event is 20th depends on
# the architecture: what the agent does at startup differs)
e = json.loads(L[20]); v = e["unmapped"]["varek"]
v["decision"] = "UNSATISFIED" if v.get("decision") == "SATISFIED" else "SATISFIED"
e["action_id"] = 2 if e.get("action_id") == 1 else 1
open(d + "/m_edit.ev", "w").write("\n".join(L[:20] + [json.dumps(e)] + L[21:]) + "\n")
open(d + "/m_drop.ev", "w").write("\n".join(L[:20] + L[21:]) + "\n")
open(d + "/m_swap.ev", "w").write("\n".join(L[:20] + [L[21], L[20]] + L[22:]) + "\n")
open(d + "/m_cut.ev", "w").write("\n".join(L[:-1]) + "\n")
PY
    for f in edit drop swap cut; do
        check "--verify finds an event $f (events: ${f}ed)" sh -c "! python3 '$OX' --verify '$OUT/m_$f.ev' --log '$OUT/m.log' --policy '$POL' --checker '$CERT' > '$OUT/v_$f.out' 2>&1"
    done
    sed '0,/"action":"net.mcp"/s/"rule":"mcp_allowed"/"rule":"mcp_allowed "/' "$OUT/m.log" > "$OUT/m_broken.log"
    # review: a forged stream, followed (a failed verdict), its verdict then edited to passed
    python3 "$HERE/tests/v1270_forge.py" "$OUT/m.log" "$OUT/x1.log" "g = next(r for r in recs if isinstance(r, dict) and r.get('action') == 'net.mcp' and r.get('rule') == 'policy_match'); g.update(decision_raw='ALLOW', decision_final='ALLOW', rule='mcp_allowed')"
    python3 "$OX" --policy "$POL" --checker "$CERT" --follow "$OUT/x1.log" > "$OUT/x1.ev" 2> /dev/null
    python3 -c 'import json,sys
L = open(sys.argv[1]).read().splitlines(); e = json.loads(L[-1]); e["unmapped"]["varek"]["audit"].update(passed=True, problems=[]); e.pop("severity_id"); e.pop("severity")
open(sys.argv[2], "w").write("\n".join(L[:-1] + [json.dumps(e, separators=(",", ":"))]) + "\n")' "$OUT/x1.ev" "$OUT/x1f.ev"
    check "--verify audits the stream: a forged one's events, the verdict edited to passed, are refused (review)" \
        sh -c "grep -q '\"passed\":false' '$OUT/x1.ev' && ! python3 '$OX' --verify '$OUT/x1f.ev' --log '$OUT/x1.log' --policy '$POL' --checker '$CERT' > '$OUT/x1v.out' 2>&1 && grep -q 'the audit refuses the stream' '$OUT/x1v.out'"
    python3 -c 'import json,sys
L = open(sys.argv[1]).read().splitlines(); e = json.loads(L[-1]); e["unmapped"]["varek"]["audit"]["not_enforced"] = True
open(sys.argv[2], "w").write("\n".join(L[:-1] + [json.dumps(e, separators=(",", ":"))]) + "\n")' "$OUT/m.ev" "$OUT/m_verdict.ev"
    check "--verify compares the verdict event too: an edited one is refused (review)" \
        sh -c "! python3 '$OX' --verify '$OUT/m_verdict.ev' --log '$OUT/m.log' --policy '$POL' --checker '$CERT' > '$OUT/mv.out' 2>&1 && grep -q 'verdict event is not the one' '$OUT/mv.out'"
    check "a stream edited after the fact: not exported, and --verify refuses it (its chain)" \
        sh -c "! python3 '$OX' --policy '$POL' --checker '$CERT' --log '$OUT/m_broken.log' -o '$OUT/b.ev' > /dev/null 2>&1 && [ ! -s '$OUT/b.ev' ] && ! python3 '$OX' --verify '$OUT/m.ev' --log '$OUT/m_broken.log' --policy '$POL' --checker '$CERT' > /dev/null 2>&1"
    python3 "$HERE/tests/v1270_forge.py" "$OUT/m.log" "$OUT/m_forged.log" "g = next(r for r in recs if isinstance(r, dict) and r.get('action') == 'net.mcp' and r.get('rule') == 'policy_match'); g['decision_final'] = 'ALLOW'; g['rule'] = 'mcp_allowed'"
    check "a stream the audit refuses (rechained, so its chain holds) is not exported" \
        sh -c "! python3 '$OX' --policy '$POL' --checker '$CERT' --log '$OUT/m_forged.log' -o '$OUT/fg.ev' > '$OUT/fg.out' 2>&1 && grep -q 'the audit refuses this stream' '$OUT/fg.out' && [ ! -s '$OUT/fg.ev' ]"
    # a dry run: would-be refusals are Detected, never Blocked
    D5="$(mktemp -d /tmp/varek_v1310d.XXXXXX)"; chmod 755 "$D5"
    printf 'import os\nfor p in ("/etc/hostname", "/etc/passwd"):\n    try: open(p).read()\n    except OSError: pass\nimport socket\ntry: socket.getaddrinfo("unlisted.example.org", 443)\nexcept OSError: pass\n' > "$D5/a.py"; chmod 644 "$D5/a.py"
    printf 'require warden 1.31\nallow host mcp.example.com\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\nallow path exact %s/a.py readonly\nallow path exact /etc/hostname readonly\n' "$D5" > "$D5/p.txt"
    timeout 60 "$WARDEN" "$D5/p.txt" --dry-run --run-as nobody --dns-server "127.0.0.1:$DP" -- /usr/bin/python3 "$D5/a.py" > /dev/null 2> "$D5/d.log"
    oex "$D5/d.log" "$D5/p.txt" "$D5/d.ev"
    check "a dry run exports, valid" python3 "$OV" "$D5/d.ev"
    check "a dry run's would-be refusals: Denied, Detected (15), mode dry_run; none Blocked" \
        ev "$D5/d.ev" "any(v.get('mode') == 'dry_run' for v in V) and all(e['action_id'] == 2 and e['disposition_id'] == 15 for e, v in zip(E, V) if v.get('mode') == 'dry_run') and not any(e.get('disposition_id') == 2 and v.get('record', {}).get('enforced') is False for e, v in zip(E, V))"
    check "a name no rule covers, asked of the stub: DNS Activity Query, its name" \
        ev "$D5/d.ev" "any(e['class_uid'] == 4003 and e['query']['hostname'] == 'unlisted.example.org' and e['action_id'] == 2 for e in E)"
    # --follow: each event as its record is chained, the audit at run_end
    printf 'import time\nfor i in range(3):\n    open("/etc/hostname").read(); time.sleep(0.3)\n' > "$D5/f.py"; chmod 644 "$D5/f.py"
    sed -i "s|exact $D5/a.py|exact $D5/f.py|" "$D5/p.txt"
    python3 "$OX" --follow "$D5/live.log" --policy "$D5/p.txt" --checker "$CERT" --device testhost --idle 20 -o "$D5/live.ev" > "$D5/fo.out" 2>&1 &
    FP=$!
    sleep 0.5
    timeout 60 "$WARDEN" "$D5/p.txt" --run-as nobody -- /usr/bin/python3 "$D5/f.py" > /dev/null 2> "$D5/live.log"
    wait $FP; echo $? > "$D5/fo.rc"
    oex "$D5/live.log" "$D5/p.txt" "$D5/live_b.ev"
    check "--follow on a live run: the same events as the batch export, then the audit's verdict (passed)" \
        python3 -c "import json,sys
F = [json.loads(l) for l in open('$D5/live.ev')]; B = [json.loads(l) for l in open('$D5/live_b.ev')]
sys.exit(0 if F[:-1] == B[:-1] and F[-1]['unmapped']['varek']['audit'] == {'passed': True, 'mode': 'follow', 'problems': []} and open('$D5/fo.rc').read().strip() == '0' else 1)"
    grep -v '^{"event":"run_end"' "$D5/live.log" > "$D5/early.src"
    : > "$D5/early.log"
    python3 "$OX" --follow "$D5/early.log" --policy "$D5/p.txt" --checker "$CERT" --device testhost --idle 2 -o "$D5/early.ev" > /dev/null 2>&1 &
    FP=$!
    sleep 0.3; cat "$D5/early.src" >> "$D5/early.log"
    wait $FP; echo $? > "$D5/early.rc"
    check "--follow on a run that ends early (no run_end): the last event says the audit did not pass" \
        sh -c "! grep -qx 0 '$D5/early.rc' && $(declare -f ev); ev '$D5/early.ev' \"V[-1]['audit']['passed'] is False and 'stopped growing' in V[-1]['audit']['problems'][0]\""
    check "varek export --format ocsf (and --verify) through the CLI" \
        sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' export --format ocsf '$D5/live.log' --policy '$D5/p.txt' -o '$D5/cli.ev' > '$D5/cli.out' 2>&1 && NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' export --format ocsf --verify '$D5/cli.ev' '$D5/live.log' --policy '$D5/p.txt' >> '$D5/cli.out' 2>&1"
    [ -n "${KEEP:-}" ] || rm -rf "$D5"
fi

echo "== 6. audit and tools: MCP servers, their rules, calls and tokens =="
V7="$HERE/tools/varek"; AUD7="$HERE/tools/varek_audit.py"; F7="$HERE/tests/v1270_forge.py"
if [ ! -f "$OUT/own.out" ] || [ ! -f "$OUT/m.log" ]; then
    skip "section 6 (needs sections 2 and 3's streams)"
else
    v7() { NO_COLOR=1 VAREK_CONFIG="${VC:-/nonexistent}" python3 "$V7" "$@"; }
    refuses7() { if python3 "$AUD7" --policy "$2" --checker "$CERT" "$3" > "$OUT/f7.out" 2>&1; then flunk "the audit refuses $1"
                 elif grep -qF -- "$4" "$OUT/f7.out"; then pass "the audit refuses $1"
                 else flunk "the audit refuses $1 ($(grep -m1 PROBLEM "$OUT/f7.out"))"; fi; }
    LA="$(grep -n "^allow path $B/fa readonly\$" "$B/p.txt" | cut -d: -f1)"
    LS="$(grep -n "^allow path $B/fs readonly for=files\$" "$B/p.txt" | cut -d: -f1)"
    python3 "$F7" "$OUT/own.out" "$OUT/h1.log" "g = next(r for r in recs if isinstance(r, dict) and r.get('cert_subject') == 1 and r.get('target') == '$B/fs'); g['policy_line'] = $LA"
    refuses7 "a server's decision citing one of the agent's rules" "$B/p.txt" "$OUT/h1.log" "cites policy line $LA, a rule for subject 0"
    python3 "$F7" "$OUT/own.out" "$OUT/h2.log" "g = next(r for r in recs if isinstance(r, dict) and r.get('target') == '$B/fa' and r.get('obo') == ['agent']); g['policy_line'] = $LS"
    refuses7 "an agent's decision citing a server's rule (for=)" "$B/p.txt" "$OUT/h2.log" "cites policy line $LS, a rule for subject 1"
    python3 "$F7" "$OUT/m.log" "$OUT/h3.log" "c = next(r for r in recs if isinstance(r, dict) and r.get('action') == 'net.mcp')['proxy_conn']; [r.update(inspected=False) for r in recs if isinstance(r, dict) and r.get('action') == 'net.proxy' and r.get('proxy_conn') == c]"
    refuses7 "an MCP call on a connection not inspected (passthrough)" "$POL" "$OUT/h3.log" "which was not passed on to be inspected"
    if [ -f "$OUT/t4.log" ]; then
        python3 "$F7" "$OUT/t4.log" "$OUT/h4.log" "g = next(r for r in recs if isinstance(r, dict) and r.get('action') == 'net.mcp' and r.get('credential') == 'mt'); g['mcp_url'] = 'https://mcp.example.com:$PS/other'"
        refuses7 "an MCP token released on a call to another server" "$POL4" "$OUT/h4.log" "(for $U) released on a call to https://mcp.example.com:$PS/other"
    fi
    python3 "$F7" "$OUT/own.out" "$OUT/h5.log" "next(r for r in recs if isinstance(r, dict) and r.get('event') == 'run_start')['note'] = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl'"
    refuses7 "a token value in the stream" "$B/p.txt" "$OUT/h5.log" "a token value in the stream (field 'note')"
    # review: forged shapes the audit refuses (or once crashed on)
    G8="g = next(r for r in recs if isinstance(r, dict) and r.get('cert_subject') == 1 and r.get('target') == '$B/fs')"
    python3 "$F7" "$OUT/own.out" "$OUT/h6.log" "$G8; g['policy_line'] = '$LA'"
    refuses7 "a decision whose policy_line is a string (review)" "$B/p.txt" "$OUT/h6.log" "is not an integer"
    LS2="$(grep -n "^allow path $B/fb readonly for=files\$" "$B/p.txt" | cut -d: -f1)"
    python3 "$F7" "$OUT/own.out" "$OUT/h7.log" "$G8; g['policy_line'] = $LS2"
    refuses7 "a certified decision citing another rule of its subject than its certificate's (review)" "$B/p.txt" "$OUT/h7.log" "but its certificate's rule is line $LS"
    MD="g = next(r for r in recs if isinstance(r, dict) and r.get('action') == 'net.mcp' and r.get('rule') == 'policy_match')"
    python3 "$F7" "$OUT/m.log" "$OUT/h8.log" "$MD; g['rule'] = None"
    refuses7 "an MCP call whose rule is null, without a crash (review)" "$POL" "$OUT/h8.log" "is not a name"
    python3 "$F7" "$OUT/m.log" "$OUT/h9.log" "$MD; g['resolved'] = ''"
    refuses7 "an MCP refusal by the policy with no object decided (review)" "$POL" "$OUT/h9.log" "with no object decided"
    python3 "$F7" "$OUT/m.log" "$OUT/h10.log" "$MD; g['event'] = 'dns_question'"
    refuses7 "a decision record that also names an event (review)" "$POL" "$OUT/h10.log" "also says it is a 'dns_question' event"
    if [ -f "$OUT/t4.log" ]; then
        python3 "$F7" "$OUT/t4.log" "$OUT/h11.log" "g = next(r for r in recs if isinstance(r, dict) and r.get('action') == 'net.mcp' and r.get('token') == 'jwt' and r.get('decision_final') == 'ALLOW'); g['token_expires'] = 1000"
        refuses7 "an MCP call allowed with a bearer token that had expired (review)" "$POL4" "$OUT/h11.log" "allowed with a bearer token that had expired"
        python3 "$F7" "$OUT/t4.log" "$OUT/h12.log" "next(r for r in recs if isinstance(r, dict) and r.get('event') == 'run_start')['credentials'] = 1"
        check "run_start credentials that are not a list: refused, no crash (review)" \
            sh -c "! python3 '$AUD7' --policy '$POL4' --checker '$CERT' '$OUT/h12.log' > '$OUT/h12.out' 2>&1 && ! grep -q Traceback '$OUT/h12.out'"
    fi
    python3 "$F7" "$OUT/own.out" "$OUT/h13.log" "next(r for r in recs if isinstance(r, dict) and r.get('event') == 'run_start')['note'] = 'ewogICJhbGciOiAiRVMyNTYiCn0.ewogICJzdWIiOiAiYWxpY2UiCn0.c2ln'"
    refuses7 "a token value whose JSON starts with whitespace (review)" "$B/p.txt" "$OUT/h13.log" "a token value in the stream (field 'note')"
    check "the audit still accepts the agent's own token sent in a request it made (its own business)" \
        python3 "$AUD7" --policy "$POL" --checker "$CERT" "$OUT/m.log"
    # the tools
    check "varek policy show lists the MCP server, its file and its rules" \
        sh -c "$(declare -f v7); V7='$V7'; v7 policy show '$B/p.txt' | grep -q 'MCP server files: $B/srv (line 2), not pinned; [0-9]* rule(s) for it'"
    v7 refusals "$OUT/notmine.out" --for files > "$OUT/r7.out" 2>&1
    check "varek refusals --for NAME: only the server's refusals, the server named as one" \
        sh -c "grep -q 'files#1 (MCP server)' '$OUT/r7.out' && grep -q '$B/fa' '$OUT/r7.out' && ! grep -q '$B/fs\$' '$OUT/r7.out'"
    v7 refusals "$OUT/m.log" -n 500 > "$OUT/r7m.out" 2>&1
    check "varek refusals: an MCP call, its method and name, and why" \
        sh -c "grep -q 'net.mcp .*tools/call delete_repo at $U' '$OUT/r7m.out' && grep -q 'its headers disagree with its body' '$OUT/r7m.out' && grep -q 'got a JSON-RPC error in a 403' '$OUT/r7m.out'"
    LD="$(mktemp -d /tmp/varek_v1310r.XXXXXX)"
    cp "$OUT/own.out" "$LD/verdicts-20261014-000001.log"
    printf '[varek]\nlog_dir = %s\npolicy = %s\n' "$LD" "$B/p.txt" > "$LD/varek.conf"
    check "varek runs shows a run's MCP servers" sh -c "$(declare -f v7); V7='$V7'; VC='$LD/varek.conf' v7 runs | grep -q 'agent +1 MCP server'"
    python3 - "$HERE/tools/varek" "$B" "$LD" <<'PY' > "$OUT/d7.out" 2>&1
import hashlib, importlib.machinery, importlib.util, os, shutil, sys
spec = importlib.util.spec_from_loader("varek_cli", importlib.machinery.SourceFileLoader("varek_cli", sys.argv[1]))
v = importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
b, d = sys.argv[2], sys.argv[3]
h = hashlib.sha256(open(b + "/srv", "rb").read()).hexdigest()
cases = {"good": f"mcp server files exec {b}/srv sha256={h}\n", "badpin": f"mcp server files exec {b}/srv sha256={'0' * 64}\n"}
shutil.copy(b + "/srv", d + "/gw"); os.chmod(d + "/gw", 0o775)
cases["groupw"] = f"mcp server files exec {d}/gw\n"
for k, line in cases.items():
    open(f"{d}/{k}.txt", "w").write("require warden 1.31\n" + line)
    print(k, v.check_server_files(f"{d}/{k}.txt"))
PY
    check "varek doctor: a server's file that is root's, written by no one else, with its pin, passes" grep -q "^good \[(True, 'MCP server files ($B/srv): its SHA-256 is the pin')\]" "$OUT/d7.out"
    check "varek doctor: a server whose pin is not its file's fails" grep -q "^badpin \[(False, .*is not the pin" "$OUT/d7.out"
    check "varek doctor: a server file others may write fails" grep -q "^groupw \[(False, .*mode 775" "$OUT/d7.out"
    sed '/^allow path \/lib64 readonly/d' "$B/p.txt" > "$LD/pc.txt"
    cp "$OUT/notmine.out" "$LD/nm.log"
    python3 -c "import sys, json
L = open('$LD/nm.log').read().replace('\"policy_sha256\":\"', '\"policy_sha256_was\":\"')
open('$LD/nm.log', 'w').write(L)" 2>/dev/null
    python3 - "$HERE" "$OUT/notmine.out" "$LD/pc.txt" > "$OUT/s7.out" 2>&1 <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1] + "/tools")
import varek_suggest as vs
recs = [json.loads(l) for l in open(sys.argv[2]) if l.startswith("{")]
for fn in ("files", None):
    d, a, c = vs.suggest(recs, open(sys.argv[3]).read(), sys.argv[3], "x", sys.argv[1] + "/tools/vdp_check", for_name=fn)
    print("== for", fn); print(d)
PY
    check "varek policy suggest --for NAME: the server's refusals, each rule for=NAME, re-checked as the server" \
        sh -c "sed -n '/^== for files/,/^== for None/p' '$OUT/s7.out' | grep -q '^allow path exact $B/fa readonly for=files ' && sed -n '/^== for files/,/^== for None/p' '$OUT/s7.out' | grep -q 'refusal(s) were for the agent'"
    check "... and without --for, only the agent's" \
        sh -c "sed -n '/^== for None/,\$p' '$OUT/s7.out' | grep -q '^allow path exact $B/fs readonly ' && ! sed -n '/^== for None/,\$p' '$OUT/s7.out' | grep -q 'readonly for=files '"
    python3 - "$HERE" "$OUT/m.log" "$POL" > "$OUT/s7m.out" 2>&1 <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1] + "/tools")
import varek_suggest as vs
recs = [json.loads(l) for l in open(sys.argv[2]) if l.startswith("{")]
print(vs.suggest(recs, open(sys.argv[3]).read(), sys.argv[3], "x", sys.argv[1] + "/tools/vdp_check")[0])
PY
    check "varek policy suggest: an MCP call no rule allowed gets its mcp rule; one a deny rule refuses does not" \
        sh -c "grep -q '^allow mcp $U tools/call other_tool ' '$OUT/s7m.out' && grep -q '^# allow mcp $U tools/call delete_repo .*NOT SUGGESTED: a deny rule' '$OUT/s7m.out'"
    # CycloneDX: each MCP server and each remote MCP endpoint
    if [ -f "$OUT/f2.log" ]; then
        python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/f2.log" --agent agent --policy "$POLF" --output "$OUT/f2.cdx" > /dev/null 2>&1
        check "CycloneDX: the MCP server as a component, with its file's SHA-256" \
            python3 -c "import json,sys; b = json.load(open('$OUT/f2.cdx')); c = [x for x in b['components'] if x['bom-ref'].startswith('mcp-server')]; sys.exit(0 if len(c) == 1 and c[0]['name'] == 'files' and c[0]['hashes'][0]['content'] == '$(sha256sum "$X/srv" | cut -c1-64)' else 1)"
    fi
    python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/m.log" --agent agent --policy "$POL" --output "$OUT/m.cdx" > /dev/null 2>&1
    check "CycloneDX: the remote MCP endpoint as a service, with its methods and names" \
        python3 -c "import json,sys; b = json.load(open('$OUT/m.cdx')); s = b['services']; p = {(x['name'], x['value']) for x in s[0]['properties']}; sys.exit(0 if s[0]['name'] == '$U' and ('varek:mcp.method', 'tools/call') in p and ('varek:mcp.name', 'get_issue') in p else 1)"
    python3 "$HERE/tests/cdx_schema_check.py" "$OUT/m.cdx" > "$OUT/cdx7.out" 2>&1; rc=$?
    if [ $rc = 2 ]; then skip "CycloneDX 1.6 schema check (cyclonedx-python-lib not installed)"
    else check "... and the BOM is valid CycloneDX 1.6" [ $rc = 0 ]; fi
    # varek run --mcp: the baseline with a confined server
    PJ="$(mktemp -d /tmp/varek_v1310p.XXXXXX)"
    (cd "$PJ" && v7 run --baseline --show-policy --mcp files="$X/srv" --run-as nobody -- /usr/bin/python3 a.py > "$OUT/bl7.txt" 2> "$OUT/bl7.err")
    check "varek run --mcp: the baseline declares the server, pinned, before the agent's launches" \
        python3 -c "import sys,hashlib; L = open('$OUT/bl7.txt').read().splitlines(); m = [i for i, l in enumerate(L) if l.startswith('mcp server files exec $X/srv sha256=' + hashlib.sha256(open('$X/srv','rb').read()).hexdigest())]; e = [i for i, l in enumerate(L) if l.startswith('allow exec ')]; sys.exit(0 if m and e and m[0] < e[0] and 'require warden 1.31' in L else 1)"
    check "... with the server's own rules (for=files), the system and the working directory read-only" \
        sh -c "grep -q '^allow path /usr/ readonly for=files' '$OUT/bl7.txt' && grep -q '^allow path $PJ/ readonly for=files' '$OUT/bl7.txt' && grep -q '^deny  path contains /.ssh/ for=files' '$OUT/bl7.txt'"
    check "... it lints, and the Warden would start it: over 256 rules (the cap is 512 from v1.31)" \
        sh -c "grep -q '^mcp server files ' '$OUT/bl7.txt' && [ \$(grep -c '^\\(allow\\|deny\\|mcp\\) ' '$OUT/bl7.txt') -gt 256 ] && '$VDP' '$OUT/bl7.txt' lint > '$OUT/bl7.lint' && '$WARDEN' '$OUT/bl7.txt' --check-startup > /dev/null 2>&1"
    touch "$PJ/srv"; chmod 755 "$PJ/srv"
    check "... a server under the working directory (which the agent may write) is refused" \
        sh -c "cd '$PJ' && $(declare -f v7); V7='$V7'; ! v7 run --baseline --show-policy --mcp files='$PJ/srv' --run-as nobody -- /bin/true 2>&1 | grep -q '^mcp server' && cd '$PJ' && v7 run --baseline --show-policy --mcp files='$PJ/srv' --run-as nobody -- /bin/true 2>&1 | grep -q 'which the agent may write'"
    check "... and --mcp with --dry-run is refused" \
        sh -c "cd '$PJ' && $(declare -f v7); V7='$V7'; v7 run --baseline --dry-run --mcp files='$X/srv' -- /bin/true 2>&1 | grep -q 'mcp with --dry-run is refused'"
    [ -n "${KEEP:-}" ] || rm -rf "$LD" "$PJ"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1310: PASS ($skips skipped)"; exit 0; fi
echo "test_v1310: FAIL"; exit 1
