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
#      Warden loading it
#   2. warden-proxy, the proxy's own program (as root): it will not run by
#      hand; it links neither libseccomp nor libsodium; the Warden runs it
#      from a sealed in-memory copy whose SHA-256 run_start records (the
#      file's own), so replacing the file mid-run changes nothing that runs;
#      the Warden refuses a proxy binary that is missing, writable by others,
#      or not a program, and the audit refuses run_start without the hash
#   3. the run's CA and the trust views (as root): the proxy makes an ECDSA
#      P-256 CA for the run, with critical name constraints permitting the
#      policy's inspected names (not its passthrough hosts), valid a week, its
#      key in the proxy's locked memory, which no process of the proxy's user
#      can read; the agent is served the host's bundle with the CA after it
#      at the usual bundle paths and /etc/varek/run-bundle.pem, the CA alone,
#      and a PKCS#12 trust store Java opens without a password, all read-only,
#      and its environment names them; run_start records every hash; an
#      inspected host is passed on to be inspected and a passthrough host
#      relayed in SNI mode; the
#      audit accepts the run and refuses forged trust records and decisions
#   4. terminating TLS (as root): for an inspected host the proxy verifies the
#      server (against --trust-bundle) before it meets the client, then
#      completes the client's handshake with a leaf from the run's CA (the
#      name only, serverAuth, kept for the run), http/1.1 only; an allowed
#      request reaches the server, decided first (section 5 has the
#      decisions); refused and recorded: a server whose name or issuer does
#      not verify (server_tls), a client that does not trust the CA or offers
#      only h2 (client_tls), a request the parser refuses, plain HTTP no
#      rule allows;
#      Python, curl, Node.js and Java trust the run's CA with no settings of
#      their own (Java through the store's metadata, answered from the
#      view); CONNECT clients and a Squid upstream; a passthrough host
#      relayed in SNI mode; the audit accepts the runs and refuses forged
#      inspected records
#   5. request decisions (as root, with section 4's root and servers): each
#      request of an inspected connection is decided on its object, certified
#      and recorded (net.request) before a byte of it is sent: allowed ones
#      reach the server, on one kept-alive connection and pipelined; at a
#      refused one (a deny rule, no rule, the request parser) the proxy stops,
#      earlier answers still reach the client, then a 403 says why, and
#      nothing after it is sent; a query only where a rule names one; a body
#      declared over max_body is refused before it is sent, a chunked one
#      passing it is cut there (max_body), and each body's length and SHA-256
#      are recorded (request_body) and are the server's; plain HTTP decided
#      on http:// objects; the audit accepts the run and refuses forged
#      request records
#
# Usage: test_v1261.sh <vdp_check> <vdp_cert_check> [<warden>]
# (section 2 uses warden-proxy beside the warden binary: make warden-proxy)
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
refused "%5C, a backslash"                   "$(Q 'GET https://api.example.com/a%5Cb')" "unreserved"
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
    got="$(printf 'request - %s\n' "$(hex "$o")" | "$VDP" "${RPOL:-$OUT/r.txt}" batch 2>/dev/null)"
    if ! printf '%s' "$got" | grep -q "\"verdict\":\"$want\""; then flunk "$d ($got)"; return; fi
    if [ "$want" = SATISFIED ]; then
        local ri w
        ri="$(printf '%s' "$got" | sed -n 's/.*"rule":\([0-9-]*\).*/\1/p')"
        w="$(printf '%s' "$got" | sed -n 's/.*"w":"\([^"]*\)".*/\1/p')"
        cert="$(printf 'request - %s %s %s\n' "$(hex "$o")" "$ri" "${w:-=}" | "$CERT" "${RPOL:-$OUT/r.txt}" batch 2>&1)"
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
decide 'PUT https://a.svc.example.com:443/q/r'               SATISFIED   "a wildcard host's request allowed"
decide 'PUT https://a.svc.example.com:443/q/r?s=1'           UNKNOWN     "a ** path without a '?' allows no query (review)"
decide 'PUT https://svc.example.com:443/q'                   UNKNOWN     "a wildcard does not match its suffix"
decide 'GET http://api.example.com:443/v1/models'            UNKNOWN     "the scheme is part of the object"

# A request rule whose host no host rule allows is never reached.
printf 'require warden 1.26\nproxy inspect\nallow host a.example.com:443\nallow request GET https://b.example.com/x\n' > "$OUT/n.txt"
if ! "$VDP" "$OUT/n.txt" lint > "$OUT/lint.out" 2>&1 && grep -q "can never fire: no host rule allows b.example.com:443" "$OUT/lint.out"
then pass "lint reports a request rule no host rule reaches"
else flunk "lint reports a request rule no host rule reaches ($(cat "$OUT/lint.out"))"; fi

# The review by AI review agents: a wildcard in a rule's path must not match
# across the query's '?', and a deny rule naming a path must hold whatever the
# query (a rule without a '?' is an allow of no query, a deny of any).
RPOL="$OUT/q.txt"
printf '%s' 'require warden 1.26
proxy inspect
allow host api.example.com:443
deny request GET https://api.example.com/v1/secret
deny request DELETE https://api.example.com/v1/projects/prod
allow request DELETE https://api.example.com/v1/items/*/tag
allow request GET https://api.example.com/v1/user[!s]
allow request GET https://api.example.com/a/**/info
allow request DELETE https://api.example.com/v1/projects/*
allow request GET https://api.example.com/v1/**
allow request GET https://api.example.com/q/**?*
' > "$RPOL"
decide 'DELETE https://api.example.com:443/v1/items/42/tag'   SATISFIED   "review: /v1/items/*/tag allows /v1/items/42/tag"
decide 'DELETE https://api.example.com:443/v1/items/42?/tag'  UNKNOWN     "review: ... but its * does not reach across the '?' (/v1/items/42?/tag)"
decide 'GET https://api.example.com:443/v1/user?'             UNKNOWN     "review: [!s] and ** do not match the '?' (/v1/user?)"
decide 'GET https://api.example.com:443/a/secret?x=/info'     UNKNOWN     "review: /**/ does not reach across the '?' (/a/secret?x=/info)"
decide 'GET https://api.example.com:443/v1/secret'            UNSATISFIED "review: a deny rule naming a path holds"
decide 'GET https://api.example.com:443/v1/secret?'           UNSATISFIED "review: ... with an empty query"
decide 'GET https://api.example.com:443/v1/secret?x=1'        UNSATISFIED "review: ... and with any query, ahead of a broader allow"
decide 'DELETE https://api.example.com:443/v1/projects/prod?' UNSATISFIED "review: ... for any method it names"
decide 'GET https://api.example.com:443/v1/models?'           UNKNOWN     "review: an allow rule without a '?' allows no query, not even an empty one"
decide 'GET https://api.example.com:443/q/a/b?x=1'            SATISFIED   "review: a rule with a query allows one, its path wildcards in the path"
# reachability under the same rules: a deny rule after an allow of the same
# glob still fires, on the path with a query (the allow takes none)
printf 'require warden 1.26\nproxy inspect\nallow host a.example.com:443\nallow request PUT https://a.example.com/v1/**\ndeny request PUT https://a.example.com/v1/**\n' > "$OUT/qr.txt"
QR="$("$VDP" "$OUT/qr.txt" analyze 2>/dev/null | grep '"line":5,')"
QW="$(printf '%s' "$QR" | python3 -c 'import json, sys; print(bytes.fromhex(json.loads(sys.stdin.read() or "{}").get("witness", "")).decode())' 2>/dev/null)"
if printf '%s' "$QR" | grep -q '"reach":"REACHABLE"' && case "$QW" in *\?*) true ;; *) false ;; esac
then pass "review: a deny rule after an allow of the same glob is reachable, by a request with a query ($QW)"
else flunk "review: the reachability of a deny rule after an allow of the same glob ($QR)"; fi
unset RPOL
refused "review: a request URL with a second '?'" "$(Q 'GET https://api.example.com/v1/x?a=1?b')" "at most one '?'"
printf 'require warden 1.26\nproxy inspect\nallow host api.example.com:443\nallow host *.svc.example.org:443 acknowledge=dns-channel\nallow request GET https://*.other.example.net/x\nallow request GET https://*.example.com/y\nallow request GET https://*.example.org/w\n' > "$OUT/n2.txt"
"$VDP" "$OUT/n2.txt" lint > "$OUT/lint2.out" 2>&1
if grep -q ":5: request rule can never fire: no host rule allows a name under other.example.net on port 443" "$OUT/lint2.out" &&
   ! grep -q ":6: \|:7: " "$OUT/lint2.out"
then pass "review: lint reports a wildcard request rule no host rule reaches, not one a name or wildcard reaches"
else flunk "review: lint and wildcard request rules ($(cat "$OUT/lint2.out"))"; fi

if python3 "$HERE/tools/varek" policy show "$OUT/r.txt" > "$OUT/show.out" 2>&1 &&
   grep -q '^Proxy    inspecting mode, ports 80, 443:' "$OUT/show.out" &&
   grep -q '^Passthrough pinned.example.net:' "$OUT/show.out" &&
   grep -qF 'Request  allow GET https://api.example.com:443/v1/files?limit=* (line 8)' "$OUT/show.out" &&
   grep -qF 'Request  allow POST https://api.example.com:443/v1/chat/completions (line 7), bodies at most 262,144 bytes' "$OUT/show.out"
then pass "varek policy show names inspecting mode, passthrough hosts and request rules"
else flunk "varek policy show ($(head -c 600 "$OUT/show.out"))"; fi

if [ -n "$WARDEN" ]; then
    "$WARDEN" "$OUT/r.txt" --check-startup > "$OUT/w.out" 2>&1; rc=$?
    if [ "$rc" = 0 ] && grep -q "loaded policy" "$OUT/w.out"
    then pass "the Warden loads the policy (both parsers agree)"
    else flunk "the Warden loads the policy (rc=$rc; $(tail -2 "$OUT/w.out"))"; fi
    "$WARDEN" "$OUT/n.txt" --check-startup > "$OUT/w2.out" 2>&1
    if grep -q "WARNING: request rule can never fire: no host rule allows b.example.com:443" "$OUT/w2.out"
    then pass "the Warden warns about a request rule no host rule reaches"
    else flunk "the Warden warns about a request rule no host rule reaches"; fi
else skip "the Warden's startup check (no warden binary given)"; skip "the Warden's warning"; fi

echo "== 2. warden-proxy =="
WP="$(dirname "${WARDEN:-/nonexistent/x}")/warden-proxy"
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ] || [ ! -x "$WP" ]; then
    skip "warden-proxy (needs root, the warden binary and warden-proxy beside it)"
else
    "$WP" > "$OUT/hand.out" 2>&1; rc=$?
    if [ "$rc" = 2 ] && grep -q "not run by hand" "$OUT/hand.out"; then pass "warden-proxy will not run by hand"
    else flunk "warden-proxy will not run by hand (rc=$rc)"; fi
    "$WP" 65532:65532 > "$OUT/hand2.out" 2>&1 3>&-; rc=$?
    if [ "$rc" = 2 ]; then pass "nor without the Warden's control socket"; else flunk "nor without the Warden's control socket (rc=$rc)"; fi
    if ldd "$WP" 2>/dev/null | grep -qE 'libseccomp|libsodium'; then flunk "warden-proxy links neither libseccomp nor libsodium"
    else pass "warden-proxy links neither libseccomp nor libsodium"; fi
    if grep -qa -- "--proxy-helper" "$WARDEN"; then flunk "the Warden no longer has a --proxy-helper mode"
    else pass "the Warden no longer has a --proxy-helper mode"; fi

    W=/tmp/varek_v1261w.$$
    rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
    POL="$OUT/proxy.policy"
    printf 'require warden 1.26\nproxy on\nallow host api.example.com:443\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' > "$POL"
    proxy_pid() { grep -o '"proxy":{[^}]*"pid":[0-9]*' "$1" 2>/dev/null | grep -o '[0-9]*$' | head -1; }
    # a copy of the proxy binary the test can replace mid-run
    cp "$WP" "$W/warden-proxy"; chmod 755 "$W/warden-proxy"
    SHA=$(sha256sum "$W/warden-proxy" | cut -d' ' -f1)
    env -i PATH=/usr/bin:/bin "$WARDEN" "$POL" --proxy-bin "$W/warden-proxy" -- /bin/sleep 3 > /dev/null 2> "$OUT/a.log" &
    WPID=$!
    for _ in $(seq 50); do grep -q '"proxy":{' "$OUT/a.log" 2>/dev/null && break; sleep 0.1; done
    PP=$(proxy_pid "$OUT/a.log")
    if grep -q "\"proxy_binary_sha256\":\"$SHA\"" "$OUT/a.log"; then pass "run_start records the proxy binary's SHA-256 (the file's own)"
    else flunk "run_start records the proxy binary's SHA-256 ($(grep -o '"proxy_binary_sha256":"[^"]*"' "$OUT/a.log"))"; fi
    exe=$(readlink "/proc/$PP/exe" 2>/dev/null)
    case "$exe" in "/memfd:warden-proxy"*) pass "the proxy runs from the sealed copy ($exe)";;
                   *) flunk "the proxy runs from the sealed copy ($exe)";; esac
    if [ -n "$PP" ] && [ "$(ls /proc/$PP/fd | wc -l)" = 6 ]; then pass "the copy's descriptor is not left open in the proxy"
    else flunk "the copy's descriptor is not left open in the proxy ($(ls -l /proc/$PP/fd 2>&1 | tail -n +2 | awk '{print $9 $10 $11}' | tr '\n' ' '))"; fi
    printf '#!/bin/sh\nexit 0\n' > "$W/warden-proxy"        # the file changes mid-run (to a script)
    if [ "$(sha256sum "/proc/$PP/exe" 2>/dev/null | cut -d' ' -f1)" = "$SHA" ]; then pass "replacing the file mid-run does not change what runs"
    else flunk "replacing the file mid-run does not change what runs"; fi
    wait "$WPID"
    "$WARDEN" "$POL" --proxy-bin "$W/warden-proxy" --check-startup > "$OUT/b.out" 2>&1; rc=$?
    if [ "$rc" != 0 ] && grep -q "not an ELF executable" "$OUT/b.out"; then pass "a proxy binary that is not a program is refused"
    else flunk "a proxy binary that is not a program is refused (rc=$rc; $(tail -1 "$OUT/b.out"))"; fi
    cp "$WP" "$W/warden-proxy"; chmod 775 "$W/warden-proxy"
    "$WARDEN" "$POL" --proxy-bin "$W/warden-proxy" --check-startup > "$OUT/c.out" 2>&1; rc=$?
    if [ "$rc" != 0 ] && grep -q "writable by its group or by others" "$OUT/c.out"; then pass "a proxy binary others may write is refused"
    else flunk "a proxy binary others may write is refused (rc=$rc)"; fi
    "$WARDEN" "$POL" --proxy-bin "$W/none" --check-startup > "$OUT/d.out" 2>&1; rc=$?
    if [ "$rc" != 0 ] && grep -q "make warden-proxy" "$OUT/d.out"; then pass "a missing proxy binary is refused, naming how to build it"
    else flunk "a missing proxy binary is refused (rc=$rc)"; fi
    printf 'require warden 1.26\nallow host api.example.com:443\n' > "$OUT/np.policy"
    "$WARDEN" "$OUT/np.policy" --proxy-bin "$W/none" --check-startup > "$OUT/e.out" 2>&1; rc=$?
    if [ "$rc" = 0 ]; then pass "without the proxy, no proxy binary is needed"; else flunk "without the proxy, no proxy binary is needed (rc=$rc)"; fi

    # the audit: run_start without the binary's hash, or with a bad one
    RUN="$OUT/run.log"
    env -i PATH=/usr/bin:/bin "$WARDEN" "$POL" -- /bin/true > /dev/null 2> "$RUN"
    if python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$RUN" > "$OUT/au.out" 2>&1
    then pass "the audit accepts the run"
    else flunk "the audit accepts the run ($(tail -3 "$OUT/au.out"))"; fi
    if grep -Eq '"event":"run_start",[^}]*"warden":"1\.(26\.[1-9][0-9]*|2[7-9]\.[0-9]+|[3-9][0-9]\.[0-9]+)"' "$RUN" &&
       NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" version 2>&1 | grep -q '1\.26\.1\|1\.2[7-9]\.'
    then pass "run_start and varek version report the Warden as 1.26.1 (or later)"
    else flunk "the Warden's version ($(grep -o '"warden":"[^"]*"' "$RUN" | head -1))"; fi
    forge() {   # forge <in> <out> <from> <to>: rewrite the first record holding <from>, rechain
        python3 - "$1" "$2" "$3" "$4" <<'PY'
import hashlib, sys
head = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
out, done = [], False
for line in open(sys.argv[1], encoding="utf-8", errors="surrogateescape"):
    if line.startswith("{") and ',"chain":"' in line:
        cut = line.index(',"chain":"')
        body = line[:cut]
        if not done and sys.argv[3] in body:
            body = body.replace(sys.argv[3], sys.argv[4])
            done = True
        head = hashlib.sha256(head + body.encode("utf-8", "surrogateescape")).digest()
        line = body + ',"chain":"' + head.hex() + line[cut + 10 + 64:]
    out.append(line)
open(sys.argv[2], "w", encoding="utf-8", errors="surrogateescape").write("".join(out))
PY
    }
    refuses() {   # refuses <description> <log> <message>
        if python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$2" > "$OUT/f.out" 2>&1; then
            flunk "the audit refuses $1"
        elif grep -qF "$3" "$OUT/f.out"; then pass "the audit refuses $1"
        else flunk "the audit refuses $1 ($(grep -m1 'problem\|FAIL' "$OUT/f.out"))"; fi
    }
    RS=$(grep -o '"proxy_binary_sha256":"[0-9a-f]*",' "$RUN")
    forge "$RUN" "$OUT/f1.log" "$RS" ""
    refuses "run_start without the proxy binary's hash" "$OUT/f1.log" "is not a SHA-256"
    forge "$RUN" "$OUT/f2.log" "$RS" '"proxy_binary_sha256":"x",'
    refuses "run_start with a hash that is not one" "$OUT/f2.log" "is not a SHA-256"
    rm -rf "$W"
fi

echo "== 3. the run's CA and the trust views =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ] || [ ! -x "$WP" ] || ! command -v openssl > /dev/null; then
    skip "the run's CA (needs root, the warden binary, warden-proxy and openssl)"
else
    W=/tmp/varek_v1261c.$$
    rm -rf "$W"; mkdir -p "$W/o"; chmod 755 "$W"; chmod 777 "$W/o"
    HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
    TP=$((45000 + RANDOM % 5000))
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -days 1 \
        -subj /CN=pinned.example.net > /dev/null 2>&1
    python3 - "$HOSTIP" "$TP" "$OUT/cert.pem" "$OUT/key.pem" <<'PY' > "$OUT/tlssrv.out" 2>&1 &
import socket, ssl, sys, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[3], sys.argv[4])
def sni(sock, name, c):
    sock.seen = name
ctx.sni_callback = sni
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind((sys.argv[1], int(sys.argv[2]))); l.listen(16)
def serve(c):
    try:
        s = ctx.wrap_socket(c, server_side=True)
        s.recv(1000)
        body = ("tls-ok " + str(getattr(s, "seen", None))).encode()
        s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        s.close()
    except Exception as e:
        print("srv", e, flush=True)
while True:
    c, _ = l.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
    SRV="$!"
    DPORT=$((20000 + RANDOM % 20000))
    printf '{"api.example.com": {"ttl": 30, "a": ["%s"]}, "pinned.example.net": {"ttl": 30, "a": ["%s"]}}\n' \
        "$HOSTIP" "$HOSTIP" > "$OUT/zone.json"
    rm -f "$OUT/ready"
    python3 "$HERE/tests/dns_test_server.py" --port "$DPORT" --zone "$OUT/zone.json" --log "$OUT/q.log" \
        --ready "$OUT/ready" > /dev/null 2>&1 &
    SRV="$SRV $!"
    for _ in $(seq 50); do
        [ -e "$OUT/ready" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $TP), 0.2)" 2>/dev/null && break
        sleep 0.1
    done
    cat > "$W/agent.py" <<'PY'
import os, socket, ssl, sys, time
TP, O = int(sys.argv[1]), sys.argv[2]
for p in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem",
          "/etc/varek/run-bundle.pem", "/etc/varek/run-ca.pem", "/etc/varek/run-trust.p12"):
    try:
        d = open(p, "rb").read()
        print("VIEW", p, d.count(b"-----BEGIN CERTIFICATE-----"), flush=True)
        open(os.path.join(O, os.path.basename(p)), "wb").write(d)
    except OSError as e:
        print("VIEW", p, "ERR", e.errno, flush=True)
for p in ("/etc/varek/run-ca.pem", "/etc/ssl/certs/ca-certificates.crt"):
    try:
        open(p, "ab"); print("WRITE", p, "OPENED", flush=True)
    except OSError as e:
        print("WRITE", p, "ERR", e.errno, flush=True)
for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "JAVA_TOOL_OPTIONS"):
    print("ENV", k, os.environ.get(k), flush=True)
c = ssl.create_default_context()           # SSL_CERT_FILE: the bundle view
print("DEFAULT_CAS", c.cert_store_stats()["x509_ca"], flush=True)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
for tag, name in (("inspected", "api.example.com"), ("passthrough", "pinned.example.net")):
    try:
        s = ctx.wrap_socket(socket.create_connection((name, TP), 10), server_hostname=name)
        s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % name.encode())
        out = b""
        while True:
            d = s.recv(4096)
            if not d: break
            out += d
        print("TLS", tag, out.split(b"\r\n\r\n", 1)[-1].decode(errors="replace"), flush=True)
    except ssl.SSLError as e:
        print("TLS", tag, "ALERT" if "HANDSHAKE_FAILURE" in str(e).upper() else "SSLERR", flush=True)
    except OSError as e:
        print("TLS", tag, "ERR", e, flush=True)
time.sleep(float(sys.argv[3]))
PY
    chmod 644 "$W/agent.py"
    POL="$OUT/inspect.policy"
    { printf 'require warden 1.26\nproxy inspect\nproxy ports %s\nproxy passthrough host pinned.example.net\n' "$TP"
      printf 'allow host api.example.com:%s\nallow host pinned.example.net:%s\n' "$TP" "$TP"
      printf 'allow host *.svc.example.com:%s acknowledge=dns-channel\n' "$TP"
      printf 'allow request GET https://api.example.com:%s/x\n' "$TP"
      printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/\n' "$W"
    } > "$POL"
    env -i PATH=/usr/bin:/bin JAVA_TOOL_OPTIONS=-Xss1m timeout 120 "$WARDEN" "$POL" --dns-server "127.0.0.1:$DPORT" -- \
        /usr/bin/python3 "$W/agent.py" "$TP" "$W/o" 2 > "$OUT/c.out" 2> "$OUT/c.log" &
    WPID=$!
    for _ in $(seq 50); do grep -q '"proxy":{' "$OUT/c.log" 2>/dev/null && break; sleep 0.1; done
    PP=$(proxy_pid "$OUT/c.log")
    sleep 1
    if [ -n "$PP" ] && ! setpriv --reuid 65532 --regid 65532 --clear-groups cat "/proc/$PP/environ" > /dev/null 2>&1 &&
       ! setpriv --reuid 65532 --regid 65532 --clear-groups python3 -c "open('/proc/$PP/mem','rb')" 2>/dev/null
    then pass "no process of the proxy's own user can read its memory (it is not dumpable)"
    else flunk "no process of the proxy's own user can read its memory"; fi
    wait "$WPID"
    sed 's/^/     /' "$OUT/c.out"
    have() { grep -qxF -- "$1" "$OUT/c.out"; }
    NB=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$(python3 -c "import json,sys; [print(json.loads(l)['trust']['host_bundle']) for l in open(sys.argv[1]) if l.startswith('{\"event\":\"run_start\"')]" "$OUT/c.log")")
    if have "VIEW /etc/ssl/certs/ca-certificates.crt $((NB + 1))" && have "VIEW /etc/pki/tls/certs/ca-bundle.crt $((NB + 1))" &&
       have "VIEW /etc/ssl/cert.pem $((NB + 1))" && have "VIEW /etc/varek/run-bundle.pem $((NB + 1))"
    then pass "the agent reads the host's bundle with the run's CA after it, at each bundle path"
    else flunk "the agent reads the host's bundle with the run's CA after it ($NB host certificates)"; fi
    if have "VIEW /etc/varek/run-ca.pem 1" && cmp -s "$W/o/run-ca.pem" <(tail -c "$(stat -c %s "$W/o/run-ca.pem")" "$W/o/run-bundle.pem")
    then pass "the CA alone at /etc/varek/run-ca.pem, the same as the bundle's last"
    else flunk "the CA alone at /etc/varek/run-ca.pem"; fi
    if have "WRITE /etc/varek/run-ca.pem ERR 13" && have "WRITE /etc/ssl/certs/ca-certificates.crt ERR 13"
    then pass "the trust views are read-only"; else flunk "the trust views are read-only"; fi
    if have "ENV SSL_CERT_FILE /etc/varek/run-bundle.pem" && have "ENV REQUESTS_CA_BUNDLE /etc/varek/run-bundle.pem" &&
       have "ENV CURL_CA_BUNDLE /etc/varek/run-bundle.pem" && have "ENV NODE_EXTRA_CA_CERTS /etc/varek/run-ca.pem" &&
       have "ENV JAVA_TOOL_OPTIONS -Xss1m -Djavax.net.ssl.trustStore=/etc/varek/run-trust.p12 -Djavax.net.ssl.trustStoreType=PKCS12"
    then pass "the agent's environment names the views (Java's options kept, the store added)"
    else flunk "the agent's environment names the views"; fi
    NS=$(python3 -c "import ssl,sys; c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.load_verify_locations(sys.argv[1]); print(c.cert_store_stats()['x509_ca'])" "$(grep -o '"host_bundle":"[^"]*"' "$OUT/c.log" | cut -d'"' -f4)")
    # (a bundle may list a certificate twice; a store keeps it once)
    if have "DEFAULT_CAS $((NS + 1))"; then pass "Python's default context trusts the host's roots and the run's CA"
    else flunk "Python's default context trusts the host's roots and the run's CA ($(grep DEFAULT_CAS "$OUT/c.out"))"; fi
    openssl x509 -in "$W/o/run-ca.pem" -noout -text > "$OUT/ca.txt" 2>&1
    if grep -q 'NIST CURVE: P-256' "$OUT/ca.txt" && grep -A1 'Basic Constraints: critical' "$OUT/ca.txt" | grep -q 'CA:TRUE, pathlen:0' &&
       grep -A1 'Key Usage: critical' "$OUT/ca.txt" | grep -q 'Certificate Sign, CRL Sign' &&
       grep -q 'CN = VAREK run CA '"$(grep -o '"run":"[0-9a-f]*"' "$OUT/c.log" | head -1 | cut -d'"' -f4)" "$OUT/ca.txt"
    then pass "the CA: ECDSA P-256, CA:TRUE pathlen 0, signing certificates only, named for the run"
    else flunk "the CA's form ($(head -c 400 "$OUT/ca.txt"))"; fi
    NCP=$(sed -n '/Name Constraints: critical/,/Excluded:/p' "$OUT/ca.txt")
    NCX=$(sed -n '/Excluded:/,/X509v3\|Signature/p' "$OUT/ca.txt")
    if grep -q 'DNS:api.example.com' <<< "$NCP" && grep -q 'DNS:svc.example.com' <<< "$NCP" &&
       ! grep -q 'DNS:pinned.example.net' <<< "$NCP" && grep -q 'DNS:pinned.example.net' <<< "$NCX" &&
       grep -q 'IP:0.0.0.0/0.0.0.0' <<< "$NCX" && grep -q 'IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0' <<< "$NCX"
    then pass "critical name constraints: the inspected names and the wildcard's suffix permitted; the passthrough host and every IP address excluded"
    else flunk "the CA's name constraints"; fi
    nb=$(date -u -d "$(openssl x509 -in "$W/o/run-ca.pem" -noout -startdate | cut -d= -f2)" +%s)
    na=$(date -u -d "$(openssl x509 -in "$W/o/run-ca.pem" -noout -enddate | cut -d= -f2)" +%s)
    now=$(date -u +%s)
    if [ $((now - nb)) -ge 240 ] && [ $((now - nb)) -le 400 ] && [ $((na - nb)) = $((7 * 86400 + 300)) ]
    then pass "valid from five minutes before the run, for a week"
    else flunk "the CA's validity ($nb $na $now)"; fi
    want=$(openssl x509 -in "$W/o/run-ca.pem" -outform DER | sha256sum | cut -d' ' -f1)
    if grep -q "\"ca_sha256\":\"$want\"" "$OUT/c.log" &&
       grep -q "\"trust_store_sha256\":\"$(sha256sum "$W/o/run-trust.p12" | cut -d' ' -f1)\"" "$OUT/c.log" &&
       grep -q '"ca_key_locked":true' "$OUT/c.log" && grep -q '"passthrough":\["pinned.example.net"\]' "$OUT/c.log"
    then pass "run_start records the CA's and the store's SHA-256, the key locked, the passthrough host"
    else flunk "run_start's trust record ($(grep -o '"trust":{[^}]*}' "$OUT/c.log"))"; fi
    if command -v java > /dev/null; then
        cat > "$OUT/P12.java" <<'JAVA'
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Collections;
public class P12 {
    public static void main(String[] a) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(a[0])) { ks.load(in, null); }
        int trusted = 0; boolean ca = false;
        for (String al : Collections.list(ks.aliases())) {
            if (ks.isCertificateEntry(al)) trusted++;
            if (al.equals("varek-run-ca") && ks.isCertificateEntry(al)) ca = true;
        }
        System.out.println("trusted=" + trusted + " ca=" + ca);
    }
}
JAVA
        if (cd "$OUT" && env -u JAVA_TOOL_OPTIONS java P12.java "$W/o/run-trust.p12" 2>/dev/null) | grep -qx "trusted=$((NB + 1)) ca=true"
        then pass "Java opens the trust store without a password: the host's roots and the run's CA, trusted"
        else flunk "Java opens the trust store ($(cd "$OUT" && env -u JAVA_TOOL_OPTIONS java P12.java "$W/o/run-trust.p12" 2>&1 | tail -1))"; fi
    else skip "Java opening the trust store (no java)"; fi
    px() { grep '"action":"net.proxy"' "$OUT/c.log" | grep -q "\"target\":\"$1\",.*\"rule\":\"$2\""; }
    # (step 4: an inspected host's TLS is terminated; this server's
    # certificate is self-signed, so it does not verify: section 4 has more)
    if have "TLS inspected ALERT" && px "api.example.com:$TP" proxy_dialed &&
       grep '"event":"proxy_close"' "$OUT/c.log" | grep -q '"why":"server_tls".*"inspected":true'
    then pass "an inspected host is passed on to be inspected (here, a server that does not verify: server_tls)"
    else flunk "an inspected host is passed on to be inspected"; fi
    if have "TLS passthrough tls-ok pinned.example.net" && px "pinned.example.net:$TP" proxy_dialed
    then pass "a passthrough host is relayed in SNI mode"
    else flunk "a passthrough host is relayed in SNI mode"; fi
    if python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/c.log" > "$OUT/au.out" 2>&1
    then pass "the audit accepts the run"
    else flunk "the audit accepts the run ($(grep -m3 'problem\|FAIL\|seq' "$OUT/au.out"))"; fi
    forge "$OUT/c.log" "$OUT/g1.log" '"passthrough":["pinned.example.net"]' '"passthrough":[]'
    refuses "a trust record without the policy's passthrough host" "$OUT/g1.log" "is not inspecting mode's"
    forge "$OUT/c.log" "$OUT/g2.log" '"ca_sha256":"' '"ca_sha256":"x'
    refuses "a trust record whose CA hash is not one" "$OUT/g2.log" "is not inspecting mode's"
    forge "$OUT/c.log" "$OUT/g3.log" '"mode":"inspect"' '"mode":"sni"'
    refuses "run_start's proxy in SNI mode under an inspecting policy" "$OUT/g3.log" "inspecting mode"
    PD=$(grep '"action":"net.proxy"' "$OUT/c.log" | grep -o '"target":"pinned.example.net:[0-9]*","resolved":"[^"]*","decision_raw":"ALLOW","decision_final":"ALLOW","rule":"proxy_dialed"' | head -1)
    forge "$OUT/c.log" "$OUT/g4.log" '"proxy_kind":"tls","inspected":true,' '"proxy_kind":"tls",'
    refuses "an inspected host passed on without being inspected" "$OUT/g4.log" "was not inspected, which it must be"
    for pid in $SRV; do kill "$pid" 2>/dev/null; done
    rm -rf "$W"

fi

echo "== 4. terminating TLS =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ] || [ ! -x "$WP" ] || ! command -v openssl > /dev/null; then
    skip "terminating TLS (needs root, the warden binary, warden-proxy and openssl)"
else
    W=/tmp/varek_v1261t.$$
    rm -rf "$W"; mkdir -p "$W/o"; chmod 755 "$W"; chmod 777 "$W/o"
    HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
    P1=$((42000 + RANDOM % 5000)); P2=$((P1 + 1)); P3=$((P1 + 2)); P4=$((P1 + 3))   # good, wrong name, self-signed, passthrough
    # a test root, servers' certificates under it, and the trust bundle given the Warden
    ( cd "$W" &&
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tca.key -out tca.pem -days 2 \
          -subj "/CN=VAREK test root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" &&
      for x in "good api.example.com" "wrong other.example.com" "pin pinned.example.net"; do
          set -- $x
          openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2" &&
          printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$2" > "$1.ext" &&
          openssl x509 -req -in "$1.csr" -CA tca.pem -CAkey tca.key -CAcreateserial -out "$1.pem" -days 1 -extfile "$1.ext"
      done &&
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout self.key -out self.pem -days 1 \
          -subj "/CN=api.example.com" -addext "subjectAltName=DNS:api.example.com" ) > "$OUT/certs.log" 2>&1
    BUNDLE="$W/bundle.pem"            # the proxy reads it, as its own user
    cat "$(python3 -c 'import ssl; print(ssl.get_default_verify_paths().openssl_cafile)')" "$W/tca.pem" > "$BUNDLE"
    chmod 644 "$BUNDLE" "$W"/*.pem
    cat > "$OUT/srv.py" <<'PY'
import socket, ssl, sys, threading
ip, port, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind((ip, port)); l.listen(16)
def serve(c):
    try:
        s = ctx.wrap_socket(c, server_side=True)
        d = s.recv(1000)
        if not d:
            s.close(); return
        print("GOT", d.split(b"\r\n")[0].decode(errors="replace"), flush=True)
        s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nserver"); s.close()
    except Exception as e:
        print("srv", type(e).__name__, flush=True)
while True:
    c, _ = l.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
    SRV=""
    for x in "$P1 good" "$P2 wrong" "$P3 self" "$P4 pin"; do
        set -- $x
        python3 "$OUT/srv.py" "$HOSTIP" "$1" "$W/$2.pem" "$W/$2.key" > "$OUT/srv$1.log" 2>&1 &
        SRV="$SRV $!"
    done
    DPORT=$((20000 + RANDOM % 20000))
    printf '{"api.example.com": {"ttl": 30, "a": ["%s"]}, "pinned.example.net": {"ttl": 30, "a": ["%s"]}}\n' \
        "$HOSTIP" "$HOSTIP" > "$OUT/zone4.json"
    rm -f "$OUT/ready4"
    python3 "$HERE/tests/dns_test_server.py" --port "$DPORT" --zone "$OUT/zone4.json" --log "$OUT/q4.log" \
        --ready "$OUT/ready4" > /dev/null 2>&1 &
    SRV="$SRV $!"
    for _ in $(seq 50); do
        [ -e "$OUT/ready4" ] && python3 -c "import socket; [socket.create_connection(('$HOSTIP', p), 0.2) for p in ($P1, $P4)]" 2>/dev/null && break
        sleep 0.1
    done
    cat > "$W/agent.py" <<'PY'
import os, socket, ssl, sys
P1, P2, P3, P4, O = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
def get(tag, ctxf, port=P1, name="api.example.com", connect=False):
    try:
        s = socket.create_connection((name, port), 10)
        if connect:
            s.sendall(b"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (name.encode(), port, name.encode(), port))
            r = b""
            while b"\r\n\r\n" not in r:
                d = s.recv(1)
                if not d: break
                r += d
        s = ctxf().wrap_socket(s, server_hostname=name)
        v = s.version() in ("TLSv1.2", "TLSv1.3")
        open(os.path.join(O, "leaf-%s.der" % tag), "wb").write(s.getpeercert(binary_form=True))
        s.sendall(b"GET /v1/models HTTP/1.1\r\nHost: %s\r\n\r\n" % name.encode())
        out = b""
        while True:
            d = s.recv(4096)
            if not d: break
            out += d
        print("TLS", tag, v, s.selected_alpn_protocol(),
              out.split(b"\r\n")[0].decode(), out.split(b"\r\n\r\n", 1)[-1].split(b";")[0].decode(), flush=True)
    except ssl.SSLError as e:
        print("TLS", tag, "SSLERR", "HANDSHAKE_FAILURE" in str(e).upper(), flush=True)
    except OSError as e:
        print("TLS", tag, "ERR", e, flush=True)
def alpn(*p):
    def f():
        c = ssl.create_default_context(); c.set_alpn_protocols(list(p)); return c
    return f
def own_roots():                     # a client that trusts only the test root (pins)
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.load_verify_locations(sys.argv[6]); return c
get("verified", ssl.create_default_context)
get("again", ssl.create_default_context)
get("alpn-both", alpn("h2", "http/1.1"))
get("alpn-h2", alpn("h2"))
get("pinning", own_roots)
get("connect", ssl.create_default_context, connect=True)
get("wrong-name", ssl.create_default_context, port=P2)
get("self-signed", ssl.create_default_context, port=P3)
get("passthrough", ssl.create_default_context, port=P4, name="pinned.example.net")
def raw(tag, head):                  # step 5: a request inside TLS, as written
    try:
        s = ssl.create_default_context().wrap_socket(socket.create_connection(("api.example.com", P1), 10),
                                                     server_hostname="api.example.com")
        s.sendall(head)
        out = b""
        while True:
            d = s.recv(4096)
            if not d: break
            out += d
        print("REQ", tag, out.split(b"\r\n")[0].decode(), out.split(b"\r\n\r\n", 1)[-1].decode().strip(), flush=True)
    except (OSError, ssl.SSLError) as e:
        print("REQ", tag, "ERR", e, flush=True)
raw("fronting", b"GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n")
raw("dotdot", b"GET /v1/../admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
raw("escaped", b"GET /v1/%61dmin HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
raw("absolute", b"GET https://api.example.com:%d/v1/models HTTP/1.1\r\nHost: api.example.com:%d\r\n\r\n" % (P1, P1))
try:
    s = socket.create_connection(("api.example.com", P1), 10)
    s.sendall(b"GET /v1/models HTTP/1.1\r\nHost: api.example.com:%d\r\nConnection: close\r\n\r\n" % P1)
    print("HTTP", s.recv(100).split(b"\r\n")[0].decode(), flush=True)
except OSError as e:
    print("HTTP ERR", e, flush=True)
st = os.stat("/etc/varek/run-trust.p12")
print("STAT", oct(st.st_mode & 0o170000), st.st_size == len(open("/etc/varek/run-trust.p12", "rb").read()), flush=True)
PY
    chmod 644 "$W/agent.py"
    POL4="$OUT/tls.policy"
    { printf 'require warden 1.26\nproxy inspect\nproxy ports %s %s %s %s\nproxy passthrough host pinned.example.net\n' "$P1" "$P2" "$P3" "$P4"
      printf 'allow host api.example.com\nallow host pinned.example.net:%s\n' "$P4"
      printf 'allow request GET https://api.example.com:%s/v1/models\n' "$P1"
      printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/\n' "$W"
    } > "$POL4"
    env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$POL4" --dns-server "127.0.0.1:$DPORT" --trust-bundle "$BUNDLE" -- \
        /usr/bin/python3 "$W/agent.py" "$P1" "$P2" "$P3" "$P4" "$W/o" "$W/tca.pem" > "$OUT/t.out" 2> "$OUT/t.log"
    sed 's/^/     /' "$OUT/t.out"
    have() { grep -qxF -- "$1" "$OUT/t.out"; }
    close_of() {   # close_of <target> -> the proxy_close of that target's connection
        python3 - "$OUT/t.log" "$1" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
ids = [r["proxy_conn"] for r in recs if r.get("action") == "net.proxy" and r.get("target") == sys.argv[2]]
for r in recs:
    if r.get("event") == "proxy_close" and r.get("proxy_conn") in ids:
        print(json.dumps(r, sort_keys=True))
PY
    }
    NB="VAREK: this request was refused"
    if have "TLS verified True None HTTP/1.1 200 OK server" && have "TLS again True None HTTP/1.1 200 OK server"
    then pass "a verifying client completes TLS with the run's CA, and its allowed request reaches the server"
    else flunk "a verifying client completes TLS with the run's CA (see above)"; fi
    # verified, again, alpn-both, connect, absolute: the five allowed requests, and only they
    if [ "$(grep -c '^GOT GET ' "$OUT/srv$P1.log")" = 5 ] && [ "$(grep -c '^GOT ' "$OUT/srv$P1.log")" = 5 ]
    then pass "the server got the allowed requests, and nothing of the refused ones"
    else flunk "the server got only the allowed requests ($(cat "$OUT/srv$P1.log"))"; fi
    openssl x509 -inform DER -in "$W/o/leaf-verified.der" -noout -text > "$OUT/leaf.txt" 2>&1
    if grep -q 'Issuer: O = VAREK Warden (this run only), CN = VAREK run CA' "$OUT/leaf.txt" &&
       grep -A1 'Subject Alternative Name' "$OUT/leaf.txt" | tail -1 | grep -qx ' *DNS:api.example.com' &&
       grep -A1 'Extended Key Usage' "$OUT/leaf.txt" | grep -q 'TLS Web Server Authentication' &&
       grep -A1 'Basic Constraints: critical' "$OUT/leaf.txt" | grep -q 'CA:FALSE' &&
       grep -A1 'Key Usage: critical' "$OUT/leaf.txt" | grep -q 'Digital Signature'
    then pass "the leaf: issued by the run's CA, the name alone, serverAuth, not a CA"
    else flunk "the leaf's form ($(head -c 300 "$OUT/leaf.txt"))"; fi
    if cmp -s "$W/o/leaf-verified.der" "$W/o/leaf-again.der"; then pass "and kept for the run (the same leaf again)"
    else flunk "and kept for the run"; fi
    if have "TLS alpn-both True http/1.1 HTTP/1.1 200 OK server" && have "TLS alpn-h2 SSLERR False" &&
       close_of "api.example.com:$P1" | grep -q '"tls_error": "handshake: no application protocol"'
    then pass "http/1.1 is chosen; a client offering only h2 is refused (client_tls)"
    else flunk "ALPN (http/1.1 chosen, h2 alone refused)"; fi
    if have "TLS pinning SSLERR False" && close_of "api.example.com:$P1" | grep -q '"tls_error": "handshake: tlsv1 alert unknown ca"'
    then pass "a client that does not trust the run's CA fails its handshake, recorded (client_tls)"
    else flunk "a client that does not trust the run's CA"; fi
    if have "TLS connect True None HTTP/1.1 200 OK server"; then pass "TLS inside a CONNECT is inspected too"
    else flunk "TLS inside a CONNECT is inspected too"; fi
    if have "TLS wrong-name SSLERR True" && close_of "api.example.com:$P2" | grep -q '"tls_error": "certificate: hostname mismatch"' &&
       have "TLS self-signed SSLERR True" && close_of "api.example.com:$P3" | grep -q '"tls_error": "certificate: self-signed certificate"' &&
       ! grep -q '^GOT ' "$OUT/srv$P2.log" "$OUT/srv$P3.log"
    then pass "a server whose name or issuer does not verify is refused before the client's handshake (server_tls)"
    else flunk "a server that does not verify is refused (server_tls)"; fi
    reqx() { python3 - "$OUT/t.log" "$1" <<'PY'
import json, sys
for l in open(sys.argv[1]):
    if l.startswith("{"):
        r = json.loads(l)
        if r.get("event") == "proxy_close" and r.get("why") == "refused_request" and r.get("request_error") == sys.argv[2]:
            print("yes"); break
PY
    }
    if have "REQ fronting HTTP/1.1 403 Forbidden VAREK: this request was refused: a Host other than the name and port the connection is for." &&
       [ "$(reqx 'a Host other than the name and port the connection is for')" = yes ]
    then pass "inside TLS, a request whose Host is not the SNI name (domain fronting) is refused, recorded with its reason"
    else flunk "inside TLS, a fronting request is refused"; fi
    if have "REQ dotdot HTTP/1.1 403 Forbidden VAREK: this request was refused: a '.' or '..' path segment." &&
       have "REQ escaped HTTP/1.1 403 Forbidden VAREK: this request was refused: a percent escape of '/', '\\' or an unreserved byte." &&
       [ "$(reqx "a '.' or '..' path segment")" = yes ]
    then pass "a '..' segment and an escaped letter are refused, recorded"
    else flunk "a '..' segment and an escaped letter are refused"; fi
    if have "REQ absolute HTTP/1.1 200 OK server"; then pass "an absolute-form request for the connection's own authority is read, decided and sent"
    else flunk "an absolute-form request is read"; fi
    if have "TLS passthrough True None HTTP/1.1 200 OK server" &&
       grep '"action":"net.proxy"' "$OUT/t.log" | grep "\"target\":\"pinned.example.net:$P4\"" | grep -vq '"inspected"'
    then pass "a passthrough host is relayed in SNI mode, not inspected"
    else flunk "a passthrough host is relayed in SNI mode"; fi
    if grep '"action":"net.request"' "$OUT/t.log" | grep "\"target\":\"GET http://api.example.com:$P1/v1/models\"" |
           grep -q '"decision_final":"DENY","rule":"default_deny_unknown"'
    then pass "plain HTTP to an inspected host is decided too (an http:// object no rule allows: refused)"
    else flunk "plain HTTP to an inspected host is decided"; fi
    GSHA=$(openssl x509 -in "$W/good.pem" -outform DER | sha256sum | cut -d' ' -f1)
    if close_of "api.example.com:$P1" | grep '"why": "closed"' | grep -q "\"server_cert_sha256\": \"$GSHA\"" &&
       ! close_of "api.example.com:$P1" | grep '"why": "refused_request"' | grep -v '"bytes_up": 0,' | grep -q https
    then pass "each inspected close records the server's certificate, and a refused request sends no bytes"
    else flunk "the inspected closes' records"; fi
    if have "STAT 0o100000 True" && grep -q '"rule":"view_metadata"' "$OUT/t.log"
    then pass "the trust store's metadata is the view's (a regular file, its size)"
    else flunk "the trust store's metadata is the view's"; fi
    if python3 "$HERE/tools/varek_audit.py" --policy "$POL4" --checker "$CERT" "$OUT/t.log" > "$OUT/au4.out" 2>&1
    then pass "the audit accepts the run"
    else flunk "the audit accepts the run ($(grep -m3 'PROBLEM' "$OUT/au4.out"))"; fi
    POL="$POL4"
    forge "$OUT/t.log" "$OUT/h1.log" '"why":"refused_request","bytes_up":0,' '"why":"refused_request","bytes_up":512,'
    refuses "an inspected connection that relayed bytes though no request was allowed" "$OUT/h1.log" "though no request was allowed"
    forge "$OUT/t.log" "$OUT/h2.log" ',"inspected":true,"requests":' ',"requests":'
    refuses "an inspected connection's close not marked inspected" "$OUT/h2.log" "not marked inspected"
    forge "$OUT/t.log" "$OUT/h3.log" "\"target\":\"pinned.example.net:$P4\"," "\"target\":\"pinned.example.net:$P4\",\"inspected\":true,"
    refuses "a passthrough host's decision marked inspected" "$OUT/h3.log" "which only a host that is not passthrough is"

    # Real clients: curl, Node.js and Java, each with no settings of its own
    NODE=$(readlink -f "$(command -v node 2>/dev/null)" 2>/dev/null)
    JAVA=$(ls /usr/lib/jvm/java-21-openjdk-*/bin/java 2>/dev/null | head -1)
    [ -n "$JAVA" ] || JAVA=$(readlink -f "$(command -v java 2>/dev/null)" 2>/dev/null)
    POLC="$OUT/clients.policy"
    { printf 'require warden 1.26\nproxy inspect\nproxy ports %s\nallow host api.example.com\n' "$P1"
      printf 'allow request GET https://api.example.com:%s/v1/models\n' "$P1"
      for d in /usr/ /lib /proc/ /sys/ "$W/" ${NODE:+$(dirname "$(dirname "$NODE")")/} \
               ${JAVA:+$(dirname "$(dirname "$JAVA")")/} /etc/java-21-openjdk/ /etc/java-17-openjdk/; do
          printf 'allow path %s readonly\n' "$d"; done
      printf 'allow path /etc/ld.so.cache readonly\nallow path /etc/ssl/openssl.cnf readonly\nallow path /tmp/hsperfdata_nobody/\n'
    } > "$POLC"
    cl() { env -i PATH=/usr/bin:/bin timeout 90 "$WARDEN" "$POLC" --dns-server "127.0.0.1:$DPORT" --trust-bundle "$BUNDLE" -- "$@" 2> "$OUT/cl.log"; }
    URL="https://api.example.com:$P1/v1/models"
    if command -v curl > /dev/null; then
        if [ "$(cl /usr/bin/curl -sS "$URL")" = server ]; then pass "curl verifies the run's CA (CURL_CA_BUNDLE), its request decided and sent"
        else flunk "curl verifies the run's CA ($(grep '^\[agent\]' "$OUT/cl.log" | head -2))"; fi
    else skip "curl (not installed)"; fi
    if [ -n "$NODE" ]; then
        out=$(cl "$NODE" -e 'require("https").get(process.argv[1], r => { let b = ""; r.on("data", d => b += d); r.on("end", () => console.log("NODE", r.statusCode, b.split(";")[0])); }).on("error", e => console.log("NODE ERR", e.message))' "$URL")
        if [ "$out" = "NODE 200 server" ]; then pass "Node.js verifies the run's CA (NODE_EXTRA_CA_CERTS), its request decided and sent"
        else flunk "Node.js verifies the run's CA ($out)"; fi
    else skip "Node.js (not installed)"; fi
    JAVAC="$(dirname "$JAVA" 2>/dev/null)/javac"
    if [ -n "$JAVA" ] && [ -x "$JAVAC" ]; then
        cat > "$OUT/V1261Get.java" <<'JAVA'
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
public class V1261Get {
    public static void main(String[] a) {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(a[0]).openConnection();
            int code = c.getResponseCode();
            InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
            System.out.println("JAVA " + code + " " + new String(in.readAllBytes()).split(";")[0]);
        } catch (Exception e) { System.out.println("JAVA ERR " + e); }
    }
}
JAVA
        "$JAVAC" --release 11 -d "$W" "$OUT/V1261Get.java" > /dev/null 2>&1 && chmod 644 "$W/V1261Get.class"
        out=$(cl "$JAVA" -Xshare:off -cp "$W" V1261Get "$URL")
        if [ "$out" = "JAVA 200 server" ]; then pass "Java verifies the run's CA (the PKCS#12 store, JAVA_TOOL_OPTIONS), its request decided and sent"
        else flunk "Java verifies the run's CA ($out)"; fi
    else skip "Java (no JDK)"; fi

    # A Squid upstream: TLS to the server through its CONNECT tunnel
    if ! command -v squid > /dev/null && [ ! -x /usr/sbin/squid ]; then
        skip "inspecting through an upstream (Squid is not installed)"
    else
        SQUID=$(command -v squid || echo /usr/sbin/squid)
        SQ=/tmp/varek_v1261sq.$$
        rm -rf "$SQ"; mkdir -p "$SQ"; chmod 777 "$SQ"
        SP=$((47500 + RANDOM % 2000))
        printf '%s api.example.com\n' "$HOSTIP" > "$SQ/hosts"
        { printf 'http_port %s:%s\nhttp_access allow all\n' "$HOSTIP" "$SP"
          printf 'hosts_file %s/hosts\naccess_log %s/access.log\ncache_log %s/cache.log\npid_filename %s/squid.pid\n' "$SQ" "$SQ" "$SQ" "$SQ"
          printf 'cache deny all\ncoredump_dir %s\nshutdown_lifetime 1 seconds\n' "$SQ"
        } > "$SQ/squid.conf"
        chmod 644 "$SQ"/*
        ( cd "$SQ" && "$SQUID" -N -f "$SQ/squid.conf" > "$SQ/out.log" 2>&1 & )
        for _ in $(seq 100); do python3 -c "import socket; socket.create_connection(('$HOSTIP', $SP), 0.2)" 2>/dev/null && break; sleep 0.1; done
        { printf 'require warden 1.26\nproxy inspect\nproxy ports %s\nproxy upstream http://%s:%s\nallow host api.example.com:%s\n' "$P1" "$HOSTIP" "$SP" "$P1"
          printf 'allow request GET https://api.example.com:%s/\n' "$P1"
          printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/\n' "$W"
        } > "$OUT/up.policy"
        cat > "$W/up.py" <<'PY'
import socket, ssl, sys
s = ssl.create_default_context().wrap_socket(socket.create_connection(("api.example.com", int(sys.argv[1])), 10),
                                             server_hostname="api.example.com")
s.sendall(b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
out = b""
while True:
    d = s.recv(4096)
    if not d: break
    out += d
print("UP", out.split(b"\r\n")[0].decode(), flush=True)
PY
        chmod 644 "$W/up.py"
        env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$OUT/up.policy" --dns-server "127.0.0.1:$DPORT" --trust-bundle "$BUNDLE" -- \
            /usr/bin/python3 "$W/up.py" "$P1" > "$OUT/up.out" 2> "$OUT/up.log"
        if grep -qx "UP HTTP/1.1 200 OK" "$OUT/up.out" && grep -q "CONNECT api.example.com:$P1" "$SQ/access.log" &&
           grep '"event":"proxy_close"' "$OUT/up.log" | grep -q '"why":"closed".*"inspected":true,"requests":1,"server_cert_sha256"'
        then pass "through a Squid upstream: the server verified inside its tunnel, the request decided and sent"
        else flunk "inspecting through a Squid upstream ($(cat "$OUT/up.out"); $(tail -2 "$SQ/access.log" 2>/dev/null))"; fi
        if python3 "$HERE/tools/varek_audit.py" --policy "$OUT/up.policy" --checker "$CERT" "$OUT/up.log" > /dev/null 2>&1
        then pass "the audit accepts the upstream run"; else flunk "the audit accepts the upstream run"; fi
        pkill -9 -f "$SQ/squid.conf" 2>/dev/null
        rm -rf "$SQ"
    fi

    echo "== 5. request decisions =="
    TP=$((P1 + 10)); HP=$((P1 + 11))
    rm -f "$OUT/echo.log"; touch "$OUT/echo.log"; chmod 666 "$OUT/echo.log"
    python3 "$HERE/tests/v1261_echo_server.py" "$HOSTIP" "$TP" "$OUT/echo.log" "$W/good.pem" "$W/good.key" > /dev/null 2>&1 &
    SRV="$SRV $!"
    python3 "$HERE/tests/v1261_echo_server.py" "$HOSTIP" "$HP" "$OUT/echo.log" > /dev/null 2>&1 &
    SRV="$SRV $!"
    for _ in $(seq 50); do python3 -c "import socket; [socket.create_connection(('$HOSTIP', p), 0.2) for p in ($TP, $HP)]" 2>/dev/null && break; sleep 0.1; done
    cat > "$W/req.py" <<'PY'
import hashlib, socket, ssl, sys, time
TP, HP = int(sys.argv[1]), int(sys.argv[2])
H = "api.example.com"
def conn(tls=True):
    s = socket.create_connection((H, TP if tls else HP), 10)
    return ssl.create_default_context().wrap_socket(s, server_hostname=H) if tls else s
def reads(s):
    out = b""
    s.settimeout(15)
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            out += d
    except (OSError, ssl.SSLError):
        pass
    return out
def answers(out):
    """each response: its status line and body (Content-Length framed)"""
    res = []
    while out:
        head, _, rest = out.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        cl = next((int(l.split(b":")[1]) for l in lines if l.lower().startswith(b"content-length:")), 0)
        res.append(lines[0].decode() + " | " + rest[:cl].decode(errors="replace").strip())
        out = rest[cl:]
    return res
def run(tag, data, tls=True, close=True):
    s = conn(tls)
    s.sendall(data)
    if close and tls:
        pass
    for a in answers(reads(s)):
        print(tag, a, flush=True)
def get(path, host=H, extra=b""):
    return b"GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\n" % (path.encode(), host.encode(), extra)
def post(path, body, chunked=False, method="POST"):
    if chunked:
        b = b"".join(b"%x\r\n%s\r\n" % (len(body[i:i + 700]), body[i:i + 700]) for i in range(0, len(body), 700)) + b"0\r\n\r\n"
        return b"%s %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n%s" % (method.encode(), path.encode(), H.encode(), b)
    return b"%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s" % (method.encode(), path.encode(), H.encode(), len(body), body)
# one kept-alive connection: two allowed, one a rule denies, one after it
s = conn()
for req in (get("/v1/models"), get("/v1/files?limit=5"), get("/v1/admin/users/1", extra=b"X-Method: DELETE\r\n"), get("/v1/models")):
    s.sendall(req)
    time.sleep(0.3)
for a in answers(reads(s)):
    print("KEEP", a, flush=True)
run("PIPE", get("/v1/models") + get("/v1/models") + get("/other"))
run("NORULE", get("/other"))
run("QUERY", get("/v1/models?x=1"))
run("FRONT", get("/v1/models") + get("/v1/models", host="other.example.com"))
body = bytes(range(256)) * 2                                   # 512 bytes
print("SHA512", hashlib.sha256(body).hexdigest(), flush=True)
run("UPLOAD", post("/v1/upload", body))
run("OVER", post("/v1/upload", b"x" * 2000))
big = b"y" * 3000
run("CUT", post("/v1/upload", big, chunked=True))
data = b"z" * 5000
print("SHA5000", hashlib.sha256(data).hexdigest(), flush=True)
run("CHUNKED", post("/v1/data", data, chunked=True, method="PUT"))
run("PLAIN", get("/plain"), tls=False)
run("PLAINNO", get("/other"), tls=False)
PY
    chmod 644 "$W/req.py"
    POL5="$OUT/req.policy"
    { printf 'require warden 1.26\nproxy inspect\nproxy ports %s %s\nallow host api.example.com\n' "$TP" "$HP"
      printf 'allow request POST https://api.example.com:%s/v1/upload max_body=1k\n' "$TP"   # line 5
      printf 'allow request GET https://api.example.com:%s/v1/models\n' "$TP"                # 6
      printf 'allow request GET https://api.example.com:%s/v1/files?limit=*\n' "$TP"         # 7
      printf 'deny request * https://api.example.com:%s/v1/admin/**\n' "$TP"                 # 8
      printf 'allow request * https://api.example.com:%s/v1/**\n' "$TP"                     # 9
      printf 'allow request GET http://api.example.com:%s/plain\n' "$HP"                     # 10
      printf 'allow request GET https://api.example.com:%s/v1/**?*\n' "$TP"                 # 11: a query (review)
      printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/\n' "$W"
    } > "$POL5"
    env -i PATH=/usr/bin:/bin timeout 180 "$WARDEN" "$POL5" --dns-server "127.0.0.1:$DPORT" --trust-bundle "$BUNDLE" -- \
        /usr/bin/python3 "$W/req.py" "$TP" "$HP" > "$OUT/r.out" 2> "$OUT/r.log"
    sed 's/^/     /' "$OUT/r.out"
    sed 's/^/     server /' "$OUT/echo.log"
    rhave() { grep -qxF -- "$1" "$OUT/r.out"; }
    ehave() { grep -qxF -- "$1" "$OUT/echo.log"; }
    E0=$(printf '' | sha256sum | cut -d' ' -f1)
    nreq() { python3 - "$OUT/r.log" "$1" "$2" "$3" <<'PY'
import json, sys
for l in open(sys.argv[1]):
    if l.startswith("{"):
        r = json.loads(l)
        if r.get("action") == "net.request" and r.get("target") == sys.argv[2] and r.get("rule") == sys.argv[3] and \
                (sys.argv[4] == "-" or str(r.get("policy_line")) == sys.argv[4]) and \
                (r.get("decision_final") != "ALLOW" or r.get("check") == "ok"):
            print("yes"); break
PY
    }
    U="https://api.example.com:$TP"
    if rhave "KEEP HTTP/1.1 200 OK | ok GET /v1/models 0 $E0" && rhave "KEEP HTTP/1.1 200 OK | ok GET /v1/files?limit=5 0 $E0" &&
       rhave "KEEP HTTP/1.1 403 Forbidden | VAREK: this request was refused: the policy denies it (line 8)." &&
       [ "$(grep -c '^KEEP' "$OUT/r.out")" = 3 ]
    then pass "on one kept-alive connection: two requests allowed and answered, then one a deny rule refuses: 403, and nothing after"
    else flunk "a kept-alive connection's requests"; fi
    if [ "$(nreq "GET $U/v1/models" request_allowed 6)" = yes ] && [ "$(nreq "GET $U/v1/files?limit=5" request_allowed 7)" = yes ] &&
       [ "$(nreq "GET $U/v1/admin/users/1" policy_match 8)" = yes ]
    then pass "each request recorded (net.request) with its rule, the allowed ones certified"
    else flunk "each request recorded with its rule"; fi
    if ! grep -q "/v1/admin" "$OUT/echo.log"; then pass "the refused request never reached the server"
    else flunk "the refused request never reached the server"; fi
    if [ "$(grep -c '^PIPE HTTP/1.1 200 OK | ok GET /v1/models' "$OUT/r.out")" = 2 ] &&
       rhave "PIPE HTTP/1.1 403 Forbidden | VAREK: this request was refused: no request rule allows it."
    then pass "pipelined requests: each decided in turn; the third, which no rule allows, refused after the first two's answers"
    else flunk "pipelined requests"; fi
    if rhave "NORULE HTTP/1.1 403 Forbidden | VAREK: this request was refused: no request rule allows it." &&
       [ "$(nreq "GET $U/other" default_deny_unknown -)" = yes ]
    then pass "a request no rule allows is refused (default_deny_unknown)"
    else flunk "a request no rule allows is refused"; fi
    if rhave "QUERY HTTP/1.1 200 OK | ok GET /v1/models?x=1 0 $E0" && [ "$(nreq "GET $U/v1/models?x=1" request_allowed 11)" = yes ]
    then pass "a query is matched: /v1/models?x=1 is not the exact rule's (line 6) nor /v1/**'s (line 9, no query), but /v1/**?*'s (line 11)"
    else flunk "a query is matched"; fi
    if rhave "FRONT HTTP/1.1 200 OK | ok GET /v1/models 0 $E0" &&
       rhave "FRONT HTTP/1.1 403 Forbidden | VAREK: this request was refused: a Host other than the name and port the connection is for."
    then pass "a later request for another Host on the same connection: refused by the parser, not sent"
    else flunk "a later request for another Host"; fi
    S512=$(grep '^SHA512 ' "$OUT/r.out" | cut -d' ' -f2); S5000=$(grep '^SHA5000 ' "$OUT/r.out" | cut -d' ' -f2)
    body_rec() { python3 - "$OUT/r.log" "$1" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
req = [r for r in recs if r.get("action") == "net.request" and r.get("target") == sys.argv[2]]
for b in recs:
    if b.get("event") == "request_body" and any(b["proxy_conn"] == r["proxy_conn"] and b["request_seq"] == r["request_seq"] for r in req):
        print(b["body_len"], b["body_sha256"], b.get("exceeded_max_body", False))
PY
    }
    if rhave "UPLOAD HTTP/1.1 200 OK | ok POST /v1/upload 512 $S512" && ehave "GOT POST /v1/upload 512 $S512" &&
       [ "$(body_rec "POST $U/v1/upload" | head -1)" = "512 $S512 False" ]
    then pass "an allowed body (512 bytes, within max_body=1k): sent, and its length and SHA-256 recorded are the server's"
    else flunk "an allowed body's record ($(body_rec "POST $U/v1/upload"))"; fi
    if rhave "OVER HTTP/1.1 403 Forbidden | VAREK: this request was refused: its body is over max_body=1024 (policy line 5)." &&
       [ "$(nreq "POST $U/v1/upload" max_body 5)" = yes ] && ! ehave "GOT POST /v1/upload 2000 $(printf 'x%.0s' $(seq 2000) | sha256sum | cut -d' ' -f1)"
    then pass "a body declared over max_body is refused before a byte is sent (max_body)"
    else flunk "a body declared over max_body is refused"; fi
    if ! grep -q "^CUT HTTP/1.1 200" "$OUT/r.out" && body_rec "POST $U/v1/upload" | grep -q "^1024 [0-9a-f]* True$" &&
       grep '"event":"proxy_close"' "$OUT/r.log" | grep -q '"why":"max_body"' && ! grep -q "^GOT POST /v1/upload 3000" "$OUT/echo.log"
    then pass "a chunked body passing max_body is cut there: recorded at 1,024 bytes, the connection ended (max_body)"
    else flunk "a chunked body passing max_body is cut"; fi
    if rhave "CHUNKED HTTP/1.1 200 OK | ok PUT /v1/data 5000 $S5000" &&
       body_rec "PUT $U/v1/data" | grep -q "^5[0-9][0-9][0-9] [0-9a-f]* False$"
    then pass "a chunked body with no max_body: sent whole, its bytes as sent recorded"
    else flunk "a chunked body with no max_body ($(body_rec "PUT $U/v1/data"))"; fi
    if rhave "PLAIN HTTP/1.1 200 OK | ok GET /plain 0 $E0" &&
       rhave "PLAINNO HTTP/1.1 403 Forbidden | VAREK: this request was refused: no request rule allows it." &&
       [ "$(nreq "GET http://api.example.com:$HP/plain" request_allowed 10)" = yes ]
    then pass "plain HTTP: each request decided on its http:// object"
    else flunk "plain HTTP: each request decided"; fi
    if python3 "$HERE/tools/varek_audit.py" --policy "$POL5" --checker "$CERT" "$OUT/r.log" > "$OUT/au5.out" 2>&1
    then pass "the audit accepts the run ($(grep -o '[0-9]* inspected requests' "$OUT/au5.out"))"
    else flunk "the audit accepts the run ($(grep -m3 'PROBLEM' "$OUT/au5.out"))"; fi
    POL="$POL5"
    forge "$OUT/r.log" "$OUT/q1.log" "\"target\":\"GET $U/v1/files?limit=5\",\"resolved\":\"GET $U/v1/files?limit=5\"" \
                                     "\"target\":\"GET $U/v1/admin/x\",\"resolved\":\"GET $U/v1/admin/x\""
    refuses "an allowed request whose object the policy denies (its certificate fails)" "$OUT/q1.log" "refused"
    forge "$OUT/r.log" "$OUT/q2.log" '"body_len":512,' '"body_len":1500,'
    refuses "a body over its rule's max_body recorded as sent" "$OUT/q2.log" "over its rule's max_body"
    forge "$OUT/r.log" "$OUT/q3.log" '"body":"length","body_declared":512,"max_body":1024,' '"body":"length","body_declared":512,'
    refuses "an allowed request without its rule's max_body" "$OUT/q3.log" "max_body is not its rule's"
    forge "$OUT/r.log" "$OUT/q4.log" '"request_seq":2,' '"request_seq":3,'
    refuses "requests out of order" "$OUT/q4.log" "out of order"

    echo "== 6. audit and tools =="
    # each inspected close counts the requests recorded on its connection
    if python3 - "$OUT/r.log" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
closes = [r for r in recs if r.get("event") == "proxy_close" and r.get("inspected")]
n = lambda c: sum(1 for r in recs if r.get("action") == "net.request" and r.get("proxy_conn") == c)
sys.exit(not closes or any(c.get("requests") != n(c["proxy_conn"]) for c in closes))
PY
    then pass "each inspected proxy_close counts the requests recorded on its connection"
    else flunk "each inspected proxy_close counts its requests"; fi
    C1=$(grep -m1 -o '"inspected":true,"requests":[0-9]*,' "$OUT/r.log")
    N1=${C1#*requests\":}; N1=${N1%,}
    forge "$OUT/r.log" "$OUT/s1.log" "$C1" "\"inspected\":true,\"requests\":$((N1 + 1)),"
    refuses "a close whose request count disagrees with the records" "$OUT/s1.log" "were recorded on it"
    # each refusal is asked of the policy again
    forge "$OUT/r.log" "$OUT/s2.log" '"rule":"policy_match","policy_line":8,' '"rule":"policy_match","policy_line":6,'
    refuses "a refusal by a deny rule at a line that is not the rule deciding it" "$OUT/s2.log" "not the deny rule that decides it"
    forge "$OUT/r.log" "$OUT/s3.log" "\"target\":\"GET $U/other\",\"resolved\":\"GET $U/other\"" \
                                     "\"target\":\"GET $U/v1/models\",\"resolved\":\"GET $U/v1/models\""
    refuses "a request refused as matching no rule, which a rule matches" "$OUT/s3.log" "but policy line 6 matches it"
    forge "$OUT/r.log" "$OUT/s4.log" '"body_declared":2000,' '"body_declared":900,'
    refuses "a max_body refusal of a body within the rule's max_body" "$OUT/s4.log" "does not limit it below"
    # varek refusals explains each refused request and each connection the proxy ended
    printf '[varek]\npolicy = %s\nlog_dir = %s\n' "$POL5" "$OUT" > "$OUT/varek.conf"
    VAREK_CONFIG="$OUT/varek.conf" python3 "$HERE/tools/varek" refusals -n 500 "$OUT/r.log" > "$OUT/rf.out" 2>&1
    VAREK_CONFIG="$OUT/varek.conf" python3 "$HERE/tools/varek" refusals -n 500 "$OUT/c.log" > "$OUT/rf4.out" 2>&1
    rf() { grep -qF -- "$2" "$OUT/$1"; }
    if rf rf.out "UNSATISFIED  net.request    GET $U/v1/admin/users/1" &&
       rf rf.out "policy line 8: deny request * $U/v1/admin/**; the agent got 403 Forbidden" &&
       rf rf.out "UNKNOWN      net.request    GET $U/other" && rf rf.out "no request rule allows it; the agent got 403" &&
       rf rf.out "MAX_BODY     net.request    POST $U/v1/upload" && rf rf.out "(2000 bytes declared) is over that rule's max_body"
    then pass "varek refusals: a deny rule's refusal with its line, a request no rule allows, a body over max_body"
    else flunk "varek refusals explains refused requests ($(grep -m2 net.request "$OUT/rf.out"))"; fi
    if rf rf.out "REFUSED      proxy_close" && rf rf.out "a Host other than the name and port the connection is for" &&
       rf rf.out "the body passed max_body=1024; the connection was cut there" &&
       rf rf4.out "SERVER_TLS   proxy_close" && rf rf4.out "the server failed verification: certificate: self-signed certificate" &&
       [ "$(grep -c '^  REFUSED      proxy_close' "$OUT/rf.out")" = 1 ]
    then pass "varek refusals: the connections the proxy ended (its parser, a cut body, a server failing verification), each once"
    else flunk "varek refusals lists the connections the proxy ended"; fi
    # the CycloneDX export carries inspecting mode
    if python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/r.log" --policy "$POL5" --output "$OUT/bom.json" > "$OUT/bom.out" 2>&1 &&
       python3 - "$OUT/bom.json" "$OUT/r.log" <<'PY'
import json, sys
b = json.load(open(sys.argv[1]))
recs = [json.loads(l) for l in open(sys.argv[2]) if l.startswith("{")]
rs = next(r for r in recs if r.get("event") == "run_start")
f = {p["name"]: p["value"] for p in b["metadata"]["component"]["properties"]}
req = [r for r in recs if r.get("action") == "net.request"]
ok = [r for r in req if r["decision_final"] == "ALLOW"]
t = b["annotations"][0]["text"]
names = {c["name"] for c in b["components"]}
sys.exit(not (f["varek:proxy.mode"] == "inspect" and f["varek:proxy.binary.sha256"] == rs["proxy_binary_sha256"]
              and f["varek:proxy.ca.sha256"] == rs["trust"]["ca_sha256"]
              and f["varek:requests.total"] == str(len(req)) and f["varek:requests.allowed"] == str(len(ok))
              and f["varek:requests.refused.max_body"] == "1" and f["varek:requests.bodies.cut"] == "1"
              and "ran in inspecting mode" in t and "never their contents" in t
              and all(r["target"] in names for r in ok)))
PY
    then pass "the CycloneDX export: the proxy's mode and hashes, the run's CA, request counts, each allowed request a component"
    else flunk "the CycloneDX export carries inspecting mode ($(tail -2 "$OUT/bom.out"))"; fi

    echo "== 7. review fixes =="
    # the v1.26.1 review by AI review agents: each finding, fixed, checked here
    XP=$((TP + 20)); CP=$((TP + 21))
    ( cd "$W" && openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout cn.key -out cn.csr \
          -subj "/CN=api.example.com" && printf 'extendedKeyUsage=serverAuth\n' > cn.ext &&
      openssl x509 -req -in cn.csr -CA tca.pem -CAkey tca.key -CAcreateserial -out cn.pem -days 1 -extfile cn.ext ) \
        >> "$OUT/certs.log" 2>&1
    chmod 644 "$W/cn.pem"
    rm -f "$OUT/rv.log"; touch "$OUT/rv.log"; chmod 666 "$OUT/rv.log"
    cat > "$OUT/rvsrv.py" <<'PY'
import hashlib, socket, ssl, sys, threading
ip, port, cert, key, log = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
def note(t):
    with open(log, "a") as f: f.write(t + "\n")
def serve(c):
    try:
        s = ctx.wrap_socket(c, server_side=True)
        buf = b""
        while True:
            while b"\r\n\r\n" not in buf:
                d = s.recv(65536)
                if not d: return
                buf += d
            head, _, buf = buf.partition(b"\r\n\r\n")
            path = head.split(b" ")[1].decode()
            if path == "/trunc":            # an answer, then the TCP connection dropped: no close_notify
                s.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nPARTIAL")
                raw = socket.socket(fileno=s.detach()); raw.shutdown(socket.SHUT_RDWR); raw.close()
                return
            if path in ("/raw", "/part"):   # what follows the head, to the connection's end
                while True:
                    d = s.recv(65536)
                    if not d: break
                    buf += d
                note(f"RAW {path} {len(buf)} {hashlib.sha256(buf).hexdigest()}")
                return
            note(f"GOT {path}")
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    except (OSError, ssl.SSLError):
        pass
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind((ip, port)); l.listen(16)
while True:
    c, _ = l.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
    python3 "$OUT/rvsrv.py" "$HOSTIP" "$XP" "$W/good.pem" "$W/good.key" "$OUT/rv.log" > /dev/null 2>&1 &
    SRV="$SRV $!"
    python3 "$OUT/rvsrv.py" "$HOSTIP" "$CP" "$W/cn.pem" "$W/cn.key" "$OUT/rv.log" > /dev/null 2>&1 &
    SRV="$SRV $!"
    for _ in $(seq 50); do python3 -c "import socket; [socket.create_connection(('$HOSTIP', p), 0.2) for p in ($XP, $CP)]" 2>/dev/null && break; sleep 0.1; done
    cat > "$W/rv.py" <<'PY'
import hashlib, os, socket, ssl, sys, time
XP, CP = int(sys.argv[1]), int(sys.argv[2])
H = "api.example.com"
ctx = ssl.create_default_context()
def conn(port=None):
    return ctx.wrap_socket(socket.create_connection((H, port or XP), 10), server_hostname=H,
                           suppress_ragged_eofs=False)
def reads(s):
    out = b""
    s.settimeout(15)
    try:
        while True:
            d = s.recv(65536)
            if not d: return out, "clean"
            out += d
    except (OSError, ssl.SSLError) as e:
        return out, type(e).__name__
# a server that drops its connection without close_notify: the agent must see it
s = conn(); s.sendall(b"GET /trunc HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % H.encode())
out, how = reads(s); print("TRUNC", how, out.split(b"\r\n\r\n")[-1].decode(), flush=True)
# a server certificate with the name in its CN alone (no subject alternative name)
try:
    s = conn(CP); s.close(); print("CNONLY connected", flush=True)
except (OSError, ssl.SSLError) as e:
    print("CNONLY", type(e).__name__, flush=True)
# the views' metadata: read-only files, read-type lookups only
print("MODE", oct(os.stat("/etc/varek/run-ca.pem").st_mode), os.access("/etc/varek/run-ca.pem", os.R_OK), flush=True)
# a chunked body over max_body=100, sent with its head in one write: the
# server gets the head and the body up to the limit, then the cut
body = b"12c\r\n" + b"A" * 300 + b"\r\n0\r\n\r\n"
s = conn(); s.sendall(b"POST /raw HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n" % H.encode() + body)
reads(s); print("CUTSENT", hashlib.sha256(body[:100]).hexdigest(), flush=True)
# a request, then the agent's TCP half-close: the answer still comes back
s = conn(); s.sendall(b"GET /v1/models HTTP/1.1\r\nHost: %s\r\n\r\n" % H.encode())
socket.socket.shutdown(s, socket.SHUT_WR)
out, how = reads(s); print("HALF", out.split(b"\r\n")[0].decode(), flush=True)
# a body declared at 1000 bytes, 300 sent, then the connection closed
s = conn(); s.sendall(b"POST /part HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000\r\n\r\n" % H.encode() + b"B" * 300)
time.sleep(0.5); s.close(); print("PARTSENT", hashlib.sha256(b"B" * 300).hexdigest(), flush=True)
time.sleep(0.5)
# a target with a second '?': refused by the proxy's parser, never decided
s = conn(); s.sendall(b"GET /v1/models?a?b HTTP/1.1\r\nHost: %s\r\n\r\n" % H.encode())
out, how = reads(s); print("TWOQ", out.split(b"\r\n")[0].decode(), out.split(b"\r\n\r\n")[-1].decode().strip(), flush=True)
PY
    POL7="$OUT/rv.policy"
    { printf 'require warden 1.26\nproxy inspect\nproxy ports %s %s\nallow host api.example.com\n' "$XP" "$CP"
      printf 'allow request GET https://api.example.com:%s/trunc\n' "$XP"
      printf 'allow request POST https://api.example.com:%s/raw max_body=100\n' "$XP"
      printf 'allow request POST https://api.example.com:%s/part max_body=10k\n' "$XP"
      printf 'allow request GET https://api.example.com:%s/v1/models\n' "$XP"
      printf 'allow request GET https://api.example.com:%s/\n' "$CP"
      printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/\n' "$W"
    } > "$POL7"
    env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$POL7" --dns-server "127.0.0.1:$DPORT" --trust-bundle "$BUNDLE" -- \
        /usr/bin/python3 "$W/rv.py" "$XP" "$CP" > "$OUT/rv.out" 2> "$OUT/rvw.log"
    sed 's/^/     /' "$OUT/rv.out"; sed 's/^/     server /' "$OUT/rv.log"
    vhave() { grep -qxF -- "$1" "$OUT/rv.out"; }
    rvrec() { grep "$1" "$OUT/rvw.log" | grep -q -- "$2"; }
    if grep -q '^TRUNC SSLEOFError PARTIAL$' "$OUT/rv.out" &&
       rvrec '"event":"proxy_close"' "\"tls_error\":\"the server's TLS ended without close_notify\""
    then pass "a server that drops its TLS without close_notify: the agent's TLS sees the cut (no clean close), recorded"
    else flunk "a server's TLS dropped without close_notify ($(grep TRUNC "$OUT/rv.out"))"; fi
    if vhave "CNONLY SSLError" && rvrec '"why":"server_tls"' 'hostname mismatch'
    then pass "a server certificate naming the host in its CN alone is refused (server_tls)"
    else flunk "a CN-only server certificate is refused ($(grep CNONLY "$OUT/rv.out"))"; fi
    if vhave "MODE 0o100444 True"
    then pass "a view's metadata: a read-only regular file (0444)"
    else flunk "a view's metadata mode ($(grep MODE "$OUT/rv.out"))"; fi
    CUTSHA=$(grep '^CUTSENT ' "$OUT/rv.out" | cut -d' ' -f2)
    if grep -q "^RAW /raw 100 $CUTSHA$" "$OUT/rv.log" &&
       rvrec '"event":"request_body"' "\"body_len\":100,\"body_sha256\":\"$CUTSHA\",\"exceeded_max_body\":true"
    then pass "a chunked body cut at max_body: the server gets what was let through, the bytes and SHA-256 recorded"
    else flunk "a chunked body cut at max_body ($(grep RAW "$OUT/rv.log"))"; fi
    if vhave "HALF HTTP/1.1 200 OK"
    then pass "an agent that half-closes after its request still gets the answer"
    else flunk "a half-closing agent's answer ($(grep HALF "$OUT/rv.out"))"; fi
    PSHA=$(grep '^PARTSENT ' "$OUT/rv.out" | cut -d' ' -f2)
    if rvrec '"event":"request_body"' "\"body_len\":300,\"body_sha256\":\"$PSHA\",\"incomplete\":true" &&
       grep -q "^RAW /part 300 $PSHA$" "$OUT/rv.log"
    then pass "a body cut short by the agent's close: what was sent recorded, marked incomplete"
    else flunk "a body cut short by the agent's close"; fi
    if vhave "TWOQ HTTP/1.1 403 Forbidden VAREK: this request was refused: more than one '?' in the target." &&
       ! grep '"action":"net.request"' "$OUT/rvw.log" | grep -q 'models?a?b'
    then pass "a target with a second '?' is refused by the proxy, never decided"
    else flunk "a target with a second '?' ($(grep TWOQ "$OUT/rv.out"))"; fi
    if python3 "$HERE/tools/varek_audit.py" --policy "$POL7" --checker "$CERT" "$OUT/rvw.log" > "$OUT/au7.out" 2>&1
    then pass "the audit accepts the run"
    else flunk "the audit accepts the review run ($(grep -m3 'PROBLEM' "$OUT/au7.out"))"; fi
    if openssl x509 -in "$W/cn.pem" -noout -ext subjectAltName 2>&1 | grep -q DNS; then
        flunk "the CN-only certificate has no subject alternative name"; fi
    # the forged streams the review found the audit (or the export) accepted
    vforge() { python3 "$HERE/tests/v1261_forge.py" "$@" || flunk "forging $2"; }
    POL="$POL5"
    vforge "$OUT/r.log" "$OUT/v1.log" --sub '"body":"length","body_declared":512,"max_body":1024,' \
                                           '"body":"length","body_declared":50000,"max_body":1024,'
    refuses "an allowed request declaring a body over its rule's max_body" "$OUT/v1.log" "over its rule's max_body"
    vforge "$OUT/r.log" "$OUT/v2.log" --sub "\"target\":\"GET $U/v1/models?x=1\",\"resolved\":\"GET $U/v1/models?x=1\"" \
                                            "\"target\":\"GET $U/v1/%61dmin/users/1\",\"resolved\":\"GET $U/v1/%61dmin/users/1\""
    refuses "an allowed request whose path is in a form the proxy must refuse (%61dmin)" "$OUT/v2.log" "which the proxy must refuse"
    UB=$(grep -m1 -o '"event":"request_body","run":"[0-9a-f]*","proxy_conn":[0-9]*,' "$OUT/r.log")
    vforge "$OUT/r.log" "$OUT/v3.log" --drop "$UB"
    refuses "an allowed body with no request_body" "$OUT/v3.log" "never recorded"
    QS=$(grep '"action":"net.request"' "$OUT/r.log" | grep "\"target\":\"GET $U/v1/models?x=1\"" | grep -o '"seq":[0-9]*,' | head -1)
    QC=$(grep '"action":"net.request"' "$OUT/r.log" | grep "\"target\":\"GET $U/v1/models?x=1\"" | grep -o '"proxy_conn":[0-9]*,' | head -1)
    QN=${QS#\"seq\":}; QN=${QN%,}
    # the connection's close moved to just before its request (closes carry no seq)
    vforge "$OUT/r.log" "$OUT/v4.log" --move "\"event\":\"proxy_close\",\"run\":\"$(grep -o '"run":"[0-9a-f]*"' "$OUT/r.log" | head -1 | cut -d'"' -f4)\",$QC" "\"seq\":$((QN - 1)),\"agent_pid\""
    refuses "a request recorded after its connection's close" "$OUT/v4.log" "after its close"
    vforge "$OUT/r.log" "$OUT/v5.log" --sub '"ca_names":1,' '"ca_names":500,'
    refuses "run_start's CA claiming names the policy does not give it" "$OUT/v5.log" "may sign for 500"
    POL="$POL7"
    VA=$(grep '"rule":"view_metadata"' "$OUT/rvw.log" | grep -o '"action":"file.access".*"access_mode":"4"' | head -1)
    vforge "$OUT/rvw.log" "$OUT/v6.log" --sub "$VA" "${VA%\"4\"}\"2\""
    refuses "a view's metadata answering access(W_OK)" "$OUT/v6.log" "not read-type"
    vforge "$OUT/rvw.log" "$OUT/v7.log" --sub '"mode":"inspect"' '"mode":"sni"'
    if python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/v7.log" --policy "$POL7" > /dev/null 2> "$OUT/v7.out"; then
        flunk "the export refuses trust views in a run not in inspecting mode"
    elif grep -q "UNKNOWN verdict into ALLOW" "$OUT/v7.out"; then
        pass "the export refuses trust views in a run not in inspecting mode"
    else flunk "the export refuses trust views in a run not in inspecting mode ($(cat "$OUT/v7.out"))"; fi
    UN=${UB##*\"proxy_conn\":}; UN=${UN%,}
    vforge "$OUT/r.log" "$OUT/v8.log" --sub "$UB" "${UB%\"proxy_conn\":*}\"proxy_conn\":[$UN],"
    POL="$POL5"
    python3 "$HERE/tools/varek_audit.py" --policy "$POL5" --checker "$CERT" "$OUT/v8.log" > "$OUT/v8.out" 2>&1
    VC=$?
    NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" refusals "$OUT/v8.log" > "$OUT/v8r.out" 2>&1
    if [ "$VC" != 0 ] && grep -q "malformed connection id" "$OUT/v8.out" && ! grep -q Traceback "$OUT/v8.out" "$OUT/v8r.out"
    then pass "a malformed connection id: the audit refuses it, and neither the audit nor varek refusals crashes"
    else flunk "a malformed connection id ($(grep -h -m2 'Error\|PASS' "$OUT/v8.out" "$OUT/v8r.out"))"; fi
    for pid in $SRV; do kill "$pid" 2>/dev/null; done
    rm -rf "$W"
fi

if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ] || [ ! -x "$WP" ]; then
    echo "== 8. bench =="
    skip "the proxied bench (needs root, the warden binary and warden-proxy)"
else
    echo "== 8. bench =="
    # varek bench --proxy: requests natively, in SNI mode and in inspecting
    # mode, every outcome checked; and no delayed-ACK stall on a new
    # inspected connection (before step 8, about 40 ms: the proxy sends
    # nothing after the client's Finished, with no session tickets)
    if NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" bench --proxy -n 30 --warmup 3 --rounds 1 \
           -o "$OUT/bench.json" > "$OUT/bench.out" 2>&1 &&
       python3 - "$OUT/bench.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
k = r["kinds"]
sys.exit(not (r["ok"] and k["https"]["added_p50_us"]["inspect"] < 30000 and
              k["request"]["added_p50_us"]["inspect"] < 10000 and r["warden_us"]["request_allowed"]["n"] >= 29))
PY
    then pass "varek bench --proxy: every check passed; inspecting mode adds $(python3 -c "import json; k = json.load(open('$OUT/bench.json'))['kinds']; print(f\"{k['https']['added_p50_us']['inspect'] / 1000:.1f} ms to a new connection, {k['request']['added_p50_us']['inspect']:.0f} us to a kept-alive request\")")"
    else flunk "varek bench --proxy ($(grep -m3 'FAIL\|varek:' "$OUT/bench.out"))"; fi
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1261: PASS ($skips skipped)"; else echo "test_v1261: FAIL"; fi
exit "$fail"
