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
#      and its environment names them; run_start records every hash; until
#      requests are decided (step 6) an inspected host is refused
#      (inspect_not_built) and a passthrough host relayed in SNI mode; the
#      audit accepts the run and refuses forged trust records and decisions
#   4. terminating TLS (as root): for an inspected host the proxy verifies the
#      server (against --trust-bundle) before it meets the client, then
#      completes the client's handshake with a leaf from the run's CA (the
#      name only, serverAuth, kept for the run), http/1.1 only; until
#      requests are decided (step 6) every request is answered 403 and the
#      server is sent nothing; refused and recorded: a server whose name or
#      issuer does not verify (server_tls), a client that does not trust the
#      CA or offers only h2 (client_tls), plain HTTP to an inspected host;
#      Python, curl, Node.js and Java trust the run's CA with no settings of
#      their own (Java through the store's metadata, answered from the
#      view); CONNECT clients and a Squid upstream; a passthrough host
#      relayed in SNI mode; the audit accepts the runs and refuses forged
#      inspected records
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
    if grep -A4 'Name Constraints: critical' "$OUT/ca.txt" | grep -q 'DNS:api.example.com' &&
       grep -A4 'Name Constraints: critical' "$OUT/ca.txt" | grep -q 'DNS:svc.example.com' &&
       ! grep -q 'DNS:pinned.example.net' "$OUT/ca.txt"
    then pass "critical name constraints: the inspected names and the wildcard's suffix, not the passthrough host"
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
        if d: print("GOT", d.split(b"\r\n")[0].decode(errors="replace"), flush=True)
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
    NB="VAREK: this request was not sent"
    if have "TLS verified True None HTTP/1.1 403 Forbidden $NB" && have "TLS again True None HTTP/1.1 403 Forbidden $NB"
    then pass "a verifying client completes TLS with the run's CA, and its request is answered 403"
    else flunk "a verifying client completes TLS with the run's CA (see above)"; fi
    if ! grep -q '^GOT ' "$OUT/srv$P1.log"; then pass "the server was verified but sent no request"
    else flunk "the server was sent no request ($(cat "$OUT/srv$P1.log"))"; fi
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
    if have "TLS alpn-both True http/1.1 HTTP/1.1 403 Forbidden $NB" && have "TLS alpn-h2 SSLERR False" &&
       close_of "api.example.com:$P1" | grep -q '"tls_error": "handshake: no application protocol"'
    then pass "http/1.1 is chosen; a client offering only h2 is refused (client_tls)"
    else flunk "ALPN (http/1.1 chosen, h2 alone refused)"; fi
    if have "TLS pinning SSLERR False" && close_of "api.example.com:$P1" | grep -q '"tls_error": "handshake: tlsv1 alert unknown ca"'
    then pass "a client that does not trust the run's CA fails its handshake, recorded (client_tls)"
    else flunk "a client that does not trust the run's CA"; fi
    if have "TLS connect True None HTTP/1.1 403 Forbidden $NB"; then pass "TLS inside a CONNECT is inspected too"
    else flunk "TLS inside a CONNECT is inspected too"; fi
    if have "TLS wrong-name SSLERR True" && close_of "api.example.com:$P2" | grep -q '"tls_error": "certificate: hostname mismatch"' &&
       have "TLS self-signed SSLERR True" && close_of "api.example.com:$P3" | grep -q '"tls_error": "certificate: self-signed certificate"' &&
       ! grep -q '^GOT ' "$OUT/srv$P2.log" "$OUT/srv$P3.log"
    then pass "a server whose name or issuer does not verify is refused before the client's handshake (server_tls)"
    else flunk "a server that does not verify is refused (server_tls)"; fi
    if have "TLS passthrough True None HTTP/1.1 200 OK server" &&
       grep '"action":"net.proxy"' "$OUT/t.log" | grep "\"target\":\"pinned.example.net:$P4\"" | grep -vq '"inspected"'
    then pass "a passthrough host is relayed in SNI mode, not inspected"
    else flunk "a passthrough host is relayed in SNI mode"; fi
    if have "HTTP HTTP/1.1 403 Forbidden" &&
       grep '"action":"net.proxy"' "$OUT/t.log" | grep "\"target\":\"api.example.com:$P1\"" | grep '"proxy_kind":"http"' | grep -q '"rule":"inspect_not_built"'
    then pass "plain HTTP to an inspected host is refused until requests are decided"
    else flunk "plain HTTP to an inspected host is refused"; fi
    GSHA=$(openssl x509 -in "$W/good.pem" -outform DER | sha256sum | cut -d' ' -f1)
    if close_of "api.example.com:$P1" | grep '"why": "inspect_not_built"' | grep -q "\"server_cert_sha256\": \"$GSHA\"" &&
       ! close_of "api.example.com:$P1" | grep '"why": "inspect_not_built"' | grep -vq '"bytes_down": 0, "bytes_up": 0'
    then pass "each inspected close records the server's certificate, and no bytes relayed"
    else flunk "the inspected closes' records"; fi
    if have "STAT 0o100000 True" && grep -q '"rule":"view_metadata"' "$OUT/t.log"
    then pass "the trust store's metadata is the view's (a regular file, its size)"
    else flunk "the trust store's metadata is the view's"; fi
    if python3 "$HERE/tools/varek_audit.py" --policy "$POL4" --checker "$CERT" "$OUT/t.log" > "$OUT/au4.out" 2>&1
    then pass "the audit accepts the run"
    else flunk "the audit accepts the run ($(grep -m3 'PROBLEM' "$OUT/au4.out"))"; fi
    POL="$POL4"
    forge "$OUT/t.log" "$OUT/h1.log" '"why":"inspect_not_built","bytes_up":0,' '"why":"inspect_not_built","bytes_up":512,'
    refuses "an inspected connection that relayed bytes before requests are decided" "$OUT/h1.log" "relayed bytes before requests are decided"
    forge "$OUT/t.log" "$OUT/h2.log" ',"inspected":true,"server_cert_sha256"' ',"server_cert_sha256"'
    refuses "an inspected connection's close not marked inspected" "$OUT/h2.log" "not marked inspected"
    forge "$OUT/t.log" "$OUT/h3.log" "\"target\":\"pinned.example.net:$P4\"," "\"target\":\"pinned.example.net:$P4\",\"inspected\":true,"
    refuses "a passthrough host's decision marked inspected" "$OUT/h3.log" "which only a host that is not passthrough is"

    # Real clients: curl, Node.js and Java, each with no settings of its own
    NODE=$(readlink -f "$(command -v node 2>/dev/null)" 2>/dev/null)
    JAVA=$(ls /usr/lib/jvm/java-21-openjdk-*/bin/java 2>/dev/null | head -1)
    [ -n "$JAVA" ] || JAVA=$(readlink -f "$(command -v java 2>/dev/null)" 2>/dev/null)
    POLC="$OUT/clients.policy"
    { printf 'require warden 1.26\nproxy inspect\nproxy ports %s\nallow host api.example.com\n' "$P1"
      for d in /usr/ /lib /proc/ /sys/ "$W/" ${NODE:+$(dirname "$(dirname "$NODE")")/} \
               ${JAVA:+$(dirname "$(dirname "$JAVA")")/} /etc/java-21-openjdk/ /etc/java-17-openjdk/; do
          printf 'allow path %s readonly\n' "$d"; done
      printf 'allow path /etc/ld.so.cache readonly\nallow path /etc/ssl/openssl.cnf readonly\nallow path /tmp/hsperfdata_nobody/\n'
    } > "$POLC"
    cl() { env -i PATH=/usr/bin:/bin timeout 90 "$WARDEN" "$POLC" --dns-server "127.0.0.1:$DPORT" --trust-bundle "$BUNDLE" -- "$@" 2> "$OUT/cl.log"; }
    URL="https://api.example.com:$P1/v1/models"
    if command -v curl > /dev/null; then
        if cl /usr/bin/curl -sS "$URL" | grep -q "^$NB"; then pass "curl verifies the run's CA (CURL_CA_BUNDLE) and gets the 403"
        else flunk "curl verifies the run's CA ($(grep '^\[agent\]' "$OUT/cl.log" | head -2))"; fi
    else skip "curl (not installed)"; fi
    if [ -n "$NODE" ]; then
        out=$(cl "$NODE" -e 'require("https").get(process.argv[1], r => { let b = ""; r.on("data", d => b += d); r.on("end", () => console.log("NODE", r.statusCode, b.split(";")[0])); }).on("error", e => console.log("NODE ERR", e.message))' "$URL")
        if [ "$out" = "NODE 403 $NB" ]; then pass "Node.js verifies the run's CA (NODE_EXTRA_CA_CERTS) and gets the 403"
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
        if [ "$out" = "JAVA 403 $NB" ]; then pass "Java verifies the run's CA (the PKCS#12 store, JAVA_TOOL_OPTIONS) and gets the 403"
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
        if grep -qx "UP HTTP/1.1 403 Forbidden" "$OUT/up.out" && grep -q "CONNECT api.example.com:$P1" "$SQ/access.log" &&
           grep '"event":"proxy_close"' "$OUT/up.log" | grep -q '"why":"inspect_not_built".*"inspected":true,"server_cert_sha256"'
        then pass "through a Squid upstream: the server verified inside its tunnel, the request answered 403"
        else flunk "inspecting through a Squid upstream ($(cat "$OUT/up.out"); $(tail -2 "$SQ/access.log" 2>/dev/null))"; fi
        if python3 "$HERE/tools/varek_audit.py" --policy "$OUT/up.policy" --checker "$CERT" "$OUT/up.log" > /dev/null 2>&1
        then pass "the audit accepts the upstream run"; else flunk "the audit accepts the upstream run"; fi
        pkill -9 -f "$SQ/squid.conf" 2>/dev/null
        rm -rf "$SQ"
    fi
    for pid in $SRV; do kill "$pid" 2>/dev/null; done
    rm -rf "$W"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1261: PASS ($skips skipped)"; else echo "test_v1261: FAIL"; fi
exit "$fail"
