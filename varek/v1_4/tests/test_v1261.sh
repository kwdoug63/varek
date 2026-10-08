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
    if have "TLS inspected ALERT" && px "api.example.com:$TP" inspect_not_built
    then pass "until requests are decided, an inspected host is refused (inspect_not_built)"
    else flunk "an inspected host is refused (inspect_not_built)"; fi
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
    forge "$OUT/c.log" "$OUT/g4.log" "\"target\":\"api.example.com:$TP\",\"resolved\":\"api.example.com:$TP\",\"decision_raw\":\"ALLOW\",\"decision_final\":\"DENY\",\"rule\":\"inspect_not_built\"" \
                                     "\"target\":\"api.example.com:$TP\",\"resolved\":\"api.example.com:$TP\",\"decision_raw\":\"ALLOW\",\"decision_final\":\"ALLOW\",\"rule\":\"proxy_dialed\""
    refuses "an inspected host passed on before requests are decided" "$OUT/g4.log" "not a passthrough host, was passed on"
    for pid in $SRV; do kill "$pid" 2>/dev/null; done
    rm -rf "$W"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1261: PASS ($skips skipped)"; else echo "test_v1261: FAIL"; fi
exit "$fail"
