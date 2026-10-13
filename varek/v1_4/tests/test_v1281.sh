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
#   2. verifying: warden-secrets checks the user's token (--on-behalf-of)
#      against a stand-in issuer (tests/v1281_idp.py: discovery and keys over
#      HTTPS, tokens of each algorithm and each failing check) and the agent's
#      X.509-SVID (--agent-svid) against a trust bundle; run_start records
#      on_behalf_of and the operator; the token is in no output.
#   3. sub-agents: a control group per sub-agent launch (tests/v1281_sub);
#      every call attributed (obo), through forks, a double fork, threads,
#      nesting and a launch that fails; the groups out of the agent's reach.
#   4. the user's token expires during the run: recorded, and the run
#      revoked (or, with --on-behalf-of-expiry record, recorded only).
#   5. the audit (forged streams it refuses), the export, varek runs,
#      refusals (--subagent, --user), policy show and doctor's issuer check.
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
    check "require on-behalf-of with no token refuses the start, saying so" \
        sh -c "! grep -qx 0 '$OUT/w2.rc' && grep -q 'give the user.s token with --on-behalf-of FILE' '$OUT/w2.out'"
fi

echo "== 2. verifying the identities: warden-secrets =="
SECRETS="$(dirname "${WARDEN:-/nonexistent}")/warden-secrets"
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ ! -x "$SECRETS" ] || ! python3 -c 'import cryptography' 2>/dev/null; then
    skip "section 2 (needs root, the warden and warden-secrets binaries, and python3-cryptography)"
else
    T="$(mktemp -d /tmp/varek_v1281.XXXXXX)"; chmod 755 "$T"
    python3 "$HERE/tests/v1281_idp.py" serve "$T" > "$T/serve.out" 2>&1 &
    IDP=$!
    trap 'kill $IDP 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT $T" || rm -rf "$OUT" "$T"' EXIT
    for _ in $(seq 100); do [ -f "$T/port" ] && break; sleep 0.1; done
    P="$(cat "$T/port")"; ISS="https://127.0.0.1:$P"
    python3 "$HERE/tests/v1281_idp.py" svid "$T"
    chmod 644 "$T/ca.pem" "$T"/bundle*.pem                       # the CA: read by the helper's own user
    printf 'oidc_ca = %s/ca.pem\n' "$T" > "$T/conf"; chmod 600 "$T/conf" "$T"/svid-*.pem
    mint() { python3 "$HERE/tests/v1281_idp.py" mint "$T" "$@" > "$T/tok"; chmod 600 "$T/tok"; }
    LIBS='allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n'
    ID="require warden 1.28\ntrust issuer $ISS audience varek-agent\n"
    printf '%b' "$ID$LIBS" > "$T/p.txt"
    # go <name> <policy> [warden options]: a run of /usr/bin/true; output in $OUT/<name>.out
    go() { local n="$1" pol="$2"; shift 2
           (cd "$T" && timeout 60 "$WARDEN" "$pol" --secrets-conf "$T/conf" "$@" -- /usr/bin/true > "$OUT/$n.out" 2>&1)
           echo $? > "$OUT/$n.rc"; }
    has() { grep -qF -- "$2" "$OUT/$1.out"; }
    ok()  { grep -qx 0 "$OUT/$1.rc"; }
    # rs <name> <python expression on r, run_start>: prints it
    rs()  { python3 -c 'import json,sys
for l in open(sys.argv[1]):
    if l.startswith("{\"event\":\"run_start\""): print(eval(sys.argv[2], {"r": json.loads(l)}))' "$OUT/$1.out" "$2"; }
    refuse() { local d="$1" n="$2" w="$3"; if has "$n" "$w" && ! ok "$n"; then pass "refused: $d"; else flunk "refused: $d ($(grep -m1 'refusing' "$OUT/$n.out"))"; fi; }

    # the user's token, each algorithm
    mint es256; go es256 "$T/p.txt" --on-behalf-of "$T/tok"
    TOKSHA="$(tr -d '\n' < "$T/tok" | sha256sum | cut -c1-64)"
    check "an ES256 token from a trusted issuer: verified, the run starts" sh -c "grep -qx 0 '$OUT/es256.rc' && grep -q 'on behalf of alice@example.test (issuer $ISS, line 2): token verified (ES256, key ec1)' '$OUT/es256.out'"
    check "run_start's on_behalf_of: the user the issuer vouched for" \
        sh -c "[ \"\$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    if l.startswith(\"{\\\"event\\\":\\\"run_start\\\"\"):
        u = json.loads(l)[\"on_behalf_of\"][\"user\"]
        print(u[\"issuer\"], u[\"audience\"], u[\"subject\"], u[\"algorithm\"], u[\"key_id\"], u[\"jti\"], u[\"verified\"], u[\"policy_line\"])' '$OUT/es256.out')\" = '$ISS varek-agent alice@example.test ES256 ec1 jti-es256 True 2' ]"
    check "its token_sha256 is the token's SHA-256" sh -c "[ \"\$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    if l.startswith(\"{\\\"event\\\":\\\"run_start\\\"\"): print(json.loads(l)[\"on_behalf_of\"][\"user\"][\"token_sha256\"])' '$OUT/es256.out')\" = '$TOKSHA' ]"
    check "its expiry, issue time and not-before are the token's" sh -c "[ \"\$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    if l.startswith(\"{\\\"event\\\":\\\"run_start\\\"\"):
        u = json.loads(l)[\"on_behalf_of\"][\"user\"]; print(u[\"expires\"] - u[\"issued_at\"], u[\"issued_at\"] == u[\"not_before\"])' '$OUT/es256.out')\" = '3610 True' ]"
    check "the agent: this run" sh -c "grep -q '\"agent\":{\"run\":\"[0-9a-f]\{32\}\"}' '$OUT/es256.out'"
    check "the audit accepts a run with a verified user (and the helper, no credential)" \
        python3 "$HERE/tools/varek_audit.py" --policy "$T/p.txt" --checker "$CERT" "$OUT/es256.out"
    TOK="$(cat "$T/tok")"; TOKSIG="${TOK##*.}"; TOKPAY="$(echo "$TOK" | cut -d. -f2)"
    check "the token is nowhere in the Warden's output or the stream (neither its claims nor its signature)" \
        sh -c "! grep -qF -- '$TOKSIG' '$OUT/es256.out' && ! grep -qF -- '$TOKPAY' '$OUT/es256.out'"
    (cd "$T" && timeout 60 "$WARDEN" "$T/p.txt" --secrets-conf "$T/conf" --on-behalf-of "$T/tok" -- /usr/bin/env > "$OUT/env.out" 2> "$OUT/env.err")
    check "nor in the agent's environment" sh -c "grep -q '^PATH=' '$OUT/env.out' && ! grep -qF -- '$TOKSIG' '$OUT/env.out' && ! grep -qF -- '$TOKPAY' '$OUT/env.out'"
    check "the helper is gone once the identities are verified" sh -c "! pgrep -fx 'warden-secrets [0-9]+:[0-9]+'"
    for c in rs256:RS256:rsa1 ps256:PS256:rsa1 eddsa:EdDSA:ed1; do
        n="${c%%:*}"; a="$(echo "$c" | cut -d: -f2)"; k="${c##*:}"
        mint "$n"; go "$n" "$T/p.txt" --on-behalf-of "$T/tok"
        check "a $a token: verified with the issuer's key $k" sh -c "grep -qx 0 '$OUT/$n.rc' && grep -q 'token verified ($a, key $k)' '$OUT/$n.out'"
    done
    mint es256-nokid; go nokid "$T/p.txt" --on-behalf-of "$T/tok"
    check "a token naming no key, with one key for its algorithm: verified" sh -c "grep -qx 0 '$OUT/nokid.rc' && grep -q 'token verified (ES256)' '$OUT/nokid.out'"
    check "the keys from the issuer's discovery document" sh -c "grep -q 'GET /.well-known/openid-configuration' '$T/requests.log' && grep -q 'GET /jwks$' '$T/requests.log'"
    mint aud-array; go audarr "$T/p.txt" --on-behalf-of "$T/tok"
    check "an audience array holding the policy's audience: verified" ok audarr
    mint exchange; go exch "$T/p.txt" --on-behalf-of "$T/tok"
    check "a token from token exchange: its two actors in run_start, the current one first" \
        sh -c "[ \"\$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    if l.startswith(\"{\\\"event\\\":\\\"run_start\\\"\"): print(json.dumps(json.loads(l)[\"on_behalf_of\"][\"actors\"]))' '$OUT/exch.out')\" = '[{\"subject\": \"agent-orchestrator\", \"issuer\": \"$ISS\"}, {\"subject\": \"ci-runner\"}]' ]"
    mint act8; go act8 "$T/p.txt" --on-behalf-of "$T/tok"
    check "an act chain 8 deep: verified, 8 actors" sh -c "grep -qx 0 '$OUT/act8.rc' && [ \"\$(grep -c 'actor [0-9]: actor-' '$OUT/act8.out')\" = 8 ]"

    # each check failing on its own
    while IFS='|' read -r c d w; do
        mint "$c"; go "t_$c" "$T/p.txt" --on-behalf-of "$T/tok"
        refuse "$d" "t_$c" "the user's token: $w"
    done <<'CASES'
none|algorithm none|algorithm none is refused
hs256|an HMAC token signed with the issuer's public key as its secret|algorithm HS256 is refused
badsig|a signature by another key|its signature does not verify with the issuer's key
unknown-kid|a key id not in the issuer's keys|its key nope is not among the issuer's keys
wrong-iss|an issuer the policy does not trust|its issuer https://idp.elsewhere.test is not one the policy trusts
wrong-aud|another audience|its audience (aud) does not hold varek-agent
expired|expired an hour ago|it expired
near-expiry|expiring in 20 s (under 60)|it expires in 20 s, under 60 s
nbf-future|not valid for 10 minutes (nbf)|it is not valid for
iat-future|issued 10 minutes ahead (iat)|it was issued
no-exp|no expiry|it has no expiry (exp)
no-sub|no subject|it has no subject (sub)
sub-ctl|a subject with a control byte|its subject (sub) is not printable ASCII
crit|a crit header|its header has crit
act9|an act chain 9 deep|its act chain is nested deeper than 8
CASES
    check "a refused token starts no agent and records no run_start" sh -c "! grep -q run_start '$OUT/t_badsig.out'"
    printf '%b' "require warden 1.28\ntrust issuer $ISS audience varek-agent jwks $ISS/jwks-two\n$LIBS" > "$T/p2.txt"
    : > "$T/requests.log"; mint rs256-nokid; go two "$T/p2.txt" --on-behalf-of "$T/tok"
    refuse "a token naming no key when the issuer has two for its algorithm" two "it names no key (kid) and the issuer has 2 keys for RS256"
    check "the policy's jwks URL is used, not the discovery document" sh -c "grep -q 'GET /jwks-two' '$T/requests.log' && ! grep -q well-known '$T/requests.log'"
    printf '%b' "require warden 1.28\ntrust issuer $ISS/liar audience varek-agent\n$LIBS" > "$T/p3.txt"
    mint es256 "$ISS/liar"; go liar "$T/p3.txt" --on-behalf-of "$T/tok"
    refuse "a discovery document naming another issuer" liar "the issuer's discovery document names another issuer ($ISS)"
    printf 'require warden 1.28\ntrust issuer https://127.0.0.1:1 audience varek-agent\n' > "$T/p4.txt"
    mint es256 "https://127.0.0.1:1"; go down "$T/p4.txt" --on-behalf-of "$T/tok"
    refuse "an issuer that cannot be reached" down "the issuer's discovery document: cannot connect to 127.0.0.1:1"
    printf 'oidc_ca = /nonexistent/ca.pem\n' > "$T/conf_noca"; chmod 600 "$T/conf_noca"
    mint es256; (cd "$T" && timeout 60 "$WARDEN" "$T/p.txt" --secrets-conf "$T/conf_noca" --on-behalf-of "$T/tok" -- /usr/bin/true > "$OUT/noca.out" 2>&1); echo $? > "$OUT/noca.rc"
    refuse "an issuer whose CA file (oidc_ca) is not there" noca "its CA file: cannot open /nonexistent/ca.pem"

    printf 'oidc_ca = %s/ca.pem\n' "$T" > "$T/conf644"; chmod 644 "$T/conf644"
    (cd "$T" && timeout 60 "$WARDEN" "$T/p.txt" --secrets-conf "$T/conf644" --on-behalf-of "$T/tok" -- /usr/bin/true > "$OUT/c644.out" 2>&1); echo $? > "$OUT/c644.rc"
    refuse "a configuration others can read, with a token and no credential: at once" c644 "the user's token: $T/conf644 must be owned by root"
    check "... not after the helper's 30 s" sh -c "! grep -q 'did not answer' '$OUT/c644.out'"

    # v1.28.1 review
    mint longkey; go longkey "$T/p.txt" --on-behalf-of "$T/tok"
    refuse "a signed token with a claim name over 255 bytes (no crash)" longkey "the user's token: its header or claims hold a member name over 255 bytes"
    check "... the helper did not crash" sh -c "! grep -q 'ended before it was ready' '$OUT/longkey.out'"
    mint es256; python3 -c 'import sys
t = open(sys.argv[1]).read().strip(); h, p, s = t.split(".")
a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
s = s[:-1] + a[a.index(s[-1]) ^ 1]                  # an unused low bit of the last character
open(sys.argv[1], "w").write(".".join((h, p, s)) + "\n")' "$T/tok"
    go noncanon "$T/p.txt" --on-behalf-of "$T/tok"
    refuse "a token whose base64url is not canonical (another hash for one token)" noncanon "the user's token: a part is not base64url"
    printf '%b' "require warden 1.28\ntrust issuer $ISS audience varek-agent jwks $ISS/jwks-odd\n$LIBS" > "$T/podd.txt"
    for c in odd-use odd-alg; do mint "$c"; go "$c" "$T/podd.txt" --on-behalf-of "$T/tok"; done
    refuse "a key whose use cannot be read" odd-use "its key odd-use is not among the issuer's keys"
    refuse "a key whose alg cannot be read" odd-alg "its key odd-alg is not among the issuer's keys"
    printf '%b' "require warden 1.28\ntrust issuer $ISS audience varek-agent jwks $ISS/jwks-shared\n$LIBS" > "$T/pshared.txt"
    mint es256; go shared "$T/pshared.txt" --on-behalf-of "$T/tok"
    check "one kid on keys of two types: the one of the token's type verifies it" sh -c "grep -qx 0 '$OUT/shared.rc' && grep -q 'token verified (ES256, key ec1)' '$OUT/shared.out'"
    printf '%b' "require warden 1.28\ntrust issuer $ISS/slow audience varek-agent\n$LIBS" > "$T/pslow.txt"
    mint es256 "$ISS/slow"; s0=$(date +%s); go slow "$T/pslow.txt" --on-behalf-of "$T/tok"; s1=$(date +%s)
    check "an issuer too slow to answer: refused for that, before the Warden's 30 s" sh -c "[ $((s1 - s0)) -lt 29 ] && grep -q 'the issuer.s discovery document: ' '$OUT/slow.out' && ! grep -q 'did not answer within' '$OUT/slow.out'"
    mint es256; mkdir -p "$T/cadir"; cp "$T/ca.pem" "$T/cadir/ca.pem"; chmod 644 "$T/cadir/ca.pem"
    printf 'oidc_ca = %s/cadir/ca.pem\n' "$T" > "$T/conf_cadir"; chmod 600 "$T/conf_cadir"
    printf '%b' "${ID}allow path $T/cadir/\n$LIBS" > "$T/pca.txt"
    (cd "$T" && timeout 60 "$WARDEN" "$T/pca.txt" --secrets-conf "$T/conf_cadir" --on-behalf-of "$T/tok" -- /usr/bin/true > "$OUT/caw.out" 2>&1); echo $? > "$OUT/caw.rc"
    refuse "a policy that lets the agent write the issuers' CA (oidc_ca)" caw "lets the agent write $T/cadir/ca.pem"
    chown 65534 "$T/cadir/ca.pem"
    (cd "$T" && timeout 60 "$WARDEN" "$T/p.txt" --secrets-conf "$T/conf_cadir" --on-behalf-of "$T/tok" -- /usr/bin/true > "$OUT/cao.out" 2>&1); echo $? > "$OUT/cao.rc"
    refuse "an issuers' CA another user owns" cao "must be owned by root and writable by no group or other user"

    # the token file and the policy
    mint es256; chmod 644 "$T/tok"; go mode "$T/p.txt" --on-behalf-of "$T/tok"
    refuse "a token file others can read" mode "readable by no group or other user"
    chmod 600 "$T/tok"
    printf 'eyJhbGciOiJFUzI1NiJ9 not a token\n' > "$T/tok_bad"; chmod 600 "$T/tok_bad"; go notjwt "$T/p.txt" --on-behalf-of "$T/tok_bad"
    refuse "a token file that is not one JWT" notjwt "is not one JWT"
    printf '%b' "${ID}allow path exact $T/tok readonly\n$LIBS" > "$T/p5.txt"; go open "$T/p5.txt" --on-behalf-of "$T/tok"
    refuse "a policy that lets the agent open the token file" open "lets the agent open $T/tok"
    printf '%b' "require warden 1.28\nrequire on-behalf-of\ntrust issuer $ISS audience varek-agent\n$LIBS" > "$T/p6.txt"
    go req0 "$T/p6.txt"
    refuse "require on-behalf-of with no token" req0 "give the user's token with --on-behalf-of FILE"
    go req1 "$T/p6.txt" --on-behalf-of "$T/tok"
    check "require on-behalf-of with a verified token: the run starts" ok req1
    printf '%b' "require warden 1.28\n$LIBS" > "$T/p7.txt"; go noiss "$T/p7.txt" --on-behalf-of "$T/tok"
    refuse "a token when the policy trusts no issuer" noiss "the policy trusts no issuer"
    go none "$T/p.txt"
    check "no token: on_behalf_of is the agent alone" sh -c "grep -qx 0 '$OUT/none.rc' && grep -q '\"on_behalf_of\":{\"agent\":{\"run\":\"[0-9a-f]\{32\}\"}}' '$OUT/none.out'"
    check "the operator, from the process (not verified)" sh -c "grep -q '\"operator\":{\"uid\":0,\"login\":\"root\",\"source\":\"process\",\"verified\":false}' '$OUT/none.out'"
    (cd "$T" && SUDO_UID=1000 SUDO_USER=kenneth timeout 60 "$WARDEN" "$T/p.txt" -- /usr/bin/true > "$OUT/sudo.out" 2>&1)
    check "the operator sudo names, when the Warden runs under sudo" sh -c "grep -q '\"operator\":{\"uid\":1000,\"login\":\"kenneth\",\"source\":\"sudo\",\"verified\":false}' '$OUT/sudo.out'"
    "$WARDEN" "$T/p.txt" --on-behalf-of "$T/tok" --check-startup > "$OUT/cs.out" 2>&1
    check "--check-startup names the token, not verifying it" sh -c "grep -q '(--check-credentials verifies it)' '$OUT/cs.out' && ! grep -q 'token verified' '$OUT/cs.out'"
    "$WARDEN" "$T/p.txt" --secrets-conf "$T/conf" --on-behalf-of "$T/tok" --check-credentials > "$OUT/cc.out" 2>&1
    check "--check-credentials verifies it" sh -c "grep -q 'token verified (ES256' '$OUT/cc.out' && grep -q 'identities: verified' '$OUT/cc.out'"
    printf 'file-value-1281\n' > "$T/k"; chmod 600 "$T/k"
    printf '%b' "require warden 1.28\nproxy inspect\ntrust issuer $ISS audience varek-agent\ncredential c from file:$T/k\nallow host api.example.com:443\nallow request GET https://api.example.com/x credential=c header=X-K\n" > "$T/p8.txt"
    "$WARDEN" "$T/p8.txt" --secrets-conf "$T/conf" --on-behalf-of "$T/tok" --check-credentials > "$OUT/both.out" 2>&1
    check "a token and a credential together: both from one helper" sh -c "grep -q 'token verified' '$OUT/both.out' && grep -q 'credential c from file:$T/k: fetched, 15 bytes' '$OUT/both.out'"

    # the agent's SVID
    printf '%b' "require warden 1.28\ntrust spiffe example.test bundle $T/bundle.pem\n$LIBS" > "$T/s.txt"
    go svid "$T/s.txt" --agent-svid "$T/svid-good.pem"
    LEAFSHA="$(python3 -c 'import sys,hashlib; from cryptography import x509; from cryptography.hazmat.primitives.serialization import Encoding; print(hashlib.sha256(x509.load_pem_x509_certificate(open(sys.argv[1],"rb").read()).public_bytes(Encoding.DER)).hexdigest())' "$T/svid-good.pem")"
    check "an X.509-SVID that chains to the bundle: verified, the run starts" sh -c "grep -qx 0 '$OUT/svid.rc' && grep -q 'agent spiffe://example.test/agents/coder: SVID verified against the bundle for example.test (line 2)' '$OUT/svid.out'"
    check "run_start's agent: its SPIFFE ID, trust domain and the leaf's SHA-256" \
        sh -c "[ \"\$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    if l.startswith(\"{\\\"event\\\":\\\"run_start\\\"\"):
        a = json.loads(l)[\"on_behalf_of\"][\"agent\"]; print(a[\"spiffe_id\"], a[\"trust_domain\"], a[\"svid_sha256\"], a[\"verified\"], a[\"svid_not_after\"] > 0)' '$OUT/svid.out')\" = 'spiffe://example.test/agents/coder example.test $LEAFSHA True True' ]"
    check "no private key in the output" sh -c "! grep -q 'PRIVATE KEY' '$OUT/svid.out'"
    go svidchain "$T/s.txt" --agent-svid "$T/svid-chain.pem"
    check "an SVID through an intermediate in its file: verified" ok svidchain
    while IFS='|' read -r c d w; do
        go "s_$c" "$T/s.txt" --agent-svid "$T/svid-$c.pem"
        refuse "$d" "s_$c" "the agent's SVID: $w"
    done <<'CASES'
expired|an expired SVID|it does not chain to the bundle for example.test: certificate has expired
other-domain|an SVID from a trust domain the policy does not trust|its trust domain (spiffe://other.test/agents/coder) is not one the policy trusts
wrong-ca|an SVID in the right domain from another authority|it does not chain to the bundle for example.test
key-mismatch|a key that does not match the SVID|its key does not match its certificate
two-uris|two URI names|its certificate has 2 URI names
ca-leaf|a CA certificate as the SVID|its certificate is a CA's
not-spiffe|a URI name that is not a SPIFFE ID|its URI name is not a SPIFFE ID
no-bcons|a leaf with no basicConstraints (review)|its certificate has no basicConstraints
CASES
    chmod 644 "$T/svid-good.pem"; go svmode "$T/s.txt" --agent-svid "$T/svid-good.pem"; chmod 600 "$T/svid-good.pem"
    refuse "an SVID file others can read (it holds the key)" svmode "readable by no group or other user"
    cp "$T/bundle.pem" "$T/bundle-w.pem"; chmod 666 "$T/bundle-w.pem"
    printf '%b' "require warden 1.28\ntrust spiffe example.test bundle $T/bundle-w.pem\n$LIBS" > "$T/s2.txt"
    go bw "$T/s2.txt" --agent-svid "$T/svid-good.pem"
    refuse "a bundle others can write" bw "must be owned by root and writable by no group or other user"
    mkdir -p "$T/b"; cp "$T/bundle.pem" "$T/b/bundle.pem"; chmod 644 "$T/b/bundle.pem"
    printf '%b' "require warden 1.28\ntrust spiffe example.test bundle $T/b/bundle.pem\nallow path $T/b/\n$LIBS" > "$T/s3.txt"
    go bpol "$T/s3.txt" --agent-svid "$T/svid-good.pem"
    refuse "a policy that lets the agent write the bundle" bpol "lets the agent write $T/b/bundle.pem"
    printf '%b' "require warden 1.28\ntrust spiffe example.test bundle $T/b/bundle.pem\nallow path $T/b/ readonly\n$LIBS" > "$T/s4.txt"
    go bro "$T/s4.txt" --agent-svid "$T/svid-good.pem"
    check "a policy that lets the agent read the bundle only: the run starts" ok bro
    printf '%b' "require warden 1.28\ntrust spiffe example.test bundle $T/missing.pem\n$LIBS" > "$T/s5.txt"
    go bmiss "$T/s5.txt" --agent-svid "$T/svid-good.pem"
    refuse "a bundle that is not there" bmiss "the bundle for example.test: cannot open $T/missing.pem"
    go s_two-keys "$T/s.txt" --agent-svid "$T/svid-two-keys.pem"
    refuse "a second key, one that cannot be read (review)" s_two-keys "the agent's SVID: $T/svid-two-keys.pem must hold exactly one private key"
    mkdir -p "$T/b2"; cp "$T/bundle-other.pem" "$T/b2/other.pem"; chmod 644 "$T/b2/other.pem"
    printf '%b' "require warden 1.28\ntrust spiffe example.test bundle $T/bundle.pem\ntrust spiffe other.test bundle $T/b2/other.pem\nallow path $T/b2/\n$LIBS" > "$T/s7.txt"
    go bother "$T/s7.txt" --agent-svid "$T/svid-good.pem"
    refuse "a policy that lets the agent write a bundle this run's SVID does not use (review)" bother "lets the agent write $T/b2/other.pem"
    go bnosvid "$T/s7.txt"
    refuse "... or with no SVID at all" bnosvid "lets the agent write $T/b2/other.pem"
    mkfifo "$T/fifo.pem"
    printf '%b' "require warden 1.28\ntrust spiffe example.test bundle $T/fifo.pem\n$LIBS" > "$T/s8.txt"
    s0=$(date +%s); go bfifo "$T/s8.txt" --agent-svid "$T/svid-good.pem"; s1=$(date +%s)
    check "a FIFO where a bundle should be: refused at once, the helper not held (review)" sh -c "[ $((s1 - s0)) -lt 10 ] && grep -q 'is not a regular file' '$OUT/bfifo.out' && ! pgrep -fx 'warden-secrets [0-9]+:[0-9]+'"
    go nospf "$T/p.txt" --agent-svid "$T/svid-good.pem"
    refuse "an SVID when the policy trusts no trust domain" nospf "the policy trusts no SPIFFE trust domain"
    printf '%b' "require warden 1.28\ntrust issuer $ISS audience varek-agent\ntrust spiffe example.test bundle $T/bundle.pem\n$LIBS" > "$T/s6.txt"
    go both "$T/s6.txt" --on-behalf-of "$T/tok" --agent-svid "$T/svid-good.pem"
    check "a user and an agent's SVID: both in on_behalf_of" sh -c "grep -qx 0 '$OUT/both.rc' && grep -q '\"user\":{\"issuer\":\"$ISS\"' '$OUT/both.out' && grep -q '\"spiffe_id\":\"spiffe://example.test/agents/coder\"' '$OUT/both.out'"
fi

echo "== 3. sub-agents: a control group each, every call attributed =="
SUBP="$HERE/tests/v1281_sub"
CGM="$(awk '$3 == "cgroup2" { print $2; exit }' /proc/self/mounts)"
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ ! -x "$SUBP" ] || [ -z "$CGM" ]; then
    skip "section 3 (needs root, the warden, tests/v1281_sub and a cgroup2 mount)"
else
    B="$(mktemp -d /tmp/varek_v1281s.XXXXXX)"; chmod 755 "$B"
    trap 'kill ${IDP:-} 2>/dev/null; rmdir "$CGM/v1281-other" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT ${T:-} $B" || rm -rf "$OUT" ${T:+"$T"} "$B"' EXIT
    for n in agent a b; do cp "$SUBP" "$B/$n"; chmod 755 "$B/$n"; done
    ln -s "$B/a" "$B/plain"; echo hi > "$B/f"; chmod 644 "$B/f"
    SL='allow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\n'
    SP="require warden 1.28\nallow exec $B/a subagent=alpha\nallow exec $B/b subagent=beta\nallow exec $B/plain\nallow path $B/f readonly\n"
    printf '%b' "$SP$SL" > "$B/p.txt"
    # sgo <name> <agent args>: the agent's stream in $OUT/<name>.out, its stdout in $OUT/<name>.so
    sgo() { local n="$1"; shift; timeout 60 "$WARDEN" "${POL:-$B/p.txt}" "${SOPT[@]}" -- "$B/agent" "$@" > "$OUT/$n.so" 2> "$OUT/$n.out"; echo $? > "$OUT/$n.rc"; }
    SOPT=()
    # opens <name>: each open of $B/f, as "pid obo" (obo joined with +), in order
    opens() { python3 -c 'import json,sys
for l in open(sys.argv[1]):
    if l.startswith("{\"report_id\""):
        r = json.loads(l)
        if r["target"] == sys.argv[2] and r["action"] == "file.open": print(r["agent_pid"], "+".join(r["obo"]), r["decision_final"])' "$OUT/$1.out" "$B/f"; }
    obos() { opens "$1" | awk '{print $2}' | sort -u | tr '\n' ' ' | sed 's/ $//'; }
    sgo fork exec "$B/a" fork "$B/f"
    [ "$(opens fork | awk '{print $1}' | sort -u | wc -l)" = 2 ] && pass "a sub-agent and the child it forks: two processes" \
        || flunk "a sub-agent and the child it forks ($(opens fork | tr '\n' ';'))"
    [ "$(obos fork)" = "agent+subagent:alpha#1" ] && pass "... attributed to it: agent+subagent:alpha#1" || flunk "... attributed to it ($(obos fork))"
    check "its launch record names the sub-agent and its group" \
        sh -c "grep -q '\"target\":\"$B/a\".*\"rule\":\"exec_allowed\"' '$OUT/fork.out' && grep -q '\"subagent\":\"alpha#1\",\"cgroup\":\"[^\"]*/varek-[0-9a-f]\{32\}/alpha-1\"' '$OUT/fork.out'"
    check "the launch is recorded launched, for the sub-agent" grep -q '"result":"launched","subagent":"alpha#1"' "$OUT/fork.out"
    check "its launch record is the agent's (who launched it)" \
        sh -c "grep '\"target\":\"$B/a\"' '$OUT/fork.out' | grep -q '\"obo\":\\[\"agent\"\\]'"
    check "the audit accepts a run with a sub-agent" python3 "$HERE/tools/varek_audit.py" --policy "$B/p.txt" --checker "$CERT" "$OUT/fork.out"
    sgo dfork exec "$B/a" doublefork "$B/f"
    [ "$(obos dfork)" = "agent+subagent:alpha#1" ] && pass "a double fork that reparents the grandchild: still the sub-agent's" || flunk "a double fork ($(obos dfork))"
    sgo thread exec "$B/a" thread "$B/f"
    [ "$(obos thread)" = "agent+subagent:alpha#1" ] && pass "a thread of the sub-agent: the sub-agent's" || flunk "a thread ($(obos thread))"
    sgo nest exec "$B/a" exec "$B/b" open "$B/f"
    [ "$(obos nest)" = "agent+subagent:alpha#1+subagent:beta#1" ] && pass "a sub-agent launched by a sub-agent: the chain grows by one" || flunk "nested ($(obos nest))"
    check "... its group under its launcher's" grep -q '"subagent":"beta#1","cgroup":"[^"]*/alpha-1/beta-1"' "$OUT/nest.out"
    VAREK_WARDEN_TEST_NO_PIDFD_INFO=1 sgo nestp exec "$B/a" exec "$B/b" open "$B/f"
    [ "$(obos nestp)" = "agent+subagent:alpha#1+subagent:beta#1" ] && grep -q 'each call.s group read from /proc' "$OUT/nestp.out" \
        && pass "... the same with each call's group read from /proc (a kernel before 6.13)" || flunk "nested, from /proc ($(obos nestp))"
    sgo two spawn "$B/f" "$B/a" open "$B/f"
    [ "$(opens two | awk '{print $2}' | tr '\n' ' ')" = "agent+subagent:alpha#1 agent " ] \
        && pass "the agent's own calls stay the agent's, after a sub-agent's" || flunk "the agent's own calls ($(opens two | tr '\n' ';'))"
    sgo again spawn "$B/f" "$B/a" spawn "$B/f" "$B/a" open "$B/f"
    check "two launches of one program: alpha#1, then alpha#2 (nested)" grep -q '"subagent":"alpha#2"' "$OUT/again.out"
    sgo plain spawn "$B/f" "$B/plain" open "$B/f"
    [ "$(obos plain)" = "agent" ] && pass "the same program launched by a rule without subagent=: the agent's" || flunk "plain ($(obos plain))"
    sgo thr threaded "$B/a" open "$B/f"
    check "a threaded process may not launch a sub-agent (subagent_threaded)" \
        sh -c "grep -q '\"target\":\"$B/a\".*\"decision_final\":\"DENY\",\"rule\":\"subagent_threaded\"' '$OUT/thr.out' && grep -q 'launch refused: Permission denied' '$OUT/thr.so'"
    sgo e2big e2big "$B/f" "$B/a"
    check "a launch allowed and then failed by the kernel (E2BIG): recorded failed" \
        sh -c "grep -q 'Argument list too long' '$OUT/e2big.so' && grep -q '\"result\":\"failed\",\"subagent\":\"alpha#1\"' '$OUT/e2big.out'"
    [ "$(obos e2big)" = "agent" ] && [ "$(opens e2big | wc -l)" = 2 ] \
        && pass "... the process and the child it forked after are the agent's again" || flunk "after a failed launch ($(opens e2big | tr '\n' ';'))"
    check "... and no call is refused for it" sh -c "! grep -q 'intent_derivation_failed' '$OUT/e2big.out'"
    # v1.28.1 review: a launch of the image the launcher already runs
    printf '%b' "require warden 1.28\nallow exec $B/agent subagent=self\nallow path $B/f readonly\n$SL" > "$B/ps.txt"
    POL="$B/ps.txt" sgo same e2big "$B/f" "$B/agent"
    [ "$(obos same)" = "agent" ] && grep -q '"event":"subagent_settled".*"subagent":"self#1","result":"failed","how":"process_events"' "$OUT/same.out" \
        && pass "a failed launch of the image the launcher runs: settled failed by the kernel's process events, the agent's (review)" \
        || flunk "a failed same-image launch ($(obos same))"
    POL="$B/ps.txt" sgo same2 exec "$B/agent" open "$B/f"
    [ "$(obos same2)" = "agent+subagent:self#1" ] && pass "... and one that happened: the sub-agent's" || flunk "a same-image launch ($(obos same2))"
    VAREK_WARDEN_TEST_NO_PROC_CONNECTOR=1 POL="$B/ps.txt" sgo samefb exec "$B/agent" open "$B/f"
    check "... without process events, refused (subagent_same_image)" sh -c "grep -q '\"rule\":\"subagent_same_image\"' '$OUT/samefb.out' && grep -q 'no process events here' '$OUT/samefb.out'"
    check "each sub-agent's launch is settled once, before its decisions (subagent_settled)" python3 -c 'import json,sys
for f in sys.argv[1:]:
    L = [json.loads(l) for l in open(f) if l.startswith("{")]
    st = [i for i, r in enumerate(L) if r.get("event") == "subagent_settled"]
    first = [i for i, r in enumerate(L) if any(x.startswith("subagent:") for x in r.get("obo", []))]
    if not st or (first and min(first) < min(st)) or any(L[i]["how"] != "process_events" for i in st): sys.exit(1)' \
        "$OUT/fork.out" "$OUT/nest.out"
    # the Warden's own group's name in a record, escaped (review)
    mkdir -p "$CGM/v1281 q\"x"
    sh -c "echo \$\$ > '$CGM/v1281 q\"x/cgroup.procs' && exec timeout 60 '$WARDEN' '$B/p.txt' -- '$B/agent' exec '$B/a' open '$B/f'" > /dev/null 2> "$OUT/cgq.out"
    rmdir "$CGM/v1281 q\"x"/varek-* 2>/dev/null; rmdir "$CGM/v1281 q\"x" 2>/dev/null
    check "a Warden in a group whose name holds a quote: every record is still JSON" python3 -c 'import json,sys
L = [l for l in open(sys.argv[1]) if l.startswith("{")]
[json.loads(l) for l in L]
sys.exit(0 if any("\"subagent\":\"alpha#1\"" in l for l in L) else 1)' "$OUT/cgq.out"
    check "every decision record carries obo" python3 -c 'import json,sys
rs=[json.loads(l) for f in sys.argv[1:] for l in open(f) if l.startswith("{\"report_id\"")]
sys.exit(0 if rs and all(isinstance(r.get("obo"), list) and r["obo"][:1] == ["agent"] for r in rs) else 1)' \
        "$OUT/fork.out" "$OUT/nest.out" "$OUT/e2big.out" "$OUT/plain.out"
    check "run_start names the run's control group" grep -q '"agent":{"run":"[0-9a-f]\{32\}","cgroup":"[^"]*/varek-[0-9a-f]\{32\}"}' "$OUT/fork.out"
    check "the run's control groups are removed at its end" sh -c "! ls '$CGM' | grep -q '^varek-'"
    # the groups out of the agent's reach
    mkdir -p "$CGM/v1281-other"
    printf '%b' "${SP}allow path $CGM/v1281-other/\n$SL" > "$B/pw.txt"
    POL="$B/pw.txt" sgo esc write "$CGM/v1281-other/cgroup.procs"
    check "the agent cannot write another control group's cgroup.procs, whatever the policy allows" \
        sh -c "grep -q 'write open: Permission denied' '$OUT/esc.so' && grep -q 'is on a control group filesystem; opening it to write is refused' '$OUT/esc.out'"
    printf '%b' "${SP}allow path /sys/\n$SL" > "$B/pw2.txt"
    POL="$B/pw2.txt" sgo wpol open "$B/f"
    check "refused: a policy that lets the agent write the control groups" \
        sh -c "! grep -qx 0 '$OUT/wpol.rc' && grep -q 'the control groups must be out of the agent.s reach' '$OUT/wpol.out'"
    VAREK_WARDEN_TEST_NO_CGROUP2=1 timeout 30 "$WARDEN" "$B/p.txt" -- "$B/agent" open "$B/f" > /dev/null 2> "$OUT/nocg.out"; echo $? > "$OUT/nocg.rc"
    check "refused: sub-agents without cgroup v2" \
        sh -c "! grep -qx 0 '$OUT/nocg.rc' && grep -q 'names a sub-agent, which needs cgroup v2' '$OUT/nocg.out'"
    "$WARDEN" "$B/p.txt" --run-as root --check-startup > "$OUT/root.out" 2>&1; echo $? > "$OUT/root.rc"
    check "refused: sub-agents with the agent as root" sh -c "! grep -qx 0 '$OUT/root.rc' && grep -q 'agent runs as root' '$OUT/root.out'"
    "$WARDEN" "$B/p.txt" --check-startup > "$OUT/cs3.out" 2>&1
    check "--check-startup: where the groups would go, and none made" \
        sh -c "grep -q 'sub-agents: a run.s control groups go under $CGM' '$OUT/cs3.out' && ! ls '$CGM' | grep -q '^varek-'"
    printf 'require warden 1.28\nallow path /usr/ readonly\n%b' "$SL" > "$B/none.txt"
    POL="$B/none.txt" sgo none open "$B/f"
    check "no sub-agent named: no control group, obo the agent" sh -c "! grep -q 'control group' '$OUT/none.out' && grep -q '\"obo\":\\[\"agent\"\\]' '$OUT/none.out'"
    if [ -n "${ISS:-}" ]; then
        printf '%b' "${SP}trust issuer $ISS audience varek-agent\n$SL" > "$B/pu.txt"
        mint es256
        SOPT=(--secrets-conf "$T/conf" --on-behalf-of "$T/tok")
        POL="$B/pu.txt" sgo user exec "$B/a" open "$B/f"
        SOPT=()
        [ "$(obos user)" = "user+agent+subagent:alpha#1" ] && pass "with a verified user: user, agent, sub-agent" || flunk "with a user ($(obos user))"
    else skip "obo with a user (section 2 did not run)"; fi
fi

echo "== 4. the user's token expires during the run =="
if [ -z "${ISS:-}" ] || [ -z "${B:-}" ]; then
    skip "section 4 (needs sections 2 and 3: the stand-in issuer and the test program)"
else
    printf '%b' "require warden 1.28\ntrust issuer $ISS audience varek-agent\nallow path $B/f readonly\n$SL" > "$B/pe.txt"
    # a token that expires 65 s after it is made (60 s is the least the Warden starts with); the
    # agent opens a file every 250 ms for 75 s
    mint exp65; cp "$T/tok" "$T/tok_rv"; cp "$T/tok" "$T/tok_rc"; chmod 600 "$T/tok_rv" "$T/tok_rc"
    timeout 120 "$WARDEN" "$B/pe.txt" --secrets-conf "$T/conf" --on-behalf-of "$T/tok_rv" -- "$B/agent" loop "$B/f" 75 \
        > "$OUT/exp_rv.so" 2> "$OUT/exp_rv.out" &
    E1=$!
    timeout 120 "$WARDEN" "$B/pe.txt" --secrets-conf "$T/conf" --on-behalf-of "$T/tok_rc" --on-behalf-of-expiry record \
        -- "$B/agent" loop "$B/f" 75 > "$OUT/exp_rc.so" 2> "$OUT/exp_rc.out" &
    E2=$!
    "$WARDEN" "$B/pe.txt" --on-behalf-of-expiry record --check-startup > "$OUT/x1.out" 2>&1; echo $? > "$OUT/x1.rc"
    check "refused: --on-behalf-of-expiry with no token" sh -c "! grep -qx 0 '$OUT/x1.rc' && grep -q 'there is no user.s token' '$OUT/x1.out'"
    "$WARDEN" "$B/pe.txt" --on-behalf-of "$T/tok" --on-behalf-of-expiry ignore --check-startup > "$OUT/x2.out" 2>&1; echo $? > "$OUT/x2.rc"
    check "refused: --on-behalf-of-expiry other than revoke or record" sh -c "! grep -qx 0 '$OUT/x2.rc' && grep -q 'takes revoke (the default) or record' '$OUT/x2.out'"
    "$WARDEN" "$B/pe.txt" --on-behalf-of "$T/tok" --check-startup > "$OUT/x3.out" 2>&1
    check "--check-startup says what the expiry will do" grep -q 'when it expires: the run is revoked' "$OUT/x3.out"
    wait $E1 $E2
    # ev <name> <event>: that event's records, one JSON a line
    ev() { grep "^{\"event\":\"$2\"" "$OUT/$1.out"; }
    check "revoke (the default): run_start says so" grep -q '"verified":true,"on_expiry":"revoke"}' "$OUT/exp_rv.out"
    check "... the expiry is recorded, at or after the token's exp" python3 -c 'import json,sys
L=[json.loads(l) for l in open(sys.argv[1]) if l.startswith("{\"event\":")]
u=[r for r in L if r["event"]=="run_start"][0]["on_behalf_of"]["user"]
e=[r for r in L if r["event"]=="on_behalf_of_expired"]
sys.exit(0 if len(e)==1 and e[0]["action"]=="revoke" and e[0]["expires"]==u["expires"] and e[0]["subject"]==u["subject"]
         and e[0]["timestamp_ns"] >= u["expires"]*10**9 else 1)' "$OUT/exp_rv.out"
    ev exp_rv revoked | grep -q '"by":"on_behalf_of_expiry"' && pass "... then the run is revoked, by the expiry" \
        || flunk "... then the run is revoked, by the expiry ($(ev exp_rv revoked))"
    check "... every open after it refused, as revoked; the agent saw both" python3 -c 'import json,sys,re
L=[l for l in open(sys.argv[1]) if l.startswith("{")]
i=[k for k,l in enumerate(L) if l.startswith("{\"event\":\"revoked\"")][0]
after=[json.loads(l) for l in L[i+1:] if l.startswith("{\"report_id\"")]
before=[json.loads(l) for l in L[:i] if l.startswith("{\"report_id\"") and sys.argv[3] in l]
m=re.search(r"opened (\d+) refused (\d+)", open(sys.argv[2]).read())
sys.exit(0 if after and all(r["decision_final"]=="DENY" and r["rule"]=="revoked" for r in after)
         and before and m and int(m.group(1)) > 0 and int(m.group(2)) > 0 else 1)' "$OUT/exp_rv.out" "$OUT/exp_rv.so" "$B/f"
    check "... and the audit accepts the run" python3 "$HERE/tools/varek_audit.py" --policy "$B/pe.txt" --checker "$CERT" "$OUT/exp_rv.out"
    check "record: the expiry is recorded, the run goes on, nothing refused" sh -c \
        "grep -q '\"event\":\"on_behalf_of_expired\".*\"action\":\"record\"' '$OUT/exp_rc.out' && ! grep -q '^{\"event\":\"revoked\"' '$OUT/exp_rc.out' && grep -q 'opened 300 refused 0' '$OUT/exp_rc.so'"
    check "... and the audit accepts the run" python3 "$HERE/tools/varek_audit.py" --policy "$B/pe.txt" --checker "$CERT" "$OUT/exp_rc.out"
fi

echo "== 5. audit, export and tools =="
if [ -z "${ISS:-}" ] || [ -z "${B:-}" ] || [ ! -s "$OUT/exp_rv.out" ]; then
    skip "section 5 (needs sections 2 to 4)"
else
    F="$HERE/tests/v1270_forge.py"
    RS='rs = next(r for r in recs if isinstance(r, dict) and r.get("event") == "run_start")'
    DR='dr = [r for r in recs if isinstance(r, dict) and "report_id" in r]'
    AUD="$HERE/tools/varek_audit.py"
    refuses() { if python3 "$AUD" --policy "$2" --checker "$CERT" "$3" > "$OUT/f.out" 2>&1; then
                    flunk "the audit refuses $1"
                elif grep -qF -- "$4" "$OUT/f.out"; then pass "the audit refuses $1"
                else flunk "the audit refuses $1 ($(grep -m1 PROBLEM "$OUT/f.out"))"; fi; }
    check "the audit reports whom the run was for, and each sub-agent's decisions" sh -c \
        "python3 '$AUD' --policy '$B/pu.txt' --checker '$CERT' '$OUT/user.out' | grep -q 'chain: on behalf of alice@example.test ($ISS); sub-agents (decisions): alpha#1 [0-9]'"
    python3 "$F" "$OUT/user.out" "$OUT/g1.log" "$RS; rs['on_behalf_of']['user']['issuer'] = 'https://idp.elsewhere.test'"
    refuses "a user vouched for by an issuer the policy does not trust" "$B/pu.txt" "$OUT/g1.log" "an issuer the policy does not trust"
    python3 "$F" "$OUT/user.out" "$OUT/g2.log" "$RS; rs['on_behalf_of']['user']['verified'] = False"
    refuses "a user not marked verified" "$B/pu.txt" "$OUT/g2.log" "is not marked verified"
    python3 "$F" "$OUT/user.out" "$OUT/g3.log" "$RS; rs['on_behalf_of']['user']['expires'] = rs['timestamp_ns'] // 10**9 - 5"
    refuses "a user's token expired before the run started" "$B/pu.txt" "$OUT/g3.log" "had expired when the run started"
    python3 "$F" "$OUT/user.out" "$OUT/g4.log" "$DR; dr[1]['obo'] = ['user', 'agent', 'subagent:alpha#1']"
    refuses "a sub-agent's decision before its launch" "$B/pu.txt" "$OUT/g4.log" "before (or without) a launch that started it"
    python3 "$F" "$OUT/user.out" "$OUT/g5.log" "import json
for r in recs:
    if isinstance(r, dict):
        if r.get('subagent') == 'alpha#1': r['subagent'] = 'gamma#1'
        if 'cgroup' in r and 'report_id' in r: r['cgroup'] = r['cgroup'].replace('alpha-1', 'gamma-1')
        if isinstance(r.get('obo'), list): r['obo'] = [x.replace('alpha#1', 'gamma#1') for x in r['obo']]"
    refuses "a sub-agent the policy does not name" "$B/pu.txt" "$OUT/g5.log" "names alpha"
    python3 "$F" "$OUT/user.out" "$OUT/g6.log" "$DR; dr[-1]['obo'] = ['agent']"
    refuses "a decision whose chain drops the user" "$B/pu.txt" "$OUT/g6.log" "does not begin with ['user', 'agent']"
    python3 "$F" "$OUT/user.out" "$OUT/g7.log" "$DR; dr[-1]['obo'] = dr[-1]['obo'] + ['subagent:beta#1']"
    refuses "a sub-agent no launch started" "$B/pu.txt" "$OUT/g7.log" "before (or without) a launch that started it"
    python3 "$F" "$OUT/e2big.out" "$OUT/g8.log" "$DR; dr[-1]['obo'] = ['agent', 'subagent:alpha#1']"
    refuses "a decision for a sub-agent after its launch failed" "$B/p.txt" "$OUT/g8.log" "after its launch failed"
    python3 "$F" "$OUT/req1.out" "$OUT/g9.log" "$RS; del rs['on_behalf_of']['user']
for r in recs:
    if isinstance(r, dict) and isinstance(r.get('obo'), list): r['obo'] = [x for x in r['obo'] if x != 'user']"
    refuses "a run of a policy that requires a user, with none" "$T/p6.txt" "$OUT/g9.log" "requires on-behalf-of, but run_start names no user"
    python3 "$F" "$OUT/exp_rv.out" "$OUT/g10.log" "$DR; dr[-1]['decision_final'] = 'ALLOW'"
    refuses "an allowed decision after the token expired and the run was revoked" "$B/pe.txt" "$OUT/g10.log" "after the run was revoked"
    python3 "$F" "$OUT/exp_rv.out" "$OUT/g11.log" "recs[:] = [r for r in recs if not (isinstance(r, dict) and r.get('event') == 'on_behalf_of_expired')]"
    refuses "a revocation by the expiry with no expiry recorded" "$B/pe.txt" "$OUT/g11.log" "no expiry that revokes is recorded before it"
    python3 "$F" "$OUT/fork.out" "$OUT/g12.log" "$RS; del rs['on_behalf_of']['agent']['cgroup']"
    refuses "a run with sub-agents whose run_start names no control group" "$B/p.txt" "$OUT/g12.log" "has no control group"
    # v1.28.1 review: forgeries the first audit accepted
    ALLOWIFY="dr = [r for r in recs if isinstance(r, dict) and 'report_id' in r]
ok = [r for r in dr if r['decision_final'] == 'ALLOW' and r['action'] == 'file.open'][-1]
keep = ('report_id', 'run', 'seq', 'agent_pid', 'obo', 'timestamp_ns', 'latency_us')
for r in dr:
    if r.get('rule') == 'revoked':
        for k in list(r):
            if k not in keep: del r[k]
        for k, v in ok.items():
            if k not in keep: r[k] = v"
    python3 "$F" "$OUT/exp_rv.out" "$OUT/g13.log" "ev = [r for r in recs if isinstance(r, dict) and r.get('event') in ('on_behalf_of_expired', 'revoked')]
for e in ev: recs.remove(e)
$ALLOWIFY
i = [k for k, r in enumerate(recs) if isinstance(r, dict) and r.get('event') == 'run_end'][0]
recs[i:i] = ev"
    refuses "an expiry and its revocation recorded late, the calls between allowed" "$B/pe.txt" "$OUT/g13.log" "not in time order"
    python3 "$F" "$OUT/exp_rv.out" "$OUT/g14.log" "recs[:] = [r for r in recs if not (isinstance(r, dict) and r.get('event') in ('on_behalf_of_expired', 'revoked', 'run_end'))]
$ALLOWIFY"
    if python3 "$AUD" --allow-incomplete --policy "$B/pe.txt" --checker "$CERT" "$OUT/g14.log" > "$OUT/f.out" 2>&1; then flunk "the audit refuses an incomplete stream past the expiry with none recorded"
    elif grep -q "allowed after the user's token expired" "$OUT/f.out"; then pass "the audit refuses an incomplete stream past the expiry with none recorded"
    else flunk "the audit refuses an incomplete stream past the expiry ($(grep -m1 PROBLEM "$OUT/f.out"))"; fi
    python3 "$F" "$OUT/e2big.out" "$OUT/g15.log" "$DR
for r in recs:
    if isinstance(r, dict) and r.get('event') in ('exec_result', 'subagent_settled'): r.pop('subagent', None)
dr[-1]['obo'] = ['agent', 'subagent:alpha#1']"
    refuses "a failed launch with its sub-agent stripped from its results" "$B/p.txt" "$OUT/g15.log" "subagent_settled event that is malformed"
    python3 "$F" "$OUT/e2big.out" "$OUT/g16.log" "ex = [r for r in recs if isinstance(r, dict) and r.get('event') in ('exec_result', 'subagent_settled')]
for e in ex: recs.remove(e)
i = [k for k, r in enumerate(recs) if isinstance(r, dict) and r.get('event') == 'run_end'][0]; recs[i:i] = ex
$DR
dr[-1]['obo'] = ['agent', 'subagent:alpha#1']"
    refuses "a sub-agent's decision before its launch settled" "$B/p.txt" "$OUT/g16.log" "before its launch is known to have happened"
    python3 "$F" "$OUT/exp_rv.out" "$OUT/g17.log" "$RS; rs['warden'] = '1.28.0'
for k in ('on_behalf_of', 'operator', 'secrets_binary_sha256'): rs.pop(k, None)
recs[:] = [r for r in recs if not (isinstance(r, dict) and r.get('event') in ('on_behalf_of_expired', 'revoked'))]
$ALLOWIFY
for r in recs:
    if isinstance(r, dict): r.pop('obo', None)"
    refuses "a run claiming a Warden that predates the chain, under a policy that trusts an issuer" "$B/pe.txt" "$OUT/g17.log" "which only a Warden of 1.28.1 or later reads"
    for code in "rs['on_behalf_of'] = 'x'" "rs['on_behalf_of']['user']['issuer'] = ['a']" "rs['on_behalf_of']['user']['expires'] = 'xx'"; do
        python3 "$F" "$OUT/exp_rv.out" "$OUT/g18.log" "$RS; $code"
        python3 "$AUD" --policy "$B/pe.txt" --checker "$CERT" "$OUT/g18.log" > "$OUT/f.out" 2>&1
        grep -q Traceback "$OUT/f.out" && flunk "the audit answers a malformed run_start ($code) without a traceback" \
            || pass "the audit answers a malformed run_start ($code) without a traceback"
    done
    # the tools
    for n in user nest es256 plain; do cp "$OUT/$n.out" "$OUT/verdicts-$n.log"; done
    printf '[varek]\npolicy = %s\nlog_dir = %s\n' "$B/pu.txt" "$OUT" > "$OUT/varek5.conf"
    V() { NO_COLOR=1 VAREK_CONFIG="$OUT/varek5.conf" python3 "$HERE/tools/varek" "$@"; }
    V runs -n 10 > "$OUT/runs.out" 2>&1
    check "varek runs: whom each run was for, and its sub-agents" sh -c "grep -q 'alice@example.test +1 sub-agent .*verdicts-user.log' '$OUT/runs.out' && grep -q 'agent +2 sub-agents .*verdicts-nest.log' '$OUT/runs.out' && grep -q ' agent  .*verdicts-plain.log' '$OUT/runs.out'"
    V refusals "$OUT/user.out" > "$OUT/rf1.out" 2>&1
    check "varek refusals: on behalf of whom, the sub-agents, and who got each refusal" sh -c \
        "grep -q 'On behalf of alice@example.test (token from $ISS, verified); sub-agents: alpha#1' '$OUT/rf1.out' && grep -q 'sub-agent alpha#1 got EACCES' '$OUT/rf1.out' && grep -q 'the agent got EACCES' '$OUT/rf1.out'"
    V refusals --subagent alpha "$OUT/user.out" > "$OUT/rf2.out" 2>&1
    check "varek refusals --subagent: that sub-agent's refusals only" sh -c "grep -q 'sub-agent alpha#1 got' '$OUT/rf2.out' && ! grep -q 'the agent got' '$OUT/rf2.out'"
    V refusals --user bob "$OUT/user.out" > "$OUT/rf3.out" 2>&1
    check "varek refusals --user: a run for someone else says so" grep -q 'This run was not on behalf of bob (it was on behalf of alice@example.test)' "$OUT/rf3.out"
    V refusals "$OUT/exp_rv.out" > "$OUT/rf4.out" 2>&1
    check "varek refusals: the token expired and the run was revoked" sh -c "grep -q 'expired during the run (the run was revoked)' '$OUT/rf4.out' && grep -q '(the user.s token expired): every call after it was refused' '$OUT/rf4.out'"
    { cat "$OUT/user.out"; printf '%s\n' '{"event":"on_behalf_of_expired","action":"revoke"}' '{"event":"revoked","by":"on_behalf_of_expiry"}'; } > "$OUT/fake.log"
    V refusals "$OUT/fake.log" > "$OUT/rf5.out" 2>&1
    check "varek refusals ignores lines with no run id (the agent's output in the same file)" sh -c "! grep -q 'expired\|was revoked' '$OUT/rf5.out'"
    python3 "$F" "$OUT/user.out" "$OUT/g19.log" "$RS; rs['on_behalf_of']['user']['verified'] = False"
    V refusals "$OUT/g19.log" > "$OUT/rf6.out" 2>&1
    check "varek refusals does not call an unverified user verified" grep -q 'NOT marked verified' "$OUT/rf6.out"
    V policy show "$B/pu.txt" > "$OUT/ps.out" 2>&1
    check "varek policy show: the trusted issuer and the sub-agents" sh -c "grep -q '^Issuer   $ISS: a user.s token it issued for varek-agent' '$OUT/ps.out' && grep -q '^  alpha: line 2: allow exec $B/a subagent=alpha' '$OUT/ps.out'"
    python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/user.out" --policy "$B/pu.txt" --output "$OUT/u.cdx.json" > /dev/null 2>&1
    check "the export carries varek:on_behalf_of.* (the user, the operator, each sub-agent's decisions)" python3 -c 'import json,sys
P={}
def walk(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "properties": P.update({p["name"]: p["value"] for p in v})
            else: walk(v)
    elif isinstance(o, list):
        for x in o: walk(x)
walk(json.load(open(sys.argv[1])))
sys.exit(0 if P.get("varek:on_behalf_of.user.subject") == "alice@example.test" and P.get("varek:on_behalf_of.user.issuer") == sys.argv[2]
         and "not verified" in P.get("varek:on_behalf_of.operator", "") and P.get("varek:on_behalf_of.subagents") == "1"
         and int(P.get("varek:on_behalf_of.subagent.alpha#1.decisions", "0")) > 0 else 1)' "$OUT/u.cdx.json" "$ISS"
    check "the export holds no token" sh -c "! grep -qF -- '$TOKSIG' '$OUT/u.cdx.json'"
    VL() { python3 -c 'import importlib.machinery,sys
m = importlib.machinery.SourceFileLoader("varekcli", sys.argv[1]).load_module()
print(*m.issuer_keys(sys.argv[2], None, sys.argv[3]))' "$HERE/tools/varek" "$@"; }
    check "varek doctor's issuer check: the stand-in's keys" sh -c "$(declare -f VL); HERE='$HERE' VL '$ISS' '$T/conf' | grep -q '^True 3 key(s) (EC, OKP, RSA) at $ISS/jwks'"
    check "... and an issuer whose discovery names another" sh -c "$(declare -f VL); HERE='$HERE' VL '$ISS/liar' '$T/conf' | grep -q 'names another issuer'"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1281: PASS ($skips skipped)"; exit 0; fi
echo "test_v1281: FAIL"; exit 1
