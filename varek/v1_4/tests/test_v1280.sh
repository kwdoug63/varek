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

echo "== 2. fetching: warden-secrets =="
SECRETS="$(dirname "$WARDEN")/warden-secrets"
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ ! -x "$SECRETS" ] || ! python3 -c 'import cryptography' 2>/dev/null; then
    skip "section 2 (needs root, the warden and warden-secrets binaries, and python3-cryptography)"
else
    SD="$OUT/stores"; T="$(mktemp -d /tmp/varek_v1280.XXXXXX)"; mkdir -p "$SD"; chmod 755 "$T"
    python3 "$HERE/tests/v1280_stores.py" "$SD" > "$SD/server.out" 2>&1 &
    SRV=$!
    trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT $T" || rm -rf "$OUT" "$T"' EXIT
    for _ in $(seq 100); do [ -f "$SD/ports" ] && break; sleep 0.1; done
    read -r HP IP < "$SD/ports"
    cp "$SD/ca.pem" "$T/ca.pem"; chmod 644 "$T/ca.pem"            # read by the helper's own user
    put() { printf '%b' "$2" > "$T/$1"; chmod "${3:-600}" "$T/$1"; }
    put k 'file-value-1234\n'
    put vt 's.test-token-v1280\n'
    put aws 'aws_access_key_id = AKIDV1280TEST\naws_secret_access_key = v1280-test-secret-key/abc\n'
    CONF="vault_addr = https://127.0.0.1:$HP\nvault_token_file = $T/vt\nvault_ca = $T/ca.pem\naws_endpoint = https://127.0.0.1:$HP\naws_ca = $T/ca.pem\n"
    put conf "${CONF}aws_credentials_file = $T/aws\n"
    put conf_imds "${CONF}aws_imds = http://127.0.0.1:$IP\n"
    ARN='arn:aws:secretsmanager:us-east-1:111122223333:secret'
    # run <name> <credential lines> [warden options]: the Warden's output in $OUT/<name>.out
    run() { local n="$1" c="$2"; shift 2
            printf 'require warden 1.28\nproxy inspect\n%ballow host api.example.com:443\nallow request GET https://api.example.com/x credential=c header=X-K\n' "$c" > "$T/$n.txt"
            chmod 644 "$T/$n.txt"
            (cd "$T" && timeout 60 "$WARDEN" "$T/$n.txt" "$@" -- /usr/bin/true > "$OUT/$n.out" 2>&1); echo $? > "$OUT/$n.rc"; }
    has() { grep -qF -- "$2" "$OUT/$1.out"; }
    : > "$SD/requests.log"
    run all "credential c from file:$T/k\ncredential gh from vault:secret/data/agents/gh#token\ncredential v1 from vault:kv1/thing#value\ncredential db from vault:database/creds/ro#password\ncredential st from aws-sm:$ARN:stripe-AbCdEf\n" --secrets-conf "$T/conf"
    check "a file store: fetched, its length and its inode and mtime as the version" \
        sh -c "grep -Eq 'credential c from file:$T/k: fetched, 15 bytes, version inode:[0-9]+ mtime:[0-9]+' '$OUT/all.out'"
    check "Vault KV version 2 (a chunked answer): fetched, version kv2:3" has all "credential gh from vault:secret/data/agents/gh#token: fetched, 20 bytes, version kv2:3"
    check "Vault KV version 1: fetched, version kv1" has all "credential v1 from vault:kv1/thing#value: fetched, 20 bytes, version kv1"
    check "a leased Vault secret: fetched, the lease as its version" has all "version lease:database/creds/ro/AbC123"
    check "AWS Secrets Manager with a key file: fetched, the version id; the stand-in checked the signature" \
        sh -c "grep -qF 'version aws:a1b2c3d4-5678-90ab-cdef-EXAMPLE11111' '$OUT/all.out' && grep -q 'key=AKIDV1280TEST signature=ok' '$SD/requests.log'"
    check "the helper's binary is hashed" sh -c "grep -Eq \"credentials' helper .*warden-secrets, SHA-256 [0-9a-f]{64}\" '$OUT/all.out'"
    check "then, the swap being step 3, the start is refused" sh -c "has() { grep -qF -- \"\$2\" '$OUT/'\"\$1\".out; }; has all 'credential release is not built in this Warden yet' && ! grep -qx 0 '$OUT/all.rc'"
    check "no value is in the Warden's output" sh -c "! grep -Eq 'file-value-1234|vault-kv2-value|vault-kv1-value|db-password|aws-sm-value' '$OUT/all.out'"
    check "the helper is gone once the Warden is" sh -c "! pgrep -fx 'warden-secrets [0-9]+:[0-9]+'"
    run imds "credential c from aws-sm:$ARN:stripe-AbCdEf\n" --secrets-conf "$T/conf_imds"
    check "AWS through the instance's role (IMDSv2): fetched, signed with the role's key and token" \
        sh -c "grep -q 'credential c from aws-sm:.*: fetched, 17 bytes' '$OUT/imds.out' && grep -q 'key=ASIAROLEV1280 signature=ok' '$SD/requests.log'"
    run as "credential c from file:$T/k\n" --secrets-as 65530:65530
    check "with --secrets-as, the helper proves it runs as that user" has as "credential c from file:$T/k: fetched"

    # refusals
    refuse() { local d="$1" n="$2" w="$3"; if has "$n" "$w" && ! grep -qx 0 "$OUT/$n.rc"; then pass "refused: $d"; else flunk "refused: $d ($(grep -m1 'refusing\|credential' "$OUT/$n.out"))"; fi; }
    put k644 'v\n' 644;            run f1 "credential c from file:$T/k644\n"
    refuse "a file store others can read" f1 "readable by no group or other user"
    put kown 'v\n'; chown 65534 "$T/kown"; run f2 "credential c from file:$T/kown\n"
    refuse "a file store not owned by root" f2 "must be owned by root"
    put kempty '';                  run f3 "credential c from file:$T/kempty\n"
    refuse "an empty file store" f3 "the value is empty"
    put k2 'a\nb\n';                run f4 "credential c from file:$T/k2\n"
    refuse "a file store of two lines" f4 "CR, LF or NUL"
    run f5 "credential c from file:$T/missing\n"
    refuse "a file store that is not there" f5 "cannot open $T/missing"
    printf 'require warden 1.28\nproxy inspect\ncredential c from file:%s/k\nallow path %s/ readonly\nallow host api.example.com:443\nallow request GET https://api.example.com/x credential=c header=X-K\n' "$T" "$T" > "$T/f6.txt"
    (cd "$T" && timeout 60 "$WARDEN" "$T/f6.txt" -- /usr/bin/true > "$OUT/f6.out" 2>&1); echo $? > "$OUT/f6.rc"
    refuse "a file store the policy lets the agent open" f6 "the policy lets the agent open $T/k"
    printf 'require warden 1.28\nproxy inspect\ncredential c from vault:secret/data/agents/gh#token\nallow path exact %s/vt readonly\nallow host api.example.com:443\nallow request GET https://api.example.com/x credential=c header=X-K\n' "$T" > "$T/f7.txt"
    (cd "$T" && timeout 60 "$WARDEN" "$T/f7.txt" --secrets-conf "$T/conf" -- /usr/bin/true > "$OUT/f7.out" 2>&1); echo $? > "$OUT/f7.rc"
    refuse "a Vault token file the policy lets the agent open" f7 "the policy lets the agent open $T/vt"
    run f8 "credential c from vault:secret/data/agents/gh#token\n" --secrets-conf "$T/vt"
    refuse "a configuration that is not key = value lines" f8 "need key = value"
    put c644 "$CONF" 644;           run c1 "credential c from vault:secret/data/agents/gh#token\n" --secrets-conf "$T/c644"
    refuse "a configuration others can read" c1 "readable by no group or other user"
    put cbad "${CONF}vault_path = x\n"; run c2 "credential c from vault:secret/data/agents/gh#token\n" --secrets-conf "$T/cbad"
    refuse "a configuration with an unknown key" c2 "unknown key vault_path"
    put vbad 's.wrong\n';           put cv "vault_addr = https://127.0.0.1:$HP\nvault_token_file = $T/vbad\nvault_ca = $T/ca.pem\n"
    run v1 "credential c from vault:secret/data/agents/gh#token\n" --secrets-conf "$T/cv"
    refuse "a wrong Vault token" v1 "vault answered 403"
    run v2 "credential c from vault:secret/data/agents/gh#nope\n" --secrets-conf "$T/conf"
    refuse "a Vault field that is not there" v2 "vault's answer has no such field"
    run v3 "credential c from vault:secret/data/agents/nl#token\n" --secrets-conf "$T/conf"
    refuse "a Vault value of two lines" v3 "CR, LF or NUL"
    put cplain "vault_addr = http://192.0.2.1:8200\nvault_token_file = $T/vt\n"
    run v4 "credential c from vault:secret/data/agents/gh#token\n" --secrets-conf "$T/cplain"
    refuse "plain http to Vault off the host" v4 "plain http to 192.0.2.1"
    put cnoca "vault_addr = https://127.0.0.1:$HP\nvault_token_file = $T/vt\n"
    run v5 "credential c from vault:secret/data/agents/gh#token\n" --secrets-conf "$T/cnoca"
    refuse "a Vault certificate the host's trust store does not know" v5 "TLS to 127.0.0.1 failed"
    put awsbad 'aws_access_key_id = AKIDV1280TEST\naws_secret_access_key = wrong\n'
    put cawsbad "${CONF}aws_credentials_file = $T/awsbad\n"
    run a1 "credential c from aws-sm:$ARN:stripe-AbCdEf\n" --secrets-conf "$T/cawsbad"
    refuse "a wrong AWS secret key" a1 "Secrets Manager answered 403"
    run a2 "credential c from aws-sm:$ARN:binary-Xy\n" --secrets-conf "$T/conf"
    refuse "a binary AWS secret" a2 "a binary secret"
    run u1 "credential c from file:$T/k\n" --secrets-as nobody --run-as nobody
    refuse "the helper as the agent's user" u1 "may not run as the agent's user"
    : > "$SD/requests.log"
    printf 'require warden 1.28\nproxy inspect\ncredential c from vault:secret/data/agents/gh#token\nallow host api.example.com:443\nallow request GET https://api.example.com/x credential=c header=X-K\n' > "$T/cs.txt"
    "$WARDEN" "$T/cs.txt" --check-startup --secrets-conf "$T/conf" > "$OUT/cs.out" 2>&1
    check "--check-startup lists the credentials and fetches nothing" \
        sh -c "grep -q 'credential c from vault:secret/data/agents/gh#token (line 3)' '$OUT/cs.out' && [ ! -s '$SD/requests.log' ]"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1280: PASS ($skips skipped)"; exit 0; fi
echo "test_v1280: FAIL"; exit 1
