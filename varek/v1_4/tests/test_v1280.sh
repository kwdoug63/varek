#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# test_v1280.sh — VAREK v1.28.0: credential release, the agent holds only
# placeholders (docs/security/v1.28-credential-release.md):
#   1. the grammar: `credential NAME from STORE:REF` and an allow request
#      rule's `credential=NAME header=HEADER[:SCHEME]`, after `require warden
#      1.28`, read the same way by the decision procedure (vdp_check) and the
#      certificate checker (vdp_cert_check), each form and each refusal; lint
#      notes a credential no rule carries; the Warden reports 1.28.0 and
#      compares the two readings at load.
#   2. fetching: warden-secrets and each store, against stand-ins.
#   3. the swap: placeholders in the agent's environment, the value put in
#      by warden-proxy where an allowing rule names it, and nowhere else.
#   4. revocation: `varek revoke` in mid-run; what is refused after, what is
#      recorded, the proxy's values cleared, the Vault leases revoked; lease
#      renewal. Sections 3 and 4 also audit their runs, and forged streams.
#   5. records and tools: --check-credentials and the preflight, varek
#      policy show, varek refusals, the CycloneDX export.
#   6. the review's fixes: second names of the files warden-secrets reads,
#      their directories, its hardening, a Vault that resets, leases revoked
#      at the end, the stub after a revocation, forged orders, the tools.
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
refused "a credential on an http:// rule" "${R}${C}allow host api.example.com:80\nallow request GET http://api.example.com/x credential=k header=X-K\n" "only on an https:// rule"

printf 'require warden 1.28\nproxy inspect\nallow host api.example.com:443\n%bcredential unused from file:/u\nallow request GET https://api.example.com/x credential=k header=X\n' "$C" > "$OUT/l.txt"
check "lint notes a credential no rule carries" sh -c "'$VDP' '$OUT/l.txt' lint | grep -q ':5: note: credential unused is named, but no request rule carries it'"
check "lint is silent on a credential a rule carries" sh -c "! '$VDP' '$OUT/l.txt' lint | grep -q 'credential k is named'"

if [ -z "$WARDEN" ]; then
    skip "the Warden's checks (no warden binary given)"
else
    check "the Warden reports 1.28 (1.28.0 or a later patch)" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | grep -Eq 'VAREK Warden  1\.28\.[0-9]+'"
    printf '%b' "$(Q 'credential=k header=Authorization:Bearer')" > "$OUT/w.txt"
    "$WARDEN" "$OUT/w.txt" --check-startup > "$OUT/w.out" 2>&1; echo $? > "$OUT/w.rc"
    check "--check-startup accepts a policy that names a credential, and lists it" \
        sh -c "grep -qx 0 '$OUT/w.rc' && grep -q 'credential k from file:/etc/varek/creds/k (line 4)' '$OUT/w.out'"
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
    check "then the proxy holds all five values (step 3)" has all "credentials: 5 held by the proxy"
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

echo "== 3. the swap =="
WP="$(dirname "$WARDEN")/warden-proxy"
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ ! -x "$SECRETS" ] || [ ! -x "$WP" ] || ! command -v openssl > /dev/null; then
    skip "section 3 (needs root, warden, warden-proxy, warden-secrets and openssl)"
else
    X=/tmp/varek_v1280x.$$
    rm -rf "$X"; mkdir -p "$X/o"; chmod 755 "$X"; chmod 777 "$X/o"
    trap 'kill $SRV $S3 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT ${T:-} $X" || rm -rf "$OUT" "${T:-}" "$X"' EXIT
    HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
    PS=$((43000 + RANDOM % 5000))
    ( cd "$X" &&
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tca.key -out tca.pem -days 2 \
          -subj "/CN=VAREK v1.28 test root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" &&
      openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout s.key -out s.csr -subj "/CN=api.example.com" &&
      printf 'subjectAltName=DNS:api.example.com\nextendedKeyUsage=serverAuth\n' > s.ext &&
      openssl x509 -req -in s.csr -CA tca.pem -CAkey tca.key -CAcreateserial -out s.pem -days 1 -extfile s.ext ) > "$OUT/certs3.log" 2>&1
    cat "$(python3 -c 'import ssl; print(ssl.get_default_verify_paths().openssl_cafile)')" "$X/tca.pem" > "$X/bundle.pem"
    chmod 644 "$X"/*.pem
    # the server logs each request's head and body as it got them (JSON lines)
    cat > "$OUT/srv3.py" <<'PY'
import json, socket, ssl, sys, threading
ip, port, cert, key, log = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind((ip, port)); l.listen(16)
lk = threading.Lock()
def serve(c):
    try:
        s = ctx.wrap_socket(c, server_side=True)
        d = b""
        while b"\r\n\r\n" not in d:
            x = s.recv(65536)
            if not x: return
            d += x
        head, body = d.split(b"\r\n\r\n", 1)
        n = 0
        for h in head.split(b"\r\n")[1:]:
            if h.lower().startswith(b"content-length:"): n = int(h.split(b":", 1)[1])
        while len(body) < n:
            x = s.recv(65536)
            if not x: break
            body += x
        with lk, open(log, "a") as f:
            f.write(json.dumps({"head": head.decode("latin-1"), "body": body.decode("latin-1")}) + "\n")
        s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"); s.close()
    except Exception as e:
        print("srv", type(e).__name__, e, flush=True)
while True:
    c, _ = l.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
    python3 "$OUT/srv3.py" "$HOSTIP" "$PS" "$X/s.pem" "$X/s.key" "$OUT/got.jsonl" > "$OUT/srv3.log" 2>&1 &
    S3=$!
    DP=$((20000 + RANDOM % 20000))
    printf '{"api.example.com": {"ttl": 30, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/zone3.json"
    python3 "$HERE/tests/dns_test_server.py" --port "$DP" --zone "$OUT/zone3.json" --log "$OUT/q3.log" --ready "$OUT/ready3" > /dev/null 2>&1 &
    S3="$S3 $!"
    for _ in $(seq 50); do
        [ -e "$OUT/ready3" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $PS), 0.2)" 2>/dev/null && break
        sleep 0.1
    done
    # the values: one longer than its placeholder (200 bytes), one shorter
    V1="$(python3 -c 'print("L" * 191 + "-long-val")')"; V2="short-v2"
    printf '%s\n' "$V1" > "$X/v1"; printf '%s\n' "$V2" > "$X/v2"; chmod 600 "$X/v1" "$X/v2"
    cat > "$X/agent.py" <<'PY'
import os, socket, ssl, sys
P, O = int(sys.argv[1]), sys.argv[2]
ph1, ph2 = os.environ.get("VAREK_CRED_C1", ""), os.environ.get("VAREK_CRED_C2", "")
print("ENV", ph1.startswith("varek_ph_c1_"), ph2.startswith("varek_ph_c2_"), len(ph1), flush=True)
with open(os.path.join(O, "env"), "w") as f:
    f.write("\n".join(f"{k}={v}" for k, v in os.environ.items()))
def req(tag, head, body=b""):
    try:
        s = ssl.create_default_context().wrap_socket(socket.create_connection(("api.example.com", P), 10),
                                                     server_hostname="api.example.com")
        s.sendall(head + body)                      # head and body in one write
        out = b""
        while True:
            d = s.recv(4096)
            if not d: break
            out += d
        print("REQ", tag, out.split(b"\r\n")[0].decode(), flush=True)
    except (OSError, ssl.SSLError) as e:
        print("REQ", tag, "ERR", type(e).__name__, flush=True)
H = b"Host: api.example.com:%d\r\n" % P
e1, e2 = ph1.encode(), ph2.encode()
body = b"body holds " + e1 + b" as sent"
req("bearer", b"POST /v1/a HTTP/1.1\r\n" + H + b"Authorization: Bearer " + e1 + b"\r\nContent-Length: %d\r\n\r\n" % len(body), body)
req("key", b"GET /v1/b HTTP/1.1\r\n" + H + b"X-Api-Key: " + e2 + b"\r\n\r\n")
req("case", b"GET /v1/a HTTP/1.1\r\n" + H + b"authorization:   bearer " + e1 + b"  \r\n\r\n")
req("missing", b"GET /v1/a HTTP/1.1\r\n" + H + b"\r\n")
req("twice", b"GET /v1/a HTTP/1.1\r\n" + H + b"Authorization: Bearer " + e1 + b"\r\nAuthorization: Bearer " + e1 + b"\r\n\r\n")
req("other", b"GET /v1/a HTTP/1.1\r\n" + H + b"Authorization: Bearer " + e2 + b"\r\n\r\n")
req("extra", b"GET /v1/a HTTP/1.1\r\n" + H + b"Authorization: Bearer " + e1 + b" x\r\n\r\n")
req("noscheme", b"GET /v1/a HTTP/1.1\r\n" + H + b"Authorization: " + e1 + b"\r\n\r\n")
req("plain", b"GET /v1/plain?q=" + e1 + b" HTTP/1.1\r\n" + H + b"Authorization: Bearer " + e1 + b"\r\nX-Other: " + e2 + b"\r\n\r\n")
PY
    chmod 644 "$X/agent.py"
    POL3="$OUT/swap.policy"
    { printf 'require warden 1.28\nproxy inspect\nproxy ports %s\n' "$PS"
      printf 'credential c1 from file:%s/v1\ncredential c2 from file:%s/v2\n' "$X" "$X"
      printf 'allow host api.example.com\n'
      printf 'allow request POST https://api.example.com:%s/v1/a credential=c1 header=Authorization:Bearer\n' "$PS"
      printf 'allow request GET https://api.example.com:%s/v1/a credential=c1 header=Authorization:Bearer\n' "$PS"
      printf 'allow request GET https://api.example.com:%s/v1/b credential=c2 header=X-Api-Key\n' "$PS"
      printf 'allow request GET https://api.example.com:%s/v1/plain?q=*\n' "$PS"
      printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path exact %s/agent.py readonly\nallow path %s/o/\n' "$X" "$X"
    } > "$POL3"
    env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$POL3" --dns-server "127.0.0.1:$DP" --trust-bundle "$X/bundle.pem" -- \
        /usr/bin/python3 "$X/agent.py" "$PS" "$X/o" > "$OUT/a3.out" 2> "$OUT/a3.log"
    sed 's/^/     /' "$OUT/a3.out"
    got() { python3 - "$OUT/got.jsonl" "$1" <<'PY'
import json, sys
for l in open(sys.argv[1]):
    r = json.loads(l)
    if eval(sys.argv[2], {"h": r["head"], "b": r["body"]}):
        sys.exit(0)
sys.exit(1)
PY
    }
    check "the agent's environment has a placeholder for each credential" grep -qx 'ENV True True 55' "$OUT/a3.out"
    check "a value longer than its placeholder, after a scheme: the server got it; the body after the head is intact" \
        got "h.startswith('POST /v1/a ') and 'Authorization: Bearer $V1\r\n' in h + '\r\n' and b.startswith('body holds varek_ph_c1_')"
    check "a value shorter than its placeholder, the whole header value: the server got it" \
        got "h.startswith('GET /v1/b ') and 'X-Api-Key: $V2' in h"
    check "a scheme in another case, with spaces around: swapped" \
        got "h.startswith('GET /v1/a ') and 'authorization:   bearer $V1' in h"
    for t in missing twice other extra noscheme; do
        check "refused ($t): 403, nothing reaches the server" grep -qx "REQ $t HTTP/1.1 403 Forbidden" "$OUT/a3.out"
    done
    check "four requests reached the server: the three swapped and the plain one" sh -c "[ \$(wc -l < '$OUT/got.jsonl') -eq 4 ]"
    check "a placeholder where no rule names its credential is sent as it is (query, another header, a rule without one)" \
        got "h.startswith('GET /v1/plain?q=varek_ph_c1_') and 'Authorization: Bearer varek_ph_c1_' in h and 'X-Other: varek_ph_c2_' in h"
    check "no value is in the agent's environment" sh -c "! grep -qF -- '$V2' '$X/o/env' && ! grep -qF -- 'long-val' '$X/o/env'"
    check "the server got a value only where a rule names it: never in the request no rule gives a credential" \
        got "h.startswith('GET /v1/plain') and '$V2' not in h + b and 'long-val' not in h + b"
    check "and in each swapped request, nowhere but its header" \
        got "h.startswith('GET /v1/b ') and h.count('$V2') == 1 and '$V2' not in b and 'long-val' not in h + b"
    check "no value is in the verdict stream" sh -c "! grep -qF -- '$V2' '$OUT/a3.log' && ! grep -qF -- 'long-val' '$OUT/a3.log'"
    rec() { python3 - "$OUT/a3.log" "$1" <<'PY'
import json, sys
recs = [json.loads(l[l.index("{"):]) for l in open(sys.argv[1], errors="replace") if l.lstrip().startswith("{") or ' {"' in l]
sys.exit(0 if eval(sys.argv[2], {"R": recs}) else 1)
PY
    }
    check "each allowed request with a credential records its name and header" \
        rec "sum(1 for r in R if r.get('action') == 'net.request' and r.get('credential') == 'c1' and r.get('credential_header') == 'Authorization') >= 6"
    check "each refused swap is recorded (credential_refused, with why)" \
        rec "sum(1 for r in R if r.get('event') == 'credential_refused' and r.get('credential') in ('c1',) and r.get('why')) == 5"
    # step 5: run_start, and the audit
    check "run_start lists each credential: store, reference, version, length, placeholder's SHA-256; and the helper's SHA-256" \
        rec "[(c['name'], c['store'], c['ref'], c['length'], len(c['placeholder_sha256']), c['version'][:6]) for r in R if r.get('event') == 'run_start' for c in r['credentials']] == [('c1', 'file', '$X/v1', 200, 64, 'inode:'), ('c2', 'file', '$X/v2', 8, 64, 'inode:')] and any(len(r.get('secrets_binary_sha256', '')) == 64 for r in R)"
    check "no placeholder is in the verdict stream, but in a request object the agent sent" \
        sh -c "! grep -v '\"action\":\"net.request\"' '$OUT/a3.log' | grep -q 'varek_ph_c[12]_[A-Za-z0-9_-]\{43\}'"
    AUD3() { python3 "$HERE/tools/varek_audit.py" --policy "$POL3" --checker "$CERT" "$1" > "$OUT/aud3.out" 2>&1; }
    check "the audit accepts the run, and counts what was carried and refused" \
        sh -c "$(declare -f AUD3); HERE='$HERE' POL3='$POL3' CERT='$CERT' OUT='$OUT'; AUD3 '$OUT/a3.log' && grep -q 'credentials: 2 named, 8 requests carried one, 5 swaps refused' '$OUT/aud3.out'"
    F="$HERE/tests/v1270_forge.py"
    RS='rs = next(r for r in recs if isinstance(r, dict) and r.get("event") == "run_start")'
    RQ='rq = [r for r in recs if isinstance(r, dict) and r.get("action") == "net.request" and r.get("credential")]'
    refuses() { if python3 "$HERE/tools/varek_audit.py" --policy "$2" --checker "$CERT" "$3" > "$OUT/f.out" 2>&1; then
                    flunk "the audit refuses $1"
                elif grep -qF -- "$4" "$OUT/f.out"; then pass "the audit refuses $1"
                else flunk "the audit refuses $1 ($(grep -m1 PROBLEM "$OUT/f.out"))"; fi; }
    python3 "$F" "$OUT/a3.log" "$OUT/g1.log" "$RQ; rq[0]['credential'] = 'c2'"
    refuses "a credential on a rule that names another" "$POL3" "$OUT/g1.log" "which its deciding rule (line"
    python3 "$F" "$OUT/a3.log" "$OUT/g2.log" "$RQ; rq[0]['credential_header'] = 'X-Api-Key'"
    refuses "a credential in another header than its rule's" "$POL3" "$OUT/g2.log" "which its deciding rule (line"
    python3 "$F" "$OUT/a3.log" "$OUT/g3.log" "$RQ; del rq[0]['credential'], rq[0]['credential_header']"
    refuses "an allowed request without the credential its rule names" "$POL3" "$OUT/g3.log" "recorded without it"
    python3 "$F" "$OUT/a3.log" "$OUT/g4.log" "$RQ; c = rq[0]['proxy_conn']; [r.update(inspected=False) for r in recs if isinstance(r, dict) and r.get('action') == 'net.proxy' and r.get('proxy_conn') == c]"
    refuses "a credential on a connection not inspected (passthrough)" "$POL3" "$OUT/g4.log" "which was not passed on to be inspected"
    python3 "$F" "$OUT/a3.log" "$OUT/g5.log" "$RS; del rs['credentials']"
    refuses "a run_start without the credentials" "$POL3" "$OUT/g5.log" "does not list the policy's 2 credential(s)"
    python3 "$F" "$OUT/a3.log" "$OUT/g6.log" "$RS; rs['credentials'][1]['ref'] = '/etc/other'"
    refuses "a run_start naming another reference" "$POL3" "$OUT/g6.log" "are not the policy's"
    python3 "$F" "$OUT/a3.log" "$OUT/g7.log" "$RS; rs['credentials'][1]['placeholder_sha256'] = rs['credentials'][0]['placeholder_sha256']"
    refuses "two credentials with one placeholder" "$POL3" "$OUT/g7.log" "a placeholder's SHA-256 of its own"
    python3 "$F" "$OUT/a3.log" "$OUT/g8.log" "cf = next(r for r in recs if isinstance(r, dict) and r.get('event') == 'credential_refused'); cf['request_seq'] = 99"
    refuses "a refused swap of a request never allowed" "$POL3" "$OUT/g8.log" "follows no allowed request"
fi

echo "== 4. revocation =="
if [ -z "${SRV:-}" ] || [ -z "${S3:-}" ] || ! command -v setpriv > /dev/null; then
    skip "section 4 (needs sections 2 and 3, and setpriv)"
else
    # the agent: a request with a credential, a connection it holds open, an
    # address it resolved; then it waits on stdin while the run is revoked,
    # and tries a request on the held connection, a file open and a connect
    cat > "$X/agent4.py" <<'PY'
import os, socket, ssl, sys
P = int(sys.argv[1])
ph = os.environ.get("VAREK_CRED_C1", "").encode()
ctx = ssl.create_default_context()
def conn(addr=("api.example.com", P)):
    return ctx.wrap_socket(socket.create_connection(addr, 10), server_hostname="api.example.com")
def req(tag, s):
    try:
        s.sendall(b"GET /v1/a HTTP/1.1\r\nHost: api.example.com:%d\r\nAuthorization: Bearer %s\r\n\r\n" % (P, ph))
        out = b""
        while True:
            d = s.recv(4096)
            if not d: break
            out += d
        print("REQ", tag, out.split(b"\r\n")[0].decode() or "EOF", flush=True)
    except (OSError, ssl.SSLError) as e:
        print("REQ", tag, "ERR", type(e).__name__, flush=True)
def opn(tag):
    try:
        open("/usr/bin/true", "rb").close(); print("OPEN", tag, "ok", flush=True)
    except OSError as e:
        print("OPEN", tag, e.errno, flush=True)
addr = socket.getaddrinfo("api.example.com", P, socket.AF_INET, socket.SOCK_STREAM)[0][4]
req("before", conn(addr))
opn("before")
held = conn(addr)
print("READY", flush=True)
sys.stdin.readline()
req("held", held)
opn("after")
try:
    socket.create_connection(addr, 10).close(); print("CONNECT after ok", flush=True)
except OSError as e:
    print("CONNECT after", type(e).__name__, flush=True)
PY
    chmod 644 "$X/agent4.py"
    POL4="$OUT/revoke.policy"
    { printf 'require warden 1.28\nproxy inspect\nproxy ports %s\n' "$PS"
      printf 'credential c1 from file:%s/v1\n' "$X"
      printf 'credential sh from vault:database/creds/short#password\ncredential sk from vault:database/creds/stuck#password\n'
      printf 'allow host api.example.com\n'
      printf 'allow request GET https://api.example.com:%s/v1/a credential=c1 header=Authorization:Bearer\n' "$PS"
      printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path exact %s/agent4.py readonly\n' "$X"
    } > "$POL4"
    n3=$(wc -l < "$OUT/got.jsonl")
    : > "$SD/requests.log"
    rm -f "$X/go"; mkfifo "$X/go"; exec 7<> "$X/go"
    env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$POL4" --secrets-conf "$T/conf" --dns-server "127.0.0.1:$DP" \
        --trust-bundle "$X/bundle.pem" -- /usr/bin/python3 "$X/agent4.py" "$PS" < "$X/go" > "$OUT/a4.out" 2> "$OUT/a4.log" &
    W4=$!
    for _ in $(seq 600); do grep -q READY "$OUT/a4.out" 2>/dev/null && break; sleep 0.1; done
    # a renewal of the short lease is due at 2 s of its 3
    for _ in $(seq 100); do grep -q 'renew database/creds/stuck' "$SD/requests.log" && grep -q 'renew database/creds/short' "$SD/requests.log" && break; sleep 0.1; done
    sleep 3        # review: long enough after the failed renewal that a retry (every 2 s) would show
    RUN=$(sed -n 's/^.*revocation: varek revoke \([0-9a-f]\{32\}\) .*$/\1/p' "$OUT/a4.log" | head -1)
    VK="$HERE/tools/varek"
    check "the Warden names how to revoke the run, and its control socket is root's alone" \
        sh -c "[ -n '$RUN' ] && [ \"\$(stat -c '%u %a' /run/varek/$RUN.ctl)\" = '0 600' ] && [ \"\$(stat -c '%u %a' /run/varek)\" = '0 700' ]"
    setpriv --reuid 65534 --regid 65534 --clear-groups python3 "$VK" revoke "$RUN" > "$OUT/rv0.out" 2>&1; echo $? > "$OUT/rv0.rc"
    check "refused: varek revoke by a user who is not root" sh -c "grep -q 'needs root' '$OUT/rv0.out' && ! grep -qx 0 '$OUT/rv0.rc'"
    check "refused: a connection to the control socket by a user who is not root (the kernel)" \
        setpriv --reuid 65534 --regid 65534 --clear-groups python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
try:
    s.connect('/run/varek/$RUN.ctl')
except PermissionError:
    sys.exit(0)
sys.exit(1)"
    python3 "$VK" revoke "$RUN" > "$OUT/rv1.out" 2>&1; echo $? > "$OUT/rv1.rc"
    check "varek revoke <run>: revoked" sh -c "grep -q '$RUN: revoked' '$OUT/rv1.out' && grep -qx 0 '$OUT/rv1.rc'"
    python3 "$VK" revoke --all > "$OUT/rv2.out" 2>&1
    check "varek revoke --all: that run is already revoked" grep -q "$RUN: already revoked" "$OUT/rv2.out"
    for _ in $(seq 50); do grep -q 'revocation_leases' "$OUT/a4.log" && grep -q 'revocation_proxy' "$OUT/a4.log" && break; sleep 0.1; done
    sleep 3        # review: long enough after the revocation that a renewal left live (every 2 s) would show
    echo go >&7
    wait $W4; echo $? > "$OUT/a4.rc"
    exec 7>&-
    sed 's/^/     /' "$OUT/a4.out"
    check "before: the request with its credential, and the file open, were allowed" \
        sh -c "grep -qx 'REQ before HTTP/1.1 200 OK' '$OUT/a4.out' && grep -qx 'OPEN before ok' '$OUT/a4.out'"
    check "after: the connection the proxy held is closed; the request on it never reaches the server" \
        sh -c "grep -Eqx 'REQ held (EOF|ERR .*)' '$OUT/a4.out' && [ \$(wc -l < '$OUT/got.jsonl') -eq \$(($n3 + 1)) ]"
    check "after: the file open is refused (EACCES)" grep -qx "OPEN after 13" "$OUT/a4.out"
    check "after: the connect is refused" grep -qx "CONNECT after PermissionError" "$OUT/a4.out"
    check "the run is not ended by the revocation: the agent finished" sh -c "grep -qx 0 '$OUT/a4.rc'"
    rec4() { python3 - "$OUT/a4.log" "$1" <<'PY'
import json, sys
recs = [json.loads(l[l.index("{"):]) for l in open(sys.argv[1], errors="replace") if l.lstrip().startswith("{") or ' {"' in l]
sys.exit(0 if eval(sys.argv[2], {"R": recs}) else 1)
PY
    }
    check "recorded: revoked, by uid 0" rec4 "any(r.get('event') == 'revoked' and r.get('by_uid') == 0 and r.get('by_pid', 0) > 0 for r in R)"
    check "recorded: the file open and the connect after it, refused with rule revoked" \
        rec4 "{r.get('action') for r in R if r.get('rule') == 'revoked' and r.get('decision_final') == 'DENY'} >= {'file.open', 'net.connect'}"
    check "recorded: the proxy holds no value after (revocation_proxy, values_held 0)" \
        rec4 "any(r.get('event') == 'revocation_proxy' and r.get('values_held') == 0 for r in R)"
    check "recorded: the proxy closed the held connection (revoked)" \
        rec4 "any(r.get('close_reason', r.get('why')) == 'revoked' for r in R)"
    check "recorded: both Vault leases revoked (revocation_leases, 2 and 0 failed)" \
        rec4 "any(r.get('event') == 'revocation_leases' and r.get('revoked') == 2 and r.get('failed') == 0 for r in R)"
    check "the stand-in got each lease's revoke, with the token" \
        sh -c "grep -q 'vault PUT revoke database/creds/short/Rn7 token=ok' '$SD/requests.log' && grep -q 'vault PUT revoke database/creds/stuck/Fx2 token=ok' '$SD/requests.log'"
    check "a leased secret renewed at two thirds of its lease (lease_renewed, ttl 3; the stand-in got increment=3)" \
        sh -c "grep -q 'vault PUT renew database/creds/short/Rn7 token=ok increment=3' '$SD/requests.log'" 
    check "recorded: lease_renewed for sh" rec4 "any(r.get('event') == 'lease_renewed' and r.get('credential') == 'sh' and r.get('ttl') == 3 for r in R)"
    check "recorded: a renewal Vault refuses (lease_renewal_failed, why), not retried" \
        sh -c "python3 - '$OUT/a4.log' <<'PY' && [ \$(grep -c 'renew database/creds/stuck' '$SD/requests.log') -eq 1 ]
import json, sys
recs = [json.loads(l[l.index('{'):]) for l in open(sys.argv[1], errors='replace') if ' {\"' in l or l.lstrip().startswith('{')]
sys.exit(0 if any(r.get('event') == 'lease_renewal_failed' and r.get('credential') == 'sk' and 'vault answered 400' in r.get('why', '') for r in recs) else 1)
PY"
    check "no renewal after the revocation" \
        sh -c "! sed -n '/vault PUT revoke/,\$p' '$SD/requests.log' | grep -q 'PUT renew'"
    check "no value is in the verdict stream" sh -c "! grep -Eq 'db-short|db-stuck|long-val' '$OUT/a4.log'"
    check "the control socket is gone with the run" sh -c "[ ! -e /run/varek/$RUN.ctl ]"
    python3 "$VK" revoke "$RUN" > "$OUT/rv3.out" 2>&1; echo $? > "$OUT/rv3.rc"
    check "refused: a revoke for a run that has ended" sh -c "grep -q 'no such run is running' '$OUT/rv3.out' && ! grep -qx 0 '$OUT/rv3.rc'"
    python3 "$VK" revoke 0123456789abcdef0123456789abcdef > "$OUT/rv4.out" 2>&1
    check "refused: a revoke for a run that never was" grep -q "no such run is running" "$OUT/rv4.out"
    # step 5: the audit
    python3 "$HERE/tools/varek_audit.py" --policy "$POL4" --checker "$CERT" "$OUT/a4.log" > "$OUT/aud4.out" 2>&1; echo $? > "$OUT/aud4.rc"
    check "the audit accepts the revoked run, says it was revoked, and notes the renewal Vault refused" \
        sh -c "grep -qx 0 '$OUT/aud4.rc' && grep -q 'the run was revoked' '$OUT/aud4.out' && grep -q 'note: the lease of credential sk could not be renewed' '$OUT/aud4.out'"
    EV='ev = lambda n: next(i for i, r in enumerate(recs) if isinstance(r, dict) and r.get("event") == n)'
    python3 "$F" "$OUT/a4.log" "$OUT/h1.log" "$EV; i = ev('revoked'); r = next(r for r in recs[i:] if isinstance(r, dict) and r.get('action') == 'file.open'); r['decision_final'] = 'ALLOW'"
    refuses "an allowed decision after revoked" "$POL4" "$OUT/h1.log" "after the run was revoked"
    python3 "$F" "$OUT/a4.log" "$OUT/h2.log" "$EV; i = ev('revoked'); r = recs.pop(i); j = next(k for k, x in enumerate(recs) if isinstance(x, dict) and x.get('credential')); recs.insert(j, r)"
    refuses "a credential carried after revoked" "$POL4" "$OUT/h2.log" "after the run was revoked"
    python3 "$F" "$OUT/a4.log" "$OUT/h3.log" "$EV; recs[ev('revoked')]['by_uid'] = 1000"
    refuses "a revocation by a peer that is not root" "$POL4" "$OUT/h3.log" "by a peer that is not root"
    python3 "$F" "$OUT/a4.log" "$OUT/h4.log" "$EV; recs[ev('revocation_proxy')]['values_held'] = 2"
    refuses "a proxy that still held values" "$POL4" "$OUT/h4.log" "the proxy still held 2"
    python3 "$F" "$OUT/a4.log" "$OUT/h5.log" "$EV; r = dict(recs[ev('lease_renewed')]); recs.insert(ev('revocation_leases') + 1, r)"
    refuses "a lease renewed after the leases were revoked" "$POL4" "$OUT/h5.log" "after the helper revoked the run's leases"
    python3 "$F" "$OUT/a4.log" "$OUT/h6.log" "$EV; del recs[ev('revoked')]"
    refuses "a revocation's answers without the revocation" "$POL4" "$OUT/h6.log" "without the run being revoked before it"
    python3 "$F" "$OUT/a4.log" "$OUT/h7.log" "$EV; r = dict(recs[ev('lease_renewal_failed')]); r['event'] = 'lease_renewed'; r['ttl'] = 3; recs.insert(ev('lease_renewal_failed') + 1, r)"
    refuses "a renewal retried after it failed" "$POL4" "$OUT/h7.log" "after its renewal failed"
fi

echo "== 5. records and tools =="
if [ -z "${SRV:-}" ] || [ -z "${S3:-}" ] || [ ! -s "$OUT/a4.log" ]; then
    skip "section 5 (needs sections 2 to 4)"
else
    printf 'require warden 1.28\nproxy inspect\ncredential c from file:%s/k\ncredential db from vault:database/creds/ro#password\nallow host api.example.com:443\nallow request GET https://api.example.com/x credential=c header=X-K\n' "$T" > "$T/cc.txt"
    : > "$SD/requests.log"
    "$WARDEN" "$T/cc.txt" --secrets-conf "$T/conf" --check-credentials > "$OUT/cc.out" 2>&1; echo $? > "$OUT/cc.rc"
    check "--check-credentials fetches each one (version and length, no value), revokes the lease it made, and passes" \
        sh -c "grep -qx 0 '$OUT/cc.rc' && grep -q 'credential db from vault:database/creds/ro#password: fetched, 16 bytes, version lease:' '$OUT/cc.out' && grep -q 'the 1 Vault lease(s) the check made are revoked' '$OUT/cc.out' && grep -q 'vault PUT revoke database/creds/ro/AbC123 token=ok' '$SD/requests.log' && ! grep -q 'db-password' '$OUT/cc.out'"
    "$WARDEN" "$T/cc.txt" --secrets-conf "$T/cv" --check-credentials > "$OUT/cc2.out" 2>&1; echo $? > "$OUT/cc2.rc"
    check "--check-credentials fails with the store's reason" \
        sh -c "! grep -qx 0 '$OUT/cc2.rc' && grep -q 'credential db (line 4): vault answered 403' '$OUT/cc2.out'"
    "$HERE/tools/varek_preflight.sh" "$T/cc.txt" --secrets-conf "$T/conf" > "$OUT/pf.out" 2>&1
    check "the preflight fetches each credential" \
        sh -c "grep -q 'PASS  credential c from file:$T/k: fetched' '$OUT/pf.out' && grep -q 'PASS  credential db from vault:database/creds/ro#password: fetched' '$OUT/pf.out'"
    "$HERE/tools/varek_preflight.sh" "$T/cc.txt" --secrets-conf "$T/cv" > "$OUT/pf2.out" 2>&1
    check "the preflight fails when a credential cannot be fetched" grep -q "FAIL  credentials: .*vault answered 403" "$OUT/pf2.out"
    NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" policy show "$POL4" > "$OUT/ps4.out" 2>&1
    check "varek policy show lists the credentials, and the rules that carry each" \
        sh -c "grep -q '^Credentials (3)' '$OUT/ps4.out' && grep -qx '  c1 from file:$X/v1' '$OUT/ps4.out' && grep -qx '    line 8: in Authorization after Bearer' '$OUT/ps4.out' && grep -qx '    no rule carries it (fetched, never sent)' '$OUT/ps4.out'"
    printf '[varek]\npolicy = %s\nlog_dir = %s\n' "$POL4" "$OUT" > "$OUT/varek4.conf"
    printf '[varek]\npolicy = %s\nlog_dir = %s\n' "$POL3" "$OUT" > "$OUT/varek3.conf"
    NO_COLOR=1 VAREK_CONFIG="$OUT/varek4.conf" python3 "$HERE/tools/varek" refusals -n 500 "$OUT/a4.log" > "$OUT/rf4.out" 2>&1
    check "varek refusals says the run was revoked, and marks each call refused after it REVOKED" \
        sh -c "grep -q '^The run was revoked at .* by uid 0' '$OUT/rf4.out' && grep -Eq '^  REVOKED +file.open +/usr/bin/true' '$OUT/rf4.out' && grep -Eq '^  REVOKED +net.connect' '$OUT/rf4.out'"
    NO_COLOR=1 VAREK_CONFIG="$OUT/varek3.conf" python3 "$HERE/tools/varek" refusals -n 500 "$OUT/a3.log" > "$OUT/rf3.out" 2>&1
    check "varek refusals explains each refused swap (credential, why)" \
        sh -c "grep -q '^5 request(s) allowed with a credential, refused by the proxy' '$OUT/rf3.out' && [ \$(grep -c '^  CREDENTIAL' '$OUT/rf3.out') -eq 5 ] && grep -q 'credential c1: the request has no header for its credential' '$OUT/rf3.out'"
    python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/a4.log" --policy "$POL4" --output "$OUT/a4.cdx.json" > /dev/null 2>&1
    cdx() { python3 - "$OUT/a4.cdx.json" "$1" <<'PY'
import json, sys
b = json.load(open(sys.argv[1]))
P = {p["name"]: p["value"] for c in b.get("components", []) + [b["metadata"].get("component", {})]
     for p in c.get("properties", [])}
sys.exit(0 if eval(sys.argv[2], {"P": P, "b": b}) else 1)
PY
    }
    check "the export carries varek:credentials.* and the revocation" \
        cdx "P['varek:credentials.count'] == '3' and P['varek:credentials.names'] == 'c1,sh,sk' and P['varek:credentials.requests'] == '1' and P['varek:credentials.sh'].startswith('vault:database/creds/short#password version lease:') and P['varek:run.revoked'] == 'true' and P['varek:revocation.proxy.values_held'] == '0' and P['varek:revocation.leases.revoked'] == '2' and P['varek:credentials.leases.renewal_failed'] == '1'"
    check "no value is in the export" sh -c "! grep -Eq 'db-short|db-stuck|long-val' '$OUT/a4.cdx.json'"
fi

echo "== 6. the review's fixes =="
# (each check fails on the build the review read, ee198c6)
printf 'require warden 1.28\nproxy inspect\ncredential k from file:/etc/varek/k\nallow request GET https://api.example.com/x credential=k header=te|trailer\n' > "$OUT/pipe.txt"
check "a header name holding '|' beside a framing name is read alike by the decision procedure and the checker" \
    sh -c "'$VDP' '$OUT/pipe.txt' credentials > '$OUT/pipe.vdp' 2>&1 && '$CERT' '$OUT/pipe.txt' credentials > '$OUT/pipe.cert' 2>&1 && cmp -s '$OUT/pipe.vdp' '$OUT/pipe.cert'"
if [ -z "${SRV:-}" ] || [ -z "${S3:-}" ] || [ ! -s "$OUT/a4.log" ]; then
    skip "the rest of section 6 (needs sections 2 to 4)"
else
    # a file warden-secrets reads, with a second name the agent could open
    mkdir -p "$T/priv" "$T/shared" "$T/vpriv" "$T/view"; chmod 700 "$T/priv" "$T/vpriv"; chmod 755 "$T/shared" "$T/view"
    printf 'second-name-value\n' > "$T/priv/k"; chmod 600 "$T/priv/k"; ln -f "$T/priv/k" "$T/shared/notes"
    printf 'require warden 1.28\nproxy inspect\ncredential c from file:%s/priv/k\nallow path %s/shared/ readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow host api.example.com:443\nallow request GET https://api.example.com/x credential=c header=X-K\n' "$T" "$T" > "$T/hl.txt"; chmod 644 "$T/hl.txt"
    (cd "$T" && timeout 60 "$WARDEN" "$T/hl.txt" --run-as nobody -- /usr/bin/cat "$T/shared/notes" > "$OUT/hl.out" 2> "$OUT/hl.err"); echo $? > "$OUT/hl.rc"
    check "refused: a file store with a hard link where the agent may read (and the agent reads nothing)" \
        sh -c "! grep -qx 0 '$OUT/hl.rc' && grep -q 'has 2 names (hard links)' '$OUT/hl.err' && ! grep -q second-name-value '$OUT/hl.out'"
    rm -f "$T/shared/notes"
    printf 's.test-token-v1280\n' > "$T/vpriv/token"; chmod 600 "$T/vpriv/token"
    printf 'vault_addr = https://127.0.0.1:%s\nvault_token_file = %s/vpriv/token\nvault_ca = %s/ca.pem\n' "$HP" "$T" "$T" > "$T/bconf"; chmod 600 "$T/bconf"
    printf 'require warden 1.28\nproxy inspect\ncredential c from vault:secret/data/agents/gh#token\nallow path %s/view/ readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow host api.example.com:443\nallow request GET https://api.example.com/x credential=c header=X-K\n' "$T" > "$T/bm.txt"; chmod 644 "$T/bm.txt"
    if mount --bind "$T/vpriv" "$T/view" 2>/dev/null; then
        (cd "$T" && timeout 60 "$WARDEN" "$T/bm.txt" --secrets-conf "$T/bconf" -- /usr/bin/cat "$T/view/token" > "$OUT/bm.out" 2> "$OUT/bm.err"); echo $? > "$OUT/bm.rc"
        umount "$T/view"
        check "refused: a Vault token file bind-mounted where the agent may read" \
            sh -c "! grep -qx 0 '$OUT/bm.rc' && grep -q 'is also mounted at $T/view/token' '$OUT/bm.err' && ! grep -q s.test-token '$OUT/bm.out'"
    else
        skip "a bind-mounted token file (no mount here)"
    fi
    mkdir -p "$T/gw"; chmod 775 "$T/gw"; chgrp 65534 "$T/gw" 2>/dev/null
    printf 'v\n' > "$T/gw/k"; chmod 600 "$T/gw/k"
    run gw "credential c from file:$T/gw/k\n"
    refuse "a file store in a directory another user may write" gw "the directory $T/gw must be root's and writable by no other user"
    put awsbad2 'aws_access_key_id = AKIDV1280TEST\naws_secret_access_key = v1280-test-secret-key/abc\naws_session_token FwoGSECRETSESSION==\n'
    put caws2 "${CONF}aws_credentials_file = $T/awsbad2\n"
    run kq "credential c from aws-sm:$ARN:stripe-AbCdEf\n" --secrets-conf "$T/caws2"
    refuse "a key file line without its ' = ', and its text is not quoted" kq "its text is not shown"
    check "no secret from that line is in the Warden's output" sh -c "! grep -q FwoGSECRET '$OUT/kq.out'"
    (cd "$T" && timeout 60 "$WARDEN" "$T/all.txt" --secrets-conf conf --check-credentials > "$OUT/rel.out" 2>&1); echo $? > "$OUT/rel.rc"
    check "a relative --secrets-conf is read from the working directory" sh -c "grep -qx 0 '$OUT/rel.rc' && grep -q 'each one fetched' '$OUT/rel.out'"
    # the helper as it runs: its own user, no capabilities, no new privileges, not dumpable
    printf 'require warden 1.28\nproxy inspect\ncredential c from file:%s/k\nallow host api.example.com:443\nallow request GET https://api.example.com/x credential=c header=X-K\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' "$T" > "$T/hz.txt"; chmod 644 "$T/hz.txt"
    (cd "$T" && timeout 60 "$WARDEN" "$T/hz.txt" -- /usr/bin/sleep 4 > "$OUT/hz.out" 2>&1) &
    HZ=$!
    hp=""; for _ in $(seq 40); do hp=$(pgrep -fx 'warden-secrets [0-9]+:[0-9]+' | head -1); [ -n "$hp" ] && break; sleep 0.1; done
    sleep 1
    check "warden-secrets runs as its own user, with no capability and no new privileges, and is not dumpable" \
        sh -c "[ -n '$hp' ] && grep -Eq '^Uid:\s+65531\s+65531\s+65531\s+65531' /proc/$hp/status && grep -q '^NoNewPrivs:\s*1' /proc/$hp/status && grep -q '^CapEff:\s*0000000000000000' /proc/$hp/status && grep -q '^CapPrm:\s*0000000000000000' /proc/$hp/status && [ \"\$(stat -c %u /proc/$hp/environ)\" = 0 ]"
    wait $HZ
    # a Vault that resets the connection: the helper reports it and lives
    RV="$OUT/rv"; mkdir -p "$RV"; chmod 755 "$RV"
    python3 "$HERE/tests/v1280_rstvault.py" "$RV" > /dev/null 2>&1 &
    RVP=$!
    for _ in $(seq 50); do [ -s "$RV/port" ] && break; sleep 0.1; done
    cp "$RV/ca.pem" "$T/rca.pem"; chmod 644 "$T/rca.pem"
    put crst "vault_addr = https://127.0.0.1:$(cat "$RV/port")\nvault_token_file = $T/vt\nvault_ca = $T/rca.pem\n"
    printf 'require warden 1.28\nproxy inspect\ncredential c from vault:database/creds/x#password\nallow host api.example.com:443\nallow request GET https://api.example.com/x credential=c header=X-K\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' > "$T/rs.txt"; chmod 644 "$T/rs.txt"
    (cd "$T" && timeout 60 "$WARDEN" "$T/rs.txt" --secrets-conf "$T/crst" -- /usr/bin/sleep 5 > "$OUT/rs.out" 2>&1)
    kill $RVP 2>/dev/null
    check "a Vault that resets the connection: the renewal is recorded as failed, and warden-secrets does not die" \
        sh -c "grep -q '\"event\":\"lease_renewal_failed\"' '$OUT/rs.out' && ! grep -q 'warden-secrets has gone' '$OUT/rs.out'"
    # leases are revoked when a run ends, and when a start is refused after a lease was made
    : > "$SD/requests.log"
    run le "credential c from vault:database/creds/ro#password\n" --secrets-conf "$T/conf"
    for _ in $(seq 50); do grep -q 'PUT revoke database/creds/ro/AbC123' "$SD/requests.log" && break; sleep 0.1; done
    check "the run's lease is revoked when the run ends" grep -q 'vault PUT revoke database/creds/ro/AbC123 token=ok' "$SD/requests.log"
    : > "$SD/requests.log"
    run lf "credential c from vault:database/creds/ro#password\ncredential d from vault:secret/data/agents/gh#nope\n" --secrets-conf "$T/conf"
    for _ in $(seq 50); do grep -q 'PUT revoke' "$SD/requests.log" && break; sleep 0.1; done
    check "a lease made for a start that is then refused is revoked" \
        sh -c "! grep -qx 0 '$OUT/lf.rc' && grep -q 'vault PUT revoke database/creds/ro/AbC123 token=ok' '$SD/requests.log'"
    # the stub resolver after a revocation: refused, nothing looked up
    printf '{"before.example.com": {"ttl": 30, "a": ["192.0.2.1"]}, "after-udp.example.com": {"ttl": 30, "a": ["192.0.2.2"]}, "after-tcp.example.com": {"ttl": 30, "a": ["192.0.2.3"]}}\n' > "$OUT/zone6.json"
    DP6=$((20000 + RANDOM % 20000))
    python3 "$HERE/tests/dns_test_server.py" --port "$DP6" --zone "$OUT/zone6.json" --log "$OUT/q6.log" --ready "$OUT/ready6" > /dev/null 2>&1 &
    DNS6=$!
    for _ in $(seq 50); do [ -e "$OUT/ready6" ] && break; sleep 0.1; done
    cat > "$X/stub6.py" <<'PY'
import socket, struct, sys
def q(name):
    return struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.connect(("127.53.53.53", 53))
t = socket.socket(socket.AF_INET, socket.SOCK_STREAM); t.connect(("127.53.53.53", 53))
u.send(q("before.example.com")); r = u.recv(512); print("BEFORE", r[3] & 15, flush=True)
print("READY", flush=True); sys.stdin.readline()
u.send(q("after-udp.example.com")); u.settimeout(5); r = u.recv(512); print("UDP", r[3] & 15, flush=True)
m = q("after-tcp.example.com"); t.sendall(struct.pack(">H", len(m)) + m); t.settimeout(5)
n = struct.unpack(">H", t.recv(2))[0]; r = t.recv(n); print("TCP", r[3] & 15, flush=True)
PY
    chmod 644 "$X/stub6.py"
    printf 'require warden 1.28\nallow host *.example.com:443 acknowledge=dns-channel\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path exact %s/stub6.py readonly\n' "$X" > "$OUT/stub6.policy"
    rm -f "$X/go6"; mkfifo "$X/go6"; exec 8<> "$X/go6"
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$OUT/stub6.policy" --dns-server "127.0.0.1:$DP6" -- /usr/bin/python3 "$X/stub6.py" < "$X/go6" > "$OUT/s6.out" 2> "$OUT/s6.log" &
    W6=$!
    for _ in $(seq 300); do grep -q READY "$OUT/s6.out" 2>/dev/null && break; sleep 0.1; done
    R6=$(sed -n 's/^.*revocation: varek revoke \([0-9a-f]\{32\}\) .*$/\1/p' "$OUT/s6.log" | head -1)
    python3 "$VK" revoke "$R6" > /dev/null 2>&1
    echo go >&8; wait $W6; exec 8>&-; kill $DNS6 2>/dev/null
    check "after a revocation the stub refuses questions on sockets connected before it, and looks nothing up" \
        sh -c "grep -qx 'UDP 5' '$OUT/s6.out' && grep -qx 'TCP 5' '$OUT/s6.out' && ! grep -q after- '$OUT/q6.log'"
    check "and records them refused as revoked; the audit accepts the run" \
        sh -c "[ \$(grep -c '\"rule\":\"revoked\",\"policy_line\":-1' '$OUT/s6.log') -ge 2 ] && python3 '$HERE/tools/varek_audit.py' --policy '$OUT/stub6.policy' --checker '$CERT' '$OUT/s6.log' > /dev/null"
    python3 "$F" "$OUT/s6.log" "$OUT/k1.log" "q = [r for r in recs if isinstance(r, dict) and r.get('rule') == 'revoked' and r.get('event') == 'dns_question'][0]; q.update(rule='policy_match', answer='lookup')"
    refuses "a stub question answered after the revocation" "$OUT/stub6.policy" "$OUT/k1.log" "answered after the revocation"
    # forged orders the audit refuses
    python3 "$F" "$OUT/a4.log" "$OUT/k2.log" "recs[:] = [r for r in recs if not (isinstance(r, dict) and r.get('event') in ('revoked', 'revocation_proxy', 'revocation_leases'))]"
    refuses "refusals marked revoked with the revocation's records deleted" "$POL4" "$OUT/k2.log" "no revocation is recorded before it"
    python3 "$F" "$OUT/a4.log" "$OUT/k3.log" "mv = [r for r in recs if isinstance(r, dict) and r.get('event') in ('revoked', 'revocation_proxy', 'revocation_leases')]; recs[:] = [r for r in recs if not any(r is m for m in mv)]; i = next(i for i, r in enumerate(recs) if isinstance(r, dict) and r.get('event') == 'run_end'); recs[i:i] = mv"
    refuses "the revocation's records moved after the refusals they explain" "$POL4" "$OUT/k3.log" "no revocation is recorded before it"
    python3 "$F" "$OUT/a4.log" "$OUT/k4.log" "rp = next(r for r in recs if isinstance(r, dict) and r.get('event') == 'revocation_proxy'); recs.remove(rp); i = next(i for i, r in enumerate(recs) if isinstance(r, dict) and r.get('event') == 'revoked'); recs.insert(i, rp)"
    refuses "the proxy's answer just before the revocation" "$POL4" "$OUT/k4.log" "revocation_proxy without the run being revoked before it"
    python3 "$F" "$OUT/a3.log" "$OUT/k5.log" "cf = next(r for r in recs if isinstance(r, dict) and r.get('event') == 'credential_refused'); recs.remove(cf); i = next(i for i, r in enumerate(recs) if isinstance(r, dict) and r.get('action') == 'net.request' and r.get('proxy_conn') == cf['proxy_conn'] and r.get('request_seq') == cf['request_seq']); recs.insert(i, cf)"
    refuses "a refused swap just before the request it refused" "$POL3" "$OUT/k5.log" "follows no allowed request"
    python3 "$F" "$OUT/a3.log" "$OUT/k6.log" "r = next(r for r in recs if isinstance(r, dict) and r.get('decision_final') == 'DENY' and r.get('action') == 'file.open'); r['rule'] = 'revoked'"
    refuses "a refusal marked revoked in a run never revoked" "$POL3" "$OUT/k6.log" "no revocation is recorded before it"
    # the tools on hostile and foreign lines
    python3 "$F" "$OUT/a4.log" "$OUT/k7.log" "r = next(r for r in recs if isinstance(r, dict) and r.get('event') == 'revoked'); r['timestamp_ns'] = 10**30"
    python3 "$F" "$OUT/a3.log" "$OUT/k8.log" "r = next(r for r in recs if isinstance(r, dict) and r.get('event') == 'credential_refused'); r['proxy_conn'] = [1]"
    NO_COLOR=1 VAREK_CONFIG="$OUT/varek4.conf" python3 "$HERE/tools/varek" refusals "$OUT/k7.log" > "$OUT/k7.out" 2>&1
    NO_COLOR=1 VAREK_CONFIG="$OUT/varek3.conf" python3 "$HERE/tools/varek" refusals "$OUT/k8.log" > "$OUT/k8.out" 2>&1
    python3 "$HERE/tools/varek_audit.py" --policy "$POL3" --checker "$CERT" "$OUT/k8.log" > "$OUT/k8a.out" 2>&1
    check "varek refusals and the audit give no traceback on malformed revocation and swap records" \
        sh -c "! grep -q Traceback '$OUT/k7.out' '$OUT/k8.out' '$OUT/k8a.out' && grep -q 'PROBLEM' '$OUT/k8a.out'"
    cp "$OUT/a3.log" "$OUT/k9.log"
    printf '{"event":"revoked","run":"00000000000000000000000000000000","by_uid":0,"by_pid":1,"timestamp_ns":1}\n' >> "$OUT/k9.log"
    NO_COLOR=1 VAREK_CONFIG="$OUT/varek3.conf" python3 "$HERE/tools/varek" refusals "$OUT/k9.log" > "$OUT/k9.out" 2>&1
    check "varek refusals ignores a revocation of another run" sh -c "! grep -q 'was revoked' '$OUT/k9.out'"
    python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/h1.log" --policy "$POL4" --output "$OUT/h1.cdx.json" > /dev/null 2>&1
    check "the export counts a decision allowed after the revocation, and does not say every one was refused" \
        sh -c "grep -q '\"varek:revocation.allowed_after\"' '$OUT/h1.cdx.json' && ! grep -q 'every decision after it was UNSATISFIED' '$OUT/h1.cdx.json'"
    # a control socket left by a Warden that was killed: varek revoke --all removes it
    STALE=/run/varek/ffffffffffffffffffffffffffffffff.ctl
    python3 -c "import socket; s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); s.bind('$STALE')"
    python3 "$VK" revoke --all > "$OUT/stale.out" 2>&1
    check "varek revoke --all removes a control socket no Warden listens on" \
        sh -c "[ ! -e '$STALE' ] && grep -q 'removed the control socket' '$OUT/stale.out'"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1280: PASS ($skips skipped)"; exit 0; fi
echo "test_v1280: FAIL"; exit 1
