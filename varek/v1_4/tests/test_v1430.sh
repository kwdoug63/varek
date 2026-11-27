#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# test_v1430.sh: VAREK v1.43, Palantir Ontology MCP (docs/security/v1.43-palantir-ontology-mcp.md).
# The parts built so far:
#   1. the grammar: `mcp gateway URL` after `require warden 1.43`, read the
#      same way by the decision procedure (vdp_check), the certificate
#      checker (vdp_cert_check) and the cross-check's oracle, each form and
#      each refusal; an mcp rule on a gateway's URL allowed under `proxy on`.
#   2. gateway mode under a real Warden, without inspecting mode: an agent
#      speaking plain HTTP to the gateway host's port 80, each call decided
#      against the https URL and sent over TLS the proxy verified (against a
#      test CA in --trust-bundle); the credential released into the calls
#      its rules allow and nowhere else; a read allowed, an action held
#      (STEP UP, mode=hold) and refused when nobody answered, a denied tool
#      and an unlisted tool refused with JSON-RPC errors, another path and a
#      Host naming another port refused; TLS and plain HTTP straight to the
#      server's port refused (gateway_host), so nothing reaches the server
#      but the calls the policy allows; the records; and the audit.
#   test_v1430.sh VDP_CHECK VDP_CERT_CHECK [WARDEN]
set -u
VDP="$1"; CERT="$2"; WARDEN="${3:-}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d /tmp/varek_v1430.XXXXXX)"
fail=0; skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
trap '[ -n "${KEEP:-}" ] && echo "kept $OUT" || rm -rf "$OUT"' EXIT

echo "== 1. the grammar: mcp gateway, read the same by all three =="
oracle() { python3 -c "
import sys; sys.path.insert(0, '$HERE/tools')
import smt_crosscheck as sc
try:
    sc.parse_policy(sys.argv[1]); sys.exit(0)
except sc.PolicyError:
    sys.exit(1)" "$1"; }
HAVE_Z3=1; python3 -c 'import z3' 2>/dev/null || HAVE_Z3=0
G='mcp gateway https://omcp.example.com/mcp/app1'
R='allow host omcp.example.com:443\nallow mcp https://omcp.example.com/mcp/app1 tools/list'
ok_pol() {   # DESC TEXT: all three accept it
    printf "$2" > "$OUT/p.txt"
    local a=0 b=0 c=0
    "$VDP" "$OUT/p.txt" lint > /dev/null 2>&1 && a=1
    "$CERT" "$OUT/p.txt" proxy > /dev/null 2>&1 && b=1
    if [ "$HAVE_Z3" = 1 ]; then oracle "$OUT/p.txt" && c=1; else c=1; fi
    if [ "$a$b$c" = 111 ]; then pass "accepted: $1"; else flunk "accepted: $1 (vdp $a, checker $b, oracle $c)"; fi
}
bad_pol() {  # DESC TEXT: all three refuse it
    printf "$2" > "$OUT/p.txt"
    local a=0 b=0 c=0
    "$VDP" "$OUT/p.txt" lint > /dev/null 2>&1 || a=1
    "$CERT" "$OUT/p.txt" proxy > /dev/null 2>&1 || b=1
    if [ "$HAVE_Z3" = 1 ]; then oracle "$OUT/p.txt" || c=1; else c=1; fi
    if [ "$a$b$c" = 111 ]; then pass "refused: $1"; else flunk "refused: $1 (vdp $a, checker $b, oracle $c)"; fi
}
[ "$HAVE_Z3" = 1 ] || skip "the oracle's reading (z3 not installed: pip install -r tools/requirements-crosscheck.txt)"
ok_pol  "a gateway under proxy on, with its mcp rule" "require warden 1.43\nproxy on\n$G\n$R\n"
ok_pol  "a gateway under proxy inspect" "require warden 1.43\nproxy inspect\n$G\n$R\n"
ok_pol  "two gateways on one host and port" "require warden 1.43\nproxy on\n$G\nmcp gateway https://omcp.example.com/mcp/app2\n$R\n"
ok_pol  "a gateway on another port, proxied" "require warden 1.43\nproxy on\nproxy ports 80 8443\nmcp gateway https://omcp.example.com:8443/mcp\nallow host omcp.example.com:8443\nallow mcp https://omcp.example.com:8443/mcp tools/list\n"
ok_pol  "a credential on a gateway's mcp rule under proxy on" "require warden 1.43\nproxy on\ncredential tok from file:/etc/varek/tok\n$G\nallow host omcp.example.com:443\nallow mcp https://omcp.example.com/mcp/app1 tools/list credential=tok\n"
bad_pol "before require warden 1.43" "require warden 1.42\nproxy on\n$G\n$R\n"
bad_pol "an http URL" "require warden 1.43\nproxy on\nmcp gateway http://omcp.example.com/mcp/app1\n$R\n"
bad_pol "an address" "require warden 1.43\nproxy on\nmcp gateway https://10.0.0.7/mcp\n"
bad_pol "without the proxy" "require warden 1.43\n$G\n"
bad_pol "port 80 not proxied" "require warden 1.43\nproxy on\nproxy ports 443\n$G\n$R\n"
bad_pol "the server's port not proxied" "require warden 1.43\nproxy on\nproxy ports 80\n$G\n$R\n"
bad_pol "a passthrough host" "require warden 1.43\nproxy inspect\nproxy passthrough host omcp.example.com\n$G\n"
bad_pol "the same URL twice" "require warden 1.43\nproxy on\n$G\n$G\n$R\n"
bad_pol "one host on two ports" "require warden 1.43\nproxy on\nproxy ports 80 443 8443\n$G\nmcp gateway https://omcp.example.com:8443/x\n$R\n"
bad_pol "no URL" "require warden 1.43\nproxy on\nmcp gateway\n"
bad_pol "a query in the URL" "require warden 1.43\nproxy on\nmcp gateway https://omcp.example.com/mcp?x=1\n"
bad_pol "an mcp rule under proxy on for another URL" "require warden 1.43\nproxy on\n$G\nallow mcp https://other.example.com/mcp tools/list\n"
printf "require warden 1.43\nproxy on\n$G\n$R\nstep_up mcp https://omcp.example.com/mcp/app1 tools/call create-* mode=hold timeout=60\n" > "$OUT/p.txt"
q=$(printf 'mcp - %s\nmcp - %s\nmcp - %s\n' \
    "$(printf '%s' 'https://omcp.example.com:443/mcp/app1#tools/list#' | od -An -tx1 | tr -d ' \n')" \
    "$(printf '%s' 'https://omcp.example.com:443/mcp/app1#tools/call#create-x' | od -An -tx1 | tr -d ' \n')" \
    "$(printf '%s' 'https://omcp.example.com:443/mcp/app1#tools/call#delete-x' | od -An -tx1 | tr -d ' \n')" | "$VDP" "$OUT/p.txt" batch)
check "a gateway's calls decided as its https URL's: allowed, held, refused" \
    sh -c "printf '%s\n' '$q' | sed -n 1p | grep -q SATISFIED && printf '%s\n' '$q' | sed -n 2p | grep -q '\"verb\":\"step_up\"' && printf '%s\n' '$q' | sed -n 3p | grep -q UNKNOWN"

echo "== 2. gateway mode under the Warden, without inspecting mode =="
WP="$(dirname "${WARDEN:-.}")/warden-proxy"
WS="$(dirname "${WARDEN:-.}")/warden-secrets"
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ ! -x "$WP" ] || [ ! -x "$WS" ] || ! command -v openssl > /dev/null; then
    skip "section 2 (needs root, the warden, warden-proxy, warden-secrets and openssl)"
else
    X="$(mktemp -d /tmp/varek_v1430g.XXXXXX)"; chmod 755 "$X"
    trap 'kill $SRV 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT $X" || rm -rf "$OUT" "$X"' EXIT
    HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
    PS=$((43000 + RANDOM % 5000))
    ( cd "$X" &&
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tca.key -out tca.pem -days 2 \
          -subj "/CN=VAREK v1.43 test root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" &&
      openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout s.key -out s.csr -subj "/CN=omcp.example.com" &&
      printf 'subjectAltName=DNS:omcp.example.com\nextendedKeyUsage=serverAuth\n' > s.ext &&
      openssl x509 -req -in s.csr -CA tca.pem -CAkey tca.key -CAcreateserial -out s.pem -days 1 -extfile s.ext &&
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout other.key -out other.pem -days 1 \
          -subj "/CN=omcp.example.com" -addext "subjectAltName=DNS:omcp.example.com" ) > "$OUT/certs.log" 2>&1
    cat "$(python3 -c 'import ssl; print(ssl.get_default_verify_paths().openssl_cafile)')" "$X/tca.pem" > "$X/bundle.pem"
    chmod 644 "$X"/*.pem
    TOKV="omcp-token-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    printf '%s\n' "$TOKV" > "$X/tok"; chmod 600 "$X/tok"
    python3 "$HERE/tests/v1430_omcp_server.py" --host "$HOSTIP" --port "$PS" --token "$TOKV" --sse --log "$OUT/got.jsonl" \
        --tls "$X/s.pem" "$X/s.key" > "$OUT/srv.log" 2>&1 &
    SRV=$!
    DP=$((20000 + RANDOM % 20000))
    printf '{"omcp.example.com": {"ttl": 30, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/zone.json"
    python3 "$HERE/tests/dns_test_server.py" --port "$DP" --zone "$OUT/zone.json" --log "$OUT/q.log" --ready "$OUT/ready" > /dev/null 2>&1 &
    SRV="$SRV $!"
    for _ in $(seq 50); do
        [ -e "$OUT/ready" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $PS), 0.2)" 2>/dev/null && break
        sleep 0.1
    done
    cp "$HERE/tests/v1430_gw_agent.py" "$X/agent.py"; chmod 644 "$X/agent.py"
    U="https://omcp.example.com:$PS/mcp/app1"
    POL="$OUT/gw.policy"
    mkpol() {   # the policy, with the server's URL
        printf 'require warden 1.43\nproxy on\nproxy ports 80 %s\ncredential tok from file:%s/tok\n' "$PS" "$X"
        printf 'mcp gateway %s\n' "$U"
        printf 'allow host omcp.example.com:%s\n' "$PS"
        printf 'allow mcp %s initialize credential=tok\n' "$U"
        printf 'allow mcp %s notifications/initialized credential=tok\n' "$U"
        printf 'allow mcp %s tools/list credential=tok\n' "$U"
        printf 'allow mcp %s tools/call search-osdk-todo-task credential=tok\n' "$U"
        printf 'allow mcp %s tools/call get-overdue-osdk-todo-tasks credential=tok\n' "$U"
        printf 'deny mcp %s tools/call delete-osdk-todo-task\n' "$U"
        printf 'step_up mcp %s tools/call create-osdk-todo-task mode=hold timeout=2\n' "$U"
        printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path exact %s/agent.py readonly\n' "$X"
    }
    mkpol > "$POL"
    env -i PATH=/usr/bin:/bin timeout 180 "$WARDEN" "$POL" --dns-server "127.0.0.1:$DP" --trust-bundle "$X/bundle.pem" -- \
        /usr/bin/python3 "$X/agent.py" "$PS" > "$OUT/g.out" 2> "$OUT/g.log"
    cut -c1-160 "$OUT/g.out" | sed 's/^/     /'
    said() { grep -q "^CALL $1 $2" "$OUT/g.out"; }
    got() { python3 - "$OUT/got.jsonl" "$1" "${2:-1}" <<'PY'
import json, sys
n = 0
for l in open(sys.argv[1]):
    r = json.loads(l)
    n += bool(eval(sys.argv[2], {"r": r, "m": r.get("method"), "nm": r.get("name"), "h": r.get("headers", {})}))
sys.exit(0 if n == int(sys.argv[3]) else 1)
PY
    }
    rec() { python3 - "$OUT/g.log" "$1" <<'PY'
import json, sys
recs = [json.loads(l[l.index("{"):]) for l in open(sys.argv[1], errors="replace") if l.startswith("{")]
M = [r for r in recs if r.get("action") == "net.mcp"]
sys.exit(0 if eval(sys.argv[2], {"json": json, "R": recs, "M": M}) else 1)
PY
    }
    check "the agent holds only the credential's placeholder" grep -q "^ENV True" "$OUT/g.out"
    check "the Warden loaded the trust bundle for the gateway" grep -q "mcp gateway: servers verified against" "$OUT/g.log"
    for t in init list search query search2; do
        check "allowed ($t): the server answered it over the gateway" said "$t" "HTTP/1.1 200 OK"
    done
    check "a notification is allowed (the server's 202)" said notify "HTTP/1.1 202 Accepted"
    check "an action held for an approver (STEP UP, mode=hold) waited, then was refused: nobody answered" \
        sh -c "grep '^CALL create ' '$OUT/g.out' | grep -q 'HTTP/1.1 403 Forbidden' && grep '^CALL create ' '$OUT/g.out' | grep -Eq '\| [2-9]\.[0-9]s$'"
    for t in delete unlisted otherpath hostport; do
        check "refused ($t): 403" said "$t" "HTTP/1.1 403 Forbidden"
    done
    check "a refused call gets a JSON-RPC error with its id, code -32000" \
        sh -c "grep '^CALL delete ' '$OUT/g.out' | grep -q '\"id\":6,\"error\":{\"code\":-32000'"
    check "TLS straight to the server's port is refused (gateway_host)" said direct_tls "ERR"
    check "plain HTTP straight to the server's port is refused (gateway_host)" \
        sh -c "grep '^CALL direct_plain ' '$OUT/g.out' | grep -Eq 'ERR|403 Forbidden'"
    check "the server got the allowed calls, each with the real token (released by the proxy)" \
        got "m in ('initialize', 'tools/list') or nm in ('search-osdk-todo-task', 'get-overdue-osdk-todo-tasks') or m == 'notifications/initialized'" 6
    check "the server got no refused call, and no request without the token" \
        got "nm in ('create-osdk-todo-task', 'delete-osdk-todo-task', 'archive-osdk-todo-task') or r.get('status') == 401 or r.get('path')" 0
    check "the server never saw the placeholder" sh -c "! grep -q 'varek_ph_tok_' '$OUT/got.jsonl'"
    check "the token is in no record" sh -c "! grep -q '$TOKV' '$OUT/g.log' '$OUT/g.out'"
    check "run_start records the gateway and the bundle that verifies it" \
        rec "any(r.get('event') == 'run_start' and r.get('proxy', {}).get('gateways') == ['$U'.replace('example.com:', 'example.com:')] and 'gateway_trust' in r.get('proxy', {}) for r in R) or any(r.get('event') == 'run_start' and '$U' in json.dumps(r) and 'gateway_trust' in json.dumps(r) for r in R)"
    check "each gateway connection is recorded as one (gateway, inspected)" \
        rec "any(r.get('gateway') is True and r.get('inspected') is True for r in R)"
    check "the direct connections are recorded as refused: gateway_host" \
        rec "sum(1 for r in R if r.get('rule_id') == 'gateway_host' or r.get('rule') == 'gateway_host') >= 2"
    check "each call is a net.mcp record against the https URL" \
        rec "len(M) >= 9 and all(r.get('url', r.get('target', '')).startswith('https://omcp.example.com:$PS/mcp/app1') or 'https://omcp.example.com:$PS/mcp/app1' in json.dumps(r) for r in M)"
    check "the audit verifies the run (each call within the policy, the chain intact)" \
        sh -c "python3 '$HERE/tools/varek_audit.py' --policy '$POL' --checker '$CERT' '$OUT/g.log' > '$OUT/audit.out' 2>&1"

    # a server whose certificate the bundle does not vouch for: 502, nothing sent
    kill $SRV 2>/dev/null; sleep 0.3
    python3 "$HERE/tests/v1430_omcp_server.py" --host "$HOSTIP" --port "$PS" --token "$TOKV" --log "$OUT/got2.jsonl" \
        --tls "$X/other.pem" "$X/other.key" > "$OUT/srv2.log" 2>&1 &
    SRV=$!
    python3 "$HERE/tests/dns_test_server.py" --port "$DP" --zone "$OUT/zone.json" --log "$OUT/q2.log" --ready "$OUT/ready2" > /dev/null 2>&1 &
    SRV="$SRV $!"
    for _ in $(seq 50); do [ -e "$OUT/ready2" ] && break; sleep 0.1; done
    sleep 0.3
    env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$POL" --dns-server "127.0.0.1:$DP" --trust-bundle "$X/bundle.pem" -- \
        /usr/bin/python3 "$X/agent.py" "$PS" > "$OUT/g2.out" 2> "$OUT/g2.log"
    check "a server the bundle does not vouch for: the agent gets 502, in HTTP" \
        sh -c "grep '^CALL init ' '$OUT/g2.out' | grep -q 'HTTP/1.1 502 Bad Gateway'"
    check "... and the server got nothing" sh -c "[ ! -s '$OUT/got2.jsonl' ]"
fi

if [ "$fail" = 0 ]; then echo; echo "test_v1430: PASS${skips:+ ($skips skipped)}"; exit 0; fi
echo; echo "test_v1430: FAIL"; exit 1
