#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1240.sh — v1.24.0, host names without agent DNS: the parts built so far
# (docs/security/v1.21-stage2-host-names.md, sections 1 and 2).
#
#   1. policy grammar: host names after `require warden 1.24`, refused forms,
#      the same answer from the decision procedure and the certificate checker
#      on every case, a name without a port matching every port, the
#      cross-check oracle on the names policy
#   2. the resolution table (warden_resolve.c) against a local test DNS
#      server: startup lookups, CNAME chains, the TTL clamp, NXDOMAIN and
#      failures, rotation and the grace period, the resolver helper
#   3. as root: the Warden resolves the policy's names before the agent runs,
#      refreshes them while it runs, and writes each result as a chained
#      record the exporter and the audit accept; --check-startup reports each
#      name. Skipped when not root.
#
# Usage: test_v1240.sh <vdp_check> <vdp_cert_check> <test_v1240_resolve> [<warden>]
set -u

VDP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
CERT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
RESOLVE="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
WARDEN="${4:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$HERE/tests"
OUT="$(mktemp -d)"
chmod 755 "$OUT"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }

SERVER=""
cleanup() { [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null; wait 2>/dev/null; rm -rf "$OUT"; }
trap cleanup EXIT

echo "== 1. policy grammar =="
# accepted <description> <policy text>: both parsers load it.
accepted() {
    printf '%b' "$2" > "$OUT/p.txt"
    if "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1 && "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then
        pass "accepted: $1"
    else
        flunk "accepted: $1 ($("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null | head -1))"
    fi
}
# refused <description> <policy text> <message part>: both parsers refuse it,
# and the decision procedure says why.
refused() {
    printf '%b' "$2" > "$OUT/p.txt"
    local e
    e="$("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null)"
    if "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1; then flunk "refused: $1 (the procedure loaded it)"
    elif "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then flunk "refused: $1 (the checker loaded it)"
    elif ! printf '%s' "$e" | grep -qF "$3"; then flunk "refused: $1 (message: $e)"
    else pass "refused: $1"; fi
}
R='require warden 1.24\n'
accepted "a name"                          "${R}allow host api.example.com\n"
accepted "a name with a port"              "${R}allow host api.example.com:443\n"
accepted "a single-label name"             "${R}allow host localhost\n"
accepted "an A-label name"                 "${R}allow host xn--bcher-kva.example:8443\n"
accepted "a 63-byte label"                 "${R}allow host $(printf 'a%.0s' $(seq 63)).example\n"
accepted "port 0 and 65535"                "${R}allow host a.example:0\nallow host a.example:65535\n"
accepted "a deny on a name"                "${R}deny host api.example.com:80\nallow host api.example.com\n"
accepted "numeric rules keep working"      "${R}allow host 10.0.0.1:443\nallow host [::1]\nallow host unix:/run/a.sock\n"
accepted "a name before 1.24 (v1.21 meaning)" "allow host api.example.com\n"
accepted "1.24 after only numeric rules"   "allow host 10.0.0.1\nrequire warden 1.24\nallow host api.example.com\n"
refused "uppercase"                        "${R}allow host Api.example.com\n"   "lowercase"
refused "a trailing dot"                   "${R}allow host api.example.com.\n"  "trailing dot"
refused "an empty label"                   "${R}allow host api..example.com\n"  "empty label"
refused "a 64-byte label"                  "${R}allow host $(printf 'a%.0s' $(seq 64)).example\n" "63 bytes"
refused "a name over 253 bytes"            "${R}allow host $(printf 'abcdefghi.%.0s' $(seq 26))com\n" "253 bytes"
refused "a U-label"                        "${R}allow host b\xc3\xbccher.example\n" "A-labels"
refused "a wildcard"                       "${R}allow host *.salesforce.com\n" "v1.25"
refused "a label starting with '-'"        "${R}allow host -api.example.com\n"  "start or end"
refused "a label ending with '-'"          "${R}allow host api-.example.com\n"  "start or end"
refused "an underscore"                    "${R}allow host api_x.example.com\n" "a-z, 0-9"
refused "an all-digit last label"          "${R}allow host api.123\n"           "all digits"
refused "the name unix"                    "${R}allow host unix\n"              "reserved"
refused "port 65536"                       "${R}allow host api.example.com:65536\n" "port"
refused "a port with a leading zero"       "${R}allow host api.example.com:0443\n"  "port"
refused "an empty port"                    "${R}allow host api.example.com:\n"  "port"
refused "two ports"                        "${R}allow host api.example.com:1:2\n" "port"
refused "require 1.24 after a host name"   "allow host api.example.com\nrequire warden 1.24\n" "before the host rules"
refused "require 1.25"                     "require warden 1.25\n"              "this is 1.24"

# Decisions: a name without a port matches every port; with a port, only it.
batch() { printf '%s\n' "$@" | "$VDP" "$T/v1240_names_policy.txt" batch; }
hx() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
batch "host 0 $(hx api.example.com:443)" "host 0 $(hx api.example.com:80)" \
      "host 0 $(hx login.example.com:443)" "host 0 $(hx login.example.com:80)" \
      "host 0 $(hx other.example.com:443)" "host 0 $(hx api.example.com)" > "$OUT/batch.out"
want='SATISFIED UNSATISFIED SATISFIED UNKNOWN UNKNOWN SATISFIED'
got="$(sed -E 's/.*"verdict":"([A-Z]+)".*/\1/' "$OUT/batch.out" | tr '\n' ' ' | sed 's/ $//')"
if [ "$got" = "$want" ]; then pass "name decisions: $got"; else flunk "name decisions: $got (want $want)"; fi
check "the names policy lints clean"       "$VDP" "$T/v1240_names_policy.txt" lint
printf 'allow host api.example.com:443\n' > "$OUT/legacy.txt"
"$VDP" "$OUT/legacy.txt" lint > "$OUT/legacy.out" 2>&1
check "a name without the directive draws a note" grep -q 'matched only after `require warden 1.24`' "$OUT/legacy.out"
if python3 -c 'import z3' 2>/dev/null; then
    if python3 "$HERE/tools/smt_crosscheck.py" --vdp "$VDP" --cert "$CERT" --queries 200 \
            "$T/v1240_names_policy.txt" > "$OUT/cc.out" 2>&1; then
        pass "cross-check oracle agrees on the names policy"
    else
        flunk "cross-check oracle agrees on the names policy"; tail -5 "$OUT/cc.out"
    fi
else
    skip "cross-check oracle (pip install -r tools/requirements-crosscheck.txt)"
fi

echo "== 2. the resolution table =="
PORT=$((20000 + RANDOM % 20000))
echo '{}' > "$OUT/zone.json"
python3 "$T/dns_test_server.py" --port "$PORT" --zone "$OUT/zone.json" --log "$OUT/q.log" \
    --ready "$OUT/ready" > "$OUT/dns.out" 2>&1 &
SERVER=$!
for _ in $(seq 50); do [ -e "$OUT/ready" ] && break; sleep 0.1; done
if [ ! -e "$OUT/ready" ]; then flunk "the test DNS server started"; cat "$OUT/dns.out"
else
    if "$RESOLVE" "$PORT" "$OUT/zone.json" "$OUT/q.log" > "$OUT/resolve.out" 2>&1; then
        pass "$(tail -1 "$OUT/resolve.out")"
    else
        flunk "resolution table unit test"; sed 's/^/     /' "$OUT/resolve.out"
    fi
fi

echo "== 3. the Warden resolves the policy's names =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "the Warden runs (needs root and the warden binary)"
else
    D=/tmp/varek_v1240
    rm -rf "$D"; mkdir -p "$D"; chmod 755 "$D"
    POL="$OUT/run.policy"
    { cat "$T/v1240_names_policy.txt"
      printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n'
    } > "$POL"
    : > "$OUT/q.log"
    cat > "$OUT/zone.json" <<'EOF'
{"api.example.com": {"ttl": 1, "a": ["192.0.2.10"], "aaaa": ["2001:db8::10"]},
 "login.example.com": {"ttl": 1, "a": ["192.0.2.11"]},
 "localhost": {"ttl": 60, "a": ["127.0.0.1"]}}
EOF
    "$WARDEN" "$POL" --dns-server "127.0.0.1:$PORT" --check-startup > "$OUT/check.out" 2>&1
    check "--check-startup passes"                    grep -q 'startup checks passed' "$OUT/check.out"
    check "--check-startup reports a resolved name"   grep -q 'host name api.example.com resolves to 2 addresses' "$OUT/check.out"
    check "--check-startup reports an unresolved name" grep -q 'host name xn--bcher-kva.example did not resolve' "$OUT/check.out"
    if grep -q '^{' "$OUT/check.out"; then flunk "--check-startup writes no records"; else pass "--check-startup writes no records"; fi
    # rotate api.example.com's answer while the agent runs
    ( sleep 2.5
      printf '{"api.example.com": {"ttl": 1, "a": ["192.0.2.12"]}, "login.example.com": {"ttl": 1, "a": ["192.0.2.11"]}, "localhost": {"ttl": 60, "a": ["127.0.0.1"]}}' > "$OUT/zone.tmp"
      mv "$OUT/zone.tmp" "$OUT/zone.json" ) &
    timeout 60 "$WARDEN" "$POL" --dns-server "127.0.0.1:$PORT" --dns-ttl-min 1 --dns-grace-max 2 \
        -- /bin/sleep 5 > /dev/null 2> "$OUT/v.log"
    wait $! 2>/dev/null
    R1="$(grep -m1 '"event":"resolution"' "$OUT/v.log")"
    S1="$(grep -m1 '"event":"run_start"' "$OUT/v.log")"
    check "run_start counts the names"        grep -q '"host_names":4,"resolver":"127.0.0.1:'"$PORT"'"' <<<"$S1"
    check "the first record is a resolution"  grep -q '"name":"api.example.com","a":"ok","aaaa":"ok","addresses":\["192.0.2.10","2001:db8::10"\]' <<<"$R1"
    # every startup resolution precedes the agent's first action
    first_res=$(grep -n '"event":"resolution"' "$OUT/v.log" | head -4 | tail -1 | cut -d: -f1)
    first_dec=$(grep -n '"decision_final"' "$OUT/v.log" | head -1 | cut -d: -f1)
    if [ -n "$first_res" ] && [ -n "$first_dec" ] && [ "$first_res" -lt "$first_dec" ]; then
        pass "every name is resolved before the agent's first action"
    else flunk "every name is resolved before the agent's first action"; fi
    n=$(grep -c '"event":"resolution","run":[^,]*,"name":"api.example.com"' "$OUT/v.log")
    if [ "$n" -ge 3 ]; then pass "refreshed while the agent ran ($n lookups of api.example.com)"
    else flunk "refreshed while the agent ran ($n lookups of api.example.com)"; fi
    check "a rotated-out address goes into grace" grep -q '"addresses":\["192.0.2.12"\],"grace":\[{"address":"192.0.2.10"' "$OUT/v.log"
    check "and leaves it"                         grep -q '"name":"api.example.com","a":"ok","aaaa":"nodata","addresses":\["192.0.2.12"\],"grace":\[\]' "$OUT/v.log"
    check "a name that does not resolve is recorded" grep -q '"name":"xn--bcher-kva.example","a":"nxdomain","aaaa":"nxdomain"' "$OUT/v.log"
    if grep -v -E 'example\.com$|example$|localhost$' "$OUT/q.log" | grep -q .; then
        flunk "only the policy's names were looked up"; else pass "only the policy's names were looked up"; fi
    if ps -eo args | grep -q '^[^ ]*warden --resolver-helper'; then flunk "no resolver helper is left after the run"
    else pass "no resolver helper is left after the run"; fi
    check "the exporter accepts the stream"   python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/v.log" --policy "$POL" --output "$OUT/bom.json"
    check "the audit accepts the stream"      python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/v.log"
    rm -rf "$D"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1240: PASS ($skips skipped)"; else echo "test_v1240: FAIL"; fi
exit "$fail"
