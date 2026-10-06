#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1240.sh — v1.24.0, host names without agent DNS
# (docs/security/v1.21-stage2-host-names.md, sections 1 to 4).
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
#   4. as root, sections 3 and 4: real clients as the agent (Python, curl and
#      Node through glibc, a static musl client, Go's own resolver, Java) resolve an allowed name through
#      the Warden's views and connect, decided on the name; other names fail at
#      once; no connect reaches port 53; the first rule over the address and
#      its names decides; an address in grace; a deny on /etc/hosts; the plan
#      gate on a name; the audit, and a forged stream it must refuse. Clients
#      that are not installed are skipped.
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
cleanup() { [ -n "$SERVER" ] && kill $SERVER 2>/dev/null; wait 2>/dev/null; rm -rf "$OUT"; }
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

echo "== 4. the agent resolves through the views; connects are decided on names =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "real clients as the agent (needs root and the warden binary)"
else
    W=/tmp/varek_v1240w
    rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
    cp "$T/v1240_client.py" "$T/v1240_client.js" "$W/"
    chmod 644 "$W"/*
    HP=$((20000 + RANDOM % 20000))
    python3 -m http.server "$HP" --bind 127.0.0.1 > /dev/null 2>&1 &
    SERVER="$SERVER $!"
    printf '%s\n' '{"api.example.com": {"ttl": 3, "a": ["127.0.0.1"]},' \
                  ' "blocked.example.com": {"ttl": 30, "a": ["127.0.0.1"]}}' > "$OUT/zone.json"
    # where the clients live (each prefix is allowed read-only)
    NODE=$(readlink -f "$(command -v node 2>/dev/null)" 2>/dev/null)
    # the distribution's OpenJDK when it is there (CI installs it), else java on PATH
    JAVA=$(ls /usr/lib/jvm/java-21-openjdk-*/bin/java 2>/dev/null | head -1)
    [ -n "$JAVA" ] || JAVA=$(readlink -f "$(command -v java 2>/dev/null)" 2>/dev/null)
    PREFIXES="/usr/ /lib /etc/ssl/ /proc/ /sys/ $W/"
    [ -n "$NODE" ] && PREFIXES="$PREFIXES $(dirname "$(dirname "$NODE")")/"
    [ -n "$JAVA" ] && PREFIXES="$PREFIXES $(dirname "$(dirname "$JAVA")")/ /etc/java-21-openjdk/ /etc/java-17-openjdk/"
    POL="$OUT/clients.policy"
    { printf 'require warden 1.24\n'
      printf 'deny  host api.example.com:%s\n' $((HP + 1))      # a name deny before a numeric allow
      printf 'allow host 127.0.0.1:%s\n' $((HP + 1))
      printf 'deny  host 127.0.0.1:%s\n' $((HP + 2))            # a numeric deny before a name allow
      printf 'allow host api.example.com\n'
      printf 'deny  host blocked.example.com\n'
      printf 'allow host 127.0.0.1:53\n'                         # refused anyway: port 53
      printf 'allow host unix:%s/s.sock\n' "$W"
      for d in $PREFIXES; do
          printf 'allow path %s readonly\n' "$d"; done
      printf 'allow path /etc/ld.so.cache readonly\nallow path /tmp/hsperfdata_nobody/\n'
    } > "$POL"
    for _ in $(seq 50); do
        python3 -c "import socket; socket.create_connection(('127.0.0.1', $HP), 0.2)" 2>/dev/null && break
        sleep 0.1
    done
    agent() { env -i PATH=/usr/bin:/bin timeout 90 "$WARDEN" "$POL" --dns-server "127.0.0.1:$PORT" "$@" 2> "$OUT/a.log"; }

    python3 -c 'import os, socket, sys, time
s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); os.chmod(sys.argv[1], 0o666); s.listen(5); time.sleep(60)' \
        "$W/s.sock" &
    SERVER="$SERVER $!"
    for _ in $(seq 50); do [ -S "$W/s.sock" ] && break; sleep 0.1; done
    agent -- /usr/bin/python3 "$W/v1240_client.py" "$HP" "127.0.0.1:$((HP + 1))" \
        "api.example.com:$((HP + 2))" "127.0.0.2:$HP" "unix:$W/s.sock" > "$OUT/py.out"
    sed 's/^/     /' "$OUT/py.out"
    check "python: an allowed name resolves through the hosts view" grep -q '^OK resolve 127.0.0.1 ' "$OUT/py.out"
    check "python: and connects"                                    grep -q '^OK http 200 ' "$OUT/py.out"
    check "the connect was decided on the name" \
        grep -q "\"resolved\":\"api.example.com:$HP\",\"decision_raw\":\"ALLOW\"" "$OUT/a.log"
    check "its record names the address dialed and every candidate" \
        grep -qF "\"dialed\":\"127.0.0.1:$HP\",\"candidates\":[\"127.0.0.1:$HP\",\"api.example.com:$HP\"]" "$OUT/a.log"
    if awk '$1 == "ERR" && $2 == "unlisted" && $4 < 100 {ok = 1} END {exit !ok}' "$OUT/py.out"; then
        pass "a name the policy does not allow fails to resolve within 100 ms"
    else flunk "a name the policy does not allow fails to resolve within 100 ms"; fi
    check "a name only a deny rule names does not resolve"     grep -q '^ERR denied-name ' "$OUT/py.out"
    check "a deny on a name wins over a later numeric allow of its address" \
        grep -q "^ERR connect 127.0.0.1:$((HP + 1)) " "$OUT/py.out"
    check "an earlier numeric deny wins over a name allow" \
        grep -q "^ERR connect api.example.com:$((HP + 2)) " "$OUT/py.out"
    check "an address no allowed name resolved to is decided as a number" \
        grep -q "\"resolved\":\"127.0.0.2:$HP\",\"decision_raw\":\"UNKNOWN\",\"decision_final\":\"DENY\"" "$OUT/a.log"
    check "the views were served"                          grep -q '"rule":"hosts_view"' "$OUT/a.log"
    check "a Unix socket connect still works (no candidates)" grep -q "^OK connect unix:$W/s.sock connected" "$OUT/py.out"
    check "python: the audit accepts the run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/a.log"
    # A forged stream: a connect with one of its address's names left out,
    # the chain recomputed (an editor without the signing key can do that).
    python3 "$T/v1240_forge.py" "$OUT/a.log" "$OUT/forged.log" "$HP"
    if python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/forged.log" \
            > "$OUT/forged.out" 2>&1; then
        flunk "the audit refuses a connect that left out a name of its address"
    else
        check "the audit refuses a connect that left out a name of its address" \
            grep -q 'is not a candidate' "$OUT/forged.out"
    fi

    if [ -n "$NODE" ]; then
        agent -- "$NODE" "$W/v1240_client.js" "$HP" > "$OUT/node.out"
        sed 's/^/     /' "$OUT/node.out"
        check "node: dns.lookup resolves an allowed name"  grep -q '^OK resolve 127.0.0.1 ' "$OUT/node.out"
        check "node: and http connects"                    grep -q '^OK http 200 ' "$OUT/node.out"
        check "node: dns.lookup of another name fails"     grep -q '^ERR unlisted ' "$OUT/node.out"
        check "node: dns.resolve4 (a DNS query) fails"     grep -q '^ERR resolve4 ' "$OUT/node.out"
    else skip "node (not installed)"; fi

    GO=$(command -v go || ls /usr/local/go/bin/go 2>/dev/null)
    if [ -n "$GO" ] && (cd "$T" && CGO_ENABLED=0 GOCACHE="$OUT/gocache" "$GO" build -o "$W/v1240_client_go" \
            v1240_client.go) > /dev/null 2>&1; then
        chmod 755 "$W/v1240_client_go"
        agent -- "$W/v1240_client_go" "$HP" > "$OUT/go.out"
        sed 's/^/     /' "$OUT/go.out"
        check "go (its own resolver): an allowed name resolves" grep -q '^OK resolve 127.0.0.1 ' "$OUT/go.out"
        check "go: and http connects"                            grep -q '^OK http 200 ' "$OUT/go.out"
        check "go: another name fails"                           grep -q '^ERR unlisted ' "$OUT/go.out"
    else skip "go (not installed)"; fi

    # compiled by the javac of the JDK that runs it (a runner may have several)
    JAVAC="$(dirname "$JAVA" 2>/dev/null)/javac"
    if [ -n "$JAVA" ] && [ -x "$JAVAC" ] && "$JAVAC" --release 11 -d "$W" "$T/V1240Client.java" > /dev/null 2>&1; then
        chmod -R a+rX "$W"
        agent -- "$JAVA" -Xshare:off -cp "$W" V1240Client "$HP" > "$OUT/java.out"
        sed 's/^/     /' "$OUT/java.out"
        if ! grep -q '^OK resolve' "$OUT/java.out"; then
            # say why: the JVM's own errors and what the Warden refused it
            echo "     java did not resolve; its stderr and the refusals:"
            grep '^\[agent\]' "$OUT/a.log" | head -10 | sed 's/^/       /'
            grep '"decision_final":"DENY"' "$OUT/a.log" | sed -E 's/.*"action":"([^"]*)","target":"([^"]*)".*"rule":"([a-z_0-9]+)".*/       \1 \2 \3/' | sort | uniq -c | head -25
        fi
        check "java: an allowed name resolves"   grep -q '^OK resolve 127.0.0.1 ' "$OUT/java.out"
        check "java: and http connects"          grep -q '^OK http 200 ' "$OUT/java.out"
        check "java: another name fails"         grep -q '^ERR unlisted ' "$OUT/java.out"
    else skip "java (no JDK)"; fi
    if command -v musl-gcc > /dev/null && musl-gcc -static -O2 -o "$W/v1240_client_musl" "$T/v1240_client_musl.c" 2>/dev/null; then
        chmod 755 "$W/v1240_client_musl"
        agent -- "$W/v1240_client_musl" "$HP" > "$OUT/musl.out"
        sed 's/^/     /' "$OUT/musl.out"
        check "musl (static, its own resolver): an allowed name resolves" grep -q '^OK resolve 127.0.0.1 ' "$OUT/musl.out"
        check "musl: and connects"                                         grep -q '^OK http 200 ' "$OUT/musl.out"
        if awk '$1 == "ERR" && $2 == "unlisted" && $4 < 100 {ok = 1} END {exit !ok}' "$OUT/musl.out"; then
            pass "musl: another name fails within 100 ms"
        else flunk "musl: another name fails within 100 ms"; fi
    else skip "musl (no musl-gcc; apt install musl-tools)"; fi
    if command -v curl > /dev/null; then
        agent -- /usr/bin/curl -s -o /dev/null -w 'OK http %{http_code}\n' --max-time 5 "http://api.example.com:$HP/" > "$OUT/curl.out"
        agent -- /usr/bin/curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 "http://other.example.com:$HP/" > "$OUT/curl2.out"
        echo "curl unlisted exit $?" >> "$OUT/curl2.out"
        sed 's/^/     /' "$OUT/curl.out" "$OUT/curl2.out"
        check "curl: fetches from an allowed name"   grep -q '^OK http 200' "$OUT/curl.out"
        check "curl: another name does not resolve"  grep -q '^curl unlisted exit 6$' "$OUT/curl2.out"
    else skip "curl (not installed)"; fi

    # Port 53: refused whatever the numeric rules say; a resolver listening
    # there gets nothing.
    python3 "$T/v1240_listen53.py" "$OUT/53.count" 8 &
    L53=$!
    sleep 0.5
    agent -- /usr/bin/python3 "$W/v1240_client.py" "$HP" "127.0.0.1:53" > /dev/null
    wait "$L53"
    check "a connect to port 53 is refused (dns_refused), even with allow host 127.0.0.1:53" \
        grep -q '"resolved":"127.0.0.1:53",.*"rule":"dns_refused"' "$OUT/a.log"
    case "$(cat "$OUT/53.count" 2>/dev/null)" in
        0) pass "a resolver listening on 127.0.0.1:53 got no connection" ;;
        busy) skip "a resolver listening on 127.0.0.1:53 (the port is taken)" ;;
        *) flunk "a resolver listening on 127.0.0.1:53 got no connection" ;;
    esac

    # Grace: api.example.com moves to 127.0.0.2 one second in (TTL 3, so the
    # Warden sees it at about 3 s); 127.0.0.1 then stays valid for 3 s more.
    ( sleep 1
      printf '%s\n' '{"api.example.com": {"ttl": 3, "a": ["127.0.0.2"]}}' > "$OUT/zone.tmp"
      mv "$OUT/zone.tmp" "$OUT/zone.json" ) &
    agent --dns-ttl-min 1 --dns-grace-max 10 -- /usr/bin/python3 "$W/v1240_client.py" timed \
        "0@127.0.0.1:$HP" "4.5@127.0.0.1:$HP" "9@127.0.0.1:$HP" > "$OUT/grace.out"
    wait $! 2>/dev/null
    sed 's/^/     /' "$OUT/grace.out"
    check "an address in the current answer is reached (decided on the name)" \
        grep -q "^OK at 0 127.0.0.1:$HP 200" "$OUT/grace.out"
    check "an address that left the answer is reached during its grace" \
        grep -q "^OK at 4.5 127.0.0.1:$HP 200" "$OUT/grace.out"
    check "and refused after it"            grep -q "^ERR at 9 127.0.0.1:$HP " "$OUT/grace.out"
    check "the audit accepts the grace run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/a.log"
    printf '%s\n' '{"api.example.com": {"ttl": 30, "a": ["127.0.0.1"]}}' > "$OUT/zone.json"

    # Every address of a name reaches the agent, IPv4 first. Found by the
    # 24-hour soak: the table appends a new address after those it keeps, so
    # once CloudFront rotated its IPv4 addresses an IPv6 one came first in the
    # hosts view; glibc, which the policy did not let read /etc/host.conf
    # ("multi on"), returned that line only, and the host had no IPv6 route.
    # Here the A record appears after the AAAA one.
    printf '%s\n' '{"api.example.com": {"ttl": 1, "aaaa": ["2001:db8::10"]}}' > "$OUT/zone.json"
    ( sleep 1
      printf '%s\n' '{"api.example.com": {"ttl": 1, "a": ["127.0.0.1"], "aaaa": ["2001:db8::10"]}}' > "$OUT/zone.tmp"
      mv "$OUT/zone.tmp" "$OUT/zone.json" ) &
    agent --dns-ttl-min 1 -- /usr/bin/python3 "$W/v1240_client.py" late 3.5 "$HP" > "$OUT/late.out"
    wait $! 2>/dev/null
    sed 's/^/     /' "$OUT/late.out"
    check "a name's addresses of both families all resolve (the host.conf view)" \
        grep -q '^OK resolve 127.0.0.1,2001:db8::10 ' "$OUT/late.out"
    check "and the agent connects although the IPv6 address was added first" \
        grep -q '^OK http 200 ' "$OUT/late.out"
    check "the host.conf view was served"      grep -q '"rule":"hostconf_view"' "$OUT/a.log"
    printf '%s\n' '{"api.example.com": {"ttl": 30, "a": ["127.0.0.1"]}}' > "$OUT/zone.json"

    # A deny covering /etc/hosts wins: the agent resolves nothing.
    { printf 'require warden 1.24\ndeny path /etc/hosts\n'; tail -n +2 "$POL"; } > "$OUT/nohosts.policy"
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$OUT/nohosts.policy" --dns-server "127.0.0.1:$PORT" \
        -- /usr/bin/python3 "$W/v1240_client.py" "$HP" > "$OUT/nohosts.out" 2> "$OUT/nh.log"
    check "a deny on /etc/hosts wins over the view: nothing resolves" grep -q '^ERR resolve ' "$OUT/nohosts.out"
    check "and the open is refused by that rule" \
        grep -q '"target":"/etc/hosts".*"decision_final":"DENY","rule":"policy_match","policy_line":2' "$OUT/nh.log"

    # The plan gate decides a net_connect step on the name.
    printf 'action a net_connect api.example.com:443\n' > "$OUT/plan_ok.txt"
    printf 'action a net_connect other.example.com:443\n' > "$OUT/plan_no.txt"
    "$WARDEN" "$POL" --dns-server "127.0.0.1:$PORT" --plan "$OUT/plan_ok.txt" -- /bin/true > /dev/null 2> "$OUT/g1.err"
    if grep -q 'plan authorized' "$OUT/g1.err" && ! grep -q 'plan rejected' "$OUT/g1.err"; then
        pass "the plan gate: a step to an allowed name passes"
    else flunk "the plan gate: a step to an allowed name passes"; fi
    "$WARDEN" "$POL" --dns-server "127.0.0.1:$PORT" --plan "$OUT/plan_no.txt" -- /bin/true > /dev/null 2> "$OUT/g2.err"
    check "the plan gate: a step to another name is rejected" grep -q 'plan rejected' "$OUT/g2.err"
    rm -rf "$W"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1240: PASS ($skips skipped)"; else echo "test_v1240: FAIL"; fi
exit "$fail"
