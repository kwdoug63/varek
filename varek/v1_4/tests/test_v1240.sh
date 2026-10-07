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
    # v1.24 review: a name never leads to a loopback, link-local, unspecified
    # or multicast address (only a numeric rule reaches one), so the names
    # here resolve to this machine's own address (private or public).
    HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
    python3 -m http.server "$HP" --bind 0.0.0.0 > /dev/null 2>&1 &
    SERVER="$SERVER $!"
    printf '{"api.example.com": {"ttl": 3, "a": ["%s"]}, "blocked.example.com": {"ttl": 30, "a": ["198.51.100.9"]}}\n' \
        "$HOSTIP" > "$OUT/zone.json"
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
      printf 'allow host %s:%s\n' "$HOSTIP" $((HP + 1))
      printf 'deny  host %s:%s\n' "$HOSTIP" $((HP + 2))        # a numeric deny before a name allow
      printf 'allow host api.example.com\n'
      printf 'deny  host blocked.example.com\n'
      printf 'allow host 127.0.0.1:53\n'                         # refused anyway: port 53
      printf 'allow host unix:%s/s.sock\n' "$W"
      for d in $PREFIXES; do
          printf 'allow path %s readonly\n' "$d"; done
      printf 'allow path /etc/ld.so.cache readonly\nallow path /tmp/hsperfdata_nobody/\n'
    } > "$POL"
    for _ in $(seq 50); do
        python3 -c "import socket; socket.create_connection(('$HOSTIP', $HP), 0.2)" 2>/dev/null && break
        sleep 0.1
    done
    agent() { env -i PATH=/usr/bin:/bin timeout 90 "$WARDEN" "$POL" --dns-server "127.0.0.1:$PORT" "$@" 2> "$OUT/a.log"; }

    python3 -c 'import os, socket, sys, time
s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); os.chmod(sys.argv[1], 0o666); s.listen(5); time.sleep(60)' \
        "$W/s.sock" &
    SERVER="$SERVER $!"
    for _ in $(seq 50); do [ -S "$W/s.sock" ] && break; sleep 0.1; done
    agent -- /usr/bin/python3 "$W/v1240_client.py" "$HP" "$HOSTIP:$((HP + 1))" \
        "api.example.com:$((HP + 2))" "127.0.0.2:$HP" "unix:$W/s.sock" > "$OUT/py.out"
    sed 's/^/     /' "$OUT/py.out"
    check "python: an allowed name resolves through the hosts view" grep -q "^OK resolve $HOSTIP " "$OUT/py.out"
    check "python: and connects"                                    grep -q '^OK http 200 ' "$OUT/py.out"
    check "the connect was decided on the name" \
        grep -q "\"resolved\":\"api.example.com:$HP\",\"decision_raw\":\"ALLOW\"" "$OUT/a.log"
    check "its record names the address dialed and every candidate" \
        grep -qF "\"dialed\":\"$HOSTIP:$HP\",\"candidates\":[\"$HOSTIP:$HP\",\"api.example.com:$HP\"]" "$OUT/a.log"
    if awk '$1 == "ERR" && $2 == "unlisted" && $4 < 100 {ok = 1} END {exit !ok}' "$OUT/py.out"; then
        pass "a name the policy does not allow fails to resolve within 100 ms"
    else flunk "a name the policy does not allow fails to resolve within 100 ms"; fi
    check "a name only a deny rule names does not resolve"     grep -q '^ERR denied-name ' "$OUT/py.out"
    check "a deny on a name wins over a later numeric allow of its address" \
        grep -q "^ERR connect $HOSTIP:$((HP + 1)) " "$OUT/py.out"
    check "an earlier numeric deny wins over a name allow" \
        grep -q "^ERR connect api.example.com:$((HP + 2)) " "$OUT/py.out"
    check "an address no allowed name resolved to is decided as a number" \
        grep -q "\"resolved\":\"127.0.0.2:$HP\",\"decision_raw\":\"UNKNOWN\",\"decision_final\":\"DENY\"" "$OUT/a.log"
    check "the views were served"                          grep -q '"rule":"hosts_view"' "$OUT/a.log"
    check "a Unix socket connect still works (no candidates)" grep -q "^OK connect unix:$W/s.sock connected" "$OUT/py.out"
    check "python: the audit accepts the run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/a.log"
    # v1.25 review (also in v1.24.0): the views are answered with no rule
    # (UNKNOWN -> ALLOW), and the exporter refused every such stream as
    # breaking symmetric suppression. They are now reported apart.
    check "python: the exporter accepts the run, views reported apart" \
        sh -c "python3 '$HERE/tools/varek_cyclonedx.py' --log '$OUT/a.log' --policy '$POL' --output '$OUT/views.bom.json' && grep -q 'answered with the Warden.s views' '$OUT/views.bom.json' && ! grep -q '\"name\": \"/etc/hosts\"' '$OUT/views.bom.json'"
    cp "$OUT/a.log" "$OUT/py.log"
    # A forged stream: a connect with one of its address's names left out,
    # the chain recomputed (an editor without the signing key can do that).
    python3 "$T/v1240_forge.py" "$OUT/a.log" "$OUT/forged.log" "$HP" "$HOSTIP"
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
        check "node: dns.lookup resolves an allowed name"  grep -q "^OK resolve $HOSTIP " "$OUT/node.out"
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
        check "go (its own resolver): an allowed name resolves" grep -q "^OK resolve $HOSTIP " "$OUT/go.out"
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
        check "java: an allowed name resolves"   grep -q "^OK resolve $HOSTIP " "$OUT/java.out"
        check "java: and http connects"          grep -q '^OK http 200 ' "$OUT/java.out"
        check "java: another name fails"         grep -q '^ERR unlisted ' "$OUT/java.out"
    else skip "java (no JDK)"; fi
    if command -v musl-gcc > /dev/null && musl-gcc -static -O2 -o "$W/v1240_client_musl" "$T/v1240_client_musl.c" 2>/dev/null; then
        chmod 755 "$W/v1240_client_musl"
        agent -- "$W/v1240_client_musl" "$HP" > "$OUT/musl.out"
        sed 's/^/     /' "$OUT/musl.out"
        check "musl (static, its own resolver): an allowed name resolves" grep -q "^OK resolve $HOSTIP " "$OUT/musl.out"
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

    # Grace: api.example.com moves to 198.51.100.7 one second in (TTL 3, so
    # the Warden sees it at about 3 s); its old address then stays valid for
    # 3 s more.
    ( sleep 1
      printf '%s\n' '{"api.example.com": {"ttl": 3, "a": ["198.51.100.7"]}}' > "$OUT/zone.tmp"
      mv "$OUT/zone.tmp" "$OUT/zone.json" ) &
    agent --dns-ttl-min 1 --dns-grace-max 10 -- /usr/bin/python3 "$W/v1240_client.py" timed \
        "0@$HOSTIP:$HP" "4.5@$HOSTIP:$HP" "9@$HOSTIP:$HP" > "$OUT/grace.out"
    wait $! 2>/dev/null
    sed 's/^/     /' "$OUT/grace.out"
    check "an address in the current answer is reached (decided on the name)" \
        grep -q "^OK at 0 $HOSTIP:$HP 200" "$OUT/grace.out"
    check "an address that left the answer is reached during its grace" \
        grep -q "^OK at 4.5 $HOSTIP:$HP 200" "$OUT/grace.out"
    check "and refused after it"            grep -q "^ERR at 9 $HOSTIP:$HP " "$OUT/grace.out"
    check "the audit accepts the grace run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/a.log"
    cp "$OUT/a.log" "$OUT/grace.log"
    printf '{"api.example.com": {"ttl": 30, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/zone.json"

    # Every address of a name reaches the agent, IPv4 first. Found by the
    # 24-hour soak: the table appends a new address after those it keeps, so
    # once CloudFront rotated its IPv4 addresses an IPv6 one came first in the
    # hosts view; glibc, which the policy did not let read /etc/host.conf
    # ("multi on"), returned that line only, and the host had no IPv6 route.
    # Here the A record appears after the AAAA one.
    printf '%s\n' '{"api.example.com": {"ttl": 1, "aaaa": ["2001:db8::10"]}}' > "$OUT/zone.json"
    ( sleep 1
      printf '{"api.example.com": {"ttl": 1, "a": ["%s"], "aaaa": ["2001:db8::10"]}}\n' "$HOSTIP" > "$OUT/zone.tmp"
      mv "$OUT/zone.tmp" "$OUT/zone.json" ) &
    agent --dns-ttl-min 1 -- /usr/bin/python3 "$W/v1240_client.py" late 3.5 "$HP" > "$OUT/late.out"
    wait $! 2>/dev/null
    sed 's/^/     /' "$OUT/late.out"
    check "a name's addresses of both families all resolve (the host.conf view)" \
        grep -q "^OK resolve $HOSTIP,2001:db8::10 " "$OUT/late.out"
    check "and the agent connects although the IPv6 address was added first" \
        grep -q '^OK http 200 ' "$OUT/late.out"
    check "the host.conf view was served"      grep -q '"rule":"hostconf_view"' "$OUT/a.log"
    printf '{"api.example.com": {"ttl": 30, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/zone.json"

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

    echo "== 5. the v1.24 review's findings (AI review agents) =="
    # A name never leads to loopback, link-local (169.254.169.254, the cloud
    # metadata service), unspecified or multicast addresses: whoever controls
    # an allowed name's DNS could otherwise open the host's own services.
    printf '{"loop.example.com": {"ttl": 30, "a": ["127.0.0.1"]}, "meta.example.com": {"ttl": 30, "a": ["169.254.169.254"]}, "evil.example.com": {"ttl": 30, "a": ["%s"]}, "mapped.example.com": {"ttl": 30, "aaaa": ["::ffff:%s"]}, "ali.example.com": {"ttl": 30, "a": ["100.100.100.200"]}, "ec2v6.example.com": {"ttl": 30, "aaaa": ["fd00:ec2::254"]}, "nat64.example.com": {"ttl": 30, "aaaa": ["64:ff9b::a9fe:a9fe"]}, "compat.example.com": {"ttl": 30, "aaaa": ["::a9fe:a9fe"]}}\n' \
        "$HOSTIP" "$HOSTIP" > "$OUT/zone.json"
    base() { printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path %s readonly\n' "$W/"; }
    { printf 'require warden 1.24\nallow host loop.example.com\nallow host meta.example.com\n'; base; } > "$OUT/sp.policy"
    run5() {   # run5 <policy> <log> -- agent...
        local pol="$1" log="$2"; shift 3
        env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$pol" --dns-server "127.0.0.1:$PORT" -- "$@" 2> "$log"
    }
    run5 "$OUT/sp.policy" "$OUT/sp.log" -- /usr/bin/python3 "$W/v1240_client.py" "$HP" \
        "loop.example.com:$HP" "meta.example.com:80" > "$OUT/sp.out"
    check "a name that resolves to loopback does not reach it" grep -q "^ERR connect loop.example.com:$HP " "$OUT/sp.out"
    check "nor one that resolves to 169.254.169.254" grep -q '^ERR connect meta.example.com:80 ' "$OUT/sp.out"
    check "the connect is decided on the address alone (special_address)" \
        grep -q "\"target\":\"127.0.0.1:$HP\",\"resolved\":\"127.0.0.1:$HP\",\"decision_raw\":\"UNKNOWN\",.*\"candidates\":\[\"127.0.0.1:$HP\"\],\"special_address\":true" "$OUT/sp.log"
    { printf 'require warden 1.24\nallow host loop.example.com\nallow host 127.0.0.1:%s\n' "$HP"; base; } > "$OUT/sp2.policy"
    run5 "$OUT/sp2.policy" "$OUT/sp2.log" -- /usr/bin/python3 "$W/v1240_client.py" "$HP" "loop.example.com:$HP" > "$OUT/sp2.out"
    check "a numeric rule still allows it"  grep -q "^OK connect loop.example.com:$HP 200 " "$OUT/sp2.out"
    check "and the audit accepts both runs" sh -c "python3 '$HERE/tools/varek_audit.py' --policy '$OUT/sp.policy' --checker '$CERT' '$OUT/sp.log' && python3 '$HERE/tools/varek_audit.py' --policy '$OUT/sp2.policy' --checker '$CERT' '$OUT/sp2.log'"
    # v1.25 review (also in v1.24.0): metadata services outside link-local
    # (Alibaba's 100.100.100.200, AWS's fd00:ec2::254), and NAT64 or
    # IPv4-compatible forms of 169.254.169.254, are special too. Each connect
    # is decided before any dial, so this holds on a host with no IPv6 route.
    { printf 'require warden 1.24\n'; for n in ali ec2v6 nat64 compat; do printf 'allow host %s.example.com\n' "$n"; done; base; } > "$OUT/sp3.policy"
    run5 "$OUT/sp3.policy" "$OUT/sp3.log" -- /usr/bin/python3 "$W/v1240_client.py" "$HP" \
        "ali.example.com:80" "ec2v6.example.com:80" "nat64.example.com:80" "compat.example.com:80" > "$OUT/sp3.out"
    check "a name that resolves to 100.100.100.200 is decided on the address alone" \
        grep -q '"resolved":"100.100.100.200:80","decision_raw":"UNKNOWN","decision_final":"DENY".*"special_address":true' "$OUT/sp3.log"
    if python3 -c 'import socket; socket.socket(socket.AF_INET6)' 2>/dev/null; then
        for t in '\[fd00:ec2::254\]:80' '\[64:ff9b::a9fe:a9fe\]:80' '\[::a9fe:a9fe\]:80'; do
            check "a name that resolves to $t is decided on the address alone" \
                grep -q "\"resolved\":\"$t\",\"decision_raw\":\"UNKNOWN\",\"decision_final\":\"DENY\".*\"special_address\":true" "$OUT/sp3.log"
        done
    else skip "IPv6 metadata and NAT64 names end to end (no IPv6 here; the table's unit test checks them)"; fi
    check "the audit's special addresses are the Warden's" python3 -c "
import ipaddress, sys
sys.path.insert(0, '$HERE/tools')
from varek_audit import _special
cases = {'127.0.0.1': 1, '169.254.169.254': 1, '100.100.100.200': 1, '100.100.100.201': 0, '10.0.0.1': 0,
         '::': 1, '::1': 1, '::a9fe:a9fe': 1, 'fe80::1': 1, 'ff02::1': 1, 'fd00:ec2::254': 1, 'fd00::1': 0,
         '2001:db8::1': 0, '64:ff9b::a9fe:a9fe': 1, '64:ff9b::c000:202': 0, '64:ff9b:1::a9fe:a9fe': 1}
bad = [a for a, w in cases.items() if bool(_special(ipaddress.ip_address(a))) != bool(w)]
sys.exit(f'differ: {bad}' if bad else 0)"
    check "and the audit accepts the run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$OUT/sp3.policy" --checker "$CERT" "$OUT/sp3.log"

    # A deny on a name no allow rule names: resolved too, so it holds on the
    # name's address (it was never resolved, so it never fired).
    { printf 'require warden 1.24\ndeny host evil.example.com\nallow host %s:%s\n' "$HOSTIP" "$HP"; base; } > "$OUT/dn.policy"
    run5 "$OUT/dn.policy" "$OUT/dn.log" -- /usr/bin/python3 "$W/v1240_client.py" "$HP" "$HOSTIP:$HP" > "$OUT/dn.out"
    check "a deny on a name no allow rule names holds on its address" grep -q "^ERR connect $HOSTIP:$HP " "$OUT/dn.out"
    check "decided on that name, by that rule" \
        grep -q "\"resolved\":\"evil.example.com:$HP\",\"decision_raw\":\"DENY\",\"decision_final\":\"DENY\",\"rule\":\"policy_match\",\"policy_line\":2" "$OUT/dn.log"
    run5 "$OUT/dn.policy" "$OUT/dn2.log" -- /usr/bin/python3 -c 'print(open("/etc/hosts").read())' > "$OUT/dn.hosts"
    if grep -q evil "$OUT/dn.hosts"; then flunk "and the denied name is not in the hosts view"
    else pass "and the denied name is not in the hosts view"; fi

    # An AAAA answer ::ffff:a.b.c.d is the address a.b.c.d.
    { printf 'require warden 1.24\ndeny host mapped.example.com:%s\nallow host %s:%s\n' "$HP" "$HOSTIP" "$HP"; base; } > "$OUT/vm.policy"
    run5 "$OUT/vm.policy" "$OUT/vm.log" -- /usr/bin/python3 "$W/v1240_client.py" "$HP" "$HOSTIP:$HP" > "$OUT/vm.out"
    check "a v4-mapped AAAA answer binds its IPv4 address (the deny on the name holds)" \
        grep -q "^ERR connect $HOSTIP:$HP " "$OUT/vm.out"

    # An open of a resolver file that could write is refused, whatever the
    # policy allows: the Warden's resolver reads the host's resolv.conf.
    { printf 'require warden 1.24\nallow host loop.example.com\nallow path /etc/\n'; base; } > "$OUT/vw.policy"
    run5 "$OUT/vw.policy" "$OUT/vw.log" -- /usr/bin/python3 -c '
for p, m in (("/etc/hosts", "r+"), ("/etc/resolv.conf", "a"), ("/etc/hosts", "r")):
    try:
        open(p, m).close(); print("OK", p, m)
    except OSError as e:
        print("ERR", p, m, type(e).__name__)' > "$OUT/vw.out"
    sed 's/^/     /' "$OUT/vw.out"
    check "an open of /etc/hosts for writing is refused (view_write_refused)" \
        sh -c "grep -q '^ERR /etc/hosts r+ PermissionError' '$OUT/vw.out' && grep -q '\"rule\":\"view_write_refused\"' '$OUT/vw.log'"
    check "and of /etc/resolv.conf"           grep -q '^ERR /etc/resolv.conf a PermissionError' "$OUT/vw.out"
    check "a read-only open still gets the view" grep -q '^OK /etc/hosts r' "$OUT/vw.out"

    # The audit: forgeries the review made (edit, then recompute the chain).
    forged() {   # forged <description> <log> <policy> <message> <tamper mode and args...>
        local d="$1" log="$2" pol="$3" msg="$4"; shift 4
        if ! python3 "$T/v1240_tamper.py" "$log" "$OUT/f.log" "$@" 2> "$OUT/f.err"; then
            flunk "$d (could not forge: $(cat "$OUT/f.err"))"; return; fi
        if python3 "$HERE/tools/varek_audit.py" --policy "$pol" --checker "$CERT" "$OUT/f.log" > "$OUT/f.out" 2>&1; then
            flunk "$d (the audit passed it)"
        elif grep -q Traceback "$OUT/f.out"; then flunk "$d (the audit crashed)"
        elif ! grep -q "$msg" "$OUT/f.out"; then flunk "$d ($(grep -m1 PROBLEM "$OUT/f.out"))"
        else pass "$d"; fi
    }
    forged "the audit refuses a connect stripped of its candidates" "$OUT/py.log" "$POL" \
        "recorded without its candidates" nocands "$HOSTIP:$HP"
    forged "the audit refuses a port spelt with a leading zero" "$OUT/py.log" "$POL" \
        "not in the Warden's spelling" port0 "$HOSTIP:$HP"
    forged "the audit refuses a connect that left out a name bound only by its grace" "$OUT/grace.log" "$POL" \
        "is not a candidate" dropname "$HOSTIP:$HP" 2 api.example.com
    forged "the audit refuses a stream missing a resolution record (the table generation)" "$OUT/grace.log" "$POL" \
        "a resolution record is missing" droprecord '"addresses":["198.51.100.7"]'
    forged "the audit refuses a view served although the policy denies its path" "$OUT/nh.log" "$OUT/nohosts.policy" \
        "denies /etc/hosts" view /etc/hosts hosts_view
    forged "the audit reads the name rules from the policy, not run_start" "$OUT/py.log" "$POL" \
        "does not match the policy file" unstart host_name_rules
    forged "a malformed resolution record fails the audit (no crash)" "$OUT/py.log" "$POL" \
        "PROBLEM" badaddrs
    rm -rf "$W"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1240: PASS ($skips skipped)"; else echo "test_v1240: FAIL"; fi
exit "$fail"
