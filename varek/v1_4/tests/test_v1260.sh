#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1260.sh — v1.26.0, the egress proxy in SNI mode: the parts built so
# far (docs/security/v1.26-egress-proxy.md).
#
#   1. policy grammar: `proxy on` and `proxy ports P...` after
#      `require warden 1.26`, refused forms (before 1.26, twice, bad or
#      repeated ports, more than 16, ports without `proxy on`, `proxy inspect`
#      until v1.26.1), the same answer from the decision procedure and the
#      certificate checker on every case, and the Warden starting with them
#   2. the proxy process (as root): started with the run, in the host's
#      network namespace, as its own user with no capabilities and
#      no-new-privileges, holding only its control socket and listener;
#      recorded in run_start; out of the agent's reach; gone when the run
#      ends or the Warden is killed; never the agent's user, never root
#   3. synthetic addresses (as root): with `proxy on` the stub runs without a
#      wildcard rule; a name allowed only on proxied ports gets a stable
#      address from 198.18.0.0/15 (A; AAAA has no data), in the hosts view
#      and from the stub, recorded, never looked up and never charged; a name
#      allowed on another port keeps its real addresses; the audit accepts
#      the run and refuses forged synthetic records
#   4. the hand-off (as root): a TCP connect on a proxied port, to a
#      synthetic address or to an address no numeric rule allows, reaches the
#      proxy's listener and is held there (recorded proxy_handoff, with its
#      connection id); a connect a numeric rule allows is dialed directly; one
#      a rule denies, one on another port, and a UDP or other-port connect to
#      a synthetic address are refused; the proxy closes a connection the
#      Warden did not announce; the audit accepts the run and refuses forged
#      hand-off records
#   5. what the proxy reads: the parsers' vectors and a short fuzz run under
#      ASan and UBSan (tests/proxy_parse_test), real ClientHellos (Python,
#      openssl s_client, curl, node where present) read for their SNI; then
#      (as root) through the proxy: a ClientHello's SNI, an HTTP Host and a
#      CONNECT's name reported to the Warden and decided (refused here, by a
#      policy that allows none of them: a TLS alert or a 403), a ClientHello
#      without SNI, junk, and a CONNECT that sends nothing more refused by the
#      proxy itself
#   6. the decision (as root): names the policy allows are decided and
#      certified, resolved (a wildcard's name on demand, charged to its
#      budgets), dialed and relayed: HTTP, TLS and TLS inside CONNECT; refused:
#      a Host other than the name connected to, a name the policy does not
#      allow, one that resolves only to loopback or to an address a rule
#      denies, and one past its wildcard's names budget; the audit accepts the
#      run and refuses forged proxied decisions
#   7. close records (as root, with section 6's run): every connection
#      passed to the proxy has one proxy_close, with the proxy's byte counts
#      (a CONNECT's own request not among them); one still open when the run
#      ends is closed then ("run_end"); the audit refuses forged closes
#   8. the audit's cross-checks (as root): on a proxied port a name reaches
#      only the proxy (a UDP connect a name allows is refused, proxy_tcp_only;
#      one a numeric rule allows is dialed); the Warden does not run `proxy
#      on` without its proxy (not as root); and the audit refuses run_start
#      without the proxy, a direct connect on a proxied port that no numeric
#      rule decided, and a hand-off of a connect a numeric rule allows or a
#      rule denies
#   9. the upstream proxy (section 5; as root, with Squid where installed):
#      `proxy upstream http://host:port` in the grammar; decided names are
#      asked of the upstream with CONNECT and relayed through it (TLS, and
#      HTTP inside the tunnel); the upstream's own refusal reaches the client
#      and is recorded with its status; a name the policy refuses never
#      reaches the upstream; an upstream named by host name is resolved by
#      the Warden and kept out of the agent's views; the audit accepts the
#      runs and refuses forged upstream records
#
# Usage: test_v1260.sh <vdp_check> <vdp_cert_check> [<warden>]
# (section 5 also uses tests/proxy_parse_test: make tests/proxy_parse_test)
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
    elif ! printf '%s' "$e" | grep -qF "$3"; then flunk "refused: $1 (message: $e)"
    else pass "refused: $1"; fi
}
R='require warden 1.26\n'
H='allow host api.example.com:443\n'
accepted "proxy on"                          "${R}proxy on\n${H}"
accepted "proxy on, then ports"              "${R}proxy on\nproxy ports 443 8443\n${H}"
accepted "ports before proxy on"             "${R}proxy ports 80\nproxy on\n${H}"
accepted "the port bounds"                   "${R}proxy on\nproxy ports 1 65535\n${H}"
accepted "16 ports"                          "${R}proxy on\nproxy ports $(seq -s ' ' 1 16)\n${H}"
accepted "a trailing comment"                "${R}proxy on   # SNI mode\n${H}"
accepted "with a wildcard rule"              "${R}proxy on\nallow host *.example.com:443 acknowledge=dns-channel\n"
refused "proxy before 1.26"                  'require warden 1.25\nproxy on\n'          "require warden 1.26"
refused "proxy with no require"              'proxy on\n'                               "require warden 1.26"
refused "proxy on twice"                     "${R}proxy on\nproxy on\n"                 "given twice"
refused "proxy ports twice"                  "${R}proxy on\nproxy ports 443\nproxy ports 80\n" "given twice"
refused "a port given twice"                 "${R}proxy on\nproxy ports 443 443\n"     "given twice"
refused "port 0"                             "${R}proxy on\nproxy ports 0\n"            "a port is 1 to 65535"
refused "port 65536"                         "${R}proxy on\nproxy ports 65536\n"        "a port is 1 to 65535"
refused "a leading zero"                     "${R}proxy on\nproxy ports 0443\n"         "a port is 1 to 65535"
refused "not a number"                       "${R}proxy on\nproxy ports https\n"        "a port is 1 to 65535"
refused "17 ports"                           "${R}proxy on\nproxy ports $(seq -s ' ' 1 17)\n" "more than 16 ports"
refused "ports without proxy on"             "${R}proxy ports 443\n"                    "without \`proxy on\`"
refused "proxy ports with none"              "${R}proxy on\nproxy ports\n"              "bad directive"
refused "proxy alone"                        "${R}proxy\n"                              "bad directive"
refused "proxy off"                          "${R}proxy off\n"                          "bad directive"
refused "proxy on with more"                 "${R}proxy on now\n"                       "bad directive"
refused "proxy inspect (v1.26.1)"            "${R}proxy inspect\n"                      "planned for v1.26.1"
refused "require 1.27"                       'require warden 1.27\n'                    "this is 1.26"
# section 5: the upstream proxy
accepted "an upstream by name"               "${R}proxy on\nproxy upstream http://Proxy.Corp.example:3128\n${H}"
accepted "an upstream by address, a slash"   "${R}proxy on\nproxy upstream http://10.0.0.5:8080/\n${H}"
accepted "an upstream on loopback"           "${R}proxy upstream http://127.0.0.1:3128\nproxy on\n${H}"
refused "an https upstream"                  "${R}proxy on\nproxy upstream https://p.example:3128\n" "https:// upstream is not taken"
refused "an upstream with credentials"       "${R}proxy on\nproxy upstream http://u:pw@p.example:3128\n" "credentials"
refused "an upstream without a port"         "${R}proxy on\nproxy upstream http://p.example\n"    "needs a port"
refused "an upstream on port 0"              "${R}proxy on\nproxy upstream http://p.example:0\n"  "port is 1 to 65535"
refused "an upstream with a path"            "${R}proxy on\nproxy upstream http://p.example:3128/x\n" "http://host:port"
refused "an upstream at a bad address"       "${R}proxy on\nproxy upstream http://256.1.1.1:3128\n" "not a host name or an IPv4"
refused "an upstream at an IPv6 address"     "${R}proxy on\nproxy upstream http://[::1]:3128\n"   "http://host:port"
refused "an upstream twice"                  "${R}proxy on\nproxy upstream http://a.example:1\nproxy upstream http://b.example:2\n" "given twice"
refused "an upstream without proxy on"       "${R}proxy upstream http://p.example:3128\n"         "without \`proxy on\`"

if [ -n "$WARDEN" ]; then
    printf 'require warden 1.26\nproxy on\nproxy ports 443 8443\nallow host api.example.com:443\n' > "$OUT/w.txt"
    check "the Warden starts with the proxy directives" "$WARDEN" "$OUT/w.txt" --check-startup
else skip "the Warden's startup check (no warden binary given)"; fi

echo "== 2. the proxy process =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "the proxy process (needs root and the warden binary)"
else
    W=/tmp/varek_v1260w
    rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
    cat > "$W/agent.py" <<'PY'
import os, socket, sys, time
# wait for the test to say where the proxy listens, then try to reach it
for _ in range(100):
    try:
        port = int(open(sys.argv[1]).read())
        break
    except (OSError, ValueError):
        time.sleep(0.1)
try:
    socket.create_connection(("127.0.0.1", port), 2)
    print("CONNECTED", flush=True)
except OSError as e:
    print("REFUSED", e.errno, flush=True)
time.sleep(float(sys.argv[2]))
PY
    chmod 644 "$W/agent.py"
    POL="$OUT/proxy.policy"
    printf 'require warden 1.26\nproxy on\nproxy ports 443 8443\nallow host api.example.com:443\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/ readonly\n' "$W" > "$POL"
    proxy_pids() { pgrep -u 65532 -f -- '--proxy-helper'; }   # its own user: never this shell
    # gone: no such process, or one that has exited and awaits its reaping
    # (it is not the Warden's child; init reaps it, and some containers' PID 1
    # does not)
    gone() { for _ in $(seq 20); do
                 [ -n "$1" ] && { [ ! -e "/proc/$1" ] || grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null; } && return 0
                 sleep 0.1; done; return 1; }
    env -i PATH=/usr/bin:/bin "$WARDEN" "$POL" -- /usr/bin/python3 "$W/agent.py" "$W/port" 3 > "$OUT/a.out" 2> "$OUT/a.log" &
    WPID=$!
    for _ in $(seq 50); do grep -q '"proxy":{' "$OUT/a.log" 2>/dev/null && break; sleep 0.1; done
    PORT=$(grep -o '"listen":"127.0.0.1:[0-9]*' "$OUT/a.log" | grep -o '[0-9]*$')
    echo "$PORT" > "$W/port.tmp"; chmod 644 "$W/port.tmp"; mv "$W/port.tmp" "$W/port"
    sleep 1
    PP=$(for p in $(proxy_pids); do grep -q '^State:[[:space:]]*Z' /proc/$p/status || echo $p; done | head -1)
    check "run_start records the proxy, its user and its ports" \
        grep -q '"proxy":{"mode":"sni","listen":"127.0.0.1:[0-9]*","uid":65532,"gid":65532,"ports":\[443,8443\]}' "$OUT/a.log"
    check "one proxy runs, listening on that port" \
        sh -c "[ -n '$PP' ] && [ -e /proc/$PP/fd/4 ] && python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", $PORT), 2)'"
    check "it runs as its own user, not the agent's" grep -q '^Uid:[[:space:]]*65532[[:space:]]65532[[:space:]]65532[[:space:]]65532$' "/proc/$PP/status"
    check "with no capabilities, an empty bounding set and no-new-privileges" \
        sh -c "grep -q '^CapEff:[[:space:]]*0*$' /proc/$PP/status && grep -q '^CapBnd:[[:space:]]*0*$' /proc/$PP/status && grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/$PP/status"
    check "and holds only /dev/null, its control socket and its listener (not the verdict stream)" \
        sh -c "[ \$(ls /proc/$PP/fd | wc -l) = 5 ] && [ \$(readlink /proc/$PP/fd/2) = /dev/null ]"
    wait "$WPID"
    check "the agent cannot reach the listener directly (the connect is decided and refused)" \
        sh -c "grep -q '^REFUSED ' '$OUT/a.out' && grep -q '\"target\":\"127.0.0.1:$PORT\",\"resolved\":\"127.0.0.1:$PORT\",\"decision_raw\":\"UNKNOWN\",\"decision_final\":\"DENY\"' '$OUT/a.log'"
    if gone "$PP"; then pass "the proxy is gone when the run ends"; else flunk "the proxy is gone when the run ends"; fi
    rm -f "$W/port"
    env -i PATH=/usr/bin:/bin "$WARDEN" "$POL" -- /usr/bin/python3 -c 'import time; time.sleep(30)' > /dev/null 2> "$OUT/k.log" &
    WPID=$!
    for _ in $(seq 50); do grep -q '"proxy":{' "$OUT/k.log" 2>/dev/null && break; sleep 0.1; done
    PP=$(for p in $(proxy_pids); do grep -q '^State:[[:space:]]*Z' /proc/$p/status || echo $p; done | head -1)
    kill -9 "$WPID"; wait "$WPID" 2>/dev/null
    sleep 0.5
    if gone "$PP"; then pass "and when the Warden is killed outright"; else flunk "and when the Warden is killed outright"; fi
    pkill -9 -f 'time.sleep\(30\)' 2>/dev/null
    "$WARDEN" "$POL" --run-as 65532:65532 --check-startup > "$OUT/same.out" 2>&1
    check "the proxy may not run as the agent's user" grep -q 'may not run as the agent' "$OUT/same.out"
    "$WARDEN" "$POL" --proxy-as root --check-startup > "$OUT/root.out" 2>&1
    check "nor as root" grep -q 'give an unprivileged user' "$OUT/root.out"
    rm -rf "$W"
fi

echo "== 3. synthetic addresses =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "synthetic addresses (needs root and the warden binary)"
else
    W=/tmp/varek_v1260s
    rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
    cat > "$W/agent.py" <<'PY'
import socket, sys
print("HOSTS " + " | ".join(l for l in open("/etc/hosts").read().splitlines() if "localhost" not in l), flush=True)
for n in sys.argv[2:]:
    for fam, tag in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
        try:
            r = sorted({a[4][0] for a in socket.getaddrinfo(n, 443, fam, socket.SOCK_STREAM)})
            print("OK", tag, n, " ".join(r), flush=True)
        except OSError as e:
            print("ERR", tag, n, e.errno, flush=True)
try:
    socket.create_connection((sys.argv[1], 443), 2)
    print("CONNECTED", flush=True)
except OSError as e:
    print("REFUSED", e.errno, flush=True)
PY
    chmod 644 "$W/agent.py"
    PORT=$((20000 + RANDOM % 20000))
    printf '{"api.example.com": {"ttl": 30, "a": ["10.9.9.1"]}, "ssh.example.com": {"ttl": 30, "a": ["10.9.9.2"]}, "both.example.com": {"ttl": 30, "a": ["10.9.9.3"]}, "x.svc.example.com": {"ttl": 30, "a": ["10.9.9.4"]}}\n' > "$OUT/zone.json"
    : > "$OUT/q.log"
    python3 "$HERE/tests/dns_test_server.py" --port "$PORT" --zone "$OUT/zone.json" --log "$OUT/q.log" \
        --ready "$OUT/ready" > "$OUT/dns.out" 2>&1 &
    DNSPID=$!
    for _ in $(seq 50); do [ -e "$OUT/ready" ] && break; sleep 0.1; done
    PATHS="allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path $W/ readonly\n"
    POL="$OUT/syn.policy"
    printf "require warden 1.26\nproxy on\nallow host api.example.com:443\nallow host ssh.example.com:22\nallow host both.example.com:443\nallow host both.example.com:22\n$PATHS" > "$POL"
    run() { env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$1" --dns-server "127.0.0.1:$PORT" -- \
                /usr/bin/python3 "$W/agent.py" "$2" api.example.com ssh.example.com both.example.com nope.example.com \
                > "$OUT/s.out" 2> "$OUT/s.log"; }
    run "$POL" 198.18.0.1
    sed 's/^/     /' "$OUT/s.out"
    check "with the proxy on, the stub runs without a wildcard rule" \
        sh -c "grep -q '\"dns_stub\":\"127.53.53.53:53\"' '$OUT/s.log' && grep -q 'synthetic addresses' '$OUT/s.log'"
    check "the hosts view lists a name allowed only on proxied ports with a synthetic address" \
        grep -q '^HOSTS 198.18.0.1 api.example.com | 10.9.9.2 ssh.example.com | 10.9.9.3 both.example.com$' "$OUT/s.out"
    check "its A answer is that address" grep -q '^OK A api.example.com 198.18.0.1$' "$OUT/s.out"
    check "and its AAAA answer has no data" \
        sh -c "grep -q '^ERR AAAA api.example.com ' '$OUT/s.out' && grep -q '\"name\":\"api.example.com\",\"type\":28,[^}]*\"synthetic\":true,\"answer\":\"noerror\",\"addresses\":\[\]' '$OUT/s.log'"
    check "the address is recorded once (synthetic_address)" \
        sh -c "[ \$(grep -c '\"event\":\"synthetic_address\",\"run\":\"[0-9a-f]*\",\"name\":\"api.example.com\",\"address\":\"198.18.0.1\",\"policy_line\":3,' '$OUT/s.log') = 1 ]"
    check "a name allowed on another port keeps its real address" grep -q '^OK A ssh.example.com 10.9.9.2$' "$OUT/s.out"
    check "and so does a name allowed on a proxied port and another" grep -q '^OK A both.example.com 10.9.9.3$' "$OUT/s.out"
    check "a name outside every rule: NXDOMAIN" grep -q '^ERR A nope.example.com -2$' "$OUT/s.out"
    check "a connect to the synthetic address on a proxied port is handed to the proxy" \
        sh -c "grep -q '^CONNECTED$' '$OUT/s.out' && grep -q '\"target\":\"198.18.0.1:443\",\"resolved\":\"127.0.0.1:[0-9]*\",[^}]*\"decision_final\":\"ALLOW\",\"rule\":\"proxy_handoff' '$OUT/s.log'"
    check "the audit accepts the run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/s.log"
    cp "$OUT/s.log" "$OUT/s1.log"

    POLW="$OUT/synw.policy"
    printf "require warden 1.26\nproxy on\nallow host *.svc.example.com:443 acknowledge=dns-channel names=1\n$PATHS" > "$POLW"
    : > "$OUT/q.log"
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$POLW" --dns-server "127.0.0.1:$PORT" -- \
        /usr/bin/python3 "$W/agent.py" 127.0.0.2 x.svc.example.com y.svc.example.com x.svc.example.com \
        > "$OUT/w.out" 2> "$OUT/w.log"
    sed 's/^/     /' "$OUT/w.out"
    check "a name a wildcard allows on a proxied port gets a synthetic address" \
        grep -q '^OK A x.svc.example.com 198.18.0.1$' "$OUT/w.out"
    check "and keeps it when asked again" sh -c "[ \$(grep -c '^OK A x.svc.example.com 198.18.0.1$' '$OUT/w.out') = 2 ]"
    check "the next name gets the next address, past the rule's names=1 (no budget is charged)" \
        grep -q '^OK A y.svc.example.com 198.18.0.2$' "$OUT/w.out"
    check "nothing was asked upstream" sh -c "! grep -q svc.example.com '$OUT/q.log'"
    check "no question was charged or sent upstream" sh -c "! grep -E '\"event\":\"dns_question\".*\"(new|upstream)\":true' '$OUT/w.log'"
    check "the audit accepts the run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POLW" --checker "$CERT" "$OUT/w.log"

    forge() {   # forge <in> <out> <from> <to> [re]: rewrite the first record holding <from>, rechain
        python3 - "$1" "$2" "$3" "$4" "${5:-}" <<'PY'
import hashlib, re, sys
head = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
out, done = [], False
for line in open(sys.argv[1], encoding="utf-8", errors="surrogateescape"):
    if line.startswith("{") and ',"chain":"' in line:
        cut = line.index(',"chain":"')
        body = line[:cut]
        if not done and sys.argv[5] == "re" and re.search(sys.argv[3], body):
            body = re.sub(sys.argv[3], sys.argv[4], body, count=1)
            done = True
        elif not done and sys.argv[5] != "re" and sys.argv[3] in body:
            body = body.replace(sys.argv[3], sys.argv[4])
            done = True
        head = hashlib.sha256(head + body.encode("utf-8", "surrogateescape")).digest()
        line = body + ',"chain":"' + head.hex() + line[cut + 10 + 64:]
    out.append(line)
open(sys.argv[2], "w", encoding="utf-8", errors="surrogateescape").write("".join(out))
PY
    }
    refuses() {   # refuses <description> <policy> <log> <message>
        if python3 "$HERE/tools/varek_audit.py" --policy "$2" --checker "$CERT" "$3" > "$OUT/f.out" 2>&1; then
            flunk "the audit refuses $1"
        elif grep -qF "$4" "$OUT/f.out"; then pass "the audit refuses $1"
        else flunk "the audit refuses $1 ($(grep -m1 'problem\|FAIL' "$OUT/f.out"))"; fi
    }
    forge "$OUT/w.log" "$OUT/f1.log" '"policy_line":3,"synthetic":true,"answer":"noerror","addresses":["198.18.0.1"]' \
                                     '"policy_line":3,"synthetic":true,"answer":"noerror","addresses":["198.18.0.7"]'
    refuses "a synthetic answer that is not the name's address" "$POLW" "$OUT/f1.log" "that is not its synthetic address"
    forge "$OUT/s1.log" "$OUT/f2.log" '"address":"198.18.0.1"' '"address":"198.18.0.9"'
    refuses "a synthetic address out of order" "$POL" "$OUT/f2.log" "not the next synthetic address"
    forge "$OUT/s1.log" "$OUT/f3.log" '"name":"ssh.example.com","type":28,"transport":"udp","rule":"exact_name","policy_line":4,' \
                                      '"name":"ssh.example.com","type":28,"transport":"udp","rule":"exact_name","policy_line":4,"synthetic":true,'
    refuses "a synthetic answer for a name allowed off the proxied ports" "$POL" "$OUT/f3.log" "allows it off the proxied ports"
    forge "$OUT/s1.log" "$OUT/f4.log" '("target":"198\.18\.0\.1:443",)"resolved":"127\.0\.0\.1:[0-9]*",("decision_raw":"[A-Z]*","decision_final":"ALLOW",)"rule":"proxy_handoff[a-z_]*",(.*)"proxy_handoff":true,' \
                                      '\1"resolved":"198.18.0.1:443",\2"rule":"dialed_fd_injection",\3' re
    refuses "a dialed connect to a synthetic address" "$POL" "$OUT/f4.log" "a connect to the synthetic address 198.18.0.1 was dialed"
    kill "$DNSPID" 2>/dev/null
    rm -rf "$W"
fi

echo "== 4. the hand-off =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "the hand-off (needs root and the warden binary)"
else
    W=/tmp/varek_v1260h
    rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
    cat > "$W/agent.py" <<'PY'
import socket, sys, time
# argv: the file the test writes the proxy's port to, then proto:host:port...
for _ in range(100):
    try:
        lport = int(open(sys.argv[1]).read())
        break
    except (OSError, ValueError):
        time.sleep(0.1)
for t in sys.argv[2:]:
    proto, host, port = t.split(":")
    port = lport if port == "L" else int(port)
    try:
        if proto == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((host, port))
            print("CONNECTED", t, flush=True)
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))            # blocking, as most clients
        s.settimeout(1)                    # sends nothing: the proxy holds it, waiting
        try:
            d = s.recv(10)
            print("CONNECTED", t, "EOF" if d == b"" else "DATA", flush=True)
        except socket.timeout:
            print("CONNECTED", t, "HELD", flush=True)
        except OSError as e:
            print("CONNECTED", t, "EOF", flush=True)   # reset: closed too
    except OSError as e:
        print("ERR", t, e.errno, flush=True)
PY
    chmod 644 "$W/agent.py"
    POLH="$OUT/handoff.policy"
    printf 'require warden 1.26\nproxy on\nproxy ports 443 8443\nallow host api.example.com:443\nallow host 192.0.2.9:8443\ndeny host 192.0.2.8:443\nallow host 127.0.0.1\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/ readonly\n' "$W" > "$POLH"
    rm -f "$W/port"
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$POLH" -- /usr/bin/python3 "$W/agent.py" "$W/port" \
        tcp:198.18.0.1:443 tcp:192.0.2.7:443 tcp:192.0.2.7:8443 tcp:192.0.2.8:443 tcp:192.0.2.9:8443 \
        tcp:192.0.2.7:22 tcp:198.18.0.1:22 udp:198.18.0.1:443 tcp:127.0.0.1:L \
        > "$OUT/h.out" 2> "$OUT/h.log" &
    WPID=$!
    for _ in $(seq 50); do grep -q '"proxy":{' "$OUT/h.log" 2>/dev/null && break; sleep 0.1; done
    LP=$(grep -o '"listen":"127.0.0.1:[0-9]*' "$OUT/h.log" | grep -o '[0-9]*$')
    echo "$LP" > "$W/port.tmp"; chmod 644 "$W/port.tmp"; mv "$W/port.tmp" "$W/port"
    wait "$WPID"
    sed 's/^/     /' "$OUT/h.out"
    check "a connect to a synthetic address on a proxied port reaches the proxy, which holds it" \
        sh -c "grep -q '^CONNECTED tcp:198.18.0.1:443 HELD$' '$OUT/h.out' && grep '\"target\":\"198.18.0.1:443\"' '$OUT/h.log' | grep -q '\"resolved\":\"127.0.0.1:$LP\",\"decision_raw\":\"UNKNOWN\",\"decision_final\":\"ALLOW\",\"rule\":\"proxy_handoff\"'"
    check "recorded with its connection id and the port the Warden dialed from" \
        sh -c "grep '\"target\":\"198.18.0.1:443\"' '$OUT/h.log' | grep -q '\"dialed\":\"198.18.0.1:443\",.*\"proxy_handoff\":true,\"proxy_conn\":1,\"proxy_from\":[1-9][0-9]*,'"
    check "so does a connect to an address no rule allows, on either proxied port" \
        sh -c "grep -q '^CONNECTED tcp:192.0.2.7:443 HELD$' '$OUT/h.out' && grep -q '^CONNECTED tcp:192.0.2.7:8443 HELD$' '$OUT/h.out'"
    check "a connect a rule denies is refused, not handed over" \
        sh -c "grep -q '^ERR tcp:192.0.2.8:443 13$' '$OUT/h.out' && grep '\"target\":\"192.0.2.8:443\"' '$OUT/h.log' | grep -q '\"decision_final\":\"DENY\",\"rule\":\"policy_match\"'"
    check "a connect a numeric rule allows is dialed directly (certified)" \
        sh -c "grep '\"target\":\"192.0.2.9:8443\"' '$OUT/h.log' | grep -q '\"resolved\":\"192.0.2.9:8443\",\"decision_raw\":\"ALLOW\",\"decision_final\":\"ALLOW\",\"rule\":\"dial[a-z_]*\".*\"check\":\"ok\"' && ! grep '\"target\":\"192.0.2.9:8443\"' '$OUT/h.log' | grep -q proxy_handoff"
    check "a connect on a port that is not proxied is decided as before (refused)" \
        grep -q '^ERR tcp:192.0.2.7:22 13$' "$OUT/h.out"
    check "a synthetic address on another port, or over UDP, is refused (synthetic_address)" \
        sh -c "grep -q '^ERR tcp:198.18.0.1:22 13$' '$OUT/h.out' && grep -q '^ERR udp:198.18.0.1:443 13$' '$OUT/h.out' && [ \$(grep -c '\"rule\":\"synthetic_address\"' '$OUT/h.log') = 2 ]"
    check "the proxy closes a connection the Warden did not announce" \
        grep -q '^CONNECTED tcp:127.0.0.1:L EOF$' "$OUT/h.out"
    check "the audit accepts the run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POLH" --checker "$CERT" "$OUT/h.log"
    forge "$OUT/h.log" "$OUT/g1.log" '"proxy_handoff":true,' ''
    refuses "a hand-off record without its flag" "$POLH" "$OUT/g1.log" "not a TCP connect to the proxy's listener"
    forge "$OUT/h.log" "$OUT/g2.log" '"target":"198.18.0.1:443"' '"target":"198.18.0.1:22"'
    refuses "a hand-off on a port that is not proxied" "$POLH" "$OUT/g2.log" "not on a proxied port"
    forge "$OUT/h.log" "$OUT/g3.log" '"proxy_conn":2,' '"proxy_conn":1,'
    refuses "two hand-offs with one connection id" "$POLH" "$OUT/g3.log" "without a connection id of its own"
    forge "$OUT/h.log" "$OUT/g4.log" '"target":"192.0.2.8:443","resolved":"192.0.2.8:443","decision_raw":"DENY","decision_final":"DENY","rule":"policy_match",' \
                                     '"target":"192.0.2.8:443","resolved":"127.0.0.1:'"$LP"'","decision_raw":"DENY","decision_final":"ALLOW","rule":"proxy_handoff","proxy_handoff":true,"proxy_conn":9,'
    refuses "a hand-off of a connect a rule denies" "$POLH" "$OUT/g4.log" "denies was handed to the proxy"
    printf 'require warden 1.26\nallow host api.example.com:443\nallow host 192.0.2.9:8443\ndeny host 192.0.2.8:443\nallow host 127.0.0.1\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/ readonly\n' "$W" > "$OUT/noproxy.policy"
    refuses "hand-offs under a policy without the proxy" "$OUT/noproxy.policy" "$OUT/h.log" "the proxy is not on"
    rm -rf "$W"
fi

echo "== 5. what the proxy reads =="
PPT="$HERE/tests/proxy_parse_test"
if [ ! -x "$PPT" ]; then
    skip "the parsers (build tests/proxy_parse_test)"
else
    check "the parsers' vectors (ASan, UBSan)" "$PPT" unit
    check "200,000 fuzzed inputs, no fault (ASan, UBSan)" "$PPT" fuzz 100000 "$RANDOM"
    # Real clients' first flights, captured by a listener that answers nothing
    capture() {   # capture <out> <command...> (the command connects to 127.0.0.1:$CP)
        local out="$1"; shift
        CP=$((30000 + RANDOM % 20000))
        python3 - "$CP" "$out" <<'PY' &
import socket, sys, time
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", int(sys.argv[1]))); l.listen(1); l.settimeout(10)
c, _ = l.accept(); c.settimeout(1); d = b""; t = time.time()
while time.time() - t < 2:
    try:
        x = c.recv(65536)
        if not x: break
        d += x
    except socket.timeout:
        break
open(sys.argv[2], "wb").write(d)
PY
        local lp=$!
        sleep 0.3
        CP=$CP "$@" > /dev/null 2>&1 &
        local cp=$!
        wait "$lp"; kill "$cp" 2>/dev/null; wait "$cp" 2>/dev/null
    }
    read_sni() {  # read_sni <description> <file> <want>
        if [ "$("$PPT" file "$2" 443)" = "OK tls $3 443" ]; then pass "$1"
        else flunk "$1 ($("$PPT" file "$2" 443))"; fi
    }
    python3 - "$OUT/py.ch" <<'PY'
import ssl, sys
ctx = ssl.create_default_context(); ctx.set_alpn_protocols(["h2", "http/1.1"])
i, o = ssl.MemoryBIO(), ssl.MemoryBIO()
s = ctx.wrap_bio(i, o, server_hostname="api.example.com")
try: s.do_handshake()
except ssl.SSLWantReadError: pass
open(sys.argv[1], "wb").write(o.read())
PY
    read_sni "a Python (OpenSSL) ClientHello" "$OUT/py.ch" api.example.com
    if command -v openssl > /dev/null; then
        capture "$OUT/ossl.ch" sh -c 'openssl s_client -connect 127.0.0.1:$CP -servername api.example.com < /dev/null'
        read_sni "an openssl s_client ClientHello" "$OUT/ossl.ch" api.example.com
    else skip "openssl s_client (not installed)"; fi
    if command -v curl > /dev/null; then
        capture "$OUT/curl.ch" sh -c 'curl -sk --noproxy api.example.com,127.0.0.1 --max-time 3 --resolve api.example.com:$CP:127.0.0.1 https://api.example.com:$CP/'
        read_sni "a curl ClientHello" "$OUT/curl.ch" api.example.com
        capture "$OUT/curl.http" sh -c 'curl -s --noproxy api.example.com,127.0.0.1 --max-time 3 --resolve api.example.com:$CP:127.0.0.1 http://api.example.com:$CP/x'
        if "$PPT" file "$OUT/curl.http" "$CP" | grep -q "^OK http api.example.com $CP$"; then pass "a curl HTTP request (Host with its port)"
        else flunk "a curl HTTP request ($("$PPT" file "$OUT/curl.http" "$CP"))"; fi
    else skip "curl (not installed)"; fi
    NODE=$(command -v node 2>/dev/null)
    if [ -n "$NODE" ]; then
        capture "$OUT/node.ch" sh -c "'$NODE' -e 'require(\"tls\").connect({host:\"127.0.0.1\",port:+process.env.CP,servername:\"api.example.com\",rejectUnauthorized:false}).on(\"error\",()=>{})'"
        read_sni "a node ClientHello" "$OUT/node.ch" api.example.com
    else skip "node (not installed)"; fi
fi

if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "through the proxy (needs root and the warden binary)"
else
    W=/tmp/varek_v1260p
    rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
    cat > "$W/agent.py" <<'PY'
import socket, ssl
def hello(sni):
    ctx = ssl.create_default_context()
    i, o = ssl.MemoryBIO(), ssl.MemoryBIO()
    s = ctx.wrap_bio(i, o, server_hostname=sni)
    try: s.do_handshake()
    except ssl.SSLWantReadError: pass
    return o.read()
def tls(sni):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    s = socket.create_connection(("198.18.0.1", 443), 5)
    try:
        ctx.wrap_socket(s, server_hostname=sni)
        print("TLS", sni, "HANDSHAKE", flush=True)
    except ssl.SSLError as e:
        print("TLS", sni, "ALERT" if "HANDSHAKE_FAILURE" in str(e).upper() else "OTHER", flush=True)
def raw(tag, *parts, wait=3):
    s = socket.create_connection(("198.18.0.1", 443), 5)
    s.settimeout(wait)
    out = b""
    for p in parts:
        s.sendall(p)
        try:
            while True:
                d = s.recv(4096)
                out += d
                if not d or b"\r\n\r\n" in out or out[-7:-5] == b"\x15\x03": break
        except OSError:
            pass
    print("RAW", tag, out.hex(), flush=True)
tls("api.example.com")
tls(None)
raw("http", b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
raw("connect", b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n", hello("api.example.com"))
raw("connect-other", b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n", hello("other.example.com"))
raw("junk", b"\x01\x02junk")
raw("idle", b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n", b"", wait=12)
PY
    chmod 644 "$W/agent.py"
    POLP="$OUT/parse.policy"
    # no rule allows the names asked for: each request is read and refused
    printf 'require warden 1.26\nproxy on\nallow host unused.example.com:443\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path /etc/ssl/ readonly\nallow path %s/ readonly\n' "$W" > "$POLP"
    env -i PATH=/usr/bin:/bin timeout 90 "$WARDEN" "$POLP" -- /usr/bin/python3 "$W/agent.py" > "$OUT/p.out" 2> "$OUT/p.log"
    sed 's/^/     /' "$OUT/p.out" | cut -c1-120
    grep 'proxy: connection' "$OUT/p.log" | sed 's/^/     /'
    pxrec() { grep '"action":"net.proxy"' "$OUT/p.log" | grep "\"proxy_conn\":$1,\"proxy_kind\":\"$2\"" | grep -q "\"target\":\"$3\",\"resolved\":\"$3\",\"decision_raw\":\"UNKNOWN\",\"decision_final\":\"DENY\""; }
    OK200=$(printf 'HTTP/1.1 200 Connection established\r\n\r\n' | od -An -tx1 | tr -d ' \n')
    ALERT=15030300020228                  # a fatal handshake_failure alert
    check "a ClientHello's SNI is read, and decided by the Warden (a net.proxy record)" \
        pxrec 1 tls api.example.com:443
    check "and, refused by the policy, answered with a handshake_failure alert" \
        grep -q '^TLS api.example.com ALERT$' "$OUT/p.out"
    check "a ClientHello without SNI is refused by the proxy" \
        sh -c "grep -q 'proxy: connection 2 (tls) refused by the proxy: no SNI' '$OUT/p.log' && grep -q '^TLS None ALERT$' '$OUT/p.out'"
    check "an HTTP request's Host is decided, and refused with a 403" \
        sh -c "$(declare -f pxrec); OUT='$OUT'; pxrec 3 http api.example.com:443 && grep -q '^RAW http $(printf 'HTTP/1.1 403' | od -An -tx1 | tr -d ' \n')' '$OUT/p.out'"
    check "a CONNECT is answered 200, and the name is decided once the ClientHello inside agrees" \
        sh -c "$(declare -f pxrec); OUT='$OUT'; pxrec 4 connect api.example.com:443 && grep -q '^RAW connect $OK200$ALERT$' '$OUT/p.out'"
    check "a CONNECT whose ClientHello names another host is refused by the proxy" \
        sh -c "grep -q 'proxy: connection 5 (connect) refused by the proxy: an SNI that is not the CONNECT target' '$OUT/p.log' && grep -q '^RAW connect-other $OK200$ALERT$' '$OUT/p.out'"
    check "neither TLS nor HTTP: closed by the proxy" \
        sh -c "grep -q 'proxy: connection 6 (none) refused by the proxy: neither TLS nor HTTP' '$OUT/p.log' && grep -q '^RAW junk $' '$OUT/p.out'"
    check "a client that sends nothing more is refused after 10 s" \
        grep -q 'proxy: connection 7 (connect) refused by the proxy: no whole request within 10 s' "$OUT/p.log"
    check "the names, not the bytes, reach the Warden: three decisions and four refusals by the proxy" \
        sh -c "[ \$(grep -c '\"action\":\"net.proxy\"' '$OUT/p.log') = 3 ] && [ \$(grep -c 'proxy: connection' '$OUT/p.log') = 4 ]"
    check "the audit accepts the run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POLP" --checker "$CERT" "$OUT/p.log"
    rm -rf "$W"
fi

echo "== 6. the decision =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ] || ! command -v openssl > /dev/null; then
    skip "the decision (needs root, the warden binary and openssl)"
else
    W=/tmp/varek_v1260d
    rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
    # a name never leads to loopback: the servers listen on this machine's own address
    HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
    HP=$((40000 + RANDOM % 5000)); TP=$((HP + 1))
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -days 1 \
        -subj /CN=api.example.com > /dev/null 2>&1
    python3 - "$HOSTIP" "$TP" "$OUT/cert.pem" "$OUT/key.pem" <<'PY' > "$OUT/tlssrv.out" 2>&1 &
import socket, ssl, sys, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[3], sys.argv[4])
def sni(sock, name, c):
    sock.seen = name                      # the SNI the server received
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
    HOLDP=$((TP + 1))                    # a server that reads nothing and never closes
    python3 - "$HOSTIP" "$HOLDP" <<'PY' > /dev/null 2>&1 &
import socket, sys, time
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind((sys.argv[1], int(sys.argv[2]))); l.listen(16)
held = []
while True:
    c, _ = l.accept(); held.append(c)
PY
    SRV="$SRV $!"
    mkdir -p "$OUT/www"; echo "http-ok" > "$OUT/www/x.txt"
    python3 -m http.server "$HP" --bind "$HOSTIP" --directory "$OUT/www" > /dev/null 2>&1 &
    SRV="$SRV $!"
    PORT=$((20000 + RANDOM % 20000))
    printf '{"api.example.com": {"ttl": 30, "a": ["%s"]}, "a.svc.example.com": {"ttl": 30, "a": ["%s"]}, "b.svc.example.com": {"ttl": 30, "a": ["%s"]}, "lo.example.com": {"ttl": 30, "a": ["127.0.0.1"]}, "den.example.com": {"ttl": 30, "a": ["192.0.2.77"]}}\n' \
        "$HOSTIP" "$HOSTIP" "$HOSTIP" > "$OUT/zone6.json"
    rm -f "$OUT/ready6"
    python3 "$HERE/tests/dns_test_server.py" --port "$PORT" --zone "$OUT/zone6.json" --log "$OUT/q6.log" \
        --ready "$OUT/ready6" > /dev/null 2>&1 &
    DNSP=$!
    SRV="$SRV $DNSP"
    for _ in $(seq 50); do
        [ -e "$OUT/ready6" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $HP), 0.2); socket.create_connection(('$HOSTIP', $TP), 0.2)" 2>/dev/null && break
        sleep 0.1
    done
    cat > "$W/agent.py" <<'PY'
import socket, ssl, sys, time, urllib.request
HP, TP = int(sys.argv[1]), int(sys.argv[2])
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def body(s):
    out = b""
    while True:
        d = s.recv(4096)
        if not d: break
        out += d
    return out.split(b"\r\n\r\n", 1)[-1].decode(errors="replace")
def http(tag, name, host=None):
    try:
        s = socket.create_connection((name, HP), 10)
        s.sendall(b"GET /x.txt HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (host or name).encode())
        out = b""
        while True:
            d = s.recv(4096)
            if not d: break
            out += d
        print("HTTP", tag, out.split(b"\r\n")[0].decode(), out.split(b"\r\n\r\n", 1)[-1].decode().strip(), flush=True)
    except OSError as e:
        print("HTTP", tag, "ERR", e, flush=True)
def tls(tag, name):
    try:
        s = ctx.wrap_socket(socket.create_connection((name, TP), 10), server_hostname=name)
        s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % name.encode())
        print("TLS", tag, body(s), flush=True)
    except ssl.SSLError as e:
        print("TLS", tag, "ALERT" if "HANDSHAKE_FAILURE" in str(e).upper() else "SSLERR", flush=True)
    except OSError as e:
        print("TLS", tag, "ERR", e, flush=True)
def connect(tag, name):
    try:
        s = socket.create_connection((name, TP), 10)
        s.sendall(b"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (name.encode(), TP, name.encode(), TP))
        r = b""
        while b"\r\n\r\n" not in r:
            d = s.recv(1)
            if not d: break
            r += d
        t = ctx.wrap_socket(s, server_hostname=name)
        t.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % name.encode())
        print("CONNECT", tag, body(t), flush=True)
    except (OSError, ssl.SSLError) as e:
        print("CONNECT", tag, "ERR", type(e).__name__, flush=True)
try:
    print("URLLIB", urllib.request.urlopen("http://api.example.com:%d/x.txt" % HP, timeout=10).read().decode().strip(), flush=True)
except Exception as e:
    print("URLLIB ERR", e, flush=True)
http("other-host", "api.example.com", "other.example.com")
tls("exact", "api.example.com")
tls("wild", "a.svc.example.com")
tls("wild-again", "a.svc.example.com")
tls("wild-nx", "c.svc.example.com")
tls("wild-over", "b.svc.example.com")
tls("loopback", "lo.example.com")
tls("denied-addr", "den.example.com")
connect("connect", "api.example.com")
# a relay still open when the run ends: a ClientHello to a server that never answers
i, o = ssl.MemoryBIO(), ssl.MemoryBIO()
b = ssl.create_default_context().wrap_bio(i, o, server_hostname="api.example.com")
try: b.do_handshake()
except ssl.SSLWantReadError: pass
h = socket.create_connection(("api.example.com", int(sys.argv[3])), 10)
h.sendall(o.read())
time.sleep(1)
print("HOLD sent", flush=True)
PY
    chmod 644 "$W/agent.py"
    POL6="$OUT/decide.policy"
    { printf 'require warden 1.26\nproxy on\nproxy ports %s %s %s\n' "$HP" "$TP" "$HOLDP"
      printf 'allow host api.example.com:%s\nallow host api.example.com:%s\nallow host api.example.com:%s\n' "$HP" "$TP" "$HOLDP"
      printf 'allow host lo.example.com:%s\ndeny host 192.0.2.77:%s\nallow host den.example.com:%s\n' "$TP" "$TP" "$TP"
      printf 'allow host *.svc.example.com:%s acknowledge=dns-channel names=2\n' "$TP"
      printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path /etc/ssl/ readonly\nallow path %s/ readonly\n' "$W"
    } > "$POL6"
    env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$POL6" --dns-server "127.0.0.1:$PORT" -- \
        /usr/bin/python3 "$W/agent.py" "$HP" "$TP" "$HOLDP" > "$OUT/d.out" 2> "$OUT/d.log"
    sed 's/^/     /' "$OUT/d.out"
    px() {  # px <target> <rule>: the net.proxy record for target, decided by rule
        grep '"action":"net.proxy"' "$OUT/d.log" | grep -q "\"target\":\"$1\",.*\"rule\":\"$2\""; }
    check "HTTP by name (urllib): decided, certified, dialed and relayed" \
        sh -c "grep -q '^URLLIB http-ok$' '$OUT/d.out' && grep '\"action\":\"net.proxy\"' '$OUT/d.log' | grep -q '\"target\":\"api.example.com:$HP\",\"resolved\":\"api.example.com:$HP\",\"decision_raw\":\"ALLOW\",\"decision_final\":\"ALLOW\",\"rule\":\"proxy_dialed\",.*\"check\":\"ok\",\"dialed\":\"$HOSTIP:$HP\",\"proxy_conn\":1,\"proxy_kind\":\"http\"'"
    check "a Host other than the name connected to is decided on the Host, and refused (403)" \
        sh -c "grep -q '^HTTP other-host HTTP/1.1 403 Forbidden' '$OUT/d.out' && grep '\"action\":\"net.proxy\"' '$OUT/d.log' | grep -q '\"target\":\"other.example.com:$HP\",.*\"decision_final\":\"DENY\"'"
    check "TLS by an exact name: relayed to the server, which saw the SNI" \
        sh -c "grep -q '^TLS exact tls-ok api.example.com$' '$OUT/d.out' && grep '\"action\":\"net.proxy\"' '$OUT/d.log' | grep -q '\"target\":\"api.example.com:$TP\",.*\"rule\":\"proxy_dialed\",.*\"proxy_kind\":\"tls\"'"
    check "TLS by a name a wildcard allows: looked up on demand (charged, a proxy question), relayed" \
        sh -c "grep -q '^TLS wild tls-ok a.svc.example.com$' '$OUT/d.out' && grep -q '\"event\":\"dns_question\",\"run\":\"[0-9a-f]*\",\"name\":\"a.svc.example.com\",\"type\":1,\"transport\":\"proxy\",\"rule\":\"policy_match\",\"policy_line\":10,\"new\":true,\"upstream\":true,\"answer\":\"lookup\"' '$OUT/d.log' && grep -q '\"name\":\"a.svc.example.com\".*\"dynamic\":true' '$OUT/d.log'"
    check "and asked again within its TTL: not looked up or charged again" \
        sh -c "grep -q '^TLS wild-again tls-ok a.svc.example.com$' '$OUT/d.out' && [ \$(grep -c '\"transport\":\"proxy\",[^}]*\"name\":\"a.svc\|\"name\":\"a.svc.example.com\",\"type\":1,\"transport\":\"proxy\"' '$OUT/d.log') = 1 ]"
    check "a wildcard's name that does not resolve: refused (resolution_failed)" \
        sh -c "grep -q '^TLS wild-nx ALERT$' '$OUT/d.out' && grep '\"action\":\"net.proxy\"' '$OUT/d.log' | grep -q '\"target\":\"c.svc.example.com:$TP\",.*\"rule\":\"resolution_failed\"'"
    check "a name past its wildcard's names budget: refused, nothing looked up (wildcard_budget)" \
        sh -c "grep -q '^TLS wild-over ALERT$' '$OUT/d.out' && grep '\"action\":\"net.proxy\"' '$OUT/d.log' | grep -q '\"target\":\"b.svc.example.com:$TP\",.*\"rule\":\"wildcard_budget\"' && ! grep -q 'b.svc.example.com' '$OUT/q6.log'"
    check "a name that resolves only to loopback: refused (address_refused)" \
        sh -c "grep -q '^TLS loopback ALERT$' '$OUT/d.out' && grep '\"action\":\"net.proxy\"' '$OUT/d.log' | grep -q '\"target\":\"lo.example.com:$TP\",.*\"rule\":\"address_refused\"'"
    check "a name whose only address a rule denies: refused (address_refused)" \
        sh -c "grep -q '^TLS denied-addr ALERT$' '$OUT/d.out' && grep '\"action\":\"net.proxy\"' '$OUT/d.log' | grep -q '\"target\":\"den.example.com:$TP\",.*\"rule\":\"address_refused\"'"
    check "TLS inside CONNECT: decided on the CONNECT's name, relayed" \
        sh -c "grep -q '^CONNECT connect tls-ok api.example.com$' '$OUT/d.out' && grep '\"action\":\"net.proxy\"' '$OUT/d.log' | grep -q '\"target\":\"api.example.com:$TP\",.*\"rule\":\"proxy_dialed\",.*\"proxy_kind\":\"connect\"'"
    check "the audit accepts the run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL6" --checker "$CERT" "$OUT/d.log"
    forge "$OUT/d.log" "$OUT/e1.log" "\"dialed\":\"$HOSTIP:$TP\"" '"dialed":"192.0.2.99:'"$TP"'"'
    refuses "a proxied connection dialed to an address the name does not have" "$POL6" "$OUT/e1.log" "does not list"
    forge "$OUT/d.log" "$OUT/e2.log" "\"dialed\":\"$HOSTIP:$TP\"" '"dialed":"127.0.0.1:'"$TP"'"'
    refuses "a proxied connection dialed to loopback" "$POL6" "$OUT/e2.log" "a special or synthetic address"
    forge "$OUT/d.log" "$OUT/e3.log" '"proxy_conn":1,"proxy_kind"' '"proxy_conn":99,"proxy_kind"'
    refuses "a proxied decision for no hand-off" "$POL6" "$OUT/e3.log" "which is not a hand-off"
    forge "$OUT/d.log" "$OUT/e4.log" "\"target\":\"api.example.com:$TP\",\"resolved\":\"api.example.com:$TP\"" \
                                     "\"target\":\"evil.example.com:$TP\",\"resolved\":\"evil.example.com:$TP\""
    refuses "a proxied decision for a name the policy does not allow" "$POL6" "$OUT/e4.log" "certificate for 'evil.example.com:"

    echo "== 7. close records =="
    pclose() { grep -o '"event":"proxy_close",[^}]*' "$OUT/d.log"; }
    pclose | sed 's/^/     /' | cut -c1-150
    DIALED=$(grep '"action":"net.proxy"' "$OUT/d.log" | grep '"rule":"proxy_dialed"' | grep -o '"proxy_conn":[0-9]*' | sort)
    CLOSED=$(pclose | grep -o '"proxy_conn":[0-9]*' | sort)
    check "every connection passed to the proxy has one proxy_close" \
        sh -c "[ -n '$DIALED' ] && [ '$DIALED' = '$CLOSED' ]"
    check "with the proxy's byte counts each way and the relay's time" \
        sh -c "[ \$(grep -o '\"event\":\"proxy_close\",[^}]*' '$OUT/d.log' | grep -c '\"why\":\"closed\",\"bytes_up\":[1-9][0-9]*,\"bytes_down\":[1-9][0-9]*,\"relay_ms\":[0-9]*,') -ge 5 ]"
    HC=$(grep '"action":"net.proxy"' "$OUT/d.log" | grep "\"target\":\"api.example.com:$HOLDP\"" | grep -o '"proxy_conn":[0-9]*' | grep -o '[0-9]*$')
    check "a relay still open when the run ends is closed then (run_end), with what it relayed" \
        sh -c "[ -n '$HC' ] && grep -q '\"event\":\"proxy_close\",\"run\":\"[0-9a-f]*\",\"proxy_conn\":$HC,\"why\":\"run_end\",\"bytes_up\":[1-9][0-9]*,\"bytes_down\":0,' '$OUT/d.log'"
    CC=$(grep '"action":"net.proxy"' "$OUT/d.log" | grep '"proxy_kind":"connect"' | grep -o '"proxy_conn":[0-9]*' | grep -o '[0-9]*$')
    TC=$(grep '"action":"net.proxy"' "$OUT/d.log" | grep '"proxy_kind":"tls"' | grep '"rule":"proxy_dialed"' | grep "\"target\":\"api.example.com:$TP\"" | grep -o '"proxy_conn":[0-9]*' | head -1 | grep -o '[0-9]*$')
    up() { grep -o "\"event\":\"proxy_close\",\"run\":\"[0-9a-f]*\",\"proxy_conn\":$1,[^}]*" "$OUT/d.log" | grep -o '"bytes_up":[0-9]*' | grep -o '[0-9]*$'; }
    check "a CONNECT's own request is not counted as sent to the server" \
        sh -c "[ -n '$CC' ] && [ -n '$TC' ] && [ \$(( $(up "$CC") - $(up "$TC") )) -lt 40 ]"
    forge "$OUT/d.log" "$OUT/c1.log" "\"event\":\"proxy_close\",\"run\":\"([0-9a-f]*)\",\"proxy_conn\":$TC," \
        "\"event\":\"proxy_close\",\"run\":\"\\1\",\"proxy_conn\":2," re
    refuses "a close of a connection never passed to the proxy" "$POL6" "$OUT/c1.log" "which was not passed to the proxy before it"
    refuses "a stream missing a close" "$POL6" "$OUT/c1.log" "never closed (a proxy_close is missing)"
    forge "$OUT/d.log" "$OUT/c2.log" '"why":"closed","bytes_up"' '"why":"unreported","bytes_up"'
    refuses "an unreported close with counts" "$POL6" "$OUT/c2.log" "an unreported close with counts"
    forge "$OUT/d.log" "$OUT/c3.log" '"why":"closed",' '"why":"vanished",'
    refuses "a close for no reason the proxy gives" "$POL6" "$OUT/c3.log" "a proxy_close for 'vanished'"
    # the proxy killed with a relay open: the run stops (fail closed), and the
    # relay is recorded unreported
    cat > "$W/hold.py" <<'PY'
import socket, ssl, sys, time
i, o = ssl.MemoryBIO(), ssl.MemoryBIO()
b = ssl.create_default_context().wrap_bio(i, o, server_hostname="api.example.com")
try: b.do_handshake()
except ssl.SSLWantReadError: pass
h = socket.create_connection(("api.example.com", int(sys.argv[1])), 10)
h.sendall(o.read())
time.sleep(30)
PY
    chmod 644 "$W/hold.py"
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$POL6" --dns-server "127.0.0.1:$PORT" -- \
        /usr/bin/python3 "$W/hold.py" "$HOLDP" > /dev/null 2> "$OUT/k7.log" &
    WPID=$!
    for _ in $(seq 100); do grep -q '"rule":"proxy_dialed"' "$OUT/k7.log" 2>/dev/null && break; sleep 0.1; done
    T0=$(date +%s)
    pkill -9 -u 65532 -f -- '--proxy-helper'
    wait "$WPID"; WRC=$?
    check "the proxy killed mid-relay: the run stops at once (fail closed)" \
        sh -c "[ $WRC != 0 ] && [ \$(( \$(date +%s) - $T0 )) -lt 10 ] && grep -q 'the egress proxy exited' '$OUT/k7.log'"
    check "and the open relay is recorded unreported" \
        grep -q '"event":"proxy_close","run":"[0-9a-f]*","proxy_conn":1,"why":"unreported","timestamp_ns"' "$OUT/k7.log"
    check "the audit accepts that run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL6" --checker "$CERT" "$OUT/k7.log"

    echo "== 8. the audit's cross-checks =="
    cat > "$W/udp.py" <<'PY'
import socket, sys
for host, port in (a.rsplit(":", 1) for a in sys.argv[1:]):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, int(port)))
        print("UDP", host, port, "CONNECTED", flush=True)
    except OSError as e:
        print("UDP", host, port, "ERR", e.errno, flush=True)
PY
    chmod 644 "$W/udp.py"
    POL8="$OUT/udp.policy"
    { sed -n 1,3p "$POL6"; printf 'allow host %s:%s\n' "$HOSTIP" "$HOLDP"; sed -n '4,$p' "$POL6"; } > "$POL8"
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$POL8" --dns-server "127.0.0.1:$PORT" -- \
        /usr/bin/python3 "$W/udp.py" "$HOSTIP:$TP" "$HOSTIP:$HOLDP" > "$OUT/u.out" 2> "$OUT/u.log"
    sed 's/^/     /' "$OUT/u.out"
    check "a UDP connect on a proxied port that a name allows is refused (proxy_tcp_only: QUIC goes nowhere)" \
        sh -c "grep -q '^UDP $HOSTIP $TP ERR 13$' '$OUT/u.out' && grep -q '\"target\":\"$HOSTIP:$TP\",[^}]*\"decision_final\":\"DENY\",\"rule\":\"proxy_tcp_only\"' '$OUT/u.log'"
    check "one a numeric rule allows is dialed (UDP has no hand-off)" \
        sh -c "grep -q '^UDP $HOSTIP $HOLDP CONNECTED$' '$OUT/u.out' && grep -q '\"target\":\"$HOSTIP:$HOLDP\",\"resolved\":\"$HOSTIP:$HOLDP\",\"decision_raw\":\"ALLOW\",\"decision_final\":\"ALLOW\",\"rule\":\"dialed_fd_injection\"' '$OUT/u.log'"
    check "the audit accepts that run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL8" --checker "$CERT" "$OUT/u.log"
    cp "$POL6" "$W/np.policy"; chmod 644 "$W/np.policy"
    env VAREK_WARDEN_NO_PIDNS=1 setpriv --reuid=65534 --regid=65534 --clear-groups "$WARDEN" "$W/np.policy" -- /bin/true > "$OUT/np.out" 2>&1
    check "the Warden does not run \`proxy on\` without its proxy (not as root)" \
        grep -q 'proxy on. needs the Warden to run as root' "$OUT/np.out"
    forge "$OUT/u.log" "$OUT/x1.log" '"proxy":\{[^}]*\},' '' re
    refuses "a run_start without the proxy the policy turns on" "$POL8" "$OUT/x1.log" "run_start's proxy None is not the policy's"
    forge "$OUT/u.log" "$OUT/x2.log" '"rule":"dialed_fd_injection","policy_line":4,"cert_rule":0,' \
                                     '"rule":"dialed_fd_injection","policy_line":5,"cert_rule":1,'
    refuses "a direct connect on a proxied port decided by a name rule" "$POL8" "$OUT/x2.log" "on a proxied port was dialed directly, not by a numeric rule"
    # section 4's run: its directly dialed numeric connect, recast as a hand-off
    forge "$OUT/h.log" "$OUT/x3.log" '("target":"192\.0\.2\.9:8443",)"resolved":"192\.0\.2\.9:8443",("decision_raw":"ALLOW","decision_final":"ALLOW",)"rule":"dial[a-z_]*",(.*)"resolution_generation":0,' \
        '\1"resolved":"127.0.0.1:'"$LP"'",\2"rule":"proxy_handoff",\3"resolution_generation":0,"proxy_handoff":true,"proxy_conn":77,' re
    refuses "a hand-off of a connect a numeric rule allows" "$POLH" "$OUT/x3.log" "allows by its address was handed to the proxy, not dialed"
    forge "$OUT/h.log" "$OUT/x4.log" '"dialed":"192.0.2.7:443","candidates":["192.0.2.7:443"]' '"dialed":"192.0.2.7:443","candidates":["192.0.2.8:443"]'
    refuses "a hand-off whose candidates are not its own" "$POLH" "$OUT/x4.log" "candidates do not begin with its target"
    forge "$OUT/h.log" "$OUT/x5.log" '"dialed":"192.0.2.7:443","candidates":["192.0.2.7:443"],"resolution_generation":0,"proxy_handoff":true' \
                                     '"dialed":"192.0.2.8:443","candidates":["192.0.2.8:443"],"resolution_generation":0,"proxy_handoff":true'
    refuses "a hand-off of a connect a rule denies (the policy asked again)" "$POLH" "$OUT/x5.log" "denies was handed to the proxy"

    echo "== 9. the upstream proxy =="
    if ! command -v squid > /dev/null && [ ! -x /usr/sbin/squid ]; then
        skip "the upstream proxy (Squid is not installed)"
    else
        SQUID=$(command -v squid || echo /usr/sbin/squid)
        SQ=/tmp/varek_v1260sq
        rm -rf "$SQ"; mkdir -p "$SQ"; chmod 777 "$SQ"
        SP=$((45500 + RANDOM % 3000))
        printf '%s api.example.com\n%s blocked.example.com\n' "$HOSTIP" "$HOSTIP" > "$SQ/hosts"
        { printf 'http_port %s:%s\n' "$HOSTIP" "$SP"
          printf 'acl blocked dstdomain blocked.example.com\nhttp_access deny blocked\nhttp_access allow all\n'
          printf 'hosts_file %s/hosts\naccess_log %s/access.log\ncache_log %s/cache.log\npid_filename %s/squid.pid\n' "$SQ" "$SQ" "$SQ" "$SQ"
          printf 'cache deny all\ncoredump_dir %s\nshutdown_lifetime 1 seconds\n' "$SQ"
        } > "$SQ/squid.conf"
        chmod 644 "$SQ"/*
        ( cd "$SQ" && "$SQUID" -N -f "$SQ/squid.conf" > "$SQ/out.log" 2>&1 & )
        for _ in $(seq 100); do python3 -c "import socket; socket.create_connection(('$HOSTIP', $SP), 0.2)" 2>/dev/null && break; sleep 0.1; done
        cat > "$W/up.py" <<'PY'
import socket, ssl, sys, urllib.request
TP, HP = int(sys.argv[1]), int(sys.argv[2])
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def tls(tag, where, sni):
    try:
        s = ctx.wrap_socket(socket.create_connection((where, TP), 10), server_hostname=sni)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        out = b""
        while True:
            d = s.recv(4096)
            if not d: break
            out += d
        print("TLS", tag, out.split(b"\r\n\r\n", 1)[-1].decode(), flush=True)
    except ssl.SSLError as e:
        print("TLS", tag, "ALERT" if "HANDSHAKE_FAILURE" in str(e).upper() else "SSLERR", flush=True)
    except OSError as e:
        print("TLS", tag, "ERR", e.errno, flush=True)
tls("allowed", "api.example.com", "api.example.com")
tls("upstream-refuses", "blocked.example.com", "blocked.example.com")
tls("policy-refuses", "api.example.com", "evil.example.com")     # api's address, another SNI
try:
    print("URLLIB", urllib.request.urlopen("http://api.example.com:%d/x.txt" % HP, timeout=10).read().decode().strip(), flush=True)
except Exception as e:
    print("URLLIB ERR", e, flush=True)
try:
    socket.getaddrinfo("squid.example.com", 80)
    print("SQUIDNAME resolves", flush=True)
except OSError:
    print("SQUIDNAME hidden", flush=True)
PY
        chmod 644 "$W/up.py"
        upol() {   # upol <upstream>: the policy chained to it
            printf 'require warden 1.26\nproxy on\nproxy ports %s %s\nproxy upstream %s\n' "$TP" "$HP" "$1"
            printf 'allow host api.example.com:%s\nallow host api.example.com:%s\nallow host blocked.example.com:%s\n' "$TP" "$HP" "$TP"
            printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path /etc/ssl/ readonly\nallow path %s/ readonly\n' "$W"
        }
        POLU="$OUT/up.policy"
        upol "http://$HOSTIP:$SP" > "$POLU"
        env -i PATH=/usr/bin:/bin timeout 90 "$WARDEN" "$POLU" --dns-server "127.0.0.1:$PORT" -- \
            /usr/bin/python3 "$W/up.py" "$TP" "$HP" > "$OUT/up.out" 2> "$OUT/up.log"
        sed 's/^/     /' "$OUT/up.out"
        sed 's/^/     squid: /' "$SQ/access.log" | cut -c1-110
        upx() { grep '"action":"net.proxy"' "$OUT/up.log" | grep "\"target\":\"$1\""; }
        check "run_start names the upstream" grep -q "\"proxy\":{[^}]*\"upstream\":\"$HOSTIP:$SP\"}" "$OUT/up.log"
        check "a name the policy allows is decided, asked of the upstream (CONNECT) and relayed through it" \
            sh -c "grep -q '^TLS allowed tls-ok api.example.com$' '$OUT/up.out' && grep -q 'TCP_TUNNEL/200 [0-9]* CONNECT api.example.com:$TP ' '$SQ/access.log'"
        check "recorded with the upstream used and its address dialed" \
            sh -c "$(declare -f upx); OUT='$OUT'; upx api.example.com:$TP | grep -q '\"rule\":\"proxy_dialed\",.*\"check\":\"ok\",\"dialed\":\"$HOSTIP:$SP\",\"proxy_conn\":[0-9]*,\"proxy_kind\":\"tls\",\"upstream\":\"$HOSTIP:$SP\"'"
        check "HTTP inside the tunnel" grep -q '^URLLIB http-ok$' "$OUT/up.out"
        check "the upstream's own refusal reaches the client and is recorded with its status (403)" \
            sh -c "grep -q '^TLS upstream-refuses ALERT$' '$OUT/up.out' && grep -q '\"why\":\"upstream_refused\",\"bytes_up\":0,\"bytes_down\":0,\"relay_ms\":[0-9]*,\"upstream_status\":403,' '$OUT/up.log'"
        check "a name the policy refuses never reaches the upstream" \
            sh -c "grep -q '^TLS policy-refuses ALERT$' '$OUT/up.out' && ! grep -q evil '$SQ/access.log' && grep '\"action\":\"net.proxy\"' '$OUT/up.log' | grep '\"target\":\"evil.example.com:$TP\"' | grep -q '\"decision_final\":\"DENY\"'"
        check "the audit accepts the run" \
            python3 "$HERE/tools/varek_audit.py" --policy "$POLU" --checker "$CERT" "$OUT/up.log"
        # the upstream by host name: the Warden resolves it (through its own
        # resolver), and the agent cannot look it up
        python3 - "$OUT/zone6.json" "$HOSTIP" <<'PY'
import json, sys
z = json.load(open(sys.argv[1])); z["squid.example.com"] = {"ttl": 30, "a": [sys.argv[2]]}
json.dump(z, open(sys.argv[1], "w"))
PY
        kill $DNSP 2>/dev/null
        rm -f "$OUT/ready6"
        python3 "$HERE/tests/dns_test_server.py" --port "$PORT" --zone "$OUT/zone6.json" --log "$OUT/q6.log" \
            --ready "$OUT/ready6" > /dev/null 2>&1 &
        DNSP=$!
        SRV="$SRV $DNSP"
        for _ in $(seq 50); do [ -e "$OUT/ready6" ] && break; sleep 0.1; done
        POLN="$OUT/upname.policy"
        upol "http://squid.example.com:$SP" > "$POLN"
        env -i PATH=/usr/bin:/bin timeout 90 "$WARDEN" "$POLN" --dns-server "127.0.0.1:$PORT" -- \
            /usr/bin/python3 "$W/up.py" "$TP" "$HP" > "$OUT/un.out" 2> "$OUT/un.log"
        check "an upstream by host name: resolved by the Warden (a resolution record), dialed by its address" \
            sh -c "grep -q '^TLS allowed tls-ok api.example.com$' '$OUT/un.out' && grep -q '\"event\":\"resolution\",\"run\":\"[0-9a-f]*\",\"name\":\"squid.example.com\",\"a\":\"ok\"' '$OUT/un.log' && grep '\"action\":\"net.proxy\"' '$OUT/un.log' | grep -q '\"dialed\":\"$HOSTIP:$SP\",.*\"upstream\":\"squid.example.com:$SP\"'"
        check "and kept out of the agent's views (it cannot look the upstream up)" grep -q '^SQUIDNAME hidden$' "$OUT/un.out"
        check "the audit accepts that run" \
            python3 "$HERE/tools/varek_audit.py" --policy "$POLN" --checker "$CERT" "$OUT/un.log"
        forge "$OUT/up.log" "$OUT/v1.log" "\"proxy_kind\":\"tls\",\"upstream\":\"$HOSTIP:$SP\"" "\"proxy_kind\":\"tls\",\"upstream\":\"192.0.2.66:$SP\""
        refuses "a proxied connection via another upstream" "$POLU" "$OUT/v1.log" "not the policy's"
        forge "$OUT/up.log" "$OUT/v2.log" "\"dialed\":\"$HOSTIP:$SP\"" "\"dialed\":\"$HOSTIP:$TP\""
        refuses "a proxied connection dialed past the upstream" "$POLU" "$OUT/v2.log" "not the upstream"
        forge "$OUT/up.log" "$OUT/v3.log" '"upstream_status":403,' ''
        refuses "an upstream refusal without its status" "$POLU" "$OUT/v3.log" "without the upstream's status"
        forge "$OUT/up.log" "$OUT/v4.log" ",\"upstream\":\"$HOSTIP:$SP\"}" "}"
        refuses "a run_start without the policy's upstream" "$POLU" "$OUT/v4.log" "run_start's proxy"
        kill "$(cat "$SQ/squid.pid" 2>/dev/null)" 2>/dev/null
        for _ in $(seq 30); do pgrep -f "$SQ/squid.conf" > /dev/null || break; sleep 0.2; done
        pkill -9 -f "$SQ/squid.conf" 2>/dev/null
        rm -rf "$SQ"
    fi
    kill $SRV 2>/dev/null
    rm -rf "$W"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1260: PASS ($skips skipped)"; exit 0; fi
echo "test_v1260: FAIL"; exit 1
