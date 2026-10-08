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
#      allowed on another port keeps its real addresses; a connect to a
#      synthetic address is refused until the hand-off (step 4); the audit
#      accepts the run and refuses forged synthetic records
#
# Usage: test_v1260.sh <vdp_check> <vdp_cert_check> [<warden>]
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
    check "a connect to the synthetic address is refused until the hand-off (synthetic_address)" \
        sh -c "grep -q '^REFUSED 13$' '$OUT/s.out' && grep -q '\"target\":\"198.18.0.1:443\",[^}]*\"decision_final\":\"DENY\",\"rule\":\"synthetic_address\"' '$OUT/s.log'"
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

    forge() {   # forge <in> <out> <python expression on body>: rewrite the first record matching, rechain
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
    forge "$OUT/s1.log" "$OUT/f4.log" '"target":"198.18.0.1:443","resolved":"198.18.0.1:443","decision_raw":"DENY","decision_final":"DENY","rule":"synthetic_address"' \
                                      '"target":"198.18.0.1:443","resolved":"198.18.0.1:443","decision_raw":"ALLOW","decision_final":"ALLOW","rule":"dialed_fd_injection"'
    refuses "a dialed connect to a synthetic address" "$POL" "$OUT/f4.log" "a connect to the synthetic address 198.18.0.1 was dialed"
    kill "$DNSPID" 2>/dev/null
    rm -rf "$W"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1260: PASS ($skips skipped)"; exit 0; fi
echo "test_v1260: FAIL"; exit 1
