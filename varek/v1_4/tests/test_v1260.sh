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
trap 'rm -rf "$OUT"' EXIT

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

echo
if [ "$fail" = 0 ]; then echo "test_v1260: PASS ($skips skipped)"; exit 0; fi
echo "test_v1260: FAIL"; exit 1
