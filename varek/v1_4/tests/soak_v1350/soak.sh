#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# soak.sh — the v1.35 soak (docs/security/v1.35-frameworks.md, step 10): a
# framework agent held to its plan for 24 hours, then soak_check.py judges
# the run.
#
#   D  an OpenAI Agents SDK agent (agent_d.py: the SDK's own loop, its MCP
#      client and a function tool; a scripted model, so nothing reaches a
#      model provider), its plan written by `varek plan generate --from
#      openai-agents` under the Warden, then run under a policy that says
#      `require plan`, held to that plan (--hold-to-plan): the docs server
#      over HTTPS through the egress proxy in inspecting mode (tools/call by
#      name), the agent's files. Every tenth turn three probes, each a call
#      the policy allows and the plan does not name: each must be refused
#      as outside the plan.
#
# Run as root, from a checkout with the Warden built (make -C varek/v1_4
# all), with openssl, and a Python that has the OpenAI Agents SDK
# (adapters/requirements-frameworks.txt) and that nobody can read:
#
#   sudo varek/v1_4/tests/soak_v1350/soak.sh --python /opt/varek-fw/bin/python3 \
#       [--hours 24] [--interval 60] [--out DIR] [--sign-key KEY]
#
# It writes DIR/d/ and, at the end, DIR/report.txt. It holds the terminal
# for the whole run: start it with setsid nohup (README.md).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
V14="$(cd "$HERE/../.." && pwd)"
HOURS=24 INTERVAL=60 OUT="" KEY="" PY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --sign-key) KEY="$2"; shift 2 ;;
        --python) PY="$2"; shift 2 ;;
        *) echo "unknown option $1"; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "soak.sh: run as root (the Warden and its proxy need it)"; exit 2; }
[ -n "$PY" ] && [ -x "$PY" ] || { echo "soak.sh: --python PATH, a Python with the OpenAI Agents SDK"; exit 2; }
runuser -u nobody -- "$PY" -I -c 'import agents, httpx' 2> /dev/null ||
    { echo "soak.sh: $PY has no OpenAI Agents SDK that nobody can read (pip install -r adapters/requirements-frameworks.txt)"; exit 2; }
for b in warden warden-proxy tools/vdp_cert_check tools/vdp_check; do
    [ -x "$V14/$b" ] || { echo "soak.sh: build first: make -C $V14 all"; exit 2; }
done
OUT="${OUT:-/var/tmp/varek-soak-v1350-$(date +%Y%m%d-%H%M%S)}"
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
    echo "soak.sh: $OUT is not empty: give the soak a directory of its own (--out)"; exit 2
fi
D="$OUT/d"; AG="$D/agent"
mkdir -p "$AG/docs" "$AG/notes" "$D/outside"
chmod 755 "$OUT" "$D" "$AG" "$AG/docs" "$D/outside"; chown nobody "$AG/notes"; chmod 755 "$AG/notes"
cp "$HERE/agent_d.py" "$AG/"; chmod 644 "$AG/agent_d.py"
for n in plans holds audit; do echo "The $n document: words for the soak's word count." > "$AG/docs/$n.txt"; done
echo "not in the agent's plan" > "$D/outside/secret.txt"; chmod 644 "$AG/docs/"*.txt "$D/outside/secret.txt"
PIDS=""
trap 'kill $PIDS 2>/dev/null' EXIT

# --- the docs server, its certificate, DNS -------------------------------------
HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
PS=$((43000 + RANDOM % 5000))
U="https://docs.example.com:$PS/mcp"
DAYS=$(python3 -c "import math; print(math.ceil(float('$HOURS') / 24) + 1)")
( cd "$D" &&
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days "$DAYS" \
      -subj "/CN=VAREK v1.35 soak root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" &&
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout srv.key -out srv.csr -subj "/CN=docs.example.com" &&
  printf 'subjectAltName=DNS:docs.example.com,DNS:status.example.com\nextendedKeyUsage=serverAuth\n' > srv.ext &&
  openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out srv.pem -days "$DAYS" -extfile srv.ext ) \
    > "$D/certs.log" 2>&1 || { echo "soak.sh: openssl failed (d/certs.log)"; exit 1; }
chmod 600 "$D/ca.key" "$D/srv.key"
cat "$(python3 -c 'import ssl; print(ssl.get_default_verify_paths().openssl_cafile)')" "$D/ca.pem" > "$D/bundle.pem"
chmod 644 "$D/bundle.pem"
python3 "$HERE/mcp_docs.py" "$HOSTIP" "$PS" "$D/srv.pem" "$D/srv.key" "$D/server.jsonl" > "$D/server.out" 2>&1 &
PIDS="$PIDS $!"
DP=$((20000 + RANDOM % 20000))
printf '{"docs.example.com": {"ttl": 300, "a": ["%s"]}, "status.example.com": {"ttl": 300, "a": ["%s"]}}\n' \
    "$HOSTIP" "$HOSTIP" > "$D/zone.json"
python3 "$V14/tests/dns_test_server.py" --port "$DP" --zone "$D/zone.json" --log "$D/dns.log" --ready "$D/dns.ready" \
    > /dev/null 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 100); do
    [ -e "$D/dns.ready" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $PS), 0.2)" 2>/dev/null && break
    sleep 0.1
done
printf '{"mcp_url": "%s", "status_url": "https://status.example.com:%s/", "docs": "%s", "notes": "%s", "outside": "%s"}\n' \
    "$U" "$PS" "$AG/docs" "$AG/notes" "$D/outside/secret.txt" > "$AG/soak.json"
chmod 644 "$AG/soak.json"

# --- the plan, from the framework, under the Warden ----------------------------
VAREK_HOME="$V14" python3 "$V14/tools/varek" plan generate --python "$PY" --log "$D/generate.log" -o "$D/agent.plan" \
    --from openai-agents "$AG" --entry agent_d.py:agent --no-traces --file "$AG/docs/:ro" --file "$AG/notes/" \
    > "$D/generate.out" 2>&1 || { cat "$D/generate.out"; echo "soak.sh: varek plan generate failed"; exit 1; }

# --- the policy: more than the plan names (the probes' calls), and require plan
POL="$D/policy.txt"
{
    echo "# the v1.35 soak, run D (soak.sh)"
    echo "require warden 1.35"
    echo "require plan"
    echo "proxy inspect"
    echo "proxy ports $PS"
    for d in /usr/ /lib/ /lib64/ /etc/ /proc/self/; do echo "allow path $d readonly"; done
    echo "allow path exact /dev/null"
    echo "allow path exact /dev/urandom readonly"
    echo "allow path /tmp/"
    for f in /proc/stat /proc/cpuinfo /proc/meminfo /proc/sys/crypto/fips_enabled; do echo "allow path exact $f readonly"; done
    echo "allow path /sys/devices/system/cpu/ readonly"
    echo "allow path /sys/fs/cgroup/ readonly"
    "$PY" -I -c 'import os, sys
for d in dict.fromkeys(os.path.normpath(x) for x in (sys.prefix, sys.base_prefix, os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix))):
    if not (d in ("/", "/usr") or d.startswith(("/usr/", "/lib", "/etc/"))): print(f"allow path {d}/ readonly")'
    echo "allow exec $(readlink -f "$PY")"
    echo "allow path exact $AG readonly"
    echo "allow path $AG/ readonly"
    echo "allow path $AG/notes/"
    echo "allow path $D/outside/ readonly"
    echo "allow host docs.example.com:$PS"
    echo "allow host status.example.com:$PS"
    echo "allow mcp $U initialize"
    echo "allow mcp $U notifications/initialized"
    echo "allow mcp $U tools/list"
    echo "allow mcp $U tools/call search_*"
    echo "allow mcp $U tools/call get_*"
} > "$POL"
chmod 644 "$POL"
python3 "$V14/tools/varek" policy check "$POL" --plan "$D/agent.plan" > "$D/plan-check.out" 2>&1 ||
    { cat "$D/plan-check.out"; echo "soak.sh: the plan is not authorized under the soak's policy"; exit 1; }
WOPTS=(--plan "$D/agent.plan" --hold-to-plan --dns-server "127.0.0.1:$DP" --trust-bundle "$D/bundle.pem")
[ -n "$KEY" ] && WOPTS+=(--sign-key "$KEY")

# --- the run --------------------------------------------------------------------
echo "soak.sh: run D for $HOURS h, a turn each ${INTERVAL}s, in $OUT (started $(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z'))"
( printf 't\twarden\tproxy\tagent\n'
  while sleep 300; do
      w=$(pgrep -fx "$V14/warden $POL.*" | head -1); px=$(pgrep -fx 'warden-proxy [0-9]+:[0-9]+' | head -1)
      ag=$(pgrep -f "agent_d.py --hours" | tail -1)
      rss() { [ -n "$1" ] && awk '/^VmRSS/ {print $2}' "/proc/$1/status" 2>/dev/null || echo -; }
      printf '%s\t%s\t%s\t%s\n' "$(date +%s)" "$(rss "$w")" "$(rss "$px")" "$(rss "$ag")"
  done ) > "$D/rss.tsv" &
PIDS="$PIDS $!"
env -i PATH=/usr/bin:/bin HOME=/nonexistent "$V14/warden" "$POL" "${WOPTS[@]}" -- \
    "$PY" "$AG/agent_d.py" --hours "$HOURS" --interval "$INTERVAL" > "$D/agent.jsonl" 2> "$D/verdicts.log"
echo "$?" > "$D/exit"

# --- the judgement ------------------------------------------------------------------
python3 "$HERE/soak_check.py" --dir "$OUT" --v14 "$V14" --hours "$HOURS" --interval "$INTERVAL" ${KEY:+--sign-key "$KEY"} \
    | tee "$OUT/report.txt"
exit "${PIPESTATUS[0]}"
