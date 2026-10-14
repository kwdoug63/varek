#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# soak.sh — the shared soak of v1.28.1, v1.29.0 and v1.31.0: three runs of
# the Warden side by side for 24 hours, then soak_check.py judges them.
#
#   A  (v1.28.1, v1.31.0) an agent on behalf of a user whose token the
#      Warden verified, the egress proxy in inspecting mode: two confined MCP
#      servers it launches once and keeps (fs reads project files, gh calls a
#      remote MCP server with the run's MCP token), MCP calls of its own,
#      and sub-agents (coder launches tester). Every tenth turn a probe.
#      The user's token expires near the end: the run is revoked by it.
#      The OCSF export follows the stream the whole run.
#   B  (v1.29.0) `varek run` with nothing set up: the baseline policy and the
#      python profile, an agent's work in its project directory (files,
#      python3, git). Every tenth turn a probe.
#   C  (v1.29.0) the same work as a dry run of a narrower policy (the project
#      read-only but for build/ and .git/): every call the policy refuses is
#      recorded and let through. At the end `varek policy suggest` drafts a
#      policy from it, and a short dry run under the draft refuses nothing.
#
# Run as root on the droplet, from a checkout with the Warden and the test
# program built (make -C varek/v1_4 all tests/v1281_sub), with
# python3-cryptography, openssl and git installed:
#
#   sudo varek/v1_4/tests/soak_shared/soak.sh [--hours 24] [--interval 60] [--out DIR] [--sign-key KEY]
#
# It writes DIR/{a,b,c}/ and, at the end, DIR/report.txt. It holds the
# terminal for the whole run: start it with setsid nohup (see README.md).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
V14="$(cd "$HERE/../.." && pwd)"
HOURS=24 INTERVAL=60 OUT="" KEY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --sign-key) KEY="$2"; shift 2 ;;
        *) echo "unknown option $1"; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "soak.sh: run as root (the Warden, its proxy and warden-secrets need it)"; exit 2; }
for b in warden warden-proxy warden-secrets tools/vdp_cert_check tools/vdp_check tools/varek_keygen tests/v1281_sub; do
    [ -x "$V14/$b" ] || { echo "soak.sh: build first: make -C $V14 all tests/v1281_sub"; exit 2; }
done
python3 -c 'import cryptography' 2>/dev/null || { echo "soak.sh: needs python3-cryptography (apt-get install -y python3-cryptography)"; exit 2; }
for c in openssl git; do command -v "$c" > /dev/null || { echo "soak.sh: needs $c (apt-get install -y $c)"; exit 2; }; done
CGM="$(awk '$3 == "cgroup2" { print $2; exit }' /proc/self/mounts)"
[ -n "$CGM" ] || { echo "soak.sh: needs cgroup v2 (the sub-agents and the MCP servers run in control groups)"; exit 2; }
id nobody > /dev/null 2>&1 || { echo "soak.sh: needs the user nobody"; exit 2; }
SECS=$(python3 -c "print(int(float('$HOURS') * 3600))")
# run A's revocation: the user's token expires LEAD seconds before the end
LEAD=$(python3 -c "print(int(min(max(5 * float('$INTERVAL'), 30), $SECS / 2)))")
[ $((SECS - LEAD)) -ge 90 ] || { echo "soak.sh: --hours too short (the user's token must last 90 s at least)"; exit 2; }
# a run may launch 1024 sub-agents: run A launches two each fifth task
python3 -c "import sys; sys.exit(0 if 0.36 * $SECS / float('$INTERVAL') + 2 < 1000 else 1)" ||
    { echo "soak.sh: --interval too short for $HOURS h (run A would launch more than the 1024 sub-agents a run may)"; exit 2; }
OUT="${OUT:-/var/tmp/varek-soak-shared-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT/a" "$OUT/b/work" "$OUT/b/outside" "$OUT/c/work" "$OUT/as"
chmod 755 "$OUT" "$OUT/a" "$OUT/b" "$OUT/c" "$OUT/as"
chmod 1777 "$OUT/b/outside"                  # its owner's rights would let the agent write: only the policy refuses
chown nobody "$OUT/b/work" "$OUT/c/work"
AG=/opt/varek-soak-shared                    # the agents' files, read-only to them
S=/etc/varek-soak-shared                     # the tokens: root's alone
mkdir -p "$AG/bin" "$AG/srv" "$AG/proj" "$S"; chmod 755 "$AG" "$AG/bin" "$AG/srv" "$AG/proj"; chmod 700 "$S"
cp "$HERE/agent_a.py" "$HERE/build_agent.py" "$AG/"; chmod 644 "$AG/agent_a.py" "$AG/build_agent.py"
cp "$HERE/fs_server.py" "$HERE/gh_server.py" "$AG/srv/"; chmod 755 "$AG/srv/fs_server.py" "$AG/srv/gh_server.py"
for n in coder tester; do cp "$V14/tests/v1281_sub" "$AG/bin/$n"; chmod 755 "$AG/bin/$n"; done
echo "project file a" > "$AG/proj/a"; echo "project file b" > "$AG/proj/b"
echo "the agent's own" > "$AG/agent_only"; echo "fs's own" > "$AG/srv_only"
chmod 644 "$AG/proj/a" "$AG/proj/b" "$AG/agent_only" "$AG/srv_only"
for d in b c; do printf 'A project for the shared soak (run %s).\n' "$d" > "$OUT/$d/work/README"; chmod 644 "$OUT/$d/work/README"; done
PIDS=""
trap 'kill $PIDS 2>/dev/null' EXIT

# --- run A's stand-ins: the user's issuer, the remote MCP server, DNS --------
python3 "$V14/tests/v1310_as.py" serve "$OUT/as" > "$OUT/as/serve.out" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 100); do [ -s "$OUT/as/port" ] && break; sleep 0.1; done
[ -s "$OUT/as/port" ] || { echo "soak.sh: the issuer stand-in did not start (as/serve.out)"; exit 1; }
AP="$(cat "$OUT/as/port")"; AB="https://localhost:$AP"
chmod 644 "$OUT/as/ca.pem"                   # read by warden-secrets as its own user
printf 'oidc_ca = %s/ca.pem\n' "$OUT/as" > "$S/secrets.conf"; chmod 600 "$S/secrets.conf"
HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
PS=$((43000 + RANDOM % 5000))
U="https://mcp.example.com:$PS/mcp"
DAYS=$(python3 -c "import math; print(math.ceil(float('$HOURS') / 24) + 1)")
( cd "$OUT/a" &&
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout mcpca.key -out mcpca.pem -days "$DAYS" \
      -subj "/CN=VAREK shared soak MCP root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" &&
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout mcp.key -out mcp.csr -subj "/CN=mcp.example.com" &&
  printf 'subjectAltName=DNS:mcp.example.com\nextendedKeyUsage=serverAuth\n' > mcp.ext &&
  openssl x509 -req -in mcp.csr -CA mcpca.pem -CAkey mcpca.key -CAcreateserial -out mcp.pem -days "$DAYS" -extfile mcp.ext ) \
    > "$OUT/a/certs.log" 2>&1 || { echo "soak.sh: openssl failed (a/certs.log)"; exit 1; }
chmod 600 "$OUT/a/mcpca.key" "$OUT/a/mcp.key"
cat "$(python3 -c 'import ssl; print(ssl.get_default_verify_paths().openssl_cafile)')" "$OUT/a/mcpca.pem" > "$OUT/a/bundle.pem"
chmod 644 "$OUT/a/bundle.pem"
# the run's MCP token (for the remote server, lasting past the run) and the
# user's token (expiring LEAD seconds before the end: it revokes the run)
mint() { python3 "$V14/tests/v1310_as.py" mint "$OUT/as" "$@"; }
mint "$AB/as" "$U" $((SECS + 7200)) > "$S/mt" && mint "$AB/oidc" api://varek-soak $((SECS - LEAD)) > "$S/utok" ||
    { echo "soak.sh: could not mint the tokens"; exit 1; }
chmod 600 "$S/mt" "$S/utok"
python3 -c "import json, sys; json.dump({'mt': open(sys.argv[1]).read().strip(), 'user': open(sys.argv[2]).read().strip()}, open(sys.argv[3], 'w'))" \
    "$S/mt" "$S/utok" "$S/values.json"
chmod 600 "$S/values.json"
python3 "$HERE/soak_remote.py" "$HOSTIP" "$PS" "$OUT/a/mcp.pem" "$OUT/a/mcp.key" "$S/values.json" "$OUT/a/remote.jsonl" \
    > "$OUT/a/remote.out" 2>&1 &
PIDS="$PIDS $!"
DP=$((20000 + RANDOM % 20000))
printf '{"mcp.example.com": {"ttl": 300, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/a/zone.json"
python3 "$V14/tests/dns_test_server.py" --port "$DP" --zone "$OUT/a/zone.json" --log "$OUT/a/dns.log" --ready "$OUT/a/dns.ready" \
    > /dev/null 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 100); do
    [ -e "$OUT/a/dns.ready" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $PS), 0.2)" 2>/dev/null && break
    sleep 0.1
done

# --- run A's policy -----------------------------------------------------------
POLA="$OUT/a/policy.txt"
SL="/usr/ /lib /lib64"
{
    echo "# the shared soak, run A (soak.sh)"
    echo "require warden 1.31"
    echo "proxy inspect"
    echo "proxy ports $PS"
    echo "trust issuer $AB/oidc audience api://varek-soak"
    echo "require on-behalf-of"
    echo "credential mt from file:$S/mt audience=$U"
    echo "mcp server fs exec $AG/srv/fs_server.py sha256=$(sha256sum "$AG/srv/fs_server.py" | cut -d' ' -f1)"
    echo "mcp server gh exec $AG/srv/gh_server.py sha256=$(sha256sum "$AG/srv/gh_server.py" | cut -d' ' -f1)"
    echo "allow exec $AG/bin/coder subagent=coder"
    echo "allow exec $AG/bin/tester subagent=tester"
    echo "# the agent's own"
    echo "allow host mcp.example.com"
    echo "allow mcp $U tools/list"
    echo "allow mcp $U tools/call search_*"
    echo "deny mcp $U tools/call delete_*"
    for d in $SL; do echo "allow path $d readonly"; done
    echo "allow path exact /etc/ld.so.cache readonly"
    echo "allow path /etc/ssl/ readonly"
    echo "allow path exact $AG/agent_a.py readonly"
    echo "allow path $AG/proj/ readonly"
    echo "allow path exact $AG/agent_only readonly"
    echo "# fs: project files"
    echo "allow exec /usr/bin/python3 for=fs"
    echo "allow path exact $AG/srv/fs_server.py readonly for=fs"
    echo "allow path $AG/proj/ readonly for=fs"
    echo "allow path exact $AG/srv_only readonly for=fs"
    for d in $SL; do echo "allow path $d readonly for=fs"; done
    echo "allow path exact /etc/ld.so.cache readonly for=fs"
    echo "# gh: the remote MCP server, with the run's MCP token"
    echo "allow exec /usr/bin/python3 for=gh"
    echo "allow path exact $AG/srv/gh_server.py readonly for=gh"
    for d in $SL; do echo "allow path $d readonly for=gh"; done
    echo "allow path exact /etc/ld.so.cache readonly for=gh"
    echo "allow path /etc/ssl/ readonly for=gh"
    echo "allow host mcp.example.com for=gh"
    echo "allow mcp $U tools/call get_* credential=mt for=gh"
    echo "deny mcp $U tools/call delete_* for=gh"
} > "$POLA"
chmod 644 "$POLA"
WOPTS=(--secrets-conf "$S/secrets.conf" --dns-server "127.0.0.1:$DP" --trust-bundle "$OUT/a/bundle.pem" --on-behalf-of "$S/utok")
[ -n "$KEY" ] && WOPTS+=(--sign-key "$KEY")
"$V14/warden" "$POLA" "${WOPTS[@]}" --check-credentials > "$OUT/a/check.out" 2>&1 ||
    { cat "$OUT/a/check.out"; echo "soak.sh: run A's Warden would not start"; exit 1; }

# --- runs B and C: varek run, kept apart from the host's own VAREK files ------
venv() { local d="$1"; shift
         env -i PATH=/usr/bin:/bin NO_COLOR=1 VAREK_CONFIG="$OUT/$d/etc/varek.conf" VAREK_LIB_DIR="$OUT/$d/lib" \
             VAREK_LOG_DIR="$OUT/$d/log" "$@"; }
BOPTS=(--interval "$INTERVAL" --seconds "$SECS")
# C's policy: the baseline varek run would write for C's directory, the
# project read-only but for build/ and .git/
( cd "$OUT/c/work" && venv c python3 "$V14/tools/varek" run --baseline --show-policy --profile python --run-as nobody \
      -- python3 "$AG/build_agent.py" ) > "$OUT/c/baseline.txt" 2> "$OUT/c/baseline.err" ||
    { cat "$OUT/c/baseline.err"; echo "soak.sh: varek run --show-policy failed"; exit 1; }
python3 - "$OUT/c/baseline.txt" "$OUT/c/work" "$OUT/c/narrow.txt" <<'PY' || { echo "soak.sh: could not write C's policy"; exit 1; }
import sys
src, cwd, dst = sys.argv[1:]
out, n = [], 0
for line in open(src).read().splitlines():
    if line.startswith("#@"):
        continue
    if line == f"allow path {cwd}/":
        out += [f"allow path {cwd}/build/", f"allow path {cwd}/.git/", f"allow path {cwd}/ readonly"]
        n += 1
        continue
    out.append(line)
if n != 1:
    sys.exit("no working-directory rule in the baseline")
open(dst, "w").write("# the shared soak, run C (soak.sh): the baseline, the project read-only but build/ and .git/\n"
                     + "\n".join(out) + "\n")
PY
chmod 644 "$OUT/c/narrow.txt"

# --- the three runs -----------------------------------------------------------
echo "soak.sh: $HOURS h, a turn every $INTERVAL s (every tenth a probe in A and B), A revoked by its user's token $LEAD s before the end, into $OUT"
T0=$(date +%s)
env -i PATH=/usr/bin:/bin "$V14/warden" "$POLA" "${WOPTS[@]}" -- \
    /usr/bin/python3 "$AG/agent_a.py" --interval "$INTERVAL" --seconds "$SECS" --port "$PS" --dir "$AG" --store "$S/mt" \
    > "$OUT/a/agent.jsonl" 2> "$OUT/a/verdicts.log" &
WA=$!
( cd "$OUT/b/work" && venv b python3 "$V14/tools/varek" run --profile python --run-as nobody --log "$OUT/b/verdicts.log" \
      -- python3 "$AG/build_agent.py" "${BOPTS[@]}" --outside "$OUT/b/outside" --probe-every 10 ) > "$OUT/b/agent.jsonl" 2> "$OUT/b/varek.err" &
WB=$!
( cd "$OUT/c/work" && venv c python3 "$V14/tools/varek" run --dry-run --policy "$OUT/c/narrow.txt" --run-as nobody \
      --log "$OUT/c/verdicts.log" -- python3 "$AG/build_agent.py" "${BOPTS[@]}" --outside "$OUT/c/work" ) \
    > "$OUT/c/agent.jsonl" 2> "$OUT/c/varek.err" &
WC=$!
# the OCSF export follows A's stream until its run_end
python3 "$V14/tools/varek_ocsf.py" --follow "$OUT/a/verdicts.log" --policy "$POLA" --checker "$V14/tools/vdp_cert_check" \
    -o "$OUT/a/events.jsonl" > "$OUT/a/ocsf.out" 2>&1 &
WO=$!
# each process's memory, every ten turns (and once at the start)
SAMPLE=$(python3 -c "print(max(int(10 * float('$INTERVAL')), 30))")
( printf 't\twarden_a\tproxy_a\tsecrets_a\tfs\tgh\twarden_b\twarden_c\n'
  sleep 5
  rss() { [ -n "$1" ] && ps -o rss= -p "$1" 2>/dev/null | tr -d ' '; }
  while kill -0 "$WA" 2>/dev/null || kill -0 "$WB" 2>/dev/null || kill -0 "$WC" 2>/dev/null; do
      px=$(pgrep -fx 'warden-proxy [0-9]+:[0-9]+' | head -1); sx=$(pgrep -fx 'warden-secrets [0-9]+:[0-9]+' | head -1)
      fs=$(pgrep -f "^/usr/bin/python3 $AG/srv/fs_server.py\$" | head -1); gh=$(pgrep -f "^/usr/bin/python3 $AG/srv/gh_server.py " | head -1)
      wb=$(pgrep -f "^$V14/warden $OUT/b/lib/" | head -1); wc=$(pgrep -f "^$V14/warden $OUT/c/narrow.txt" | head -1)
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$(rss "$WA")" "$(rss "$px")" "$(rss "$sx")" \
          "$(rss "$fs")" "$(rss "$gh")" "$(rss "$wb")" "$(rss "$wc")"
      sleep "$SAMPLE"
  done ) > "$OUT/rss.tsv" &
PIDS="$PIDS $!"
wait "$WA"; RA=$?
wait "$WB"; RB=$?
wait "$WC"; RC=$?
echo "soak.sh: the runs finished (A exit $RA, B exit $RB, C exit $RC)"
for _ in $(seq 60); do kill -0 "$WO" 2>/dev/null || break; sleep 1; done
kill "$WO" 2>/dev/null

# --- C's draft: varek policy suggest, then a short dry run under it ------------
( cd "$OUT/c/work" && venv c python3 "$V14/tools/varek" policy suggest "$OUT/c/verdicts.log" -o "$OUT/c/draft.txt" ) \
    > "$OUT/c/suggest.out" 2> "$OUT/c/suggest.err"
if [ -s "$OUT/c/draft.txt" ]; then
    chmod 644 "$OUT/c/draft.txt"
    ( cd "$OUT/c/work" && venv c python3 "$V14/tools/varek" run --dry-run --policy "$OUT/c/draft.txt" --run-as nobody \
          --log "$OUT/c/draft.log" -- python3 "$AG/build_agent.py" --interval 1 --seconds 12 --outside "$OUT/c/work" ) \
        > "$OUT/c/draft.jsonl" 2> "$OUT/c/draft.err"
fi

PK=()
[ -n "$KEY" ] && [ -e "$KEY.pub" ] && PK=(--pubkey "$KEY.pub")
python3 "$HERE/soak_check.py" --dir "$OUT" --checker "$V14/tools/vdp_cert_check" --vdp "$V14/tools/vdp_check" \
    --values "$S/values.json" --hours "$HOURS" --interval "$INTERVAL" --lead "$LEAD" --dir-ag "$AG" "${PK[@]}"
