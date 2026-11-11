#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# varek_audit_demo.sh: reproduce VAREK's audit-reconstructibility claim
# end to end, on your own machine.
#
#   "AgentCore can tell you which policy said yes. VAREK can prove, later,
#    why yes was correct for the action that actually ran."
#
# What it does:
#   1. Clones VAREK at a release tag (default v1.36.3) and builds it.
#   2. Runs an agent under the Warden twice, with a signing key and an
#      anchor file:
#        Part 1: file opens (allowed, denied, UNKNOWN)
#        Part 2: a direct TCP connect, MCP tool calls and HTTPS requests
#                through the inspecting egress proxy
#   3. Copies only four artifacts to a separate "later" folder (the verdict
#      log, the policy file, the public key and the anchor) and audits the
#      run from those alone.
#   4. Tampers with the evidence in every way listed below and shows which
#      check catches each one. The final rows bypass the cryptography
#      entirely (the attacker's own key is trusted and there is no anchor),
#      so only the proof itself stands between a forgery and a PASS.
#
# Where to run it: a disposable Linux x86_64 VM or cloud instance where you
# are root (Ubuntu 24.04 or Fedora tested), with internet access to GitHub.
# The Warden uses seccomp user-notify, network namespaces and Landlock, so it
# needs root and a recent kernel. It does not work inside an unprivileged
# container or on macOS.
#
# Usage (as root):
#   sudo bash varek_audit_demo.sh --install-deps    # first run: installs build deps
#   sudo bash varek_audit_demo.sh                   # later runs
#
# Environment:
#   VAREK_REF   tag or branch to test (default v1.36.3)
#   VAREK_SRC   use an existing checkout instead of cloning
#   WORK        working folder (default ./varek-audit-demo)
#
# Exit status 0 only if every row came out as expected.
set -u

REF="${VAREK_REF:-v1.36.3}"
WORK="$(realpath -m "${WORK:-$PWD/varek-audit-demo}")"
INSTALL=0
[ "${1:-}" = "--install-deps" ] && INSTALL=1

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

# ---------------------------------------------------------------- preflight
say "Preflight"
[ "$(id -u)" = 0 ] || die "run as root (sudo bash $0)"
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || die "needs Linux on x86_64"
if [ "$INSTALL" = 1 ]; then
    if command -v apt-get >/dev/null; then
        apt-get update -qq && apt-get install -y -qq git build-essential libseccomp-dev libsodium-dev libssl-dev \
            python3 python3-cryptography openssl >/dev/null || die "apt-get install failed"
    elif command -v dnf >/dev/null; then
        dnf install -y -q git gcc make libseccomp-devel libsodium-devel openssl-devel glibc-static \
            python3 python3-cryptography openssl >/dev/null || die "dnf install failed"
    else die "install git, gcc, make, libseccomp, libsodium and OpenSSL dev packages, python3, python3-cryptography, openssl"; fi
fi
for c in git gcc make python3 openssl; do command -v "$c" >/dev/null || die "missing $c (rerun with --install-deps)"; done
python3 -c 'import cryptography' 2>/dev/null || die "missing the Python cryptography package (rerun with --install-deps)"
echo "kernel $(uname -r), $(. /etc/os-release; echo "$PRETTY_NAME")"

rm -rf "$WORK"; mkdir -p "$WORK/evidence"
EV="$WORK/evidence"
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

# ------------------------------------------------------------ clone + build
say "Build VAREK ($REF)"
if [ -n "${VAREK_SRC:-}" ]; then SRC="$(realpath "$VAREK_SRC")"
else
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$REF" https://github.com/kwdoug63/varek.git "$WORK/varek" || die "git clone failed"
    SRC="$WORK/varek"
fi
echo "commit $(git -C "$SRC" rev-parse HEAD)"
T="$SRC/varek/v1_4"
( cd "$T" && make -s warden warden-proxy warden-secrets tools/vdp_cert_check tools/varek_keygen tests/v1150_probe ) \
    > "$EV/build.log" 2>&1 || { tail -20 "$EV/build.log"; die "build failed (see $EV/build.log)"; }
echo "built: warden, warden-proxy, the certificate checker, the key generator"
"$T/tools/varek_keygen" "$EV/warden" > /dev/null || die "keygen failed"
echo "signing key: $EV/warden (private), $EV/warden.pub (public)"

# ------------------------------------------------------------ helpers
cat > "$WORK/edit.py" <<'EOF'
# edit.py LOG SEQ KEY=VALUE ...   rewrite fields of one record (kept before the chain value)
# edit.py LOG SEQ --drop          remove the record
import json, sys
src, seq, kv = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
for l in open(src):
    s = l.rstrip("\n")
    if s.startswith("{"):
        r = json.loads(s)
        if r.get("seq") == seq:
            if kv == ["--drop"]:
                continue
            tail = {k: r.pop(k) for k in ("chain", "sig") if k in r}
            for p in kv:
                k, v = p.split("=", 1)
                r[k] = int(v) if v.lstrip("-").isdigit() else v
            r.update(tail)
            s = json.dumps(r, separators=(",", ":"))
    print(s)
EOF
cat > "$WORK/find.py" <<'EOF'
# find.py LOG ACTION DECISION SUBSTRING [FIELD]   print FIELD (default seq) of the first match
import json, sys
log, act, dec, sub = sys.argv[1:5]
f = sys.argv[5] if len(sys.argv) > 5 else "seq"
for l in open(log):
    if l.startswith("{"):
        r = json.loads(l)
        if r.get("action") == act and r.get("decision_final") == dec and sub in r.get("target", ""):
            print(r.get(f, "")); break
EOF
pk() { python3 -c "import json,sys;print(next(json.loads(l)['log_pubkey'] for l in open(sys.argv[1]) if '\"run_start\"' in l[:40]))" "$1"; }
fnd() { python3 "$WORK/find.py" "$@"; }
python3 -c "import os;print(os.urandom(32).hex())" > "$WORK/attacker.seed"

ROWS=0 OK=0
row() {   # row EXPECT LABEL -- audit args...
    local expect="$1" label="$2"; shift 3
    local out="$EV/audit_$(printf '%02d' $((ROWS + 1))).txt" rc got why
    python3 -I "$T/tools/varek_audit.py" --checker "$T/tools/vdp_cert_check" "$@" > "$out" 2>&1; rc=$?
    if [ "$rc" = 0 ]; then got=PASS; else got=FAIL; fi
    why="$(grep -E 'PROBLEM|FAIL:' "$out" | head -1 | sed -E 's/^ *PROBLEM //; s/^varek_audit: FAIL: varek_cyclonedx: [^:]*:[0-9]*: //' | cut -c1-90)"
    ROWS=$((ROWS + 1))
    if [ "$got" = "$expect" ]; then OK=$((OK + 1)); mark="ok"; else mark="UNEXPECTED"; fi
    printf '  %-3s %-62s %-5s %-10s %s\n' "$ROWS" "$label" "$got" "$mark" "${why:-}"
}
forge() {  # forge LOG OUT SEQ KEY=VALUE... : edit, recompute the chain, re-sign with the attacker's key
    local log="$1" out="$2"; shift 2
    python3 "$WORK/edit.py" "$log" "$@" > "$out.edited"
    python3 -I "$T/tests/log_rechain.py" --resign "$WORK/attacker.seed" "$out.edited" > "$out"
}
header() { printf '\n  %-3s %-62s %-5s %-10s %s\n' "#" "Change made to the saved evidence" "Audit" "" "Reason the audit gives"; }

# ------------------------------------------------------------ part 1: files
say "Part 1: live run, file opens (signed and anchored)"
F=/tmp/varek_v1150
rm -rf "$F"; mkdir -p "$F/work/x" "$F/logs" "$F/shared/c" "$F/secret" "$F/pub"
for f in work/k.pem work/x/.inject logs/app.log shared/c/data.bin secret/.inject pub/.inject; do echo content > "$F/$f"; done
P1="$EV/part1"; mkdir -p "$P1"; cp "$T/tests/v1150_policy.txt" "$P1/policy.txt"
( cd "$P1" && timeout 60 "$T/warden" policy.txt --sign-key "$EV/warden" --anchor anchor --checkpoint-every 4 \
    -- "$T/tests/v1150_probe" > agent.out 2> verdicts.log ) || die "part 1 run failed (see $P1)"
sed 's/^/    agent: /' "$P1/agent.out"

L1="$EV/part1_later"; mkdir -p "$L1"; cp "$P1/verdicts.log" "$P1/policy.txt" "$P1/anchor" "$EV/warden.pub" "$L1/"
cd "$L1"
SA=$(fnd verdicts.log file.open ALLOW /logs/app.log)
SC=$(fnd verdicts.log file.open ALLOW /shared/c/)
SD=$(fnd verdicts.log file.open DENY /work/k.pem)
CR=$(fnd verdicts.log file.open ALLOW /shared/c/ cert_rule)
sed 's#^deny  path suffix .pem#allow path suffix .pem#' policy.txt > policy_loosened.txt
python3 "$WORK/edit.py" verdicts.log "$SA" target=$F/secret/payroll.db resolved=$F/secret/payroll.db > retarget.log
python3 -I "$T/tests/log_rechain.py" retarget.log > retarget_rechained.log
python3 "$WORK/edit.py" verdicts.log "$SD" --drop > drop.log; python3 -I "$T/tests/log_rechain.py" drop.log > drop_rechained.log
grep -v '"event":"run_end"' verdicts.log > truncated.log
"$T/tools/varek_keygen" other > /dev/null
python3 -I "$T/tests/log_rechain.py" --resign "$WORK/attacker.seed" retarget.log > resigned.log
python3 -I "$T/tests/log_rechain.py" --resign "$WORK/attacker.seed" verdicts.log > ctrl.log
forge verdicts.log forged_cert.log "$SC" cert_rule=$((CR + 1))
forge verdicts.log forged_target.log "$SA" target=$F/secret/payroll.db resolved=$F/secret/payroll.db

say "Part 1: audit from the 'later' folder (log, policy, public key, anchor only)"
header
row PASS "Clean run: pinned public key + anchor"                       -- --policy policy.txt --pubkey warden.pub --anchor anchor verdicts.log
row FAIL "Policy file loosened after the run"                          -- --policy policy_loosened.txt --pubkey warden.pub --anchor anchor verdicts.log
row FAIL "ALLOW record retargeted to secret/payroll.db"                -- --policy policy.txt --pubkey warden.pub --anchor anchor retarget.log
row FAIL "Same edit, hash chain recomputed"                            -- --policy policy.txt --pubkey warden.pub --anchor anchor retarget_rechained.log
row FAIL "DENY record deleted, chain recomputed"                       -- --policy policy.txt --pubkey warden.pub --anchor anchor drop_rechained.log
row FAIL "Log cut short (run_end removed)"                             -- --policy policy.txt --pubkey warden.pub --anchor anchor truncated.log
row FAIL "Audited against a different public key"                      -- --policy policy.txt --pubkey other.pub --anchor anchor verdicts.log
row FAIL "Edited + re-signed with attacker key; real key pinned"       -- --policy policy.txt --pubkey warden.pub --anchor anchor resigned.log
row FAIL "Edited + re-signed; attacker key trusted, anchor kept"       -- --policy policy.txt --pubkey "$(pk resigned.log)" --anchor anchor resigned.log
echo "  --- crypto bypassed below: attacker's key trusted, no anchor; only the proof re-check remains ---"
row PASS "Control: unedited log, attacker key trusted, no anchor"      -- --policy policy.txt --pubkey "$(pk ctrl.log)" ctrl.log
row FAIL "Certificate forged to name another rule"                     -- --policy policy.txt --pubkey "$(pk forged_cert.log)" forged_cert.log
row FAIL "ALLOW retargeted to secret/payroll.db"                       -- --policy policy.txt --pubkey "$(pk forged_target.log)" forged_target.log

# ------------------------------------------------------------ part 2: network
say "Part 2: live run, direct connect, MCP calls and HTTPS via the egress proxy"
X="$(mktemp -d /tmp/varek_demo_net.XXXXXX)"; chmod 755 "$X"
P2="$EV/part2"; mkdir -p "$P2"
HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
free() { python3 -c 'import socket; s = socket.socket(); s.bind(("", 0)); print(s.getsockname()[1])'; }
PS=$(free) PE=$(free) PD=$(free) DP=$(free)
( cd "$X" && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tca.key -out tca.pem -days 2 \
      -subj "/CN=Demo upstream root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" &&
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout s.key -out s.csr -subj "/CN=mcp.example.com" &&
  printf 'subjectAltName=DNS:mcp.example.com\nextendedKeyUsage=serverAuth\n' > s.ext &&
  openssl x509 -req -in s.csr -CA tca.pem -CAkey tca.key -CAcreateserial -out s.pem -days 1 -extfile s.ext ) > "$P2/certs.log" 2>&1 \
  || die "certificate setup failed"
cat "$(python3 -c 'import ssl; print(ssl.get_default_verify_paths().openssl_cafile)')" "$X/tca.pem" > "$X/bundle.pem"; chmod 644 "$X"/*.pem
cat > "$X/echo.py" <<'EOF'
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(16)
def h(c):
    try: c.recv(64); c.sendall(b"pong\n")
    finally: c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
EOF
cat > "$X/agent.py" <<'EOF'
# Demo agent: direct TCP connects, MCP tool calls and plain HTTPS requests.
import json, socket, ssl, sys
HOSTIP, PE, PD, PS = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
H = "mcp.example.com"
def out(tag, r): print(tag, r, flush=True)
def tcp(tag, port):
    try:
        s = socket.create_connection((HOSTIP, port), 5); s.sendall(b"ping\n"); out(tag, "CONNECTED " + s.recv(64).decode().strip()); s.close()
    except OSError as e: out(tag, "REFUSED " + (e.strerror or type(e).__name__))
def https(tag, raw):
    try:
        s = ssl.create_default_context().wrap_socket(socket.create_connection((H, PS), 15), server_hostname=H)
        s.sendall(raw); d = b""
        while b"\r\n\r\n" not in d:
            x = s.recv(65536)
            if not x: break
            d += x
        out(tag, d.split(b"\r\n")[0].decode() or "EMPTY"); s.close()
    except (OSError, ssl.SSLError) as e: out(tag, "ERR " + type(e).__name__)
def mcp(tag, i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params: m["params"] = params
    b = json.dumps(m).encode()
    https(tag, ("POST /mcp HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n"
                "MCP-Protocol-Version: 2025-06-18\r\nContent-Length: %d\r\n\r\n" % (H, PS, len(b))).encode() + b)
tcp("connect, allowed port   ", PE)
tcp("connect, denied port    ", PD)
mcp("MCP tools/list          ", 1, "tools/list")
mcp("MCP tools/call get_issue", 2, "tools/call", {"name": "get_issue", "arguments": {"n": 1}})
mcp("MCP tools/call delete_repo", 3, "tools/call", {"name": "delete_repo"})
https("HTTPS GET /status       ", ("GET /status HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (H, PS)).encode())
https("HTTPS POST /admin       ", ("POST /admin HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: 0\r\n\r\n" % (H, PS)).encode())
EOF
chmod 644 "$X"/*.py
python3 "$T/tests/v1310_mcp_server.py" "$HOSTIP" "$PS" "$X/s.pem" "$X/s.key" "$P2/server_got.jsonl" > "$P2/mcp_server.log" 2>&1 & PIDS="$PIDS $!"
python3 "$X/echo.py" "$HOSTIP" "$PE" > /dev/null 2>&1 & PIDS="$PIDS $!"
python3 "$X/echo.py" "$HOSTIP" "$PD" > /dev/null 2>&1 & PIDS="$PIDS $!"
printf '{"mcp.example.com": {"ttl": 30, "a": ["%s"]}}\n' "$HOSTIP" > "$P2/zone.json"
python3 "$T/tests/dns_test_server.py" --port "$DP" --zone "$P2/zone.json" --log "$P2/dns.log" --ready "$P2/dns.ready" > /dev/null 2>&1 & PIDS="$PIDS $!"
for _ in $(seq 50); do [ -e "$P2/dns.ready" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $PS), 0.2)" 2>/dev/null && break; sleep 0.1; done
U="https://mcp.example.com:$PS"
cat > "$P2/policy.txt" <<EOF
require warden 1.31
proxy inspect
proxy ports $PS
allow host mcp.example.com:$PS
allow host $HOSTIP:$PE
deny  host $HOSTIP:$PD
allow mcp $U/mcp tools/list
deny  mcp $U/mcp tools/call delete_*
allow mcp $U/mcp tools/call get_*
allow request GET $U/status
allow path /usr/ readonly
allow path /lib readonly
allow path /etc/ld.so.cache readonly
allow path exact $X/agent.py readonly
EOF
( cd "$P2" && env -i PATH=/usr/bin:/bin timeout 120 "$T/warden" policy.txt --dns-server "127.0.0.1:$DP" --trust-bundle "$X/bundle.pem" \
    --sign-key "$EV/warden" --anchor anchor --checkpoint-every 4 \
    -- /usr/bin/python3 "$X/agent.py" "$HOSTIP" "$PE" "$PD" "$PS" > agent.out 2> verdicts.log ) || die "part 2 run failed (see $P2)"
sed 's/^/    agent: /' "$P2/agent.out"
cleanup; PIDS=""

L2="$EV/part2_later"; mkdir -p "$L2"; cp "$P2/verdicts.log" "$P2/policy.txt" "$P2/anchor" "$EV/warden.pub" "$L2/"
cd "$L2"
S_CON=$(fnd verdicts.log net.connect ALLOW "$HOSTIP:$PE")
S_GET=$(fnd verdicts.log net.mcp ALLOW "get_issue")
S_DEL=$(fnd verdicts.log net.mcp DENY "delete_repo")
S_REQ=$(fnd verdicts.log net.request ALLOW "GET $U/status")
S_ADM=$(fnd verdicts.log net.request DENY "POST $U/admin")
S_PRX=$(fnd verdicts.log net.proxy ALLOW "mcp.example.com:$PS")
G_LINE=$(fnd verdicts.log net.mcp ALLOW get_issue policy_line);  G_CR=$(fnd verdicts.log net.mcp ALLOW get_issue cert_rule);  G_W=$(fnd verdicts.log net.mcp ALLOW get_issue cert_witness)
R_LINE=$(fnd verdicts.log net.request ALLOW "GET $U/status" policy_line); R_CR=$(fnd verdicts.log net.request ALLOW "GET $U/status" cert_rule); R_W=$(fnd verdicts.log net.request ALLOW "GET $U/status" cert_witness)
sed 's/^deny  mcp/allow mcp/' policy.txt > policy_loosened.txt
python3 -I "$T/tests/log_rechain.py" --resign "$WORK/attacker.seed" verdicts.log > ctrl.log
forge verdicts.log n1.log "$S_CON" "target=$HOSTIP:$PD" "resolved=$HOSTIP:$PD"
forge verdicts.log n2.log "$S_GET" "target=$U/mcp#tools/call#delete_repo" "resolved=$U/mcp#tools/call#delete_repo" mcp_name=delete_repo
forge verdicts.log n3.log "$S_DEL" decision_raw=ALLOW decision_final=ALLOW rule=mcp_allowed policy_line="$G_LINE" cert_rule="$G_CR" cert_witness="$G_W" check=ok kernel_verdict=ALLOW errno=0
forge verdicts.log n4.log "$S_REQ" "target=POST $U/admin" "resolved=POST $U/admin"
forge verdicts.log n5.log "$S_ADM" decision_raw=ALLOW decision_final=ALLOW rule=request_allowed policy_line="$R_LINE" cert_rule="$R_CR" cert_witness="$R_W" check=ok kernel_verdict=ALLOW errno=0
forge verdicts.log n6.log "$S_PRX" "target=evil.example.net:$PS" "resolved=evil.example.net:$PS"
forge verdicts.log n7.log "$S_GET" latency_us=999

say "Part 2: audit from the 'later' folder (log, policy, public key, anchor only)"
header
row PASS "Clean run: pinned public key + anchor"                       -- --policy policy.txt --pubkey warden.pub --anchor anchor verdicts.log
row FAIL "Policy file changed after the run (delete_* now allowed)"    -- --policy policy_loosened.txt --pubkey warden.pub --anchor anchor verdicts.log
row FAIL "MCP call retargeted + re-signed; real key pinned"            -- --policy policy.txt --pubkey warden.pub --anchor anchor n2.log
echo "  --- crypto bypassed below: attacker's key trusted, no anchor; only the proof re-check remains ---"
row PASS "Control: unedited log"                                        -- --policy policy.txt --pubkey "$(pk ctrl.log)" ctrl.log
row PASS "Control: harmless field edited (latency)"                     -- --policy policy.txt --pubkey "$(pk n7.log)" n7.log
row FAIL "Direct connect retargeted to the denied port"                 -- --policy policy.txt --pubkey "$(pk n1.log)" n1.log
row FAIL "MCP get_issue ALLOW retargeted to delete_repo"                -- --policy policy.txt --pubkey "$(pk n2.log)" n2.log
row FAIL "MCP delete_repo DENY flipped to ALLOW (get_* certificate)"    -- --policy policy.txt --pubkey "$(pk n3.log)" n3.log
row FAIL "HTTPS GET /status ALLOW retargeted to POST /admin"            -- --policy policy.txt --pubkey "$(pk n4.log)" n4.log
row FAIL "HTTPS POST /admin DENY flipped to ALLOW (GET certificate)"    -- --policy policy.txt --pubkey "$(pk n5.log)" n5.log
row FAIL "Proxy dial retargeted to evil.example.net"                    -- --policy policy.txt --pubkey "$(pk n6.log)" n6.log

# ------------------------------------------------------------ result
say "Result"
echo "  $OK of $ROWS rows came out as expected.   Evidence: $EV"
echo "  Every audit's full output is in $EV/audit_NN.txt; each run's verdict log, policy and anchor are in part1/ and part2/."
rm -rf "$X" "$F"
[ "$OK" = "$ROWS" ] && { echo "  DEMO RESULT: PASS"; exit 0; } || { echo "  DEMO RESULT: UNEXPECTED ROWS ABOVE"; exit 1; }
