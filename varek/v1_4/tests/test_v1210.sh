#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1210.sh — v1.21.0: decided connections.
#
#   1. the probe (tests/v1210_probe.c) as the agent: TCP, UDP, Unix, IPv6
#      decisions, options carried over, relayed sends, every refusal, a slow
#      connect that does not stall the Warden, and the destination-swap race
#   2. the verdict records: each connect decided on the destination dialed,
#      certified, and re-checked by tools/varek_audit.py; the CycloneDX export
#   3. the plan gate: allowed net_connect steps pass, others are refused
#   4. load-time notes for host constants a connect can never produce
#   5. real clients as the agent: curl, Python requests, Node.js (HTTP, HTTPS,
#      TCP, UDP, Unix); where the host can reach it, a real CDN-hosted API
#      (pypi.org, by address: host names are v1.21 stage 2)
#   6. latency: each connect natively and under the Warden, for the probe's
#      benchmark client and for Python and Node; the Warden's own time from its
#      records. Written to $VAREK_LATENCY_OUT if set.
#
# Usage: test_v1210.sh <warden> <vdp_cert_check> <probe> <bench>   (as root)
set -u

WARDEN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
CERT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
PROBE="${3:?}" BENCH="${4:?}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$HERE/tests"
D=/tmp/varek_v1210
OUT="$(mktemp -d)"
POL="$T/v1210_policy.txt" CPOL="$OUT/clients.policy"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }

SERVERS=""
cleanup() { [ -n "$SERVERS" ] && kill "$SERVERS" 2>/dev/null; wait 2>/dev/null; rm -rf "$OUT" "$D"; }
trap cleanup EXIT

# A server left by an interrupted run would hold the ports.
pkill -f "v1210_servers\.py $D\$" 2>/dev/null && sleep 0.5
rm -rf "$D"
mkdir -p "$D/work" "$D/tls"
chmod 755 "$D" "$D/work" "$D/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" -keyout "$D/tls/key.pem" -out "$D/tls/cert.pem" \
    >/dev/null 2>&1 && chmod 644 "$D/tls/cert.pem"
python3 "$T/v1210_servers.py" "$D" > "$OUT/servers.out" 2>&1 &
SERVERS=$!
for _ in $(seq 100); do [ -e "$D/ready" ] && break; sleep 0.1; done
[ -e "$D/ready" ] || { echo "the test servers did not start:"; cat "$OUT/servers.out"; exit 1; }
cp "$T/v1210_clients.py" "$T/v1210_clients.js" "$D/work/"
chmod 644 "$D/work/"*

echo "== 1. the probe as the agent =="
"$WARDEN" "$POL" -- "$PROBE" 2000 > "$OUT/probe.out" 2> "$OUT/v.log"
sed 's/^/     /' "$OUT/probe.out"
check "the probe ran to the end"                   grep -q '^PROBE done' "$OUT/probe.out"
if grep -q 'BYPASSED' "$OUT/probe.out"; then flunk "no destination the policy denies was reached"
else pass "no destination the policy denies was reached"; fi
if grep -q ' FAIL ' "$OUT/probe.out"; then flunk "every case had the promised outcome"
else pass "every case had the promised outcome"; fi
while read -r _ c _ why; do skip "probe case $c: $why"; done < <(grep '^PROBE [^ ]* *SKIP' "$OUT/probe.out")
check "the race ran and had no escapes"            grep -q 'toctou_race .* OK .* 0 escapes' "$OUT/probe.out"
check "the Unix server saw the agent's uid, not root" grep -q 'unix:s.sock peer uid=65534' "$D/servers.log"
check "the Unix datagram reached its server"       grep -q 'unix-dgram d.sock got 5 bytes' "$D/servers.log"

echo "== 2. the records =="
python3 - "$OUT/v.log" <<'PY' > "$OUT/rec.out"
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith('{"report_id"')]
c = [r for r in recs if r["action"] == "net.connect"]
def has(**kw):
    return any(all(r.get(k) == v for k, v in kw.items()) for r in c)
checks = {
  "an allowed connect is dialed and handed over, certified":
      has(resolved="127.0.0.1:18181", decision_final="ALLOW", rule="dialed_fd_injection", check="ok", sock="tcp"),
  "a non-blocking connect is handed over in progress":
      has(resolved="127.0.0.1:18181", rule="dialed_in_progress", kernel_verdict="ALLOW", errno=115),
  "a denied connect is refused by the policy":
      has(resolved="127.0.0.1:18182", decision_final="DENY", kernel_verdict="EACCES"),
  "the race's denied side never reached ALLOW":
      not has(resolved="127.0.0.1:18182", decision_final="ALLOW"),
  "an IPv4-mapped destination is decided as its IPv4 form":
      has(target="[::ffff:127.0.0.1]:18182", resolved="127.0.0.1:18182", decision_final="DENY"),
  "an IPv6 destination is decided on its canonical text":
      has(resolved="[2001:db8::1]:443", decision_final="ALLOW", rule="dial_failed"),
  "a scope id is refused before the policy":  has(rule="scope_id_refused"),
  "a Unix socket is decided on its canonical path":
      has(resolved="unix:/tmp/varek_v1210/sock/s.sock", decision_final="ALLOW", sock="unix-stream"),
  "a symlink to an allowed socket is decided as the socket":
      has(target="unix:/tmp/varek_v1210/sock/link-ok.sock", resolved="unix:/tmp/varek_v1210/sock/s.sock"),
  "a symlink to a denied socket is decided as the denied socket":
      has(target="unix:/tmp/varek_v1210/sock/link-bad.sock", resolved="unix:/tmp/varek_v1210/outside/other.sock", decision_final="DENY"),
  "an allowed socket only root may use: the agent's permissions apply":
      has(resolved="unix:/tmp/varek_v1210/sock/root.sock", decision_final="ALLOW", rule="dial_failed", errno=13),
  "an abstract Unix address is refused":      has(rule="unix_abstract_refused"),
  "AF_UNSPEC is refused":                     has(rule="unspec_refused"),
  "another address family is refused":        has(rule="family_refused"),
  "a malformed address gets EINVAL":          has(rule="bad_address", errno=22),
  "a connect on a connected socket answers EISCONN": has(rule="already_connected", errno=106),
  "the slow connect was handed over at SO_SNDTIMEO":
      has(resolved="127.0.0.1:18184", rule="dialed_in_progress"),
  "a second connect on a socket still connecting answers EALREADY":
      has(resolved="127.0.0.1:18181", rule="already_connected", errno=114),
  "a descriptor replaced while its connect waited is left alone":
      has(resolved="127.0.0.1:18184", rule="dialed_descriptor_replaced"),
  "no connect is refused by the old deny-only rule":
      not any(r.get("rule") == "deny_only_nonfile_v191" for r in c),
  "every ALLOW carries a certificate the checker accepted":
      all(r.get("check") == "ok" for r in c if r["decision_final"] == "ALLOW"),
  "every connect record names its socket kind and dial time":
      all("sock" in r and "dial_us" in r for r in c if r["rule"] not in ("bad_address", "unspec_refused", "family_refused", "not_a_socket", "bad_descriptor")),
  "sends with a destination are refused and recorded":
      any(r["action"] == "net.send" and r["decision_final"] == "DENY" for r in recs),
  "control data on a relayed send is refused": any(r.get("rule") == "send_control_refused" for r in recs),
}
for k, v in checks.items():
    print(("PASS " if v else "FAIL ") + k)
PY
while read -r st msg; do [ "$st" = PASS ] && pass "$msg" || flunk "$msg"; done < "$OUT/rec.out"
a="$(python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/v.log" 2>&1)"
grep -q 'varek_audit: PASS' <<<"$a" && pass "varek_audit re-checks every connect certificate: $(grep -o '[0-9]* authorized connects' <<<"$a")" \
    || { flunk "varek_audit passes"; printf '%s\n' "$a" | head -5; }
python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/v.log" --policy "$POL" --output "$OUT/bom.json" >/dev/null 2>&1 \
    && grep -q '127.0.0.1:18181' "$OUT/bom.json" && pass "the CycloneDX export lists the connected destinations" \
    || flunk "the CycloneDX export lists the connected destinations"
sed 's/"resolved":"127.0.0.1:18181"/"resolved":"127.0.0.1:18182"/' "$OUT/v.log" > "$OUT/tampered.log"
python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/tampered.log" 2>&1 | grep -q 'varek_audit: FAIL' \
    && pass "a record rewritten to name another destination fails the audit" \
    || flunk "a record rewritten to name another destination fails the audit"

echo "== 3. the plan gate =="
plan() { printf '%s\n' "$2" > "$OUT/$1"; }
gate() { "$WARDEN" "$POL" --plan "$OUT/$1" -- /bin/true > /dev/null 2> "$OUT/gate.err"; }
plan ok.txt 'action a net_connect 127.0.0.1:18181
action b net_connect unix:/tmp/varek_v1210/sock/../sock/s.sock
action c net_connect [::ffff:127.0.0.1]:18181
edge a b'
gate ok.txt; check "allowed connect steps (IPv4, Unix, IPv4-mapped) are authorized" grep -q 'plan authorized (3 actions)' "$OUT/gate.err"
plan deny.txt 'action a net_connect 127.0.0.1:18182'
gate deny.txt; check "a connect step no rule allows is rejected" grep -q 'plan rejected (UNKNOWN)' "$OUT/gate.err"
plan deny2.txt 'action a net_connect 203.0.113.7:443'
printf 'allow host 127.0.0.1:18181\ndeny host 203.0.113.7\n' > "$OUT/deny.pol"
"$WARDEN" "$OUT/deny.pol" --plan "$OUT/deny2.txt" -- /bin/true > /dev/null 2> "$OUT/gate.err"
check "a connect step a deny rule matches is UNSATISFIED"         grep -q 'plan rejected (UNSATISFIED)' "$OUT/gate.err"
plan name.txt 'action a net_connect api.example.com:443'
gate name.txt; check "a host-name step is UNKNOWN, with the reason" grep -q 'is UNKNOWN: not a numeric address' "$OUT/gate.err"
plan noport.txt 'action a net_connect 127.0.0.1'
gate noport.txt; check "a step without a port is UNKNOWN"      grep -q 'plan rejected (UNKNOWN)' "$OUT/gate.err"
plan exec.txt 'action a process_exec /bin/true'
gate exec.txt; check "a launch step is still UNSATISFIED"      grep -q 'refuses every launch after the first' "$OUT/gate.err"

echo "== 4. host constants a connect can never produce =="
printf 'deny host evil.example.com\nallow host [::1]\nallow host 010.1.2.3:80\nallow host unix:run/x.sock\nallow host [::ffff:10.0.0.1]:80\nallow host 127.0.0.1:8443\n' > "$OUT/names.txt"
"$HERE/tools/vdp_check" "$OUT/names.txt" lint > "$OUT/lint.out" 2>&1
check "a host name is reported as never matching"              grep -q 'names.txt:1: note: not a numeric address' "$OUT/lint.out"
check "an IPv4-mapped constant names its IPv4 form"            grep -q 'names.txt:5: note: an IPv4-mapped address is decided as its IPv4 form, 10.0.0.1' "$OUT/lint.out"
check "a relative unix: constant is reported"                  grep -q 'names.txt:4: note: a unix: constant must name an absolute path' "$OUT/lint.out"
if grep -q 'names.txt:[26]: note' "$OUT/lint.out"; then flunk "canonical constants draw no note"; else pass "canonical constants draw no note"; fi
"$WARDEN" "$HERE/policy.txt" -- /bin/true > /dev/null 2> "$OUT/sample.err"
if grep -Eq '^[[:space:]]*(allow|deny)[[:space:]]+host[[:space:]]+[a-z]' "$HERE/policy.txt" "$HERE/policies/"*.txt; then
    flunk "no shipped policy has a host-name rule"; else pass "no shipped policy has a host-name rule"; fi
"$HERE/tools/vdp_check" "$HERE/policy.txt" lint 2>&1 | grep -q 'note:' && flunk "the sample policy lints without notes" \
    || pass "the sample policy lints without notes"

echo "== 4b. the sector policies' name rules match in any case =="
python3 - "$HERE" <<'PY' > "$OUT/sector.out"
import json, subprocess, sys
here = sys.argv[1]
cases = {
  "healthcare": [("/var/lib/ehr/records/p1/server.PEM", 0), ("/var/lib/ehr/records/p1/x.pem.bak", 0),
                 ("/var/lib/ehr/records/p1/id_rsa", 0), ("/var/lib/ehr/records/p1/Psychotherapy/n.txt", 0),
                 ("/var/lib/ehr/records/p1/PSYCHOTHERAPY", 0), ("/tmp/varek/.SSH/config", 0),
                 ("/tmp/varek/.ssh-old/k", 0), ("/tmp/varek/.Env", 0), ("/tmp/varek/app.KEY", 0),
                 ("/var/lib/ehr/records/p1/chart.json", 1), ("/usr/lib/python3.11/keyword.py", 1),
                 ("/var/lib/ehr/records/p1/x.pem~", 0), ("/tmp/varek/.env~", 0),
                 ("/var/lib/ehr/records/Deceased/p9.json", 0),
                 # not refused: a longer name, not a copy (documented in the policy)
                 ("/var/lib/ehr/records/p1/j.pemberton.json", 1),
                 ("/var/lib/ehr/records/p1/visit.keynotes.txt", 1),
                 ("/var/lib/ehr/records/p1/psychotherapy-referral.txt", 1)],
  "national-defense": [("/var/lib/intel/products/a/Compartmented/x", 0), ("/tmp/varek/id_ECDSA", 0)],
  "finance": [("/tmp/varek/Server.Pem", 0)], "utility": [("/tmp/varek/ID_ED25519.bak", 0)],
  "cybersecurity": [("/tmp/varek/x.key~", 0)],
}
for pol, cs in cases.items():
    q = "".join(f"path 0 {p.encode().hex()}\n" for p, _ in cs)
    out = subprocess.run([f"{here}/tools/vdp_check", f"{here}/policies/{pol}.policy.txt", "batch"],
                         input=q, capture_output=True, text=True).stdout.splitlines()
    for (path, allowed), o in zip(cs, out):
        v = json.loads(o)["verdict"]
        want = "SATISFIED" if allowed else "UNSATISFIED"
        print(("PASS " if v == want else "FAIL ") + f"{pol}: {path} is {want} (got {v})")
PY
while read -r st msg; do [ "$st" = PASS ] && pass "$msg" || flunk "$msg"; done < "$OUT/sector.out"

echo "== 4c. the preflight checks the plan gate and its count file =="
PF="$HERE/tools/varek_preflight.sh" HOTL="$HERE/../../v1_7/hotl_policy.cfg"
mkdir -p "$OUT/st" "$OUT/st-open" && chmod 700 "$OUT/st" && chmod 777 "$OUT/st-open"
"$PF" "$HERE/policies/healthcare.policy.txt" --flow-policy "$HOTL" --breaker-state "$OUT/st/state" > "$OUT/pf1" 2>&1
check "a good flow policy and count file pass"          grep -q 'preflight: PASS' "$OUT/pf1"
"$PF" "$HERE/policies/healthcare.policy.txt" --flow-policy "$HERE/../../v1_7/uncertified_policy.cfg" --breaker-state "$OUT/st/state" > "$OUT/pf2" 2>&1
check "a flow policy that is not progress-safe fails"   grep -q 'FAIL .*not progress-safe' "$OUT/pf2"
"$PF" "$HERE/policies/healthcare.policy.txt" --flow-policy "$HOTL" --breaker-state "$OUT/st-open/state" > "$OUT/pf3" 2>&1
check "a count file in a directory others can write fails" grep -q 'FAIL .*writable by no one else' "$OUT/pf3"
mkdir -p /tmp/varek/v1210-st && chmod 700 /tmp/varek/v1210-st
"$PF" "$HERE/policies/healthcare.policy.txt" --flow-policy "$HOTL" --breaker-state /tmp/varek/v1210-st/state > "$OUT/pf4" 2>&1
check "a count file the agent could open fails"         grep -q 'FAIL .*would let the agent open the breaker state' "$OUT/pf4"
rm -rf /tmp/varek/v1210-st
"$PF" "$HERE/policies/healthcare.policy.txt" --breaker-state "$OUT/st/state" > "$OUT/pf5" 2>&1
check "--breaker-state without --flow-policy is a usage error" grep -q 'need --flow-policy' "$OUT/pf5"

echo "== 5. real clients as the agent =="
cp "$T/v1210_clients_policy.txt" "$CPOL"
# A clean environment: no proxy settings, no extra CA variables pointing at
# files the policy does not name.
RUN_ENV=()
run() { env -i PATH=/usr/local/bin:/usr/bin:/bin:/opt/node22/bin HOME=/tmp LANG=C.UTF-8 "${RUN_ENV[@]}" \
            "$WARDEN" "$CPOL" -- "$@" 2>> "$OUT/clients.log"; }
PYC="$D/work/v1210_clients.py" JSC="$D/work/v1210_clients.js"
NODE="$(command -v node || echo /opt/node22/bin/node)"
: > "$OUT/clients.log"
client() { # client <label> <expected-regex> <cmd...>
    local label="$1" want="$2"; shift 2
    local o; o="$(run "$@" 2>/dev/null)"
    if grep -Eq "$want" <<<"$o"; then pass "$label: $(grep -Eo "$want" <<<"$o" | head -1)"
    else flunk "$label (got: $(tr '\n' ' ' <<<"$o" | cut -c1-160))"; fi
}
if command -v curl >/dev/null; then
    client "curl http"               'http=200'            /usr/bin/curl -sS -o /dev/null -w 'http=%{http_code}' http://127.0.0.1:18187/
    client "curl https (test CA)"    'http=200'            /usr/bin/curl -sS -o /dev/null -w 'http=%{http_code}' --cacert "$D/tls/cert.pem" https://127.0.0.1:18188/
    client "curl --unix-socket"      'http=200'            /usr/bin/curl -sS -o /dev/null -w 'http=%{http_code}' --unix-socket "$D/sock/http.sock" http://localhost/
    client "curl to a denied port"   'http=000'            /usr/bin/curl -sS -o /dev/null -w 'http=%{http_code}' http://127.0.0.1:18182/
else skip "curl not installed"; fi
if python3 -c 'import requests' 2>/dev/null; then
    client "python requests http"    'status=200'          /usr/bin/python3 "$PYC" requests-get http://127.0.0.1:18187/
    client "python requests https"   'status=200'          /usr/bin/python3 "$PYC" requests-get https://127.0.0.1:18188/ "$D/tls/cert.pem"
    client "python unix socket"      'echo=ping'           /usr/bin/python3 "$PYC" unix "$D/sock/s.sock"
    client "python connected UDP (send, sendmsg)" 'echo=one,two' /usr/bin/python3 "$PYC" udp 127.0.0.1 18183
else skip "python3 requests not installed"; fi
if [ -x "$NODE" ]; then
    client "node http"               'status=200'          "$NODE" "$JSC" http http://127.0.0.1:18187/
    client "node https (test CA)"    'status=200'          "$NODE" "$JSC" https https://127.0.0.1:18188/ "$D/tls/cert.pem"
    client "node net (TCP)"          'echo=ping'           "$NODE" "$JSC" net 127.0.0.1 18181
    client "node net (Unix)"         'echo=ping'           "$NODE" "$JSC" unix "$D/sock/s.sock"
    client "node dgram (connected UDP)" 'echo=one,two'     "$NODE" "$JSC" dgram 127.0.0.1 18183
else skip "node not installed"; fi
check "every client connect was certified" python3 -c '
import json,sys
c=[json.loads(l) for l in open(sys.argv[1]) if "\"net.connect\"" in l and l.startswith("{")]
ok=[r for r in c if r["decision_final"]=="ALLOW"]
sys.exit(0 if ok and all(r.get("check")=="ok" for r in ok) else 1)' "$OUT/clients.log"

# A real CDN-hosted API, where this host can reach it. Stage 1 decides
# addresses, so the name is resolved here, outside the agent, and the
# addresses are allowed; the clients verify the real certificate for the name.
CDN_IPS="$(python3 -c 'import socket; print(" ".join(sorted({a[4][0] for a in socket.getaddrinfo("pypi.org", 443, socket.AF_INET, socket.SOCK_STREAM)})))' 2>/dev/null)"
CDN_OK=0
if [ -n "$CDN_IPS" ] && timeout 10 curl -sS -o /dev/null --noproxy '*' "https://pypi.org/simple/" 2>/dev/null; then CDN_OK=1; fi
if [ "$CDN_OK" = 1 ]; then
    for ip in $CDN_IPS; do echo "allow host $ip:443" >> "$CPOL"; done
    IP1="${CDN_IPS%% *}"
    client "curl https://pypi.org (CDN, by address)" 'http=200' /usr/bin/curl -sS -o /dev/null -w 'http=%{http_code}' \
        --resolve "pypi.org:443:$IP1" https://pypi.org/pypi/requests/json
    # The system CA store, as curl uses: a host whose egress re-terminates TLS
    # (as this test's may) adds its CA there; Node reads it via
    # NODE_EXTRA_CA_CERTS.
    client "python TLS to pypi.org (CDN, verified)" 'HTTP/1.1 200' \
        /usr/bin/python3 "$PYC" raw-tls "$IP1" 443 pypi.org /pypi/requests/json /etc/ssl/certs/ca-certificates.crt
    RUN_ENV=(NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt)
    [ -x "$NODE" ] && client "node TLS to pypi.org (CDN, verified)" 'HTTP/1.1 200 OK authorized=true' \
        "$NODE" "$JSC" tls "$IP1" 443 pypi.org /pypi/requests/json
    RUN_ENV=()
    NPM_IP="$(python3 -c 'import socket; print(socket.getaddrinfo("registry.npmjs.org", 443, socket.AF_INET)[0][4][0])' 2>/dev/null)"
    [ -n "$NPM_IP" ] && client "an address the policy does not name is refused" 'http=000' /usr/bin/curl -sS -o /dev/null \
        -w 'http=%{http_code}' --resolve "registry.npmjs.org:443:$NPM_IP" https://registry.npmjs.org/
else
    skip "no route to pypi.org from this host: the CDN check did not run"
fi

echo "== 6. latency per connection =="
LAT="$OUT/latency.txt"
{
    echo "VAREK v1.21.0 connect latency ($(date -u +%Y-%m-%dT%H:%MZ); kernel $(uname -r); $(nproc) vCPU)"
    echo "Each line: one connect after another to a local listener, n connects, percentiles in microseconds."
    echo "'native' runs the same client outside the Warden; 'warden' runs it as the agent."
} > "$LAT"
bench() { # bench <label> <native-cmd...> -- <warden-cmd...>
    local label="$1"; shift
    local n=() w=() side=n
    for x in "$@"; do if [ "$x" = "--" ] && [ $side = n ]; then side=w; elif [ $side = n ]; then n+=("$x"); else w+=("$x"); fi; done
    local no wo
    no="$("${n[@]}" 2>/dev/null | grep '^BENCH')"
    wo="$(env -i PATH=/usr/bin:/bin:/opt/node22/bin HOME=/tmp "$WARDEN" "${w[@]}" 2> "$OUT/bench.log" | grep '^BENCH')"
    printf '%-26s native  %s\n%-26s warden  %s\n' "$label" "${no#BENCH }" "$label" "${wo#BENCH }" >> "$LAT"
    python3 - "$OUT/bench.log" "$label" >> "$LAT" <<'PY'
import json, sys
c = [json.loads(l) for l in open(sys.argv[1]) if l.startswith('{"report_id"') and '"net.connect"' in l]
c = [r for r in c if r["decision_final"] == "ALLOW"]
if c:
    def p(v, q):
        v = sorted(v); return v[min(len(v) - 1, int(len(v) * q))]
    lat = [r["latency_us"] for r in c]; dial = [r["dial_us"] for r in c]
    own = [a - b for a, b in zip(lat, dial)]
    print(f"{sys.argv[2]:<26s} records n={len(c)} warden latency p50={p(lat,.5)} p90={p(lat,.9)} p99={p(lat,.99)}; "
          f"of which dial p50={p(dial,.5)} p99={p(dial,.99)}; Warden's own p50={p(own,.5)} p99={p(own,.99)} (us)")
PY
    [ -n "$wo" ] && [ -n "$no" ] || flunk "latency run: $label"
}
bench "C, blocking TCP"     "$BENCH" 127.0.0.1 18190 3000 -- "$POL" -- "$BENCH" 127.0.0.1 18190 3000
bench "C, non-blocking TCP" "$BENCH" 127.0.0.1 18190 3000 --nonblock -- "$POL" -- "$BENCH" 127.0.0.1 18190 3000 --nonblock
bench "C, Unix stream"      "$BENCH" unix:$D/sock/bench.sock 0 3000 -- "$POL" -- "$BENCH" unix:$D/sock/bench.sock 0 3000
python3 -c 'import requests' 2>/dev/null && {
    bench "Python create_connection" python3 "$PYC" bench-connect 127.0.0.1 18190 500 -- "$CPOL" -- /usr/bin/python3 "$PYC" bench-connect 127.0.0.1 18190 500
    bench "Python requests.get"  python3 "$PYC" bench-requests http://127.0.0.1:18187/ 200 -- "$CPOL" -- /usr/bin/python3 "$PYC" bench-requests http://127.0.0.1:18187/ 200
}
[ -x "$NODE" ] && bench "Node net.connect" "$NODE" "$JSC" bench-connect 127.0.0.1 18190 500 -- "$CPOL" -- "$NODE" "$JSC" bench-connect 127.0.0.1 18190 500
sed 's/^/     /' "$LAT"
[ -n "${VAREK_LATENCY_OUT:-}" ] && cp "$LAT" "$VAREK_LATENCY_OUT"

echo
if [ "$fail" -eq 0 ]; then
    if [ "$skips" -gt 0 ]; then echo "ALL PASSED (v1.21.0), $skips SKIPPED (see SKIP lines above)"
    else echo "ALL PASSED (v1.21.0)"; fi
else echo "FAILURES PRESENT"; fi
exit "$fail"
