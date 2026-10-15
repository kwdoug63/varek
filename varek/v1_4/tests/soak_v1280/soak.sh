#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# soak.sh — the v1.28 soak test (docs/security/v1.28-credential-release.md,
# step 7): credential release for 24 hours. An agent under the Warden, the
# egress proxy in inspecting mode, holds four placeholders: a file store, a
# Vault lease (60 s, renewed by warden-secrets every 40 s), Vault KV version 2
# and AWS Secrets Manager, from local stand-ins (tests/v1280_stores.py). Once
# a minute it calls a local API (soak_api.py) with one credential in turn;
# the API checks at the receiving end that the header holds the value. Every
# tenth turn is a probe (a missing header, another credential's placeholder,
# a placeholder where no rule names one, a read of the file store). Near the
# end the run is revoked (varek revoke): every turn after must be refused.
# Then soak_check.py judges the run.
#
# Run as root on the droplet, from a checkout with the Warden built (make -C
# varek/v1_4 all), with python3-cryptography and openssl installed:
#
#   sudo varek/v1_4/tests/soak_v1280/soak.sh [--hours 24] [--interval 60] [--out DIR] [--sign-key KEY]
#
# The run writes DIR/verdicts.log, DIR/agent.jsonl, DIR/api.jsonl,
# DIR/stores/requests.log, DIR/rss.tsv, DIR/revoke.txt, DIR/policy.txt and,
# at the end, DIR/report.txt. It holds the terminal for the whole run: start
# it with nohup (see README.md).
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
for b in warden warden-proxy warden-secrets tools/vdp_cert_check; do
    [ -x "$V14/$b" ] || { echo "soak.sh: build first: make -C $V14 all"; exit 2; }
done
python3 -c 'import cryptography' 2>/dev/null || { echo "soak.sh: needs python3-cryptography (apt-get install -y python3-cryptography)"; exit 2; }
command -v openssl > /dev/null || { echo "soak.sh: needs openssl"; exit 2; }
OUT="${OUT:-/var/tmp/varek-soak1280-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT/stores"; chmod 755 "$OUT" "$OUT/stores"
AG=/opt/varek-soak1280-agent                 # the agent's script, read-only to it
S=/etc/varek-soak1280                        # the stores' secrets: root's alone
mkdir -p "$AG" "$S"; chmod 755 "$AG"; chmod 700 "$S"
cp "$HERE/soak_agent.py" "$AG/"; chmod 644 "$AG/soak_agent.py"
SECS=$(python3 -c "print(int(float('$HOURS') * 3600))")
PIDS=""
trap 'kill $PIDS 2>/dev/null' EXIT

# the stand-in stores (Vault, AWS Secrets Manager), their certificates
# lasting the run
V1280_CERT_HOURS=$(python3 -c "print(float('$HOURS') + 2)") python3 "$V14/tests/v1280_stores.py" "$OUT/stores" \
    > "$OUT/stores/server.out" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 100); do [ -f "$OUT/stores/ports" ] && break; sleep 0.1; done
read -r HP _ < "$OUT/stores/ports" || { echo "soak.sh: the stores did not start"; exit 1; }
chmod 644 "$OUT/stores/ca.pem"               # read by warden-secrets as its own user
# the stores' values (test values, not secrets: tests/v1280_stores.py holds them)
put() { printf '%b' "$2" > "$S/$1"; chmod 600 "$S/$1"; }
APIV="soak-file-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
put api.key "$APIV\n"
put vt 's.test-token-v1280\n'
put aws 'aws_access_key_id = AKIDV1280TEST\naws_secret_access_key = v1280-test-secret-key/abc\n'
put secrets.conf "vault_addr = https://127.0.0.1:$HP\nvault_token_file = $S/vt\nvault_ca = $OUT/stores/ca.pem\naws_endpoint = https://127.0.0.1:$HP\naws_ca = $OUT/stores/ca.pem\naws_credentials_file = $S/aws\n"
printf '{"api": "%s", "db": "db-soak-3e9d", "gh": "vault-kv2-value-7f3a", "st": "aws-sm-value-c4b1"}\n' "$APIV" > "$S/values.json"
chmod 600 "$S/values.json"

# the API: its certificate from a CA of the run's own, added to the trust
# bundle the Warden gives the proxy
HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
PS=$((43000 + RANDOM % 5000))
DAYS=$(python3 -c "import math; print(math.ceil(float('$HOURS') / 24) + 1)")
( cd "$OUT" &&
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout apica.key -out apica.pem -days "$DAYS" \
      -subj "/CN=VAREK v1.28 soak API root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" &&
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout api.key -out api.csr -subj "/CN=api.example.com" &&
  printf 'subjectAltName=DNS:api.example.com\nextendedKeyUsage=serverAuth\n' > api.ext &&
  openssl x509 -req -in api.csr -CA apica.pem -CAkey apica.key -CAcreateserial -out api.pem -days "$DAYS" -extfile api.ext ) \
    > "$OUT/certs.log" 2>&1 || { echo "soak.sh: openssl failed (certs.log)"; exit 1; }
chmod 600 "$OUT/apica.key" "$OUT/api.key"
cat "$(python3 -c 'import ssl; print(ssl.get_default_verify_paths().openssl_cafile)')" "$OUT/apica.pem" > "$OUT/bundle.pem"
chmod 644 "$OUT/bundle.pem"
python3 "$HERE/soak_api.py" "$HOSTIP" "$PS" "$OUT/api.pem" "$OUT/api.key" "$S/values.json" "$OUT/api.jsonl" \
    > "$OUT/api.out" 2>&1 &
PIDS="$PIDS $!"
DP=$((20000 + RANDOM % 20000))
printf '{"api.example.com": {"ttl": 300, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/zone.json"
python3 "$V14/tests/dns_test_server.py" --port "$DP" --zone "$OUT/zone.json" --log "$OUT/dns.log" --ready "$OUT/dns.ready" \
    > /dev/null 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 100); do
    [ -e "$OUT/dns.ready" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $PS), 0.2)" 2>/dev/null && break
    sleep 0.1
done

POL="$OUT/policy.txt"
ARN='arn:aws:secretsmanager:us-east-1:111122223333:secret:stripe-AbCdEf'
{
    echo "# v1.28 soak test policy (soak.sh)"
    echo "require warden 1.28"
    echo "proxy inspect"
    echo "proxy ports $PS"
    echo "credential api from file:$S/api.key"
    echo "credential db from vault:database/creds/soak#password"
    echo "credential st from aws-sm:$ARN"
    echo "credential gh from vault:secret/data/agents/gh#token"
    echo "allow host api.example.com"
    echo "allow request GET https://api.example.com:$PS/v1/a credential=api header=Authorization:Bearer"
    echo "allow request GET https://api.example.com:$PS/v1/b credential=db header=X-Api-Key"
    echo "allow request POST https://api.example.com:$PS/v1/c credential=st header=X-Token"
    echo "allow request GET https://api.example.com:$PS/v1/d credential=gh header=Authorization:token"
    echo "allow request GET https://api.example.com:$PS/v1/plain?q=*"
    for d in /usr/ /lib /etc/ssl/ "$AG/"; do echo "allow path $d readonly"; done
    echo "allow path /etc/ld.so.cache readonly"
} > "$POL"
chmod 644 "$POL"
WOPTS=(--secrets-conf "$S/secrets.conf" --dns-server "127.0.0.1:$DP" --trust-bundle "$OUT/bundle.pem")
[ -n "$KEY" ] && WOPTS+=(--sign-key "$KEY")

# revoked near the end: every turn after it must be refused
LEAD=$(python3 -c "print(int(min(max(5 * float('$INTERVAL'), 30), $SECS / 2)))")
echo "soak.sh: $HOURS h, one call every $INTERVAL s (every tenth a probe), revoked $LEAD s before the end, into $OUT"
"$V14/warden" "$POL" "${WOPTS[@]}" --check-credentials || { echo "soak.sh: the Warden would not start"; exit 1; }
T0=$(date +%s)
env -i PATH=/usr/bin:/bin "$V14/warden" "$POL" "${WOPTS[@]}" -- \
    /usr/bin/python3 "$AG/soak_agent.py" --interval "$INTERVAL" --seconds "$SECS" --port "$PS" --store "$S/api.key" \
    > "$OUT/agent.jsonl" 2> "$OUT/verdicts.log" &
W=$!
RUN=""
for _ in $(seq 300); do
    RUN=$(sed -n 's/^.*revocation: varek revoke \([0-9a-f]\{32\}\) .*$/\1/p' "$OUT/verdicts.log" | head -1)
    [ -n "$RUN" ] && break
    kill -0 "$W" 2>/dev/null || break
    sleep 0.2
done
[ -n "$RUN" ] || echo "soak.sh: the Warden named no control socket; the run cannot be revoked" >&2
# each helper's memory, every ten turns (and once at the start)
SAMPLE=$(python3 -c "print(max(int(10 * float('$INTERVAL')), 30))")
( printf 't\twarden_kb\tproxy_kb\tsecrets_kb\n'
  while kill -0 "$W" 2>/dev/null; do
      rss() { ps -o rss= -p "$1" 2>/dev/null | tr -d ' '; }
      px=$(pgrep -fx 'warden-proxy [0-9]+:[0-9]+' | head -1); sx=$(pgrep -fx 'warden-secrets [0-9]+:[0-9]+' | head -1)
      printf '%s\t%s\t%s\t%s\n' "$(date +%s)" "$(rss "$W")" "${px:+$(rss "$px")}" "${sx:+$(rss "$sx")}"
      sleep "$SAMPLE"
  done ) > "$OUT/rss.tsv" &
PIDS="$PIDS $!"
if [ -n "$RUN" ]; then
    ( sleep $((SECS - LEAD - ($(date +%s) - T0))) 2>/dev/null
      kill -0 "$W" 2>/dev/null || exit 0
      t=$(date +%s.%N)
      o=$(python3 "$V14/tools/varek" revoke "$RUN" 2>&1)
      printf '%s\t%s\t%s\n' "$t" "$(date +%s.%N)" "$o" > "$OUT/revoke.txt" ) &
    PIDS="$PIDS $!"
fi
wait "$W"
echo "soak.sh: the agent finished (exit $?); checking"
sleep 1
PK=()
[ -n "$KEY" ] && [ -e "$KEY.pub" ] && PK=(--pubkey "$KEY.pub")
python3 "$HERE/soak_check.py" --dir "$OUT" --policy "$POL" --checker "$V14/tools/vdp_cert_check" \
    --values "$S/values.json" --hours "$HOURS" --interval "$INTERVAL" "${PK[@]}"
