#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# soak.sh — the v1.26.1 soak test (docs/security/v1.26.1-inspecting-mode.md,
# section 6): the v1.26.0 soak (tests/soak_v1260) with the egress proxy in
# inspecting mode. An agent under the Warden fetches real APIs behind Fastly,
# Cloudflare and CloudFront, one request a minute, for 24 hours; each server
# is verified by the proxy, the agent's TLS is terminated with the run's CA,
# and each request is decided on its method, path and query by a request
# rule. Every tenth fetch is a probe the policy must refuse (domain fronting
# by SNI and by Host, a path written another way, a path a deny rule refuses,
# a path no rule allows). Then soak_check.py judges the run.
#
# Run as root on a host with outbound HTTPS (the droplet), from a checkout
# with the Warden built (make -C varek/v1_4 all):
#
#   sudo varek/v1_4/tests/soak_v1261/soak.sh [--hours 24] [--interval 60] \
#        [--out DIR] [--sign-key KEY] [--dns-server A:P] [--upstream URL] \
#        [--trust-bundle PEM] [--rules 'name:port,...'] [--requests 'METHOD URL,...'] \
#        [--urls URL,...] [--probe-via NAME --probe-path P --denied-path P --unlisted-path P]
#        [--insecure]
#
# The probes go to --probe-via (pypi.org): --probe-path must be a path a
# request rule allows there, --denied-path one the --deny rule refuses, and
# --unlisted-path one no rule allows; change them with --probe-via or --deny.
#
# The run writes DIR/verdicts.log, DIR/agent.jsonl, DIR/policy.txt and, at
# the end, DIR/report.txt. It holds the terminal for the whole run: start it
# with nohup (see README.md).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
V14="$(cd "$HERE/../.." && pwd)"
HOURS=24 INTERVAL=60 OUT="" KEY="" DNS="" UPSTREAM="" INSECURE="" TRUST=""
URLS='https://pypi.org/pypi/sampleproject/json,https://api.cloudflare.com/client/v4/ips,https://www.cloudflare.com/cdn-cgi/trace,https://ip-ranges.amazonaws.com/ip-ranges.json,http://www.cloudflare.com/cdn-cgi/trace'
RULES='pypi.org:443,api.cloudflare.com:443,ip-ranges.amazonaws.com:443,www.cloudflare.com:80,*.cloudflare.com:443 acknowledge=dns-channel'
# one request rule per URL (the Cloudflare trace over HTTPS by a wildcard
# host), and the deny rule the "denied" probe meets
REQUESTS='GET https://pypi.org/pypi/sampleproject/json,GET https://api.cloudflare.com/client/v4/ips,GET https://*.cloudflare.com/cdn-cgi/trace,GET https://ip-ranges.amazonaws.com/ip-ranges.json,GET http://www.cloudflare.com/cdn-cgi/trace'
DENY='* https://pypi.org/simple/**'
PROBE_VIA=pypi.org PROBE_PATH=/pypi/sampleproject/json DENIED_PATH=/simple/pip/ UNLISTED_PATH=/pypi/pip/json
while [ $# -gt 0 ]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --sign-key) KEY="$2"; shift 2 ;;
        --dns-server) DNS="$2"; shift 2 ;;
        --upstream) UPSTREAM="$2"; shift 2 ;;
        --trust-bundle) TRUST="$2"; shift 2 ;;
        --urls) URLS="$2"; shift 2 ;;
        --rules) RULES="$2"; shift 2 ;;
        --requests) REQUESTS="$2"; shift 2 ;;
        --deny) DENY="$2"; shift 2 ;;
        --probe-via) PROBE_VIA="$2"; shift 2 ;;
        --probe-path) PROBE_PATH="$2"; shift 2 ;;       # an allowed path of --probe-via
        --denied-path) DENIED_PATH="$2"; shift 2 ;;     # one --deny refuses there
        --unlisted-path) UNLISTED_PATH="$2"; shift 2 ;; # one no rule allows there
        --insecure) INSECURE=--insecure; shift ;;
        *) echo "unknown option $1"; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "soak.sh: run as root (the Warden and its proxy need it)"; exit 2; }
for b in warden warden-proxy tools/vdp_cert_check; do
    [ -x "$V14/$b" ] || { echo "soak.sh: build first: make -C $V14 all"; exit 2; }
done
OUT="${OUT:-/var/tmp/varek-soak1261-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
chmod 755 "$OUT"
AG=/opt/varek-soak1261-agent             # outside every path the policy lets the agent write
mkdir -p "$AG"
cp "$HERE/soak_agent.py" "$AG/"
chmod 755 "$AG"; chmod 644 "$AG/soak_agent.py"

POL="$OUT/policy.txt"
{
    echo "# v1.26.1 soak test policy (soak.sh)"
    echo "require warden 1.26"
    echo "proxy inspect"
    [ -n "$UPSTREAM" ] && echo "proxy upstream $UPSTREAM"
    IFS=, read -r -a RL <<< "$RULES"
    for r in "${RL[@]}"; do echo "allow host $r"; done
    [ -n "$DENY" ] && echo "deny request $DENY"
    IFS=, read -r -a QL <<< "$REQUESTS"
    for r in "${QL[@]}"; do echo "allow request $r"; done
    for d in /usr/ /lib /etc/ssl/ /etc/ca-certificates/ /etc/pki/ "$AG/"; do echo "allow path $d readonly"; done
    echo "allow path /etc/ld.so.cache readonly"
} > "$POL"

SECS=$(python3 -c "print(int(float('$HOURS') * 3600))")
WOPTS=()
[ -n "$KEY" ] && WOPTS+=(--sign-key "$KEY")
[ -n "$DNS" ] && WOPTS+=(--dns-server "$DNS")
[ -n "$TRUST" ] && WOPTS+=(--trust-bundle "$TRUST")
IFS=, read -r -a ULIST <<< "$URLS"

echo "soak.sh: $HOURS h, one of ${#ULIST[@]} URLs every $INTERVAL s (every tenth a refused probe), inspecting mode, into $OUT"
"$V14/warden" "$POL" "${WOPTS[@]}" --check-startup || { echo "soak.sh: the Warden would not start"; exit 1; }
env -i PATH=/usr/bin:/bin "$V14/warden" "$POL" "${WOPTS[@]}" -- \
    /usr/bin/python3 "$AG/soak_agent.py" --interval "$INTERVAL" --seconds "$SECS" \
    --probe-via "$PROBE_VIA" --probe-path "$PROBE_PATH" --denied-path "$DENIED_PATH" \
    --unlisted-path "$UNLISTED_PATH" $INSECURE "${ULIST[@]}" > "$OUT/agent.jsonl" 2> "$OUT/verdicts.log"
echo "soak.sh: the agent finished (exit $?); checking"

PK=()
[ -n "$KEY" ] && [ -e "$KEY.pub" ] && PK=(--pubkey "$KEY.pub")
python3 "$HERE/soak_check.py" --dir "$OUT" --policy "$POL" --checker "$V14/tools/vdp_cert_check" \
    --hours "$HOURS" --interval "$INTERVAL" "${PK[@]}"
