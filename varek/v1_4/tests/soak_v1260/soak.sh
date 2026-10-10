#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# soak.sh — the v1.26 soak test (docs/security/v1.26-egress-proxy.md, section
# 6): an agent under the Warden, with the egress proxy on in SNI mode, fetches
# real APIs behind Fastly, Cloudflare and CloudFront, one request a minute,
# for 24 hours, with every tenth fetch a probe the policy must refuse; then
# soak_check.py judges the run.
#
# Run as root on a host with outbound HTTPS (the droplet), from a checkout
# with the Warden built (make -C varek/v1_4 all):
#
#   sudo varek/v1_4/tests/soak_v1260/soak.sh [--hours 24] [--interval 60] \
#        [--out DIR] [--sign-key KEY] [--dns-server A:P] [--upstream URL] \
#        [--rules 'name:port,...'] [--urls URL,...] [--probe-via NAME] [--insecure]
#
# The default workload (URLS below) and its policy (RULES): PyPI's JSON API
# (Fastly), Cloudflare's public IP list API and its trace endpoint over HTTPS
# and plain HTTP (Cloudflare, the HTTPS one by a wildcard rule), and AWS's IP
# ranges (CloudFront), each fetched with a small Range. --upstream chains the
# proxy to a customer proxy (section 5).
#
# The run writes DIR/verdicts.log, DIR/agent.jsonl, DIR/policy.txt and, at
# the end, DIR/report.txt. It holds the terminal for the whole run: start it
# with nohup (see README.md).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
V14="$(cd "$HERE/../.." && pwd)"
HOURS=24 INTERVAL=60 OUT="" KEY="" DNS="" UPSTREAM="" INSECURE=""
URLS='https://pypi.org/pypi/sampleproject/json,https://api.cloudflare.com/client/v4/ips,https://www.cloudflare.com/cdn-cgi/trace,https://ip-ranges.amazonaws.com/ip-ranges.json,http://www.cloudflare.com/cdn-cgi/trace'
RULES='pypi.org:443,api.cloudflare.com:443,ip-ranges.amazonaws.com:443,www.cloudflare.com:80,*.cloudflare.com:443 acknowledge=dns-channel'
PROBE_VIA=pypi.org
while [ $# -gt 0 ]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --sign-key) KEY="$2"; shift 2 ;;
        --dns-server) DNS="$2"; shift 2 ;;
        --upstream) UPSTREAM="$2"; shift 2 ;;
        --urls) URLS="$2"; shift 2 ;;
        --rules) RULES="$2"; shift 2 ;;
        --probe-via) PROBE_VIA="$2"; shift 2 ;;
        --insecure) INSECURE=--insecure; shift ;;
        *) echo "unknown option $1"; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "soak.sh: run as root (the Warden and its proxy need it)"; exit 2; }
for b in warden warden-proxy tools/vdp_cert_check; do
    [ -x "$V14/$b" ] || { echo "soak.sh: build first: make -C $V14 all"; exit 2; }
done
OUT="${OUT:-/var/tmp/varek-soak126-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
chmod 755 "$OUT"
AG=/opt/varek-soak126-agent              # outside every path the policy lets the agent write
mkdir -p "$AG"
cp "$HERE/soak_agent.py" "$AG/"
chmod 755 "$AG"; chmod 644 "$AG/soak_agent.py"

POL="$OUT/policy.txt"
{
    echo "# v1.26 soak test policy (soak.sh)"
    echo "require warden 1.26"
    echo "proxy on"
    [ -n "$UPSTREAM" ] && echo "proxy upstream $UPSTREAM"
    IFS=, read -r -a RL <<< "$RULES"
    for r in "${RL[@]}"; do echo "allow host $r"; done
    for d in /usr/ /lib /etc/ssl/ /etc/ca-certificates/ /etc/pki/ "$AG/"; do echo "allow path $d readonly"; done
    echo "allow path /etc/ld.so.cache readonly"
} > "$POL"

SECS=$(python3 -c "print(int(float('$HOURS') * 3600))")
WOPTS=()
[ -n "$KEY" ] && WOPTS+=(--sign-key "$KEY")
[ -n "$DNS" ] && WOPTS+=(--dns-server "$DNS")
IFS=, read -r -a ULIST <<< "$URLS"

echo "soak.sh: $HOURS h, one of ${#ULIST[@]} URLs every $INTERVAL s (every tenth a refused probe), into $OUT"
"$V14/warden" "$POL" "${WOPTS[@]}" --check-startup || { echo "soak.sh: the Warden would not start"; exit 1; }
env -i PATH=/usr/bin:/bin "$V14/warden" "$POL" "${WOPTS[@]}" -- \
    /usr/bin/python3 "$AG/soak_agent.py" --interval "$INTERVAL" --seconds "$SECS" \
    --probe-via "$PROBE_VIA" $INSECURE "${ULIST[@]}" > "$OUT/agent.jsonl" 2> "$OUT/verdicts.log"
echo "soak.sh: the agent finished (exit $?); checking"

PK=()
[ -n "$KEY" ] && [ -e "$KEY.pub" ] && PK=(--pubkey "$KEY.pub")
python3 "$HERE/soak_check.py" --dir "$OUT" --policy "$POL" --checker "$V14/tools/vdp_cert_check" \
    --hours "$HOURS" --interval "$INTERVAL" "${PK[@]}"
