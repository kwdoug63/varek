#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# soak.sh — the v1.24 soak test (docs/security/v1.21-stage2-host-names.md,
# section 5): an agent under the Warden fetches real CDN-hosted APIs, by name,
# every minute for 24 hours; then soak_check.py judges the run.
#
# Run as root on a host with outbound HTTPS (the droplet), from a checkout
# with the Warden built (make -C varek/v1_4 all):
#
#   sudo varek/v1_4/tests/soak_v1240/soak.sh [--hours 24] [--interval 60] \
#        [--out DIR] [--sign-key KEY] [--url URL=cdn ...] [--dns-server A:P]
#
# Default URLs, one per content network (check them with --hours 0.05 first):
#   https://pypi.org/robots.txt                     Fastly
#   https://www.cloudflare.com/cdn-cgi/trace        Cloudflare
#   https://aws.amazon.com/robots.txt             CloudFront
# A URL whose responses do not show the expected network's headers fails the
# check, so a target that moved to another network is noticed.
#
# The run writes DIR/verdicts.log (the verdict stream), DIR/agent.jsonl (one
# line per fetch), DIR/policy.txt and, at the end, DIR/report.txt. It holds
# the terminal for the whole run: start it in tmux or screen, or with nohup.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
V14="$(cd "$HERE/../.." && pwd)"
HOURS=24 INTERVAL=60 OUT="" KEY="" DNS=""
URLS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --sign-key) KEY="$2"; shift 2 ;;
        --url) URLS+=("$2"); shift 2 ;;
        --dns-server) DNS="$2"; shift 2 ;;
        *) echo "unknown option $1"; exit 2 ;;
    esac
done
[ ${#URLS[@]} -gt 0 ] || URLS=("https://pypi.org/robots.txt=fastly"
                               "https://www.cloudflare.com/cdn-cgi/trace=cloudflare"
                               "https://aws.amazon.com/robots.txt=cloudfront")
[ "$(id -u)" = 0 ] || { echo "soak.sh: run as root (the Warden needs CAP_SYS_ADMIN)"; exit 2; }
for b in warden tools/vdp_cert_check; do
    [ -x "$V14/$b" ] || { echo "soak.sh: build first: make -C $V14 all"; exit 2; }
done
OUT="${OUT:-/var/tmp/varek-soak-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
chmod 755 "$OUT"
AG=/opt/varek-soak-agent                 # outside every path the policy lets the agent write
mkdir -p "$AG"
cp "$HERE/soak_agent.py" "$AG/"
chmod 755 "$AG"; chmod 644 "$AG/soak_agent.py"

# The policy: the three names on 443, and what Python and its TLS need to read.
POL="$OUT/policy.txt"
{
    echo "# v1.24 soak test policy (soak.sh)"
    echo "require warden 1.24"
    for u in "${URLS[@]}"; do
        h=$(python3 -c 'import sys, urllib.parse as p; u = p.urlsplit(sys.argv[1]); print("%s:%d" % (u.hostname, u.port or (443 if u.scheme == "https" else 80)))' "${u%=*}")
        echo "allow host $h"
    done
    for d in /usr/ /lib /etc/ssl/ /etc/ca-certificates/ /etc/pki/ "$AG/"; do echo "allow path $d readonly"; done
    echo "allow path /etc/ld.so.cache readonly"
} > "$POL"

SECS=$(python3 -c "print(int(float('$HOURS') * 3600))")
ARGS=()
for u in "${URLS[@]}"; do ARGS+=("${u%=*}"); done
WOPTS=()
[ -n "$KEY" ] && WOPTS+=(--sign-key "$KEY")
[ -n "$DNS" ] && WOPTS+=(--dns-server "$DNS")

echo "soak.sh: $HOURS h, every $INTERVAL s, into $OUT"
"$V14/warden" "$POL" "${WOPTS[@]}" --check-startup || { echo "soak.sh: the Warden would not start"; exit 1; }
env -i PATH=/usr/bin:/bin "$V14/warden" "$POL" "${WOPTS[@]}" -- \
    /usr/bin/python3 "$AG/soak_agent.py" --interval "$INTERVAL" --seconds "$SECS" "${ARGS[@]}" \
    > "$OUT/agent.jsonl" 2> "$OUT/verdicts.log"
echo "soak.sh: the agent finished (exit $?); checking"

EXP=()
for u in "${URLS[@]}"; do [ "${u#*=}" != "$u" ] && EXP+=(--expect "$u"); done
PK=()
[ -n "$KEY" ] && [ -e "$KEY.pub" ] && PK=(--pubkey "$KEY.pub")
python3 "$HERE/soak_check.py" --dir "$OUT" --policy "$POL" --checker "$V14/tools/vdp_cert_check" \
    --hours "$HOURS" --interval "$INTERVAL" "${EXP[@]}" "${PK[@]}"
