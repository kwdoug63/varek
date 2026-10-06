#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# soak.sh — the v1.25 soak test (docs/security/v1.25-wildcard-host-names.md,
# section 5): an agent under the Warden fetches a real API reached through
# many names under one suffix, one name a minute in turn, for 24 hours, with a
# wildcard rule at the default budgets; then soak_check.py judges the run.
#
# Run as root on a host with outbound HTTPS (the droplet), from a checkout
# with the Warden built (make -C varek/v1_4 all):
#
#   sudo varek/v1_4/tests/soak_v1250/soak.sh [--hours 24] [--interval 60] \
#        [--out DIR] [--sign-key KEY] [--dns-server A:P] \
#        [--suffix wikipedia.org --port 443 --template URL --names a,b,...]
#
# The default workload: the Wikipedia API (siteinfo) of 40 language editions,
# https://<lang>.wikipedia.org/w/api.php?..., under `allow host
# *.wikipedia.org:443`. Wikimedia alone creates names under wikipedia.org
# (so the wildcard is not refused as a shared domain), and every edition is
# served from the same addresses, as per-tenant names behind a CDN are. One
# request a minute in all, with a User-Agent naming this project, as
# Wikimedia's API etiquette asks.
#
# The run writes DIR/verdicts.log, DIR/agent.jsonl, DIR/policy.txt and, at
# the end, DIR/report.txt. It holds the terminal for the whole run: start it
# with nohup (see README.md).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
V14="$(cd "$HERE/../.." && pwd)"
HOURS=24 INTERVAL=60 OUT="" KEY="" DNS=""
SUFFIX=wikipedia.org PORT=443
TEMPLATE='https://{name}/w/api.php?action=query&meta=siteinfo&format=json'
LANGS=en,de,fr,ja,es,ru,it,zh,pt,pl,nl,ar,fa,uk,sv,id,vi,ko,he,tr,cs,fi,no,hu,ro,el,da,th,bg,ca,sr,ms,hi,sk,eo,eu,lt,sl,et,simple
NAMES=""
while [ $# -gt 0 ]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --sign-key) KEY="$2"; shift 2 ;;
        --dns-server) DNS="$2"; shift 2 ;;
        --suffix) SUFFIX="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --template) TEMPLATE="$2"; shift 2 ;;
        --names) NAMES="$2"; shift 2 ;;
        *) echo "unknown option $1"; exit 2 ;;
    esac
done
if [ -z "$NAMES" ]; then
    NAMES=$(echo "$LANGS" | tr ',' '\n' | sed "s/\$/.$SUFFIX/" | paste -sd, -)
fi
[ "$(id -u)" = 0 ] || { echo "soak.sh: run as root (the Warden needs CAP_SYS_ADMIN)"; exit 2; }
for b in warden tools/vdp_cert_check; do
    [ -x "$V14/$b" ] || { echo "soak.sh: build first: make -C $V14 all"; exit 2; }
done
OUT="${OUT:-/var/tmp/varek-soak125-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
chmod 755 "$OUT"
AG=/opt/varek-soak125-agent              # outside every path the policy lets the agent write
mkdir -p "$AG"
cp "$HERE/soak_agent.py" "$AG/"
chmod 755 "$AG"; chmod 644 "$AG/soak_agent.py"

# The policy: one wildcard at the default budgets (section 5 checks that
# normal use stays within them), and what Python and its TLS need to read.
POL="$OUT/policy.txt"
{
    echo "# v1.25 soak test policy (soak.sh)"
    echo "require warden 1.25"
    echo "allow host *.$SUFFIX:$PORT"
    for d in /usr/ /lib /etc/ssl/ /etc/ca-certificates/ /etc/pki/ "$AG/"; do echo "allow path $d readonly"; done
    echo "allow path /etc/ld.so.cache readonly"
} > "$POL"

SECS=$(python3 -c "print(int(float('$HOURS') * 3600))")
WOPTS=()
[ -n "$KEY" ] && WOPTS+=(--sign-key "$KEY")
[ -n "$DNS" ] && WOPTS+=(--dns-server "$DNS")
IFS=, read -r -a NLIST <<< "$NAMES"

echo "soak.sh: $HOURS h, one of ${#NLIST[@]} names every $INTERVAL s, into $OUT"
"$V14/warden" "$POL" "${WOPTS[@]}" --check-startup || { echo "soak.sh: the Warden would not start"; exit 1; }
env -i PATH=/usr/bin:/bin "$V14/warden" "$POL" "${WOPTS[@]}" -- \
    /usr/bin/python3 "$AG/soak_agent.py" --interval "$INTERVAL" --seconds "$SECS" \
    --template "$TEMPLATE" "${NLIST[@]}" > "$OUT/agent.jsonl" 2> "$OUT/verdicts.log"
echo "soak.sh: the agent finished (exit $?); checking"

PK=()
[ -n "$KEY" ] && [ -e "$KEY.pub" ] && PK=(--pubkey "$KEY.pub")
python3 "$HERE/soak_check.py" --dir "$OUT" --policy "$POL" --checker "$V14/tools/vdp_cert_check" \
    --hours "$HOURS" --interval "$INTERVAL" --port "$PORT" "${PK[@]}"
