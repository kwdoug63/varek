#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# soak.sh — the v1.27 soak test (docs/security/v1.27-program-launches.md,
# section 7): an agent under the Warden, with `require warden 1.27`, launches
# git, python3 and (where a compiler is installed) a compile, one task a
# minute for 24 hours; every tenth turn is a launch the policy must refuse.
# Then soak_check.py judges the run.
#
# Run as root on a host with Landlock, from a checkout with the Warden built
# (make -C varek/v1_4 all):
#
#   sudo varek/v1_4/tests/soak_v1270/soak.sh [--hours 24] [--interval 60] [--out DIR] [--sign-key KEY]
#
# The run writes DIR/verdicts.log, DIR/agent.jsonl, DIR/policy.txt and, at the
# end, DIR/report.txt. It holds the terminal for the whole run: start it with
# nohup (see README.md).
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
[ "$(id -u)" = 0 ] || { echo "soak.sh: run as root"; exit 2; }
for b in warden tools/vdp_cert_check; do
    [ -x "$V14/$b" ] || { echo "soak.sh: build first: make -C $V14 all"; exit 2; }
done
OUT="${OUT:-/var/tmp/varek-soak1270-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"; chmod 755 "$OUT"
AG=/opt/varek-soak1270-agent                 # the agent's script, read-only to it
WK=/var/tmp/varek-soak1270-work              # its work directory (written)
rm -rf "$WK"; mkdir -p "$AG" "$WK/run"; chmod 755 "$AG"; chmod 777 "$WK" "$WK/run"
cp "$HERE/soak_agent.py" "$AG/"; chmod 644 "$AG/soak_agent.py"
printf 'int main(void) { return 0; }\n' > "$WK/t.c"; chmod 644 "$WK/t.c"
CC="" CCP=""
if [ -x /usr/bin/cc ]; then
    v="$(/usr/bin/cc -dumpversion 2>/dev/null | cut -d. -f1)"
    for d in "/usr/libexec/gcc/x86_64-linux-gnu/$v" "/usr/libexec/gcc/x86_64-redhat-linux/$v" "/usr/libexec/gcc/x86_64-amazon-linux/$v"; do
        [ -x "$d/cc1" ] && CCP="$d" && break
    done
    [ -n "$CCP" ] && [ -x /usr/bin/as ] && [ -x /usr/bin/ld ] && CC=--cc
fi
POL="$OUT/policy.txt"
{
    echo "# v1.27 soak test policy (soak.sh)"
    echo "require warden 1.27"
    echo "deny exec /usr/bin/env"
    echo "allow exec /usr/bin/python3"
    echo "allow exec /usr/bin/git"
    if [ -n "$CC" ]; then
        echo "allow exec /usr/bin/cc"; echo "allow exec /usr/bin/as"; echo "allow exec /usr/bin/ld"
        echo "allow exec prefix $CCP/"
    fi
    echo "allow exec prefix $WK/run/"
    echo "allow path $WK/"
    for d in /usr/ /lib /etc/ "$AG/"; do echo "allow path $d readonly"; done
    echo "allow path /dev/null"
} > "$POL"
chmod 644 "$POL"
SECS=$(python3 -c "print(int(float('$HOURS') * 3600))")
WOPTS=()
[ -n "$KEY" ] && WOPTS+=(--sign-key "$KEY")
echo "soak.sh: $HOURS h, one task every $INTERVAL s (every tenth a probe that must be refused)${CC:+, compiles with $CCP}, into $OUT"
"$V14/warden" "$POL" "${WOPTS[@]}" --check-startup || { echo "soak.sh: the Warden would not start"; exit 1; }
(cd "$WK" && env -i PATH=/usr/bin:/bin "$V14/warden" "$POL" "${WOPTS[@]}" -- \
    /usr/bin/python3 "$AG/soak_agent.py" --interval "$INTERVAL" --seconds "$SECS" --work "$WK" $CC \
    > "$OUT/agent.jsonl" 2> "$OUT/verdicts.log")
echo "soak.sh: the agent finished (exit $?); checking"
PK=()
[ -n "$KEY" ] && [ -e "$KEY.pub" ] && PK=(--pubkey "$KEY.pub")
python3 "$HERE/soak_check.py" --dir "$OUT" --policy "$POL" --checker "$V14/tools/vdp_cert_check" \
    --hours "$HOURS" --interval "$INTERVAL" "${PK[@]}"
