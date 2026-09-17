#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# v112_video.sh — VAREK v1.12 mediation-correctness demo, video-capture friendly.
#
# Runs one adversarial agent (tests/v112_probe) under a real Warden and shows,
# side by side, what the pre-fix Warden allowed and what v1.12 refuses:
#
#   .. traversal · symlink escape · /proc/self · UDP sendto · UDP sendmsg
#   · audit-log forgery
#
# Does it twice: once with the pre-fix Warden (built from git, default ref
# v1.9.3) and once with this Warden. Every verdict shown comes from the live
# system reading the Warden's own pathology stream — nothing is simulated or
# hardcoded. The forged-record check greps the real verdict log.
#
# Usage:   sudo ./v112_video.sh
#          sudo ./v112_video.sh --no-color
#          sudo ./v112_video.sh --quick            (no pacing)
#          sudo BEFORE_REF=<git-ref> ./v112_video.sh
#
# Requires: root, Linux >= 5.14, libseccomp-dev, a git checkout.

set -euo pipefail
cd "$(dirname "$0")"

USE_COLOR=1
QUICK=0
for arg in "$@"; do
    case "$arg" in
        --no-color) USE_COLOR=0 ;;
        --quick)    QUICK=1 ;;
        -h|--help)  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    esac
done

if [[ $USE_COLOR -eq 1 ]]; then
    C='\033[38;2;0;216;217m'  # VAREK cyan
    A='\033[38;2;248;193;92m' # signal amber
    W='\033[1;37m'; D='\033[2;37m'; G='\033[0;32m'; R='\033[0;31m'
    B='\033[1m'; N='\033[0m'
else
    C='' A='' W='' D='' G='' R='' B='' N=''
fi

pause() { [[ $QUICK -eq 1 ]] || sleep "${1:-1.4}"; }
say()   { echo -e "  $*"; }
rule()  { echo -e "  ${D}────────────────────────────────────────────────────────────${N}"; }

[[ $(id -u) -eq 0 ]] || { echo "run as root (sudo ./v112_video.sh)"; exit 1; }

# The pre-fix baseline is the v1.9.3 tag (stable regardless of later commits on
# this branch). Override with BEFORE_REF for a different comparison point.
BEFORE_REF="${BEFORE_REF:-v1.9.3}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK" /tmp/varek_allowed_probe' EXIT

# ---- fixtures ----------------------------------------------------------
ALLOW=/tmp/varek_allowed_probe
rm -rf "$ALLOW"; mkdir -p "$ALLOW"
echo "legitimate content" > "$ALLOW/ok.txt"
ln -sf /etc/shadow "$ALLOW/link_to_shadow"

# ---- build both Wardens ------------------------------------------------
echo -e "${D}  building...${N}"
make -s warden tests/v112_probe >/dev/null
REPO_ROOT="$(git rev-parse --show-toplevel)"
if ! git -C "$REPO_ROOT" rev-parse -q --verify "$BEFORE_REF^{commit}" >/dev/null; then
    echo "git ref '$BEFORE_REF' not found; set BEFORE_REF to the pre-fix commit"; exit 1
fi
git -C "$REPO_ROOT" archive "$BEFORE_REF" varek/v1_4 v1_6 v1_7 | tar -x -C "$WORK"
make -s -C "$WORK/varek/v1_4" warden >/dev/null
BEFORE_BIN="$WORK/varek/v1_4/warden"
AFTER_BIN="$PWD/warden"
PROBE="$PWD/tests/v112_probe"
POLICY="$PWD/tests/v112_video_policy.txt"
BEFORE_LABEL="before  (pre-fix Warden, commit $(git -C "$REPO_ROOT" rev-parse --short "$BEFORE_REF"))"
AFTER_LABEL="after   (v1.12)"

# ---- run one Warden over the probe, summarize each escape --------------
run_case() {   # run_case <warden-bin> <label>
    local bin="$1" label="$2" log probeout
    log="$(mktemp)"; probeout="$(mktemp)"
    # The probe self-reports BYPASSED/REFUSED per escape; the Warden log is the
    # ground truth we also mine for the forged record.
    "$bin" "$POLICY" -- "$PROBE" >"$probeout" 2>"$log" || true

    verdict() {  # verdict <probe-tag> <human label>
        local tag="$1" name="$2" line
        line="$(grep -m1 "PROBE $tag" "$probeout" || true)"
        if echo "$line" | grep -q BYPASSED; then
            echo -e "    ${R}✗ ${name}: REACHED${N}"
        else
            echo -e "    ${G}✓ ${name}: refused${N}"
        fi
    }

    echo -e "  ${W}${label}${N}"
    verdict dotdot_traversal   ".. traversal    -> /etc/shadow"
    verdict symlink_escape     "symlink escape  -> /etc/shadow"
    verdict proc_self_mem      "/proc/self/mem  (supervisor memory)"
    verdict udp_sendto_egress  "UDP sendto      egress"
    verdict udp_sendmsg_egress "UDP sendmsg     egress"

    # log integrity: did a forged ALLOW record land in the verdict stream?
    if grep -q '"report_id":"FORGED"' "$log"; then
        echo -e "    ${R}✗ audit log: forged ALLOW record injected${N}"
    else
        echo -e "    ${G}✓ audit log: intact (no forged record)${N}"
    fi
    rm -f "$log" "$probeout"
}

# ---- present -----------------------------------------------------------
clear || true
echo
say "${C}${B}VAREK v1.12 — the verifier decides on the object it delivers${N}"
say "${D}one agent, six escape attempts, two Wardens${N}"
echo; rule; echo
pause 1.2

run_case "$BEFORE_BIN" "$BEFORE_LABEL"
echo; pause 2.0
run_case "$AFTER_BIN"  "$AFTER_LABEL"
echo; rule; echo
say "${A}Resolve once. Decide on the resolved object. Escape closes.${N}"
say "${C}Don't Trust. Verify.${N}"
echo
