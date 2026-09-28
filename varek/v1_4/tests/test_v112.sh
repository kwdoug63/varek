#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v112.sh — regression test for the five mediation fixes in VAREK v1.12.
#
#   1. `..` traversal out of an allowed directory       -> refused
#   2. symlink inside an allowed directory              -> refused
#   3. /proc/self magic link (supervisor's context)     -> refused
#   4. audit-log forgery via a crafted pathname         -> record stays sound
#   5. datagram egress via sendto AND sendmsg           -> refused
#   + a legitimate open inside the allowed directory    -> still succeeds
#   + the verdict stream is valid JSON, one object/line -> no forged record
#
# Usage: ./test_v112.sh <warden> <policy> <probe_bin>
# Exit 0 iff every assertion holds.
set -u

WARDEN="${1:?usage: test_v112.sh <warden> <policy> <probe>}"
POLICY="${2:?}"
PROBE="${3:?}"

fail=0
note() { printf '  %-6s %s\n' "$1" "$2"; }
check() { # check <desc> <cond-cmd...>
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then note PASS "$desc"; else note FAIL "$desc"; fail=1; fi
}

# --- fixtures --------------------------------------------------------------
ALLOW=/tmp/varek_allowed_probe
rm -rf "$ALLOW"; mkdir -p "$ALLOW"
echo "legitimate content" > "$ALLOW/ok.txt"
ln -sf /etc/shadow "$ALLOW/link_to_shadow"

OUT="$(mktemp)"
# Warden JSON -> stderr, probe -> stdout; keep them separate.
"$WARDEN" "$POLICY" -- "$PROBE" >"$OUT.stdout" 2>"$OUT.stderr"

VERDICTS="$OUT.stderr"
PROBEOUT="$OUT.stdout"

echo "== probe self-report =="
cat "$PROBEOUT" | sed 's/^/  /'

echo "== assertions =="

# The probe must have completed (not been killed).
check "probe ran to completion" grep -q '^PROBE done' "$PROBEOUT"

# No probe line may report a BYPASS.
if grep -q 'BYPASSED' "$PROBEOUT"; then note FAIL "no bypass reported by probe"; fail=1
else note PASS "no bypass reported by probe"; fi

# The one legitimate open must have worked.
check "legit open inside allowed dir succeeds" grep -q '^PROBE legit_open .*OK' "$PROBEOUT"

# Each bypass must appear in the Warden log as a non-ALLOW final decision.
assert_denied() { # assert_denied <target-substring> <label>
    local sub="$1" label="$2"
    # every verdict record whose target contains <sub> must be DENY-final.
    if grep -F "$sub" "$VERDICTS" | grep -q '"decision_final":"ALLOW"'; then
        note FAIL "$label denied in verdict log"; fail=1
    elif grep -F "$sub" "$VERDICTS" | grep -q '"decision_final":"DENY"'; then
        note PASS "$label denied in verdict log"
    else
        note FAIL "$label present in verdict log"; fail=1
    fi
}
assert_denied '/../../etc/shadow'  "dotdot traversal"
assert_denied 'link_to_shadow'     "symlink escape"
assert_denied '/proc/self/mem'     "proc/self magic link"
assert_denied '127.0.0.1:9999'     "udp sendto egress"

# Audit-log soundness: no record with report_id "FORGED" may exist, and every
# line of the verdict stream must be a single well-formed JSON object.
if grep -q '"report_id":"FORGED"' "$VERDICTS"; then
    note FAIL "no forged verdict record injected"; fail=1
else
    note PASS "no forged verdict record injected"
fi

if command -v python3 >/dev/null 2>&1; then
    if python3 - "$VERDICTS" <<'PY'
import json, sys
ok = True
for ln in open(sys.argv[1]):
    ln = ln.strip()
    if not ln.startswith('{'):  # human status lines, relayed [agent] output
        continue
    try:
        json.loads(ln)
    except Exception:
        ok = False
        break
sys.exit(0 if ok else 1)
PY
    then note PASS "every verdict line is well-formed JSON"
    else note FAIL "every verdict line is well-formed JSON"; fail=1; fi
fi

rm -f "$OUT" "$OUT.stdout" "$OUT.stderr"
rm -rf "$ALLOW"

echo
if [ "$fail" -eq 0 ]; then echo "ALL PASSED (v1.12 mediation)"; else echo "FAILURES PRESENT"; fi
exit "$fail"
