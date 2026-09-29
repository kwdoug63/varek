#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1124.sh — regression test for the --plan file-open gate (VAREK v1.12.4).
#
# Since v1.12.0 policy_decide() has decided a file open on the RESOLVED canonical
# path, but the plan decider (verified before the agent is forked) left that
# field empty, so every file_open node came back UNKNOWN and the gate rejected
# every plan that opened a file. v1.12.4 fills the field with the lexically
# canonical form of the declared absolute path.
#
# This suite drives the real Warden's --plan path and asserts on the plan_verify
# record and the "plan authorized"/"plan rejected" line. Nothing is forked: the
# target is /bin/true and we only read the pre-fork decision.
#
# Usage: ./test_v1124.sh <warden>
# Exit 0 iff every assertion holds.
set -u

WARDEN="${1:?usage: test_v1124.sh <warden>}"
fail=0
pass() { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }

OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
POLICY="$OUT/policy.txt"
cat > "$POLICY" <<'EOF'
allow path /var/data/
allow path /etc/ld.so.cache
allow exec /usr/bin/python3
deny  host api.example.com
allow host 127.0.0.1:8080
EOF

# run_plan <plan-text> -> sets $VERDICT (SATISFIED/UNSATISFIED/UNKNOWN) and $LINE
run_plan() {
    printf '%s\n' "$1" > "$OUT/plan.txt"
    local o
    o="$("$WARDEN" "$POLICY" --plan "$OUT/plan.txt" -- /bin/true 2>&1 || true)"
    VERDICT="$(sed -n 's/.*"type":"plan_verify".*"decision":"\([A-Z]*\)".*/\1/p' <<<"$o" | head -1)"
    if grep -q 'plan authorized' <<<"$o"; then LINE=authorized
    elif grep -q 'plan rejected' <<<"$o"; then LINE=rejected
    elif grep -q 'plan load failed' <<<"$o"; then LINE=loadfail
    else LINE=none; fi
    FORKED=no; grep -q 'supervising pid=' <<<"$o" && FORKED=yes
}

expect() { # expect <desc> <wanted-verdict> <wanted-line>
    local desc="$1" wv="$2" wl="$3"
    if [ "$VERDICT" = "$wv" ] && [ "$LINE" = "$wl" ]; then pass "$desc"
    else flunk "$desc (got decision=$VERDICT line=$LINE)"; fi
}

echo "== the fix: a plan that opens an allowed file is authorized =="
run_plan 'action load file_open /var/data/input.json
action audit file_open /var/data/audit.log
edge load audit'
expect "allowed file_opens are SATISFIED" SATISFIED authorized
[ "$FORKED" = yes ] && pass "target is forked after an authorized plan" || flunk "target is forked after an authorized plan"

echo "== a file_open the policy does not cover is UNKNOWN (rejected) =="
run_plan 'action load file_open /home/secret.txt'
expect "unlisted file_open is UNKNOWN" UNKNOWN rejected
[ "$FORKED" = no ] && pass "target is NOT forked after a rejected plan" || flunk "target is NOT forked after a rejected plan"

echo "== a file_open the policy denies is UNSATISFIED =="
# First-match-wins, so the deny must precede the broad allow to take effect.
DENYPOL="$OUT/deny_policy.txt"
cat > "$DENYPOL" <<'EOF'
deny  path /var/data/secret/
allow path /var/data/
EOF
run_plan_with() { # run_plan_with <policy> <plan>
    printf '%s\n' "$2" > "$OUT/plan.txt"
    local o
    o="$("$WARDEN" "$1" --plan "$OUT/plan.txt" -- /bin/true 2>&1 || true)"
    VERDICT="$(sed -n 's/.*"type":"plan_verify".*"decision":"\([A-Z]*\)".*/\1/p' <<<"$o" | head -1)"
    if grep -q 'plan authorized' <<<"$o"; then LINE=authorized
    elif grep -q 'plan rejected' <<<"$o"; then LINE=rejected; else LINE=none; fi
}
run_plan_with "$DENYPOL" 'action load file_open /var/data/secret/keys'
expect "explicitly denied file_open is UNSATISFIED" UNSATISFIED rejected
run_plan_with "$DENYPOL" 'action load file_open /var/data/ok.json'
expect "an allowed file under the same policy is SATISFIED" SATISFIED authorized

echo "== lexical canonicalization: . and .. collapse before the decision =="
run_plan 'action load file_open /var/data/sub/../input.json'
expect "..-inside-allowed canonicalizes and is SATISFIED" SATISFIED authorized
run_plan 'action load file_open /var/./data/./input.json'
expect "./ segments collapse and it is SATISFIED" SATISFIED authorized

echo "== .. cannot lexically escape an allowed prefix =="
run_plan 'action load file_open /var/data/../etc/shadow'
expect "..-escape to a denied path is UNKNOWN, not authorized" UNKNOWN rejected
run_plan 'action load file_open /var/data/../../etc/passwd'
expect "double ..-escape is UNKNOWN" UNKNOWN rejected

echo "== a relative plan path cannot be verified pre-fork -> UNKNOWN =="
run_plan 'action load file_open var/data/input.json'
expect "relative file_open target is UNKNOWN" UNKNOWN rejected

echo "== exec steps are UNSATISFIED even when the policy allows them =="
# v1.18.0: the runtime refuses every launch after the first, whatever the
# policy says, so a plan that needs one cannot run as declared. Through v1.17.0
# the gate authorized this plan. (v1.18.0 to v1.20.0 refused connect steps the
# same way; from v1.21 they are decided, see below.)
run_plan 'action load file_open /var/data/in.json
action exec process_exec /usr/bin/python3
action post net_connect 127.0.0.1:8080
edge load exec
edge exec post'
expect "file_open + policy-allowed exec + connect is UNSATISFIED" UNSATISFIED rejected
run_plan 'action exec process_exec /usr/bin/python3'
expect "a lone policy-allowed exec step is UNSATISFIED" UNSATISFIED rejected

echo "== a refused non-file node still rejects a plan that also opens a file =="
# v1.21: connects are decided on the numeric destination the Warden dials, so
# a host name cannot be decided before the agent runs: the step is UNKNOWN
# (through v1.20.0 every connect step was UNSATISFIED).
run_plan 'action load file_open /var/data/in.json
action post net_connect api.example.com:443
edge load post'
expect "a connect step naming a host is UNKNOWN, and rejects the plan" UNKNOWN rejected
run_plan 'action load file_open /var/data/in.json
action post net_connect 127.0.0.1:9999
edge load post'
expect "a connect step no rule allows rejects the plan" UNKNOWN rejected

echo "== v1.21: a connect step the policy allows is authorized =="
run_plan 'action load file_open /var/data/in.json
action post net_connect 127.0.0.1:8080
edge load post'
expect "file_open + policy-allowed connect is SATISFIED" SATISFIED authorized

echo
if [ "$fail" -eq 0 ]; then echo "test_v1124: PASS"; else echo "test_v1124: FAIL"; fi
exit "$fail"
