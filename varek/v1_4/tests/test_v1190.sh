#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1190.sh — regression test for VAREK v1.19.0: a refusal limit per
# session.
#
# Through v1.18.0 the --plan gate's breaker counted refusals per (session,
# plan): a planner that changed one step each time got a fresh count every
# time and was never stopped. v1.19.0 adds session_refusal_budget, which the
# Warden requires with --flow-policy:
#
#   1. A flow policy without it stops the Warden at startup.
#   2. Plans that differ each time are counted together; the limit makes the
#      session terminal (exit 5, the policy's on_exhaustion action), and every
#      later refused plan in it is terminal at once, whatever it is.
#   3. An authorized plan in that session still runs, and does not reset it.
#   4. Another session has its own count.
#   5. --gate-status and the plan_gate record report the session's count.
#   6. The count persists across Warden runs (state format 2); a v1.18.0
#      (format 1) table is read and its sessions start from the refusals it
#      holds.
#
# Usage: ./test_v1190.sh <warden> <vdp_cert_check> <probe>
# Exit 0 iff every check holds.
set -u

WARDEN="${1:?usage: test_v1190.sh <warden> <vdp_cert_check> <probe>}"
CERT="${2:?}"
PROBE="${3:?}"
abs() { case "$1" in /*) echo "$1";; *) echo "$PWD/$1";; esac; }
WARDEN="$(abs "$WARDEN")"; CERT="$(abs "$CERT")"; PROBE="$(abs "$PROBE")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT="$HERE/tools/varek_audit.py"

fail=0
pass()  { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }

D=/tmp/varek_v1190
OUT="$(mktemp -d)"
cleanup() { rm -rf "$D" "$OUT"; }
trap cleanup EXIT
rm -rf "$D"
mkdir -p "$D/data/secret" "$D/data/public" "$D/state"
chmod 755 "$D" "$D/data" "$D/data/secret" "$D/data/public"
chmod 700 "$D/state"
echo "top secret" > "$D/data/secret/k"
echo "hello" > "$D/data/public/ok.txt"
chmod 644 "$D/data/secret/k" "$D/data/public/ok.txt"

POL="$D/policy.txt"
printf 'allow path /tmp/varek_v1190/data/\n' > "$POL"
# Per plan 2, per session 3.
FLOW="$D/flow.cfg"
cat > "$FLOW" <<'EOF'
varek_policy 1
label SECRET 0
sticky SECRET
refusal_budget 2
session_refusal_budget 3
on_exhaustion terminal abort_txn
unknown_disposition deny
rule file_open
  match target /tmp/varek_v1190/data/secret/*
  origin SECRET
rule file_open
  match target /tmp/varek_v1190/data/public/*
  deny_in SECRET
rule file_open
rule abort_txn
EOF
STATE="$D/state/breaker"

# leak <n>: a plan that routes the secret to public/out<n> (a different plan,
# and signature, for each n).
leak() {
    printf 'action read  file_open /tmp/varek_v1190/data/secret/k\naction write file_open /tmp/varek_v1190/data/public/out%s\nedge read write\n' "$1" > "$D/leak$1.txt"
    echo "leak$1.txt"
}
printf 'action read file_open /tmp/varek_v1190/data/public/ok.txt\n' > "$D/ok.txt"

# gate <session> <plan>: run the gated Warden; set RC, G (stderr), S (gate status), R (plan_gate record).
gate() {
    "$WARDEN" "$POL" --plan "$D/$2" --flow-policy "$FLOW" --breaker-state "$STATE" \
        --session "$1" --gate-status "$D/state/gs" -- "$PROBE" > "$OUT/gate.out" 2> "$OUT/gate.err"
    RC=$?
    G="$(cat "$OUT/gate.err")"
    S="$(cat "$D/state/gs" 2>/dev/null)"
    R="$(grep '^{"event":"plan_gate"' "$OUT/gate.err" | head -1)"
}
has() { grep -q -- "$1" <<<"$G"; }

echo "== 1. the Warden requires a session_refusal_budget =="
grep -v '^session_refusal_budget' "$FLOW" > "$D/nosession.cfg"
"$WARDEN" "$POL" --plan "$D/ok.txt" --flow-policy "$D/nosession.cfg" --breaker-state "$D/state/n" \
    -- "$PROBE" > /dev/null 2> "$OUT/e.err"; rc=$?
[ "$rc" -eq 1 ] && grep -q 'declares no session_refusal_budget' "$OUT/e.err" && ! grep -q 'supervising pid=' "$OUT/e.err" \
    && pass "a flow policy with no session_refusal_budget stops the Warden" \
    || flunk "a flow policy with no session_refusal_budget stops the Warden (rc=$rc)"
printf 'varek_policy 1\nsession_refusal_budget 3\nrule file_open\n' > "$D/alone.cfg"
"$WARDEN" "$POL" --plan "$D/ok.txt" --flow-policy "$D/alone.cfg" --breaker-state "$D/state/n" \
    -- "$PROBE" > /dev/null 2> "$OUT/e.err"; rc=$?
[ "$rc" -eq 1 ] && grep -q "requires 'refusal_budget'" "$OUT/e.err" \
    && pass "session_refusal_budget without refusal_budget is a policy error" \
    || flunk "session_refusal_budget without refusal_budget is a policy error (rc=$rc)"

echo "== 2. plans that differ each time are counted together =="
gate A "$(leak 1)"
[ "$RC" -eq 3 ] && [ "$S" = "REFUSED_RETRYABLE 1/2 session 1/3" ] \
    && pass "1st plan: retryable, session 1 of 3 (exit 3)" || flunk "1st plan: retryable, session 1 of 3 (exit $RC, '$S')"
gate A "$(leak 2)"
[ "$RC" -eq 3 ] && [ "$S" = "REFUSED_RETRYABLE 1/2 session 2/3" ] && has '1 of 2 for this plan and 2 of 3 in session A' \
    && pass "2nd, different plan: its own count is 1, the session's 2 (exit 3)" || flunk "2nd plan: session 2 of 3 (exit $RC, '$S')"
gate A "$(leak 3)"
[ "$RC" -eq 5 ] && [ "$S" = "TERMINAL_ACTION abort_txn" ] && has 'session refusal limit reached' \
    && pass "3rd, different plan: the session's limit is reached, terminal abort_txn (exit 5)" \
    || flunk "3rd plan reaches the session limit (exit $RC, '$S')"
grep -q '"breaker":"TERMINAL_ACTION","refusals":1,"budget":2,"session_refusals":3,"session_budget":3,"session_exhausted":true' <<<"$R" \
    && pass "plan_gate record: session 3 of 3, exhausted, though this plan was refused once" || flunk "plan_gate record reports the session ($R)"
gate A "$(leak 4)"
[ "$RC" -eq 5 ] && grep -q '"session_refusals":3,"session_budget":3,"session_exhausted":true' <<<"$R" \
    && pass "a 4th, new plan is terminal at once and not counted again" || flunk "a 4th plan is terminal at once (exit $RC; $R)"
gate A leak1.txt
[ "$RC" -eq 5 ] && pass "the 1st plan, which had budget left, is terminal too" || flunk "the 1st plan is terminal too (exit $RC)"
! has 'supervising pid=' && pass "no refused plan started the agent" || flunk "no refused plan started the agent"

echo "== 3. an authorized plan still runs, and does not reset the count =="
gate A ok.txt
[ "$RC" -eq 0 ] && [ "$S" = "PASS" ] && has 'supervising pid=' \
    && pass "an authorized plan in the exhausted session runs (PASS)" || flunk "an authorized plan runs (exit $RC, '$S')"
grep -q '"breaker":"PASS".*"session_refusals":3,"session_budget":3,"session_exhausted":true' <<<"$R" \
    && pass "its record still shows the session's 3 refusals, exhausted" || flunk "PASS record shows the session count ($R)"
gate A "$(leak 5)"
[ "$RC" -eq 5 ] && pass "the next refused plan is still terminal" || flunk "the next refused plan is still terminal (exit $RC)"

echo "== 4. another session has its own count =="
gate B leak1.txt
[ "$RC" -eq 3 ] && [ "$S" = "REFUSED_RETRYABLE 1/2 session 1/3" ] \
    && pass "session B starts at 1 of 3" || flunk "session B has its own count (exit $RC, '$S')"
gate B leak1.txt
[ "$RC" -eq 5 ] && [ "$S" = "TERMINAL_ACTION abort_txn" ] && ! has 'session refusal limit reached' \
    && pass "the same plan twice in B is terminal by its own budget (2), before the session's" \
    || flunk "the per-plan budget still applies (exit $RC, '$S')"
grep -q '"session_refusals":2,"session_budget":3,"session_exhausted":false' <<<"$R" \
    && pass "B's session is not exhausted (2 of 3)" || flunk "B's session is not exhausted ($R)"
gate B "$(leak 6)"
[ "$RC" -eq 5 ] && has 'session refusal limit reached' && pass "one more plan in B reaches its limit" || flunk "one more plan in B reaches its limit (exit $RC)"

echo "== 5. the count persists: format 2, and a v1.18.0 table is read =="
check "the state file is format 2" grep -qx 'varek-breaker 2' "$STATE"
check "it holds session A's latched count (session 41 3 1 3 abort_txn)" grep -qx 'session 41 3 1 3 abort_txn' "$STATE"
# A v1.18.0 table: session C (43) holds 2 refusals of one plan. It is read,
# and C starts at 2, so one more refused plan reaches the limit of 3.
SIG_OTHER=0123456789abcdef
printf 'varek-breaker 1\n43 %s 1 0 2 -\n43 fedcba9876543210 1 0 2 -\nend 2\n' "$SIG_OTHER" > "$STATE"
chmod 600 "$STATE"
gate C "$(leak 7)"
[ "$RC" -eq 5 ] && has 'session refusal limit reached' \
    && pass "a v1.18.0 table is read; its session starts from the 2 refusals it holds" \
    || flunk "a v1.18.0 table is read and counted (exit $RC; $G)"
check "and is written back as format 2" grep -qx 'varek-breaker 2' "$STATE"
printf 'varek-breaker 2\nsession 43 1 0 2 -\nsession 43 1 0 2 -\nend 2\n' > "$STATE"
gate C "$(leak 8)"
[ "$RC" -eq 1 ] && [ "$S" = "ERROR breaker_state" ] && pass "a table with a duplicated session is refused (state fault)" \
    || flunk "a duplicated session is refused (exit $RC, '$S')"

gate D ok.txt
python3 "$AUDIT" --policy "$POL" --checker "$CERT" "$OUT/gate.err" > "$OUT/audit" 2>&1 \
    && pass "varek_audit accepts a stream whose plan_gate record has the session fields" \
    || flunk "varek_audit accepts the new plan_gate record ($(tail -2 "$OUT/audit"))"

echo
if [ "$fail" -eq 0 ]; then echo "v1.19.0: all checks passed"; else echo "v1.19.0: FAILURES"; fi
exit "$fail"
