#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1200.sh — regression test for VAREK v1.20.0: fields on plan steps.
#
# Through v1.19.0 a plan step had one field, its target, so the data-flow
# policy could not see anything else a step declared. v1.20.0 lets a plan
# step carry key=value fields after its target, and the Warden's --plan gate
# hands them to the --flow-policy's rules as named arguments.
#
#   1. A flow rule that matches a field decides the plan: the same plan with
#      and without the field gets different verdicts; quoted values keep
#      their spaces.
#   2. Fields reach only the flow policy: they cannot make a step the Warden's
#      own policy refuses pass the node check.
#   3. Fields are part of the plan's breaker signature, in key order: the same
#      fields in another order are the same plan, a changed value is not.
#   4. Malformed fields refuse the plan file (exit 1); a plan with fields is
#      still read by --plan alone.
#   5. varek_audit accepts the stream.
#
# Usage: ./test_v1200.sh <warden> <vdp_cert_check> <probe>
# Exit 0 iff every check holds.
set -u

WARDEN="${1:?usage: test_v1200.sh <warden> <vdp_cert_check> <probe>}"
CERT="${2:?}"
PROBE="${3:?}"
abs() { case "$1" in /*) echo "$1";; *) echo "$PWD/$1";; esac; }
WARDEN="$(abs "$WARDEN")"; CERT="$(abs "$CERT")"; PROBE="$(abs "$PROBE")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT="$HERE/tools/varek_audit.py"

fail=0
pass()  { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }

D=/tmp/varek_v1200
OUT="$(mktemp -d)"
cleanup() { rm -rf "$D" "$OUT"; }
trap cleanup EXIT
rm -rf "$D"
mkdir -p "$D/data/secret" "$D/data/public" "$D/state"
chmod 755 "$D" "$D/data" "$D/data/secret" "$D/data/public"
chmod 700 "$D/state"
echo "top secret" > "$D/data/secret/k"
chmod 644 "$D/data/secret/k"

POL="$D/policy.txt"
printf 'deny path /tmp/varek_v1200/data/secret/private\nallow path /tmp/varek_v1200/data/\n' > "$POL"
mkdir -p "$D/data/inbox" && chmod 755 "$D/data/inbox"
# A step that declares it reads a customer record is SECRET, like anything
# under secret/; SECRET may not reach public/. The field rule only adds a
# label; the flow policy says it trusts declared fields.
FLOW="$D/flow.cfg"
cat > "$FLOW" <<'EOF'
varek_policy 1
trust_declared_fields
label SECRET 0
sticky SECRET
refusal_budget 5
session_refusal_budget 50
on_exhaustion deny
unknown_disposition deny
rule file_open
  match target /tmp/varek_v1200/data/secret/*
  origin SECRET
rule file_open
  match target /tmp/varek_v1200/data/inbox/*
  match contains *customer?record*
  origin SECRET
rule file_open
  match target /tmp/varek_v1200/data/public/*
  deny_in SECRET
rule file_open
EOF
STATE="$D/state/breaker"

# plan <name> <read-step fields> [<read target>]: read (inbox/msg by default),
# then write public/out.
plan() {
    printf 'action read  file_open %s %s\naction write file_open /tmp/varek_v1200/data/public/out\nedge read write\n' \
        "${3:-/tmp/varek_v1200/data/inbox/msg}" "$2" > "$D/$1"
}
gate() {
    "$WARDEN" "$POL" --plan "$D/$2" --flow-policy "${FLOWARG:-$FLOW}" --breaker-state "$STATE" \
        --session "$1" --gate-status "$D/state/gs" -- "$PROBE" > "$OUT/gate.out" 2> "$OUT/gate.err"
    RC=$?
    G="$(cat "$OUT/gate.err")"
    S="$(cat "$D/state/gs" 2>/dev/null)"
    R="$(grep '^{"event":"plan_gate"' "$OUT/gate.err" | head -1)"
}
has() { grep -q -- "$1" <<<"$G"; }
sig() { sed -n 's/.*"signature":"\([0-9a-f]*\)".*/\1/p' <<<"$R"; }

echo "== 0. a flow policy that matches fields must say it trusts them =="
grep -v '^trust_declared_fields' "$FLOW" > "$D/notrust.cfg"
plan plain.txt ''
FLOWARG="$D/notrust.cfg" gate s0 plain.txt
[ "$RC" -eq 1 ] && has "matches 'contains', a field the plan step declares" && has 'trust_declared_fields' && ! has 'supervising pid=' \
    && pass "without trust_declared_fields, a rule on a field stops the Warden and says why" \
    || flunk "a rule on a field needs trust_declared_fields (exit $RC)"
grep -v 'match contains' "$D/notrust.cfg" > "$D/targetonly.cfg"
FLOWARG="$D/targetonly.cfg" gate s0 plain.txt
[ "$RC" -ne 1 ] && has 'plan_gate\|plan rejected\|plan authorized' && ! has 'trust_declared_fields' \
    && pass "a policy whose rules match only the target needs no such line (it starts and gates)" \
    || flunk "a target-only policy starts (exit $RC)"

echo "== 1. a flow rule decides on a step's field =="
gate s1 plain.txt
[ "$RC" -eq 0 ] && [ "$S" = "PASS" ] && has 'flow SATISFIED' && has 'supervising pid=' \
    && pass "reading an inbox message into a public file, with no field: authorized, the agent runs" \
    || flunk "the plan without the field is authorized (exit $RC, '$S')"
plan rec.txt 'contains="a customer record"'
gate s1 rec.txt
[ "$RC" -eq 3 ] && has 'flow UNSATISFIED' && ! has 'supervising pid=' \
    && pass "declaring contains=\"a customer record\" makes it SECRET: refused (exit 3); the quoted value keeps its spaces" \
    || flunk "the declared field makes the flow refused (exit $RC)"
plan esc.txt 'contains="customer\x20record"'
gate s1 esc.txt
[ "$RC" -eq 3 ] && pass "an escaped value (\\x20) is decoded before matching" || flunk "an escaped value is decoded (exit $RC)"
plan other.txt 'contains=invoice'
gate s1 other.txt
[ "$RC" -eq 0 ] && pass "a value the rule does not match (contains=invoice) changes nothing" || flunk "a non-matching value changes nothing (exit $RC)"

# What trust_declared_fields accepts: a rule that PERMITS on a field is
# unlocked by the agent declaring it.
awk '/^rule file_open$/ && !done {print "rule file_open\n  match target /tmp/varek_v1200/data/public/*\n  match sink audit_log\n  permit_in SECRET"; done=1} {print}' "$FLOW" > "$D/permit.cfg"
plan sec_sink.txt 'x=0' /tmp/varek_v1200/data/secret/k
printf 'action read  file_open /tmp/varek_v1200/data/secret/k\naction write file_open /tmp/varek_v1200/data/public/out sink=audit_log\nedge read write\n' > "$D/sink.txt"
FLOWARG="$D/permit.cfg" gate s6 sec_sink.txt
rc_no=$RC
FLOWARG="$D/permit.cfg" gate s6 sink.txt
[ "$rc_no" -eq 3 ] && [ "$RC" -eq 0 ] \
    && pass "with trust_declared_fields, a permit on a field is unlocked by declaring it (the risk the line accepts)" \
    || flunk "a permit on a field behaves as documented (exit $rc_no then $RC)"

echo "== 2. fields reach only the flow policy =="
printf 'action w file_open /tmp/varek_v1200/data/secret/private contains=nothing\n' > "$D/node.txt"
gate s2 node.txt
[ "$RC" -ne 0 ] && has 'node UNSATISFIED' && ! has 'supervising pid=' \
    && pass "a field does not make a path the Warden's policy denies pass the node check" \
    || flunk "a field cannot pass the node check (exit $RC)"

echo "== 3. fields are part of the plan's signature, in key order =="
plan xy.txt 'contains=customer_record x=1 y=2'
gate s3 xy.txt
SIG1="$(sig)"
[ "$RC" -eq 3 ] && [ "$S" = "REFUSED_RETRYABLE 1/5 session 1/50" ] && pass "a refused plan with fields x=1 y=2: 1 of 5" \
    || flunk "a refused plan with fields counts once (exit $RC, '$S')"
plan yx.txt 'y=2 x=1 contains=customer_record'
gate s3 yx.txt
[ "$RC" -eq 3 ] && [ "$S" = "REFUSED_RETRYABLE 2/5 session 2/50" ] && [ "$(sig)" = "$SIG1" ] \
    && pass "the same fields in another order are the same plan: 2 of 5, same signature" \
    || flunk "reordered fields are the same plan ('$S', $(sig) vs $SIG1)"
plan x2.txt 'contains=customer_record x=2 y=2'
gate s3 x2.txt
[ "$RC" -eq 3 ] && [ "$S" = "REFUSED_RETRYABLE 1/5 session 3/50" ] && [ "$(sig)" != "$SIG1" ] \
    && pass "a changed value is a different plan (1 of 5), still counted for the session (3 of 50)" \
    || flunk "a changed value is a different plan ('$S')"
gate s3 plain.txt
[ "$(sig)" != "$SIG1" ] && pass "the plan without fields has its own signature" || flunk "the plan without fields has its own signature"

echo "== 4. malformed fields refuse the plan file =="
for bad in 'target=/etc/passwd' 'reason="open' 'Sink=x' 'm=1 m=2' 'b="\x00"' 'extra'; do
    plan bad.txt "$bad"
    gate s4 bad.txt
    [ "$RC" -eq 1 ] && has 'plan load failed' && ! has 'supervising pid=' \
        && pass "refused at load: $bad" || flunk "refused at load: $bad (exit $RC)"
done
# A target longer than the Warden's 4096-byte path buffer is refused at load:
# cut short, the node check would decide a different path (here, one that
# collapses to the denied secret/private).
LONG="/tmp/varek_v1200/data/public/$(printf 'x/%.0s' $(seq 2033))$(printf '../%.0s' $(seq 2034))secret/private"
printf 'action w file_open %s\n' "$LONG" > "$D/long.txt"
"$WARDEN" "$POL" --plan "$D/long.txt" -- "$PROBE" > /dev/null 2> "$OUT/long.err"; rc=$?
[ "$rc" -ne 0 ] && grep -q 'target too long' "$OUT/long.err" && ! grep -q 'supervising pid=' "$OUT/long.err" \
    && pass "a ${#LONG}-byte target is refused at load, not truncated and authorized" \
    || flunk "an over-long target is refused (rc=$rc)"
printf 'action w file_open /tmp/varek_v1200/data/public/ok k=v\0 j=evil\n' > "$D/nul.txt"
"$WARDEN" "$POL" --plan "$D/nul.txt" -- "$PROBE" > /dev/null 2> "$OUT/nul.err"; rc=$?
[ "$rc" -ne 0 ] && grep -q 'NUL byte' "$OUT/nul.err" && pass "a NUL byte in a line refuses the plan file" || flunk "a NUL byte refuses the plan (rc=$rc)"

"$WARDEN" "$POL" --plan "$D/sink.txt" -- "$PROBE" > /dev/null 2> "$OUT/plain.err"; rc=$?
[ "$rc" -eq 0 ] && grep -q 'plan authorized' "$OUT/plain.err" \
    && pass "--plan without --flow-policy reads a plan with fields (the node check ignores them)" \
    || flunk "--plan alone reads a plan with fields (rc=$rc)"

echo "== 5. the audit =="
gate s5 rec.txt
python3 "$AUDIT" --policy "$POL" --checker "$CERT" "$OUT/gate.err" > "$OUT/audit" 2>&1 \
    && pass "varek_audit accepts the stream" || flunk "varek_audit accepts the stream ($(tail -2 "$OUT/audit"))"

echo
if [ "$fail" -eq 0 ]; then echo "v1.20.0: all checks passed"; else echo "v1.20.0: FAILURES"; fi
exit "$fail"
