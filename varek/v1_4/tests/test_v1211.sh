#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1211.sh — regression test for VAREK v1.21.1: a plan step may declare
# how it opens its file.
#
# A plan step has no open flags of its own, so through v1.21.0 the --plan
# gate decided a file_open step with the flags unknown, and a path allowed
# only by a rule with a flag clause (`readonly`, `access=ro`, ...) was UNKNOWN
# at the gate although the runtime allowed the same open. v1.21.1 reads an
# `open` field on a file_open step (open=read, or O_RDONLY|O_WRONLY|O_RDWR
# followed by O_ flags) and decides the step with those flags.
#
#   1. Without an `open` field a step is decided as before (UNKNOWN on a
#      read-only rule).
#   2. open=read and O_RDONLY|... are SATISFIED where the policy allows that
#      read; the agent then runs and its read is allowed at run time.
#   3. Flags the rule does not allow are not authorized (and are decided, not
#      refused as malformed); a denied path is UNSATISFIED whatever valid
#      flags the field declares; a write declared on a read-write path is
#      SATISFIED; flag names mean what they mean in the policy language
#      (O_LARGEFILE the kernel's bit) or what an agent's open() passes
#      (O_SYNC includes O_DSYNC).
#   4. A field the gate does not understand makes the step UNKNOWN, with the
#      reason, never SATISFIED.
#   5. With --flow-policy: a declared plan passes and a malformed field is
#      refused with its reason; varek_audit accepts the run.
#
# Usage: ./test_v1211.sh <warden> <vdp_cert_check> <probe>
# Exit 0 iff every check holds.
set -u

WARDEN="${1:?usage: test_v1211.sh <warden> <vdp_cert_check> <probe>}"
CERT="${2:?}"
PROBE="${3:?}"
abs() { case "$1" in /*) echo "$1";; *) echo "$PWD/$1";; esac; }
WARDEN="$(abs "$WARDEN")"; CERT="$(abs "$CERT")"; PROBE="$(abs "$PROBE")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT="$HERE/tools/varek_audit.py"

fail=0
pass()  { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }

D=/tmp/varek_v1211
OUT="$(mktemp -d)"
cleanup() { rm -rf "$D" "$OUT"; }
trap cleanup EXIT
rm -rf "$D"
mkdir -p "$D/ref" "$D/work" "$D/secret" "$D/state" "$D/lf" "$D/sync"
chmod 755 "$D" "$D/ref" "$D/work" "$D/secret" "$D/lf" "$D/sync"
chmod 700 "$D/state"
echo "reference data" > "$D/ref/in.txt"
echo "top secret" > "$D/secret/k"
chmod 644 "$D/ref/in.txt" "$D/secret/k"

POL="$D/policy.txt"
cat > "$POL" <<'EOF'
require warden 1.13
deny  path /tmp/varek_v1211/secret/
allow path /tmp/varek_v1211/ref/ readonly
allow path /tmp/varek_v1211/work/
EOF
FPOL="$D/flags.policy.txt"
cat > "$FPOL" <<'EOF'
require warden 1.13
deny  path /tmp/varek_v1211/lf/ +O_LARGEFILE
allow path /tmp/varek_v1211/lf/
deny  path /tmp/varek_v1211/sync/ +O_DSYNC
allow path /tmp/varek_v1211/sync/
EOF

# gate <label> <plan lines...>: run the gate alone (the agent is the probe,
# reading the reference file) and print the gate's result line and any
# per-step reason.
gate() {
    local name="$1"; shift
    printf '%s\n' "$@" > "$OUT/$name.plan"
    "$WARDEN" "${GATE_POLICY:-$POL}" --plan "$OUT/$name.plan" -- "$PROBE" "$D/ref/in.txt" \
        > "$OUT/$name.out" 2> "$OUT/$name.log"
    echo $? > "$OUT/$name.rc"
}
authorized() { grep -q '^\[warden\] plan authorized' "$OUT/$1.log"; }
rejected()   { grep -q "^\[warden\] plan rejected ($2)" "$OUT/$1.log"; }
reason()     { grep -qF "is UNKNOWN: $2" "$OUT/$1.log"; }
noreason()   { ! grep -q "is UNKNOWN: the open field\|is UNKNOWN: an open field" "$OUT/$1.log"; }

R=/tmp/varek_v1211/ref/in.txt
W=/tmp/varek_v1211/work/out.txt

echo "== 1. without an open field: as in v1.21.0 =="
gate nofield "action a file_open $R"
rejected nofield UNKNOWN && pass "a read-only path with no declared flags is UNKNOWN (unchanged)" \
    || flunk "a read-only path with no declared flags is UNKNOWN (unchanged)"
gate nofield_rw "action a file_open $W"
authorized nofield_rw && pass "a path whose rule has no flag clause is SATISFIED without a field" \
    || flunk "a path whose rule has no flag clause is SATISFIED without a field"

echo "== 2. declared reads =="
gate read "action a file_open $R open=read"
authorized read && pass "open=read on a read-only path is authorized" \
    || flunk "open=read on a read-only path is authorized"
grep -q "^PROBE open $R OK" "$OUT/read.out" && pass "... and the agent's read of it is allowed at run time" \
    || flunk "... and the agent's read of it is allowed at run time"
gate quoted "action a file_open $R open=\"read\""
authorized quoted && pass "a quoted value is read the same" || flunk "a quoted value is read the same"
gate cloexec "action a file_open $R open=O_RDONLY|O_CLOEXEC"
authorized cloexec && pass "open=O_RDONLY|O_CLOEXEC is authorized" || flunk "open=O_RDONLY|O_CLOEXEC is authorized"

echo "== 3. flags the rule does not allow; denied paths; writes =="
for f in "O_RDWR" "O_WRONLY" "O_RDONLY|O_TRUNC" "O_RDONLY|O_CREAT"; do
    n="bad_$(printf '%s' "$f" | tr -c 'A-Za-z0-9' _)"
    gate "$n" "action a file_open $R open=$f"
    if ! authorized "$n" && noreason "$n"; then pass "open=$f on a read-only path is decided and not authorized"
    else flunk "open=$f on a read-only path is decided and not authorized"; fi
done
gate denied "action a file_open /tmp/varek_v1211/secret/k open=read"
rejected denied UNSATISFIED && pass "a denied path is UNSATISFIED whatever the field says" \
    || flunk "a denied path is UNSATISFIED whatever the field says"
gate write "action a file_open $W open=O_WRONLY|O_CREAT|O_TRUNC"
authorized write && pass "a declared write on a read-write path is authorized" \
    || flunk "a declared write on a read-write path is authorized"
gate write_ro "action a file_open $R open=O_WRONLY|O_CREAT|O_TRUNC"
if authorized write_ro; then flunk "a declared write on a read-only path is not authorized"
else pass "a declared write on a read-only path is not authorized"; fi
gate mixed "action r file_open $R open=read" "action w file_open $W open=O_WRONLY|O_CREAT" "edge r w"
authorized mixed && pass "a plan that reads read-only data and writes its result is authorized" \
    || flunk "a plan that reads read-only data and writes its result is authorized"
GATE_POLICY="$FPOL" gate lf "action a file_open /tmp/varek_v1211/lf/x open=O_RDONLY|O_LARGEFILE"
rejected lf UNSATISFIED && pass "O_LARGEFILE is the policy language's bit: a +O_LARGEFILE denial applies" \
    || flunk "O_LARGEFILE is the policy language's bit: a +O_LARGEFILE denial applies"
GATE_POLICY="$FPOL" gate lf_plain "action a file_open /tmp/varek_v1211/lf/x open=read"
authorized lf_plain && pass "... and a read without it is authorized" || flunk "... and a read without it is authorized"
GATE_POLICY="$FPOL" gate sync "action a file_open /tmp/varek_v1211/sync/x open=O_WRONLY|O_SYNC"
rejected sync UNSATISFIED && pass "O_SYNC includes O_DSYNC, as an agent's open() passes it" \
    || flunk "O_SYNC includes O_DSYNC, as an agent's open() passes it"

echo "== 4. a field the gate does not understand: UNKNOWN, with the reason =="
check_bad() {
    local n="$1" v="$2" why="$3"
    gate "$n" "action a file_open $R open=$v"
    if rejected "$n" UNKNOWN && reason "$n" "$why"; then pass "open=$v: UNKNOWN ($why)"
    else flunk "open=$v: UNKNOWN ($why)"; fi
}
check_bad word    "bogus"                       "the open field must be read"
check_bad lower   "o_rdonly"                    "the open field must be read"
check_bad flagfst "O_CLOEXEC"                   "the open field must be read"
check_bad unknown "O_RDONLY|O_FOO"              "the open field names an unknown flag"
check_bad acc2    "O_RDONLY|O_RDWR"             "the open field names an unknown flag"
check_bad repeat  "O_RDONLY|O_CLOEXEC|O_CLOEXEC" "the open field repeats a flag"
check_bad double  "O_RDONLY||O_CLOEXEC"         "the open field is empty or malformed"
check_bad trail   "O_RDONLY|"                   "the open field is empty or malformed"
check_bad lead    "|O_RDONLY"                   "the open field is empty or malformed"
check_bad empty   '""'                          "the open field is empty or malformed"
check_bad long    "O_RDONLY$(printf '|O_CLOEXEC%.0s' $(seq 60))" "the open field is too long"
gate onconnect "action a net_connect 127.0.0.1:9 open=read"
if rejected onconnect UNKNOWN && reason onconnect "an open field is only for a file_open step"; then
    pass "an open field on a net_connect step is UNKNOWN"
else flunk "an open field on a net_connect step is UNKNOWN"; fi
gate onexec "action a process_exec /usr/bin/true open=read"
if rejected onexec UNKNOWN && reason onexec "an open field is only for a file_open step"; then
    pass "an open field on a process_exec step is UNKNOWN"
else flunk "an open field on a process_exec step is UNKNOWN"; fi

echo "== 5. with --flow-policy; the audit =="
FLOW="$D/flow.cfg"
cat > "$FLOW" <<'EOF'
varek_policy 1
label SECRET 0
sticky SECRET
refusal_budget 3
session_refusal_budget 10
on_exhaustion deny
unknown_disposition deny
rule file_open
  match target /tmp/varek_v1211/ref/*
  origin SECRET
rule file_open
  match target /tmp/varek_v1211/work/*
  permit_in SECRET
EOF
printf '%s\n' "action r file_open $R open=read" "action w file_open $W open=O_WRONLY|O_CREAT|O_TRUNC" "edge r w" \
    > "$OUT/flow.plan"
"$WARDEN" "$POL" --plan "$OUT/flow.plan" --flow-policy "$FLOW" --session t1211 \
    --breaker-state "$D/state/breaker.state" --gate-status "$D/state/gate.status" \
    -- "$PROBE" "$R" > "$OUT/flow.out" 2> "$OUT/flow.log"
rc=$?
if [ "$rc" -eq 0 ] && [ "$(cat "$D/state/gate.status" 2>/dev/null)" = "PASS" ] \
   && grep -q "^PROBE open $R OK" "$OUT/flow.out"; then
    pass "the gate with --flow-policy authorizes the plan (PASS) and the agent reads its data"
else
    flunk "the gate with --flow-policy authorizes the plan (rc=$rc, status $(cat "$D/state/gate.status" 2>/dev/null))"
    sed 's/^/      /' "$OUT/flow.log" | grep -v '^      {"report' | head -8
fi
printf '%s\n' "action r file_open $R open=O_RDONLY|" > "$OUT/flowbad.plan"
"$WARDEN" "$POL" --plan "$OUT/flowbad.plan" --flow-policy "$FLOW" --session t1211b \
    --breaker-state "$D/state/breaker.state" --gate-status "$D/state/gate2.status" \
    -- "$PROBE" "$R" > "$OUT/flowbad.out" 2> "$OUT/flowbad.log"
rc=$?
if [ "$rc" -ne 0 ] && [ "$(cat "$D/state/gate2.status" 2>/dev/null)" != "PASS" ] \
   && grep -qF "is UNKNOWN: the open field is empty or malformed" "$OUT/flowbad.log" \
   && ! grep -q "^PROBE" "$OUT/flowbad.out"; then
    pass "with --flow-policy a malformed field is refused with its reason, and the agent never runs"
else
    flunk "with --flow-policy a malformed field is refused (rc=$rc, status $(cat "$D/state/gate2.status" 2>/dev/null))"
fi
if python3 "$AUDIT" --policy "$POL" --checker "$CERT" "$OUT/flow.log" > "$OUT/audit.out" 2>&1; then
    pass "varek_audit accepts the run"
else
    flunk "varek_audit accepts the run"; sed 's/^/      /' "$OUT/audit.out"
fi

echo
if [ "$fail" -eq 0 ]; then echo "v1.21.1: all checks passed"; else echo "v1.21.1: FAILURES PRESENT"; fi
exit "$fail"
