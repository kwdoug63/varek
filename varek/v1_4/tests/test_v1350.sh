#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1350.sh — v1.35.0, agent frameworks: plans from the framework
# (docs/security/v1.35-frameworks.md). The parts built so far:
#
#   1. the present mismatches (step 2, D9), as root: with the policy deciding
#      launches (require warden 1.27), a plan's process_exec step is decided
#      as the launch would be (the program's canonical path, the policy, the
#      launch set): allowed, refused by a deny rule, not allowed by any rule,
#      a symlink decided on the file it names, a relative path; without the
#      opt-in the step stays UNSATISFIED, as the runtime refuses the launch
#   2. the plan gate's records (D9): each step not SATISFIED a chained
#      plan_step record, the outcome a plan_gate record (an unreadable plan
#      too), the stream audited
#   3. `varek refusals` and `varek run`'s summary on a refused plan
#   4. `varek policy check --plan`: the plan decided as the run would, no
#      agent run
#
# Usage: test_v1350.sh <warden> (tools/varek, tools/vdp_cert_check beside it)
set -u
WARDEN=$(realpath "$1")
HERE=$(dirname "$WARDEN")
VAREK="$HERE/tools/varek"
CHECKER="$HERE/tools/vdp_cert_check"
OUT=$(mktemp -d /tmp/varek_v1350.XXXXXX)
chmod 755 "$OUT"
trap 'rm -rf "$OUT"' EXIT
fail=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
check() { local what=$1; shift; if "$@" > /dev/null 2>&1; then pass "$what"; else flunk "$what"; fi; }

if [ "$(id -u)" != 0 ]; then echo "test_v1350: needs root (the Warden supervises)"; exit 2; fi

echo "== 1. the present mismatches (D9): a plan's launch decided as the launch =="
LP="$OUT/launch.policy"
printf 'require warden 1.27\nallow exec /usr/bin/true\ndeny exec /usr/bin/false\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' > "$LP"
ln -s /usr/bin/true "$OUT/true-link"
plan() { printf '%s\n' "$2" > "$OUT/$1"; }
gate() { "$WARDEN" "$1" --plan "$OUT/$2" -- /usr/bin/true > /dev/null 2> "$OUT/gate.err"; }
plan ok.txt 'action a process_exec /usr/bin/true'
gate "$LP" ok.txt
if grep -q 'plan authorized (1 actions)' "$OUT/gate.err"; then
    pass "a launch the policy allows, in the launch set: SATISFIED"
elif grep -q 'no Landlock' "$OUT/gate.err"; then
    pass "a launch the policy allows: UNSATISFIED here, as this host has no Landlock (every later launch is refused)"
else flunk "a launch the policy allows ($(grep -m1 'plan' "$OUT/gate.err"))"; fi
plan deny.txt 'action a process_exec /usr/bin/false'
gate "$LP" deny.txt
check "a launch a deny rule matches: UNSATISFIED, the reason said" \
    grep -q 'is UNSATISFIED: the policy refuses it' "$OUT/gate.err"
plan norule.txt 'action a process_exec /usr/bin/env'
gate "$LP" norule.txt
check "a launch no rule allows: UNKNOWN, the reason said" \
    grep -q 'is UNKNOWN: no rule of the policy allows it' "$OUT/gate.err"
plan link.txt "action a process_exec $OUT/true-link"
gate "$LP" link.txt
check "a symlink to an allowed program: decided on the file it names" \
    grep -Eq 'plan authorized|no Landlock' "$OUT/gate.err"
plan rel.txt 'action a process_exec usr/bin/true'
gate "$LP" rel.txt
check "a relative program path: UNKNOWN" grep -q 'is UNKNOWN: a launch is named by its absolute path' "$OUT/gate.err"
plan missing.txt "action a process_exec $OUT/nosuch"
gate "$LP" missing.txt
check "a program that is not a file here: UNKNOWN" grep -q 'is UNKNOWN: the program is not a file here' "$OUT/gate.err"
NP="$OUT/nolaunch.policy"
printf 'allow exec /usr/bin/true\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' > "$NP"
gate "$NP" ok.txt
check "without require warden 1.27: still UNSATISFIED, the runtime refusing every later launch" \
    grep -q 'refuses every launch after the first at runtime, as the policy does not decide launches' "$OUT/gate.err"

echo "== 2. the plan gate's records: chained, and audited =="
plan mixed.txt "$(printf 'action a process_exec /usr/bin/false\naction b file_open /etc/shadow\naction c no_such_kind x\nedge a b')"
gate "$LP" mixed.txt
RC=$?
cp "$OUT/gate.err" "$OUT/mixed.log"
rec() { grep "^{\"event\":\"$1\"" "$OUT/mixed.log"; }
[ "$RC" = 1 ] && pass "a refused plan: exit 1, the agent not started" || flunk "a refused plan: exit $RC"
check "the deny step: a plan_step record, UNSATISFIED, with the deciding line and the reason" \
    grep -q '"label":"a","kind":"process_exec","target":"/usr/bin/false","resolved":"/usr/bin/false","decision":"UNSATISFIED","policy_line":3,"why":"the policy refuses it"' "$OUT/mixed.log"
check "the step no rule allows: UNKNOWN, no line" \
    grep -q '"label":"b","kind":"file_open","target":"/etc/shadow","resolved":"/etc/shadow","decision":"UNKNOWN","policy_line":-1,"why":"no rule of the policy allows it"' "$OUT/mixed.log"
check "a kind the Warden does not decide: UNKNOWN, said so" \
    grep -q '"label":"c","kind":"no_such_kind".*"why":"the Warden decides no step of this kind"' "$OUT/mixed.log"
check "the outcome: a plan_gate record (gate plan, 3 actions, 1 edge, UNSATISFIED)" \
    grep -q '^{"event":"plan_gate","run":"[0-9a-f]*","gate":"plan","plan":"[^"]*mixed.txt","actions":3,"edges":1,"verdict":"UNSATISFIED"' "$OUT/mixed.log"
[ "$(rec plan_step | grep -c '"chain":"[0-9a-f]\{64\}"')" = 3 ] && rec plan_gate | grep -q '"chain":"[0-9a-f]\{64\}"' \
    && pass "each plan record is chained" || flunk "each plan record is chained"
python3 "$HERE/tools/varek_audit.py" --policy "$LP" --checker "$CHECKER" "$OUT/mixed.log" > "$OUT/audit" 2>&1 \
    && grep -q 'varek_audit: PASS' "$OUT/audit" && pass "varek_audit accepts the stream (the chain holds)" \
    || flunk "varek_audit accepts the stream ($(tail -2 "$OUT/audit"))"
sed 's/"decision":"UNSATISFIED"/"decision":"SATISFIED"/' "$OUT/mixed.log" > "$OUT/forged.log"
python3 "$HERE/tools/varek_audit.py" --policy "$LP" --checker "$CHECKER" "$OUT/forged.log" > "$OUT/audit" 2>&1 \
    && flunk "a plan_step record changed after the fact: refused by the audit" \
    || pass "a plan_step record changed after the fact: refused by the audit"
gate "$LP" ok.txt
if grep -q 'plan authorized' "$OUT/gate.err"; then
    grep -q '^{"event":"plan_gate",.*"verdict":"SATISFIED"' "$OUT/gate.err" && ! grep -q '"event":"plan_step"' "$OUT/gate.err" \
        && pass "an authorized plan: a plan_gate record SATISFIED, no plan_step" || flunk "an authorized plan's records"
else pass "an authorized plan's records: not tried (no Landlock here)"; fi
printf 'not a plan line\n' > "$OUT/bad.txt"
"$WARDEN" "$LP" --plan "$OUT/bad.txt" -- /usr/bin/true > /dev/null 2> "$OUT/bad.log"
check "a plan that cannot be read: a plan_gate record, UNKNOWN, with the parser's reason" \
    grep -q '^{"event":"plan_gate",.*"actions":0,"edges":0,"verdict":"UNKNOWN","error":"[^"]*unknown directive' "$OUT/bad.log"

echo "== 3. varek refusals and varek run on a refused plan =="
export VAREK_CONFIG="$OUT/none.conf" VAREK_HOME="$HERE"
(cd "$OUT" && python3 "$VAREK" refusals "$OUT/mixed.log") > "$OUT/ref" 2>&1
check "varek refusals: the plan refused, the agent not started" grep -q 'mixed.txt was refused (UNSATISFIED): the agent did not start' "$OUT/ref"
check "varek refusals: the deny step, with the policy line's text" \
    grep -q 'step a: policy line 3: deny exec /usr/bin/false (the policy refuses it)' "$OUT/ref"
check "varek refusals: the UNKNOWN steps, each with its reason" \
    sh -c "grep -q 'step b: no rule of the policy allows it' '$OUT/ref' && grep -q 'step c: the Warden decides no step of this kind' '$OUT/ref'"
python3 "$VAREK" refusals "$OUT/bad.log" > "$OUT/ref" 2>&1
check "varek refusals: an unreadable plan, the parser's reason" grep -q 'the plan could not be read: .*unknown directive' "$OUT/ref"
CONF="$OUT/varek.conf"
printf '[varek]\npolicy = %s\nlog_dir = %s/logs\nsign_key =\nanchor =\n' "$LP" "$OUT" > "$CONF"
mkdir -p "$OUT/logs"
VAREK_CONFIG="$CONF" python3 "$VAREK" run --plan "$OUT/mixed.txt" -- /usr/bin/true > /dev/null 2> "$OUT/run.err"
check "varek run --plan: the summary says the plan was refused (not \"0 refused\" alone)" \
    grep -q 'the plan was refused (UNSATISFIED, 3 step(s) not SATISFIED): the agent did not start' "$OUT/run.err"

echo "== 4. varek policy check --plan =="
NLOGS=$(ls "$OUT/logs" | wc -l)
python3 "$VAREK" policy check "$LP" --plan "$OUT/mixed.txt" > "$OUT/pc" 2>&1
RC=$?
[ "$RC" = 1 ] && grep -q 'refused under .* (UNSATISFIED)' "$OUT/pc" \
    && pass "a refused plan: exit 1, refused, as the run would" || flunk "a refused plan: exit $RC ($(tail -1 "$OUT/pc"))"
check "each step's reason shown" grep -q 'process_exec step "/usr/bin/false" is UNSATISFIED: the policy refuses it' "$OUT/pc"
python3 "$VAREK" policy check "$LP" --plan "$OUT/ok.txt" > "$OUT/pc" 2>&1
RC=$?
if [ "$RC" = 0 ]; then grep -q 'authorized under' "$OUT/pc" && pass "an allowed plan: exit 0, authorized" || flunk "an allowed plan: says authorized"
elif grep -q 'no Landlock' "$OUT/pc"; then pass "an allowed plan: refused here for no Landlock, as a run would be"
else flunk "an allowed plan: exit $RC ($(tail -1 "$OUT/pc"))"; fi
python3 "$VAREK" policy check "$LP" --plan "$OUT/bad.txt" > "$OUT/pc" 2>&1
[ $? = 1 ] && grep -q 'could not be read' "$OUT/pc" && pass "an unreadable plan: exit 1, said so" || flunk "an unreadable plan ($(tail -1 "$OUT/pc"))"
[ "$(ls "$OUT/logs" | wc -l)" = "$NLOGS" ] && pass "a check runs no agent and writes no stream" || flunk "a check wrote a stream"

echo
if [ "$fail" = 0 ]; then echo "test_v1350: PASS"; else echo "test_v1350: FAIL"; fi
exit "$fail"
