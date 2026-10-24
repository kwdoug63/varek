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
#
# Usage: test_v1350.sh <warden>
set -u
WARDEN=$(realpath "$1")
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
printf 'require warden 1.27\nallow exec /usr/bin/true\ndeny exec /usr/bin/false\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\n' > "$LP"
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
printf 'allow exec /usr/bin/true\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\n' > "$NP"
gate "$NP" ok.txt
check "without require warden 1.27: still UNSATISFIED, the runtime refusing every later launch" \
    grep -q 'refuses every launch after the first at runtime, as the policy does not decide launches' "$OUT/gate.err"

echo
if [ "$fail" = 0 ]; then echo "test_v1350: PASS"; else echo "test_v1350: FAIL"; fi
exit "$fail"
