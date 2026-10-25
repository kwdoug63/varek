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
#   5. plan 1.35 (step 3: D3, D4, D6): mcp_call, subagent and credential
#      steps, a step decided as a confined subject (as=), and the same plan
#      without `plan 1.35`, read as through v1.34
#   6. a run held to its plan (step 4, D2): a call the policy allows but no
#      step covers refused (outside_plan) as the agent makes it: a file, a
#      write under a read-only step, a launch, a connection; what the plan
#      covers let through; run_start, the audit, varek refusals, varek run
#   7. `require plan` (step 4b, D7): a run without a held plan refused; the
#      audit and `varek policy show`; the grammar (1.35, once), both parsers
#      alike; the node agent carries it, a pod naming no plan refused (4c)
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

echo "== 5. plan 1.35: mcp_call, subagent, credential, as= =="
U=https://mcp.example.com/mcp
MP="$OUT/mcp.policy"
printf 'require warden 1.31\nproxy inspect\nallow host mcp.example.com:443\nmcp server files exec /usr/bin/true\nallow exec /usr/bin/false subagent=helper\ncredential gh from file:/etc/varek/creds/gh\nallow mcp %s tools/call search credential=gh\nallow mcp %s tools/list\ndeny mcp %s tools/call delete_*\nallow path /srv/data/ readonly for=files\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow mcp https://nohost.example.com/mcp tools/list\ndeny host blocked.example.com:443\nallow mcp https://blocked.example.com/mcp tools/list\n' "$U" "$U" "$U" > "$MP"
steps() {   # steps <header?>: the plan, with or without `plan 1.35`
    [ "$1" = 1 ] && echo 'plan 1.35'
    cat <<EOF
action m1 mcp_call $U name=search
action m2 mcp_call $U method=tools/list
action m3 mcp_call $U name=delete_all
action m4 mcp_call $U name=other
action m5 mcp_call $U
action m6 mcp_call stdio:files
action m7 mcp_call https://nohost.example.com/mcp method=tools/list
action m8 mcp_call https://blocked.example.com/mcp method=tools/list
action s1 subagent helper
action s2 subagent files
action s3 subagent nobody
action s4 subagent helper exec=/usr/bin/true
action c1 credential gh
action c2 credential nope
action f1 file_open /srv/data/x.csv open=read as=files
action f2 file_open /srv/data/x.csv open=read
action f3 file_open /usr/lib/os-release open=read as=files
action f4 file_open /srv/data/x.csv as=ghost
EOF
}
steps 1 > "$OUT/p135.txt"
"$WARDEN" "$MP" --check-startup --plan "$OUT/p135.txt" > /dev/null 2> "$OUT/p135.err"
says() { grep -qF "plan: $1 step \"$2\" is $3" "$OUT/p135.err"; }
quiet() { ! grep -qF "plan: $1 step \"$2\" is " "$OUT/p135.err"; }
check "mcp_call: a tool a rule allows (certified): SATISFIED" quiet mcp_call "https://mcp.example.com:443/mcp#tools/call#search"
check "mcp_call: method= (tools/list): SATISFIED" quiet mcp_call "https://mcp.example.com:443/mcp#tools/list#"
check "mcp_call: a tool a deny rule matches: UNSATISFIED" says mcp_call "https://mcp.example.com:443/mcp#tools/call#delete_all" UNSATISFIED
check "mcp_call: a tool no rule allows: UNKNOWN" says mcp_call "https://mcp.example.com:443/mcp#tools/call#other" UNKNOWN
check "mcp_call: the server, no tool named, where no rule allows any: UNKNOWN" says mcp_call "https://mcp.example.com:443/mcp#tools/call#" UNKNOWN
check "mcp_call: a stdio server: UNKNOWN, said why" says mcp_call stdio:files "UNKNOWN: a stdio MCP server"
check "mcp_call: a call its rule allows, on a server no host rule allows: UNKNOWN (the connection is decided first, as at run time)" \
    says mcp_call https://nohost.example.com/mcp "UNKNOWN: no host rule allows the connection to its server's host and port"
check "mcp_call: on a server a host rule refuses: UNSATISFIED" \
    says mcp_call https://blocked.example.com/mcp "UNSATISFIED: the connection to its server's host and port is refused by a host rule"
if grep -q 'no Landlock' "$OUT/p135.err"; then
    pass "subagent: launches refused on this host (no Landlock), as a run's would be"
else
    check "subagent: an unconfined sub-agent's launch, allowed by its subagent= rule: SATISFIED" quiet subagent helper
    check "subagent: a confined MCP server (mcp server NAME exec PATH): SATISFIED" quiet subagent files
    check "subagent: a program allowed, but not by a subagent= rule for that name: UNKNOWN" \
        says subagent /usr/bin/true "UNKNOWN: the program is allowed, but by a rule that does not launch it as this sub-agent"
fi
check "subagent: a name no rule launches: UNKNOWN" says subagent nobody UNKNOWN
check "credential: named and released by a rule: SATISFIED" quiet credential gh
check "credential: a name the policy does not give: UNKNOWN" says credential nope UNKNOWN
[ "$(grep -cF 'file_open step "/srv/data/x.csv" is UNKNOWN: no rule of the policy allows it' "$OUT/p135.err")" = 1 ] \
    && pass "as=: a confined subject's own rule allows it: SATISFIED (and the same file as the agent, which no rule of its allows: UNKNOWN)" \
    || flunk "as=: /srv/data/x.csv decided as files and as the agent"
check "as=: the subject's rules alone decide (not the agent's): UNKNOWN" says file_open /usr/lib/os-release "UNKNOWN: no rule"
check "as=: a name the policy does not give: UNKNOWN" grep -qF 'is UNKNOWN: the policy names no sub-agent or MCP server by that name' "$OUT/p135.err"
steps 0 > "$OUT/p134.txt"
"$WARDEN" "$MP" --check-startup --plan "$OUT/p134.txt" > /dev/null 2> "$OUT/p134.err"
[ "$(grep -cF 'is UNKNOWN: this kind of step needs `plan 1.35`' "$OUT/p134.err")" = 14 ] \
    && pass "without plan 1.35: each mcp_call, subagent and credential step UNKNOWN, said why" \
    || flunk "without plan 1.35: the new kinds ($(grep -cF 'needs `plan 1.35`' "$OUT/p134.err") said why)"
check "without plan 1.35: an as= field UNKNOWN, said why" grep -qF 'is UNKNOWN: an as= field needs `plan 1.35`' "$OUT/p134.err"

echo "== 6. a run held to its plan (--hold-to-plan) =="
mkdir -p "$OUT/w"
chmod 777 "$OUT/w"
HP="$OUT/hold.policy"
printf 'require warden 1.27\nallow exec /usr/bin/cat\nallow exec /usr/bin/tee\nallow exec /usr/bin/stat\nallow exec /usr/bin/sh\nallow exec /usr/bin/true\nallow exec /usr/bin/false\nallow exec /usr/bin/python3\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path /etc/hostname readonly\nallow path /etc/passwd readonly\nallow path %s/w/\nallow host 127.0.0.1:%s\nallow host 127.0.0.1:%s\n' "$OUT" 20801 20802 > "$HP"
base() { printf 'plan 1.35\naction r1 file_open /usr/ open=read\naction r2 file_open /lib/ open=read\naction r3 file_open /etc/ld.so.cache open=read\n'; }
held() {   # held <plan> <agent...>: run held, stderr in held.err
    local pl="$1"; shift
    "$WARDEN" "$HP" --plan "$pl" --hold-to-plan -- "$@" > "$OUT/held.out" 2> "$OUT/held.err"
}
rec_of() { grep '^{"event"\|^{"seq"\|"decision_final"' "$OUT/held.err" | grep -F "\"resolved\":\"$1\"" | head -1; }
{ base; printf 'action h file_open /etc/hostname open=read\n'; } > "$OUT/h1.plan"
held "$OUT/h1.plan" /usr/bin/cat /etc/hostname /etc/passwd
grep -q "$(cat /etc/hostname)" "$OUT/held.out" && pass "held: a file a step covers is read" || flunk "held: a file a step covers is read"
R=$(rec_of /etc/passwd)
grep -q '"decision_raw":"ALLOW","decision_final":"DENY","rule":"outside_plan"' <<<"$R" && grep -q "\"plan\":\"$OUT/h1.plan\"" <<<"$R" \
    && pass "held: a file the policy allows but no step covers: refused, outside_plan, the policy's verdict kept, the plan named" \
    || flunk "held: the outside file ($R)"
check "held: the agent got EACCES for it" grep -q 'cat: /etc/passwd: Permission denied' "$OUT/held.err"
check "run_start names the plan and its SHA-256" grep -q "\"hold\":{\"plan\":\"$OUT/h1.plan\",\"plan_sha256\":\"$(sha256sum "$OUT/h1.plan" | cut -c1-64)\"}" "$OUT/held.err"
python3 "$HERE/tools/varek_audit.py" --policy "$HP" --checker "$CHECKER" "$OUT/held.err" > "$OUT/audit" 2>&1 \
    && grep -q 'varek_audit: PASS' "$OUT/audit" && pass "varek_audit accepts the held run" || flunk "varek_audit on the held run ($(tail -2 "$OUT/audit"))"
cp "$OUT/held.err" "$OUT/h1.log"
python3 "$VAREK" refusals "$OUT/h1.log" > "$OUT/ref" 2>&1
check "varek refusals: OUTSIDE_PLAN, the plan named" grep -q "OUTSIDE_PLAN  file.open      /etc/passwd" "$OUT/ref"
{ base; printf 'action w file_open %s/w/ open=read\n' "$OUT"; } > "$OUT/h2.plan"
held "$OUT/h2.plan" /usr/bin/tee "$OUT/w/f" < /dev/null
check "held: a write under a step with open=read: outside_plan" sh -c "grep -F '\"resolved\":\"$OUT/w/f\"' '$OUT/held.err' | grep -q '\"rule\":\"outside_plan\"'"
{ base; printf 'action w file_open %s/w/\n' "$OUT"; } > "$OUT/h3.plan"
held "$OUT/h3.plan" /usr/bin/tee "$OUT/w/f" < /dev/null
[ -e "$OUT/w/f" ] && pass "held: a write under a directory step without open=: allowed" || flunk "held: a write under a directory step"
held "$OUT/h3.plan" /usr/bin/stat -c %n "$OUT"
check "held: a stat of a directory above a covered path: answered" grep -qx "$OUT" "$OUT/held.out"
if grep -q '"landlock":{"abi":[1-9]' "$OUT/held.err"; then
    { base; printf 'action t process_exec /usr/bin/true\n'; } > "$OUT/h4.plan"
    held "$OUT/h4.plan" /usr/bin/sh -c '/usr/bin/true && echo true-ran; /usr/bin/false; echo "false: $?"'
    check "held: a launch a process_exec step names: run" grep -q true-ran "$OUT/held.out"
    check "held: a launch the policy allows but no step names: outside_plan" \
        sh -c "grep -F '\"action\":\"process.exec\"' '$OUT/held.err' | grep -F '/usr/bin/false' | grep -q '\"rule\":\"outside_plan\"'"
    # step 4c (found under CRI-O, busybox): a hardlink is held by its own
    # name, not by the launch set entry's, which its other names share
    mkdir -m 755 "$OUT/hl"; cp /usr/bin/true "$OUT/hl/a"; ln "$OUT/hl/a" "$OUT/hl/b"
    { cat "$HP"; printf 'allow path %s/hl/ readonly\nallow exec %s/hl/a\nallow exec %s/hl/b\n' "$OUT" "$OUT" "$OUT"; } > "$OUT/hl.policy"
    { base; printf 'action a process_exec %s/hl/a\n' "$OUT"; } > "$OUT/h6.plan"
    "$WARDEN" "$OUT/hl.policy" --plan "$OUT/h6.plan" --hold-to-plan -- /usr/bin/sh -c "$OUT/hl/a && echo a-ran; $OUT/hl/b; echo \"b: \$?\"" \
        > "$OUT/held.out" 2> "$OUT/held.err"
    check "held: a hardlink a step names: run" grep -qx a-ran "$OUT/held.out"
    check "held: another name of the same file, which no step names: outside_plan" \
        sh -c "grep -F '\"action\":\"process.exec\"' '$OUT/held.err' | grep -F '\"resolved\":\"$OUT/hl/b\"' | grep -q '\"rule\":\"outside_plan\"'"
else pass "held launches: not tried (no Landlock here)"; fi
python3 - "$OUT" <<'PY' &
import socket, sys, time
ss = []
for port in (20801, 20802):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(4); ss.append(s)
time.sleep(30)
PY
SRV=$!
sleep 1
{ base; printf 'action c net_connect 127.0.0.1:20801\n'; } > "$OUT/h5.plan"
held "$OUT/h5.plan" /usr/bin/python3 -c '
import socket
for p in (20801, 20802):
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", p)); print(p, "connected")
    except OSError as e:
        print(p, "refused", e.errno)
'
kill $SRV 2>/dev/null
check "held: a connection a net_connect step names: made" grep -q '20801 connected' "$OUT/held.out"
check "held: a connection the policy allows but no step names: refused (outside_plan)" \
    sh -c "grep -q '20802 refused 13' '$OUT/held.out' && grep -F '127.0.0.1:20802' '$OUT/held.err' | grep -q '\"rule\":\"outside_plan\"'"
"$WARDEN" "$HP" --hold-to-plan -- /usr/bin/true > /dev/null 2> "$OUT/held.err"
[ $? = 2 ] && grep -q 'give --plan too' "$OUT/held.err" && pass "--hold-to-plan without --plan: refused, said why" || flunk "--hold-to-plan without --plan"
printf '[varek]\npolicy = %s\nlog_dir = %s/hlogs\nsign_key =\nanchor =\n' "$HP" "$OUT" > "$OUT/hold.conf"
mkdir -p "$OUT/hlogs"
VAREK_CONFIG="$OUT/hold.conf" python3 "$VAREK" run --plan "$OUT/h1.plan" --hold-to-plan -- /usr/bin/cat /etc/passwd > /dev/null 2> "$OUT/vrun.err"
check "varek run --hold-to-plan: the run held (the outside file refused)" sh -c "grep -h '\"rule\":\"outside_plan\"' '$OUT'/hlogs/*.log | grep -q /etc/passwd"

echo "== 7. require plan (step 4b, D7) =="
RP="$OUT/rp.policy"
sed 's/^require warden 1.27$/require warden 1.35/' "$HP" > "$RP"; printf 'require plan\n' >> "$RP"
"$WARDEN" "$RP" -- /usr/bin/true > /dev/null 2> "$OUT/rp.err"
[ $? = 1 ] && grep -q 'the policy says `require plan`: a run needs a plan it is held to' "$OUT/rp.err" \
    && pass "require plan: a run without a plan refused, said why" || flunk "require plan: no plan ($(tail -1 "$OUT/rp.err"))"
"$WARDEN" "$RP" --plan "$OUT/h1.plan" -- /usr/bin/true > /dev/null 2> "$OUT/rp.err"
[ $? = 1 ] && grep -q 'refusing to start' "$OUT/rp.err" \
    && pass "require plan: a plan not held (no --hold-to-plan) refused" || flunk "require plan: --plan alone"
"$WARDEN" "$RP" --plan "$OUT/h1.plan" --hold-to-plan -- /usr/bin/cat /etc/hostname /etc/passwd > "$OUT/rp.out" 2> "$OUT/rp.err"
grep -q "$(cat /etc/hostname)" "$OUT/rp.out" && grep -q '"rule":"outside_plan"' "$OUT/rp.err" \
    && pass "require plan: a held run runs, held" || flunk "require plan: held run"
python3 "$HERE/tools/varek_audit.py" --policy "$RP" --checker "$CHECKER" "$OUT/rp.err" > "$OUT/audit" 2>&1 \
    && grep -q 'varek_audit: PASS' "$OUT/audit" && pass "require plan: varek_audit accepts the held run" \
    || flunk "require plan: the audit ($(grep PROBLEM "$OUT/audit" | head -2))"
python3 "$VAREK" policy show "$RP" > "$OUT/show" 2>&1
check "require plan: varek policy show says so" grep -q 'Requires a plan: a run without one it is held to refuses to start' "$OUT/show"
"$WARDEN" "$RP" --check-startup > /dev/null 2> "$OUT/rp.err"
grep -q 'note: the policy says `require plan`' "$OUT/rp.err" \
    && pass "require plan: --check-startup notes it" || flunk "require plan: --check-startup"
printf 'require warden 1.34\nrequire plan\n' > "$OUT/rp134.policy"
"$WARDEN" "$OUT/rp134.policy" --check-startup > /dev/null 2> "$OUT/rp.err"
[ $? != 0 ] && grep -q '`require plan` needs `require warden 1.35` before it' "$OUT/rp.err" \
    && pass "require plan under require warden 1.34: refused" || flunk "require plan before 1.35 ($(tail -1 "$OUT/rp.err"))"
printf 'require warden 1.35\nrequire plan\nrequire plan\n' > "$OUT/rp2.policy"
"$WARDEN" "$OUT/rp2.policy" --check-startup > /dev/null 2> "$OUT/rp.err"
[ $? != 0 ] && grep -q '`require plan` given twice' "$OUT/rp.err" \
    && pass "require plan given twice: refused" || flunk "require plan twice"
"$HERE/tools/vdp_check" "$RP" identity > "$OUT/id1" 2>&1
"$CHECKER" "$RP" identity > "$OUT/id2" 2>&1
grep -qx 'require plan' "$OUT/id1" && cmp -s "$OUT/id1" "$OUT/id2" \
    && pass "require plan: vdp_check and the checker read it alike (identity)" || flunk "require plan: identity ($(diff "$OUT/id1" "$OUT/id2" | head -3))"
"$WARDEN" "$RP" --oci-filter > /dev/null 2> "$OUT/rp.err" && pass "require plan: the node agent carries it (step 4c: --oci-filter)" \
    || flunk "require plan: --oci-filter ($(tail -1 "$OUT/rp.err"))"
"$WARDEN" "$RP" --oci-filter --no-plan > /dev/null 2> "$OUT/rp.err"
[ $? = 1 ] && grep -q 'a pod under it names its plan' "$OUT/rp.err" \
    && pass "require plan: a pod naming no plan refused (--oci-filter --no-plan)" || flunk "require plan: --no-plan"

echo
if [ "$fail" = 0 ]; then echo "test_v1350: PASS"; else echo "test_v1350: FAIL"; fi
exit "$fail"
