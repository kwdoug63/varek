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
#   8. `varek plan generate --from agentcore` (step 5, D5): the adapter on
#      the two samples (adapters/samples/), what it refuses, the command,
#      the adapter under the Warden, each sample's plan under its policy
#   9. the other adapters (step 6): watsonx and claude on their samples,
#      read as data, each sample's plan under its policy (one authorized, one
#      refused, the step and its reason given), the same plan under the
#      Warden; `varek plan merge`; and, where VAREK_FW_PYTHON names a Python
#      that has the frameworks (adapters/requirements-frameworks.txt) and
#      nobody can read, the code adapters (langgraph, openai-agents) under the
#      Warden in that Python: nothing refused, the agent's prints kept out of
#      the plan, each sample's plan under its policy
#  10. audit and tools for the plan's records (step 7): the plan gate's
#      record names the plan by its SHA-256; the audit checks the gate's
#      records with each other, the run and its hold (each forgery refused),
#      and --plan the plan file; the OCSF export (the gate an event, its
#      refused steps folded in, valid OCSF 1.9.0, --verify); the CycloneDX
#      evidence; varek audit --plan; varek doctor's adapters
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

echo "== 8. varek plan generate --from agentcore (step 5, D5) =="
AD="$HERE/adapters/agentcore.py"
SM="$HERE/adapters/samples"
cp -r "$SM/agentcore-weather" "$SM/agentcore-travel" "$OUT/"
chmod -R a+rX "$OUT/agentcore-weather" "$OUT/agentcore-travel"
gen() { python3 -I "$AD" "$@" > "$OUT/gen.plan" 2> "$OUT/gen.err"; }
WGW=https://weather-tools-q1w2e3r4t5.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp
gen "$OUT/agentcore-weather"
check "the adapter: a plan 1.35 from the weather sample's agentcore.json" sh -c "[ \$(grep -cx 'plan 1.35' '$OUT/gen.plan') = 1 ]"
check "... its gateway's MCP calls, each tool as the gateway names it (TARGET___TOOL)" sh -c \
    "grep -qx 'action gw_weather-tools_initialize mcp_call $WGW method=initialize' '$OUT/gen.plan' &&
     grep -q 'mcp_call $WGW method=tools/list\$' '$OUT/gen.plan' &&
     grep -q 'mcp_call $WGW method=tools/call name=forecast___get_forecast\$' '$OUT/gen.plan' &&
     grep -q 'mcp_call $WGW method=tools/call name=forecast___get_alerts\$' '$OUT/gen.plan'"
check "... the AWS hosts its features reach, in its region (Identity and Memory, X-Ray, CloudWatch Logs)" sh -c \
    "grep -q 'net_connect bedrock-agentcore.us-east-1.amazonaws.com:443\$' '$OUT/gen.plan' &&
     grep -q 'net_connect xray.us-east-1.amazonaws.com:443\$' '$OUT/gen.plan' &&
     grep -q 'net_connect logs.us-east-1.amazonaws.com:443\$' '$OUT/gen.plan'"
check "... its session storage (read and written), its code at the Dockerfile's WORKDIR, the runtime's reads" sh -c \
    "grep -q 'file_open /mnt/session/\$' '$OUT/gen.plan' && grep -q 'file_open /app/ open=read\$' '$OUT/gen.plan' &&
     grep -q 'action sys_usr file_open /usr/ open=read' '$OUT/gen.plan'"
check "... no model host unless named (the framework's, not agentcore.json's); its credential a comment, not a step" sh -c \
    "! grep -q bedrock-runtime '$OUT/gen.plan' && grep -q '^#   forecast-api-key (ApiKeyCredentialProvider)' '$OUT/gen.plan' &&
     ! grep -q '^action [^ ]* credential ' '$OUT/gen.plan'"
gen "$OUT/agentcore-weather" --model-host bedrock-runtime.us-east-1.amazonaws.com:443 --no-runtime
check "--model-host names the model's host; --no-runtime leaves out the runtime's own reads" sh -c \
    "grep -q 'action model net_connect bedrock-runtime.us-east-1.amazonaws.com:443' '$OUT/gen.plan' && ! grep -q sys_usr '$OUT/gen.plan'"
gen "$OUT/agentcore-travel"
TGW=https://travel-tools-z9x8c7v6b5.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp
check "the travel sample: CodeZip's code at /var/task; a target whose tools the gateway lists live: one step naming no tool, said so" sh -c \
    "grep -q 'file_open /var/task/ open=read' '$OUT/gen.plan' && grep -q 'mcp_call $TGW method=tools/call\$' '$OUT/gen.plan' &&
     ! grep -q 'name=flights___' '$OUT/gen.plan' && grep -q 'target hotels: its tools are an MCP server' '$OUT/gen.plan' &&
     ! grep -q bedrock-agentcore.us-west-2.amazonaws.com:443 '$OUT/gen.plan'"
# what the adapter refuses
cp -r "$OUT/agentcore-weather" "$OUT/w2"
python3 - "$OUT/w2/agentcore/agentcore.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
r = dict(d["runtimes"][0]); r["name"] = "second_agent"; d["runtimes"].append(r)
d["agentCoreGateways"][0]["enableSemanticSearch"] = True
json.dump(d, open(p, "w"))
PY
gen "$OUT/w2"
check "two runtimes, none named: no plan, said why" sh -c "[ ! -s '$OUT/gen.plan' ] && grep -q 'name one with --runtime' '$OUT/gen.err'"
gen "$OUT/w2" --runtime second_agent
check "... --runtime names one; semantic search on: the gateway's own search tool a step" sh -c \
    "grep -q 'runtime second_agent' '$OUT/gen.plan' && grep -q 'name=x_amz_bedrock_agentcore_search\$' '$OUT/gen.plan'"
rm "$OUT/w2/agentcore/.cli/deployed-state.json"
gen "$OUT/w2" --runtime weather_agent
check "a gateway not deployed (no URL): no plan, said why" sh -c "[ ! -s '$OUT/gen.plan' ] && grep -q 'gateway weather-tools has no URL' '$OUT/gen.err'"
gen "$OUT/w2" --runtime weather_agent --gateway-url weather-tools=https://gw.example.com/mcp
check "... --gateway-url gives it" grep -q 'mcp_call https://gw.example.com/mcp method=tools/list' "$OUT/gen.plan"
echo '{"runtimes": [' > "$OUT/w2/agentcore/agentcore.json"
gen "$OUT/w2"
check "a project file that is not JSON: no plan, said why" sh -c "[ ! -s '$OUT/gen.plan' ] && grep -q 'is not JSON' '$OUT/gen.err'"
# the command
python3 "$VAREK" plan generate --no-confine -o "$OUT/w.plan" --from agentcore "$OUT/agentcore-weather" > "$OUT/cli.out" 2>&1
python3 -I "$AD" "$OUT/agentcore-weather" > "$OUT/direct.plan"
check "varek plan generate --no-confine -o: the plan written, its steps counted" sh -c \
    "grep -q 'a plan of 24 steps, from' '$OUT/cli.out' && cmp -s '$OUT/w.plan' '$OUT/direct.plan'"
python3 "$VAREK" plan generate --no-confine -o "$OUT/w.plan" --from agentcore "$OUT/agentcore-weather" > "$OUT/cli.out" 2>&1
check "... an existing file not written over without --force" sh -c "[ \$? != 0 ] || grep -q 'exists' '$OUT/cli.out'"
check "... a framework with no adapter: refused, the adapters named" sh -c \
    "! python3 '$VAREK' plan generate --no-confine --from crewai '$OUT/agentcore-weather' > '$OUT/cli.out' 2>&1 && grep -q 'no adapter for' '$OUT/cli.out'"
# under the Warden (D5): the adapter as an agent, the project read-only, no network
mkdir -m 755 "$OUT/home"; cp -r "$HERE/adapters" "$OUT/home/"; chmod -R a+rX "$OUT/home/adapters"
ln -s "$WARDEN" "$OUT/home/warden"; ln -s "$HERE/tools" "$OUT/home/tools"
VAREK_HOME="$OUT/home" python3 "$VAREK" plan generate --log "$OUT/gen.log" -o "$OUT/wc.plan" --from agentcore \
    "$OUT/agentcore-weather" > "$OUT/cli.out" 2>&1
check "under the Warden: the same plan, the adapter's run a verdict stream with nothing refused" sh -c \
    "cmp -s '$OUT/w.plan' '$OUT/wc.plan' && grep -q '\"event\":\"run_start\"' '$OUT/gen.log' &&
     ! grep -q '\"decision_final\":\"DENY\"' '$OUT/gen.log' && ! grep -q 'refused the adapter' '$OUT/cli.out'"
check "... its confinement: the project read-only, no host rule, no launch after its own" sh -c \
    "grep -q 'allow path $OUT/agentcore-weather/ readonly' '$OUT/gen.log' || python3 - '$OUT/gen.log' <<'PY'
import json, sys
rs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith('{\"event\":\"run_start\"')]
sys.exit(0 if rs and not rs[0].get('hosts') else 1)
PY"
# decided under each sample's policy, as the run would (needs the AWS names to resolve)
if getent hosts xray.us-east-1.amazonaws.com > /dev/null 2>&1; then
    python3 "$VAREK" plan generate --no-confine --policy "$OUT/agentcore-weather/weather.policy" --from agentcore \
        "$OUT/agentcore-weather" --model-host bedrock-runtime.us-east-1.amazonaws.com:443 > "$OUT/cli.out" 2>&1; wrc=$?
    check "the weather sample's plan under its policy: authorized" sh -c "[ $wrc = 0 ] && grep -q 'the plan: authorized under' '$OUT/cli.out'"
    python3 "$VAREK" plan generate --no-confine --policy "$OUT/agentcore-travel/travel.policy" --from agentcore \
        "$OUT/agentcore-travel" > "$OUT/gen.plan" 2> "$OUT/cli.out"; trc=$?
    check "the travel sample's under its: refused, the step and its reason given" sh -c \
        "[ $trc = 1 ] && grep -q 'the plan: refused under' '$OUT/cli.out' && grep -q 'tools/call#\\\" is UNKNOWN: no rule of the policy allows it' '$OUT/cli.out' &&
         ! grep -q 'refused under' '$OUT/gen.plan'"
else pass "the samples under their policies: not tried (the AWS host names do not resolve here)"; fi

echo "== 9. the other adapters (step 6): watsonx, claude, langgraph, openai-agents; plan merge =="
for d in watsonx-banking claude-reviewer claude-deployer langgraph-research openai-support; do cp -r "$SM/$d" "$OUT/"; done
chmod -R a+rX "$OUT"/watsonx-banking "$OUT"/claude-* "$OUT"/langgraph-research "$OUT"/openai-support
pgen() { python3 "$VAREK" plan generate "$@" > "$OUT/gen.plan" 2> "$OUT/cli.out"; }
pgen --no-confine --from watsonx "$OUT/watsonx-banking"
check "watsonx: three agents, none named: no plan, said why" sh -c \
    "[ ! -s '$OUT/gen.plan' ] && grep -q 'the project has 3 agents' '$OUT/cli.out'"
pgen --no-confine --from watsonx "$OUT/watsonx-banking" --agent banking_agent
check "watsonx: the banking agent's toolkit, each tool it allows, its model at watsonx.ai in its region" sh -c \
    "grep -q 'mcp_call https://banking.example.com/mcp method=tools/call name=get_balance\$' '$OUT/gen.plan' &&
     grep -q 'action model net_connect us-south.ml.cloud.ibm.com:443\$' '$OUT/gen.plan'"
check "... its collaborator's toolkit too (fx), said so" sh -c \
    "grep -q 'mcp_call https://fx.example.com/mcp method=tools/call name=convert\$' '$OUT/gen.plan' &&
     grep -q '^# collaborator fx_agent (of banking_agent)' '$OUT/gen.plan'"
pgen --no-confine --from watsonx "$OUT/watsonx-banking" --agent banking_agent --watsonx-region eu-de --no-runtime
check "... --watsonx-region gives the model's host; --no-runtime leaves the runtime's reads out" sh -c \
    "grep -q 'net_connect eu-de.ml.cloud.ibm.com:443\$' '$OUT/gen.plan' && ! grep -q sys_usr '$OUT/gen.plan'"
pgen --no-confine --policy "$OUT/watsonx-banking/banking.policy" --from watsonx "$OUT/watsonx-banking" --agent banking_agent; rc=$?
check "watsonx: the banking agent's plan under the sample's policy: authorized" sh -c \
    "[ $rc = 0 ] && grep -q 'the plan: authorized under' '$OUT/cli.out'"
pgen --no-confine --policy "$OUT/watsonx-banking/banking.policy" --from watsonx "$OUT/watsonx-banking" --agent payments_agent; rc=$?
check "... the payments agent's (tools: [\"*\"]): refused, its step naming no tool" sh -c \
    "[ $rc = 1 ] && grep -q 'payments.example.com:443/mcp#tools/call#\" is UNKNOWN: no rule of the policy allows it' '$OUT/cli.out'"
VAREK_HOME="$OUT/home" python3 "$VAREK" plan generate --log "$OUT/wx.log" -o "$OUT/wxc.plan" --from watsonx \
    "$OUT/watsonx-banking" --agent banking_agent > "$OUT/cli.out" 2>&1
python3 "$VAREK" plan generate --no-confine -o "$OUT/wx.plan" --from watsonx "$OUT/watsonx-banking" --agent banking_agent > /dev/null 2>&1
check "watsonx under the Warden (the system's PyYAML, -I without -S): the same plan, nothing refused" sh -c \
    "cmp -s '$OUT/wx.plan' '$OUT/wxc.plan' && ! grep -q '\"decision_final\":\"DENY\"' '$OUT/wx.log'"
# claude: the CLI the SDK runs is a stub here (in the project, which the adapter may read under the
# Warden, as it may /usr/ where the CLI is installed), the sample's policies naming it
CLI="$OUT/claude-reviewer/.bin/claude"
mkdir -m 755 "$OUT/claude-reviewer/.bin"; printf '#!/bin/sh\n' > "$CLI"; chmod 755 "$CLI"
for s in reviewer deployer; do
    sed "s|^allow exec /opt/claude/bin/claude\$|allow exec $CLI|" "$OUT/claude-$s/$s.policy" > "$OUT/$s.policy"
done
CL="--home /home/agent --cli $CLI"
pgen --no-confine --from claude "$OUT/claude-reviewer" --app-dir /srv/reviewer $CL
check "claude: Read/Grep a directory read, Write written, where the agent runs (--app-dir)" sh -c \
    "grep -q 'file_open /srv/reviewer/src/ open=read\$' '$OUT/gen.plan' && grep -q 'file_open /srv/reviewer/reviews/\$' '$OUT/gen.plan'"
check "... Bash(git diff:*) the program's launch, the CLI's, WebFetch's host, Anthropic's API, the CLI's state" sh -c \
    "grep -q 'process_exec /usr/bin/git\$' '$OUT/gen.plan' && grep -q 'action claude_cli process_exec $CLI\$' '$OUT/gen.plan' &&
     grep -q 'net_connect docs.python.org:443\$' '$OUT/gen.plan' && grep -q 'net_connect api.anthropic.com:443\$' '$OUT/gen.plan' &&
     grep -q 'file_open /home/agent/.claude/\$' '$OUT/gen.plan'"
check "... each mcp__SERVER__TOOL a step; the CLI's telemetry left out where its env turns it off" sh -c \
    "grep -q 'mcp_call https://issues.example.com/mcp method=tools/call name=get_issue\$' '$OUT/gen.plan' &&
     grep -q 'name=add_comment\$' '$OUT/gen.plan' && ! grep -q statsig '$OUT/gen.plan'"
pgen --no-confine --from claude "$OUT/claude-reviewer" $CL --allow 'Bash(curl:*)' --app-dir /srv/reviewer
check "... --allow adds the agent's own options' rules" grep -q 'process_exec /usr/bin/curl$' "$OUT/gen.plan"
pgen --no-confine --policy "$OUT/reviewer.policy" --from claude "$OUT/claude-reviewer" --app-dir /srv/reviewer $CL; rc=$?
check "claude: the reviewer's plan under its policy: authorized" sh -c "[ $rc = 0 ] && grep -q 'the plan: authorized under' '$OUT/cli.out'"
pgen --no-confine --policy "$OUT/deployer.policy" --from claude "$OUT/claude-deployer" --app-dir /srv/deployer $CL; rc=$?
check "... the deployer's (mcp__deploy, the server whole): refused, its step naming no tool" sh -c \
    "[ $rc = 1 ] && grep -q 'deploy.example.com:443/mcp#tools/call#\" is UNKNOWN: no rule of the policy allows it' '$OUT/cli.out' &&
     grep -q 'an allow rule grants it whole (mcp__deploy)' '$OUT/gen.plan'"
VAREK_HOME="$OUT/home" python3 "$VAREK" plan generate --log "$OUT/cl.log" -o "$OUT/clc.plan" --from claude \
    "$OUT/claude-reviewer" $CL > "$OUT/cli.out" 2>&1
python3 "$VAREK" plan generate --no-confine -o "$OUT/cl.plan" --from claude "$OUT/claude-reviewer" $CL > /dev/null 2>&1
check "claude under the Warden: the same plan, nothing refused" sh -c \
    "cmp -s '$OUT/cl.plan' '$OUT/clc.plan' && ! grep -q '\"decision_final\":\"DENY\"' '$OUT/cl.log'"
check "a code adapter (langgraph) is not run unconfined" sh -c \
    "! python3 '$VAREK' plan generate --no-confine --from langgraph '$OUT/langgraph-research' > '$OUT/cli.out' 2>&1 &&
     grep -q 'so it runs confined' '$OUT/cli.out'"
# plan merge: a step in both written once, a label taken twice renamed
python3 "$VAREK" plan merge -o "$OUT/m.plan" "$OUT/wx.plan" "$OUT/cl.plan" > "$OUT/cli.out" 2>&1
nwx=$(grep -c '^action' "$OUT/wx.plan"); ncl=$(grep -c '^action' "$OUT/cl.plan"); nm=$(grep -c '^action' "$OUT/m.plan")
check "plan merge: every step of each, the runtime's reads written once" sh -c \
    "[ $nm = \$(( $nwx + $ncl - 14 )) ] && [ \$(grep -c 'action sys_usr file_open /usr/ open=read\$' '$OUT/m.plan') = 1 ]"
check "... a label taken twice renamed (model), and the merged plan read as a plan" sh -c \
    "grep -q '^action model net_connect us-south.ml.cloud.ibm.com:443\$' '$OUT/m.plan' &&
     grep -q '^action model_2 net_connect api.anthropic.com:443\$' '$OUT/m.plan' &&
     python3 '$VAREK' policy check --plan '$OUT/m.plan' '$OUT/reviewer.policy' > /dev/null 2>&1; [ \$? != 2 ]"
# the code adapters, in the agent's own Python (VAREK_FW_PYTHON)
FWPY=${VAREK_FW_PYTHON:-}
if [ -n "$FWPY" ] && runuser -u nobody -- "$FWPY" -I -c 'import langgraph, langchain_anthropic, langchain_openai, langchain_mcp_adapters, agents' > /dev/null 2>&1; then
    cgen() { VAREK_HOME="$OUT/home" python3 "$VAREK" plan generate --python "$FWPY" --log "$OUT/c.log" "$@" > "$OUT/gen.plan" 2> "$OUT/cli.out"; }
    # the agent's Python environment, which the plan names and each sample's policy must allow (step 10)
    "$FWPY" -I -c 'import os, sys
for d in dict.fromkeys(os.path.normpath(x) for x in (sys.prefix, sys.base_prefix, os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix))):
    if not (d in ("/", "/usr") or d.startswith(("/usr/", "/lib", "/etc/"))): print(f"allow path {d}/ readonly")' > "$OUT/venv.rules"
    for p in langgraph-research/research openai-support/support; do cat "$OUT/$p.policy" "$OUT/venv.rules" > "$OUT/$p.venv.policy"; done
    cgen --from langgraph "$OUT/langgraph-research" --graph researcher --app-dir /srv/research
    check "langgraph under the Warden in the agent's Python: the graph's model, its MCP client's server, nothing refused" sh -c \
        "grep -q 'action model net_connect api.anthropic.com:443\$' '$OUT/gen.plan' &&
         grep -q 'mcp_call https://docs.example.com/mcp method=tools/call\$' '$OUT/gen.plan' &&
         ! grep -q '\"decision_final\":\"DENY\"' '$OUT/c.log'"
    check "... the agent's Python environment named, read-only (the plan's python_env steps)" sh -c \
        "[ -s '$OUT/venv.rules' ] && grep -q '^action python_env[^ ]* file_open /[^ ]*/ open=read\$' '$OUT/gen.plan'"
    check "... the graph's print as it is imported kept out of the plan (on standard error)" sh -c \
        "! grep -q 'researcher built' '$OUT/gen.plan' && grep -q 'researcher built' '$OUT/cli.out'"
    cgen --policy "$OUT/langgraph-research/research.venv.policy" --from langgraph "$OUT/langgraph-research" --graph researcher --app-dir /srv/research; rc=$?
    check "... the researcher's plan under the sample's policy: authorized" sh -c "[ $rc = 0 ] && grep -q 'the plan: authorized under' '$OUT/cli.out'"
    cgen --policy "$OUT/langgraph-research/research.venv.policy" --from langgraph "$OUT/langgraph-research" --graph publisher --app-dir /srv/research; rc=$?
    check "... the publisher's (a factory; a stdio MCP server it launches): refused, the sub-agent named" sh -c \
        "[ $rc = 1 ] && grep -q 'subagent step \"files\" is UNKNOWN: no rule of the policy launches a sub-agent by that name' '$OUT/cli.out' &&
         ! grep -q '\"decision_final\":\"DENY\"' '$OUT/c.log'"
    cgen --from openai-agents "$OUT/openai-support" --entry support.py:triage --app-dir /srv/support
    check "openai-agents under the Warden: the handoff's agent too, the static filter's tools, the traces' host" sh -c \
        "grep -q 'name=search_articles\$' '$OUT/gen.plan' && grep -q 'name=get_article\$' '$OUT/gen.plan' &&
         grep -q \"agent billing's tool invoice_total\" '$OUT/gen.plan' && grep -q \"^#   api.openai.com:443: the SDK's traces\" '$OUT/gen.plan' &&
         ! grep -q '\"decision_final\":\"DENY\"' '$OUT/c.log'"
    cgen --policy "$OUT/openai-support/support.venv.policy" --from openai-agents "$OUT/openai-support" --entry support.py:triage --app-dir /srv/support; rc=$?
    check "... the triage agent's plan under the sample's policy: authorized" sh -c "[ $rc = 0 ] && grep -q 'the plan: authorized under' '$OUT/cli.out'"
    cgen --policy "$OUT/openai-support/support.venv.policy" --from openai-agents "$OUT/openai-support" --entry support.py:ops --app-dir /srv/support; rc=$?
    check "... the ops agent's (no tool filter): refused, its step naming no tool" sh -c \
        "[ $rc = 1 ] && grep -q 'ops.example.com:443/mcp#tools/call#\" is UNKNOWN: no rule of the policy allows it' '$OUT/cli.out'"
else pass "the code adapters under the Warden: not tried (VAREK_FW_PYTHON names no Python with the frameworks that nobody can read)"; fi

echo "== 10. audit and tools for the plan's records (step 7) =="
AUD="$HERE/tools/varek_audit.py"
SHA_MIXED=$(sha256sum "$OUT/mixed.txt" | cut -d' ' -f1); SHA_H1=$(sha256sum "$OUT/h1.plan" | cut -d' ' -f1)
check "the plan gate's record names the plan by its SHA-256 (refused, and held)" sh -c \
    "grep -q '^{\"event\":\"plan_gate\",.*\"plan_sha256\":\"$SHA_MIXED\"' '$OUT/mixed.log' &&
     grep -q '^{\"event\":\"plan_gate\",.*\"verdict\":\"SATISFIED\",\"plan_sha256\":\"$SHA_H1\"' '$OUT/h1.log'"
python3 "$AUD" --policy "$LP" --checker "$CHECKER" --plan "$OUT/mixed.txt" "$OUT/mixed.log" > "$OUT/audit" 2>&1; rc=$?
check "the audit: a refused plan, its steps and SHA-256 (--plan the same file): PASS" sh -c \
    "[ $rc = 0 ] && grep -q 'varek_audit: plan: .*mixed.txt (3 steps, SHA-256 $SHA_MIXED): UNSATISFIED, 3 step(s) not SATISFIED; not held to it' '$OUT/audit'"
python3 "$AUD" --policy "$HP" --checker "$CHECKER" --plan "$OUT/h1.plan" "$OUT/h1.log" > "$OUT/audit" 2>&1; rc=$?
check "... a held run: the gate's plan the one held to, the calls refused outside it counted" sh -c \
    "[ $rc = 0 ] && grep -q 'varek_audit: plan: .*h1.plan (4 steps, SHA-256 $SHA_H1): SATISFIED; held to it, [1-9][0-9]* call(s) refused outside it' '$OUT/audit'"
python3 "$AUD" --policy "$HP" --checker "$CHECKER" --plan "$OUT/h2.plan" "$OUT/h1.log" > "$OUT/audit" 2>&1; rc=$?
check "... --plan another file: refused, the two SHA-256s given" sh -c \
    "[ $rc = 1 ] && grep -q 'PROBLEM the plan .*h2.plan hashes to [0-9a-f]\{64\}, the run.s plan to $SHA_H1' '$OUT/audit'"
VAREK_HOME="$HERE" VAREK_CONFIG="$OUT/hold.conf" python3 "$VAREK" audit --plan "$OUT/h2.plan" "$OUT/h1.log" > "$OUT/audit" 2>&1
check "varek audit --plan: passed to the audit" grep -q 'h2.plan hashes to' "$OUT/audit"
# what the audit refuses, the chain aside (a holder of the signing key could re-chain): each check by itself
python3 - "$HERE/tools" > "$OUT/forge.out" 2>&1 <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import varek_audit as va
S = "a" * 64
def gate(v, **k):
    return dict({"event": "plan_gate", "gate": "plan", "plan": "/p", "actions": 2, "edges": 0, "verdict": v,
                 "plan_sha256": S}, **k)
step = {"event": "plan_step", "plan": "/p", "label": "a", "kind": "file_open", "target": "/x",
        "decision": "UNKNOWN", "policy_line": -1, "why": "no rule of the policy allows it"}
dec = [{"seq": 0, "action": "file.open", "decision_final": "ALLOW"}]
rs = {"warden": "1.35.0"}
nosha = {k: v for k, v in gate("SATISFIED").items() if k != "plan_sha256"}
cases = {
    "a refused plan, and the agent's calls": ({"run_start": rs, "plan_events": [(0, step), (0, gate("UNSATISFIED"))]}, dec),
    "an authorized plan, and a step not SATISFIED": ({"run_start": rs, "plan_events": [(0, step), (0, gate("SATISFIED"))]}, []),
    "a refused plan, no step its reason": ({"run_start": rs, "plan_events": [(0, gate("UNKNOWN"))]}, []),
    "a step recorded SATISFIED": ({"run_start": rs, "plan_events": [(0, dict(step, decision="SATISFIED")),
                                                                    (0, gate("UNSATISFIED"))]}, []),
    "a step after the gate": ({"run_start": rs, "plan_events": [(0, gate("UNSATISFIED")), (0, step)]}, []),
    "the gate after the agent's calls": ({"run_start": rs, "plan_events": [(1, gate("SATISFIED"))]}, dec),
    "a second plan gate": ({"run_start": rs, "plan_events": [(0, gate("SATISFIED")), (0, gate("SATISFIED"))]}, []),
    "a 1.35 gate without the plan's SHA-256": ({"run_start": rs, "plan_events": [(0, nosha)]}, []),
    "a held run no gate decided": ({"run_start": dict(rs, hold={"plan": "/p", "plan_sha256": S})}, []),
    "a held run, the gate on another plan": ({"run_start": dict(rs, hold={"plan": "/q", "plan_sha256": S}),
                                              "plan_events": [(0, gate("SATISFIED"))]}, []),
    "a held run, the plan changed between gate and hold": (
        {"run_start": dict(rs, hold={"plan": "/p", "plan_sha256": "b" * 64}), "plan_events": [(0, gate("SATISFIED"))]}, []),
}
for what, (meta, recs) in cases.items():
    problems = []
    va.check_plan_gate(meta, recs, problems)
    print(("REFUSED " if problems else "MISSED  ") + what + (": " + problems[0] if problems else ""))
problems = []
va.check_plan_gate({"run_start": rs, "plan_events": [(0, step), (0, gate("UNSATISFIED"))]}, [], problems)
print("CLEAN" if not problems else "NOT CLEAN " + problems[0])
PY
check "the audit refuses each of 11 forgeries of the gate's records, and passes the true one" sh -c \
    "[ \$(grep -c '^REFUSED ' '$OUT/forge.out') = 11 ] && grep -qx CLEAN '$OUT/forge.out'"
# the OCSF export
OC="$HERE/tools/varek_ocsf.py"; OV="$HERE/tests/ocsf_validate.py"
python3 "$OC" --log "$OUT/mixed.log" --policy "$LP" --checker "$CHECKER" --output "$OUT/m.ocsf" > /dev/null 2>&1
python3 - "$OUT/m.ocsf" > "$OUT/oc.out" 2>&1 <<'PY'
import json, sys
ev = [json.loads(l) for l in open(sys.argv[1])]
g = [e for e in ev if e["unmapped"]["varek"].get("event") == "plan_gate"]
assert len(g) == 1, len(g)
g = g[0]; v = g["unmapped"]["varek"]
assert g["class_uid"] == 6002 and g["activity_id"] == 99, (g["class_uid"], g["activity_id"])
assert g["action"] == "Denied" and g["disposition"] == "Blocked" and g["status"] == "Failure"
assert v["decision"] == "UNSATISFIED" and v["plan"]["actions"] == 3 and len(v["plan"]["plan_sha256"]) == 64
st = {s["label"]: s for s in v["plan_steps"]}
assert set(st) == {"a", "b", "c"}, st
assert st["a"]["decision"] == "UNSATISFIED" and st["a"]["policy_text"] == "deny exec /usr/bin/false", st["a"]
assert st["b"]["why"] == "no rule of the policy allows it"
assert not any(e["unmapped"]["varek"].get("event") == "plan_step" for e in ev)
print("ok")
PY
check "OCSF: the refused plan an Application Lifecycle event, Denied and Blocked, its steps folded in with each reason" \
    grep -qx ok "$OUT/oc.out"
python3 "$OC" --log "$OUT/h1.log" --policy "$HP" --checker "$CHECKER" --output "$OUT/h.ocsf" > /dev/null 2>&1
check "... a held run's gate Allowed; a call refused outside the plan names the plan it is held to" python3 -c "
import json
ev = [json.loads(l) for l in open('$OUT/h.ocsf')]
g = [e for e in ev if e['unmapped']['varek'].get('event') == 'plan_gate'][0]
o = [e for e in ev if e['unmapped']['varek'].get('rule') == 'outside_plan']
assert g['action'] == 'Allowed' and g['unmapped']['varek']['plan_steps'] == []
assert o and all(e['unmapped']['varek']['plan'] == {'plan': '$OUT/h1.plan', 'plan_sha256': '$SHA_H1', 'held': True} for e in o)
assert all(e['disposition'] == 'Blocked' for e in o)"
check "... both valid OCSF 1.9.0, and --verify finds them the stream's" sh -c \
    "python3 '$OV' '$OUT/m.ocsf' && python3 '$OV' '$OUT/h.ocsf' &&
     python3 '$OC' --verify '$OUT/h.ocsf' --log '$OUT/h1.log' --policy '$HP' --checker '$CHECKER'"
# the CycloneDX evidence
CX="$HERE/tools/varek_cyclonedx.py"
python3 "$CX" --log "$OUT/mixed.log" --policy "$LP" --agent t > "$OUT/m.cdx" 2> /dev/null
python3 "$CX" --log "$OUT/h1.log" --policy "$HP" --agent t > "$OUT/h.cdx" 2> /dev/null
check "CycloneDX: the refused plan by its SHA-256, the agent not started, the steps counted" sh -c \
    "grep -q 'was decided UNSATISFIED under the policy (3 step(s) not SATISFIED, each recorded with its reason), so the agent was not started' '$OUT/m.cdx' &&
     grep -q '\"varek:plan.sha256\"' '$OUT/m.cdx' && grep -q '$SHA_MIXED' '$OUT/m.cdx'"
check "... the held run: held, and the calls refused outside its plan" sh -c \
    "grep -q 'The run was held to its plan: [1-9][0-9]* call(s) the policy allowed were refused as outside it' '$OUT/h.cdx' &&
     grep -q '\"varek:plan.held\"' '$OUT/h.cdx'"
VAREK_HOME="$HERE" VAREK_CONFIG="$OUT/none.conf" python3 "$VAREK" doctor > "$OUT/doc" 2>&1
check "varek doctor names the plan adapters installed" \
    grep -q 'plan adapters: agentcore, watsonx, langgraph, openai-agents, claude' "$OUT/doc"

echo
if [ "$fail" = 0 ]; then echo "test_v1350: PASS"; else echo "test_v1350: FAIL"; fi
exit "$fail"
