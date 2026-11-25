#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1420.sh — regression test for VAREK v1.42: approvals as grants,
# STEP_UP and DEFER (docs/security/v1.42-step-up-defer.md). Built in steps;
# each step adds its section.
#
# Step 1, the grammar and the decision, in the procedure and in the checker
# (no Warden code):
#   1. step_up rules and their options, max_held and max_pending, read the
#      same by the decision procedure (vdp_check) and the certificate
#      checker (vdp_cert_check): each form accepted by both, each malformed
#      one refused by both; the Warden loads such a policy, its two parsers
#      agreeing.
#   2. The decision: a call a step_up rule decides is refused (UNSATISFIED,
#      the rule a step_up rule); with symbolic flags, a mix of step_up with
#      allow or with deny is UNKNOWN.
#   3. Grants: the text read by both parsers, each malformed or overreaching
#      grant refused by both (another kind, a deny rule, for=, credential=, a
#      wildcard, too many rules, no limit, a bad time, a line given twice).
#   4. Within grants: a call under the step_up rule and one of a grant's
#      rules is SATISFIED with a two-part certificate the checker accepts;
#      a grant reaches no call the policy decides otherwise (a deny before
#      it, an allow, another step_up rule); the checker refuses each forged
#      certificate (the wrong step_up rule, a write under a read-only grant,
#      another object, a grant's half missing or naming a rule that does not
#      hold, symbolic flags a grant does not cover).
#
# Step 2, runtime grants in mode=grant (section 5, as root):
#   5. A policy needing a step not built yet (mode=hold) is refused at start.
#      A read the step_up rule refuses proposes the narrowest grant, which
#      the approvers' socket lists only to who may answer it. The agent's own
#      user, another user (no approvers=), and grants wider than the proposal
#      (count, time, run, another step_up rule) are refused; root approves,
#      the next read is allowed with both halves checked, exactly once; a
#      denial and a late answer; the records; the audit passes, and refuses
#      each forgery for its own reason (the text edited, the grant or a
#      proposal's record or ending dropped, the object changed, a second use,
#      a grant for no open proposal). With approvers=GROUP: outsiders and
#      root alone refused, a member approves; a proposal times out.
#
# Step 3, mode=hold (section 6, as root):
#   6. A read a hold rule decides waits in the kernel (a held step_up
#      record, no decision yet); approved, the same read goes on, decided
#      again within the grant; denied, or past the timeout, it is refused,
#      its refusal recorded before the ending; max_held refuses one more at
#      once; another process's calls go on while one is held; a symlink
#      swapped while held is refused when decided again; a held launch,
#      approved, runs (the step_up program is in the launch set); a step_up
#      rule that writes gets its noexec mount; the audit passes each run and
#      refuses a held call's refusal dropped.
#
# Step 3b, held at the egress proxy (section 7, as root, a local DNS and
# HTTP server):
#   7. A plain-HTTP request and an MCP call a mode=hold rule decides are held
#      at the proxy, each proposal the call itself; approved, each is sent
#      on; denied, the request is refused (403) and never reaches the server;
#      the records and the audit.
#
# Usage: sudo ./test_v1420.sh   (from varek/v1_4, after `make warden tools/vdp_check tools/vdp_cert_check`;
#        sections 1 to 4 need no root, and run without it)
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VDP="$HERE/tools/vdp_check"
CERT="$HERE/tools/vdp_cert_check"
WARDEN="$HERE/warden"
fail=0
n=0
pass() { printf '  %-6s %s\n' PASS "$1"; n=$((n + 1)); }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
hx() { printf %s "$1" | od -An -tx1 | tr -d ' \n'; }

# accepted NAME POLICY: both parsers read it
accepted() {
    printf "$2" > "$T/a.txt"
    if "$VDP" "$T/a.txt" lint > "$T/a.out" 2>&1 && "$CERT" "$T/a.txt" digest > /dev/null 2>&1; then pass "$1"
    else flunk "$1"; sed 's/^/        /' "$T/a.out"; fi
}
# refused NAME POLICY [WHY]: both parsers refuse it (the procedure saying WHY)
refused() {
    printf "$2" > "$T/r.txt"
    local o; o="$("$VDP" "$T/r.txt" lint 2>&1)"
    if ! "$VDP" "$T/r.txt" lint > /dev/null 2>&1 && ! "$CERT" "$T/r.txt" digest > /dev/null 2>&1 &&
       { [ -z "${3:-}" ] || grep -q -- "$3" <<<"$o"; }; then pass "refused: $1"
    else flunk "refused: $1"; echo "        $o"; fi
}

echo "== 1. the grammar =="
accepted "a step_up rule of each kind (a request over a step_up host not dead: a grant may open it)" 'require warden 1.42\nproxy inspect\nstep_up path /srv/data/\nstep_up host api.example.com:443\nstep_up exec /usr/bin/curl\nstep_up request POST https://api.example.com/pay\nstep_up mcp https://m.example.com/mcp tools/call refund\nallow host m.example.com:443\n'
accepted "every option, in any order" 'require warden 1.42\nstep_up path /srv/data/ approvers=varek-approvers mode=hold timeout=120 scope=run notify=https://hooks.example.test/x\nstep_up path /srv/b/ readonly scope=thread mode=grant timeout=3600 approvers=_ops$\n'
accepted "max_held and max_pending" 'require warden 1.42\nmax_held 4\nmax_pending 1024\nallow path /tmp/\n'
refused "step_up before 1.42"              'require warden 1.35\nstep_up path /srv/\n'                 "needs \`require warden 1.42\`"
refused "max_held before 1.42"             'require warden 1.35\nmax_held 4\n'                         "needs \`require warden 1.42\`"
refused "max_held 0"                       'require warden 1.42\nmax_held 0\n'
refused "max_pending 1025"                 'require warden 1.42\nmax_pending 1025\n'
refused "max_held twice"                   'require warden 1.42\nmax_held 2\nmax_held 2\n'             "given twice"
refused "mode=x"                           'require warden 1.42\nstep_up path /s/ mode=x\n'           "mode= is grant or hold"
refused "timeout=0"                        'require warden 1.42\nstep_up path /s/ timeout=0\n'
refused "timeout=3601"                     'require warden 1.42\nstep_up path /s/ timeout=3601\n'
refused "timeout=01"                       'require warden 1.42\nstep_up path /s/ timeout=01\n'
refused "approvers=Ops"                    'require warden 1.42\nstep_up path /s/ approvers=Ops\n'
refused "scope=all"                        'require warden 1.42\nstep_up path /s/ scope=all\n'
refused "notify=http://"                   'require warden 1.42\nstep_up path /s/ notify=http://h.example/x\n'
refused "an option twice"                  'require warden 1.42\nstep_up path /s/ mode=hold mode=grant\n' "given twice"
refused "an option before a flag clause"   'require warden 1.42\nstep_up path /s/ mode=hold readonly\n'
refused "a step_up option on an allow rule" 'require warden 1.42\nallow path /s/ mode=hold\n'
refused "credential= on a step_up rule"    'require warden 1.42\nproxy inspect\ncredential k from file:/k\nstep_up request POST https://a.example.com/x credential=k header=Authorization\nallow host a.example.com:443\n'
refused "a wildcard budget on a step_up rule" 'require warden 1.42\nstep_up host *.example.com names=4\n'
printf 'require warden 1.42\nallow path /tmp/\nstep_up path /srv/data/ mode=hold timeout=60 approvers=ops notify=https://h.example/x\nstep_up path /srv/data/x\n' > "$T/w.txt"
o="$("$WARDEN" "$T/w.txt" --check-startup 2>&1)"
grep -q "read this rule differently" <<<"$o" && flunk "the Warden's two parsers disagree on a step_up rule: $o" \
  || pass "the Warden loads a step_up policy, its two parsers agreeing on every option"
"$VDP" "$T/w.txt" lint 2>&1 | grep -q ":4: step_up path .* can never fire" \
  && pass "lint names a step_up rule that can never fire" || flunk "lint on a dead step_up rule: $("$VDP" "$T/w.txt" lint 2>&1)"

echo "== 2. the decision =="
cat > "$T/p.txt" <<'EOF'
require warden 1.42
allow path /tmp/
deny path /srv/data/secret
step_up path /srv/data/ approvers=ops
step_up host api.payments.example:443
allow path /srv/
step_up path /mix/ readonly
allow path /mix/
deny path /mixd/ readonly
step_up path /mixd/
EOF
"$VDP" "$T/p.txt" lint > /dev/null 2>&1 && pass "the policy loads" || flunk "the policy: $("$VDP" "$T/p.txt" lint 2>&1)"
q() { printf '%s %s %s\n' "$1" "$2" "$(hx "$3")" | "$VDP" "$T/p.txt" batch "${@:4}"; }
o="$(q path 0 /srv/data/r.csv)"
grep -q '"verdict":"UNSATISFIED","rule":2,"line":4.*"verb":"step_up"' <<<"$o" && pass "a step_up rule alone refuses: UNSATISFIED, line 4, step_up" || flunk "step_up alone: $o"
o="$(q host - api.payments.example:443)"
grep -q '"verdict":"UNSATISFIED".*"verb":"step_up"' <<<"$o" && pass "... a host too" || flunk "step_up host: $o"
o="$(q path - /srv/data/r.csv)"
grep -q '"verdict":"UNSATISFIED".*"verb":"step_up"' <<<"$o" && pass "... and with symbolic flags, when it decides every flags value" || flunk "symbolic step_up: $o"
o="$(q path - /mix/a)"
grep -q '"verdict":"UNKNOWN".*symbolic_flags_mixed' <<<"$o" && pass "symbolic flags, step_up for reads and allow for writes: UNKNOWN" || flunk "step_up/allow mix: $o"
o="$(q path - /mixd/a)"
grep -q '"verdict":"UNKNOWN".*symbolic_flags_mixed' <<<"$o" && pass "symbolic flags, deny for reads and step_up for writes: UNKNOWN (an outcome of its own)" || flunk "deny/step_up mix: $o"
o="$(q path 0 /srv/data/secret)"
grep -q '"verdict":"UNSATISFIED","rule":1,"line":3.*"verb":"deny"' <<<"$o" && pass "a deny rule before it still decides" || flunk "deny first: $o"

echo "== 3. grants =="
# good NAME GRANT: both parsers read it; bad NAME GRANT [WHY]: both refuse it
good() {
    printf "$2" > "$T/g.txt"
    if "$VDP" "$T/p.txt" grant "$T/g.txt" > "$T/g.out" 2>&1 && "$CERT" "$T/p.txt" grant "$T/g.txt" > /dev/null 2>&1; then pass "grant: $1"
    else flunk "grant: $1"; sed 's/^/        /' "$T/g.out"; "$CERT" "$T/p.txt" grant "$T/g.txt"; fi
}
bad() {
    printf "$2" > "$T/b.txt"
    local o; o="$("$VDP" "$T/p.txt" grant "$T/b.txt" 2>&1)"
    if ! "$VDP" "$T/p.txt" grant "$T/b.txt" > /dev/null 2>&1 && ! "$CERT" "$T/p.txt" grant "$T/b.txt" > /dev/null 2>&1 &&
       { [ -z "${3:-}" ] || grep -q -- "$3" <<<"$o"; }; then pass "grant refused: $1"
    else flunk "grant refused: $1"; echo "        $o"; fi
}
good "the narrowest: one file, read, once" 'grant\nstep_up line 4\nallow path /srv/data/r.csv readonly\ncount 1\nuntil 2026-11-25T17:00:00Z\n'
o="$(cat "$T/g.out")"
grep -q '"step_up_line":4,"rules":1,"count":1,"until":1795626000' <<<"$o" && pass "... its step_up line, rule, count and time (UTC) as read" || flunk "the grant as read: $o"
good "scope, comments and blank lines" '# proposed by the Warden\ngrant\n\nstep_up line 4\nallow path /srv/data/a/   # a directory\nallow path /srv/data/b.csv\nfor user=alice@example.test subagent=billing run=r-17\nuntil 2026-12-31T23:59:59Z\n'
good "eight rules" "grant\nstep_up line 4\n$(for i in 1 2 3 4 5 6 7 8; do printf 'allow path /srv/data/%s\\n' $i; done)count 2\n"
good "a host" 'grant\nstep_up line 5\nallow host api.payments.example:443\ncount 3\n'
bad "no grant line"                 'step_up line 4\nallow path /srv/data/x\ncount 1\n'                  "starts with the line"
bad "grant twice"                   'grant\ngrant\nstep_up line 4\nallow path /srv/data/x\ncount 1\n'
bad "no step_up line"               'grant\nallow path /srv/data/x\ncount 1\n'                        "no \`step_up line N\`"
bad "a line that is not step_up"    'grant\nstep_up line 2\nallow path /tmp/x\ncount 1\n'             "is not a step_up rule"
bad "step_up line twice"            'grant\nstep_up line 4\nstep_up line 4\nallow path /srv/data/x\ncount 1\n'
bad "no rule"                       'grant\nstep_up line 4\ncount 1\n'                                "no allow rule"
bad "nine rules"                    "grant\nstep_up line 4\n$(for i in 1 2 3 4 5 6 7 8 9; do printf 'allow path /srv/data/%s\\n' $i; done)count 2\n" "more than 8"
bad "neither count nor until"       'grant\nstep_up line 4\nallow path /srv/data/x\n'                 "a grant is limited"
bad "another kind"                  'grant\nstep_up line 4\nallow host api.payments.example:443\ncount 1\n' "a grant's rules are of its kind"
bad "a deny rule"                   'grant\nstep_up line 4\ndeny path /srv/data/x\ncount 1\n'
bad "a step_up rule"                'grant\nstep_up line 4\nstep_up path /srv/data/x\ncount 1\n'
bad "for= on a rule"                'grant\nstep_up line 4\nallow path /srv/data/x for=bot\ncount 1\n'
bad "a wildcard host"               'grant\nstep_up line 5\nallow host *.payments.example acknowledge=dns-channel\ncount 1\n' "no wildcard"
bad "a sub-agent launch"            'grant\nstep_up line 4\nallow exec /usr/bin/x subagent=a\ncount 1\n'
bad "count 0"                       'grant\nstep_up line 4\nallow path /srv/data/x\ncount 0\n'
bad "count twice"                   'grant\nstep_up line 4\nallow path /srv/data/x\ncount 1\ncount 1\n'
bad "until Feb 30"                  'grant\nstep_up line 4\nallow path /srv/data/x\nuntil 2026-02-30T00:00:00Z\n'
bad "until not UTC"                 'grant\nstep_up line 4\nallow path /srv/data/x\nuntil 2026-11-25T17:00:00+01:00\n'
bad "for with an unknown scope"     'grant\nstep_up line 4\nallow path /srv/data/x\nfor team=a\ncount 1\n'
bad "for twice"                     'grant\nstep_up line 4\nallow path /srv/data/x\nfor user=a\nfor user=b\ncount 1\n'
bad "an unknown line"               'grant\nstep_up line 4\nallow path /srv/data/x\napprover alice\ncount 1\n' "unknown line"
bad "a rule the parser refuses, by the grant's own line" 'grant\nstep_up line 4\n\nallow path /srv/data/x +bogus\ncount 1\n' "grant:4:"

echo "== 4. within grants, and the two-part certificate =="
printf 'grant\nstep_up line 4\nallow path /srv/data/r.csv readonly\ncount 1\n' > "$T/g0.txt"
printf 'grant\nstep_up line 4\nallow path /srv/\ncount 5\n' > "$T/g1.txt"        # wider than its envelope
printf 'grant\nstep_up line 5\nallow host api.payments.example:443\ncount 1\n' > "$T/g2.txt"
gq() { printf '%s %s %s\n' "$1" "$2" "$(hx "$3")" | "$VDP" "$T/p.txt" batch "$T/g0.txt" "$T/g1.txt" "$T/g2.txt"; }
o="$(gq path 0 /srv/data/r.csv)"
grep -q '"verdict":"SATISFIED","rule":2,"line":4.*"verb":"step_up".*"grant":0,"grant_rule":0,"grant_line":3' <<<"$o" \
  && pass "a read of the granted file: SATISFIED under grant 0 (its line 3), the step_up rule line 4" || flunk "granted read: $o"
o="$(gq path 2 /srv/data/r.csv)"
grep -q '"verdict":"SATISFIED".*"grant":1' <<<"$o" && pass "a write of it: not grant 0's (read only), grant 1's" || flunk "granted write: $o"
o="$(printf 'path 2 %s\n' "$(hx /srv/data/r.csv)" | "$VDP" "$T/p.txt" batch "$T/g0.txt")"
grep -q '"verdict":"UNSATISFIED".*"verb":"step_up"' <<<"$o" && ! grep -q '"grant"' <<<"$o" && pass "... refused with grant 0 alone" || flunk "write, grant 0 alone: $o"
o="$(gq path 0 /srv/data/secret)"
grep -q '"verdict":"UNSATISFIED","rule":1,"line":3.*"verb":"deny"' <<<"$o" && ! grep -q '"grant"' <<<"$o" \
  && pass "a grant wider than its envelope reaches nothing the policy denies first" || flunk "wide grant, deny first: $o"
o="$(gq path 0 /srv/other)"
grep -q '"verdict":"SATISFIED","rule":4,"line":6.*"verb":"allow"' <<<"$o" && ! grep -q '"grant"' <<<"$o" \
  && pass "... nor what the policy allows (decided by the policy alone, no grant named)" || flunk "wide grant, allow: $o"
o="$(gq host - api.payments.example:443)"
grep -q '"verdict":"SATISFIED","rule":3,"line":5.*"grant":2' <<<"$o" && pass "a host under its own step_up rule's grant" || flunk "host grant: $o"
o="$(printf 'host - %s\n' "$(hx api.payments.example:443)" | "$VDP" "$T/p.txt" batch "$T/g0.txt" "$T/g1.txt")"
grep -q '"verdict":"UNSATISFIED"' <<<"$o" && pass "... and no path rule's grant allows it" || flunk "host under path grants: $o"
o="$(gq path - /srv/data/r.csv)"
grep -q '"verdict":"SATISFIED".*"grant":1' <<<"$o" && pass "symbolic flags: the grant that covers every flags value (1, not the read-only 0)" || flunk "symbolic grant: $o"

R="$(hx /srv/data/r.csv)"; H="$(hx api.payments.example:443)"
chk() { printf '%s\n' "$2" | "$CERT" "$T/p.txt" batch "$T/g0.txt" "$T/g1.txt" "$T/g2.txt"; }
ok()  { o="$(chk "$1" "$2")"; grep -q '"check":"ok"' <<<"$o" && pass "checker accepts: $1" || flunk "checker accepts: $1: $o"; }
rej() { o="$(chk "$1" "$2")"; grep -q '"check":"reject"' <<<"$o" && pass "checker refuses: $1 ($(sed 's/.*"why":"\(.*\)"}/\1/' <<<"$o"))" || flunk "checker refuses: $1: $o"; }
ok  "the granted read"                         "path 0 $R 2 - grant=0:0:-"
ok  "the granted host"                         "host 0 $H 3 - grant=2:0:-"
ok  "symbolic flags under the grant that covers them" "path - $R 2 - grant=1:0:-"
rej "the step_up half alone, as an allow"      "path 0 $R 2 -"
rej "a write under the read-only grant"        "path 2 $R 2 - grant=0:0:-"
rej "another file under grant 0"               "path 0 $(hx /srv/data/other) 2 - grant=0:0:-"
rej "the wrong step_up rule for the grant"     "path 0 $R 3 - grant=0:0:-"
rej "a host under a path rule's grant"         "host 0 $H 3 - grant=0:0:-"
rej "a call a deny rule decides first"         "path 0 $(hx /srv/data/secret) 2 - grant=1:0:-"
rej "a call an allow rule decides"             "path 0 $(hx /srv/other) 4 - grant=1:0:-"
rej "a grant rule that does not exist"         "path 0 $R 2 - grant=0:1:-"
rej "symbolic flags the read-only grant does not cover" "path - $R 2 - grant=0:0:-"
o="$(chk x "path 0 $R 2 - grant=7:0:-")"
grep -q '"check":"error"' <<<"$o" && pass "checker: a grant not given is an error" || flunk "unknown grant: $o"

echo "== 5. step 2: runtime grants, mode=grant (as root) =="
if [ "$(id -u)" != 0 ] || ! command -v setpriv > /dev/null; then
    echo "  SKIP   section 5 needs root and setpriv"
else
W="$T/w"; mkdir -p "$W/bin" "$W/data"; chmod 755 "$T" "$W" "$W/bin" "$W/data"
echo "a,b" > "$W/data/r.csv"; chmod 644 "$W/data/r.csv"
cat > "$W/bin/agent.sh" <<'AG'
# read the file every quarter second, N times; say what each try got
for i in $(seq 1 "$2"); do
  if read -r l < "$1"; then echo "$i ok"; else echo "$i no"; fi
  sleep 0.25
done
AG
cat > "$W/bin/apv.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall(sys.argv[2].encode()); s.shutdown(socket.SHUT_WR)
out = b""
while True:
    b = s.recv(65536)
    if not b: break
    out += b
sys.stdout.write(out.decode())
PY
chmod 755 "$W/bin/agent.sh" "$W/bin/apv.py"
BASE="require warden 1.42\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ readonly\nallow path $W/bin/ readonly\nallow exec /usr/bin/sleep\nallow exec /usr/bin/seq\n"
# apv UID GID REQUEST: a request on the approvers' socket, as that user
apv() { setpriv --reuid="$1" --regid="$2" --clear-groups python3 -I "$W/bin/apv.py" "$SOCK" "$(printf '%b' "$3")"; }
# wait_prop [OLD]: the next open proposal's id other than OLD (as AU:AG, an approver), within 10 s
AU=0; AG=0
wait_prop() {
    local k
    for k in $(seq 1 40); do
        local id; id="$(apv "$AU" "$AG" pending | python3 -c 'import json,sys; l=sys.stdin.readline(); print(json.loads(l)["id"] if l.startswith("{") else "")' 2>/dev/null)"
        [ -n "$id" ] && [ "$id" != "${1:-}" ] && { echo "$id"; return 0; }
        sleep 0.25
    done
    return 1
}
start() {   # start POLICY OUT N: the Warden on the agent, in the background; SOCK and RUN
    "$WARDEN" "$1" -- /bin/bash "$W/bin/agent.sh" "$W/data/r.csv" "$3" > "$2.out" 2> "$2.log" &
    WPID=$!
    SOCK=""; local k
    for k in $(seq 1 40); do
        SOCK="$(grep -o '/run/varek-approve/[0-9a-f]*\.sock' "$2.log" 2>/dev/null | head -1)"
        [ -n "$SOCK" ] && [ -S "$SOCK" ] && break
        sleep 0.25
    done
    RUN="$(basename "$SOCK" .sock)"
}
recs() { python3 -c "import json,sys; rs=[json.loads(l) for l in open(sys.argv[1]) if l.startswith('{')]; sys.exit(0 if $2 else 1)" "$1"; }

printf "${BASE}step_up path $W/data/ scope=run\n" > "$W/hold.txt"
o="$("$WARDEN" "$W/hold.txt" --check-startup 2>&1)"
grep -q "scope=run is not built yet" <<<"$o" && pass "a policy with scope=run is refused at start (built in step 4)" || flunk "scope=run at start: $o"

printf "${BASE}step_up path $W/data/ timeout=30\nstep_up host api.example.test:443\n" > "$W/p1.txt"     # step_up on line 9, the host one 10
start "$W/p1.txt" "$W/r1" 80
[ -n "$SOCK" ] && pass "the run opens its approvers' socket ($SOCK)" || flunk "no approvers' socket: $(tail -3 "$W/r1.log")"
ID1="$(wait_prop)"
[ -n "$ID1" ] && pass "a read the step_up rule refuses proposes a grant ($ID1)" || flunk "no proposal"
o="$(apv 0 0 pending)"
grep -q "allow path exact $W/data/r.csv access=ro -O_CREAT -O_TRUNC -O_APPEND" <<<"$o" && grep -q "step_up line 9" <<<"$o" \
  && grep -q "for run=$RUN" <<<"$o" && grep -q 'count 1' <<<"$o" \
  && pass "... the narrowest: the exact file, the call's access, this run, count 1, until the rule's timeout" || flunk "the proposal: $o"
o="$(apv 65534 65534 pending)"
grep -q "not an approver in this run" <<<"$o" && pass "the agent's own user is no approver: pending shows it nothing" || flunk "pending as the agent: $o"
o="$(apv 65534 65534 "approve $ID1")"
grep -q "not an approver in this run" <<<"$o" && pass "... and its approval is refused" || flunk "approve as the agent: $o"
o="$(apv 4242 4242 "approve $ID1")"
grep -q "not an approver in this run" <<<"$o" && pass "another user is refused, where the rule names no approvers= (root alone)" || flunk "approve as uid 4242: $o"
o="$(timeout 3 setpriv --reuid=4242 --regid=4242 --clear-groups python3 -I -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.settimeout(2); print(s.recv(200).decode().strip())" "$SOCK")"
grep -q "not an approver" <<<"$o" && pass "a user who connects and sends nothing is answered at once (no wait on another user)" || flunk "silent outsider: $o"
U="$(date -u -d '+20 seconds' +%Y-%m-%dT%H:%M:%SZ)"; L="$(date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%SZ)"
o="$(apv 0 0 "approve $ID1\ngrant\nstep_up line 9\nallow path $W/data/\nfor run=$RUN\ncount 5\nuntil $U\n")"
grep -q "count is wider" <<<"$o" && pass "a grant with a wider count is refused" || flunk "wider count: $o"
o="$(apv 0 0 "approve $ID1\ngrant\nstep_up line 9\nallow path $W/data/r.csv\nfor run=$RUN\ncount 1\nuntil $L\n")"
grep -q "time is later" <<<"$o" && pass "... a later time" || flunk "later time: $o"
o="$(apv 0 0 "approve $ID1\ngrant\nstep_up line 9\nallow path $W/data/r.csv\nfor run=0123456789abcdef0123456789abcdef\ncount 1\nuntil $U\n")"
grep -q "not for this run" <<<"$o" && pass "... another run's" || flunk "another run: $o"
o="$(apv 0 0 "approve $ID1\ngrant\nstep_up line 10\nallow host api.example.test:443\nfor run=$RUN\ncount 1\nuntil $U\n")"
grep -q "another step_up rule" <<<"$o" && pass "... one under another step_up rule" || flunk "another rule: $o"
o="$(apv 0 0 "approve $ID1\ngrant\nstep_up line 9\ndeny path $W/data/r.csv\nfor run=$RUN\ncount 1\n")"
grep -q "refused" <<<"$o" && pass "... a grant the procedure does not read (a deny rule)" || flunk "deny rule in a grant: $o"
o="$(apv 0 0 "approve $ID1\nreason test_v1420")"
GID1="$(sed -n 's/^approved \([0-9a-f]\{64\}\)$/\1/p' <<<"$o")"
[ -n "$GID1" ] && pass "root approves it as proposed: grant $(cut -c1-16 <<<"$GID1")" || flunk "approve: $o"
for k in $(seq 1 40); do grep -q ' ok$' "$W/r1.out" && break; sleep 0.25; done
grep -q ' ok$' "$W/r1.out" && pass "the agent's next read is allowed" || flunk "no read allowed: $(tail -3 "$W/r1.out")"
ID2="$(wait_prop "$ID1")"
[ -n "$ID2" ] && [ "$ID2" != "$ID1" ] && pass "its count used, the read after is refused and proposed again ($ID2)" || flunk "no second proposal"
o="$(apv 0 0 "deny $ID2\nreason no more")"
[ "$o" = "denied" ] && pass "root denies the second" || flunk "deny: $o"
o="$(apv 0 0 "approve $ID2")"
grep -q "no open proposal" <<<"$o" && pass "an answer for a proposal that has ended is refused" || flunk "answer after the end: $o"
wait "$WPID"
[ "$(grep -c ' ok$' "$W/r1.out")" = 1 ] && pass "exactly one read was allowed (count 1)" || flunk "reads allowed: $(grep -c ' ok$' "$W/r1.out")"
check() { if "${@:2}"; then pass "$1"; else flunk "$1"; fi; }
check "the allowed read: cert_grant, both halves checked (check ok)" recs "$W/r1.log" \
  "[r for r in rs if r.get('cert_grant') == '$GID1' and r['decision_final'] == 'ALLOW' and r['check'] == 'ok' and r['cert_grant_rule'] == 0]"
check "the grant record: its text, approver root, the reason" recs "$W/r1.log" \
  "[r for r in rs if r.get('event') == 'grant' and r['id'] == '$GID1' and r['approver_uid'] == 0 and r['reason'] == 'test_v1420' and r['proposal'] == '$ID1']"
check "the endings: approved, denied, and abandoned for what was open at the end" recs "$W/r1.log" \
  "[r['ending'] for r in rs if r.get('event') == 'step_up_end' and r['ending'] != 'abandoned'] == ['approved', 'denied'] and all(r['ending'] in ('approved', 'denied', 'abandoned') for r in rs if r.get('event') == 'step_up_end')"
check "every refusal by the step_up rule names a proposal" recs "$W/r1.log" \
  "all(r.get('step_up') for r in rs if r.get('policy_line') == 9 and r.get('decision_final') == 'DENY')"
o="$(python3 "$HERE/tools/varek_audit.py" --policy "$W/p1.txt" --checker "$CERT" "$W/r1.log" 2>&1)"
grep -q 'varek_audit: PASS' <<<"$o" && pass "the audit passes the run (the grant's certificate re-checked by the checker)" || flunk "audit: $(grep PROBLEM <<<"$o" | head -3)"
qforge() {   # qforge LABEL PYTHON WORDS: the audit fails the forged stream for its reason
    (cd "$HERE/tests" && python3 v1270_forge.py "$W/r1.log" "$W/f.log" "$2") > /dev/null 2>&1
    if python3 "$HERE/tools/varek_audit.py" --policy "$W/p1.txt" --checker "$CERT" "$W/f.log" > "$W/f.out" 2>&1; then
        flunk "forged: $1 (the audit passed it)"
    elif grep -qF -- "$3" "$W/f.out"; then pass "forged: $1"
    else flunk "forged: $1 (not for its own reason: $(grep '^  PROBLEM' "$W/f.out" | head -2 | tr '\n' ' '))"; fi
}
G="[r for r in recs if isinstance(r, dict) and r.get('event') == 'grant'][0]"
qforge "the grant's count edited" "$G['text'] = $G['text'].replace('count 1', 'count 9')" "its id is not the SHA-256 of its text"
qforge "the grant record dropped" "recs.remove($G)" "which no grant record before it holds"
qforge "a proposal's ending dropped" "recs.remove([r for r in recs if isinstance(r, dict) and r.get('event') == 'step_up_end' and r['ending'] == 'denied'][0])" "never ended"
qforge "a proposal's record dropped" "recs.remove([r for r in recs if isinstance(r, dict) and r.get('event') == 'step_up'][0])" "which no step_up record holds"
qforge "the allowed read's object changed" "[r.__setitem__('resolved', '$W/data/other.csv') for r in recs if isinstance(r, dict) and r.get('cert_grant')]" "refused"
# a later refusal of the same read rewritten as an allow under the grant, its certificate copied
FT="A = [r for r in recs if isinstance(r, dict) and r.get('cert_grant')][0]
B = [r for r in recs if isinstance(r, dict) and r.get('step_up') and r.get('seq', 0) > A['seq']][0]
B.pop('step_up')
for k in ('decision_raw', 'decision_final', 'kernel_verdict', 'rule', 'errno', 'cert_rule', 'cert_witness', 'cert_grant', 'cert_grant_rule', 'cert_grant_witness', 'check'):
    B[k] = A[k]"
qforge "the grant used twice" "$FT" "past its count"
qforge "a grant approving no open proposal" "$G['proposal'] = 'ffffffffffffffff'" "which is not an open proposal"

groupadd -f vk1420 2>/dev/null; GG="$(getent group vk1420 | cut -d: -f3)"
AU=4243; AG="$GG"                    # pending, as a member of the rule's approvers
printf "${BASE}step_up path $W/data/ approvers=vk1420 timeout=3\n" > "$W/p2.txt"
start "$W/p2.txt" "$W/r2" 40
ID3="$(wait_prop)"
o="$(apv 4243 4243 "approve $ID3")"
grep -q "not an approver in this run" <<<"$o" && pass "approvers=vk1420: a user outside the group may not approve" || flunk "outside the group: $o"
o="$(apv 0 0 "approve $ID3")"
grep -q "not an approver in this run" <<<"$o" && pass "... nor root alone, outside it" || flunk "root outside the group: $o"
o="$(apv 4243 "$GG" "approve $ID3")"
grep -q '^approved ' <<<"$o" && pass "... a user whose group it is may" || flunk "in the group: $o"
ID4="$(wait_prop "$ID3")"
sleep 4
o="$(apv 4243 "$GG" "approve $ID4")"
grep -q "no open proposal\|has ended" <<<"$o" && pass "a proposal not answered within the rule's timeout ends; an answer after is refused" || flunk "after the timeout: $o"
wait "$WPID"
check "... recorded as timeout" recs "$W/r2.log" "[r for r in rs if r.get('event') == 'step_up_end' and r['id'] == '$ID4' and r['ending'] == 'timeout']"
o="$(python3 "$HERE/tools/varek_audit.py" --policy "$W/p2.txt" --checker "$CERT" "$W/r2.log" 2>&1)"
grep -q 'varek_audit: PASS' <<<"$o" && pass "the audit passes the second run" || flunk "audit 2: $(grep PROBLEM <<<"$o" | head -3)"

echo "== 6. step 3: mode=hold, a call held at the kernel (as root) =="
AU=0; AG=0
cat > "$W/bin/one.sh" <<'AG'
# one try at each file named; say what each got
for f in "$@"; do if read -r l < "$f"; then echo "$f: ok $l"; else echo "$f: no"; fi; done
AG
cat > "$W/bin/two.sh" <<'AG'
# the first file read in the background (held), the second read meanwhile
( if read -r l < "$1"; then echo "first: ok"; else echo "first: no"; fi ) &
sleep 0.5
if read -r l < "$2"; then echo "second: ok"; else echo "second: no"; fi
wait
AG
chmod 755 "$W/bin/one.sh" "$W/bin/two.sh"
echo "b" > "$W/data/b.csv"; chmod 644 "$W/data/b.csv"; echo "free" > "$W/bin/free.txt"; chmod 644 "$W/bin/free.txt"
hstart() {   # hstart POLICY OUT SCRIPT ARGS...: as start, with the script and its files
    local pol="$1" out="$2" scr="$3"; shift 3
    "$WARDEN" "$pol" -- /bin/bash "$W/bin/$scr" "$@" > "$out.out" 2> "$out.log" &
    WPID=$!
    SOCK=""; local k
    for k in $(seq 1 40); do
        SOCK="$(grep -o '/run/varek-approve/[0-9a-f]*\.sock' "$out.log" 2>/dev/null | head -1)"
        [ -n "$SOCK" ] && [ -S "$SOCK" ] && break
        sleep 0.25
    done
    RUN="$(basename "$SOCK" .sock)"
}
audit_ok() { python3 "$HERE/tools/varek_audit.py" --policy "$1" --checker "$CERT" "$2" > "$2.audit" 2>&1; }
printf "${BASE}step_up path $W/data/ mode=hold timeout=20\nmax_held 1\n" > "$W/h1.txt"
HB="$(printf '%b' "$BASE" | wc -l)"

hstart "$W/h1.txt" "$W/h1" one.sh "$W/data/r.csv"
H1="$(wait_prop)"
sleep 1
[ -n "$H1" ] && [ ! -s "$W/h1.out" ] && pass "a read the hold rule decides waits in the kernel, a grant proposed ($H1)" || flunk "no hold: $(cat "$W/h1.out")"
check "... its step_up record says held, with the call (no decision record yet)" recs "$W/h1.log" \
  "[r for r in rs if r.get('event') == 'step_up' and r['id'] == '$H1' and r['mode'] == 'hold' and r['state'] == 'held' and r['resolved'] == '$W/data/r.csv'] and not [r for r in rs if r.get('resolved') == '$W/data/r.csv' and 'decision_final' in r]"
o="$(apv 0 0 "approve $H1")"
wait "$WPID"
grep -q "r.csv: ok a,b" "$W/h1.out" && pass "approved, the same read goes on: allowed, its one try" || flunk "after approval: $o / $(cat "$W/h1.out")"
check "... decided again within the grant: ALLOW, cert_grant, checked" recs "$W/h1.log" \
  "[r for r in rs if r.get('resolved') == '$W/data/r.csv' and r.get('decision_final') == 'ALLOW' and r.get('cert_grant') and r.get('check') == 'ok']"
audit_ok "$W/h1.txt" "$W/h1.log" && pass "the audit passes a held, approved call" || flunk "audit h1: $(grep PROBLEM "$W/h1.log.audit" | head -2)"

hstart "$W/h1.txt" "$W/h2" one.sh "$W/data/r.csv"
H2="$(wait_prop)"
o="$(apv 0 0 "deny $H2\nreason no")"
wait "$WPID"
grep -q "r.csv: no" "$W/h2.out" && [ "$o" = denied ] && pass "denied, the held read is refused (EACCES)" || flunk "deny a hold: $o / $(cat "$W/h2.out")"
check "... its refusal recorded then, naming the proposal (held), before step_up_end denied" recs "$W/h2.log" \
  "(lambda d, e: d < e)(*[next(i for i, r in enumerate(rs) if c(r)) for c in (lambda r: r.get('step_up') == '$H2' and r.get('held') is True and r['decision_final'] == 'DENY', lambda r: r.get('event') == 'step_up_end' and r['id'] == '$H2' and r['ending'] == 'denied')])"
audit_ok "$W/h1.txt" "$W/h2.log" && pass "the audit passes a held, denied call" || flunk "audit h2: $(grep PROBLEM "$W/h2.log.audit" | head -2)"
cp "$W/h2.log" "$W/r1.log"; cp "$W/h1.txt" "$W/p1.txt"
# the records after it renumbered too (the agent may make calls after the refused read), so the
# stream's seq and count still hold and only the missing refusal is left to find
qforge "a held call's refusal dropped (run_end's count lowered, later records renumbered)" "X = [r for r in recs if isinstance(r, dict) and r.get('held') is True][0]; recs.remove(X)
for r in recs:
    if isinstance(r, dict) and r.get('seq', -1) > X['seq']: r['seq'] -= 1
[r for r in recs if isinstance(r, dict) and r.get('event') == 'run_end'][0]['records'] -= 1" "with no record of its refusal before"

printf "${BASE}step_up path $W/data/ mode=hold timeout=2\n" > "$W/h3.txt"
hstart "$W/h3.txt" "$W/h3" one.sh "$W/data/r.csv"
wait "$WPID"
grep -q "r.csv: no" "$W/h3.out" && pass "unanswered, the held read is refused at the rule's timeout" || flunk "timeout: $(cat "$W/h3.out")"
check "... recorded as timeout" recs "$W/h3.log" "[r for r in rs if r.get('event') == 'step_up_end' and r['ending'] == 'timeout']"
audit_ok "$W/h3.txt" "$W/h3.log" && pass "the audit passes a held call that timed out" || flunk "audit h3: $(grep PROBLEM "$W/h3.log.audit" | head -2)"

hstart "$W/h1.txt" "$W/h4" two.sh "$W/data/r.csv" "$W/data/b.csv"
H4="$(wait_prop)"
sleep 1.5
grep -q "second: no" "$W/h4.out" && pass "max_held 1: a second call to hold is refused at once" || flunk "max_held: $(cat "$W/h4.out")"
check "... its record saying max_held" recs "$W/h4.log" "[r for r in rs if r.get('step_up') == 'none' and r.get('step_up_why') == 'max_held' and r['resolved'] == '$W/data/b.csv']"
apv 0 0 "approve $H4" > /dev/null; wait "$WPID"
grep -q "first: ok" "$W/h4.out" && pass "... and the held one, approved, goes on" || flunk "first after approval: $(cat "$W/h4.out")"

printf "${BASE}step_up path $W/data/r.csv mode=hold timeout=20\n" > "$W/h5.txt"
hstart "$W/h5.txt" "$W/h5" two.sh "$W/data/r.csv" "$W/bin/free.txt"
H5="$(wait_prop)"
sleep 1.5
grep -q "second: ok" "$W/h5.out" && ! grep -q "first:" "$W/h5.out" && pass "while one call is held, another process's allowed read goes on" || flunk "other calls: $(cat "$W/h5.out")"
apv 0 0 "approve $H5" > /dev/null; wait "$WPID"

ln -sf "$W/data/r.csv" "$W/data/link"
hstart "$W/h1.txt" "$W/h6" one.sh "$W/data/link"
H6="$(wait_prop)"
o="$(apv 0 0 pending)"
grep -q "allow path exact $W/data/r.csv" <<<"$o" && pass "a read through a symlink: the proposal names the file it resolves to" || flunk "symlink proposal: $o"
ln -sf "$W/data/b.csv" "$W/data/link"
apv 0 0 "approve $H6" > /dev/null; wait "$WPID"
grep -q "link: no" "$W/h6.out" && pass "the link swapped before approval: decided again, the grant's file is not the one reached: refused" || flunk "swapped link: $(cat "$W/h6.out")"
check "... recorded as decided again, not within the grant" recs "$W/h6.log" "[r for r in rs if r.get('step_up_why', '').startswith('held and approved, then decided again') and r['resolved'] == '$W/data/b.csv']"
audit_ok "$W/h1.txt" "$W/h6.log" && pass "the audit passes it" || flunk "audit h6: $(grep PROBLEM "$W/h6.log.audit" | head -2)"

printf "${BASE}step_up exec /usr/bin/id mode=hold timeout=20\n" > "$W/h7.txt"
cat > "$W/bin/launch.sh" <<'AG'
/usr/bin/id -u && echo launched || echo "not launched"
AG
chmod 755 "$W/bin/launch.sh"
hstart "$W/h7.txt" "$W/h7" launch.sh
check "a step_up exec rule's program is in the launch set (Landlock lets it run once allowed)" recs "$W/h7.log" "[e for r in rs if r.get('event') == 'run_start' for e in r['exec_ruleset'] if e['path'] == '/usr/bin/id' and e['why'] == 'rule']"
H7="$(wait_prop)"
apv 0 0 "approve $H7" > /dev/null; wait "$WPID"
grep -q "^launched" "$W/h7.out" && pass "a held launch, approved, runs" || flunk "held launch: $(cat "$W/h7.out")"

printf "${BASE}step_up path $W/data/ access=rw mode=hold\n" > "$W/h8.txt"
check "a step_up rule that may write: its directory is mounted noexec, as an allow rule's" sh -c "'$WARDEN' '$W/h8.txt' -- /bin/true 2>&1 | grep -q 'noexec: 1 writable director'"
printf "require warden 1.42\nproxy inspect\nallow host api.example.test:443\nstep_up request POST https://api.example.test/x mode=hold\n" > "$W/h9.txt"
o="$("$WARDEN" "$W/h9.txt" --check-startup 2>&1)"
! grep -q "not built yet" <<<"$o" && pass "mode=hold on a request rule is accepted at start (held at the proxy, step 3b)" || flunk "hold on a request rule: $o"


echo "== 7. step 3b: held at the egress proxy (requests and MCP calls, as root) =="
HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
HP=$((25000 + RANDOM % 4000)); DP=$((20000 + RANDOM % 2000))
touch "$W/echo.log"; chmod 666 "$W/echo.log"
python3 "$HERE/tests/v1261_echo_server.py" "$HOSTIP" "$HP" "$W/echo.log" > /dev/null 2>&1 &
SRVS="$!"
printf '{"api.example.com": {"ttl": 30, "a": ["%s"]}}\n' "$HOSTIP" > "$W/zone.json"
python3 "$HERE/tests/dns_test_server.py" --port "$DP" --zone "$W/zone.json" --log "$W/q.log" --ready "$W/dns.ready" > /dev/null 2>&1 &
SRVS="$SRVS $!"
trap 'kill $SRVS 2>/dev/null; rm -rf "$T"' EXIT
for _ in $(seq 50); do [ -e "$W/dns.ready" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $HP), 0.2)" 2>/dev/null && break; sleep 0.1; done
mkdir -p "$W/a"; chmod 755 "$W/a"
cat > "$W/a/px.py" <<'PY'
import json, socket, sys
P = int(sys.argv[1])
def one(tag, raw):
    s = socket.create_connection(("api.example.com", P), 60)
    s.settimeout(60)
    s.sendall(raw)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            d = s.recv(65536)
            if not d: break
            buf += d
    except OSError:
        pass
    print(tag, (buf.split(b"\r\n")[0].decode(errors="replace").split(" ") + ["", "-"])[1], flush=True)
    s.close()
H = "Host: api.example.com:%d\r\n" % P
one("PLAIN", ("GET /plain HTTP/1.1\r\n" + H + "\r\n").encode())
one("PLAIN2", ("GET /plain2 HTTP/1.1\r\n" + H + "\r\n").encode())
b = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "refund", "arguments": {}}}).encode()
one("MCP", ("POST /mcp HTTP/1.1\r\n" + H + "Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n"
            "Content-Length: %d\r\n\r\n" % len(b)).encode() + b)
PY
chmod 644 "$W/a/px.py"
printf "require warden 1.42\nproxy inspect\nproxy ports $HP\nallow host api.example.com\nstep_up request GET http://api.example.com:$HP/plain* mode=hold timeout=20\nstep_up mcp http://api.example.com:$HP/mcp tools/call * mode=hold timeout=20\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ readonly\nallow path $W/a/\n" > "$W/x.txt"
# the host's CA bundle (the requests are plain HTTP; the Warden only needs one to start): Debian and
# Ubuntu name it ca-certificates.crt, RHEL, Rocky and Amazon Linux ca-bundle.crt
TB=""; for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-bundle.crt; do [ -f "$f" ] && TB="$f" && break; done
env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$W/x.txt" --dns-server "127.0.0.1:$DP" --trust-bundle "$TB" \
    -- /usr/bin/python3 "$W/a/px.py" "$HP" > "$W/x.out" 2> "$W/x.log" &
WPID=$!
SOCK=""; for _ in $(seq 40); do SOCK="$(grep -o '/run/varek-approve/[0-9a-f]*\.sock' "$W/x.log" 2>/dev/null | head -1)"; [ -n "$SOCK" ] && [ -S "$SOCK" ] && break; sleep 0.25; done
AU=0; AG=0
X1="$(wait_prop)"; o="$(apv 0 0 pending)"
grep -q "allow request GET http://api.example.com:$HP/plain\\\\n" <<<"$o" && pass "a request a mode=hold rule decides is held at the proxy, its proposal the request itself" || flunk "request proposal: $o"
apv 0 0 "approve $X1" > /dev/null
X2="$(wait_prop "$X1")"
apv 0 0 "deny $X2" > /dev/null
X3="$(wait_prop "$X2")"; o="$(apv 0 0 pending)"
grep -q "allow mcp http://api.example.com:$HP/mcp tools/call refund" <<<"$o" && pass "an MCP call is held too, its proposal the call (its server, method and tool)" || flunk "mcp proposal: $o"
apv 0 0 "approve $X3" > /dev/null
wait "$WPID"
grep -qx "PLAIN 200" "$W/x.out" && pass "approved, the held request is sent on and answered" || flunk "approved request: $(cat "$W/x.out")"
grep -qx "PLAIN2 403" "$W/x.out" && ! grep -q "GOT GET /plain2" "$W/echo.log" && pass "denied, it is refused (403) and never reaches the server" || flunk "denied request: $(cat "$W/x.out")"
grep -qx "MCP 200" "$W/x.out" && grep -q "GOT POST /mcp" "$W/echo.log" && pass "approved, the held MCP call is sent on" || flunk "approved mcp call: $(cat "$W/x.out")"
check "the records: three held, two allowed under their grants, one refused naming its proposal" recs "$W/x.log" \
  "len([r for r in rs if r.get('event') == 'step_up' and r.get('state') == 'held']) == 3 and len([r for r in rs if r.get('cert_grant') and r.get('decision_final') == 'ALLOW' and r.get('action') in ('net.request', 'net.mcp')]) == 2 and [r for r in rs if r.get('held') is True and r.get('action') == 'net.request' and r['decision_final'] == 'DENY']"
audit_ok "$W/x.txt" "$W/x.log" && pass "the audit passes the run" || flunk "audit x: $(grep PROBLEM "$W/x.log.audit" | head -2)"

fi

echo
[ $fail = 0 ] && echo "test_v1420: PASS ($n checks)" || echo "test_v1420: FAIL"
exit $fail
