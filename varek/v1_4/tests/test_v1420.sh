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
# Usage: ./test_v1420.sh   (from varek/v1_4, after `make warden tools/vdp_check tools/vdp_cert_check`)
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

echo
[ $fail = 0 ] && echo "test_v1420: PASS ($n checks)" || echo "test_v1420: FAIL"
exit $fail
