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
#   5. A policy needing a step not built yet (notify=) is refused at start.
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
# Step 4, scope=run (section 8, as root):
#   8. Where the run can be frozen (cgroup v2, and Linux 5.19 or later for a
#      held call to wait through the freeze): a read a scope=run rule holds
#      freezes the run, so another process's counter stops; approved, the
#      read goes on, then the run is thawed and the counter goes on; past
#      the timeout, refused, then thawed; the records in order (step_up
#      scope run, run_frozen, the ending, the call decided again,
#      run_thawed) and the audit, which refuses a thaw moved before the
#      ending or before the call decided again, and a freeze or thaw
#      dropped; the run stopped while frozen thaws after its endings. Where
#      it cannot (forced with VAREK_WARDEN_TEST_NO_FREEZE, and on such a
#      host), run_start says why and the read is refused at once with a
#      proposal, its record saying why it was not held (unheld), the counter
#      going on; the audit passes. A startup check says which.
#
# Step 5, DEFER (sections 1, 4 and 9):
#   1, 4. defer rules and the `on unknown` line read the same by both
#      parsers, each malformed form refused; a defer rule's call refused
#      alone, allowed within a grant under it with escalate; a ground call no
#      rule holds within a grant under the `on unknown` line; the checker
#      accepts a defer rule's certificate, and each such grant's, and refuses
#      the forged.
#   9. A read a defer rule decides is deferred; a root-owned marker naming
#      the run releases it, allowed under the marker; a marker present
#      before the call allows it at once; a marker that is the agent's,
#      group-writable, names another run or is a link is not accepted
#      (refused at the timeout); escalate turns the timeout into a proposal,
#      approved; on unknown defer escalate proposes at once for a read no
#      rule names, approved under the `on unknown` line; a policy whose
#      marker the agent could write is refused at start; with the default
#      scope the run is frozen while deferred (where it can be); the
#      records, the audit, and its refusal of each forgery (an ending
#      dropped, the marker not named or not the one that resolved it, the
#      allow before its ending, a timed-out refusal dropped, an
#      escalation's proposal dropped).
#
# Step 5b, on outside_plan defer (section 10, as root):
#  10. Under --hold-to-plan with `on outside_plan defer`, a read the policy
#      allows but the plan does not cover is held; pending lists it with a
#      one-step extension; the agent's own user and another user may not
#      extend; root sends the suggestion back as it is and the plan gate
#      authorizes it: the read is decided again and allowed, the records in
#      order and the audit passing, which refuses a resolved ending naming an
#      extension never recorded or one the gate did not authorize. An
#      extension with a step the policy refuses adds nothing, and the call is
#      refused at its timeout. Without --hold-to-plan the line is inert.
#
# Step 6, signed approvals (sections 1 and 11):
#   1. approver lines (key=HEX group=GROUP [name=NAME], the key pinned by
#      value) read the same by both parsers and the Warden, each malformed
#      form refused (a short, upper-case or non-point key, a key given as a
#      file, no group, a key twice, seventeen lines); the checker lists the
#      keys and each rule's approvers= group for the audit.
#  11. varek_keygen makes two approvers' keys, one per group, and signs and
#      verifies (another key or kind refused). A standing grant (--grants)
#      signed by an approver of its rule's group allows from the start,
#      within its count, recorded with its signer; the start is refused for
#      a grant unsigned, signed by the other group's or an unpinned key,
#      changed after signing, naming a run, expired, or under a rule with no
#      approvers=, and for a --grants directory it cannot read. varek plan
#      approve signs a plan: --require-approved-plan runs it (run_start's
#      plan_approved_by) and refuses one unapproved, changed or signed by an
#      unpinned key; without the flag a failing approval is a note. At the
#      socket, an approval signed by the other group's key, or over other
#      text, is refused; varek approve --sign-key is recorded with signed_by.
#      The audit passes each run and refuses each forgery: a signature
#      altered or dropped, a signer swapped for an unpinned key or named of
#      another group, a plan approval's signature, key or name changed.
#
# Usage: sudo ./test_v1420.sh   (from varek/v1_4, after `make warden tools/vdp_check tools/vdp_cert_check tools/varek_keygen`;
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
# v1.42 step 5: defer rules and the `on unknown` line
accepted "a defer rule of each kind, and every option" 'require warden 1.42\nproxy inspect\ndefer path /srv/prod/ until=/etc/varek/ok\ndefer host api.example.com:443 until=/etc/varek/net escalate scope=thread timeout=60 approvers=ops\ndefer exec /usr/bin/deploy until=/etc/varek/dep\ndefer request POST https://api.example.com/pay until=/etc/varek/pay\n'
accepted "on unknown deny" 'require warden 1.42\non unknown deny\nallow path /tmp/\n'
accepted "on unknown defer escalate, with its options" 'require warden 1.42\non unknown defer escalate timeout=30 scope=thread approvers=ops\nallow path /tmp/\n'
refused "defer before 1.42"                 'require warden 1.35\ndefer path /s/ until=/m\n'            "needs \`require warden 1.42\`"
refused "a defer rule without until="       'require warden 1.42\ndefer path /s/ escalate\n'            "needs until=FILE"
refused "until= a relative path"            'require warden 1.42\ndefer path /s/ until=m\n'             "until= is an absolute path"
refused "until= with a .. part"             'require warden 1.42\ndefer path /s/ until=/a/../m\n'       "until= is an absolute path"
refused "until= ending in /"                'require warden 1.42\ndefer path /s/ until=/a/\n'           "until= is an absolute path"
refused "a step_up option on a defer rule"  'require warden 1.42\ndefer path /s/ until=/m mode=hold\n'  "are a step_up rule's"
refused "a defer option on a step_up rule"  'require warden 1.42\nstep_up path /s/ until=/m\n'         "are a defer rule's"
refused "escalate twice"                    'require warden 1.42\ndefer path /s/ until=/m escalate escalate\n' "given twice"
refused "on unknown defer without escalate" 'require warden 1.42\non unknown defer timeout=30\n'         "needs escalate"
refused "on unknown allow"                  'require warden 1.42\non unknown allow\n'
refused "on unknown twice"                  'require warden 1.42\non unknown deny\non unknown deny\n'  "given twice"
refused "on unknown before 1.42"            'require warden 1.35\non unknown deny\n'                     "needs \`require warden 1.42\`"
refused "until= on the on unknown line"     'require warden 1.42\non unknown defer escalate until=/m\n'
# v1.42 step 5b: the on outside_plan line (escalate refused: a plan extension resolves it)
accepted "on outside_plan deny" 'require warden 1.42\non outside_plan deny\nallow path /tmp/\n'
accepted "on outside_plan defer, with its options" 'require warden 1.42\non outside_plan defer timeout=30 scope=thread approvers=ops\nallow path /tmp/\n'
refused "escalate on the on outside_plan line"   'require warden 1.42\non outside_plan defer escalate\n'   "resolved by a plan extension"
refused "escalate=1 on the on outside_plan line" 'require warden 1.42\non outside_plan defer escalate=1\n'
refused "until= on the on outside_plan line"     'require warden 1.42\non outside_plan defer until=/m\n'
refused "on outside_plan allow"                  'require warden 1.42\non outside_plan allow\n'
refused "on outside_plan twice"                  'require warden 1.42\non outside_plan deny\non outside_plan defer\n'  "given twice"
refused "on outside_plan before 1.42"            'require warden 1.35\non outside_plan deny\n'
# v1.42 step 6: approver lines, each key pinned by value (as varek_keygen writes KEY.pub)
KA="04$(printf 'a1%.0s' $(seq 1 96))"; KB="04$(printf 'b2%.0s' $(seq 1 96))"
accepted "approver lines: key= and group=, name= optional, in any order" "require warden 1.42\napprover key=$KA group=ops name=alice.1\napprover group=sec key=$KB\nstep_up path /s/ approvers=ops\n"
refused "approver before 1.42"              "require warden 1.35\napprover key=$KA group=ops\n"             "needs \`require warden 1.42\`"
refused "an approver key too short"         "require warden 1.42\napprover key=04a1 group=ops\n"            "194 lowercase"
refused "an approver key in upper case"     "require warden 1.42\napprover key=$(tr a-f A-F <<<"$KA") group=ops\n" "194 lowercase"
refused "an approver key not a point (03...)" "require warden 1.42\napprover key=03${KA#04} group=ops\n"     "194 lowercase"
refused "an approver key given as a file"   "require warden 1.42\napprover /etc/varek/ops.pub group=ops\n"
refused "an approver without group="        "require warden 1.42\napprover key=$KA\n"                       "need: approver key=HEX group=GROUP"
refused "an approver group=Ops"             "require warden 1.42\napprover key=$KA group=Ops\n"             "group= is a Unix group name"
refused "an approver name with a space"     "require warden 1.42\napprover key=$KA group=ops name=a/b\n"    "name= is 1 to 32"
refused "key= twice on one line"            "require warden 1.42\napprover key=$KA key=$KB group=ops\n"     "each once"
refused "the same approver key twice"       "require warden 1.42\napprover key=$KA group=ops\napprover key=$KA group=sec\n" "the same approver key given twice"
MANY="require warden 1.42\n"; for i in $(seq 10 26); do MANY="${MANY}approver key=04$(printf "$i%.0s" $(seq 1 96)) group=ops\n"; done
refused "seventeen approver lines"          "$MANY"                                                          "more than 16 approver lines"
printf "require warden 1.42\napprover key=$KA group=ops name=alice\napprover key=$KB group=sec\nallow path /tmp/\nstep_up path /srv/data/ approvers=ops\n" > "$T/w6.txt"
o="$("$WARDEN" "$T/w6.txt" --check-startup 2>&1)"
grep -q "startup checks passed" <<<"$o" && ! grep -q "approver lines differently" <<<"$o" \
  && pass "the Warden loads approver lines, its two parsers agreeing on each key, group and name" || flunk "the Warden on approver lines: $o"
o="$("$CERT" "$T/w6.txt" approvers)"
[ "$o" = "$(printf 'approver %s ops alice 2\napprover %s sec - 3\nrule 5 ops' "$KA" "$KB")" ] \
  && pass "the checker lists them for the audit (approvers): the keys, and each rule's approvers= group" || flunk "checker approvers: $o"
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

# v1.42 step 5: a defer rule (its marker), a grant under one with escalate, and under the `on unknown` line
printf 'require warden 1.42\nallow path /tmp/\ndefer path /srv/prod/ until=/etc/varek/ok\ndefer path /srv/esc/ until=/etc/varek/ok escalate\non unknown defer escalate\n' > "$T/p5.txt"
printf 'grant\nstep_up line 4\nallow path exact /srv/esc/a readonly\ncount 1\n' > "$T/g5a.txt"
printf 'grant\nstep_up line 5\nallow path exact /opt/x readonly\ncount 1\n' > "$T/g5b.txt"
printf 'grant\nstep_up line 3\nallow path exact /srv/prod/a readonly\ncount 1\n' > "$T/g5c.txt"
o="$("$VDP" "$T/p5.txt" grant "$T/g5a.txt")"; grep -q '"ok":true,"step_up_line":4' <<<"$o" && pass "grant: under a defer rule with escalate" || flunk "grant under defer: $o"
o="$("$VDP" "$T/p5.txt" grant "$T/g5b.txt")"; grep -q '"ok":true,"step_up_line":5' <<<"$o" && pass "grant: under the on unknown line" || flunk "grant under on unknown: $o"
o="$("$VDP" "$T/p5.txt" grant "$T/g5c.txt" 2>&1)"; c="$("$CERT" "$T/p5.txt" batch "$T/g5c.txt" < /dev/null 2>&1)"
grep -q "is not a step_up rule" <<<"$o" && grep -q -i "no step_up" <<<"$c" && pass "grant refused: under a defer rule without escalate (both parsers)" || flunk "grant under plain defer: $o / $c"
dq() { printf '%s %s %s\n' "$1" "$2" "$(hx "$3")" | "$VDP" "$T/p5.txt" batch "$T/g5a.txt" "$T/g5b.txt"; }
o="$(dq path 0 /srv/prod/a)"
grep -q '"verdict":"UNSATISFIED","rule":1,"line":3.*"verb":"defer"' <<<"$o" && ! grep -q '"grant"' <<<"$o" && pass "a defer rule's call alone: UNSATISFIED, the defer rule deciding (the Warden checks its marker)" || flunk "defer decision: $o"
o="$(dq path 0 /srv/esc/a)"
grep -q '"verdict":"SATISFIED","rule":2,"line":4.*"verb":"defer".*"grant":0' <<<"$o" && pass "a call under a defer rule with escalate, within its grant" || flunk "defer grant: $o"
o="$(dq path 0 /opt/x)"
grep -q '"verdict":"SATISFIED","rule":-1,.*"why":"no_rule".*"grant":1' <<<"$o" && pass "a call no rule holds, within a grant under the on unknown line" || flunk "unknown grant: $o"
o="$(dq path - /opt/x)"
grep -q '"verdict":"UNKNOWN"' <<<"$o" && ! grep -q '"grant"' <<<"$o" && pass "... but not with symbolic flags (a grant under on unknown is for a ground call)" || flunk "unknown grant, symbolic: $o"
o="$(dq path 0 /tmp/x)"
grep -q '"verdict":"SATISFIED","rule":0' <<<"$o" && ! grep -q '"grant"' <<<"$o" && pass "... nor a call a rule decides" || flunk "unknown grant, ruled call: $o"
P5="$(hx /srv/prod/a)"; E5="$(hx /srv/esc/a)"; X5="$(hx /opt/x)"
chk5() { printf '%s\n' "$2" | "$CERT" "$T/p5.txt" batch "$T/g5a.txt" "$T/g5b.txt"; }
ok5()  { o="$(chk5 "$1" "$2")"; grep -q '"check":"ok"' <<<"$o" && pass "checker accepts: $1" || flunk "checker accepts: $1: $o"; }
rej5() { o="$(chk5 "$1" "$2")"; grep -q '"check":"reject"' <<<"$o" && pass "checker refuses: $1 ($(sed 's/.*"why":"\(.*\)"}/\1/' <<<"$o"))" || flunk "checker refuses: $1: $o"; }
ok5  "a defer rule's certificate (its marker passed)"      "path 0 $P5 1 - defer"
ok5  "a grant under a defer rule with escalate"            "path 0 $E5 2 - grant=0:0:-"
ok5  "a grant under the on unknown line"                   "path 0 $X5 -1 - grant=1:0:-"
rej5 "an allow rule's certificate as a defer rule's"       "path 0 $(hx /tmp/a) 0 - defer"
rej5 "a defer rule's certificate as an allow"              "path 0 $P5 1 -"
rej5 "another file under the defer rule"                   "path 0 $(hx /srv/other) 1 - defer"
rej5 "a grant under on unknown for a call a rule holds"    "path 0 $(hx /tmp/x) -1 - grant=1:0:-"
rej5 "a grant under on unknown naming a rule"              "path 0 $X5 0 - grant=1:0:-"
rej5 "symbolic flags under the on unknown line"            "path - $X5 -1 - grant=1:0:-"

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

printf "${BASE}step_up path $W/data/ notify=https://hooks.example.test/x\n" > "$W/hold.txt"
o="$("$WARDEN" "$W/hold.txt" --check-startup 2>&1)"
grep -q "notify= is not built yet" <<<"$o" && pass "a policy with notify= is refused at start (built in step 7)" || flunk "notify= at start: $o"

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

echo "== 8. step 4: scope=run, the run frozen while a call is held (as root) =="
mkdir -p "$W/out"; chmod 777 "$W/out"
cat > "$W/bin/tick.sh" <<'AG'
# a counter in one process; then a read (held) in another; the counter's last value at the end
( i=0; while [ $i -lt 40 ]; do i=$((i+1)); echo $i > "$2/n"; sleep 0.1; done ) &
until [ -s "$2/n" ]; do sleep 0.1; done; sleep 0.3
( if read -r l < "$1"; then echo "held: ok $l"; else echo "held: no"; fi ) &
wait
read -r c < "$2/n"; echo "counted: $c"
AG
chmod 755 "$W/bin/tick.sh"
FB="${BASE}allow path $W/out/\n"
printf "${FB}step_up path $W/data/ mode=hold scope=run timeout=20\n" > "$W/s1.txt"
AU=0; AG=0
o="$("$WARDEN" "$W/s1.txt" --check-startup 2>&1)"
grep -q "calls held with scope=run" <<<"$o" && pass "a startup check says whether the run can be frozen" || flunk "check: $o"
cnt() { cat "$W/out/n" 2>/dev/null || echo 0; }
rm -f "$W/out/n"
hstart "$W/s1.txt" "$W/s1" tick.sh "$W/data/r.csv" "$W/out"
if grep -q "freeze the run's control group" "$W/s1.log"; then
    S1="$(wait_prop)"
    a="$(cnt)"; sleep 1.2; b="$(cnt)"
    [ -n "$S1" ] && [ "$a" -gt 0 ] && [ "$a" = "$b" ] && pass "a read a scope=run rule holds freezes the run: another process's counter stops ($a)" \
        || flunk "frozen: $S1 / $a -> $b / $(tail -3 "$W/s1.log")"
    apv 0 0 "approve $S1" > /dev/null; wait "$WPID"
    grep -q "held: ok a,b" "$W/s1.out" && grep -q "counted: 40" "$W/s1.out" && pass "approved, the read goes on, the run is thawed and the counter goes on" \
        || flunk "after approval: $(cat "$W/s1.out")"
    check "the records in order: step_up (scope run), run_frozen, step_up_end, the read decided again, run_thawed" recs "$W/s1.log" \
      "(lambda i: i[0] < i[1] < i[2] < i[3] < i[4])([next(k for k, r in enumerate(rs) if c(r)) for c in (lambda r: r.get('event') == 'step_up' and r.get('scope') == 'run', lambda r: r.get('event') == 'run_frozen' and r.get('step_up') == '$S1', lambda r: r.get('event') == 'step_up_end' and r.get('ending') == 'approved', lambda r: r.get('resolved') == '$W/data/r.csv' and r.get('decision_final') == 'ALLOW' and r.get('cert_grant'), lambda r: r.get('event') == 'run_thawed' and r.get('frozen_ms', 0) >= 1000)]) and [r for r in rs if r.get('event') == 'run_start' and r['scope_run']['freeze'] is True]"
    audit_ok "$W/s1.txt" "$W/s1.log" && pass "the audit passes a run frozen and thawed" || flunk "audit s1: $(grep PROBLEM "$W/s1.log.audit" | head -2)"
    cp "$W/s1.log" "$W/r1.log"; cp "$W/s1.txt" "$W/p1.txt"
    TH="X = [r for r in recs if isinstance(r, dict) and r.get('event') == 'run_thawed'][0]; recs.remove(X)"
    qforge "the thaw moved before the hold's ending" "$TH; recs.insert([i for i, r in enumerate(recs) if isinstance(r, dict) and r.get('event') == 'step_up_end'][0], X)" "held with scope=run, was still held"
    qforge "the thaw moved before the call is decided again" "$TH; recs.insert([i for i, r in enumerate(recs) if isinstance(r, dict) and r.get('event') == 'step_up_end'][0] + 1, X)" "was decided again"
    qforge "the freeze's record dropped" "recs.remove([r for r in recs if isinstance(r, dict) and r.get('event') == 'run_frozen'][0])" "no run_frozen follows it"
    qforge "the thaw's record dropped" "$TH" "the run ended frozen"

    printf "${FB}step_up path $W/data/ mode=hold scope=run timeout=2\n" > "$W/s2.txt"
    rm -f "$W/out/n"
    hstart "$W/s2.txt" "$W/s2" tick.sh "$W/data/r.csv" "$W/out"
    wait "$WPID"
    grep -q "held: no" "$W/s2.out" && grep -q "counted: 40" "$W/s2.out" && pass "unanswered, the read is refused at the rule's timeout and the run thawed" \
        || flunk "timeout: $(cat "$W/s2.out")"
    check "... the refusal and the ending before the thaw" recs "$W/s2.log" \
      "(lambda i: i[0] < i[1] < i[2])([next(k for k, r in enumerate(rs) if c(r)) for c in (lambda r: r.get('held') is True and r.get('decision_final') == 'DENY', lambda r: r.get('event') == 'step_up_end' and r.get('ending') == 'timeout', lambda r: r.get('event') == 'run_thawed')])"
    audit_ok "$W/s2.txt" "$W/s2.log" && pass "the audit passes it" || flunk "audit s2: $(grep PROBLEM "$W/s2.log.audit" | head -2)"

    rm -f "$W/out/n"
    hstart "$W/s1.txt" "$W/s4" tick.sh "$W/data/r.csv" "$W/out"
    S4="$(wait_prop)"
    kill -TERM "$WPID"; wait "$WPID"
    check "the run stopped while frozen: the hold abandoned, then the thaw, then run_end" recs "$W/s4.log" \
      "(lambda i: i[0] < i[1] < i[2])([next(k for k, r in enumerate(rs) if c(r)) for c in (lambda r: r.get('event') == 'step_up_end' and r.get('id') == '$S4' and r.get('ending') == 'abandoned', lambda r: r.get('event') == 'run_thawed', lambda r: r.get('event') == 'run_end')])"
    audit_ok "$W/s1.txt" "$W/s4.log" && pass "the audit passes it" || flunk "audit s4: $(grep PROBLEM "$W/s4.log.audit" | head -2)"
else
    printf '  %-6s %s\n' SKIP "freezing the run: this host cannot ($(grep -o 'cannot freeze the run: [^;]*' "$W/s1.log" | head -1))"
    wait "$WPID"
fi

rm -f "$W/out/n"
VAREK_WARDEN_TEST_NO_FREEZE=1 hstart "$W/s1.txt" "$W/s3" tick.sh "$W/data/r.csv" "$W/out"
wait "$WPID"
grep -q "held: no" "$W/s3.out" && grep -q "counted: 40" "$W/s3.out" && pass "where the run cannot be frozen, the read is refused at once and the run goes on" \
    || flunk "no freeze: $(cat "$W/s3.out")"
check "... run_start says why; the refusal names a proposal and why it was not held; nothing frozen" recs "$W/s3.log" \
  "[r for r in rs if r.get('event') == 'run_start' and r['scope_run'] == {'freeze': False, 'why': 'VAREK_WARDEN_TEST_NO_FREEZE is set'}] and [r for r in rs if r.get('resolved') == '$W/data/r.csv' and r.get('decision_final') == 'DENY' and len(r.get('step_up', '')) == 16 and r.get('unheld') == 'scope=run: VAREK_WARDEN_TEST_NO_FREEZE is set'] and not [r for r in rs if r.get('event') in ('run_frozen', 'run_thawed') or r.get('state') == 'held']"
audit_ok "$W/s1.txt" "$W/s3.log" && pass "the audit passes it" || flunk "audit s3: $(grep PROBLEM "$W/s3.log.audit" | head -2)"

echo "== 9. step 5: DEFER, a marker, a timeout, escalate, on unknown (as root) =="
mkdir -p "$W/m"; chown 0:0 "$W/m"; chmod 755 "$W/m"; rm -f "$W/m/ok"
dstart() {   # dstart POLICY OUT SCRIPT ARGS...: the Warden in the background; RUN once run_start is written
    local pol="$1" out="$2" scr="$3"; shift 3
    "$WARDEN" "$pol" -- /bin/bash "$W/bin/$scr" "$@" > "$out.out" 2> "$out.log" &
    WPID=$!
    RUN=""; local k
    for k in $(seq 1 40); do
        RUN="$(grep -o '"event":"run_start","run":"[0-9a-f]*"' "$out.log" 2>/dev/null | head -1 | sed 's/.*"run":"//; s/"$//')"
        [ -n "$RUN" ] && break
        sleep 0.25
    done
    SOCK="$(grep -o '/run/varek-approve/[0-9a-f]*\.sock' "$out.log" 2>/dev/null | head -1)"
}
wait_ev() {  # wait_ev LOG EVENT: up to 10 s for a record of the event
    local k; for k in $(seq 1 40); do grep -q "\"event\":\"$2\"" "$1" 2>/dev/null && return 0; sleep 0.25; done; return 1
}
marker() { rm -f "$W/m/ok"; printf '%s\n' "$1" > "$W/m/ok"; chown "${2:-0:0}" "$W/m/ok"; chmod "${3:-644}" "$W/m/ok"; }
printf "${BASE}defer path $W/data/ until=$W/m/ok timeout=20 scope=thread\n" > "$W/d1.txt"
dstart "$W/d1.txt" "$W/d1" one.sh "$W/data/r.csv"
wait_ev "$W/d1.log" defer && sleep 0.5
[ ! -s "$W/d1.out" ] && grep -q '"event":"defer"' "$W/d1.log" && pass "a read a defer rule decides, with no marker, is deferred: held, a defer record" || flunk "no deferral: $(cat "$W/d1.out") / $(tail -3 "$W/d1.log")"
marker "$RUN"
wait "$WPID"
grep -q "r.csv: ok a,b" "$W/d1.out" && pass "a root-owned marker naming the run releases it: allowed" || flunk "after the marker: $(cat "$W/d1.out")"
check "... the records in order: defer, defer_end resolved (its SHA-256), the read allowed under the marker (cert_defer, checked)" recs "$W/d1.log" \
  "(lambda i: i[0] < i[1] < i[2])([next(k for k, r in enumerate(rs) if c(r)) for c in (lambda r: r.get('event') == 'defer' and r.get('state') == 'held' and r.get('scope') == 'thread', lambda r: r.get('event') == 'defer_end' and r.get('ending') == 'resolved' and len(r.get('marker_sha256', '')) == 64, lambda r: r.get('resolved') == '$W/data/r.csv' and r.get('decision_final') == 'ALLOW' and r.get('cert_defer') is True and r.get('check') == 'ok' and r.get('defer_marker', {}).get('path') == '$W/m/ok' and len(r.get('defer', '')) == 16)])"
audit_ok "$W/d1.txt" "$W/d1.log" && pass "the audit passes a deferral its marker resolved" || flunk "audit d1: $(grep PROBLEM "$W/d1.log.audit" | head -2)"
cp "$W/d1.log" "$W/r1.log"; cp "$W/d1.txt" "$W/p1.txt"
qforge "a deferral's ending dropped" "recs.remove([r for r in recs if isinstance(r, dict) and r.get('event') == 'defer_end'][0])" "which has not ended resolved"
qforge "an allow under a marker, its marker not named" "[r.pop('defer_marker') for r in recs if isinstance(r, dict) and r.get('cert_defer')]" "which it does not name"
qforge "the allow before its deferral's resolved ending" "X = [r for r in recs if isinstance(r, dict) and r.get('cert_defer')][0]; recs.remove(X); recs.insert([i for i, r in enumerate(recs) if isinstance(r, dict) and r.get('event') == 'defer_end'][0], X)" "which has not ended resolved"
qforge "a marker other than the one that resolved it" "[r['defer_marker'].__setitem__('sha256', '0' * 64) for r in recs if isinstance(r, dict) and r.get('cert_defer')]" "under a marker other than"

marker '*'
dstart "$W/d1.txt" "$W/d2" one.sh "$W/data/r.csv"
wait "$WPID"
grep -q "r.csv: ok a,b" "$W/d2.out" && pass "the marker present before the call: allowed at once" || flunk "marker first: $(cat "$W/d2.out")"
check "... under the marker, with no deferral" recs "$W/d2.log" \
  "[r for r in rs if r.get('resolved') == '$W/data/r.csv' and r.get('decision_final') == 'ALLOW' and r.get('cert_defer') is True and 'defer' not in r] and not [r for r in rs if r.get('event') == 'defer']"
audit_ok "$W/d1.txt" "$W/d2.log" && pass "the audit passes it" || flunk "audit d2: $(grep PROBLEM "$W/d2.log.audit" | head -2)"

printf "${BASE}defer path $W/data/ until=$W/m/ok timeout=2 scope=thread\n" > "$W/d3.txt"
for v in "the agent's:RUN:65534:65534:644" "group-writable:*:0:0:664" "naming another run:0123456789abcdef0123456789abcdef:0:0:644" "a link:link"; do
    nm="${v%%:*}"; rest="${v#*:}"
    rm -f "$W/m/ok" "$W/m/real"
    if [ "$rest" = link ]; then printf '*\n' > "$W/m/real"; chmod 644 "$W/m/real"; ln -s "$W/m/real" "$W/m/ok"; fi
    dstart "$W/d3.txt" "$W/d3" one.sh "$W/data/r.csv"
    if [ "$rest" != link ]; then
        IFS=: read -r mrun mu mg mm <<<"$rest"
        [ "$mrun" = RUN ] && mrun="$RUN"
        marker "$mrun" "$mu:$mg" "$mm"
    fi
    wait "$WPID"
    grep -q "r.csv: no" "$W/d3.out" && recs "$W/d3.log" "[r for r in rs if r.get('event') == 'defer_end' and r.get('ending') == 'timeout']" \
      && pass "a marker $nm is not accepted: the read stays deferred, refused at the timeout" || flunk "marker $nm: $(cat "$W/d3.out")"
done
rm -f "$W/m/ok" "$W/m/real"
check "... the refusal names the deferral (held), before its ending timeout" recs "$W/d3.log" \
  "(lambda d, e: d < e)(*[next(i for i, r in enumerate(rs) if c(r)) for c in (lambda r: r.get('held') is True and len(r.get('defer', '')) == 16 and r.get('decision_final') == 'DENY', lambda r: r.get('event') == 'defer_end' and r.get('ending') == 'timeout')])"
audit_ok "$W/d3.txt" "$W/d3.log" && pass "the audit passes a deferral timed out" || flunk "audit d3: $(grep PROBLEM "$W/d3.log.audit" | head -2)"
cp "$W/d3.log" "$W/r1.log"; cp "$W/d3.txt" "$W/p1.txt"
qforge "a timed-out deferral's refusal dropped" "X = [r for r in recs if isinstance(r, dict) and r.get('held') is True][0]; recs.remove(X)
for r in recs:
    if isinstance(r, dict) and r.get('seq', -1) > X['seq']: r['seq'] -= 1
[r for r in recs if isinstance(r, dict) and r.get('event') == 'run_end'][0]['records'] -= 1" "with no record of its call's refusal before"

DL="$(printf "${BASE}" | wc -l)"; DL=$((DL + 1))
printf "${BASE}defer path $W/data/ until=$W/m/ok timeout=2 scope=thread escalate\n" > "$W/d4.txt"
hstart "$W/d4.txt" "$W/d4" one.sh "$W/data/r.csv"
D4="$(wait_prop)"
o="$(apv 0 0 pending)"
grep -q "step_up line $DL\\\\nallow path exact $W/data/r.csv" <<<"$o" && pass "escalate: at its timeout the deferral becomes a proposal under the defer rule" || flunk "escalation: $D4 / $o"
apv 0 0 "approve $D4" > /dev/null; wait "$WPID"
grep -q "r.csv: ok a,b" "$W/d4.out" && pass "... approved, the read is allowed under the grant" || flunk "escalated approval: $(cat "$W/d4.out")"
check "... the records: defer, defer_end escalated naming the proposal, its step_up record, the read under the grant" recs "$W/d4.log" \
  "(lambda i: i[0] < i[1] < i[2] < i[3])([next(k for k, r in enumerate(rs) if c(r)) for c in (lambda r: r.get('event') == 'defer' and r.get('escalate') is True, lambda r: r.get('event') == 'defer_end' and r.get('ending') == 'escalated' and r.get('step_up') == '$D4', lambda r: r.get('event') == 'step_up' and r.get('id') == '$D4' and r.get('state') == 'held', lambda r: r.get('resolved') == '$W/data/r.csv' and r.get('decision_final') == 'ALLOW' and r.get('cert_grant'))])"
audit_ok "$W/d4.txt" "$W/d4.log" && pass "the audit passes an escalated deferral" || flunk "audit d4: $(grep PROBLEM "$W/d4.log.audit" | head -2)"
cp "$W/d4.log" "$W/r1.log"; cp "$W/d4.txt" "$W/p1.txt"
qforge "an escalation's proposal record dropped" "recs.remove([r for r in recs if isinstance(r, dict) and r.get('event') == 'step_up'][0])" "whose step_up record does not follow"

UL="$(printf "${BASE}" | wc -l)"; UL=$((UL + 1))
printf "${BASE}on unknown defer escalate timeout=20 scope=thread\n" > "$W/u1.txt"
hstart "$W/u1.txt" "$W/u1" one.sh "$W/data/r.csv"
# the read no rule holds: its proposal at once. bash's own such calls (a tty, its directories) are denied
U1=""; UT=""
for k in $(seq 1 40); do
    o="$(apv 0 0 pending)"
    while read -r ln; do
        case "$ln" in "{"*) ;; *) continue ;; esac
        id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "$ln")"
        if grep -q "allow path exact $W/data/r.csv" <<<"$ln"; then U1="$id"; UT="$ln"; else apv 0 0 "deny $id" > /dev/null; fi
    done <<<"$o"
    [ -n "$U1" ] && break
    sleep 0.25
done
grep -q "step_up line $UL\\\\n" <<<"$UT" && pass "on unknown defer escalate: a read no rule names is held, its proposal at once under the on unknown line" || flunk "on unknown: ${UT:-none} / $(tail -3 "$W/u1.log")"
apv 0 0 "approve $U1" > /dev/null; wait "$WPID"
grep -q "r.csv: ok a,b" "$W/u1.out" && pass "... approved, the read is allowed" || flunk "on unknown approval: $(cat "$W/u1.out")"
check "... a defer record (unknown), escalated at once, the read under the grant with no policy rule (cert_rule -1, checked)" recs "$W/u1.log" \
  "[r for r in rs if r.get('event') == 'defer' and r.get('unknown') is True and r.get('resolved') == '$W/data/r.csv'] and [r for r in rs if r.get('event') == 'defer_end' and r.get('ending') == 'escalated' and r.get('step_up') == '$U1'] and [r for r in rs if r.get('resolved') == '$W/data/r.csv' and r.get('decision_final') == 'ALLOW' and r.get('cert_rule') == -1 and r.get('cert_grant') and r.get('check') == 'ok']"
audit_ok "$W/u1.txt" "$W/u1.log" && pass "the audit passes it (the grant re-checked under the on unknown line)" || flunk "audit u1: $(grep PROBLEM "$W/u1.log.audit" | head -2)"

printf "${BASE}allow path $W/m/\ndefer path $W/data/ until=$W/m/ok\n" > "$W/d5.txt"
o="$("$WARDEN" "$W/d5.txt" --check-startup 2>&1)"
grep -q "could write the defer rule's marker" <<<"$o" && pass "a policy whose marker the agent could write is refused at start" || flunk "writable marker: $o"

# the default scope (run): the run frozen while the call is deferred, where it can be
printf "${FB}defer path $W/data/ until=$W/m/ok timeout=20\n" > "$W/d6.txt"
rm -f "$W/out/n" "$W/m/ok"
dstart "$W/d6.txt" "$W/d6" tick.sh "$W/data/r.csv" "$W/out"
if grep -q "freeze the run's control group" "$W/d6.log"; then
    wait_ev "$W/d6.log" defer
    a="$(cnt)"; sleep 1.2; b="$(cnt)"
    [ "$a" -gt 0 ] && [ "$a" = "$b" ] && pass "a deferral with the default scope (run) freezes the run ($a)" || flunk "deferral freeze: $a -> $b"
    marker "$RUN"; wait "$WPID"
    grep -q "held: ok a,b" "$W/d6.out" && grep -q "counted: 40" "$W/d6.out" && pass "... the marker releases it, then the run is thawed" || flunk "deferral thaw: $(cat "$W/d6.out")"
    check "... records: defer (scope run), run_frozen, defer_end resolved, the read allowed, run_thawed" recs "$W/d6.log" \
      "(lambda i: i[0] < i[1] < i[2] < i[3] < i[4])([next(k for k, r in enumerate(rs) if c(r)) for c in (lambda r: r.get('event') == 'defer' and r.get('scope') == 'run', lambda r: r.get('event') == 'run_frozen', lambda r: r.get('event') == 'defer_end' and r.get('ending') == 'resolved', lambda r: r.get('resolved') == '$W/data/r.csv' and r.get('cert_defer') is True, lambda r: r.get('event') == 'run_thawed')])"
    audit_ok "$W/d6.txt" "$W/d6.log" && pass "the audit passes it" || flunk "audit d6: $(grep PROBLEM "$W/d6.log.audit" | head -2)"
else
    printf '  %-6s %s\n' SKIP "a deferral freezing the run: this host cannot ($(grep -o 'cannot freeze the run: [^;]*' "$W/d6.log" | head -1))"
    wait "$WPID"
fi
rm -f "$W/m/ok"

echo "== 10. step 5b: on outside_plan defer, varek plan extend (as root) =="
# the run held to a plan that covers what bash reads, not the data
printf "plan 1.35\naction r1 file_open /usr/ open=read\naction r2 file_open /lib/ open=read\naction r3 file_open /lib64/ open=read\naction r4 file_open /etc/ open=read\naction r5 file_open $W/bin/ open=read\n" > "$W/hp.plan"
pstart() {   # pstart POLICY OUT SCRIPT ARGS...: as dstart, held to $W/hp.plan
    local pol="$1" out="$2" scr="$3"; shift 3
    "$WARDEN" "$pol" --plan "$W/hp.plan" --hold-to-plan -- /bin/bash "$W/bin/$scr" "$@" > "$out.out" 2> "$out.log" &
    WPID=$!
    RUN=""; local k
    for k in $(seq 1 40); do
        RUN="$(grep -o '"event":"run_start","run":"[0-9a-f]*"' "$out.log" 2>/dev/null | head -1 | sed 's/.*"run":"//; s/"$//')"
        [ -n "$RUN" ] && break
        sleep 0.25
    done
    SOCK="$(grep -o '/run/varek-approve/[0-9a-f]*\.sock' "$out.log" 2>/dev/null | head -1)"
}
printf "${BASE}allow path $W/data/ readonly\non outside_plan defer timeout=20 scope=thread\n" > "$W/o1.txt"
pstart "$W/o1.txt" "$W/o1" one.sh "$W/data/r.csv"
wait_ev "$W/o1.log" defer && sleep 0.5
[ ! -s "$W/o1.out" ] && grep -q '"outside_plan":true' "$W/o1.log" && pass "a read the policy allows but the plan does not cover is deferred: held, a defer record (outside_plan)" \
    || flunk "no outside_plan deferral: $(cat "$W/o1.out") / $(tail -3 "$W/o1.log")"
o="$(apv 0 0 pending)"
EXT="$(python3 -c 'import json,sys
for l in sys.stdin:
    if l.startswith("{") and json.loads(l).get("defer") == "outside_plan": print(json.loads(l)["extension"], end="")' <<<"$o")"
grep -q "action ext1 file_open $W/data/r.csv open=read" <<<"$EXT" && pass "pending lists it, with a one-step extension that covers it" || flunk "pending: $o"
o="$(apv 65534 65534 "extend\n$EXT")"
grep -q "^refused" <<<"$o" && pass "the agent's own user may not extend the plan" || flunk "agent extend: $o"
o="$(apv 4242 4242 "extend\n$EXT")"
grep -q "^refused" <<<"$o" && pass "nor another user, where the line names no approvers= (root alone)" || flunk "outsider extend: $o"
o="$(apv 0 0 "extend\n$EXT")"
grep -q "^extended [0-9a-f]\{64\}" <<<"$o" && pass "root sends the suggested extension back as it is: the plan gate authorizes it" || flunk "extend: $o"
wait "$WPID"
grep -q "r.csv: ok a,b" "$W/o1.out" && pass "... and the held read is decided again and allowed" || flunk "after the extension: $(cat "$W/o1.out")"
check "... records in order: defer (outside_plan), plan_extended (SATISFIED), defer_end resolved (the extension), the read allowed" recs "$W/o1.log" \
  "(lambda i: i[0] < i[1] < i[2] < i[3])([next(k for k, r in enumerate(rs) if c(r)) for c in (lambda r: r.get('event') == 'defer' and r.get('outside_plan') is True, lambda r: r.get('event') == 'plan_extended' and r.get('verdict') == 'SATISFIED' and r.get('entries') == 1 and r.get('approver_uid') == 0, lambda r: r.get('event') == 'defer_end' and r.get('ending') == 'resolved' and len(r.get('plan_extension', '')) == 64, lambda r: r.get('resolved') == '$W/data/r.csv' and r.get('decision_final') == 'ALLOW' and r.get('defer'))])"
audit_ok "$W/o1.txt" "$W/o1.log" && pass "the audit passes the run" || flunk "audit o1: $(grep PROBLEM "$W/o1.log.audit" | head -2)"
cp "$W/o1.log" "$W/r1.log"; cp "$W/o1.txt" "$W/p1.txt"
qforge "a resolved ending naming an extension never recorded" "[r.__setitem__('plan_extension', 'f' * 64) for r in recs if isinstance(r, dict) and r.get('event') == 'defer_end']" "no plan_extended record before it holds"
qforge "an extension the gate did not authorize, then a resolved ending" "[r.__setitem__('verdict', 'UNSATISFIED') for r in recs if isinstance(r, dict) and r.get('event') == 'plan_extended']" "did not authorize"

printf "${BASE}allow path $W/data/ readonly\non outside_plan defer timeout=3 scope=thread\n" > "$W/o2.txt"
pstart "$W/o2.txt" "$W/o2" one.sh "$W/data/r.csv"
wait_ev "$W/o2.log" defer && sleep 0.3
o="$(apv 0 0 "extend\nplan 1.35\naction x1 file_open /root/.ssh/id_rsa open=read\n")"
grep -q "^refused" <<<"$o" && pass "an extension with a step the policy refuses is refused by the plan gate" || flunk "refused extension: $o"
wait "$WPID"
grep -q "r.csv: no" "$W/o2.out" && pass "... it adds nothing: the call stays held, and is refused at its timeout" || flunk "after a refused extension: $(cat "$W/o2.out")"
check "... plan_extended (not SATISFIED, no entries), then the refusal (held) before defer_end timeout" recs "$W/o2.log" \
  "(lambda i: i[0] < i[1] < i[2])([next(k for k, r in enumerate(rs) if c(r)) for c in (lambda r: r.get('event') == 'plan_extended' and r.get('verdict') != 'SATISFIED' and r.get('entries') == 0, lambda r: r.get('held') is True and r.get('decision_final') == 'DENY' and r.get('rule') == 'outside_plan', lambda r: r.get('event') == 'defer_end' and r.get('ending') == 'timeout')])"
audit_ok "$W/o2.txt" "$W/o2.log" && pass "the audit passes it" || flunk "audit o2: $(grep PROBLEM "$W/o2.log.audit" | head -2)"

dstart "$W/o1.txt" "$W/o3" one.sh "$W/data/r.csv"
wait "$WPID"
grep -q "r.csv: ok a,b" "$W/o3.out" && grep -q "holds nothing: the run is not held to a plan" "$W/o3.log" && pass "without --hold-to-plan the line is inert (a note), the read allowed" \
    || flunk "inert: $(cat "$W/o3.out") / $(grep -c 'holds nothing' "$W/o3.log")"

echo "== 11. step 6: signed approvals (as root) =="
KG="$HERE/tools/varek_keygen"
groupadd -f vk1420s 2>/dev/null; GS="$(getent group vk1420s | cut -d: -f3)"
mkdir -p "$W/k" "$W/g" "$W/k43"; chmod 700 "$W/k"
for k in ops sec odd; do "$KG" "$W/k/$k" > /dev/null; done
KO="$(cat "$W/k/ops.pub")"; KS="$(cat "$W/k/sec.pub")"
[ ${#KO} = 194 ] && [ ${#KS} = 194 ] && pass "varek_keygen makes the approvers' keys (KEY, and KEY.pub: the point pinned in the policy)" || flunk "keygen: $KO"
AP="approver key=$KO group=vk1420 name=ops1\napprover key=$KS group=vk1420s name=sec1\n"
SL=$((HB + 3))                       # the step_up rule's line, after the two approver lines
printf "${BASE}${AP}step_up path $W/data/ approvers=vk1420 timeout=20\n" > "$W/s6.txt"
printf "${BASE}${AP}step_up path $W/data/ timeout=20\n" > "$W/s6n.txt"
U2="$(date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%SZ)"; UP="$(date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ)"
sgrant() {   # sgrant NAME KEY TEXT: $W/g/NAME.grant, signed with $W/k/KEY (KEY "": unsigned)
    printf '%b' "$3" > "$W/g/$1.grant"; rm -f "$W/g/$1.grant.sig"
    if [ -n "$2" ]; then "$KG" --sign grant "$W/k/$2" "$W/g/$1.grant" > /dev/null; fi
}
GT="grant\nstep_up line $SL\nallow path exact $W/data/r.csv readonly\ncount 2\nuntil $U2\n"
sgrant a ops "$GT"
grep -q "^kind grant$" "$W/g/a.grant.sig" && grep -q "^key $KO$" "$W/g/a.grant.sig" \
  && pass "varek_keygen --sign: a detached signature (varek-approval 1, kind, key, sig)" || flunk "--sign: $(cat "$W/g/a.grant.sig")"
"$KG" --verify grant "$KO" "$W/g/a.grant" > /dev/null 2>&1 && pass "--verify: it holds under the signer's key" || flunk "--verify"
! "$KG" --verify grant "$KS" "$W/g/a.grant" > /dev/null 2>&1 && ! "$KG" --verify plan "$KO" "$W/g/a.grant" > /dev/null 2>&1 \
  && pass "... and not under another key, nor as another kind (plan)" || flunk "--verify accepts another key or kind"
grun() { local pol="$1" out="$2"; shift 2; "$WARDEN" "$pol" "$@" > "$out.out" 2> "$out.log"; }
grun "$W/s6.txt" "$W/s1" --grants "$W/g" -- /bin/bash "$W/bin/one.sh" "$W/data/r.csv" "$W/data/r.csv" "$W/data/r.csv"
[ "$(grep -c 'r.csv: ok' "$W/s1.out")" = 2 ] && [ "$(grep -c 'r.csv: no' "$W/s1.out")" = 1 ] \
  && pass "a standing grant (count 2) signed by an approver of its rule's group: two reads allowed from the start, the third refused" \
  || flunk "standing grant: $(cat "$W/s1.out") / $(grep warden "$W/s1.log" | tail -2)"
SGID="$(sha256sum "$W/g/a.grant" | cut -c1-64)"
check "... recorded before any decision: standing, signed_by (its key, ops1, vk1420), sig, its text; no proposal" recs "$W/s1.log" \
  "[r for r in rs if r.get('event') == 'grant' and r.get('standing') is True and r['id'] == '$SGID' and r['signed_by'] == {'key': '$KO', 'name': 'ops1', 'group': 'vk1420'} and len(r.get('sig', '')) > 16 and 'proposal' not in r and 'approver_uid' not in r] and next(k for k, r in enumerate(rs) if r.get('event') == 'grant') < next(k for k, r in enumerate(rs) if 'decision_final' in r)"
check "... the two reads allowed under it (cert_grant, checked), the third a proposal" recs "$W/s1.log" \
  "len([r for r in rs if r.get('cert_grant') == '$SGID' and r.get('decision_final') == 'ALLOW' and r.get('check') == 'ok']) == 2 and [r for r in rs if r.get('step_up') and r.get('decision_final') == 'DENY']"
audit_ok "$W/s6.txt" "$W/s1.log" && pass "the audit passes it, the grant's signature verified" || flunk "audit s1: $(grep PROBLEM "$W/s1.log.audit" | head -2)"

refuse_start() {   # refuse_start LABEL POLICY WORDS: a start with --grants $W/g refused, for its reason
    "$WARDEN" "$2" --grants "$W/g" -- /bin/true > "$W/rf.out" 2>&1
    if grep -q "refusing to start" "$W/rf.out" && grep -qF -- "$3" "$W/rf.out"; then pass "refused at start: $1"
    else flunk "refused at start: $1: $(grep warden "$W/rf.out" | tail -2)"; fi
}
mv "$W/g" "$W/g1"; mkdir "$W/g"
sgrant b "" "$GT";  refuse_start "an unsigned standing grant" "$W/s6.txt" "b.grant.sig: No such file"
sgrant b sec "$GT"; refuse_start "a grant signed by an approver of another group" "$W/s6.txt" "signed by a key of group vk1420s, and its rule (line $SL) is approved by group vk1420"
sgrant b odd "$GT"; refuse_start "a grant signed by a key the policy does not pin" "$W/s6.txt" "pins as no approver's"
sgrant b ops "$GT"; sed -i 's/count 2/count 9/' "$W/g/b.grant"
refuse_start "a grant changed after it was signed" "$W/s6.txt" "the signature does not verify"
sgrant b ops "grant\nstep_up line $SL\nallow path exact $W/data/r.csv readonly\nfor run=0123456789abcdef0123456789abcdef\ncount 1\n"
refuse_start "a signed grant naming a run" "$W/s6.txt" "a standing grant names no run"
sgrant b ops "grant\nstep_up line $SL\nallow path exact $W/data/r.csv readonly\ncount 1\nuntil $UP\n"
refuse_start "a signed grant whose until has passed" "$W/s6.txt" "its until has passed"
sgrant b ops "$GT"; refuse_start "a signed grant under a rule that names no approvers=" "$W/s6n.txt" "names no approvers= group"
rm -f "$W/g/b.grant" "$W/g/b.grant.sig"; rmdir "$W/g"; mv "$W/g1" "$W/g"
"$WARDEN" "$W/s6.txt" --grants "$W/nogrants" -- /bin/true > "$W/rf.out" 2>&1
grep -q "\-\-grants $W/nogrants" "$W/rf.out" && ! grep -q '"event":"run_start"' "$W/rf.out" && pass "refused at start: a --grants directory that cannot be read" || flunk "no grants dir: $(tail -2 "$W/rf.out")"

sforge() {   # sforge LABEL LOG POLICY PYTHON WORDS [AUDIT ARGS...]: the audit fails the forged stream for its reason
    local lab="$1" log="$2" pol="$3" py="$4" words="$5"; shift 5
    (cd "$HERE/tests" && python3 v1270_forge.py "$log" "$W/f.log" "$py") > /dev/null 2>&1
    if python3 "$HERE/tools/varek_audit.py" --policy "$pol" --checker "$CERT" "$@" "$W/f.log" > "$W/f.out" 2>&1; then
        flunk "forged: $lab (the audit passed it)"
    elif grep -qF -- "$words" "$W/f.out"; then pass "forged: $lab"
    else flunk "forged: $lab (not for its own reason: $(grep '^  PROBLEM' "$W/f.out" | head -2 | tr '\n' ' '))"; fi
}
SG="[r for r in recs if isinstance(r, dict) and r.get('event') == 'grant'][0]"
sforge "a standing grant's signature altered" "$W/s1.log" "$W/s6.txt" "$SG['sig'] = $SG['sig'][:-6] + ('000000' if $SG['sig'][-6:] != '000000' else '111111')" "its signature does not verify over its text"
sforge "a standing grant's signer swapped for a key the policy does not pin" "$W/s1.log" "$W/s6.txt" "$SG['signed_by']['key'] = '$KA'" "signed by a key the policy does not pin"
sforge "a standing grant's signer named of another group" "$W/s1.log" "$W/s6.txt" "$SG['signed_by']['group'] = 'vk1420s'" "names its signer"
sforge "a standing grant's signature dropped" "$W/s1.log" "$W/s6.txt" "$SG.pop('sig'); $SG.pop('signed_by')" "standing grant $(cut -c1-16 <<<"$SGID"): no signature"
sforge "a standing grant signed by the other group's approver" "$W/s1.log" "$W/s6.txt" "$SG['signed_by'] = {'key': '$KS', 'name': 'sec1', 'group': 'vk1420s'}" "line $SL's approvers are 'vk1420'"

# plans: varek plan approve, and --require-approved-plan
printf "plan 1.35\naction r1 file_open /usr/ open=read\naction r2 file_open /lib/ open=read\naction r3 file_open /lib64/ open=read\naction r4 file_open /etc/ open=read\naction r5 file_open $W/bin/ open=read\naction r6 file_open $W/data/ open=read\n" > "$W/ap.plan"
printf "${BASE}${AP}allow path $W/data/ readonly\n" > "$W/s6p.txt"
python3 "$HERE/tools/varek" plan approve "$W/ap.plan" --key "$W/k/sec" > "$W/pa.out" 2>&1
grep -q "^kind plan$" "$W/ap.plan.sig" 2>/dev/null && pass "varek plan approve signs the plan (PLAN.sig, kind plan)" || flunk "plan approve: $(cat "$W/pa.out")"
grun "$W/s6p.txt" "$W/pl1" --plan "$W/ap.plan" --require-approved-plan -- /bin/bash "$W/bin/one.sh" "$W/data/r.csv"
grep -q "r.csv: ok a,b" "$W/pl1.out" && grep -q "the plan is approved by sec1 (group vk1420s)" "$W/pl1.log" \
  && pass "--require-approved-plan: a plan an approver signed runs" || flunk "approved plan: $(cat "$W/pl1.out") / $(grep warden "$W/pl1.log" | tail -2)"
check "... run_start's plan_approved_by: sec1's key and group, the signature, the plan's SHA-256" recs "$W/pl1.log" \
  "[r for r in rs if r.get('event') == 'run_start' and r['plan_approved_by']['key'] == '$KS' and r['plan_approved_by']['name'] == 'sec1' and r['plan_approved_by']['group'] == 'vk1420s' and r['plan_approved_by']['plan_sha256'] == '$(sha256sum "$W/ap.plan" | cut -c1-64)' and len(r['plan_approved_by']['sig']) > 16]"
python3 "$HERE/tools/varek_audit.py" --policy "$W/s6p.txt" --checker "$CERT" --plan "$W/ap.plan" "$W/pl1.log" > "$W/pl1.audit" 2>&1 \
  && pass "the audit passes it with --plan, the signature verified over the plan's bytes" || flunk "audit pl1: $(grep PROBLEM "$W/pl1.audit" | head -2)"
audit_ok "$W/s6p.txt" "$W/pl1.log" && grep -q "note: plan approval: not verified: give --plan" "$W/pl1.log.audit" \
  && pass "... without --plan it passes, and says the signature could not be verified" || flunk "audit pl1 without --plan: $(grep 'PROBLEM\|note' "$W/pl1.log.audit" | head -2)"
cp "$W/ap.plan" "$W/up.plan"
grun "$W/s6p.txt" "$W/pl2" --plan "$W/up.plan" --require-approved-plan -- /bin/bash "$W/bin/one.sh" "$W/data/r.csv"
grep -q "has no approval" "$W/pl2.log" && ! grep -q '"event":"run_start"' "$W/pl2.log" && pass "an unapproved plan is refused at start" || flunk "unapproved plan: $(tail -2 "$W/pl2.log")"
cp "$W/ap.plan" "$W/tp.plan"; cp "$W/ap.plan.sig" "$W/tp.plan.sig"; echo "action r7 file_open /usr/lib/ open=read" >> "$W/tp.plan"
grun "$W/s6p.txt" "$W/pl3" --plan "$W/tp.plan" --require-approved-plan -- /bin/bash "$W/bin/one.sh" "$W/data/r.csv"
grep -q "approval $W/tp.plan.sig fails: the signature does not verify" "$W/pl3.log" && ! grep -q '"event":"run_start"' "$W/pl3.log" \
  && pass "a plan changed after it was approved is refused at start" || flunk "tampered plan: $(tail -2 "$W/pl3.log")"
"$KG" --sign plan "$W/k/odd" "$W/up.plan" > /dev/null
grun "$W/s6p.txt" "$W/pl4" --plan "$W/up.plan" --require-approved-plan -- /bin/bash "$W/bin/one.sh" "$W/data/r.csv"
grep -q "pins as no approver's" "$W/pl4.log" && ! grep -q '"event":"run_start"' "$W/pl4.log" && pass "a plan signed by a key the policy does not pin is refused at start" || flunk "unpinned plan: $(tail -2 "$W/pl4.log")"
grun "$W/s6p.txt" "$W/pl5" --plan "$W/tp.plan" -- /bin/bash "$W/bin/one.sh" "$W/data/r.csv"
grep -q "r.csv: ok a,b" "$W/pl5.out" && recs "$W/pl5.log" "[r for r in rs if r.get('event') == 'run_start' and 'plan_approved_by' not in r and 'does not verify' in r.get('plan_approval_note', '')]" \
  && pass "without the flag, a plan whose approval fails runs unapproved, with a note in run_start" || flunk "without the flag: $(cat "$W/pl5.out") / $(grep warden "$W/pl5.log" | tail -2)"
PA="[r for r in recs if isinstance(r, dict) and r.get('event') == 'run_start'][0]['plan_approved_by']"
sforge "the plan approval's signature altered" "$W/pl1.log" "$W/s6p.txt" "$PA['sig'] = $PA['sig'][:-6] + ('000000' if $PA['sig'][-6:] != '000000' else '111111')" "the plan's approval signature does not verify" --plan "$W/ap.plan"
sforge "the plan approval's key swapped for one the policy does not pin" "$W/pl1.log" "$W/s6p.txt" "$PA['key'] = '$KA'" "signed by a key the policy does not pin"
sforge "the plan approval's signer renamed" "$W/pl1.log" "$W/s6p.txt" "$PA['name'] = 'ops1'" "names its signer"

# runtime grants signed at the approvers' socket (varek approve --sign-key)
AU=4243; AG="$GG"
start "$W/s6.txt" "$W/s2" 40
ID6="$(wait_prop)"
[ -n "$ID6" ] && pass "under the same rule with no standing grant, a read proposes a grant ($ID6)" || flunk "no proposal (s2)"
apv "$AU" "$AG" pending | python3 -c 'import json,sys
for l in sys.stdin:
    if l.startswith("{") and json.loads(l)["id"] == sys.argv[1]: open(sys.argv[2], "w").write(json.loads(l)["proposal"])' "$ID6" "$W/pt.txt"
cp "$W/pt.txt" "$W/pt2.txt"; echo "#" >> "$W/pt2.txt"
"$KG" --sign grant "$W/k/sec" "$W/pt.txt" > /dev/null; "$KG" --sign grant "$W/k/ops" "$W/pt2.txt" > /dev/null
o="$(apv "$AU" "$AG" "approve $ID6\nsig $(sed -n 's/^sig //p' "$W/pt.txt.sig") key $KS\n$(cat "$W/pt.txt")\n")"
grep -q "refused: signed by a key of group vk1420s; the rule is approved by group vk1420" <<<"$o" \
  && pass "an approval signed by the other group's approver is refused" || flunk "wrong group's signature: $o"
o="$(apv "$AU" "$AG" "approve $ID6\nsig $(sed -n 's/^sig //p' "$W/pt2.txt.sig") key $KO\n$(cat "$W/pt.txt")\n")"
grep -q "refused: the signature does not verify" <<<"$o" && pass "... and one whose signature is over other text" || flunk "bad signature: $o"
cp "$W/k/ops" "$W/k43/ops"; chown -R 4243 "$W/k43"; chmod 700 "$W/k43"; chmod 600 "$W/k43/ops"
# the CLI as a user other than root: a copy it can read (the checkout may be
# readable by its owner alone, as on GitHub's runners), with its modules and varek_keygen beside
# it, where the CLI finds it (VAREK_HOME/tools)
mkdir -p "$W/vh/tools" && cp "$HERE/tools/varek" "$HERE/tools/varek_keygen" "$HERE"/tools/*.py "$W/vh/tools/" && chmod -R a+rX "$W/vh"
o="$(cd "$W/k43" && setpriv --reuid=4243 --regid="$GG" --clear-groups env HOME="$W/k43" VAREK_HOME="$W/vh" python3 "$W/vh/tools/varek" approve "$RUN" "$ID6" --sign-key "$W/k43/ops" --reason signed 2>&1)"
grep -q "approved [0-9a-f]\{64\}" <<<"$o" && pass "varek approve --sign-key, by a member of the rule's group with ops1's key: approved" || flunk "approve --sign-key: $o"
for k in $(seq 1 40); do grep -q ' ok$' "$W/s2.out" && break; sleep 0.25; done
grep -q ' ok$' "$W/s2.out" && pass "... the agent's next read is allowed" || flunk "no read after the signed approval: $(tail -2 "$W/s2.out")"
wait "$WPID"
check "... its grant record: approver_uid 4243, signed_by ops1 (vk1420), the signature" recs "$W/s2.log" \
  "[r for r in rs if r.get('event') == 'grant' and r.get('proposal') == '$ID6' and r['approver_uid'] == 4243 and r['signed_by'] == {'key': '$KO', 'name': 'ops1', 'group': 'vk1420'} and len(r.get('sig', '')) > 16 and r.get('reason') == 'signed']"
audit_ok "$W/s6.txt" "$W/s2.log" && pass "the audit passes it, the signature verified" || flunk "audit s2: $(grep PROBLEM "$W/s2.log.audit" | head -2)"
RG="[r for r in recs if isinstance(r, dict) and r.get('event') == 'grant' and 'signed_by' in r][0]"
sforge "a signed runtime grant's signature altered" "$W/s2.log" "$W/s6.txt" "$RG['sig'] = $RG['sig'][:-6] + ('000000' if $RG['sig'][-6:] != '000000' else '111111')" "its signature does not verify over its text"
sforge "a signed runtime grant's signer swapped for a key the policy does not pin" "$W/s2.log" "$W/s6.txt" "$RG['signed_by']['key'] = '$KA'" "signed by a key the policy does not pin"

fi

echo
[ $fail = 0 ] && echo "test_v1420: PASS ($n checks)" || echo "test_v1420: FAIL"
exit $fail
