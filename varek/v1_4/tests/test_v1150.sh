#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1150.sh — regression test for VAREK v1.15: certificates for every
# authorization, checked by an independent checker before the action happens.
#
#   1. Every open the live Warden authorizes carries a certificate that the
#      in-line checker accepted; run_start records the policy's SHA-256.
#   2. The audit tool re-checks a saved stream and fails on a tampered
#      certificate, a removed certificate, or a different policy file.
#   3. A Warden with a planted bug in its decision procedure (test-only build)
#      wrongly says SATISFIED; the checker refuses both wrong verdicts, so the
#      opens are denied and recorded as certificate_refused, and accepts the
#      one verdict that is right.
#   4. The --plan gate authorizes only what the checker confirms.
#   5. The checker on its own: the policy digest, and hand-forged certificates
#      (an earlier rule holds, a deny rule, a false witness, flags outside the
#      fragment) are refused.
#   6. The decision procedure, the solver and the checker agree
#      (tools/smt_crosscheck.py --cert; needs python3 + z3-solver).
#
# Usage: ./test_v1150.sh <warden> <warden_faultinject> <vdp_check> <vdp_cert_check> <probe_bin>
set -u

WARDEN="${1:?usage: test_v1150.sh <warden> <warden_faultinject> <vdp_check> <vdp_cert_check> <probe>}"
FAULTY="${2:?}"
VDP="${3:?}"
CERT="${4:?}"
PROBE="${5:?}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
POL="$HERE/tests/v1150_policy.txt"
AUDIT="$HERE/tools/varek_audit.py"

fail=0
pass() { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }

OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
D=/tmp/varek_v1150
rm -rf "$D"
mkdir -p "$D/work/x" "$D/logs" "$D/shared/c" "$D/secret" "$D/pub"
for f in work/k.pem work/x/.inject logs/app.log shared/c/data.bin secret/.inject pub/.inject; do
    echo "content" > "$D/$f"
done

says() { grep -Eq "^PROBE $2 +$3" "$1"; }
expect() { if says "$1" "$3" "$4"; then pass "$2"; else flunk "$2 ($(grep -E "^PROBE $3 " "$1" | sed 's/^PROBE //'))"; fi; }

echo "== 1. every authorization carries an accepted certificate =="
timeout 30 "$WARDEN" "$POL" -- "$PROBE" >"$OUT/probe" 2>"$OUT/verdicts"
rc=$?
sed 's/^/    /' "$OUT/probe"
[ "$rc" -eq 0 ] && pass "agent ran to completion" || flunk "agent ran to completion (rc=$rc)"
grep -q BYPASSED "$OUT/probe" && flunk "no bypass reported" || pass "no bypass reported"
expect "$OUT/probe" "prefix rule admits a write"            prefix_write OK
expect "$OUT/probe" "glob rule admits a read"               glob_read OK
expect "$OUT/probe" "contains rule admits a read"           contains_read OK
expect "$OUT/probe" "suffix .pem refused"                   suffix_pem REFUSED
expect "$OUT/probe" "readonly glob refuses a write"         glob_write REFUSED
expect "$OUT/probe" "explicit deny glob refuses"            inject_under_deny REFUSED
expect "$OUT/probe" "denied directory refuses"              inject_denied_dir REFUSED
expect "$OUT/probe" "an allowed path is admitted"           inject_allowed OK
allowed="$(grep '^{' "$OUT/verdicts" | grep '"action":"file.open"' | grep -c '"decision_final":"ALLOW"')"
certok="$(grep '^{' "$OUT/verdicts" | grep '"action":"file.open"' | grep '"decision_final":"ALLOW"' | grep -c '"cert_rule":[0-9]*,"cert_witness":"[^"]*","check":"ok"')"
[ "$allowed" -gt 0 ] && [ "$allowed" -eq "$certok" ] \
  && pass "all $allowed authorized opens carry a certificate the checker accepted" \
  || flunk "authorized opens with an accepted certificate ($certok of $allowed)"
grep '^{' "$OUT/verdicts" | grep '"resolved":"/tmp/varek_v1150/logs/app.log"' | grep '"decision_final":"ALLOW"' \
  | grep -q '"cert_witness":"g:' && pass "a glob authorization carries its span witness" || flunk "a glob authorization carries its span witness"
grep '^{' "$OUT/verdicts" | grep '"resolved":"/tmp/varek_v1150/shared/c/data.bin"' | grep -q '"cert_witness":"c:' \
  && pass "a contains authorization carries its offset witness" || flunk "a contains authorization carries its offset witness"
want="$(sha256sum "$POL" | cut -d' ' -f1)"
grep -q "\"policy_sha256\":\"$want\"" "$OUT/verdicts" && pass "run_start records the policy's SHA-256" \
  || flunk "run_start records the policy's SHA-256"
ver="$(sed -n 's/.*"event":"run_start".*"warden":"\([0-9.]*\)".*/\1/p' "$OUT/verdicts" | head -1)"
[ -n "$ver" ] && [ "$(printf '%s\n1.15.0\n' "$ver" | sort -V | head -1)" = 1.15.0 ] \
  && pass "run_start names Warden $ver (>= 1.15.0)" || flunk "run_start names Warden >= 1.15.0 (saw '$ver')"

echo "== 2. the audit tool re-checks a saved stream =="
o="$(python3 "$AUDIT" --policy "$POL" --checker "$CERT" "$OUT/verdicts" 2>&1)"
echo "$o" | sed 's/^/    /' | head -3
grep -q "varek_audit: PASS" <<<"$o" && pass "audit of the stream passes" || flunk "audit of the stream passes"
sed -E '0,/"cert_witness":"g:[0-9]+-[0-9]+"/s//"cert_witness":"g:0-1"/' "$OUT/verdicts" > "$OUT/tampered"
o="$(python3 "$AUDIT" --policy "$POL" --checker "$CERT" "$OUT/tampered" 2>&1)"
grep -q "varek_audit: FAIL" <<<"$o" && grep -q "refused" <<<"$o" \
  && pass "a tampered witness fails the audit" || flunk "a tampered witness fails the audit"
sed -E '0,/"cert_rule":[0-9]+,"cert_witness":"[^"]*","check":"ok",/s///' "$OUT/verdicts" > "$OUT/stripped"
o="$(python3 "$AUDIT" --policy "$POL" --checker "$CERT" "$OUT/stripped" 2>&1)"
grep -q "without an accepted certificate" <<<"$o" && pass "a removed certificate fails the audit" \
  || flunk "a removed certificate fails the audit"
sed -E '0,/"decision_final":"DENY","rule":"policy_match"/s//"decision_final":"ALLOW","rule":"policy_match"/' \
    "$OUT/verdicts" > "$OUT/flipped"
o="$(python3 "$AUDIT" --policy "$POL" --checker "$CERT" "$OUT/flipped" 2>&1)"
grep -q "not a certified file open" <<<"$o" && pass "a denial rewritten as ALLOW fails the audit" \
  || flunk "a denial rewritten as ALLOW fails the audit"
{ cat "$POL"; echo "allow path /"; } > "$OUT/other_policy.txt"
o="$(python3 "$AUDIT" --policy "$OUT/other_policy.txt" --checker "$CERT" "$OUT/verdicts" 2>&1)"
grep -q "the policy file hashes to" <<<"$o" && pass "a different policy file fails the audit" \
  || flunk "a different policy file fails the audit"

echo "== 3. a planted bug in the decision procedure cannot authorize =="
timeout 30 "$FAULTY" "$POL" -- "$PROBE" >"$OUT/fprobe" 2>"$OUT/fverdicts"
sed 's/^/    /' "$OUT/fprobe" | grep inject
expect "$OUT/fprobe" "wrong SATISFIED under an explicit deny: refused"  inject_under_deny REFUSED
expect "$OUT/fprobe" "wrong SATISFIED under a denied directory: refused" inject_denied_dir REFUSED
expect "$OUT/fprobe" "the one right SATISFIED: admitted"                 inject_allowed OK
n="$(grep '^{' "$OUT/fverdicts" | grep '"decision_raw":"ALLOW"' | grep '"decision_final":"DENY"' \
     | grep '"rule":"certificate_refused"' | grep -c '"check":"refused","check_why":"an earlier rule holds"')"
[ "$n" -eq 2 ] && pass "both recorded: procedure ALLOW, final DENY, certificate_refused (an earlier rule holds)" \
  || flunk "certificate_refused records (saw $n)"
[ "$(grep -c '^\[warden\] certificate refused (record seq [0-9]*): an earlier rule holds' "$OUT/fverdicts")" -eq 2 ] \
  && pass "the Warden reports both refusals (without echoing the agent's path)" || flunk "the Warden reports the refusals"
grep -q '"build":"faultinject"' "$OUT/fverdicts" && pass "the test build marks its run_start" \
  || flunk "the test build marks its run_start"
[ "$(cat "$D/secret/.inject")" = content ] && pass "the denied file is untouched" || flunk "the denied file is untouched"
o="$(python3 "$AUDIT" --policy "$POL" --checker "$CERT" "$OUT/fverdicts" 2>&1)"
grep -q "test build" <<<"$o" && grep -q "varek_audit: FAIL" <<<"$o" \
  && pass "the audit refuses a stream from the test build" || flunk "the audit refuses a stream from the test build"
o="$(python3 "$AUDIT" --allow-test-build --policy "$POL" --checker "$CERT" "$OUT/fverdicts" 2>&1)"
grep -q "2 refused in-line" <<<"$o" && grep -q "varek_audit: PASS" <<<"$o" \
  && pass "with --allow-test-build: the 2 in-line refusals counted, every authorization re-checked" \
  || flunk "audit of the fault-injected run"

echo "== 4. the --plan gate authorizes only what the checker confirms =="
plan() { printf 'action a file_open %s\n' "$2" > "$OUT/plan.txt"
         "$1" "$POL" --plan "$OUT/plan.txt" -- /bin/true 2>&1 | sed -n 's/.*"type":"plan_verify".*"decision":"\([A-Z]*\)".*/\1/p' | head -1; }
[ "$(plan "$WARDEN" /tmp/varek_v1150/pub/f.txt)" = SATISFIED ] && pass "an allowed planned open: SATISFIED" \
  || flunk "an allowed planned open: SATISFIED"
r="$(plan "$FAULTY" /tmp/varek_v1150/secret/.inject)"
[ "$r" != SATISFIED ] && pass "a wrong SATISFIED from the planted bug is not authorized ($r)" \
  || flunk "the plan gate authorized a wrong SATISFIED"

echo "== 5. the checker on its own =="
[ "$("$CERT" "$POL" digest)" = "$want" ] && pass "vdp_cert_check digest is the file's SHA-256" \
  || flunk "vdp_cert_check digest"
hx() { printf %s "$1" | od -An -tx1 | tr -d ' \n'; }
{
  echo "path 0x0 $(hx /tmp/varek_v1150/work/x/.inject) 6 -"      # rule 6 holds, but rule 2 (deny glob) holds first
  echo "path 0x0 $(hx /tmp/varek_v1150/work/k.pem) 0 -"          # rule 0 is a deny rule
  echo "path 0x0 $(hx /tmp/varek_v1150/logs/app.log) 3 g:0-3"    # a false span witness
  echo "path 0x3 $(hx /tmp/varek_v1150/pub/f.txt) 6 -"           # access mode 3: outside the fragment
  echo "path 0x80000000 $(hx /tmp/varek_v1150/pub/f.txt) 6 -"    # a flag bit outside open(2)
  echo "path 0x1 $(hx /tmp/varek_v1150/logs/app.log) 3 g:22-25"  # readonly rule, write access
  echo "path 0x0 $(hx /tmp/varek_v1150/logs/app.log) 3 g:22-25"  # the true certificate
} > "$OUT/forged"
r="$("$CERT" "$POL" batch < "$OUT/forged" | cut -d'"' -f4 | tr '\n' ' ')"
[ "$r" = "reject reject reject reject reject reject ok " ] \
  && pass "six forged certificates refused, the true one accepted" || flunk "forged certificates ($r)"
CP="$HERE/tests/v1150_cert_policy.txt"
{
  echo "path - $(hx /srv/modes/f) -1 -"                   # true: access mode 3 is outside the fragment
  echo "path 0x0 $(hx /srv/pub/xf.txt) 3 g:9-10"          # /**/ span "x" does not end in '/'
  echo "path 0x0 $(hx /srv/pub/a/f.txt) 3 g:9-11"         # the true witness
  echo "path 0x0 $(hx /srv/one/a/b.log) 4 g:9-12"         # '/' inside a * span
} > "$OUT/forged2"
r="$("$CERT" "$CP" batch < "$OUT/forged2" | cut -d'"' -f4 | tr '\n' ' ')"
[ "$r" = "ok reject ok reject " ] \
  && pass "symbolic claim over every access mode accepted; witnesses breaking /**/ or * refused" \
  || flunk "fixture certificates ($r)"

echo "== 6. decision procedure vs solver vs certificate checker =="
if python3 -c 'import z3' 2>/dev/null; then
    o="$(python3 "$HERE/tools/smt_crosscheck.py" --vdp "$VDP" --cert "$CERT" --fuzz 25 --seed 1150 --queries 40 \
         "$HERE"/policies/*.txt "$HERE"/tests/*policy*.txt 2>&1)"
    echo "$o" | grep -E "certificates:|PASS|FAIL" | sed 's/^/    /'
    grep -q "smt_crosscheck: PASS (0 disagreements)" <<<"$o" && pass "zero disagreements" || flunk "zero disagreements"
else
    flunk "python3 module z3 not found (pip install z3-solver): the cross-check is required"
fi

echo
if [ "$fail" -eq 0 ]; then echo "test_v1150: PASS"; else echo "test_v1150: FAIL"; fi
exit "$fail"
