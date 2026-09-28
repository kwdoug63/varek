#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1130.sh — regression test for VAREK v1.13: the SMT decision procedure
# in the enforcement path.
#
#   1. Enforcement of the open-flag (bitvector) fragment under a live Warden:
#      a `readonly` rule admits reads and refuses write access, O_APPEND,
#      O_RDONLY|O_TRUNC and O_RDONLY|O_CREAT; the file is unchanged and nothing
#      is created. Flag bits outside the ABI open(2) set are refused as outside
#      the fragment, even under a permissive rule.
#   2. Load-time analysis: the Warden reports a rule that can never fire.
#   3. The policy parser refuses instead of dropping: more than 256 rules, a
#      contradictory flag clause, a flag clause on a non-path rule.
#   4. The shipped policies lint clean (no rule that can never fire).
#   5. The --plan gate treats a planned file_open's flags as symbolic.
#   6. The decision procedure agrees with an SMT solver on every check
#      (tools/smt_crosscheck.py; needs python3 + z3-solver).
#   7. The verdict-distribution harness gate: unsafe_satisfied == 0.
#
# Usage: ./test_v1130.sh <warden> <vdp_check> <probe_bin>
set -u

WARDEN="${1:?usage: test_v1130.sh <warden> <vdp_check> <probe>}"
VDP="${2:?}"
PROBE="${3:?}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

fail=0
pass() { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }

OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
RO=/tmp/varek_ro_v1130
RW=/tmp/varek_rw_v1130
rm -rf "$RO" "$RW"; mkdir -p "$RO" "$RW"
echo "original content" > "$RO/data.txt"
SUM="$(sha256sum "$RO/data.txt" | cut -d' ' -f1)"

echo "== 1. open-flag fragment enforced by the live Warden =="
timeout 30 "$WARDEN" "$HERE/tests/v1130_policy.txt" -- "$PROBE" >"$OUT/probe" 2>"$OUT/verdicts"
rc=$?
sed 's/^/    /' "$OUT/probe"
says() { grep -Eq "^PROBE $1 +$2" "$OUT/probe"; }
expect() { if says "$2" "$3"; then pass "$1"; else flunk "$1 ($(grep -E "^PROBE $2 " "$OUT/probe" | sed 's/^PROBE //'))"; fi; }
[ "$rc" -eq 0 ] && pass "agent ran to completion" || flunk "agent ran to completion (rc=$rc)"
grep -q BYPASSED "$OUT/probe" && flunk "no bypass reported" || pass "no bypass reported"
expect "readonly admits O_RDONLY"                    ro_read OK
expect "readonly admits O_RDONLY|O_CLOEXEC"          ro_read_cloexec OK
expect "the delivered fd reads the real file"        ro_read_content OK
expect "readonly refuses O_WRONLY"                   ro_write REFUSED
expect "readonly refuses O_RDWR"                     ro_readwrite REFUSED
expect "readonly refuses O_WRONLY|O_APPEND"          ro_append REFUSED
expect "readonly refuses O_RDONLY|O_TRUNC"           ro_rdonly_trunc REFUSED
expect "readonly refuses O_RDONLY|O_CREAT"           ro_rdonly_creat_new REFUSED
expect "readonly refuses O_TMPFILE"                  ro_tmpfile REFUSED
[ "$(sha256sum "$RO/data.txt" | cut -d' ' -f1)" = "$SUM" ] && pass "read-only file unchanged" || flunk "read-only file unchanged"
[ -e "$RO/new.txt" ] && flunk "nothing created in the read-only tree" || pass "nothing created in the read-only tree"
expect "a rule without flag clauses admits writes"   rw_write OK
expect "... and appends"                             rw_append OK
expect "flag bit 31 (outside the ABI set) refused"   unknown_bit_31 REFUSED
expect "flag bit 24 (outside the ABI set) refused"   unknown_bit_24 REFUSED
n="$(grep -c '"rule":"fragment_escape_flags"' "$OUT/verdicts")"
[ "$n" -eq 2 ] && pass "both recorded as fragment_escape_flags" || flunk "both recorded as fragment_escape_flags (saw $n)"
grep '^{' "$OUT/verdicts" | grep '"decision_final":"ALLOW"' | grep "$RO/data.txt" | grep -q '"policy_line":3' \
  && pass "an ALLOW record names the deciding policy line" || flunk "an ALLOW record names the deciding policy line"
grep -Eq '"warden":"1\.13\.' "$OUT/verdicts" && pass "run_start names Warden 1.13.x" || flunk "run_start names Warden 1.13.x"

echo "== 2. load-time analysis reports a rule that can never fire =="
cat > "$OUT/dead.txt" <<'EOF'
deny  path /etc/
allow path /etc/ld.so.cache readonly
allow path /tmp/
EOF
o="$("$WARDEN" "$OUT/dead.txt" -- /bin/true 2>&1 || true)"
grep -q "dead.txt:2: WARNING: allow path rule can never fire" <<<"$o" \
  && pass "Warden warns: line 2 can never fire" || flunk "Warden warns: line 2 can never fire"
grep -q "(1 can never fire)" <<<"$o" && pass "load summary counts it" || flunk "load summary counts it"
"$VDP" "$OUT/dead.txt" lint >/dev/null 2>&1; [ $? -eq 1 ] && pass "vdp_check lint exits 1 on a dead rule" || flunk "vdp_check lint exits 1 on a dead rule"

echo "== 3. the parser refuses instead of dropping =="
{ for i in $(seq 1 256); do echo "allow path /tmp/r$i/"; done; echo "deny path /tmp/"; } > "$OUT/big.txt"
o="$("$WARDEN" "$OUT/big.txt" -- /bin/true 2>&1 || true)"
grep -q "more than 256 rules; refusing to drop any" <<<"$o" && ! grep -q "supervising pid=" <<<"$o" \
  && pass "257 rules: refused, agent not started (v1.12 silently dropped rule 257)" || flunk "257 rules refused"
printf 'allow path /tmp/ +O_TRUNC -O_TRUNC\n' > "$OUT/contra.txt"
o="$("$WARDEN" "$OUT/contra.txt" -- /bin/true 2>&1 || true)"
grep -q "contradictory flag clause" <<<"$o" && pass "contradictory flag clause refused" || flunk "contradictory flag clause refused"
printf 'allow host 127.0.0.1:80 readonly\n' > "$OUT/hostflag.txt"
o="$("$WARDEN" "$OUT/hostflag.txt" -- /bin/true 2>&1 || true)"
grep -q "flag clause 'readonly' on a non-path rule" <<<"$o" && pass "flag clause on a host rule refused" || flunk "flag clause on a host rule refused"
printf 'allow path /tmp/ +O_BOGUS\n' > "$OUT/bogus.txt"
o="$("$WARDEN" "$OUT/bogus.txt" -- /bin/true 2>&1 || true)"
grep -q "unknown flag clause '+O_BOGUS'" <<<"$o" && pass "unknown flag name refused" || flunk "unknown flag name refused"

echo "== 4. shipped policies lint clean =="
for p in "$HERE"/policy.txt "$HERE"/conformance_policy.txt "$HERE"/policies/*.txt; do
    check "$(basename "$p"): no rule that can never fire" "$VDP" "$p" lint
done

echo "== 5. --plan gate: a planned file_open's flags are symbolic =="
printf 'allow path /data/ro/ readonly\nallow path /data/rw/\n' > "$OUT/plan_pol.txt"
plan() { printf 'action a file_open %s\n' "$1" > "$OUT/plan.txt"
         "$WARDEN" "$OUT/plan_pol.txt" --plan "$OUT/plan.txt" -- /bin/true 2>&1 | sed -n 's/.*"type":"plan_verify".*"decision":"\([A-Z]*\)".*/\1/p' | head -1; }
[ "$(plan /data/rw/x)" = SATISFIED ] && pass "file_open under a flag-free allow: SATISFIED" || flunk "file_open under a flag-free allow: SATISFIED"
[ "$(plan /data/ro/x)" = UNKNOWN ] && pass "file_open under a readonly allow: UNKNOWN (some flags would be refused)" || flunk "file_open under a readonly allow: UNKNOWN"

echo "== 6. decision procedure vs SMT solver =="
if python3 -c 'import z3' 2>/dev/null; then
    o="$(python3 "$HERE/tools/smt_crosscheck.py" --vdp "$VDP" --fuzz 60 --seed 1100 --queries 40 \
         "$HERE"/policy.txt "$HERE"/conformance_policy.txt "$HERE"/policies/*.txt "$HERE"/tests/*policy*.txt 2>&1)"
    echo "$o" | sed 's/^/    /' | tail -3
    grep -q "smt_crosscheck: PASS (0 disagreements)" <<<"$o" && pass "zero disagreements with the solver" || flunk "zero disagreements with the solver"
else
    flunk "python3 module z3 not found (pip install z3-solver): the solver cross-check is required"
fi

echo "== 7. verdict-distribution harness gate =="
o="$(cd "$HERE" && python3 tools/verdict_harness.py --vdp "$VDP" harness/corpus/ 2>&1)"
echo "$o" | sed 's/^/    /' | grep -v "over-refusal" | head -6
grep -q "gate unsafe_satisfied == 0: PASS" <<<"$o" && pass "harness gate unsafe_satisfied == 0" || flunk "harness gate unsafe_satisfied == 0"

echo
if [ "$fail" -eq 0 ]; then echo "test_v1130: PASS"; else echo "test_v1130: FAIL"; fi
exit "$fail"
