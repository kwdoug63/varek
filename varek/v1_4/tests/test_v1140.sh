#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1140.sh — regression test for VAREK v1.14: the bounded string fragment
# of the SMT decision procedure (exact, prefix, suffix, contains and glob
# matchers on path and exec rules).
#
#   1. Each matcher enforced by the live Warden on the resolved path, including
#      through a symlink; the run_start record names Warden 1.14.x and records
#      name the deciding policy line.
#   2. Load-time analysis: a rule shadowed by an earlier glob / suffix rule is
#      reported, found by the automaton search.
#   3. The parser refuses malformed globs, matchers on host rules, too many
#      wildcards, a malformed `require`, a matcher with no constant under
#      `require warden 1.14`, and glob patterns over the policy-wide token cap;
#      and keeps every v1.13 policy's meaning (a constant spelt like a matcher
#      keyword and followed by a flag clause is still a prefix).
#   4. The shipped policies lint clean (every rule decided reachable); the
#      v1.13.0 and v1.12.4 policies, and a v1.13 policy whose constants are
#      spelt like matcher keywords, decide exactly as under v1.13.0 (when git
#      and the v1.13.0 tag are available).
#   5. The --plan gate decides planned file_opens with the matchers.
#   6. The decision procedure agrees with the solver and the derivative oracle
#      (tools/smt_crosscheck.py; needs python3 + z3-solver).
#   7. The verdict-distribution harness gate: unsafe_satisfied == 0.
#
# Usage: ./test_v1140.sh <warden> <vdp_check> <probe_bin>
set -u

WARDEN="${1:?usage: test_v1140.sh <warden> <vdp_check> <probe>}"
VDP="${2:?}"
PROBE="${3:?}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

fail=0
pass() { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }

OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
D=/tmp/varek_v1140
rm -rf "$D"
mkdir -p "$D/work/.ssh" "$D/work/x/y" "$D/work/private" "$D/work/sub/private" "$D/logs/2026" "$D/keys"
for f in work/cert.pem work/pem-notes.txt work/.ssh/id_ed25519 work/secret-top work/x/y/secret-token \
         work/x/y/not-secret work/private/k work/sub/private/k only.txt only.txt.bak logs/app.log \
         logs/2026/app.log keys/server.pem; do echo "content" > "$D/$f"; done
ln -s "$D/keys/server.pem" "$D/work/innocent.txt"

echo "== 1. string matchers enforced by the live Warden =="
timeout 30 "$WARDEN" "$HERE/tests/v1140_policy.txt" -- "$PROBE" >"$OUT/probe" 2>"$OUT/verdicts"
rc=$?
sed 's/^/    /' "$OUT/probe"
says() { grep -Eq "^PROBE $1 +$2" "$OUT/probe"; }
expect() { if says "$2" "$3"; then pass "$1"; else flunk "$1 ($(grep -E "^PROBE $2 " "$OUT/probe" | sed 's/^PROBE //'))"; fi; }
[ "$rc" -eq 0 ] && pass "agent ran to completion" || flunk "agent ran to completion (rc=$rc)"
grep -q BYPASSED "$OUT/probe" && flunk "no bypass reported" || pass "no bypass reported"
expect "prefix rule still admits the workspace"            work_write OK
expect "suffix .pem refuses a key"                          suffix_pem REFUSED
expect "suffix .pem refuses it through an innocent symlink" suffix_pem_via_symlink REFUSED
expect "suffix does not match a name that only mentions pem" suffix_nearmiss OK
expect "contains /.ssh refuses a key"                       contains_ssh_key REFUSED
expect "contains /.ssh refuses the directory"               contains_ssh_dir REFUSED
expect "glob /**/secret-* at zero segments"                 glob_segs_zero REFUSED
expect "glob /**/secret-* at depth"                         glob_segs_deep REFUSED
expect "glob /**/secret-* near miss admitted"               glob_segs_nearmiss OK
expect "glob * matches one segment"                         glob_star_one_segment REFUSED
expect "glob * never crosses '/'"                           glob_star_no_cross OK
expect "exact rule admits the file read-only"               exact_read OK
expect "exact rule keeps its flag clause"                   exact_write REFUSED
expect "exact rule does not admit a sibling (prefix would)" exact_sibling REFUSED
expect "glob *.log admits a read"                           glob_log_read OK
expect "glob *.log readonly refuses an append"              glob_log_write REFUSED
expect "glob *.log does not reach a subdirectory"           glob_log_subdir REFUSED
[ "$(cat "$D/keys/server.pem")" = content ] && pass "the key behind the symlink is untouched" || flunk "the key behind the symlink is untouched"
pemline="$(grep -n '^deny  path suffix .pem' "$HERE/tests/v1140_policy.txt" | cut -d: -f1)"
grep '^{' "$OUT/verdicts" | grep '"decision_final":"DENY"' | grep "$D/work/cert.pem" | grep -q "\"policy_line\":$pemline," \
  && pass "a DENY record names the suffix rule's line ($pemline)" || flunk "a DENY record names the suffix rule's line ($pemline)"
grep '^{' "$OUT/verdicts" | grep '"decision_final":"DENY"' | grep -q "$D/keys/server.pem" \
  && pass "the symlinked open is recorded under its resolved path" || flunk "the symlinked open is recorded under its resolved path"
ver="$(sed -n 's/.*"event":"run_start".*"warden":"\([0-9.]*\)".*/\1/p' "$OUT/verdicts" | head -1)"
[ -n "$ver" ] && [ "$(printf '%s\n1.14.0\n' "$ver" | sort -V | head -1)" = 1.14.0 ] \
  && pass "run_start names Warden $ver (>= 1.14.0)" || flunk "run_start names Warden >= 1.14.0 (saw '$ver')"

echo "== 2. load-time analysis with the automaton search =="
cat > "$OUT/dead.txt" <<'POL'
require warden 1.14
deny  path suffix .txt
allow path glob /tmp/*.txt
allow path glob /tmp/**
deny  path glob /tmp/*/private/**
POL
o="$("$WARDEN" "$OUT/dead.txt" -- /bin/true 2>&1 || true)"
grep -q "dead.txt:3: WARNING: allow path rule can never fire" <<<"$o" \
  && pass "Warden warns: a glob shadowed by a suffix rule" || flunk "Warden warns: a glob shadowed by a suffix rule"
grep -q "dead.txt:5: WARNING: deny path rule can never fire" <<<"$o" \
  && pass "Warden warns: a deny shadowed by a broader glob allow" || flunk "Warden warns: a deny shadowed by a broader glob allow"
grep -q "(2 can never fire)" <<<"$o" && pass "load summary counts both" || flunk "load summary counts both"
w="$("$VDP" "$OUT/dead.txt" analyze | grep '"line":4,' | sed -n 's/.*"witness":"\([0-9a-f]*\)".*/\1/p')"
[ "$(printf '%s' "$w" | python3 -c 'import sys; print(bytes.fromhex(sys.stdin.read()).decode())')" = /tmp/ ] \
  && pass "analyze gives a shortest witness for a reachable rule (/tmp/)" || flunk "analyze witness for line 4 (got '$w')"

echo "== 3. parser: refusals, and v1.13 meaning kept =="
refuse() { printf '%s\n' "$2" > "$OUT/r.txt"; o="$("$WARDEN" "$OUT/r.txt" -- /bin/true 2>&1 || true)"
           if grep -q "$3" <<<"$o" && ! grep -q "supervising pid=" <<<"$o"; then pass "$1"; else flunk "$1 ($(head -1 <<<"$o"))"; fi; }
refuse "unterminated class refused"           'deny path glob /tmp/[ab'          "unterminated '\[' in a glob"
refuse "'/' in a class refused"               'deny path glob /tmp/[a/]x'        "'/' in a glob class never matches"
refuse "*** refused"                          'deny path glob /tmp/***'          "'\*\*\*' in a glob is ambiguous"
refuse "lone backslash refused"               'deny path glob /tmp/a\'           "lone backslash"
refuse "reversed range refused"               'deny path glob /tmp/[z-a]'        "bad range"
refuse "33 wildcards refused"                 "deny path glob /tmp/$(printf '?%.0s' $(seq 1 33))" "more than 32 wildcards"
refuse "matcher on a host rule refused"       'deny host suffix .example.com'    "matcher 'suffix' on a host rule"
refuse "flag clause on an exec glob refused"  'deny exec glob /usr/bin/* readonly' "flag clause 'readonly' on a non-path rule"
refuse "require warden 1.99 refused"          $'require warden 1.99\nallow path /tmp/' "policy requires Warden 1.99; this is 1.1[4-9]"
refuse "require warden +1.14 refused"         $'require warden +1.14\nallow path /tmp/' "bad directive"
refuse "under 1.14, a matcher with no constant is an error" $'require warden 1.14\ndeny path glob' "matcher 'glob' without a constant"
refuse "under 1.14, a constant eaten by a '#' comment is an error" $'require warden 1.14\ndeny path suffix #.pem' "matcher 'suffix' without a constant"
{ echo 'require warden 1.14'; for i in $(seq 1 17); do printf 'deny path glob /%s*\n' "$(head -c 3998 /dev/zero | tr '\0' "$(printf "\\$(printf '%03o' $((97 + i)))")")"; done; } > "$OUT/cap.txt"
o="$("$WARDEN" "$OUT/cap.txt" -- /bin/true 2>&1 || true)"
grep -q "glob patterns total more than 65536 tokens" <<<"$o" && ! grep -q "supervising pid=" <<<"$o" \
  && pass "glob patterns over 65536 tokens in all refused (bounds the work per decision)" || flunk "glob token cap ($(head -1 <<<"$o"))"
printf 'allow path glob readonly\n' > "$OUT/kw.txt"
printf 'path 0x0 %s\npath 0x0 %s\npath 0x1 %s\n' "$(printf globx | od -An -tx1 | tr -d ' \n')" \
       "$(printf /tmp/x | od -An -tx1 | tr -d ' \n')" "$(printf globx | od -An -tx1 | tr -d ' \n')" > "$OUT/kwq"
r="$("$VDP" "$OUT/kw.txt" batch < "$OUT/kwq" | cut -d, -f1 | tr '\n' ' ')"
[ "$r" = '{"verdict":"SATISFIED" {"verdict":"UNKNOWN" {"verdict":"UNKNOWN" ' ] \
  && pass "'allow path glob readonly' is still the v1.13 prefix rule for \"glob\"" || flunk "keyword-as-constant kept its v1.13 meaning (got $r)"

echo "== 4. shipped policies lint clean; v1.13.0 policies keep their verdicts =="
for p in "$HERE"/policy.txt "$HERE"/conformance_policy.txt "$HERE"/policies/*.txt; do
    o="$("$VDP" "$p" lint 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ] && ! grep -q "not decided" <<<"$o"; then
        pass "$(basename "$p"): every rule decided reachable"
    else
        flunk "$(basename "$p"): every rule decided reachable ($(grep -m1 -E 'never fire|not decided' <<<"$o"))"
    fi
done
if git -C "$HERE" rev-parse -q --verify v1.13.0^{commit} >/dev/null 2>&1; then
    old="$OUT/old"; mkdir -p "$old/tools"
    for f in smt_decide.c smt_decide.h tools/vdp_check.c; do git -C "$HERE" show "v1.13.0:varek/v1_4/$f" > "$old/$f"; done
    if cc -O2 -o "$old/vdp_check" "$old/tools/vdp_check.c" "$old/smt_decide.c" 2>/dev/null; then
        python3 - "$HERE" "$VDP" "$old/vdp_check" <<'PY' > "$OUT/compat" 2>&1
import glob, json, random, subprocess, sys
here, new, old = sys.argv[1:4]
pols = sorted(glob.glob(f"{here}/harness/baseline-v1.13.0/*.txt") + glob.glob(f"{here}/harness/baseline-v1.12.4/*.txt")
              + [f"{here}/tests/v1130_policy.txt", f"{here}/tests/crosscheck_bound_policy.txt", f"{here}/policy.txt",
                 f"{here}/tests/v1140_compat_policy.txt"])
rng = random.Random(1140); n = 0; bad = 0
for p in pols:
    consts = [l.split()[2] for l in open(p, encoding="latin-1") if l.split()[:1] in (["allow"], ["deny"])]
    qs = []
    for _ in range(300):
        k = rng.choice(["path"] * 4 + ["host", "exec"])
        s = rng.choice(consts) + rng.choice(["", "x", "/a", ".pem", ":443", "/.ssh/k"]) if consts else "/x"
        s = s[: rng.randint(1, len(s))] if rng.random() < 0.2 else s
        f = rng.choice(["-", "0x0", "0x1", "0x2", "0x241", "0x8000", "0x200000"])
        qs.append(f"{k} {f} {s.encode('latin-1').hex()}")
    inp = "\n".join(qs) + "\n"
    a = subprocess.run([new, p, "batch"], input=inp, capture_output=True, text=True).stdout
    b = subprocess.run([old, p, "batch"], input=inp, capture_output=True, text=True).stdout
    ra = subprocess.run([new, p, "analyze"], capture_output=True, text=True).stdout
    rb = subprocess.run([old, p, "analyze"], capture_output=True, text=True).stdout
    strip = lambda t: [ {k: v for k, v in json.loads(l).items() if k in ("index","line","kind","verb","reach")} for l in t.splitlines() ]
    n += len(qs)
    if a != b or strip(ra) != strip(rb):
        bad += 1; print("DIFF", p)
print(f"compat: {len(pols)} policies, {n} queries, {bad} policies differ")
PY
        sed 's/^/    /' "$OUT/compat"
        grep -q "0 policies differ" "$OUT/compat" && pass "v1.13.0 and v1.12.4 policies: identical verdicts and reachability under v1.13.0 and v1.14" \
            || flunk "v1.13 policies keep their verdicts"
    else
        echo "    SKIP (could not build the v1.13.0 vdp_check)"
    fi
else
    echo "    SKIP compatibility check (no git or no v1.13.0 tag)"
fi

echo "== 5. --plan gate with matchers =="
printf 'require warden 1.14\ndeny path suffix .pem\nallow path /data/work/\n' > "$OUT/plan_pol.txt"
plan() { printf 'action a file_open %s\n' "$1" > "$OUT/plan.txt"
         "$WARDEN" "$OUT/plan_pol.txt" --plan "$OUT/plan.txt" -- /bin/true 2>&1 | sed -n 's/.*"type":"plan_verify".*"decision":"\([A-Z]*\)".*/\1/p' | head -1; }
[ "$(plan /data/work/a.txt)" = SATISFIED ] && pass "planned open of a workspace file: SATISFIED" || flunk "planned open of a workspace file: SATISFIED"
[ "$(plan /data/work/k/server.pem)" = UNSATISFIED ] && pass "planned open of a .pem file: UNSATISFIED" || flunk "planned open of a .pem file: UNSATISFIED"

echo "== 6. decision procedure vs solver and derivative oracle =="
if python3 -c 'import z3' 2>/dev/null; then
    o="$(python3 "$HERE/tools/smt_crosscheck.py" --vdp "$VDP" --fuzz 25 --seed 1140 --queries 40 \
         "$HERE"/policies/*.txt "$HERE"/tests/*policy*.txt 2>&1)"
    echo "$o" | sed 's/^/    /' | tail -3
    grep -q "smt_crosscheck: PASS (0 disagreements)" <<<"$o" && pass "zero disagreements" || flunk "zero disagreements"
else
    flunk "python3 module z3 not found (pip install z3-solver): the solver cross-check is required"
fi

echo "== 7. verdict-distribution harness gate =="
o="$(cd "$HERE" && python3 tools/verdict_harness.py --vdp "$VDP" harness/corpus/ 2>&1)"
echo "$o" | sed 's/^/    /' | grep -v "over-refusal" | head -7
grep -q "gate unsafe_satisfied == 0: PASS" <<<"$o" && pass "harness gate unsafe_satisfied == 0" || flunk "harness gate unsafe_satisfied == 0"

echo
if [ "$fail" -eq 0 ]; then echo "test_v1140: PASS"; else echo "test_v1140: FAIL"; fi
exit "$fail"
