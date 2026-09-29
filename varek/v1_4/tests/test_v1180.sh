#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1180.sh — regression test for VAREK v1.18.0: where the published claims
# and the code disagreed, the code or the claim is fixed, and this checks the
# code side of each.
#
#   1. The --plan gate calls a connect or launch step UNSATISFIED: the runtime
#      refuses those whatever the policy says.
#   2. --flow-policy runs the v1.7 data-flow check, the v1.8.2 refusal breaker
#      (state kept across runs and replaced atomically, the lock held for the
#      gate only, protected from the agent) and the v1.9 progress-safety check
#      in the Warden; --gate-status reports the outcome apart from the agent's
#      exit status.
#   3. A refusal's record says the errno the agent received (EACCES).
#   4. The CycloneDX export: attestation derived from the stream, the policy
#      file checked against the Warden's, a JSF Ed25519 signature that
#      verifies only under a key the caller gives and catches tampering, the
#      stream's own signatures checked under that key, CycloneDX 1.6
#      schema-valid, and a stream that authorizes an UNKNOWN refused.
#   5. The Python suites collect (v1.2 prototype, v1.1 regression) and the
#      v1.0 names the v1.1 CHANGELOG kept are importable.
#
# Usage: ./test_v1180.sh <warden> <vdp_cert_check> <varek_keygen> <probe>
# Exit 0 iff every check holds.
set -u

WARDEN="${1:?usage: test_v1180.sh <warden> <vdp_cert_check> <varek_keygen> <probe>}"
CERT="${2:?}"
KEYGEN="${3:?}"
PROBE="${4:?}"
abs() { case "$1" in /*) echo "$1";; *) echo "$PWD/$1";; esac; }
WARDEN="$(abs "$WARDEN")"; CERT="$(abs "$CERT")"; KEYGEN="$(abs "$KEYGEN")"; PROBE="$(abs "$PROBE")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
AUDIT="$HERE/tools/varek_audit.py"
CDX="$HERE/tools/varek_cyclonedx.py"
SCHEMA="$HERE/tests/cdx_schema_check.py"
RECHAIN="$HERE/tests/log_rechain.py"

fail=0
pass()  { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
nocheck() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then flunk "$d"; else pass "$d"; fi; }

D=/tmp/varek_v1180
OUT="$(mktemp -d)"
cleanup() { umount "$D/data/alias" 2>/dev/null; rm -rf "$D" "$OUT"; }
trap cleanup EXIT
umount "$D/data/alias" 2>/dev/null; rm -rf "$D"
mkdir -p "$D/data/secret" "$D/data/public" "$D/state"
chmod 755 "$D" "$D/data" "$D/data/secret" "$D/data/public"
chmod 700 "$D/state"
echo "top secret" > "$D/data/secret/k"
echo "hello" > "$D/data/public/ok.txt"
chmod 644 "$D/data/secret/k" "$D/data/public/ok.txt"

POL="$D/policy.txt"
cat > "$POL" <<'EOF'
allow path /tmp/varek_v1180/data/
allow exec /usr/bin/python3
allow host 127.0.0.1:8080
EOF
FLOW="$D/flow.cfg"
cat > "$FLOW" <<'EOF'
varek_policy 1
label SECRET 0
sticky SECRET
refusal_budget 2
on_exhaustion terminal abort_txn
unknown_disposition deny
rule file_open
  match target /tmp/varek_v1180/data/secret/*
  origin SECRET
rule file_open
  match target /tmp/varek_v1180/data/public/*
  deny_in SECRET
rule file_open
rule abort_txn
EOF
STATE="$D/state/breaker"
plan() { printf '%s\n' "$2" > "$D/$1"; }
plan leak.txt 'action read  file_open /tmp/varek_v1180/data/secret/k
action write file_open /tmp/varek_v1180/data/public/out
edge read write'
plan apart.txt 'action read  file_open /tmp/varek_v1180/data/secret/k
action write file_open /tmp/varek_v1180/data/public/out'
plan dotdot.txt 'action read  file_open /tmp/varek_v1180/data/public/../secret/k
action write file_open /tmp/varek_v1180/data/public/out
edge read write'

# gate <session> <plan> [extra warden args...]: run the gated Warden with the
# probe (its arguments in PARGS); set RC and G (the Warden's stderr).
PARGS=()
gate() {
    local s="$1" p="$2"; shift 2
    "$WARDEN" "$POL" --plan "$D/$p" --flow-policy "$FLOW" --breaker-state "$STATE" \
        --session "$s" "$@" -- "$PROBE" "${PARGS[@]}" > "$OUT/gate.out" 2> "$OUT/gate.err"
    RC=$?
    G="$(cat "$OUT/gate.err")"
}
has() { grep -q -- "$1" <<<"$G"; }
gate_rec() { grep '^{"event":"plan_gate"' "$OUT/gate.err" | head -1; }

echo "== 1. connect and launch steps are UNSATISFIED at the plan gate =="
plan conn.txt 'action read file_open /tmp/varek_v1180/data/public/ok.txt
action post net_connect 127.0.0.1:8080
edge read post'
"$WARDEN" "$POL" --plan "$D/conn.txt" -- "$PROBE" > "$OUT/c.out" 2> "$OUT/c.err"; rc=$?
check "a policy-allowed connect step rejects the plan"      grep -q 'plan rejected (UNSATISFIED)' "$OUT/c.err"
check "the gate says the runtime refuses every connect"     grep -q 'refuses every connect at runtime' "$OUT/c.err"
nocheck "the agent is not started"                          grep -q 'supervising pid=' "$OUT/c.err"
[ "$rc" -ne 0 ] && pass "the Warden exits non-zero ($rc)" || flunk "the Warden exits non-zero"
plan exec.txt 'action run process_exec /usr/bin/python3'
"$WARDEN" "$POL" --plan "$D/exec.txt" -- "$PROBE" > /dev/null 2> "$OUT/x.err"
check "a policy-allowed launch step is UNSATISFIED"         grep -q 'plan rejected (UNSATISFIED)' "$OUT/x.err"
plan files.txt 'action a file_open /tmp/varek_v1180/data/public/ok.txt'
"$WARDEN" "$POL" --plan "$D/files.txt" -- "$PROBE" > /dev/null 2> "$OUT/f.err"
check "a file-only plan is still authorized"                grep -q 'plan authorized (1 actions)' "$OUT/f.err"

echo "== 2. --flow-policy: data flow, refusal breaker, progress safety =="
"$WARDEN" "$POL" --flow-policy "$FLOW" -- "$PROBE" > /dev/null 2> "$OUT/e.err"; rc=$?
[ "$rc" -eq 2 ] && grep -q 'give --plan too' "$OUT/e.err" && pass "--flow-policy without --plan is a usage error" \
    || flunk "--flow-policy without --plan is a usage error (rc=$rc)"
"$WARDEN" "$POL" --plan "$D/files.txt" --session s -- "$PROBE" > /dev/null 2> "$OUT/e.err"; rc=$?
[ "$rc" -eq 2 ] && grep -q 'need --flow-policy' "$OUT/e.err" && pass "--session without --flow-policy is a usage error" \
    || flunk "--session without --flow-policy is a usage error (rc=$rc)"

printf 'varek_policy 1\nlabel SECRET 0\nsticky SECRET\nrefusal_budget 2\non_exhaustion terminal no_such_action\nrule file_open\n' > "$D/unsafe.cfg"
"$WARDEN" "$POL" --plan "$D/files.txt" --flow-policy "$D/unsafe.cfg" --breaker-state "$D/state/u" -- "$PROBE" > /dev/null 2> "$OUT/e.err"; rc=$?
[ "$rc" -eq 1 ] && grep -q 'is not progress-safe' "$OUT/e.err" && pass "a flow policy that is not progress-safe stops the Warden at startup" \
    || flunk "a flow policy that is not progress-safe stops the Warden at startup (rc=$rc)"
printf 'varek_policy 1\nrule file_open\n' > "$D/nobudget.cfg"
"$WARDEN" "$POL" --plan "$D/files.txt" --flow-policy "$D/nobudget.cfg" --breaker-state "$D/state/n" -- "$PROBE" > /dev/null 2> "$OUT/e.err"; rc=$?
[ "$rc" -eq 1 ] && grep -q 'declares no refusal_budget' "$OUT/e.err" && pass "a flow policy with no refusal_budget stops the Warden" \
    || flunk "a flow policy with no refusal_budget stops the Warden (rc=$rc)"

gate s1 leak.txt --gate-status "$D/state/gs"
[ "$RC" -eq 3 ] && pass "a plan routing SECRET to public is refused, retryable (exit 3)" || flunk "a plan routing SECRET to public is refused, retryable (exit $RC)"
has 'node SATISFIED, flow UNSATISFIED' && pass "the refusal is on the flow axis, the node axis passes" || flunk "the refusal is on the flow axis"
has 'plan flow pathology: {' && pass "the flow pathology names the offending flow" || flunk "the flow pathology names the offending flow"
has 'plan rejected' && ! has 'supervising pid=' && pass "the agent is not started" || flunk "the agent is not started"
R="$(gate_rec)"
grep -q '"breaker":"REFUSED_RETRYABLE","refusals":1,"budget":2' <<<"$R" && pass "plan_gate record: REFUSED_RETRYABLE, 1 of 2" || flunk "plan_gate record: REFUSED_RETRYABLE, 1 of 2 ($R)"
[ "$(cat "$D/state/gs" 2>/dev/null)" = "REFUSED_RETRYABLE 1/2" ] && pass "--gate-status says REFUSED_RETRYABLE 1/2" || flunk "--gate-status says REFUSED_RETRYABLE 1/2 ($(cat "$D/state/gs" 2>/dev/null))"
check "the breaker state holds its header and trailer" grep -qx 'end 1' "$STATE"

gate s1 leak.txt
[ "$RC" -eq 5 ] && has 'pre-authorized action abort_txn' && pass "the second refusal, in a new Warden run, spends the budget: terminal abort_txn (exit 5)" \
    || flunk "the second refusal spends the budget: terminal abort_txn (exit $RC)"
gate s1 leak.txt
R="$(gate_rec)"
[ "$RC" -eq 5 ] && grep -q '"refusals":2' <<<"$R" && pass "the latch holds on a third run, without re-counting" || flunk "the latch holds on a third run (exit $RC; $R)"
plan reorder.txt 'action write file_open /tmp/varek_v1180/data/public/out
action read  file_open /tmp/varek_v1180/data/secret/k
edge read write
edge read write'
gate s1 reorder.txt
[ "$RC" -eq 5 ] && pass "the same graph with its steps reordered and an edge repeated hits the same latch" \
    || flunk "a reordered, repeated-edge copy of the graph hits the same latch (exit $RC)"
gate s2 leak.txt
[ "$RC" -eq 3 ] && pass "another session keeps its own count" || flunk "another session keeps its own count (exit $RC)"
PARGS=(--exit 5)
gate s1 apart.txt --gate-status "$D/state/gs"
PARGS=()
[ "$RC" -eq 5 ] && has 'plan authorized (2 actions; node SATISFIED, flow SATISFIED)' && has 'supervising pid=' \
    && pass "the same steps without the leaking edge are authorized and the agent runs" || flunk "the same steps without the edge are authorized (exit $RC)"
[ "$(cat "$D/state/gs" 2>/dev/null)" = "PASS" ] && pass "--gate-status says PASS although the agent itself exited 5" \
    || flunk "--gate-status says PASS although the agent exited 5 ($(cat "$D/state/gs" 2>/dev/null))"
gate s1 leak.txt
[ "$RC" -eq 5 ] && pass "authorizing that different graph did not clear the leaking plan's latch" || flunk "the leaking plan's latch survives an authorized different graph (exit $RC)"
gate s3 dotdot.txt
[ "$RC" -eq 3 ] && pass "a flow rule is not stepped around with '..' (the target is canonical)" || flunk "a flow rule is not stepped around with '..' (exit $RC)"

# The table is replaced atomically: a Warden killed while writing it (here by a
# file-size limit on the Warden alone; its stderr goes to a pipe, which the
# limit does not cover) leaves the previous table, and the count holds.
cp "$STATE" "$OUT/before.state"
python3 -c '
import resource, subprocess, sys
r = subprocess.run(sys.argv[1:], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                   preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)))
sys.stdout.write(r.stderr.decode(errors="replace"))
print("rc=%d" % r.returncode)' "$WARDEN" "$POL" --plan "$D/leak.txt" --flow-policy "$FLOW" \
    --breaker-state "$STATE" --session s4 -- "$PROBE" > "$OUT/xfsz.out" 2>&1
grep -q 'plan flow pathology' "$OUT/xfsz.out" && grep -qx 'rc=-25' "$OUT/xfsz.out" \
    && pass "a Warden is killed (SIGXFSZ) while writing the table, after deciding the plan" \
    || flunk "a Warden is killed (SIGXFSZ) while writing the table ($(tail -1 "$OUT/xfsz.out"))"
check "that interrupted write left the previous table" cmp -s "$STATE" "$OUT/before.state"
gate s1 leak.txt
[ "$RC" -eq 5 ] && pass "and the latch still holds after it" || flunk "the latch holds after an interrupted write (exit $RC)"

cp "$STATE" "$OUT/state.bak"
: > "$STATE"
gate s1 apart.txt --gate-status "$D/state/gs"
[ "$RC" -eq 1 ] && has 'does not read back' && ! has 'supervising pid=' && pass "an empty table is refused, not read as a new one (exit 1)" \
    || flunk "an empty table is refused (exit $RC)"
[ "$(cat "$D/state/gs" 2>/dev/null)" = "ERROR breaker_state" ] && pass "--gate-status says ERROR breaker_state" || flunk "--gate-status says ERROR breaker_state ($(cat "$D/state/gs" 2>/dev/null))"
head -n -1 "$OUT/state.bak" > "$STATE"
gate s1 apart.txt
[ "$RC" -eq 1 ] && has 'does not read back' && pass "a table cut at a line boundary is refused" || flunk "a table cut at a line boundary is refused (exit $RC)"
printf 'varek-breaker 1\ngarbage\n' > "$STATE"
gate s1 apart.txt
[ "$RC" -eq 1 ] && has 'state fault' && pass "a malformed table is refused as a state fault" || flunk "a malformed table is refused as a state fault (exit $RC)"
cp "$OUT/state.bak" "$STATE"
chmod 666 "$STATE"
gate s1 apart.txt
[ "$RC" -eq 1 ] && has 'writable by no one else' && pass "a table others can write stops the Warden" || flunk "a table others can write stops the Warden (exit $RC)"
chmod 600 "$STATE"
chmod 777 "$D/state"
gate s1 apart.txt
[ "$RC" -eq 1 ] && has 'directory' && has 'writable by no one else' && pass "a state directory others can write stops the Warden" \
    || flunk "a state directory others can write stops the Warden (exit $RC)"
chmod 700 "$D/state"
ln -sf "$STATE" "$D/state/link"
"$WARDEN" "$POL" --plan "$D/apart.txt" --flow-policy "$FLOW" --breaker-state "$D/state/link" -- "$PROBE" > /dev/null 2> "$OUT/l.err"; rc=$?
[ "$rc" -eq 1 ] && grep -q 'not a symlink' "$OUT/l.err" && pass "a symlinked table is refused" || flunk "a symlinked table is refused (rc=$rc)"

# The lock covers the gate only: a second Warden gates while the first agent runs.
"$WARDEN" "$POL" --plan "$D/apart.txt" --flow-policy "$FLOW" --breaker-state "$STATE" --session s5 \
    -- "$PROBE" --sleep 4 > "$OUT/bg.out" 2> "$OUT/bg.err" &
bg=$!
sleep 1.5
t0=$(date +%s%N)
gate s6 leak.txt
t1=$(date +%s%N)
wait "$bg"
grep -q 'supervising pid=' "$OUT/bg.err" || flunk "the first Warden's agent ran (setup for the next check)"
ms=$(( (t1 - t0) / 1000000 ))
[ "$RC" -eq 3 ] && [ "$ms" -lt 2000 ] && pass "a second Warden is not held up by the first one's agent (${ms} ms)" \
    || flunk "a second Warden is not held up by the first one's agent (exit $RC, ${ms} ms)"

# A policy that reaches the state directory is refused at startup.
OPENPOL="$D/open_policy.txt"
printf 'allow path /tmp/varek_v1180/\n' > "$OPENPOL"
"$WARDEN" "$OPENPOL" --plan "$D/apart.txt" --flow-policy "$FLOW" --breaker-state "$STATE" -- "$PROBE" > /dev/null 2> "$OUT/o.err"; rc=$?
[ "$rc" -eq 1 ] && grep -q 'would let the agent open the breaker state' "$OUT/o.err" && pass "a policy that allows the state directory stops the Warden" \
    || flunk "a policy that allows the state directory stops the Warden (rc=$rc)"
# Through another name (a bind mount into an allowed tree), the table is refused by identity.
mkdir -p "$D/data/alias"
mount --bind "$D/state" "$D/data/alias"
PARGS=("$D/data/alias/breaker" "$D/data/public/ok.txt")
gate s9 apart.txt
PARGS=()
cp "$OUT/gate.err" "$OUT/p.err"
check "the agent is refused the table through a bind mount" grep -q "^PROBE open $D/data/alias/breaker REFUSED EACCES" "$OUT/gate.out"
check "that refusal is recorded as protected_object" grep -q "\"target\":\"$D/data/alias/breaker\".*\"rule\":\"protected_object\"" "$OUT/p.err"
check "an ordinary allowed file still opens" grep -q "^PROBE open $D/data/public/ok.txt OK hello" "$OUT/gate.out"
umount "$D/data/alias"
python3 "$AUDIT" --policy "$POL" --checker "$CERT" "$OUT/p.err" > "$OUT/p.audit" 2>&1 \
    && pass "varek_audit accepts a stream holding a plan_gate record" || flunk "varek_audit accepts a stream holding a plan_gate record ($(tail -2 "$OUT/p.audit"))"

echo "== 3. a refusal records the errno the agent received =="
DENYPOL="$D/deny_policy.txt"
printf 'deny  path /tmp/varek_v1180/data/secret/\nallow path /tmp/varek_v1180/data/\n' > "$DENYPOL"
"$KEYGEN" "$D/state/log.key" > /dev/null
"$WARDEN" "$DENYPOL" --sign-key "$D/state/log.key" -- "$PROBE" "$D/data/secret/k" "$D/data/public/ok.txt" /etc/hostname \
    > "$OUT/r.out" 2> "$OUT/run.log"
check "the agent gets EACCES for a denied file" grep -q "^PROBE open $D/data/secret/k REFUSED EACCES (13)" "$OUT/r.out"
check "its record says kernel_verdict EACCES, errno 13" \
    grep -q "\"target\":\"$D/data/secret/k\".*\"decision_final\":\"DENY\".*\"kernel_verdict\":\"EACCES\",\"errno\":13" "$OUT/run.log"
nocheck "no record says kernel_verdict EPERM" grep -q '"kernel_verdict":"EPERM"' "$OUT/run.log"

echo "== 4. the CycloneDX export =="
python3 "$CDX" --log "$OUT/run.log" --agent v1180_probe --policy "$DENYPOL" --output "$OUT/bom.json" 2> "$OUT/x.err" \
    && pass "the exporter accepts the run" || flunk "the exporter accepts the run ($(cat "$OUT/x.err"))"
TXT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["annotations"][0]["text"])' "$OUT/bom.json" 2>/dev/null)"
grep -q 'equal to the file named' <<<"$TXT" && pass "the attestation says the policy file matches the Warden's" || flunk "the attestation says the policy file matches ($TXT)"
grep -q 'UNKNOWN verdict(s) were refused' <<<"$TXT" && pass "the attestation counts the UNKNOWN verdicts and says they were refused" || flunk "the attestation counts the UNKNOWN verdicts"
grep -q 'are not recorded' <<<"$TXT" && pass "the attestation says which calls the record does not cover" || flunk "the attestation states its scope"
grep -q 'no action reached the kernel without a verdict' <<<"$TXT" && flunk "the old fixed claim is gone" || pass "the old fixed claim is gone"
python3 "$CDX" --log "$OUT/run.log" --agent a --policy "$POL" --output "$OUT/bad.json" 2> "$OUT/x.err"; rc=$?
[ "$rc" -ne 0 ] && grep -q 'decided with' "$OUT/x.err" && pass "a --policy file that is not the one the Warden used is refused" \
    || flunk "a --policy file that is not the one the Warden used is refused (rc=$rc)"

python3 "$CDX" --log "$OUT/run.log" --agent v1180_probe --policy "$DENYPOL" --sign-key "$D/state/log.key" \
    --pubkey "$D/state/log.key.pub" --output "$OUT/signed.json" 2> "$OUT/x.err" \
    && pass "the exporter checks the stream's signatures and signs with the log key" || flunk "the exporter checks and signs ($(cat "$OUT/x.err"))"
STXT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["annotations"][0]["text"])' "$OUT/signed.json" 2>/dev/null)"
grep -q 'verify under the key given' <<<"$STXT" && pass "the attestation says the stream's signatures verified" || flunk "the attestation says the stream's signatures verified"
grep -q 'not checked here' <<<"$TXT" && pass "without --pubkey it says the signatures were not checked" || flunk "without --pubkey it says the signatures were not checked ($TXT)"
python3 "$CDX" --verify "$OUT/signed.json" --pubkey "$D/state/log.key.pub" > "$OUT/v.out" 2>&1 \
    && pass "the BOM's signature verifies under the Warden's public key" || flunk "the BOM's signature verifies ($(cat "$OUT/v.out"))"
python3 "$CDX" --verify "$OUT/signed.json" > /dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && pass "--verify without --pubkey is refused (the BOM's own key proves nothing)" || flunk "--verify without --pubkey is refused (rc=$rc)"
python3 -c '
import json, sys
b = json.load(open(sys.argv[1]))
b["annotations"][0]["text"] = b["annotations"][0]["text"].replace("refused", "authorized", 1)
json.dump(b, open(sys.argv[2], "w"), indent=2)' "$OUT/signed.json" "$OUT/tampered.json"
nocheck "a changed attestation fails verification" python3 "$CDX" --verify "$OUT/tampered.json" --pubkey "$D/state/log.key.pub"
python3 -c '
import sys
t = open(sys.argv[1]).read()
open(sys.argv[2], "w").write(t.replace("\"bomFormat\": \"CycloneDX\",", "\"bomFormat\": \"CycloneDX\", \"bomFormat\": \"CycloneDX\",", 1))' "$OUT/signed.json" "$OUT/dup.json"
nocheck "a BOM with a duplicated key fails verification" python3 "$CDX" --verify "$OUT/dup.json" --pubkey "$D/state/log.key.pub"
"$KEYGEN" "$D/state/other.key" > /dev/null
nocheck "a different --pubkey fails verification" python3 "$CDX" --verify "$OUT/signed.json" --pubkey "$D/state/other.key.pub"
nocheck "an unsigned BOM does not verify" python3 "$CDX" --verify "$OUT/bom.json" --pubkey "$D/state/log.key.pub"
# A stream whose signatures were stripped (the chain does not cover them), and
# one re-signed under another key, are refused under the Warden's key.
python3 -c '
import re, sys
t = open(sys.argv[1], encoding="utf-8", errors="surrogateescape").read()
open(sys.argv[2], "w", encoding="utf-8", errors="surrogateescape").write(re.sub(r",\"sig\":\"[0-9a-f]{128}\"", "", t))' "$OUT/run.log" "$OUT/nosig.log"
python3 "$CDX" --log "$OUT/nosig.log" --policy "$DENYPOL" --pubkey "$D/state/log.key.pub" --output "$OUT/r.json" 2> "$OUT/x.err"; rc=$?
[ "$rc" -ne 0 ] && grep -q 'not signed' "$OUT/x.err" && pass "a stream with its signatures stripped is refused under the Warden's key" \
    || flunk "a stream with its signatures stripped is refused under the Warden's key (rc=$rc)"
if python3 -c 'import cryptography' 2>/dev/null; then
    python3 "$RECHAIN" --resign "$D/state/other.key" "$OUT/run.log" > "$OUT/resigned.log" 2>/dev/null
    python3 "$CDX" --log "$OUT/resigned.log" --policy "$DENYPOL" --pubkey "$D/state/log.key.pub" --output "$OUT/r.json" 2> "$OUT/x.err"; rc=$?
    [ "$rc" -ne 0 ] && pass "a stream re-signed with another key is refused under the Warden's key" \
        || flunk "a stream re-signed with another key is refused under the Warden's key"
fi
python3 "$SCHEMA" "$OUT/bom.json" "$OUT/signed.json" > "$OUT/s.out" 2>&1; rc=$?
if [ "$rc" -eq 0 ]; then pass "unsigned and signed BOMs are valid CycloneDX 1.6"
elif [ "$rc" -eq 2 ]; then flunk "CycloneDX schema validation (validator missing: pip install -r tools/requirements-test.txt)"
else flunk "unsigned and signed BOMs are valid CycloneDX 1.6 ($(cat "$OUT/s.out"))"; fi

# A stream that authorizes an UNKNOWN (edited, chain recomputed) is refused.
python3 - "$OUT/run.log" "$OUT/forged.log" <<'PY'
import json, re, sys
out = []
done = False
for line in open(sys.argv[1], encoding="utf-8", errors="surrogateescape"):
    if not done and '"decision_raw":"UNKNOWN"' in line and '"decision_final":"DENY"' in line:
        line = line.replace('"decision_final":"DENY"', '"decision_final":"ALLOW"', 1)
        done = True
    out.append(line)
open(sys.argv[2], "w", encoding="utf-8", errors="surrogateescape").writelines(out)
sys.exit(0 if done else 1)
PY
if python3 "$RECHAIN" "$OUT/forged.log" > "$OUT/forged2.log" 2>/dev/null; then
    python3 "$CDX" --log "$OUT/forged2.log" --policy "$DENYPOL" --output "$OUT/f.json" 2> "$OUT/x.err"; rc=$?
    [ "$rc" -ne 0 ] && grep -q 'symmetric suppression' "$OUT/x.err" && pass "a stream that authorizes an UNKNOWN is refused" \
        || flunk "a stream that authorizes an UNKNOWN is refused (rc=$rc: $(cat "$OUT/x.err"))"
else
    flunk "could not build the forged stream"
fi

echo "== 5. the Python suites collect; v1.0 names are importable =="
( cd "$REPO" && python3 -m pytest -q -p no:cacheprovider --collect-only tests > "$OUT/py.out" 2>&1 ); rc=$?
[ "$rc" -eq 0 ] && pass "pytest collects the repository's tests without errors" || flunk "pytest collects without errors ($(tail -3 "$OUT/py.out"))"
( cd "$REPO" && python3 -m pytest -q -p no:cacheprovider tests/v1_2 > "$OUT/py2.out" 2>&1 ) \
    && pass "the v1.2 prototype's tests pass" || flunk "the v1.2 prototype's tests pass ($(tail -3 "$OUT/py2.out"))"
( cd "$REPO" && python3 -c 'from varek_warden import enforce_strict_mode, KineticIntercept, subscribe_telemetry; enforce_strict_mode(); enforce_strict_mode()' ) \
    && pass "enforce_strict_mode and KineticIntercept import (and arm twice harmlessly)" || flunk "enforce_strict_mode and KineticIntercept import"

echo
if [ "$fail" -eq 0 ]; then echo "ALL PASSED (v1.18.0)"; else echo "FAILURES PRESENT"; fi
exit "$fail"
