#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1160.sh — regression test for VAREK v1.16: a verdict stream its holder
# cannot rewrite undetected, and a bound on the work of one decision.
#
#   1. A live run with --sign-key and --anchor: every record is hash-chained,
#      run_start / checkpoints / run_end are Ed25519-signed and anchored, and
#      the audit reports "signed, anchored".
#   2. Someone holding the log but not the key: an edited record breaks the
#      chain; with the chain recomputed, the signatures fail; a log cut short
#      has no signed run_end; a log re-signed with another key fails against
#      the pinned key.
#   3. Someone holding the log AND the key: a rewritten, re-signed log passes
#      the signature check but fails against the anchor.
#   4. Anchor failures are recorded (anchor_error for a full FIFO; a status
#      line at exit for records no reader took) and fail the anchored audit;
#      supervision is not affected.
#   5. The Warden refuses to start when the policy would let the agent open the
#      signing key, the anchor, the verdict stream itself or a raw block device,
#      or when the key is not private, has a second name, or is malformed.
#   6. Glob tokens are capped at 4,096 per policy, by the Warden's decision
#      procedure, the certificate checker and vdp_check alike.
#   7. The audit's Ed25519 verifier (tools/varek_ed25519.py) passes the RFC 8032
#      test vectors and agrees with OpenSSL (Python "cryptography") when present.
#
# Usage: ./test_v1160.sh <warden> <vdp_check> <vdp_cert_check> <varek_keygen> <probe>
set -u

WARDEN="${1:?usage: test_v1160.sh <warden> <vdp_check> <vdp_cert_check> <varek_keygen> <probe>}"
VDP="${2:?}"
CERT="${3:?}"
KEYGEN="${4:?}"
PROBE="${5:?}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
POL="$HERE/tests/v1160_policy.txt"
AUDIT="$HERE/tools/varek_audit.py"
RECHAIN="$HERE/tests/log_rechain.py"

fail=0
pass() { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }
skip() { printf '  %-6s %s\n' SKIP "$1"; }

OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"; rm -rf /tmp/varek_v1160' EXIT
D=/tmp/varek_v1160
rm -rf "$D"; mkdir -p "$D/data" "$D/keys"
for i in $(seq 1 12); do echo "file $i" > "$D/data/f$i"; done
echo "do not read" > "$D/data/secret"
FILES=("$D"/data/f{1..12} "$D/data/secret")

"$KEYGEN" "$D/keys/k1" > "$OUT/k1.out" && "$KEYGEN" "$D/keys/k2" > /dev/null
[ "$(stat -c %a "$D/keys/k1")" = 600 ] && [ "$(cat "$D/keys/k1.pub")" = "$(cat "$OUT/k1.out")" ] \
  && pass "varek_keygen writes a 0600 key and its public half" || flunk "varek_keygen output"
"$KEYGEN" "$D/keys/k1" >/dev/null 2>&1 && flunk "varek_keygen overwrites a key" \
  || pass "varek_keygen refuses to overwrite a key"
A=(python3 "$AUDIT" --policy "$POL" --checker "$CERT")
HAVE_CRYPTO=0; python3 -c "import cryptography" 2>/dev/null && HAVE_CRYPTO=1

echo "== 1. a signed, anchored run =="
timeout 30 "$WARDEN" "$POL" --sign-key "$D/keys/k1" --anchor "$D/anchor" --checkpoint-every 4 \
    -- /bin/cat "${FILES[@]}" > "$OUT/stdout" 2> "$OUT/v"
grep -q '"event":"run_start".*"log":"chain-1".*"log_pubkey":"'"$(cat "$D/keys/k1.pub")"'"' "$OUT/v" \
  && pass "run_start names the chain format and the signing key" || flunk "run_start log fields"
nck=$(grep -c '"event":"checkpoint"' "$OUT/v")
[ "$nck" -ge 3 ] && pass "checkpoints written ($nck, every 4 records)" || flunk "checkpoints written ($nck)"
nrec=$(grep -c '^{.*"run":' "$OUT/v"); nch=$(grep -c '"chain":"[0-9a-f]\{64\}"}$\|"chain":"[0-9a-f]\{64\}","sig"' "$OUT/v")
[ "$nrec" -eq "$nch" ] && pass "every record of the run carries a chain value ($nch)" || flunk "chained records ($nch of $nrec)"
nsig=$(grep -c '"sig":"[0-9a-f]\{128\}"}$' "$OUT/v"); nanc=$(wc -l < "$D/anchor")
[ "$nsig" -eq $((nck + 2)) ] && [ "$nanc" -eq "$nsig" ] \
  && pass "run_start, checkpoints and run_end signed and anchored ($nsig)" || flunk "signed $nsig, anchored $nanc"
grep -q "file 12" "$OUT/stdout" && grep -q '"target":"/tmp/varek_v1160/data/secret".*"decision_final":"DENY"' "$OUT/v" \
  && pass "the agent ran normally (12 reads allowed, the secret denied)" || flunk "agent run"
o="$("${A[@]}" --pubkey "$D/keys/k1.pub" --anchor "$D/anchor" "$OUT/v" 2>&1)"
grep -q "integrity: signed, anchored" <<<"$o" && grep -q "varek_audit: PASS" <<<"$o" \
  && pass "audit: PASS, integrity signed, anchored" || { flunk "audit of the live stream"; echo "$o" | head -5; }
o="$("${A[@]}" "$OUT/v" 2>&1)"
grep -q "key not pinned" <<<"$o" && grep -q PASS <<<"$o" \
  && pass "without --pubkey the audit says the key is not pinned" || flunk "unpinned report"

echo "== 2. holder without the key =="
# An authorized read rewritten as a read of the secret.
sed -E '0,/"target":"\/tmp\/varek_v1160\/data\/f3"/s//"target":"\/tmp\/varek_v1160\/data\/secret"/' "$OUT/v" > "$OUT/edit"
o="$("${A[@]}" --pubkey "$D/keys/k1.pub" "$OUT/edit" 2>&1)"
grep -q "hash chain broken" <<<"$o" && pass "an edited record breaks the hash chain" || flunk "edit detected by the chain"
python3 "$RECHAIN" "$OUT/edit" > "$OUT/edit2"
o="$("${A[@]}" "$OUT/edit2" 2>&1)"
grep -q "signature does not verify" <<<"$o" && grep -q FAIL <<<"$o" \
  && pass "chain recomputed: the signatures no longer verify" || flunk "rechained edit detected by the signatures"
# A record removed, with every count after it (checkpoints, run_end) and the
# chain fixed up: only the signatures catch it.
python3 - "$OUT/v" > "$OUT/drop.raw" <<'EOF'
import json, re, sys
lines = open(sys.argv[1], "rb").read().split(b"\n")
last = max(i for i, l in enumerate(lines) if b'"seq":' in l)
out = []
for i, l in enumerate(lines):
    if i == last:
        continue
    if i > last and (b'"event":"checkpoint"' in l or b'"event":"run_end"' in l):
        n = json.loads(l)["records"]
        l = l.replace(b'"records":%d,' % n, b'"records":%d,' % (n - 1), 1)
    out.append(l)
sys.stdout.buffer.write(b"\n".join(out))
EOF
python3 "$RECHAIN" "$OUT/drop.raw" > "$OUT/drop"
o="$("${A[@]}" "$OUT/drop" 2>&1)"
grep -q "signature does not verify" <<<"$o" && pass "a record removed, counts and chain fixed up: the signatures fail" \
  || { flunk "removed record detected"; echo "$o" | head -4; }
# Cut short.
# The stream cut right after its last decision record: the checkpoint and
# run_end that followed are gone.
last=$(grep -n '"seq":' "$OUT/v" | tail -1 | cut -d: -f1)
head -n "$last" "$OUT/v" > "$OUT/cut"
o="$("${A[@]}" --pubkey "$D/keys/k1.pub" "$OUT/cut" 2>&1)"
grep -q "no run_end record" <<<"$o" && pass "a stream cut short fails (no run_end)" || flunk "cut stream"
o="$("${A[@]}" --pubkey "$D/keys/k1.pub" --allow-incomplete "$OUT/cut" 2>&1)"
grep -q "INCOMPLETE" <<<"$o" && grep -q "follow the last signature.*not audited" <<<"$o" \
  && grep -q "covers the first" <<<"$o" && grep -q PASS <<<"$o" \
  && pass "--allow-incomplete audits only up to the last signature, and says so" \
  || { flunk "incomplete report"; echo "$o" | head -4; }
# A holder who removes every checkpoint after run_start and rewrites the rest
# (here: the secret's DENY deleted, later seqs and counts fixed up).
python3 - "$OUT/v" > "$OUT/fab.raw" <<'EOF'
import json, sys
out, seq = [], 0
for l in open(sys.argv[1], "rb").read().split(b"\n"):
    if b'"event":"checkpoint"' in l or b'"event":"run_end"' in l:
        continue
    if b'"seq":' in l:
        r = json.loads(l)
        if r.get("decision_final") == "DENY":
            continue
        l = l.replace(b'"seq":%d,' % r["seq"], b'"seq":%d,' % seq, 1)
        seq += 1
    out.append(l)
sys.stdout.buffer.write(b"\n".join(out))
EOF
python3 "$RECHAIN" "$OUT/fab.raw" > "$OUT/fab"
o="$("${A[@]}" --pubkey "$D/keys/k1.pub" --allow-incomplete "$OUT/fab" 2>&1)"
grep -q "checkpoints were removed" <<<"$o" && grep -q FAIL <<<"$o" \
  && pass "an incomplete stream with its checkpoints removed fails (checkpoint_every)" \
  || { flunk "checkpoints removed from an incomplete stream"; echo "$o" | head -4; }
# ... with an unsigned run_end forged in its place.
{ cat "$OUT/cut"; grep '"event":"run_end"' "$OUT/v" | sed -E 's/,"sig":"[0-9a-f]{128}"//'; } > "$OUT/fakeend.raw"
# (run_end's record count still matches: no decision record was cut.)
python3 "$RECHAIN" "$OUT/fakeend.raw" > "$OUT/fakeend"
o="$("${A[@]}" --pubkey "$D/keys/k1.pub" "$OUT/fakeend" 2>&1)"
grep -q "run_end record is not signed" <<<"$o" && pass "a forged unsigned run_end fails" || flunk "forged run_end"
# The key dropped from run_start: the stream then claims no signing at all.
sed -E 's/"log_pubkey":"[0-9a-f]{64}","checkpoint_every":[0-9]+,//; s/,"sig":"[0-9a-f]{128}"//' "$OUT/edit" > "$OUT/nokey.raw"
python3 "$RECHAIN" "$OUT/nokey.raw" > "$OUT/nokey"
o="$("${A[@]}" --pubkey "$D/keys/k1.pub" "$OUT/nokey" 2>&1)"
grep -q "the stream is not signed" <<<"$o" && grep -q FAIL <<<"$o" \
  && pass "signatures stripped: fails against the pinned key" || flunk "stripped signatures"
# Downgrade: every chain field and the log format stripped.
sed -E 's/,"chain":"[0-9a-f]{64}"//; s/,"sig":"[0-9a-f]{128}"//; s/"log":"chain-1",//' "$OUT/edit" > "$OUT/down"
o="$("${A[@]}" "$OUT/down" 2>&1)"
grep -q "the chain was stripped" <<<"$o" && pass "a 1.16 stream with its chain stripped is refused (no downgrade)" \
  || { flunk "downgrade"; echo "$o" | head -3; }
o="$("${A[@]}" --run 0123456789abcdef0123456789abcdef "$OUT/v" 2>&1)"
grep -q "not the run asked for" <<<"$o" && pass "--run binds the audit to one run" || flunk "--run"
if [ "$HAVE_CRYPTO" = 1 ]; then
    python3 "$RECHAIN" --resign "$D/keys/k2" "$OUT/edit" > "$OUT/other"
    o="$("${A[@]}" "$OUT/other" 2>&1)"
    grep -q "key not pinned" <<<"$o" && grep -q PASS <<<"$o" \
      && pass "re-signed with another key: consistent, but only 'key not pinned'" || flunk "re-signed, unpinned"
    o="$("${A[@]}" --pubkey "$D/keys/k1.pub" "$OUT/other" 2>&1)"
    grep -q "not by the pinned key" <<<"$o" && pass "re-signed with another key: fails against the pinned key" \
      || flunk "re-signed, pinned"
else
    skip "re-signing cases (python3 cryptography not installed)"
fi

echo "== 3. holder with the key: the anchor =="
if [ "$HAVE_CRYPTO" = 1 ]; then
    python3 "$RECHAIN" --resign "$D/keys/k1" "$OUT/edit" > "$OUT/forged"
    o="$("${A[@]}" --pubkey "$D/keys/k1.pub" "$OUT/forged" 2>&1)"
    grep -q "varek_audit: PASS" <<<"$o" \
      && pass "rewritten and re-signed with the Warden's key: signatures alone pass (as documented)" \
      || flunk "key-holder forgery vs signatures"
    o="$("${A[@]}" --pubkey "$D/keys/k1.pub" --anchor "$D/anchor" "$OUT/forged" 2>&1)"
    grep -q "rewritten after it was anchored" <<<"$o" && grep -q FAIL <<<"$o" \
      && pass "... and fails against the anchor" || flunk "key-holder forgery vs anchor"
else
    skip "key-holder forgery (python3 cryptography not installed)"
fi
# Anchor only, no key: the chain values that reached the anchor seal the log.
rm -f "$D/anchor_only"
timeout 30 "$WARDEN" "$POL" --anchor "$D/anchor_only" --checkpoint-every 4 \
    -- /bin/cat "${FILES[@]}" > /dev/null 2> "$OUT/vao"
o1="$("${A[@]}" --anchor "$D/anchor_only" "$OUT/vao" 2>&1)"
sed -E '0,/"target":"\/tmp\/varek_v1160\/data\/f3"/s//"target":"\/tmp\/varek_v1160\/data\/secret"/' "$OUT/vao" > "$OUT/vao_e.raw"
python3 "$RECHAIN" "$OUT/vao_e.raw" > "$OUT/vao_e"
o2="$("${A[@]}" --anchor "$D/anchor_only" "$OUT/vao_e" 2>&1)"
grep -q "integrity: chain, anchored" <<<"$o1" && grep -q PASS <<<"$o1" && grep -q "rewritten after it was anchored" <<<"$o2" \
  && pass "anchor without a key: PASS as 'chain, anchored'; an edit with the chain recomputed fails" \
  || { flunk "anchor-only mode"; echo "$o1" | tail -3; echo "$o2" | tail -3; }
sed '2d' "$D/anchor" > "$OUT/anchor_gap"
o="$("${A[@]}" --pubkey "$D/keys/k1.pub" --anchor "$OUT/anchor_gap" "$OUT/v" 2>&1)"
grep -q "was never anchored" <<<"$o" && pass "an anchor missing a checkpoint fails" || flunk "anchor gap"
: > "$OUT/anchor_empty"
o="$("${A[@]}" --anchor "$OUT/anchor_empty" "$OUT/v" 2>&1)"
grep -q "anchor holds nothing for this run" <<<"$o" && pass "an anchor from elsewhere fails" || flunk "foreign anchor"

echo "== 4. anchor failures =="
mkfifo "$D/fifo"
( head -n 1 "$D/fifo" > "$OUT/fifo_got" ) &
rd=$!
sleep 0.2
timeout 30 "$WARDEN" "$POL" --sign-key "$D/keys/k1" --anchor "$D/fifo" --checkpoint-every 4 \
    -- /bin/cat "${FILES[@]}" > "$OUT/stdout2" 2> "$OUT/v2"
rc=$?; wait "$rd" 2>/dev/null
grep -q "file 12" "$OUT/stdout2" && grep -q '"event":"run_end"' "$OUT/v2" \
  && pass "the FIFO reader went away: the run completes (Warden rc $rc)" || flunk "run with a dead anchor reader"
# v1.16.2: the Warden holds a FIFO anchor read-write, so the records it writes
# after the reader left wait in the pipe; at exit it waits 10 s for a reader,
# then reports them as lost (run_end stays the last record).
grep -q '^\[warden\] anchor: .* not read within 10 s' "$OUT/v2" \
  && [ "$(grep '^{' "$OUT/v2" | tail -1 | grep -c '"event":"run_end"')" = 1 ] \
  && pass "unread anchor records are reported at exit, and run_end stays the last record" || flunk "unread anchor records"
o="$("${A[@]}" --pubkey "$D/keys/k1.pub" --anchor "$OUT/fifo_got" "$OUT/v2" 2>&1)"
grep -q "was never anchored" <<<"$o" && grep -q FAIL <<<"$o" \
  && pass "the anchored audit fails and names the records never anchored" || { flunk "anchored audit after lost records"; echo "$o" | head -6; }
o="$("${A[@]}" --pubkey "$D/keys/k1.pub" "$OUT/v2" 2>&1)"
grep -q PASS <<<"$o" && pass "the signed stream itself still verifies" || { flunk "signed stream after anchor errors"; echo "$o" | head -6; }
# A reader that never reads: the FIFO fills (EAGAIN) and supervision goes on.
rm -f "$D/fifo3"; mkfifo "$D/fifo3"
exec 7<>"$D/fifo3"
s=$(date +%s%N)
timeout 60 "$WARDEN" "$POL" --sign-key "$D/keys/k1" --anchor "$D/fifo3" --checkpoint-every 1 \
    -- "$PROBE" -n 400 "$D/data/f1" > "$OUT/stdout3" 2> "$OUT/v3"
el=$(( ($(date +%s%N) - s) / 1000000 ))
exec 7<&-
grep -q "opened=400" "$OUT/stdout3" && grep -q '"event":"anchor_error".*"errno":11' "$OUT/v3" \
  && pass "a full anchor FIFO: EAGAIN recorded, the run completes (${el} ms)" || flunk "full FIFO"
rm -f "$D/fifo2"; mkfifo "$D/fifo2"
o="$("$WARDEN" "$POL" --anchor "$D/fifo2" -- /bin/true 2>&1)"
grep -q "no reader on the FIFO" <<<"$o" && pass "a FIFO anchor with no reader is refused at startup" \
  || flunk "FIFO without reader"

echo "== 4b. checkpoints by time; a stream that cannot be written =="
timeout 30 "$WARDEN" "$POL" --sign-key "$D/keys/k1" -- "$PROBE" -s 1500 "$D/data/f1" "$D/data/f2" \
    > /dev/null 2> "$OUT/v4"
python3 - "$OUT/v4" <<'EOF' && pass "a checkpoint is written after one second with records pending" || flunk "time-based checkpoint"
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
first = next(r for r in recs if r.get("target") == "/tmp/varek_v1160/data/f1")
cks = [r for r in recs if r.get("event") == "checkpoint"]
# checkpoint_every is 64, so any checkpoint here is time-based; it must seal f1's
# open while the probe still sleeps (before f2's open).
f2 = next(r for r in recs if r.get("target") == "/tmp/varek_v1160/data/f2")
assert any(first["timestamp_ns"] < c["timestamp_ns"] < f2["timestamp_ns"] for c in cks), cks
EOF
s=$(date +%s%N)
timeout 30 "$WARDEN" "$POL" -- "$PROBE" -s 3000 "$D/data/f1" > "$OUT/stdout5" 2>/dev/full; rc=$?
el=$(( ($(date +%s%N) - s) / 1000000 ))
[ "$rc" -ne 0 ] && [ "$el" -lt 2500 ] && ! grep -q "PROBE opened" "$OUT/stdout5" \
  && pass "an unwritable verdict stream stops supervision and the agent (rc $rc, ${el} ms)" \
  || flunk "unwritable stream (rc $rc, ${el} ms)"

echo "== 5. startup refusals =="
refuse() {  # name, expected message, warden args...
    local name="$1" msg="$2"; shift 2
    local o; o="$("$WARDEN" "$@" -- /bin/true 2>&1)"
    if grep -q -- "$msg" <<<"$o" && ! grep -q "supervising pid=" <<<"$o"; then pass "$name"
    else flunk "$name ($(head -1 <<<"$o"))"; fi
}
cp "$D/keys/k1" "$D/keys/open"; chmod 644 "$D/keys/open"
refuse "a key readable by others is refused" "readable or writable by group or others" "$POL" --sign-key "$D/keys/open"
printf 'not a key\n' > "$D/keys/bad"; chmod 600 "$D/keys/bad"
refuse "a malformed key is refused" "not a VAREK signing key" "$POL" --sign-key "$D/keys/bad"
ln -sf "$D/keys/k1" "$D/keys/link"
refuse "a key reached through a symlink is refused" "signing key" "$POL" --sign-key "$D/keys/link"
{ cat "$POL"; echo "allow path /tmp/varek_v1160/keys/"; } > "$OUT/leaky.txt"
refuse "a policy that lets the agent open the key is refused" "would let the agent open the signing key" \
    "$OUT/leaky.txt" --sign-key "$D/keys/k1"
{ cat "$POL"; echo "allow path /tmp/varek_v1160/keys/k1 access=wo"; } > "$OUT/leaky2.txt"
refuse "... even write-only through a flag clause" "would let the agent open the signing key" \
    "$OUT/leaky2.txt" --sign-key "$D/keys/k1"
{ cat "$POL"; echo "deny path /tmp/varek_v1160/keys/"; echo "allow path /tmp/varek_v1160/"; } > "$OUT/safe.txt"
o="$("$WARDEN" "$OUT/safe.txt" --sign-key "$D/keys/k1" -- /bin/true 2>&1)"
grep -q "supervising pid=" <<<"$o" && pass "a policy that denies the key's directory first is accepted" \
  || flunk "key behind an earlier deny ($(head -1 <<<"$o"))"
{ cat "$POL"; echo "allow path /tmp/varek_v1160/anch"; } > "$OUT/leaky3.txt"
refuse "a policy that lets the agent open the anchor is refused" "would let the agent open the anchor" \
    "$OUT/leaky3.txt" --anchor "$D/anchor3"
refuse "--checkpoint-every 0 is refused" "takes 1 to 1000000" "$POL" --checkpoint-every 0
refuse "--checkpoint-every 1000001 is refused" "takes 1 to 1000000" "$POL" --checkpoint-every 1000001
o="$("$WARDEN" "$POL" --checkpoint-every 1000000 -- /bin/true 2>&1)"
grep -q "supervising pid=" <<<"$o" && pass "--checkpoint-every 1000000 is accepted" || flunk "--checkpoint-every 1000000"
ln "$D/keys/k1" "$D/keys/k1.alias"
refuse "a key with a second name (hard link) is refused" "has 2 names" "$POL" --sign-key "$D/keys/k1"
rm -f "$D/keys/k1.alias"
{ cat "$POL"; echo "allow path $OUT/"; } > "$OUT/streampol.txt"
o="$("$WARDEN" "$OUT/streampol.txt" -- /bin/true 2> "$OUT/stream.log")"; o="$(cat "$OUT/stream.log")"
grep -q "would let the agent open the verdict stream" <<<"$o" && ! grep -q "supervising pid=" <<<"$o" \
  && pass "a policy that lets the agent open the verdict stream file is refused" || flunk "exposed verdict stream"
blk="$(find /dev -maxdepth 2 -type b 2>/dev/null | head -1)"
if [ -n "$blk" ]; then
    { cat "$POL"; echo "allow path $(dirname "$blk")/ readonly"; } > "$OUT/rawpol.txt"
    refuse "a policy that lets the agent open a block device ($blk) is refused with a key" \
        "raw access to storage" "$OUT/rawpol.txt" --sign-key "$D/keys/k1"
else
    skip "block-device refusal (no block device on this host)"
fi
refuse "a repeated --sign-key is refused" "usage:" "$POL" --sign-key "$D/keys/k1" --sign-key "$D/keys/k1"

echo "== 6. glob tokens capped at 4,096 per policy =="
mk() { { echo 'require warden 1.16'; printf 'deny path glob /%s*\n' "$(head -c "$1" /dev/zero | tr '\0' a)"; \
         printf 'deny path glob /%s*\n' "$(head -c "$2" /dev/zero | tr '\0' b)"; echo 'allow path /usr/lib/'; } > "$3"; }
mk 2045 2047 "$OUT/g4096.txt"      # (1 + 2045 + 1) + (1 + 2047 + 1) = 4096 tokens
mk 2046 2047 "$OUT/g4097.txt"
o1="$("$VDP" "$OUT/g4096.txt" lint 2>&1)"; o2="$("$VDP" "$OUT/g4097.txt" lint 2>&1)"
grep -q "glob tokens 4096 of 4096" <<<"$o1" && grep -q "more than 4096 tokens" <<<"$o2" \
  && pass "vdp_check: 4,096 accepted (lint reports it), 4,097 refused" || flunk "vdp_check cap"
"$CERT" "$OUT/g4096.txt" digest >/dev/null 2>&1 && ! "$CERT" "$OUT/g4097.txt" digest >/dev/null 2>&1 \
  && pass "certificate checker: 4,096 accepted, 4,097 refused" || flunk "checker cap"
# The same boundary with every kind of token: a set, an escape, *, ** and the
# /**/ unit, counted by vdp_check and padded to the cap with a literal glob.
G='/[a-c]\*x/**/y*z**'
n=$(printf 'deny path glob %s\n' "$G" > "$OUT/one.txt"; "$VDP" "$OUT/one.txt" lint | sed -n 's/.*glob tokens \([0-9]*\) of.*/\1/p')
for tot in 4096 4097; do
    { echo 'require warden 1.16'; for i in 1 2 3 4 5 6 7 8; do printf 'deny path glob %s\n' "$G"; done
      printf 'deny path glob /%s\n' "$(head -c $((tot - 8 * n - 1)) /dev/zero | tr '\0' q)"; } > "$OUT/m$tot.txt"
done
"$VDP" "$OUT/m4096.txt" lint >/dev/null 2>&1; r1=$?; "$VDP" "$OUT/m4097.txt" lint >/dev/null 2>&1; r2=$?
"$CERT" "$OUT/m4096.txt" digest >/dev/null 2>&1; r3=$?; "$CERT" "$OUT/m4097.txt" digest >/dev/null 2>&1; r4=$?
[ "$r1" -le 1 ] && [ "$r2" -eq 2 ] && [ "$r3" -eq 0 ] && [ "$r4" -eq 2 ] \
  && pass "mixed tokens ($n per glob): both parsers accept 4,096 and refuse 4,097" \
  || flunk "mixed-token cap ($n: $r1 $r2 $r3 $r4)"
o="$("$WARDEN" "$OUT/g4097.txt" -- /bin/true 2>&1)"
grep -q "more than 4096 tokens" <<<"$o" && ! grep -q "supervising pid=" <<<"$o" \
  && pass "Warden: 4,097 refused" || flunk "Warden cap"

echo "== 7. the audit's Ed25519 verifier =="
python3 - "$HERE/tools" "$HAVE_CRYPTO" <<'EOF' && pass "RFC 8032 vectors, and agreement with OpenSSL on 400 cases (when installed)" || flunk "Ed25519 verifier"
import os, random, sys
sys.path.insert(0, sys.argv[1])
from varek_ed25519 import verify
V = [("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
     ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")]
for pk, m, s in V:
    assert verify(bytes.fromhex(pk), bytes.fromhex(m), bytes.fromhex(s))
    bad = bytearray.fromhex(s); bad[0] ^= 1
    assert not verify(bytes.fromhex(pk), bytes.fromhex(m), bytes(bad))
# S >= L (a malleated signature) and a small-order public key are refused.
pk, m, s = V[0]
L = 2 ** 252 + 27742317777372353535851937790883648493
S = int.from_bytes(bytes.fromhex(s)[32:], "little") + L
assert not verify(bytes.fromhex(pk), b"", bytes.fromhex(s)[:32] + S.to_bytes(32, "little"))
assert not verify(bytes(32), b"", bytes(64))
assert not verify((1).to_bytes(32, "little"), b"", bytes(64))
# Non-canonical encodings: y >= p for R, and x = 0 with the sign bit set.
P = 2 ** 255 - 19
sig = bytes.fromhex(s)
assert not verify(bytes.fromhex(pk), b"", P.to_bytes(32, "little") + sig[32:])
assert not verify(bytes.fromhex(pk), b"", ((1 << 255) | 1).to_bytes(32, "little") + sig[32:])
assert not verify(((1 << 255) | 1).to_bytes(32, "little"), b"", sig)
if sys.argv[2] == "1":
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    rng = random.Random(1160)
    for i in range(100):
        k = Ed25519PrivateKey.generate()
        pk = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        m = os.urandom(rng.randrange(0, 64)); s = k.sign(m)
        cases = [(pk, m, s)]
        b = bytearray(s); b[rng.randrange(64)] ^= 1 << rng.randrange(8); cases.append((pk, m, bytes(b)))
        b = bytearray(m + b"x"); b[rng.randrange(len(b))] ^= 1; cases.append((pk, bytes(b), s))
        b = bytearray(pk); b[rng.randrange(32)] ^= 1 << rng.randrange(8); cases.append((bytes(b), m, s))
        for a, mm, ss in cases:
            try:
                Ed25519PublicKey.from_public_bytes(a).verify(ss, mm); ref = True
            except Exception:
                ref = False
            assert verify(a, mm, ss) == ref, (a.hex(), mm.hex(), ss.hex())
EOF

echo
if [ "$fail" -eq 0 ]; then echo "test_v1160: PASS"; else echo "test_v1160: FAIL"; fi
exit "$fail"
