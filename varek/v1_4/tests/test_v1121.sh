#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1121.sh — regression test for the three fixes in VAREK v1.12.1.
#
#   1. A denied open has no side effect: no truncation, no file created.
#      (Allowed creates, O_EXCL, O_TRUNC, directories and FIFOs still behave.)
#   2. The agent cannot forge verdict records: its stderr is relayed with an
#      "[agent] " prefix, every record carries a per-run id and a contiguous
#      seq, and the CycloneDX exporter refuses a stream holding a foreign record.
#   3. The agent cannot accept inbound connections: bind/listen/accept are
#      refused and the agent runs in its own, empty network namespace.
#
# Usage: ./test_v1121.sh <warden> <policy> <probe_bin> <exporter.py>
# Exit 0 iff every assertion holds.
set -u

WARDEN="${1:?usage: test_v1121.sh <warden> <policy> <probe> <exporter>}"
POLICY="${2:?}"
PROBE="${3:?}"
EXPORTER="${4:?}"

fail=0
note() { printf '  %-6s %s\n' "$1" "$2"; }
pass() { note PASS "$1"; }
flunk() { note FAIL "$1"; fail=1; }
check() { # check <desc> <cmd...>
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then pass "$desc"; else flunk "$desc"; fi
}
probe_says() { grep -Eq "^PROBE $1 +$2" "$PROBEOUT"; }

# --- fixtures --------------------------------------------------------------
ALLOW=/tmp/varek_allowed_probe
DENIED=/tmp/varek_denied_probe
setup() {
    rm -rf "$ALLOW" "$DENIED"
    mkdir -p "$ALLOW/sub" "$DENIED"
    echo "legitimate content" > "$ALLOW/ok.txt"
    echo "truncate me" > "$ALLOW/trunc_me.txt"
    mkfifo "$ALLOW/fifo"
    printf 'top secret 14\n' > "$DENIED/secret.txt"     # 14 bytes
}
setup
SECRET_SUM="$(sha256sum "$DENIED/secret.txt" | cut -d' ' -f1)"

OUT="$(mktemp -d)"
PROBEOUT="$OUT/probe.stdout"
VERDICTS="$OUT/warden.stderr"

# Run A: Warden verdicts -> stderr, probe -> stdout (the documented layout).
# umask 077 so the create test can check the agent's umask is honoured.
( umask 077; timeout 30 "$WARDEN" "$POLICY" -- "$PROBE" >"$PROBEOUT" 2>"$VERDICTS" )
rc=$?

echo "== probe self-report =="
sed 's/^/  /' "$PROBEOUT"
echo "== assertions =="

if [ "$rc" -eq 124 ]; then flunk "Warden finished within 30 s (it hung)"; else pass "Warden finished within 30 s"; fi
check "probe ran to completion" grep -q '^PROBE done' "$PROBEOUT"
if grep -q 'BYPASSED' "$PROBEOUT"; then flunk "no bypass reported by probe"; else pass "no bypass reported by probe"; fi

echo "-- 1. denied opens have no side effect"
check "O_TRUNC on a denied file refused"            probe_says trunc_denied REFUSED
check "O_CREAT|O_TRUNC on a denied file refused"    probe_says creat_trunc_denied REFUSED
if [ "$(sha256sum "$DENIED/secret.txt" | cut -d' ' -f1)" = "$SECRET_SUM" ]; then
    pass "denied file unchanged (still $(stat -c %s "$DENIED/secret.txt") bytes)"
else
    flunk "denied file unchanged (now $(stat -c %s "$DENIED/secret.txt") bytes)"
fi
check "O_CREAT in a denied directory refused"       probe_says creat_denied REFUSED
if [ -e "$DENIED/created.txt" ]; then flunk "no file created in denied directory"
else pass "no file created in denied directory"; fi
check "O_CREAT in the allowed directory succeeds"   probe_says creat_allowed OK
check "created file holds what the agent wrote"     grep -qx hello "$ALLOW/created.txt"
mode="$(stat -c %a "$ALLOW/created.txt" 2>/dev/null)"
if [ "$mode" = "600" ]; then pass "created file honours the agent's umask (0666 & ~077 = 600)"
else flunk "created file honours the agent's umask (got ${mode:-none})"; fi
check "O_CREAT|O_EXCL on an existing file gives EEXIST" probe_says excl_existing EEXIST
check "O_TRUNC on an allowed file succeeds"         probe_says trunc_allowed OK
if [ "$(stat -c %s "$ALLOW/trunc_me.txt")" = "0" ]; then pass "allowed O_TRUNC truncated the file"
else flunk "allowed O_TRUNC truncated the file"; fi
check "O_DIRECTORY open of an allowed directory succeeds" probe_says dir_allowed OK
check "FIFO with no reader gives ENXIO, not a hang" probe_says fifo_no_reader ENXIO
check "Warden still answering after the FIFO"       probe_says legit_after_fifo OK

echo "-- 2. verdict records cannot be forged"
check "stream opens with a run_start record"        grep -q '^{"event":"run_start"' "$VERDICTS"
check "stream closes with a run_end record"         grep -q '^{"event":"run_end"' "$VERDICTS"
if grep '^{' "$VERDICTS" | grep -q '"rule":"FORGED"'; then
    flunk "no agent-written line starts a record"
else
    pass "no agent-written line starts a record"
fi
check "agent stderr relayed with the [agent] prefix" grep -q '^\[agent\] .*"rule":"FORGED"' "$VERDICTS"
if python3 - "$VERDICTS" <<'PY'
import json, sys
for ln in open(sys.argv[1], encoding="utf-8", errors="surrogateescape", newline="\n"):
    if ln.startswith("{"):
        json.loads(ln)
PY
then pass "every record line is well-formed JSON"; else flunk "every record line is well-formed JSON"; fi

BOM="$OUT/bom.json"
if python3 "$EXPORTER" --log "$VERDICTS" --agent probe --policy "$POLICY" --output "$BOM" 2>"$OUT/exp.err"; then
    pass "exporter accepts the Warden's own stream"
    if grep -q '/etc/shadow' "$BOM"; then flunk "forged /etc/shadow absent from the BOM"
    else pass "forged /etc/shadow absent from the BOM"; fi
    check "BOM lists the file the agent was allowed to create" grep -q "$ALLOW/created.txt" "$BOM"
else
    flunk "exporter accepts the Warden's own stream ($(cat "$OUT/exp.err"))"
fi

# Run B: stdout merged into the verdict stream (2>&1). The probe's forged
# stdout line now lands in the log unprefixed; it cannot know the run id, so
# the exporter must refuse to attest the stream.
setup
MERGED="$OUT/merged.log"
( umask 077; timeout 30 "$WARDEN" "$POLICY" -- "$PROBE" >"$MERGED" 2>&1 )
if python3 "$EXPORTER" --log "$MERGED" --agent probe --policy "$POLICY" --output "$OUT/bom2.json" 2>"$OUT/exp2.err"; then
    flunk "exporter refuses a stream holding a forged record"
else
    if grep -q 'foreign' "$OUT/exp2.err"; then pass "exporter refuses a stream holding a forged record"
    else flunk "exporter refuses a stream holding a forged record ($(cat "$OUT/exp2.err"))"; fi
fi

echo "-- 3. no inbound networking"
check "TCP bind refused"                 probe_says tcp_bind REFUSED
check "TCP listen refused"               probe_says tcp_listen REFUSED
check "TCP accept refused"               probe_says tcp_accept REFUSED
check "abstract unix-socket bind refused" probe_says unix_abstract_bind REFUSED
check "socketpair still works"           probe_says socketpair OK
check "Warden reports its own network namespace" grep -q 'netns=on' "$VERDICTS"

rm -rf "$OUT" "$ALLOW" "$DENIED"

echo
if [ "$fail" -eq 0 ]; then echo "ALL PASSED (v1.12.1)"; else echo "FAILURES PRESENT"; fi
exit "$fail"
