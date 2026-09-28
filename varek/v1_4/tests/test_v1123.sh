#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1123.sh — regression test for VAREK v1.12.3.
#
#   1. Dynamically linked agents start. The probe is dynamically linked, so its
#      loader opens (/lib -> /usr/lib, libc.so.6 -> the versioned file) go
#      through the Warden. Through v1.12.2 RESOLVE_NO_SYMLINKS refused any path
#      with a symlink and the probe never reached main().
#   2. Ordinary symlinks are followed and the decision is made on the canonical
#      path: a symlink to an allowed file is delivered; a symlink escaping to a
#      denied file, a symlink chain, and an absolute-denied symlink are refused.
#   3. A trailing symlink opened O_NOFOLLOW is refused.
#   4. /proc/self and /proc/thread-self map to the AGENT, not the supervisor
#      (proved by reading back the probe's own cmdline); another process's
#      /proc/<pid>/ and denied /proc entries are refused.
#
# Usage: ./test_v1123.sh <warden> <policy> <probe_bin> <exporter.py>
# Exit 0 iff every assertion holds.
set -u

WARDEN="${1:?usage: test_v1123.sh <warden> <policy> <probe> <exporter>}"
POLICY="${2:?}"
PROBE="${3:?}"
EXPORTER="${4:?}"

fail=0
note() { printf '  %-6s %s\n' "$1" "$2"; }
pass() { note PASS "$1"; }
flunk() { note FAIL "$1"; fail=1; }
probe_says() { grep -Eq "^PROBE $1 +$2" "$PROBEOUT"; }
expect() { if probe_says "$2" "$3"; then pass "$1"
    else flunk "$1 (probe: $(grep -E "^PROBE $2 " "$PROBEOUT" | sed 's/^PROBE //' || true))"; fi; }

ALLOW=/tmp/varek_allowed_v1123
DENIED=/tmp/varek_denied_v1123
rm -rf "$ALLOW" "$DENIED"
mkdir -p "$ALLOW/sub" "$DENIED"
echo "legitimate content" > "$ALLOW/ok.txt"
echo "inner ok"           > "$ALLOW/sub/inner.txt"
printf 'top secret 14\n'  > "$DENIED/secret.txt"
SECRET_SUM="$(sha256sum "$DENIED/secret.txt" | cut -d' ' -f1)"

# Fixtures: symlinks the probe opens.
ln -s ok.txt                       "$ALLOW/link_to_ok"          # -> allowed file (relative)
ln -s sub                          "$ALLOW/dirlink"             # -> allowed subdir
ln -s "$ALLOW/ok.txt"              "$ALLOW/rel_link"            # -> allowed file (absolute)
ln -s "$DENIED/secret.txt"         "$ALLOW/link_to_secret"      # -> denied file
ln -s /etc/shadow                  "$ALLOW/link_to_etc_shadow"  # -> absolute denied
ln -s link_to_secret               "$ALLOW/chain_a"             # -> symlink -> denied
ln -s /proc/self/mem               "$ALLOW/link_to_proc_self_mem" # magic link -> refused during resolution
ln -s /proc/1/mem                  "$ALLOW/link_to_proc_pid1_mem" # numeric foreign proc -> refused by the /proc check

OUT="$(mktemp -d)"
PROBEOUT="$OUT/probe.stdout"
VERDICTS="$OUT/warden.stderr"

timeout 30 "$WARDEN" "$POLICY" -- "$PROBE" >"$PROBEOUT" 2>"$VERDICTS"
rc=$?

echo "== probe self-report =="
sed 's/^/  /' "$PROBEOUT"
echo "== assertions =="

if [ "$rc" -eq 124 ]; then flunk "Warden finished within 30 s (it hung)"; else pass "Warden finished within 30 s"; fi
# The dynamically linked probe reaching 'done' IS the headline fix.
if grep -q '^PROBE done' "$PROBEOUT"; then pass "dynamically linked agent ran to completion (loader opens followed symlinks)"
else flunk "dynamically linked agent ran to completion"; fi
if grep -q 'BYPASSED' "$PROBEOUT"; then flunk "no bypass reported by probe"; else pass "no bypass reported by probe"; fi

echo "-- 1. symlinks followed to allowed objects"
expect "a symlink to an allowed file is followed and delivered"   symlink_to_allowed OK
expect "a symlinked directory component is followed"              dir_symlink_component OK
expect "an absolute symlink to an allowed file is followed"       relative_symlink OK
expect "a plain (non-symlink) allowed open still works"           plain_allowed OK

echo "-- 2. symlinks escaping to denied objects refused"
expect "a symlink to a denied file is refused"                    symlink_escape REFUSED
expect "a symlink to an absolute denied path is refused"          symlink_abs_denied REFUSED
expect "a symlink chain ending at a denied file is refused"       symlink_chain_escape REFUSED
expect "the denied file opened directly is refused"               denied_direct REFUSED
if [ "$(sha256sum "$DENIED/secret.txt" | cut -d' ' -f1)" = "$SECRET_SUM" ]; then
    pass "the denied file is unchanged"; else flunk "the denied file is unchanged"; fi

echo "-- 3. O_NOFOLLOW on a trailing symlink"
expect "a trailing symlink opened O_NOFOLLOW is refused"          nofollow_trailing_link REFUSED

echo "-- 4. /proc/self maps to the agent; other /proc refused"
expect "/proc/self/cmdline reads back the agent's own argv"       proc_self_is_agent OK
expect "/proc/thread-self/cmdline reads back the agent's own argv" proc_thread_self_agent OK
expect "a symlink to /proc/self (a magic link) is refused at resolution" symlink_to_proc_self REFUSED
expect "a symlink to another process's numeric /proc/1/mem is refused"   symlink_to_proc_pid1 REFUSED
expect "another process's /proc/1/mem opened directly is refused"       proc_pid1_mem REFUSED
expect "/proc/kcore (a non-process /proc entry) is refused by default-deny" proc_kcore REFUSED
# The agent's own /proc really was reached (an ALLOW on a /proc/self path).
if grep '^{' "$VERDICTS" | grep '"file.open"' | grep '"ALLOW"' | grep -q '"/proc/self/cmdline"'; then
    pass "the agent's /proc/self/cmdline was decided as /proc/self/... and allowed"
else flunk "the agent's /proc/self/cmdline was decided as /proc/self/... and allowed"; fi
# No verdict record names another process's or the supervisor's /proc as ALLOW.
if grep '^{' "$VERDICTS" | grep '"ALLOW"' | grep -Eq '"/proc/(1|[0-9]+/task)?/?(mem|kcore)"'; then
    flunk "no foreign /proc object was allowed"
else pass "no foreign /proc object was allowed"; fi

echo "-- 5. verdict stream still attests"
wv="$(grep -o '"warden":"[0-9.]*"' "$VERDICTS" | head -1 | cut -d'"' -f4)"
if [ -n "$wv" ] && printf '%s\n%s\n' 1.12.3 "$wv" | sort -V -C; then pass "run_start names Warden 1.12.3 or later ($wv)"
else flunk "run_start names Warden 1.12.3 or later (got ${wv:-none})"; fi
if python3 "$EXPORTER" --log "$VERDICTS" --output "$OUT/bom.json" >/dev/null 2>"$OUT/exp.err"; then
    pass "CycloneDX exporter accepts the stream"
else flunk "CycloneDX exporter accepts the stream ($(head -1 "$OUT/exp.err"))"; fi

rm -rf "$OUT"
echo
if [ "$fail" -eq 0 ]; then echo "test_v1123: PASS"; else echo "test_v1123: FAIL"; fi
exit "$fail"
