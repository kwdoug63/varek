#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1122.sh — regression test for VAREK v1.12.2.
#
#   1. Threads work. glibc >= 2.34 creates threads with clone3, which the
#      baseline filter killed through v1.12.1. clone3 now answers ENOSYS, libc
#      falls back to clone(), and a thread's own opens are mediated exactly like
#      the main thread's.
#   2. No namespace denial got weaker. clone3 with any namespace bit creates
#      nothing; legacy clone(CLONE_NEWUSER) is still killed.
#   3. An agent can collect its children's exit status (wait4, waitid).
#   4. ioctl is admitted for six read-or-own-fd-flag requests only; TIOCSTI,
#      TCSETS and junk upper bits are refused.
#   5. The bootstrap exec (answered with CONTINUE) is granted once per run, to
#      the launched process only; a thread or child re-executing the agent's
#      binary is refused.
#   6. A killed agent is reported on the Warden's status output.
#
# Usage: ./test_v1122.sh <warden> <policy> <probe_bin> <exporter.py>
# Exit 0 iff every assertion holds.
set -u

WARDEN="${1:?usage: test_v1122.sh <warden> <policy> <probe> <exporter>}"
POLICY="${2:?}"
PROBE="${3:?}"
EXPORTER="${4:?}"

fail=0
note() { printf '  %-6s %s\n' "$1" "$2"; }
pass() { note PASS "$1"; }
flunk() { note FAIL "$1"; fail=1; }
probe_says() { grep -Eq "^PROBE $1 +$2" "$PROBEOUT"; }
expect() { # expect <desc> <tag> <verdict-regex>
    if probe_says "$2" "$3"; then pass "$1"
    else flunk "$1 (probe: $(grep -E "^PROBE $2 " "$PROBEOUT" | sed 's/^PROBE //' || true))"; fi
}

ALLOW=/tmp/varek_allowed_v1122
DENIED=/tmp/varek_denied_v1122
rm -rf "$ALLOW" "$DENIED"
mkdir -p "$ALLOW" "$DENIED"
echo "legitimate content" > "$ALLOW/ok.txt"
printf 'top secret\n' > "$DENIED/secret.txt"

OUT="$(mktemp -d)"
PROBEOUT="$OUT/probe.stdout"
VERDICTS="$OUT/warden.stderr"

timeout 60 "$WARDEN" "$POLICY" -- "$PROBE" >"$PROBEOUT" 2>"$VERDICTS"
rc=$?

echo "== probe self-report =="
sed 's/^/  /' "$PROBEOUT"
echo "== assertions =="

if [ "$rc" -eq 124 ]; then flunk "Warden finished within 60 s (it hung)"; else pass "Warden finished within 60 s"; fi
if [ "$rc" -eq 0 ]; then pass "agent exited 0 (it was not killed)"
else flunk "agent exited 0 (Warden rc=$rc; $(grep -m1 'agent killed' "$VERDICTS" || echo 'no kill line'))"; fi
if grep -q '^PROBE done' "$PROBEOUT"; then pass "probe ran to completion"; else flunk "probe ran to completion"; fi
if grep -Eq 'BYPASSED|CREATED|ADMITTED|SURVIVED' "$PROBEOUT"; then flunk "no bypass reported by probe"
else pass "no bypass reported by probe"; fi

echo "-- 1. threads"
expect "pthread_create succeeds"                      pthread_create OK
expect "the thread is its own task (distinct tid)"   thread_is_separate_task OK
expect "a thread's allowed open is delivered"        thread_allowed_open OK
expect "a thread's denied open is refused"           thread_denied_open REFUSED
expect "8 threads x 50 concurrent opens all delivered" thread_concurrent_opens OK
# The Warden saw the threads as separate requesters: more than one agent_pid
# on file.open ALLOW records.
npids="$(grep '^{' "$VERDICTS" | python3 -c '
import sys, json
s = set()
for l in sys.stdin:
    r = json.loads(l)
    if r.get("action") == "file.open" and r.get("decision_final") == "ALLOW":
        s.add(r.get("agent_pid"))
print(len(s))' 2>/dev/null)"
if [ "${npids:-0}" -ge 9 ]; then pass "verdicts attribute opens to each thread ($npids requesters)"
else flunk "verdicts attribute opens to each thread (${npids:-0} requesters, want >= 9)"; fi
if grep '^{' "$VERDICTS" | grep '"file.open"' | grep '"DENY"' | grep -q "$DENIED/secret.txt"; then
    pass "the thread's denied open is in the verdict stream"
else flunk "the thread's denied open is in the verdict stream"; fi

echo "-- 2. clone3 refused without killing; namespace denials intact"
for t in plain newuser newns newnet newpid into_cgroup; do
    expect "clone3 ($t) returns ENOSYS and creates nothing" "clone3_$t" ENOSYS
done
expect "legacy clone(CLONE_NEWUSER) still killed (SIGSYS)" clone_newuser_killed KILLED

echo "-- 3. wait family"
expect "fork succeeds"                               fork OK
expect "waitpid reports the child's exit status"    waitpid_status OK
expect "wait4 with rusage reports the exit status"  wait4_rusage OK
expect "waitid reports the exit status"             waitid_status OK
expect "waitpid WNOHANG on a running child returns 0" waitpid_wnohang OK

echo "-- 4. ioctl allowlist"
expect "isatty() on a pipe fails ENOTTY, not EPERM" ioctl_isatty_enotty OK
expect "FIOCLEX / FIONCLEX set and clear FD_CLOEXEC" ioctl_fioclex OK
expect "FIONREAD reports bytes ready"               ioctl_fionread OK
expect "TIOCSTI refused"                            ioctl_tiocsti REFUSED
expect "TCSETS refused"                             ioctl_tcsets REFUSED
expect "admitted request with junk upper bits refused" ioctl_upper_bits REFUSED

echo "-- 5. exec mediation"
expect "a thread re-executing the agent's binary is refused"  thread_reexec_self REFUSED
expect "a child re-executing the agent's binary is refused"   child_reexec_self REFUSED
nboot="$(grep '^{' "$VERDICTS" | grep -c '"bootstrap_exec_allow"')"
if [ "$nboot" -eq 1 ]; then pass "exactly one bootstrap exec allowed per run"
else flunk "exactly one bootstrap exec allowed per run (saw $nboot)"; fi
expect "posix_spawn of an unlisted binary refused, agent survives" spawn_unlisted REFUSED
if grep '^{' "$VERDICTS" | grep '"process.exec"' | grep '"DENY"' | grep -q '/bin/true'; then
    pass "the refused spawn is in the verdict stream"
else flunk "the refused spawn is in the verdict stream"; fi

echo "-- 6. verdict stream still attests"
if grep '^{' "$VERDICTS" | grep -q '"warden":"1.12.2"'; then pass "run_start names Warden 1.12.2"
else flunk "run_start names Warden 1.12.2"; fi
if python3 "$EXPORTER" --log "$VERDICTS" --output "$OUT/bom.json" >/dev/null 2>"$OUT/exp.err"; then
    pass "CycloneDX exporter accepts the multithreaded stream"
else flunk "CycloneDX exporter accepts the multithreaded stream ($(head -1 "$OUT/exp.err"))"; fi
# The BOM names the Warden version from run_start, not the exporter's own.
sed 's/"warden":"1\.12\.2"/"warden":"9.9.9"/' "$VERDICTS" > "$OUT/relabel.log"
if python3 "$EXPORTER" --log "$OUT/relabel.log" --output "$OUT/relabel.json" >/dev/null 2>&1 \
   && grep -q '"version": "9.9.9"' "$OUT/relabel.json"; then
    pass "BOM takes the Warden version from run_start"
else flunk "BOM takes the Warden version from run_start"; fi

echo "-- 7. a killed agent is reported"
# A static one-liner that makes a hard-denied call. Built here so the suite has
# no extra artifact; skipped (not failed) if no compiler is present.
KILLER="$OUT/killer"
if printf '#include <unistd.h>\n#include <sys/syscall.h>\nint main(void){syscall(SYS_ptrace,0,0,0,0);return 0;}\n' \
     | ${CC:-cc} -static -x c -o "$KILLER" - 2>/dev/null; then
    timeout 30 "$WARDEN" "$POLICY" -- "$KILLER" >/dev/null 2>"$OUT/killer.err"
    if grep -q 'agent killed by signal 31' "$OUT/killer.err"; then
        pass "Warden reports the agent was killed by SIGSYS"
    else flunk "Warden reports the agent was killed by SIGSYS"; fi
else
    flunk "build the kill-report helper (needs a C compiler with static libc)"
fi

rm -rf "$OUT"
echo
if [ "$fail" -eq 0 ]; then echo "test_v1122: PASS"; else echo "test_v1122: FAIL"; fi
exit "$fail"
