#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# test_v1290.sh — VAREK v1.29.0: `varek run` with nothing set up first, a dry
# run, and `varek policy suggest` (docs/security/v1.29-varek-run.md). The
# parts built so far:
#   1. opening files as the agent: `require warden 1.29`, read the same way by
#      the decision procedure (vdp_check) and the certificate checker
#      (vdp_cert_check); the Warden reports 1.29.0 and compares the two
#      readings at load; under it, the Warden resolves and opens each file it
#      hands the agent with the agent's user, group and its user's
#      supplementary groups (tests/v1290_open makes the opens): a created
#      file is the agent's, a file the agent's user could not open is not
#      opened whatever the policy allows (the kernel's error, recorded with
#      the decision), and a v1.28 policy opens as root, as before.
#
#   test_v1290.sh VDP_CHECK VDP_CERT_CHECK [WARDEN]
set -u

VDP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
CERT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
WARDEN="${3:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
TUSER=varek1290u TGROUP=varek1290g MADE_USER=
cleanup() {
    if [ -n "$MADE_USER" ]; then userdel "$TUSER" >/dev/null 2>&1; groupdel "$TGROUP" >/dev/null 2>&1; fi
    [ -n "${KEEP:-}" ] && echo "kept $OUT" || rm -rf "$OUT"
}
trap cleanup EXIT

echo "== 1. opening files as the agent =="
# both parsers load the policy and say the same about opening as the agent
openas() {
    printf '%b' "$2" > "$OUT/p.txt"
    local a b
    a="$("$VDP" "$OUT/p.txt" openas 2>&1)"; b="$("$CERT" "$OUT/p.txt" openas 2>&1)"
    if [ "$a" = "$3" ] && [ "$b" = "$3" ]; then pass "$1"; else flunk "$1 (procedure: $a; checker: $b)"; fi
}
openas "require warden 1.29: files opened as the agent, in both parsers" 'require warden 1.29\nallow path /tmp/\n' on
openas "require warden 1.28: as root, as before"                         'require warden 1.28\nallow path /tmp/\n' off
openas "require warden 1.27: as root"                                    'require warden 1.27\nallow path /tmp/\n' off
openas "no require: as root"                                             'allow path /tmp/\n'                      off
openas "1.29 after 1.28: the highest counts"                             'require warden 1.28\nrequire warden 1.29\n' on
printf 'require warden 1.99\n' > "$OUT/p.txt"
check "require warden 1.99: refused by the procedure" sh -c "'$VDP' '$OUT/p.txt' analyze 2>&1 | grep -q 'requires Warden 1.99; this is 1.29'"
check "require warden 1.99: refused by the checker" sh -c "! '$CERT' '$OUT/p.txt' digest"
printf 'require warden 1.29\nallow path /usr/ readonly\n' > "$OUT/p.txt"

if [ -z "$WARDEN" ]; then
    skip "the Warden's checks (no warden binary given)"
elif [ "$(id -u)" != 0 ]; then
    skip "the Warden's checks (they run as root: the agent runs as another user)"
else
    check "the Warden reports 1.29.0 or later" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | python3 -c 'import re,sys; m=re.search(r\"VAREK Warden  (\\d+)\\.(\\d+)\\.(\\d+)\", sys.stdin.read()); sys.exit(0 if m and tuple(map(int, m.groups())) >= (1, 29, 0) else 1)'"
    check "the Warden starts a 1.29 policy, read as version 1.29" sh -c "'$WARDEN' '$OUT/p.txt' --check-startup 2>&1 | grep -q 'loaded policy .* v1.29 '"

    # the agent's files: W writable by anyone; a root-owned 0644 file and a
    # 0600 file in it; a directory the agent cannot search, with a file
    # anyone could read; a file only the test group may read
    chmod 755 "$OUT"
    mkdir -p "$OUT/bin" "$OUT/w" "$OUT/w/closed" "$OUT/w/tmpd"
    cp "$HERE/tests/v1290_open" "$OUT/bin/"
    chmod 1777 "$OUT/w" "$OUT/w/tmpd"
    echo root > "$OUT/w/rootfile";  chmod 644 "$OUT/w/rootfile"
    echo secret > "$OUT/w/private"; chmod 600 "$OUT/w/private"
    echo inside > "$OUT/w/closed/f"; chmod 644 "$OUT/w/closed/f"; chmod 700 "$OUT/w/closed"
    echo group > "$OUT/w/grp"
    pol() {   # pol FILE VERSION: the policy for these runs
        printf 'require warden %s\nallow path /usr/ readonly\nallow path /etc/ld.so.cache readonly\nallow path /dev/ readonly\nallow path %s/w/\n' \
            "$2" "$OUT" > "$1"
    }
    pol "$OUT/p129.txt" 1.29
    pol "$OUT/p128.txt" 1.28
    # run LOG POLICY RUNAS ARGS...: the program's output in LOG.out, the stream
    # in LOG; the agent inherits umask 027 (the filter refuses umask itself)
    run() {
        local log="$1" p="$2" ra="$3"; shift 3
        (umask 027; "$WARDEN" "$p" --run-as "$ra" -- "$OUT/bin/v1290_open" "$@" > "$log.out" 2> "$log")
    }
    # a raw device present here (refused by identity, whatever the policy)
    RAW=/dev/mem
    [ -e "$RAW" ] || RAW="$(find /dev -maxdepth 1 -type b 2>/dev/null | head -1)"
    # rec LOG PYEXPR: some record r of the stream satisfies PYEXPR
    rec() {
        python3 - "$1" "$2" <<'PY'
import json, sys
for line in open(sys.argv[1], errors="replace"):
    if not line.startswith("{"): continue
    try: r = json.loads(line)
    except ValueError: continue
    try:
        if eval(sys.argv[2]): sys.exit(0)
    except Exception: pass
sys.exit(1)
PY
    }
    NB=65534
    run "$OUT/a1.log" "$OUT/p129.txt" nobody create "$OUT/w/new" write "$OUT/w/rootfile" \
        read "$OUT/w/private" read "$OUT/w/closed/f" create "$OUT/w/closed/g" tmpfile "$OUT/w/tmpd" read "$RAW"
    check "the run ended" rec "$OUT/a1.log" "r.get('event') == 'run_end'"
    check "run_start records opening as the agent: nobody's uid, gid and groups" \
        rec "$OUT/a1.log" "r.get('event') == 'run_start' and r.get('open_as') == {'agent': True, 'uid': $NB, 'gid': $NB, 'groups': [$NB]}"
    check "a file the agent creates is the agent's (the agent sees it so)" grep -qx "create ok $NB $NB 640" "$OUT/a1.log.out"
    check "... and on disk: nobody's, with the agent's mode and umask" sh -c "[ \"\$(stat -c '%u %g %a' '$OUT/w/new')\" = '$NB $NB 640' ]"
    check "a root-owned 0644 file under a writable tree is not writable (the kernel's EACCES)" grep -qx "write Permission denied" "$OUT/a1.log.out"
    check "... and is unchanged" sh -c "[ \"\$(cat '$OUT/w/rootfile')\" = root ]"
    check "... recorded as the decision it was (ALLOW), the open failing with errno 13" \
        rec "$OUT/a1.log" "r.get('resolved') == '$OUT/w/rootfile' and r['decision_final'] == 'ALLOW' and r['rule'] == 'allowed_open_failed' and r['errno'] == 13"
    check "a root-only 0600 file under an allowed tree is not readable" sh -c "sed -n 3p '$OUT/a1.log.out' | grep -qx 'read Permission denied'"
    check "a file in a directory the agent cannot search is not opened" sh -c "sed -n 4p '$OUT/a1.log.out' | grep -qx 'read Permission denied'"
    check "... though its own mode lets anyone read it; recorded ALLOW, errno 13" \
        rec "$OUT/a1.log" "r.get('resolved') == '$OUT/w/closed/f' and r['decision_final'] == 'ALLOW' and r['errno'] == 13"
    check "nothing is created in a directory the agent cannot search" sh -c "sed -n 5p '$OUT/a1.log.out' | grep -qx 'create Permission denied' && [ ! -e '$OUT/w/closed/g' ]"
    check "... recorded ALLOW on the name it would have had, errno 13" \
        rec "$OUT/a1.log" "r.get('resolved') == '$OUT/w/closed/g' and r['decision_final'] == 'ALLOW' and r['errno'] == 13"
    check "an unnamed file (O_TMPFILE) the agent makes is the agent's" grep -qx "tmpfile ok $NB $NB" "$OUT/a1.log.out"
    check "a raw device ($RAW) is still refused by identity, though the policy allows /dev/" \
        rec "$OUT/a1.log" "r.get('resolved') == '$RAW' and r['decision_final'] == 'DENY' and r['rule'] == 'raw_device'"
    check "the stream stays root's, written to the end after the agent's opens" \
        sh -c "[ \"\$(stat -c %u '$OUT/a1.log')\" = 0 ] && tail -n 3 '$OUT/a1.log' | grep -q '\"event\":\"run_end\"'"

    # the same opens under a v1.28 policy: as root, as before
    rm -f "$OUT/w/new"
    run "$OUT/a2.log" "$OUT/p128.txt" nobody create "$OUT/w/new" write "$OUT/w/rootfile" read "$OUT/w/closed/f"
    check "require warden 1.28: no open_as in run_start" rec "$OUT/a2.log" "r.get('event') == 'run_start' and 'open_as' not in r"
    check "require warden 1.28: a created file is root's, as before" sh -c "[ \"\$(stat -c '%u %g' '$OUT/w/new')\" = '0 0' ]"
    check "require warden 1.28: the root-owned file is written, as before" sh -c "grep -qx 'write ok' '$OUT/a2.log.out' && [ \"\$(tail -n 1 '$OUT/w/rootfile')\" = x ]"
    check "require warden 1.28: the closed directory is reached, as before" grep -qx "read ok" "$OUT/a2.log.out"
    echo root > "$OUT/w/rootfile"

    # --run-as root: files opened as root, and run_start says why
    rm -f "$OUT/w/new"
    run "$OUT/a3.log" "$OUT/p129.txt" root create "$OUT/w/new"
    check "--run-as root under 1.29: run_start says the agent is root" \
        rec "$OUT/a3.log" "r.get('event') == 'run_start' and r.get('open_as') == {'agent': False, 'why': 'run_as_root'}"
    check "... and the file is root's" sh -c "[ \"\$(stat -c %u '$OUT/w/new')\" = 0 ]"

    # a user's supplementary groups: by name, the group's file is readable; as
    # uid:gid (no groups beyond the gid), it is not
    if groupadd "$TGROUP" >/dev/null 2>&1 && useradd -M -N -g nogroup -G "$TGROUP" -s /usr/sbin/nologin "$TUSER" >/dev/null 2>&1; then
        MADE_USER=1
        TU="$(id -u "$TUSER")" TG="$(getent group "$TGROUP" | cut -d: -f3)" PG="$(id -g "$TUSER")"
        chgrp "$TGROUP" "$OUT/w/grp"; chmod 640 "$OUT/w/grp"
        run "$OUT/a4.log" "$OUT/p129.txt" "$TUSER" read "$OUT/w/grp"
        check "a user named by --run-as: run_start lists its supplementary groups" \
            rec "$OUT/a4.log" "r.get('event') == 'run_start' and r['open_as']['uid'] == $TU and $TG in r['open_as']['groups']"
        check "... and a file its group may read is read" grep -qx "read ok" "$OUT/a4.log.out"
        run "$OUT/a5.log" "$OUT/p129.txt" "$TU:$PG" read "$OUT/w/grp"
        check "--run-as uid:gid: no supplementary groups, so the group's file is not read" \
            sh -c "grep -qx 'read Permission denied' '$OUT/a5.log.out'"
        check "the agent itself still has no supplementary groups (v1.17)" \
            sh -c "'$WARDEN' '$OUT/p129.txt' --run-as '$TUSER' -- /usr/bin/id -G 2>/dev/null | grep -qx '$PG'"
    else
        skip "supplementary groups (cannot add a test user and group here)"
    fi
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1290: all checks passed ($skips skipped)"; else echo "test_v1290: FAILURES"; fi
exit "$fail"
