#!/bin/bash
# SPDX-License-Identifier: MIT
# test_v1271.sh — VAREK v1.27.1: nothing written during the run is mapped
# executable (docs/security/v1.27.1-writable-noexec.md).
#
#   1. the writable directories (as root, with the warden binary): under
#      `require warden 1.27`, each allow path rule that lets the agent write
#      names a directory to mount noexec (a prefix ending in /, its own; one
#      that does not, its parent; a glob, the directory before its first
#      wildcard; an exact path, the file itself, or its parent while it does
#      not exist); readonly rules and deny rules name none; one inside another
#      is dropped; a missing directory is reported; a rule no directory bounds
#      (suffix, contains, a glob from a wildcard) and a writable / refuse the
#      start; the agent's own program under one refuses the start; a file of
#      the launch set under one is reported; --writable-exec turns the mounts
#      off and says so; without the opt-in there is no list; the Warden
#      reports 1.27.1
#
# Usage: test_v1271.sh <vdp_check> <vdp_cert_check> [<warden>]
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
trap '[ -n "${KEEP:-}" ] && echo "kept $OUT" || rm -rf "$OUT"' EXIT

echo "== 1. the writable directories =="
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ]; then
    skip "section 1 (needs root and the warden binary)"
else
    W="$(mktemp -d /tmp/varek_v1271.XXXXXX)"; chmod 755 "$W"
    trap '[ -n "${KEEP:-}" ] && echo "kept $OUT $W" || rm -rf "$OUT" "$W"' EXIT
    mkdir -p "$W/a/sub" "$W/b/c" "$W/ro" "$W/g/x" "$W/bin"; chmod -R 755 "$W"
    : > "$W/f.txt"
    cp /usr/bin/true "$W/bin/t"; chmod 755 "$W/bin/t"
    # nx <policy body> [warden options]: --check-startup, its report in $OUT/nx.out, its status in $OUT/nx.rc
    nx() { local b="$1"; shift
           printf 'require warden 1.27\n%b' "$b" > "$W/p.txt"; chmod 644 "$W/p.txt"
           # through a pipe: a policy allowing / would let the agent open a file the Warden writes to
           "$WARDEN" "$W/p.txt" "$@" --check-startup 2>&1 | cat > "$OUT/nx.out"; echo "${PIPESTATUS[0]}" > "$OUT/nx.rc"; }
    has()  { grep -qx "\[warden\]   noexec $1 (line $2)" "$OUT/nx.out"; }
    hasf() { grep -qx "\[warden\]   noexec $1 (a file) (line $2)" "$OUT/nx.out"; }
    count() { grep -q "^\[warden\] noexec: $1 writable director" "$OUT/nx.out"; }

    nx "allow path $W/a/\n"
    check "a prefix ending in /: its own directory" has "$W/a" 2
    nx "allow path $W/a/sub/out\n"
    check "a prefix not ending in /: its parent (it admits out2 too)" has "$W/a/sub" 2
    nx "allow path glob $W/g/*/log\n"
    check "a glob: the directory before its first wildcard" has "$W/g" 2
    nx "allow path exact $W/f.txt\n"
    check "an exact path that exists: the file itself" hasf "$W/f.txt" 2
    nx "allow path exact $W/b/new.txt\n"
    check "an exact path that does not exist yet: its directory" has "$W/b" 2
    nx "allow path $W/ro/ readonly\nallow path $W/a/ access=rw\n"
    check "a readonly rule names none; access=rw does" sh -c "$(declare -f has count); OUT='$OUT'; count 1 && has '$W/a' 3"
    nx "allow path $W/ro/x access=ro\n"
    check "access=ro alone is writable (it admits O_TRUNC)" has "$W/ro" 2
    nx "deny path $W/a/\nallow path $W/ro/ readonly\n"
    check "deny rules and readonly rules: no directory" count 0
    nx "allow path $W/a/sub/\nallow path $W/a/\n"
    check "one inside another is dropped, the outer kept" sh -c "$(declare -f has count); OUT='$OUT'; count 1 && has '$W/a' 3"
    nx "allow path $W/missing/\n"
    check "a directory that does not exist: reported, listed as not there, none mounted" \
        sh -c "grep -q 'noexec: policy line 2: $W/missing does not exist' '$OUT/nx.out' && grep -q 'noexec: 0 writable directories to mount noexec, 1 not there' '$OUT/nx.out' && grep -qx '\[warden\]   noexec $W/missing (not there; opens under it refused if it appears) (line 2)' '$OUT/nx.out' && grep -qx 0 '$OUT/nx.rc'"
    # v1.27.1 review: a glob with no wildcard is an exact path; a relative glob matches nothing
    nx "allow path glob $W/g/new.so\n"
    check "a glob with no wildcard, not there yet: its directory, as an exact path" has "$W/g" 2
    nx "allow path glob $W/f.txt\n"
    check "a glob with no wildcard naming a file: the file itself" hasf "$W/f.txt" 2
    nx "allow path glob rel/*.so\n"
    check "a relative glob matches no absolute path: nothing, and the start goes on" sh -c "grep -qx 0 '$OUT/nx.rc' && grep -q 'noexec: 0 writable directories' '$OUT/nx.out'"
    # v1.27.1 review: the interpreter of the agent's own program under a writable directory
    printf '#!%s/bin/t\n' "$W" > "$OUT/s.sh"; chmod 755 "$OUT/s.sh"
    printf 'require warden 1.27\nallow path %s/bin/\n' "$W" > "$W/p.txt"
    "$WARDEN" "$W/p.txt" --check-startup -- "$OUT/s.sh" > "$OUT/it.out" 2>&1; echo $? > "$OUT/it.rc"
    check "the interpreter the agent's own program needs, under a writable directory, refuses the start" \
        sh -c "grep -qx 1 '$OUT/it.rc' && grep -q 'the interpreter a launch needs, is under $W/bin' '$OUT/it.out'"
    nx "allow path suffix .log\n"
    check "a writable suffix rule refuses the start" \
        sh -c "grep -qx 1 '$OUT/nx.rc' && grep -q 'line 2 lets the agent write paths no directory bounds' '$OUT/nx.out'"
    nx "allow path contains /cache/\n"
    check "a writable contains rule refuses the start" grep -qx 1 "$OUT/nx.rc"
    nx "allow path glob */out\n"
    check "a writable glob from a wildcard refuses the start" grep -qx 1 "$OUT/nx.rc"
    nx "allow path /\n"
    check "a writable / refuses the start" \
        sh -c "grep -qx 1 '$OUT/nx.rc' && grep -q 'write under /, which cannot be mounted noexec' '$OUT/nx.out'"
    nx "allow path /\n" --writable-exec
    check "--writable-exec turns the mounts off, and the Warden says so" \
        sh -c "grep -qx 0 '$OUT/nx.rc' && grep -q 'noexec: off (--writable-exec)' '$OUT/nx.out'"
    nx "allow exec $W/bin/t\nallow path $W/bin/\n"
    check "a file of the launch set under one: reported, it will not launch" \
        sh -c "grep -qx 0 '$OUT/nx.rc' && grep -q 'noexec: $W/bin/t (in the launch set) is under $W/bin, which policy line 3 lets the agent write; it will not launch' '$OUT/nx.out'"
    printf 'require warden 1.27\nallow path %s/\n' "$W/bin" > "$W/p.txt"; chmod 644 "$W/p.txt"
    "$WARDEN" "$W/p.txt" --check-startup -- "$W/bin/t" > "$OUT/nx.out" 2>&1; echo $? > "$OUT/nx.rc"
    check "the agent's own program under one refuses the start" \
        sh -c "grep -qx 1 '$OUT/nx.rc' && grep -q 'the agent.s own program $W/bin/t is under $W/bin' '$OUT/nx.out'"
    printf 'allow path %s/a/\n' "$W" > "$W/p26.txt"; chmod 644 "$W/p26.txt"
    "$WARDEN" "$W/p26.txt" --check-startup > "$OUT/nx.out" 2>&1
    check "without the opt-in (require warden 1.26 or none): no list" sh -c "! grep -q noexec '$OUT/nx.out'"
    check "the Warden reports 1.27.1 or later" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | python3 -c 'import re,sys; m=re.search(r\"VAREK Warden  (\\d+)\\.(\\d+)\\.(\\d+)\", sys.stdin.read()); sys.exit(0 if m and tuple(map(int, m.groups())) >= (1, 27, 1) else 1)'"
fi

echo "== 2. the mounts =="
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ]; then
    skip "section 2 (needs root and the warden binary)"
else
    M="$(mktemp -d /tmp/varek_v1271m.XXXXXX)"; chmod 755 "$M"
    mkdir -p "$M/w" "$M/s" "$M/ns" "$M/e"; : > "$M/e/f"; chmod -R 755 "$M"
    mount -t tmpfs -o size=1m tmpfs "$M/s" && mkdir -p "$M/s/in" && mount -t tmpfs -o size=1m tmpfs "$M/s/in"
    mount -t tmpfs -o size=1m,nosuid tmpfs "$M/ns"
    chmod 755 "$M/s" "$M/s/in" "$M/ns"
    trap 'umount "$M/s/in" "$M/s" "$M/ns" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT" || rm -rf "$OUT" "${W:-}" "$M"' EXIT
    # mi <policy body> [warden options]: the agent's /proc/self/mountinfo in $OUT/mi.out
    mi() { local b="$1"; shift
           printf 'require warden 1.27\n%ballow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path /proc/ readonly\n' "$b" > "$M/p.txt"
           chmod 644 "$M/p.txt"
           (cd "$M" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$M/p.txt" "$@" -- /usr/bin/cat /proc/self/mountinfo > "$OUT/mi.out" 2> "$OUT/mi.log"); }
    opts() { awk -v m="$1" '$5 == m { print $6 }' "$OUT/mi.out" | tail -1; }
    grep -v " $M" /proc/self/mountinfo | awk '{print $5, $6}' | sort > "$OUT/host.before"
    mi "allow path $M/w/\nallow path $M/s/\nallow path $M/ns/\nallow path exact $M/e/f\n"
    check "the agent sees each writable directory mounted noexec" sh -c "awk -v m='$M/w' '\$5 == m' '$OUT/mi.out' | grep -q noexec"
    check "a mount beneath one is mounted noexec too" sh -c "awk -v m='$M/s/in' '\$5 == m' '$OUT/mi.out' | tail -1 | grep -q noexec"
    check "a mount's own flags are kept (nosuid)" sh -c "awk -v m='$M/ns' '\$5 == m' '$OUT/mi.out' | tail -1 | grep -q 'nosuid.*noexec\|noexec.*nosuid'"
    check "an exact path that is a file: the file itself, noexec" sh -c "awk -v m='$M/e/f' '\$5 == m' '$OUT/mi.out' | grep -q noexec"
    check "the Warden says what it mounted" grep -q 'noexec: 4 writable directories mounted noexec' "$OUT/mi.log"
    check "a read-only path is not touched" sh -c "! awk -v m='/usr' '\$5 == m' '$OUT/mi.out' | grep -q noexec || awk '\$5 == \"/usr\"' /proc/self/mountinfo | grep -q noexec"
    grep -v " $M" /proc/self/mountinfo | awk '{print $5, $6}' | sort > "$OUT/host.after"
    check "the host's mounts are unchanged by the run" sh -c "cmp -s '$OUT/host.before' '$OUT/host.after' && ! grep -q ' $M/w ' /proc/self/mountinfo"
    # v1.27.1 review: nosymfollow kept; a mount beneath whose mountinfo line is long
    mkdir -p "$M/y/nsf" "$M/l/sub"; chmod -R 755 "$M/y" "$M/l"
    mount -t tmpfs -o size=1m,nosymfollow tmpfs "$M/y/nsf" && chmod 755 "$M/y/nsf"
    LONG="$M/deep"; for i in 1 2 3 4 5 6 7 8 9 10 11 12; do LONG="$LONG/$(printf '%200s' '')"; done
    mkdir -p "$LONG" && chmod -R 755 "$M/deep" && mount --bind "$LONG" "$M/l/sub"
    trap 'umount "$M/s/in" "$M/s" "$M/ns" "$M/y/nsf" "$M/l/sub" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT" || rm -rf "$OUT" "${W:-}" "$M"' EXIT
    mi "allow path $M/y/\nallow path $M/l/\n"
    check "a mount's nosymfollow is kept" sh -c "awk -v m='$M/y/nsf' '\$5 == m' '$OUT/mi.out' | tail -1 | grep -q 'noexec.*nosymfollow\|nosymfollow.*noexec'"
    check "a mount beneath one whose mountinfo line is over 8 KB is mounted noexec too" \
        sh -c "[ \$(grep ' $M/l/sub ' /proc/self/mountinfo | wc -c) -gt 8192 ] && awk -v m='$M/l/sub' '\$5 == m' '$OUT/mi.out' | tail -1 | grep -q noexec"
    umount "$M/y/nsf" "$M/l/sub" 2>/dev/null
    mi "allow path $M/w/\n" --writable-exec
    check "--writable-exec: no noexec mount" sh -c "! awk -v m='$M/w' '\$5 == m' '$OUT/mi.out' | grep -q ."
    printf 'require warden 1.26\nallow path %s/w/\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path /proc/ readonly\n' "$M" > "$M/p26.txt"; chmod 644 "$M/p26.txt"
    (cd "$M" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$M/p26.txt" -- /usr/bin/cat /proc/self/mountinfo > "$OUT/mi.out" 2> "$OUT/mi.log")
    check "without the opt-in: no noexec mount" sh -c "! awk -v m='$M/w' '\$5 == m' '$OUT/mi.out' | grep -q ."
fi

echo "== 3. what the agent sees =="
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ]; then
    skip "section 3 (needs root and the warden binary)"
else
    A="$(mktemp -d /tmp/varek_v1271a.XXXXXX)"; chmod 755 "$A"; mkdir -p "$A/w" "$A/bin"; chmod 755 "$A/w" "$A/bin"
    cp "$HERE/tests/v1271_probe.py" "$A/"; chmod 644 "$A/v1271_probe.py"
    trap 'umount "${M:-/nonexistent}/s/in" "${M:-/nonexistent}/s" "${M:-/nonexistent}/ns" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT" || rm -rf "$OUT" "${W:-}" "${M:-}" "$A"' EXIT
    BASE="allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path /proc/ readonly\nallow path $A/v1271_probe.py readonly\n"
    probe() { local o="$1" b="$2"; shift 2
              rm -rf "$A/w"/*; printf 'require warden 1.27\n%b%b' "$b" "$BASE" > "$A/p.txt"; chmod 644 "$A/p.txt"
              (cd "$A" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$A/p.txt" "$@" -- /usr/bin/python3 "$A/v1271_probe.py" "$A/w" > "$OUT/$o.out" 2> "$OUT/$o.log"); }
    probe on "allow path $A/w/\n"
    got() { grep -qx "$2" "$OUT/$1.out"; }
    check "a system library at its own path loads" got on "LIB_ORIGINAL loaded"
    check "a copy of it in a writable directory cannot be loaded" got on "LIB_COPY refused"
    check "a copy of a Python extension module cannot be imported" sh -c "grep -qx 'EXT_COPY refused' '$OUT/on.out' || grep -qx 'EXT_COPY skipped' '$OUT/on.out'"
    check "a pure-Python module written there imports" got on "PURE_PY imported"
    check "mmap with PROT_EXEC of a file there: EPERM" got on "MMAP_EXEC refused Operation not permitted"
    check "mprotect adding PROT_EXEC to a mapping of it: EACCES" got on "MPROTECT_EXEC refused Permission denied"
    check "anonymous memory may still be made executable" got on "ANON_EXEC mapped"
    check "a ctypes callback (libffi) works" got on "CALLBACK ok"
    check "the agent goes on, and the Warden exits 0" sh -c "[ \$(wc -l < '$OUT/on.out') -eq 8 ] && grep -q 'noexec: 1 writable directory mounted noexec' '$OUT/on.log'"
    check "the audit accepts the run" python3 "$HERE/tools/varek_audit.py" --policy "$A/p.txt" --checker "$CERT" "$OUT/on.log"
    # v1.27.1 review: the Warden (and so the agent) started inside the writable directory
    (cd "$A/w" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$A/p.txt" -- /usr/bin/python3 "$A/v1271_probe.py" "$A/w" > "$OUT/cw.out" 2> "$OUT/cw.log")
    check "from a working directory inside it, a copy by a relative name cannot be loaded or mapped either" \
        sh -c "grep -qx 'REL_LIB_COPY refused' '$OUT/cw.out' && grep -qx 'REL_MMAP_EXEC refused Operation not permitted' '$OUT/cw.out' && grep -qx 'LIB_COPY refused' '$OUT/cw.out'"
    # v1.27.1 review: a writable directory the host makes during the run, and
    # a file an exact rule names that the host replaces during the run: the
    # agent's opens there are refused (they reach no noexec mount)
    rm -rf "$A/late"; : > "$A/w/f.txt"; chmod 666 "$A/w/f.txt"
    printf 'require warden 1.27\nallow path %s/late/\nallow path exact %s/w/f.txt\n%b' "$A" "$A" "$BASE" > "$A/p.txt"; chmod 644 "$A/p.txt"
    LATE='import time
def op(n, p, m):
    try:
        open(p, m).close(); print(n, "opened", flush=True)
    except OSError as e:
        print(n, "refused", e.errno, flush=True)
op("BOUND_BEFORE", "'"$A/w/f.txt"'", "r")
time.sleep(3)
op("LATE", "'"$A/late/x"'", "w")
op("BOUND_AFTER", "'"$A/w/f.txt"'", "r")'
    ( sleep 1; mkdir -m 777 "$A/late"; : > "$A/f.new"; chmod 666 "$A/f.new"; mv "$A/f.new" "$A/w/f.txt" ) &
    (cd "$A" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$A/p.txt" -- /usr/bin/python3 -c "$LATE" > "$OUT/late.out" 2> "$OUT/late.log")
    wait
    check "a writable directory missing at start: listed, and if the host makes it during the run the agent's opens there are refused" \
        sh -c "grep -qx 'LATE refused 13' '$OUT/late.out' && grep -q 'reached through a mount that is not noexec' '$OUT/late.log'"
    check "a file an exact rule names, replaced by the host during the run: opened before, refused after" \
        sh -c "grep -qx 'BOUND_BEFORE opened' '$OUT/late.out' && grep -qx 'BOUND_AFTER refused 13' '$OUT/late.out'"
    probe off "allow path $A/w/\n" --writable-exec
    check "with --writable-exec the copy loads, as on v1.27.0" sh -c "grep -qx 'LIB_COPY loaded' '$OUT/off.out' && grep -qx 'MMAP_EXEC mapped' '$OUT/off.out'"
    # a file of the launch set under a writable directory: allowed, but the kernel refuses it
    cp /usr/bin/true "$A/bin/t"; chmod 755 "$A/bin/t"
    printf 'import subprocess\ntry:\n    print("LAUNCH", subprocess.run(["%s/bin/t"]).returncode, flush=True)\nexcept OSError as e:\n    print("LAUNCH refused", e.errno, flush=True)\n' "$A" > "$A/v1271_probe.py"
    printf 'require warden 1.27\nallow exec %s/bin/t\nallow path %s/bin/\n%b' "$A" "$A" "$BASE" > "$A/p.txt"; chmod 644 "$A/p.txt"
    (cd "$A" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$A/p.txt" -- /usr/bin/python3 "$A/v1271_probe.py" > "$OUT/l.out" 2> "$OUT/l.log")
    check "a launch-set file under a writable directory: reported, and the kernel refuses its launch (EACCES)" \
        sh -c "grep -qx 'LAUNCH refused 13' '$OUT/l.out' && grep -q 'it will not launch' '$OUT/l.log' && grep -Eq '\"result\":\"(failed|gone)\"' '$OUT/l.log'"
fi

echo "== 4. records, audit and tools =="
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ]; then
    skip "section 4 (needs root and the warden binary)"
else
    R="$(mktemp -d /tmp/varek_v1271r.XXXXXX)"; chmod 755 "$R"; mkdir -p "$R/w" "$R/ro"; chmod 755 "$R/w" "$R/ro"
    trap 'umount "${M:-/nonexistent}/s/in" "${M:-/nonexistent}/s" "${M:-/nonexistent}/ns" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $OUT" || rm -rf "$OUT" "${W:-}" "${M:-}" "${A:-}" "$R"' EXIT
    printf 'require warden 1.27\nallow path %s/w/\nallow path %s/ro/ readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' "$R" "$R" > "$R/p.txt"; chmod 644 "$R/p.txt"
    (cd "$R" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$R/p.txt" -- /usr/bin/true 2> "$OUT/r.log")
    (cd "$R" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$R/p.txt" --writable-exec -- /usr/bin/true 2> "$OUT/rx.log")
    rs() { python3 - "$1" "$2" <<'PY'
import json, sys
r = next(json.loads(l[l.index("{"):]) for l in open(sys.argv[1], errors="replace") if '"event":"run_start"' in l)
sys.exit(0 if eval(sys.argv[2]) else 1)
PY
    }
    check "run_start records each directory mounted noexec, with its policy line" \
        rs "$OUT/r.log" "r['noexec'] == [{'path': '$R/w', 'target': '$R/w', 'policy_line': 2}] and tuple(map(int, r['warden'].split('.'))) >= (1, 27, 1)"
    check "with --writable-exec, run_start records noexec null" rs "$OUT/rx.log" "r['noexec'] is None"
    # v1.27.1 review: a descriptor the agent would inherit, open for reading on a file there
    : > "$R/w/in"; chmod 644 "$R/w/in"
    (cd "$R" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$R/p.txt" -- /usr/bin/true < "$R/w/in" > /dev/null 2> "$OUT/in.log"); echo $? > "$OUT/in.rc"
    check "standard input open on a file in a writable directory refuses the start" \
        sh -c "! grep -qx 0 '$OUT/in.rc' && grep -q 'descriptor 0, which the agent would inherit' '$OUT/in.log'"
    (cd "$R" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$R/p.txt" -- /usr/bin/true < /dev/null >> "$R/w/out" 2> "$OUT/in2.log"); echo $? > "$OUT/in2.rc"
    check "output appended to a file there does not (it cannot be read)" grep -qx 0 "$OUT/in2.rc"
    rm -f "$R/w/in" "$R/w/out"
    audit() { python3 "$HERE/tools/varek_audit.py" --policy "$R/p.txt" --checker "$CERT" "$1" > "$OUT/a.out" 2>&1; }
    check "the audit accepts the run" audit "$OUT/r.log"
    check "the audit accepts a --writable-exec run, and says so" \
        sh -c "$(declare -f audit); HERE='$HERE' R='$R' CERT='$CERT' OUT='$OUT'; audit '$OUT/rx.log' && grep -q 'note: the Warden ran with --writable-exec' '$OUT/a.out'"
    F="$HERE/tests/v1270_forge.py"
    RS='rs = next(r for r in recs if isinstance(r, dict) and r.get("event") == "run_start")'
    refuses() { if python3 "$HERE/tools/varek_audit.py" --policy "$R/p.txt" --checker "$CERT" "$2" > "$OUT/f.out" 2>&1; then
                    flunk "the audit refuses $1"
                elif grep -qF "$3" "$OUT/f.out"; then pass "the audit refuses $1"
                else flunk "the audit refuses $1 ($(grep -m1 PROBLEM "$OUT/f.out"))"; fi; }
    python3 "$F" "$OUT/r.log" "$OUT/n1.log" "$RS; rs['noexec'][0]['policy_line'] = 3"
    refuses "a directory mounted for a line that does not let the agent write" "$OUT/n1.log" "which does not let the agent write"
    python3 "$F" "$OUT/r.log" "$OUT/n2.log" "$RS; del rs['noexec']"
    refuses "a 1.27.1 run with no noexec record" "$OUT/n2.log" "records its noexec mounts, but has none"
    python3 "$F" "$OUT/r.log" "$OUT/n3.log" "$RS; rs['noexec'] = [{'path': 'w', 'policy_line': 2}]"
    refuses "a noexec record that is not absolute paths" "$OUT/n3.log" "noexec is malformed"
    python3 "$F" "$OUT/r.log" "$OUT/n4.log" "$RS; rs['noexec'].append(dict(rs['noexec'][0]))"
    refuses "a directory named twice" "$OUT/n4.log" "names a directory twice"
    python3 "$F" "$OUT/r.log" "$OUT/n5.log" "$RS; rs['noexec'] = [{'path': '/', 'target': '/', 'policy_line': 2}]"
    refuses "/ mounted noexec" "$OUT/n5.log" "mounts /, which the Warden refuses"
    # v1.27.1 review: each entry against its rule, and the list against the writes recorded
    python3 "$F" "$OUT/r.log" "$OUT/n6.log" "$RS; rs['noexec'][0]['path'] = '/etc'"
    refuses "another directory named for a writable rule's" "$OUT/n6.log" "matches no path the Warden resolves"
    python3 "$F" "$OUT/r.log" "$OUT/n7.log" "$RS; rs['noexec'] = [{'path': '$R/ro', 'target': '$R/ro', 'policy_line': 2}]"
    refuses "a read-only directory named in place of the writable one" "$OUT/n7.log" "the rule's is '$R/w'"
    python3 "$F" "$OUT/r.log" "$OUT/n8.log" "$RS; rs['noexec'][0]['path'] = rs['noexec'][0]['target'] = '$R/w/.'"
    refuses "a directory not spelled canonically" "$OUT/n8.log" "not spelled as a canonical path"
    python3 "$F" "$OUT/r.log" "$OUT/n9.log" "$RS; rs['noexec'].append({'path': '$R/w/sub', 'target': '$R/w', 'policy_line': 2})"
    refuses "one directory inside another" "$OUT/n9.log" "inside '$R/w'"
    python3 "$F" "$OUT/r.log" "$OUT/n10.log" "$RS; rs['noexec'][0]['file'] = True"
    refuses "a file named for a rule that names a directory" "$OUT/n10.log" "names no single file there"
    python3 "$F" "$OUT/r.log" "$OUT/n11.log" "$RS; rs['warden'] = '1.27.0'"
    refuses "a noexec record from a Warden before 1.27.1" "$OUT/n11.log" "which mounts nothing noexec"
    (cd "$R" && env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$R/p.txt" -- /usr/bin/touch "$R/w/made" 2> "$OUT/r2.log")
    check "the audit accepts a run that writes in the directory it lists" \
        python3 "$HERE/tools/varek_audit.py" --policy "$R/p.txt" --checker "$CERT" "$OUT/r2.log"
    python3 "$F" "$OUT/r2.log" "$OUT/n12.log" "$RS; rs['noexec'] = []"
    refuses "an empty list when the stream records a write" "$OUT/n12.log" "for writing, under no directory"
    python3 "$F" "$OUT/r.log" "$OUT/n13.log" "$RS; rs['noexec'] = []"
    refuses "a list that leaves out a writable rule's directory" "$OUT/n13.log" "which run_start's noexec does not list"
    rm -f "$R/w/made"
    NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" policy show "$R/p.txt" > "$OUT/ps.out" 2>&1
    check "varek policy show lists the directories it would mount noexec" \
        sh -c "grep -q 'Mounted noexec (v1.27.1)' '$OUT/ps.out' && grep -qx '  $R/w (line 2)' '$OUT/ps.out'"
    printf 'require warden 1.27\nallow path %s/missing/\n' "$R" > "$R/pm.txt"; chmod 644 "$R/pm.txt"
    NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" policy show "$R/pm.txt" > "$OUT/pm.out" 2>&1
    check "varek policy show names a writable directory missing on this host, not \"nowhere\"" \
        sh -c "grep -q '  $R/missing (not there; opens under it refused if it appears) (line 2)' '$OUT/pm.out' && ! grep -q 'write nowhere' '$OUT/pm.out'"
    NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" doctor > "$OUT/dr.out" 2>&1
    check "varek doctor checks the Warden can make a mount namespace" grep -q 'OK    Mount namespaces' "$OUT/dr.out"
    python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/r.log" --policy "$R/p.txt" --output "$OUT/bom.json" > /dev/null 2>&1
    python3 "$HERE/tools/varek_cyclonedx.py" --log "$OUT/rx.log" --policy "$R/p.txt" --output "$OUT/bomx.json" > /dev/null 2>&1
    bomfact() { python3 - "$1" "$2" "$3" <<'PY'
import json, sys
def walk(o):
    if isinstance(o, dict):
        if o.get("name") == sys.argv[2] and "value" in o: yield o["value"]
        for v in o.values(): yield from walk(v)
    elif isinstance(o, list):
        for v in o: yield from walk(v)
sys.exit(0 if sys.argv[3] in walk(json.load(open(sys.argv[1]))) else 1)
PY
    }
    check "the CycloneDX export carries the noexec facts (varek:noexec.dirs, varek:noexec.off)" \
        sh -c "$(declare -f bomfact); bomfact '$OUT/bom.json' varek:noexec.dirs 1 && bomfact '$OUT/bomx.json' varek:noexec.off true"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1271: PASS ($skips skipped)"; exit 0; fi
echo "test_v1271: FAIL"; exit 1
