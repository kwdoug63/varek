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
    check "a directory that does not exist: reported, none mounted" \
        sh -c "grep -q 'noexec: policy line 2: $W/missing does not exist' '$OUT/nx.out' && grep -q 'noexec: 0 writable directories' '$OUT/nx.out' && grep -qx 0 '$OUT/nx.rc'"
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
    check "the Warden reports 1.27.1" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | grep -q 'VAREK Warden  1.27.1'"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1271: PASS ($skips skipped)"; exit 0; fi
echo "test_v1271: FAIL"; exit 1
