#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1270.sh — v1.27.0, decided program launches: the parts built so far
# (docs/security/v1.27-program-launches.md).
#
#   1. the grammar and the opt-in: `require warden 1.27` is accepted by the
#      decision procedure and the certificate checker, and a later one refused
#      by both; launches after the first are decided only after it (both
#      parsers say so, and every shipped policy pack keeps its v1.26 meaning);
#      the policy check notes an exec rule for a shell or interpreter, a file
#      both launched and written, and exec rules without the opt-in; `varek
#      policy show` says whether launches are decided; the Warden loads such a
#      policy, reports grammar 1.27 and prints the same notes
#
# Usage: test_v1270.sh <vdp_check> <vdp_cert_check> [<warden>]
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

echo "== 1. the grammar and the opt-in =="
accepted() {
    printf '%b' "$2" > "$OUT/p.txt"
    if "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1 && "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then
        pass "accepted: $1"
    else flunk "accepted: $1 ($("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null | head -1))"; fi
}
refused() {
    printf '%b' "$2" > "$OUT/p.txt"
    local e
    e="$("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null)"
    if "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1; then flunk "refused: $1 (the procedure loaded it)"
    elif "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then flunk "refused: $1 (the checker loaded it)"
    elif ! printf '%s' "$e" | grep -qF -- "$3"; then flunk "refused: $1 (message: $e)"
    else pass "refused: $1"; fi
}
# launches <description> <policy text> <on|off>: both parsers say so
launches() {
    printf '%b' "$2" > "$OUT/l.txt"
    local a b
    a="$("$VDP" "$OUT/l.txt" launches 2>&1)"; b="$("$CERT" "$OUT/l.txt" launches 2>&1)"
    if [ "$a" = "$3" ] && [ "$b" = "$3" ]; then pass "launches $3: $1"
    else flunk "launches $3: $1 (procedure $a, checker $b)"; fi
}
X='allow exec /usr/bin/git\nallow path /usr/ readonly\n'
accepted "require warden 1.27"                 'require warden 1.27\n'
accepted "with exec rules"                     "require warden 1.27\n$X"
accepted "with exec matchers"                  'require warden 1.27\nallow exec prefix /usr/bin/\ndeny exec glob /usr/bin/*sh\n'
accepted "with the v1.26 proxy"                'require warden 1.27\nproxy inspect\nallow host api.example.com:443\nallow request GET https://api.example.com/x\n'
refused  "require warden 1.28"                 'require warden 1.28\n'                 "this is 1.27"
refused  "require warden 2.0"                  'require warden 2.0\n'                  "this is 1.27"
launches "no require"                          "$X"                                    off
launches "require warden 1.26"                 "require warden 1.26\n$X"               off
launches "require warden 1.27"                 "require warden 1.27\n$X"               on
launches "1.27 with no exec rule"              'require warden 1.27\n'                 on
launches "1.26, then 1.27"                     "require warden 1.26\nrequire warden 1.27\n$X" on
launches "1.27, then 1.24 (the highest holds)" "require warden 1.27\nrequire warden 1.24\n$X" on
# the shipped packs keep their v1.26 meaning: their exec rules decide only the
# agent's own launch until a pack says require warden 1.27
packs=0 packs_off=0
for f in "$HERE"/policies/*.txt; do
    packs=$((packs + 1))
    [ "$("$VDP" "$f" launches 2>/dev/null)" = off ] && [ "$("$CERT" "$f" launches 2>/dev/null)" = off ] &&
        packs_off=$((packs_off + 1))
done
if [ "$packs" -gt 0 ] && [ "$packs" = "$packs_off" ]; then
    pass "every shipped policy pack ($packs) keeps launches off"
else flunk "every shipped policy pack keeps launches off ($packs_off of $packs)"; fi

# the policy check's notes
lint() { printf '%b' "$1" > "$OUT/n.txt"; "$VDP" "$OUT/n.txt" lint > "$OUT/n.out" 2>&1; echo $? > "$OUT/n.rc"; }
lint "require warden 1.27\nallow exec /usr/bin/python3\nallow exec /usr/bin/python3.12\nallow exec /bin/bash\nallow exec /usr/bin/git\nallow path /usr/ readonly\n"
check "lint notes an interpreter allowed to launch" grep -q ':2: note: /usr/bin/python3 is a shell or general-purpose interpreter' "$OUT/n.out"
check "and one with a version (python3.12)" grep -q ':3: note: /usr/bin/python3.12 is a shell' "$OUT/n.out"
check "and a shell (bash)" grep -q ':4: note: /bin/bash is a shell' "$OUT/n.out"
check "but not git" sh -c "! grep -q ':5: note' '$OUT/n.out'"
check "notes do not fail lint" grep -qx 0 "$OUT/n.rc"
check "with the opt-in, no note about it" sh -c "! grep -q 'only with .require warden 1.27.' '$OUT/n.out'"
lint "require warden 1.27\nallow exec /usr/bin/git\nallow path /usr/bin/git\nallow exec /usr/bin/make\nallow path /usr/bin/make readonly\nallow exec /usr/bin/cc\nallow path /usr/bin/cc access=wo\n"
check "lint notes a file both launched and written" grep -q ':2: note: /usr/bin/git may be both launched and written' "$OUT/n.out"
check "not one the policy opens only to read" sh -c "! grep -q ':4: note' '$OUT/n.out'"
check "and one writable only (access=wo)" grep -q ':6: note: /usr/bin/cc may be both launched and written' "$OUT/n.out"
lint "require warden 1.26\nallow exec /usr/bin/git\nallow exec /usr/bin/make\nallow path /usr/ readonly\n"
check "without the opt-in, lint says exec rules decide only the first launch (once)" \
    sh -c "[ \$(grep -c 'only with .require warden 1.27.' '$OUT/n.out') = 1 ] && grep -q ':2: note: exec rules take effect' '$OUT/n.out'"
lint "require warden 1.26\ndeny exec /usr/bin/git\nallow path /usr/ readonly\n"
check "and nothing for a deny exec rule alone" sh -c "! grep -q 'require warden 1.27' '$OUT/n.out'"

# varek policy show
show() { printf '%b' "$1" > "$OUT/s.txt"; NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 "$HERE/tools/varek" policy show "$OUT/s.txt" > "$OUT/s.out" 2>&1; }
show "require warden 1.27\n$X"
check "varek policy show: launches decided by the exec rules" grep -q '^Launches decided by the exec rules (require warden 1.27)' "$OUT/s.out"
show "require warden 1.27\nallow path /usr/ readonly\n"
check "varek policy show: decided, but no exec rule allows one" grep -q 'no exec rule allows one' "$OUT/s.out"
show "require warden 1.26\n$X"
check "varek policy show: refused without the opt-in" grep -q "^Launches after the agent's own are refused" "$OUT/s.out"
show "require warden 1.26\nallow path /usr/ readonly\n"
check "varek policy show: nothing about launches without exec rules" sh -c "! grep -q '^Launches' '$OUT/s.out'"

if [ -n "$WARDEN" ] && [ "$(id -u)" = 0 ]; then
    printf 'require warden 1.27\nallow exec /usr/bin/python3\n%b' "$X" > "$OUT/w.txt"
    "$WARDEN" "$OUT/w.txt" --check-startup > "$OUT/w.out" 2>&1; rc=$?
    check "the Warden loads a 1.27 policy" grep -q 'startup checks passed' "$OUT/w.out"
    check "and reports grammar 1.27" grep -q 'loaded policy default v1\.27 ' "$OUT/w.out"
    check "with the interpreter note" grep -q 'note: /usr/bin/python3 is a shell or general-purpose interpreter' "$OUT/w.out"
    printf 'require warden 1.26\n%b' "$X" > "$OUT/w.txt"
    "$WARDEN" "$OUT/w.txt" --check-startup > "$OUT/w.out" 2>&1
    check "a 1.26 policy with exec rules loads, with the opt-in note" \
        sh -c "grep -q 'startup checks passed' '$OUT/w.out' && grep -q 'only with .require warden 1.27.' '$OUT/w.out'"
    printf 'require warden 1.28\n' > "$OUT/w.txt"
    check "the Warden refuses require warden 1.28" sh -c "! '$WARDEN' '$OUT/w.txt' --check-startup"
else
    skip "the Warden's load (needs root and the warden binary)"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1270: PASS ($skips skipped)"; exit 0; fi
echo "test_v1270: FAIL"; exit 1
