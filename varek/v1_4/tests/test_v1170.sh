#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1170.sh — regression test for VAREK v1.17.0.
#
#   1. The signing key, the verdict stream and the anchor are refused by
#      identity: reached through a bind mount inside the allowed tree, every
#      open and lookup is denied ("protected_object"). Raw devices planted in
#      the allowed tree are denied ("raw_device"). An ordinary file still opens.
#   2. stat, statx, access and readlink are mediated: decided like a read-only
#      open, recorded, answered by the Warden. Outside the policy they say
#      EACCES (existence is not revealed), inside it ENOENT for a missing name;
#      realpath() works on an allowed path; a held descriptor's fstat works.
#   3. The agent runs as an unprivileged user with no capabilities; --run-as
#      picks the user; --run-as root keeps the old behaviour with a warning.
#
# Against v1.16.3 the key, stream and anchor are read through the alias, the
# lookups outside the policy succeed unrecorded, and the agent is uid 0 with
# every capability.
#
# Usage: ./test_v1170.sh <warden> <vdp_cert_check> <varek_keygen> <probe>
set -u

WARDEN="${1:?usage: test_v1170.sh <warden> <vdp_cert_check> <varek_keygen> <probe>}"
CERT="${2:?}"
KEYGEN="${3:?}"
PROBE="${4:?}"
abs() { case "$1" in /*) echo "$1";; *) echo "$PWD/$1";; esac; }
WARDEN="$(abs "$WARDEN")"; CERT="$(abs "$CERT")"; KEYGEN="$(abs "$KEYGEN")"; PROBE="$(abs "$PROBE")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
POL="$HERE/tests/v1170_policy.txt"
AUDIT="$HERE/tools/varek_audit.py"

fail=0
pass() { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }

D=/tmp/varek_v1170
OUT="$(mktemp -d)"
cleanup() {
    umount "$D/allowed/keys" 2>/dev/null; umount "$D/allowed/logs" 2>/dev/null
    rm -rf "$D" "$OUT"
}
trap cleanup EXIT
cleanup; OUT="$(mktemp -d)"
mkdir -p "$D/allowed/ro" "$D/allowed/sub" "$D/allowed/keys" "$D/allowed/logs" "$D/secret"
chmod 755 "$D" "$D/allowed"
echo ok > "$D/allowed/ok.txt"
echo x > "$D/allowed/ro/x"
ln -s ok.txt "$D/allowed/lnk"
ln -s /root/varek_v1170_missing "$D/allowed/dangle"
ln -s /etc/shadow "$D/allowed/outlink"
mkdir -p "$D/hidden/bob/work"
"$KEYGEN" "$D/secret/log.key" > "$D/secret/log.key.hex"
mknod "$D/allowed/blk" b 7 0
mknod "$D/allowed/mem" c 1 1
# The secret directory, reachable a second time under the allowed tree.
mount --bind "$D/secret" "$D/allowed/keys"
mount --bind "$D/secret" "$D/allowed/logs"

line() { grep -E "^PROBE $1 " "$2"; }
expect() { # expect <desc> <file> <tag> <regex>
    if line "$3" "$2" | grep -Eq "$4"; then pass "$1"; else flunk "$1 ($(line "$3" "$2"))"; fi
}
rules() { grep -c "\"rule\":\"$1\"" "$2"; }

echo "== 1. protected files and raw devices, by identity =="
A="$OUT/alias.out"
"$WARDEN" "$POL" --sign-key "$D/secret/log.key" --anchor "$D/secret/anchor.log" \
    -- "$PROBE" alias > "$A" 2> "$D/secret/run.log"
expect "signing key through a bind mount: refused"     "$A" key_via_alias      "ERR Permission denied"
expect "signing key lookup through the mount: refused" "$A" key_stat_via_alias "ERR Permission denied"
expect "verdict stream through the mount: refused"     "$A" stream_via_alias   "ERR Permission denied"
expect "anchor through the mount: refused"             "$A" anchor_via_alias   "ERR Permission denied"
expect "block device in the allowed tree: refused"     "$A" block_device       "ERR Permission denied"
expect "/dev/mem twin in the allowed tree: refused"    "$A" dev_mem            "ERR Permission denied"
expect "an ordinary allowed file still opens"          "$A" ordinary_file      "READ 3"
[ "$(rules protected_object "$D/secret/run.log")" -ge 4 ] && pass "protected_object recorded for each" \
    || flunk "protected_object records ($(rules protected_object "$D/secret/run.log"))"
[ "$(rules raw_device "$D/secret/run.log")" -ge 2 ] && pass "raw_device recorded for both" \
    || flunk "raw_device records ($(rules raw_device "$D/secret/run.log"))"
if python3 "$AUDIT" --policy "$POL" --checker "$CERT" --pubkey "$(cat "$D/secret/log.key.hex")" \
        --anchor "$D/secret/anchor.log" "$D/secret/run.log" > "$OUT/a1" 2>&1 \
   && grep -q "integrity: signed, anchored" "$OUT/a1"; then
    pass "the run audits: signed, anchored"
else
    flunk "audit ($(tail -3 "$OUT/a1" | tr '\n' ' '))"
fi

echo "== 2. stat, access and readlink are mediated =="
M="$OUT/meta.out"
( cd /var && "$WARDEN" "$POL" -- "$PROBE" meta > "$M" 2> "$OUT/meta.log" )
expect "stat inside the policy: answered"            "$M" stat_allowed         "OK size=3"
expect "stat of /etc/shadow: refused"                 "$M" stat_shadow          "ERR Permission denied"
expect "missing name inside the policy: ENOENT"       "$M" stat_missing_inside  "ERR No such file"
expect "missing name outside the policy: EACCES"      "$M" stat_missing_outside "ERR Permission denied"
expect "lstat of a symlink: answered"                 "$M" lstat_link           "OK"
expect "readlink inside the policy: the target"       "$M" readlink_link        "OK ok.txt"
expect "readlink of the host's /proc/1: refused"      "$M" readlink_host_proc   "ERR Permission denied"
expect "readlink of /proc/self/exe: answered"         "$M" readlink_self_exe    "OK"
expect "access(F_OK) of /etc/shadow: refused"         "$M" access_F_shadow      "ERR Permission denied"
expect "access(R_OK) on a read-only rule: yes"        "$M" access_R_readonly    "OK"
expect "access(W_OK) on a read-only rule: no"         "$M" access_W_readonly    "ERR Permission denied"
expect "access(X_OK): no (nothing may be executed)"   "$M" access_X             "ERR Permission denied"
expect "fstat of a held descriptor: answered"         "$M" fstat_held           "OK size=3"
expect "statx inside the policy: answered"            "$M" statx                "OK size=3"
expect "realpath() of an allowed path works"          "$M" realpath             "OK /tmp/varek_v1170/allowed/ok.txt"
expect "trailing slash on the key's alias: refused"   "$M" key_trailing_slash   "ERR Permission denied"
expect "dangling link to outside: refused, no oracle" "$M" dangling_link_out    "ERR Permission denied"
expect "link to /etc/shadow: refused"                 "$M" link_to_outside      "ERR Permission denied"
expect "ancestor under a deny rule: refused"          "$M" denied_ancestor      "ERR Permission denied"
expect "ancestor answer: existence only (no times)"   "$M" ancestor_stat        "OK mtime=0 nlink=1"
expect "stat of a cwd outside the policy: refused"    "$M" cwd_empty_path       "ERR Permission denied"
expect "access(W_OK) on that cwd: refused"            "$M" cwd_access_w         "ERR Permission denied"
expect "readlink size is an int (writes 5 bytes)"     "$M" readlink_int_size    "^PROBE readlink_int_size +5$"
expect "unknown stat flags: EINVAL"                   "$M" stat_bad_flags       "ERR Invalid argument"
grep -q '"action":"file.stat","target":"/etc/shadow",[^}]*"decision_final":"DENY"' "$OUT/meta.log" \
    && pass "the refused stat is recorded" || flunk "no record of the refused stat"
grep -q '"action":"file.readlink","target":"/tmp/varek_v1170/allowed/lnk",[^}]*"rule":"metadata_answered"' "$OUT/meta.log" \
    && pass "the answered readlink is recorded" || flunk "no record of the answered readlink"
if python3 "$AUDIT" --policy "$POL" --checker "$CERT" "$OUT/meta.log" > "$OUT/a2" 2>&1; then
    pass "the audit re-checks every certified lookup: $(grep -o '[0-9]* lookups' "$OUT/a2")"
else
    flunk "audit of lookups ($(grep PROBLEM "$OUT/a2" | head -2 | tr '\n' ' '))"
fi

echo "== 3. the agent runs unprivileged =="
P="$OUT/priv.out"
"$WARDEN" "$POL" -- "$PROBE" priv > "$P" 2> "$OUT/priv.log"
grep -Eq '^PROBE Uid:\s+65534\s+65534\s+65534\s+65534$' "$P" && pass "default: uid nobody (65534)" \
    || flunk "default uid ($(grep Uid "$P"))"
grep -Eq '^PROBE CapEff:\s+0+$' "$P" && grep -Eq '^PROBE CapBnd:\s+0+$' "$P" \
    && pass "no effective capabilities, empty bounding set" || flunk "capabilities ($(grep Cap "$P" | tr '\n' ' '))"
expect "setuid(0) fails" "$P" setuid_0 "ERR Operation not permitted"
grep -q 'uid=65534 caps=none' "$OUT/priv.log" && pass "status line: uid=65534 caps=none" \
    || flunk "status line"
"$WARDEN" "$POL" --run-as 4321:4321 -- "$PROBE" priv > "$P" 2>/dev/null
grep -Eq '^PROBE Uid:\s+4321\s' "$P" && grep -Eq '^PROBE Gid:\s+4321\s' "$P" \
    && pass "--run-as 4321:4321" || flunk "--run-as uid:gid ($(grep -E 'Uid|Gid' "$P" | tr '\n' ' '))"
"$WARDEN" "$POL" --run-as root -- "$PROBE" priv > "$P" 2> "$OUT/root.log"
grep -Eq '^PROBE Uid:\s+0\s' "$P" && grep -q 'WARNING: --run-as root' "$OUT/root.log" \
    && pass "--run-as root: uid 0, with a warning" || flunk "--run-as root"
"$WARDEN" "$POL" --run-as no_such_user_v1170 -- "$PROBE" priv > /dev/null 2>&1; rc=$?
[ "$rc" = 2 ] && pass "an unknown user is refused (exit 2)" || flunk "unknown user (exit $rc)"
"$WARDEN" "$POL" --run-as 1000: -- "$PROBE" priv > /dev/null 2>&1; rc=$?
[ "$rc" = 2 ] && pass "--run-as 1000: (empty group) is refused" || flunk "empty group (exit $rc)"
"$WARDEN" "$POL" --run-as 65534:0 -- "$PROBE" priv > /dev/null 2>&1; rc=$?
[ "$rc" = 2 ] && pass "--run-as with group root is refused" || flunk "group root (exit $rc)"
"$WARDEN" "$POL" -- "$D/no_such_program" > /dev/null 2> "$OUT/missing.log"; rc=$?
[ "$rc" = 127 ] && grep -q 'program not found' "$OUT/missing.log" \
    && pass "a missing program: a clear refusal (exit 127)" || flunk "missing program (exit $rc)"
cp "$PROBE" "$D/secret/private_probe"; chmod 700 "$D/secret/private_probe"
"$WARDEN" "$POL" -- "$D/secret/private_probe" priv > "$P" 2> "$OUT/noexec.log"; rc=$?
[ "$rc" = 127 ] && grep -q 'cannot execute' "$OUT/noexec.log" \
    && pass "a program nobody may execute: a clear refusal (exit 127)" || flunk "non-executable program (exit $rc)"

echo
if [ "$fail" -eq 0 ]; then echo "test_v1170: PASS"; else echo "test_v1170: FAIL"; fi
exit "$fail"
