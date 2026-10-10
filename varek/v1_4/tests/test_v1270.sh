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
#   2. the launch set (as root): allow exec rules expanded to files (exact,
#      prefix, glob; symlinks by name, held as their files; an earlier deny
#      keeps a file out), each dynamic program's loader, the operator's
#      program and a script's interpreter; refused: more than 256 files for
#      a rule, rules that cannot be expanded, a malformed ELF header; notes
#      for missing files, interpreters, files both launched and written, and
#      scripts whose interpreter is not in the set; runs whose run_start
#      records Landlock's ABI and each file's name, path, device, inode and
#      SHA-256 (checked against the file), the agent running in the domain,
#      a run without the opt-in and one without Landlock, all accepted by the
#      audit
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
lint "require warden 1.27\nallow exec /lib64/ld-linux-x86-64.so.2\nallow path /usr/ readonly\n"
check "and the dynamic loader named in a rule (it runs any ELF file)" grep -q ':2: note: /lib64/ld-linux-x86-64.so.2 is a shell or general-purpose interpreter' "$OUT/n.out"
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

echo "== 2. the launch set =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "section 2 (needs root and the warden binary)"
else
    export OUT
    W=/tmp/varek_v1270.$$
    rm -rf "$W"; mkdir -p "$W/bin/sub" "$W/many" "$W/bad" "$OUT/log"; chmod 755 "$W" "$W/bin" "$W/bin/sub" "$W/many" "$W/bad"
    trap '[ -n "${KEEP:-}" ] && echo "kept $OUT $W" || rm -rf "$OUT" "$W"' EXIT
    TRUE=/usr/bin/true
    cp "$TRUE" "$W/bin/a1"; cp "$TRUE" "$W/bin/a2"; cp "$TRUE" "$W/bin/sub/a3"; cp "$TRUE" "$W/bin/noexec"
    chmod 755 "$W/bin/a1" "$W/bin/a2" "$W/bin/sub/a3"; chmod 644 "$W/bin/noexec"
    ln -s "$TRUE" "$W/bin/lnk"; ln -s /usr/bin "$W/bin/dlink"
    printf '#!/bin/sh\necho hi\n' > "$W/bin/s.sh"; chmod 755 "$W/bin/s.sh"
    cp "$TRUE" "$W/many/t0"; chmod 755 "$W/many/t0"
    for i in $(seq 1 256); do ln "$W/many/t0" "$W/many/t$i"; done
    python3 -c "
import struct,sys
e=b'\x7fELF'+bytes([2,1,1])+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0,64,0,0,64,56,1000,64,0,0)
open(sys.argv[1],'wb').write(e)" "$W/bad/elf"; chmod 755 "$W/bad/elf"
    # set <description> <policy body>: --check-startup, its report in $OUT/set.out
    set_of() { printf 'require warden 1.27\n%b' "$1" > "$W/p.txt"; chmod 644 "$W/p.txt"
               "$WARDEN" "$W/p.txt" --check-startup > "$OUT/set.out" 2>&1; echo $? > "$OUT/set.rc"; }
    in_set()  { grep -q "^\[warden\]   $1[ ,]" "$OUT/set.out"; }
    set_of "deny exec $W/bin/a2\nallow exec prefix $W/bin/\n"
    check "a prefix rule admits each launchable file beneath it" bash -c "$(declare -f in_set); in_set '$W/bin/a1' && in_set '$W/bin/sub/a3' && in_set '$W/bin/s.sh'"
    check "a symlink by its name, held as its file" bash -c "$(declare -f in_set); in_set '$W/bin/lnk -> $(readlink -f "$TRUE")'"
    check "not a file an earlier deny rule decides" bash -c "$(declare -f in_set); ! in_set '$W/bin/a2'"
    check "nor one without an execute bit, nor a directory (or a link to one)" \
        bash -c "$(declare -f in_set); ! in_set '$W/bin/noexec' && ! in_set '$W/bin/dlink' && ! grep -q '$W/bin/dlink/' '$OUT/set.out'"
    check "each dynamic program's loader is added" grep -q ', loader$' "$OUT/set.out"
    check "a script whose interpreter the policy does not allow: a note" \
        grep -q "note: launch set: $W/bin/s.sh is a script for /bin/sh, which the policy does not allow" "$OUT/set.out"
    check "the report counts the files and says Landlock holds them" grep -q 'launch set: [0-9]* files, held by Landlock' "$OUT/set.out"
    set_of "allow exec prefix $W/bin/\ndeny exec $W/bin/a2\n"
    check "a deny rule after the allow does not remove it (first match)" bash -c "$(declare -f in_set); in_set '$W/bin/a2'"
    set_of "allow exec glob $W/bin/a[12]\n"
    check "a glob rule admits what it matches" bash -c "$(declare -f in_set); in_set '$W/bin/a1' && in_set '$W/bin/a2' && ! in_set '$W/bin/sub/a3'"
    set_of "allow exec glob $W/bin/*/a3\n"
    check "a glob across a directory level" bash -c "$(declare -f in_set); in_set '$W/bin/sub/a3' && ! in_set '$W/bin/a1'"
    set_of "allow exec prefix $W/many/\n"
    check "a rule admitting more than 256 files is refused" \
        sh -c "grep -qx 1 '$OUT/set.rc' && grep -q 'line 2 admits more than 256 files to launch' '$OUT/set.out'"
    set_of "allow exec suffix /true\n"
    check "an allow exec suffix rule is refused (no bounded set of files)" \
        sh -c "grep -qx 1 '$OUT/set.rc' && grep -q 'cannot be expanded to the files it admits' '$OUT/set.out'"
    set_of "allow exec contains true\n"
    check "and a contains rule" sh -c "grep -qx 1 '$OUT/set.rc' && grep -q 'cannot be expanded' '$OUT/set.out'"
    set_of "allow exec glob */true\n"
    check "and a glob that starts with a wildcard" sh -c "grep -qx 1 '$OUT/set.rc' && grep -q 'must start with a directory' '$OUT/set.out'"
    set_of "allow exec prefix $W/bad/\n"
    check "a malformed ELF header is refused" sh -c "grep -qx 1 '$OUT/set.rc' && grep -q 'a malformed ELF header' '$OUT/set.out'"
    set_of "allow exec $W/bin/nope\n"
    check "an exact rule for a missing file: a note, not in the set" \
        sh -c "grep -qx 0 '$OUT/set.rc' && grep -q 'line 2: $W/bin/nope is not a launchable file on this host' '$OUT/set.out'"
    set_of "allow exec prefix $W/bin/\nallow path $W/bin/\n"
    check "a file both launched and written: a note" \
        grep -q "note: launch set: $W/bin/a1 ($W/bin/a1) may be both launched and written" "$OUT/set.out"
    set_of "allow exec glob /usr/bin/python3*\n"
    check "an interpreter a matcher admits: a note" grep -q 'note: launch set: /usr/bin/python3[^ ]* (line 2) is a shell or general-purpose interpreter' "$OUT/set.out"

    # real runs: run_start records Landlock and the set; the agent runs in the domain
    printf 'print("AGENT ok", flush=True)\n' > "$W/a.py"; printf '#!/usr/bin/python3\nprint("SCRIPT ok", flush=True)\n' > "$W/s.py"
    chmod 644 "$W/a.py"; chmod 755 "$W/s.py"
    POLR="require warden 1.27\nallow exec /usr/bin/python3\nallow exec $W/bin/a1\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\nallow path $W/ readonly\n"
    run() {  # run <name> <policy> <program...>: $OUT/log/<name>.log and .out
        local n="$1" pol="$2"; shift 2
        printf '%b' "$pol" > "$W/$n.policy"; chmod 644 "$W/$n.policy"
        env -i PATH=/usr/bin:/bin ${RUNENV:-} timeout 60 "$WARDEN" "$W/$n.policy" -- "$@" > "$OUT/log/$n.out" 2> "$OUT/log/$n.log"
    }
    rs() {   # rs <log> <python expression over r, the run_start record>
        python3 - "$1" "$2" <<'PY'
import json, os, sys, hashlib
r = next(json.loads(l[l.index("{"):]) for l in open(sys.argv[1], errors="replace") if '"event":"run_start"' in l)
def ent(name): return next((e for e in r.get("exec_ruleset", []) if e["name"] == name), None)
def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
def interp(p):
    import struct
    b = open(p, "rb").read()
    phoff, = struct.unpack_from("<Q", b, 32); n, = struct.unpack_from("<H", b, 56)
    for k in range(n):
        t, = struct.unpack_from("<I", b, phoff + 56 * k)
        if t == 3:
            o, = struct.unpack_from("<Q", b, phoff + 56 * k + 8); sz, = struct.unpack_from("<Q", b, phoff + 56 * k + 32)
            return b[o:o + sz - 1].decode()
sys.exit(0 if eval(sys.argv[2]) else 1)
PY
    }
    run r1 "$POLR" /usr/bin/python3 "$W/a.py"
    check "a run with require warden 1.27: the agent runs in the Landlock domain" grep -qx 'AGENT ok' "$OUT/log/r1.out"
    check "run_start records the Landlock ABI" rs "$OUT/log/r1.log" 'r["landlock"]["abi"] >= 1'
    check "and each file: its name, canonical path, device, inode and SHA-256" \
        rs "$OUT/log/r1.log" "(lambda e, st: e and e['path'] == '$W/bin/a1' and e['dev'] == st.st_dev and e['ino'] == st.st_ino and e['sha256'] == sha('$W/bin/a1') and e['why'] == 'rule' and e['policy_line'] == 3)(ent('$W/bin/a1'), os.stat('$W/bin/a1'))"
    check "a symlink's name with its file's path" \
        rs "$OUT/log/r1.log" "ent('/usr/bin/python3')['path'] == os.path.realpath('/usr/bin/python3')"
    check "the loader, as PT_INTERP names it" \
        rs "$OUT/log/r1.log" "(lambda e: e and e['why'] == 'loader' and e['path'] == os.path.realpath(e['name']))(ent(interp(os.path.realpath('/usr/bin/python3'))))"
    run r2 "$POLR" "$W/bin/a2"
    check "the program the operator names, though no rule allows it, runs" \
        grep -q '"event":"run_end","run":"[0-9a-f]*","records":[0-9]*,"exit_status":0' "$OUT/log/r2.log"
    check "in the set as bootstrap" rs "$OUT/log/r2.log" "ent('$W/bin/a2')['why'] == 'bootstrap'"
    run r3 "$POLR" "$W/s.py"
    check "a script the operator names runs, with its interpreter in the set" \
        sh -c "grep -qx 'SCRIPT ok' '$OUT/log/r3.out'"
    check "recorded as bootstrap and its interpreter's file" \
        rs "$OUT/log/r3.log" "ent('$W/s.py')['why'] == 'bootstrap' and ent('/usr/bin/python3') is not None"
    run r4 "$(printf '%b' "$POLR" | sed 's/require warden 1.27/require warden 1.26/')" /usr/bin/python3 "$W/a.py"
    check "without the opt-in: no Landlock, no set in run_start, the agent runs" \
        sh -c "grep -qx 'AGENT ok' '$OUT/log/r4.out' && ! grep -q 'exec_ruleset\|\"landlock\"' '$OUT/log/r4.log'"
    RUNENV=VAREK_WARDEN_TEST_NO_LANDLOCK=1 run r5 "$POLR" /usr/bin/python3 "$W/a.py"
    check "without Landlock: the agent runs, run_start says landlock null, and the Warden says why" \
        sh -c "grep -qx 'AGENT ok' '$OUT/log/r5.out' && grep -q '\"landlock\":null' '$OUT/log/r5.log' && grep -q 'launches after the first will be refused (exec_no_landlock)' '$OUT/log/r5.log'"
    for n in r1 r2 r3 r4 r5; do
        check "the audit accepts run $n" python3 "$HERE/tools/varek_audit.py" --policy "$W/$n.policy" --checker "$CERT" "$OUT/log/$n.log"
    done
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1270: PASS ($skips skipped)"; exit 0; fi
echo "test_v1270: FAIL"; exit 1
