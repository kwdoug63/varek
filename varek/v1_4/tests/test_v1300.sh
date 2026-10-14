#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1300.sh — VAREK v1.30 (docs/security/v1.30-macos.md): the Warden on
# x86_64 and arm64 from one source. Run on each architecture:
#   1. open flags: this architecture's kernel encoding and VAREK's (x86_64's
#      uapi values, which rules, certificates and records use on both)
#      translate exactly (tests/v1300_oflags);
#   2. in a run: flag clauses decide on the flags the agent passed
#      (-O_NOFOLLOW, -O_DIRECTORY refuse what they exclude, on both), the
#      records carry VAREK's encoding, the certificates check, and the audit
#      passes;
#   3. run_start names the architecture, the audit reports it, and refuses
#      one the Warden does not write.
#
#   test_v1300.sh VDP_CERT_CHECK [WARDEN]
set -u
CERT="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
WARDEN="${2:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
trap '[ -n "${KEEP:-}" ] && echo "kept $OUT ${D:-}" || rm -rf "$OUT" "${D:-}"' EXIT

echo "== 1. open flags: the kernel's encoding and VAREK's ($(uname -m)) =="
if [ -x "$HERE/tests/v1300_oflags" ]; then
    "$HERE/tests/v1300_oflags" > "$OUT/oflags.out" 2>&1
    check "every flag translates exactly, both ways (tests/v1300_oflags)" grep -qx 'v1300_oflags: PASS' "$OUT/oflags.out"
else skip "tests/v1300_oflags (make tests/v1300_oflags)"; fi

echo "== 2. in a run: flag clauses, records, certificates =="
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ]; then
    skip "section 2 (needs root and the warden)"
else
    D="$(mktemp -d /tmp/varek_v1300.XXXXXX)"; chmod 755 "$D"
    mkdir "$D/dir"; echo hi > "$D/a"; chmod 755 "$D/dir"; chmod 644 "$D/a"
    cat > "$D/agent.py" <<'PY'
import os, sys
D = sys.argv[1]
def t(tag, path, flags):
    try:
        os.close(os.open(path, flags)); print(tag, "ok", flush=True)
    except OSError as e:
        print(tag, e.errno, flush=True)
t("plain", D + "/a", os.O_RDONLY)
t("nofollow", D + "/a", os.O_RDONLY | os.O_NOFOLLOW)
t("dir_plain", D + "/dir", os.O_RDONLY)
t("dir_directory", D + "/dir", os.O_RDONLY | os.O_DIRECTORY)
t("dir_both", D + "/dir", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
PY
    chmod 644 "$D/agent.py"
    # the agent's own files decided by clauses on the bits arm64 moves
    { printf 'require warden 1.29\n'
      printf 'allow path exact %s/a readonly -O_NOFOLLOW\n' "$D"
      printf 'allow path exact %s/dir readonly -O_DIRECTORY\n' "$D"
      printf 'allow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\n'
      printf 'allow path exact /etc/ld.so.cache readonly\nallow path exact %s/agent.py readonly\n' "$D"
    } > "$D/p.txt"
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$D/p.txt" --run-as nobody -- /usr/bin/python3 "$D/agent.py" "$D" \
        > "$OUT/r.out" 2> "$OUT/r.log"
    sed 's/^/     /' "$OUT/r.out"
    said() { grep -qx "$1" "$OUT/r.out"; }
    check "an open without O_NOFOLLOW is allowed by the rule (-O_NOFOLLOW)" said "plain ok"
    check "an open with O_NOFOLLOW is refused: the clause excludes it (EACCES)" said "nofollow 13"
    check "a directory opened without O_DIRECTORY is allowed (-O_DIRECTORY)" said "dir_plain ok"
    check "with O_DIRECTORY it is refused, alone and with O_NOFOLLOW" sh -c "grep -qx 'dir_directory 13' '$OUT/r.out' && grep -qx 'dir_both 13' '$OUT/r.out'"
    flags() { python3 - "$OUT/r.log" "$1" <<'PY'
import json, sys
for l in open(sys.argv[1], errors="replace"):
    if l.startswith('{"report_id"'):
        r = json.loads(l)
        if r.get("target") == sys.argv[2] and r.get("action") == "file.open":
            print(r.get("open_flags"), r.get("decision_final"))
PY
    }
    flags "$D/a" > "$OUT/fa.txt"; flags "$D/dir" > "$OUT/fd.txt"
    # VAREK's encoding (x86_64's): O_NOFOLLOW 0x20000, O_DIRECTORY 0x10000; plus
    # what Python's os.open adds (O_CLOEXEC 0x80000)
    check "records carry VAREK's encoding: O_NOFOLLOW as 0x20000" python3 -c "
import sys
L = [l.split() for l in open('$OUT/fa.txt')]
sys.exit(0 if any(int(f, 16) & 0x20000 and d == 'DENY' for f, d in L) and any(not int(f, 16) & 0x20000 and d == 'ALLOW' for f, d in L) else 1)"
    check "... and O_DIRECTORY as 0x10000" python3 -c "
import sys
L = [l.split() for l in open('$OUT/fd.txt')]
sys.exit(0 if any(int(f, 16) & 0x10000 and d == 'DENY' for f, d in L) and any(not int(f, 16) & 0x10000 and d == 'ALLOW' for f, d in L) else 1)"
    check "no record carries a bit outside VAREK's open flags" python3 -c "
import json, sys
bad = [r for r in map(json.loads, (l for l in open('$OUT/r.log', errors='replace') if l.startswith('{\"report_id\"')))
       if r.get('open_flags') and int(r['open_flags'], 16) & ~0x007fffc3]
sys.exit(1 if bad else 0)"
    python3 "$HERE/tools/varek_audit.py" --policy "$D/p.txt" --checker "$CERT" "$OUT/r.log" > "$OUT/aud.out" 2>&1; echo $? > "$OUT/aud.rc"
    check "the audit passes: each certificate re-checked with the recorded flags" sh -c "grep -qx 0 '$OUT/aud.rc' && grep -q 'varek_audit: PASS' '$OUT/aud.out'"

    echo "== 3. run_start names the architecture =="
    A="$(uname -m)"; [ "$A" = arm64 ] && A=aarch64
    check "run_start's arch is this host's ($A)" python3 -c "
import json, sys
rs = next(json.loads(l) for l in open('$OUT/r.log', errors='replace') if l.startswith('{\"event\":\"run_start\"'))
sys.exit(0 if rs.get('arch') == '$A' else 1)"
    check "the audit reports it" grep -qx "varek_audit: architecture: $A" "$OUT/aud.out"
    python3 "$HERE/tests/v1270_forge.py" "$OUT/r.log" "$OUT/g1.log" \
        "rs = next(r for r in recs if isinstance(r, dict) and r.get('event') == 'run_start'); rs['arch'] = 'riscv64'"
    if python3 "$HERE/tools/varek_audit.py" --policy "$D/p.txt" --checker "$CERT" "$OUT/g1.log" > "$OUT/g1.out" 2>&1; then
        flunk "the audit refuses an architecture the Warden does not write"
    elif grep -q "run_start's arch 'riscv64' is not one the Warden writes" "$OUT/g1.out"; then
        pass "the audit refuses an architecture the Warden does not write"
    else flunk "the audit refuses an architecture the Warden does not write ($(grep -m1 PROBLEM "$OUT/g1.out"))"; fi
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1300: PASS ($skips skipped)"; else echo "test_v1300: FAIL"; fi
exit "$fail"
