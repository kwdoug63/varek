#!/bin/bash
# SPDX-License-Identifier: MIT
# landlock_table.sh — VAREK v1.27 open item 1: the measured table as checks.
#   1. the table: in a Landlock domain granting LANDLOCK_ACCESS_FS_EXECUTE on
#      one (static) program, which launches the kernel refuses (with a control
#      column: the same launch outside any domain)
#   2. memfd_create refused for an agent under the Warden (require warden 1.27)
# Usage (as root): tests/landlock_table.sh [path/to/warden]
# Exit 0 when every check holds, 1 when one fails, 2 when it cannot run here.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WARDEN="${1:-$HERE/warden}"
S="$(mktemp -d /tmp/ll_table.XXXXXX)"; chmod 755 "$S"
trap 'rm -rf "$S" /dev/shm/varek_ll_table.*' EXIT
BIN="$S/landlock_table"
gcc -O2 -Wall -Wno-format-truncation -static -o "$BIN" "$HERE/tests/landlock_table.c" 2>"$S/cc.err" ||
    { echo "landlock_table: cannot build a static program here: $(tail -1 "$S/cc.err")"; exit 2; }
chmod 755 "$BIN"
mkdir -p "$S/w"; chmod 1777 "$S/w"
rc=0
echo "== 1. the table (kernel $(uname -r))"
LL_TABLE_SCRATCH="$S/w" "$BIN" probe; prc=$?
[ $prc = 2 ] && { echo "landlock_table: no Landlock here"; exit 2; }
[ $prc = 0 ] || rc=1
echo
echo "== 2. memfd_create for an agent under the Warden"
P="$S/agent"; mkdir -p "$P"; chmod 755 "$P"
cp "$BIN" "$P/landlock_table"; chmod 755 "$P/landlock_table"
printf 'require warden 1.27\n' > "$S/p.txt"; chmod 644 "$S/p.txt"
env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$S/p.txt" -- "$P/landlock_table" memfd-agent > "$S/out" 2> "$S/log"
grep '^MEMFD' "$S/out" | cut -f2- | tr "\t" "|"
grep -q 'launch set: [0-9]* files, held by Landlock' "$S/log" ||
    { rc=1; echo "FAIL: the agent did not run in the launch set's Landlock domain"; }
grep -q 'verdict	ok' "$S/out" || { rc=1; echo "FAIL: memfd_create was not refused"; tail -5 "$S/log"; }
echo
[ $rc = 0 ] && echo "landlock_table: PASS" || echo "landlock_table: FAIL"
exit $rc
