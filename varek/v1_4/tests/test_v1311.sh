#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1311.sh — VAREK v1.31.1: calls glibc and bash make that the Warden
# refused under every policy (RELEASE-v1.31.1.md).
#
# On x86_64 glibc calls epoll_wait(2) for epoll_wait() and epoll_create(2)
# for epoll_create(), so Python's select.epoll and asyncio's default event
# loop failed with EPERM; glibc before 2.37 (RHEL 9) calls pipe(2) for
# pipe(), so a shell's command substitution failed; and bash calls
# getpgrp(2) at its start, admitted only under 1.29 and later policies, so
# bash did not start under an earlier one. Under a 1.31 policy (the agent
# as nobody) and under one with no require line:
#   1. the Warden reports 1.31.1;
#   2. asyncio's default event loop runs; on x86_64, epoll_create(2),
#      epoll_wait(2) and pipe(2) are admitted;
#   3. bash starts and runs a command substitution; getpgrp(2) is admitted.
#
#   test_v1311.sh VDP_CHECK VDP_CERT_CHECK WARDEN
set -u
WARDEN="${3:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
trap '[ -n "${KEEP:-}" ] && echo "kept $OUT ${W:-}" || rm -rf "$OUT" "${W:-}"' EXIT

echo "== 1. the version =="
# (v1.32: 1.31.1 or a later release)
check "the Warden reports 1.31.1 or later" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | python3 -c 'import re,sys; m=re.search(r\"VAREK Warden  (\\d+)\\.(\\d+)\\.(\\d+)\", sys.stdin.read()); sys.exit(0 if m and tuple(map(int, m.groups())) >= (1, 31, 1) else 1)'"

if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "the calls under the Warden (needs root and the warden binary)"
else
    W="$(mktemp -d /tmp/varek_v1311.XXXXXX)"; chmod 755 "$W"
    cat > "$W/agent.py" <<'PY'
import asyncio, ctypes, platform
libc = ctypes.CDLL(None, use_errno=True)
async def nap():
    await asyncio.sleep(0.01)
    return "ok"
try:
    print("asyncio", asyncio.run(nap()), flush=True)
except OSError as e:
    print("asyncio", e.errno, flush=True)
if platform.machine() == "x86_64":
    ep = libc.syscall(213, 4)                  # epoll_create(2)
    print("epoll_create", "ok" if ep >= 0 else ctypes.get_errno(), flush=True)
    ev = ctypes.create_string_buffer(12)
    print("epoll_wait", "ok" if ep >= 0 and libc.syscall(232, ep, ev, 1, 0) == 0 else ctypes.get_errno(), flush=True)
    fds = (ctypes.c_int * 2)()
    print("pipe", "ok" if libc.syscall(22, fds) == 0 else ctypes.get_errno(), flush=True)
    print("getpgrp", "ok" if libc.syscall(111) > 0 else ctypes.get_errno(), flush=True)
PY
    chmod 644 "$W/agent.py"
    BASE='allow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path exact /etc/ld.so.cache readonly\n'
    printf "require warden 1.31\n${BASE}allow path exact %s/agent.py readonly\n" "$W" > "$W/p131.txt"
    printf "${BASE}allow path exact %s/agent.py readonly\n" "$W" > "$W/p127.txt"
    for v in 131 127; do
        if [ "$v" = 131 ]; then as="--run-as nobody"; what="a 1.31 policy"; else as=""; what="a policy with no require line"; fi
        echo "== 2. under $what: asyncio and the calls glibc makes =="
        # shellcheck disable=SC2086
        env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$W/p$v.txt" $as -- /usr/bin/python3 "$W/agent.py" \
            > "$OUT/a$v.out" 2> "$OUT/a$v.log"
        sed 's/^/     /' "$OUT/a$v.out"
        said() { grep -qx "$1" "$OUT/a$v.out"; }
        check "asyncio's default event loop runs ($what)" said "asyncio ok"
        if [ "$(uname -m)" = x86_64 ]; then
            check "epoll_create(2) and epoll_wait(2) are admitted, as epoll_create1 and epoll_pwait are ($what)" \
                sh -c "grep -qx 'epoll_create ok' '$OUT/a$v.out' && grep -qx 'epoll_wait ok' '$OUT/a$v.out'"
            check "pipe(2) is admitted, as pipe2 is ($what)" said "pipe ok"
            check "getpgrp(2) is admitted ($what)" said "getpgrp ok"
        fi
        echo "== 3. under $what: bash =="
        # shellcheck disable=SC2016,SC2086
        env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$W/p$v.txt" $as -- /bin/bash -c 'x=$(echo sub); echo "bash $x"' \
            > "$OUT/b$v.out" 2> "$OUT/b$v.log"
        check "bash starts and runs a command substitution ($what)" grep -qx "bash sub" "$OUT/b$v.out"
    done
    [ "$(uname -m)" = x86_64 ] || skip "epoll_create(2), epoll_wait(2), pipe(2) and getpgrp(2) by number (x86_64 only: arm64 has none of them)"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1311: PASS ($skips skipped)"; else echo "test_v1311: FAIL"; fi
exit "$fail"
