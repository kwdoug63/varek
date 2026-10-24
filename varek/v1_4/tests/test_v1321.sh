#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1321.sh — VAREK v1.32.1: rootless Podman without --systemd=always
# (RELEASE-v1.32.1.md; D10 of docs/security/v1.32-containers.md).
#
# Through v1.32.0 the Warden refused a read-only cgroup filesystem in a user
# namespace (rootless) for a policy that names a sub-agent, naming
# --systemd=always. Measured on rootless Podman after v1.32's review, the
# bind remount the Warden makes works there, so from v1.32.1 it is made in a
# user namespace too, and refused, naming --systemd=always, only where the
# kernel refuses it (a mount locked read-only by a more privileged one):
#   1. the Warden reports 1.32.1 or later;
#   2. in a user namespace (rootless) whose group is delegated to its user,
#      a read-only cgroup filesystem: --check-startup tries the remount and
#      says a run makes it; a run makes it, its sub-agent attributed;
#   3. one whose group is not delegated: refused at --check-startup and at
#      a run alike, naming the delegation (v1.32.1 review);
#   4. one locked read-only before the user namespace was made: refused,
#      naming --systemd=always, with the kernel's reason.
#
#   test_v1321.sh VDP_CHECK VDP_CERT_CHECK WARDEN
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
trap '[ -n "${KEEP:-}" ] && echo "kept $OUT ${B:-}" || rm -rf "$OUT" "${B:-}"' EXIT

echo "== 1. the version =="
check "the Warden reports 1.32.1 or later" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | python3 -c 'import re,sys; m=re.search(r\"VAREK Warden  (\\d+)\\.(\\d+)\\.(\\d+)\", sys.stdin.read()); sys.exit(0 if m and tuple(map(int, m.groups())) >= (1, 32, 1) else 1)'"

echo "== 2. to 4. a read-only cgroup filesystem in a user namespace =="
# As rootless Podman makes it: each case in a group of its own, the host's
# cgroup2 mount unmounted in an outer mount namespace, and a fresh one made
# read-only in a user, mount, cgroup and network namespace whose root is
# uid 100000 outside (so it starts from any group, v1.32.1 review)
CGM="$(awk '$3 == "cgroup2" { print $2; exit }' /proc/self/mounts)"
SUBP="$HERE/tests/v1281_sub"
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ ! -x "$SUBP" ] || [ -z "$CGM" ] || ! command -v python3 > /dev/null ||
   ! unshare -U -r -m -C --fork true 2>/dev/null || ! mkdir "$CGM/varek-v1321-probe" 2>/dev/null; then
    skip "a user namespace with a read-only cgroup filesystem (needs root, the warden, tests/v1281_sub, python3, cgroup2 groups and user namespaces)"
else
    rmdir "$CGM/varek-v1321-probe"
    B="$(mktemp -d /tmp/varek_v1321.XXXXXX)"; chmod 755 "$B"
    for n in agent a; do cp "$SUBP" "$B/$n"; chmod 755 "$B/$n"; done
    cp "$WARDEN" "$B/warden"; chmod 755 "$B/warden"
    echo hi > "$B/f"; chmod 644 "$B/f"
    R="$B/out"; mkdir "$R"; chown 100000:100000 "$R"       # written by the user namespace's root
    printf 'require warden 1.28\nallow exec %s/a subagent=alpha\nallow path %s/f readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\n' \
        "$B" "$B" > "$B/p.txt"
    cat > "$B/userns.py" <<'PY'
# userns.py OUTER CMD...: CMD as root of new user, mount, cgroup and network
# namespaces, whose root is uid and gid OUTER (65536 of them) outside
import ctypes, os, sys
outer, cmd = int(sys.argv[1]), sys.argv[2:]
r, w = os.pipe(); r2, w2 = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r); os.close(w2)
    if ctypes.CDLL(None, use_errno=True).unshare(0x10000000 | 0x20000 | 0x02000000 | 0x40000000) != 0:
        os._exit(125)
    os.write(w, b"x"); os.close(w)
    os.read(r2, 1)
    os.setgid(0); os.setuid(0)
    os.execvp(cmd[0], cmd)
os.close(w); os.close(r2)
os.read(r, 1)
for m in ("uid_map", "gid_map"):
    with open(f"/proc/{pid}/{m}", "w") as fh:
        fh.write(f"0 {outer} 65536\n")
os.write(w2, b"x")
_, st = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(st))
PY
    # case NAME DELEGATE LOCKED: in group varek-v1321-NAME (owned by 100000 if
    # DELEGATE), the cgroup2 mount made read-only outside the user namespace
    # (locked) if LOCKED, else inside it; --check-startup, then a run
    case_() {
        local d="$CGM/varek-v1321-$1" ro_out="" ro_in="mount -t cgroup2 -o ro,nosuid,nodev,noexec none '$CGM' &&"
        mkdir -p "$d"
        [ "$2" = 1 ] && chown 100000:100000 "$d" "$d/cgroup.procs" "$d/cgroup.subtree_control" "$d/cgroup.threads"
        if [ "$3" = 1 ]; then ro_out="mount -t cgroup2 -o ro,nosuid,nodev,noexec none '$CGM' &&"; ro_in=""; fi
        unshare -m sh -c "echo \$\$ > '$d/cgroup.procs' && exec unshare -C sh -c \"mount --make-rprivate / && umount '$CGM' && $ro_out \
            exec python3 '$B/userns.py' 100000 sh -c \\\"$ro_in stat -Lc %i /proc/self/ns/user > '$R/$1.ns'; \
            timeout 60 '$B/warden' '$B/p.txt' --check-startup > '$R/$1.cs' 2>&1; \
            timeout 60 '$B/warden' '$B/p.txt' -- '$B/agent' exec '$B/a' open '$B/f' > /dev/null 2> '$R/$1.run'\\\"\""
        find "$d" -mindepth 1 -depth -type d -exec rmdir {} + 2>/dev/null; rmdir "$d" 2>/dev/null
    }
    case_ deleg 1 0
    check "in a user namespace (not the initial one)" sh -c "[ -s '$R/deleg.ns' ] && [ \"\$(cat '$R/deleg.ns')\" != 4026531837 ]"
    check "2. delegated: --check-startup tries the remount and says the run makes it" \
        sh -c "grep -q 'is read-only (a container.s, its own groups only): a run remounts it read-write in the Warden.s own mount namespace (tried)' '$R/deleg.cs' && ! grep -q 'refusing to start' '$R/deleg.cs'"
    check "... a run remounts it and its sub-agent is launched and attributed" \
        sh -c "grep -q 'remounted read-write in the Warden.s own mount namespace' '$R/deleg.run' && grep -q '\"event\":\"subagent_settled\".*\"subagent\":\"alpha#1\",\"result\":\"launched\"' '$R/deleg.run'"
    case_ nodeleg 0 0
    check "3. not delegated: --check-startup refuses, naming the delegation (as the run would)" \
        sh -c "grep -q 'cannot make groups in .* (Permission denied): in a user namespace (rootless) the container.s control group must be delegated to its user' '$R/nodeleg.cs'"
    check "... and the run refuses the same" grep -q "cannot make the run's control group .* (Permission denied): in a user namespace (rootless) the container's control group must be delegated" "$R/nodeleg.run"
    case_ locked 1 1
    check "4. locked read-only by a more privileged namespace: refused, naming --systemd=always" \
        sh -c "grep -q 'cannot remount the container.s cgroup filesystem .* read-write (Operation not permitted) in this user namespace (rootless); run the container with --systemd=always' '$R/locked.cs'"
fi

echo
[ "$fail" = 0 ] && echo "test_v1321: PASS ($skips skipped)" || echo "test_v1321: FAIL"
[ "$fail" = 0 ]
