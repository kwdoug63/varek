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
#   1. the Warden reports 1.32.1;
#   2. in a user namespace with its own mount namespace, a read-only cgroup
#      filesystem: --check-startup tries the remount and says a run makes it;
#   3. one locked read-only before the user namespace was made: refused,
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
check "the Warden reports 1.32.1" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | grep -q 'VAREK Warden  1.32.1'"

echo "== 2. and 3. a read-only cgroup filesystem in a user namespace =="
CGM="$(awk '$3 == "cgroup2" { print $2; exit }' /proc/self/mounts)"
SUBP="$HERE/tests/v1281_sub"
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ ! -x "$SUBP" ] || [ -z "$CGM" ] || ! unshare -U -r -m -C --fork true 2>/dev/null; then
    skip "a user namespace with a read-only cgroup filesystem (needs root, the warden, tests/v1281_sub, cgroup2 and user namespaces)"
else
    B="$(mktemp -d /tmp/varek_v1321.XXXXXX)"; chmod 755 "$B"
    for n in agent a; do cp "$SUBP" "$B/$n"; chmod 755 "$B/$n"; done
    echo hi > "$B/f"; chmod 644 "$B/f"
    printf 'require warden 1.28\nallow exec %s/a subagent=alpha\nallow path %s/f readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /lib64 readonly\nallow path /etc/ld.so.cache readonly\n' \
        "$B" "$B" > "$B/p.txt"
    # made read-only inside the user namespace, as rootless Podman's runtime makes it
    unshare -U -r -m -C --fork sh -c "mount --make-rprivate / && mount -o remount,bind,ro '$CGM' && \
        stat -Lc %i /proc/self/ns/user > '$OUT/ns'; timeout 60 '$WARDEN' '$B/p.txt' --check-startup > '$OUT/u.out' 2>&1"
    check "in a user namespace (not the initial one)" sh -c "[ -s '$OUT/ns' ] && [ \"\$(cat '$OUT/ns')\" != 4026531837 ]"
    check "a read-only cgroup filesystem there: --check-startup tries the remount and says the run makes it" \
        sh -c "grep -q 'is read-only (a container.s, its own groups only): a run remounts it read-write in the Warden.s own mount namespace (tried)' '$OUT/u.out' && ! grep -q 'refusing to start' '$OUT/u.out'"
    # locked: read-only before the user namespace was made
    unshare -m sh -c "mount --make-rprivate / && mount -o remount,bind,ro '$CGM' && \
        unshare -U -r -m -C --fork sh -c \"timeout 60 '$WARDEN' '$B/p.txt' --check-startup > '$OUT/l.out' 2>&1\""
    check "one locked read-only by a more privileged namespace: refused, naming --systemd=always" \
        sh -c "grep -q 'cannot remount the container.s cgroup filesystem .* read-write (Operation not permitted) in this user namespace (rootless); run the container with --systemd=always' '$OUT/l.out'"
fi

echo
[ "$fail" = 0 ] && echo "test_v1321: PASS ($skips skipped)" || echo "test_v1321: FAIL"
[ "$fail" = 0 ]
