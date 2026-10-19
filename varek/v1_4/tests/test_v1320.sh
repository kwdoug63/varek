#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1320.sh — VAREK v1.32.0: containers (docs/security/v1.32-containers.md).
#
# What v1.32 adds, checked on any host; the suites run inside the container
# itself by tests/container_sweep.sh (and CI's .github/workflows/container.yml):
#   1. the version: the Warden reports 1.32.0, its run_start names it, and the
#      grammar stays 1.31 (`require warden 1.32` refused, 1.31 loads) (D12);
#   2. `varek doctor` in a container (D11), here as one (VAREK_DOCTOR_CONTAINER):
#      its container section, and the Warden's mounts made in a child;
#   3. the preflight's share: `varek run` refused before the agent starts when
#      the container lacks a capability (SYS_PTRACE taken from the bounding set
#      with setpriv), naming --cap-add SYS_PTRACE, and run when it has them;
#      tools/varek_preflight.sh's section 2b says the same;
#   4. the packaging: the AppArmor profile compiles with the Warden's mount
#      rules and denies the rest as docker-default does; the SELinux module's
#      four rules; the Containerfile's stages and entrypoint; the CI and release
#      workflows (the release signs, attests and verifies).
#
#   test_v1320.sh VDP_CHECK VDP_CERT_CHECK WARDEN
set -u
VDP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
WARDEN="${3:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$(mktemp -d)"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
trap '[ -n "${KEEP:-}" ] && echo "kept $OUT ${W:-}" || rm -rf "$OUT" "${W:-}"' EXIT
unset SUDO_UID SUDO_GID SUDO_USER SUDO_COMMAND
VAREK="$HERE/tools/varek"

echo "== 1. the version =="
check "the Warden reports 1.32.0" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$VAREK' version | grep -q 'VAREK Warden  1.32.0'"
printf 'require warden 1.32\nallow path /usr/ readonly\n' > "$OUT/p132.txt"
printf 'require warden 1.31\nallow path /usr/ readonly\n' > "$OUT/p131.txt"
check "the grammar stays 1.31: require warden 1.32 is refused" sh -c "! '$VDP' '$OUT/p132.txt' lint && '$VDP' '$OUT/p132.txt' lint 2>&1 | grep -q 'policy requires Warden 1.32; this is 1.31'"
check "... and require warden 1.31 loads" "$VDP" "$OUT/p131.txt" lint
# v1.32 second review: varek run's container check asks whether the Warden
# will mount anything (vdp_check mounts), not only whether launches are decided
printf 'require warden 1.27\nallow path /usr/ readonly\nallow exec /usr/bin/true\n' > "$OUT/mro.txt"
printf 'require warden 1.27\nallow path /usr/ readonly\nallow path /tmp/varek-v1320-w/\n' > "$OUT/mrw.txt"
printf 'require warden 1.26\nallow path /tmp/varek-v1320-w/\n' > "$OUT/m126.txt"
printf 'require warden 1.27\nallow exec /usr/bin/true\nallow path relative/x\n' > "$OUT/mrel.txt"
check "the noexec mounts: none for a policy that decides launches but writes nothing" \
    sh -c "[ \"\$('$VDP' '$OUT/mro.txt' launches)\" = on ] && [ \"\$('$VDP' '$OUT/mro.txt' mounts)\" = off ]"
check "... made for one that writes, and none where launches are not decided" \
    sh -c "[ \"\$('$VDP' '$OUT/mrw.txt' mounts)\" = on ] && [ \"\$('$VDP' '$OUT/m126.txt' mounts)\" = off ]"
check "... and none for a rule that writes no absolute path, as the Warden lists them" \
    sh -c "[ \"\$('$VDP' '$OUT/mrel.txt' mounts)\" = off ]"
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "run_start's version (needs root and the warden binary)"
else
    (cd /tmp && timeout 60 "$WARDEN" "$OUT/p131.txt" -- /usr/bin/true > /dev/null 2> "$OUT/rs.log")
    check "run_start names the Warden 1.32.0" grep -q '"event":"run_start".*"warden":"1.32.0"' "$OUT/rs.log"
fi

echo "== 2. varek doctor in a container (D11) =="
VAREK_CONFIG=/nonexistent VAREK_DOCTOR_CONTAINER=test NO_COLOR=1 python3 "$VAREK" doctor > "$OUT/doc.out" 2>&1
check "doctor has a container section when it runs in one" grep -q 'In a container (test): the settings in packaging/container/README.md' "$OUT/doc.out"
if [ "$(id -u)" = 0 ] && [ "$(awk '/^CapEff:/ {print $2}' /proc/self/status)" = 000001ffffffffff ]; then
    check "... with the capabilities checked: all ten, as root with every capability" grep -qE 'OK +the 10 capabilities' "$OUT/doc.out"
else
    check "... with the capabilities checked" grep -qE '(OK|FAIL)  +(the 10 capabilities|capability )' "$OUT/doc.out"
fi
if [ "$(id -u)" = 0 ]; then
    check "... and the Warden's mounts made in a child" grep -q 'OK    a test of the Warden.s mounts: a mount namespace of its own, a directory mounted noexec' "$OUT/doc.out"
else
    skip "the mount test (needs root)"
fi
VAREK_CONFIG=/nonexistent NO_COLOR=1 python3 "$VAREK" doctor > "$OUT/doc0.out" 2>&1
check "outside a container, no container section" sh -c "! grep -q 'In a container' '$OUT/doc0.out' || [ -f /.dockerenv ] || [ -f /run/.containerenv ]"

echo "== 3. the preflight's share =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ] || ! command -v setpriv > /dev/null; then
    skip "varek run in a container that lacks a capability (needs root, the warden binary and setpriv)"
else
    W="$(mktemp -d /tmp/varek_v1320.XXXXXX)"; chmod 755 "$W"; mkdir -m 755 "$W/proj"
    vr() { (cd "$W/proj" && env VAREK_CONFIG="$W/none/varek.conf" VAREK_DOCTOR_CONTAINER=test NO_COLOR=1 "$@" \
              python3 "$VAREK" run -- /usr/bin/true); }
    vr > "$OUT/run.out" 2>&1; echo $? > "$OUT/run.rc"
    check "with the capabilities, the run goes ahead" sh -c "grep -qx 0 '$OUT/run.rc' && grep -q 'ended (exit 0)' '$OUT/run.out'"
    vr setpriv --bounding-set -sys_ptrace > "$OUT/norun.out" 2>&1; echo $? > "$OUT/norun.rc"
    check "without SYS_PTRACE, refused before the agent starts" sh -c "! grep -qx 0 '$OUT/norun.rc' && grep -q 'this container cannot carry the run: capability SYS_PTRACE is missing' '$OUT/norun.out' && ! grep -q 'supervising' '$OUT/norun.out'"
    check "... naming the flag that grants it" grep -q 'fix: --cap-add SYS_PTRACE' "$OUT/norun.out"
    POL="$HERE/policy.txt"
    VAREK_DOCTOR_CONTAINER=test setpriv --bounding-set -sys_ptrace "$HERE/tools/varek_preflight.sh" "$POL" > "$OUT/pf.out" 2>&1
    check "the preflight's section 2b in a container" grep -q '^== 2b. the container' "$OUT/pf.out"
    check "... FAILs the missing capability, with its flag" grep -q 'FAIL  capability SYS_PTRACE is missing: .*(--cap-add SYS_PTRACE)' "$OUT/pf.out"
    "$HERE/tools/varek_preflight.sh" "$POL" > "$OUT/pf0.out" 2>&1
    check "... and has no section 2b outside one" sh -c "! grep -q '^== 2b' '$OUT/pf0.out' || [ -f /.dockerenv ] || [ -f /run/.containerenv ]"
fi

echo "== 4. the packaging =="
PK="$ROOT/packaging/container"
AA="$PK/apparmor/varek-container"
if command -v apparmor_parser > /dev/null; then
    F=; for a in 4.0 3.0; do [ -f "/etc/apparmor.d/abi/$a" ] && F="-M /etc/apparmor.d/abi/$a" && break; done
    # shellcheck disable=SC2086
    check "the AppArmor profile compiles" sh -c "apparmor_parser -Q -K -S $F '$AA' > /dev/null"
else
    skip "the AppArmor profile compiles (no apparmor_parser here)"
fi
# the profile's rules that name mounts, exactly the Warden's three (v1.32 review)
cat > "$OUT/aa.want" <<'EOF2'
mount options=(rprivate) -> /,
mount options=(rbind) /** -> /**,
mount options=(remount, bind) options in (noexec, ro, nosuid, nodev, noatime, nodiratime, relatime, nosymfollow) -> /**,
EOF2
grep -E '^\s*(audit\s+|allow\s+|deny\s+)*(mount|remount|umount|pivot_root)\b' "$AA" | sed 's/^ *//' > "$OUT/aa.have"
check "... allows the Warden's mounts and no other: exactly its three mount rules, and umount" \
    sh -c "grep -vx 'umount,' '$OUT/aa.have' | diff -q '$OUT/aa.want' - && grep -qx 'umount,' '$OUT/aa.have'"
check "... and keeps docker-default's denials (/proc, /sys, AF_ALG, AF_VSOCK)" sh -c "grep -q 'deny @{PROC}/sysrq-trigger rwklx' '$AA' && grep -q 'deny /sys/firmware/\*\* rwklx' '$AA' && grep -qx '  deny network alg,' '$AA' && grep -qx '  deny network vsock,' '$AA'"
cat > "$OUT/se.want" <<'EOF2'
(allow container_init_t cgroup_t (filesystem (remount)))
(allow container_init_t container_file_t (chr_file (mounton)))
(allow container_init_t null_device_t (chr_file (mounton)))
(allow container_init_t devtty_t (chr_file (mounton)))
EOF2
check "the SELinux module: exactly container_init_t's four rules (the cgroup remount; mounton the container's and the host's /dev/null and /dev/tty)" \
    sh -c "grep -v '^ *;' '$PK/selinux/varek_container.cil' | grep -v '^ *\$' | diff -q '$OUT/se.want' -"
CF="$PK/Containerfile"
check "the Containerfile: build, runtime and test stages; the entrypoint varek run" \
    sh -c "grep -q ' AS build\$' '$CF' && grep -q ' AS runtime\$' '$CF' && grep -q ' AS test\$' '$CF' && grep -qF 'ENTRYPOINT [\"varek\", \"run\", \"--\"]' '$CF'"
check "the container sweep parses and says how to use it" sh -c "bash -n '$HERE/tests/container_sweep.sh' && bash '$HERE/tests/container_sweep.sh' --help | grep -q -- '--apparmor'"
if python3 -c 'import yaml' 2> /dev/null; then
    WF="$ROOT/.github/workflows"
    check "CI builds both images and runs the sweep under the profile" python3 -c "
import yaml, sys
s = yaml.safe_load(open('$WF/container.yml'))['jobs']['image']['steps']
run = ' '.join(x.get('run', '') for x in s)
sys.exit(0 if '--target runtime' in run and '--target test' in run and 'container_sweep.sh' in run and '--apparmor' in run else 1)"
    check "the release publishes, signs, attests and verifies" python3 -c "
import yaml, sys
import re
d = yaml.safe_load(open('$WF/container-release.yml'))
j = d['jobs']['publish']
run = ' '.join(x.get('run', '') for x in j['steps'])
ok = d['permissions'] == {} and j['permissions'].get('id-token') == 'write' and j['permissions'].get('packages') == 'write'
ok = ok and all(w in run for w in ('docker push', 'cosign sign', 'cosign attest', 'cosign verify ', 'cosign verify-attestation'))
# every action pinned by its commit; no expression in a script (v1.32 review)
ok = ok and all(re.fullmatch(r'[\w.-]+/[\w./-]+@[0-9a-f]{40}', x['uses']) for x in j['steps'] if 'uses' in x)
ok = ok and '\${{' not in run and 'merge-base --is-ancestor' in run
sys.exit(0 if ok else 1)"
else
    skip "the workflows (no python3-yaml here)"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1320: PASS ($skips skipped)"; else echo "test_v1320: FAIL"; fi
exit "$fail"
