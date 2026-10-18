#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# rootless_remount.sh — the v1.32 second review's open question (D10 of
# docs/security/v1.32-containers.md): in rootless Podman, without
# --systemd=always, can the container's read-only cgroup filesystem be
# bind-remounted read-write in a mount namespace of the container's own, as
# the Warden does since the review (sub_cg_remount), and can groups then be
# made and a process moved into one? D10 was measured with the plain
# remount, which the kernel refused. Run as the rootless user (not root),
# on the RHEL host with Podman and VAREK's SELinux module loaded:
#
#   bash rootless_remount.sh [IMAGE]
#
# IMAGE: an image with util-linux (default: the newest varek-test image
# here, else registry.access.redhat.com/ubi9/ubi). Each case prints its
# steps; the last lines are the verdict.
set -u
[ "$(id -u)" != 0 ] || { echo "rootless_remount.sh: run as the rootless user, not root" >&2; exit 2; }
IMG="${1:-$(podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -m1 'varek-test')}"
IMG="${IMG:-registry.access.redhat.com/ubi9/ubi}"
CAPS="SYS_ADMIN SYS_PTRACE SETPCAP SETUID SETGID DAC_OVERRIDE KILL NET_ADMIN NET_BIND_SERVICE CHOWN"
args=(--rm --cap-drop ALL --cgroupns=private --security-opt label=type:container_init_t)
for c in $CAPS; do args+=(--cap-add "$c"); done
echo "host: $(uname -r); $(podman --version); image $IMG"
echo "selinux module: $(sudo -n semodule -l 2>/dev/null | grep -c varek_container || echo '? (sudo semodule -l | grep varek_container)')"
echo "cgroup delegation (this user's session): $(cat "/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers" 2>/dev/null)"

PROBE='
m() { grep " /sys/fs/cgroup " /proc/self/mounts | head -1 | cut -d" " -f3,4; }
echo "  user ns inode: $(stat -Lc %i /proc/self/ns/user) (4026531837 is the initial one)"
echo "  cgroup: $(cat /proc/self/cgroup)"
echo "  the mount: $(m)"
case "$(m)" in cgroup2*) ;; *) echo "  not a cgroup2 mount: nothing measured"; exit 0 ;; esac
unshare -m sh -c "
  mount --make-rprivate / && echo \"  private: ok\" || echo \"  private: FAILED\"
  if mount -o remount,bind,rw /sys/fs/cgroup 2>/tmp/e; then echo \"  bind remount rw: ok\"; else echo \"  bind remount rw: FAILED (\$(cat /tmp/e))\"; fi
  echo \"  after: \$(grep \" /sys/fs/cgroup \" /proc/self/mounts | head -1 | cut -d\" \" -f3,4)\"
  if mkdir /sys/fs/cgroup/varek-probe 2>/tmp/e; then echo \"  make a group: ok\"
    if echo \$\$ > /sys/fs/cgroup/varek-probe/cgroup.procs 2>/tmp/e; then echo \"  move a process into it: ok\"; else echo \"  move a process into it: FAILED (\$(cat /tmp/e))\"; fi
    echo \$\$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null; rmdir /sys/fs/cgroup/varek-probe 2>/dev/null
  else echo \"  make a group: FAILED (\$(cat /tmp/e))\"; fi
  if mount -o remount,rw /sys/fs/cgroup 2>/tmp/e; then echo \"  plain remount rw (D10 as measured): ok\"; else echo \"  plain remount rw (D10 as measured): FAILED (\$(cat /tmp/e))\"; fi
"
'
out=""
for mode in plain systemd; do
    extra=()
    [ "$mode" = systemd ] && extra=(--systemd=always)
    if [ "$mode" = systemd ]; then echo "== rootless, with --systemd=always (as documented)"; else echo "== rootless, without --systemd=always"; fi
    r="$(podman run "${args[@]}" "${extra[@]}" "$IMG" sh -c "$PROBE" 2>&1)"
    echo "$r"
    out+="$mode:$r"$'\n'
done
echo
plain="$(sed -n '/^plain:/,/^systemd:/p' <<< "$out")"
if grep -q 'bind remount rw: ok' <<< "$plain" && grep -q 'move a process into it: ok' <<< "$plain"; then
    echo "VERDICT: without --systemd=always, the bind remount works and a group can be made and used: the Warden's refusal in a user namespace can be lifted (to be built and tested)"
elif grep -q 'bind remount rw: ok' <<< "$plain"; then
    echo "VERDICT: the bind remount works, but a group cannot be made or used: the refusal stays (the reason: the groups, not the mount)"
else
    echo "VERDICT: the bind remount is refused in a user namespace: the refusal stays, its reason now measured"
fi
