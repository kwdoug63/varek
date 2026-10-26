#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# m1_cgroup.sh — v1.36 step 1, M1 (tests/measure_v1360/README.md; the
# design note's D3): under the systemd cgroup driver, a group made from the
# node below a container's own, a process moved into it, a call attributed
# by it, systemd's reload, the container's end, and the pod's limits. On a
# cluster node_cluster.sh made; as root.
#
#   sudo -E varek/v1_4/tests/measure_v1360/m1_cgroup.sh [--out DIR]
#
# Each check prints a MEASURE line and the next one runs whatever it said.
# Exits 1 only if the test pod does not start.
set -uo pipefail

OUT=/var/tmp/measure_v1360
[ "${1:-}" = --out ] && OUT="$2"
[ "$(id -u)" = 0 ] || { echo "m1_cgroup.sh: run as root" >&2; exit 2; }
export KUBECONFIG=/etc/kubernetes/admin.conf
KUBECTL=/usr/bin/kubectl
IMG="${POD_IMAGE:-registry.k8s.io/e2e-test-images/busybox:1.36.1-1}"
mkdir -p "$OUT"
LOG="$OUT/m1.log"
measure() {
    echo "MEASURE m1.$1: $2" | tee -a "$OUT/measure.txt"
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- \`m1.$1\`: $2" >> "$GITHUB_STEP_SUMMARY"
    return 0
}
yn() { if "$@" >> "$LOG" 2>&1; then echo yes; else echo "no ($(tail -1 "$LOG"))"; fi; }

rt="$("$KUBECTL" get node -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}')"
case "$rt" in
    cri-o://*) EP=unix:///var/run/crio/crio.sock ;;
    containerd://*) EP=unix:///run/containerd/containerd.sock ;;
    *) echo "m1_cgroup.sh: runtime $rt" >&2; exit 1 ;;
esac
measure runtime "$rt; kernel $(uname -r)"
crictl() { command crictl --runtime-endpoint "$EP" "$@"; }
# A container's process id on the node, by pod name
cpid() {
    local id
    id="$("$KUBECTL" get pod "$1" -o jsonpath='{.status.containerStatuses[0].containerID}')"
    crictl inspect "${id#*://}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["pid"])'
}
cg_of() { awk -F: '$1 == "0" {print $3}' "/proc/$1/cgroup"; }
# A process of the container (its group under the container's), by its
# command line: not kubectl's own, which carries the same words
in_ctr() {
    local p
    for p in $(pgrep -f "$1"); do
        case "$(cg_of "$p" 2> /dev/null)" in "$cg"|"$cg"/*) echo "$p"; return ;; esac
    done
}
# The cgroup id the kernel reports through a pidfd (Linux 6.13), as the
# Warden reads it (warden_subagent.inc.c, sub_cgid_of); "none" before 6.13
pidfd_cgid() {
    python3 - "$1" <<'EOF'
import fcntl, os, struct, sys
fmt = "<QQ11IiII"                       # struct pidfd_info, 72 bytes
size = struct.calcsize(fmt)
req = (3 << 30) | (size << 16) | (0xFF << 8) | 11
try:
    fd = os.pidfd_open(int(sys.argv[1]))
    buf = bytearray(struct.pack(fmt, 1 << 2, 0, *([0] * 11), 0, 0, 0))
    fcntl.ioctl(fd, req, buf)
    mask, cgid = struct.unpack_from("<QQ", buf)
    print(cgid if mask & (1 << 2) else "none")
except OSError as e:
    print("none (%s)" % e.strerror)
EOF
}

cat > "$OUT/m1-pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata: {name: m1}
spec:
  terminationGracePeriodSeconds: 5
  containers:
  - name: c
    image: $IMG
    command: [sleep, "31415926"]
    resources:
      requests: {cpu: 100m, memory: 64Mi}
      limits: {cpu: 500m, memory: 128Mi}
EOF
"$KUBECTL" apply -f "$OUT/m1-pod.yaml" >> "$LOG" 2>&1
"$KUBECTL" wait --for=condition=Ready pod/m1 --timeout=300s >> "$LOG" 2>&1 || {
    "$KUBECTL" describe pod m1 >> "$LOG" 2>&1; measure pod "did not start"; exit 1; }

# 1. The container's group
pid="$(cpid m1)"
# Every check below acts on this process's group: without it they would act
# on the node's root group (the first run, crictl missing, did)
case "$pid" in ''|*[!0-9]*|0) measure setup "the container's process was not found (crictl: $(command -v crictl || echo missing))"; exit 1 ;; esac
cg="$(cg_of "$pid")"
[ -n "$cg" ] && [ "$cg" != / ] || { measure setup "the container's group was not found (pid $pid)"; exit 1; }
G="/sys/fs/cgroup$cg"
measure container_cgroup "$cg"
measure systemd_scope "$([[ "$cg" == *.scope ]] && echo yes || echo no)"
measure controllers "$(cat "$G/cgroup.controllers"); subtree_control: '$(cat "$G/cgroup.subtree_control")'"

# 2. A group below, the container's process moved into it, pids enabled below
S="$G/varek-sub-1"
measure mkdir_below "$(yn mkdir "$S")"
measure move_process "$(yn sh -c "echo $pid > '$S/cgroup.procs'")"
measure process_in_sub "$([ "$(cg_of "$pid")" = "$cg/varek-sub-1" ] && echo yes || echo "no ($(cg_of "$pid"))")"
measure enable_pids_below "$(yn sh -c "echo +pids > '$G/cgroup.subtree_control'")"

# 3. A second process in the container (kubectl exec), its group as the
# kernel reports it through a pidfd
"$KUBECTL" exec m1 -- sleep 271828 >> "$LOG" 2>&1 &
sleep 5
epid="$(in_ctr 'sleep 271828')"
if [ -n "$epid" ]; then
    measure exec_after_enable "yes, its group $(cg_of "$epid")"
else
    measure exec_after_enable "no ($(tail -1 "$LOG"))"
fi
measure pidfd_cgroupid "moved process: $(pidfd_cgid "$pid"); varek-sub-1's inode: $(stat -c %i "$S")"
[ -n "$epid" ] && measure pidfd_cgroupid_exec "$(pidfd_cgid "$epid"); the container group's inode: $(stat -c %i "$G")"
measure disable_pids_below "$(yn sh -c "echo -pids > '$G/cgroup.subtree_control'")"

# 4. systemd's reload leaves the group below the scope as it was
systemctl daemon-reload
sleep 3
measure after_daemon_reload "$([ -d "$S" ] && [ "$(cg_of "$pid")" = "$cg/varek-sub-1" ] && echo "kept" || echo "changed: $(cg_of "$pid"), sub exists: $([ -d "$S" ] && echo yes || echo no)")"

# 6. The pod's limits over a process moved below: the kubelet's figure
node="$("$KUBECTL" get node -o jsonpath='{.items[0].metadata.name}')"
ws() {
    "$KUBECTL" get --raw "/api/v1/nodes/$node/proxy/stats/summary" | python3 -c '
import json, sys
for p in json.load(sys.stdin).get("pods", []):
    if p["podRef"]["name"] == "m1":
        print(sum(c.get("memory", {}).get("workingSetBytes", 0) for c in p.get("containers", [])))'
}
before="$(ws)"
for _ in 1 2 3 4 5 6; do [ -n "$before" ] && break; sleep 5; before="$(ws)"; done
"$KUBECTL" exec m1 -- sh -c 'sleep 3; x=$(head -c 60000000 /dev/zero | tr "\0" a); sleep 90' >> "$LOG" 2>&1 &
sleep 1
hold="$(in_ctr 'sleep 3; x=')"
if [ -n "$hold" ]; then
    echo "$hold" > "$S/cgroup.procs" 2>> "$LOG"
    sleep 40
    measure kubelet_counts_below "working set before $before, with 60 MB held below $(ws) (the kubelet's summary)"
    measure memory_current "container group $(cat "$G/memory.current"), varek-sub-1 $(cat "$S/memory.current" 2>/dev/null || echo "none (memory is not enabled below)")"
else
    measure kubelet_counts_below "not measured (no exec)"
fi
# 5. The pod deleted: every process below ended, the scope and its groups gone
"$KUBECTL" delete pod m1 --grace-period=5 --wait=true --timeout=120s >> "$LOG" 2>&1
sleep 5
measure process_ended "$(kill -0 "$pid" 2> /dev/null && echo "no, $pid still runs" || echo yes)"
measure groups_removed "$([ -d "$G" ] && echo "no: $(find "$G" -type d | wc -l) groups left" || echo yes)"

# 6b. The memory limit over a process moved below, in a pod of its own. The
# sixth run did this in m1: the container's group was gone after it (the
# kubelet sets memory.oom.group, so the kill takes the whole container and
# it restarts in a new group), and that left step 5 measuring the old one.
sed 's/name: m1}/name: m1lim}/' "$OUT/m1-pod.yaml" > "$OUT/m1lim-pod.yaml"
"$KUBECTL" apply -f "$OUT/m1lim-pod.yaml" >> "$LOG" 2>&1
if "$KUBECTL" wait --for=condition=Ready pod/m1lim --timeout=300s >> "$LOG" 2>&1; then
    lpid="$(cpid m1lim)"; cg="$(cg_of "$lpid")"; LG="/sys/fs/cgroup$cg"; LS="$LG/varek-sub-1"
    mkdir "$LS" 2>> "$LOG"
    echo "$lpid" > "$LS/cgroup.procs" 2>> "$LOG"
    measure limit_settings "memory.max $(cat "$LG/memory.max"), memory.oom.group $(cat "$LG/memory.oom.group" 2>/dev/null || echo none)"
    "$KUBECTL" exec m1lim -- sh -c 'sleep 3; head -c 300000000 /dev/zero | tail > /dev/null' >> "$LOG" 2>&1 &
    sleep 1
    big="$(in_ctr 'sleep 3; head -c 300000000')"
    if [ -n "$big" ]; then
        echo "$big" > "$LS/cgroup.procs" 2>> "$LOG"
        moved="$([ "$(cg_of "$big")" = "$cg/varek-sub-1" ] && echo yes || echo "no, $(cg_of "$big")")"
        sleep 20
        st="$("$KUBECTL" get pod m1lim -o jsonpath='{.status.containerStatuses[0].restartCount} {.status.containerStatuses[0].lastState.terminated.reason}')"
        measure limit_enforced_below "moved below: $moved; after: restarts and reason '$st', the first process $(kill -0 "$lpid" 2> /dev/null && echo "still runs" || echo ended), the old group $([ -d "$LG" ] && echo "still there" || echo gone)"
    else
        measure limit_enforced_below "not measured (no exec)"
    fi
    "$KUBECTL" delete pod m1lim --grace-period=5 --wait=true --timeout=120s >> "$LOG" 2>&1
else
    measure limit_enforced_below "not measured (m1lim did not start)"
fi
exit 0
