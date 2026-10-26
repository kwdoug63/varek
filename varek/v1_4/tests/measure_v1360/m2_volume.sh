#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# m2_volume.sh — v1.36 step 1, M2 (tests/measure_v1360/README.md; the
# design note's D5): a pod declares a Secret volume that no container
# mounts. Does the kubelet mount it on the node, before the container's
# first process, out of the pod's sight, and remove it with the pod? On a
# cluster node_cluster.sh made; as root.
#
#   sudo -E varek/v1_4/tests/measure_v1360/m2_volume.sh [--out DIR]
set -uo pipefail

OUT=/var/tmp/measure_v1360
[ "${1:-}" = --out ] && OUT="$2"
[ "$(id -u)" = 0 ] || { echo "m2_volume.sh: run as root" >&2; exit 2; }
export KUBECONFIG=/etc/kubernetes/admin.conf
KUBECTL=/usr/bin/kubectl
IMG="${POD_IMAGE:-registry.k8s.io/e2e-test-images/busybox:1.36.1-1}"
mkdir -p "$OUT"
LOG="$OUT/m2.log"
measure() {
    echo "MEASURE m2.$1: $2" | tee -a "$OUT/measure.txt"
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- \`m2.$1\`: $2" >> "$GITHUB_STEP_SUMMARY"
    return 0
}
now() { date +%s.%N; }

value="m2-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
"$KUBECTL" create secret generic obo-token --from-literal=token="$value" >> "$LOG" 2>&1
cat > "$OUT/m2-pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata: {name: m2}
spec:
  terminationGracePeriodSeconds: 5
  containers:
  - name: c
    image: $IMG
    command: [sleep, "16180339"]
  volumes:
  - name: obo-token
    secret: {secretName: obo-token}
EOF
"$KUBECTL" apply -f "$OUT/m2-pod.yaml" >> "$LOG" 2>&1
uid=""
for _ in $(seq 100); do
    uid="$("$KUBECTL" get pod m2 -o jsonpath='{.metadata.uid}' 2> /dev/null)"; [ -n "$uid" ] && break; sleep 0.1
done
[ -n "$uid" ] || { measure pod "not created"; exit 1; }
V="/var/lib/kubelet/pods/$uid/volumes/kubernetes.io~secret/obo-token"

# 2. Which comes first on the node: the volume's directory, or the
# container's first process (its command, in a group of the pod's)
t_vol="" t_ctr=""
for _ in $(seq 3000); do
    [ -z "$t_vol" ] && [ -f "$V/token" ] && t_vol="$(now)"
    if [ -z "$t_ctr" ]; then
        for p in $(pgrep -x -f 'sleep 16180339'); do
            grep -q "${uid//-/_}\|$uid" "/proc/$p/cgroup" 2> /dev/null && { t_ctr="$(now)"; break; }
        done
    fi
    [ -n "$t_vol" ] && [ -n "$t_ctr" ] && break
    sleep 0.05
done
"$KUBECTL" wait --for=condition=Ready pod/m2 --timeout=300s >> "$LOG" 2>&1 || {
    "$KUBECTL" describe pod m2 >> "$LOG" 2>&1; measure pod "did not start"; exit 1; }

# 1. The directory, its key, and what it is
if [ -f "$V/token" ]; then
    measure volume_on_node "yes, $V ($(findmnt -no FSTYPE "$V" 2> /dev/null || echo "not a mount point"))"
    measure token_matches "$([ "$(cat "$V/token")" = "$value" ] && echo yes || echo no)"
else
    measure volume_on_node "no ($(ls "/var/lib/kubelet/pods/$uid/volumes/" 2>&1 | tr '\n' ' '))"
fi
if [ -n "$t_vol" ] && [ -n "$t_ctr" ]; then
    measure volume_before_container "$(python3 -c "print('yes, %.2f s before' % ($t_ctr - $t_vol) if $t_vol <= $t_ctr else 'no, %.2f s after' % ($t_vol - $t_ctr))")"
else
    measure volume_before_container "not measured (volume seen: ${t_vol:-no}, container seen: ${t_ctr:-no})"
fi

# 4. The pod's container does not see it
seen="$("$KUBECTL" exec m2 -- grep -c obo-token /proc/self/mountinfo 2>> "$LOG")"
measure hidden_from_container "$([ "$seen" = 0 ] && echo "yes (not in its mounts)" || echo "no: ${seen:-the exec failed} of its mounts name it")"

# 3. Gone with the pod
"$KUBECTL" delete pod m2 --grace-period=5 --wait=true --timeout=120s >> "$LOG" 2>&1
for _ in $(seq 60); do [ -e "$V" ] || break; sleep 1; done
measure removed_with_pod "$([ -e "$V" ] && echo "no, $V remains" || echo yes)"
"$KUBECTL" delete secret obo-token >> "$LOG" 2>&1

# 5. M2b: the same Secret mounted by an init container that ends before the
# pod's container starts (the first run found the kubelet does not mount a
# volume no container names). Is it on the node while the pod runs, and
# still out of the pod's container's sight?
value="m2b-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
"$KUBECTL" create secret generic obo-token --from-literal=token="$value" >> "$LOG" 2>&1
cat > "$OUT/m2b-pod.yaml" <<EOF2
apiVersion: v1
kind: Pod
metadata: {name: m2b}
spec:
  terminationGracePeriodSeconds: 5
  initContainers:
  - name: i
    image: $IMG
    command: ["true"]
    volumeMounts: [{name: obo-token, mountPath: /obo, readOnly: true}]
  containers:
  - name: c
    image: $IMG
    command: [sleep, "16180340"]
  volumes:
  - name: obo-token
    secret: {secretName: obo-token}
EOF2
"$KUBECTL" apply -f "$OUT/m2b-pod.yaml" >> "$LOG" 2>&1
if "$KUBECTL" wait --for=condition=Ready pod/m2b --timeout=300s >> "$LOG" 2>&1; then
    uid="$("$KUBECTL" get pod m2b -o jsonpath='{.metadata.uid}')"
    V="/var/lib/kubelet/pods/$uid/volumes/kubernetes.io~secret/obo-token"
    if [ -f "$V/token" ]; then
        measure init_volume_on_node "yes, while the pod's container runs ($(findmnt -no FSTYPE "$V" 2> /dev/null || echo "not a mount point"))"
        measure init_token_matches "$([ "$(cat "$V/token")" = "$value" ] && echo yes || echo no)"
    else
        measure init_volume_on_node "no ($(ls "/var/lib/kubelet/pods/$uid/volumes/" 2>&1 | tr '\n' ' '))"
    fi
    seen="$("$KUBECTL" exec m2b -c c -- grep -c obo-token /proc/self/mountinfo 2>> "$LOG")"
    measure init_hidden_from_container "$([ "$seen" = 0 ] && echo "yes (not in its mounts)" || echo "no: ${seen:-the exec failed} of its mounts name it")"
    "$KUBECTL" delete pod m2b --grace-period=5 --wait=true --timeout=120s >> "$LOG" 2>&1
    for _ in $(seq 60); do [ -e "$V" ] || break; sleep 1; done
    measure init_removed_with_pod "$([ -e "$V" ] && echo "no, $V remains" || echo yes)"
else
    "$KUBECTL" describe pod m2b 2>&1 | tail -25; measure init_pod "did not start"
fi
"$KUBECTL" delete secret obo-token >> "$LOG" 2>&1
exit 0
