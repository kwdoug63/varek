#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# v1340_k8s.sh — v1.34 step 1 (docs/security/v1.34-kubernetes.md), the
# Kubernetes half: on a fresh Ubuntu 24.04 host (cgroup v2), as root, from a
# checkout of this branch. It installs Docker, kind and kubectl, starts a
# one-node cluster (containerd 2.x), and measures:
#   1. a pod whose seccomp profile (Localhost) is the Warden's filter in
#      OCI's form with listenerPath: does the kubelet carry listenerPath to
#      the runtime, and does the stand-in node agent (tests/v1340_listener.c)
#      receive the container's state (the pod's annotations) and descriptor;
#   2. the launcher's Landlock under that filter (the three landlock calls
#      admitted), in the pod as the agent's user;
#   3. D6: from the node, can a group be made under the container's own
#      control group and one of its processes moved into it;
#   4. NRI: is it on in the node's containerd, and its socket there.
# Then it deletes the cluster. The summary is DIR/summary.txt (default
# /var/tmp/varek-k8s); everything else is beside it.
#
#   varek/v1_4/tests/v1340_k8s.sh [--out DIR] [--keep]
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT=/var/tmp/varek-k8s KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "v1340_k8s.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "v1340_k8s.sh: run as root" >&2; exit 2; }
grep -q cgroup2 /proc/filesystems && [ -e /sys/fs/cgroup/cgroup.controllers ] ||
    { echo "v1340_k8s.sh: this host has no cgroup v2 (the unified hierarchy)" >&2; exit 2; }
KIND_V=v0.29.0 KUBE_V=v1.33.1 NODE_IMG=kindest/node:v1.33.1 POD_IMG=mirror.gcr.io/library/busybox:1.36
S=/opt/varek-k8s
mkdir -p "$OUT" "$S"
SUM="$OUT/summary.txt"
: > "$SUM"
say() { echo "$*" | tee -a "$SUM"; }
say "v1340_k8s.sh $(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z'); $(uname -sr); commit $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null)"

echo "== installing Docker, gcc, libseccomp, kind $KIND_V, kubectl $KUBE_V"
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update > "$OUT/apt.log" 2>&1 && apt-get -qq install -y docker.io gcc libseccomp-dev python3 >> "$OUT/apt.log" 2>&1 ||
    { tail -5 "$OUT/apt.log"; echo "v1340_k8s.sh: the packages did not install" >&2; exit 1; }
systemctl start docker
curl -fsSLo /usr/local/bin/kind "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_V/kind-linux-amd64" &&
curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/$KUBE_V/bin/linux/amd64/kubectl" &&
    chmod +x /usr/local/bin/kind /usr/local/bin/kubectl || { echo "v1340_k8s.sh: kind or kubectl did not download" >&2; exit 1; }

echo "== building the filter's OCI form, the stand-in node agent and the Landlock probe"
cd "$HERE" || exit 1
gcc -O2 -I. -o "$S/v1340_oci_filter" tests/v1340_oci_filter.c -lseccomp 2> "$OUT/build.log" &&
gcc -O2 -static -o "$S/v1340_listener" tests/v1340_listener.c 2>> "$OUT/build.log" &&
cat > "$S/ll.c" <<'EOF'
#define _GNU_SOURCE
#include <linux/landlock.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    printf("landlock abi: %ld (%s)\n", abi, abi < 0 ? strerror(errno) : "ok");
    struct landlock_ruleset_attr ra = { .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE };
    int rs = (int)syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
    if (rs < 0) { printf("create_ruleset: %s\n", strerror(errno)); return 0; }
    int d = open("/etc", O_PATH | O_CLOEXEC);
    struct landlock_path_beneath_attr pb = { .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE, .parent_fd = d };
    long r = syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    long q = syscall(SYS_landlock_restrict_self, rs, 0);
    int f = open("/etc/hostname", O_RDONLY), g = open("/bin/sh", O_RDONLY);
    printf("add_rule %s, restrict_self %s; after: /etc/hostname %s, /bin/sh %s\n", r < 0 ? strerror(errno) : "ok",
           q < 0 ? "refused" : "ok", f >= 0 ? "opened" : "refused", g >= 0 ? "opened" : "refused");
    return 0;
}
EOF
gcc -O2 -static -o "$S/ll" "$S/ll.c" 2>> "$OUT/build.log" || { tail -5 "$OUT/build.log"; echo "v1340_k8s.sh: the build failed" >&2; exit 1; }
mkdir -p "$S/f" && "$S/v1340_oci_filter" 1 "$S/f" > /dev/null &&
python3 - "$S/f/oci.json" "$S/varek.json" <<'EOF' || exit 1
import json, sys
p = json.load(open(sys.argv[1]))
p.pop("warden_badarch", None)
p["architectures"] = ["SCMP_ARCH_X86_64"]
for s in p["syscalls"]:
    s.pop("nr", None)
p["syscalls"].append({"names": ["landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self"],
                      "action": "SCMP_ACT_ALLOW"})
p["listenerPath"] = "/opt/varek-k8s/agent.sock"
p["listenerMetadata"] = "varek-v1340-k8s"
json.dump(p, open(sys.argv[2], "w"))
EOF
chmod -R a+rX "$S"

echo "== a kind cluster ($NODE_IMG)"
kind delete cluster --name varek > /dev/null 2>&1
cat > "$OUT/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: $S
    containerPath: $S
EOF
kind create cluster --name varek --image "$NODE_IMG" --config "$OUT/kind.yaml" --wait 300s > "$OUT/kind.log" 2>&1 ||
    { tail -20 "$OUT/kind.log"; echo "v1340_k8s.sh: the cluster did not start" >&2; exit 1; }
N=varek-control-plane
say "node: $(docker exec $N sh -c 'containerd --version; runc --version | head -1' | tr '\n' ' ')"
docker exec $N mkdir -p /var/lib/kubelet/seccomp && docker cp "$S/varek.json" $N:/var/lib/kubelet/seccomp/varek.json
docker exec -d $N "$S/v1340_listener" "$S/agent.sock" "$S/listener.log" 400
for _ in $(seq 50); do docker exec $N test -S "$S/agent.sock" && break; sleep 0.2; done

say "== 1. a pod under the Warden's filter, with listenerPath (Localhost profile)"
cat > "$OUT/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: varek-agent
  annotations:
    varek.dev/policy: test
spec:
  restartPolicy: Never
  securityContext:
    runAsUser: 65534
    runAsGroup: 65534
    seccompProfile:
      type: Localhost
      localhostProfile: varek.json
  containers:
  - name: agent
    image: $POD_IMG
    command: ["/bin/sh", "-c", "echo hostname \$(cat /etc/hostname); ls / | wc -l; /varek/ll; sleep 90"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities: {drop: ["ALL"]}
    volumeMounts:
    - {name: varek, mountPath: /varek, readOnly: true}
  volumes:
  - name: varek
    hostPath: {path: $S}
EOF
kubectl apply -f "$OUT/pod.yaml" > /dev/null
for _ in $(seq 120); do
    ph="$(kubectl get pod varek-agent -o jsonpath='{.status.phase}' 2>/dev/null)"
    [ "$ph" = Running ] || [ "$ph" = Succeeded ] || [ "$ph" = Failed ] && break
    sleep 1
done
say "  the pod: ${ph:-not started}"
kubectl describe pod varek-agent > "$OUT/pod.describe" 2>&1
[ "$ph" = Running ] || [ "$ph" = Succeeded ] || grep -E 'Warning|Error|seccomp' "$OUT/pod.describe" | tail -5 | tee -a "$SUM"
sleep 3
kubectl logs varek-agent > "$OUT/pod.log" 2>&1
sed 's/^/  pod: /' "$OUT/pod.log" | tee -a "$SUM"
cp "$S/listener.log" "$OUT/listener.log" 2>/dev/null
if grep -q 'descriptors received: 1' "$OUT/listener.log" 2>/dev/null; then
    say "  the node agent received the descriptor: yes"
    grep -o '"annotations":{[^}]*}' "$OUT/listener.log" | head -1 | sed 's/^/  annotations: /' | tee -a "$SUM"
    grep -E 'memory read|pidfd_getfd|openat2|notifications answered' "$OUT/listener.log" | sed 's/^/  /' | tee -a "$SUM"
else
    say "  the node agent received the descriptor: NO ($(wc -l < "$OUT/listener.log" 2>/dev/null || echo 0) log lines)"
fi

say "== 3. D6: a group under the container's own, from the node"
pid="$(docker exec $N sh -c "crictl inspect \$(crictl ps -q --name agent | head -1) 2>/dev/null" | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["pid"])' 2>/dev/null)"
if [ -n "$pid" ]; then
    docker exec $N sh -c "
        cg=\$(sed -n 's/^0:://p' /proc/$pid/cgroup); d=/sys/fs/cgroup\$cg
        echo \"  the container's group: \$cg\"
        echo \"  its controllers: \$(cat \$d/cgroup.controllers); enabled below it: \$(cat \$d/cgroup.subtree_control)\"
        if mkdir \$d/varek-sub 2>/tmp/e; then echo '  make a group under it: ok'
            if echo $pid > \$d/varek-sub/cgroup.procs 2>/tmp/e; then echo '  move its process into it: ok'; echo $pid > \$d/cgroup.procs; else echo \"  move its process into it: FAILED (\$(cat /tmp/e))\"; fi
            if echo +pids > \$d/cgroup.subtree_control 2>/tmp/e; then echo '  enable pids below it: ok'; echo -pids > \$d/cgroup.subtree_control; else echo \"  enable pids below it: FAILED (\$(cat /tmp/e))\"; fi
            rmdir \$d/varek-sub
        else echo \"  make a group under it: FAILED (\$(cat /tmp/e))\"; fi
    " 2>&1 | tee -a "$SUM"
else
    say "  the container's process was not found (the pod did not run)"
fi

say "== 4. NRI in the node's containerd"
docker exec $N sh -c "containerd config dump 2>/dev/null | sed -n '/io.containerd.nri.v1.nri/,/^ *\$/p' | grep -E 'disable|socket_path' | head -3; ls -l /var/run/nri/nri.sock 2>&1" | sed 's/^/  /' | tee -a "$SUM"

if [ "$KEEP" = 0 ]; then kind delete cluster --name varek > /dev/null 2>&1; say "(the cluster deleted)"; fi
say "v1340_k8s.sh: done; $SUM"
