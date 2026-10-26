#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# node_cluster.sh — v1.36 step 1 (tests/measure_v1360/README.md, M4a and
# M4b): a one-node kubeadm cluster on this host, the systemd cgroup driver,
# under CRI-O or containerd, then a plain pod run on it. Made for GitHub's
# hosted runners (Ubuntu 24.04, systemd, cgroup v2): it stops the runner's
# own Docker and containerd, turns swap off and installs packages, so it is
# not for a machine anyone uses.
#
#   sudo -E varek/v1_4/tests/measure_v1360/node_cluster.sh --runtime crio --version 1.35 --oci runc [--out DIR]
#   sudo -E varek/v1_4/tests/measure_v1360/node_cluster.sh --runtime containerd --version 2.2 [--k8s 1.35] [--out DIR]
#
# Prints MEASURE lines (and adds them to $GITHUB_STEP_SUMMARY). Exits 1 if
# the cluster or the pod did not come up: for M4 that is the finding.
set -uo pipefail

RUNTIME="" VERSION="" OCI=runc K8S="" OUT=/var/tmp/measure_v1360
while [ $# -gt 0 ]; do
    case "$1" in
        --runtime) RUNTIME="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --oci) OCI="$2"; shift 2 ;;
        --k8s) K8S="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        *) echo "node_cluster.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "node_cluster.sh: run as root" >&2; exit 2; }
case "$RUNTIME" in crio|containerd) ;; *) echo "node_cluster.sh: --runtime crio|containerd" >&2; exit 2 ;; esac
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+$ ]] || { echo "node_cluster.sh: --version X.Y" >&2; exit 2; }
case "$OCI" in runc|crun) ;; *) echo "node_cluster.sh: --oci runc|crun" >&2; exit 2 ;; esac
[ "$RUNTIME" = containerd ] && [ "$OCI" != runc ] && { echo "node_cluster.sh: containerd here runs runc only" >&2; exit 2; }
# CRI-O's minor is the Kubernetes minor it is made for
[ -n "$K8S" ] || { [ "$RUNTIME" = crio ] && K8S="$VERSION" || K8S=1.35; }

# The CRI-O project's package repository for one minor (its install guide,
# github.com/cri-o/packaging). To be confirmed on the first run.
CRIO_REPO="https://download.opensuse.org/repositories/isv:/cri-o:/stable:/v$VERSION/deb/"
K8S_REPO="https://pkgs.k8s.io/core:/stable:/v$K8S/deb/"
FLANNEL="https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml"
# A test image the Kubernetes project keeps, with a shell and sleep
export POD_IMAGE="${POD_IMAGE:-registry.k8s.io/e2e-test-images/busybox:1.36.1-1}"
KUBECTL=/usr/bin/kubectl
export KUBECONFIG=/etc/kubernetes/admin.conf

mkdir -p "$OUT"
LOG="$OUT/node_cluster.log"
measure() {
    echo "MEASURE $1: $2" | tee -a "$OUT/measure.txt"
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- \`$1\`: $2" >> "$GITHUB_STEP_SUMMARY"
    return 0
}
run() { echo "+ $*" >> "$LOG"; "$@" >> "$LOG" 2>&1; }
fail() { measure "cluster.failed_at" "$1"; tail -30 "$LOG"; exit 1; }
START=$(date +%s)
CELL="$RUNTIME-$VERSION-$OCI"
measure "cell" "$CELL, Kubernetes $K8S, $(uname -sr), cgroup $(stat -fc %T /sys/fs/cgroup)"

# --- the host
run swapoff -a
run systemctl stop docker.socket docker containerd
run modprobe overlay
run modprobe br_netfilter
printf 'net.ipv4.ip_forward = 1\nnet.bridge.bridge-nf-call-iptables = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\n' > /etc/sysctl.d/90-measure.conf
run sysctl --system
install -d -m 0755 /etc/apt/keyrings
key() { curl -fsSL "$1Release.key" | gpg --dearmor --yes -o "$2"; }
key "$K8S_REPO" /etc/apt/keyrings/kubernetes.gpg || fail "the Kubernetes package key"
echo "deb [signed-by=/etc/apt/keyrings/kubernetes.gpg] $K8S_REPO /" > /etc/apt/sources.list.d/kubernetes.list

# --- the runtime
if [ "$RUNTIME" = crio ]; then
    key "$CRIO_REPO" /etc/apt/keyrings/cri-o.gpg || fail "the CRI-O package key ($CRIO_REPO)"
    echo "deb [signed-by=/etc/apt/keyrings/cri-o.gpg] $CRIO_REPO /" > /etc/apt/sources.list.d/cri-o.list
    run apt-get update || fail "apt-get update"
    run apt-get install -y cri-o kubelet kubeadm kubectl || fail "installing cri-o and kubeadm"
    # CRI-O's packages bring crun (and runc in newer ones); the OS's if not.
    # To be confirmed on the first run: where each package puts them.
    ociPath="$(command -v "$OCI" || ls "/usr/libexec/crio/$OCI" 2>/dev/null || true)"
    if [ -z "$ociPath" ]; then run apt-get install -y "$OCI"; ociPath="$(command -v "$OCI" || true)"; fi
    [ -n "$ociPath" ] || fail "no $OCI binary"
    install -d /etc/crio/crio.conf.d
    cat > /etc/crio/crio.conf.d/90-measure.conf <<EOF
[crio.runtime]
cgroup_manager = "systemd"
default_runtime = "$OCI"

[crio.runtime.runtimes.$OCI]
runtime_path = "$ociPath"
EOF
    run systemctl enable --now crio || fail "starting crio"
    SOCK=unix:///var/run/crio/crio.sock
    measure "runtime" "$(crio --version 2>/dev/null | awk '/^Version/ {print $2}'), $OCI $("$ociPath" --version 2>/dev/null | head -1)"
else
    run apt-get update || fail "apt-get update"
    run apt-get install -y kubelet kubeadm kubectl || fail "installing kubeadm"
    # The newest release of that minor, from the project's releases
    full="$(curl -fsSL "https://api.github.com/repos/containerd/containerd/releases?per_page=100" |
        python3 -c "import json,sys,re
v=[r['tag_name'][1:] for r in json.load(sys.stdin) if re.fullmatch(r'v$VERSION\.\d+', r['tag_name'])]
v.sort(key=lambda s: [int(x) for x in s.split('.')]); print(v[-1] if v else '')")"
    [ -n "$full" ] || fail "no containerd $VERSION release found"
    curl -fsSL -o "$OUT/containerd.tgz" "https://github.com/containerd/containerd/releases/download/v$full/containerd-$full-linux-amd64.tar.gz" || fail "downloading containerd $full"
    curl -fsSL "https://github.com/containerd/containerd/releases/download/v$full/containerd-$full-linux-amd64.tar.gz.sha256sum" |
        awk '{print $1}' > "$OUT/containerd.sha" || fail "containerd's checksum"
    [ "$(sha256sum "$OUT/containerd.tgz" | awk '{print $1}')" = "$(cat "$OUT/containerd.sha")" ] || fail "containerd's checksum does not match"
    run tar -C /usr/local -xzf "$OUT/containerd.tgz" || fail "unpacking containerd"
    command -v runc > /dev/null || run apt-get install -y runc
    curl -fsSL -o /etc/systemd/system/containerd.service "https://raw.githubusercontent.com/containerd/containerd/v$full/containerd.service" || fail "containerd's unit"
    install -d /etc/containerd
    /usr/local/bin/containerd config default > /etc/containerd/config.toml
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
    # If the default config leaves it out, it goes under runc's options
    # (containerd 2.x's table name; to be confirmed on the first run)
    grep -q 'SystemdCgroup = true' /etc/containerd/config.toml ||
        sed -i "/^ *\[plugins\.'io\.containerd\.cri\.v1\.runtime'\.containerd\.runtimes\.runc\.options\]/a\\            SystemdCgroup = true" /etc/containerd/config.toml
    grep -q 'SystemdCgroup = true' /etc/containerd/config.toml || fail "SystemdCgroup could not be set in containerd's config"
    run systemctl daemon-reload
    run systemctl enable --now containerd || fail "starting containerd"
    SOCK=unix:///run/containerd/containerd.sock
    measure "runtime" "containerd $full, $(runc --version | head -1)"
fi
# CNI plugins (bridge, portmap, loopback) for flannel, from the project's releases
cni="$(curl -fsSL https://api.github.com/repos/containernetworking/plugins/releases/latest | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"
install -d /opt/cni/bin
curl -fsSL "https://github.com/containernetworking/plugins/releases/download/$cni/cni-plugins-linux-amd64-$cni.tgz" | tar -C /opt/cni/bin -xz || fail "the CNI plugins"

# --- the cluster
cat > "$OUT/kubeadm.yaml" <<EOF
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
nodeRegistration:
  criSocket: $SOCK
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
networking:
  podSubnet: 10.244.0.0/16
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
EOF
run kubeadm init --config "$OUT/kubeadm.yaml" || fail "kubeadm init"
measure "kubeadm" "$(kubeadm version -o short)"
run "$KUBECTL" taint nodes --all node-role.kubernetes.io/control-plane- || true
run "$KUBECTL" apply -f "$FLANNEL" || fail "flannel"
if run "$KUBECTL" wait --for=condition=Ready node --all --timeout=300s; then
    measure "node_ready" "yes, $(( $(date +%s) - START )) s from the start"
else
    measure "node_ready" "no"; "$KUBECTL" describe node >> "$LOG" 2>&1; fail "the node not Ready"
fi
measure "node_runtime" "$("$KUBECTL" get node -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}')"

# --- a plain pod
t0=$(date +%s)
run "$KUBECTL" run m4-plain --image="$POD_IMAGE" --restart=Never -- sleep 3600
if run "$KUBECTL" wait --for=condition=Ready pod/m4-plain --timeout=300s; then
    measure "pod_running" "yes, $(( $(date +%s) - t0 )) s"
else
    measure "pod_running" "no"; "$KUBECTL" describe pod m4-plain >> "$LOG" 2>&1; fail "the plain pod"
fi
run "$KUBECTL" delete pod m4-plain --wait=false
measure "cluster" "up in $(( $(date +%s) - START )) s"
exit 0
