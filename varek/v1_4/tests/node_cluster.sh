#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# node_cluster.sh — a one-node kubeadm cluster on this host, the systemd
# cgroup driver, under CRI-O or containerd, NRI on, then a plain pod run on
# it. Made for v1.36 step 1 (tests/measure_v1360/README.md, M4a and M4b),
# and the matrix's cluster since step 2 (.github/workflows/matrix.yml, D11
# of docs/security/v1.36-kubernetes-parity.md). For GitHub's hosted runners
# (Ubuntu 24.04, systemd, cgroup v2, amd64 or arm64): it stops the runner's
# own Docker and containerd, turns swap off and installs packages, so it is
# not for a machine anyone uses. Since step 2's second part it also makes a
# CRI-O cell on a dnf host (Rocky Linux 9 in a VM on the runner,
# tests/vm_cell.sh): with SELinux enforcing, CRI-O labels each container,
# the control plane runs as spc_t (kubeadm's patches), and pods use a bridge
# on the node instead of flannel.
#
#   sudo -E varek/v1_4/tests/node_cluster.sh --runtime crio --version 1.35 --oci runc [--out DIR]
#   sudo -E varek/v1_4/tests/node_cluster.sh --runtime containerd --version 2.2 [--k8s 1.35] [--out DIR]
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
# the release downloads' architecture (amd64, arm64)
ARCH="$(dpkg --print-architecture 2>/dev/null || { case "$(uname -m)" in aarch64) echo arm64 ;; *) echo amd64 ;; esac; })"
# the host's packages: apt (Ubuntu, the runner) or dnf (RHEL 9 and its
# rebuilds), each project's repository in that format
if command -v apt-get > /dev/null; then PM=apt; elif command -v dnf > /dev/null; then PM=dnf; else
    echo "node_cluster.sh: no apt-get or dnf here" >&2; exit 2; fi
[ "$PM" = dnf ] && [ "$RUNTIME" != crio ] && { echo "node_cluster.sh: a dnf host's cell is CRI-O's only" >&2; exit 2; }
FMT=deb; [ "$PM" = dnf ] && FMT=rpm
CRIO_REPO="https://download.opensuse.org/repositories/isv:/cri-o:/stable:/v$VERSION/$FMT/"
K8S_REPO="https://pkgs.k8s.io/core:/stable:/v$K8S/$FMT/"
# SELinux as the host has it (none on the runner)
SELINUX="$(getenforce 2>/dev/null || echo none)"
# v1.36 step 11 (review): flannel's manifest, the CNI plugins and
# containerd's unit pinned, each checked by a SHA-256 kept here (each the
# download's own, 2026-10-28; the project's published sums agree)
FLANNEL_V=v0.28.10
FLANNEL="https://github.com/flannel-io/flannel/releases/download/$FLANNEL_V/kube-flannel.yml"
FLANNEL_SHA=393bdbce53eb50c8eb97dd513b218518b7d6e7985dc7b889be956e112a711084
CNI_V=v1.9.1
case "$ARCH" in
    amd64) CNI_SHA=b98f74a0f8522f0a83867178729c1aa70f2158f90c45a2ca8fa791db1c76b303 ;;
    arm64) CNI_SHA=56171987d3947707c3563db2f4001bccaf50fd63468611b9f3cbecb1375ee7ec ;;
    *) CNI_SHA="" ;;
esac
# containerd.service, the same file in 2.2.10 and 2.3.7
UNIT_V=v2.3.7
UNIT_SHA=1941362cbaa89dd591b99c32b050d82c583d3cd2e5fa63085d7017457ec5fca8
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
# The newest release tag of a GitHub project matching PATTERN (a sed
# regex: vX.Y.Z), without the leading v, read with git's own protocol: the
# matrix's first run asked GitHub's API, unauthenticated, from eight
# runners at once, and was answered 504. Tried three times.
latest() {   # OWNER/REPO PATTERN
    local t i
    for i in 1 2 3; do
        t="$(git ls-remote --tags --refs "https://github.com/$1" 2>> "$LOG" |
            sed -n "s|.*refs/tags/\($2\)$|\1|p" | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)"
        [ -n "$t" ] && { echo "$t"; return 0; }
        sleep $((i * 5))
    done
    return 1
}
get() { curl -fsSL --retry 3 --retry-delay 5 "$@"; }
sha_is() { [ "$(sha256sum "$1" | awk '{print $1}')" = "$2" ]; }   # FILE HEX
# On a failure, what the runtime and the kubelet said, and the containers
# the runtime made (the first run's crun cells failed with neither kept)
# The log's own tail is printed first: the fourth run's install failures
# were hidden under the journal, which fail() appended before printing.
fail() {
    measure "cluster.failed_at" "$1"
    echo "--- the log's last 40 lines"; tail -40 "$LOG"
    echo "--- the package manager's errors"; grep -E '^(E|W): |^Error|^Problem|^ - ' "$LOG" | tail -20
    { echo "--- crictl ps -a"; crictl ps -a 2>&1
      echo "--- journal"; journalctl -u crio -u containerd -u kubelet --no-pager 2>&1 | tail -200; } >> "$LOG"
    tail -60 "$LOG"; exit 1
}
# Kubernetes at the cell's minor, then crictl. The third run's CRI-O 1.35
# cell got kubeadm 1.37.1 unpinned; the fourth run's single install with
# cri-tools failed in every cell. crictl comes from apt if a repository has
# it, else from the cri-tools project's release for that minor (or its newest).
# The runner's image has a newer kubectl from apt, so pinning below it is a
# downgrade, which apt refuses under -y unless allowed (the fifth run).
# On a dnf host cri-tools comes with Kubernetes, from its repository, and
# the kubelet is enabled here (apt's package enables it itself).
k8s_install() {
    if [ "$PM" = dnf ]; then
        # --allowerasing: the cloud images' curl-minimal gives way if asked
        run dnf -y --allowerasing install "$@" "kubelet-$K8S.*" "kubeadm-$K8S.*" "kubectl-$K8S.*" cri-tools ||
            fail "installing ${*:+$* and }Kubernetes $K8S"
        run systemctl enable kubelet
    else
        run apt-cache policy kubeadm kubelet kubectl cri-tools "$@"
        run apt-get install -y --allow-downgrades "$@" "kubelet=$K8S.*" "kubeadm=$K8S.*" "kubectl=$K8S.*" ||
            fail "installing ${*:+$* and }Kubernetes $K8S"
    fi
    command -v crictl > /dev/null && return 0
    [ "$PM" = apt ] && run apt-get install -y cri-tools && command -v crictl > /dev/null && return 0
    measure "crictl.note" "no cri-tools package; the cri-tools release"
    local v
    v="$(latest kubernetes-sigs/cri-tools "v${K8S//./\\.}\\.[0-9]*" || latest kubernetes-sigs/cri-tools 'v1\.[0-9]*\.[0-9]*')"
    [ -n "$v" ] || fail "no cri-tools release found"
    get -o "$OUT/crictl.tgz" "https://github.com/kubernetes-sigs/cri-tools/releases/download/v$v/crictl-v$v-linux-$ARCH.tar.gz" || fail "downloading crictl $v"
    get "https://github.com/kubernetes-sigs/cri-tools/releases/download/v$v/crictl-v$v-linux-$ARCH.tar.gz.sha256" |
        awk '{print $1}' > "$OUT/crictl.sha" || fail "crictl's checksum"
    [ "$(sha256sum "$OUT/crictl.tgz" | awk '{print $1}')" = "$(cat "$OUT/crictl.sha")" ] || fail "crictl's checksum does not match"
    run tar -C /usr/local/bin -xzf "$OUT/crictl.tgz" crictl || fail "unpacking crictl"
}
START=$(date +%s)
CELL="$RUNTIME-$VERSION-$OCI"
measure "cell" "$CELL, Kubernetes $K8S, $(uname -sr), cgroup $(stat -fc %T /sys/fs/cgroup), $(. /etc/os-release && echo "$PRETTY_NAME"), SELinux $SELINUX"

# --- the host
run swapoff -a
run systemctl stop docker.socket docker containerd
run modprobe overlay
run modprobe br_netfilter
printf 'net.ipv4.ip_forward = 1\nnet.bridge.bridge-nf-call-iptables = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\n' > /etc/sysctl.d/90-measure.conf
run sysctl --system
# a dnf repository, its packages checked with the key it publishes
repo() {   # NAME URL
    printf '[%s]\nname=%s\nbaseurl=%s\nenabled=1\ngpgcheck=1\ngpgkey=%srepodata/repomd.xml.key\n' \
        "$1" "$1" "$2" "$2" > "/etc/yum.repos.d/$1.repo"
}
if [ "$PM" = apt ]; then
    install -d -m 0755 /etc/apt/keyrings
    key() { get "$1Release.key" | gpg --dearmor --yes -o "$2"; }
    key "$K8S_REPO" /etc/apt/keyrings/kubernetes.gpg || fail "the Kubernetes package key"
    echo "deb [signed-by=/etc/apt/keyrings/kubernetes.gpg] $K8S_REPO /" > /etc/apt/sources.list.d/kubernetes.list
else
    repo kubernetes "$K8S_REPO"
    # the API server's and the kubelet's ports, and the pods' traffic
    systemctl is-active -q firewalld && run systemctl disable --now firewalld
fi

# --- the runtime
if [ "$RUNTIME" = crio ] && [ "$PM" = dnf ]; then
    repo cri-o "$CRIO_REPO"
    # container-selinux: the types CRI-O labels containers with
    k8s_install cri-o container-selinux
elif [ "$RUNTIME" = crio ]; then
    key "$CRIO_REPO" /etc/apt/keyrings/cri-o.gpg || fail "the CRI-O package key ($CRIO_REPO)"
    echo "deb [signed-by=/etc/apt/keyrings/cri-o.gpg] $CRIO_REPO /" > /etc/apt/sources.list.d/cri-o.list
    run apt-get update || fail "apt-get update"
    # Kubernetes pinned to the cell's minor: the first fixed run's CRI-O 1.35
    # cell got kubeadm 1.37.1 from an unpinned install
    k8s_install cri-o
fi
if [ "$RUNTIME" = crio ]; then
    # CRI-O's own build of the runtime first: the runner's image has an older
    # crun (1.14.1, podman's) on the PATH, under which the first run's
    # control plane never started. The OS's only if CRI-O brings none.
    ociPath="$(ls "/usr/libexec/crio/$OCI" 2>/dev/null || true)"
    if [ -z "$ociPath" ]; then
        measure "runtime.note" "CRI-O's packages bring no $OCI; the OS's"
        ociPath="$(command -v "$OCI" || true)"
        if [ -z "$ociPath" ]; then
            if [ "$PM" = apt ]; then run apt-get install -y "$OCI"; else run dnf -y install "$OCI"; fi
            ociPath="$(command -v "$OCI" || true)"
        fi
    fi
    [ -n "$ociPath" ] || fail "no $OCI binary"
    install -d /etc/crio/crio.conf.d
    # SELinux enforcing: CRI-O labels each container (container_t, a
    # category pair of its own), as OpenShift's nodes do; its default is off
    SEL=false; [ "$SELINUX" = Enforcing ] && SEL=true
    # conmon, CRI-O's monitor of each container: the runtime's table above
    # replaces the package's, which named CRI-O's own; on the runner one is
    # on the PATH (podman's), on Rocky Linux 9 none is (the VM cell's first
    # run: "conmon: executable file not found in $PATH")
    MON=""
    command -v conmon > /dev/null || { [ -x /usr/libexec/crio/conmon ] && MON='monitor_path = "/usr/libexec/crio/conmon"'; }
    cat > /etc/crio/crio.conf.d/90-measure.conf <<EOF
[crio.runtime]
cgroup_manager = "systemd"
default_runtime = "$OCI"
selinux = $SEL

[crio.runtime.runtimes.$OCI]
runtime_path = "$ociPath"
$MON

# VAREK's plugin adjusts each container through NRI
[crio.nri]
enable_nri = true
EOF
    run systemctl enable --now crio || fail "starting crio"
    SOCK=unix:///var/run/crio/crio.sock
    measure "runtime" "CRI-O $(crio --version 2>/dev/null | grep -Eom1 '[0-9]+\.[0-9]+\.[0-9]+'), $OCI $("$ociPath" --version 2>/dev/null | head -1) ($ociPath), selinux = $SEL"
else
    run apt-get update || fail "apt-get update"
    k8s_install
    # The newest release of that minor, from the project's releases
    full="$(latest containerd/containerd "v${VERSION//./\\.}\\.[0-9]*")"
    [ -n "$full" ] || fail "no containerd $VERSION release found"
    get -o "$OUT/containerd.tgz" "https://github.com/containerd/containerd/releases/download/v$full/containerd-$full-linux-$ARCH.tar.gz" || fail "downloading containerd $full"
    get "https://github.com/containerd/containerd/releases/download/v$full/containerd-$full-linux-$ARCH.tar.gz.sha256sum" |
        awk '{print $1}' > "$OUT/containerd.sha" || fail "containerd's checksum"
    [ "$(sha256sum "$OUT/containerd.tgz" | awk '{print $1}')" = "$(cat "$OUT/containerd.sha")" ] || fail "containerd's checksum does not match"
    run tar -C /usr/local -xzf "$OUT/containerd.tgz" || fail "unpacking containerd"
    command -v runc > /dev/null || run apt-get install -y runc
    get -o "$OUT/containerd.service" "https://raw.githubusercontent.com/containerd/containerd/$UNIT_V/containerd.service" || fail "containerd's unit"
    sha_is "$OUT/containerd.service" "$UNIT_SHA" || fail "containerd's unit ($UNIT_V) does not match its SHA-256"
    install -m 0644 "$OUT/containerd.service" /etc/systemd/system/containerd.service
    install -d /etc/containerd
    /usr/local/bin/containerd config default > /etc/containerd/config.toml
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
    # If the default config leaves it out, it goes under runc's options
    # (containerd 2.x's table name; to be confirmed on the first run)
    grep -q 'SystemdCgroup = true' /etc/containerd/config.toml ||
        sed -i "/^ *\[plugins\.'io\.containerd\.cri\.v1\.runtime'\.containerd\.runtimes\.runc\.options\]/a\\            SystemdCgroup = true" /etc/containerd/config.toml
    grep -q 'SystemdCgroup = true' /etc/containerd/config.toml || fail "SystemdCgroup could not be set in containerd's config"
    # NRI, through which VAREK's plugin adjusts each container: on in 2.x's
    # default config, and kept on
    python3 - /etc/containerd/config.toml <<'PY' || fail "NRI could not be turned on in containerd's config"
import re, sys
p = sys.argv[1]; s = open(p).read()
m = re.search(r"^[ \t]*\[plugins\.'io\.containerd\.nri\.v1\.nri'\]\n((?:[ \t]*[^\s\[].*\n|[ \t]*\n)*)", s, re.M)
if not m:
    sys.exit(1)
body = re.sub(r"^([ \t]+)disable = true", r"\1disable = false", m.group(1), flags=re.M)
s = s[:m.start(1)] + body + s[m.end(1):]
open(p, "w").write(s)
PY
    run systemctl daemon-reload
    run systemctl enable --now containerd || fail "starting containerd"
    SOCK=unix:///run/containerd/containerd.sock
    measure "runtime" "containerd $full, $(runc --version | head -1)"
fi
# CNI plugins (bridge, portmap, loopback) for flannel, from the project's releases
# (kubelet's kubernetes-cni package brings them; the project's release if not)
if [ -x /opt/cni/bin/bridge ] && [ -x /opt/cni/bin/portmap ] && [ -x /opt/cni/bin/loopback ]; then
    measure "cni" "the kubernetes-cni package's plugins"
else
    [ -n "$CNI_SHA" ] || fail "no pinned CNI plugins for $ARCH"
    install -d /opt/cni/bin
    get -o "$OUT/cni.tgz" "https://github.com/containernetworking/plugins/releases/download/$CNI_V/cni-plugins-linux-$ARCH-$CNI_V.tgz" || fail "downloading the CNI plugins $CNI_V"
    sha_is "$OUT/cni.tgz" "$CNI_SHA" || fail "the CNI plugins ($CNI_V) do not match their SHA-256"
    run tar -C /opt/cni/bin -xzf "$OUT/cni.tgz" || fail "unpacking the CNI plugins"
    measure "cni" "the CNI plugins $CNI_V"
fi

# --- the cluster
# Under SELinux enforcing, kubeadm's static pods (etcd, the API server, the
# controller manager, the scheduler) read and write the node's own files
# (/var/lib/etcd, /etc/kubernetes/pki), which container_t may not: they run
# as spc_t, as OpenShift runs its control plane, through kubeadm's patches.
# VAREK's own pods keep the types the chart gives them.
PATCHES=""
if [ "$SELINUX" = Enforcing ]; then
    install -d "$OUT/patches"
    for c in etcd kube-apiserver kube-controller-manager kube-scheduler; do
        printf 'spec:\n  securityContext:\n    seLinuxOptions:\n      type: spc_t\n' > "$OUT/patches/$c+strategic.yaml"
    done
    PATCHES="patches:
  directory: $OUT/patches"
fi
cat > "$OUT/kubeadm.yaml" <<EOF
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
nodeRegistration:
  criSocket: $SOCK
$PATCHES
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
# apt's kubeadm by its path: the runner's image may have another on the PATH
KUBEADM=/usr/bin/kubeadm
run "$KUBEADM" init --config "$OUT/kubeadm.yaml" || fail "kubeadm init"
measure "kubeadm" "$("$KUBEADM" version -o short) (on the PATH: $(command -v kubeadm))"
run "$KUBECTL" taint nodes --all node-role.kubernetes.io/control-plane- || true
# The pods' network: flannel, or under SELinux enforcing a bridge on the
# node (one node needs no overlay; the CNI plugins run on the node, not in
# a container), in the pod subnet kubeadm was given
if [ "$SELINUX" = Enforcing ]; then
    install -d /etc/cni/net.d
    cat > /etc/cni/net.d/10-varek-bridge.conflist <<'EOF'
{"cniVersion": "1.0.0", "name": "varek-bridge", "plugins": [
  {"type": "bridge", "bridge": "cni0", "isGateway": true, "ipMasq": true, "hairpinMode": true,
   "ipam": {"type": "host-local", "ranges": [[{"subnet": "10.244.0.0/16"}]], "routes": [{"dst": "0.0.0.0/0"}]}},
  {"type": "portmap", "capabilities": {"portMappings": true}}]}
EOF
    measure "pod_network" "a bridge on the node (10-varek-bridge.conflist)"
else
    get -o "$OUT/kube-flannel.yml" "$FLANNEL" || fail "downloading flannel $FLANNEL_V"
    sha_is "$OUT/kube-flannel.yml" "$FLANNEL_SHA" || fail "flannel's manifest ($FLANNEL_V) does not match its SHA-256"
    run "$KUBECTL" apply -f "$OUT/kube-flannel.yml" || fail "flannel"
fi
if run "$KUBECTL" wait --for=condition=Ready node --all --timeout=300s; then
    measure "node_ready" "yes, $(( $(date +%s) - START )) s from the start"
else
    measure "node_ready" "no"; "$KUBECTL" describe node >> "$LOG" 2>&1; fail "the node not Ready"
fi
measure "node_runtime" "$("$KUBECTL" get node -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}')"

# --- a plain pod, once the namespace's default service account exists: the
# controller manager makes it after the node is Ready (the first run started
# the pod before it, and was refused)
for _ in $(seq 60); do "$KUBECTL" get serviceaccount default > /dev/null 2>&1 && break; sleep 2; done
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
