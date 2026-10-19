#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# v1340_nri.sh — v1.34 step 1 (docs/security/v1.34-kubernetes.md), the NRI
# half: on a fresh Ubuntu 24.04 host (cgroup v2), as root, from a checkout of
# this branch. A stand-in for VAREK's NRI plugin (tests/v1340_nri) gives each
# container of a pod annotated varek.dev/policy the Warden's filter with
# listenerPath (the pod's spec naming RuntimeDefault, as Pod Security's
# "restricted" requires), the launcher first in its command with the launch
# set (D3, tests/v1340_init.c), and its writable mounts noexec (D4); the
# stand-in node agent (tests/v1340_listener.c) receives the descriptor and
# logs the container's mounts as it arrives. Three pods, each running the
# same checks inside: A annotated, its root read-only; B not annotated; C
# annotated, its root writable. On:
#   1. a kind cluster (kind $KIND_V: containerd 2.3, runc 1.4);
#   2. CRI-O $CRIO_V on the host, through crictl, under crun (its default and
#      OpenShift's) and under runc.
# The summary is DIR/summary.txt (default /var/tmp/varek-nri); everything
# else is beside it.
#
#   varek/v1_4/tests/v1340_nri.sh [--out DIR] [--keep] [--only kind|crio]
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT=/var/tmp/varek-nri KEEP=0 ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --only) ONLY="$2"; shift 2 ;;
        *) echo "v1340_nri.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "v1340_nri.sh: run as root" >&2; exit 2; }
grep -q cgroup2 /proc/filesystems && [ -e /sys/fs/cgroup/cgroup.controllers ] ||
    { echo "v1340_nri.sh: this host has no cgroup v2 (the unified hierarchy)" >&2; exit 2; }
KIND_V=v0.33.0 KUBE_V=v1.37.0 NODE_IMG=kindest/node:v1.37.0
CRIO_V=v1.37.2 CRIO_SHA=b8824b49ac082fe0a445bab498e6b5c8daff90c680092c7f9f098c968c7f5370
POD_IMG=mirror.gcr.io/library/busybox:1.36
# the launch set: the image's /bin (busybox under each of its commands' names)
# and its loader. Not /bin/busybox alone: through overlayfs, as a container's
# root is, a Landlock rule on one name of a file does not cover its hardlinks
LAUNCH=/bin,/lib64/ld-linux-x86-64.so.2
S=/opt/varek-nri
mkdir -p "$OUT" "$S"
SUM="$OUT/summary.txt"
: > "$SUM"
say() { echo "$*" | tee -a "$SUM"; }
say "v1340_nri.sh $(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z'); $(uname -sr); commit $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null)"

echo "== installing Docker, gcc, libseccomp, Go, kind $KIND_V, kubectl $KUBE_V"
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update > "$OUT/apt.log" 2>&1 &&
    apt-get -qq install -y docker.io gcc libseccomp-dev python3 golang-go >> "$OUT/apt.log" 2>&1 ||
    { tail -5 "$OUT/apt.log"; echo "v1340_nri.sh: the packages did not install" >&2; exit 1; }
systemctl start docker
curl -fsSLo /usr/local/bin/kind "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_V/kind-linux-amd64" &&
curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/$KUBE_V/bin/linux/amd64/kubectl" &&
    chmod +x /usr/local/bin/kind /usr/local/bin/kubectl || { echo "v1340_nri.sh: kind or kubectl did not download" >&2; exit 1; }

echo "== building the filter's OCI form, the node agent, the launcher and the NRI plugin"
cd "$HERE" || exit 1
gcc -O2 -I. -o "$S/v1340_oci_filter" tests/v1340_oci_filter.c -lseccomp 2> "$OUT/build.log" &&
gcc -O2 -static -o "$S/v1340_listener" tests/v1340_listener.c 2>> "$OUT/build.log" &&
gcc -O2 -static -o "$S/v1340_init" tests/v1340_init.c 2>> "$OUT/build.log" &&
(cd tests/v1340_nri && GOTOOLCHAIN=go1.24.7 CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath -o "$S/v1340_nri" .) >> "$OUT/build.log" 2>&1 ||
    { tail -5 "$OUT/build.log"; echo "v1340_nri.sh: the build failed" >&2; exit 1; }
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
json.dump(p, open(sys.argv[2], "w"))
EOF
chmod -R a+rX "$S"

# The checks each pod runs, as its user (65534); /work is its writable volume
CHECK='echo "pid 1: $(tr "\0" "\n" < /proc/1/cmdline | head -2 | tr "\n" " ")"
grep -E "^(Seccomp|NoNewPrivs):" /proc/self/status | tr "\t" " "
awk "\$5 == \"/\" || \$5 == \"/work\" || \$5 == \"/dev/shm\" || \$5 == \"/varek/init\" { print \"mount \" \$5 \": \" \$6 }" /proc/self/mountinfo
if cp /bin/busybox /tmp/true 2> /dev/null; then /tmp/true 2> /dev/null; echo "write a copy to the root (/tmp): allowed; run it: exit $?"; else echo "write a copy to the root (/tmp): refused"; fi
cp /bin/busybox /work/true && /work/true 2> /dev/null; echo "run a copy written to /work: exit $?"
/bin/true; echo "run /bin/true (in the launch set): exit $?"
if [ -e /varek/init ]; then /varek/init /bin -- /bin/true 2> /dev/null; echo "run /varek/init (not in the launch set): exit $?"; fi
sleep 3'

# the summary lines for a run: the pod's own, then the plugin's and the node agent's
report() {   # report LABEL PODLOG
    sed "s/^/  $1: /" "$2" | tee -a "$SUM"
}
agent_lines() {   # agent_lines LOG FROM: the node agent's lines after line FROM
    tail -n +"$2" "$1" 2>/dev/null | grep -E 'descriptors received|mounts at receipt|"metadata"|notifications answered' |
        sed -E 's/state \([0-9]+ bytes\): .*"metadata":"([^"]*)".*/state received, metadata \1/; s/^/  node agent: /' | tee -a "$SUM"
}

if [ "$ONLY" != crio ]; then
say "== 1. kind ($NODE_IMG)"
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
    { tail -20 "$OUT/kind.log"; echo "v1340_nri.sh: the cluster did not start" >&2; exit 1; }
N=varek-control-plane
say "  node: $(docker exec $N sh -c 'containerd --version; runc --version | head -1' | tr '\n' ' ')"
docker exec $N sh -c "containerd config dump 2>/dev/null | sed -n '/io.containerd.nri.v1.nri/,/^ *\$/p'" > "$OUT/kind-nri-config.txt"
grep -E 'disable|validator|reject|enable' "$OUT/kind-nri-config.txt" | sed 's/^ */  nri config: /' | tee -a "$SUM"
: > "$S/listener-kind.log"; : > "$S/nri-kind.log"
docker exec -d $N "$S/v1340_listener" "$S/agent-kind.sock" "$S/listener-kind.log" 100000
docker exec -d $N "$S/v1340_nri" -filter "$S/varek.json" -listener "$S/agent-kind.sock" -launcher "$S/v1340_init" \
    -launch "$LAUNCH" -log "$S/nri-kind.log"
for _ in $(seq 50); do grep -q '^configure:' "$S/nri-kind.log" && break; sleep 0.2; done
say "  plugin: $(grep -m1 '^configure:' "$S/nri-kind.log" || echo 'NOT registered'; grep -m1 -v -E '^(configure|v1340_nri: starting)' "$S/nri-kind.log")"
kubectl create namespace varek > /dev/null
kubectl label namespace varek pod-security.kubernetes.io/enforce=restricted > /dev/null
for pod in a:test:true b::true c:test:false; do
    IFS=: read -r name pol ro <<< "$pod"
    python3 - "$name" "$pol" "$ro" "$POD_IMG" "$CHECK" > "$OUT/pod-$name.json" <<'EOF'
import json, sys
name, pol, ro, img, check = sys.argv[1:]
meta = {"name": "varek-" + name, "namespace": "varek"}
if pol:
    meta["annotations"] = {"varek.dev/policy": pol}
print(json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": {
    "restartPolicy": "Never",
    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                        "seccompProfile": {"type": "RuntimeDefault"}},
    "containers": [{"name": "agent", "image": img, "command": ["/bin/sh", "-c", check],
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": ro == "true",
                                        "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [{"name": "work", "mountPath": "/work"}]}],
    "volumes": [{"name": "work", "emptyDir": {}}]}}))
EOF
    say "  -- pod $name ($([ -n "$pol" ] && echo annotated || echo "not annotated"); root $([ "$ro" = true ] && echo read-only || echo writable))"
    la=$(($(wc -l < "$S/listener-kind.log") + 1)); lp=$(($(wc -l < "$S/nri-kind.log") + 1))
    kubectl apply -f "$OUT/pod-$name.json" > "$OUT/apply-$name.txt" 2>&1 || sed 's/^/  apply: /' "$OUT/apply-$name.txt" | tee -a "$SUM"
    ph=""
    for _ in $(seq 120); do
        ph="$(kubectl -n varek get pod "varek-$name" -o jsonpath='{.status.phase}' 2>/dev/null)"
        [ "$ph" = Succeeded ] || [ "$ph" = Failed ] && break
        sleep 1
    done
    say "  the pod: ${ph:-not started}"
    kubectl -n varek describe pod "varek-$name" > "$OUT/pod-$name.describe" 2>&1
    [ "$ph" = Succeeded ] || grep -E 'Warning|Error|Reason|Message' "$OUT/pod-$name.describe" | tail -6 | sed 's/^/  /' | tee -a "$SUM"
    kubectl -n varek logs "varek-$name" > "$OUT/pod-$name.log" 2>&1
    report pod "$OUT/pod-$name.log"
    tail -n +"$lp" "$S/nri-kind.log" | grep -E '^  ' | sed 's/^ */  plugin: /' | tee -a "$SUM"
    sleep 2; agent_lines "$S/listener-kind.log" "$la"
done
cp "$S/listener-kind.log" "$S/nri-kind.log" "$OUT/"
if [ "$KEEP" = 0 ]; then kind delete cluster --name varek > /dev/null 2>&1; say "  (the cluster deleted)"; fi
fi

if [ "$ONLY" != kind ]; then
say "== 2. CRI-O $CRIO_V on the host, through crictl"
if ! command -v crio > /dev/null; then
    curl -fsSLo "$OUT/cri-o.tgz" "https://storage.googleapis.com/cri-o/artifacts/cri-o.amd64.$CRIO_V.tar.gz" &&
    echo "$CRIO_SHA  $OUT/cri-o.tgz" | sha256sum -c --quiet &&
    tar -C "$OUT" -xzf "$OUT/cri-o.tgz" && (cd "$OUT/cri-o" && ./install) > "$OUT/crio-install.log" 2>&1 ||
        { tail -5 "$OUT/crio-install.log" 2>/dev/null; echo "v1340_nri.sh: CRI-O did not install" >&2; exit 1; }
fi
mkdir -p /etc/crio/crio.conf.d
printf '[crio.nri]\nenable_nri = true\n' > /etc/crio/crio.conf.d/90-varek-nri.conf
systemctl daemon-reload && systemctl restart crio
for _ in $(seq 100); do [ -S /var/run/crio/crio.sock ] && [ -S /var/run/nri/nri.sock ] && break; sleep 0.2; done
say "  $(crio --version 2>/dev/null | head -1); $(/usr/libexec/crio/crun --version | head -1); $(/usr/libexec/crio/runc --version | head -1)"
crio config 2> /dev/null | sed -n '/^\[crio.nri\]/,/^\[crio.stats\]/p' | grep -E '^[a-z_]+ =|default_validator' | sed 's/^/  nri config: /' | tee -a "$SUM"
crictl pull "$POD_IMG" > "$OUT/crictl-pull.log" 2>&1 || { cat "$OUT/crictl-pull.log"; echo "v1340_nri.sh: the image did not pull" >&2; exit 1; }
: > "$S/listener-crio.log"; : > "$S/nri-crio.log"
"$S/v1340_listener" "$S/agent-crio.sock" "$S/listener-crio.log" 100000 &
LPID=$!
"$S/v1340_nri" -filter "$S/varek.json" -listener "$S/agent-crio.sock" -launcher "$S/v1340_init" \
    -launch "$LAUNCH" -log "$S/nri-crio.log" &
PPID_NRI=$!
for _ in $(seq 50); do grep -q '^configure:' "$S/nri-crio.log" && break; sleep 0.2; done
say "  plugin: $(grep -m1 '^configure:' "$S/nri-crio.log" || echo 'NOT registered')"
mkdir -p "$OUT/crio-logs"
for rt in crun runc; do
    for pod in a:test:true b::true c:test:false; do
        IFS=: read -r name pol ro <<< "$pod"
        W="$OUT/work-$rt-$name"; mkdir -p "$W"; chmod 1777 "$W"
        python3 - "$rt" "$name" "$pol" "$ro" "$POD_IMG" "$CHECK" "$W" "$OUT/crio-logs" "$OUT" <<'EOF'
import json, sys, uuid
rt, name, pol, ro, img, check, work, logs, out = sys.argv[1:]
pod = {"metadata": {"name": f"varek-{name}-{rt}", "namespace": "varek", "uid": str(uuid.uuid4()), "attempt": 0},
       "log_directory": logs, "linux": {"security_context": {"namespace_options": {"network": 2, "pid": 1}}}}
if pol:
    pod["annotations"] = {"varek.dev/policy": pol}
ctr = {"metadata": {"name": "agent"}, "image": {"image": img}, "command": ["/bin/sh", "-c", check],
       "log_path": f"agent-{rt}-{name}.log", "mounts": [{"container_path": "/work", "host_path": work}],
       "linux": {"security_context": {"namespace_options": {"network": 2, "pid": 1},
                                      "run_as_user": {"value": 65534}, "readonly_rootfs": ro == "true",
                                      "no_new_privs": True, "capabilities": {"drop_capabilities": ["ALL"]},
                                      "seccomp": {"profile_type": 0}}}}
json.dump(pod, open(f"{out}/crio-pod-{rt}-{name}.json", "w"))
json.dump(ctr, open(f"{out}/crio-ctr-{rt}-{name}.json", "w"))
EOF
        say "  -- $rt, pod $name ($([ -n "$pol" ] && echo annotated || echo "not annotated"); root $([ "$ro" = true ] && echo read-only || echo writable))"
        la=$(($(wc -l < "$S/listener-crio.log") + 1)); lp=$(($(wc -l < "$S/nri-crio.log") + 1))
        P="$(crictl runp --runtime "$rt" "$OUT/crio-pod-$rt-$name.json" 2> "$OUT/crio-runp-$rt-$name.err")"
        if [ -z "$P" ]; then sed 's/^/  runp: /' "$OUT/crio-runp-$rt-$name.err" | tee -a "$SUM"; continue; fi
        C="$(crictl create "$P" "$OUT/crio-ctr-$rt-$name.json" "$OUT/crio-pod-$rt-$name.json" 2> "$OUT/crio-create-$rt-$name.err")"
        if [ -z "$C" ]; then sed 's/^/  create: /' "$OUT/crio-create-$rt-$name.err" | tee -a "$SUM"
        else
            crictl start "$C" > /dev/null 2> "$OUT/crio-start-$rt-$name.err" || sed 's/^/  start: /' "$OUT/crio-start-$rt-$name.err" | tee -a "$SUM"
            st=""
            for _ in $(seq 60); do st="$(crictl inspect -o go-template --template '{{.status.state}}' "$C" 2>/dev/null)"; [ "$st" = CONTAINER_EXITED ] && break; sleep 1; done
            say "  the container: ${st:-not found}, exit $(crictl inspect -o go-template --template '{{.status.exitCode}}' "$C" 2>/dev/null)"
            crictl logs "$C" > "$OUT/crio-$rt-$name.log" 2>&1
            report pod "$OUT/crio-$rt-$name.log"
        fi
        tail -n +"$lp" "$S/nri-crio.log" | grep -E '^  ' | sed 's/^ */  plugin: /' | tee -a "$SUM"
        sleep 2; agent_lines "$S/listener-crio.log" "$la"
        crictl stopp "$P" > /dev/null 2>&1; crictl rmp "$P" > /dev/null 2>&1
    done
done
kill "$PPID_NRI" "$LPID" 2> /dev/null
cp "$S/listener-crio.log" "$S/nri-crio.log" "$OUT/"
fi
say "v1340_nri.sh: done; $SUM"
