#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# v1340_kind.sh — v1.34 step 7 (docs/security/v1.34-kubernetes.md, section
# 4): VAREK's Helm chart (packaging/helm/varek) installed on a one-node kind
# cluster (containerd 2.2 or later, NRI on) with the node image, and checked
# as a cluster runs it:
#   1. the chart installs and its node agent, plugin, exporter and webhook
#      are ready; the node's signing key and anchor given;
#   2. the webhook (a real API server's calls): a VarekPolicy the Warden
#      does not load, and one naming a credential no VarekCredential gives,
#      refused at deploy with the Warden's reason; a policy
#      that loads accepted, and written to the node by the plugin's -sync;
#      pods refused for a policy not in their namespace, a command by a
#      relative path, a writable root under a policy that decides launches,
#      a seccomp profile other than VAREK's unsupervised one, and, in a
#      namespace that requires it, for naming no policy;
#   3. a pod naming the policy, in a namespace enforcing Pod Security's
#      "restricted" level (its seccomp profile VAREK's unsupervised one, a
#      Localhost profile, as the level allows): the plugin's filter in its
#      place, the launcher first; a read the
#      policy allows and one it does not, a program it allows to launch and
#      one it does not, a copy written to its volume (noexec) and launched;
#      a pod naming no policy left as it is;
#   4. the evidence: the pod's stream on the node, signed with the node's
#      key and anchored, verified by the audit; the exporter's OCSF events
#      in its log;
#   5. the policy changed: written to the node again, and a new pod run
#      under the new one; the policy deleted: removed from the node;
#   6. the node agent's pods taken off the node: a pod naming the policy
#      does not run (its unsupervised profile kept); they come back, and a
#      new pod is supervised;
#   7. credentials (v1.36 step 4, docs/security/v1.36-kubernetes-parity.md,
#      D1, D2): a VarekCredential whose file: source is not under the
#      chart's directory refused; one giving a Secret's key to team-a,
#      written to the node by the plugin's -sync; a policy naming it refused
#      in a namespace it is not given to; a pod naming it runs with the
#      plugin's placeholder, never the value, which warden-secrets fetched
#      on the node (run_start);
#   8. sub-agents and confined MCP servers (v1.36 step 5, D3, D4): a pod whose
#      policy names a sub-agent and a confined MCP server, each launched by
#      its shell: each in a group the node agent made below the container's
#      own (as each reads its /proc/self/cgroup), the server held to its own
#      rules, each launch settled, and the audit verifies the stream.
#
#   varek/v1_4/tests/v1340_kind.sh --image IMAGE [--out DIR] [--keep]
#                                  [--node-image kindest/node:TAG]
#   varek/v1_4/tests/v1340_kind.sh --host --image IMAGE --archive FILE [--out DIR]
#
# IMAGE is the node image (packaging/container/Containerfile --target node),
# built where this runs. Needs docker, kind, kubectl, helm, python3 and this
# checkout's tools/varek_keygen and tools/vdp_cert_check (make all). The
# summary is DIR/summary.txt (default /var/tmp/varek-kind); everything else
# is beside it. CI: .github/workflows/kubernetes.yml.
#
# --host (v1.36 step 2, the matrix): the same checks on a one-node cluster
# already running on this host (tests/node_cluster.sh, kubeadm under CRI-O
# or containerd), its kubeconfig in KUBECONFIG or ~/.kube/config. IMAGE is
# loaded into the node's runtime from FILE (`docker save IMAGE`, made before
# the cluster: node_cluster.sh stops the runner's Docker), fully named
# (docker.io/library/... when it has no registry), and the node's files are
# read with sudo. Needs no kind or docker; skopeo or podman for CRI-O, ctr
# for containerd. CI: .github/workflows/matrix.yml.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT=/var/tmp/varek-kind KEEP=0 IMAGE="" NODE_IMG=kindest/node:v1.37.0 HOST=0 ARCHIVE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --node-image) NODE_IMG="$2"; shift 2 ;;
        --host) HOST=1; shift ;;
        --archive) ARCHIVE="$2"; shift 2 ;;
        *) echo "v1340_kind.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ -n "$IMAGE" ] || { echo "usage: v1340_kind.sh [--host] --image IMAGE [--out DIR] [--keep] [--node-image IMG]" >&2; exit 2; }
TOOLS="docker kind kubectl helm python3"
[ "$HOST" = 1 ] && TOOLS="kubectl helm python3 sudo crictl"
[ "$HOST" = 0 ] || [ -s "$ARCHIVE" ] || { echo "v1340_kind.sh: --host needs --archive FILE (docker save IMAGE)" >&2; exit 2; }
for t in $TOOLS; do
    command -v "$t" > /dev/null || { echo "v1340_kind.sh: $t is needed" >&2; exit 2; }
done
[ -x "$HERE/tools/varek_keygen" ] && [ -x "$HERE/tools/vdp_cert_check" ] ||
    { echo "v1340_kind.sh: build the tools first (make -C varek/v1_4 all)" >&2; exit 2; }
POD_IMG=mirror.gcr.io/library/busybox:1.36
CL=varek-ci N=varek-ci-control-plane NS=varek-system
rm -rf "$OUT"; mkdir -p "$OUT"
SUM="$OUT/summary.txt" fail=0
say() { echo "$*" | tee -a "$SUM"; }
pass() { say "  PASS   $1"; }
flunk() { say "  FAIL   $1"; fail=1; }
check() { local d="$1"; shift; if "$@" > /dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
# A command on the node: in kind's node container, or on this host as root
if [ "$HOST" = 1 ]; then NODE_EXEC="sudo"; else NODE_EXEC="docker exec $N"; fi
on_node() { $NODE_EXEC "$@"; }
node_logs() {   # SUFFIX: the node agent's and the plugin's logs, as OUT/{node-agent,plugin}SUFFIX.log
    kubectl -n "$NS" logs ds/varek-node -c node-agent > "$OUT/node-agent$1.log" 2>&1
    kubectl -n "$NS" logs ds/varek-node -c plugin > "$OUT/plugin$1.log" 2>&1
}
cleanup() {
    node_logs ""
    kubectl -n "$NS" logs deploy/varek-admission > "$OUT/admission.log" 2>&1
    # a failure's logs in the job's log too (the artifact holds them whole)
    if [ "$fail" != 0 ]; then
        for l in "$OUT"/node-agent*.log "$OUT"/plugin*.log; do
            [ -s "$l" ] && { echo "== ${l##*/}, its end"; tail -40 "$l"; }
        done
        # the first supervised pod, its streams and what the node saw (the
        # matrix's first CRI-O cells: every supervised pod killed at its start)
        for l in "$OUT/pod-a.log" "$OUT/pod-a.describe"; do
            [ -s "$l" ] && { echo "== ${l##*/}, its end"; tail -30 "$l"; }
        done
        rm -rf "$OUT/streams-end"; mkdir -p "$OUT/streams-end"
        if [ "$HOST" = 1 ]; then
            sudo sh -c 'cp -a /var/log/varek/. "$1"/' sh "$OUT/streams-end" 2>/dev/null
            sudo chown -R "$(id -u):$(id -g)" "$OUT/streams-end" 2>/dev/null
        else
            docker cp "$N:/var/log/varek/." "$OUT/streams-end" > /dev/null 2>&1
        fi
        for l in "$OUT"/streams-end/*.jsonl; do
            [ -s "$l" ] && { echo "== stream ${l##*/}, its end"; tail -12 "$l" | cut -c1-400; }
        done
        # v1.36 step 4: what the runtime confines the node agent with (its
        # LSM label, its seccomp mode), as each runtime gives a privileged pod
        echo "== the node agent's confinement"
        kubectl -n "$NS" exec ds/varek-node -c node-agent -- sh -c \
            'echo "label: $(cat /proc/self/attr/current 2>&1)"; grep -E "^(Seccomp|NoNewPrivs|CapEff):" /proc/self/status' 2>&1 | head -6
        echo "== the node's kernel: seccomp, AppArmor and kills"
        on_node dmesg 2>/dev/null | grep -iE 'seccomp|type=1326|killed|segfault|apparmor=.DENIED' | tail -20
        if [ "$HOST" = 1 ]; then
            echo "== the runtime's journal: errors and warnings"
            sudo journalctl -u crio -u containerd --since "-15 min" --no-pager 2>/dev/null |
                grep -iE 'level=(error|warn)|seccomp|notif|nri' | tail -40 | cut -c1-400
        fi
    fi
    [ "$KEEP" = 1 ] || [ "$HOST" = 1 ] || kind delete cluster --name "$CL" > /dev/null 2>&1
}
trap cleanup EXIT
echo "== 1. the cluster and the chart"
if [ "$HOST" = 1 ]; then
    say "v1340_kind.sh --host $(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z'); $(uname -srm); image $IMAGE; commit $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)"
    # the API server can still be settling just after the cluster's own checks
    for _ in $(seq 15); do kubectl get node > "$OUT/kubectl.log" 2>&1 && break; sleep 2; done
    kubectl get node > "$OUT/kubectl.log" 2>&1 || { cat "$OUT/kubectl.log"; ls -l "${KUBECONFIG:-$HOME/.kube/config}";
        echo "v1340_kind.sh: no cluster here (KUBECONFIG=${KUBECONFIG:-unset})" >&2; exit 1; }
    RT="$(kubectl get node -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}')"
    say "  node: $RT, kubelet $(kubectl get node -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}'), $(uname -r)"
    # The image, fully named: CRI-O does not resolve a short name in its own
    # storage unless it is told a registry to search
    first="${IMAGE%%/*}"
    case "$IMAGE" in
        */*) case "$first" in *.*|*:*|localhost) QUAL="$IMAGE" ;; *) QUAL="docker.io/$IMAGE" ;; esac ;;
        *) QUAL="docker.io/library/$IMAGE" ;;
    esac
    # (the log is this user's file: only the command runs as root)
    # shellcheck disable=SC2024
    case "$RT" in
        cri-o://*)
            if command -v skopeo > /dev/null; then
                sudo skopeo copy "docker-archive:$ARCHIVE" "containers-storage:$QUAL" > "$OUT/load.log" 2>&1
            else
                sudo podman load -i "$ARCHIVE" > "$OUT/load.log" 2>&1 && sudo podman tag "$IMAGE" "$QUAL" >> "$OUT/load.log" 2>&1
            fi ;;
        containerd://*)
            sudo ctr -n k8s.io images import "$ARCHIVE" > "$OUT/load.log" 2>&1 ;;
        *) echo "v1340_kind.sh: the runtime $RT" >&2; exit 1 ;;
    esac || { cat "$OUT/load.log"; echo "v1340_kind.sh: the image did not load into $RT" >&2; exit 1; }
    sudo crictl inspecti "$QUAL" > /dev/null 2>&1 || { cat "$OUT/load.log"; echo "v1340_kind.sh: $QUAL is not in the node's runtime" >&2; exit 1; }
    IMAGE="$QUAL"
else
    say "v1340_kind.sh $(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z'); $(uname -sr); kind $(kind version | cut -d' ' -f2); $NODE_IMG; image $IMAGE; commit $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)"
    kind delete cluster --name "$CL" > /dev/null 2>&1
    kind create cluster --name "$CL" --image "$NODE_IMG" --wait 300s > "$OUT/kind.log" 2>&1 ||
        { tail -20 "$OUT/kind.log"; echo "v1340_kind.sh: the cluster did not start" >&2; exit 1; }
    say "  node: $(on_node sh -c 'containerd --version | cut -d" " -f3; runc --version | head -1' | tr '\n' ' ')$(on_node uname -r)"
    kind load docker-image "$IMAGE" --name "$CL" > "$OUT/load.log" 2>&1 || { cat "$OUT/load.log"; exit 1; }
fi
"$HERE/tools/varek_keygen" "$OUT/node.key" > /dev/null
kubectl create namespace "$NS" > /dev/null
kubectl label namespace "$NS" pod-security.kubernetes.io/enforce=privileged > /dev/null
kubectl -n "$NS" create secret generic varek-node-key --from-file=key="$OUT/node.key" \
    --from-file=key.pub="$OUT/node.key.pub" > /dev/null
# section 7's credential: a value made here, in a Secret the chart mounts in
# the node agent (credentials.secrets)
CRED_VAL="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
kubectl -n "$NS" create secret generic varek-test-cred --from-literal=token="$CRED_VAL" > /dev/null
# the chart's runtime (its default containerd): the node agent reads each
# container's bundle from the runtime's state, mounted from the node (the
# matrix's first CRI-O cells installed the default, mounted /run/containerd,
# and every supervised container was refused: no config.json in its bundle)
CHART_RT=containerd
[ "$HOST" = 1 ] && case "$RT" in cri-o://*) CHART_RT=cri-o ;; esac
REPO="${IMAGE%:*}" TAG="${IMAGE##*:}"
[ "$REPO" = "$IMAGE" ] && TAG=latest
check "the chart installs, its pods ready (the node agent, the plugin, the exporter, the webhook)" \
    helm install varek "$ROOT/packaging/helm/varek" -n "$NS" --wait --timeout 6m \
    --set image.repository="$REPO" --set image.tag="$TAG" --set image.pullPolicy=Never \
    --set signing.secretName=varek-node-key --set signing.checkpointEvery=8 --set anchor.enabled=true \
    --set admission.replicas=1 --set runtime="$CHART_RT" --set 'credentials.secrets={varek-test-cred}'
for _ in $(seq 60); do grep -q '^varek-nri: runtime' <(kubectl -n "$NS" logs ds/varek-node -c plugin 2>/dev/null) && break; sleep 2; done
say "  plugin: $(kubectl -n "$NS" logs ds/varek-node -c plugin 2>/dev/null | grep -m1 '^varek-nri: runtime' || echo 'NOT registered')"
check "the plugin registered with the node's runtime (NRI)" sh -c "kubectl -n '$NS' logs ds/varek-node -c plugin | grep -q '^varek-nri: runtime'"

# the policy: v1340_crio.sh's, for busybox (its commands hardlinks of one
# file, each named; each check launches its program)
POLICY='require warden 1.29
allow path /bin/ readonly
allow path /lib/ readonly
allow path /lib64/ readonly
allow path /etc/ld.so.cache readonly
allow path /etc/hostname readonly
allow path /proc/self/ readonly
allow path /dev/null
allow path /work/
allow exec /bin/sh
allow exec /bin/cat
allow exec /bin/cp
allow exec /bin/true
allow exec /bin/sleep'
vp() {   # NAME TEXT: a VarekPolicy in team-a
    python3 -c 'import json, sys; print(json.dumps({"apiVersion": "varek.dev/v1alpha1", "kind": "VarekPolicy",
        "metadata": {"name": sys.argv[1], "namespace": "team-a"}, "spec": {"policy": sys.argv[2] + "\n"}}))' "$1" "$2"
}
CHECK='while read -r k v; do case "$k" in Seccomp:|NoNewPrivs:) echo "$k $v" ;; esac; done < /proc/self/status
(exec /bin/cat /etc/hostname) > /dev/null 2>&1; echo "read_allowed: $?"
(exec /bin/cat /etc/passwd) > /dev/null 2>&1; echo "read_denied: $?"
(exec /bin/true); echo "launch_allowed: $?"
(exec /bin/ls /) > /dev/null 2>&1; echo "launch_denied: $?"
(exec /bin/cp /bin/true /work/copy) 2>/dev/null; echo "copy_written: $?"
(exec /work/copy) 2>/dev/null; echo "launch_written: $?"'
pod() {   # NAME NAMESPACE POLICY|- [EDIT]: a pod as "restricted" requires, running CHECK
    python3 - "$1" "$2" "$3" "${4:-}" "$POD_IMG" "$CHECK" <<'EOF'
import json, sys
name, ns, pol, edit, img, check = sys.argv[1:]
meta = {"name": name, "namespace": ns}
if pol != "-":
    meta["annotations"] = {"varek.dev/policy": pol}
c = {"name": "agent", "image": img, "command": ["/bin/sh", "-c", check],
     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                         "capabilities": {"drop": ["ALL"]}},
     "volumeMounts": [{"name": "work", "mountPath": "/work"}]}
if edit == "relative":
    c["command"] = ["sh", "-c", check]
if edit == "writable":
    c["securityContext"]["readOnlyRootFilesystem"] = False
# VAREK's unsupervised profile, which the plugin replaces (a pod naming no
# policy keeps the runtime's)
profile = {"type": "RuntimeDefault"}
if pol != "-" and edit != "runtimedefault":
    profile = {"type": "Localhost", "localhostProfile": "varek/unsupervised.json"}
print(json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": {
    "restartPolicy": "Never",
    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                        "seccompProfile": profile},
    "containers": [c], "volumes": [{"name": "work", "emptyDir": {}}]}}))
EOF
}
refused() {   # WHAT FILE PATTERN: kubectl apply fails, saying PATTERN
    if kubectl apply -f "$2" > "$2.out" 2>&1; then flunk "$1 (admitted)"
    elif grep -q "$3" "$2.out"; then pass "$1"
    else flunk "$1 ($(tail -1 "$2.out"))"; fi
}
ran() {   # POD [NAMESPACE]: wait for the pod to end; its log in OUT/POD.log
    local ph=""
    for _ in $(seq 120); do
        ph="$(kubectl -n "${2:-team-a}" get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null)"
        [ "$ph" = Succeeded ] || [ "$ph" = Failed ] && break
        sleep 1
    done
    kubectl -n "${2:-team-a}" logs "$1" > "$OUT/$1.log" 2>&1
    kubectl -n "${2:-team-a}" describe pod "$1" > "$OUT/$1.describe" 2>&1
    # in the job's log too: what a failed check saw
    sed "s/^/     $1: /" "$OUT/$1.log" | tee -a "$SUM"
    [ "$ph" = Succeeded ] || { echo "     $1: phase ${ph:-none}"; grep -E '^ *(Reason|Message|Exit Code):' "$OUT/$1.describe" | sed "s/^ */     $1: /"; }
    [ "$ph" = Succeeded ]
}
said() { grep -q "$2" "$OUT/$1.log"; }

echo "== 2. the webhook and the sync"
kubectl create namespace team-a > /dev/null
kubectl label namespace team-a pod-security.kubernetes.io/enforce=restricted > /dev/null
vp broken "allow pathh /tmp/" > "$OUT/vp-broken.json"
refused "a VarekPolicy the Warden does not load: refused at deploy, with its reason" "$OUT/vp-broken.json" "refuses this policy"
vp creds 'require warden 1.28
proxy on
credential k from file:/etc/varek/creds/k
allow host api.example.com:443' > "$OUT/vp-creds.json"
refused "a VarekPolicy naming a credential no VarekCredential gives (D2): refused at deploy" "$OUT/vp-creds.json" "is given by no VarekCredential"
vp busybox "$POLICY" > "$OUT/vp-busybox.json"
check "a VarekPolicy the Warden loads: admitted" kubectl apply -f "$OUT/vp-busybox.json"
synced() { for _ in $(seq 30); do on_node cat /var/lib/varek/policies/team-a/busybox.policy 2> /dev/null | grep -qx "$1" && return 0; sleep 1; done; return 1; }
check "... written to the node by the plugin's -sync (POLICY_DIR/team-a/busybox.policy)" synced 'allow exec /bin/sleep'
check "... root's, 0644, in a directory others cannot write" sh -c \
    "[ \"\$($NODE_EXEC stat -c '%u %a' /var/lib/varek/policies/team-a/busybox.policy)\" = '0 644' ] && [ \"\$($NODE_EXEC stat -c '%u %a' /var/lib/varek/policies)\" = '0 755' ]"
pod p-nosuch team-a nosuch > "$OUT/p-nosuch.json"
refused "a pod naming a policy not in its namespace: refused" "$OUT/p-nosuch.json" "no VarekPolicy nosuch in namespace team-a"
pod p-relative team-a busybox relative > "$OUT/p-relative.json"
refused "a pod whose command is named by a relative path: refused" "$OUT/p-relative.json" "absolute path"
pod p-writable team-a busybox writable > "$OUT/p-writable.json"
refused "a writable root under a policy that decides launches (D4): refused" "$OUT/p-writable.json" "must be read-only"
pod p-default team-a busybox runtimedefault > "$OUT/p-default.json"
refused "a seccomp profile other than VAREK's unsupervised one: refused" "$OUT/p-default.json" "seccompProfile must be"
check "VAREK's unsupervised profile on the node (every call refused)" sh -c \
    "$NODE_EXEC cat /var/lib/kubelet/seccomp/varek/unsupervised.json | grep -q '\"defaultAction\":\"SCMP_ACT_ERRNO\"'"
kubectl create namespace team-req > /dev/null
kubectl label namespace team-req varek.dev/policy-required=true pod-security.kubernetes.io/enforce=restricted > /dev/null
pod p-none team-req - > "$OUT/p-none.json"
refused "a namespace that requires a policy: a pod naming none refused" "$OUT/p-none.json" "requires every pod to name its policy"

echo "== 3. a supervised pod, and one left as it is"
pod pod-a team-a busybox > "$OUT/pod-a.json"
kubectl apply -f "$OUT/pod-a.json" > /dev/null 2>&1
check "the pod naming the policy ran to its end" ran pod-a
check "the plugin's filter in place of the unsupervised profile (Seccomp 2), no new privileges" sh -c \
    "grep -q '^Seccomp: 2' '$OUT/pod-a.log' && grep -q '^NoNewPrivs: 1' '$OUT/pod-a.log'"
check "the launcher first: the launch set applied, then the pod's command" \
    said pod-a '^varek-init: Landlock ABI [0-9]*, a launch set of [0-9]* file(s) applied; running /bin/sh'
check "a read the policy allows, and one it does not (refused)" sh -c \
    "grep -qx 'read_allowed: 0' '$OUT/pod-a.log' && grep -q '^read_denied: [1-9]' '$OUT/pod-a.log'"
check "a program the policy allows to launch ran; one it does not, refused" sh -c \
    "grep -qx 'launch_allowed: 0' '$OUT/pod-a.log' && grep -q '^launch_denied: [1-9]' '$OUT/pod-a.log'"
check "a copy written to its volume (noexec) and launched: refused" sh -c \
    "grep -qx 'copy_written: 0' '$OUT/pod-a.log' && grep -q '^launch_written: [1-9]' '$OUT/pod-a.log'"
pod pod-b team-a - > "$OUT/pod-b.json"
kubectl apply -f "$OUT/pod-b.json" > /dev/null 2>&1
ran pod-b
check "a pod naming no policy: left as it is, its command ran" sh -c \
    "grep -qx 'launch_denied: 0' '$OUT/pod-b.log' && ! grep -q varek-init '$OUT/pod-b.log'"

echo "== 4. the evidence"
sleep 3
rm -rf "$OUT/streams"
if [ "$HOST" = 1 ]; then
    sudo cp -a /var/log/varek "$OUT/streams" && sudo chown -R "$(id -u):$(id -g)" "$OUT/streams"
else
    docker cp "$N:/var/log/varek" "$OUT/streams" > /dev/null 2>&1
fi
SA="$(python3 - "$OUT/streams" <<'EOF'
import glob, json, sys
for p in sorted(glob.glob(sys.argv[1] + "/*.jsonl")):
    for l in open(p):
        if l.startswith("{"):
            r = json.loads(l)
            if r.get("event") == "run_start" and r.get("node", {}).get("pod", {}).get("name") == "pod-a":
                print(p)
            break
EOF
)"
check "the pod's stream on the node: run_start names the pod, its namespace and the policy" sh -c "[ -n '$SA' ] && [ -s '$SA' ]"
check "... the policy copied beside it (root's, 0400), the stream root's (0600)" sh -c \
    "on() { $NODE_EXEC stat -c '%u %a' \"/var/log/varek/\$(basename \"\$1\")\"; }; [ \"\$(on '$SA')\" = '0 600' ] && [ \"\$(on '${SA%.jsonl}.policy')\" = '0 400' ]"
check "the audit verifies it: signed with the node's key, anchored, each decision under its policy" \
    python3 "$HERE/tools/varek_audit.py" --policy "${SA%.jsonl}.policy" --checker "$HERE/tools/vdp_cert_check" \
    --pubkey "$OUT/node.key.pub" --anchor "$OUT/streams/anchor" "$SA"
RUN="$(python3 -c 'import json,sys; print([json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")][0]["run"])' "$SA" 2>/dev/null)"
check "the anchor holds the run's checkpoints" grep -q "$RUN" "$OUT/streams/anchor"
for _ in $(seq 30); do kubectl -n "$NS" logs ds/varek-node -c exporter 2>/dev/null | grep -q "$RUN" && break; sleep 2; done
kubectl -n "$NS" logs ds/varek-node -c exporter > "$OUT/exporter.log" 2>&1
check "the exporter's log: the run as OCSF events (each an object, with its class), its audit passed" python3 - "$OUT/exporter.log" "$RUN" <<'EOF'
import json, sys
ev = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
mine = [e for e in ev if sys.argv[2] in json.dumps(e)]
audit = [e["unmapped"]["varek"]["audit"] for e in mine
         if isinstance(e, dict) and e.get("unmapped", {}).get("varek", {}).get("event") == "audit"]
sys.exit(0 if mine and all(isinstance(e, dict) and "class_uid" in e for e in mine) and
         len(audit) == 1 and audit[0].get("passed") is True else 1)
EOF

echo "== 5. the policy changed, then deleted"
vp busybox "$POLICY
allow path /etc/passwd readonly" > "$OUT/vp-busybox2.json"
check "the changed policy admitted, and written to the node again" sh -c \
    "kubectl apply -f '$OUT/vp-busybox2.json' && for i in \$(seq 30); do $NODE_EXEC grep -qx 'allow path /etc/passwd readonly' /var/lib/varek/policies/team-a/busybox.policy && exit 0; sleep 1; done; exit 1"
pod pod-a2 team-a busybox > "$OUT/pod-a2.json"
kubectl apply -f "$OUT/pod-a2.json" > /dev/null 2>&1
ran pod-a2
check "a new pod runs under the new policy (the read it now allows)" grep -qx 'read_denied: 0' "$OUT/pod-a2.log"
kubectl -n team-a delete varekpolicy busybox > /dev/null 2>&1
check "the policy deleted: removed from the node" sh -c \
    "for i in \$(seq 30); do $NODE_EXEC test -e /var/lib/varek/policies/team-a/busybox.policy || exit 0; sleep 1; done; exit 1"

echo "== 6. the node agent's pods taken off the node, then back"
node_logs "-before-restart"   # the restart below ends these
kubectl apply -f "$OUT/vp-busybox.json" > /dev/null 2>&1
synced 'allow exec /bin/sleep' > /dev/null
# step 8 review (G-1): a pod the plugin does not adjust keeps its
# unsupervised profile, and does not run
kubectl -n "$NS" patch ds varek-node --type merge \
    -p '{"spec":{"template":{"spec":{"nodeSelector":{"varek.dev/no-node":"x"}}}}}' > /dev/null
for _ in $(seq 90); do [ -z "$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=node -o name 2>/dev/null)" ] && break; sleep 2; done
check "the node agent's pods off the node" sh -c "[ -z \"\$(kubectl -n '$NS' get pod -l app.kubernetes.io/component=node -o name)\" ]"
pod pod-u team-a busybox > "$OUT/pod-u.json"
kubectl apply -f "$OUT/pod-u.json" > /dev/null 2>&1
for _ in $(seq 60); do
    [ "$(kubectl -n team-a get pod pod-u -o jsonpath='{.status.containerStatuses[0].state.terminated.reason}{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null)" != "" ] &&
        [ "$(kubectl -n team-a get pod pod-u -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null)" != ContainerCreating ] && break
    sleep 2
done
kubectl -n team-a logs pod-u > "$OUT/pod-u.log" 2>&1
kubectl -n team-a describe pod pod-u > "$OUT/pod-u.describe" 2>&1
grep -E '^ *(State|Reason|Message|Exit Code):' "$OUT/pod-u.describe" | sed 's/^ */     pod-u: /' | tee -a "$SUM"
check "a pod naming the policy, with no plugin on its node: its command did not run" sh -c \
    "[ \"\$(kubectl -n team-a get pod pod-u -o jsonpath='{.status.phase}')\" != Succeeded ] && ! grep -q 'read_allowed' '$OUT/pod-u.log'"
kubectl -n team-a delete pod pod-u --wait=false > /dev/null 2>&1
kubectl -n "$NS" patch ds varek-node --type json \
    -p '[{"op":"remove","path":"/spec/template/spec/nodeSelector/varek.dev~1no-node"}]' > /dev/null
check "the DaemonSet's new pod ready" kubectl -n "$NS" rollout status ds/varek-node --timeout=180s
for _ in $(seq 60); do kubectl -n "$NS" logs ds/varek-node -c plugin 2>/dev/null | grep -q '^varek-nri: runtime' && break; sleep 2; done
pod pod-a3 team-a busybox > "$OUT/pod-a3.json"
kubectl apply -f "$OUT/pod-a3.json" > /dev/null 2>&1
ran pod-a3
check "a new pod supervised by it, as before" sh -c \
    "grep -q '^varek-init: Landlock' '$OUT/pod-a3.log' && grep -q '^launch_denied: [1-9]' '$OUT/pod-a3.log'"

echo "== 7. credentials (v1.36 step 4: D1, D2)"
vc() {   # NAME CREDENTIAL SOURCE NAMESPACE: a VarekCredential
    python3 -c 'import json, sys; print(json.dumps({"apiVersion": "varek.dev/v1alpha1", "kind": "VarekCredential",
        "metadata": {"name": sys.argv[1]}, "spec": {"credential": sys.argv[2], "source": sys.argv[3], "namespaces": [sys.argv[4]]}}))' "$@"
}
CSRC=file:/var/lib/varek/credentials/varek-test-cred/token
vc outside test_cred file:/etc/varek/creds/k team-a > "$OUT/vc-outside.json"
refused "a VarekCredential whose file: source is not under the chart's directory: refused" "$OUT/vc-outside.json" "the node agent's credentials directory"
vc varek-test-cred test_cred "$CSRC" team-a > "$OUT/vc.json"
check "a VarekCredential giving a Secret's key to team-a: admitted" kubectl apply -f "$OUT/vc.json"
check "... written to the node by the plugin's -sync (POLICY_DIR/.credentials)" sh -c \
    "for i in \$(seq 30); do $NODE_EXEC cat /var/lib/varek/policies/.credentials 2>/dev/null | grep -qx 'test_cred	team-a	$CSRC	varek-test-cred' && exit 0; sleep 1; done; exit 1"
CPOL="require warden 1.29
proxy inspect
credential test_cred from $CSRC
${POLICY#*
}
allow host kubernetes.default.svc.cluster.local:443
allow request GET https://kubernetes.default.svc.cluster.local/version credential=test_cred header=X-Varek-Test"
kubectl create namespace team-b > /dev/null
kubectl label namespace team-b pod-security.kubernetes.io/enforce=restricted > /dev/null
vp creds "$CPOL" | sed 's/"team-a"/"team-b"/' > "$OUT/vp-creds-b.json"
refused "a policy naming it in a namespace it is not given to (team-b): refused at deploy" "$OUT/vp-creds-b.json" "is not given to namespace team-b"
vp creds "$CPOL" > "$OUT/vp-creds-a.json"
check "a policy naming it in team-a: admitted, and written to the node" sh -c \
    "kubectl apply -f '$OUT/vp-creds-a.json' && for i in \$(seq 30); do $NODE_EXEC grep -q '^credential test_cred' /var/lib/varek/policies/team-a/creds.policy 2>/dev/null && exit 0; sleep 1; done; exit 1"
CHECK='echo "placeholder: ${VAREK_CRED_TEST_CRED:-none}"
(exec /bin/true); echo "launch_allowed: $?"' pod pod-c team-a creds > "$OUT/pod-c.json"
kubectl apply -f "$OUT/pod-c.json" > /dev/null 2>&1
check "the pod naming it ran to its end" ran pod-c
check "... supervised (the launcher first)" said pod-c '^varek-init: Landlock'
PH="$(sed -n 's/^placeholder: //p' "$OUT/pod-c.log")"
check "... its environment holds the plugin's placeholder (VAREK_CRED_TEST_CRED), not the value" sh -c \
    "printf %s '$PH' | grep -Eqx 'varek_ph_test_cred_[A-Za-z0-9_-]{43}' && ! grep -qF -- '$CRED_VAL' '$OUT/pod-c.log' && grep -qx 'launch_allowed: 0' '$OUT/pod-c.log'"
rm -rf "$OUT/streams7"
if [ "$HOST" = 1 ]; then
    sudo cp -a /var/log/varek "$OUT/streams7" && sudo chown -R "$(id -u):$(id -g)" "$OUT/streams7"
else
    docker cp "$N:/var/log/varek" "$OUT/streams7" > /dev/null 2>&1
fi
check "... run_start: fetched by warden-secrets on the node (its length), the placeholder's SHA-256 the pod's" \
    python3 - "$OUT/streams7" "${#CRED_VAL}" "$(printf %s "$PH" | sha256sum | cut -c1-64)" <<'EOF'
import glob, json, sys
for p in sorted(glob.glob(sys.argv[1] + "/*.jsonl")):
    for l in open(p):
        if l.startswith("{"):
            r = json.loads(l)
            if r.get("event") == "run_start" and r.get("node", {}).get("pod", {}).get("name") == "pod-c":
                c = r.get("credentials") or [{}]
                sys.exit(0 if len(c) == 1 and c[0].get("name") == "test_cred" and c[0].get("length") == int(sys.argv[2])
                         and c[0].get("placeholder_sha256") == sys.argv[3] else 1)
            break
sys.exit(1)
EOF
check "... the value in no stream on the node" sh -c "! grep -rqF -- '$CRED_VAL' '$OUT/streams7'"

echo "== 8. sub-agents and confined MCP servers (v1.36 step 5: D3, D4)"
# busybox's programs are one file: each launch is of the image its shell
# runs, settled by its memory layout (the pod's network has no process events)
SPOL="require warden 1.31
mcp server files exec /bin/head
$(printf '%s\n' "${POLICY#*
}" | sed 's|^allow exec /bin/cat$|allow exec /bin/cat subagent=reader|')
allow path /proc/self/ readonly for=files
allow path /etc/hostname readonly for=files
allow path /lib/ readonly for=files
allow path /lib64/ readonly for=files
allow path /etc/ld.so.cache readonly for=files"
vp subs "$SPOL" > "$OUT/vp-subs.json"
check "a policy naming a sub-agent and a confined MCP server: admitted (carried), and written to the node" sh -c \
    "kubectl apply -f '$OUT/vp-subs.json' && for i in \$(seq 30); do $NODE_EXEC grep -q '^mcp server files' /var/lib/varek/policies/team-a/subs.policy 2>/dev/null && exit 0; sleep 1; done; exit 1"
CHECK='echo "reader: $(exec /bin/cat /proc/self/cgroup)"
echo "files: $(exec /bin/head -n 1 /proc/self/cgroup)"
(exec /bin/head -n 1 /etc/hostname) > /dev/null 2>&1; echo "files_allowed: $?"
(exec /bin/head -n 1 /etc/passwd) > /dev/null 2>&1; echo "files_denied: $?"' pod pod-s team-a subs > "$OUT/pod-s.json"
kubectl apply -f "$OUT/pod-s.json" > /dev/null 2>&1
check "the pod ran to its end" ran pod-s
check "... supervised (the launcher first)" said pod-s '^varek-init: Landlock'
check "the sub-agent in a group below the container's own (its /proc/self/cgroup: .../reader-1)" said pod-s '^reader: 0::/\(.*/\)\{0,1\}reader-1$'
check "the confined server in its own (.../files-1)" said pod-s '^files: 0::/\(.*/\)\{0,1\}files-1$'
check "... held to its own rules: a file they allow read, one they do not refused" sh -c \
    "grep -qx 'files_allowed: 0' '$OUT/pod-s.log' && grep -q '^files_denied: [1-9]' '$OUT/pod-s.log'"
rm -rf "$OUT/streams8"
if [ "$HOST" = 1 ]; then
    sudo cp -a /var/log/varek "$OUT/streams8" && sudo chown -R "$(id -u):$(id -g)" "$OUT/streams8"
else
    docker cp "$N:/var/log/varek" "$OUT/streams8" > /dev/null 2>&1
fi
SS="$(python3 - "$OUT/streams8" <<'EOF'
import glob, json, sys
for p in sorted(glob.glob(sys.argv[1] + "/*.jsonl")):
    for l in open(p):
        if l.startswith("{"):
            r = json.loads(l)
            if r.get("event") == "run_start" and r.get("node", {}).get("pod", {}).get("name") == "pod-s":
                print(p)
            break
EOF
)"
check "... its stream: the run's group the container's, each sub-agent's below it, each launch settled" python3 - "$SS" <<'EOF'
import json, sys
R = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
cg = R[0]["on_behalf_of"]["agent"]["cgroup"]
subs = {r["subagent"]: r["cgroup"] for r in R if r.get("action") == "process.exec" and "subagent" in r}
settled = {r["subagent"] for r in R if r.get("event") == "subagent_settled" and r.get("result") == "launched"}
sys.exit(0 if subs.get("reader#1") == cg + "/reader-1" and subs.get("files#1") == cg + "/files-1" and
         {"reader#1", "files#1"} <= settled else 1)
EOF
check "... and the audit verifies it" python3 "$HERE/tools/varek_audit.py" --policy "${SS%.jsonl}.policy" \
    --checker "$HERE/tools/vdp_cert_check" --pubkey "$OUT/node.key.pub" "$SS"

echo
[ "$fail" = 0 ] && say "v1340_kind: PASS" || say "v1340_kind: FAIL"
[ "$fail" = 0 ]
