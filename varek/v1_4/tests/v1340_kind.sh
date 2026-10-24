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
#      does not load, and one with what the node agent does not carry
#      (credentials), refused at deploy with the Warden's reason; a policy
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
#      new pod is supervised.
#
#   varek/v1_4/tests/v1340_kind.sh --image IMAGE [--out DIR] [--keep]
#                                  [--node-image kindest/node:TAG]
#
# IMAGE is the node image (packaging/container/Containerfile --target node),
# built where this runs. Needs docker, kind, kubectl, helm, python3 and this
# checkout's tools/varek_keygen and tools/vdp_cert_check (make all). The
# summary is DIR/summary.txt (default /var/tmp/varek-kind); everything else
# is beside it. CI: .github/workflows/kubernetes.yml.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT=/var/tmp/varek-kind KEEP=0 IMAGE="" NODE_IMG=kindest/node:v1.37.0
while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --node-image) NODE_IMG="$2"; shift 2 ;;
        *) echo "v1340_kind.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ -n "$IMAGE" ] || { echo "usage: v1340_kind.sh --image IMAGE [--out DIR] [--keep] [--node-image IMG]" >&2; exit 2; }
for t in docker kind kubectl helm python3; do
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
on_node() { docker exec "$N" "$@"; }
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
    fi
    [ "$KEEP" = 1 ] || kind delete cluster --name "$CL" > /dev/null 2>&1
}
trap cleanup EXIT
say "v1340_kind.sh $(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z'); $(uname -sr); kind $(kind version | cut -d' ' -f2); $NODE_IMG; image $IMAGE; commit $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)"

echo "== 1. the cluster and the chart"
kind delete cluster --name "$CL" > /dev/null 2>&1
kind create cluster --name "$CL" --image "$NODE_IMG" --wait 300s > "$OUT/kind.log" 2>&1 ||
    { tail -20 "$OUT/kind.log"; echo "v1340_kind.sh: the cluster did not start" >&2; exit 1; }
say "  node: $(on_node sh -c 'containerd --version | cut -d" " -f3; runc --version | head -1' | tr '\n' ' ')$(on_node uname -r)"
kind load docker-image "$IMAGE" --name "$CL" > "$OUT/load.log" 2>&1 || { cat "$OUT/load.log"; exit 1; }
"$HERE/tools/varek_keygen" "$OUT/node.key" > /dev/null
kubectl create namespace "$NS" > /dev/null
kubectl label namespace "$NS" pod-security.kubernetes.io/enforce=privileged > /dev/null
kubectl -n "$NS" create secret generic varek-node-key --from-file=key="$OUT/node.key" \
    --from-file=key.pub="$OUT/node.key.pub" > /dev/null
REPO="${IMAGE%:*}" TAG="${IMAGE##*:}"
[ "$REPO" = "$IMAGE" ] && TAG=latest
check "the chart installs, its pods ready (the node agent, the plugin, the exporter, the webhook)" \
    helm install varek "$ROOT/packaging/helm/varek" -n "$NS" --wait --timeout 6m \
    --set image.repository="$REPO" --set image.tag="$TAG" --set image.pullPolicy=Never \
    --set signing.secretName=varek-node-key --set signing.checkpointEvery=8 --set anchor.enabled=true \
    --set admission.replicas=1
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
refused "a VarekPolicy with credentials (not carried by the node agent yet): refused at deploy" "$OUT/vp-creds.json" "does not carry credentials"
vp busybox "$POLICY" > "$OUT/vp-busybox.json"
check "a VarekPolicy the Warden loads: admitted" kubectl apply -f "$OUT/vp-busybox.json"
synced() { for _ in $(seq 30); do on_node cat /var/lib/varek/policies/team-a/busybox.policy 2> /dev/null | grep -qx "$1" && return 0; sleep 1; done; return 1; }
check "... written to the node by the plugin's -sync (POLICY_DIR/team-a/busybox.policy)" synced 'allow exec /bin/sleep'
check "... root's, 0644, in a directory others cannot write" sh -c \
    "[ \"\$(docker exec $N stat -c '%u %a' /var/lib/varek/policies/team-a/busybox.policy)\" = '0 644' ] && [ \"\$(docker exec $N stat -c '%u %a' /var/lib/varek/policies)\" = '0 755' ]"
pod p-nosuch team-a nosuch > "$OUT/p-nosuch.json"
refused "a pod naming a policy not in its namespace: refused" "$OUT/p-nosuch.json" "no VarekPolicy nosuch in namespace team-a"
pod p-relative team-a busybox relative > "$OUT/p-relative.json"
refused "a pod whose command is named by a relative path: refused" "$OUT/p-relative.json" "absolute path"
pod p-writable team-a busybox writable > "$OUT/p-writable.json"
refused "a writable root under a policy that decides launches (D4): refused" "$OUT/p-writable.json" "must be read-only"
pod p-default team-a busybox runtimedefault > "$OUT/p-default.json"
refused "a seccomp profile other than VAREK's unsupervised one: refused" "$OUT/p-default.json" "seccompProfile must be"
check "VAREK's unsupervised profile on the node (every call refused)" sh -c \
    "docker exec $N cat /var/lib/kubelet/seccomp/varek/unsupervised.json | grep -q '\"defaultAction\":\"SCMP_ACT_ERRNO\"'"
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
rm -rf "$OUT/streams"; docker cp "$N:/var/log/varek" "$OUT/streams" > /dev/null 2>&1
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
    "on() { docker exec $N stat -c '%u %a' \"/var/log/varek/\$(basename \"\$1\")\"; }; [ \"\$(on '$SA')\" = '0 600' ] && [ \"\$(on '${SA%.jsonl}.policy')\" = '0 400' ]"
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
    "kubectl apply -f '$OUT/vp-busybox2.json' && for i in \$(seq 30); do docker exec $N grep -qx 'allow path /etc/passwd readonly' /var/lib/varek/policies/team-a/busybox.policy && exit 0; sleep 1; done; exit 1"
pod pod-a2 team-a busybox > "$OUT/pod-a2.json"
kubectl apply -f "$OUT/pod-a2.json" > /dev/null 2>&1
ran pod-a2
check "a new pod runs under the new policy (the read it now allows)" grep -qx 'read_denied: 0' "$OUT/pod-a2.log"
kubectl -n team-a delete varekpolicy busybox > /dev/null 2>&1
check "the policy deleted: removed from the node" sh -c \
    "for i in \$(seq 30); do docker exec $N test -e /var/lib/varek/policies/team-a/busybox.policy || exit 0; sleep 1; done; exit 1"

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

echo
[ "$fail" = 0 ] && say "v1340_kind: PASS" || say "v1340_kind: FAIL"
[ "$fail" = 0 ]
