#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# v1340_apiserver.sh — v1.34 step 7 (docs/security/v1.34-kubernetes.md):
# the chart's resource and webhook, and the plugin's sync, against a real
# API server where kind cannot run (no cgroup v2, no Docker): kube-apiserver
# and etcd from envtest (sigs.k8s.io/controller-runtime/tools/setup-envtest),
# the plugin kept up by CRI-O's NRI socket. As the chart renders them:
#   1. the CRD installs; its name rule (CEL) refuses a name the node agent
#      does not take;
#   2. the webhook (varek-admission, the chart's hooks pointed at it):
#      a policy the Warden does not load and one naming a credential no
#      VarekCredential gives refused with the Warden's reason; one that loads admitted; pods refused for a
#      policy not in their namespace, root, a relative command, a writable
#      root under a policy that decides launches, a capability added, a
#      seccomp profile other than VAREK's unsupervised one, a PID namespace
#      shared, DNS servers of its own; a pod naming no policy, in a
#      namespace that requires one, refused; a pod's policy annotation
#      changed after it is created, refused; the chart's own namespace not
#      checked;
#   3. the sync (varek-nri -sync) through the API server: each policy
#      written to POLICY_DIR/<namespace>/<name>.policy, changed, and removed.
# v1.35 step 4c (D11): the VarekPlan CRD and its name rule; a plan the Warden
# reads admitted, one with an mcp_call step refused; a policy saying
# `require plan` admitted, its pod refused naming no plan or one not in its
# namespace, admitted naming its plan, the plan annotation fixed after; each
# plan written to POLICY_DIR/<namespace>/<name>.plan, and removed.
# v1.36 step 4 (D1, D2): the VarekCredential CRD; one whose file: source is
# not under the chart's directory refused, one given to team-a admitted; a
# policy naming it refused in team-b, admitted in team-a, and its pod; the
# cluster's list written to POLICY_DIR/.credentials, and changed.
#
#   sudo varek/v1_4/tests/v1340_apiserver.sh ASSETS [--out DIR]
#
# ASSETS holds kube-apiserver, etcd and kubectl (setup-envtest use -p path).
# Needs root, crio, openssl, go, helm and python3; builds the Warden, the
# plugin and the webhook.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
A="${1:?usage: v1340_apiserver.sh ASSETS [--out DIR]}"; shift
OUT=/var/tmp/varek-apiserver
[ "${1:-}" = --out ] && OUT="$2"
[ "$(id -u)" = 0 ] || { echo "v1340_apiserver.sh: run as root" >&2; exit 2; }
for t in crio openssl go helm python3; do command -v "$t" > /dev/null || { echo "v1340_apiserver.sh: $t is needed" >&2; exit 2; }; done
rm -rf "$OUT"; mkdir -p "$OUT/etcd" "$OUT/pki" "$OUT/pol"; chmod 755 "$OUT/pol"
fail=0 PIDS=""
pass() { echo "  PASS   $1"; }
flunk() { echo "  FAIL   $1"; fail=1; }
check() { local d="$1"; shift; if "$@" > /dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
K() { "$A/kubectl" --server https://127.0.0.1:6443 --token admin-token --certificate-authority "$OUT/pki/apiserver.crt" "$@"; }

echo "== building"
make -s -C "$HERE" warden > "$OUT/build.log" 2>&1 &&
    (cd "$HERE/k8s" && go build -o "$OUT/varek-nri" ./cmd/varek-nri && go build -o "$OUT/varek-admission" ./cmd/varek-admission) >> "$OUT/build.log" 2>&1 ||
    { tail "$OUT/build.log"; exit 1; }

echo "== the API server"
P="$OUT/pki"
openssl genrsa -out "$P/sa.key" 2048 2>/dev/null; openssl rsa -in "$P/sa.key" -pubout -out "$P/sa.pub" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=apiserver -addext subjectAltName=IP:127.0.0.1 \
    -keyout "$P/apiserver.key" -out "$P/apiserver.crt" 2>/dev/null
# the webhook's CA and certificate (for 127.0.0.1: the hooks point at a URL here)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=varek-ca -keyout "$P/ca.key" -out "$P/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj /CN=varek-admission -addext subjectAltName=IP:127.0.0.1 \
    -keyout "$P/wh.key" -out "$P/wh.csr" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1\n' > "$P/ext"
openssl x509 -req -in "$P/wh.csr" -CA "$P/ca.crt" -CAkey "$P/ca.key" -CAcreateserial -days 1 -extfile "$P/ext" -out "$P/wh.crt" 2>/dev/null
echo 'admin-token,admin,1,system:masters' > "$P/tokens.csv"
"$A/etcd" --data-dir "$OUT/etcd" --listen-client-urls http://127.0.0.1:12379 --advertise-client-urls http://127.0.0.1:12379 \
    --listen-peer-urls http://127.0.0.1:12380 > "$OUT/etcd.log" 2>&1 &
PIDS="$PIDS $!"
"$A/kube-apiserver" --etcd-servers http://127.0.0.1:12379 --bind-address 127.0.0.1 --secure-port 6443 \
    --tls-cert-file "$P/apiserver.crt" --tls-private-key-file "$P/apiserver.key" --token-auth-file "$P/tokens.csv" \
    --service-account-issuer https://kubernetes.default.svc --service-account-key-file "$P/sa.pub" \
    --service-account-signing-key-file "$P/sa.key" --service-cluster-ip-range 10.0.0.0/24 \
    --authorization-mode RBAC --allow-privileged \
    --disable-admission-plugins ServiceAccount > "$OUT/apiserver.log" 2>&1 &   # no controller makes service accounts
PIDS="$PIDS $!"
for _ in $(seq 120); do K get --raw /readyz > /dev/null 2>&1 && break; sleep 0.5; done
check "the API server is ready ($("$A/kube-apiserver" --version))" K get --raw /readyz

echo "== 1. the resource"
helm template t "$ROOT/packaging/helm/varek" -n varek-system --kube-version 1.31.0 --include-crds > "$OUT/chart.yaml"
python3 - "$OUT/chart.yaml" "$OUT" "$(base64 -w0 < "$P/ca.crt")" <<'EOF'
import json, sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
crds = {d["metadata"]["name"]: d for d in docs if d["kind"] == "CustomResourceDefinition"}
json.dump(crds["varekpolicies.varek.dev"], open(sys.argv[2] + "/crd.json", "w"))
json.dump(crds["varekplans.varek.dev"], open(sys.argv[2] + "/crd-plan.json", "w"))       # v1.35 step 4c
json.dump(crds["varekcredentials.varek.dev"], open(sys.argv[2] + "/crd-cred.json", "w"))  # v1.36 step 4
vwc = [d for d in docs if d["kind"] == "ValidatingWebhookConfiguration"][0]
for h in vwc["webhooks"]:
    path = h["clientConfig"]["service"]["path"]
    h["clientConfig"] = {"url": "https://127.0.0.1:18443" + path, "caBundle": sys.argv[3]}
json.dump(vwc, open(sys.argv[2] + "/vwc.json", "w"))
EOF
crd() { K apply -f "$OUT/crd.json" -f "$OUT/crd-plan.json" -f "$OUT/crd-cred.json" &&
        K wait --for condition=established crd/varekpolicies.varek.dev crd/varekplans.varek.dev \
            crd/varekcredentials.varek.dev --timeout=30s; }
check "the chart's CRDs (VarekPolicy, VarekPlan from v1.35, VarekCredential from v1.36) install and are established" crd
vp() { python3 -c 'import json, sys; print(json.dumps({"apiVersion": "varek.dev/v1alpha1", "kind": "VarekPolicy",
    "metadata": {"name": sys.argv[1], "namespace": sys.argv[2]}, "spec": {"policy": sys.argv[3] + "\n"}}))' "$@"; }
K create namespace team-a > /dev/null; K create namespace varek-system > /dev/null; K create namespace team-b > /dev/null
K create namespace team-req > /dev/null; K label namespace team-req varek.dev/policy-required=true > /dev/null
refused() {   # WHAT FILE PATTERN
    if K apply -f "$2" > "$2.out" 2>&1; then flunk "$1 (admitted)"
    elif grep -q "$3" "$2.out"; then pass "$1"
    else flunk "$1 ($(tail -1 "$2.out"))"; fi
}
vp Bad_Name team-a "allow path /tmp/" > "$OUT/vp-badname.json"
refused "a name the node agent does not take: refused by the CRD's rule" "$OUT/vp-badname.json" "is 1 to 63 of a-z, 0-9 and -"
vpl() { python3 -c 'import json, sys; print(json.dumps({"apiVersion": "varek.dev/v1alpha1", "kind": "VarekPlan",
    "metadata": {"name": sys.argv[1], "namespace": sys.argv[2]}, "spec": {"plan": sys.argv[3] + "\n"}}))' "$@"; }
vpl Bad_Plan team-a "plan 1.35" > "$OUT/vpl-badname.json"
refused "a VarekPlan's name the node agent does not take: refused by its CRD's rule" "$OUT/vpl-badname.json" "VarekPlan's name is 1 to 63"

echo "== 2. the webhook"
echo admin-token > "$P/token"
"$OUT/varek-admission" -warden "$HERE/warden" -tls-cert "$P/wh.crt" -tls-key "$P/wh.key" -listen 127.0.0.1:18443 \
    -api https://127.0.0.1:6443 -api-token "$P/token" -api-ca "$P/apiserver.crt" \
    -credentials-dir /var/lib/varek/credentials > "$OUT/admission.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 50); do curl -sk https://127.0.0.1:18443/healthz | grep -q ok && break; sleep 0.2; done
check "the chart's five hooks registered, pointed at the webhook" K apply -f "$OUT/vwc.json"
sleep 2
vp broken team-a "allow pathh /tmp/" > "$OUT/vp-broken.json"
refused "a policy the Warden does not load: refused, with its reason" "$OUT/vp-broken.json" "refuses this policy"
vp creds team-a 'require warden 1.28
proxy on
credential k from file:/etc/varek/creds/k
allow host api.example.com:443' > "$OUT/vp-creds.json"
refused "a policy naming a credential no VarekCredential gives (D2): refused" "$OUT/vp-creds.json" "is given by no VarekCredential"
# v1.36 step 4 (D1, D2): credentials given to namespaces
vc() { python3 -c 'import json, sys; print(json.dumps({"apiVersion": "varek.dev/v1alpha1", "kind": "VarekCredential",
    "metadata": {"name": sys.argv[1]}, "spec": {"credential": sys.argv[2], "source": sys.argv[3], "namespaces": sys.argv[4].split(",")}}))' "$@"; }
CSRC=file:/var/lib/varek/credentials/gh/token
vc outside gh file:/etc/varek/creds/k team-a > "$OUT/vc-outside.json"
refused "a VarekCredential whose file: source is not under the chart's directory: refused" "$OUT/vc-outside.json" "the node agent's credentials directory"
vc Bad_Name gh "$CSRC" team-a > "$OUT/vc-badname.json"
refused "... a credential name the policies do not take: refused" "$OUT/vc-badname.json" "VarekCredential"
vc gh gh "$CSRC" team-a > "$OUT/vc.json"
check "a VarekCredential giving gh to team-a: admitted" K apply -f "$OUT/vc.json"
CPOL="require warden 1.29
proxy inspect
credential gh from $CSRC
allow path /work/
allow exec /usr/bin/agent
allow host api.example.com:443
allow request GET https://api.example.com/x credential=gh header=X-K"
vp cagent team-b "$CPOL" > "$OUT/vp-cagent-b.json"
refused "a policy naming it in team-b, which it is not given to: refused" "$OUT/vp-cagent-b.json" "is not given to namespace team-b"
vp cagent team-a "${CPOL/$CSRC/file:/var/lib/varek/credentials/other/token}" > "$OUT/vp-cagent-src.json"
refused "a policy naming it from another source: refused" "$OUT/vp-cagent-src.json" "names another source than the policy"
vp cagent team-a "$CPOL" > "$OUT/vp-cagent.json"
check "a policy naming it in team-a: admitted" K apply -f "$OUT/vp-cagent.json"
vp agent team-a 'require warden 1.29
allow path /work/
allow exec /usr/bin/agent' > "$OUT/vp-agent.json"
check "a policy the Warden loads: admitted" K apply -f "$OUT/vp-agent.json"
# v1.35 step 4c (D11): plans
vpl p1 team-a 'plan 1.35
action a file_open /work/x' > "$OUT/vpl-p1.json"
check "a VarekPlan the Warden reads: admitted" K apply -f "$OUT/vpl-p1.json"
vpl pmcp team-a 'plan 1.35
action m mcp_call http://10.0.0.1:8080/mcp' > "$OUT/vpl-mcp.json"
refused "a VarekPlan with an mcp_call step: refused (not carried by the node agent yet)" "$OUT/vpl-mcp.json" "does not carry mcp_call steps yet"
vp needs team-a 'require warden 1.35
require plan
allow path /work/
allow exec /usr/bin/agent' > "$OUT/vp-needs.json"
check "a policy that says require plan: admitted" K apply -f "$OUT/vp-needs.json"
pod() {   # NAME NAMESPACE POLICY|- EDIT [PLAN]
    python3 - "$@" <<'EOF'
import json, sys
name, ns, pol, edit = sys.argv[1:5]
meta = {"name": name, "namespace": ns}
if pol != "-":
    meta["annotations"] = {"varek.dev/policy": pol}
if len(sys.argv) > 5:
    meta.setdefault("annotations", {})["varek.dev/plan"] = sys.argv[5]
sc = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "runAsNonRoot": True, "runAsUser": 1000,
      "capabilities": {"drop": ["ALL"]}}
c = {"name": "agent", "image": "example/agent:1", "command": ["/usr/bin/agent"], "securityContext": sc}
if edit == "root":
    sc.pop("runAsNonRoot"); sc["runAsUser"] = 0
if edit == "relative":
    c["command"] = ["agent"]
if edit == "writable":
    sc["readOnlyRootFilesystem"] = False
if edit == "caps":
    sc["capabilities"]["add"] = ["NET_RAW"]
spec = {"containers": [c], "securityContext": {"seccompProfile": {"type": "Localhost", "localhostProfile": "varek/unsupervised.json"}}}
if edit == "runtimedefault":
    spec["securityContext"]["seccompProfile"] = {"type": "RuntimeDefault"}
if edit == "sharepid":
    spec["shareProcessNamespace"] = True
if edit == "dns":
    spec["dnsPolicy"] = "None"
    spec["dnsConfig"] = {"nameservers": ["203.0.113.5"]}
print(json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec}))
EOF
}
pod p1 team-a nosuch - > "$OUT/p1.json"; refused "a pod naming a policy not in its namespace: refused" "$OUT/p1.json" "no VarekPolicy nosuch in namespace team-a"
pod p2 team-a agent root > "$OUT/p2.json"; refused "a pod running as root: refused" "$OUT/p2.json" "runs as root"
pod p3 team-a agent relative > "$OUT/p3.json"; refused "a command by a relative path: refused" "$OUT/p3.json" "absolute path"
pod p4 team-a agent writable > "$OUT/p4.json"; refused "a writable root under a policy that decides launches: refused" "$OUT/p4.json" "must be read-only"
pod p8 team-a agent caps > "$OUT/p8.json"; refused "a capability added back: refused" "$OUT/p8.json" "adds capabilities"
pod p9 team-a agent runtimedefault > "$OUT/p9.json"; refused "a seccomp profile other than VAREK's unsupervised one: refused" "$OUT/p9.json" "seccompProfile must be"
pod p10 team-a agent sharepid > "$OUT/p10.json"; refused "a PID namespace shared between its containers: refused" "$OUT/p10.json" "shareProcessNamespace"
pod p11 team-a agent dns > "$OUT/p11.json"; refused "DNS servers of its own: refused" "$OUT/p11.json" "names DNS servers of its own"
pod p5 team-a agent - > "$OUT/p5.json"; check "a pod as the node agent requires: admitted" K apply -f "$OUT/p5.json"
if K -n team-a annotate pod p5 --overwrite varek.dev/policy=other > "$OUT/p5-annotate.out" 2>&1; then
    flunk "... its policy annotation changed after: refused (changed)"
elif grep -q "not added, changed or removed" "$OUT/p5-annotate.out"; then pass "... its policy annotation changed after: refused"
else flunk "... its policy annotation changed after: refused ($(tail -1 "$OUT/p5-annotate.out"))"; fi
check "... a label added: admitted" K -n team-a label pod p5 x=y
pod p6 team-req - - > "$OUT/p6.json"; refused "a pod naming no policy where one is required: refused" "$OUT/p6.json" "requires every pod to name its policy"
pod p12 team-a needs - > "$OUT/p12.json"; refused "require plan, a pod naming no plan: refused" "$OUT/p12.json" "names its plan (varek.dev/plan)"
pod p13 team-a needs - nosuch > "$OUT/p13.json"; refused "a pod naming a plan not in its namespace: refused" "$OUT/p13.json" "no VarekPlan nosuch in namespace team-a"
pod p14 team-a needs - p1 > "$OUT/p14.json"; check "require plan, a pod naming its plan: admitted" K apply -f "$OUT/p14.json"
if K -n team-a annotate pod p14 --overwrite varek.dev/plan=other > "$OUT/p14-annotate.out" 2>&1; then
    flunk "... its plan annotation changed after: refused (changed)"
elif grep -q "varek.dev/plan annotation is set when the pod is created" "$OUT/p14-annotate.out"; then pass "... its plan annotation changed after: refused"
else flunk "... its plan annotation changed after: refused ($(tail -1 "$OUT/p14-annotate.out"))"; fi
pod p15 team-a cagent - > "$OUT/p15.json"; check "a pod naming the policy with the credential: admitted (v1.36)" K apply -f "$OUT/p15.json"
pod p7 varek-system nosuch root > "$OUT/p7.json"; check "the chart's own namespace not checked" K apply -f "$OUT/p7.json"

echo "== 3. the sync"
nri_up() { python3 -c 'import socket; s = socket.socket(socket.AF_UNIX); s.connect("/var/run/nri/nri.sock")' 2>/dev/null; }
if ! nri_up; then
    crio > "$OUT/crio.log" 2>&1 &
    PIDS="$PIDS $!"
    for _ in $(seq 150); do nri_up && break; sleep 0.2; done
fi
"$OUT/varek-nri" -warden "$HERE/warden" -policies "$OUT/pol" -listener /run/varek-x.sock -launcher /opt/varek/bin/varek-init \
    -sync -api https://127.0.0.1:6443 -api-token "$P/token" -api-ca "$P/apiserver.crt" > "$OUT/nri.log" 2>&1 &
PIDS="$PIDS $!"
waitfor() { for _ in $(seq 40); do eval "$1" && return 0; sleep 0.25; done; return 1; }
check "each policy written to POLICY_DIR/<namespace>/<name>.policy" waitfor "grep -qx 'allow exec /usr/bin/agent' '$OUT/pol/team-a/agent.policy'"
vp other team-a 'allow path /tmp/' > "$OUT/vp-other.json"; K apply -f "$OUT/vp-other.json" > /dev/null
check "a new one, watched" waitfor "[ -f '$OUT/pol/team-a/other.policy' ]"
vp agent team-a 'require warden 1.29
allow path /work/
allow path /data/ readonly
allow exec /usr/bin/agent' > "$OUT/vp-agent2.json"; K apply -f "$OUT/vp-agent2.json" > /dev/null
check "a change, written again" waitfor "grep -qx 'allow path /data/ readonly' '$OUT/pol/team-a/agent.policy'"
K -n team-a delete varekpolicy other > /dev/null
check "a deletion, removed" waitfor "[ ! -e '$OUT/pol/team-a/other.policy' ]"
check "the files root's, 0644" sh -c "[ \"\$(stat -c '%u %a' '$OUT/pol/team-a/agent.policy')\" = '0 644' ]"
check "each plan written to POLICY_DIR/<namespace>/<name>.plan (v1.35)" waitfor "grep -qx 'action a file_open /work/x' '$OUT/pol/team-a/p1.plan'"
K -n team-a delete pod p14 > /dev/null 2>&1; K -n team-a delete varekplan p1 > /dev/null
check "... a plan's deletion, removed" waitfor "[ ! -e '$OUT/pol/team-a/p1.plan' ]"
# v1.36 step 4 (D2): the cluster's VarekCredential resources, one list
check "the cluster's credentials written to POLICY_DIR/.credentials (v1.36)" \
    waitfor "grep -qx 'gh	team-a	$CSRC	gh' '$OUT/pol/.credentials'"
vc gh gh "$CSRC" team-a,team-b > "$OUT/vc2.json"; K apply -f "$OUT/vc2.json" > /dev/null
check "... a change, written again" waitfor "grep -qx 'gh	team-a,team-b	$CSRC	gh' '$OUT/pol/.credentials'"
K delete varekcredential gh > /dev/null
check "... a deletion, its line removed" waitfor "! grep -q '^gh	' '$OUT/pol/.credentials'"
check "... root's, 0644" sh -c "[ \"\$(stat -c '%u %a' '$OUT/pol/.credentials')\" = '0 644' ]"
sed 's/^/     nri: /' "$OUT/nri.log" | head -8

echo
[ "$fail" = 0 ] && echo "v1340_apiserver: PASS" || echo "v1340_apiserver: FAIL"
[ "$fail" = 0 ]
