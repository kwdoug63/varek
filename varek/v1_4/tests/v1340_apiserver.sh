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
#   2. the webhook (varek-admission, the chart's three hooks pointed at it):
#      a policy the Warden does not load and one with credentials refused
#      with the Warden's reason; one that loads admitted; pods refused for a
#      policy not in their namespace, root, a relative command, a writable
#      root under a policy that decides launches, a capability added; a pod naming no policy, in
#      a namespace that requires one, refused; the chart's own namespace not
#      checked;
#   3. the sync (varek-nri -sync) through the API server: each policy
#      written to POLICY_DIR/<namespace>/<name>.policy, changed, and removed.
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
crd = [d for d in docs if d["kind"] == "CustomResourceDefinition"][0]
json.dump(crd, open(sys.argv[2] + "/crd.json", "w"))
vwc = [d for d in docs if d["kind"] == "ValidatingWebhookConfiguration"][0]
for h in vwc["webhooks"]:
    path = h["clientConfig"]["service"]["path"]
    h["clientConfig"] = {"url": "https://127.0.0.1:18443" + path, "caBundle": sys.argv[3]}
json.dump(vwc, open(sys.argv[2] + "/vwc.json", "w"))
EOF
crd() { K apply -f "$OUT/crd.json" && K wait --for condition=established crd/varekpolicies.varek.dev --timeout=30s; }
check "the chart's CRD installs and is established" crd
vp() { python3 -c 'import json, sys; print(json.dumps({"apiVersion": "varek.dev/v1alpha1", "kind": "VarekPolicy",
    "metadata": {"name": sys.argv[1], "namespace": sys.argv[2]}, "spec": {"policy": sys.argv[3] + "\n"}}))' "$@"; }
K create namespace team-a > /dev/null; K create namespace varek-system > /dev/null
K create namespace team-req > /dev/null; K label namespace team-req varek.dev/policy-required=true > /dev/null
refused() {   # WHAT FILE PATTERN
    if K apply -f "$2" > "$2.out" 2>&1; then flunk "$1 (admitted)"
    elif grep -q "$3" "$2.out"; then pass "$1"
    else flunk "$1 ($(tail -1 "$2.out"))"; fi
}
vp Bad_Name team-a "allow path /tmp/" > "$OUT/vp-badname.json"
refused "a name the node agent does not take: refused by the CRD's rule" "$OUT/vp-badname.json" "is 1 to 63 of a-z, 0-9 and -"

echo "== 2. the webhook"
echo admin-token > "$P/token"
"$OUT/varek-admission" -warden "$HERE/warden" -tls-cert "$P/wh.crt" -tls-key "$P/wh.key" -listen 127.0.0.1:18443 \
    -api https://127.0.0.1:6443 -api-token "$P/token" -api-ca "$P/apiserver.crt" > "$OUT/admission.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 50); do curl -sk https://127.0.0.1:18443/healthz | grep -q ok && break; sleep 0.2; done
check "the chart's three hooks registered, pointed at the webhook" K apply -f "$OUT/vwc.json"
sleep 2
vp broken team-a "allow pathh /tmp/" > "$OUT/vp-broken.json"
refused "a policy the Warden does not load: refused, with its reason" "$OUT/vp-broken.json" "refuses this policy"
vp creds team-a 'require warden 1.28
proxy on
credential k from file:/etc/varek/creds/k
allow host api.example.com:443' > "$OUT/vp-creds.json"
refused "a policy with credentials: refused (not carried by the node agent yet)" "$OUT/vp-creds.json" "does not carry credentials"
vp agent team-a 'require warden 1.29
allow path /work/
allow exec /usr/bin/agent' > "$OUT/vp-agent.json"
check "a policy the Warden loads: admitted" K apply -f "$OUT/vp-agent.json"
pod() {   # NAME NAMESPACE POLICY|- EDIT
    python3 - "$@" <<'EOF'
import json, sys
name, ns, pol, edit = sys.argv[1:]
meta = {"name": name, "namespace": ns}
if pol != "-":
    meta["annotations"] = {"varek.dev/policy": pol}
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
print(json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": {"containers": [c]}}))
EOF
}
pod p1 team-a nosuch - > "$OUT/p1.json"; refused "a pod naming a policy not in its namespace: refused" "$OUT/p1.json" "no VarekPolicy nosuch in namespace team-a"
pod p2 team-a agent root > "$OUT/p2.json"; refused "a pod running as root: refused" "$OUT/p2.json" "runs as root"
pod p3 team-a agent relative > "$OUT/p3.json"; refused "a command by a relative path: refused" "$OUT/p3.json" "absolute path"
pod p4 team-a agent writable > "$OUT/p4.json"; refused "a writable root under a policy that decides launches: refused" "$OUT/p4.json" "must be read-only"
pod p8 team-a agent caps > "$OUT/p8.json"; refused "a capability added back: refused" "$OUT/p8.json" "adds capabilities"
pod p5 team-a agent - > "$OUT/p5.json"; check "a pod as the node agent requires: admitted" K apply -f "$OUT/p5.json"
pod p6 team-req - - > "$OUT/p6.json"; refused "a pod naming no policy where one is required: refused" "$OUT/p6.json" "requires every pod to name its policy"
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
sed 's/^/     nri: /' "$OUT/nri.log" | head -8

echo
[ "$fail" = 0 ] && echo "v1340_apiserver: PASS" || echo "v1340_apiserver: FAIL"
[ "$fail" = 0 ]
