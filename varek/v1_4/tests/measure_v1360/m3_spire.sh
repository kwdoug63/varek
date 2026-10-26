#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# m3_spire.sh — v1.36 step 1, M3 (tests/measure_v1360/README.md; the
# design note's D5): can a process on the node, outside the pod, get the
# pod's X.509 SVID from the node's SPIRE agent? Attesting the caller would
# give the caller's own identity, so it asks through the agent's Delegated
# Identity API, as an authorized delegate, by the pod's process id. On a
# cluster node_cluster.sh made; as root, with helm and go.
#
#   sudo -E varek/v1_4/tests/measure_v1360/m3_spire.sh [--out DIR]
#
# Several of SPIRE's chart values and API fields below are to be confirmed
# on the first run (marked so): the run's MEASURE lines say what held.
set -uo pipefail

OUT=/var/tmp/measure_v1360
[ "${1:-}" = --out ] && OUT="$2"
[ "$(id -u)" = 0 ] || { echo "m3_spire.sh: run as root" >&2; exit 2; }
export KUBECONFIG=/etc/kubernetes/admin.conf
KUBECTL=/usr/bin/kubectl
IMG="${POD_IMAGE:-registry.k8s.io/e2e-test-images/busybox:1.36.1-1}"
TD=measure.varek.test
DELEGATE="spiffe://$TD/varek-delegate"
mkdir -p "$OUT"
LOG="$OUT/m3.log"
measure() {
    echo "MEASURE m3.$1: $2" | tee -a "$OUT/measure.txt"
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- \`m3.$1\`: $2" >> "$GITHUB_STEP_SUMMARY"
    return 0
}
for t in helm go; do command -v "$t" > /dev/null || { measure setup "$t is not installed"; exit 1; }; done

# --- SPIRE, from its own charts (spiffe/helm-charts-hardened)
# To be confirmed on the first run: the values' names for the default
# identity, the agent's admin socket, its authorized delegates and the unix
# workload attestor.
cat > "$OUT/spire-values.yaml" <<EOF
global:
  spire:
    trustDomain: $TD
    clusterName: measure
spiffe-oidc-discovery-provider:
  enabled: false
spire-server:
  persistence:
    type: emptyDir
  controllerManager:
    watchClassless: true
    identities:
      clusterSPIFFEIDs:
        default:
          enabled: false
spire-agent:
  sockets:
    admin:
      enabled: true
      mountOnHost: true
  authorizedDelegates:
    - $DELEGATE
  workloadAttestors:
    unix:
      enabled: true
EOF
# The sixth run: the server's claim stayed unbound (a kubeadm cluster has no
# storage class), so the server never ran and nothing else came up. The
# server's data goes in an emptyDir above; in case the chart still asks for
# a claim, a volume on the node with no class binds it.
"$KUBECTL" create namespace spire-mgmt >> "$LOG" 2>&1 || true
install -d -m 0700 /var/lib/measure-spire
"$KUBECTL" apply -f - >> "$LOG" 2>&1 <<EOF
apiVersion: v1
kind: PersistentVolume
metadata: {name: measure-spire-data}
spec:
  capacity: {storage: 5Gi}
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Delete
  storageClassName: ""
  hostPath: {path: /var/lib/measure-spire, type: Directory}
EOF
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ >> "$LOG" 2>&1
helm repo update >> "$LOG" 2>&1
helm upgrade --install spire-crds spiffe/spire-crds -n spire-mgmt --create-namespace --wait >> "$LOG" 2>&1 ||
    { measure setup "spire-crds did not install"; exit 1; }
helm upgrade --install spire spiffe/spire -n spire-mgmt -f "$OUT/spire-values.yaml" --wait --timeout 10m >> "$LOG" 2>&1 ||
    { measure setup "spire did not install ($(tail -1 "$LOG"))"
      # into the job's log itself: its artifacts are not always reachable
      "$KUBECTL" get pods -A -o wide 2>&1
      "$KUBECTL" get events -A --sort-by=.lastTimestamp 2>&1 | tail -40
      for p in $("$KUBECTL" get pods -n spire-mgmt -o name 2>/dev/null); do
          "$KUBECTL" get -n spire-mgmt "$p" -o jsonpath='{.status.phase}' | grep -qx Running && continue
          "$KUBECTL" describe -n spire-mgmt "$p" 2>&1 | tail -25
          "$KUBECTL" logs -n spire-mgmt "$p" --all-containers --tail=20 2>&1
      done
      exit 1; }
measure chart "$(helm list -n spire-mgmt -o json | python3 -c 'import json,sys; print(", ".join(r["chart"] + " (app " + r["app_version"] + ")" for r in json.load(sys.stdin)))')"

server="$("$KUBECTL" get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' | grep -m1 '/spire-server-')"
srv() { "$KUBECTL" -n "${server%%/*}" exec "${server##*/}" -c spire-server -- /opt/spire/bin/spire-server "$@"; }
agent_id="$(srv agent list 2>> "$LOG" | awk '/SPIFFE ID/ {print $4; exit}')"
measure agent_id "${agent_id:-none found}"

# The pods: one registered by label, one not
cat > "$OUT/m3.yaml" <<EOF
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata: {name: varek-m3}
spec:
  className: spire-mgmt-spire
  spiffeIDTemplate: "spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}/m3"
  podSelector: {matchLabels: {varek-m3: registered}}
---
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterStaticEntry
metadata: {name: varek-delegate}
spec:
  className: spire-mgmt-spire
  spiffeID: $DELEGATE
  parentID: ${agent_id:-spiffe://$TD/unknown}
  selectors: ["unix:uid:0"]
---
apiVersion: v1
kind: Pod
metadata: {name: m3-registered, labels: {varek-m3: registered}}
spec:
  containers: [{name: c, image: "$IMG", command: [sleep, "14142135"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: m3-unregistered, labels: {varek-m3: none}}
spec:
  containers: [{name: c, image: "$IMG", command: [sleep, "17320508"]}]
EOF
"$KUBECTL" apply -f "$OUT/m3.yaml" >> "$LOG" 2>&1 || measure entries "not applied ($(tail -1 "$LOG"))"
"$KUBECTL" wait --for=condition=Ready pod/m3-registered pod/m3-unregistered --timeout=300s >> "$LOG" 2>&1
# The controller manager writes the entries. Run 7 found none after 20 s:
# the chart's controller manager reconciles only resources of its own class
# (spire-mgmt-spire), and these had none. If there are still none, what it
# said, into the job's log
n=0
for _ in $(seq 1 18); do
    n="$(srv entry show 2>> "$LOG" | grep -c 'Entry ID')"
    [ "$n" -ge 2 ] && break
    sleep 5
done
measure entries "$n on the server"
srv entry show >> "$LOG" 2>&1
if [ "$n" -lt 2 ]; then
    "$KUBECTL" get clusterspiffeids,clusterstaticentries -o yaml 2>&1 | tail -60
    "$KUBECTL" -n "${server%%/*}" logs "${server##*/}" -c spire-controller-manager --tail=40 2>&1
fi

# --- the agent's admin socket, as the node sees it
apid="$(pgrep -f 'spire-agent run' | head -1)"
conf="$(tr '\0' ' ' < "/proc/$apid/cmdline" | sed -n 's/.*-config \([^ ]*\).*/\1/p')"
adm="$(python3 - "/proc/$apid/root${conf:-/run/spire/config/agent.conf}" <<'EOF'
import re, sys
try:
    m = re.search(r'"?admin_socket_path"?\s*[:=]\s*"([^"]+)"', open(sys.argv[1]).read())
    print(m.group(1) if m else "")
except OSError:
    print("")
EOF
)"
measure admin_socket "${adm:-not configured}"
[ -n "$adm" ] || { measure delegated_svid "not measured (no admin socket)"; exit 0; }
SOCK="/proc/$apid/root$adm"

# --- the delegate: SPIRE's API SDK, asking by process id. To be confirmed
# on the first run: the request's Pid field (SPIRE 1.9 and later).
D="$OUT/delegate"
mkdir -p "$D"
cat > "$D/main.go" <<'EOF'
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	delegated "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	pid, _ := strconv.Atoi(os.Args[2])
	conn, err := grpc.NewClient("unix://"+os.Args[1], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := delegated.NewDelegatedIdentityClient(conn).SubscribeToX509SVIDs(ctx,
		&delegated.SubscribeToX509SVIDsRequest{Pid: int32(pid)})
	if err == nil {
		var r *delegated.SubscribeToX509SVIDsResponse
		if r, err = st.Recv(); err == nil {
			if len(r.X509Svids) == 0 {
				fmt.Println("none")
			}
			for _, s := range r.X509Svids {
				fmt.Printf("spiffe://%s%s\n", s.X509Svid.Id.TrustDomain, s.X509Svid.Id.Path)
			}
			return
		}
	}
	fmt.Println("error:", err)
}
EOF
(cd "$D" && go mod init varek/m3delegate && go get github.com/spiffe/spire-api-sdk@latest google.golang.org/grpc@latest &&
    go mod tidy && go build -o delegate .) >> "$LOG" 2>&1 || { measure delegated_svid "not measured (the client did not build)"; exit 0; }
measure sdk "$(cd "$D" && go list -m github.com/spiffe/spire-api-sdk 2>/dev/null)"

cpid() {
    local id ep
    id="$("$KUBECTL" get pod "$1" -o jsonpath='{.status.containerStatuses[0].containerID}')"
    case "$id" in cri-o://*) ep=unix:///var/run/crio/crio.sock ;; *) ep=unix:///run/containerd/containerd.sock ;; esac
    crictl --runtime-endpoint "$ep" inspect "${id#*://}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["pid"])'
}
reg="$(cpid m3-registered)" unreg="$(cpid m3-unregistered)"
measure delegated_svid "$("$D/delegate" "$SOCK" "$reg" 2>&1 | tr '\n' ' ')(want spiffe://$TD/ns/default/sa/default/m3)"
measure unregistered_refused "$("$D/delegate" "$SOCK" "$unreg" 2>&1 | tr '\n' ' ')(want none or an error)"
exit 0
