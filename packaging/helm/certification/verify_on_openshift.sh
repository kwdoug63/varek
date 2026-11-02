#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# verify_on_openshift.sh — Red Hat's chart certification run (chart-verifier,
# the partner profile) of the varek chart on an OpenShift cluster, whose
# report goes in the chart's pull request to openshift-helm-charts/charts
# (packaging/helm/certification/README.md).
#
#   verify_on_openshift.sh --version 1.36.1 [--out DIR] [--namespace NS]
#   verify_on_openshift.sh --chart varek-1.36.1.tgz --crds varek-crds-1.36.1.tgz [...]
#   verify_on_openshift.sh --crds-only --version VERSION [--out DIR] [--namespace NS]
#
# --crds-only runs chart-verifier on the varek-crds chart instead, for its
# own certification: it needs OpenShift and nothing of the node's (no CRI-O
# or NRI check), refuses a cluster that already has a varek.dev CRD (so that
# the CRDs it checks are the ones it installs), installs nothing itself, and
# deletes the four CRDs after chart-verifier (they are kept on an uninstall,
# and they were made by this run). Its namespace (default varek-crds-verify)
# is an ordinary one: the test pod runs as restricted-v2 allows. Run it
# before the varek chart's run on the same cluster, not after.
#
# --version pulls both charts of that release from oci://ghcr.io/kwdoug63/charts.
# Before anything is changed it checks the cluster: OpenShift, CRI-O 1.35 or
# later on every node, and NRI turned on by VAREK's MachineConfig with every
# pool updated. Then it makes the namespace (privileged, for the node agent),
# installs the CRDs' chart there (the varek chart refuses to install without
# them, and chart-verifier installs only the chart it checks), runs
# chart-verifier (podman, its image pinned; or CHART_VERIFIER=a binary) and
# prints each check's outcome. OUT/report.yaml is the report to submit.
# Runs where `oc` reaches the cluster (KUBECONFIG); it changes nothing but the
# namespace and the CRDs' release.
set -euo pipefail
VERSION="" CHART="" CRDS="" OUT="chart-verifier-out" NS="" CRDS_ONLY=0
REPO="oci://ghcr.io/kwdoug63/charts"
VERIFIER_IMAGE="${VERIFIER_IMAGE:-quay.io/redhat-certification/chart-verifier:1.16.1}"
VALUES="$(cd "$(dirname "$0")" && pwd)/values-openshift.yaml"
KCFG="${KUBECONFIG:-$HOME/.kube/config}"
die() { echo "verify_on_openshift: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --chart) CHART="$2"; shift 2 ;;
        --crds) CRDS="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --namespace) NS="$2"; shift 2 ;;
        --crds-only) CRDS_ONLY=1; shift ;;
        *) die "unknown argument $1 (see the header of $0)" ;;
    esac
done
if [ "$CRDS_ONLY" = 1 ]; then
    [ -n "$VERSION" ] || [ -n "$CRDS" ] || die "--crds-only: give --version, or --crds"
    [ -z "$CHART" ] || die "--crds-only checks the varek-crds chart: give --crds, not --chart"
    NS="${NS:-varek-crds-verify}"
else
    [ -n "$VERSION" ] || { [ -n "$CHART" ] && [ -n "$CRDS" ]; } || die "give --version, or --chart and --crds"
    NS="${NS:-varek-system}"
fi
for t in oc helm python3; do command -v "$t" > /dev/null || die "no $t on the PATH"; done
[ -n "${CHART_VERIFIER:-}" ] || command -v podman > /dev/null || die "no podman on the PATH (or set CHART_VERIFIER to a chart-verifier binary)"
[ -r "$KCFG" ] || die "no kubeconfig at $KCFG (set KUBECONFIG)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

echo "== the cluster: $(oc config current-context)"
oc api-resources --api-group=security.openshift.io -o name 2> /dev/null | grep -q '^securitycontextconstraints' ||
    die "$(oc config current-context) is not OpenShift (KUBECONFIG?)"
ocp="$(oc version -o json | python3 -c 'import json,sys; v=json.load(sys.stdin).get("openshiftVersion",""); print(".".join(v.split(".")[:2]))')"
[ -n "$ocp" ] || die "oc version gives no OpenShift version"
echo "   OpenShift $ocp"
if [ "$CRDS_ONLY" = 1 ]; then
    have="$(oc get crd -o name | grep '\.varek\.dev$' | tr '\n' ' ' || true)"
    [ -z "$have" ] || die "--crds-only: the cluster already has VAREK's CRDs ($have); run it on a cluster without them (before the varek chart's run), or delete them: oc delete $have"
    echo "   no varek.dev CRD yet"
else
# CRI-O 1.35 or later on every node: earlier CRI-O's NRI cannot set a container's seccomp policy
bad="$(oc get nodes -o jsonpath='{range .items[*]}{.metadata.name}={.status.nodeInfo.containerRuntimeVersion}{"\n"}{end}' |
    python3 -c '
import re, sys
for line in sys.stdin:
    name, _, rt = line.strip().partition("=")
    m = re.match(r"cri-o://(\d+)\.(\d+)", rt)
    if not m or (int(m.group(1)), int(m.group(2))) < (1, 35):
        print(f"{name} ({rt})")')"
[ -z "$bad" ] || die "a node without CRI-O 1.35 or later: $bad"
# NRI on: VAREK's MachineConfig (varek/v1_4/tests/soak_v1340/openshift-nri-*.yaml), every pool updated
oc get machineconfig -o name | grep -q -- '-varek-nri$' ||
    die "no VAREK NRI MachineConfig: oc apply -f varek/v1_4/tests/soak_v1340/openshift-nri-master.yaml (single-node; and -worker.yaml with workers), then wait for the pools"
notready="$(oc get mcp -o jsonpath='{range .items[*]}{.metadata.name}={.status.conditions[?(@.type=="Updated")].status}{"\n"}{end}' | grep -v '=True$' || true)"
[ -z "$notready" ] || die "a machine config pool not yet updated (oc get mcp -w): $notready"
echo "   CRI-O 1.35 or later on every node, NRI on, every pool updated"
fi

if [ -n "$VERSION" ]; then
    echo "== the charts of $VERSION, from $REPO"
    [ "$CRDS_ONLY" = 1 ] || helm pull "$REPO/varek" --version "$VERSION" -d "$OUT" > /dev/null
    helm pull "$REPO/varek-crds" --version "$VERSION" -d "$OUT" > /dev/null
    [ "$CRDS_ONLY" = 1 ] || CHART="$OUT/varek-$VERSION.tgz"
    CRDS="$OUT/varek-crds-$VERSION.tgz"
fi
[ -e "$CRDS" ] || die "no CRDs' chart at $CRDS"

if [ "$CRDS_ONLY" = 1 ]; then
    echo "== the namespace $NS (an ordinary one: the test pod is restricted-v2's)"
    oc create namespace "$NS" > /dev/null 2>&1 || true
    CHART="$CRDS"
    cp "$CHART" "$OUT/" 2> /dev/null || cp -r "$CHART" "$OUT/"
    args=(verify --set profile.vendortype=partner
          --namespace "$NS" --openshift-version "$ocp" --helm-install-timeout 10m)
    echo "== chart-verifier, the partner profile, on varek-crds (installs it, runs helm test, uninstalls it)"
else
[ -e "$CHART" ] || die "no chart at $CHART"

echo "== the namespace $NS (privileged: the node agent) and the CRDs"
oc create namespace "$NS" > /dev/null 2>&1 || true
oc label namespace "$NS" --overwrite pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/audit=privileged pod-security.kubernetes.io/warn=privileged > /dev/null
helm upgrade --install varek-crds "$CRDS" -n "$NS" --wait --timeout 5m > "$OUT/helm-crds.log" 2>&1 ||
    { tail -20 "$OUT/helm-crds.log" >&2; die "the CRDs' chart did not install"; }

echo "== chart-verifier, the partner profile (installs the chart, runs helm test, uninstalls it)"
cp "$VALUES" "$OUT/values-openshift.yaml"
cp "$CHART" "$OUT/" 2> /dev/null || cp -r "$CHART" "$OUT/"
args=(verify --set profile.vendortype=partner --chart-values /work/values-openshift.yaml
      --namespace "$NS" --openshift-version "$ocp" --helm-install-timeout 10m)
fi
chart="$(basename "$CHART")"
rc=0
if [ -n "${CHART_VERIFIER:-}" ]; then
    (cd "$OUT" && KUBECONFIG="$KCFG" "$CHART_VERIFIER" "${args[@]/\/work\//$OUT/}" "$OUT/$chart" \
        > "$OUT/report.yaml" 2> "$OUT/chart-verifier.log") || rc=$?
else
    podman run --rm -e KUBECONFIG=/kube/config -v "$KCFG:/kube/config:ro,z" -v "$OUT:/work:z" -w /work \
        "$VERIFIER_IMAGE" "${args[@]}" "/work/$chart" > "$OUT/report.yaml" 2> "$OUT/chart-verifier.log" || rc=$?
fi

python3 - "$OUT/report.yaml" <<'EOF' || rc=1
import re, sys
text = open(sys.argv[1]).read()
checks = re.findall(r"-\s*check:\s*(\S+)\s*\n\s*type:\s*(\S+)\s*\n\s*outcome:\s*(\S+)\s*\n\s*reason:\s*(.*)", text)
if not checks:
    print("  FAIL   no results in the report (chart-verifier.log says why)")
    sys.exit(1)
bad = 0
for check, kind, outcome, reason in checks:
    # SKIPPED is not a failure (signature-is-valid on an unsigned chart)
    print(f"  {outcome:<7} {check} ({kind}): {reason.strip()[:160]}")
    bad |= outcome not in ("PASS", "SKIPPED")
sys.exit(bad)
EOF
if [ "$CRDS_ONLY" = 1 ]; then
    # the four CRDs this run made (there were none before it): kept on
    # chart-verifier's uninstall, deleted here, so that the varek chart's run
    # installs varek-crds afresh
    made="$(oc get crd -o name | grep '\.varek\.dev$' | tr '\n' ' ' || true)"
    # shellcheck disable=SC2086  # $made: the CRDs' names, split into words
    [ -z "$made" ] || oc delete $made > /dev/null || echo "verify_on_openshift: could not delete $made" >&2
    echo "   the CRDs it made deleted; the namespace stays: oc delete namespace $NS"
fi
[ "$rc" = 0 ] && echo "verify_on_openshift: PASS: $OUT/report.yaml is the report to submit" ||
    echo "verify_on_openshift: FAIL: see $OUT/report.yaml and $OUT/chart-verifier.log"
exit "$rc"
