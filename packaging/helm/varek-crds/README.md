# varek-crds

The custom resources of VAREK on Kubernetes: `VarekPolicy`, `VarekPlan`,
`VarekCredential` and `VarekNodeKey`. Install this chart before the `varek`
chart (`packaging/helm/varek/README.md`); the `varek` chart refuses to
install on a cluster that has none of them.

```sh
helm install varek-crds oci://ghcr.io/kwdoug63/charts/varek-crds --version 1.38.0
```

They are a chart of their own for two reasons:

- **Red Hat's chart certification** refuses a chart that holds a CRD, in
  `crds/` or in `templates/` (chart-verifier's `not-contains-crds`), so the
  certified `varek` chart holds none.
- **`helm upgrade` changes them.** Helm installs a chart's `crds/` once and
  never upgrades them; these are templates, so `helm upgrade varek-crds`
  applies a new version.

## Its test

`helm test varek-crds` checks that the API server serves the four kinds:
a pod reads the group's discovery document (`/apis/varek.dev/v1alpha1`)
with its own service account token, which any identity may read, so the
chart grants no role. It runs the varek chart's node image, at the chart's
version (`image` in `values.yaml`, its only values), as restricted-v2
allows: on OpenShift the namespace gives its user, elsewhere 65532.

## On OpenShift

Installed on OpenShift (where the API server serves
`security.openshift.io/v1`, which Helm sees on its own), this chart also
creates the SecurityContextConstraints the `varek` chart's node agent runs
under, `varek-node-agent`: privileged, in the node's PID namespace, with
host paths. It names no user or group, so no one may use it until a role
grants `use` of it; the `varek` chart, with `openshift.enabled=true`, grants
that to its node agent's service account alone. It is this chart's so that
it exists before the `varek` chart's DaemonSet makes its first pod: Helm
creates an SCC, a kind it does not know, after a DaemonSet. Unlike the CRDs
it is not kept: `helm uninstall varek-crds` removes it.

## Not certified by Red Hat

This chart cannot be a certified chart: chart-verifier's `not-contains-crds` check, mandatory in the partner
profile, flags a CustomResourceDefinition in a chart's `templates/` as
well as in its `crds/`, and Red Hat's own run installs a chart with a
service account confined to its test namespace, which cannot create
cluster-scoped resources such as CRDs. Its submission,
[openshift-helm-charts/charts#3624](https://github.com/openshift-helm-charts/charts/pull/3624)
(November 2, 2026), passed the other 11 checks and failed those two; it was
withdrawn. Red Hat's route for CRDs is an Operator. The `varek` chart, which
holds none, is certified; this chart is published and signed on ghcr.io
with each release. It keeps its values schema, its test and its
`charts.openshift.io` annotations.

## Kept on an uninstall

Each carries `helm.sh/resource-policy: keep`: `helm uninstall varek-crds`
leaves it, and every `VarekPolicy`, `VarekPlan`, `VarekCredential` and
`VarekNodeKey` of the cluster with it. Remove them with `kubectl delete crd`,
which deletes every resource of their kinds.

## From a chart of 1.36.0 or before

There the `varek` chart installed them from its `crds/`, which no release
owns. Before installing this chart, give them to its release (the release's
name and namespace), so that Helm takes them over:

```sh
for c in varekpolicies varekplans varekcredentials vareknodekeys; do kubectl annotate crd $c.varek.dev meta.helm.sh/release-name=varek-crds meta.helm.sh/release-namespace=varek-system --overwrite && kubectl label crd $c.varek.dev app.kubernetes.io/managed-by=Helm --overwrite; done
helm upgrade --install varek-crds oci://ghcr.io/kwdoug63/charts/varek-crds -n varek-system
```
