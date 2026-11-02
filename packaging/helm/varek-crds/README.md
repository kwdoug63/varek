# varek-crds

The custom resources of VAREK on Kubernetes: `VarekPolicy`, `VarekPlan`,
`VarekCredential` and `VarekNodeKey`. Install this chart before the `varek`
chart (`packaging/helm/varek/README.md`); the `varek` chart refuses to
install on a cluster that has none of them.

```sh
helm install varek-crds oci://ghcr.io/kwdoug63/charts/varek-crds --version 1.36.1
```

They are a chart of their own for two reasons:

- **Red Hat's chart certification** refuses a chart that holds a CRD
  (chart-verifier's `not-contains-crds`), so the certified `varek` chart
  holds none.
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

## Red Hat's certification

The chart carries what chart-verifier's partner profile asks for: no
`crds/` directory (the CRDs are templates), a values schema, the test
above, in an image Red Hat certified, and the `charts.openshift.io`
annotations. Its run on OpenShift is
`packaging/helm/certification/verify_on_openshift.sh --crds-only`
(`packaging/helm/certification/README.md`).

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
