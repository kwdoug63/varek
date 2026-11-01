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
