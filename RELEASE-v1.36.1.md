# VAREK v1.36.1 — Packaged for Red Hat's Certification

Released 2026-11-01 · MIT · github.com/kwdoug63/varek

## Summary

A patch release of v1.36.0. The images and the Helm chart are packaged as
Red Hat's container and chart certifications ask, and CI runs Red Hat's
container checks on every change. The Warden reports 1.36.1; nothing it
decides changes: no policy line, rule, record or option. The grammar stays
1.35.

One change needs a step on upgrade: the custom resources are now a chart
of their own, `varek-crds`, installed before the `varek` chart (below,
"Upgrading").

## The images

- **Labels and licenses.** Both images (`ghcr.io/kwdoug63/varek`, the
  runtime, and `ghcr.io/kwdoug63/varek-node`, the chart's) carry the labels
  preflight asks for, `name`, `vendor`, `version`, `release`, `summary`,
  `description` and `maintainer`, each VAREK's (the UBI base's name a Red
  Hat image and vendor), and the licenses in `/licenses`. The release
  workflow passes the tag's version and the commit
  (`--build-arg VAREK_VERSION=`, `VAREK_REVISION=`); a local build says
  `dev`.
- **preflight in CI.** `container.yml` builds preflight v1.14.1 from source
  (its modules checked against Go's checksum database) and runs it on both
  images as built, on every change
  (`packaging/container/preflight_check.sh`, which pushes each to a
  registry on the runner). Every check must pass but `RunAsNonRoot`, which
  both images fail by design: they run as root, for the Warden and the node
  agent, under the certification project's host-level access Privileged,
  which Red Hat reviews (`docs/security/node-agent-privilege.md`). The
  results are kept as the run's `preflight` artifact.
- **Base images pinned by digest.** Each stage's base in the `Containerfile`
  is pinned by its index digest (every architecture's): AlmaLinux 9 (build),
  UBI 9 minimal (runtime and node), Go 1.24 (the cluster's binaries) and
  Ubuntu 24.04 (the test stage, not released). A build is the same build
  whenever it is made; a newer base is taken by changing the digest, in a
  change CI checks.

## The chart

chart-verifier's partner profile refused four of its mandatory checks on
v1.36.0's chart. Each now passes. Of its 13 mandatory checks, the 11 that
need no cluster were run on v1.36.1's chart here: 10 pass, and
`signature-is-valid` is skipped, as for any chart without a Helm provenance
file (the release signs the chart with cosign). The other two need what
only the certification run has (below).

- **`not-contains-crds`: the CRDs are a chart of their own.** `VarekPolicy`,
  `VarekPlan`, `VarekCredential` and `VarekNodeKey` move from the `varek`
  chart's `crds/` to the `varek-crds` chart (`packaging/helm/varek-crds`),
  as templates, each with `helm.sh/resource-policy: keep` (an uninstall
  leaves them and every resource of their kinds). `helm upgrade varek-crds`
  now upgrades them, where Helm never upgraded a chart's `crds/`. The
  `varek` chart refuses to install on a cluster without them
  (`crds.check`, true by default), naming `varek-crds`. The release
  workflow packages, pushes and signs both charts, at
  `oci://ghcr.io/kwdoug63/charts/varek` and `.../varek-crds`, each the
  tag's version, and verifies both signatures before moving `:1.36` and
  `latest`.
- **`contains-values-schema`.** `values.schema.json` gives each value's
  type; a value of the wrong type is refused when the chart is rendered.
  The chart's own checks still give the reasons for the rest.
- **`contains-test`.** `helm test` checks that the admission webhook
  answers its health check over HTTPS, its certificate verified with the CA
  the chart gives the API server for it. The webhook refuses every pod and
  policy it checks when down (`failurePolicy: Fail`), so this is the check
  that the chart is up. The test pod runs as `restricted-v2` allows, and
  connects to the Service's address the kubelet gives it, so it checks the
  webhook rather than the cluster's DNS. It is kept until the next test run
  (`helm test --logs` reads it).
- **`required-annotations-present`.** `charts.openshift.io/name`,
  `provider`, `supportURL` and `archs` (`x86_64,aarch64`).

## The certification run on OpenShift

`packaging/helm/certification/` holds what Red Hat's certification run of
the chart needs: the values for OpenShift (`values-openshift.yaml`: CRI-O,
the chart's SecurityContextConstraints, the chart's own image) and
`verify_on_openshift.sh`, which checks the cluster (OpenShift, CRI-O 1.35
or later on every node, VAREK's NRI MachineConfig with every pool updated),
makes the namespace, installs `varek-crds`, runs chart-verifier with the
partner profile and prints each check's outcome. The two checks it adds,
`chart-testing` (the chart installed and its `helm test` run, on OpenShift)
and `images-are-certified` (the node image in Red Hat's catalog), are run
once v1.36.1's node image is certified; this release has not had that run.

## Tested

- `test_varek_chart.py`: no CRD in the `varek` chart and four in
  `varek-crds`, each kept on an uninstall, both charts at the same version;
  the annotations; the values schema refusing a value of the wrong type;
  the test pod; the OpenShift values rendering both SecurityContextConstraints
  and the chart's own image.
- `v1340_kind.sh` (kind, in CI on amd64 and arm64), the matrix's kubeadm
  cells (CRI-O 1.35 to 1.37 under runc and crun, containerd 2.2 and 2.3),
  the API server test and the soak harness install `varek-crds` first, then
  the chart; kind and the matrix cells run `helm test`, its output and the
  test pod's log kept and shown when it fails.
- preflight on both images, as above, every check passing but
  `RunAsNonRoot`.
- The Warden reports 1.36.1 (`test-v1320`'s and `test-v1321`'s version
  checks take 1.32.0 and 1.32.1 "or later"); the release workflow checks
  that each image's Warden is the tag's version.

## Upgrading

From 1.36.0 or before, the CRDs were installed from the `varek` chart's
`crds/`, which no release owns. Give them to the `varek-crds` release, so
that Helm takes them over, install it, then upgrade the chart
(`packaging/helm/varek-crds/README.md`):

```sh
for c in varekpolicies varekplans varekcredentials vareknodekeys; do kubectl annotate crd $c.varek.dev meta.helm.sh/release-name=varek-crds meta.helm.sh/release-namespace=varek-system --overwrite && kubectl label crd $c.varek.dev app.kubernetes.io/managed-by=Helm --overwrite; done
helm upgrade --install varek-crds oci://ghcr.io/kwdoug63/charts/varek-crds --version 1.36.1 -n varek-system
helm upgrade varek oci://ghcr.io/kwdoug63/charts/varek --version 1.36.1 -n varek-system
```

No resource is changed or lost: the CRDs' schemas are 1.36.0's, and Helm
never deletes a CRD a chart installed from `crds/`. Afterwards,
upgrade `varek-crds` first, then `varek`, each release.

A new install: `varek-crds`, then `varek`
(`packaging/helm/varek/README.md`). The images and the host install
change nothing but their labels and the version they report.
