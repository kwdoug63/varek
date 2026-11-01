# The chart's certification run on OpenShift

Red Hat certifies a Helm chart from a chart-verifier report made with the
partner profile on an OpenShift cluster. Two of its mandatory checks need
that cluster: `chart-testing` installs the chart and runs its `helm test`,
and `images-are-certified` looks up each image the chart names in Red Hat's
catalog. This directory holds what that run needs:

| File | What it is |
| --- | --- |
| `values-openshift.yaml` | the varek chart's values for OpenShift: `runtime: cri-o`, `openshift.enabled: true` (its SecurityContextConstraints); the image is the chart's own |
| `verify_on_openshift.sh` | checks the cluster, makes the namespace, installs the CRDs' chart, runs chart-verifier and prints each check's outcome |

The CRDs come from the `varek-crds` chart, installed first: the varek chart
refuses to install without them, and chart-verifier installs only the chart
it checks. Only the `varek` chart is submitted for certification.

## Order

Run it after the release's node image is certified and published in Red
Hat's catalog (preflight, `packaging/container/README.md`). Until then
`images-are-certified` fails, and everything else can still be read from the
report.

## What the cluster needs

- OpenShift 4.22 or later (CRI-O 1.35 or later: earlier CRI-O's NRI cannot
  set a container's seccomp policy). A single-node OpenShift is enough; the
  24-hour run's makes one (`varek/v1_4/tests/soak_v1340/README.md`,
  section 3).
- CRI-O's NRI turned on, by VAREK's MachineConfig:
  `varek/v1_4/tests/soak_v1340/openshift-nri-master.yaml` (single-node: its
  one node is in the master pool), and `openshift-nri-worker.yaml` too on a
  cluster with workers. The Machine Config Operator writes the drop-in
  (`[crio.nri] enable_nri = true`) and reboots each pool's nodes, one at a
  time.
- Where the commands run: a host where `oc` and `helm` reach the cluster
  (`KUBECONFIG`), with podman (or a chart-verifier binary, `CHART_VERIFIER`),
  and access to ghcr.io, quay.io and catalog.redhat.com.

## The run

Every command is one line, run on that host, in the repository's root.

NRI on (single-node), then wait until the pool says UPDATED True:

```sh
oc apply -f varek/v1_4/tests/soak_v1340/openshift-nri-master.yaml && oc get mcp master -w # end
```

The run, for the release (both charts pulled from
`oci://ghcr.io/kwdoug63/charts`; or `--chart` and `--crds` for local ones):

```sh
packaging/helm/certification/verify_on_openshift.sh --version 1.36.1 --out ~/chart-verifier-1.36.1 # end
```

Before it changes anything it refuses a cluster that is not OpenShift, a
node without CRI-O 1.35 or later, a cluster without VAREK's NRI
MachineConfig, and a machine config pool not yet updated. Then it makes the
namespace `varek-system` (Pod Security `privileged`, for the node agent),
installs `varek-crds` there, and runs chart-verifier
(`quay.io/redhat-certification/chart-verifier:1.16.1`), which installs the
chart, runs its `helm test` and uninstalls it. Each check's outcome is
printed; it ends `PASS` when none failed (`SKIPPED` is not a failure:
`signature-is-valid` on an unsigned chart).

## Then

`OUT/report.yaml` and the chart's archive go in the chart's pull request to
[openshift-helm-charts/charts](https://github.com/openshift-helm-charts/charts),
at `charts/partners/<the organization>/varek/<version>/`. The namespace and
the `varek-crds` release stay; remove them when done:

```sh
helm uninstall varek-crds -n varek-system && oc delete namespace varek-system # end
```

The CRDs stay after that (`helm.sh/resource-policy: keep`); delete them
with `oc delete crd varekpolicies.varek.dev varekplans.varek.dev
varekcredentials.varek.dev vareknodekeys.varek.dev` if the cluster is kept.
