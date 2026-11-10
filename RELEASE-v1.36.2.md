# VAREK v1.36.2 — The Node Key Published Again; a Test for varek-crds

Released 2026-11-02 · MIT · github.com/kwdoug63/varek

## Summary

A patch release of v1.36.1. The NRI plugin now publishes a node's key
whenever the node agent makes a new one. The `varek-crds` chart has a
`helm test`, a values schema and OpenShift's annotations.
`varek doctor` warns, rather than fails, on a host with no settings. A
guide installs VAREK on RHEL 9.

The Warden reports 1.36.2 and decides nothing differently: no policy line,
rule, record or option changes, and the grammar stays 1.35. The CRDs'
schemas are 1.36.1's. Upgrading takes no step beyond upgrading both charts
(below).

## The node's key, published again when it changes

Since v1.36.0 each node signs its streams with its own key (D10 of
`docs/security/v1.36-kubernetes-parity.md`). The node agent makes the key
at its first start, and the NRI plugin publishes its public key as the
node's `VarekNodeKey`, which the audit checks a stream against.

Through 1.36.1 the plugin published once and stopped. When the node agent
made a new key after the plugin had read the old file (a node rebuilt with
its key lost, the node agent's pod restarted), the new key was never
published. The node's streams from then on could not be verified with the
cluster's list. CI found it: `v1340_kind.sh`'s rebuild check on the
CRI-O 1.35, runc cell.

From 1.36.2 the plugin reads the node's public key file every 5 s for as
long as it runs. A key that differs from the one it published is
published as a new `VarekNodeKey`; the old one is kept, so streams signed
before the change still verify. Errors back off from 2 s, doubled up to a
minute (`varek/v1_4/k8s/cmd/varek-nri/nodekey.go`).

## varek-crds: a test, a values schema, annotations

**Corrected November 2, 2026.** This release said `varek-crds` was ready
for its own Red Hat chart certification. It is not, and cannot be:
chart-verifier's `not-contains-crds` check, mandatory in the partner
profile, flags a CustomResourceDefinition in a chart's `templates/` as
well as in its `crds/`, and Red Hat's own run installs a chart with a
service account confined to its test namespace, which cannot create
cluster-scoped resources such as CRDs. Its submission,
[openshift-helm-charts/charts#3624](https://github.com/openshift-helm-charts/charts/pull/3624),
passed the other 11 checks and failed those two; it was withdrawn. Red
Hat's route for CRDs is an Operator. The certified `varek` chart, which
holds no CRD, is unaffected. The additions below stay, for what they check:

1.36.1's `varek-crds` chart lacked three things chart-verifier's partner
profile asks of a chart. 1.36.2's has them:

- **`required-annotations-present`:** the `charts.openshift.io`
  annotations: name "VAREK CRDs", provider, support URL, and the
  architectures `x86_64,aarch64`.
- **`contains-values-schema`:** `values.schema.json`, for the chart's only
  values, which are its test's image.
- **`contains-test`:** `helm test varek-crds` checks that the API server
  serves the four kinds at `varek.dev/v1alpha1`.
  - It reads the group's discovery document with the pod's own service
    account token. Any authenticated identity may read it
    (`system:discovery`), so the chart grants no role.
  - It runs the `varek` chart's node image at the chart's version, which
    Red Hat certifies with each release, so `images-are-certified` holds.
  - It runs as OpenShift's restricted-v2 allows: no fixed user on
    OpenShift (found by its `security.openshift.io/v1` API), 65532
    elsewhere. Red Hat's own run of a chart passes no values, so this is
    found, not set.

The release's `verify_on_openshift.sh --crds-only`, which made the
chart's report on OpenShift, has since been removed (the correction above).

## varek doctor on a host with no settings

`varek run` works with no settings (the baseline, since v1.29). Through
1.36.1, `varek doctor` on such a host failed with "no configuration at
/etc/varek/varek.conf" and exited 1. From 1.36.2 that is a WARN, naming
`sudo varek init --pack <name>`. Settings that are there and do not load
still fail. The install guide's first run on RHEL 9.8 found it.

## Installing on RHEL 9

`docs/install/rhel9.md` installs the Warden, its helpers and the `varek`
command on a RHEL 9 host from a release's tag: EPEL 9 for libsodium, the
build's packages from BaseOS and AppStream, `make install
BINDIR=/usr/bin`, `varek doctor`, a first run, a policy pack. It was run
end to end on RHEL 9.8 (Amazon EC2, SELinux enforcing) from the v1.36.1
tag, with no SELinux denial, and corrected from what that run showed:
CodeReady Builder is not needed, and `varek refusals` is root's. It
names RHEL 9.8 on x86_64 as the minimum, the version VAREK Enterprise's
Red Hat software certification is made on, and each release's copy is
at its tag, which the certification's listing links to.

## CI

- **preflight 1.22.0.** Red Hat refuses results from preflight 1.14.1,
  which CI ran. `container.yml` now downloads Red Hat's 1.22.0 release
  binary, checks its SHA-256 and its `--version`, and runs it on both
  images on every change, as before.
- **The six-minute soak trial's memory check.** It judged the node
  agent's memory from the run's first sample, which can come before the
  agents run, and read a supervisor's steady size as growth. A run under
  three hours is now judged from a third into it; the 24-hour runs, from
  the first hour, as before (`soak_check.py`, `test_soak_v1340_check.py`).
- **The image on containerd.** `v1340_kind.sh` waits up to 30 s for the
  CRI plugin to see an image imported with `ctr`, which it learns of from
  an event after the import returns.

## Tested

- CI on each change (#114, #115, #117): the Warden's builds on x86_64 and
  aarch64; every suite in the container image; kind on amd64 and arm64;
  the six-minute soak trials; the matrix cells (CRI-O 1.35 to 1.37 under
  runc and crun, containerd 2.2 and 2.3, amd64 and arm64); SELinux
  enforcing (CRI-O 1.35 on Rocky Linux 9); and every suite on Rocky
  Linux 9 and Amazon Linux 2023 hosts.
- `helm test varek-crds` passes in kind and in every matrix cell, on
  amd64 and arm64.
- `nodekey_test.go`: a key that changes after the first publish is
  published as a second `VarekNodeKey`, the old one kept, each key posted
  once; it fails on 1.36.1's publisher and passes with `-race`.
- `test_varek_cli.py`: no settings, a WARN naming `varek init` and no
  FAIL; a file with no `[varek]` section, a FAIL and a non-zero exit.
- `test_varek_chart.py`: the CRDs chart's annotations, schema, lint and
  test pod, its OpenShift render with no fixed user.

## Red Hat's certification

Partner Connect certifies each release's images and charts. For 1.36.2:

1. Both images' 1.36.2 tags, submitted with preflight 1.22.0 to the
   "VAREK node" and "VAREK runtime" components, then published.
2. The `varek` chart's 1.36.2 report from an OpenShift run, in a pull
   request to openshift-helm-charts/charts at
   `charts/partners/soberagents/varek/1.36.2/`.

The `varek-crds` chart is not certified (above); it is published and
signed on ghcr.io.

## Upgrading

From 1.36.1, upgrade `varek-crds` first, then `varek`:

```sh
helm upgrade varek-crds oci://ghcr.io/kwdoug63/charts/varek-crds --version 1.36.2 -n varek-system
helm upgrade varek oci://ghcr.io/kwdoug63/charts/varek --version 1.36.2 -n varek-system
```

The CRDs do not change. `helm test varek-crds` pulls the node image; on a
cluster that pulls from a mirror, give `image.repository` (and
`imagePullSecrets`) as for the `varek` chart.

From 1.36.0 or before, give the CRDs to the `varek-crds` release first, as
`RELEASE-v1.36.1.md` says ("Upgrading"), then install 1.36.2's charts.

On a host, build and install the v1.36.2 tag as before
(`docs/install/rhel9.md`, `varek/v1_4/README.md`).
