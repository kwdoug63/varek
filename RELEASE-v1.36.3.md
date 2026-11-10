# VAREK v1.36.3 — The Container a Connection Names, Confirmed

Released 2026-11-04 · MIT · github.com/kwdoug63/varek

## Summary

A security patch release of v1.36.2. The node agent confirms the
container each runtime connection names before it does anything for it,
and the admission webhook refuses a pod that mounts the node agent's
socket's directory. Upgrade from v1.36.0, v1.36.1 or v1.36.2.

The Warden reports 1.36.3 and decides nothing differently: no policy line,
rule, record or option changes, and the grammar stays 1.35. The CRDs'
schemas are 1.36.1's.

## Security

**What was wrong.** When a runtime starts a container under VAREK's
filter, it connects to the node agent's socket and sends the filter's
descriptor with the container's state. The node agent checked who sent it
and which process the descriptor is for, but took the container's id, its
bundle and its annotations from the state as sent. Those decide the policy
the process is held to, the identity its stream is signed under, the
credentials released for it and the user token read for it.

v1.36.0 added two ways of taking a runtime the node agent cannot read
(runc 1.2 in a mount namespace of its own; crun reaped by conmon at once),
in which the kernel ties the descriptor to the process the state names. A
pod allowed a hostPath of the socket's directory, running as root, could
use them to have a process of its own supervised as another pod's
container: held to that pod's policy, its stream signed as that pod's, with
the credentials given to that pod's namespace and that pod's user token.

**Severity:** High (`SECURITY.md`): a pod held to another pod's policy,
identity and credentials, with a precondition (a hostPath of the socket's
directory, as root).

**Affected:** v1.36.0, v1.36.1 and v1.36.2, under Kubernetes. A host's and a
container's Warden are not affected: they start the agent themselves.

**Fixed in v1.36.3**, on every path a connection is taken by
(`docs/security/v1.36.3-bundle-confirmation.md`):

- the process the state names must be in that container's cgroup, which
  the kernel holds (`crio-<id>.scope`, `cri-containerd-<id>.scope`, `<id>`
  under the cgroupfs driver, and crun's `container` leaf below its scope),
  and in its pod's when the state names a pod;
- the bundle must be that id's, under the runtime's own directory, named
  through no link, root's and written by no one else;
- the annotations VAREK reads must be the bundle's `config.json`'s, which
  the runtime wrote;
- otherwise the connection is refused, as any other is, and the process it
  named is not ended.

The admission webhook, besides, refuses a pod it serves that mounts the
node agent's socket's directory, or a directory above it, as a hostPath,
read-only or not.

**What to do.** Upgrade both charts (below). No pod ran unsupervised: a
pod supervised under another's identity was supervised all the same. If a
node may have run a pod with a hostPath of the socket's directory
(`/run/varek-node` by default) or a directory above it, audit the streams
recorded there by v1.36.0 to v1.36.2 with `varek audit --node-keys`, and
check that each stream's `run_start` names the pod that ran.

**Advisory:** GHSA-pcxh-jj4w-2jcc, published with this release
(https://github.com/kwdoug63/varek/security/advisories/GHSA-pcxh-jj4w-2jcc);
its CVE has been requested and is added here when it is assigned.

## What changes for an operator

- **`--node-bundle-root DIR`**, a node agent option (repeatable): where the
  runtimes keep the containers' bundles. Without it, containerd's and
  CRI-O's defaults. The chart gives the one under its state directory
  (`node.state`), so a platform that keeps that directory elsewhere (k3s's
  `/run/k3s/containerd`) is followed. A bundle anywhere else is refused,
  with the path in the node agent's log.
- **`-node-socket-dir`**, the webhook's: the chart sets it to
  `node.socket`. A pod refused for it says which of its volumes mounts what.
- **A refused container** says why in the node agent's log: its process's
  cgroup, or its bundle, against the id the runtime gave.

## Measured first

A report-only build of the checks ran on every cell of the matrix (CRI-O
1.35 to 1.37 under runc and crun; containerd 2.2 and 2.3; amd64 and arm64)
and on kind: 18 cells, 387 containers, both of v1.36.0's paths taken. The
cgroup named each container and its pod everywhere (under crun one level
lower, `…/crio-<id>.scope/container`); the bundle was always the id's,
root's, mode 700; the state's annotations and `config.json`'s were equal on
every container. The checks add under 0.1 ms to a container's start at the
median (`docs/security/v1.36.3-bundle-confirmation.md`, "Measured").

## Tested

- `test_v1340.sh` section 16: a state naming another container, its
  process in a cgroup of its own, sent through each way a runtime is taken
  (ended and read, reaped, in a mount namespace of its own): refused, the
  process not ended, no stream under that id; a bundle outside the
  runtime's directory, and one named through a link: refused; a state
  whose annotations are not its bundle's: refused in its supervisor. The
  suite's own containers run in cgroups and bundles of their own, as a
  runtime's do, and every one of them is confirmed.
- The webhook's tests: the socket's directory, a directory above it, `/`,
  `/var/run`, a trailing slash, a pod naming no policy: refused; other
  hostPaths: admitted.
- The chart's tests: the bundle directory under each runtime's state
  directory, and under one of the platform's own; the webhook's socket
  directory.
- kind: a pod mounting the node's `/run` refused at deploy.
- CI on each change: the matrix, kind, the SELinux cell, and every suite on
  Rocky Linux 9 and Amazon Linux 2023 hosts, amd64 and arm64.

## Upgrading

From 1.36.0, 1.36.1 or 1.36.2, upgrade `varek-crds` first, then `varek`:

```sh
helm upgrade varek-crds oci://ghcr.io/kwdoug63/charts/varek-crds --version 1.36.3 -n varek-system
helm upgrade varek oci://ghcr.io/kwdoug63/charts/varek --version 1.36.3 -n varek-system
```

The CRDs do not change. From 1.36.0 or before, give the CRDs to the
`varek-crds` release first, as `RELEASE-v1.36.1.md` says ("Upgrading").

A pod that mounts the socket's directory, or one above it, is refused when
it is next created: look for one before upgrading, outside VAREK's own
namespace:

```sh
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{range .spec.volumes[*]} {.hostPath.path}{end}{"\n"}{end}' |
  grep -E ' (/|/run|/var/run|/run/varek-node|/var/run/varek-node)/?( |$)'
```

On a host, build and install the v1.36.3 tag as before
(`docs/install/rhel9.md`, `varek/v1_4/README.md`); nothing changes there.
