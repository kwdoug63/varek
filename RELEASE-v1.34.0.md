# VAREK v1.34.0 — Kubernetes: a Node Agent and a Helm Chart

> **DRAFT.** Not released. These notes are a draft until the ship gate, the
> 24-hour runs with a real agent on Amazon EKS and on OpenShift (step 9 of
> `docs/security/v1.34-kubernetes.md`), has run and its figures are here.
>
> v1.34.0 had a review by AI review agents: seven, each on one part (the
> node agent, in two parts; the strict JSON reader, the OCI filter and the
> launcher; the Go plugin, policy sync and webhook; the chart, images and
> workflows; the tools and tests; the documentation against the code). Its
> findings are fixed or stated as limits (below). A human or third-party
> review has not been done.

Not yet released.

MIT · github.com/kwdoug63/varek

## Summary

v1.32 runs the Warden inside the agent's container, which needs ten
capabilities, a confinement profile of VAREK's and a private cgroup
namespace in the pod: a cluster's admission policy (Pod Security's
"restricted" and "baseline" levels, OpenShift's default constraints)
refuses that pod. From v1.34.0 the Warden can supervise a pod's containers
from outside them, and the agent's pod passes "restricted":

1. **A node agent.** One Warden on each node (a DaemonSet), privileged on
   the node as Falco or Tetragon are, listening on a socket the runtime
   dials. The container's seccomp filter is the Warden's own for its
   policy, in the OCI form, with `SCMP_ACT_NOTIFY` and
   `linux.seccomp.listenerPath`; the runtime hands the filter's
   notification descriptor and the container's state to the node agent as
   it creates the container, and from then on its calls are decided as
   the Warden decides an agent's on a host. Each container has its own
   supervisor, policy and stream. The node agent takes a connection only
   from root running where the runtime runs, and the descriptor only for a
   process the runtime started.
2. **An NRI plugin** (`varek-nri`, containerd 2.2 or later, CRI-O 1.35 or
   later). For each container of a pod annotated `varek.dev/policy: NAME`
   it sets the Warden's filter (written by the Warden, from the policy's
   bytes, which the node agent loads again and holds to their SHA-256),
   puts the launcher first in the command, and makes every writable mount
   noexec. A container it cannot carry is refused, the reason in the pod's
   events.
3. **The launch set in a pod** (D3). Landlock cannot be added to a running
   process from outside, so a small static launcher, `varek-init`, bound
   read-only at `/varek/init`, applies the launch set and runs the
   container's command; the node agent checks it is that file. A policy
   that decides launches needs a read-only root (D4).
4. **A container that is not adjusted does not run.** Each container of a
   supervised pod names VAREK's unsupervised seccomp profile, which
   refuses every call and which only the plugin replaces. With no plugin
   on the node, an old runtime, or a plugin that does not answer in time,
   the container keeps it and does not start (found in review, below).
5. **The pod's network** (D5). The agent has the pod's network namespace;
   every connect and send is decided as on a host, and the stub resolver
   and the egress proxy run inside the pod's namespace, entered by the
   node agent.
6. **Policies as cluster resources** (D7). `VarekPolicy`
   (`varek.dev/v1alpha1`), namespaced, its text the policy as written for
   the Warden. The plugin writes each to the node
   (`POLICY_DIR/<namespace>/<name>.policy`); a pod names a policy of its
   own namespace. An admission webhook refuses a policy the Warden does not
   load, with the Warden's reason, and most of what the node agent would
   refuse at a container's start; a namespace labelled
   `varek.dev/policy-required=true` refuses pods that name none.
7. **Evidence on the node** (D8). One stream per container on the node,
   outside every pod, signed with the node's key and anchored, the policy
   copied beside it; an exporter gives each as OCSF in the DaemonSet's log,
   for the cluster's collector.
8. **A Helm chart**, signed and published with the node image
   (`oci://ghcr.io/kwdoug63/charts/varek`), pinning the image by the
   digest the release signed; OpenShift's security context constraint for
   the node agent.

It changes no policy line. The Warden reports 1.34.0; the grammar stays
1.31 (`require warden 1.34` is refused). On a host nothing changes.

## Tested

- **`make test-v1340`** (as root, under runc): the node agent, the
  plugin's adjustments and the launcher end to end with a stand-in
  runtime, in eight sections: the node agent's options; a container
  under it, and a second; what is refused at the start, the container
  ended; the listener (who may connect, the runtime's exit race, a slow
  peer); the launcher, policies by name and decided launches; the pod's
  network; the evidence and the exporter. It passes, 0 skipped.
- **`kind` in CI** (`.github/workflows/kubernetes.yml`): the chart
  installed on a one-node cluster (containerd 2.2 or later); the webhook's
  refusals from a real API server; a pod in a "restricted" namespace
  supervised (the plugin's filter in place of the unsupervised profile,
  the launcher first, reads and launches decided, a copy written to its
  volume refused); its stream audited and exported; the policy changed and
  deleted; the node agent's pods taken off the node (a supervised pod does
  not run) and back (a new pod supervised).
- **CRI-O** (`tests/v1340_crio.sh`, CRI-O 1.37.2 and runc): the same pods
  under CRI-O, and a container with the unsupervised profile that the
  plugin leaves: it never starts.
- **A real API server** (`tests/v1340_apiserver.sh`, Kubernetes 1.37.0's
  `kube-apiserver` and `etcd`): the CRD, every refusal of the webhook, and
  the plugin's sync, 25 checks.
- **The sweep** (`tests/v1340_sweep.sh`): every suite run twice, once under
  the Warden and once with each agent a pod's container under the node
  agent; every check that differs has its reason listed
  (`tests/v1340_sweep_known.txt`).
- **The chart** (`make test-varek-chart`, 19 tests) and the Go tests.

## Compatibility

- Every v1.31 policy loads unchanged. Under the node agent, a policy with
  credentials, sub-agents (and the MCP servers confined by them) or
  `require on-behalf-of` is refused at deploy and at the container's start.
- Under the node agent every file is opened as the container's user and
  groups, whatever the policy's version (on a host, a policy before 1.29
  has the Warden open allowed files as root).
- New: `varek-nri`, `varek-admission`, `varek-init`, the node image
  (`packaging/container/Containerfile --target node`), the chart
  (`packaging/helm/varek`), `tools/varek_node_export.py`, the Warden's
  `--node-agent`, `--node-streams`, `--node-launcher` and `--oci-filter`.

## Found in review

Seven AI review agents each reviewed one part; each finding was read in the
code before it was fixed (commits `9a05660`, `c956810`).

- **A supervised pod could run unsupervised.** Where the plugin did not
  adjust a container (no plugin on its node, an old runtime, an arm64
  node, or a plugin that did not answer NRI within its 2 s, after which
  NRI creates the container as it was), the pod ran under its own profile.
  NRI's validator does not close this (it counts a plugin that timed out
  as present). Now every container of a supervised pod names VAREK's
  unsupervised profile, required by the webhook and replaced only by the
  plugin; the plugin answers before NRI's deadline, saying why.
- **A runtime reaped before it was read was taken on its parent's word.**
  The node agent's step 7 change, for containerd's runc, which exits
  without waiting, tied the container to the named process's parent
  alone: a root process that could reach the socket could name another
  pod's process and have it supervised or ended. Such a peer is refused.
- **The pod chose the resolver for its policy's host names.** The node
  agent resolved through the container's `resolv.conf`, which `dnsPolicy:
  None` lets the pod's author write. The webhook refuses that, and the
  chart gives the node agent the cluster's DNS service.
- **The webhook read its certificate once,** so a rotation stopped pod
  creation; it reads it again when it changes, and bounds its requests,
  its checks at once and what it keeps.
- **The policy sync listed every policy at once** in the plugin's process
  on every node; it lists them in pages.
- **The exporter started a process per stream without a bound,** and again
  for every stream on a restart; it follows at most 64 at once and records
  what it has exported on the node.
- **A slow peer held the node agent's listener**: one deadline now covers
  a connection's whole state.
- **A PID namespace shared by the pod's containers** let the agent's
  `kill` reach its siblings and its processes outlive the run; such a
  container is refused.
- **A sandboxed runtime** (Kata, gVisor) runs no seccomp listener; the
  plugin refuses its handler, the webhook its runtime class.
- **A pod's policy annotation** could be changed after it was created; the
  webhook refuses that.
- **The audit took any launch set under the launcher**; it now checks the
  set is the command alone and what starts it.
- **The sweep could hide a regression** in a suite listed whole, or a
  pytest error; each listed suite now needs its reason's evidence.
- Smaller: supplementary group 0 refused; the plugin checks the
  container's own namespaces too; `require warden` read on the Warden's
  white space; the webhook's replicas spread, with a disruption budget;
  the plugin and exporter under `RuntimeDefault`; two workflows' tokens
  read only; a nested 16 MiB state read in 0.09 s, not 75 s; two
  zero-length copies from a null buffer; checks that could pass when
  nothing ran.

## Known limits

- **The webhook is part of the guarantee.** Each supervised container must
  name the unsupervised profile; the webhook (`failurePolicy: Fail`)
  requires it in the namespaces it checks. The plugin checks it again
  where the runtime tells it the container's profile; CRI-O 1.37 does not.
  An annotated pod in an excluded namespace (`kube-system` by default) is
  not checked.
- **The exporter audits each stream whole** when its run ends, about 3.7 KB
  of memory a record (measured: 202,857 records, 748 MB, 110 s). Its limit
  is 2 GiB, about 550,000 records: a day of a busy agent's work. A run whose
  audit does not fit is reported not verified, never verified. The streams
  are not rotated on the node (that agent's day: some 250 MB).
- **The node's signing key** is one Secret given to every node.
- **The pod's other containers share its network namespace**: they can
  reach the agent's stub resolver and the addresses its connects go to.
- **The node agent does not read the kernel's filter back**: that the
  filter is the Warden's rests on the runtime's spec, which only the
  node's root writes.
- **Not carried yet**: credentials, sub-agents and confined MCP servers,
  `require on-behalf-of`, plans and the dry run.
- **containerd before 2.2 and CRI-O before 1.35** cannot set a container's
  seccomp policy and command through NRI; the plugin refuses to start
  there, and supervised pods on those nodes do not run.
- **amd64 only**: the node image is built for amd64 and the DaemonSet is
  placed on amd64 nodes.
- A volume with mounts beneath it keeps those submounts executable, and the
  node agent refuses the container (D4).
- Base images, and `kind`'s node image in CI, are taken by tag.
- From v1.32: the image in the pod remains the fallback where the node
  agent cannot run. From v1.31.0: the agent's calls to a stdio MCP server
  are not decided.

## The 24-hour runs

*To be run (step 9): EKS and OpenShift, a real agent, 24 hours each.*

## Upgrading

1. On a host, nothing changes: rebuild (`make all`) and reinstall.
2. On a cluster: install the chart into a namespace of its own that admits
   privileged pods (`packaging/helm/varek/README.md`), check its
   signatures first with `cosign verify`.
3. Create a `VarekPolicy` in the agent's namespace, annotate the pod
   `varek.dev/policy: NAME`, and give each container
   `seccompProfile: {type: Localhost, localhostProfile:
   varek/unsupervised.json}`; the webhook says what else is missing.
