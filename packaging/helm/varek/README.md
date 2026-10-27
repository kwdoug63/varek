# VAREK's Helm chart

VAREK on Kubernetes (v1.34, `docs/security/v1.34-kubernetes.md`). Each
container of a pod that names a policy runs with the Warden deciding its calls
under that policy, as on a host, or does not run: its seccomp profile is
VAREK's unsupervised one (every call refused), which only the NRI plugin
replaces, with the Warden's filter. A node without the plugin, or a plugin
that does not answer the runtime in time, leaves the profile in place, and
the container does not start. The chart installs:

- **on each node** (a DaemonSet): the Warden's node agent, the NRI plugin
  (`varek-nri`), which writes each container's filter and adds the launcher,
  the exporter, which gives each container's stream as OCSF in its log, and
  the unsupervised profile, under the kubelet's seccomp root;
- **the `VarekPolicy` resource** (`varek.dev/v1alpha1`), a policy as written
  for the Warden, kept in the pod's namespace;
- **the `VarekPlan` resource** (from 1.35), a plan as written for the Warden,
  kept in the pod's namespace beside its policy;
- **the admission webhook** (`varek-admission`), which refuses a policy the
  Warden does not load, and most of what the node agent would refuse at a
  container's start (the rest fails at the start).

## Requirements

- Kubernetes 1.30 or later, Linux nodes with Landlock (kernel 5.13 or later).
- A runtime whose NRI lets a plugin set a container's seccomp policy and
  command: **containerd 2.2** or later (EKS, kind), or **CRI-O 1.35** or
  later (OpenShift). With an earlier one the plugin says so in its log and
  does not start, and the supervised pods on that node do not run.
- amd64 or arm64 nodes: the release builds the node image for both, as
  one image (v1.36), and the DaemonSet is placed on every Linux node
  (`nodeSelector`). A supervised pod placed on a node without the node
  agent does not run.
- A namespace of its own that admits privileged pods. The node agent is
  privileged on the node, in the node's PID namespace, as Falco and Tetragon
  are.

## Install

The chart and its image are published together, each signed with cosign by
the release workflow (`.github/workflows/container-release.yml`). The chart
pins its image by the digest that was signed.

```sh
kubectl create namespace varek-system
kubectl label namespace varek-system pod-security.kubernetes.io/enforce=privileged
helm install varek oci://ghcr.io/kwdoug63/charts/varek --version 1.35.0 -n varek-system
```

To check the signatures first:

```sh
cosign verify ghcr.io/kwdoug63/charts/varek:1.35.0 \
  --certificate-identity https://github.com/kwdoug63/varek/.github/workflows/container-release.yml@refs/tags/v1.35.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

and the same for `ghcr.io/kwdoug63/varek-node:1.35.0`. From v1.36 the node
image is one image for amd64 and arm64, and each architecture's is also
tagged `:<version>-amd64` and `:<version>-arm64`, signed the same way, with
its bill of materials attested on it (`cosign verify-attestation --type
cyclonedx` on that tag, with the same two options).

On OpenShift (CRI-O), add `--set runtime=cri-o --set openshift.enabled=true`.
This creates a SecurityContextConstraints that only the node agent's service
account may use.

## A supervised pod

```yaml
apiVersion: varek.dev/v1alpha1
kind: VarekPolicy
metadata: { name: agent, namespace: team-a }
spec:
  policy: |
    require warden 1.29
    allow path /work/
    allow host api.example.com:443
---
apiVersion: v1
kind: Pod
metadata:
  name: agent
  namespace: team-a
  annotations: { varek.dev/policy: agent }
spec:
  containers:
    - name: agent
      image: example/agent:1
      command: ["/usr/bin/agent"]
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        readOnlyRootFilesystem: true
        capabilities: { drop: [ALL] }
        seccompProfile: { type: Localhost, localhostProfile: varek/unsupervised.json }
      volumeMounts: [{ name: work, mountPath: /work }]
  volumes: [{ name: work, emptyDir: {} }]
```

The webhook refuses an annotated pod whose containers would be refused at
their start, and says why. A container must:

- name VAREK's unsupervised seccomp profile (`Localhost`,
  `varek/unsupervised.json`), on the container or the pod;
- turn privilege escalation off;
- drop every capability, and add none;
- not run as root, nor in group 0 (`runAsGroup`, `supplementalGroups`,
  `fsGroup`);
- name its command by an absolute path;
- not use the node's network, PID or IPC namespace, nor share a PID
  namespace with the pod's other containers (`shareProcessNamespace`);
- use the cluster's DNS (no `dnsPolicy: None`, no `dnsConfig.nameservers`):
  the policy's host names are resolved through the pod's DNS server;
- give no runtime class, or one in `admission.runtimeClasses` (a sandboxed
  runtime, Kata or gVisor, does not run the Warden's filter);
- have a read-only root under a policy that decides launches.

A pod's `varek.dev/policy` annotation is not added, changed or removed after
it is created.

Label a namespace `varek.dev/policy-required=true` to also refuse its pods
that name no policy.

## A plan (from 1.35)

A pod can name a plan as it names its policy: a `VarekPlan` of its
namespace, by the annotation `varek.dev/plan: NAME`. The node agent decides
the plan with the pod's policy as each container starts, in the container's
view (each step SATISFIED, or the container does not run), and holds the run
to it: a call the policy allows and no step of the plan covers is refused
(`outside_plan`). A policy that says `require plan` admits no pod that names
no plan.

```yaml
apiVersion: varek.dev/v1alpha1
kind: VarekPlan
metadata: { name: summarize, namespace: team-a }
spec:
  plan: |
    plan 1.35
    action read file_open /work/ open=read
    action api net_connect api.example.com:443
```

and on the pod, beside `varek.dev/policy: agent`, `varek.dev/plan: summarize`.
What the agent's own runtime reads as it starts is held too, so it is a
step as well (`file_open /usr/ open=read` and the like).
The webhook refuses a plan the Warden does not read, a step of a kind the node
agent does not carry yet (`mcp_call`, `subagent`, `credential`: planned for
1.36), a pod naming a plan not in its namespace, and a pod naming a plan
whose policy does not say `require warden 1.35` (a node still on 1.34 during
an upgrade would run it under its policy alone, not held; with that line it
refuses the container). Like the policy's, a pod's `varek.dev/plan`
annotation is not added, changed or removed after it is created.

A plan is bound by its name, as a policy is: each container start (a restart
too) takes the `VarekPlan` of that name as it is then, so whoever may update
`varekplans` in the namespace decides what its pods are held to. The run's
first record names the plan it was held to by its SHA-256
(`run_start.hold.plan_sha256`).

Helm installs a chart's CRDs only when it first installs the chart, so on an
upgrade from 1.34 apply the new one by hand:
`kubectl apply -f https://raw.githubusercontent.com/kwdoug63/varek/v1.35.0/packaging/helm/varek/crds/varekplan.yaml`.

## Values

| Value | Default | |
| --- | --- | --- |
| `runtime` | `containerd` | `containerd` or `cri-o`: where the node agent reads each container's state |
| `image.repository`, `image.tag`, `image.digest` | `ghcr.io/kwdoug63/varek-node`, the chart's version, the signed digest | a digest pins the image whatever its tag points at |
| `node.*` | `/var/lib/varek/policies`, `/var/log/varek`, `/run/varek-node`, `/opt/varek/bin`, `/run/varek`, `/var/lib/varek/export` | the node's paths: policies, streams, the node agent's socket, the launcher, each run's control socket, the exporter's record of what it exported |
| `node.seccompRoot` | `/var/lib/kubelet/seccomp` | the kubelet's seccomp root, where the unsupervised profile is put |
| `node.dnsServer` | `""` | the DNS server the node agent resolves policies' host names through: `""` the cluster's DNS service, looked up at install (`helm template` sees no cluster, and gives none); `none` the pod's own (the webhook keeps it to the cluster's) |
| `nri.runtimeHandlers` | `[runc, crun]` | the runtime handlers whose containers run the Warden's filter; a supervised pod of another is refused by the plugin |
| `signing.secretName` | `""` | a Secret with `key` and `key.pub` (from `tools/varek_keygen`): each stream signed with the node's key |
| `signing.checkpointEvery` | `256` | a checkpoint every this many records |
| `anchor.enabled`, `anchor.file` | `false`, `anchor` | each run's checkpoints appended to the node's anchor, in the streams' directory |
| `exporter.enabled`, `exporter.maxFollowers` | `true`, `64` | the streams as OCSF in the exporter's log; at most this many followed at once |
| `nodeAgent.extraArgs` | `[]` | more of the Warden's options |
| `admission.failurePolicy` | `Fail` | while the webhook is down, what it checks is refused, not let in |
| `admission.excludeNamespaces` | `[kube-system]` | not checked (the chart's own namespace never is): an annotated pod there is not checked, and still does not run unless the plugin adjusts it |
| `admission.runtimeClasses` | `[]` | RuntimeClass names a supervised pod may give: ones whose handler is in `nri.runtimeHandlers` |
| `admission.tls.*` | the chart's own CA | or a `kubernetes.io/tls` Secret (`secretName`, with its `ca.crt` or `caBundle`), or cert-manager (`certManager.enabled`, `issuerName`) |
| `openshift.enabled` | `false` | the SecurityContextConstraints for the node agent |

## What it does not do yet

A policy with credentials, sub-agents or `require on-behalf-of` is refused by
the webhook and at the container's start. The node agent does not carry
them yet.

The node's signing key (`signing.secretName`) is one Secret, given to every
node: a stream says which node wrote it (its `device`), but each node's key
is the same key. A key of each node's own is not made by this chart.

The plugin checks again that a supervised container names the unsupervised
profile where the runtime tells it the container's profile. CRI-O 1.37 does
not, so there the webhook's check is the one.

## Tests

```sh
make -C varek/v1_4 test-varek-chart
```

This runs `helm lint` and checks each setting's render. With `KUBECONFORM`
set, each render is also checked against Kubernetes' schemas. The chart
installed on a cluster (kind, in CI) is step 7 of the design note.
