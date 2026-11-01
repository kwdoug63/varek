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
- **the `VarekCredential` resource** (from 1.36), cluster-scoped: a credential
  a policy names, given from one source to the namespaces whose policies may
  name it;
- **the admission webhook** (`varek-admission`), which refuses a policy the
  Warden does not load, and most of what the node agent would refuse at a
  container's start (the rest fails at the start).

## Requirements

- Kubernetes 1.30 or later (from 1.30 a pod's service account token names
  its node, which a node's key is tied to), Linux nodes with Landlock
  (kernel 5.13 or later). CI runs Kubernetes 1.35, 1.36 and 1.37 (the
  repository README's platform table); earlier versions the chart takes are
  not tested.
- The kubelet's root at `node.kubelet` (`/var/lib/kubelet`): the DaemonSet
  mounts its `pods/` directory, which must exist (a pod acting for a user's
  token is read there), so a node whose kubelet keeps its root elsewhere
  sets `node.kubelet`.
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
helm install varek-crds oci://ghcr.io/kwdoug63/charts/varek-crds --version VERSION -n varek-system
helm install varek oci://ghcr.io/kwdoug63/charts/varek --version VERSION -n varek-system
```

The custom resources (`VarekPolicy`, `VarekPlan`, `VarekCredential`,
`VarekNodeKey`) are a chart of their own, `varek-crds`
(`packaging/helm/varek-crds`), installed first: Red Hat's chart
certification refuses a chart that holds a CRD, and `helm upgrade` changes
a chart's templates where it never changes its `crds/`. Installed on a
cluster without them, this chart refuses and says so (`crds.check`). The
split is from 1.36.1; the charts of 1.36.0 and before hold them: install
one of those alone.

To check the signatures first:

```sh
cosign verify ghcr.io/kwdoug63/charts/varek:1.36.1 \
  --certificate-identity https://github.com/kwdoug63/varek/.github/workflows/container-release.yml@refs/tags/v1.36.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

and the same for `ghcr.io/kwdoug63/charts/varek-crds:1.36.1` and
`ghcr.io/kwdoug63/varek-node:1.36.1`. From v1.36 the node
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
The webhook refuses a plan the Warden does not read, a pod naming a plan not in its namespace, and a pod naming a plan
whose policy does not say `require warden 1.35` (a node still on 1.34 during
an upgrade would run it under its policy alone, not held; with that line it
refuses the container). Like the policy's, a pod's `varek.dev/plan`
annotation is not added, changed or removed after it is created.

A plan is bound by its name, as a policy is: each container start (a restart
too) takes the `VarekPlan` of that name as it is then, so whoever may update
`varekplans` in the namespace decides what its pods are held to. The run's
first record names the plan it was held to by its SHA-256
(`run_start.hold.plan_sha256`).

Helm installs a chart's CRDs only when it first installs the chart: on an
upgrade apply every CRD of the release first (see [Upgrading](#upgrading)).

## Credentials (from 1.36)

A policy names a credential as on a host (`credential gh_token from
file:/var/lib/varek/credentials/gh-token/token`, then `credential=gh_token
header=Authorization` on a request rule). On a node, the node agent fetches
its value with warden-secrets, in the node agent's own network and under the
DaemonSet's identity, and hands it to the proxy in the pod's network. The
agent's pod never holds it: the plugin sets a placeholder
(`VAREK_CRED_GH_TOKEN=varek_ph_gh_token_...`), new for each container, which
the proxy replaces on the requests the policy names.

A cluster administrator gives each credential to namespaces:

```yaml
apiVersion: varek.dev/v1alpha1
kind: VarekCredential
metadata:
  name: gh-token
spec:
  credential: gh_token
  source: file:/var/lib/varek/credentials/gh-token/token
  namespaces: [agents]
```

A pod runs only where a `VarekCredential` gives each credential its policy
names, from the policy's source, to the pod's namespace: the webhook refuses
the pod otherwise, and the node agent refuses the container at its start
(from the list the plugin writes on each node, `POLICY_DIR/.credentials`).
The webhook also refuses a `VarekCredential` whose `file:` source is not
under `credentials.dir`. Whoever may write `varekcredentials` decides which
namespaces' agents may use which values; whoever may write a namespace's
`varekpolicies` decides which requests carry them.

The sources:

- **`file:`**: a key of a Secret of the chart's namespace, named in
  `credentials.secrets`, mounted in the node agent at
  `credentials.dir/<secret>/<key>` (root's, 0400);
- **`vault:`**: `credentials.vault.addr`, with Vault's Kubernetes auth
  (`kubernetesAuth.role`): the node agent's service account's token, which
  the kubelet projects with audience `kubernetesAuth.audience`, logs in as
  that role; `caSecret` names a Secret with `ca.crt` to verify Vault with;
- **`aws-sm:`**: IRSA (`credentials.aws.roleArn`: that role, assumed with a
  projected token of audience `sts.amazonaws.com`), or EKS Pod Identity
  (`credentials.aws.podIdentity`: the role associated with the node agent's
  service account, from the node's Pod Identity agent), or neither: the
  node's instance role (IMDSv2).

The chart writes warden-secrets' configuration from these values (a Secret,
`<release>-node-secrets-conf`). It holds no token or key.

Helm installs a chart's CRDs only when it first installs the chart: on an
upgrade apply every CRD of the release first (see [Upgrading](#upgrading)).

## Sub-agents and confined MCP servers (from 1.36)

A policy names sub-agents (`allow exec PATH subagent=NAME`) and confined MCP
servers (`mcp server NAME exec PATH`) as on a host. The container's own
control group (the runtime's) is the run's: the node agent makes each
sub-agent's group below it from the node, and attributes each call by the
calling process's group, so a sub-agent's calls, and those of everything it
starts, are its own whatever it says. The pod gets no capability and nothing
is delegated to it. A plan's `subagent` and `mcp_call` steps are decided as
on a host (an `mcp_call` to a stdio server is UNKNOWN there too).

The node's own refusals: a sub-agent launched by the container's
first process itself (`subagent_first_process`: that process stays in the
container's group, so a process started in the container later, with
`kubectl exec`, is not put in a sub-agent's), and a container running as
root. A pod's network has none of the kernel's process events, so a
sub-agent of the program its launcher runs is told from a failed launch by
its memory layout, and refused where the node's layouts are not randomized
(`kernel.randomize_va_space` not 2).

## A pod acting for a user (from 1.36)

A policy trusts the user's token's issuer (`trust issuer URL audience AUD
[jwks URL]`) as on a host, and may say `require on-behalf-of`. A pod acting
for a user names the Secret holding the token (key `token`):

```yaml
metadata:
  annotations:
    varek.dev/policy: agent
    varek.dev/on-behalf-of: alice-token
```

The webhook's mutating hook gives the pod a Secret volume of it,
`varek-obo`, and an init container that alone mounts it: the node image,
`/bin/true`, not root, with no privilege and the runtime's default seccomp
profile. The kubelet mounts no volume that no container names, so the init
container is what makes the kubelet keep a copy on the node. The node agent
reads that copy by the pod's uid, under `node.kubelet`'s `pods/` (mounted
read-only, as the kubelet mounts each volume, with HostToContainer
propagation). warden-secrets verifies the token on the node as the Warden's
`--on-behalf-of` does on a host. `run_start` names the user, and every
decision is the user's. No container of the agent's can read the token: the
webhook refuses a pod whose other containers mount `varek-obo`, an ephemeral
container added later that mounts it, an init container of that name other
than its own, and the annotation added, changed or removed after the pod is
created. A pod naming no Secret under a policy that says `require
on-behalf-of` is refused at deploy, and again by the node agent.

An issuer reached over TLS with a private CA, such as the cluster's own
service account issuer, is verified with `onBehalfOf.issuerCaConfigMap`
(`kube-root-ca.crt` for that one). Its discovery document and keys must be
readable by the node agent's pod without credentials. On many clusters that
means binding `system:service-account-issuer-discovery` to
`system:unauthenticated`, as for federation.

The agent's SVID (a policy's `trust spiffe DOMAIN bundle FILE`) comes from
the node's SPIRE agent through its Delegated Identity API. `varek-svid`
asks by the container's process id. Set `spire.adminSocket` (the SPIRE
agent's `admin_socket_path`) and name the node agent's SPIFFE ID among the
SPIRE agent's `authorized_delegates`. Give that ID as `spire.self` too: an
entry selected by the DaemonSet's uid alone also matches the pods'
processes, and varek-svid leaves it out. The trust bundle the policy names
can come from a ConfigMap of the release's namespace
(`spire.bundleConfigMap`, at `/etc/varek/spire-bundle/KEY`). SPIRE's
Kubernetes workload attestor must attest the container's process as soon
as it starts. A configuration that waits for the container's status
(selectors by container image or name) can miss that moment, and the start
is refused. Selectors by namespace, service account and pod label are
attested from the pod alone (`disable_container_selectors = true`).

## A dry run, a flow policy, a trust bundle (from 1.36)

A `VarekPolicy` can say three more things beside its policy, as a host's
Warden takes them on its command line:

```yaml
spec:
  policy: |
    require warden 1.35
    allow path /data/allowed readonly
  dryRun: false          # --dry-run
  trustBundle: corp.pem  # --trust-bundle: a key of trustBundles.configMap
  flowPolicy: |          # --flow-policy
    varek_policy 1
    refusal_budget 2
    session_refusal_budget 10
    ...
```

- **A dry run** decides and records every call and lets through one the
  policy refuses, for `varek policy suggest`. In a pod a connect the policy
  refuses is refused all the same: it would reach the cluster's network
  (other pods, the API server, the instance metadata service). Its record
  says `"dry_run_refused": true`, and suggest reads it as the policy's
  refusal. No launch is held (no writable mount is made noexec, and the
  launcher's Landlock set is `/`, moving files between directories
  granted; on a node whose Landlock is ABI 1, with no REFER right, a move
  between directories is refused all the same). As on a host, a dry run
  takes no plan (a policy that says `require plan` is refused with it), no
  flow policy, credentials or sub-agents. A dry run's listen or accept is
  refused all the same too: the cluster could connect to it.
- **A trust bundle** is the roots inspecting mode trusts in place of the
  node image's. Put the bundles in a ConfigMap of the release's namespace
  and set `trustBundles.configMap`; it is mounted (projected) at
  `/etc/varek/trust-bundles`, and `trustBundle` names a key. Without it, a
  pod's inspecting mode trusts the node image's roots, not its own image's.
- **A flow policy** gates the pod's plan (the pod names one, `varek.dev/plan`)
  with its refusal breaker. The breaker's table is kept on each node, in
  `flowPolicy.stateDir` (a host path), so its budgets bound each node, not
  the cluster: a pod scheduled on another node starts its counts again. Its
  session is the pod's namespace and service account (`NAMESPACE/ACCOUNT`, at
  most 128 characters, or the container is refused), which the plugin reads
  from the API server (the chart gives it `get` on pods, in every
  namespace: RBAC cannot narrow it to the node's own).

## A key for each node (from 1.36)

Each node agent makes its own signing key at its first start
(`signing.nodeKey`). The key stays on the node, root's and mode 0400, in a
directory only the node agent mounts (`signing.nodeKey.dir`; the init
container that makes the directory, root's and 0700, mounts it too, before
any key is in it). Its public
key is written apart (`signing.nodeKey.pubDir`), where the plugin and the
exporter read it. The plugin publishes it as the node's `VarekNodeKey`, a
cluster-scoped resource named for the node and the key:

```sh
kubectl get vareknodekeys
NAME                          NODE     KEY                     ADMITTED
node-1-3f9a0c2e71d4b856       node-1   3f9a0c2e71d4b856...     2d
```

- **Only that node publishes it.** The webhook admits a `VarekNodeKey` only
  from the node agent's service account, and only for the node its token was
  given on: the API server gives the node's name with a token bound to the
  DaemonSet's pod (one bound to the node alone is refused). The account's
  token is in the plugin's container alone (`automountServiceAccountToken:
  false`; the plugin's is projected). A key is never changed, has no owner
  (it outlives any), and a node does not remove one; a cluster administrator
  may. The webhook is never skipped for these
  (`failurePolicy: Fail` whatever `admission.failurePolicy` says), since it is
  what ties each key to its node.
- **Each stream names its node** (`run_start`'s `node.node_name`), and is
  signed with that node's key. A node that is taken over signs only as
  itself.
- **To audit a stream**, give the audit the cluster's list:

  ```sh
  kubectl get vareknodekeys -o json > node-keys.json
  varek_audit.py --policy STREAM.policy --checker vdp_cert_check \
      --node-keys node-keys.json --anchor ANCHOR STREAM.jsonl STREAM.jsonl.2 ...
  ```

  The stream's key must be the one listed for its node, and every segment
  of a rotated stream given, in order (`streams.rotateBytes`).
- **A rebuilt node** (its key gone) makes a new key, published as a new
  `VarekNodeKey`; the one before is kept for the streams it signed. The old
  key is retired at the new one's `creationTimestamp`, a time the cluster
  sets, and the audit trusts it only for runs that began before then and
  signed nothing after (a run left unfinished is not finished later with
  the old key). The
  time a run began is the anchor host's when the anchor holds its
  `run_start` with a receive time (`tools/varek_anchor_receiver.sh`);
  otherwise it is the node's own clock, and the report says so.
- **With the anchor on** (`anchor.enabled`), each start of the node agent
  also announces its key there (a `node_key` line, carried by the
  forwarder and stamped by the receiver). `varek_audit.py --list-runs
  --anchor FILE` lists them.

`signing.secretName` instead signs every node's streams with one key, a
Secret (v1.34's way); then no node makes a key of its own.

## Upgrading

Upgrade the CRDs' chart first, then this one:

```sh
helm upgrade varek-crds oci://ghcr.io/kwdoug63/charts/varek-crds --version VERSION -n varek-system
helm upgrade varek oci://ghcr.io/kwdoug63/charts/varek --version VERSION -n varek-system
```

From a chart of 1.36.0 or before, which installed the CRDs from its
`crds/` (owned by no release): give them to the `varek-crds` release before
installing it (`packaging/helm/varek-crds/README.md`), then install it and
upgrade this chart.

Charts of 1.36.0 and before: Helm installs a chart's CRDs only when it
first installs the chart, and never upgrades them. Before `helm upgrade`,
apply every CRD of the release you upgrade to: a CRD left at an older release's schema prunes the fields
it does not know (a `VarekPolicy`'s `dryRun`, `trustBundle` and
`flowPolicy` would be dropped without a word), and a resource it does not
have cannot be made (`VarekCredential`, `VarekNodeKey`):

```sh
V=v1.36.0
for crd in varekpolicy varekplan varekcredential vareknodekey; do
  kubectl apply -f https://raw.githubusercontent.com/kwdoug63/varek/$V/packaging/helm/varek/crds/$crd.yaml
done
```

From 1.35: each node now signs with its own key by default
(`signing.nodeKey`), and streams rotate at 256 MiB (`streams.rotateBytes`);
the chart's `fail`s name a value it cannot render with.

## Values

| Value | Default | |
| --- | --- | --- |
| `runtime` | `containerd` | `containerd` or `cri-o`: where the node agent reads each container's state |
| `image.repository`, `image.tag`, `image.digest` | `ghcr.io/kwdoug63/varek-node`, the chart's version, the signed digest | a digest pins the image whatever its tag points at |
| `node.*` | `/var/lib/varek/policies`, `/var/log/varek`, `/run/varek-node`, `/opt/varek/bin`, `/run/varek`, `/var/lib/varek/export` | the node's paths: policies, streams, the node agent's socket, the launcher, each run's control socket, the exporter's record of what it exported |
| `node.seccompRoot` | `/var/lib/kubelet/seccomp` | the kubelet's seccomp root, where the unsupervised profile is put |
| `node.dnsServer` | `""` | the DNS server the node agent resolves policies' host names through: `""` the cluster's DNS service, looked up at install (`helm template` sees no cluster, and gives none); `none` the pod's own (the webhook keeps it to the cluster's) |
| `nri.runtimeHandlers` | `[runc, crun]` | the runtime handlers whose containers run the Warden's filter; a supervised pod of another is refused by the plugin |
| `signing.nodeKey.enabled`, `.dir`, `.pubDir` | `true`, `/var/lib/varek/key`, `/var/lib/varek/key-pub` | each node agent's own key, made at its first start, and where its public key is written (published as the node's `VarekNodeKey`) |
| `signing.secretName` | `""` | one key for every node instead: a Secret with `key` and `key.pub` (from `tools/varek_keygen`) |
| `signing.checkpointEvery` | `256` | a checkpoint every this many records |
| `anchor.enabled`, `anchor.file` | `false`, `anchor` | each run's checkpoints appended to the node's anchor, in the streams' directory |
| `exporter.enabled`, `exporter.maxFollowers` | `true`, `64` | the streams as OCSF in the exporter's log; at most this many followed at once |
| `exporter.scratchSize` | `4Gi` | the exporter's scratch volume on the node's disk (`/tmp`), where each audit keeps what it holds back as it reads |
| `nodeAgent.extraArgs` | `[]` | more of the Warden's options |
| `admission.failurePolicy` | `Fail` | while the webhook is down, what it checks is refused, not let in |
| `admission.excludeNamespaces` | `[kube-system]` | not checked (the chart's own namespace never is): an annotated pod there is not checked, and still does not run unless the plugin adjusts it |
| `admission.runtimeClasses` | `[]` | RuntimeClass names a supervised pod may give: ones whose handler is in `nri.runtimeHandlers` |
| `admission.tls.*` | the chart's own CA | or a `kubernetes.io/tls` Secret (`secretName`, with its `ca.crt` or `caBundle`), or cert-manager (`certManager.enabled`, `issuerName`) |
| `openshift.enabled` | `false` | the SecurityContextConstraints for the node agent |
| `crds.check` | `true` | refuse to install on a cluster without the `varek-crds` chart's CRDs (checked where the chart installs on a cluster; `helm template` sees none) |
| `credentials.dir`, `credentials.secrets` | `/var/lib/varek/credentials`, `[]` | where a `file:` source is, and the Secrets mounted there |
| `credentials.vault.*` | `addr: ""`, `caSecret: ""`, `kubernetesAuth: {role: "", mount: kubernetes, audience: vault}` | `vault:` sources, signed in to with the node agent's service account |
| `credentials.aws.*` | `region: ""`, `roleArn: ""`, `podIdentity: false` | `aws-sm:` sources: IRSA, EKS Pod Identity, or the node's instance role |
| `node.kubelet` | `/var/lib/kubelet` | the kubelet's root: a pod's user's token is read from its `pods/` |
| `onBehalfOf.user` | `65534` | the token's init container's user and group (on OpenShift, the namespace's) |
| `onBehalfOf.issuerCaConfigMap` | `""` | a ConfigMap whose `ca.crt` verifies the token issuers' TLS (`kube-root-ca.crt` for the cluster's own); `""` the image's trust store |
| `spire.adminSocket`, `spire.self`, `spire.bundleConfigMap` | `""` | the SPIRE agent's admin socket on the node, the node agent's own SPIFFE ID, a ConfigMap holding the trust bundle |
| `flowPolicy.stateDir` | `/var/lib/varek/flow` | where each node keeps a flow policy's breaker table (a host path, root's) |
| `trustBundles.configMap` | `""` | a ConfigMap of trust bundles a `VarekPolicy` names by key (`spec.trustBundle`) |
| `streams.rotateBytes` | `268435456` (256 MiB) | a stream past this size goes on in a new segment beside it (`.jsonl.2`, `.jsonl.3`, ...); 65536 or more, or `0` for none (the chart then leaves the Warden's `--node-stream-rotate` out) |

## What it does not do yet

A node's key is tied to its node by the node's name in the plugin's service
account token, which the API server gives for a token bound to a pod. A
cluster whose tokens do not name their node admits no `VarekNodeKey`; use
`signing.secretName` there.

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
