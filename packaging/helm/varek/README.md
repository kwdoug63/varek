# VAREK's Helm chart

VAREK on Kubernetes (v1.34, `docs/security/v1.34-kubernetes.md`). Every call
of each container of a pod that names a policy is decided by the Warden under
that policy, as on a host. The chart installs:

- **on each node** (a DaemonSet): the Warden's node agent, the NRI plugin
  (`varek-nri`), which writes each container's filter and adds the launcher,
  and the exporter, which gives each container's stream as OCSF in its log;
- **the `VarekPolicy` resource** (`varek.dev/v1alpha1`), a policy as written
  for the Warden, kept in the pod's namespace;
- **the admission webhook** (`varek-admission`), which refuses a policy the
  Warden does not load and a pod the node agent would refuse at its start.

## Requirements

- Kubernetes 1.30 or later, Linux nodes with Landlock (kernel 5.13 or later).
- A runtime whose NRI lets a plugin set a container's seccomp policy and
  command: **containerd 2.2** or later (EKS, kind), or **CRI-O 1.35** or
  later (OpenShift). With an earlier one the plugin says so in its log and
  supervises nothing.
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
helm install varek oci://ghcr.io/kwdoug63/charts/varek --version 1.34.0 -n varek-system
```

To check the signatures first:

```sh
cosign verify ghcr.io/kwdoug63/charts/varek:1.34.0 \
  --certificate-identity https://github.com/kwdoug63/varek/.github/workflows/container-release.yml@refs/tags/v1.34.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

and the same for `ghcr.io/kwdoug63/varek-node:1.34.0`.

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
        readOnlyRootFilesystem: true
      volumeMounts: [{ name: work, mountPath: /work }]
  volumes: [{ name: work, emptyDir: {} }]
```

The webhook refuses an annotated pod whose containers would be refused at
their start, and says why. A container must:

- turn privilege escalation off;
- not run as root;
- name its command by an absolute path;
- not use the node's network, PID or IPC namespace;
- have a read-only root under a policy that decides launches.

Label a namespace `varek.dev/policy-required=true` to also refuse its pods
that name no policy.

## Values

| Value | Default | |
| --- | --- | --- |
| `runtime` | `containerd` | `containerd` or `cri-o`: where the node agent reads each container's state |
| `image.repository`, `image.tag`, `image.digest` | `ghcr.io/kwdoug63/varek-node`, the chart's version, the signed digest | a digest pins the image whatever its tag points at |
| `node.*` | `/var/lib/varek/policies`, `/var/log/varek`, `/run/varek-node`, `/opt/varek/bin`, `/run/varek` | the node's paths: policies, streams, the node agent's socket, the launcher, each run's control socket |
| `signing.secretName` | `""` | a Secret with `key` and `key.pub` (from `tools/varek_keygen`): each stream signed with the node's key |
| `signing.checkpointEvery` | `256` | a checkpoint every this many records |
| `anchor.enabled`, `anchor.file` | `false`, `anchor` | each run's checkpoints appended to the node's anchor, in the streams' directory |
| `exporter.enabled` | `true` | the streams as OCSF in the exporter's log |
| `nodeAgent.extraArgs` | `[]` | more of the Warden's options |
| `admission.failurePolicy` | `Fail` | while the webhook is down, what it checks is refused, not let in |
| `admission.excludeNamespaces` | `[kube-system]` | not checked (the chart's own namespace never is) |
| `admission.tls.*` | the chart's own CA | or a `kubernetes.io/tls` Secret (`secretName`, with its `ca.crt` or `caBundle`), or cert-manager (`certManager.enabled`, `issuerName`) |
| `openshift.enabled` | `false` | the SecurityContextConstraints for the node agent |

## What it does not do yet

A policy with credentials, sub-agents or `require on-behalf-of` is refused by
the webhook and at the container's start. The node agent does not carry
them yet.

## Tests

```sh
make -C varek/v1_4 test-varek-chart
```

This runs `helm lint` and checks each setting's render. With `KUBECONFORM`
set, each render is also checked against Kubernetes' schemas. The chart
installed on a cluster (kind, in CI) is step 7 of the design note.
