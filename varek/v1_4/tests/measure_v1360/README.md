# v1.36 step 1: the measurements (runbook)

Step 1 of `docs/security/v1.36-kubernetes-parity.md`. Every decision there
is made (October 26, 2026), but four rest on something not yet measured.
This runbook measures each one before any of v1.36 is built. A finding
that goes against a decision comes back to Ken before the step that
depends on it.

Times are Central. Each command says where it runs.

## What is measured, and where

| | The question | Decision | Where | Cost |
|---|---|---|---|---|
| M1 | Under the systemd cgroup driver, can the node make a group below a container's group, move a process into it, and attribute a call by it? And does the runtime still end the container, groups below included? | D3 | GitHub's hosted runner: a one-node kubeadm cluster, CRI-O and containerd | none |
| M2 | Does the kubelet mount a Secret volume that no container names, where the node can read it? | D5 | the same cluster | none |
| M3 | Can the node agent get a pod's SVID from the node's SPIRE agent, though it is not in the pod? | D5 | the same cluster, SPIRE installed by its Helm chart | none |
| M4 | Does a hosted runner run kubeadm with CRI-O (1.35, 1.36, 1.37, under runc and under crun)? Does it give KVM, so a VM with SELinux enforcing can run in it? | D11 | GitHub's hosted runners | none |
| M5 | What does a flow policy, and a trust bundle, need under the node agent beyond its input file? | D7 | this session: the code | none |
| M6 | Where does the audit's 3.7 KB a record go, check by check? | D9 | this session: the audit on a large stream | none |
| M7 (optional) | M1 on OpenShift's own CRI-O, with SELinux enforcing | D3 | single-node OpenShift on AWS, about 2 hours | a few dollars |

M1 to M4 run as one GitHub Actions workflow, `measure_v1360.yml`, started
by hand (`workflow_dispatch`), on the same hosted runners CI already uses,
so it adds runner minutes and no other cost. The runner is a fresh VM with systemd and cgroup v2, so
kubeadm can build a real one-node cluster on it. `kind` cannot do this:
its nodes are containers, and their cgroups are not a host's.

Running the workflow is Ken's call, as every workflow run beyond reading
logs is. It is added to the repository by a pull request, and only then
can it be started.

## M5 and M6: in this session

**M5, flow policies and trust bundles (D7).** I read the Warden's code
for `--flow-policy` and `--trust-bundle`: what each reads, when, as which
user, and what each opens later in the run. Under the node agent, the
supervisor opens what is the node's before entering the container's
namespaces, so the question is whether either is read only at the start.
The answer goes into the design note as M5. If either needs more than its
input file (for example, a path read later in the container's view),
D7 (a) comes back to Ken.

**M6, the audit's memory (D9).** I make a stream of 1,000,000 records with
the soak's mix: decisions, launches, plan records and a proxy's requests.
I audit it under `tracemalloc`, taking a snapshot after each check, then
write a table: each check, the memory it holds per record, and whether it
looks back over the stream or could keep running state instead. That table
becomes D9's work list.

## M1 to M4: the workflow

Each job builds its cluster from nothing, prints what it measured as
`MEASURE name: value` lines, and uploads its logs.

### M4a: CRI-O on a hosted runner (matrix: 1.35, 1.36, 1.37 × runc, crun)

1. Install CRI-O's packages for that minor version (the CRI-O project's
   own package repository) and kubeadm, kubelet and kubectl at a
   Kubernetes version that CRI-O minor supports.
2. Set the OCI runtime (`runc` or `crun`) in CRI-O's configuration. Keep
   CRI-O's default cgroup manager, which is systemd.
3. `kubeadm init` for a single node, with the systemd cgroup driver.
   Remove the control-plane taint, install a CNI (flannel), and wait for
   the node to be Ready.
4. Run a plain pod and wait for it to run.

Measured: whether each cell gets a Ready node and a running pod, and in
how long.

### M4b: containerd with the systemd driver

As M4a, with containerd 2.2 and 2.3 (the project's release binaries) and
`SystemdCgroup = true`. This is EKS's Amazon Linux 2023 setting.

### M1: a sub-agent's group (D3), on M4a's CRI-O 1.35/runc and on M4b's containerd 2.2

On the node, as root, with a pod running `sleep infinity`:

1. Find the container's cgroup (`/proc/<pid>/cgroup` for its process) and
   print its path. Under systemd it is a scope
   (`crio-<id>.scope`, `cri-containerd-<id>.scope`).
2. Make a group `varek-sub-1` below it, move the container's process into
   it, and enable `pids` below the container's group. This is v1.34's
   step 1 measurement, here under systemd.
3. Start a second process in the container (`kubectl exec`). Read its
   cgroup, and the cgroup id the kernel reports through a pidfd, as the
   Warden attributes a call.
4. `systemctl daemon-reload`, then check that systemd has left the group
   below the scope where it was. systemd owns the scope, and a reload is
   when it would tidy up.
5. Delete the pod. Check that every process in `varek-sub-1` has ended,
   and that the scope and the groups below it are gone.
6. A pod with a CPU and memory limit: check that the kubelet's reported
   usage and the limit's enforcement still cover a process moved below.

Measured: each check, yes or no, with the paths seen.

### M2: an unmounted Secret volume (D5)

A pod declaring a Secret volume `obo-token` that no container mounts. On
the node:

1. Does `/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~secret/obo-token/`
   exist, with the Secret's key in it?
2. Is it mounted before the container's first process runs? A loop on
   the node watches for the directory and the container's start, and
   records which comes first.
3. Is it gone when the pod is deleted?
4. Does any container of the pod see it (`kubectl exec ... ls`)? It
   should not.

Measured: each check, yes or no.

### M3: SPIRE (D5)

SPIRE's server and agent are installed from SPIRE's Helm chart, with the
Kubernetes workload attestor and a registration entry for the test pod's
service account. A process on the node is not in the pod, so attesting the
caller gives the node agent its own identity, not the pod's. SPIRE's
agent has an admin API that lets authorized delegates (a configured list,
by their own attested identity) fetch SVIDs for other workloads by their
process id: the Delegated Identity API. The measurement:

1. Configure a test program on the node as an authorized delegate.
2. Have it ask, by the test pod's process id, for that pod's X.509 SVID.
3. Check that the SVID's SPIFFE ID is the pod's. Then ask for a pod with
   no registration entry, and check that SPIRE refuses.

Measured: whether the node agent can get the pod's SVID this way, and
which SPIRE version and settings it needs. If it cannot, D5's SVID half
comes back to Ken. The token half (M2) stands on its own.

### M4c: KVM on a hosted runner (D11)

1. Is `/dev/kvm` present, and usable once the runner's user is given
   access (a udev rule)?
2. Boot a Fedora Cloud image under QEMU with KVM, cloud-init giving it a
   user and a command that prints `getenforce` and the kernel version to
   the serial console. Check that it says `Enforcing`, and how long the
   boot took.

Measured: whether the matrix's SELinux cell can run in a VM on the
hosted runner (D11 (a)), or must go to a cloud instance.

## M7 (optional): OpenShift

M1 again on single-node OpenShift (CRI-O, SELinux enforcing), with v1.34
step 9's runbook (`tests/soak_v1340/`, SNO on AWS), for about two hours
and then torn down. Only worth doing if M1 passes on CRI-O 1.35 with
systemd but leaves a doubt about SELinux labels on a group made from the
node. Ken's account and Ken's commands; the pull secret is entered by Ken
and never pasted into chat.

## After the measurements

Each result goes into the design note under step 1 ("Measured", with the
date and the run), as v1.34's measurements did. If a finding contradicts a
decision, that decision is put back to Ken with the finding. Otherwise
step 2, the matrix, starts from the workflow's jobs: M4's cells become the
matrix.

## Files (to be written)

- `.github/workflows/measure_v1360.yml`: M1 to M4, started by hand.
- `varek/v1_4/tests/measure_v1360/node_cluster.sh`: the one-node kubeadm
  cluster (CRI-O or containerd, runc or crun).
- `varek/v1_4/tests/measure_v1360/m1_cgroup.sh`, `m2_volume.sh`,
  `m3_spire.sh`, `m4_kvm.sh`: one measurement each, printing `MEASURE`
  lines.
- `varek/v1_4/tests/measure_v1360/m6_audit_memory.py`: the audit's
  memory, check by check.
