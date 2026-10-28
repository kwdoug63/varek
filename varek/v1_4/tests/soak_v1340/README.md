# The 24-hour runs: Amazon EKS and OpenShift

Step 9 of `docs/security/v1.34-kubernetes.md`, and from v1.36 step 12 of
`docs/security/v1.36-kubernetes-parity.md` the ship gate: 24 hours each on
Amazon EKS (an amd64 node and a Graviton node in one cluster) and on
single-node OpenShift, of agents in pods under the node agent, the pods
passing Pod Security's "restricted" level with no added capability, under a
policy that names a credential, a sub-agent, a confined MCP server and a
plan. Each node's streams are audited under that node's own key, and a
stream of over 1,000,000 records is audited in fixed memory.

## What runs

`soak.sh` installs the chart (the release `varek`, in `varek-system`: each
node's own key, the anchor, the soak's token as a credential, the allowed
service's CA as the trust bundle) and then, for `--hours`:

| What | Where | Each |
|---|---|---|
| A long agent pod on each node (`long-N`) | `varek-soak`: "restricted", a policy required | a turn a minute for the whole run: writes its project's files, runs its build as the sub-agent `builder` (`python3`), has the confined MCP server `files` (`head`) read a note back, calls the allowed service over HTTPS with the token's placeholder, every fifth turn `git commit`; every tenth turn a probe |
| A volume pod on each node (`volume-N`) | the same | 15 reads a second of a file of its project, each a record: the ship gate's stream of over 1,000,000 records |
| A short Job every 15 minutes (`short-...`) | the same | a minute of turns and probes, then it ends: containers started and ended under the node agent all run |
| The allowed and the denied service (`servers.py`) | `varek-soak-svc`, unsupervised | logs each request it is sent; the allowed one (HTTPS) whether it got the token |

Each agent pod names the VarekPolicy `agent` (`policy.txt`) and the
VarekPlan `agent` (`plan.txt`), and VAREK's unsupervised seccomp profile.
The policy says `require plan`, `proxy inspect`, the credential
`soak_token` (a Secret's key the chart mounts in the node agent, given to
`varek-soak` by a VarekCredential), the sub-agent `builder`
(`/usr/local/bin/python3`; the agent itself runs as `python3.12`) and the
confined MCP server `files` (`/usr/bin/head`, its own rules); the egress
proxy swaps the agent's placeholder for the token on the allowed service's
`/turn/` requests alone. The plan names all the policy gives but
`/etc/hostname`. The probes, in turn, each to be refused or not to reach
its server: `/etc/shadow`; a file in a volume the policy names not; a
program it wrote (a copy of `true`); the denied service by name, and by its
address; the instance metadata service (169.254.169.254: the egress proxy's
refusal); `/etc/hostname`, allowed by the policy and outside the plan, read
by the agent and by its sub-agent; `/etc/passwd`, the agent's to read, by
the MCP server; and the placeholder sent on a request no rule gives the
credential to (the server must get the placeholder, not the token).

Every 5 minutes it records the pods, the finished pods' logs and each
node's VAREK processes' memory; each node's exporter log is followed
throughout, across the kubelet's rotations of it, for its audit events and
errors. At the end it collects each node's streams and anchor, and
`soak_check.py` judges the run: every turn done and every probe held; the
token at the allowed service on every turn's request and on no other, and
in no stream, log or export; the denied service reached by nothing; one
stream per agent container, each held to its plan, nothing refused outside
it but the probes' reads, nothing else refused but the probes' calls (and
glibc's nscd); the sub-agent and the server launched and settled; each
stream audited (signed with its node's key as the cluster's VarekNodeKey
list holds it, anchored, each decision under its policy and plan); the
largest volume stream over 1,000,000 records and its audit's memory flat
(within 16 MB from its first tenth to its last); each run's audit passed in
the exporter's log; VAREK's own pods not restarted; the node agent's memory
flat. It writes `report.txt`.

The same harness runs for six minutes on kind in CI (`kubernetes.yml`, job
`soak`, on amd64 and arm64) on every change, its volume pod at 200 reads a
second and its streams in 4 MiB segments. `crio_trial.sh` runs v1.34's
agent and policy (`policy_v1340.txt`) on one CRI-O host.

**Sizes.** A long agent writes about 160 records a turn (its python3, the
sub-agent and the server, git), some 230,000 in a day; a volume pod one a
read, about 1.3 million in a day, some 700 MB on its node, in segments of
256 MiB (the chart's `streams.rotateBytes`). The exporter audits each
stream at its end in bounded memory (about 32 MB, a minute or so for a
million records); `soak.sh` waits for those audits before it collects.
`soak_check.py` audits each again.

## What it needs

- Where `soak.sh` runs: a Linux host that stays up for the 24 hours (the
  sampling runs from it), not a laptop: this checkout built (`make -C
  varek/v1_4 all`), `kubectl`, `helm`, `python3`, `openssl`, and Docker with
  buildx (to build the node image for both architectures).
- **EKS**: an AWS account, `aws` and `eksctl`. The nodes run Amazon Linux
  2023, whose containerd is 2.2 or later.
- **OpenShift**: OpenShift 4.22 or later (CRI-O 1.35; earlier CRI-O's NRI
  cannot set a container's seccomp policy), and a Red Hat account, for a
  single-node OpenShift on one EC2 instance.

Prices as of mid-2026, on-demand, us-east-1; check them before creating
anything.

| Cluster | For about 26 hours |
|---|---|
| EKS: the control plane ($0.10/h), an m6i.large ($0.096/h) and an m7g.large ($0.082/h), a NAT gateway ($0.045/h), 2 × 40 GB gp3, the images pulled | about $9 |
| Single-node OpenShift (D11): one m6i.2xlarge ($0.384/h), 120 GB gp3, the installer's load balancers and a NAT gateway in one zone, the cluster's IAM roles and OIDC bucket behind CloudFront (a 60-day evaluation subscription) | about $15 |

Every command below is one line, ending `# end`, and says where it runs.
`ACCOUNT` is the AWS account's number. The AWS commands set `AWS_PAGER=""`.

## 1. The node image, for both architectures

On the host, as root, from the top of this branch's checkout. The tools,
the emulator for the arm64 half (registered once per boot), a builder that
builds both, and the repository:

```sh
make -C varek/v1_4 all # end
docker run --privileged --rm tonistiigi/binfmt --install arm64 # end
docker buildx create --name varek-multi --use # end
AWS_PAGER="" aws ecr create-repository --repository-name varek-node --region us-east-1 # end
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.us-east-1.amazonaws.com # end
```

The image, both architectures in one manifest list, pushed (the arm64 half
is built under emulation: expect it to take several times the amd64
half's), then the list's digest:

```sh
docker buildx build --platform linux/amd64,linux/arm64 -f packaging/container/Containerfile --target node -t ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-node:soak136 --push . # end
docker buildx imagetools inspect ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-node:soak136 # end
```

The first `Digest:` it prints (`sha256:...`, the list's) goes to `soak.sh`
as `--digest`; its manifests must name `linux/amd64` and `linux/arm64`. The
agents' image (`mirror.gcr.io/library/python:3.12-bookworm`, multi-arch)
and the services' are pulled by the nodes from the internet.

## 2. EKS

On the host, from the top of the checkout. The cluster (about 20 minutes),
then its nodes, one of each architecture, each `containerd://2.2` or later:

```sh
eksctl create cluster -f varek/v1_4/tests/soak_v1340/eks-cluster.yaml # end
kubectl get nodes -L kubernetes.io/arch -o wide # end
```

A six-minute trial first (it must end `soak_check: PASS`):

```sh
varek/v1_4/tests/soak_v1340/soak.sh --image ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-node:soak136 --digest sha256:... --hours 0.1 --interval 3 --short-every 2 --sample 30 --volume-rate 200 --rotate-bytes 4194304 --out /var/tmp/varek-soak-eks-trial # end
```

If it stops at "the plugin did not register on every node", the nodes'
containerd has NRI off: the plugin's log (`kubectl -n varek-system logs
ds/varek-node -c plugin`) says why.

Then the 24 hours, detached. Each command names its cluster
(`KUBECONFIG`), not the shell: a shell that times out comes back without
what was exported in it, and a run on the same host against the other
cluster (section 3) then lands on this one. (It did once, in v1.34: the
OpenShift trial's namespaces deleted, on EKS, the 24-hour run's agents.
`soak.sh` refuses `--openshift` on a cluster that is not OpenShift, and
the converse, before it changes anything.) The trial's namespaces go first
(its release is upgraded in place):

```sh
KUBECONFIG=~/.kube/config kubectl delete namespace varek-soak varek-soak-svc --wait # end
setsid nohup env KUBECONFIG=$HOME/.kube/config varek/v1_4/tests/soak_v1340/soak.sh --image ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-node:soak136 --digest sha256:... --hours 24 --out /var/tmp/varek-soak-eks-24h > /var/tmp/varek-soak-eks.out 2>&1 < /dev/null & # end
tail -f /var/tmp/varek-soak-eks-24h/soak.log # end
```

(a line every 5 minutes). At the end, `/var/tmp/varek-soak-eks-24h/report.txt`.
If the steps after the run were cut short, `soak.sh --check-only DIR`
judges a run already collected.

Then remove everything, on the host:

```sh
eksctl delete cluster -f varek/v1_4/tests/soak_v1340/eks-cluster.yaml # end
AWS_PAGER="" aws ecr delete-repository --repository-name varek-node --region us-east-1 --force # end
```

(the ECR repository after the OpenShift run, which pulls the same image).

## 3. OpenShift (single-node, on AWS)

Decided October 21, 2026 (D11): a single-node OpenShift on one EC2
instance, made by `openshift-install` 4.22 or later (CRI-O 1.35) in the
account's Route 53 domain (`soberagents-lab.com`). Its one node is amd64
and schedulable, so the run has one long agent and one volume pod; it
pulls the amd64 half of the image above. It can run beside the EKS run,
from the same host, in a shell of its own.

On the host, as root. The tools (the mirror's `stable-4.22` channel;
`openshift-install version` must say 4.22 or later):

```sh
mkdir -p ~/ocp && cd ~/ocp && for t in openshift-install openshift-client; do curl -fLO https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/stable-4.22/$t-linux.tar.gz; done # end
tar xzf ~/ocp/openshift-install-linux.tar.gz -C /usr/local/bin openshift-install && tar xzf ~/ocp/openshift-client-linux.tar.gz -C /usr/local/bin oc && openshift-install version # end
```

The pull secret, put on the host by its owner (pasted into the file in the
host's own terminal, then Ctrl-D; it is not shown again, and never goes
anywhere else), and an SSH key made for the cluster:

```sh
umask 077; cat > ~/ocp/pull-secret.json # end
ssh-keygen -q -t ed25519 -N '' -f ~/ocp/varek-sno-ssh # end
```

The host's AWS access is an instance role, whose temporary credentials the
installer's default mode refuses ("not valid for default credentials
mode"): the cluster runs in manual mode with STS, each component given an
IAM role of its own by the release's `ccoctl`, and no long-lived key
anywhere. On the host, from the top of the checkout: the release's
`ccoctl`, the install config (`openshift_sno_config.py --manual`: the
template with the pull secret and key put in, mode 0600), the credential
requests, and the roles (`--create-private-s3-bucket`: the OIDC documents
behind CloudFront, for an account that blocks public buckets):

```sh
oc adm release extract --command=ccoctl --registry-config ~/ocp/pull-secret.json --to ~/ocp "$(openshift-install version | awk '/^release image/ {print $3}')" # end
python3 varek/v1_4/tests/soak_v1340/openshift_sno_config.py --manual --pull-secret ~/ocp/pull-secret.json --ssh-key ~/ocp/varek-sno-ssh.pub --dir ~/varek-sno # end
oc adm release extract --credentials-requests --included --install-config ~/varek-sno/install-config.yaml --registry-config ~/ocp/pull-secret.json --to ~/ocp/credreqs "$(openshift-install version | awk '/^release image/ {print $3}')" # end
~/ocp/ccoctl aws create-all --name varek-sno --region us-east-1 --credentials-requests-dir ~/ocp/credreqs --output-dir ~/ocp/ccoctl-out --create-private-s3-bucket # end
```

The cluster takes one Elastic IP (its NAT gateway's) of the region's 5 (the
default quota; EKS's NAT gateway holds another): the template gives both
pools the one zone. Check first, on the host:

```sh
AWS_PAGER="" aws ec2 describe-addresses --region us-east-1 --query 'length(Addresses)' # end
```

The manifests, with the roles' and NRI's, and the cluster (about 45
minutes, detached), on the host from the top of the checkout:

```sh
openshift-install create manifests --dir ~/varek-sno && cp ~/ocp/ccoctl-out/manifests/* ~/varek-sno/manifests/ && cp -a ~/ocp/ccoctl-out/tls ~/varek-sno/ && cp varek/v1_4/tests/soak_v1340/openshift-nri-master.yaml ~/varek-sno/openshift/99-master-varek-nri.yaml # end
setsid nohup openshift-install create cluster --dir ~/varek-sno --log-level info > ~/varek-sno/create.out 2>&1 < /dev/null & # end
tail -3 ~/varek-sno/.openshift_install.log # end
```

(until "Install complete!"). Then its node (`cri-o://1.35` or later) and
NRI on it, on the host:

```sh
KUBECONFIG=~/varek-sno/auth/kubeconfig oc get nodes -o wide # end
KUBECONFIG=~/varek-sno/auth/kubeconfig oc debug node/$(KUBECONFIG=~/varek-sno/auth/kubeconfig oc get nodes -o name | cut -d/ -f2) -- chroot /host cat /etc/crio/crio.conf.d/99-varek-nri.conf # end
```

On a cluster made without the MachineConfig, `oc apply -f
openshift-nri-master.yaml` and `oc get mcp master -w` until it is UPDATED
(the node reboots).

The node image is the EKS run's, in ECR. OpenShift's node has no ECR
access of its own: `--ecr-pull-secret` makes a pull secret for it from the
host's AWS access (its token lasts 12 hours; the node pulls once).
`--openshift` installs the chart with `runtime=cri-o` and
`openshift.enabled=true`: the node agent's SCC, the plugin, the exporter and
the init container as `spc_t`, the launcher labelled for containers, and the
supervised pods' SCC (`varek-supervised`: restricted-v2 with VAREK's
unsupervised profile admitted), which it gives the agents' service account.
On OpenShift the agents run as the namespace's user, and give `runAsGroup`
(the node agent refuses group 0). The trial, then the 24 hours if it
passes, detached, on the host from the top of the checkout:

```sh
setsid nohup bash -c "export KUBECONFIG=$HOME/varek-sno/auth/kubeconfig; S=varek/v1_4/tests/soak_v1340/soak.sh; R=ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-node:soak136; D=sha256:...; \$S --openshift --ecr-pull-secret --image \$R --digest \$D --hours 0.1 --interval 3 --short-every 2 --sample 30 --volume-rate 200 --rotate-bytes 4194304 --out /var/tmp/varek-soak-ocp-trial && kubectl delete namespace varek-soak varek-soak-svc --wait && \$S --openshift --ecr-pull-secret --image \$R --digest \$D --hours 24 --out /var/tmp/varek-soak-ocp-24h" > /var/tmp/varek-soak-ocp.out 2>&1 < /dev/null & # end
tail -f /var/tmp/varek-soak-ocp.out # end
```

Then remove everything, on the host: the cluster (its instance, load
balancers, NAT gateway, volumes and DNS records), the roles, the OIDC
provider, its bucket and CloudFront, and the two files that hold the pull
secret:

```sh
openshift-install destroy cluster --dir ~/varek-sno # end
~/ocp/ccoctl aws delete --name varek-sno --region us-east-1 # end
rm -f ~/ocp/pull-secret.json ~/varek-sno-install-config.yaml.keep # end
```

## Files

| File | What it does |
|---|---|
| `soak.sh` | The run: the token, the CA, the chart, the services, the credential, the policy, the plan, the agents, the samples, the collection, the check. |
| `pod_agent.py` | The agents' work and probes (as run B of the shared soak, with the pod's network); `--ship-gate`, v1.36's; `--volume`, the large stream. |
| `servers.py` | The allowed and the denied service: each logs the requests it is sent; the allowed one over HTTPS, telling the token from anything else. |
| `policy.txt` | The agents' VarekPolicy (v1.36 step 12). |
| `plan.txt` | The agents' VarekPlan. |
| `policy_v1340.txt` | v1.34's policy, `crio_trial.sh`'s. |
| `soak_check.py` | Judges a run and writes `report.txt`. |
| `crio_trial.sh` | v1.34's agent and its policy on one CRI-O host, under the plugin and the node agent. |
| `eks-cluster.yaml` | The EKS cluster (eksctl): an amd64 node group and a Graviton one. |
| `openshift-nri-worker.yaml`, `openshift-nri-master.yaml` | CRI-O's NRI turned on (a MachineConfig). |
| `openshift-sno-install-config.yaml` | The single-node OpenShift (openshift-install), without its pull secret and SSH key. |
| `openshift_sno_config.py` | The install config with the pull secret and SSH key put in (0600; the secret never printed). |
