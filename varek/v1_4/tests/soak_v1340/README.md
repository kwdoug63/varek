# v1.34's 24-hour runs: Amazon EKS and OpenShift

Step 9 of `docs/security/v1.34-kubernetes.md`, the ship gate: a 24-hour run
on Amazon EKS and on OpenShift of agents in pods under the node agent, the
pods passing Pod Security's "restricted" level with no added capability,
every guarantee the Warden gives on a host either held or refused with the
reason named.

## What runs

`soak.sh` installs the chart (the release `varek`, in `varek-system`, the
node's key and anchor given) and then, for `--hours`:

| What | Where | Each |
|---|---|---|
| A long agent pod on each node (`long-N`) | `varek-soak`: "restricted", a policy required | a turn a minute for the whole run: writes its project's files, runs `python3`, every fifth turn `git commit`, calls the allowed service by its name; every tenth turn a probe |
| A short Job every 15 minutes (`short-...`) | the same | a minute of turns and probes, then it ends: containers started and ended under the node agent all run |
| The allowed and the denied service (`servers.py`) | `varek-soak-svc`, unsupervised | logs each request it is sent |

Each agent pod names the VarekPolicy `agent` (`policy.txt`: the
`python:3.12-bookworm` image's system read, its project, `python3` and git
to launch, the allowed service by its name) and VAREK's unsupervised seccomp
profile. Its probes, in turn, each to be refused or not to reach its server:
`/etc/shadow`; a file in a volume the policy names not; a program it wrote
(a copy of `true`); the denied service by name, and by its address; the
instance metadata service (169.254.169.254).

Every 5 minutes it records the pods, the finished pods' logs and each
node's VAREK processes' memory; each node's exporter log is followed
throughout, across the kubelet's rotations of it, for its audit events and
errors. At the end it collects each node's streams and anchor, and `soak_check.py` judges the run: every turn
done and every probe held, the denied service reached by nothing, one
stream per agent container, each audited (signed with the node's key,
anchored), each run's audit passed in the exporter's log, VAREK's own pods
not restarted, the node agent's memory flat. It writes `report.txt` (a
table as v1.32's 24-hour run's).

The same harness runs for six minutes on kind in CI (`kubernetes.yml`, job
`soak`) on every change, and `crio_trial.sh` runs the agent and its policy
on one CRI-O host (`sudo varek/v1_4/tests/soak_v1340/crio_trial.sh`).

**Sizes.** A long agent writes about 338 records a turn (its python3 and
git), some 440,000 in a day, about 245 MB on its node; the exporter audits
each stream whole at its end, about 3.7 KB of memory a record (1.6 GB and
some 4 minutes for a day's, within its 2 GiB; a follower in that audit is
given an hour). `soak.sh` waits for those last audits before it collects.

## What it needs

- Where `soak.sh` runs: this checkout built (`make -C varek/v1_4 all`),
  `kubectl` and `helm`, `python3`, Docker (to build the node image), and a
  host that stays up for the 24 hours (the sampling runs from it): the
  droplet, or a small instance in the cluster's region, not a laptop.
- **EKS**: an AWS account, `aws` and `eksctl`. The nodes run Amazon Linux
  2023, whose containerd is 2.2 or later.
- **OpenShift**: OpenShift 4.22 or later (CRI-O 1.35; earlier CRI-O's NRI
  cannot set a container's seccomp policy), and a Red Hat account: either
  Red Hat OpenShift Service on AWS (ROSA, hosted control planes) or a
  single-node OpenShift on one EC2 instance.

Prices as of mid-2026, on-demand, us-east-1; check them before creating
anything.

| Cluster | For about 26 hours |
|---|---|
| EKS: the control plane ($0.10/h), 2 m6i.large ($0.096/h each), a NAT gateway ($0.045/h), 2 × 40 GB gp3, the images pulled | about $10 |
| ROSA HCP: the cluster ($0.25/h), 2 m5.xlarge workers ($0.192/h each, and $0.171/h each to Red Hat) | about $25 |
| Single-node OpenShift (the choice, D11): one m6i.2xlarge ($0.384/h), 120 GB gp3, the installer's load balancers and a NAT gateway in one zone (a 60-day evaluation subscription) | about $15 |

## 1. The images

The node image, from this branch, pushed where the nodes can pull it (ECR
in the cluster's account and region):

```sh
make -C varek/v1_4 all
docker build -f packaging/container/Containerfile --target node -t varek-node:soak .
aws ecr create-repository --repository-name varek-node --region us-east-1
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
docker tag varek-node:soak ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-node:soak
docker push ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-node:soak
```

`docker push` prints the digest (`sha256:...`): give it to `soak.sh` as
`--digest`. The agents' image (`mirror.gcr.io/library/python:3.12-bookworm`)
and the services' are pulled by the nodes from the internet.

## 2. EKS

```sh
eksctl create cluster -f varek/v1_4/tests/soak_v1340/eks-cluster.yaml   # about 20 minutes
kubectl get nodes -o wide                                                # containerd://2.2 or later
```

A six-minute trial first (it must end `soak_check: PASS`):

```sh
varek/v1_4/tests/soak_v1340/soak.sh --image ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-node:soak \
  --digest sha256:... --hours 0.1 --interval 3 --short-every 2 --sample 30 --out /var/tmp/varek-soak-eks-trial
```

If it stops at "the plugin did not register on every node", the nodes'
containerd has NRI off: the plugin's log (`kubectl -n varek-system logs
ds/varek-node -c plugin`) says why.

Then the 24 hours, detached (a second release of the same chart on the same
cluster is the trial's, upgraded in place; its namespaces' pods are
replaced):

```sh
kubectl delete namespace varek-soak varek-soak-svc --wait
setsid nohup varek/v1_4/tests/soak_v1340/soak.sh --image ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-node:soak \
  --digest sha256:... --hours 24 --out /var/tmp/varek-soak-eks-24h > /var/tmp/varek-soak-eks.out 2>&1 < /dev/null &
tail -f /var/tmp/varek-soak-eks-24h/soak.log      # a line every 5 minutes
```

At the end, `/var/tmp/varek-soak-eks-24h/report.txt`. If the steps after the
run were cut short, `soak.sh --check-only DIR` judges a run already
collected.

Then remove everything:

```sh
eksctl delete cluster -f varek/v1_4/tests/soak_v1340/eks-cluster.yaml
aws ecr delete-repository --repository-name varek-node --region us-east-1 --force
```

## 3. OpenShift (single-node, on AWS)

Decided October 21, 2026 (D11): a single-node OpenShift on one EC2
instance, made by `openshift-install` 4.22 or later (CRI-O 1.35) in the
account's Route 53 domain (`soberagents-lab.com`). Its one node is
schedulable, so the run has one long agent. It can run beside the EKS run,
from the same host, in a shell of its own (its own `KUBECONFIG`).

As root on the host, where the EKS image was built and pushed. The tools
(the mirror's `stable-4.22` channel; `openshift-install version` must say
4.22 or later):

```sh
mkdir -p ~/ocp && cd ~/ocp
for t in openshift-install openshift-client; do
  curl -fLO https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/stable-4.22/$t-linux.tar.gz
done
tar xzf openshift-install-linux.tar.gz -C /usr/local/bin openshift-install
tar xzf openshift-client-linux.tar.gz -C /usr/local/bin oc
openshift-install version
```

The pull secret, put on the host by its owner (pasted into the file, then
Ctrl-D; it is not shown again), and an SSH key made for the cluster:

```sh
umask 077; cat > ~/ocp/pull-secret.json
ssh-keygen -q -t ed25519 -N '' -f ~/ocp/varek-sno-ssh
```

The host's AWS access is an instance role, whose temporary credentials the
installer's default mode refuses ("not valid for default credentials
mode"): the cluster runs in manual mode with STS, each component given an
IAM role of its own by the release's `ccoctl`, and no long-lived key
anywhere. The install config (`openshift_sno_config.py --manual`: the
template with the pull secret and key put in, mode 0600), the credential
requests, and the roles (`--create-private-s3-bucket`: the OIDC documents
behind CloudFront, for an account that blocks public buckets):

```sh
cd /root/varek-ocp
REL=$(openshift-install version | awk '/^release image/ {print $3}')
oc adm release extract --command=ccoctl --registry-config ~/ocp/pull-secret.json --to ~/ocp "$REL"
python3 varek/v1_4/tests/soak_v1340/openshift_sno_config.py --manual \
  --pull-secret ~/ocp/pull-secret.json --ssh-key ~/ocp/varek-sno-ssh.pub --dir ~/varek-sno
oc adm release extract --credentials-requests --included --install-config ~/varek-sno/install-config.yaml \
  --registry-config ~/ocp/pull-secret.json --to ~/ocp/credreqs "$REL"
~/ocp/ccoctl aws create-all --name varek-sno --region us-east-1 --credentials-requests-dir ~/ocp/credreqs \
  --output-dir ~/ocp/ccoctl-out --create-private-s3-bucket
```

The manifests, with the roles' and NRI's, and the cluster (about 45
minutes, detached):

```sh
openshift-install create manifests --dir ~/varek-sno
cp ~/ocp/ccoctl-out/manifests/* ~/varek-sno/manifests/ && cp -a ~/ocp/ccoctl-out/tls ~/varek-sno/
cp varek/v1_4/tests/soak_v1340/openshift-nri-master.yaml ~/varek-sno/openshift/99-master-varek-nri.yaml
setsid nohup openshift-install create cluster --dir ~/varek-sno --log-level info \
  > ~/varek-sno/create.out 2>&1 < /dev/null &
tail -3 ~/varek-sno/.openshift_install.log     # until "Install complete!"
```

Then, in that shell only:

```sh
export KUBECONFIG=~/varek-sno/auth/kubeconfig
oc get nodes -o wide                                       # cri-o://1.35 or later
oc debug node/$(oc get nodes -o name | cut -d/ -f2) -- chroot /host cat /etc/crio/crio.conf.d/99-varek-nri.conf
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
passes:

```sh
R=ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-node; D=sha256:...
S=varek/v1_4/tests/soak_v1340/soak.sh
setsid nohup bash -c "$S --openshift --ecr-pull-secret --image $R:soak --digest $D --hours 0.1 --interval 3 \
    --short-every 2 --sample 30 --out /var/tmp/varek-soak-ocp-trial \
  && kubectl delete namespace varek-soak varek-soak-svc --wait \
  && $S --openshift --ecr-pull-secret --image $R:soak --digest $D --hours 24 --out /var/tmp/varek-soak-ocp-24h" \
  > /var/tmp/varek-soak-ocp.out 2>&1 < /dev/null &
```

What is not yet measured on OpenShift, and the trial shows first: the
SELinux labels (the launcher bound into each container, the plugin's and
the exporter's host paths), and the supervised SCC. A failure there is a
container that does not start, not one that runs unsupervised.

Then remove everything: `openshift-install destroy cluster --dir
~/varek-sno` (its instance, load balancers, NAT gateway, volumes and DNS
records), `~/ocp/ccoctl aws delete --name varek-sno --region us-east-1` (the
roles, the OIDC provider, its bucket and CloudFront), then `~/ocp/pull-secret.json` and
`~/varek-sno-install-config.yaml.keep` (both hold the pull secret).

## Files

| File | What it does |
|---|---|
| `soak.sh` | The run: the chart, the services, the policy, the agents, the samples, the collection, the check. |
| `pod_agent.py` | The agents' work and probes (as run B of the shared soak, with the pod's network). |
| `servers.py` | The allowed and the denied service: each logs the requests it is sent. |
| `policy.txt` | The agents' VarekPolicy. |
| `soak_check.py` | Judges a run and writes `report.txt`. |
| `crio_trial.sh` | The agent and its policy on one CRI-O host, under the plugin and the node agent. |
| `eks-cluster.yaml` | The EKS cluster (eksctl). |
| `openshift-nri-worker.yaml`, `openshift-nri-master.yaml` | CRI-O's NRI turned on (a MachineConfig). |
| `openshift-sno-install-config.yaml` | The single-node OpenShift (openshift-install), without its pull secret and SSH key. |
| `openshift_sno_config.py` | The install config with the pull secret and SSH key put in (0600; the secret never printed). |
