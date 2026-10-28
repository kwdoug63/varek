# VAREK v1.36.0 — Kubernetes at Parity, and the Supported Platforms

> Draft (October 28, 2026). v1.36.0 had a review by AI review agents, six,
> each on one part (the node agent's C code; the one-pass audit and the
> exports; the cluster's Go code; the Helm chart and its RBAC; CI and the
> test scripts; the docs against the code). Its findings are fixed or
> stated as limits (below). A human or third-party review has not been
> done. The ship gate's 24-hour runs (EKS with amd64 and Graviton nodes,
> and single-node OpenShift) are still to come.

MIT · github.com/kwdoug63/varek

## Summary

v1.34 put the Warden on a Kubernetes node, as a DaemonSet that supervises
the agent containers of annotated pods from outside them. It refused a pod
whose policy needed what it did not carry. From v1.36.0 every policy and
every plan that runs on a host runs under the node agent, decided the same
way; what cannot be carried into a pod from outside is still refused,
never run with less.

1. **Credentials** in pods (D1, D2). The node agent runs warden-secrets in
   the node's network, under the DaemonSet's identity: `file:` sources
   from the chart's Secrets, `vault:` through Vault's Kubernetes auth,
   `aws-sm:` through IRSA, EKS Pod Identity or the node's role. A
   cluster-scoped `VarekCredential` gives a credential, from one source,
   to the namespaces whose policies may name it. The pod holds only a
   placeholder the NRI plugin sets; the proxy in the pod's network swaps
   in the value.
2. **Sub-agents and confined MCP servers** in pods (D3, D4): each
   sub-agent's group is made below the container's own, and each call is
   attributed by it, as on a host. A plan's `mcp_call`, `subagent` and
   `credential` steps are decided as on a host.
3. **The on-behalf-of chain** in pods (D5): the user's token is a Secret
   the pod names (`varek.dev/on-behalf-of`); the webhook gives the pod the
   token's volume and init container, the node agent reads the kubelet's
   copy, and the agent's SVID comes from the node's SPIRE agent by the
   container's process (`varek-svid`, the Delegated Identity API).
4. **The dry run, flow policies and trust bundles** in pods (D6, D7),
   each a `VarekPolicy`'s field (`dryRun`, `flowPolicy`, `trustBundle`). A
   dry run's refused connects are refused in a pod all the same
   (`dry_run_refused`): they would reach the cluster's network.
5. **arm64** (D8): the node image is one image for amd64 and arm64, each
   built and checked on its own runner, and the DaemonSet runs on every
   Linux node of either.
6. **An audit in bounded memory** (D9): the audit (`varek audit`,
   `tools/varek_audit.py`) reads a stream once,
   in memory bounded by the policy and the plan, not the stream (1,008,566
   records: 31,960 kB at most, flat from the first tenth to the last;
   v1.35.0's audit of the same stream: 3.6 GB). The node agent rotates
   each stream at a size the chart sets (256 MiB by default), each segment
   beginning with a signed checkpoint naming it and the chain value the
   one before ended on.
7. **A key for each node** (D10): each node agent makes its own signing
   key; the NRI plugin publishes it as the node's `VarekNodeKey`, which the
   webhook admits only from that node. `tools/varek_audit.py --node-keys`
   checks a stream's key against the cluster's list; a rebuilt node's old key is
   trusted only for runs that began before its next key was admitted.
8. **The supported platforms, tested** (D11): each platform the README
   calls supported runs in CI, and the README's table names each job:
   CRI-O 1.35, 1.36 and 1.37 under runc and crun, and containerd 2.2 and
   2.3, on amd64 and arm64; SELinux enforcing (CRI-O 1.35 on Rocky Linux
   9); every host suite on Rocky Linux 9 (standing for RHEL 9) and Amazon
   Linux 2023; kind.

The Warden's grammar is unchanged (D12): every carried feature is written
as it is on a host. A 1.35 node agent refuses a pod needing one, so an
upgrade in progress refuses rather than runs with less.

## Tested

- **`make test-v1340`** (as root): the node agent's sections, one for each
  carried feature (sections 10 to 15: credentials, sub-agents and MCP
  servers, the on-behalf-of chain, the dry run with flow policies and trust
  bundles, streams in segments, the node's key); 274 checks, 0 skipped.
- **The sweep** (`tests/v1340_sweep.sh`, every suite, once under the Warden
  and once as pods under the node agent): 2,872 checks hold in both, 121
  differ, each with its reason listed, none unlisted.
- **The regression count against v1.35.0**: every suite run under the
  Warden at v1.35.0 and at this release, in the same container, compared
  by name: 2,846 checks passed then, 2,993 now, none that passed then
  fails now. `test_v1210`'s three Python `requests` checks fail in the
  test container in both, as before.
- **The audit's verdicts**: every audit the host suites ran on v1.35.0,
  replayed with this release's audit: 375 of 377 the same report byte for
  byte; of the two left, a tampered stream is refused by both (this audit
  names one problem more), and a forged dry-run record is refused by both
  in other words (the review's wording). The same verdict in all 377.
- **The cluster**: on kind and on each matrix cell, `v1340_kind.sh` (each
  carried feature as pods, and a node rebuilt with a new key); the Go
  tests; the chart's tests (36); `v1340_apiserver.sh` against a real API
  server.
- **The ship gate's runs**: to come (step 12).

## Compatibility

- Every v1.35 policy and plan loads unchanged; the grammar is v1.35's.
- **The chart's defaults change.**
  - Each node signs its streams with its own key (`signing.nodeKey`);
    before, nothing was signed unless `signing.secretName` named a Secret.
    `signing.secretName` still signs every node with one key.
  - Streams rotate at 256 MiB (`streams.rotateBytes`; `0` for none). Audit
    a rotated stream with all its segments, in order, or put together.
- **New CRDs**: `VarekCredential` and `VarekNodeKey`; `VarekPolicy` gains
  `dryRun`, `trustBundle` and `flowPolicy`. Helm does not upgrade CRDs:
  apply every one of `crds/` by hand before the upgrade. A `VarekPolicy`
  CRD left at 1.35's schema drops those three fields without a word (the
  API server prunes what its schema does not name).
- **The DaemonSet's service account token** is no longer in every
  container (`automountServiceAccountToken: false`): the plugin, the one
  container that reads the API server, has it projected. The account no
  longer gets VarekCredentials one by one (it lists and watches them).
- **The chart refuses at render** what the node would refuse or expose: a
  `streams.rotateBytes` under 65536 (other than 0), the node key's
  directories inside each other or inside another mounted directory, a
  path that is not absolute. A credential's Secret volume is named by its
  place (`cred-0`, ...), so a Secret's name may hold dots.
- **The exporter's `/tmp`** is a scratch volume on the node's disk
  (`exporter.scratchSize`, 4Gi), where the audit keeps what it holds back.
- **New records and fields**: `run_start`'s `node.node_name`; a segment's
  checkpoint (`segment`, `prev_chain`); `dry_run_refused` under the node
  agent; the anchor's `node_key` line. An audit of a v1.35 stream is as
  before.
- **On CRI-O**, install the chart with `--set runtime=cri-o`: with the
  default, every supervised container is refused (the node agent cannot
  read its bundle's `config.json`).

## Found in review

Six AI review agents read v1.36's changes against v1.35.0, each one part.
Every finding was checked against the code; those that held were fixed, or
are stated below as limits. The largest:

- **The node's account token in every container** (chart, high): the
  exporter could have published a node's key with it, and a credential's
  process signed in with it. The token is now in the plugin alone.
- **The user's token's init container could be changed** (cluster, high
  twice): the webhook took extra mounts and securityContext keys in
  `varek-obo` (a volume of the pod's at `/bin` would have run the pod's own
  program with the token readable), and an update could change its image,
  which the runtime does not tell the NRI plugin. The webhook now takes the
  token's mount and the service account's alone and only the keys it sets,
  refuses any change to the container after creation, and refuses another
  volume, projected volume or environment variable naming the token's
  Secret; the plugin checks the init container against the API server's
  copy of the pod as well.
- **The upgrade instructions** named one new CRD (docs, high): a
  `VarekPolicy` CRD left at 1.35's schema would have dropped a policy's flow
  policy without a word. Every CRD is now named.
- **`--node-keys` was not checked on a stream with no hash chain** (audit,
  high): such a stream passed with any list, or none. Now refused, as
  `--pubkey` is.
- **A retired key** could finish a run begun before its retirement; the
  audit now refuses a run signed after its key was retired (past
  `--clock-slack`). Two keys of a node admitted in the same second now
  retire each other then.
- **The node's key** was admitted from a token bound to the node alone; the
  webhook now asks for one bound to the DaemonSet's pod, refuses an owner on
  a key (the collector would remove it with its owner), and refuses the
  node agent's own update of one.
- **In a pod's dry run, a listen or accept was let through** (node agent):
  the cluster could connect to it. Refused all the same now, as a refused
  connect is (`dry_run_refused`). A container that mounts its pod's
  `varek-obo` volume is refused by the node agent too.
- **The audit**: a malformed connection id or process id crashed it rather
  than failing it (it fails it now, with the problem); a stream's DNS names
  were asked of the checker one at a time (5,000 names: 7.7 s; now in
  batches, 0.2 s), and scattered connection ids made its id set slow.
- **The Warden still reported 1.35.0** (D12 said 1.36.0); it reports 1.36.0,
  the grammar staying 1.35.
- **A refusal named more than its author gave**: the namespaces a
  credential is given to, and another source's resource name. It names
  neither now.
- **The release did not wait for the matrix** (CI): a tag published its
  images and chart whatever the matrix said. It now runs both matrices on
  the tag's commit, and publishes nothing unless every cell passes. The
  arm64 image was pushed unsigned while the rest was built; it is signed
  as it is pushed. The matrices' actions are pinned by commit, a host cell
  fails on a check it skips unexpectedly, the SELinux cell on SELinux not
  enforcing at the end, and the test cluster's downloads are pinned by
  SHA-256.

## Found building the ship gate's runs

- **A connection the egress proxy could not read left no record of its
  refusal** (fixed). The proxy refuses a connection whose head it cannot
  read: an HTTP `Host` that is an address (the instance metadata service,
  `169.254.169.254`, asked for on port 80 under inspecting mode), no whole
  request within 10 s, a TLS hello without a name. The stream held the
  connect, allowed and handed to the proxy, and nothing after it; only the
  Warden's log said it was refused. Each is now a chained
  `proxy_unreadable` record (the connection, what the proxy read it as,
  its reason). The audit takes it in place of the hand-off's decision,
  once for each hand-off. `varek refusals` lists it as UNREADABLE, and the
  OCSF export writes it as a Network Activity refusal (Denied, Blocked) to
  where the agent connected.

## Known limits

- **A flow policy's breaker counts per node**, not across the cluster: a
  pod scheduled on another node starts its counts again.
- **A dry run in a pod refuses the connects its policy refuses**, unlike a
  host's, since they would reach the cluster's network; `varek policy
  suggest` reads those refusals as the policy's.
- **A sub-agent launched by the container's first process is refused**
  (`subagent_first_process`): that process is never moved out of the
  container's group. An agent that `exec`s itself into a sub-agent does not
  run its sub-agent in a pod.
- **A node's key is tied to its node** by the node's name in the plugin's
  service account token, which the API server gives for a token bound to a
  pod. A cluster whose tokens do not name their node admits no
  `VarekNodeKey`; use `signing.secretName` there.
- **The anchor's `node_key` line is the node's own announcement**; the
  audit relies on the cluster's list (`--node-keys`), kept with the
  evidence by whoever audits.
- **A retired key's time** is the run's start as the anchor host received
  it when the anchor holds it, else the node's own clock, which a node
  taken over can set; the report says which.
- **CRI-O 1.37 does not tell the plugin a container's seccomp profile**, so
  there the webhook's check that each supervised container names VAREK's
  unsupervised profile is the only one.
- **RHEL 9 is tested on Rocky Linux 9**, whose images need no
  subscription.
- **Kubernetes 1.30 to 1.34** are taken by the chart (from 1.30 a pod's
  token names its node) and not tested; CI runs 1.35, 1.36 and 1.37.
- **With EKS Pod Identity**, EKS's own webhook puts the Pod Identity token
  in every container of the DaemonSet, not the node agent's alone; the
  plugin and the exporter do not use it. With neither IRSA nor Pod
  Identity, warden-secrets uses the node's instance role through IMDSv2,
  which the node agent's pod reaches only where the instance's metadata
  hop limit allows a pod to.
- **The plugin gets pods in every namespace** (a flow policy's session):
  RBAC cannot narrow a grant to the pods of one node.
- **The admission webhook answers whoever reaches its service**: the API
  server's calls are not told from others', and a refusal says why. Keep
  its namespace's ingress to the API server with a NetworkPolicy where that
  matters.
- **A policy's `trust issuer`** discovery document and keys are fetched by
  the node agent, from its pod's network: a policy's author chooses where
  it connects (as on a host, where the Warden's host does).
- **The pod's SVID** is the one SPIRE gives for the container's process,
  the node agent's own left out; it is verified against the policy's trust
  domain and bundle, not against an expected ID.
- **The CRDs' schemas check less than the webhook** (the names and sources
  a policy may use); the webhook's checks are the binding ones.
- **A container starting while its VarekPolicy changes** may be refused:
  the plugin writes a policy's files one at a time, and the node agent
  checks each against the SHA-256 the plugin annotated.

## Upgrading

1. Apply the new CRDs (`kubectl apply -f packaging/helm/varek/crds/`).
2. Upgrade the chart. Each node agent makes its key at its first start and
   the plugin publishes it; check with `kubectl get vareknodekeys`.
3. Audit with the cluster's list: `kubectl get vareknodekeys -o json >
   node-keys.json`, then `tools/varek_audit.py --policy STREAM.policy
   --checker tools/vdp_cert_check --node-keys node-keys.json STREAM.jsonl`
   (with `--anchor` for the anchor host's times).
4. On CRI-O, keep `--set runtime=cri-o`.
