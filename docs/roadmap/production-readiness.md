# VAREK production readiness (plan)

**Status:** Planned, not built. It follows the v1.36 and v1.37 plan
(`docs/roadmap/v1.36-v1.37.md`) and adds no feature. It says what has to
be true before VAREK is offered as production software, and what the
first pilots need from it. Each piece that changes code still gets its own
design note before it is built.
**Author:** Kenneth Wayne Douglas, MD
**Last updated:** October 30, 2026 (Central)

The question (October 29, 2026) was what is left after v1.37 before VAREK
is ready to sell, with the market reached by customers, not by raising
money first. v1.36 and v1.37 answer what a buyer asks of the product
(does it work on our cluster, will our security team see it). This plan
answers what a buyer asks of the vendor: has anyone outside looked at it,
does it hold up at our scale, what does it cost us to run, and what
happens when something breaks.

None of it changes the three-state decision semantics: no extension may
move a genuinely unsafe action to SATISFIED.

## What "production ready" means here

Ready means that each line below is true and has a public record in the
repository: a CI run, a report, or a document.

| # | The buyer's question | Ready when |
|---|---|---|
| R1 | Has anyone outside looked at it? | The free assurance items run in CI, and at least one outside review's findings are published (a pilot's security team, a funded review, or a paid one) |
| R2 | Does it hold up at our scale? | The scale and churn tests below pass and are in the release notes |
| R3 | What does it cost us to run? | The overhead is measured and published per release |
| R4 | Can we upgrade it and roll it back? | Upgrade from the previous release, and rollback, are tested with pods running |
| R5 | What happens when it breaks? | A runbook, a support policy and an advisory process are published |
| R6 | Can our security team use what it records? | v1.37 ships, ordered by the first pilot's SIEM |
| R7 | Can we try it in an afternoon? | A clean EKS or OpenShift cluster to a refused and an allowed pod in under 15 minutes, timed |
| R8 | Has anyone like us run it? | Two pilots finished, at least one with a reference |
| R9 | Why does it need so much privilege? | A page says what the node agent holds and why, and it runs with a named, measured set of capabilities instead of `privileged: true` |

R1 and R8 are the ones money cannot buy quickly, so they start now, with
the design partners (below), alongside the rest.

## 1. Assurance (R1)

The roadmap's assurance list (`docs/roadmap/v1.36-v1.37.md`, "Assurance
before market, without a paid audit") stands. What exists today: the
proxy's parsers are fuzzed under ASan and UBSan in CI
(`make fuzz-proxy-parse`, in `warden-build.yml`); the MCP JSON parser has
a target run by hand. Nothing else on the list is built. The order:

1. **The node agent's JSON first.** It reads the runtime's state from a
   root-owned socket, and the step 12 findings (the reaped runtime, the
   private mount namespace) were in the code around it. A fuzz target for
   `node_receive`'s parser, then the plan parser, the stub resolver's DNS
   parsing and the three policy parsers. All of them under
   ClusterFuzzLite on each pull request, and an OSS-Fuzz application once
   four targets exist.
2. **CodeQL** on the C and Go code on each pull request, and **Coverity
   Scan** weekly.
3. **`test-v1340` and the sweep under ASan and UBSan**, weekly, on the
   matrix's amd64 `kind` cell.
4. **OpenSSF Scorecard** on the default branch, and the **Best Practices
   badge** self-assessed. The badge asks for a documented release and
   advisory process, which R5 writes anyway.
5. **The public bypass challenge** (`docs/security/bypass-classes.md`
   through `SECURITY.md`), credited in the release notes.
6. **The pilots' security teams' findings** (the roadmap's item 6). Each
   pilot's terms ask for them (below). Findings are fixed or answered in
   the open, with the reporter's consent, under `SECURITY.md`'s timelines.
7. **OSTIF and the Sovereign Tech Agency**, applied to once items 1 to 4
   are green, since both ask what a project already does.
8. **A narrow paid review** of the trusted computing base
   (`docs/security/TRUSTED-COMPUTING-BASE.md`) when the first contract
   allows, scoped to the Warden's decision and handover paths, the node
   agent and the egress proxy.

The threat model keeps saying "No human or third-party review has been
made" until item 6, 7 or 8 makes one, and then says which, of what, and
when.

## 2. Scale and churn (R2)

The 24-hour runs test a steady cluster. What a production cluster does
that they do not:

- **Pods per node.** The kubelet's default ceiling is 110 pods a node.
  Fill one node to it with supervised pods, and on EKS go past it where
  prefix delegation allows. Record the node agent's memory and file
  descriptors, and the time each pod takes to start, against an
  unsupervised node.
- **Pods started together.** v1.36's burst check starts 20. Raise it to
  100, after the first open item below (the accept loop receives one
  connection at a time, up to 5 s each).
- **The node agent restarted** with supervised pods running: they keep
  their decisions (fail closed, never open), new pods wait or are
  refused, and nothing is left untied.
- **A node rebooted and drained**: pods return supervised or are refused,
  never unsupervised.
- **The chart upgraded from the previous release with pods running**, and
  rolled back (R4). Helm does not upgrade CRDs, so the test applies them
  as the release notes say, and is the check that the notes are right.
- **A 7-day run** on one platform per release line, after the 24-hour
  runs, with the same report as `soak_check.py`.

Each goes in `varek/v1_4/tests/` beside the soak harness, and its numbers
in the release notes, as the 24-hour runs' are.

## 3. Operations (R3, R4, R5, R7)

- **Overhead, published.** Per supervised call (the time a decision adds),
  per pod (the start time added), and per node (the node agent's and the
  plugin's memory and CPU). The soak reports already hold most of it; one
  table in each release's notes, measured the same way each time.
- **Upgrade and rollback**, tested (above) and written in one page: what
  order, what the CRDs need, what a rollback keeps.
- **A support policy.** Which releases get security fixes (the latest
  release and the one before, recommended), for how long, and how a fix
  reaches them (a patch release, never a silent change).
- **An advisory process.** GitHub security advisories, with a CVE
  requested through GitHub for each one that affects a release. Each
  advisory says what is affected and whether a running pod was
  unsupervised.
- **A runbook.** What a refused pod looks like and how to find why; what
  happens when the node agent is down (pods refused, never run
  unsupervised); how to read and audit a stream; how to rotate a node's
  key; how to remove VAREK from a cluster cleanly.
- **Install in under 15 minutes**, timed from a clean cluster to one pod
  refused and one allowed, on EKS and on OpenShift. Whatever makes it
  longer is the first thing to fix.
- **A limits page** for buyers: what VAREK does not do, in one place,
  from the release notes' Known limits and `bypass-classes.md`.

## 4. The product (R6)

- **The three items open after v1.36's runs**
  (`docs/security/v1.36-kubernetes-parity.md`, step 12), first, before
  v1.37's integrations:
  1. **A tied connection's bundle and container id.** When a connection
     is tied without its runtime (by its parent, or by its first call),
     the policy and the stream's identity still come from what the sender
     says. A root process that reaches the socket could name another
     pod's bundle. Confirming the bundle (by the process's cgroup, or by
     the NRI plugin's word for the container) is the one an outside
     reviewer would find first.
  2. **The accept loop's 5 s receive**, one connection at a time. Receive
     in the forked child, or several at once.
  3. **The plugin's memory on OpenShift**, read from the 24-hour report;
     found and fixed if it grows.
- **The node agent's privilege (R9).** v1.36.0 runs it as `privileged:
  true`, root, in the node's PID namespace. A platform team will set that
  beside supervisors that run inside the pod with no privilege. Answered in
  three steps (`docs/security/node-agent-privilege.md`):
  1. **The page** (written October 30, 2026): what the node agent does that
     needs each right, what the agent pods are spared, and what
     `privileged: true` gives that it does not use.
  2. **A named set instead of `privileged: true`**: eight capabilities
     (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_CHROOT, CAP_SETUID,
     CAP_SETGID, CAP_KILL, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH),
     `hostPID`, SELinux `spc_t`, and a seccomp profile of VAREK's, measured
     on every cell of the matrix. The OpenShift security context constraint
     then no longer allows a privileged container. A v1.37 candidate, built
     with the step 12 items.
  3. **Splitting what holds the rights** from the parsers and the
     decisions, scoped with the review of the trusted computing base
     (section 1, item 8).

  `hostPID`, CAP_SYS_ADMIN and CAP_SYS_PTRACE stay: they are the
  supervision itself, and the page says so plainly.
- **v1.37** (security operations) as planned, with its order set by the
  first pilot: the SIEM the first pilot runs is built and tested first.
- **What a compliance function reads.** The Agent Baseline mapping
  (`docs/standards/agent-baseline.md`) is there. Add one page each for
  the frameworks the pilots answer to, saying which records VAREK makes
  and which control asks for them, and what it does not cover: SOC 2
  (CC6 and CC7), HIPAA's audit controls (45 CFR 164.312(b)), and, for
  banks, the model risk guidance (SR 11-7) as it is read for agents.
  Written with the first pilot's compliance team, not before.

## 5. Pilots (R8, and R1's item 6)

Three to five design partners: teams already running AI agents on
Kubernetes who must show a security or compliance function what those
agents did. Who they are and how they are reached is kept outside the
repository. What the repository holds is the offer and what a pilot
counts as:

- **The offer.** Free for the pilot (60 to 90 days), and a discount on the
  first year's support if they buy. In return: feedback on a fixed
  schedule, their security team's findings from testing it (shared with
  VAREK, published only with their consent), and a reference (named, or
  anonymous with their sector and size) if it meets its criteria.
- **A pilot succeeds when**, on their cluster: the install meets R7; their
  agents run under policy for 30 days with no unsupervised start and no
  outage the node agent caused; their security team can find a given
  agent's actions in their own SIEM or in the audited stream; and the
  findings are in.
- **What VAREK gives each pilot:** a named contact, a response within one
  business day, fixes in a patch release, and a written summary at the
  end.

## Order and why

1. **Now, while v1.36 is tagged:** start the design partners (R8 takes the
   longest), and the assurance items 1 to 5 (free, and the first thing a
   pilot's security team looks for).
2. **v1.36's three open items**, first the bundle confirmation, since it
   is a security finding and the pilots' testers would find it; with them,
   the node agent's named capability set (R9), since both change the node
   agent and are measured on the same matrix.
3. **Scale and churn and operations**, together: the tests produce the
   overhead table, and the runbook comes from what they break.
4. **v1.37**, in the order the first pilot asks for.
5. **The compliance pages**, with the pilots.
6. **OSTIF and the Sovereign Tech Agency** once items 1 to 4 are green;
   **the paid review** at the first contract.

Ready (every row of the table true) is targeted for about twelve weeks
after v1.36.0 is tagged: about four for the open items and the assurance
items, about four for scale, churn and operations alongside v1.37, and the
rest for the pilots to finish. The pilots set the real date.

## Decided

- Nothing yet. This plan is new (October 29, 2026).

## Decisions open, with recommendations

- **The license.** Recommended: the core stays MIT. The pilots, OSS-Fuzz,
  OSTIF and the Sovereign Tech Agency all count on it, and a buyer's
  security team can read what it is testing.
- **What is sold.** Recommended: a support subscription (response times,
  patch releases, upgrade help, the compliance pages kept current), priced
  per cluster or per node. Later, and only if pilots ask: a managed
  evidence service (streams kept and audited off the cluster).
- **The pilots' terms**: free, and a first-year discount (recommended), or
  paid at a low fixed price, which tests willingness to pay sooner but
  finds fewer partners.
- **The support window**: the latest release and the one before
  (recommended), or a long-term release line once there is a paying
  customer to hold it for.
- **Whether to publish the overhead before the pilots** (recommended: yes;
  a buyer will measure it anyway).

## Sources

- `docs/roadmap/v1.36-v1.37.md` ("Assurance before market, without a paid
  audit"; "Order and why").
- `docs/security/v1.36-kubernetes-parity.md` (step 12, "Open after the
  runs, for v1.37"), `RELEASE-v1.36.0.md` (Known limits).
- `docs/security/threat-model.md`, `docs/security/TRUSTED-COMPUTING-BASE.md`,
  `docs/security/bypass-classes.md`, `SECURITY.md`.
- `docs/standards/agent-baseline.md`.
- `docs/security/node-agent-privilege.md` (R9).
- `varek/v1_4/tests/soak_v1340/` (the 24-hour runs' harness).
