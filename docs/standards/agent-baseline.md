# VAREK and Agent Baseline: a control-by-control mapping

**Status:** a draft, published ahead of v1.31.0 (decision D11 in
`docs/security/v1.31-standards.md`). It maps a draft as well: see
"Which Agent Baseline" below.
**Author:** Kenneth Wayne Douglas, MD
**Last updated:** October 13, 2026

[Agent Baseline](https://agentbaseline.org) sets out six outcomes an
enterprise must achieve to run AI agents (Discover, Constrain, Authorize,
Observe, Validate, Respond) and 35 controls that show them. This document
takes each control in turn and says what VAREK does about it, how far that
goes, and what is left to the operator or to other products.

## Which Agent Baseline

- **Version:** `v1.0-draft`, as `whitepaper/controls.yaml` stood at commit
  `f686aeb` (October 13, 2026) of the
  [agentbaseline/agentbaseline](https://github.com/agentbaseline/agentbaseline)
  repository. Public comment closed on September 30, 2026.
- **Identifiers are not frozen.** They freeze at Agent Baseline v1.0 and may
  change until then. This mapping cites the bare identifiers, as the
  standard asks (`AUT-04`, qualified where needed as `agentbaseline.org/AUT-04`),
  and will be checked against v1.0 when it is tagged.
- **Not a certification.** Agent Baseline is not a standard and has no
  conformance program. Nothing here is a claim of conformance, and Agent
  Baseline does not endorse VAREK or this mapping. By Agent Baseline's own
  reading, no single product is a complete implementation; VAREK is not.
- **Attribution.** The control identifiers and titles are quoted from Agent
  Baseline, © its contributors, under the Creative Commons Attribution 4.0
  International license. The rest of each row is VAREK's reading.

## Which VAREK

VAREK supervises one agent run on one Linux host. The Warden decides each
file open and change, connect, request, program launch and system call the
agent makes, with three possible verdicts (SATISFIED, UNSATISFIED and
UNKNOWN), and only SATISFIED is carried out. It records every decision in a
chained, signed stream that `varek audit` checks. It is not a registry, an
approval workflow, a testing product or a detection product, and it does
not see what the agent's model was asked or answered.

Each row names the release a mechanism comes from:

- **v1.27.1 and earlier:** released. The current release is v1.27.1.
- **v1.28.0, v1.28.1 and v1.29.0:** release candidates, built and reviewed
  and awaiting their soaks.
- **v1.31.0:** planned, not built (`docs/security/v1.31-standards.md`).
  A row's v1.31 part says "planned" until it ships.

## The grades

- **Addressed:** VAREK enforces or provides what the control asks, for the
  actions it decides. The row says where that stops.
- **In part:** VAREK covers part of the control. The row names the part,
  and what is not covered.
- **Evidence:** VAREK does not meet the control, but records something
  another system needs to meet it. The row names the record.
- **Not addressed:** outside what VAREK does.

## Summary

| Outcome | Addressed | In part | Evidence | Not addressed |
|---|---|---|---|---|
| Discover (7) | | DIS-06 | DIS-04, DIS-05 | DIS-01, DIS-02, DIS-03, DIS-07 |
| Constrain (4) | | CON-01, CON-03, CON-04 | | CON-02 |
| Authorize (9) | AUT-06 | AUT-01, AUT-02, AUT-03, AUT-04 | | AUT-05, AUT-07, AUT-08, AUT-09 |
| Observe (6) | | OBS-01, OBS-02, OBS-06 | OBS-05 | OBS-03, OBS-04 |
| Validate (4) | | | VAL-01, VAL-03 | VAL-02, VAL-04 |
| Respond (5) | | RES-01, RES-02, RES-03, RES-04, RES-05 | | |
| **All (35)** | **1** | **16** | **5** | **13** |

The weight is on Constrain, Authorize and Respond, and on evidence for
Observe: what one host's enforcement point can do. Discover and Validate
are mostly other products' work.

## Discover

| Control | Grade | What VAREK does | What it does not |
|---|---|---|---|
| DIS-01 Authoritative agent registry | Not addressed | Each run has a run id, and `run_start` records the policy and, with launches decided (v1.27), every program the run may launch by SHA-256. | No stable identifier for an agent across runs, and no registry. |
| DIS-02 Ownership and risk context | Not addressed | | Purpose, owners and risk class are not recorded. |
| DIS-03 Status and decision history | Not addressed | Each run records the policy it ran under by SHA-256, so past runs show which policy version applied. | No operating, approval or exception status. |
| DIS-04 Authoritative component registry | Evidence | Per run: the launch set (each program the policy lets the run launch, by path and SHA-256, v1.27) and each launch made (v1.27); sub-agents (v1.28.1); from v1.31.0 (planned), each MCP server, local or remote. The CycloneDX export lists every object the run was allowed to reach. | No registry of components, owners or sources; models, instructions, skills and plugins are not seen. |
| DIS-05 Agent composition mapping | Evidence | The approved composition (the launch set) and the observed one (each launch and sub-agent) of each run, by SHA-256, in a signed stream. | Finding the runs that used a vulnerable component means searching the streams; VAREK has no index across runs. |
| DIS-06 Effective-access mapping | In part | The policy is the run's effective access: which files, hosts, requests and programs (`varek policy show`), and, from v1.28.0, which credentials by name and store, and the request and header each may go into. From v1.28.1 every record names the user the run acts for (a verified token, with its delegation chain) and the sub-agent that made the call: the authority actually delegated. | What a credential permits at the system it is for; access an agent has outside the supervised run. |
| DIS-07 Automated discovery and reconciliation | Not addressed | The stream (and, from v1.31.0, planned, its OCSF export) is runtime evidence a discovery product can reconcile against. | No discovery. |

## Constrain

| Control | Grade | What VAREK does | What it does not |
|---|---|---|---|
| CON-01 Admission enforcement | In part | Enforces the runtime boundaries: the run is held to its policy from its first call. With launches decided (v1.27), only programs in the launch set run, and from v1.27.1 nothing written during the run can be launched or mapped executable. | Registration, risk classification, approval and validation evidence are not checked before a run starts. |
| CON-02 Toxic capability combinations | Not addressed | A policy can leave out one leg of a combination (for example, no network except named hosts). | Combinations are not modelled or detected. |
| CON-03 Isolated and confined execution | In part | Files (each open and change decided, files opened as the agent's own user from v1.29.0), network (an empty network namespace; each connect decided and dialled by the Warden, v1.21; by host name from v1.24; each HTTP request under inspecting mode, v1.26.1), launches (v1.27), credential delivery (placeholders only, v1.28.0) and system calls (seccomp-BPF and seccomp user-notify: an allowlist, the rest mediated or refused), on the host the agent runs on. From v1.31.0 (planned), each MCP server confined to its own rules. | Compute, duration, process count, persistence and retained state are not limited. The agent shares the host's kernel; the boundary is the Warden's mediation, not a VM. |
| CON-04 Use-case-scoped capability profiles | In part | Policies are files, each run records its policy's SHA-256; v1.29.0 adds a baseline and a profile per known agent, recorded the same way. Sector packs (`varek init --pack`) are profiles per use case. | No central governance or assignment of profiles to teams; no compute or duration scope. |

## Authorize

| Control | Grade | What VAREK does | What it does not |
|---|---|---|---|
| AUT-01 Distinct identity and action attribution | In part | Every decision record names the run, the agent's process, the target as asked and as resolved, the deciding rule and the time. From v1.28.1 it also names the user (a token verified against an issuer the policy trusts), the agent (optionally its SPIFFE ID) and the sub-agent that made the call. | No task or deployment identity. |
| AUT-02 Purpose and task-bound authority | In part | The SMT decision procedure decides each action on its target resource and kind (read, write, connect, request method and path, launch). From v1.28.1 the run's authority lasts only as long as the user's token, by default. | Purpose, task, data scope, limits, jurisdiction and approval conditions are not inputs to a decision. |
| AUT-03 Delegation attenuation | In part | Records each hop: the token's delegation chain (its `act` claims) and each sub-agent, with the user carried to every sub-agent's records (v1.28.1). Within a run a sub-agent is decided by the agent's own rules, so it never holds more than the agent. | Attenuation is not enforced beyond the run, and from v1.31.0 (planned) an operator may give a confined MCP server rules the agent does not have (by choice; lint notes each). |
| AUT-04 Just-in-time credentialing | In part | From v1.28.0 the agent holds only placeholders. The proxy puts a credential's value only into the header an allowing rule names, on a request the Warden decided SATISFIED; the value is never in the agent's memory, environment, files or the stream. Vault dynamic secrets are leased, renewed, and revoked by `varek revoke`. From v1.31.0 (planned), MCP access tokens bound to their server. | Values are fetched at the run's start, not issued per action; whether a credential is short-lived is the store's choice. |
| AUT-05 Independent approval | Not addressed | The Warden is itself a deterministic decision point independent of the agent, for every action it decides; the plan gate decides a declared plan as a whole. | No tier of actions sent to a person or another decision point for approval. |
| AUT-06 Fail-closed authorization and circuit breaking | Addressed | UNKNOWN is never carried out; only SATISFIED is, and only when the independent certificate checker accepts the decision. The Warden refuses to start when its parsers read a policy differently, a required identity is missing or fails its checks (`require on-behalf-of`, v1.28.1), or a credential cannot be fetched (v1.28.0); a malformed report from its helpers stops the run. The plan gate's breaker ends a session after a set number of refused plans (v1.19.0). | Covers the actions VAREK decides; system calls on the allowlist are admitted without a decision. |
| AUT-07 Step-up verification | Not addressed | | |
| AUT-08 Just-in-time authority elevation | Not addressed | | A run's policy is fixed at its start; more authority means a new run. |
| AUT-09 Proof-of-possession credential binding | Not addressed | A placeholder taken from the agent is useless anywhere but that run's proxy (v1.28.0). | The value the proxy sends is whatever the store holds, usually a bearer token; VAREK does not bind it to a holder. |

## Observe

| Control | Grade | What VAREK does | What it does not |
|---|---|---|---|
| OBS-01 Agent-native telemetry | In part | Each record: the principal (v1.28.1), agent and sub-agent, run, the run's composition (v1.27), target, the policy decision (verdict, rule, policy line, certificate), the action as requested and as resolved, and the kernel's result. From v1.31.0 (planned), the tool, resource or prompt of each call to a remote MCP server. | Deployment, task and model are not seen; a call to a local MCP server is seen only through what the server then does. |
| OBS-02 End-to-end correlation | In part | Stable run ids and sequence numbers on every record; the run id in the CycloneDX export. From v1.31.0 (planned), the OCSF export's correlation id and the W3C trace context an MCP request carries. | No trace ids across other systems' events. |
| OBS-03 Behaviour and drift monitoring | Not addressed | A dry run (v1.29.0) and `varek refusals` show what departs from a policy. | No baseline of behaviour, and no detection. |
| OBS-04 Unintended action detection | Not addressed | | Actions a policy allows are not judged against the task. |
| OBS-05 Intent-to-outcome evidence | Evidence | Identities, composition, delegated authority, policy and each action and its result, linked by run id. | Business intent, approvals, validation and the target system's results. |
| OBS-06 Evidence integrity, completeness and protection | In part | Timestamps in nanoseconds; each record chained by SHA-256, with signed checkpoints (Ed25519) and an off-host anchor (v1.16.2); `varek audit` checks the chain, the sequence and the run's counts; the stream, its key and its anchor are refused to the agent by identity (v1.17.0); credential values and tokens are never recorded. | Encryption at rest, retention, deletion and legal hold are the operator's. |

## Validate

| Control | Grade | What VAREK does | What it does not |
|---|---|---|---|
| VAL-01 Agent-specific security testing | Evidence | Run under VAREK, a test shows each action and its verdict; a dry run (v1.29.0) lists everything a policy would refuse. A test can check them against its expected outcomes. | The testing itself. |
| VAL-02 First-party agentic components testing | Not addressed | | |
| VAL-03 Agent-generated artifact testing | Evidence | The stream lists each file the agent created, wrote, renamed or removed (v1.29.0 records changes by name), which tells a tester what the agent produced. | The testing itself. |
| VAL-04 Agent outcome validation | Not addressed | | |

## Respond

| Control | Grade | What VAREK does | What it does not |
|---|---|---|---|
| RES-01 Immediate stop and authority revocation | In part | From v1.28.0, `varek revoke <run>` makes every later decided call UNSATISFIED, clears every credential value the proxy holds and revokes the run's Vault leases; from v1.28.1 the user's token expiring does the same by default. | The agent's process is not stopped (it goes on, held to refusals); what was already sent stays sent; credentials outside VAREK are not revoked. |
| RES-02 Version and component quarantine | In part | A program left out of the launch set, or a deny rule, keeps it from later runs. From v1.31.0 (planned), an MCP server pinned by SHA-256. | No quarantine across hosts or of models, skills or plugins; a policy changes for the next run, not the current one. |
| RES-03 Impact scoping and evidence preservation | In part | The signed stream preserves what the run did; the CycloneDX export lists every object it was allowed to reach, and `varek refusals` what it was refused. | Customers, transactions and records in other systems. |
| RES-04 Safe failure and non-agent fallback | In part | An action that cannot be decided (UNKNOWN) is refused. | No fallback workflow. |
| RES-05 Agentic component rug-pull protection | In part | The launch set is fixed at the run's start by device and inode, with each file's SHA-256 recorded; from v1.27.1 nothing written during the run can be launched. From v1.31.0 (planned), an MCP server's launch file pinned by SHA-256. | Changes between runs are recorded, not blocked; instructions, tool definitions and requested permissions are not seen. |

## Revising this mapping

- When Agent Baseline v1.0 is tagged: identifiers and wording checked, and
  this document moved to cite v1.0.
- When v1.28.0, v1.28.1 and v1.29.0 ship: "release candidate" removed.
- When v1.31.0 ships: its "planned" parts checked against what was built.
- Each revision reviewed by AI review agents for any row that claims more
  than the code does.
