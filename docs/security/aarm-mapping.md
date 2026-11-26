# VAREK and the AARM specification: a mapping

Status: draft, current as of v1.41.0 (November 2026), with v1.42.0's STEP_UP and DEFER as built (`docs/security/v1.42-step-up-defer.md`, steps 1 to 8; not yet released, and their conformance tests in `mode=hold` are step 9's). **VAREK does not claim AARM conformance.** This page maps each AARM requirement to what VAREK does today, with the code and the test behind each claim. It also names what is missing.

## The specification, and the version checked

AARM (Autonomous Action Runtime Management) is an open system specification for runtime security of AI agents. It defines what a system must do, not how to build it.
- **Author:** Herman Errico.
- **Published:** arXiv:2602.09433, February 2026, CC BY 4.0.
- **Maintained by:** the Cloud Security Alliance's AARM Technical Working Group.

This mapping checks:
- **Spec v1.0:** the paper, and the specification at https://aarm.dev/spec. Its source is https://github.com/aarm-dev/aarm, checked at commit `98494ec`, November 10, 2026.
- **The conformance page** at https://aarm.dev/conformance, and the component and pattern documentation in https://github.com/aarm-dev/docs.

v2.0 is announced as coming soon. It extends the threat model and adds multi-agent coordination and long-horizon task requirements. Check each row again when it's published.

### What "AARM-conformant" means

Requirements R1 to R6 are MUST. Meeting all six is **AARM Core**; meeting R1 to R9 (adding three SHOULDs) is **AARM Extended**. The paper allows a claim of partial conformance that names the requirements met. Only a system meeting every MUST may be called AARM-compliant.

Public use of "AARM-conformant" now also requires all of the following:
- an evidence package following the CSA's *AARM Conformance Testing Protocol*, reviewed by the Technical Working Group;
- an active representative in the AARM community;
- production use: at least 5 customers for at least 3 months;
- a recognised security certification (SOC 2 Type II, ISO 27001 or FedRAMP);
- a commitment to its benchmarking.

This page is none of those. It is VAREK's own reading, so that a reader can check each row.

## Summary

| | Requirement | Level | VAREK v1.41.0, and v1.42.0 as built |
|---|---|---|---|
| R1 | Pre-execution interception | MUST | **Met for ALLOW and DENY.** v1.42.0: STEP_UP and DEFER held at the kernel or the proxy (`mode=hold`). |
| R2 | Context accumulation | MUST | **Partly.** v1.42.0 records the original request. |
| R3 | Policy evaluation with intent alignment | MUST | **Partly.** v1.42.0: DEFER on missing context, STEP_UP where a person decides. |
| R4 | Five authorization decisions | MUST | **v1.41.0: not met** (ALLOW and DENY; MODIFY only for credentials). **v1.42.0: four of five,** adding STEP_UP and DEFER; MODIFY still only for credentials. |
| R5 | Tamper-evident receipts | MUST | **Largely met;** v1.42.0 adds approval and deferral receipts. |
| R6 | Identity binding | MUST | **Largely met;** v1.42.0 keeps it across a deferral. |
| R7 | Semantic distance tracking | SHOULD | **Not met.** |
| R8 | Telemetry export | SHOULD | **Met;** v1.42.0 exports STEP_UP and DEFER events. |
| R9 | Least privilege enforcement | SHOULD | **Largely met.** |

**Partial conformance, as the paper allows a claim of it (v1.41.0):** R1 (ALLOW and DENY), R5, R6, R8 and R9 met or largely met; R2 and R3 in part; R4 and R7 not met. v1.42.0 (`docs/security/v1.42-step-up-defer.md`) adds STEP_UP and DEFER, the largest gap. They are built (steps 1 to 8) but not released, and AARM's conformance tests for them, in `mode=hold`, are recorded here in step 9; until then this page claims nothing for them beyond what `make test-v1420` checks.

## How VAREK is built, against AARM's four architectures

AARM describes four ways to build the control plane:
- **(A)** a gateway (proxy);
- **(B)** an SDK in the agent's code;
- **(C)** a kernel monitor (eBPF/LSM);
- **(D)** a vendor's own hooks.

It states that "kernel-level (eBPF/LSM) implementations alone cannot satisfy AARM conformance" for context-dependent decisions, and that such implementations belong alongside a semantic-aware architecture.

VAREK is not a kernel-only monitor:
- **The Warden enforces at the kernel**, with seccomp-BPF and seccomp user-notify. Every file open, lookup, connect, program launch and datagram send is *held* by the kernel until the Warden answers. That is the non-bypassable enforcement AARM credits to Architecture C.
- **The decision is made in user space** (`warden.c`, `smt_decide.h`), with the run's context. That context:
  - **the policy**, decided by an SMT procedure and an independent certificate checker;
  - **the plan the run is held to** (`--hold-to-plan`);
  - **on whose behalf**, a verified user token and the agent's SPIFFE SVID;
  - **which sub-agent made the call**, by its control group.
- **The gateway (A)** is the egress proxy, with MCP tool-call inspection (`warden_proxy.c`, v1.26 and v1.31).
- **The SDK (B)** is the framework adapters, which generate the plan from the agent framework (`adapters/`, v1.35).

So VAREK combines A, B and C, with one decision point and one signed record.

VAREK is also designed to keep the human out of the loop at run time (HOOTL). People decide when they write the policy and approve the plan, and the machine checks every call against those decisions. Its approvals follow suit (v1.42.0, below): an approval is a scoped grant, signed where the policy pins approvers' keys, that the machine checks, given before the run where possible.

## Requirement by requirement

### R1: Pre-execution interception (MUST)

**Met for ALLOW and DENY:**
- **Interception:** each mediated call is held by seccomp user-notify until the Warden decides, and is carried out only on ALLOW (`warden.c`).
- **DENY:** a refused call returns an error to the agent and has no effect.
- **The record:** every refusal names its rule and policy line.
- **Fail-closed:** there is no fail-open mode. UNKNOWN is refused, and an agent whose Warden stops is killed with its descendants (`v1_7/warden_lifecycle.c`).
- **Network and tools:** calls are mediated by the egress proxy and, for MCP, by tool name and arguments.

**v1.42.0 (built):** a call a `step_up` rule decides in `mode=hold`, or a `defer` rule decides, is held: at the kernel (the seccomp notification is not answered) or at the egress proxy (the request is not forwarded), until it is approved, released by its context, denied or timed out. It is decided again before it is carried out. `scope=run` freezes the whole run meanwhile. Nothing held is carried out by default: a timeout refuses it.

**Tests:**
- `make test-v1420`: holds at the kernel and the proxy, their endings, the freeze (step 9 records AARM's test);
- `make test-lifecycle`: the Warden stopped, its agent and descendants gone;
- `make test-v1121`, `test-v1122` and `test-v1160`: decisions, refusals and their records;
- `make test-v1260` and `test-v1310`: network and MCP calls.

### R2: Context accumulation (MUST)

**Partly.** What VAREK keeps per session:
- **the plan** the run is held to, and the steps taken (`--plan`, `--hold-to-plan`; plan 1.35 from the framework, v1.35);
- **refusals counted per session** across plans: `session_refusal_budget`, which ends the session at its limit (v1.19);
- **the on-behalf-of chain:** the verified user, any `act` actors, and the agent;
- **each sub-agent's calls** (v1.28.1);
- **the verdict stream itself,** append-only and hash-chained. That is the form AARM recommends for the context store.

**v1.42.0:** the user's **original request** (`varek run --intent FILE` or `--intent-text`) is recorded in `run_start`, its SHA-256 and its text (or a file beside the stream), shown to approvers by `varek pending` and carried in the export. It is context for people, never for a decision.

**Missing:**
- the policy engine does not receive **data classifications accessed** at runtime. Data-flow labels are checked on the plan's edges before the run (`--flow-policy`), not across calls during it.

**Tests:**
- `make test-v1350`: plans and holding a run to one;
- `make test-v1190`: the session's refusal budget;
- `make test-v1200`: plan step fields;
- `make test-v1281`: the chain and sub-agents.

### R3: Policy evaluation with intent alignment (MUST)

**Partly.**
- **Static policy:** forbidden actions are refused at once (deny rules, the SMT decision, and a certificate the checker verifies before any ALLOW).
- **Intent:** with `--hold-to-plan`, a call the policy allows but no plan step covers is refused as `outside_plan`. That is VAREK's form of the intent check: the plan is the agent's declared intent, generated from its framework.
- **Parameter validation:** paths, hosts, flags, and MCP arguments.

**v1.42.0:** **DEFER** on missing context: `defer ... until=FILE` waits for a marker the approvers' side writes; `on unknown defer escalate` turns a call no rule names into an approval; `on outside_plan defer` waits for a plan extension (`varek plan extend`), decided by the plan gate. **STEP_UP** puts a context-dependent allow to a person, as AARM's test expects (STEP_UP or ALLOW).

**Missing:**
- **context-dependent deny across calls** (for example, a send after a read of sensitive data), outside the plan gate.

**Tests:** `make test-v1350`, `make test-v1130` to `test-v1150` (the decision procedure and the checker), `make test-v1310` (MCP arguments).

### R4: Five authorization decisions (MUST)

**v1.41.0: not met. v1.42.0 (built): four of five.**

| Decision | VAREK |
|---|---|
| ALLOW | Yes. |
| DENY | Yes. |
| MODIFY | Only one transformation: credential release replaces a placeholder with the real credential in an allowed request (v1.28, `warden_proxy_helper.c`). There is no general parameter rewrite. |
| STEP_UP | v1.42.0: `step_up` rules. `mode=grant` (the default) refuses the call with a proposal and allows its retry once a person approves; `mode=hold` holds it until they answer. |
| DEFER | v1.42.0: `defer` rules, `on unknown defer escalate` and `on outside_plan defer`. UNKNOWN is still refused unless the policy defers it. |

v1.42.0 adds STEP_UP and DEFER (`docs/security/v1.42-step-up-defer.md`), with approvals that go beyond AARM's model:
- **An approval is a grant, not a verdict.** A person approves a signed, scoped rule (this object, this many times, until this time, for this user or sub-agent), within the policy's `step_up` rule. The approved call is then decided by the machine against the policy plus the grant, with a certificate the checker verifies.
- **The audit replays every approval.** Each call falls within its grant, and each grant within its `step_up` rule, approved by a member of its group (and signed by a pinned key, where the policy pins them).
- **Routing to approvers** (AARM's R4 MUST): `approvers=GROUP` names who may answer, on the run's approvers' socket (the Unix user from the kernel's peer credentials); `varek pending` shows them what waits, and `notify=URL` posts each proposal to a webhook (a chat or a ticketing system), notification only.
- **People approve ahead of time where they can.** That means a plan approved before the run, or standing grants. At run time the default is `mode=grant`: the call is refused at once, and its retry passes once the grant is approved, so the agent never waits on a person.
- **AARM's hold mode** (`mode=hold`) keeps the call held at the kernel (seccomp user-notify) until the approver answers. AARM's conformance test uses that mode.

**Tests:** `make test-v1280` (the credential swap); `make test-v1420` (STEP_UP and DEFER; AARM's conformance tests in step 9).

### R5: Tamper-evident receipts (MUST)

**Largely met.**
- **The chain:** every decision is a record in a hash chain (SHA-384, format chain-2). `run_start`, checkpoints and `run_end` are signed with ECDSA P-384 through the host's OpenSSL, the FIPS module in the Defense build. The signatures are verifiable offline (`tools/varek_audit.py`), and optionally appended to an external anchor.
- **What a record carries:**
  - the action and its resolved object;
  - the decision, rule and policy line;
  - the time;
  - the outcome: the kernel's verdict and errno;
  - the identity chain (`obo`).
- **What `run_start` carries:** the policy's SHA-256, the identities, and the crypto provider.
- **Tamper detection:** the audit detects a record changed, inserted, removed or reordered.
- **CycloneDX evidence** is signed with JSF ES384.

**v1.42.0:** approval and deferral receipts. A hold or proposal (`step_up`, `defer`) with its reason, rule and timeout; the `grant` with its text, its approver, its signature and its time; the ending (`approved`, `denied`, `resolved`, `escalated`, `timeout`, `abandoned`); each use, its decision naming the grant or the marker; the freeze and thaw; each webhook post's outcome. All are chained and signed like every record, and the audit replays them.

**Gaps against AARM's receipt schema:**
- a record is covered by the signature of the next checkpoint through the chain; it is not signed on its own.

**Tests:** `make test-v1160` (the audit chain and every forgery), `make test-v1410`, `make test-v1161`, `tests/test_varek_v140_logs.py`.

### R6: Identity binding (MUST)

**Largely met.**
- **Who the run is for:** `run_start` binds the run to the human principal (a JWT verified against the issuer's keys, freshness checked, the run revoked at its expiry), the agent (its X.509-SVID, verified against a SPIFFE trust bundle), and the run's own id.
- **Who made each call:** every record carries `obo` (`["user", "agent", "subagent:NAME#N"]`), attributed by the kernel's control groups, not by what the agent says.
- **Binding:** records are bound to all of this by the signed chain.

**v1.42.0:** a held or deferred call keeps its process and its `obo`: it is decided again for the same process, and its records name the call (the export carries its `obo`). An approver is identified by the kernel's peer credentials, and by a pinned key where signatures are required.

**Not done:**
- an SVID's revocation status is not checked (CRL/OCSP);
- a role or privilege scope is recorded only as the policy and the token's claims.

**Tests:** `make test-v1281`, which covers the chain, expiry and sub-agents.

### R7: Semantic distance tracking (SHOULD)

**Not met.** VAREK makes no embedding-based drift measurement. The plan gate's step-by-step hold is structural, not semantic.

### R8: Telemetry export (SHOULD)

**Met.**
- **Format:** OCSF 1.9.0 events (`varek export --format ocsf`).
- **Destinations:**
  - OpenTelemetry (OTLP/HTTP), `--format otlp`;
  - Splunk HEC, with an app, `--format splunk`;
  - Microsoft Sentinel, `--format sentinel`;
  - CrowdStrike Falcon Next-Gen SIEM, `--format falcon`, tested against a stand-in.
- **Live and batch:** `--follow` streams a live run, and a finished run is exported in batch.
- **Filtering:** the analytics rules filter by decision.
- **v1.42.0:** each approval, deferral, grant, ending, freeze and webhook post is an OCSF event of its own (Application Lifecycle, with OCSF's own dispositions: Delayed, Challenge, Approved, Rejected), in every destination; Sentinel raises an incident for an approval nobody gave in time, and Splunk has a macro for it.

**Tests:** `tests/test_varek_otel.py`, `test_varek_splunk.py`, `test_varek_sentinel.py`, `test_varek_falcon.py`, `test_varek_export_resume.py`, `test_varek_ocsf_v142.py` (v1.42), and `make test-v1420` section 13 (the Warden's own v1.42 streams, exported); live tests are in `docs/security/v1.39-security-operations.md`.

### R9: Least privilege enforcement (SHOULD)

**Largely met.**
- **Credentials** are released per request (v1.28). The agent holds only placeholders; `warden-secrets` fetches each credential for the run (Vault leases revoked at its end), and the proxy inserts it only into a request an allowing rule names. Each use is recorded.
- **The agent runs** with no capabilities, as its own user (v1.29). Launches are held by Landlock, and writable directories are mounted `noexec`.

**Not met:** AARM's test (a credential issued for a read cannot write) depends on the credential store's scoping, which VAREK does not issue.

**Tests:** `make test-v1280`, `make test-v1270`, `make test-v1271`, `make test-v1290`.

## Against AARM's conformance tests

The conformance page lists a minimum test per requirement. VAREK v1.41.0, and v1.42.0 as built. The v1.42.0 entries are what `make test-v1420` checks; AARM's own tests, in `mode=hold`, are recorded here in step 9 (pending).

| Test | VAREK |
|---|---|
| R1: a DENY policy's action doesn't execute; a denial receipt | Yes |
| R1: a DEFER condition suspends the action | v1.42.0: built (held at the kernel or the proxy); AARM's test pending (step 9) |
| R1: the control plane unavailable, the action fails | Yes (the agent is killed with its Warden) |
| R2: the policy engine receives all prior actions and data classifications | Partly (the plan's progress, the session's refusals; no runtime classification) |
| R2: tampering with a prior context entry detected | Yes (the hash chain) |
| R3: a forbidden action denied at once | Yes |
| R3: an allowed action denied after sensitive data was read | No (data flow is checked on the plan, not across runtime calls) |
| R3: a context-dependent allow gives STEP_UP or ALLOW | Partly (ALLOW through the plan); v1.42.0: STEP_UP built, AARM's test pending (step 9) |
| R3: ambiguous context gives DEFER | v1.42.0: built (`on unknown defer escalate`, `defer ... until=`); AARM's test pending (step 9) |
| R4: each of five decisions | v1.41.0: no (two, and a narrow MODIFY). v1.42.0: four, and a narrow MODIFY |
| R4: STEP_UP or DEFER timing out gives DENY | v1.42.0: built (a timeout refuses the call); AARM's test pending (step 9) |
| R5: receipts with requester context, delegation chain and policy hash | Yes (ALLOW and DENY) |
| R5: a receipt's signature verifies offline; tampering fails it | Yes |
| R5: a deferral receipt's reason and resolution | v1.42.0: built (`defer`, `defer_end`); AARM's test pending (step 9) |
| R6: identity attributed per principal and session | Yes |
| R6: identity preserved across deferral | v1.42.0: built (the same process and `obo`); AARM's test pending (step 9) |
| R8: SIEM export with the right schema, DEFER events included | Yes; DEFER and STEP_UP events from v1.42.0 (`make test-v1420` section 13) |
| R9: a read credential cannot write | Not tested |

## What would close the gaps

1. **v1.42.0, STEP_UP and DEFER** (`docs/security/v1.42-step-up-defer.md`), built in steps 1 to 8:
   - approvals as scoped grants, signed where the policy pins keys, that the machine checks and the audit replays;
   - plan approval and standing grants ahead of time;
   - `mode=grant` by default, and `mode=hold` for AARM's test;
   - approvers from a Unix group, with a webhook carrying each proposed grant.

   This closes, once step 9 records AARM's conformance tests, R4 but for a general MODIFY, and the DEFER parts of R1, R3, R5 and R6.
2. **Recording the original request** (R2): `varek run --intent`, recorded in `run_start` and shown to approvers. Built in v1.42.0.
3. **Context across runtime calls** (R2, R3): labels on what the agent reads, and a rule that refuses or steps up a later send. This is VAREK's cross-action data-flow candidate (v1.11).
4. **A general MODIFY,** for example narrowing an MCP call's arguments, kept to transformations the checker can verify.
5. **SVID revocation checks** (R6).
6. **Semantic drift** (R7), if wanted; it needs an embedding model in the decision path.
