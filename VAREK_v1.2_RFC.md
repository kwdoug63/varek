# VAREK v1.2 — Policy & Admissibility Control

**Status:** Draft RFC for internal and partner technical review
**Scope:** Policy data model, evaluator, integration with the v1.1 sandbox, and tier surfaces (turnkey bundles, self-serve authoring, bespoke engagements)
**Builds on:** VAREK v1.1 (subprocess isolation via seccomp-bpf, cgroups v2, namespaces)
**Last updated:** April 27, 2026

---

## 1. Motivation

VAREK v1.1 establishes a kernel-enforced containment boundary: untrusted code runs inside a seccomp-bpf + cgroups + namespace sandbox where `execve` is denied by default and high-risk syscalls trigger `SIGSYS`. The boundary holds — hostile code cannot escape to the host. v1.1 answers *"can it break out?"* with a structural no.

v1.2 answers the next question: **given that the boundary holds, which permitted actions are admissible?**

A syscall allowlist prevents privilege escalation and host tampering, but it permits a broad class of behaviors inside the sandbox: file I/O within the mount namespace, network sockets (when policy allows), memory allocation, thread creation, signal handling. Many legitimate workflows require these. A data-analysis agent needs to read CSVs. A report-generation agent needs to write temp files. A web-scraping agent needs outbound HTTP. But not all uses of these primitives are equally safe. An agent writing `/work/analysis.csv` is materially different from an agent writing `/work/exfil.sh` and attempting `chmod +x` (which the v1.1 sandbox would deny on the syscall, but the *intent* is observable before denial). The containment boundary is necessary but not sufficient.

**Admissibility control** sits above the boundary: a policy layer that observes proposed transitions, evaluates them against declared rules, and gates execution before the syscall dispatches. Unlike v1.1 enforcement (which applies a universal deny on certain syscall classes), admissibility decisions are contextual, composable, and operator-specified.

This document defines the substrate — the policy data model, the evaluator, the integration contract with the v1.1 sandbox — and the three tier surfaces through which operators consume it.

### 1.1 Deployment Model

VAREK v1.2 is a **standalone runtime**, not a framework plugin. The admissibility evaluator and the v1.1 sandbox both live in VAREK's own process space, on the host where untrusted code is executed. Operators deploy VAREK as the execution environment; agents, pipelines, and orchestration frameworks invoke it from outside.

Where VAREK exposes adapters for popular orchestration frameworks (Prefect, LangChain, CrewAI, etc.), those adapters are **thin translation layers**: they map a framework's task or tool invocation into a VAREK execution payload, hand the payload to VAREK, and return the result. Adapters do not enforce policy. They do not evaluate transitions. They do not interpret bundles. Policy enforcement is exclusive to VAREK's own process.

This positioning is intentional and load-bearing. It means an enterprise security team can adopt VAREK without taking a dependency on any particular orchestration framework, and it means a single VAREK deployment can sit behind multiple frameworks simultaneously without policy drift between them. The unit of trust is the VAREK runtime, not the framework calling it. Reviewers should read the §6 tier surfaces (turnkey, self-serve, bespoke) as packaging models for VAREK runtime configuration, not as framework integrations.

---

## 2. Core Concepts

### 2.1 Transitions

A **transition** is a proposed state change with externally-observable consequences. Transitions are the unit of admissibility evaluation.

In v1.2, transitions are observed at the **syscall layer**: every syscall the policy layer cares about is marked with `SECCOMP_RET_USER_NOTIF`, and the evaluator receives the syscall number, the calling thread's PID/TID, and the argument register values. This gives the evaluator a precise, kernel-mediated view of what the sandboxed process is about to do.

**Scope note (deferred to v1.3+):** v1.2 does *not* match against semantic actions like `HTTPRequest(url=...)` or `WriteFile(path=...)`. Deriving a stable semantic action from a syscall stream across multiple language runtimes is an unsolved problem in the general case (a TLS-encrypted `write()` on a socket fd does not, by itself, surface the request URL). v1.2 ships the syscall-layer evaluator and defers semantic-layer policy expression to a later RFC. The data model in §3 is forward-compatible with semantic transitions; the v1.2 evaluator simply does not produce them.

### 2.2 Policies

A **policy** is a declarative artifact that maps transitions to decisions. Policies are static (no Turing-completeness), versioned (each carries its own semver), and composable (multiple policies may evaluate the same transition; see §4.2).

A policy consists of an identifier, a version, a scope (which executions it applies to), and an ordered list of rules. Each rule has a `match` pattern, an optional `condition`, a `decision`, and decision-specific `metadata`.

### 2.3 Decision Types

v1.2 supports three decision types:

- **Allow** — the transition proceeds.
- **Deny** — the transition is blocked. At the syscall layer this returns `EPERM`. The denial is logged.
- **RateLimit** — the transition is allowed up to a configured quota within a configured time window. On exhaustion, behavior is determined by `on_exceeded` (deny, or queue with timeout).

**Scope note (deferred to v1.3+):** v1.2 does not include `Defer` (human-in-the-loop approval) or `Transform` (in-flight modification of transition arguments). Defer requires a full approval-protocol design — callback interface, timeout cascades, partial-failure semantics — that is its own RFC. Transform requires modifying syscall argument data while the calling thread is suspended, which is technically feasible via `SECCOMP_NOTIF_IOCTL_ADDFD` and `process_vm_writev` but is research-grade ergonomics in v1.2's timeline. The decision-type enum in the schema is open: adding values in v1.3 is a non-breaking change.

---

## 3. Policy Data Model

### 3.1 Schema

Policies are expressed as YAML conforming to the following schema. JSON is also accepted; the canonical wire format is JSON, the canonical authoring format is YAML.

```yaml
apiVersion: varek.io/policy/v1
kind: Policy
metadata:
  id: agentic-code-execution.network-egress
  version: 1.0.0
  description: >
    Restrict outbound network from sandboxed agentic code to an
    allowlist of egress hosts. Block direct IP connections.
  tags:
    - bundle:agentic-code-execution
    - capability:network

scope:
  runtime: sandbox          # sandbox | host
  applies_to:
    execution_labels:
      - agent.role: code-runner
    not_labels:
      - environment: dev

priority: 100               # used in priority_weighted composition

rules:
  - id: allow-pypi
    match:
      syscall: connect
      af: AF_INET
      destination:
        host_in:
          - pypi.org
          - files.pythonhosted.org
    decision: allow
    metadata:
      audit_log: false

  - id: allow-customer-api
    match:
      syscall: connect
      af: AF_INET
      destination:
        host_in:
          - api.customer.example.com
    decision: rate_limit
    metadata:
      window_seconds: 60
      max_invocations: 30
      on_exceeded: deny
      audit_log: true
      reason: "Customer API quota"

  - id: deny-direct-ip
    match:
      syscall: connect
      af: AF_INET
      destination:
        host_matches: '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    decision: deny
    metadata:
      audit_log: true
      reason: "Direct-IP egress is not permitted from agentic runtime"

  - id: default-deny-egress
    match:
      syscall: connect
      af: AF_INET
    decision: deny
    metadata:
      audit_log: true
      reason: "Egress not on allowlist"
```

### 3.2 Field Semantics

- **`apiVersion`, `kind`** — versioned identifiers for the schema. Operators pin to a major version; minor versions add fields without breaking older policies.
- **`metadata`** — `id` is globally unique within a deployment; `version` is the semver of the policy itself, independent of the schema version.
- **`scope.runtime`** — `sandbox` policies evaluate inside the sandboxed process via `SECCOMP_RET_USER_NOTIF`. `host` policies evaluate on the host before sandbox instantiation; useful for resource-allocation and cohort-level denials.
- **`scope.applies_to`** — selects executions by label. Policies that omit `applies_to` apply to all executions in the deployment.
- **`priority`** — only consulted when the deployment composition mode is `priority_weighted` (see §4.2).
- **`rules`** — evaluated in declaration order. The first rule whose `match` pattern selects the transition determines the policy's vote. Subsequent rules in the same policy do not fire. If no rule matches, the policy abstains.
- **`match`** — pattern that selects which transitions a rule applies to. v1.2 patterns match on syscall name, argument values, destination host (resolved via the sandbox's DNS shim), file path (canonicalized), and label selectors on the calling execution.
- **`decision`** — one of `allow`, `deny`, `rate_limit`. Open enum; v1.3+ may add values.
- **`metadata`** — decision-specific parameters. `rate_limit` requires `window_seconds`, `max_invocations`, and `on_exceeded`. `allow` and `deny` support optional `audit_log`, `tags`, and `reason` fields for observability.

### 3.3 What This Model Does Not Do

- It does not match against semantic actions (see §2.1 scope note).
- It does not support decision types beyond Allow / Deny / RateLimit in v1.2 (see §2.3 scope note).
- It does not perform content inspection of data flowing through syscalls (no regex-on-payload matching, no DPI of network bytes). Content inspection requires crossing a trust boundary in a way that creates its own attack surface; v1.2 is structural.
- It does not support stateful predicates beyond rate-limit counters (no "allow this transition only if a different transition happened earlier"). General stateful policies are a known limitation and a candidate for v1.3+.

---

## 4. Policy Evaluator

The **policy evaluator** is the runtime component that consumes policies and transitions, applies matching logic, and returns decisions. It runs as a supervisor thread (or, in defense profiles, a separate process attached via `SCM_RIGHTS`) that holds the seccomp notification fd for each sandboxed execution.

### 4.1 Evaluation Flow

```
1. Transition observed: sandboxed process invokes a syscall whose
   filter rule was SECCOMP_RET_USER_NOTIF. The kernel suspends
   the calling thread and emits a seccomp_notif on the fd.

2. Evaluator reads the notification and resolves it to a Transition
   record (syscall, args, calling execution context, resolved
   destination host or canonical path where applicable).

3. Evaluator retrieves active policies for the current execution
   context (matched by scope.applies_to labels).

4. For each active policy, evaluate rules in declaration order:
   a. Does the `match` pattern select this transition?
   b. If yes, record the rule's `decision` as this policy's vote
      and stop evaluating rules in this policy.
   c. If no rule matches, the policy abstains.

5. Compose votes across all active policies (see §4.2).

6. Apply the final decision:
   - Allow      → seccomp_notif_resp with SECCOMP_USER_NOTIF_FLAG_CONTINUE
   - Deny       → seccomp_notif_resp with error EPERM; log
   - RateLimit  → consult quota; resolve to Allow or Deny per metadata
```

The evaluator is invoked in the kernel-suspended path; the calling thread is blocked until `seccomp_notif_resp` is written. Performance matters (see §4.4).

### 4.2 Composition

Multiple policies may vote on the same transition. The composition mode is configured per deployment. v1.2 ships two modes:

- **`deny_dominates` (default).** If any policy returns Deny, the final decision is Deny. If no policy returns Deny and at least one returns Allow (or RateLimit resolving to Allow), the decision is that. If all policies abstain, the decision is Allow (permissive abstention). Safe default for security-critical systems.

- **`priority_weighted` (opt-in).** Each policy declares a numeric `priority`. The highest-priority non-abstaining policy wins. Ties broken by policy `id` lexicographic order for determinism. Supports use cases where different policies represent different stakeholders (operator > agent-author > default-bundle).

Edge cases:

- *Abstention in `priority_weighted`.* An abstaining higher-priority policy is skipped; evaluation continues to the next-highest. Abstention is not a vote.
- *Empty active set.* If no policies apply to the execution, the decision is Allow. The v1.1 syscall allowlist still applies — admissibility is *additional* gating, not the only gating.
- *Evaluator failure.* If the evaluator panics, times out, or loses the policy set, the result is Deny (fail-closed). See §5.

### 4.3 Integration with the v1.1 Sandbox

The v1.1 `SeccompBpfBackend` is extended with an optional `policy_evaluator` parameter:

```python
backend = SeccompBpfBackend(
    syscall_allowlist=DEFAULT_AGENTIC_ALLOWLIST,
    cgroup_limits=CgroupLimits(memory_mb=512, cpu_quota_us=50000),
    namespaces=NamespaceConfig(net=True, mount=True, pid=True, user=True),
    policy_evaluator=PolicyEvaluator(             # NEW in v1.2
        policies=load_bundle("agentic-code-execution", values=values),
        composition=Composition.DENY_DOMINATES,
    ),
)
```

When `policy_evaluator` is `None`, the backend behaves identically to v1.1 (syscall allowlist only). Existing v1.1 deployments upgrade to v1.2 without configuration changes; admissibility is opt-in.

Two integration points:

- **Pre-syscall (sandbox-side).** Policies with `scope.runtime: sandbox` evaluate inside the sandboxed process via `SECCOMP_RET_USER_NOTIF`. The supervisor thread holds the notification fd, evaluates, and writes `seccomp_notif_resp`.

- **Pre-instantiation (host-side).** Policies with `scope.runtime: host` evaluate the `ExecutionPayload` before the sandbox is created. Useful for resource-allocation decisions ("deny payloads requesting >32 GB memory") and blanket denials ("deny all payloads from untrusted sources during an active incident response").

### 4.4 Performance Targets

- **Syscall-layer evaluation, P99: < 1 ms.** Measured from kernel emit of `seccomp_notif` to `seccomp_notif_resp` write, with a representative policy set of 50 rules across 5 active policies.
- **Host-layer evaluation, P99: < 10 ms.** Measured against an `ExecutionPayload` of typical agentic-code-execution shape.
- **Policy load time, cold start: < 100 ms** for a 50-rule policy set.

These are budgets, not commitments. Deployments with hundreds of rules or expensive `match` predicates (regex, DNS resolution) will exceed them; the evaluator exposes per-policy timing so operators can identify offenders.

---

## 5. Threat Model

The admissibility layer is not a containment boundary. The v1.1 sandbox is the containment boundary. The admissibility layer is a **second gate** that operates inside the boundary the sandbox provides.

### 5.1 What v1.2 Defends Against

- **Misuse of permitted primitives.** Syscalls allowed by the v1.1 allowlist can still be misused (egress to unapproved hosts, writes to sensitive paths, runaway invocation of `open()`). v1.2 lets operators express "this primitive is permitted, but only to these targets, at this rate."
- **Operator policy drift.** With v1.1, operators tune the syscall allowlist directly — a coarse, error-prone interface that mixes structural defense with domain policy. v1.2 separates them: the allowlist is structural, the policy layer is domain.
- **Cohort-level denials.** Host-scoped policies (§4.3) let operators stop classes of execution at deployment time without reconfiguring the sandbox itself.

### 5.2 What v1.2 Does Not Defend Against

- **Sandbox escape.** That is v1.1's job. If an attacker has escaped the sandbox, they are on the host and the admissibility layer is no longer in the path.
- **Compromised evaluator.** If an attacker can inject or modify policies in the running deployment, they control admissibility. Policy distribution is out of scope for v1.2; operators are expected to treat policy artifacts as signed configuration and gate them through their existing deployment-trust process.
- **Side-channel exfiltration.** A policy that allows DNS lookups can be used to encode information into DNS query patterns. A policy that allows writes to `/work/` can be used to encode information into file size or timing. v1.2 is not a covert-channel countermeasure.
- **Semantic-layer attacks.** A request to `pypi.org` for a malicious package is, at the syscall layer, indistinguishable from a request for a benign one. v1.2 does not inspect what is fetched. Package-level provenance is the responsibility of a separate layer (signed bundles, hash-pinned deps) that v1.2 does not provide.

### 5.3 Failure Modes

- **Evaluator unreachable.** If the supervisor thread crashes, hangs, or loses the seccomp notification fd, sandboxed syscalls that require notification are denied (fail-closed). The sandbox does not silently degrade to allowlist-only.
- **Policy load error.** If a policy fails schema validation at load time, the sandbox refuses to start. There is no partial-load mode.
- **Quota exhaustion in `rate_limit`.** Behavior is governed by `on_exceeded`. The evaluator does not have an implicit fallback.

---

## 6. Tier Surfaces

The data model in §3 is the substrate. Operators consume it through one of three surfaces; all three produce the same canonical YAML conforming to §3.1, and all three are composable in a single deployment.

### 6.1 Tier A — Turnkey Bundles

**Audience.** Operators who want a working policy set without authoring rules themselves. Typical profile: platform teams adopting VAREK as an execution substrate; defense and compliance-sensitive operators who prefer vendor-maintained policy sets they can audit.

**Shape.** A bundle is a versioned artifact (semver, signed, distributed via the VAREK package channel) containing one or more policies and a `values` schema. Operators install a bundle and supply a `values.yaml` to configure deployment-specific parameters (allowlist hosts, rate-limit quotas, resource caps).

**Validation.** Each bundle ships with a test suite — input transitions and expected decisions. Operators run `varek-bundles validate my-deployment.values.yaml` to confirm the bundle behaves as expected under their configuration before deployment.

**Target for v1.2 GA.** One reference bundle: `agentic-code-execution`. Covers the scope of the v1.1 sandbox (outbound network allowlist, filesystem scoping to a work directory, resource caps, rate-limited subprocess invocation). Functions as a migration target for v1.1 users and as a reference implementation for future bundles.

**Not committed for v1.2 GA.** A menu of domain-specific bundles (HIPAA-compliant code execution, PCI-DSS database gateway, classified-environment execution, etc.). These are v1.2.x and v1.3 work, prioritized by customer demand rather than speculative coverage.

### 6.2 Tier B — Self-Serve Policy Authoring

**Audience.** Operators with security-engineering capability who need to express rules not covered by turnkey bundles. Typical profile: fintech security teams, platform-infrastructure teams at AI-native companies, consultancies building on VAREK for their clients.

**Shape.** Operators author YAML policies directly, conforming to the §3.1 schema. VAREK provides:

- **Schema validation** — a JSON Schema for the policy format; errors caught at lint time rather than evaluation time.
- **Test harness** — `varek-policy test my-policy.yaml --transitions test-transitions.yaml` evaluates the policy against synthetic transitions and reports which rules fired, which abstained, and whether the composed decision matches expectations.
- **Dry-run mode** — a runtime flag that evaluates policies and logs decisions without enforcing them, for validation against real traffic before enforcement.
- **Reference documentation** — every schema field documented with examples; common patterns (allowlist, denylist, rate-limit-with-burst) provided as snippets.

**Not committed for v1.2 GA.** A higher-level policy language that compiles to the YAML schema. Whether to design a VAREK-specific language (vs. adopting Rego, Cedar, or Polar) is deferred to v1.3. The v1.2 position: YAML authoring is sufficient for the self-serve use case when backed by good tooling; a higher-level language is a v1.3 question driven by evidence of authoring friction.

**Target for v1.2 GA.** Schema + validator + test harness. Dry-run mode is a stretch goal; can ship in v1.2.1 if not ready for GA.

### 6.3 Tier C — Bespoke Authoring

**Audience.** Operators with custom requirements that warrant direct engagement with the VAREK team or an authorized partner. Typical profile: defense primes with classified threat models, large enterprises adopting VAREK for a specific high-stakes deployment, early strategic customers whose input shapes the product.

**Shape.** A VAREK engineer (or authorized partner) authors policy directly with the customer, delivered as a versioned bundle in the customer's deployment repo. Engagement artifacts (statements of work, validation plans, sign-off documentation) are commercial materials and are not specified in this RFC.

**Validation.** Same tooling as Tier B (`varek-policy test`), plus a customer-specific validation plan negotiated as part of the engagement.

**Composability.** A Tier C deployment typically runs a Tier A bundle plus one or more Tier C policies, with `priority_weighted` composition arranged so that customer-specific rules can override or augment bundle defaults without forking the bundle.

---

## 7. Open Questions

The following are acknowledged as unresolved and targeted for follow-up work, not v1.2 GA.

1. **Semantic action derivation.** §2.1 defers semantic-layer policies to v1.3. The underlying derivation problem — mapping syscall streams to meaningful actions across languages and runtimes — is unsolved in the general case and worth a dedicated RFC.
2. **Decision types: Defer and Transform.** §2.3 defers these. Defer in particular has clear customer demand (human-in-the-loop workflows) and should be prioritized for v1.3 with a full design covering approval protocols, timeout cascades, and fallback behavior.
3. **Stateful policies.** §3.3 notes that v1.2 has no support for policies whose decisions depend on prior transitions (e.g., "allow `write()` to `/work/report.csv` only if a corresponding `open()` happened in the same execution"). Stateful policies require execution-scoped state with attendant complexity around persistence, scope lifetimes, and evaluation performance. Candidate for v1.3+.
4. **Policy language vs. YAML.** §6.2 defers the question of shipping a higher-level policy language. Decision should be driven by evidence from v1.2 customers about authoring friction.
5. **Multi-tenant policy isolation.** If a single VAREK deployment serves multiple tenants (e.g., a shared platform inside an enterprise), how do tenants' policies stay isolated from each other? Not addressed in v1.2; viable via deployment-level separation, but not ergonomic.
6. **Policy versioning and migration.** When a bundle updates from v1.0.0 to v1.1.0, what is the migration story for existing customers? §6.1 says updates are explicit opt-in; §3.2 says policies carry their own versions. The operational flow is not fully designed.
7. **Audit and compliance reporting.** Operators will need to demonstrate to auditors which policies were in effect during which time windows. v1.2 logs decisions; a full audit-trail and compliance-report story is v1.3.

---

## 8. Success Criteria

v1.2 GA is successful if:

1. **The data model is expressive enough** to represent the `agentic-code-execution` reference bundle cleanly, without requiring schema extensions or escape hatches.
2. **The evaluator meets the §4.4 performance targets** under realistic policy sets.
3. **v1.1 deployments upgrade cleanly** — sandboxes without a `policy_evaluator` parameter behave identically to v1.1; no regressions against the existing v1.1 regression suite.
4. **The three tier surfaces are architecturally distinct but share the substrate** — the same YAML policy can be produced by a bundle template, by an operator authoring directly, or by a VAREK engineer in a bespoke engagement.
5. **At least one external deployment** runs a v1.2 policy set in dry-run mode for at least two weeks before GA is declared.

---

## 9. Non-Goals

The following are explicitly out of scope for v1.2.

1. **Semantic-layer transition matching.** v1.2 is syscall-layer only. Semantic actions (`HTTPRequest`, `WriteFile`, `LLMInvocation`) are not part of the v1.2 vocabulary. See §2.1.
2. **`Defer` and `Transform` decision types.** v1.2 ships Allow / Deny / RateLimit only. See §2.3.
3. **A higher-level policy language.** v1.2 authoring is YAML. No DSL, no Rego adoption, no custom compiler. See §6.2.
4. **Content inspection.** v1.2 does not perform DPI, payload regex, or any inspection of the data flowing through allowed syscalls. See §3.3.
5. **A menu of domain-specific bundles.** v1.2 ships one reference bundle. See §6.1.
6. **Policy distribution and trust.** Signed-bundle distribution, key management, and supply-chain integrity for policy artifacts are out of scope. Operators integrate VAREK policies with their existing configuration-trust process.
7. **Stateful, multi-transition predicates.** v1.2 is stateless beyond rate-limit counters. See §3.3.
8. **Framework-plugin packaging.** VAREK v1.2 is not distributed as a plugin or extension to any orchestration framework (Prefect, LangChain, CrewAI, LlamaIndex, Airflow, or others). Where adapters exist, they are thin translation layers in VAREK's repo (or in a framework's optional contrib namespace) that convert framework invocations into VAREK execution payloads. Policy evaluation happens in VAREK's process space, not the framework's. Reviewers should not interpret §6 tier surfaces as framework-specific bundles ("a bundle for LangChain," "self-serve for crewAI"); the tier surfaces are packaging models for VAREK runtime configuration. See §1.1.

---

## 10. References

- VAREK v1.1 Security Update RFC — `VAREK_v1.1_SECURITY_UPDATE.md`
- VAREK v1.1 Threat Model — `docs/security/threat-model.md`
- Linux kernel documentation: `Documentation/userspace-api/seccomp_filter.rst` (`SECCOMP_RET_USER_NOTIF`, `seccomp_notif_resp`, `SECCOMP_NOTIF_IOCTL_ADDFD`)
- Issue #223 (dengluozhang) — original report motivating v1.1 and the boundary distinction relied on throughout this document
