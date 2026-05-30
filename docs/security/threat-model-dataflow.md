# VAREK Data-Flow Layer — Threat Model

**Version:** 1.0
**Last updated:** May 30, 2026
**Scope:** the cross-action data-flow verification layer (`v1_7/`),
which augments v1.6 plan-graph verification with a flow axis and adds
explicit, audited declassification (v1.8.0).

This is a **companion** to
[`threat-model.md`](./threat-model.md), which covers the runtime
containment (Guardrails) layer. The two layers address different parts
of VAREK's defense surface and have non-overlapping trust boundaries:

- `threat-model.md` (Guardrails): "the isolation layer used to execute
  untrusted code (code-interpreter tools, agentic execution contexts,
  sandboxed eval)." Defends against malicious code *executing* inside
  VAREK's seccomp sandbox.
- This document (data-flow verifier): the pre-execution verification
  of an agent's *proposed plan* over its action graph. Defends
  against plans that compose individually-permitted actions into a
  leak, before any action runs.

A deployment relies on both. Read both.

This document is written for two readers: a CISO evaluating the layer
for deployment, and an external auditor (Trail of Bits, NCC Group,
Doyensec, or equivalent) scoping an engagement.

## 1. What the layer does

Given an agent's proposed plan — a directed acyclic graph of actions
— the layer produces a single tri-state verdict (`SATISFIED` /
`UNSATISFIED` / `UNKNOWN`) before any action executes. The verdict is
the join over two axes:

- **Node axis (v1.6):** each action's own policy decision (the
  existing v1.4 Warden `policy_decide()` lifted to a plan-level
  decision in v1.6).
- **Flow axis (v1.7 + v1.8):** what sensitive labels flow along the
  plan's edges. Labels originate at actions, propagate forward in
  topological order, and are policed at every node they reach. v1.8.0
  adds operator-controlled, audited declassification.

Only `SATISFIED` on both axes authorizes execution. The intended
deployment binds this verdict to the v1.4 Warden's `--plan` gate.

The canonical case the layer addresses: every action in a plan is
individually permitted, but the composition moves a secret to a
denying sink. The v1.4 per-syscall guardrail and the v1.6 per-action
guardrail cannot see this by construction. The v1.7 flow axis can,
because it reasons over the whole plan at once.

## 2. Assets and security goals

- **Asset:** confidential or capability-bearing data observed by an
  agent during plan execution (secrets, PII, credentials, internal
  records, model weights, training data).
- **Primary goal:** prevent a plan from moving a labeled asset to a
  disallowed sink (exfiltration), including via *compositions* of
  individually-permitted actions.
- **Secondary goal:** when a plan is refused, produce an actionable,
  deterministic, machine-readable account of why. The pathology
  record names the offending node, the labels involved, the immediate
  predecessor edges, and (v1.7.4) the originating node traced back
  through the hops.

## 3. Trust boundaries

**Trusted inputs** (authored by the operator or vouched for by the
trusted Warden):

- The policy — labels, the sticky set, per-action rules with
  `permit_in` / `deny_in` / `unknown_in` / `declassify` slots, glob
  patterns on arguments. Whoever can write `policy.cfg` controls the
  verdict.
- The per-node node-axis decisions stamped on the plan
  (`policy_decide()` results from the v1.4 Warden).
- Label classifications and declassifier designations as operator
  assertions about action semantics.

**Untrusted inputs** (adversary-influenceable; prompt injection can
shape them):

- The plan structure: nodes, edges, action names, and arguments. The
  agent / planner proposes this. The layer's entire job is to refuse
  unsafe plans, so it treats the graph as hostile.

**The load-bearing precondition (read this).** Flow classification
keys on the action descriptor — its `name` and `named_args`. Those
describe what an action *is*. If an adversary can present a descriptor
that does not match the action's real effect (call an exfiltrating
action `read_secret`; hide the true destination URL), classification
is fooled. Therefore the host MUST construct action descriptors from
*ground truth* — the actual operation the Warden intercepts — and
never from agent-supplied self-description. The layer cannot detect a
lying descriptor; it trusts the descriptor to faithfully name the
action. An auditor should confirm the host honors this.

This precondition is the analogue of the AST-gate clarification in
`threat-model.md` §4: a structural surface that looks like enforcement
but is actually trust-bound at the boundary above it.

## 4. Adversary model

A compromised or prompt-injected agent that can propose arbitrary
plans (any nodes, edges, action names, arguments) and attempt to:

- compose individually-permitted actions into a leak;
- route a labeled asset around a declassifier;
- introduce a node intended to declassify or relabel;
- craft inputs to crash or corrupt the verifier;
- exploit the structural surface (glob patterns, config parsing) to
  influence the verdict.

The adversary cannot write the policy file, cannot alter the trusted
Warden's node-axis decisions, and (per the §3 precondition) cannot
forge a descriptor that diverges from the intercepted operation.

## 5. Security properties and their preconditions

- **P1 — Fail-safe / symmetric suppression.** Only `SATISFIED` on
  both axes authorizes; `UNSATISFIED` and `UNKNOWN` both suppress.
  *Precondition:* the host refuses on `rc == -1` from
  `plan_warden_verify()` as well as on a non-`SATISFIED` verdict.
- **P2 — Sticky fail-safe.** A label the operator marks sticky that
  reaches a node with no explicit disposition yields `UNKNOWN`
  (suppress), not silent pass. *Precondition:* the operator marks
  sensitive labels sticky in the config.
- **P3 — Compositional leak detection.** A plan whose composition
  moves a denied label to a denying sink is refused even when every
  node passes in isolation.
- **P4 — Controlled declassification.** A label is removed from the
  flow only at nodes the operator designates; the designation is
  policy-only (never plan/agent-supplied), requires the declassifier
  to also be permitted to see the label (two assertions), cannot be
  routed around (a bypass path still carries the raw label to the
  sink), and is audited (`plan_dataflow_node_declassified`).
  *Precondition:* L1 below.
- **P5 — Determinism.** Verdict and pathology bytes are
  byte-reproducible for a fixed plan / actions / policy.
- **P6 — Boundedness / no UB.** Verification terminates; storage is
  fixed-capacity; the suite (207 checks) and the reference Warden
  gate run clean under AddressSanitizer and UndefinedBehaviorSanitizer
  with `-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
  -Wmissing-prototypes` and zero warnings.

## 6. Known limitations (stated, not hidden)

- **L1 — Declassification is trusted, not verified.** VAREK cannot
  confirm that a designated redactor actually sanitizes. If the
  operator designates a node a `SECRET` declassifier and it does not
  in fact remove the secret, VAREK authorizes the flow. The control
  is that the assertion is explicit, per-node, per-label,
  operator-only, and audited — not that sanitization is mechanically
  proven. This matches the posture of CaMeL (Google DeepMind + ETH,
  arXiv 2503.18813) and FIDES (Microsoft Research, arXiv 2505.23643).
- **L2 — Garbage descriptor, garbage verdict.** Classification is
  only as good as the action descriptor (see §3 precondition).
- **L3 — Implicit / causal flows are out of scope.** The flat-set
  model tracks data flow, not control-flow influence. A plan that
  leaks one bit through *which* action it takes (branch on a secret)
  is not caught. This is a known limitation of flat provenance
  tracking; CaMeL and FIDES share the gap.
- **L4 — Flat set, not a lattice.** No level ordering (`PUBLIC <
  INTERNAL < SECRET`) and no partial declassification; a label is
  present or absent. Sufficient for tag-and-cleanse workflows; level
  reasoning is future work.
- **L5 — The verifier checks the PLAN, not the execution.** The
  guarantee holds only if what executes is the plan that was
  verified. Binding execution to the verified plan is the v1.4
  Warden's job (per-syscall enforcement). The plan gate is
  necessary, not sufficient, on its own.
- **L6 — Capacity is a fail-safe boundary.** Plans exceeding
  `PLAN_MAX_NODES` / `PLAN_MAX_EDGES` / `PLAN_MAX_LABELS` are
  rejected at construction, not verified. Size the bounds for the
  deployment.
- **L7 — The node axis is trusted.** This layer joins with, but does
  not re-derive, the v1.6 `exec_plan_verify` result. Defects in v1.6
  source files are out of scope for *this* layer's guarantees, and
  are covered by v1.6's own validation (`v1_6/tests/`).
- **L8 — Policy file integrity is assumed.** A writable policy file
  is a full compromise of the verdict. Protect it with filesystem
  permissions; that control is outside this layer.

## 7. Attack surface and where to focus a review

- **Declassification (`v1_7/plan_dataflow.c`, the non-monotone step).**
  The newest and most security-critical code — the one place labels
  leave the flow. Confirm the declassify set is only ever populated
  from the policy, that policing happens on full inbound before
  removal, and that the audit set reflects exactly what was dropped.
- **Config parser (`v1_7/plan_policy_config.c`).** A text parser over
  file content. The input is operator-authored (trusted), but it is
  still an untrusted-shaped surface worth fuzzing for memory safety:
  line handling, tokenization, the rules/labels vectors,
  ownership/free paths. Recommend a fuzz target here.
- **Glob matcher (`v1_7/plan_dataflow_adapter.c`).** Hand-rolled
  two-pointer matcher over descriptor argument values. Confirm no
  over-read on adversarial patterns or values; values originate from
  the (untrusted) descriptor.
- **Pathology emitter (`v1_7/plan_dataflow_pathology.c`).** Bounded
  writer emitting JSON with string escaping; node labels and label
  names are embedded. Confirm escaping (quotes, control bytes), the
  bounds, and the v1.7.4 NUL-termination contract.
- **Propagation / topological sort (`v1_7/plan_dataflow.c`).**
  Fixed-capacity Kahn's algorithm; confirm queue bounds and the
  cycle path (cycle → `UNKNOWN`, fail-safe).
- **v1.6 internal coupling (`v1_7/v1_6_compat.h`).** Two static-inline
  helpers reach into `v1_6/execution_plan_internal.h` to read edge
  endpoints and node labels by index. Confirm read-only access; v1.6
  source files must be unchanged.

## 8. Implementation posture

- C11, libc-only, no external dependencies.
- Fixed-capacity storage; no dynamic allocation on the per-syscall
  hot path. One companion allocation per plan submission, freed
  before the gate returns.
- Memory-safe under ASan/UBSan across the full suite (207 checks)
  and the reference Warden gate; zero compiler warnings at
  `-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
  -Wmissing-prototypes`.
- Deterministic output suitable for CI diffing and audit replay.
- v1.6 source files are unchanged by the v1.7 layer; tagged v1.6.x
  releases stay byte-identical.

## 9. Recommended external-audit scope

1. Memory safety of the config parser and glob matcher under fuzzing
   (libFuzzer / AFL targets on
   `plan_label_policy_config_load_stream` and the descriptor-matching
   path).
2. Correctness of the declassification non-monotone step against the
   four P4 sub-properties (operator-only, two-assertion, no-route-
   around, audited).
3. Soundness of the two-axis join and the sticky fail-safe against
   the symmetric-suppression invariant (no path authorizes on an
   `UNSATISFIED` or `UNKNOWN` either axis).
4. The §3 descriptor-integrity precondition as wired in the host:
   are descriptors built from intercepted ground truth or from agent
   metadata?
5. Run the suite under Valgrind and MemorySanitizer in addition to
   the committed ASan/UBSan runs.
6. Read-only-ness of the `v1_6_compat.h` coupling — confirm no
   v1.6 source file is modified by the v1.7 build.

## 10. Out of scope for this document

The Guardrails layer (covered in `threat-model.md`), the v1.6
node-axis evaluator internals (covered by `v1_6/`), the VAREK
language and compiler, policy-file distribution and access control,
and runtime binding of execution to the verified plan (L5). Each
bounds the end-to-end guarantee and should be reviewed in its own
right.

## 11. Changelog of this document itself

- **2026-05-30 (v1.0):** initial document. Created for the v1.8.1
  release. Companion to `threat-model.md`, scoped explicitly to the
  cross-action data-flow layer.
