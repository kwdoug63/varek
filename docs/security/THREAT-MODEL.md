# VAREK — Threat Model

Version: current as of v1.9.1 · MIT · github.com/kwdoug63/varek

This document states what VAREK defends, against whom, and what it explicitly
does not defend. It is deliberately conservative: where a guarantee is
conditional, the condition is named. VAREK relocates trust rather than
eliminating it — from "trust the model's judgment" to "trust the policy, the
decision procedure, and the enforcement boundary" — and the boundaries below are
where that relocated trust lives.

## 1. What VAREK is

VAREK decides, before an action takes effect, whether that action complies with
an explicit, human-authored policy, and enforces the decision at the system
boundary. Every action resolves to SATISFIED (provably compliant, may proceed),
UNSATISFIED (provably non-compliant, denied), or UNKNOWN (not decidable within
bounds, fails closed). The runtime proceeds only on a provable SATISFIED.

## 2. Assets and trust boundaries

- **Asset:** the integrity of the authorization decision — that no action takes
  effect unless it is SATISFIED under the active policy.
- **Trust boundary 1:** the policy author (trusted to express intent correctly —
  see §5, non-goal 1).
- **Trust boundary 2:** the verification chain — surface-language compiler,
  obligation encoder, and the SMT decision procedure (see the Trusted Computing
  Base document for per-component status).
- **Trust boundary 3:** the enforcement layer — the Warden supervisor and the
  kernel mechanisms it relies on (seccomp user-notification, and, where
  deployed, Landlock and capability restrictions).

## 3. Adversary models

VAREK is specified against two adversaries. The default deployment posture is
Model A; Model B is the hardened posture and is named wherever a guarantee
depends on it.

**Model A — capable but non-adversarial agent (default).** An autonomous agent
that may be mistaken, misaligned, or manipulated into *attempting* actions
outside policy, but is not assumed to be actively exploiting the sandbox
implementation. VAREK's purpose under Model A is to ensure that attempted
out-of-policy actions are denied before they take effect.

**Model B — adversarial co-resident process (hardened).** A process that
actively tries to defeat enforcement: racing argument memory, routing operations
off the mediated path, or probing for an action that is SATISFIED-but-harmful
near a policy boundary. VAREK's enforcement layer is hardened against the known
Model-B techniques below, with the residual limits stated honestly.

## 4. In-scope guarantees

- **Authorization before execution.** No mediated action takes effect without a
  SATISFIED verdict under the active policy. UNKNOWN and UNSATISFIED both fail
  closed.
- **Compositional plan safety (action-graph).** A planned directed acyclic graph
  of actions is verified before its first action runs, and re-verified as the
  agent revises it.
- **Cross-action data-flow bounds.** A source labeled secret cannot reach a sink
  forbidden by policy, across actions, with declassification only where audited.
- **Progress-safety / liveness (v1.9).** At policy load the verifier certifies
  that every refusal resolves to an automated terminal in finitely many steps —
  human-out-of-the-loop is a certified property, not a setting.
- **Enforcement-layer hardening (v1.9.1).**
  - *io_uring is denied in the baseline policy.* io_uring dispatches operations
    off the syscall entry path, where seccomp cannot observe them; instance
    creation is refused so the mediated path cannot be bypassed.
  - *Scalar vs. pointer arguments.* Decisions on scalar register arguments
    (flags, fd numbers, integer modes) are TOCTOU-safe because the kernel
    snapshots them. Decisions on pointer-dereferenced data are not made by
    letting the syscall continue; the supervisor performs the action on copied,
    validated arguments and injects the result, or denies.
  - *Stale-notification safety.* Every notification is revalidated immediately
    before the supervisor acts.

## 5. Out of scope / non-goals

These are real limits, not omissions. Several are addressed on the roadmap; none
are claimed as solved.

1. **Policy validity.** VAREK proves compliance with the policy as written. It
   does not prove the policy is correct or complete. A catastrophic action can be
   SATISFIED if the policy failed to forbid it. Validation of policy intent is
   the operator's responsibility.
2. **Application-level semantics beyond the mediated boundary.** Where harm is
   indistinct at the syscall layer (e.g. "send funds" is a socket write), policy
   must be expressed at the tool-call / function-call interceptor layer; syscall
   mediation alone under-constrains such actions.
3. **Kernel and hardware integrity.** A kernel zero-day, a hypervisor escape, a
   hardware/microarchitectural side channel, or a fault-injection attack is below
   VAREK's enforcement layer and out of scope. Defense in depth (Landlock,
   capability drops, namespaces, seccomp) reduces but does not eliminate exposure.
4. **Covert/side channels.** VAREK bounds explicit data flow across mediated
   actions; it does not claim to close timing or other covert channels.
5. **Availability under forced UNKNOWN.** An adversary who can force decision
   timeouts forces UNKNOWN — which is safe (fail closed) but is an availability
   concern, not an authorization breach. Bounded deterministically in v1.9.1.
6. **Soundness of the trusted chain.** Until proof objects are independently
   checked, the SMT decision procedure and the compilation to obligations are
   trusted, not verified. See the Trusted Computing Base document.

## 6. Residual risks (acknowledged)

- Pointer-argument operations rely on the supervisor-performs-and-inject pattern;
  deployments that mediate path-based access should layer Landlock for in-kernel,
  race-free filesystem restriction rather than relying on argument copying alone.
- The verification chain's soundness rests on components currently trusted (§5.6).
- An agent may probe for SATISFIED-but-harmful actions near a policy boundary;
  this is a policy-tightness question (§5.1), not an enforcement bypass.

## 7. Versioning

This threat model tracks the released runtime. Guarantees attributed to a version
hold only at or after that tag. Statements of roadmap intent are marked as such
and are not guarantees.
