# VAREK — Technical Specification

**Version 1.9.1 (current)**
Deterministic runtime verification of autonomous AI agents using formal methods.

Author: Kenneth Wayne Douglas, MD
Published by Sober Agentic Infrastructure, Inc.
Security contact: kenneth.douglas@soberagents.ai
License: MIT · Project: varek-lang.org · Source: github.com/kwdoug63/varek

---

## Abstract

VAREK is an open-source compiled language and runtime for verifying the behavior
of autonomous AI agents before that behavior takes effect. Policies are compiled
to a satisfiability-modulo-theories decision procedure that returns one of three
results — SATISFIED, UNSATISFIED, or UNKNOWN — and the runtime is fail-closed: an
action proceeds only on an explicit SATISFIED. The stack is vertical, from
runtime behavior at the system boundary to a formal decision over agent plans.
Through v1.8 the system proves *safety* — nothing unauthorized executes. v1.9
adds a complementary load-time *liveness* proof, certifying that an unattended
(human-out-of-the-loop) deployment always has a legal automated next move, so
"never requires a human" is certified per policy rather than assumed. v1.9.1
hardens the enforcement boundary itself: it closes an io_uring bypass, makes
file-open mediation provably race-free against a time-of-check-to-time-of-use
(TOCTOU) attack — measured at zero leaks where the prior approach leaked 510
across 20,000 attempts — fails closed on actions it cannot yet mediate race-free,
and publishes the project threat model and trusted-computing-base.

---

## 1. Motivation

Agentic AI systems act in the world: they call tools, read and write data, and
chain those actions toward goals. The dominant safety posture is probabilistic —
a system that is "usually right." Medicine does not deploy systems that are
usually right, because the tail is where people get hurt. VAREK applies that
standard to agent behavior.

The governing principle is **authorization before execution**: an action is
checked against an explicit policy, with a determinate decision, before it is
allowed to take effect. The decision procedure does not guess. When it cannot
prove an action satisfies policy, it returns UNKNOWN, and the runtime refuses to
proceed. A refusal is a safe outcome; an unverified action is not.

---

## 2. Architecture overview

VAREK is a single vertical stack. Runtime behavior observed at the system
boundary is mapped to structured actions; those actions, individually and as
plans, are checked against compiled policy; and a determinate decision gates
execution.

### 2.1 Surface language and compilation

Policies are written in the `var::` surface language and compiled to a formal
representation suitable for a decision procedure. The compiler is the trust
boundary between human-authored intent and machine-checked obligation.

### 2.2 Decision procedure and three-state semantics

Compiled policy is discharged by a satisfiability-modulo-theories decision
procedure returning SATISFIED, UNSATISFIED, or UNKNOWN. UNKNOWN is never coerced
to a pass; the runtime treats it as fail-closed.

### 2.3 Pre-execution action-graph verification (v1.6)

Agent plans are represented as action graphs and verified compositionally before
any constituent action runs. As a plan is revised mid-task it is re-verified, so
the authorization guarantee holds across plan changes rather than only at the
start.

### 2.4 Kernel-boundary integration (v1.7)

The verification layer binds to runtime enforcement at the system boundary.
Observed low-level behavior is intercepted, lifted into structured actions,
checked against policy, and gated before the action completes. The same policy a
developer reasons about in the surface language is the policy enforced against
the agent's actual runtime behavior — not a weaker approximation of it.

### 2.5 Cross-action data-flow verification (v1.8)

v1.8 extends verification from single actions to data flow across sequences of
actions, tracking where data originates and where it is permitted to travel.
Policies can express constraints over information movement — for example, that
data drawn from a sensitive source must not reach a particular sink — rather than
evaluating each action without regard to what came before it. v1.8.0 adds
operator-designated, audited declassification (sanitize-then-send), the only
mechanism that can bypass the read-secret-then-exfiltrate guarantee, governed by
four test-pinned safety properties.

### 2.6 Progress-safety verification (v1.9)

v1.6–v1.8 prove safety: nothing unauthorized executes. They do not by themselves
prove *liveness* — that the system always has a legal, automated next move. An
unattended deployment needs both, or "never requires a human" is a hope: a policy
could admit a reachable state in which an action is refused and no authorized
fallback exists, a deadlock only a human could break.

v1.9 discharges that obligation once, at policy load, before anything runs. It
certifies:

> For every non-authorizing verdict (UNSATISFIED or UNKNOWN) the policy can
> produce, the deterministic refusal resolution reaches an automated terminal
> outcome in finitely many steps, with no point requiring human intervention.

The proof decomposes into four obligations — bounded refusal, disposed UNKNOWN,
disposed exhaustion, and an authorized-fallback reachability proof that composes
the underlying decision procedure as its authorization oracle. The result is
three-state like every other VAREK verdict: SATISFIED (certified
human-out-of-the-loop), UNSATISFIED (a concrete gap, failing obligation named),
UNKNOWN (could not decide; fail closed, not certified). Used as an
unattended-startup gate, it makes "no human at run time" provable: if no
automated terminal is guaranteed, the system never reaches run time.

### 2.7 Enforcement hardening (v1.9.1)

v1.9.1 hardens the Warden's kernel-boundary enforcement and is the first release
to publish a measured result for the enforcement layer itself.

**io_uring bypass closed.** io_uring dispatches operations from kernel worker
threads off the syscall entry path, where a seccomp filter — and therefore the
Warden's user-notification mediation — cannot observe them. A policy that mediates
file or network syscalls was silently bypassable by routing the same operations
through an io_uring instance. The Warden's filter now denies io_uring instance
creation outright; there is no sound way to mediate it at this layer.

**TOCTOU discipline, measured.** When a mediation decision depends on a pointer
argument — a path, a socket address — letting the original syscall proceed after
approval is unsafe: a second thread in the target can rewrite the argument between
the check and the kernel's use of it. v1.9.1 removes that pattern. For file opens,
the supervisor resolves the approved path itself (with magic-link resolution
disabled) and injects the resulting descriptor into the target, so the target's
syscall never runs against mutable memory. Measured against a TOCTOU race harness,
the approve-then-continue strategy leaked the protected target 510 times across
20,000 attempts; the resolve-and-inject strategy leaked 0. Network and exec
actions (`connect`, `execve`) cannot yet be mediated race-free — there is no
descriptor to inject for a connection — so they are deny-only (fail closed)
pending the supervisor-dials-and-injects path on the v1.10 roadmap. Agent network
egress is deny-only at this version, by design.

**Scope.** The hardening applies to the reference Warden supervisor. In the public
source tree the verification layer and the Warden are integrated by reference; the
syscall filter is allow-by-default for unlisted syscalls, so alternate-ABI and
variant-syscall bypass classes remain open and are addressed by a planned
default-deny allowlist. These boundaries are stated in the published threat model
rather than blurred.

---

## 3. Three-state decision semantics

The three-state result is the core of VAREK's safety claim and the reason the
system is honest about its own limits.

| Result | Meaning | Runtime behavior |
|---|---|---|
| SATISFIED | Provably compliant | Proceed |
| UNSATISFIED | Provably non-compliant | Deny |
| UNKNOWN | Not provable within bounds | Fail closed (deny) |

A two-state system is forced to convert every UNKNOWN into either a false pass or
a false block. VAREK refuses that conversion: it reports UNKNOWN as UNKNOWN and
lets the fail-closed runtime resolve it safely. This is the difference between a
verifier and a heuristic.

### 3.1 Soundness, and why UNKNOWN is the honest residue

VAREK is **sound but deliberately incomplete**. Soundness: no action is reported
SATISFIED unless it provably satisfies policy. Incompleteness: some safe actions
cannot be proved safe within the decision procedure's bounds and are reported
UNKNOWN. The asymmetry is intentional — over-refusing a safe action is a utility
cost; wrongly authorizing an unsafe one is a safety failure. The system is built
to never make the second trade.

This is also why the input space being effectively infinite is not a problem the
way enumerating edge cases would be. The decision procedure reasons over whole
domains symbolically rather than sampling points, and the three-state verdict is
*total*: every input lands in exactly one of SATISFIED / UNSATISFIED / UNKNOWN,
deterministically, with UNKNOWN as the fail-safe residue. Coverage of the
infinite space is by construction, not by enumeration.

### 3.2 UNKNOWN diagnostics and resource bounds (v1.9.1)

Two additive changes in v1.9.1 touch the decision layer without altering any
SATISFIED or UNSATISFIED outcome. UNKNOWN verdicts now carry a diagnostic — the
undischarged predicate and the fragment that would resolve it — so a refusal is
navigable rather than opaque, ahead of the v1.10/v1.11 fragments that will
actually shrink the UNKNOWN region. And the decision procedure now enforces
deterministic resource bounds (a step ceiling, a wall-clock safety net, and
obligation memoization); a bound hit yields UNKNOWN, never a coerced pass, so a
forced timeout degrades to a safe refusal rather than a hang or a silent
authorization.

---

## 4. Verification scope and guarantees

VAREK verifies that agent actions and plans satisfy explicitly authored policy,
that data flow across actions respects explicitly authored information-flow
constraints, and (v1.9) that an unattended policy is progress-safe. The
guarantees are relative to the policy as written and to the fidelity of the
action model derived at the system boundary.

**Explicit information flow.** The v1.8 data-flow subsystem covers explicit flows
— data that moves through observable action inputs and outputs. Coverage of
implicit flows (information conveyed through control structure rather than data
movement) is on the roadmap and is not claimed in this release. The boundary is
stated rather than blurred.

The published `docs/security/THREAT-MODEL.md` and
`docs/security/TRUSTED-COMPUTING-BASE.md` are the authoritative statement of
assumptions, in-scope and out-of-scope threats, the adversary models, and the
per-component trusted-vs-verified status of the verification chain. The dataflow
threat model documents the v1.8 information-flow boundary.

---

## 5. Quality and testing

The testing posture mirrors the runtime posture: where a guarantee cannot be
established, the build fails closed rather than presenting an unverified result
as a passing one.

- Verification checks across multiple test suites; sanitizer-clean builds on all
  supported platforms.
- Platform fail-closed CI: the build fails closed on platforms where the
  enforcement backend cannot be guaranteed, rather than degrading silently.
- v1.9 progress verifier: `test_v19_progress.c`, 10/10, clean under
  `-fsanitize=address,undefined`.
- v1.9.1 enforcement, measured directly: a TOCTOU race harness
  (`tests/seccomp_toctou_harness.c`) reports 510 sentinel leaks across 20,000
  attempts for approve-then-continue versus 0 for resolve-and-inject; io_uring
  denial is checked under the Warden filter (`v1_7/tests/test_v191_io_uring.c`).

---

## 6. Demo

A narrated demo walks through the stack end to end: authorization on a compliant
action, denial on a violating action, fail-closed behavior on UNKNOWN, and
cross-action data-flow scenarios where a sequence is blocked on the basis of
where data originated. A browser visualization of the three-state verdict is
published on the project site; the runnable C demo is in the repository
(`v1_7`, `make demo`; `demo_hootl.c` for the v1.9 HOOTL walkthrough).

---

## 7. Documentation

- **INTEGRATION-hotl.md** — using the progress verifier as an unattended-startup
  gate.
- **docs/security/THREAT-MODEL.md** — adversary models, in-scope guarantees,
  out-of-scope non-goals, and the open bypass classes, stated rather than blurred.
- **docs/security/TRUSTED-COMPUTING-BASE.md** — per-component trusted-vs-verified
  status of the verification chain and the plan to shrink the trusted base.
- **docs/security/v1.9.1-verifier-notes.md** — the UNKNOWN-diagnostic and
  resource-bound specifications.
- **RELEASE-v1.9.1.md** — the v1.9.1 enforcement-hardening release notes, with the
  measured TOCTOU result.
- **threat-model-dataflow.md** — the v1.8 information-flow boundary.
- **docs/adr/0001-syscall-layer.md** — the syscall-layer architecture decision
  (libseccomp over raw ctypes, on correctness and audit-surface grounds).
- **SECURITY.md** — supported versions, private vulnerability reporting, and the
  security contact (kenneth.douglas@soberagents.ai).

---

## 8. Roadmap — shrinking UNKNOWN without weakening soundness

The next line (v1.10, planned; v1.11, candidate) is one program: move cases out
of UNKNOWN into provable SATISFIED or UNSATISFIED, raising the clear rate on safe
actions, under a soundness obligation that forbids ever turning an unsafe action
into SATISFIED. The marketable end is a measured number — clear rate on a
realistic workload at sub-millisecond decision latency with zero unsafe
authorizations — not theory coverage; theory extension is only the means.

1. **Verdict-distribution harness (v1.10, first).** Measurement and regression
   gating over a corpus of realistic agent action-graphs. Ground truth is the
   customer-authored policy; adversarial near-miss labels come from an
   independent oracle. A measured baseline is itself a milestone.
2. **Bitvector flag/argument fragment (v1.10).** Decidable reasoning over
   syscall flag/argument bits; lowest audit cost; aligned with the Warden kernel
   layer.
3. **Bounded string fragment (v1.10, headline).** Length-bounded path/host
   reasoning so prefix and allowlist predicates are provable rather than refused;
   the largest expected reduction in over-refusal, with a length-guard escape
   that keeps it sound.
4. **Bounded sequence fragment (v1.11, candidate).** Element-level reasoning for
   the cross-action data-flow subsystem, composed on top of the string and
   bitvector fragments.

Also on the roadmap: race-free network mediation (a supervisor-dials-and-injects
path that replaces the v1.9.1 deny-only posture for `connect`); a default-deny
syscall allowlist closing the alternate-ABI and variant-syscall bypass classes at
the Warden boundary; expanded information-flow coverage including implicit flows;
surface-language ergonomics for `var::`; and continued external audit and
independent assurance engagement. These are stated as direction; they are not
present in the current release and are not claimed.

External validation context: the DARPA/NSF AI Forge program (June 2026) names
provably secure-by-construction agent sandboxes with verifiable action and
information-flow bounds and low-latency runtime intervention as a national
priority — the problem class VAREK's shipped architecture addresses. This is
cited as third-party validation of the problem, not as a claim of program
involvement.

---

## 9. Licensing and intellectual property

VAREK is released under the **MIT license**. Three provisional patent
applications are on file covering the formal-verification (SMT decision
procedure) layer, the Warden kernel-level enforcement architecture, and
action-graph compositional policy decision. The project is **patent-pending**;
nothing in this release is granted. Non-provisional conversions begin in 2027.
Relicensing considerations are deferred pending conversion.

---

## Appendix A — Version history

| Version | Focus |
|---|---|
| v1.0 (Apr 2026) | Public launch. Formal-verification layer, MIT license. |
| v1.1 | Same-day security release: pluggable isolation backend; subprocess-boundary fix. |
| v1.5 | Warden runtime (seccomp-unotify, kernel-boundary enforcement). |
| v1.6 | Pre-execution verification of agent action graphs; compositional three-state decision. |
| v1.7 | Kernel-boundary integration; vertical stack from system boundary to formal decision. |
| v1.8 | Cross-action data-flow verification; audited declassification (v1.8.0); bounded-refusal breaker (v1.8.2). |
| v1.8.1 | Stable release candidate for the v1.7/v1.8 line; narrated demo; threat-model docs. |
| v1.9 | Progress-safety verification. Load-time liveness proof; certified human-out-of-the-loop. |
| **v1.9.1** | **Enforcement hardening.** io_uring bypass closed; TOCTOU-safe file-open mediation (measured 510&#8594;0 on the race harness); connect/execve deny-only; threat-model and trusted-computing-base published. |
| v1.10 (planned) | Verdict-distribution harness; bitvector and bounded-string fragments. Shrinking UNKNOWN. |
| v1.11 (candidate) | Bounded-sequence fragment for cross-action data flow. |

---

*Copyright Sober Agentic Infrastructure, Inc. VAREK is open source under the MIT
license.*
