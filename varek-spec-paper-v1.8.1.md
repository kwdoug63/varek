# VAREK — Technical Specification

**Version 1.8.1 (stable release candidate)**
Deterministic runtime verification of autonomous AI agents using formal methods.

Author: Kenneth Wayne Douglas, MD
Published by Sober Agentic Infrastructure, Inc.
Security contact: kenneth.douglas@soberagents.ai
License: MIT · Project: varek-lang.org · Source: github.com/kwdoug63/varek

---

## Abstract

VAREK is an open-source compiled language and runtime for verifying the behavior of
autonomous AI agents before that behavior takes effect. Policies are compiled to a
satisfiability-modulo-theories decision procedure that returns one of three results —
SATISFIED, UNSATISFIED, or UNKNOWN — and the runtime is fail-closed: an action proceeds
only on an explicit SATISFIED. v1.8.1 consolidates the v1.7 kernel-boundary integration
and the v1.8 cross-action data-flow verification subsystem into a single vertical stack,
from runtime behavior at the system boundary to a formal decision over agent plans. This
release is the stable candidate for the v1.7/v1.8 line: 207 verification checks across six
test suites, sanitizer-clean builds on all supported platforms, an eight-scenario narrated
demo, and published integration and threat-model documentation.

---

## 1. Motivation

Agentic AI systems act in the world: they call tools, read and write data, and chain
those actions toward goals. The dominant safety posture is probabilistic — a system that
is "usually right." Medicine does not deploy systems that are usually right, because the
tail is where people get hurt. VAREK applies that standard to agent behavior.

The governing principle is **authorization before execution**: an action is checked
against an explicit policy, with a determinate decision, before it is allowed to take
effect. The decision procedure does not guess. When it cannot prove an action satisfies
policy, it returns UNKNOWN, and the runtime refuses to proceed. A refusal is a safe
outcome; an unverified action is not.

---

## 2. Architecture overview

VAREK is a single vertical stack. Runtime behavior observed at the system boundary is
mapped to structured actions; those actions, individually and as plans, are checked
against compiled policy; and a determinate decision gates execution.

### 2.1 Surface language and compilation

Policies are written in the `var::` surface language and compiled to a formal
representation suitable for a decision procedure. The compiler is the trust boundary
between human-authored intent and machine-checked obligation.

### 2.2 Decision procedure and three-state semantics

Compiled policy is discharged by a satisfiability-modulo-theories decision procedure. The
procedure returns one of three results:

- **SATISFIED** — the action provably satisfies policy. Execution may proceed.
- **UNSATISFIED** — the action provably violates policy. Execution is denied.
- **UNKNOWN** — the procedure cannot establish either result within its bounds.

UNKNOWN is not coerced to a pass. The runtime treats UNKNOWN as fail-closed.

### 2.3 Kernel-boundary integration (v1.7)

The verification layer binds to runtime enforcement at the system boundary. Observed
low-level behavior is intercepted, lifted into structured, semantically meaningful actions,
checked against policy, and gated before the action completes. This is what makes the
stack vertical: the same policy that a developer reasons about in the surface language is
the policy enforced against the agent's actual runtime behavior, not a separate, weaker
approximation of it.

### 2.4 Pre-execution action-graph verification (v1.6)

Agent plans are represented as action graphs and verified compositionally before any
constituent action runs. As a plan is revised mid-task, it is re-verified continuously, so
the authorization guarantee holds across plan changes rather than only at the start.

### 2.5 Cross-action data-flow verification (v1.8)

v1.8 extends verification from single actions to data flow across sequences of actions.
The subsystem tracks where data originates and where it is permitted to travel, so policies
can express constraints over information movement — for example, that data drawn from a
sensitive source must not reach a particular sink — rather than evaluating each action
without regard to what came before it.

---

## 3. Three-state decision semantics

The three-state result is the core of VAREK's safety claim and the reason the system is
honest about its own limits.

| Result | Meaning | Runtime behavior |
|---|---|---|
| SATISFIED | Provably compliant | Proceed |
| UNSATISFIED | Provably non-compliant | Deny |
| UNKNOWN | Not provable within bounds | Fail closed (deny) |

A two-state system is forced to convert every UNKNOWN into either a false pass or a false
block. VAREK refuses that conversion: it reports UNKNOWN as UNKNOWN and lets the fail-closed
runtime resolve it safely. This is the difference between a verifier and a heuristic.

---

## 4. Verification scope and guarantees

VAREK verifies that agent actions and plans satisfy explicitly authored policy, and that
data flow across actions respects explicitly authored information-flow constraints. The
guarantees are relative to the policy as written and to the fidelity of the action model
derived at the system boundary.

**Explicit information flow.** The v1.8 data-flow subsystem covers explicit flows — data
that moves through observable action inputs and outputs. Coverage of implicit flows
(information conveyed through control structure rather than data movement) is on the
roadmap and is not claimed in this release. This boundary is stated rather than blurred:
the system is designed to be precise about what it does and does not prove.

The published THREAT_MODEL.md is the authoritative statement of assumptions, in-scope
threats, and out-of-scope conditions.

---

## 5. Quality and testing

v1.8.1 is the stable release candidate for the v1.7/v1.8 line.

- **207 verification checks** across **six test suites**.
- **Sanitizer-clean builds** on all supported platforms.
- **Platform fail-closed CI**: the build fails closed on platforms where the enforcement
  backend cannot be guaranteed, rather than degrading silently.

The testing posture mirrors the runtime posture: where a guarantee cannot be established,
the system fails closed rather than presenting an unverified result as a passing one.

---

## 6. Demo

An eight-scenario narrated demo walks through the stack end to end: authorization on a
compliant action, denial on a violating action, fail-closed behavior on UNKNOWN, and
cross-action data-flow scenarios where a sequence is blocked on the basis of where data
originated. The demo is available via the project site and repository. [add demo link]

---

## 7. Documentation

- **INTEGRATION.md** — integrating VAREK into an agent runtime, including the isolation
  backend interface and the enforcement path.
- **THREAT_MODEL.md** — assumptions, in-scope and out-of-scope threats, and the boundaries
  of the guarantee.
- **SECURITY.md** — supported versions, private vulnerability reporting, and the security
  contact (kenneth.douglas@soberagents.ai).

---

## 8. Licensing and intellectual property

VAREK is released under the **MIT license**. Three provisional patent applications are on
file covering the formal-verification layer, the kernel-level enforcement architecture, and
pre-execution verification of agent action graphs. The project is **patent-pending**;
nothing in this release is granted. Relicensing considerations are deferred pending
non-provisional conversion.

---

## 9. Roadmap

Near-term direction, in priority order:

1. Expanded information-flow coverage, including implicit flows.
2. Surface-language ergonomics for `var::`.
3. Continued external audit and independent assurance engagement.

These are stated as direction. They are not present in v1.8.1 and are not claimed.

---

## Appendix A — Version history

| Version | Focus |
|---|---|
| v1.0 (Apr 2026) | Public launch. Formal-verification layer, MIT license. |
| v1.1 | Same-day security release: pluggable isolation backend; subprocess-boundary fix. |
| v1.6 | Pre-execution verification of agent action graphs; compositional three-state decision. |
| v1.7 | Kernel-boundary integration; vertical stack from system boundary to formal decision. |
| v1.8 | Cross-action data-flow verification subsystem. |
| **v1.8.1** | **Stable release candidate.** 207 checks / six suites / sanitizer-clean; eight-scenario narrated demo; integration and threat-model docs. |

---

*Copyright Sober Agentic Infrastructure, Inc. VAREK is open source under the MIT license.
Replace `[add demo link]` before publication.*
