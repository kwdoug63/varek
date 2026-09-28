<!-- SPDX-License-Identifier: MIT -->

# VAREK — Technical Specification

**Version 1.12.0 (current)**

*Deterministic runtime verification of autonomous AI agents using formal methods.*

Author: Kenneth Wayne Douglas, MD
Published by Sober Agentic Infrastructure, Inc.
Security contact: kenneth.douglas@soberagents.ai
License: MIT · Project: [varek-lang.org](https://varek-lang.org) · Source: [github.com/kwdoug63/varek](https://github.com/kwdoug63/varek)

---

## Abstract

VAREK is an open-source compiled language and runtime for verifying the behavior of autonomous AI agents before that behavior takes effect. Policies are compiled to a satisfiability-modulo-theories decision procedure that returns one of three results — SATISFIED, UNSATISFIED, or UNKNOWN — and the runtime is fail-closed: an action proceeds only on an explicit SATISFIED. The stack is vertical, from runtime behavior at the system boundary to a formal decision over agent plans.

Through v1.8 the system proves *safety* — nothing unauthorized executes. v1.9 adds a complementary load-time *liveness* proof, certifying that an unattended (human-out-of-the-loop) deployment always has a legal automated next move, so "never requires a human" is certified per policy rather than assumed. v1.9.1 hardened the enforcement boundary — closing an io_uring bypass and making file-open mediation provably race-free against a time-of-check-to-time-of-use (TOCTOU) attack, measured at zero leaks where the prior approach leaked 510 across 20,000 attempts. v1.9.2 completes that boundary's inversion: the Warden's syscall filter moves from allow-by-default to a *default-deny allowlist* with native-ABI lockdown (closing the x32 bypass), a hard-deny set for never-admissible syscalls, and scalar-flag denial of unprivileged user namespaces. The default-deny baseline is wired into the live reference Warden and validated end-to-end by a conformance target that passes under enforcement; the same target surfaced and fixed a launch regression in the deny-only exec path. The previously open alternate-ABI and variant-syscall bypass classes are now closed by construction. v1.9.3 couples the agent's lifetime to the supervisor's in the live Warden: the agent runs as the first process of its own PID namespace and is killed if the supervisor stops, so neither the agent nor anything it spawned keeps running without oversight — asserted by a crash test that kills a live supervisor. v1.12 makes the Warden decide on the object it actually delivers: file opens are resolved once with symlink and magic-link resolution disabled, policy is decided on the canonical path of the resolved descriptor, and that same descriptor is handed to the agent, closing path-traversal, symlink, and `/proc/self` escapes. It also makes the authorization record unforgeable by agent-controlled input, mediates datagram egress, and exports authorization evidence in the CycloneDX 1.6 format. Releases v1.9.1 through v1.12 make no change to the three-state decision semantics.

---

## 1. Motivation

Agentic AI systems act in the world: they call tools, read and write data, and chain those actions toward goals. The dominant safety posture is probabilistic — a system that is "usually right." Medicine does not deploy systems that are usually right, because the tail is where people get hurt. VAREK applies that standard to agent behavior.

The governing principle is **authorization before execution**: an action is checked against an explicit policy, with a determinate decision, before it is allowed to take effect. The decision procedure does not guess. When it cannot prove an action satisfies policy, it returns UNKNOWN, and the runtime refuses to proceed. A refusal is a safe outcome; an unverified action is not.

---

## 2. Architecture overview

VAREK is a single vertical stack. Runtime behavior observed at the system boundary is mapped to structured actions; those actions, individually and as plans, are checked against compiled policy; and a determinate decision gates execution.

### 2.1 Surface language and compilation

Policies are written in the `var::` surface language and compiled to a formal representation suitable for a decision procedure. The compiler is the trust boundary between human-authored intent and machine-checked obligation.

### 2.2 Decision procedure and three-state semantics

Compiled policy is discharged by a satisfiability-modulo-theories decision procedure returning SATISFIED, UNSATISFIED, or UNKNOWN. UNKNOWN is never coerced to a pass; the runtime treats it as fail-closed.

In the reference Warden (from v1.13) the procedure is purpose-built for a quantifier-free fragment of two theories: bounded strings for the object an action names (canonical path, `host:port`, exec path; prefix, equality and host atoms) and 32-bit bitvectors for the open flags (`(flags & mask) == value`, ABI-faithful to the kernel's `int flags`). A policy compiles to one ordered formula per action kind. The same procedure answers concrete per-syscall queries (where satisfiability reduces to evaluation), symbolic-flag queries for the pre-execution plan gate (SATISFIED only if every admissible flags value is), and rule-reachability queries at policy load (is there any action for which a rule fires first). Its fragment boundary is a soundness obligation: an over-length string, a flag bit outside the ABI set, or a symbolic query beyond the enumeration bound is UNKNOWN. A general SMT solver is kept off the hot path (v1.5 measured tail latencies of tens of milliseconds for string theory) and used instead as an independent differential oracle over every repository policy and seeded random policies.

### 2.3 Pre-execution action-graph verification (v1.6)

Agent plans are represented as action graphs and verified compositionally before any constituent action runs. As a plan is revised mid-task it is re-verified, so the authorization guarantee holds across plan changes rather than only at the start.

### 2.4 Kernel-boundary integration (v1.7)

The verification layer binds to runtime enforcement at the system boundary. Observed low-level behavior is intercepted, lifted into structured actions, checked against policy, and gated before the action completes. The same policy a developer reasons about in the surface language is the policy enforced against the agent's actual runtime behavior — not a weaker approximation of it.

### 2.5 Cross-action data-flow verification (v1.8)

v1.8 extends verification from single actions to data flow across sequences of actions, tracking where data originates and where it is permitted to travel. Policies can express constraints over information movement — for example, that data drawn from a sensitive source must not reach a particular sink — rather than evaluating each action without regard to what came before it. v1.8.0 adds operator-designated, audited declassification (sanitize-then-send), the only mechanism that can bypass the read-secret-then-exfiltrate guarantee, governed by four test-pinned safety properties.

### 2.6 Progress-safety verification (v1.9)

v1.6–v1.8 prove safety: nothing unauthorized executes. They do not by themselves prove *liveness* — that the system always has a legal, automated next move. An unattended deployment needs both, or "never requires a human" is a hope: a policy could admit a reachable state in which an action is refused and no authorized fallback exists, a deadlock only a human could break.

v1.9 discharges that obligation once, at policy load, before anything runs. It certifies:

> For every non-authorizing verdict (UNSATISFIED or UNKNOWN) the policy can produce, the deterministic refusal resolution reaches an automated terminal outcome in finitely many steps, with no point requiring human intervention.

The proof decomposes into four obligations — bounded refusal, disposed UNKNOWN, disposed exhaustion, and an authorized-fallback reachability proof that composes the underlying decision procedure as its authorization oracle. The result is three-state like every other VAREK verdict: SATISFIED (certified human-out-of-the-loop), UNSATISFIED (a concrete gap, failing obligation named), UNKNOWN (could not decide; fail closed, not certified). Used as an unattended-startup gate, it makes "no human at run time" provable: if no automated terminal is guaranteed, the system never reaches run time.

### 2.7 Enforcement hardening (v1.9.1)

v1.9.1 hardens the Warden's kernel-boundary enforcement and is the first release to publish a measured result for the enforcement layer itself.

**io_uring bypass closed.** io_uring dispatches operations from kernel worker threads off the syscall entry path, where a seccomp filter — and therefore the Warden's user-notification mediation — cannot observe them. A policy that mediates file or network syscalls was silently bypassable by routing the same operations through an io_uring instance. The Warden's filter now denies io_uring instance creation outright; there is no sound way to mediate it at this layer.

**TOCTOU discipline, measured.** When a mediation decision depends on a pointer argument — a path, a socket address — letting the original syscall proceed after approval is unsafe: a second thread in the target can rewrite the argument between the check and the kernel's use of it. v1.9.1 removes that pattern. For file opens, the supervisor resolves the approved path itself (with magic-link resolution disabled) and injects the resulting descriptor into the target, so the target's syscall never runs against mutable memory. Measured against a TOCTOU race harness, the approve-then-continue strategy leaked the protected target 510 times across 20,000 attempts; the resolve-and-inject strategy leaked 0. Network and exec actions (`connect`, `execve`) cannot yet be mediated race-free — there is no descriptor to inject for a connection — so they are deny-only (fail closed) pending the supervisor-dials-and-injects path on the v1.10 roadmap.

**Scope, as of v1.9.1.** The hardening applied to the reference Warden supervisor, whose syscall filter was allow-by-default for unlisted syscalls — leaving the alternate-ABI and variant-syscall bypass classes open. v1.9.2 (§2.8) closes them; v1.9.3 (§2.9) closes the supervisor-lifecycle class. These boundaries are stated in the published threat model rather than blurred.

### 2.8 Mediation completeness (v1.9.2)

v1.9.2 inverts the Warden's enforcement model and wires the result into the live supervisor. Where v1.9.1 mediated a fixed set of syscalls under an allow-by-default filter, v1.9.2 makes the filter *default-deny*, so the residue — every syscall not explicitly admitted — is refused by construction rather than by enumeration. Completeness of mediation is treated as a closure property: for each policy-relevant effect, the obligation is to have enumerated all the syscalls that produce it, across all application binary interfaces.

**Default-deny allowlist.** The baseline filter is seeded with a denying default action; only an explicit allowlist is admitted. Unknown syscalls, variant syscalls (`clone3`, `openat2`, `faccessat2`, the `pidfd_*` family), and the 32-bit multiplexers (`socketcall`, `ipc`) are denied unless admitted — a bypass that was not enumerated becomes one that was not admitted.

**Native-ABI lockdown.** The deny default applies across every architecture, and no secondary ABI is admitted, so the same operation re-issued through the 32-bit compat ABI (`int 0x80`) or the x32 ABI (the syscall number with `__X32_SYSCALL_BIT` set) hits the deny path. The prior hand-built filter validated only the native architecture token and therefore serviced x32 calls as if unfiltered — the most common real-world seccomp escape. This is now closed, and is asserted on the live kernel by a release-blocking test.

**Hard-deny set and namespace denial.** Syscalls with no legitimate use inside a mediated agent — `ptrace`, `bpf`, `userfaultfd`, `process_vm_readv`/`writev`, `pidfd_getfd`, the mount/FUSE family, the kernel-module and `kexec` family, `perf_event_open`, and the key-management calls — are denied with process termination in strict mode. `clone` and `unshare` are filtered on their scalar flags argument (a register value the kernel snapshots, so the check is race-free) to deny `CLONE_NEWUSER` and the namespace-creation set, the root of a large fraction of container escapes; `clone3`, whose flags live behind a pointer that cannot be inspected at this layer, never executes: from v1.12.2 it is answered `ENOSYS`, so the C library falls back to `clone` and every thread or child passes the same flag filter (through v1.12.1 it was hard-denied, which killed any agent that started a thread).

**Supervisor and target lifetimes (specified in v1.9.2, enforced in v1.9.3).** v1.9.2 specified and shipped a lifecycle-coupling module — death-signal coupling of the target to the supervisor, a process-descriptor watch, and close-on-exec on injected descriptors. Close-on-exec was enforced by the live Warden at release; the death-signal coupling and process-descriptor watch were not yet wired into it, so the supervisor-lifecycle bypass class was partially mitigated in v1.9.2. §2.9 describes the v1.9.3 integration.

**Integration and validation.** The default-deny baseline is not a parallel artifact: it replaces the allow-by-default filter the reference Warden actually installs, mediating exactly the syscalls the supervisor models (`openat`, `connect`, `execve`, `execveat`) and admitting the rest of a target's legitimate surface. A conformance target — a running, agent-shaped workload — exercises the boundary end to end and reports a verdict per phase: it opens an allowed file (mediated, satisfied by descriptor injection), is refused a denied path, creates a socket (admitted), and is denied an outbound connection (deny-only). Under live enforcement it passes every phase. Flipping a real workload to default-deny is gated on an observe-then-enforce pass: the filter offers an observe mode whose default action logs rather than blocks, so a target's required syscalls are harvested before the deny default is turned on, while the hard-deny set still terminates on a dangerous call even while observing.

**A found-and-fixed regression.** The conformance target surfaced a latent fault: the v1.9.1 deny-only exec mediation denied *every* authorizing exec verdict, including the target's own bootstrap `execve` — so no target could launch under the post-v1.9.1 supervisor. v1.9.2 authorizes exactly the operator-specified target's first exec, once per process, before the target runs any code (no TOCTOU: the target is single-threaded and blocked in `execve`), and leaves every later, agent-initiated exec deny-only. The break was found by the conformance target and the fix verified by it.

### 2.9 Supervisor/target lifecycle coupling (v1.9.3)

Enforcement assumes the supervisor is alive. If it stops, mediated calls fail closed, but an agent that keeps running can still act through capabilities it already holds. v1.9.3 removes that window in the live Warden.

**The agent dies with the supervisor.** The target requests a kill signal on supervisor death before it installs its filter; the agent cannot clear the request afterwards, because the call that sets it is outside the baseline allowlist. A supervisor that dies between fork and that request would leave the target unmonitored, so the target first confirms, through a pipe only the supervisor holds open, that the supervisor is still alive, and refuses to continue if it is not.

**So does everything the agent spawned.** A death signal applies to one process, not to the processes it creates. The target therefore runs as the first process of a dedicated PID namespace; when that process dies, the kernel kills every other process in the namespace. On orderly shutdown the supervisor kills the whole tree (namespace and process group). The supervisor watches the target through a process descriptor alongside the notification listener, which also closes a hang in which the target exited just before the supervisor blocked waiting for its next request.

**Fail closed on setup.** The namespace requires `CAP_SYS_ADMIN`. The Warden checks for it at startup and refuses to run without it; an explicit opt-out runs without the namespace and states that spawned processes are then not covered on a supervisor crash.

**Validation.** A crash test runs the live Warden over an agent that spawns a child, kills the supervisor with `SIGKILL` and, separately, stops it with `SIGTERM`, and asserts that no agent process survives either; it also checks the fork-race guard. Against the pre-fix Warden it fails (two survivors after a crash, one after orderly shutdown); against v1.9.3 it passes. Policy decisions on the demo, plan-verification, benchmark, and conformance workloads are unchanged. Inside the namespace the agent observes its own process ID as 1; audit records carry the host process ID.

The single-threaded reference Warden handles one notification at a time, so pending requests queue in the kernel rather than in supervisor memory. The in-flight notification bound described with the v1.9.2 module applies to a future multi-threaded supervisor and is not claimed for this release.

### 2.10 Mediation correctness (v1.12)

A decision is only as sound as the identity of the object it is made about, and a record is only evidence if the process it describes cannot forge it. Through v1.9.3 the reference Warden fell short on both counts in ways that did not change the decision *procedure* but let a determined agent reach a denied object or corrupt the authorization log. v1.12 closes them. The three-state semantics and the symmetric-suppression invariant are unchanged; v1.10 and v1.11 remain reserved for the verification program of §8.

**Resolve-then-decide.** The prior Warden matched policy against the pathname string the agent supplied and then, separately, opened whatever that string resolved to — two steps that could name two different objects. A relative-path escape (`/allowed/../../denied`) matched an allowed prefix as text; a symlink planted inside an allowed directory was followed to a denied target; and `/proc/self`, a magic symlink the kernel resolves in the *caller's* context, resolved to the supervisor rather than the agent, so an agent opening `/proc/self/mem` received a handle on the Warden. v1.12 opens the object once with symlink and magic-link resolution disabled, reads the canonical path back from the resolved descriptor, decides policy on that path, and hands the agent the same descriptor it resolved. Decision and delivered capability refer to the same inode by construction, and there is no second resolution to race. The resolver flags the prior threat model already claimed (no-symlinks in addition to no-magic-links) are now the flags the code sets; the earlier build set only the latter.

**Audit-log integrity.** The agent-controlled pathname was interpolated into the JSON pathology record without escaping, so a crafted path could inject a forged authorization record into the verdict stream a downstream consumer reads. v1.12 escapes every agent-controlled field, so each record is well-formed for any input and no agent string can begin, end, or fabricate a record. Each record additionally reports the resolved canonical object the decision was made on.

**Datagram-egress mediation.** The baseline filter admitted the datagram send calls unconditionally, so an agent could reach the network with a connectionless send and never invoke the deny-only connection call — a residue of the superseded allow-by-default model. Those sends are now mediated on the same footing as connection setup: a send carrying a network destination is refused under the deny-only network posture, while inbound receive calls remain admitted. Mediating the send path required moving the bootstrap handoff of the notification listener off of message-passing (which the new mediation would itself trap during startup) and onto a descriptor-transfer primitive the supervisor drives, so no post-filter message send is needed.

**Evidence export.** The pathology stream exports as a Bill of Materials in the CycloneDX 1.6 format — the runtime as a tool component with its license and provisional-patent references, the supervised run as the subject component, each authorized object as a component, and an Authorization-Before-Execution attestation as an annotation. Output validates against the published CycloneDX 1.6 schema. The exporter refuses a stream that does not parse cleanly, so a corrupted log cannot be laundered into an attestation. (CycloneDX is a trademark of the OWASP Foundation; VAREK is not affiliated with or endorsed by the OWASP Foundation or the CycloneDX project, and uses the name only to describe interoperability with the openly published CycloneDX format, standardized as ECMA-424. See the project NOTICE file.)

**Validation.** An adversarial target exercises all four escapes and one legitimate open under the reference Warden; the harness asserts on both the agent's view and the verdict stream, including that the stream remains well-formed with no injected record. It fails against the pre-v1.12 Warden and passes against v1.12. Decisions on the demo, plan-verification, benchmark, and conformance workloads are unchanged except that traversal and symlink opens previously mis-authorized are now correctly refused.

---

## 3. Three-state decision semantics

The three-state result is the core of VAREK's safety claim and the reason the system is honest about its own limits.

| Result | Meaning | Runtime behavior |
|--------|---------|------------------|
| SATISFIED | Provably compliant | Proceed |
| UNSATISFIED | Provably non-compliant | Deny |
| UNKNOWN | Not provable within bounds | Fail closed (deny) |

A two-state system is forced to convert every UNKNOWN into either a false pass or a false block. VAREK refuses that conversion: it reports UNKNOWN as UNKNOWN and lets the fail-closed runtime resolve it safely. This is the difference between a verifier and a heuristic.

### 3.1 Soundness, and why UNKNOWN is the honest residue

VAREK is **sound but deliberately incomplete**. Soundness: no action is reported SATISFIED unless it provably satisfies policy. Incompleteness: some safe actions cannot be proved safe within the decision procedure's bounds and are reported UNKNOWN. The asymmetry is intentional — over-refusing a safe action is a utility cost; wrongly authorizing an unsafe one is a safety failure. The system is built to never make the second trade.

This is also why the input space being effectively infinite is not a problem the way enumerating edge cases would be. The decision procedure reasons over whole domains symbolically rather than sampling points, and the three-state verdict is *total*: every input lands in exactly one of SATISFIED / UNSATISFIED / UNKNOWN, deterministically, with UNKNOWN as the fail-safe residue. Coverage of the infinite space is by construction, not by enumeration.

### 3.2 UNKNOWN diagnostics and resource bounds (v1.9.1)

Two additive changes in v1.9.1, unchanged through v1.12, touch the decision layer without altering any SATISFIED or UNSATISFIED outcome. UNKNOWN verdicts carry a diagnostic — the undischarged predicate and the fragment that would resolve it — so a refusal is navigable rather than opaque, ahead of the v1.10/v1.11 fragments that will actually shrink the UNKNOWN region. The decision procedure enforces deterministic resource bounds (a step ceiling, a wall-clock safety net, and obligation memoization); a bound hit yields UNKNOWN, never a coerced pass, so a forced timeout degrades to a safe refusal rather than a hang or a silent authorization.

---

## 4. Verification scope and guarantees

VAREK verifies that agent actions and plans satisfy explicitly authored policy, that data flow across actions respects explicitly authored information-flow constraints, and (v1.9) that an unattended policy is progress-safe. The guarantees are relative to the policy as written and to the fidelity of the action model derived at the system boundary.

**Independence from the agent platform.** The decision procedure and the Warden run outside the supervised agent and do not depend on its model provider, agent framework, or orchestration platform: the action model is derived at the system boundary, and enforcement uses Linux seccomp user-notify (seccomp-BPF), which applies to any supervised process. The verdict stream and its CycloneDX 1.6 export are produced by the Warden, not by the agent or its vendor, so a third party can inspect the authorization record without relying on the vendor that built the agent. The dependency is on the host kernel (Linux with seccomp user-notify) and on the Warden's trusted computing base, stated in `docs/security/TRUSTED-COMPUTING-BASE.md`; it is not on any particular model or agent platform.

**Explicit information flow.** The v1.8 data-flow subsystem covers explicit flows — data that moves through observable action inputs and outputs. Coverage of implicit flows (information conveyed through control structure rather than data movement) is on the roadmap and is not claimed in this release. The boundary is stated rather than blurred. The published `docs/security/threat-model.md`, `docs/security/bypass-classes.md`, and `docs/security/TRUSTED-COMPUTING-BASE.md` are the authoritative statement of assumptions, adversary models, in-scope and out-of-scope threats, the per-class mediation status, and the per-component trusted-vs-verified status of the verification chain.

---

## 5. Quality and testing

The testing posture mirrors the runtime posture: where a guarantee cannot be established, the build fails closed rather than presenting an unverified result as a passing one.

- Verification checks across multiple test suites; sanitizer-clean builds on all supported platforms.
- Platform fail-closed CI: the build fails closed on platforms where the enforcement backend cannot be guaranteed, rather than degrading silently.
- v1.9 progress verifier: `test_v19_progress.c`, 10/10, clean under `-fsanitize=address,undefined`.
- v1.9.1 enforcement, measured directly: a TOCTOU race harness (`tests/seccomp_toctou_harness.c`) reports 510 sentinel leaks across 20,000 attempts for approve-then-continue versus 0 for resolve-and-inject; io_uring denial is checked under the Warden filter (`v1_7/tests/test_v191_io_uring.c`).
- v1.9.2 mediation completeness, asserted on the live kernel: `test_v192_abi_lockdown.c` admits the native call and kills the x32 call (release-blocking); `test_v192_baseline_deny.c` confirms `ptrace`, `bpf`, `userfaultfd`, `process_vm_readv`, `pidfd_getfd`, `perf_event_open`, and `clone`/`unshare(CLONE_NEWUSER)` are all denied.
- v1.9.2 end-to-end, under the live Warden: `target_conformance` passes all phases (allowed-file round-trip via descriptor injection, denied-path refusal, socket admitted, outbound connect denied); the bootstrap-exec fix is corroborated by the demo target launching under enforcement. The target reports a missing work directory as a setup failure rather than a boundary failure (v1.9.3).
- v1.9.3 lifecycle coupling, under the live Warden: `test_v193_lifecycle.c` kills the supervisor (`SIGKILL`, then `SIGTERM`) while it supervises an agent with a child process and asserts no agent process survives; it also exercises the fork-race guard.

---

## 6. Demo

A narrated demo walks through the stack end to end: authorization on a compliant action, denial on a violating action, fail-closed behavior on UNKNOWN, and cross-action data-flow scenarios where a sequence is blocked on the basis of where data originated. A browser visualization of the three-state verdict is published on the project site; the runnable C demo is in the repository (`v1_7`, `make demo`; `demo_hootl.c` for the v1.9 HOOTL walkthrough), and the conformance target (`target_conformance`) runs a real workload under the live Warden.

---

## 7. Documentation

- `INTEGRATION-hotl.md` — using the progress verifier as an unattended-startup gate.
- `docs/security/threat-model.md` — adversary models, in-scope guarantees, and out-of-scope non-goals.
- `docs/security/bypass-classes.md` — the bypass-class checklist and mediation-completeness argument, with per-class status (closed / contained / roadmap / out-of-scope).
- `docs/security/v1.9.2-baseline-allowlist.md` — the default-deny allowlist rationale and class-to-syscall map.
- `docs/security/v1.10-architecture-roadmap.md` — the model- and TCB-changing track (Landlock, acquisition-tiering, post-grant re-mediation, the UNKNOWN escalation ladder, TCB shrink via proof-checking).
- `docs/security/TRUSTED-COMPUTING-BASE.md` — per-component trusted-vs-verified status of the verification chain and the plan to shrink the trusted base.
- `RELEASE-v1.9.3.md` — the v1.9.3 lifecycle-coupling release notes.
- `RELEASE-v1.9.2.md` — the v1.9.2 mediation-completeness release notes.
- `docs/adr/0001-syscall-layer.md` — the syscall-layer architecture decision (libseccomp over raw ctypes, on correctness and audit-surface grounds).
- `SECURITY.md` — supported versions, private vulnerability reporting, and the security contact (kenneth.douglas@soberagents.ai).

---

## 8. Roadmap — shrinking UNKNOWN without weakening soundness

The program (named v1.10/v1.11; its first release shipped as v1.13.0 — the decision procedure above, the bitvector flag fragment, the prefix/equality part of the string fragment, and a verdict-distribution harness with an `unsafe_satisfied == 0` gate) is one program: move cases out of UNKNOWN into provable SATISFIED or UNSATISFIED, raising the clear rate on safe actions, under a soundness obligation that forbids ever turning an unsafe action into SATISFIED. The marketable end is a measured number — clear rate on a realistic workload at sub-millisecond decision latency with zero unsafe authorizations — not theory coverage; theory extension is only the means.

1. **Verdict-distribution harness (v1.10, first).** Measurement and regression gating over a corpus of realistic agent action-graphs. Ground truth is the customer-authored policy; adversarial near-miss labels come from an independent oracle. A measured baseline is itself a milestone.
2. **Bitvector flag/argument fragment (v1.10).** Decidable reasoning over syscall flag/argument bits; lowest audit cost; aligned with the Warden kernel layer.
3. **Bounded string fragment (v1.10, headline).** Length-bounded path/host reasoning so prefix and allowlist predicates are provable rather than refused; the largest expected reduction in over-refusal, with a length-guard escape that keeps it sound.
4. **Bounded sequence fragment (v1.11, candidate).** Element-level reasoning for the cross-action data-flow subsystem, composed on top of the string and bitvector fragments.

Also on the enforcement roadmap, tracked in the v1.10 architecture document: race-free network mediation (a supervisor-dials-and-injects path that replaces the v1.9.1 deny-only posture for `connect`); race-free filesystem enforcement and trusted-base reduction via a kernel-native sandbox; acquisition-time mediation tiering with a latency gate; an optional post-grant re-mediation mode; expanded information-flow coverage including implicit flows; surface-language ergonomics for `var::`; and continued external audit and independent assurance engagement. The default-deny allowlist that closes the alternate-ABI and variant-syscall bypass classes, previously listed here as direction, shipped in v1.9.2. These remaining items are stated as direction; they are not present in the current release and are not claimed.

External validation context: the DARPA/NSF AI Forge program (June 2026) names provably secure-by-construction agent sandboxes with verifiable action and information-flow bounds and low-latency runtime intervention as a national priority — the problem class VAREK's shipped architecture addresses. This is cited as third-party validation of the problem, not as a claim of program involvement.

---

## 9. Licensing and intellectual property

VAREK is released under the **MIT license**. Three provisional patent applications are on file covering the formal-verification (SMT decision procedure) layer, the Warden kernel-level enforcement architecture, and action-graph compositional policy decision. The project is **patent-pending**; nothing in this release is granted. Non-provisional conversions begin in 2027. Relicensing considerations are deferred pending conversion.

---

## Appendix A — Version history

| Version | Focus |
|---------|-------|
| v1.0 (Apr 2026) | Public launch. Formal-verification layer, MIT license. |
| v1.1 | Same-day security release: pluggable isolation backend; subprocess-boundary fix. |
| v1.5 | Warden runtime (seccomp-unotify, kernel-boundary enforcement). |
| v1.6 | Pre-execution verification of agent action graphs; compositional three-state decision. |
| v1.7 | Kernel-boundary integration; vertical stack from system boundary to formal decision. |
| v1.8 | Cross-action data-flow verification; audited declassification (v1.8.0); bounded-refusal breaker (v1.8.2). |
| v1.8.1 | Stable release candidate for the v1.7/v1.8 line; narrated demo; threat-model docs. |
| v1.9 | Progress-safety verification. Load-time liveness proof; certified human-out-of-the-loop. |
| v1.9.1 | Enforcement hardening. io_uring bypass closed; TOCTOU-safe file-open mediation (measured 510→0 on the race harness); connect/execve deny-only; threat-model and trusted-computing-base published. |
| v1.9.2 | Mediation completeness. Default-deny allowlist replacing allow-by-default; native-ABI lockdown (x32 bypass closed); hard-deny set; scalar-flag CLONE_NEWUSER denial; lifecycle-coupling module (integrated in v1.9.3). Default-deny baseline wired into the live Warden and validated by a conformance target; deny-only bootstrap-exec regression found and fixed. |
| v1.9.3 | Lifecycle coupling in the live Warden. Agent runs in its own PID namespace and dies with the supervisor, along with everything it spawned; fork-race guard; process-descriptor watch; `CAP_SYS_ADMIN` preflight; crash test. Corrects the v1.9.2 status of the supervisor-lifecycle bypass class (partial at v1.9.2). |
| **v1.13.0** | **SMT decision procedure in the enforcement path** (first release of the v1.10 program). Bounded-string + bitvector fragment; open-flag policy clauses (`readonly`); load-time rule-reachability analysis; solver cross-check (zero disagreements); verdict-distribution harness (synthetic seed: 88.5% clear, 0 unsafe SATISFIED, vs 42.3% for the only v1.12 policy with 0). Adds `test-v1130`. |
| **v1.12.4** | **`--plan` gate fix.** The optional pre-execution plan gate decides a `file_open` node on the lexically canonical declared path; since v1.12.0 it left the resolved field the per-open decision reads empty, so every plan that opened a file was rejected as UNKNOWN. Symlinks are not followed at plan time (advisory pre-check; runtime enforcement unchanged). Adds `test-v1124`. |
| **v1.12.3** | **Dynamically linked agents.** Symlinks are followed and policy is decided on the object's canonical path (v1.12.0–v1.12.2 refused any symlinked path, blocking every dynamically linked agent's loader); `/proc/self`/`thread-self` mapped to the agent, foreign and supervisor `/proc` refused. Security property unchanged (a symlink to a denied object is decided as that object). Adds `test-v1123`. |
| **v1.12.2** | **Threads and child processes.** `clone3` answered `ENOSYS` so libc falls back to the flag-filtered `clone` (it was hard-denied, killing any threading agent); `wait4`/`waitid` and a narrow `ioctl` allowlist admitted; the bootstrap exec granted once per run (a per-pid grant let a thread race its path). Adds `test-v1122`. |
| **v1.12.0** | **Mediation correctness.** Resolve-then-decide for file opens (closes `..` traversal, symlink escape, and `/proc/self` supervisor-context confusion); audit-log integrity (agent-controlled fields escaped; records carry the resolved object); datagram-egress mediation (`sendto`/`sendmsg` refused for network destinations under the deny-only posture); listener handoff moved to a descriptor-transfer primitive. Adds a tool that exports authorization evidence in the CycloneDX 1.6 format and the `test-v112` regression suite. No verdict-semantics change; v1.10/v1.11 reserved for §8. |
| v1.10 (planned) | Verdict-distribution harness; bitvector and bounded-string fragments. Shrinking UNKNOWN. Race-free network and filesystem mediation; trusted-base reduction. |
| v1.11 (candidate) | Bounded-sequence fragment for cross-action data flow. |

---

Copyright Sober Agentic Infrastructure, Inc. VAREK is open source under the MIT license.
