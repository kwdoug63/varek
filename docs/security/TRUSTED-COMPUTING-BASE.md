# VAREK — Trusted Computing Base

Version: current as of v1.12.0 · MIT · github.com/kwdoug63/varek

A SATISFIED verdict is only as sound as the components that produce and enforce
it. This document lists every component in the verification-and-enforcement
chain and states, honestly, whether it is **verified** (its correctness is
established), **checked** (its output is independently validated at run time), or
**trusted** (assumed correct, not yet verified). The goal of the roadmap is to
move components leftward — and, above all, to shrink the set that must be trusted.

## Status definitions

- **Verified** — correctness established by proof or by construction; a bug would
  require the established result to be wrong.
- **Checked** — not itself verified, but its output is validated by a smaller,
  independently auditable mechanism at run time, so a fault is caught rather than
  trusted.
- **Trusted** — assumed correct. A defect here could in principle produce a wrong
  verdict. These are the components an auditor should scrutinize first and the
  ones the roadmap targets.

## Components

| Component | Role | Status | Notes / plan |
|-----------|------|--------|--------------|
| Surface-language compiler | Lowers human-authored policy to a formal obligation | Trusted | Unverified lowering; planned move to *checked* via obligation round-trip validation. |
| Obligation encoder | Encodes the obligation for the decision procedure | Trusted | Planned: encoder-faithfulness checks per fragment (already part of the v1.10/v1.11 soundness obligations). |
| SMT decision procedure, enforcement (`varek/v1_4/smt_decide.c`) | Decides every Warden action to SATISFIED / UNSATISFIED / UNKNOWN; decides rule reachability at policy load | Trusted | Added in v1.13. Purpose-built for a quantifier-free bounded-string + bitvector fragment, in-process, bounded worst case, no external solver on the enforcement path. Its fragment boundary (length guard, conservative flag mask, enumeration bound) returns UNKNOWN. **Differentially checked** against an off-the-shelf SMT solver (`tools/smt_crosscheck.py`: independent parser and encoding; zero disagreements over 26,624 checks on the repository policies and 600 fuzzed policies) and mutation-tested. The cross-check validates the implementation against its specification; it cannot find a gap between the specification and kernel behaviour (such as flags `fcntl` can change after open). Still trusted rather than *checked*: no per-verdict proof object yet. |
| SMT decision procedure (external backend) | Discharges richer obligations (plan-level and future fragments); serves as the differential oracle for the enforcement procedure | Trusted (not on the enforcement path) | Third-party; solvers have historically shipped soundness bugs. Since v1.13 the Warden does not call it at run time; a solver bug can mask a disagreement in the cross-check but cannot change a live decision. **Primary TCB-reduction target:** emit proof objects validated by a small independent checker (below). |
| Proof checker | Independently validates the decision procedure's proof objects | Planned (Checked) | Once shipped, the procedure moves from *trusted* to *checked*: trust collapses to a small, auditable checker rather than the whole solver. |
| Warden supervisor (C) | Mediates syscalls; enforces the decision at the boundary | Trusted | Memory-safe-reviewed. v1.9.1 hardened the TOCTOU discipline; v1.9.2 moved the baseline to a default-deny allowlist; v1.9.3 coupled the agent's lifetime to the supervisor's; v1.12 made the Warden decide on the resolved object it delivers and escape all agent-controlled fields in the verdict stream. In external-audit scope. |
| Evidence exporter (`varek/v1_4/tools/varek_cyclonedx.py`) | Converts the verdict stream to a CycloneDX 1.6 BOM | Trusted | Added in v1.12. Refuses a stream that does not parse cleanly, so a corrupted log cannot become an attestation; output validates against the published CycloneDX 1.6 schema. Its correctness does not affect enforcement, only the exported record. |
| Kernel mechanisms (seccomp, PID namespaces, capabilities) | In-kernel enforcement primitives the Warden builds on | Trusted | Out of VAREK's control; relied upon as a platform assumption (see Threat Model §5.3). Landlock is roadmap (v1.10), not wired in. |
| Build / toolchain | Produces the deployed binaries | Trusted | Planned: reproducible builds so a third party can reproduce the artifact bit-for-bit. |

## Soundness of the chain

The current chain is **trusted end to end above the kernel**: a defect in the
compiler lowering, the encoder, or the decision procedure could yield a wrong
SATISFIED. The mitigation strategy, in priority order:

1. **Shrink the trusted base.** Have the decision procedure emit proof objects
   that a small, independently auditable checker validates (an LCF-style move).
   Trust then rests on the checker, not the solver — a far smaller surface.
2. **Differential cross-checking.** On critical verdicts, corroborate with a
   second, independent backend; a disagreement is escalated, never silently
   resolved to SATISFIED.
3. **Reproducible builds + public benchmark corpus.** Let third parties
   reproduce both the binary and the verdicts independently.
4. **External audit** scoped to the *soundness of the verification chain*, not
   only to memory-safety defects.

## What this does not claim

No component above the kernel is currently *verified* in the strong sense. This
document exists so that fact is stated rather than discovered. The roadmap moves
the SMT decision procedure to *checked* first (it is the highest-leverage item),
followed by the compiler and encoder.
