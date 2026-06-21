# VAREK — Trusted Computing Base

Version: current as of v1.9.1 · MIT · github.com/kwdoug63/varek

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
| SMT decision procedure (external backend) | Discharges the obligation to SATISFIED / UNSATISFIED / UNKNOWN | Trusted | Third-party; solvers have historically shipped soundness bugs. **Primary TCB-reduction target:** emit proof objects validated by a small independent checker (below), plus differential cross-checking on critical verdicts. |
| Proof checker | Independently validates the decision procedure's proof objects | Planned (Checked) | Once shipped, the procedure moves from *trusted* to *checked*: trust collapses to a small, auditable checker rather than the whole solver. |
| Warden supervisor (C) | Mediates syscalls; enforces the decision at the boundary | Trusted | Memory-safe-reviewed; v1.9.1 hardened the TOCTOU discipline. In external-audit scope. |
| Kernel mechanisms (seccomp, Landlock, capabilities) | In-kernel enforcement primitives the Warden builds on | Trusted | Out of VAREK's control; relied upon as a platform assumption (see Threat Model §5.3). |
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
