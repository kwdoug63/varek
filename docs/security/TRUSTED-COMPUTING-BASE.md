# VAREK — Trusted Computing Base

Version: current as of v1.16.0 · MIT · github.com/kwdoug63/varek

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
| SMT decision procedure, enforcement (`varek/v1_4/smt_decide.c`) | Decides every Warden action to SATISFIED / UNSATISFIED / UNKNOWN; decides rule reachability at policy load | **Checked** for authorizations (v1.15); trusted for refusals and analysis | Added in v1.13; v1.14 added the glob compiler, the word-parallel matcher and the automaton reachability search. **Since v1.15 every SATISFIED verdict carries a certificate — the deciding rule and a witness that its constant matches — and the Warden authorizes the action only if the independent certificate checker (next row) accepts it.** A defect confined to the procedure can therefore no longer authorize an action; it can still wrongly *refuse* one (a wrong UNSATISFIED/UNKNOWN is fail-closed and uncertified), and its load-time reachability analysis is advisory. Also differentially checked against an off-the-shelf SMT solver and, for string reachability, a derivative-based procedure (`tools/smt_crosscheck.py`), and mutation-tested. |
| Certificate checker (`varek/v1_4/checker/vdp_checker.c`) | Accepts or refuses each SATISFIED verdict's certificate before the Warden acts on it; re-checks saved streams (`tools/varek_audit.py`) | Trusted | Added in v1.15. About 540 lines of C including SHA-256, written separately from the procedure: its own policy parser and matchers, no shared source, none of the procedure's optimizations (no word-parallel automata, bitset tricks, reachability search or enumeration pruning). It is not independent in design: both follow the same grammar, its glob parser mirrors the procedure's structure, and its matcher runs the same automaton one step at a time; the diversity comes from the Python oracle and the review's own translations. It runs in the Warden's process, so the separation holds against logic bugs in the procedure, not memory corruption. For "no action is authorized that the policy does not allow", this checker — not the procedure — is now the trusted decision code. Validated by the cross-check (every procedure certificate accepted; forged claims refused; mutated witnesses judged as the definition says; its parser and SHA-256 compared with the procedure's and Python's), by a live test with a deliberately broken procedure, and by its own mutation test. Both parsers follow the grammar in `smt_decide.h`, so a mistake in the grammar itself is common-mode; the grammar is small and documented rule by rule. |
| SMT decision procedure (external backend) | Discharges richer obligations (plan-level and future fragments); serves as the differential oracle for the enforcement procedure | Trusted (not on the enforcement path) | Third-party; solvers have historically shipped soundness bugs. Since v1.13 the Warden does not call it at run time; a solver bug can mask a disagreement in the cross-check but cannot change a live decision. |
| Warden supervisor (C) | Mediates syscalls; enforces the decision at the boundary | Trusted | Memory-safe-reviewed. v1.9.1 hardened the TOCTOU discipline; v1.9.2 moved the baseline to a default-deny allowlist; v1.9.3 coupled the agent's lifetime to the supervisor's; v1.12 made the Warden decide on the resolved object it delivers and escape all agent-controlled fields in the verdict stream. In external-audit scope. |
| Evidence exporter (`varek/v1_4/tools/varek_cyclonedx.py`) | Converts the verdict stream to a CycloneDX 1.6 BOM | Trusted | Added in v1.12. Refuses a stream that does not parse cleanly, so a corrupted log cannot become an attestation; output validates against the published CycloneDX 1.6 schema. Its correctness does not affect enforcement, only the exported record. v1.15 adds the policy SHA-256 and each authorization's certificate to the BOM. |
| Audit tool (`varek/v1_4/tools/varek_audit.py`) | Re-checks a saved verdict stream: authenticates it against the agent, ties it to a policy file by SHA-256, refuses any authorization other than certified file opens and the launch exec, and re-runs the certificate checker on every authorization; from v1.16 verifies the hash chain, the signatures against a pinned key and the anchor | Trusted (the Python glue); the decisions it re-checks rest on the certificate checker | Added in v1.15. Does not affect enforcement. v1.16 adds protection against the log's holder (next two rows). |
| Log signing (libsodium: Ed25519, SHA-256; `warden.c` log chain) | Chains every record and signs run_start, checkpoints and run_end; appends them to the external anchor | Trusted | Added in v1.16. For "the log is the one the Warden wrote", the trusted parts are libsodium (widely deployed and audited), the ~150 lines of chaining and key handling in `warden.c`, and the custody of the key. The chain format is specified in `warden.c` and checked by the audit's own code. The Warden refuses to start when the policy would let the agent open the key or the anchor. |
| Signature verifier (`varek/v1_4/tools/varek_ed25519.py`) | Verifies the stream's signatures for the audit | Trusted | Added in v1.16. About 100 lines of Python following RFC 8032, written separately from the signer so the audit does not rely on the library that made the signatures. Strict (canonical encodings, S < L, no small-order key). Passes the RFC 8032 vectors and agrees with OpenSSL on the test suite's cases. |
| Kernel mechanisms (seccomp, PID namespaces, capabilities) | In-kernel enforcement primitives the Warden builds on | Trusted | Out of VAREK's control; relied upon as a platform assumption (see Threat Model §5.3). Landlock is roadmap (v1.10), not wired in. |
| Build / toolchain | Produces the deployed binaries | Trusted | Planned: reproducible builds so a third party can reproduce the artifact bit-for-bit. |

## Soundness of the chain

Above the kernel, the Warden's authorizations now rest on the certificate
checker rather than on the decision procedure (v1.15): an action is authorized
only when the procedure says SATISFIED **and** the separately written checker
accepts the certificate. A defect in the surface-language compiler or the
encoder could still yield a wrong policy text, and the checker is trusted. The
mitigation strategy, in priority order:

1. **Shrink the trusted base.** *Done for Warden authorizations in v1.15:*
   certificates checked by a small, independent checker before the action takes
   effect (an LCF-style move). Next: a checker small enough to verify formally,
   and certificates for the plan-level backend.
2. **Differential cross-checking.** On critical verdicts, corroborate with a
   second, independent backend; a disagreement is escalated, never silently
   resolved to SATISFIED.
3. **Reproducible builds + public benchmark corpus.** Let third parties
   reproduce both the binary and the verdicts independently.
4. **External audit** scoped to the *soundness of the verification chain*, not
   only to memory-safety defects.

## Integrity of the record (v1.16)

The asset "the verdict stream reflects the decisions actually made" has two
adversaries. The supervised agent has been unable to forge, drop or reorder a
record since v1.12.1 (run id, sequence numbers, relayed stderr). From v1.16 the
log's holder cannot either, up to what the key and the anchor cover: without
the key, nothing before the last signature can change and a stream cannot be
cut short undetected; with an anchor, anchored history cannot change even for
the key holder. Not covered: records after the last anchored checkpoint of an
unfinished run, root on the Warden host during the run, and the unchained
lines (status lines, the agent's relayed stderr, pre-launch plan records).

## What this does not claim

No component above the kernel is currently *verified* in the strong sense. This
document exists so that fact is stated rather than discovered. v1.15 moved the
enforcement decision procedure to *checked* for authorizations; the certificate
checker that took its place is trusted, and is the natural candidate for formal
verification. The compiler and encoder come next.
