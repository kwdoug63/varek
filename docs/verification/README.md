# Verification notes — the UNKNOWN-shrinking program (v1.10 / v1.11)

These are design and auditor-facing notes for the post-v1.9 verification program.
The goal of the program is to migrate cases out of the UNKNOWN verdict into a
provable verdict — raising the clear rate on safe agent actions — under a hard
invariant: **no extension may ever move a genuinely unsafe action into SATISFIED.**
"Cannot prove safe" remains UNSATISFIED/UNKNOWN.

**Status: these document planned (v1.10) and candidate (v1.11) work. They are not
present in a released tag and are not claimed as shipped.** Shipped behavior is
described in `CHANGELOG.md` and the spec paper.

| Note | Role |
|------|------|
| `verdict-distribution-harness.md` | Engineering spec: how coverage extension is measured (clear-rate, per-TCB-line ledger, hard `unsafe_allows == 0` gate). |
| `corpus-v1-schema.md` | Corpus format, the customer-policy labeling decision, and adversarial near-miss starter pairs. |
| `bitvector-fragment.md` | v1.10 step: decidable reasoning over fixed-width syscall flag/argument bits. Lowest audit cost. |
| `bounded-string-fragment.md` | v1.10 headline: length-bounded string predicates (path-prefix, host-allowlist) made provable instead of refused. |
| `bounded-sequence-fragment.md` | v1.11 candidate: element-level reasoning for the cross-action data-flow subsystem, composed on the fragments above. |

Each note carries a single auditable soundness obligation and names the trusted
code it adds. The fragments are sequenced bitvector → string → sequence because
the sequence fragment's soundness is conditional on its element fragment's.
