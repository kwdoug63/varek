# Bitvector Flag/Argument Fragment — Decidability and Soundness Note

Status: Draft for v1.10
Scope: The fixed-width bitvector reasoning the verifier admits for syscall-layer policy decisions
Audience: Third-party runtime security auditor; verifier engineering

---

## 1. Why this extension is first

Syscall arguments and seccomp flag fields are fixed-width bit vectors. When the
verifier abstracts them away, it cannot prove "the create bit is clear" or "the
access mode is read-only," so it emits UNKNOWN at exactly the boundary the Warden
layer enforces. Admitting bitvector reasoning discharges a class of
Warden-boundary cases directly, and it does so at the lowest audit cost of any
v1.10 extension: the theory is standard, decidable, and already within the
verifier's existing decision procedure. It is the cheapest place to prove the
full UNKNOWN-shrinking loop end to end before the larger string work.

This fragment is directly aligned with the Warden kernel architecture covered by
the patent-pending provisional (#64/059,592). Reasoning about flag and argument
bits is the verifier-side complement to the kernel-boundary enforcement that
provisional describes.

Governing invariant, unchanged: this extension may only migrate cases out of
UNKNOWN into ALLOW or REFUSE. It may never move an unsafe action into ALLOW.
"Cannot prove safe" remains REFUSE/UNKNOWN.

---

## 2. The fragment

### 2.1 Domain

Arguments range over fixed-width bit vectors `BV[w]`, where `w` is the argument's
width in the syscall ABI (e.g. 32 or 64). Width is a property of the ABI, fixed
per argument, not runtime-variable.

### 2.2 Admitted predicates

Over bitvector terms, the fragment admits:

- `eq(x, c)`, `ne(x, c)` — equality / disequality with a constant.
- `bit_set(x, i)`, `bit_clear(x, i)` — a named bit is 1 / 0.
- `mask_eq(x, m, v)` — `(x & m) == v`: the bits selected by mask `m` equal `v`.
  This is the workhorse for access-mode and flag-group checks.
- `mask_zero(x, m)` — `(x & m) == 0`: none of the masked bits are set.
- range predicates `ule/ult/uge/ugt` and signed `sle/slt/sge/sgt` against
  constants, for numeric arguments (sizes, offsets, fds).

Masks `m`, constants `c`/`v`, and bit indices `i` are fixed by the policy, not by
the action under verification.

Deliberately excluded (escape to UNKNOWN): bit-shift or arithmetic relating two
variable arguments, multiplication of two variables, and any predicate whose
width or signedness is not pinned by the ABI declaration. Exclusion is
conservative: excluded constructs do not clear.

---

## 3. Decidability

Claim: satisfiability of any conjunction of admitted predicates is decidable.

Argument. The predicates lie within the quantifier-free theory of fixed-size bit
vectors (QF_BV). QF_BV is decidable — every fixed-width bitvector formula has a
finite bit-blasted propositional equivalent, and propositional satisfiability is
decidable. The masking and bitwise predicates are the native operations of the
theory; the range predicates are its standard unsigned/signed comparisons. No
construct in the fragment leaves QF_BV.

This introduces no new decision procedure. QF_BV is already discharged by the
SMT decision procedure in scope. The new trusted code is the **lowering** of
policy flag/argument predicates into QF_BV terms (Section 5), not a new theory.

---

## 4. The soundness obligation

One obligation, with two parts the auditor checks.

### 4.1 ABI-faithfulness lemma

> For every admitted predicate `phi` and every concrete argument value `a`, the
> lowered QF_BV constraint `enc(phi)` holds for the bitvector encoding of `a`
> **if and only if** `phi` holds of `a` under the syscall ABI's width and
> signedness for that argument.

The right-to-left (soundness) direction is the priority: a spurious QF_BV model
that corresponds to no real argument value could let the verifier "prove" a flag
predicate that is false at runtime, producing an unsafe allow. The two classic
failure modes to check:

- **Width.** The encoding must use the argument's true ABI width. Encoding a
  64-bit argument as 32 bits (or vice versa) can make high bits invisible, and a
  flag in a high bit could then be ignored — unsound.
- **Signedness.** Range predicates must use the comparison (signed vs. unsigned)
  that matches the ABI's treatment of the argument. A size compared as signed
  when the ABI treats it as unsigned admits negative-looking values that wrap to
  large positives at the kernel boundary — unsound.

### 4.2 Conservative-mask rule (the boundary)

A policy reasons over a mask of bits it considers relevant (e.g. the access-mode
bits of an `open` flags field). Bits **outside** that mask still affect kernel
behavior. The rule:

> An action may be ALLOWed only if either (a) the bits outside the policy's
> considered mask are proven zero, or (b) the policy explicitly declares those
> bits don't-care. Otherwise the action escapes to UNKNOWN. Unmodeled set bits
> are never silently ignored.

This is the bitvector analog of the string fragment's length-guard, and it is the
highest-value audit point here. Masking the flags down to the access-mode bits
and then allowing — while a create or truncate bit is set in the unconsidered
region — is exactly the unsound move. The corpus adversarial `bitvector-flags`
pairs (F1, F3) are built to surface it: the UNSAFE twin differs from the SAFE
twin only by a bit outside the access-mode mask, so an implementation that
ignores unmodeled bits will wrongly clear it.

The auditor verifies there is no mask-then-allow path that drops unmodeled bits,
and that the escape is wired to the same deterministic, fail-safe UNKNOWN
disposition as every other UNKNOWN (terminating authorized, loop bound enforced
in the Warden layer).

Together, 4.1 right-to-left and 4.2 give: any action ALLOWed on the strength of a
flag/argument predicate is one where that predicate truly holds of the actual
argument bits at the ABI width and signedness, with no unmodeled bit unaccounted
for.

---

## 5. Trusted computing base added

Narrow by design:

- **The predicate lowering** (flag/argument predicates -> QF_BV terms), carrying
  the ABI width and signedness for each argument. The focus of 4.1. Its
  correctness depends on a correct ABI table.
- **The ABI table** (argument -> width, signedness, and the policy-relevant
  masks). Trusted data; a wrong width or mask is a soundness defect. Mitigation:
  the table is small, per-syscall, and can be checked against the kernel headers
  it is derived from.
- **The conservative-mask guard** (Section 4.2). Small, safety-critical, and
  exhaustively testable at the mask boundary.

Not added: any new decision procedure. The fragment lowers into QF_BV, already in
scope.

### 5.1 Evidence the harness supplies

The verdict-distribution harness supplies this extension's audit-ledger row: the
count of SAFE actions migrating `UNKNOWN -> ALLOW` on the `bitvector-flags`
stratum, and `unsafe_allows == 0` across the corpus including the F1/F3
adversarial pairs. A clean gate over those pairs is the empirical complement to
the ABI-faithfulness lemma and the conservative-mask rule.

---

## 6. Auditor checklist

1. Confirm each argument's width and signedness are taken from the ABI, fixed
   per argument, not runtime-derived.
2. Confirm masks, constants, and bit indices are policy-fixed, not action-derived.
3. For each admitted predicate, check the right-to-left direction of the
   ABI-faithfulness lemma, prioritizing width and signedness.
4. Confirm the conservative-mask rule: no mask-then-allow path drops unmodeled
   bits; unmodeled set bits force UNKNOWN unless the policy declares don't-care.
5. Confirm the escape uses the same deterministic, fail-safe UNKNOWN disposition
   as all other UNKNOWN verdicts.
6. Confirm the ABI table is validated against its source kernel headers.
7. Review the harness `bitvector-flags` adversarial result: `unsafe_allows == 0`
   over F1/F3 and any added flag near-misses.

Items 3 and 4 are load-bearing. The rest keep the fragment from widening past
what those two checks cover.
