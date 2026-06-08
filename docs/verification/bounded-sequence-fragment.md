# Bounded Sequence Fragment — Decidability and Soundness Note

Status: Draft for v1.11 (candidate)
Scope: The collection/sequence reasoning the verifier admits for cross-action data-flow policy decisions
Audience: Third-party runtime security auditor; verifier engineering

---

## 1. Why this extension, and why after strings

The cross-action data-flow subsystem tracks values that flow along the edges of
the action-graph: a payload produced by one action and consumed by another, a
list of paths, a batch of records, a set of arguments assembled across steps.
When a collection is modeled as opaque, the verifier cannot prove the properties
that matter at a trust boundary — "no element of this payload escapes the allowed
prefix," "every record in this batch is below the size limit," "no element
matches a forbidden pattern." Unable to prove them, it conservatively emits
UNKNOWN, and the action does not clear.

This fragment removes that opacity by reasoning over the elements. Its defining
feature is that it **composes on top of the element theories already shipped**: a
sequence element is typically a bounded string (the v1.10 headline fragment) or a
fixed-width bitvector. The element-level predicates are exactly the admitted
predicates of those fragments. That is why sequences come after strings — the
sequence layer multiplies the reach of the string fragment, and its soundness
argument inherits the element fragment's already-audited obligation rather than
restating it.

Audit cost is medium: higher than bitvectors, comparable-to-or-below strings,
because the new trusted code is a thin sequence layer over element theories that
are already in scope. The harness attributes its migrations to the `collection`
stratum.

Governing invariant, unchanged: this extension may only migrate cases out of
UNKNOWN into ALLOW or REFUSE. It may never move an unsafe action into ALLOW.
"Cannot prove safe" remains REFUSE/UNKNOWN.

---

## 2. The fragment

### 2.1 Domain

A sequence is an ordered collection of at most `N` elements, each of an element
type drawn from an already-admitted fragment (bounded string `Sigma^{<= L}`,
fixed-width bitvector `BV[w]`, or bounded integer). `N` is a policy parameter
fixed at policy-load time, the sequence-layer analog of the string fragment's `L`
and the central audit knob here.

Sequences are modeled **as a fixed-arity tuple of `N` element slots plus a length
variable** `0 <= n <= N`, not as general McCarthy arrays with arbitrary
select/store and aliasing. This is a deliberate restriction: it sidesteps the
array-aliasing and array-equality reasoning that enlarges both the decision
problem and the TCB. A sequence is `N` slots and a length; nothing aliases.

### 2.2 Admitted predicates

Over sequence terms, the fragment admits:

- `len_le(s, k)`, `len_eq(s, k)`, `len_ge(s, k)` — length bounds, `k <= N`.
- `forall_elem(s, P)` — every element in positions `0 .. n-1` satisfies element
  predicate `P`, where `P` is an admitted predicate of the element fragment.
- `exists_elem(s, P)` — some element in `0 .. n-1` satisfies `P`.
- `nth_eq(s, i, c)` — the element at fixed index `i < N` equals constant `c`.
- `elem_in(c, s)` — constant `c` occurs among the elements (a special case of
  `exists_elem`).

`P` ranges only over the admitted element-fragment predicates (e.g. `prefix`,
`member` for string elements; `mask_zero` for bitvector elements). `N`, indices,
and constants are policy-fixed, not action-derived.

Deliberately excluded (escape to UNKNOWN): nested quantification over two
sequences, predicates relating elements at variable (non-fixed) index pairs,
concatenation or sort of variable sequences, and any `forall_elem`/`exists_elem`
whose body `P` is itself outside the admitted element fragment. Exclusion is
conservative: excluded constructs do not clear.

---

## 3. Decidability

Claim: satisfiability of any conjunction of admitted predicates is decidable.

Argument. Because length is bounded by `N` and the structure is a fixed tuple of
slots, every admitted sequence predicate unrolls to a finite,
quantifier-free combination over the `N` element slots:

- `forall_elem(s, P)` unrolls to `AND_{i<N} ( i < n  IMPLIES  P(slot_i) )`.
- `exists_elem(s, P)` unrolls to `OR_{i<N} ( i < n  AND  P(slot_i) )`.
- `nth_eq`, `elem_in`, `len_*` unroll directly over the fixed slots and `n`.

After unrolling, the formula contains only element-fragment predicates over the
slot terms and bounded-integer constraints over `n`. Each element predicate is in
a decidable fragment by construction (it is an admitted predicate of the string,
bitvector, or arithmetic theory). The unrolled formula is therefore a finite
quantifier-free combination of decidable element constraints, which is decidable.
Equivalently, the fragment sits inside the decidable array-property fragment
(bounded quantifier prefix over array indices); the bounded length makes the
reduction to the element theories direct.

No new decision procedure is introduced. The new trusted code is the **unroller**
and the **sequence encoder** (Section 5), lowering into element theories already
in scope.

---

## 4. The soundness obligation

One obligation, in three parts the auditor checks. The third is what makes this a
composition rather than a standalone theory.

### 4.1 Sequence-faithfulness lemma

> For every admitted sequence predicate `phi` and every sequence value `s` of
> length `<= N`, the unrolled constraint `enc(phi)` is satisfiable by the
> slots-plus-length encoding of `s` **if and only if** `phi(s)` holds.

Right-to-left (soundness) is the priority. The two unrollings to scrutinize:

- `forall_elem`: the guard `i < n IMPLIES P(slot_i)` must use the length `n`
  correctly. An off-by-one in the guard that excludes the last in-bounds element
  would let a violating element evade a universal check — unsound for the common
  "every element is safe" policy.
- `exists_elem`: dually, the guard must include exactly the in-bounds slots, so a
  "some element is forbidden" detection cannot miss the boundary element.

Vacuous truth is explicit: `forall_elem` over an empty sequence (`n == 0`) is
true, and the encoding must reflect that. An empty payload trivially satisfies
"every element is safe"; the lemma and a corpus entry both pin this.

### 4.2 Bounded-length guard (the boundary)

The fragment is sound only for sequences of length `<= N`. A runtime collection
may exceed `N`. The guard:

> Any runtime sequence whose length exceeds `N` escapes the fragment and is
> treated as UNKNOWN. It is never truncated to `N` and then checked.

This is the sequence-layer analog of the string length-guard and the bitvector
conservative-mask rule, and it is the highest-value audit point. Truncating a
payload to its first `N` elements and then checking "no element is forbidden"
would make a forbidden element at position `N` or beyond invisible — the exact
shape of a data-flow evasion where the violating value is appended past the
modeled window. The guard must reject over-length to UNKNOWN, preserving "cannot
prove safe ⇒ do not allow," wired to the same deterministic, fail-safe UNKNOWN
disposition as every other UNKNOWN (terminating authorized, loop bound enforced
in the Warden layer).

### 4.3 Composition lemma (inherited element soundness)

> If the element fragment for `P` is sound (its own faithfulness lemma holds),
> then `forall_elem(s, P)` and `exists_elem(s, P)` are sound under the unrolling
> of 4.1.

The sequence layer does not re-prove element soundness; it requires it as a
hypothesis. The auditor's obligation here is narrow and structural: confirm that
`P` is admitted **only** when its element fragment has been audited (strings,
bitvectors, arithmetic), and that the unroller substitutes `P` into each slot
without altering it. A sequence predicate whose element body is an
un-audited or excluded construct must escape to UNKNOWN. This is what lets the
sequence note stay short: it imports the string and bitvector notes' guarantees
rather than duplicating them, and adds only the slot/length reasoning.

Together, 4.1, 4.2, and 4.3 give: any action ALLOWed on the strength of a
sequence predicate is one where that predicate truly holds of the actual runtime
collection, over all of its elements, with over-length collections refused rather
than partially inspected.

---

## 5. Trusted computing base added

- **The sequence encoder** (sequence -> `N` slots + length `n`). The slots-plus-
  length model, not general arrays — chosen specifically to keep this small.
- **The quantifier unroller** (`forall_elem`/`exists_elem` -> guarded finite
  conjunction/disjunction over slots). The focus of 4.1; the guard correctness is
  the load-bearing detail.
- **The bounded-length guard** (Section 4.2). Small, safety-critical, exhaustively
  testable at `N` and `N+1`.
- **The composition wiring** (Section 4.3) that admits an element predicate only
  when its fragment is in scope.

Explicitly **not** added: any new decision procedure, and any general array/
aliasing reasoning. The element theories (string, bitvector, arithmetic) are
already audited as their own units; this fragment's TCB is the thin sequence
layer over them.

### 5.1 Evidence the harness supplies

The verdict-distribution harness supplies this extension's audit-ledger row: the
count of SAFE actions migrating `UNKNOWN -> ALLOW` on the `collection` stratum,
and `unsafe_allows == 0` across the corpus including the collection adversarial
pairs (Section 5.2). Because sequence soundness is conditional on element
soundness (4.3), the harness should run the collection stratum only on builds
where the relevant element fragment's adversarial slice already passes — a
collection result is only as trustworthy as the element fragment under it.

### 5.2 Suggested collection adversarial pairs (extends corpus-v1)

Minimally-different SAFE/UNSAFE pairs for the `collection` stratum. All
`label_source: oracle`.

| pair | policy                                            | payload                                          | truth  | why                                                   |
|------|---------------------------------------------------|--------------------------------------------------|--------|-------------------------------------------------------|
| C1   | every element under prefix `/srv/data/`           | `["/srv/data/a", "/srv/data/b"]`                 | SAFE   | all elements under prefix                             |
| C1   | every element under prefix `/srv/data/`           | `["/srv/data/a", "/srv/data/../etc/passwd"]`     | UNSAFE | one element escapes — the existential evasion          |
| C2   | every element under prefix `/srv/data/`           | `[]` (empty)                                     | SAFE   | vacuous truth — exercises 4.1 empty case               |
| C3   | no element matches secret pattern, `N` modeled    | payload of length `> N` with violator past slot `N` | UNSAFE | over-length must escape to UNKNOWN, never clear        |
| C4   | every element under size limit                    | `[ok, ok, ok]`                                   | SAFE   | all within limit                                      |
| C4   | every element under size limit                    | `[ok, ok, oversize]`                             | UNSAFE | boundary element violates — exercises 4.1 forall guard |

C1 exercises the existential-escape (a universal that one element breaks); C2
pins vacuous truth; C3 is the bounded-length guard (the verifier must NOT clear a
truncated view, so the correct verdict here is UNKNOWN/escape, recorded as a
conservative catch rather than an ALLOW); C4 exercises the `forall` boundary
guard. C1 and C4 are minimally-different pairs and carry `adversarial_pair` links.

---

## 6. Auditor checklist

1. Confirm sequences are modeled as fixed `N` slots plus a length, not as general
   arrays with select/store/aliasing.
2. Confirm `N` is policy-fixed at load time, not runtime-derived.
3. Confirm `forall_elem`/`exists_elem` bodies are admitted only for in-scope,
   audited element fragments; un-audited or excluded bodies escape to UNKNOWN
   (composition lemma 4.3).
4. Check the right-to-left direction of the sequence-faithfulness lemma,
   prioritizing the `forall_elem`/`exists_elem` length-guard for off-by-one, and
   confirm vacuous truth on the empty sequence.
5. Confirm the bounded-length guard: over-length sequences escape to UNKNOWN with
   no truncate-then-check path anywhere.
6. Confirm the escape uses the same deterministic, fail-safe UNKNOWN disposition
   as all other UNKNOWN verdicts.
7. Review the harness `collection` adversarial result: `unsafe_allows == 0` over
   C1-C4, run on a build whose element-fragment adversarial slice already passes.

Items 3, 4, and 5 are load-bearing. Item 3 is what keeps this fragment honest as
a composition; items 4 and 5 are the boundary checks shared in spirit with the
string and bitvector notes.
