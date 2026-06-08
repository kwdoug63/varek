# Bounded String Fragment — Decidability and Soundness Note

Status: Draft for v1.10
Scope: The string-reasoning fragment the VAREK verifier admits for policy decisions
Audience: Third-party runtime security auditor; verifier engineering

---

## 1. Why this note exists

Agent actions are saturated with string arguments: filesystem paths, URLs and
hostnames, command strings, API parameters. When the verifier treats these as
opaque, it cannot prove policy predicates such as "this path stays under an
allowed prefix" or "this host is in the allowlist," and so it conservatively
emits UNKNOWN (and the action does not clear). Adding string reasoning is the
single largest available reduction in over-refusal.

String theory is also where solver complexity and unsoundness historically
concentrate. The full theory of strings with unbounded length, concatenation,
and general regular constraints is a setting where decidability is delicate and
implementation bugs are real. VAREK therefore does **not** admit full string
theory. It admits a deliberately restricted, length-bounded fragment with a
clean decidability argument and a small trusted computing base (TCB). This note
specifies that fragment precisely, states its decidability, states the single
soundness obligation the auditor must check, and accounts for the TCB added.

The governing invariant, unchanged from the rest of the verifier: a string
extension may only migrate cases out of UNKNOWN into ALLOW or REFUSE. It may
never move a genuinely unsafe action into ALLOW. The verifier proves safety; it
does not assume it. "Cannot prove safe" remains REFUSE/UNKNOWN.

---

## 2. The fragment

### 2.1 Domain

Strings range over `Sigma^{<= L}`: finite sequences over a fixed finite alphabet
`Sigma`, of length at most a fixed bound `L`. Both `Sigma` and `L` are policy
parameters fixed at policy-load time, not runtime-variable.

`L` is the central audit knob. It bounds the decision problem's size and is the
hinge of the soundness argument (Section 4). A typical `L` is chosen to cover
realistic path/host/parameter lengths with margin; the over-length case is
handled conservatively, not by raising `L` without bound.

### 2.2 Admitted predicates

The fragment admits exactly these predicates over string terms, and no others:

- `eq(s, t)` — equality.
- `len_le(s, k)`, `len_eq(s, k)`, `len_ge(s, k)` — length bounds, `k <= L`.
- `prefix(p, s)` — `p` is a prefix of `s`, `p` a fixed literal.
- `suffix(q, s)` — `q` is a suffix of `s`, `q` a fixed literal.
- `contains(sub, s)` — `sub` occurs in `s`, `sub` a fixed literal.
- `member(s, R)` — `s` is matched by regex `R`, where `R` is drawn from a
  **fixed finite set of regexes declared in the policy** (`R in RegexSet`).

Deliberately excluded (escape to UNKNOWN if encountered): concatenation of two
variable strings, replace/substitution, length arithmetic relating two variable
strings, regexes constructed at runtime, and any predicate over strings that may
exceed `L`. Exclusion is conservative: an excluded construct does not get an
ALLOW, it gets UNKNOWN.

Literals (`p`, `q`, `sub`) and the regex set are fixed by the policy, not by the
action under verification. This is what keeps the fragment from drifting toward
full string theory through the back door.

---

## 3. Decidability

Claim: satisfiability of any conjunction of admitted predicates over the bounded
domain `Sigma^{<= L}` is decidable.

Argument. The domain is finite: `|Sigma^{<= L}|` is finite for fixed finite
`Sigma` and fixed `L`. Every admitted predicate is a computable relation over
this finite domain. Satisfiability over a finite domain is decidable by
construction. Decidability is therefore immediate and does not rest on any deep
result about string theories.

Practicality. Finiteness alone would permit naive enumeration, which is not
viable. The intended discharge is by encoding each bounded string as a
fixed-width vector of `L` character cells (each cell a bounded integer / small
bitvector over `Sigma`, plus a length variable `0 <= n <= L`), and lowering each
admitted predicate to a quantifier-free constraint over those cells:

- `prefix(p, s)`: fix the first `|p|` cells of `s` to the code points of `p` and
  require `n >= |p|`.
- `suffix(q, s)`: constrain the cells at positions `n-|q| .. n-1` to `q`.
- `contains(sub, s)`: a finite disjunction over the `<= L` candidate start
  positions, each a fixed-cell equality conjunction.
- `member(s, R)`: compile `R` to a deterministic finite automaton and unroll its
  run over the `L` cells with the length cut at `n`. Because `R` is from the
  fixed `RegexSet`, every DFA is built once at policy-load time, not per action.
- `len_*`, `eq`: direct constraints over `n` and the cells.

This lowers the fragment into the quantifier-free bounded-integer / fixed-size
vector setting the SMT decision procedure already discharges. No new solver
theory is introduced — the new TCB is the **encoder** (Section 5), not a new
decision procedure.

---

## 4. The soundness obligation (the one thing to check)

Each theory extension carries exactly one soundness obligation. For this
fragment it has two coupled parts, both of which the auditor checks.

### 4.1 Encoding faithfulness lemma

> For every admitted predicate `phi` and every string `s in Sigma^{<= L}`, the
> encoded constraint `enc(phi)` is satisfiable by the cell-vector assignment
> `enc(s)` **if and only if** `phi(s)` holds over `Sigma^{<= L}`.

Iff in both directions. Completeness of the encoding (left-to-right: real
satisfaction implies encoded satisfaction) protects utility — without it the
extension would needlessly fail to clear safe actions, which is merely wasteful.
Soundness of the encoding (right-to-left: encoded satisfaction implies real
satisfaction) is the one that protects the safety guarantee — a spurious model
of `enc(phi)` that corresponds to no real string could let the verifier "prove"
a policy predicate that is in fact false, and that is the path to an unsafe
allow. The auditor's priority is the right-to-left direction, predicate by
predicate. The `contains` disjunction and the `member` DFA unrolling are the two
encodings most worth direct scrutiny.

### 4.2 Length-guard escape (the conservative boundary)

The fragment is sound **only** for strings within `Sigma^{<= L}`. A runtime
string argument may exceed `L`. The guard:

> Any runtime string whose length exceeds `L`, or which contains a code point
> outside `Sigma`, escapes the fragment and is treated as UNKNOWN. It is never
> truncated, never clamped, and never silently accepted.

This is the subtle, high-value audit point. Truncating an over-length string to
`L` before checking would be unsound: a malicious suffix beyond position `L`
(for example, a path-traversal tail, or an allowlist-evading host suffix) would
be invisible to a check that only ever sees the first `L` characters, and the
action could be wrongly allowed. The guard must therefore reject over-length to
UNKNOWN, preserving "cannot prove safe ⇒ do not allow." The auditor should
verify that no code path performs a length-clamp-then-check, and that the escape
is wired to the same deterministic, fail-safe disposition as every other UNKNOWN
(terminating in an authorized state, loop bound enforced in the Warden layer).

Together, 4.1 right-to-left plus 4.2 give the property that matters: any action
the verifier ALLOWs on the strength of a string predicate is one where that
predicate truly holds of the actual runtime string. Everything else refuses or
escapes.

---

## 5. Trusted computing base added

The audit cost of this extension is the new code that, if wrong, could cause an
unsafe allow. It is deliberately narrow:

- **The encoder** (predicates -> cell-vector constraints). This is the new
  trusted component and the focus of 4.1.
- **The regex-to-DFA compiler** for the fixed `RegexSet`, run at policy-load
  time. Trusted because a wrong DFA breaks `member` faithfulness. Mitigation:
  the `RegexSet` is small and fixed per policy, so each DFA can be
  differentially tested against an independent matcher at load time, and the
  result cached.
- **The length/alphabet guard** (Section 4.2). Small but safety-critical; its
  correctness is a refusal-preserving property, easy to test exhaustively at the
  boundary `L` and `L+1`.

Explicitly **not** added to the TCB: any new decision procedure or solver theory.
The fragment lowers into procedures already in the verifier and already in the
audit scope. This is the reason string support can be the headline utility win
while remaining a bounded, checkable addition rather than an open-ended one.

### 5.1 Evidence the harness supplies

The verdict-distribution harness (separate document) supplies the utility
numerator for this extension's audit-ledger row: the count of SAFE actions that
migrate `UNKNOWN -> ALLOW` once the fragment lands, and confirmation that the
soundness gate (`unsafe_allows == 0`) holds across the corpus, including the
adversarial near-miss slice (prefix-escape paths, off-by-one allowlist hosts).
The adversarial slice is where an unsound encoding or a missing length-guard
would surface as an unsafe allow; a clean gate over that slice is the empirical
complement to the lemma in 4.1.

---

## 6. Auditor checklist

1. Confirm `Sigma` and `L` are fixed at policy-load time and not runtime-mutable.
2. Confirm the admitted-predicate set is closed: no concatenation of two
   variables, no runtime-constructed regexes, no cross-variable length
   arithmetic. Confirm excluded constructs escape to UNKNOWN.
3. For each admitted predicate, check the right-to-left (soundness) direction of
   the encoding-faithfulness lemma. Prioritize `contains` and `member`.
4. Confirm the length/alphabet guard rejects over-length and out-of-alphabet
   inputs to UNKNOWN with no truncate-then-check path anywhere.
5. Confirm the UNKNOWN disposition for escaped strings is the same deterministic,
   fail-safe path as all other UNKNOWN verdicts.
6. Confirm the regex-to-DFA compiler runs at load time and its outputs are
   differentially validated.
7. Review the harness adversarial-slice result: `unsafe_allows == 0` over
   near-miss SAFE/UNSAFE pairs.

Items 3 and 4 are the load-bearing checks. The rest are containment checks that
keep the fragment from quietly widening into territory items 3 and 4 no longer
cover.
