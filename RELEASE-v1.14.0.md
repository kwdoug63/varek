# VAREK v1.14.0 — The Bounded String Fragment

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

v1.14.0 is the second release of the v1.10 verification program: **shrink the
UNKNOWN region without weakening soundness.** v1.13.0 put the SMT decision
procedure in the enforcement path with prefix, equality and host atoms for the
object an action names. v1.14.0 completes the bounded string fragment. Path and
exec rules can now match a string in five ways:

| Matcher | Holds when the resolved path… |
|---|---|
| `exact` | equals the constant |
| `prefix` | starts with it (the default for path rules, as before) |
| `suffix` | ends with it |
| `contains` | contains it anywhere |
| `glob` | matches a path glob, anchored at both ends |

What this buys, in one line: **a policy can now deny a kind of file wherever it
appears**, which a prefix rule could not express. Examples are private keys
(`suffix .pem`), dotenv files at any depth (`glob /**/.env`) and a patient's
psychotherapy notes (`glob /var/lib/ehr/records/**/psychotherapy/**`), even
inside trees the agent is otherwise allowed to read or write. A policy can also
allow exactly one file (`exact /etc/hosts`) rather than every name that begins
with it (`/etc/hosts.allow`).

Every v1.13 policy keeps its meaning. The one exception is a `require` version
written with a sign (`+1.13`), which v1.13 accepted and v1.14 refuses at load.
Three-state semantics and symmetric suppression are unchanged: SATISFIED, UNSATISFIED or UNKNOWN, with UNKNOWN
refused.

## The fragment

Each matcher is a regular language over bytes 1–255, and the length bound
(4095 bytes) still applies. Globs are the fixed regular family below. General
regular expressions are not admitted, because they are harder for a policy
author to read correctly and they make the load-time analysis costlier.

| Glob | Matches |
|---|---|
| `?` | one byte other than `/` |
| `[abc]`, `[a-z]`, `[!a]` / `[^a]` | one byte from the set, never `/` (a `/` inside a set is refused) |
| `*` | zero or more bytes, none of them `/` |
| `**` | zero or more bytes of any value |
| `/**/` | a `/`, then zero or more whole segments: `/a/**/b` matches `/a/b` and `/a/x/y/b` |
| `\x` | the byte `x` literally |

More precisely:

- Matching is byte-wise and case-sensitive. To match any case, use a set:
  `glob **.[pP][eE][mM]`.
- A `]` first in a set and a `-` last are literal. `\x` inside a set is the
  byte `x`. The `/**/` unit needs an unescaped `/` before the `**`.
- A glob has at most 32 wildcards, and `***` is refused.
- A policy's globs total at most 65,536 tokens. This bounds the work of any
  single decision (see Latency).
- Matching is on the **resolved canonical path**, as for every path rule since
  v1.12.3. A symlink named `innocent.txt` that points at `server.pem` is decided
  as `server.pem`.

**Grammar and compatibility.** The matcher is an optional keyword before the
constant:

```
<allow|deny> <path|exec> [exact|prefix|suffix|contains|glob] <constant> [flag-clause...]
```

- A keyword is read as a matcher only when a constant follows it that is not
  itself a flag clause. So `allow path glob readonly`, a v1.13 prefix rule for a
  constant named `glob`, keeps its v1.13 meaning.
- After `require warden 1.14`, a matcher keyword with no constant after it is an
  error rather than a prefix rule for the word. That covers the case where the
  constant was forgotten, and the case where a `#` turned it into a comment
  (`deny path suffix #.pem`).
- A v1.13 Warden refuses every matcher line: it reads the constant as an
  unknown flag clause. Start a policy that uses matchers with
  `require warden 1.14` so the reason is explicit.
- Matchers on `host` rules are refused. Host constants are addresses, and
  address-range matching is a separate piece of work.

## How it is decided

- **Concrete actions (every syscall).** `prefix`, `exact`, `suffix` and
  `contains` compare bytes (`memcmp` and `memmem`).
- **Globs** compile at load into a small automaton, a sequence of tokens with
  forward skips.
  - A match first checks a literal prefix, a literal suffix, a literal run the
    path must contain, and a minimum length. That rejects most paths at once.
  - It then steps the automaton **word-parallel**: 64 states per machine word,
    with a carry trick for the skips.
  - So the cost of a step does not depend on how many states are active.
- **Symbolic flags** (the `--plan` gate) work as in v1.13. The string is always
  concrete.
- **Rule reachability** (at policy load). Once a kind has a `suffix`,
  `contains` or `glob` rule, the v1.13 witness-set method no longer covers every
  class of strings. Reachability is then decided on the rules' automata:
  - **Byte classes.** Bytes are grouped into classes on which every program
    agrees.
  - **Product search.** A breadth-first search over the product of the rules'
    subset-construction automata finds the **shortest** string on which rule
    *i* holds and no earlier rule does. The search stops at depth 4095, so the
    length bound is decided exactly.
  - **Flags.** Flags are handled by enumerating the distinct sets of earlier
    rules whose flag atom can hold together with rule *i*. Reachability is
    monotone in that set, so only the inclusion-minimal sets are searched.
  - **Budgets.** Past a state or work budget the answer is UNKNOWN, never a
    guessed DEAD or REACHABLE. The Warden then prints "reachability not
    decided".
- **Witnesses.** `tools/vdp_check <policy> analyze` now prints, for every
  reachable rule, a shortest string and a flags value on which it is the first
  rule to hold. The cross-check re-verifies every witness.

## Independent cross-check

`tools/smt_crosscheck.py` re-parses each policy independently of the C code,
including an independent translation of each glob into a regular expression. It
requires three things:

- **Ground and symbolic-flag verdicts** must equal the solver's. The solver sees
  suffix, contains and glob through its string and regular-expression theories.
- **Every REACHABLE witness** must make its rule fire first, confirmed by the
  solver on the concrete string and flags.
- **Every DEAD / REACHABLE answer** must equal a **Brzozowski-derivative
  decision procedure** written for the cross-check. It searches breadth-first to
  depth 4095, so it is exact at the length bound. It enumerates flag signatures
  with the solver and checks every signature, not only the minimal ones.
  - The procedure must also agree with the solver's unbounded regex query
    whenever that query is conclusive. Near the bound the solver's models run
    past 4095 bytes, and with the bound added it does not finish.
  - Both of the procedure's reachability methods are checked on every path and
    exec rule. `analyze automaton` forces the automaton search on rules the trie
    method normally decides.
  - An UNKNOWN is accepted only with a documented budget reason.

**Results** (the exact runs `make crosscheck` performs):

| Run | Checks | Disagreements |
|---|---|---|
| Every policy in the repository (21 files) | 1,656 | 0 |
| 300 fuzzed policies, seed 1 | 18,289 | 0 |
| 300 fuzzed policies, seed 2 | 18,331 | 0 |
| 300 fuzzed policies, seed 3 | 18,582 | 0 |

In all, 56,858 checks with zero disagreements:

- **Fuzzed policies.** 775 of the 900 fuzzed policies were accepted and 125
  rejected, identically by both parsers; 560 of the accepted ones use suffix,
  contains or glob rules.
- **Witnesses.** 4,313 reachability witnesses were confirmed by the solver.
- **Derivatives and the solver.** The derivative procedure decided 2,534
  string-reachability questions. The solver's unbounded query was conclusive
  on 2,514 of them and agreed every time. The other 20 were inconclusive,
  either because the model ran past the length bound or because of a timeout.
- **UNKNOWN at a budget.** The procedure answered UNKNOWN on reachability seven
  times: four at the flag enumeration bound and three at the state budget, one
  of them the `tests/v1140_budget_policy.txt` fixture. It hit the enumeration bound
  on 167 verdicts. It never gave a definite answer that differed from the
  oracle's.

The fuzzer produces:

- all five matchers, with globs built both from random pieces and from stems of
  earlier rules, so rules overlap and shadow each other;
- escapes, sets and ranges, `/**/`, and `\/` before `**`;
- near-bound constants, non-ASCII bytes and malformed globs;
- keyword-spelt constants, over-long lines and malformed `require` directives;
- queries sampled from each rule's language, including text that looks like the
  solver's own string escapes.

The repository fixtures cover the rest:

- rules decided only by the length bound (`tests/v1140_bound*_policy.txt`);
- shadowing across every matcher (`tests/v1140_shadow_policy.txt`);
- the state budget (`tests/v1140_budget_policy.txt`);
- v1.13 keyword compatibility (`tests/v1140_compat_policy.txt`).

**Mutation test.** Twenty bugs were planted in the procedure and 18 were
flagged.

- **The two survivors do not change any output in the current code:**
  - a length check in the no-competitor shortcut that cannot trigger, since a
    program has at most 4,095 single-byte tokens;
  - dropping the explicit `/` byte class, since every program that can tell `/`
    apart already splits it.
- **The flagged ones cover:**
  - every glob construct;
  - the word-parallel step's carries across 64-bit words;
  - the fast-rejection paths;
  - the parser's keyword rules;
  - the length bound, minimal-set, universal-state and flag-implication logic
    of the reachability search.
- **One flag is for a different reason.** A mutant that let the pairwise
  prefilter drop a candidate whose search hit the budget was flagged because
  its answer on the budget fixture could not be confirmed within the oracle's
  own budget, not because the answer was wrong.
- **Fixtures.** Two mutants survived an earlier version of the fuzzer: an
  over-eager pruning rule, and an escaped `/` starting the `/**/` unit.
  Fixtures now catch both deterministically.

**What the cross-check can and cannot show.** The grammar-level decisions are
common to both parsers, because both follow `smt_decide.h`. Examples are when
`/**/` is a unit, how escapes work inside a set, and which tokens are keywords.
The cross-check therefore validates the matching and reachability engines
against the documented grammar; it cannot find a mistake in the grammar itself.
Those decisions were reviewed by hand and by an independent review, which also
compared the C matcher with a third glob translation on 176,000 pattern/string
pairs, with zero differences.

Two lessons from the oracle itself:

- Z3's string literal constructor decodes `\u{..}` escape sequences. A path
  containing that text was compared as a different string, and a 4,201-byte
  string passed its length guard. The cross-check now escapes every backslash.
- The solver's regex theory answers unbounded reachability instantly, but not
  the same question with the 4095-byte bound. That is why the bounded answer
  comes from the derivative procedure.

## Security

The example sector policies now deny key material and credentials under every
tree the agent may reach, including its scratch space. Each file starts with
`require warden 1.14`.

- **All five policies:**
  - `deny path suffix .pem`
  - `deny path suffix .key`
  - `deny path glob /**/.env` and `/**/.env.*`
  - `deny path contains /.ssh` (the directory and everything under it)
- **finance:** macro-capable workbooks in the read/write workpapers tree:
  `.xlsm`, `.xlsb`, `.xltm`, `.xlam` and legacy `.xls`, in any letter case.
- **healthcare:** psychotherapy notes, which need separate patient
  authorization. Both the directory and its files are denied, at any depth under
  the records tree.
- **national-defense:** compartmented intelligence products, with the directory
  and its files denied, at any depth.

These rules judge the resolved path's **name**, not the file's identity. A hard
link that already exists under another name is decided by that name. When the
Warden enforces, the agent itself cannot rename files or create links: `rename`,
`link` and `symlink` are outside the syscall allowlist. In observe mode
(`VAREK_WARDEN_OBSERVE=1`) they are only logged, so name matchers are not a
boundary there. `suffix .pem` also denies public certificates and CA bundles.
That is harmless in these policies because `/etc` is already denied.

## Load-time analysis

As in v1.13, the Warden decides at startup whether each rule can ever fire, and
warns on every rule that cannot. The automaton search finds shadowing across
matchers, for example a glob that an earlier suffix rule covers, or a
one-segment glob covered by a `/**/` glob:

```
[warden] policy p.txt:3: WARNING: allow path rule can never fire: every action it matches is decided by an earlier rule, or it matches no string within the length bound
```

The Warden and `vdp_check lint` also add a note for two cases:

- a path or exec constant that cannot match an absolute path, such as
  `deny path glob` with the constant forgotten in a v1.13-style policy;
- a rule whose reachability was not decided within the budget.

The analysis is advisory. It never changes a decision.

## Verdict-distribution harness

The harness now has a **v1.13.0 shipped** view: verbatim copies of the policies
as v1.13.0 shipped them, in `harness/baseline-v1.13.0/`. The corpus gains 24
actions:

- **17 UNSAFE**, for example key material, dotenv files and psychotherapy notes
  under allowed trees, upper-case and legacy workbook extensions, and a nested
  compartmented product;
- **7 SAFE near misses**, for example `pem-rotation-notes.txt`, a
  `psychotherapy-referral.txt` letter, an ordinary `.xlsx` workbook and an
  `environment-notes.txt` scratch file.

| Policies decided as… | Safe opens proved SATISFIED | Unsafe opens proved SATISFIED |
|---|---|---|
| **v1.14** | **87.5%** (42 of 48) | **0** |
| v1.13.0 as shipped | 87.5% (42 of 48) | 17 (16 distinct) |
| v1.12.4 as shipped | 79.2% (38 of 48) | 41 (32 distinct) |

130 actions in all, 88 distinct; the table counts file opens, the runtime
outcome.

- **The new rules cost no safe open.** Every SAFE near miss is still cleared.
- **The 17 unsafe opens** that v1.13.0 authorized are all actions added in this
  release, alongside the rules that stop them. The difference is therefore a
  demonstration by construction, not a measurement.
- **These numbers are synthetic.** The policies and the SAFE/UNSAFE labels are
  SAI's. A customer-derived corpus with independently written labels is still
  outstanding.

## Latency

Per-decision cost of the procedure alone, on the same 2-vCPU build host (median
of five runs of a tight loop over eight representative paths):

| Policy | v1.13.0 file | v1.14 file |
|---|---|---|
| finance | 46 ns | 163 ns |
| healthcare | 51 ns | 155 ns |

The added cost is well under a microsecond. The Warden's end-to-end median
decision latency is unchanged: P50 8 µs in every run. That covers
five interleaved runs of `bench_target 10000` each, for the v1.13.0 Warden, for
v1.14 on the same policy, and for v1.14 with the five hazard rules added. P99
was 84–96, 86–104 and 85–109 µs respectively. P99 on this host is noisy and
moves with load.

**Worst case.** One decision's cost is bounded by the policy's total glob size.
An adversarial policy at the 65,536-token cap measured 12 ms. That policy has 16
globs of about 4,000 literal bytes each, with a leading `**` and a trailing set,
and the query is a 4,095-byte agent-chosen path that passes every fast-rejection
test. Without the cap and the word-parallel step, an independent review measured
5 s per decision on such a policy.

Load-time reachability is bounded by a per-rule work budget. A realistic
250-rule policy takes under a second. A pathological one with 100 overlapping
2,000-byte `contains` rules takes about 8 s and reports most rules as "not
decided".

## Records

- `run_start` reads `"warden":"1.14.0"`.
- Records are otherwise unchanged. `policy_line` names the deciding rule
  whatever its matcher.

## Compatibility

- **Every v1.13 policy keeps its meaning.** `make test-v1140` builds the v1.13.0
  `vdp_check` from the tag. It then compares verdicts and reachability for
  4,200 queries over every v1.13.0 and v1.12.4 example policy, plus a fixture of
  keyword-spelt constants. There are zero differences.
- **Do not load a v1.14 policy into an older Warden.** v1.13 refuses matcher
  lines. Start such policies with `require warden 1.14`.
- **Stricter `require` parsing.** The version must be `<digits>.<digits>`. A
  sign (`+1.13`, `1.+13`, `-0.13`), which the v1.13 parser accepted, is refused.
- **Example sector policies are stricter.** An agent that read a `.pem`, `.key`
  or `.env` file, or anything under a `.ssh` directory, inside an allowed tree
  is now refused.

## Not in this release

- Address-range matching for host rules (CIDR), and a fixed regular-expression
  family beyond globs.
- Proof objects and an independent proof checker. This is the next release in
  the program. Every SATISFIED verdict would carry a certificate that a small
  separate checker re-verifies.
- A customer-derived corpus and a measured baseline.
- `fcntl(F_SETFL)` mediation, and flags in the `--plan` file format.
- The bounded sequence fragment (v1.11 candidate).

## Testing

- `make test-v1140` runs against a live Warden and covers:
  - **Every matcher on the resolved path.** This includes a `.pem` file reached
    through an innocently named symlink, `*` never crossing `/`, `/**/` at zero
    and several segments, and `exact` not admitting a sibling. A glob keeps its
    flag clause.
  - **Load-time analysis.** The automaton search reports shadowed rules, and a
    shortest witness is printed.
  - **Parser refusals:**
    - malformed globs;
    - matchers on host rules;
    - 33 wildcards;
    - the glob-token cap;
    - a malformed `require`;
    - a bare keyword under `require warden 1.14`.
  - **v1.13 compatibility**, against the v1.13.0 build.
  - **Lint.** Every shipped policy lints clean, with every rule decided.
  - **The `--plan` gate with matchers.**
  - **Cross-checks.** A short solver and derivative cross-check passes.
  - **The harness gate.**
- `make crosscheck` (the table above) and `make harness`.
- The earlier suites also pass:
  - `make test-v1130`, `test-v1124`, `test-v1123`, `test-v1122`, `test-v1121`,
    `test-v112` and `test-lifecycle`;
  - `run-conformance` and `v1_6/integration_test.sh`.

  `test-v1130` now compares the Warden's version with `sort -V`.
- **CPython.** A dynamically linked, multithreaded CPython agent runs under the
  updated utility policy. Its scratch writes are allowed, its read of
  `/tmp/varek/.env` is refused, and its write to `libz` is refused.
- **Independent review.** It found no blocker, and no concrete action wrongly
  SATISFIED or wrong reachability answer. Its findings are all addressed in this
  release:
  - malformed matcher lines loading as prefix rules;
  - sector rules that missed case, depth and file variants;
  - Z3 escape decoding in the oracle;
  - unverified UNKNOWN reasons;
  - worst-case decision and analysis cost;
  - parser corner cases.

## Requirements

Runtime: unchanged from v1.13.0 (Linux ≥ 5.14, `pidfd_getfd`, `CAP_SYS_ADMIN`,
x86_64). The solver is not a runtime dependency. The cross-check and
`make test-v1140` also need `python3` and the `z3-solver` package. The
compatibility section of `make test-v1140` needs `git` and the `v1.13.0` tag, and
is skipped without them.
