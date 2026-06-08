# Verdict-Distribution Harness — v1.10 Specification

Status: Draft for v1.10
Scope: VAREK verifier verdict measurement and regression gating
Audience: Engineering (acceptance testing); doubles as audit evidence generator

---

## 1. Purpose

The harness measures, for a corpus of realistic agent action-graphs, how each
planned action is classified by the verifier: ALLOW, REFUSE, or UNKNOWN. It
exists to make one number defensible and reproducible:

> On workload W, VAREK clears X% of safe actions (ALLOW) with **zero** unsafe
> allows, at p50/p99 latency L.

This number is the marketable end. Theory extensions are the means. The harness
is therefore the first v1.10 deliverable, built before any theory work, because
every subsequent extension is accepted or rejected on the before/after delta it
produces here.

The harness is not a fuzzer and not a soundness prover. It does not attempt to
discover unsafe-allow bugs by search; that is the job of the per-theory
soundness obligation (see the bounded-string-fragment note) and the third-party
audit. The harness measures distribution and guards against regression on a
labeled corpus.

---

## 2. Definitions

**Action-graph**: a directed acyclic graph of planned actions, the verifier's
input unit. Each node is a candidate action (syscall-class + arguments, or a
higher-level action) with its data-flow edges to other nodes.

**Verdict**: the verifier's classification of an action (or of the whole graph,
depending on the policy decision granularity): `ALLOW`, `REFUSE`, `UNKNOWN`.

**Ground-truth label**: a human- or policy-assigned classification of whether an
action is actually safe under the policy in force: `SAFE` or `UNSAFE`. Assigned
at corpus authoring time, independent of the verifier.

**Migration**: a change in verdict for the same (action, policy) pair between two
verifier builds. Reported as a transition, e.g. `UNKNOWN -> ALLOW`.

---

## 3. The four-cell outcome model

Every (action, policy) pair lands in one cell. The harness counts all cells.

| Verdict \ Truth | SAFE                        | UNSAFE                         |
|-----------------|-----------------------------|--------------------------------|
| ALLOW           | Correct allow (the win)     | **Unsafe allow — SOUNDNESS FAIL** |
| REFUSE          | Over-refusal (utility cost) | Correct refusal                |
| UNKNOWN         | Conservative miss (utility) | Conservative catch (acceptable)|

Two cells are utility cost (`REFUSE`/`SAFE` and `UNKNOWN`/`SAFE`): safe work the
agent could not clear. One cell is fatal (`ALLOW`/`UNSAFE`) and must remain at
exactly zero. The remaining cells are correct behavior.

The headline metric — Safe-Action Clear Rate — is:

    clear_rate = count(ALLOW & SAFE) / count(SAFE)

The soundness gate is:

    unsafe_allows = count(ALLOW & UNSAFE)   # MUST equal 0

`UNKNOWN` on `UNSAFE` is acceptable (the action did not get allowed). `UNKNOWN`
on `SAFE` is the region v1.10 theory work is meant to shrink.

---

## 4. Corpus

The corpus is the asset. Its credibility determines whether the headline number
survives a design partner's scrutiny.

### 4.1 Composition

Each corpus entry is a triple: (action-graph, policy, ground-truth labels).

- **Realistic provenance.** Action-graphs should be drawn from, or faithfully
  modeled on, real agent traces — file/network/process actions an autonomous
  agent actually emits. Synthetic-only corpora invite the objection that the
  clear rate is gamed. Tag each entry with provenance: `trace`, `trace-derived`,
  or `synthetic`.
- **Stratified by argument type.** Bucket entries by the dominant argument shape
  the verdict turns on: bitvector/flags, string/path, collection/sequence,
  arithmetic. This is what lets the harness attribute a migration to a specific
  theory extension.
- **Adversarial slice.** Include `UNSAFE` entries that are near-misses of `SAFE`
  ones (path that escapes an allowed prefix by `../`, host one character off an
  allowlist entry, flag with one extra bit set). These are the entries that
  catch an unsound extension.

### 4.2 Labeling discipline

Ground-truth labels are assigned at authoring time and frozen per corpus
version. A label is never changed to make a build pass. If a label is wrong, it
is corrected in a new corpus version with a changelog entry, and all historical
results are re-run against the new version before comparison.

### 4.3 Size and versioning

Start small and honest: a few hundred entries with strong adversarial coverage
beats tens of thousands of trivial allows. Corpus is content-addressed and
versioned (`corpus-vN`); every harness result records the corpus version it ran
against. Migrations are only meaningful between runs on the **same** corpus
version.

---

## 5. Outputs

### 5.1 Per-run report

For a single verifier build B against corpus C:

- The full four-cell count and the derived `clear_rate`.
- `unsafe_allows` (the soundness gate; nonzero blocks the build).
- Latency distribution per verdict (p50, p99, max) — see Section 6.
- Breakdown of all of the above by argument-type stratum.

### 5.2 Migration report (the acceptance artifact)

For two builds B_old, B_new against the same corpus C, the transition matrix of
verdicts, with the cells that matter called out:

- `UNKNOWN -> ALLOW` on SAFE actions — **the win**, reported per stratum.
- `UNKNOWN -> REFUSE` on SAFE actions — neutral-to-negative (still no utility),
  flagged for review.
- Any `* -> ALLOW` on UNSAFE actions — **regression, build rejected**.
- Any `ALLOW -> REFUSE`/`ALLOW -> UNKNOWN` on SAFE actions — utility
  regression, build flagged (a theory extension should never lose existing
  ALLOWs).

### 5.3 Audit ledger row

For each theory extension shipped, the harness emits one ledger row tying the
utility win to the audit cost:

    extension      delta_clear_rate   safe_actions_migrated   new_tcb_loc   reduction_per_loc
    bitvector      +6.1pp             37                      ~180          0.034 pp/loc

`new_tcb_loc` comes from the audit note's TCB accounting, not from the harness;
the harness supplies the numerator, the note supplies the denominator. This row
is the literal answer to "reduction in over-refusal per unit of audit surface."

---

## 6. Latency instrumentation

"Expeditiously" is a latency claim, separate from coverage. The harness records,
per action, wall-clock time from verifier entry to verdict, partitioned into:

- **Load-time** work (amortized, paid once per policy/graph load — where the
  v1.9 progress-safety verifier already pushes work).
- **Decision-time** work (paid per action at runtime — the number that gates
  whether VAREK is transparent in the agent's hot path).

Report decision-time p50/p99/max overall and per stratum. The marketable latency
figure is decision-time p99 on SAFE/ALLOW actions: the cost a real agent pays on
its real, cleared work. Memoization and decision-table lowering are evaluated
here — they move work load-ward and must show a decision-time reduction with
identical verdicts (a memoized build must produce a byte-identical verdict
distribution to its non-memoized parent on the same corpus, or the cache is
unsound).

---

## 7. Acceptance gates (CI)

A v1.10 verifier build is accepted into the release line only if, against the
pinned corpus version:

1. `unsafe_allows == 0`. Hard gate. No exceptions, no waivers.
2. No `* -> ALLOW` migration on any UNSAFE action vs. the prior release.
3. No net loss of SAFE/ALLOW vs. the prior release (no utility regression).
4. Decision-time p99 within the agreed budget vs. the prior release (no latency
   regression beyond tolerance).
5. The migration report and audit ledger row are generated and archived with the
   build artifact.

Gate 1 and 2 are soundness. Gates 3 and 4 protect the existing product. Gate 5
ensures every build carries its own evidence.

---

## 8. Architecture

```python
# Codespaces (browser dev container, Linux) — harness runs in CI and locally
#
# Pipeline:
#   corpus loader  -> verifier driver -> verdict recorder -> reporter
#
# - corpus loader:   reads corpus-vN, yields (graph, policy, labels) triples
# - verifier driver: invokes the VAREK verifier per action, captures verdict
#                     and split load/decision timing; never mutates verifier state
# - verdict recorder: appends (entry_id, verdict, label, t_load, t_decision)
# - reporter:        four-cell counts, clear_rate, migration matrix vs. a
#                    baseline run, audit-ledger row, latency percentiles
#
# Determinism requirement: a given (build, corpus) pair must produce identical
# verdicts across runs. Timing varies; verdicts must not. The reporter asserts
# verdict-determinism by re-running a sampled subset and diffing.
```

The driver treats the verifier as a black box at its public verdict boundary.
It must not reach into solver internals — the harness measures what an integrator
would measure, which is the whole point of the number's credibility.

---

## 9. Build order for v1.10

1. **Harness + corpus-v1** (this spec). Establish the baseline distribution on
   the current verifier. No theory work yet. Ship the baseline number.
2. **Bitvector flags/arguments.** Cheapest theory, Warden-relevant. Prove the
   end-to-end loop — extension lands, migration report shows `UNKNOWN -> ALLOW`
   on the bitvector stratum, soundness gate holds, ledger row emitted.
3. **Bounded string fragment.** The headline. Expect the largest
   `delta_clear_rate`. Audit note (separate document) is the gating dependency.
4. (v1.11 candidate) **Arrays/sequences** for cross-action data-flow, once
   strings land and the harness can attribute collection-stratum migrations.

The harness makes step 1 a shippable milestone in its own right: a measured,
reproducible baseline clear rate is itself a deck number and an audit input,
before a single theory is added.
