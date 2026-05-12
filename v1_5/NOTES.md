# VAREK v1.5 — design notes

## Decision: hybrid prefix-DFA + SMT architecture

`policy_decide()` in v1.5 routes simple rules (path-prefix, exact host,
exec path) through a compiled in-memory matcher (`fast_match.c`) and
reserves the SMT layer for rules that genuinely require it.

For the v1.4 policy.txt, this means **every rule lands on the fast
path** at sub-microsecond latency, while the SMT layer is available
for future policies expressing regex constraints, integer ranges, or
conjunctions of conditions.

This file documents the experimental work that led to the decision,
in case anyone looks at the SMT probes (`smt_probe.c`, `smt_probe2.c`)
and wonders why we didn't ship them as the core decision procedure.

## Probes built and measured

Three benchmarks, all in this directory:

| Probe | Description | Hot-path? |
|---|---|---|
| `smt_probe.c`  | Z3 string-theory, fresh context per call (worst case) | No |
| `smt_probe2.c` | Z3 string-theory, context reuse with push/pop          | No |
| `fast_match.c` | Sorted prefix array + binary search                    | **Yes** |

Each emits JSON pathology records compatible with `bench_summarize.py`.

## What we found

### SMT probe results (DigitalOcean 1 vCPU / 512 MB, Z3 4.8.12)

| Probe | P50 | P99 | Max | Notes |
|---|---|---|---|---|
| `smt_probe`  (fresh ctx) | 13,172 µs | 21,187 µs | 42,731 µs | Confirmed worst case |
| `smt_probe2` (reuse ctx) |    465 µs | 51,959 µs | 69,328 µs | Bimodal distribution |

The dramatic P50 drop from probe 1 to probe 2 confirmed that fresh-
context creation dominates the worst case. But probe 2's P99 went *up*
relative to probe 1, exposing a textbook Z3 string-theory pathology:

- Most decisions complete in ~500 µs (excellent).
- A meaningful fraction take 40-50 ms (catastrophic).
- Almost nothing in between.

Z3 string theory accumulates internal state across `push/pop` cycles
(learned lemmas, string-axiom unfoldings, propagation cache). Over
thousands of queries this state grows and occasionally triggers
expensive recomputation on individual checks. This is a known issue
in the formal-methods literature and is why production systems rarely
use SMT string theory on a hot path.

### fast_match results (same host)

| Metric | Value |
|---|---|
| P50 | 93 nanoseconds |
| P99 | 271 nanoseconds |
| P99.9 | 526 nanoseconds |
| Max | 8.26 µs |
| 10K decisions | 50 ms wall-clock |
| False negatives | 0 |
| UNKNOWN suppressions | 2,500 of 2,500 |

Sub-microsecond at all percentiles up to P99.9. Three orders of
magnitude faster than the v1.4 Warden's measured 57 µs P99 — which
tells us the Warden's tail latency is dominated by seccomp, proc/mem,
and kernel-injection overhead, not the policy decision itself.

## Why we kept the SMT probes in the repo

Three reasons.

1. **Honest engineering record.** The probes document what we tried
   and why we didn't ship pure SMT. Failed-but-documented experiments
   are credibility-positive in security communities — they show we
   measured before committing to an architecture.

2. **Patent claim integrity.** The pending patent application
   describes a three-state SMT decision procedure with symmetric
   suppression. The probes demonstrate that procedure is real and
   working — it's just on the slow path rather than the hot path.
   Anyone questioning whether the claim corresponds to running code
   can clone the repo and run `./smt_probe2`.

3. **Extensibility floor.** When future policy rules require richer
   constraints (regex, integer ranges, multi-rule conjunctions), the
   SMT layer is already wired up. We benchmark the hybrid combined
   system at that point, not the pure SMT system.

## What's NOT in v1.5

This is a fast-path matcher and SMT feasibility study. The following
are tracked separately and explicitly out of scope here:

- **Integration with the Warden's seccomp-unotify hot path.** Currently
  `fast_match.c` is a standalone benchmark; integrating into
  `varek/v1_4/warden.c` is a follow-up.
- **The SMT slow path with rule classification.** Currently every rule
  routes through the fast path because every current rule is simple.
- **Trie or DFA optimization for very large policy files.** Sorted
  prefix array is fine for v1.4-scale policies (tens of rules). At
  10K+ rules a real DFA would be worth the implementation cost.

## Reproduce

```sh
sudo apt install -y libz3-dev
make
./fast_match  10000 ../v1_4/policy.txt 2> bench_fast.log
./smt_probe2  1000                     2> bench_probe2.log
python3 bench_summarize.py bench_fast.log
python3 bench_summarize.py bench_probe2.log
```

The `bench_summarize.py` in this directory uses `latency_ns` when
present (v1.5 records) and falls back to `latency_us` (v1.4 records).
