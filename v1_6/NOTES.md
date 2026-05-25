# VAREK v1.6.1 — design notes

## Scope: pre-execution verification of an ExecutionPlan

v1.6 lifts VAREK's per-Action policy decision to a plan-level
decision over a directed acyclic graph of Actions. Verification
fires before any node executes; only a fully `SATISFIED` plan
authorizes execution. This implements USPTO Provisional
64/062,549 (filed May 2026), covering pre-execution verification
of action graphs as compositional policy decisions.

The v1.4 Warden's `policy_decide()` returns `ALLOW` / `DENY` /
`UNKNOWN` per syscall on the hot path. The v1.6 evaluator returns
`SATISFIED` / `UNSATISFIED` / `UNKNOWN` over a plan, ahead of any
execution. The symmetric-suppression invariant — both negative
states block, only the positive state authorizes — is preserved
under graph composition.

## Release line

The v1.6 release line ships in three sequential tags:

- **v1.6.0** — verification kernel. ExecutionPlan primitive,
  compositional evaluator, decision API. No external consumers.
- **v1.6.1** *(this release)* — adapter layer. Declarative
  `plan_spec_t` input, callback-driven plan builder, JSON
  pathology record emission. The adapter is the bridge between
  a caller's per-action policy logic and the kernel's plan-level
  decision.
- **v1.6.2** — patched v1.4 Warden integration: text plan-file
  format, `--plan` CLI flag, pre-fork verification gate, end-to-end
  integration smoke test.

## What ships in v1.6.0

1. ExecutionPlan primitive — node and edge construction with
   compile-time fixed capacity (1024 nodes, 4096 edges) and no
   dynamic allocation past the plan struct itself.
2. Compositional evaluator — iterative-DFS cycle detection plus
   per-node decision aggregation under an information-preserving
   join.
3. Plan-level tri-state decision: `SATISFIED` / `UNSATISFIED` /
   `UNKNOWN`.
4. Authorization API: `exec_plan_authorized()`.
5. Test suite for kernel invariants.

## What ships in v1.6.1

1. `plan_spec_t` — declarative description of an intended plan.
   Carries action kind, target, parameters, edges, and capacity
   metadata. Stable across deciders.
2. `warden_build_and_verify()` — callback-driven adapter. Given a
   spec and a `plan_decide_fn` callback, builds an `exec_plan_t`,
   calls the kernel evaluator, optionally emits a pathology
   record, and returns the plan-level decision.
3. JSON pathology emission matching the format and prefix
   convention of the v1.4 Warden's per-action records. Plan-level
   records use the `pp-` prefix; per-action records use `pr-`.
4. Capacity, validity, and structural error classifiers in the
   pathology output: `node`, `cycle`, `empty`, `capacity`,
   `edge_index`.
5. Two additional test binaries: `test_adapter` and
   `test_pathology`.

## What is NOT in v1.6.1

- **v1.4 Warden integration.** The patched supervisor with a
  `--plan` CLI flag and a pre-fork verification gate is tracked
  for v1.6.2. The adapter shipped here is callable from any
  caller; the actual wiring into the v1.4 `main()` is the v1.6.2
  patch.
- **Text plan-file parser.** Reading a plan declaration from a
  file format suitable for the `--plan` CLI flag is v1.6.2 work.
- **`var::` stdlib surface for plan construction.** Public stdlib
  surfaces commit us to compatibility guarantees the kernel and
  adapter do not yet require. Deferred until the kernel and
  adapter have been exercised against the patched Warden in
  v1.6.2.
- **Per-edge policy semantics.** Edges carry only ordering /
  data-dependency information used by the cycle check. Policies
  that reason about data flow across edges (taint propagation,
  capability transfer) are tracked for v1.7+.
- **Persistent plan serialization.** Plans are in-memory only.

## Why adapter is callback-driven

The kernel module (v1.6.0) is intentionally independent of any
specific per-action policy implementation. The adapter could have
taken a direct dependency on the v1.4 Warden's `policy_decide()`,
but that would have created a circular-ish import (warden depends
on adapter depends on warden) and would have prevented unit
testing the adapter against synthetic deciders.

The callback shape is:

```c
typedef plan_decision_t (*plan_decide_fn)(const plan_spec_node_t *node,
                                          void *ctx);
```

The v1.4 Warden's `policy_decide()` will be wrapped in a thin shim
that translates a `plan_spec_node_t` into the Warden's internal
`struct action` and returns the resulting `decision_t` as a
`plan_decision_t`. That shim lives in the v1.6.2 patch, not in
this release.

## Compositional decision rule

For a plan with per-node decisions `D = {d_1, ..., d_n}`:

| Condition                          | Plan decision   |
|------------------------------------|-----------------|
| Cycle present in edge set          | `UNKNOWN`       |
| `n == 0`                           | `UNKNOWN`       |
| Any `d_i == UNSATISFIED`           | `UNSATISFIED`   |
| Else any `d_i == UNKNOWN`          | `UNKNOWN`       |
| Else (all `d_i == SATISFIED`)      | `SATISFIED`     |

The aggregator is the join over the lattice
`SATISFIED < UNKNOWN < UNSATISFIED`. Associative, commutative,
idempotent. Exhaustively tested for order invariance over 960
permutations.

## Symmetric suppression under composition

`UNSATISFIED` and `UNKNOWN` both suppress per-Action execution
in the v1.4 patent. That invariant lifts directly to the plan
level under the join above: either value at any node propagates
to the plan-level result. The join preserves the more
informative of the two for pathology output (`UNSATISFIED`
dominates `UNKNOWN`); both block the plan equally.

## JSON pathology format

One JSON object per verification, written to stderr by the
adapter when `emit_pathology` is true. Fields are detailed in
`README.md`. Two design choices worth noting:

1. **`pp-` prefix on `report_id`.** Plan-level records use `pp-`
   so they're trivially distinguishable from the v1.4 Warden's
   per-action `pr-` records. When v1.6.2 lands and both record
   types share a stderr stream, the prefix lets downstream
   consumers (log aggregators, SIEMs, pathology dashboards)
   filter without parsing the body.
2. **`suppression_reason` is a classifier, not a free-text
   explanation.** Values are fixed: `none`, `node`, `cycle`,
   `empty`, `capacity`, `edge_index`. This keeps the format
   parseable and the cardinality bounded for telemetry
   aggregation.

## Determinism and allocation

No allocation on the verification path. The kernel's cycle
detection scratch lives in thread-local arrays sized to
`PLAN_MAX_NODES` and `PLAN_MAX_EDGES`. The adapter allocates one
`exec_plan_t` per build via `exec_plan_new()`; the caller is
responsible for freeing.

The pathology emission path uses a fixed-size stack buffer for
the JSON record; record sizes are bounded by the field set above.
No `malloc` on the emit path.

## Threading model

The kernel and adapter are single-threaded by contract:
verification happens on a single supervisor thread, before any
forked process runs. Multiple supervisor threads with disjoint
plans are safe (the thread-local scratch in the kernel
guarantees this); concurrent verification of the same plan from
multiple threads is not supported and not exercised.

## Validation

All tests pass under gcc 13.3 with
`-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
-Wmissing-prototypes` (zero warnings) and under
`-fsanitize=address,undefined` (zero diagnostics). Run with
`make check`.
