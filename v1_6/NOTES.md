# VAREK v1.6.0 — design notes

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

## What ships in v1.6.0

1. ExecutionPlan primitive — node and edge construction with
   compile-time fixed capacity (1024 nodes, 4096 edges) and no
   dynamic allocation past the plan struct itself.
2. Compositional evaluator — iterative-DFS cycle detection plus
   per-node decision aggregation under an information-preserving
   join.
3. Plan-level tri-state decision: `SATISFIED` / `UNSATISFIED` /
   `UNKNOWN`.
4. Authorization API: `exec_plan_authorized()` returns `true`
   exactly when the plan-level decision is `SATISFIED`.
5. Test suite covering symmetric suppression on `UNSAT`, symmetric
   suppression on `UNKNOWN`, all-`SAT` acceptance, fanout poisoning
   at every position, exhaustive permutation invariance, and cycle
   rejection.

## What is NOT in v1.6.0

- **Warden adapter.** The v1.6.0 evaluator consumes pre-computed
  per-node decisions. The callback-driven adapter that calls the
  v1.4 `policy_decide()` per node, builds a plan, and emits
  pathology records is tracked for v1.6.1.
- **v1.4 Warden integration.** The patched Warden with a `--plan`
  CLI flag and a pre-fork verification gate is tracked for v1.6.2.
- **`var::` stdlib surface for plan construction.** Deferred.
  Public stdlib surfaces are far harder to change than internal
  kernel APIs; keeping the surface back until the kernel has been
  exercised by a real consumer lets us iterate on the kernel
  without breaking a stable contract.
- **Per-edge policy semantics.** Edges in v1.6.0 carry only
  ordering / data-dependency information used by the cycle check.
  Policies that reason about data flow across edges (taint
  propagation, capability transfer) are tracked for v1.7+.
- **Persistent plan serialization.** Plans are in-memory only.

## Why kernel-first

Three reasons.

1. **Patent substance.** The patentable element is the
   compositional evaluator over the plan graph. Hardening that in
   isolation, with a focused test suite, is the right risk
   posture for the v1.6 line.
2. **API stability.** Public stdlib surfaces commit us to
   compatibility guarantees the kernel itself does not require.
   Letting the kernel settle first means surface ergonomics can
   be tuned against real consumers rather than guessed at.
3. **Blast radius.** v1.6.0 with no public surface affects only
   internal callers. If a defect surfaces, the fix doesn't break
   downstream consumers because there aren't any yet.

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
`SATISFIED < UNKNOWN < UNSATISFIED`. It is:

- **Associative**: `join(a, join(b, c)) = join(join(a, b), c)`.
- **Commutative**: `join(a, b) = join(b, a)`.
- **Idempotent**: `join(a, a) = a`.

Fold order is therefore observably irrelevant. The structural DFS
in phase 1 imposes an order for cycle detection only;
`tests/test_order_invariance.c` verifies the algebraic property
exhaustively over 960 permutations across three node-set shapes.

## Symmetric suppression under composition

The patent invariant — `UNSATISFIED` and `UNKNOWN` both suppress
per-Action execution — lifts directly to the plan level under the
join above. Either of those values at any node propagates to the
plan-level result.

The join preserves the **more informative** of the two for
pathology output: `UNSATISFIED` dominates `UNKNOWN`, because
"a specific action is known-disallowed" carries more information
than "the verifier could not form an opinion." Both block the
plan equally. `exec_plan_authorized()` returns `true` only on
`SATISFIED`, encoding the invariant at the API boundary so the
caller cannot accidentally execute a suppressed plan.

## Why cycle yields UNKNOWN, not UNSATISFIED

A cyclic edge set is a structurally unverifiable input. The plan
graph contract requires acyclicity (the directed-acyclic part is
load-bearing for compositional reasoning). Returning `UNKNOWN`
rather than `UNSATISFIED` reflects what actually happened: the
verifier could not form a meaningful opinion about the action
set. Both still suppress the plan; the distinction matters for
pathology telemetry and for downstream debugging.

The contract also rejects self-edges at insertion. Longer cycles
are caught by the DFS in `plan_evaluator.c`.

## Determinism and allocation

No allocation on the verification path. The cycle-detection
scratch (color array, CSR adjacency, DFS stack) lives in
thread-local arrays sized to `PLAN_MAX_NODES` and
`PLAN_MAX_EDGES`. The fold over node decisions is a single
linear pass with a short-circuit at the top of the lattice.

There is no recursion. The DFS uses an explicit stack to avoid
stack-overflow concerns under large plans and to keep memory
consumption predictable.

The only allocation in the entire module is the single `calloc`
in `exec_plan_new()`. `tests/` exercises this without leaks under
ASan.

## Validation

All tests pass under gcc 13.3 with
`-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
-Wmissing-prototypes` (zero warnings) and under
`-fsanitize=address,undefined` (zero diagnostics). Run with
`make check`.
