# VAREK v1.6.0 — ExecutionPlan verification

Pre-execution verification of an agent's action graph as a single
compositional policy decision. Implements USPTO Provisional
64/062,549 (May 2026), covering pre-execution verification of
action graphs as compositional policy decisions.

This release is the verification kernel only. The Warden adapter
that wires per-node decisions through the v1.4 `policy_decide()`,
and the v1.4 Warden integration patch, are tracked for v1.6.1
and v1.6.2 respectively.

## Overview

Where the v1.4 Warden returns `ALLOW` / `DENY` / `UNKNOWN` per
intercepted syscall, v1.6 returns `SATISFIED` / `UNSATISFIED` /
`UNKNOWN` over a whole ExecutionPlan — a directed acyclic graph of
Actions an agent intends to execute. Verification fires before any
node runs; only a fully `SATISFIED` plan authorizes execution.

The same symmetric-suppression invariant the patent specifies at
the per-action layer lifts compositionally to the plan layer: both
`UNSATISFIED` and `UNKNOWN` block the plan equally. The distinction
is preserved in the return value for pathology output.

## Layout

| File                          | Purpose                                                |
|-------------------------------|--------------------------------------------------------|
| `execution_plan.h`            | Public C API.                                          |
| `execution_plan_internal.h`   | Internal layout shared with the evaluator.             |
| `execution_plan.c`            | Node and edge construction.                            |
| `plan_evaluator.c`            | Cycle detection plus compositional aggregation.        |
| `plan_demo.c`                 | Minimal demo binary.                                   |
| `tests/`                      | One test binary per behavior.                          |
| `Makefile`                    | `make`, `make demo`, `make check`, `make clean`.       |
| `NOTES.md`                    | Design rationale and decision-rule derivation.         |

## Build

```sh
make
make check    # runs the test binaries
make demo     # runs the demo
```

C11, no external dependencies. Built and tested on Linux with gcc.
The compile line uses `-Wall -Wextra -Wpedantic -Wshadow
-Wstrict-prototypes -Wmissing-prototypes` and produces zero
warnings.

## API

```c
#include "execution_plan.h"

exec_plan_t *p = exec_plan_new();

plan_node_id_t a = exec_plan_add_node(p, "fetch", PLAN_DEC_SATISFIED);
plan_node_id_t b = exec_plan_add_node(p, "write", PLAN_DEC_SATISFIED);
exec_plan_add_edge(p, a, b);   /* b depends on a */

if (exec_plan_authorized(p)) {
    /* execute the plan */
} else {
    /* suppress; emit pathology with exec_plan_verify(p) */
}
exec_plan_free(p);
```

Per-node decisions are supplied by the caller. In v1.6.0 the
evaluator consumes pre-computed decisions; the adapter that calls
the v1.4 Warden `policy_decide()` per node and assembles a plan
will land in v1.6.1.

## Compositional decision rule

| Condition                          | Plan decision   |
|------------------------------------|-----------------|
| Cycle present in edge set          | `UNKNOWN`       |
| Empty plan                         | `UNKNOWN`       |
| Any node `UNSATISFIED`             | `UNSATISFIED`   |
| Else any node `UNKNOWN`            | `UNKNOWN`       |
| Else (all nodes `SATISFIED`)       | `SATISFIED`     |

The aggregator is the join over the lattice
`SATISFIED < UNKNOWN < UNSATISFIED`. It is associative,
commutative, and idempotent, so the fold order is observably
irrelevant. `tests/test_order_invariance.c` confirms this
exhaustively on small mixed sets.

## Symmetric suppression

Both `UNSATISFIED` and `UNKNOWN` block plan execution. Only
`SATISFIED` authorizes. The distinction is preserved in the
return value for pathology output; the authorization API
encodes the invariant directly:

```c
bool exec_plan_authorized(const exec_plan_t *plan);
/* returns true iff exec_plan_verify(plan) == PLAN_DEC_SATISFIED */
```

## Tests

| Binary                                  | Coverage                                                                 |
|-----------------------------------------|--------------------------------------------------------------------------|
| `tests/test_evaluator`                  | Empty plan, single node, all-`SATISFIED`, `NULL` plan, invalid decision. |
| `tests/test_symmetric_suppression`      | Single `UNSAT`, single `UNKNOWN`, mixed, all-`UNSAT`, all-`UNKNOWN`.     |
| `tests/test_order_invariance`           | 960 exhaustive permutations across three node-set shapes.                |
| `tests/test_fanout`                     | One `UNSAT` leaf poisons every position; clean fanout authorizes.        |
| `tests/test_cycle_detection`            | 2-cycle, 3-cycle, self-edge rejection, diamond, mixed components.        |

Run with `make check`. All tests are also clean under
`-fsanitize=address,undefined`.

## Scope

In scope for v1.6.0:

- ExecutionPlan construction and fixed-capacity storage.
- Structural verification (acyclicity).
- Compositional per-node decision aggregation.
- Plan-level tri-state decision.
- Authorization predicate.

Tracked separately, not part of this release:

- Warden adapter (callback-driven plan builder + JSON pathology emission). v1.6.1.
- Patched v1.4 Warden with `--plan` CLI flag and pre-fork verification gate. v1.6.2.
- `var::` stdlib surface for plan construction. v1.6.3+.
- Per-edge data-flow or capability-transfer policies. v1.7+.
- Plan serialization and replay. v1.7+.

See `NOTES.md` for the full design rationale.

## License

MIT. See SPDX headers in source files.
