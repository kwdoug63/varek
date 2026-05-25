# VAREK v1.6.1 — ExecutionPlan verification + Warden adapter

Pre-execution verification of an agent's action graph as a single
compositional policy decision. Implements USPTO Provisional
64/062,549 (May 2026), covering pre-execution verification of
action graphs as compositional policy decisions.

This release stacks two tiers:

- **v1.6.0** — the verification kernel: ExecutionPlan primitive
  and compositional evaluator (tagged previously).
- **v1.6.1** — the adapter layer: a callback-driven plan builder
  that turns a declarative `plan_spec_t` into a verified
  `exec_plan_t`, plus JSON pathology record emission in the same
  format as the v1.4 Warden's per-action records.

The actual patch against the v1.4 Warden — adding a `--plan` CLI
flag and a pre-fork verification gate — is tracked for v1.6.2.

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
| `execution_plan.h`            | Public C API for the kernel.                           |
| `execution_plan_internal.h`   | Internal layout shared with the evaluator.             |
| `execution_plan.c`            | Node and edge construction.                            |
| `plan_evaluator.c`            | Cycle detection plus compositional aggregation.        |
| `plan_demo.c`                 | Kernel demo binary.                                    |
| `plan_spec.h`                 | Declarative plan input type.                           |
| `warden_adapter.h`            | Adapter API.                                           |
| `warden_adapter.c`            | Callback-driven plan-spec → verified plan adapter.     |
| `pathology.h`                 | Plan-level pathology record format.                    |
| `pathology.c`                 | JSON emission matching the v1.4 Warden's record style. |
| `adapter_demo.c`              | Adapter demo binary with two scenarios.                |
| `tests/`                      | One test binary per behavior.                          |
| `Makefile`                    | `make`, `make demo`, `make adapter-demo`, `make check`.|
| `NOTES.md`                    | Design rationale.                                      |

## Build

```sh
make
make check          # runs the 7 test binaries
make demo           # runs the kernel demo
make adapter-demo   # runs the adapter demo with pathology emission
```

C11, no external dependencies. Built and tested on Linux with gcc.

## API at a glance

### v1.6.0 kernel (unchanged)

```c
exec_plan_t *p = exec_plan_new();
plan_node_id_t a = exec_plan_add_node(p, "fetch", PLAN_DEC_SATISFIED);
plan_node_id_t b = exec_plan_add_node(p, "write", PLAN_DEC_SATISFIED);
exec_plan_add_edge(p, a, b);
bool ok = exec_plan_authorized(p);
exec_plan_free(p);
```

### v1.6.1 adapter

```c
#include "warden_adapter.h"

plan_decision_t my_decider(const plan_spec_node_t *node, void *ctx)
{
    /* Inspect node->kind, node->target, node->parameters.
     * Return PLAN_DEC_SATISFIED / PLAN_DEC_UNSATISFIED / PLAN_DEC_UNKNOWN. */
}

plan_spec_t spec = { ... };
exec_plan_t *plan = NULL;
plan_decision_t d = warden_build_and_verify(&spec, my_decider, /*ctx*/NULL,
                                            &plan, /*emit_pathology*/true);
/* plan is owned by the caller; pathology record is written to stderr as
 * one JSON object per verification. */
exec_plan_free(plan);
```

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
commutative, and idempotent.

## Pathology record format

One JSON object per verification, written to stderr. Fields:

| Field                 | Type    | Notes                                                                       |
|-----------------------|---------|-----------------------------------------------------------------------------|
| `report_id`           | string  | `pp-<ns_timestamp>-<seq>`; the `pp-` prefix distinguishes from v1.4 `pr-`.  |
| `type`                | string  | `"plan_verify"`.                                                            |
| `decision`            | string  | `"SATISFIED"` / `"UNSATISFIED"` / `"UNKNOWN"`.                              |
| `authorized`          | bool    | `true` iff `decision == "SATISFIED"`.                                        |
| `n_nodes`, `n_edges`  | int     | Plan size.                                                                   |
| `latency_us`          | int     | Monotonic-clock verification duration.                                       |
| `suppression_reason`  | string  | `"none"`, `"node"`, `"cycle"`, `"empty"`, `"capacity"`, or `"edge_index"`.   |
| `suppressed_node`     | string  | Node label that triggered suppression, or `null`.                            |
| `suppressed_decision` | string  | Per-node decision at the suppressed node.                                    |
| `timestamp_ns`        | int     | Wall clock (nanoseconds since epoch).                                        |

The `pp-` prefix is deliberate. A v1.6.2 release that lands the
Warden adapter into the actual v1.4 supervisor will emit both
record types into the same stderr stream; the two-character prefix
lets downstream consumers filter without parsing.

## Tests

| Binary                                  | Coverage                                                                 |
|-----------------------------------------|--------------------------------------------------------------------------|
| `tests/test_evaluator`                  | Empty plan, single node, all-`SATISFIED`, `NULL` plan, invalid decision. |
| `tests/test_symmetric_suppression`      | Single `UNSAT`, single `UNKNOWN`, mixed, all-`UNSAT`, all-`UNKNOWN`.     |
| `tests/test_order_invariance`           | 960 exhaustive permutations across three node-set shapes.                |
| `tests/test_fanout`                     | One `UNSAT` leaf poisons every position; clean fanout authorizes.        |
| `tests/test_cycle_detection`            | 2-cycle, 3-cycle, self-edge rejection, diamond, mixed components.        |
| `tests/test_adapter`                    | Callback dispatch, decision propagation, capacity exhaustion, edge errors. |
| `tests/test_pathology`                  | JSON record format, field presence, prefix correctness, timestamp ordering. |

Run with `make check`. All tests are also clean under
`-fsanitize=address,undefined`.

## Scope

In scope for v1.6.1:

- Everything from v1.6.0 (unchanged).
- `plan_spec_t` declarative plan description.
- Callback-driven plan builder.
- JSON pathology record emission.

Tracked separately:

- Patched v1.4 Warden with `--plan` flag and pre-fork
  verification gate, plus text plan-file parser. v1.6.2.
- `var::` stdlib surface for plan construction. v1.6.3+.
- Per-edge data-flow or capability-transfer policies. v1.7+.
- Plan serialization and replay. v1.7+.

See `NOTES.md` for the full design rationale.

## License

MIT. See SPDX headers in source files.
