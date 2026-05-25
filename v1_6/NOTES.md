# VAREK v1.6 — design notes

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

The v1.6 line breaks into three patch releases, each strictly
additive over the previous:

- **v1.6.0** — verification kernel. ExecutionPlan primitive,
  compositional evaluator, plan-level tri-state decision,
  authorization predicate. No consumers, no integration.
- **v1.6.1** — adapter and pathology. A callback-based adapter
  turns a `plan_spec_t` into per-node decisions and feeds the
  v1.6.0 evaluator. JSON pathology sink matches v1.4 record style.
- **v1.6.2** — real Warden integration. A text-format plan file
  parser and a unified-diff patch against `varek/v1_4/warden.c`
  add a `--plan` CLI flag and a pre-fork verification gate. The
  patched Warden refuses to start the target process if the plan
  does not verify as `SATISFIED`.

Each release was designed to ship as a separate tag.

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

## What ships in v1.6.1

1. `plan_spec_t` — a declarative input type. Borrow-only; no
   deep copies.
2. `warden_adapter_verify()` — turns a spec into per-node decisions
   via a caller-supplied decider callback, builds the
   `exec_plan_t`, runs verification, emits a pathology record.
3. `pathology_sink_t` — JSON-emitting sink matching the v1.4
   `emit_pathology()` style (`pp-` prefix for plan-level records).
4. Defensive coercion of decider return values outside the
   tri-state to `UNKNOWN`.
5. JSON-safe label escaping.
6. Tests covering happy path, every suppression mode, every
   structural failure mode, JSON output format validation, and
   sequence-counter monotonicity.

## What ships in v1.6.2

1. `plan_parser` — text-format plan file loader. Two directives
   only (`action`, `edge`). Structured `file:line: reason` errors
   surface every parse failure. Owns its string storage so the
   produced `plan_spec_t` is safe to borrow until the parser
   handle is freed.
2. `warden_v1_4.patch` — a unified diff against the v1.4 Warden:
   - Adds v1.6 includes after the existing block.
   - Adds a `kind_from_string()` mapping helper.
   - Adds a `warden_plan_decider()` that wraps the existing
     `policy_decide()` into the `plan_action_decider_fn`
     signature. This is the only required glue because
     `policy_decide()` already exposes the right granularity
     and only consults `(kind, target)`.
   - Adds a `warden_verify_plan()` orchestration function.
   - Updates `usage()` and `main()` to accept the optional
     `--plan <file>` between the policy path and `--`.
   - Inserts the pre-fork gate: on a non-`SATISFIED` plan,
     `main()` returns `1` before `fork()` is called.
3. Makefile edits adding `-I../../v1_6`, linking the v1.6
   sources into the warden binary, and adding a
   `run-plan-demo` target.
4. `integration_test.sh` — end-to-end regression check that
   builds the patched warden and runs four cases against it.

## What is NOT in v1.6.x

### `var::` stdlib surface for plan construction

This was on the v1.6.1 roadmap when I recommended "kernel-only
for v1.6.0, surface ergonomics in v1.6.1." Investigating the
repo at HEAD changed the recommendation.

The post-rename Python `var::` stdlib only exists in the frozen
`varek-v1.0/` directory, where the modules still use legacy
`syn::` references (a known release-artifact issue). The active
Warden line moved from Python (v1.2 / v1.3 prototypes, both
`DEPRECATED.md`-marked) to C in v1.4 onward. There is no
maintained Python `var::` surface at HEAD to add a `var::plan`
module to.

Options for the future:

1. Resurrect the Python `var::` layer outside the v1.0 archive
   as a separate, larger project — call it the "var:: language
   layer revival" — and add `var::plan` once that scaffolding
   exists.
2. Build a fresh Python surface for plan construction specifically.
3. Defer plan construction to a different surface entirely
   (the text format that v1.6.2 ships, a structured API binding,
   an agent SDK).

None of these is a small task that fits cleanly under the v1.6
line. The text format in `plan_parser` is the surface for v1.6.x;
the language-level surface decision is moved out as a separate
planning item.

### Per-edge data-flow or capability-transfer policies

Edges in v1.6 carry only ordering / data-dependency information
used by the cycle check. Policies that reason about data flow
across edges (taint propagation, capability transfer) are
tracked for v1.7+.

### Persistent plan serialization

Plans are in-memory only. The text format is the loader, not the
serializer.

### Richer plan-file format

Quoted targets, parameter fields, conditional edges, includes,
and similar elaborations are out of scope for v1.6.2. The format
shipped is the minimum needed to declare an action graph the
existing v1.4 `policy_decide()` can act on. Richer surfaces wait
until the C-API integration has run in real deployments.

## Why kernel-first, surface-later, integration-last

Three reasons:

1. **Patent substance.** The patentable element is the
   compositional evaluator over the plan graph. Hardening that
   in isolation, with a focused test suite, is the right risk
   posture for the v1.6 line.
2. **API stability.** Public surfaces commit us to compatibility
   guarantees the kernel does not require. Letting the kernel
   settle first (v1.6.0) means the adapter (v1.6.1) and the
   integration (v1.6.2) were tuned against real consumers
   rather than speculation.
3. **Blast radius.** Each step is reviewable in isolation. The
   v1.6.2 patch is 213 lines of unified diff against existing
   files; everything else lives in `v1_6/` and does not touch
   the operating Warden code unless `warden_v1_4.patch` is
   applied.

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
idempotent — fold order is observably irrelevant.

## Symmetric suppression under composition

The patent invariant — `UNSATISFIED` and `UNKNOWN` both suppress
per-Action execution — lifts directly to the plan level under the
join above. Either of those values at any node propagates to the
plan-level result.

The join preserves the **more informative** of the two for
pathology output: `UNSATISFIED` dominates `UNKNOWN`. Both block
the plan equally; `exec_plan_authorized()` returns `true` only on
`SATISFIED`.

The v1.6.1 pathology record extends this with `suppression_reason`
so operators can distinguish node-level denials (`"node"`) from
structural problems (`"cycle"`, `"empty"`, `"capacity"`,
`"edge_index"`).

## Why cycle yields UNKNOWN, not UNSATISFIED

A cyclic edge set is a structurally unverifiable input. The plan
graph contract requires acyclicity (the directed-acyclic part is
load-bearing for compositional reasoning). Returning `UNKNOWN`
rather than `UNSATISFIED` reflects what actually happened: the
verifier could not form a meaningful opinion about the action
set. Both still suppress the plan; the distinction matters for
pathology telemetry and for downstream debugging.

## Determinism and allocation

No allocation on the verification path. The cycle-detection
scratch (color array, CSR adjacency, DFS stack) lives in
thread-local arrays sized to `PLAN_MAX_NODES` and
`PLAN_MAX_EDGES`. The fold over node decisions is a single
linear pass with a short-circuit at the top of the lattice.

The v1.6.1 adapter caches per-node decisions on a stack array
sized to `PLAN_MAX_NODES` so the pathology pass can name the
first non-`SATISFIED` node without re-querying the decider. The
parser owns its string storage and frees in one pass via
`plan_parser_free()`.

Heap allocations: `exec_plan_new()`, `pathology_sink_new()`,
`plan_parser_load()` (handle + `strdup`'d tokens). All free
cleanly in their dual; tests run without leaks under ASan.

There is no recursion. The DFS uses an explicit stack to avoid
stack-overflow concerns under large plans.

## Threading model

Single-threaded by contract, matching the v1.4 Warden's
supervisor-thread invariant. The pathology sequence counter is
not atomic. The cycle-detection scratch is thread-local so
calling the evaluator from multiple supervisor threads is safe
in principle; the sink and adapter are not. If a multi-threaded
adapter call site appears later, the sink will need a mutex.

## Patched Warden behavior

The v1.6.2 patch inserts the plan-verification gate between
`policy_load()` + `log_init()` and `fork()`. The sequence becomes:

```
parse argv (now accepts optional --plan)
policy_load()
log_init()
if plan_path:
    plan_parser_load()
    warden_adapter_verify() with policy_decide-wrapping decider
    emit plan-level pathology record
    if not SATISFIED: return 1   <-- no fork, no child process
fork()
... existing v1.4 supervise path unchanged ...
```

Without `--plan`, the binary's behavior is exact-equivalent to
v1.4. With `--plan`, an unauthorized plan halts the supervisor
before the target ever starts, which is the strongest possible
realization of "pre-execution verification."

## JSON pathology format

The plan-level record format mirrors the v1.4 per-action style
(see `varek/v1_4/warden.c::emit_pathology`) with the `pp-`
prefix on `report_id`:

```json
{"report_id":"pp-<sec>.<nsec>-<seq>",
 "type":"plan_verify",
 "decision":"SATISFIED|UNSATISFIED|UNKNOWN",
 "authorized":true|false,
 "n_nodes":<size_t>,
 "n_edges":<size_t>,
 "latency_us":<uint64>,
 "suppression_reason":"none|node|cycle|empty|capacity|edge_index",
 "suppressed_node":"<label>"|null,
 "suppressed_decision":"SATISFIED|UNSATISFIED|UNKNOWN",
 "timestamp_ns":<int64>}
```

Latency is monotonic-clock microseconds across the full adapter
call (decider dispatch, plan build, verify). Timestamp is wall
clock.

## Validation

All v1.6.x unit tests pass under gcc 13.3 with
`-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
-Wmissing-prototypes` (zero warnings) and under
`-fsanitize=address,undefined` (zero diagnostics). The v1.6.2
integration smoke test (`integration_test.sh`) passes against a
freshly-built patched Warden on the same toolchain.

The patch applies cleanly via `patch -p1 < v1_6/warden_v1_4.patch`
from the repo root against the current HEAD of github.com/kwdoug63/varek.
