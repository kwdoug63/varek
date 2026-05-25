# VAREK v1.6 — ExecutionPlan verification

Pre-execution verification of an agent's action graph as a single
compositional policy decision. Implements USPTO Provisional
64/062,549 (May 2026), covering pre-execution verification of
action graphs as compositional policy decisions.

The v1.6 line ships in three patch releases:

- **v1.6.0** — verification kernel: ExecutionPlan primitive,
  compositional evaluator, plan-level tri-state decision,
  authorization predicate.
- **v1.6.1** — Warden adapter and pathology extension: a
  declarative `plan_spec_t` is turned into per-node decisions
  via a caller-supplied callback, fed to the v1.6.0 evaluator,
  and emitted as a plan-level JSON pathology record in the
  v1.4 record style.
- **v1.6.2** — actual v1.4 Warden integration: text-format plan
  file parser, a unified-diff patch against
  `varek/v1_4/warden.c` adding a `--plan` CLI flag and a
  pre-fork plan-verification gate, and an end-to-end
  integration smoke test.

## Demo

A recorded end-to-end demo lives in `demo/`. Two ways to view it:

**Self-host the player on your own domain.** Drop `demo/index.html`
and `demo/varek_v1_6_demo.cast` into a directory on your web server
(e.g. `varek-lang.org/demo/`) and open the URL. No CLI, no
third-party service, no account.

**Play locally** with the asciinema CLI:

```sh
# Linux / macOS / WSL
pip install asciinema
asciinema play v1_6/demo/varek_v1_6_demo.cast

# Windows (native): download the Rust 3.x static binary from
# https://github.com/asciinema/asciinema/releases  (the Python
# 2.x CLI on PyPI is Unix-only)
```

The cast walks through the unit tests, the kernel and adapter
demos, and the patched Warden refusing to fork on an UNSATISFIED
plan and then layering plan-level and per-action verification on
an authorized plan. See `demo/DEMO.md` for the annotated transcript,
patent-claim mapping, and full embedding instructions (asciinema.org
badge, self-host, GIF, SVG).

## Overview

Where the v1.4 Warden returns `ALLOW` / `DENY` / `UNKNOWN` per
intercepted syscall, v1.6 returns `SATISFIED` / `UNSATISFIED` /
`UNKNOWN` over a whole ExecutionPlan — a directed acyclic graph of
Actions an agent intends to execute. Verification fires before any
node runs; only a fully `SATISFIED` plan authorizes execution.

The patent's per-action symmetric-suppression invariant lifts
compositionally to the plan layer: both `UNSATISFIED` and `UNKNOWN`
block the plan equally. The distinction is preserved in the return
value for pathology output.

## Layout

| File                          | Purpose                                                |
|-------------------------------|--------------------------------------------------------|
| `execution_plan.h`            | v1.6.0 public API.                                     |
| `execution_plan_internal.h`   | Internal layout shared with the evaluator.             |
| `execution_plan.c`            | Node and edge construction.                            |
| `plan_evaluator.c`            | Cycle detection plus compositional aggregation.        |
| `plan_spec.h`                 | v1.6.1 declarative plan input type.                    |
| `pathology.h` / `.c`          | v1.6.1 plan-level pathology sink (JSON to a FILE*).    |
| `warden_adapter.h` / `.c`     | v1.6.1 spec -> verified plan, with decider callback.   |
| `plan_parser.h` / `.c`        | v1.6.2 text-format plan file parser.                   |
| `warden_v1_4.patch`           | v1.6.2 unified diff applying integration to v1.4.      |
| `sample_plan.txt`             | v1.6.2 example plan file.                              |
| `integration_test.sh`         | v1.6.2 end-to-end smoke test for the patched Warden.   |
| `plan_demo.c`                 | v1.6.0 demo.                                           |
| `adapter_demo.c`              | v1.6.1 demo, prints pathology records to stderr.       |
| `tests/`                      | One test binary per behavior.                          |
| `Makefile`                    | Build, run, and test targets.                          |
| `NOTES.md`                    | Design rationale and release scope notes.              |

## Build

```sh
make
make check          # runs all test binaries
make demo           # v1.6.0 demo
make adapter-demo   # v1.6.1 demo, with pathology records on stderr
```

C11, no external dependencies. Built and tested with gcc 13.3 under
`-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
-Wmissing-prototypes` with zero warnings, and clean under
`-fsanitize=address,undefined`.

## API at a glance

### v1.6.0 core

```c
exec_plan_t *p = exec_plan_new();

plan_node_id_t a = exec_plan_add_node(p, "fetch", PLAN_DEC_SATISFIED);
plan_node_id_t b = exec_plan_add_node(p, "write", PLAN_DEC_SATISFIED);
exec_plan_add_edge(p, a, b);   /* b depends on a */

if (exec_plan_authorized(p)) {
    /* execute the plan */
} else {
    /* suppress; pathology already emitted by the adapter (if used) */
}
exec_plan_free(p);
```

### v1.6.1 adapter

```c
static plan_decision_t my_decider(const plan_spec_action_t *a, void *ud) {
    return my_policy_decide(a->kind, a->target, ud);
}

plan_spec_action_t actions[] = {
    { "file_open",   "/in",      NULL, "load"    },
    { "net_connect", "host:443", NULL, "publish" },
};
plan_spec_edge_t edges[] = { { 0, 1 } };
plan_spec_t spec = { actions, 2, edges, 1 };

pathology_sink_t *sink = pathology_sink_new(stderr);
plan_decision_t d = warden_adapter_verify(&spec, my_decider, NULL, sink);
pathology_sink_free(sink);
```

### v1.6.2 plan parser

```c
char err[256];
plan_parsed_t *parsed = plan_parser_load("plan.txt", err, sizeof(err));
if (!parsed) { fprintf(stderr, "%s\n", err); return 1; }
const plan_spec_t *spec = plan_parser_spec(parsed);
/* feed spec to warden_adapter_verify ... */
plan_parser_free(parsed);
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
`SATISFIED < UNKNOWN < UNSATISFIED`. Associative, commutative,
idempotent.

## Plan file format (v1.6.2)

Line-oriented text. See `sample_plan.txt` for a worked example.

```
# Comments begin with #.
action <label> <kind> <target>
edge   <from_label> <to_label>
```

- `<label>` matches `[A-Za-z_][A-Za-z0-9_-]*`, up to 63 chars,
  unique within the file.
- `<kind>` is a free-form token interpreted by the decider. The
  v1.4 Warden glue recognizes `file_open`, `net_connect`,
  `process_exec`; everything else maps to `ACT_OTHER` and is
  suppressed under symmetric-suppression semantics.
- `<target>` is a single whitespace-free token.
- Edge labels must reference action lines declared earlier in
  the file. Self-edges are rejected at parse time.
- Errors are reported as `file:line: reason`.

Capacity: 256 actions, 1024 edges per file. Plans exceeding the
plan-graph evaluator's compile-time bounds
(`PLAN_MAX_NODES`/`PLAN_MAX_EDGES`) are still bounded by these
file-format limits.

## Pathology record format

Single-line JSON, written to whatever `FILE*` the sink was opened
on. Mirrors v1.4's per-action style with the `pp-` prefix for
plan-level records:

```json
{
  "report_id":           "pp-<sec>.<nsec>-<seq>",
  "type":                "plan_verify",
  "decision":            "SATISFIED" | "UNSATISFIED" | "UNKNOWN",
  "authorized":          true | false,
  "n_nodes":             <size_t>,
  "n_edges":             <size_t>,
  "latency_us":          <uint64>,
  "suppression_reason":  "none" | "node" | "cycle" | "empty" | "capacity" | "edge_index",
  "suppressed_node":     "<label>" | null,
  "suppressed_decision": "SATISFIED" | "UNSATISFIED" | "UNKNOWN",
  "timestamp_ns":        <int64>
}
```

## Applying the v1.4 integration

From the repo root:

```sh
patch -p1 < v1_6/warden_v1_4.patch
cd varek/v1_4
make
sudo ./warden policy.txt --plan ../../v1_6/sample_plan.txt -- ./target_binary
```

The patch makes two file edits:

- `varek/v1_4/warden.c` — adds v1.6 includes, a `kind_from_string()`
  helper, a `warden_plan_decider()` wrapper around the existing
  `policy_decide()`, a `warden_verify_plan()` orchestration
  function, the `--plan <file>` CLI flag, and the pre-fork gate
  that aborts before `fork()` when the plan does not verify as
  `SATISFIED`.
- `varek/v1_4/Makefile` — adds `-I../../v1_6` and the v1.6 source
  files to the `warden` link line, plus a `run-plan-demo` target.

The patched Warden remains backwards-compatible: invoking without
`--plan` preserves exact v1.4 behavior, including no plan-level
pathology output.

End-to-end regression coverage lives in `integration_test.sh`,
which builds the patched binary, runs four cases against it, and
asserts on stderr output:

1. Denied plan does not fork the target.
2. Authorized plan emits a `SATISFIED` pathology record.
3. Omitting `--plan` preserves v1.4 behavior unchanged.
4. Malformed plan files produce `file:line: reason` errors.

Run with:

```sh
./v1_6/integration_test.sh
```

## Tests

| Binary / script                         | Coverage                                                                 |
|-----------------------------------------|--------------------------------------------------------------------------|
| `tests/test_evaluator`                  | Empty plan, single node, all-`SATISFIED`, `NULL`, invalid decision.      |
| `tests/test_symmetric_suppression`      | Single `UNSAT`, single `UNKNOWN`, mixed, all-`UNSAT`, all-`UNKNOWN`.     |
| `tests/test_order_invariance`           | 960 exhaustive permutations across three node-set shapes.                |
| `tests/test_fanout`                     | One `UNSAT` leaf poisons every position; clean fanout authorizes.        |
| `tests/test_cycle_detection`            | 2-cycle, 3-cycle, self-edge rejection, diamond, disjoint components.     |
| `tests/test_adapter`                    | Happy path, all-UNSAT, all-UNKNOWN, targeted denial, NULL spec/decider, empty spec, invalid edge, capacity overflow, bogus return coerced, userdata threading. |
| `tests/test_pathology`                  | JSON output for SAT/UNSAT/UNKNOWN/empty/edge/cycle, label escaping, sequence monotonicity. |
| `tests/test_plan_parser`                | Minimal valid, full diamond, comments+blanks, duplicate labels, undefined edge labels, self-edges, unknown directives, invalid label chars, missing target, empty plan, missing file, NULL safety. |
| `integration_test.sh`                   | Denied plan blocks fork; authorized plan proceeds; backwards compat; parse errors surface. Requires patched Warden built. |

Run unit tests with `make check`. All are also clean under
`-fsanitize=address,undefined`. Run the integration test
separately: `./integration_test.sh` from the repo root after
applying the patch.

## Scope

In scope for v1.6.0:

- ExecutionPlan construction and fixed-capacity storage.
- Structural verification (acyclicity).
- Compositional per-node decision aggregation.
- Plan-level tri-state decision.
- Authorization predicate.

In scope for v1.6.1:

- `plan_spec_t` declarative input type.
- Decider-callback adapter (`warden_adapter_verify`).
- Plan-level pathology sink with JSON-escaped labels.
- Operator-facing `suppression_reason` classification.

In scope for v1.6.2:

- Text-format plan file parser with structured error reporting.
- v1.4 Warden integration patch with `--plan` CLI flag.
- Pre-fork gate refusing target execution on non-`SATISFIED`.
- Integration smoke test.

Tracked separately, not part of this release:

- `var::` stdlib surface for plan construction. The post-rename
  Python `var::` stdlib at HEAD lives only in the frozen
  `varek-v1.0/` directory; the active line moved to C in v1.4.
  See `NOTES.md`.
- Per-edge data-flow / capability-transfer policies (v1.7+).
- Plan serialization and replay (v1.7+).
- Richer plan-file format (quoted targets, parameters,
  conditional edges) — out of scope until the C-API integration
  has run in real deployments.

## License

MIT. See SPDX headers in source files.
