# VAREK v1.7 / v1.8 — cross-action data-flow verification

Pre-execution verification of how sensitive labels flow across an
agent's action graph. v1.6 decides each action's policy in
isolation (USPTO Provisional 64/062,549); v1.7 adds a second axis
that decides over the *path between actions* before any action
runs. v1.8.0 adds explicit, audited declassification so sanitize-
then-send workflows authorize without weakening the guarantee.

This is the layer that catches the leak per-action checks miss:
every action individually permitted, but the composition moves a
secret to a denying sink.

The v1.7 / v1.8 line ships in seven releases:

- **v1.7.0** — flat-set data-flow kernel (pre-release; development
  snapshot, not for deployment).
- **v1.7.1** — production posture: per-label sticky fail-safe,
  classification adapter, deterministic JSON pathology.
- **v1.7.2** — Warden integration: single-call `plan_warden_verify()`.
- **v1.7.3** — policy config file format.
- **v1.7.4** — argument-pattern matching (glob) and lineage tracing.
- **v1.8.0** — explicit, audited declassification (first non-
  monotone kernel op; security-significant minor bump).
- **v1.8.1** — documentation, tooling, demo.

## Demo

A narrated 8-scenario demo lives in `demo/`. Build and run with one
command:

```sh
cd v1_7
make demo
```

The demo exercises the real verifier against `demo_policy.cfg`:

- Scenario 1: clean plan (authorized — VAREK doesn't get in the way).
- Scenario 2: direct exfiltration (refused).
- Scenario 3: compositional exfiltration through `transform` and
  `enrich` (refused; lineage traces the secret back to its origin).
- Scenario 4: sanitize-then-send via declassification (authorized).
- Scenario 5: bypass attempt around the redactor (refused).
- Scenarios 6a/6b: argument-sensitive egress (internal authorized,
  external refused — same plan shape, different URL).
- Scenario 7: fail-safe on the unknown (`UNKNOWN`, suppresses).

The demo exits 0 only if all eight scenarios behave as documented,
so it doubles as a full-stack smoke test. Annotated walkthrough in
`demo/DEMO.md`.

## Reference Warden gate

`warden_integration_example.c` is the runnable template the
Warden's `--plan` handler follows: load a policy once at startup,
then for each submitted plan build the plan + action array, call
`plan_warden_verify()`, gate on the verdict, emit pathology on
refusal. Built and run with `make example`. Read this alongside
the README's "API at a glance" section below before integrating
into the v1.4 Warden.

## Overview

Where the v1.4 Warden returns `ALLOW` / `DENY` / `UNKNOWN` per
intercepted syscall and v1.6 returns `SATISFIED` / `UNSATISFIED` /
`UNKNOWN` over a whole ExecutionPlan node-by-node, v1.7 adds the
*flow* axis: what labels move along the plan's edges.

The plan verdict is the join over the v1.6 node-axis verdict and
the new v1.7 flow-axis verdict, under the same lattice. Symmetric
suppression composes: a non-`SATISFIED` on either axis suppresses
the plan; only `SATISFIED` on both authorizes execution.

## Layout

| File                              | Purpose                                                       |
|-----------------------------------|---------------------------------------------------------------|
| `varek_dataflow.h`                | Public umbrella header (v1.8.1).                              |
| `plan_label.h`                    | Flat-set label primitive (v1.7.0; extended for v1.8.0).       |
| `plan_label_policy.h`             | Classification surface — descriptor, callback, table policy.  |
| `plan_dataflow.h` / `.c`          | Flow kernel: propagation, sticky posture, declassification.   |
| `plan_dataflow_adapter.h` / `.c`  | `populate()` over action array; reference table policy.       |
| `plan_dataflow_pathology.h` / `.c`| Deterministic JSON refusal output + lineage.                  |
| `plan_warden_binding.h` / `.c`    | Single-call gate (v1.7.2).                                    |
| `plan_policy_config.h` / `.c`     | Text config-file loader (v1.7.3).                             |
| `v1_6_compat.h`                   | Read-only access to v1.6 internals (does NOT modify v1.6).    |
| `varek_demo.c`                    | Narrated 8-scenario demo (v1.8.1).                            |
| `demo_policy.cfg`                 | Policy file driving the demo.                                 |
| `warden_integration_example.c`    | Runnable reference Warden gate (v1.8.1).                      |
| `example_policy.cfg`              | Operator-facing config reference.                             |
| `tests/`                          | Six test binaries; cumulative 207 checks.                     |
| `demo/DEMO.md`                    | Annotated demo walkthrough (async-shareable).                 |
| `Makefile`                        | Build, run, and test targets.                                 |
| `NOTES.md`                        | Design rationale and release scope notes.                     |

## Build

```sh
cd v1_7
make            # builds demo + example + all six test binaries
make check      # runs all test binaries under -fsanitize=address,undefined
make demo       # builds and runs the narrated demo
make example    # builds and runs the reference Warden gate
```

C11, no external dependencies beyond libc. Built and tested under
gcc with `-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
-Wmissing-prototypes` with zero warnings, and clean under
`-fsanitize=address,undefined`.

The v1.7 layer links against `../v1_6/execution_plan.c` and
`../v1_6/plan_evaluator.c` directly. v1.6 source files are
unchanged.

## API at a glance

### Single-call gate (v1.7.2 — recommended entry point)

```c
#include "varek_dataflow.h"

/* Once at startup: load the policy. */
plan_label_policy_config_t *cfg;
int line; const char *msg;
if (plan_label_policy_config_load("policy.cfg", &cfg, &line, &msg) != 0) {
    log_fatal("policy %s:%d: %s", path, line, msg);
}

/* Per submission. */
char pbuf[64 * 1024];
plan_pathology_opts_t opts = plan_label_policy_config_pathology_opts(cfg);
plan_warden_request_t req = {
    .plan             = plan,        /* built by the v1.6.1 adapter */
    .actions          = actions,     /* one per node, in node-id order */
    .n_actions        = n,
    .policy           = plan_label_policy_config_policy(cfg),
    .path_opts        = &opts,
    .pathology_buf    = pbuf,
    .pathology_buf_sz = sizeof pbuf,
};
plan_warden_response_t resp;
int rc = plan_warden_verify(&req, &resp);

if (rc != 0 || !plan_warden_authorized(&resp)) {
    emit_refusal(pbuf, resp.pathology_len, &resp);
    refuse_plan();
} else {
    proceed_to_per_syscall_enforcement();   /* v1.4 Warden */
}
```

Refuse on `rc != 0` *and* on a non-`SATISFIED` verdict. Both are
plan-refusal cases; `rc != 0` is the stronger "verifier itself
failed" signal.

### Lower level (manual companion)

```c
plan_dataflow_t *df = plan_dataflow_new(plan);

/* Operator policy populates the companion. */
plan_dataflow_mark_sticky(df, L_SECRET);
plan_dataflow_add_origin(df, source_node, L_SECRET);
plan_dataflow_add_deny_in(df, egress_node, L_SECRET);
plan_dataflow_add_permit_in(df, redactor_node, L_SECRET);   /* v1.7.1 */
plan_dataflow_add_declassify(df, redactor_node, L_SECRET);  /* v1.8.0 */

plan_decision_t flow = plan_dataflow_flow_verdict(df);
plan_decision_t node = exec_plan_verify(plan);              /* v1.6 */
plan_decision_t total = plan_decision_join(node, flow);

if (total != PLAN_DEC_SATISFIED) {
    plan_pathology_opts_t opts = { .label_name = my_label_namer };
    plan_dataflow_emit_pathology(df, &opts, stderr);
}

plan_dataflow_free(df);
```

## Config grammar (v1.7.3 + v1.7.4 + v1.8.0)

```
varek_policy 1                  # optional version pragma
strict                          # optional; default non-strict

label NAME ID                   # declare a label
sticky NAME                     # plan-wide sticky

rule ACTION_NAME                # rule block; closed by next non-indent
  match KEY PATTERN             # v1.7.4 glob predicate (AND-combined)
  origin NAME
  deny_in NAME
  unknown_in NAME
  permit_in NAME
  declassify NAME               # v1.8.0
```

Labels must be declared before use. Comments (`#`) only at the
start of a line. Rules are evaluated in declaration order, first
match wins — place specific rules before catch-alls.

See `example_policy.cfg` and `demo_policy.cfg` for worked examples,
including the canonical internal-vs-external egress split via
argument matching.

## Compositional decision rule (flow axis)

| Condition on the flow axis        | Flow result   |
|-----------------------------------|---------------|
| Cycle in edge set                 | `UNKNOWN`     |
| Any node `UNSATISFIED`            | `UNSATISFIED` |
| Else any node `UNKNOWN`           | `UNKNOWN`     |
| Else (all nodes `SATISFIED`)      | `SATISFIED`   |

Plan verdict = `plan_decision_join(node_axis, flow_axis)` over the
v1.6 lattice. Only `SATISFIED` on both axes authorizes execution.

## Per-node flow decision (v1.7.1 sticky posture)

For each label on a node's inbound set, in the context of a sticky
set `S`:

| Predicate                              | Decision contribution |
|----------------------------------------|------------------------|
| `label ∈ deny_in`                      | `UNSATISFIED`          |
| `label ∈ unknown_in`                   | `UNKNOWN`              |
| `label ∈ S` AND `label ∉ permit_in`    | `UNKNOWN` (sticky)     |
| `label ∈ S` AND `label ∈ permit_in`    | `SATISFIED`            |
| `label ∉ S`                            | `SATISFIED`            |

The sticky branch is the fail-safe: any sensitive label reaching a
node the operator has not classified for it refuses. A node's
decision is the join over its inbound labels.

## Declassification (v1.8.0)

`outbound[u] = (inbound[u] \ declassify[u]) ∪ origin[u]`.

The node is policed on its full inbound *before* declassification
removes labels from outbound. Two assertions are required at a
redactor to authorize a sanitize-then-send workflow on a sticky
label: `permit_in LABEL` (the redactor may observe it) *and*
`declassify LABEL` (the redactor cleanses it). Either alone fails
closed. The `declassify` set is operator-policy only; an attacker
cannot introduce a declassifying node. Every label dropped is
recoverable via `plan_dataflow_node_declassified()`.

**Stated limitation:** VAREK confirms a designated redactor was
permitted to see a label and that the label was dropped during
propagation. It does *not* prove the redactor's code sanitizes.
Declassification is an operator trust assertion, audited but not
verified. Same posture as CaMeL and FIDES.
See `docs/security/threat-model-dataflow.md` L1.

## Pathology record format (v1.7.1 + v1.7.4 lineage)

Single-line deterministic JSON, written to a `FILE*` or a
caller-supplied buffer. NUL-terminated on success (snprintf
semantics; effective capacity is `bufsz - 1`):

```json
{
  "verdict":       "SATISFIED"|"UNSATISFIED"|"UNKNOWN",
  "node_axis":     "SATISFIED"|"UNSATISFIED"|"UNKNOWN",
  "flow_axis":     "SATISFIED"|"UNSATISFIED"|"UNKNOWN",
  "suppressions": [
    {
      "node":         <plan_node_id>,
      "node_label":   "<label>",
      "decision":     "UNSATISFIED"|"UNKNOWN",
      "offenses": [
        {
          "kind":         "deny_in"|"unknown_in"|"sticky_unclassified",
          "labels":       ["LABEL", ...],
          "sources":      [[{"from":<id>, "from_label":"<label>", "label":"LABEL"}], ...],
          "originators":  [[{"node":<id>, "node_label":"<label>", "label":"LABEL"}], ...]
        }
      ]
    }
  ]
}
```

`sources` names the immediate predecessor edges that carried the
offending label. `originators` (v1.7.4) traces the label back
through the hops to where it entered the plan. A refusal report
reads: "send_http denied SECRET; immediate source: enrich;
originated at: read_secret."

## v1.6 coupling

The v1.7 layer reads v1.6 state through `v1_6_compat.h`, a small
header that exposes two static-inline accessors over
`execution_plan_internal.h`. This is one-way read-only coupling;
v1.6 source files are unchanged. Tagged v1.6.x releases stay
byte-identical.

The two helpers:

```c
int dataflow_plan_get_edge(const exec_plan_t *plan, size_t i,
                           plan_node_id_t *from, plan_node_id_t *to);
const char *dataflow_plan_get_node_label(const exec_plan_t *plan,
                                         plan_node_id_t id);
```

Used only by `plan_dataflow.c` (propagation walks edges by index)
and `plan_dataflow_pathology.c` (refusal output names nodes by
label).

## Tests

| Binary                            | Coverage                                                                                    |
|-----------------------------------|---------------------------------------------------------------------------------------------|
| `tests/test_dataflow`             | v1.7.0 kernel: canonical exfil, fanout, suppression precedence, cycle UNKNOWN, two-axis join, determinism, empty plan. |
| `tests/test_v17_1`                | v1.7.1 sticky posture, adapter populate, pathology emission, NUL-termination, predecessor sources. |
| `tests/test_v17_2`                | v1.7.2 binding: happy path, all suppression modes, two failure modes, pathology buffer sizing. |
| `tests/test_v17_3`                | v1.7.3 config grammar: parse errors (14 enumerated), label scoping, strict mode, end-to-end through binding. |
| `tests/test_v17_4`                | v1.7.4 argument matching: glob behavior, first-match ordering, internal-vs-external split, lineage tracing across hops. |
| `tests/test_v18_0`                | v1.8.0 declassification: four safety properties (operator-only, two assertions, cannot-route-around, audited), backward compat, end-to-end through config. |

Run unit tests with `make check`. All clean under
`-fsanitize=address,undefined`. Cumulative: 207 checks across the
six binaries.

## Scope

In scope for v1.7.0:

- Flat-set label primitive.
- Cross-action data-flow kernel with topological propagation.
- Tri-state per-node flow decision.
- Two-axis join with v1.6 node verdict.

In scope for v1.7.1:

- Per-label sticky fail-safe.
- Classification surface and reference table policy.
- Populate adapter.
- Deterministic JSON refusal pathology with predecessor sources.

In scope for v1.7.2:

- Single-call Warden binding.
- Two-failure-mode contract.

In scope for v1.7.3:

- Text policy config file with line-numbered parse errors.
- 14 enumerated error paths.

In scope for v1.7.4:

- Argument-pattern matching via hand-rolled glob.
- Lineage tracing in pathology.
- Duplicate `action_name` rules permitted (first-match-wins).
- Pathology buffer NUL-terminated on success.

In scope for v1.8.0:

- Operator-designated, audited declassification.
- Non-monotone propagation step.
- Two-assertion composition with sticky.

In scope for v1.8.1:

- Public umbrella header.
- Reference Warden gate.
- Narrated 8-scenario demo (doubles as full-stack smoke test).
- Companion threat-model document at `docs/security/`.

Tracked separately, not part of this line:

- Partial-order label lattice with automatic flow-down.
- `var::` stdlib surface for in-band label declarations
  (language-frontend feature, not verifier feature).
- Implicit-flow / causality-laundering coverage (research; flat
  provenance does not capture it; CaMeL and FIDES share the gap).
- Verifying-rather-than-trusting sanitizers (open research).
- Pathology JSON surfacing of declassifications on `SATISFIED`
  verdicts (currently exposed only via audit accessor).

## License

MIT. See SPDX headers in source files.
