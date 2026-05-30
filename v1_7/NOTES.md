# VAREK v1.7 / v1.8 — design notes

## Scope: pre-execution data-flow verification across an ExecutionPlan

v1.6 lifted the per-Action policy decision to a plan-level decision
over the action graph (USPTO Provisional 64/062,549). v1.7 adds a
second axis to that decision: what *flows* along the plan's edges.
The two-axis verdict — node axis (v1.6) joined with flow axis (v1.7)
— is the join over the same `SATISFIED < UNKNOWN < UNSATISFIED`
lattice, so symmetric suppression composes across both axes
unchanged. v1.8.0 then introduces the first non-monotone operation
in the flow-axis kernel: explicit, audited declassification, which
makes sanitize-then-send workflows expressible without weakening the
guarantee.

This layer answers the cross-action exfiltration case that
per-action decisions cannot see by construction: every action is
individually permitted, but the composition moves a secret to a
denying sink. The v1.7 propagation kernel evaluates that composition
before any action executes; only a plan SATISFIED on both axes
authorizes execution.

## Release line

The v1.7 / v1.8 line breaks into seven patch / minor releases, each
strictly additive over the previous except where called out:

- **v1.7.0** — flat-set data-flow kernel. Pre-production internal
  snapshot. Deny-list posture; not for deployment.
- **v1.7.1** — production posture. Switches the kernel from deny-list
  to per-label sticky semantics (fail-safe). Adds the label-policy
  classification surface, the populate adapter, and deterministic
  JSON refusal pathology.
- **v1.7.2** — Warden integration binding. A single-call entry point
  (`plan_warden_verify`) wraps companion allocation, classification,
  two-axis verification, pathology emission, and cleanup.
- **v1.7.3** — policy config file format. Operators author policy in
  a text file at startup; the hot path remains allocation-free.
- **v1.7.4** — argument-pattern matching (glob) and lineage tracing.
  Resolves the v1.7.3 expressiveness gap (internal-vs-external
  egress). Two intentional behavior changes documented below.
- **v1.8.0** — explicit, audited declassification. First non-monotone
  kernel operation; security-significant minor bump.
- **v1.8.1** — documentation and tooling patch. No behavior change.
  Adds the public umbrella header, the narrated 8-scenario demo, and
  the reference Warden gate.

Each release was designed to ship as a separate tag. v1.7.0 ships as
a GitHub pre-release; v1.7.1 through v1.8.1 are normal releases.

## What ships in v1.7.0

1. Flat-set label primitive — `plan_label_set_t` fixed-capacity
   bitset (`PLAN_MAX_LABELS = 128`), set-union semantics, no
   allocation on the propagation path.
2. Cross-action data-flow kernel — Kahn-topological forward
   propagation, per-node disposition slots (`origin`, `deny_in`,
   `unknown_in`), tri-state node-level decision.
3. Two-axis join — `plan_decision_join` over the v1.6 node-axis
   verdict and the new flow-axis verdict, same lattice as v1.6.
4. Initial test suite — 28 checks covering canonical exfil,
   inbound-only semantics, fanout poisoning, suppression
   precedence, cycle detection, two-axis join, determinism, empty
   plan.

The v1.7.0 deny-list posture passes unclassified labels silently —
inconsistent with VAREK's fail-safe discipline and replaced in
v1.7.1. v1.7.0 is published as a pre-release for tag continuity, not
as a recommended starting point. Install v1.7.1+ directly.

## What ships in v1.7.1

1. Per-label sticky posture — `plan_dataflow_mark_sticky()` plus
   the kernel's sticky-unclassified fail-safe: a sticky label
   reaching a node with no explicit disposition yields `UNKNOWN`,
   which suppresses.
2. `plan_label_policy.h` — classification surface: action
   descriptor, policy callback contract, reference table-driven
   policy.
3. `plan_dataflow_adapter.{h,c}` — `plan_dataflow_populate()` walks
   an action array against a policy and writes label sets onto the
   data-flow companion.
4. `plan_dataflow_pathology.{h,c}` — deterministic JSON refusal
   output, immediate-predecessor sources, optional label-name
   callback for human-readable output.
5. `plan_dataflow_add_permit_in()` — explicit "this node may see
   this label" assertion, composes with sticky for legitimate
   internal carriers.
6. v1.7.1 test suite — 32 checks (cumulative 60).

Posture change is the substantive item: with no labels marked
sticky, behavior is byte-identical to v1.7.0. Production policies
should mark sensitive labels sticky to engage the fail-safe path.

## What ships in v1.7.2

1. `plan_warden_binding.{h,c}` — single-call entry point. Wraps:
   companion allocation, `plan_dataflow_populate`,
   `plan_dataflow_flow_verdict`, `exec_plan_verify` (v1.6),
   `plan_decision_join`, optional pathology emission, cleanup.
2. Two-failure-mode contract documented at the API. `rc == 0` with
   non-SATISFIED verdict = refused plan; `rc == -1` = verifier
   failure (verdict defaults to UNKNOWN). Both require refusal.
3. v1.7.2 test suite — 50 checks (cumulative 110).

The binding is the single supported entry point for the Warden's
`--plan` gate. The lower-level API (manual companion +
populate + verdict + pathology) stays public for callers with
specialized needs but is not the recommended call site.

## What ships in v1.7.3

1. `plan_policy_config.{h,c}` — line-oriented text config loader.
   Grammar: `varek_policy 1`, `strict`, `label NAME ID`,
   `sticky NAME`, `rule ACTION_NAME` blocks with
   `origin`/`deny_in`/`unknown_in`/`permit_in NAME` rule-body
   statements.
2. 14 enumerated parse errors with 1-based line numbers and static
   error-message pointers.
3. `example_policy.cfg` — canonical operator-facing reference.
4. v1.7.3 test suite — 42 checks (cumulative 152).

Load-time allocation only; the loaded `plan_label_policy_config_t`
is read-only and safe to share across threads. Free at shutdown.

## What ships in v1.7.4

1. Argument-pattern matching: `plan_action_arg_t` and
   `named_args`/`n_named_args` on the action descriptor;
   `plan_label_rule_match_t` and `matches`/`n_matches` on the rule;
   hand-rolled two-pointer glob (`*`, `?`, literals) — bounded,
   auditable, no ReDoS surface; `match KEY PATTERN` rule-body
   statement.
2. Lineage tracing — pathology suppression records gain an
   `originators` array alongside `sources`. A refusal report names
   the immediate carrier *and* the originating node, traced back
   through the hops.
3. `plan_dataflow_node_origin()` accessor for callers that need
   lineage outside the pathology emitter.
4. v1.7.4 test suite — 37 checks (cumulative 191).

### Two intentional semantic changes from v1.7.3

- **Duplicate `action_name` rules are now allowed.** v1.7.3 rejected
  them with `ERR_RULE_DUPLICATE`. v1.7.4 needs them — first-match-
  wins ordering with different `match` clauses is exactly how the
  internal-vs-external egress split is expressed. Configs that
  previously failed to load with that error now load and evaluate in
  declaration order. Order is significant; place specific rules
  before catch-alls.
- **Pathology buffer is NUL-terminated on success** (snprintf
  semantics). The returned length still excludes the NUL; effective
  capacity is `bufsz - 1`. `printf("%s", buf)` is now safe — it
  previously read past unterminated content into uninitialized
  memory. Length-based callers (including `plan_warden_verify`) are
  unaffected. A regression test asserts `n == strlen(buf)`.

## What ships in v1.8.0

The substantive item is the kernel propagation rule itself.

v1.7.x propagation was monotone: `outbound = inbound ∪ origin`.
v1.8.0 makes it `outbound = (inbound \ declassify) ∪ origin` —
labels can now disappear from the flow. A node carries a per-node
`declassify` set; the operator's policy designates which labels it
may strip. The audit set `declassified = inbound ∩ declassify`
records exactly which labels were dropped where.

This is the only mechanism in VAREK that can bypass the
read-secret-then-exfil guarantee, so the design is built around
making the escape hatch as hard to misuse as the leak it enables.
Four safety properties, each pinned by a test:

- **Operator-only.** The `declassify` set is populated by policy,
  never by the plan or agent. An attacker cannot introduce a
  declassifying node.
- **Two explicit assertions.** Declassification affects only
  outbound. The node is still policed on its full inbound, so a
  redactor of a sticky label must *also* carry `permit_in` for that
  label — otherwise it fails closed to `UNKNOWN`. Sanitize-then-
  send authorizes iff the operator declared both.
- **Cannot be routed around.** A bypass edge from the secret source
  straight to the denying sink still carries the raw label.
  Declassification cleanses only paths that pass through the
  declassifier.
- **Audited.** Every declassification is recoverable via
  `plan_dataflow_node_declassified()` — which labels, at which
  node, on every plan submission.

### Stated limitation (L1 in the threat model)

VAREK cannot *verify* that a designated redactor actually
sanitizes. Declassification is an operator trust assertion about a
node's semantics, audited but not proven. If the operator
designates a node a `SECRET` declassifier and that node does not in
fact remove the secret, VAREK authorizes the flow. This matches the
posture of CaMeL (Google DeepMind + ETH, arXiv 2503.18813) and
FIDES (Microsoft Research, arXiv 2505.23643). The control VAREK
provides is that the assertion is explicit, narrow, operator-only,
and audited — not that sanitization is mechanically guaranteed.

The minor-version bump signals to operators: review your trust
assumptions before enabling. Backward compatible — with no
declassify set, behavior is identical to v1.7.4.

v1.8.0 test suite — 16 checks (cumulative 207).

## What ships in v1.8.1

Documentation and tooling, no behavior change, test count unchanged.

1. `varek_dataflow.h` — public umbrella header. One include for the
   whole subsystem.
2. `warden_integration_example.c` (`make example`) — runnable
   reference of the Warden `--plan` gate over the full stack.
3. `varek_demo.c` + `demo_policy.cfg` + `demo/DEMO.md` (`make
   demo`) — narrated 8-scenario walkthrough. Doubles as a smoke
   test (exits 0 only if all scenarios behave as documented).
4. `docs/security/threat-model-dataflow.md` — companion to the
   existing `docs/security/threat-model.md`, scoped explicitly to
   the v1.7 / v1.8 data-flow layer.

A patch release for documentation looks unusual but is the correct
semver position: a released tag identifies a fixed, reproducible
state, and adding substantive artifacts to the tree under the
existing v1.8.0 tag would mean v1.8.0 no longer identifies one
specific state. v1.8.1 is the no-behavior-change docs/tooling
release; v1.8.0 stays immutable.

## v1.6 coupling

The v1.7 layer reads two pieces of v1.6 state that v1.6's public
API does not expose by index: edge endpoints and node labels. The
options were:

1. Patch v1.6 to add the accessors (changes the tagged v1.6.x
   releases).
2. Reach into `execution_plan_internal.h` from a v1.7-owned compat
   header (one-way read-only coupling; v1.6 unchanged).
3. Maintain a parallel v1.7 mirror of edge endpoints and labels
   (data duplication, two sources of truth).

We chose option 2. `v1_6_compat.h` exposes two static-inline
helpers, `dataflow_plan_get_edge()` and
`dataflow_plan_get_node_label()`, that read v1.6's internal layout
through `execution_plan_internal.h`. v1.6 source files are
unchanged; tagged v1.6.x releases stay byte-identical. The compat
header is internal to v1.7 — it is included only from v1.7
implementation files, never from v1.7 public headers.

## Compositional decision rule (flow axis)

For a plan with per-node flow decisions `F = {f_1, ..., f_n}`
computed by the v1.7 kernel, and the v1.6 node-axis verdict `N`:

| Condition on the flow axis        | Flow result   |
|-----------------------------------|---------------|
| Cycle in edge set                 | `UNKNOWN`     |
| Any `f_i == UNSATISFIED`          | `UNSATISFIED` |
| Else any `f_i == UNKNOWN`         | `UNKNOWN`     |
| Else (all `f_i == SATISFIED`)     | `SATISFIED`   |

The plan verdict is `plan_decision_join(N, F)` over the same
`SATISFIED < UNKNOWN < UNSATISFIED` lattice as v1.6. Symmetric
suppression composes: a non-SATISFIED on either axis suppresses;
only SATISFIED on both authorizes.

## Per-node flow decision (v1.7.1 sticky posture)

For each label `l` on a node's finalized inbound set, in the
context of a sticky set `S`:

| Predicate on the node's classification | Decision contribution |
|----------------------------------------|------------------------|
| `l ∈ deny_in`                          | `UNSATISFIED`          |
| `l ∈ unknown_in`                       | `UNKNOWN`              |
| `l ∈ S` AND `l ∉ permit_in`            | `UNKNOWN` (sticky)     |
| `l ∈ S` AND `l ∈ permit_in`            | `SATISFIED`            |
| `l ∉ S`                                | `SATISFIED`            |

The node's flow decision is the join over its inbound labels. The
sticky branch is the fail-safe: any sensitive label reaching a node
the operator has not classified for it refuses, by default.

## Propagation (v1.8.0 non-monotone form)

1. Topological order via Kahn's algorithm. A cycle yields
   `UNKNOWN`.
2. For each node `u` in topological order:
   - `inbound[u]` = union of `outbound[p]` over predecessors `p`.
   - The node is policed on its full inbound (the rule above).
     The flow verdict joins this node decision into the running
     plan flow verdict.
   - `declassified[u]` = `inbound[u] ∩ declassify[u]` (audit).
   - `outbound[u]` = `(inbound[u] \ declassify[u]) ∪ origin[u]`.

Declassification only changes outbound. The node sees the full
inbound and is policed on it. This is what makes the two-assertion
composition with sticky work: a redactor that lacks `permit_in`
for a sticky label still gets caught at its own decision step,
before the declassify step strips the label from outbound.

## Determinism and allocation

The propagation path performs no allocation. The companion struct
is sized at the maximum and allocated once per
`plan_warden_verify()` call. Fixed-capacity arrays for `inbound`,
`outbound`, `node_dec`, `declassified`, and the topo queue.

For a fixed plan, action array, and policy, the verdict and the
pathology bytes are byte-reproducible across calls and processes.
Safe to diff in CI and audit pipelines.

## Threading model

A loaded `plan_label_policy_config_t` is read-only after load and
safe to share across threads. `plan_warden_verify()` allocates its
own companion per call; concurrent calls on the same config are
safe. `plan_dataflow_emit_pathology_buf()` is reentrant
(caller-supplied buffer); the `FILE*` convenience wrapper uses a
thread-local static buffer and is thread-safe but not reentrant
within a thread.

## Capacity

Compile-time bounds, override with `-D` if larger plans are
needed:

- `PLAN_MAX_NODES`  (default 1024)
- `PLAN_MAX_EDGES`  (default 4096)
- `PLAN_MAX_LABELS` (default 128; must be a multiple of 64)

The per-call companion grows with
`PLAN_MAX_NODES * PLAN_MAX_LABELS`. Keep both no larger than the
deployment needs.

## What is NOT in the v1.7 / v1.8 line

### Partial-order label lattice

A full lattice (e.g. `PUBLIC < INTERNAL < SECRET` with automatic
flow-down) is the academic framing; declassification is the
practically useful part. Most deployments think "this data is
tagged sensitive" + "this node cleanses it," which is flat-set +
declassification. Level-ordering stays future work unless customer
deployments demand it.

### `var::` stdlib surface for in-band label declarations

A language-frontend feature, not a verifier feature. The post-
rename Python `var::` stdlib only exists in the frozen
`varek-v1.0/` directory; the active line is C. A `var::label`
surface would belong to the language layer revival, not to v1.7+.

### Implicit-flow / causality-laundering coverage

Tracking control-flow influence on top of data flow (a plan that
leaks one bit through *which* tool gets called rather than data
flowing into it) is a research problem and may not be tractable in
the fixed pre-execution DAG model. CaMeL and FIDES carry the same
gap. `docs/security/threat-model-dataflow.md` L3 states this as a
documented limitation.

### Verifying-rather-than-trusting sanitizers

VAREK confirms a designated redactor was permitted to see a label
and that the label was dropped during propagation. It does not
prove the redactor's actual code sanitizes. Open research; likely
requires per-node semantic contracts beyond structural analysis.

### Pathology JSON surfacing of declassifications on SATISFIED

Currently declassifications are exposed via
`plan_dataflow_node_declassified()` (audit accessor) but the
pathology JSON is emitted only on refusal. Surfacing
declassifications inline on `SATISFIED` verdicts is tracked.

## IP posture

The flow-axis kernel is implementation of established
information-flow control technique (Denning & Denning, 1977),
substantially overlapping with concurrent prior art — CaMeL (March
2025) and FIDES (May 2025) — which predate every provisional in
the portfolio. The only narrow candidate for surviving claim
language over that prior art is the cross-layer integration: a
single pre-execution two-axis verdict bound to kernel-boundary
syscall enforcement (Provisional 64/059,592). Whether that
combination is patentably distinct is for IP counsel; see the
counsel memo (internal). v1.7 source files do not claim coverage
of the broad concept.

## Validation

All v1.7 / v1.8 tests pass under gcc 13.3 with `-Wall -Wextra
-Wpedantic -Wshadow -Wstrict-prototypes -Wmissing-prototypes`
(zero warnings) and under `-fsanitize=address,undefined` (zero
diagnostics). 207 checks across six test binaries.

`make demo` exercises the full stack against `demo_policy.cfg`
and exits 0 only if all eight narrated scenarios behave as
documented. `make example` runs the reference Warden gate over
two demo plans (sanitize-then-send authorized; direct exfil
refused with full pathology).

## License

MIT. See SPDX headers in source files.
