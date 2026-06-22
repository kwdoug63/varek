# Changelog

All notable changes to VAREK are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] â€” v1.10 / v1.11 (planned, not shipped)

The next line is one program: **shrink the UNKNOWN region without weakening
soundness.** Every item below moves cases out of UNKNOWN into a provable
SATISFIED or UNSATISFIED, and is admitted only under a soundness obligation that
forbids it from ever turning a genuinely unsafe action into SATISFIED. Nothing in
this section is present in a released tag; it is stated as direction.

### Planned â€” v1.10

- **Verdict-distribution harness.** Measurement and regression gating over a
  corpus of realistic agent action-graphs. Reports the four-cell outcome
  (SATISFIED/UNSATISFIED/UNKNOWN against ground-truth SAFE/UNSAFE), the
  safe-action clear rate, and a hard `unsafe_satisfied == 0` gate. Ground truth
  is the customer-authored policy; adversarial near-miss labels come from an
  independent oracle, never from SAI. Built first; a measured baseline is itself
  a shippable milestone.
- **Bitvector flag/argument fragment.** Decidable QF_BV reasoning over syscall
  flag/argument bits, aligned with the Warden kernel layer (provisional
  #64/059,592). Soundness obligation: ABI-faithful width/signedness, plus a
  conservative-mask rule (bits outside the policy's mask force UNKNOWN, never a
  silent SATISFIED). Lowest audit cost; lands first to prove the loop end to end.
- **Bounded string fragment.** A deliberately restricted, length-bounded string
  fragment (prefix/suffix/contains and membership in a fixed regex set) so the
  verifier can prove path-prefix and host-allowlist predicates instead of
  refusing them. The expected headline reduction in over-refusal. Soundness
  obligation: encoding faithfulness plus a length-guard (over-length strings
  escape to UNKNOWN; never truncate-then-check). No new decision procedure â€” the
  fragment lowers into procedures already in scope.

### Candidate â€” v1.11

- **Bounded sequence fragment.** Element-level reasoning for the cross-action
  data-flow subsystem, modeling collections as a fixed `N` slots plus a length.
  Composes on top of the bounded string/bitvector fragments (a sequence element
  is one of those). Soundness obligation adds a composition lemma and a
  bounded-length guard. Sequenced after strings because it inherits the element
  fragment's guarantee.

---

## [1.9.2] - 2026-06-21

Hardening patch. No verdict-semantics changes; the v1.9 progress-safety proof is
untouched. The invariant is unchanged: no extension may move a genuinely unsafe
action to SATISFIED.

### Security

- **Default-deny allowlist.** The Warden baseline is inverted from
  allow-plus-denylist to default-deny allowlist: only an explicit allowlist is
  admitted, so unknown and variant syscalls (`clone3`, `openat2`, `faccessat2`,
  `pidfd_*`) and 32-bit multiplexers (`socketcall`, `ipc`) are denied by
  construction. New: `v1_7/warden_seccomp_baseline.{c,h}`,
  `v1_7/tests/test_v192_baseline_deny.c`.
- **Native-ABI lockdown.** The deny default applies across all architectures and
  no secondary ABI is admitted, so the 32-bit compat (`int 0x80`) and x32
  (`__X32_SYSCALL_BIT`) paths are denied. Asserted on the live kernel by
  `v1_7/tests/test_v192_abi_lockdown.c` (release-blocking).
- **Unprivileged-user-namespace denial.** `clone`/`unshare` are filtered on the
  scalar flags argument to deny `CLONE_NEWUSER` and the namespace set; `clone3`,
  `setns` hard-denied.
- **Hard-deny set** (`SCMP_ACT_KILL_PROCESS` in strict mode) for `ptrace`,
  `bpf`, `userfaultfd`, `process_vm_readv/writev`, `pidfd_getfd`, the mount/FUSE
  family, the module/`kexec`/`perf_event_open`/`keyctl` family, and
  `memfd_create` â€” mapping to bypass classes 3â€“6. io_uring denial (v1.9.1) is
  retained inside this set.
- **Supervisor/target lifecycle coupling.** Target SIGKILLed on supervisor death
  (`PR_SET_PDEATHSIG` + re-parent re-check + cgroup.kill fallback); supervisor
  watches target via pidfd; injected fds carry `O_CLOEXEC`; in-flight
  notifications bounded (excess fails closed, trips the v1.8.2 breaker). New:
  `v1_7/warden_lifecycle.{c,h}`.

### Added

- `docs/security/bypass-classes.md` â€” bypass-class checklist and
  mediation-completeness argument.
- `docs/security/v1.9.2-baseline-allowlist.md` â€” allowlist rationale and
  class-to-syscall map.
- `docs/security/v1.10-architecture-roadmap.md` â€” model/TCB-changing track
  (Landlock, acquisition tiering, post-grant re-mediation, UNKNOWN escalation
  ladder, TCB shrink via proof-checking).
- `v1_7/warden_landlock.c` â€” v1.10 skeleton (not wired into v1.9.2).

### Changed

- The io_uring denial is now an entry in the default-deny allowlist's hard-deny
  set rather than a standalone denylist rule.

---

## [1.9.1] - 2026-06-20

Hardening and disclosure patch. No verdict-semantics changes; the v1.9
progress-safety proof is untouched. The invariant is unchanged: no extension may
move a genuinely unsafe action to SATISFIED.

### Security

- **io_uring bypass closed.** The Warden baseline policy now denies the io_uring
  submission interface (`io_uring_setup`, `io_uring_enter`, `io_uring_register`)
  with `EPERM`. io_uring dispatches operations off the syscall entry path, where
  seccomp â€” and therefore the Warden's user-notification mediation â€” cannot
  observe them; denying instance creation is the only sound mitigation at this
  layer. New: `v1_7/warden_seccomp_baseline.c`,
  `v1_7/tests/test_v191_io_uring.c`.
- **seccomp user-notification TOCTOU discipline.** Hardened the supervisor
  against time-of-check-to-time-of-use on pointer arguments:
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE` is no longer used to authorize any syscall
  whose decision depended on user-pointer contents; pointer-argument operations
  are performed by the supervisor on validated, copied arguments and the result
  is injected via `SECCOMP_IOCTL_NOTIF_ADDFD`; every notification is revalidated
  with `SECCOMP_IOCTL_NOTIF_ID_VALID` before the supervisor acts. New:
  `v1_7/warden_notify_hardening.{h,c}`.

### Added

- **UNKNOWN-reason diagnostics.** UNKNOWN verdicts now carry the undischarged
  predicate and the fragment that would resolve it. Additive; SATISFIED and
  UNSATISFIED are unchanged and soundness is unaffected.
  Spec: `docs/security/v1.9.1-verifier-notes.md`.
- **Deterministic resource bounds** on the decision procedure (max step / time
  ceilings, obligation memoization). A bound hit yields UNKNOWN (fail closed),
  never a coerced pass.
- `docs/security/threat-model.md`, `docs/security/TRUSTED-COMPUTING-BASE.md`.

### Changed

- Documented the per-component trusted-vs-verified status of the verification
  chain and the plan to shrink the trusted base (see TRUSTED-COMPUTING-BASE.md).

---

## [1.9.0] - 2026-05-30

### Added

- `v1_7/plan_progress.h`, `v1_7/plan_progress.c`: **Progress-safety
  verification.** A load-time liveness proof that turns human-out-of-the-loop
  (HOOTL) from a configuration choice into a property the verifier certifies per
  policy. v1.6â€“v1.8 prove safety (nothing unauthorized executes); v1.9 adds the
  complementary proof that the system always has a legal, automated next move, so
  "never requires a human" is certified rather than hoped.
- `v1_7/INTEGRATION-hotl.md`, `v1_7/warden_hotl_example.c`: integration guide and
  runnable reference for using the progress verifier as an unattended-startup
  gate.
- `v1_7/demo_hootl.c`: HOOTL demonstration.
- `v1_7/tests/test_v19_progress.c`: 10/10, clean under
  `-fsanitize=address,undefined`.

### The theorem certified

For every non-authorizing verdict (UNSATISFIED or UNKNOWN) the policy can
produce, the v1.8.2 breaker's deterministic resolution reaches an automated
terminal outcome in finitely many steps, with no point requiring human
intervention. Decomposed into four obligations: P1 bounded refusal, P2 disposed
UNKNOWN, P3 disposed exhaustion, P4 authorized fallback (the reachability proof,
discharged by composing the underlying decision procedure as its authorization
oracle).

### Result shape

Three-state, matching VAREK semantics: `SATISFIED` (certified progress-safe /
HOOTL), `UNSATISFIED` (a concrete gap, with the failing obligation named),
`UNKNOWN` (could not decide â€” fail closed, treated as not certified).

### Operational use

Call `plan_progress_verify()` at policy load and refuse to start unattended
unless it certifies. If no automated terminal is guaranteed, the system never
reaches run time.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check

---

## [1.8.2] - 2026-05-30

Point release. Adds a non-bypassable loop bound to the enforcement layer without
touching the decision procedure.

### Added

- `v1_7/plan_breaker.h`, `v1_7/plan_breaker.c`: **Bounded-refusal breaker.** The
  decision procedure answers "may this submission run?" purely and statelessly; a
  refused plan returns UNSATISFIED and what the agent does next is the host's
  business. Left unbounded, a stuck or adversarial planner can resubmit the same
  refused action-graph forever â€” a self-inflicted denial of service, and in an
  unattended deployment a hang only a human could break. The breaker closes that
  loop in the trusted boundary, keyed by `(session, action-signature)`, so the
  bound cannot be defeated by buggy or compromised harness code. Each individual
  verdict stays a pure function of `(plan, policy)`; the breaker only interprets
  the *sequence* of verdicts for one signature.
- `v1_7/tests/test_v18_2_breaker.c`: 19/19, clean under
  `-fsanitize=address,undefined`.

### Changed

- `v1_7/plan_policy_config.h`, `v1_7/plan_policy_config.c`: three optional
  top-level policy directives plus accessors. Fully backward compatible â€” a policy
  declaring none of them behaves exactly as pre-v1.8.2, and the v1.8.0
  declassification suite passes unchanged (16/0).

### Policy grammar additions

    refusal_budget N                 # N >= 1; absent => breaker disabled
    on_exhaustion deny               # default when absent
    on_exhaustion terminal NAME      # fire a pre-authorized safe action
    unknown_disposition deny         # default when absent
    unknown_disposition terminal NAME

### Semantics

- `SATISFIED` clears the signature's counter and latch (authorization always wins;
  a now-authorized action is never blocked by past refusals).
- `UNSATISFIED` increments. Below budget: retryable refusal (host may re-plan).
  At/over budget: fire `on_exhaustion`, latch.
- `UNKNOWN` routes immediately to `unknown_disposition` and latches â€” never
  retried, because re-running the same input reproduces UNKNOWN.
- A latched signature replays its terminal outcome idempotently. With the breaker
  disabled, UNSATISFIED is always retryable and never latches (pre-v1.8.2
  pass-through). Memory pressure interning a new entry fails closed to the
  exhaustion disposition.

### Boundaries

The decision procedure is untouched; the counter is enforcement state, not
decision state. The breaker never authors a corrected action â€” re-planning and
executing a named safe action remain the host's job.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check

---

## [1.8.1] - 2026-05-30

### Added

- `v1_7/varek_dataflow.h`: Public umbrella header. One include for the whole v1.7/v1.8 surface (plan, label, policy, dataflow kernel, adapter, pathology, binding, config).
- `v1_7/warden_integration_example.c` (`make example`): Runnable reference of the Warden's `--plan` gate over the full stack. Demonstrates sanitize-then-send authorizing and direct exfiltration refused with full pathology.
- `v1_7/varek_demo.c`, `v1_7/demo_policy.cfg`, `v1_7/demo/DEMO.md` (`make demo`): Narrated 8-scenario walkthrough exercising the real verifier against `demo_policy.cfg`. Exits 0 only if all scenarios behave as documented, so doubles as a full-stack smoke test.
- `docs/security/threat-model-dataflow.md`: Companion to `docs/security/threat-model.md`, scoped explicitly to the v1.7/v1.8 cross-action data-flow layer. Trust boundaries, security properties (each pinned to a test), eight stated limitations, recommended external-audit scope.

### Notes

- No behavior change, no API change. The v1.8.0 kernel, adapter, binding, pathology, and config source files are byte-identical. v1.8.1 turns the v1.8.0 tree into something a customer can adopt and a reviewer can sign off on.
- Why a patch release for documentation: a released tag should identify a fixed, reproducible state. Adding substantive artifacts under the existing v1.8.0 tag would mean v1.8.0 no longer identifies one specific state. v1.8.1 is the correct semver position; v1.8.0 stays immutable.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    make demo

### Verify

    git verify-tag v1.8.1

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.8.1

---

## [1.8.0] - 2026-05-30

### Added

- `v1_7/plan_dataflow.h`, `v1_7/plan_dataflow.c`: Operator-designated, audited declassification. `plan_dataflow_add_declassify()` populates a per-node declassify set; `plan_dataflow_node_declassified()` exposes the audit set (`inbound âˆ© declassify`) recoverable after verification.
- `v1_7/plan_label_policy.h`: `declassify` slot on `plan_label_class_t`.
- `v1_7/plan_policy_config.c`: `declassify NAME` rule-body statement.
- `v1_7/plan_label.h`: `plan_label_set_minus_into()` and `plan_label_set_intersect_into()` set primitives.
- `v1_7/tests/test_v18_0.c`: v1.8.0 safety properties (16 checks).

### Changed

- **Kernel propagation rule.** v1.7.x: `outbound = inbound âˆª origin` (monotone â€” labels only accumulate). v1.8.0: `outbound = (inbound \ declassify) âˆª origin`. Labels can now disappear from the flow. Backward compatible: with no labels declassified, behavior is byte-identical to v1.7.4.

### Security

This is the only mechanism in VAREK that can bypass the read-secret-then-exfiltrate guarantee. Four safety properties are pinned by tests:

1. **Operator-only.** The `declassify` set is populated by the policy, never by the plan or agent. An attacker cannot introduce a declassifying node.
2. **Two explicit assertions.** Declassification affects only outbound. A node is still policed on its full inbound, so a redactor of a sticky label must also carry `permit_in` for that label, or it fails closed to `UNKNOWN`. Both assertions are required to authorize a sanitize-then-send flow.
3. **Cannot be routed around.** A bypass edge from the secret's source straight to the denying sink still carries the raw label and is refused.
4. **Audited.** Every label dropped is recoverable via `plan_dataflow_node_declassified()` â€” which sensitive labels, at which node, on every plan submission.

**Stated limitation.** VAREK confirms a designated redactor was permitted to see a label and that the label was dropped during propagation. It does not prove the redactor's code sanitizes. Declassification is an operator trust assertion, audited but not verified. Same posture as CaMeL (Google DeepMind + ETH, arXiv 2503.18813) and FIDES (Microsoft Research, arXiv 2505.23643). See `docs/security/threat-model-dataflow.md` L1.

The minor-version bump signals operators to review their trust assumptions before enabling declassification. Polish releases should not carry that signal; this one should.

### Patent

- This is implementation of established information-flow control technique (Denning & Denning, 1977), substantially overlapping with concurrent prior art (CaMeL, FIDES). No claim of novelty on the data-flow verifier itself; the only narrow candidate for surviving claim language is the cross-layer integration of plan-level data-flow verification with kernel-boundary syscall enforcement (Provisional 64/059,592). Counsel evaluation is the operative path; no claim coverage is asserted in source.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check          # 207 checks across six test binaries

### Verify

    git verify-tag v1.8.0

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.8.0
- Discussion: https://github.com/kwdoug63/varek/discussions  (v1.8.0 â€” declassification: design, safety properties, and your review questions)

---

## [1.7.4] - 2026-05-30

### Added

- `v1_7/plan_label_policy.h`: `plan_action_arg_t` and `named_args`/`n_named_args` on the action descriptor; `plan_label_rule_match_t` and `matches`/`n_matches` on the rule.
- `v1_7/plan_dataflow_adapter.c`: Hand-rolled two-pointer `glob_match` (`*`, `?`, literals). Bounded, auditable, no ReDoS surface. Regex was deliberately not chosen for a security-policy matcher.
- `v1_7/plan_policy_config.c`: `match KEY PATTERN` rule-body statement.
- `v1_7/plan_dataflow_pathology.c`: `originators` array on suppression records. Traces an offending label back through the hops to where it entered the plan (the node whose `origin` set contains it).
- `v1_7/plan_dataflow.c`, `v1_7/plan_dataflow.h`: `plan_dataflow_node_origin()` read accessor for callers that need lineage outside the pathology emitter.
- `v1_7/tests/test_v17_4.c`: Argument matching + lineage tests (37 checks).

### Changed

- **Duplicate `action_name` rules now permitted (intentional behavior change).** v1.7.3 rejected them with `ERR_RULE_DUPLICATE`. v1.7.4 evaluates them in declaration order â€” first match wins. This is how the canonical internal-vs-external egress split is expressed: `rule send_http` with `match url *internal*` and `permit_in SECRET`, then a catch-all `rule send_http` with `deny_in SECRET`. Place specific rules before catch-alls. Configs that previously failed to load with the duplicate-rule error will now load and evaluate.
- **Pathology buffer NUL-terminated on success (snprintf semantics).** Previously the buffer was not NUL-terminated and a caller doing `printf("%s", buf)` read past the content into uninitialized memory. Returned length still excludes the NUL; effective capacity is `bufsz - 1`. Length-based callers (including `plan_warden_verify`) are unaffected. A regression test asserts `n == strlen(buf)`.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    ./tests/test_v17_4

### Verify

    git verify-tag v1.7.4

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.7.4

---

## [1.7.3] - 2026-05-30

### Added

- `v1_7/plan_policy_config.c`, `v1_7/plan_policy_config.h`: Line-oriented text policy config loader. Grammar: `varek_policy 1`, `strict`, `label NAME ID`, `sticky NAME`, `rule ACTION_NAME` blocks with `origin`/`deny_in`/`unknown_in`/`permit_in NAME` rule-body statements. Comments only at the start of a line.
- `v1_7/example_policy.cfg`: Canonical operator-facing reference.
- `v1_7/tests/test_v17_3.c`: Config grammar tests, 14 enumerated parse errors with 1-based line numbers and static error-message pointers (42 checks).

### Notes

- Load once at Warden startup; the loaded `plan_label_policy_config_t` is read-only after load and safe to share across threads. Free at shutdown. Allocation happens at load, never on the per-plan verification path.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    ./tests/test_v17_3

### Verify

    git verify-tag v1.7.3

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.7.3

---

## [1.7.2] - 2026-05-30

### Added

- `v1_7/plan_warden_binding.c`, `v1_7/plan_warden_binding.h`: `plan_warden_verify(req, resp)` â€” single-call entry point that wraps companion allocation, classification, two-axis verification, pathology emission, and cleanup. Companion lifetime is entirely inside the call. This is the supported entry point for the v1.4 Warden's `--plan` gate.
- `v1_7/plan_dataflow.h`: `plan_decision_join()` publicized; the lattice join is used in three places and the rank table is no longer duplicated.
- `v1_7/tests/test_v17_2.c`: Binding tests (50 checks).

### Notes

- Two-failure-mode contract documented at the API. `rc == 0` with non-`SATISFIED` verdict means refused plan (pathology in the buffer). `rc == -1` means verifier failure itself (verdict defaults to `UNKNOWN`). Both require refusal; `-1` is the stronger "something is wrong with the verifier" signal.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    ./tests/test_v17_2

### Verify

    git verify-tag v1.7.2

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.7.2

---

## [1.7.1] - 2026-05-30

### Added

- `v1_7/plan_dataflow.c`, `v1_7/plan_dataflow.h`: Per-label sticky model. `plan_dataflow_mark_sticky()` marks a label sticky; the kernel's sticky-unclassified path returns `UNKNOWN` (which suppresses) for any sticky label reaching a node without an explicit disposition. `plan_dataflow_add_permit_in()` is the explicit "this node may see this label" assertion that turns sticky off at a trusted carrier.
- `v1_7/plan_label_policy.h`: Classification surface â€” `plan_action_desc_t`, `plan_label_class_t`, policy-callback contract, reference table-driven policy.
- `v1_7/plan_dataflow_adapter.c`, `v1_7/plan_dataflow_adapter.h`: `plan_dataflow_populate()` walks an action array against a policy and writes label sets onto the data-flow companion.
- `v1_7/plan_dataflow_pathology.c`, `v1_7/plan_dataflow_pathology.h`: Deterministic JSON refusal output. Names the offending node, the kind of offense (`deny_in` / `unknown_in` / `sticky_unclassified`), the labels involved, and the immediate predecessor edges that carried each offending label.
- `v1_7/tests/test_v17_1.c`: Sticky posture, adapter populate, pathology emission tests (32 checks; cumulative 60).

### Changed

- **Kernel posture: deny-list â†’ per-label sticky (fail-safe).** With no labels marked sticky, behavior is byte-identical to v1.7.0. Production policies should mark sensitive labels sticky to engage the fail-safe path; the v1.7.0 deny-list default of passing unclassified labels silently is inconsistent with VAREK's discipline elsewhere.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    ./tests/test_v17_1

### Verify

    git verify-tag v1.7.1

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.7.1

---

## [1.7.0] - 2026-05-30

### Added

- `v1_7/plan_label.h`: Flat-set label primitive. Fixed-capacity bitset (`PLAN_MAX_LABELS = 128`), set-union semantics, allocation-free.
- `v1_7/plan_dataflow.c`, `v1_7/plan_dataflow.h`: Cross-action data-flow kernel. Kahn-topological forward propagation, per-node disposition slots (`origin`, `deny_in`, `unknown_in`), tri-state node-level flow decision.
- `v1_7/plan_dataflow.h`: `plan_decision_join()` â€” the lattice join over the v1.6 node-axis verdict and the new v1.7 flow-axis verdict. Same `SATISFIED < UNKNOWN < UNSATISFIED` lattice as v1.6, so symmetric suppression composes across both axes.
- `v1_7/v1_6_compat.h`: Read-only access to v1.6 internals via `execution_plan_internal.h`. Two static-inline helpers (`dataflow_plan_get_edge`, `dataflow_plan_get_node_label`) used by propagation and pathology. v1.6 source files are unchanged; tagged v1.6.x releases stay byte-identical.
- `v1_7/tests/test_dataflow.c`: Kernel tests covering canonical exfil, fanout poisoning, suppression precedence, cycle UNKNOWN, two-axis join, determinism, empty plan (28 checks).

### Notes

- **Pre-release / development snapshot.** v1.7.0 ships with a deny-list posture: unclassified inbound labels are SATISFIED by default. That posture is inconsistent with VAREK's fail-safe discipline elsewhere and is replaced in v1.7.1 with per-label sticky semantics. **Install v1.7.1+ instead.** v1.7.0 is published as a pre-release for tag continuity, not as a recommended starting point.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    ./tests/test_dataflow

### Verify

    git verify-tag v1.7.0

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.7.0 (pre-release)

---

## [1.6.2] - 2026-05-24

### Added

- `v1_6/plan_parser.c`, `v1_6/plan_parser.h`: Text plan-file format parser. Reads `action` and `edge` directives into an owning parsed-plan handle; reports errors with `file:line` precision.
- `v1_6/sample_plan.txt`: Example plan file demonstrating the format.
- `v1_6/warden_v1_4.patch`: Unified diff against `varek/v1_4/warden.c` and its Makefile. Adds a `--plan` CLI flag and a pre-fork plan-verification gate to the v1.4 Warden. On any non-`SATISFIED` plan the supervisor refuses to fork the target; behavior without `--plan` is preserved bit-for-bit.
- `v1_6/integration_test.sh`: End-to-end integration smoke test. Four cases: denied plan blocks the fork, authorized plan emits a `SATISFIED` record, absent `--plan` preserves v1.4 behavior, malformed plan surfaces a `file:line` parse error.
- `v1_6/demo/`: Recorded asciinema cast of the end-to-end demo, a reproducible cast generator (`make_cast.py`), a drop-on-server HTML player page (`index.html`), and an annotated transcript (`DEMO.md`).
- `v1_6/tests/test_plan_parser.c`: Parser unit tests.

### Changed

- `varek/v1_4/warden.c`, `varek/v1_4/Makefile` (on applying `warden_v1_4.patch`): `--plan <file>` flag verifies the declared action graph before `fork()`. Plan-level pathology records are emitted with a `pp-` prefix; the existing per-action records keep their `pr-` prefix, so both coexist in a single stderr stream and are filterable by prefix.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_6
    make check
    git apply warden_v1_4.patch        # from repo root: git apply v1_6/warden_v1_4.patch
    make -C ../varek/v1_4 warden
    ./integration_test.sh

### Verify

    git verify-tag v1.6.2

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.6.2

---

## [1.6.1] - 2026-05-24

### Added

- `v1_6/plan_spec.h`: Declarative plan-input type. Carries action kind, target, parameters, and edges; stable across per-action deciders.
- `v1_6/warden_adapter.c`, `v1_6/warden_adapter.h`: Callback-driven plan builder. `warden_build_and_verify()` takes a `plan_spec_t` and a `plan_decide_fn` callback, constructs an `exec_plan_t`, runs the v1.6.0 evaluator, optionally emits a pathology record, and returns the plan-level decision.
- `v1_6/pathology.c`, `v1_6/pathology.h`: JSON pathology record emission matching the v1.4 Warden's record style. Plan-level records use a `pp-` prefix. Suppression-reason classifier: `none`, `node`, `cycle`, `empty`, `capacity`, `edge_index`.
- `v1_6/adapter_demo.c`: Adapter demo with permissive and denying decider scenarios.
- `v1_6/tests/test_adapter.c`, `v1_6/tests/test_pathology.c`: Adapter dispatch and pathology-format unit tests.

### Notes

- The adapter is callback-driven by design: the v1.6.0 kernel stays independent of any specific per-action policy implementation. A thin shim wrapping the v1.4 `policy_decide()` lands in v1.6.2, not here.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_6
    make check
    make adapter-demo

### Verify

    git verify-tag v1.6.1

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.6.1

---

## [1.6.0] - 2026-05-24

### Added

- `v1_6/execution_plan.c`, `v1_6/execution_plan.h`, `v1_6/execution_plan_internal.h`: ExecutionPlan primitive. Fixed-capacity directed acyclic graph of Actions (1024 nodes, 4096 edges); no dynamic allocation past the plan struct.
- `v1_6/plan_evaluator.c`: Compositional evaluator. Iterative-DFS cycle detection plus per-node decision aggregation under the join over the lattice `SATISFIED < UNKNOWN < UNSATISFIED`. Three-state return with symmetric suppression preserved on both `UNSATISFIED` and `UNKNOWN` from the v1.4 per-action layer.
- `v1_6/plan_demo.c`: Kernel demo binary.
- `v1_6/tests/`: Five test binaries â€” evaluator basics, symmetric suppression, exhaustive order-invariance (960 permutations across three node-set shapes), fanout poisoning at every position, and cycle detection.
- `v1_6/README.md`, `v1_6/NOTES.md`: Documentation and design rationale.

### Patent

- Implements USPTO Provisional 64/062,549 (filed 2026-05-11): pre-execution verification of action graphs as compositional policy decisions. Lifts the per-Action decision of the v1.4 Warden to a plan-level decision over the whole action graph, evaluated before any node executes.

### Performance

- Verification is a single linear fold with a short-circuit at the top of the lattice, plus one DFS pass for cycle detection. No allocation on the verification path; cycle-detection scratch is in fixed-size thread-local arrays.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_6
    make check

### Verify

    git verify-tag v1.6.0

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.6.0

## [1.5.0] - 2026-05-12

### Added

- `v1_5/fast_match.c`: Fast-path policy matcher using sorted prefix arrays with binary-search lookup. Three-state `ALLOW` / `DENY` / `UNKNOWN` decision procedure with symmetric suppression preserved from v1.4.
- `v1_5/smt_probe.c`, `v1_5/smt_probe2.c`: SMT decision-procedure feasibility benchmarks (fresh-context and context-reuse access patterns). Retained for richer policies â€” regex, integer ranges, multi-rule conjunctions â€” that the prefix matcher cannot express.
- `v1_5/bench_summarize.py`: Nanosecond-precision summarizer. Backward-compatible with v1.4 pathology logs.
- `v1_5/NOTES.md`: Design notes documenting the hybrid prefix-DFA + SMT architecture decision.
- `v1_5/bench_results_v1_5.txt`: Provenance record (host, kernel, CPU, memory) from the measured benchmark run.

### Performance

- `fast_match`: P50 = 93 ns, P99 = 271 ns, P99.9 = 526 ns across 10,000 decisions on DigitalOcean 1 vCPU / 512 MB. Two orders of magnitude (210x) faster than the v1.4 Warden's 57 Âµs P99 â€” policy-decision time is not the bottleneck in seccomp-unotify enforcement.
- SMT context-reuse probe: P50 = 465 Âµs, P99 = 51,959 Âµs (bimodal distribution). Disqualified from hot-path use; retained for the slow-path role on richer policies.
- Zero false negatives. Full `UNKNOWN` â†’ `DENY` suppression across the benchmark.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_5
    sudo apt install -y libz3-dev
    make
    ./fast_match 10000 ../v1_4/policy.txt 2> bench_fast.log
    python3 bench_summarize.py bench_fast.log

### Verify

    git verify-tag v1.5.0

### Links
- Pull request: [#11](https://github.com/kwdoug63/varek/pull/11)
- Design notes: [`v1_5/NOTES.md`](https://github.com/kwdoug63/varek/blob/v1.5.0/v1_5/NOTES.md)
- Provenance: [`v1_5/bench_results_v1_5.txt`](https://github.com/kwdoug63/varek/blob/v1.5.0/v1_5/bench_results_v1_5.txt)

---

## [1.4.0] - 2026-05-10

### Added

- `v1_4/warden.c`: Production seccomp-unotify Warden in C. Privileged parent process intercepting syscalls, performing cross-process `/proc/<pid>/mem` extraction, and injecting kernel verdicts.
- `v1_4/policy.txt`: Declarative policy file with `allow` / `deny` verbs across `path`, `host`, and `exec` rule kinds.
- `v1_4/bench_target.c`, `v1_4/target_demo.c`: Benchmark targets for end-to-end pipeline measurement.
- `v1_4/bench_summarize.py`: JSON pathology summarizer producing latency percentile reports.
- `v1_4/Makefile`: Build system for the Warden and its targets.
- `v1_4/README.md`, `v1_4/RFC_ISSUE.md`: Reference documentation.

### Changed

- Warden migrated from Python (`waren.py`) to C for seccomp-unotify call performance.
- Policy evaluation hosted in the supervisor process with cross-process memory extraction at the syscall trap boundary.

### Performance

- End-to-end Warden pipeline (seccomp-unotify + `/proc/<pid>/mem` + kernel injection): P99 = 57 Âµs measured.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_4
    make
    ./warden ./bench_target 10000 2> bench.log
    python3 bench_summarize.py bench.log

### Verify

    git verify-tag v1.4.0

### Links
- Pull request: [#10](https://github.com/kwdoug63/varek/pull/10)
- Design RFC: [`docs/RFC_seccomp_unotify_design.md`](https://github.com/kwdoug63/varek/blob/v1.4.0/docs/RFC_seccomp_unotify_design.md)



## [1.3.0] - 2026-05-08

### Added

- `v1_3/`: Architecture scaffolding for the supervisor-based defense layer.
- High-speed visual benchmark script for measured rule evaluation.
- `RFC_TEMPLATE.md` and `VAREK_v1.2_RFC.md`: RFC infrastructure documenting fail-closed semantics and linear rule evaluation.
- `CONTRIBUTING.md` and Contributor License Agreement (CLA) details.
- `seccomp_toctou_harness.c`: TOCTOU harness for seccomp-unotify exploration.

### Changed

- Refactored VAREK defense layer and Ant Colony Optimization agent simulation.
- DARPA I2O whitepaper revised for v1.1 and v1.3 architectures.
- License unified to MIT across all source files (resolved earlier Apache 2.0 / MIT inconsistency).
- README consolidated (removed README2 / README3 iterations).

---

## [1.2.1] - 2026-05-03
### Added
- `waren.py`: Supervisor parent process to enforce out-of-band policy evaluation.
- `seccomp_bridge.py`: Kernel translation layer handling simulated OS traps and system call verdicts (`ALLOW` / `DENY`).
- "Warden/Agent" boundary architecture, strictly separating the AI execution space from the policy decision engine.

### Changed
- Moved evaluation logic out of the single-process agent simulator to prove true hard-enforcement capabilities.
- Audit logs are now securely written by the parent process, guaranteeing immutability from child process tampering.

## [1.2.0] - 2026-04-28
### Added
- Official VAREK v1.2 RFC publication detailing fail-closed semantics and linear rule evaluation.
- `evaluator.py`: Core policy decision engine with sub-millisecond execution times.
- `policy.py`: YAML loader for parsing human/AI-readable policy definitions.
- `decision_log.py`: Deterministic audit logging system for system call transitions.
- Simulator agent (`agent.py`) to test standard API access, exfiltration attempts, and fail-closed safety pathways.

---

## [1.1.1] â€” 2026-04-24

### Added

- `varek_warden.py` â€” real implementation of the orchestration layer advertised in v1.1. Exposes `configure_backend()`, `execute_untrusted()`, and `subscribe_telemetry()` as callable module-level entry points over the sandbox primitives.
- `varek_guardrails/` package â€” public re-export surface. Existing intercept files and external code can now `pip install -e .` and `from varek_guardrails import ...` without resolving loose top-level modules by `sys.path` manipulation.
- `pyproject.toml` â€” PEP 621 package metadata. `pytest` is now an optional dev dependency; production installs no longer require it.

### Fixed

- `configure_backend()` now fails closed when `IsolationBackend.is_available()` returns a non-None unavailability reason string. The prior draft had the check inverted, which would have silently accepted unavailable backends â€” a fail-open bug in a security primitive.

### Moved

- Smoke tests previously resident in `varek_warden.py` relocated to `tests/security/test_warden_smoke.py`.

---

## [1.1.0] â€” 2026-04-20

### Security

**Resolves a subprocess-escape weakness in the v1.0 containment design** reported by @dengluozhang in issue #223. The v1.0 architecture used a PEP 578 audit hook to deny `subprocess.Popen`, `os.exec*`, and related events by matching against a string-based signature list. Review demonstrated two flaws:

1. `sys.addaudithook` installs a callback in the current interpreter only. Child processes spawned via `subprocess.run` execute in a fresh interpreter or a non-Python binary that never inherits the hook. Parent-side audit callbacks cannot observe syscalls in the child. The reporter's proof-of-concept exploited this directly â€” the malicious payload executed in the child process while the parent hook saw nothing.
2. String-signature denylists on command arguments (`nc -e`, `nmap`, known C2 hostnames) were trivially bypassable via absolute paths (`/bin/nc`), base64-encoded commands, renamed binaries, or any attacker tooling not enumerated in the list.

**Fix:** enforcement moved out of the interpreter and into the kernel. The new reference backend combines seccomp-bpf, cgroups v2, and user/mount/network/IPC/UTS/PID namespaces, loaded under `PR_SET_NO_NEW_PRIVS`. The filter is installed before untrusted code runs, inherited across every `fork` and `clone`, and cannot be dropped by any descendant. `execve` is denied by default, which structurally prevents the subprocess-escape class of bypass regardless of argv content.

Severity: **High**. Users running v1.0 with untrusted code should upgrade.

### Added

- `sandbox.py` â€” new module. Defines the `IsolationBackend` interface and ships `SeccompBpfBackend` as the reference implementation. Additional backends (gVisor, bubblewrap, Windows Job Objects) will implement the same interface in future releases.
- `ExecutionPayload`, `ExecutionPolicy`, `ExecutionOutcome`, `ResourceLimits` â€” typed policy and result primitives.
- `default_python_policy()` â€” safe defaults for untrusted Python execution: allowlisted-only syscall profile, killlist for high-risk syscalls, network denied, 512 MB / 50% CPU / 64 pids / 30 s wall-clock caps.
- `varek_warden.configure_backend()` â€” installs the active isolation backend. Fails closed if the backend reports unavailable; no silent downgrade.
- `varek_warden.execute_untrusted()` â€” the v1.1 entry point for running untrusted code. Requires a configured backend.
- `varek_warden.subscribe_telemetry()` â€” registers callbacks for PEP 578 audit events, now emitted as advisory telemetry only.
- `docs/security/threat-model.md` â€” explicit in-scope and out-of-scope threats for the containment layer.
- `tests/security/test_issue_223_regression.py` â€” the reporter's PoC is now a regression test. Must fail to execute under the default policy. Tests also cover subprocess escape via base64-encoded commands, renamed binaries, `os.execv`, plus network isolation, killlist triggers, resource caps, and fail-closed behavior.

### Changed

- **Binary enforcement inverted from denylist to allowlist.** Policy now specifies which interpreters are permitted to run (default: the current interpreter only). Attempts to exec anything outside the allowlist raise `IsolationError` before the child process is spawned.
- **PEP 578 audit hook demoted to telemetry.** The hook still fires and emits structured events to subscribers, but it never raises and never denies. Security no longer depends on it firing. If the hook is evaded, disabled, or crashed by untrusted code, the kernel-level boundary still holds.
- `enforce_strict_mode()` keeps its name and call signature for v1.0 compatibility, but its semantics now arm telemetry only. Callers must additionally call `configure_backend()` and route untrusted code through `execute_untrusted()` to get containment.

### Deprecated

- `KineticIntercept` â€” retained as an importable symbol so v1.0 code does not break at import time, but the audit hook no longer raises it. Enforcement failures now surface as `sandbox.IsolationError`. The symbol will be removed in v2.0.

### Removed

- String-signature denylist in the audit hook (`threat_signatures = ["nc -e", "nmap", ...]`). Denylists are unsound against adaptive adversaries; this approach has been replaced entirely by the allowlist-based design above.

### Migration from v1.0

Code that called `enforce_strict_mode()` and then ran untrusted payloads in the same process must now:

1. Call `enforce_strict_mode()` as before (arms telemetry).
2. Additionally call `configure_backend()` at startup.
3. Route untrusted code through `execute_untrusted(payload, policy)` instead of executing it in-process.

A v1.0 call that previously looked like:

```python
varek_warden.enforce_strict_mode()
exec(untrusted_code)  # relied on the audit hook to catch escapes â€” unsafe
```

becomes:

```python
varek_warden.enforce_strict_mode()
varek_warden.configure_backend()
outcome = varek_warden.execute_untrusted(
    ExecutionPayload(interpreter_path=sys.executable, code=untrusted_code)
)
```

### Requirements

- Linux kernel 5.10 or later with cgroups v2 mounted
- Unprivileged user namespaces enabled
- `libseccomp` Python binding: `pip install pyseccomp` or distro equivalent
- Write access to a cgroup slice for the running process. Recommended: systemd unit with `Delegate=yes`, or a pre-created `/sys/fs/cgroup/varek.slice/` owned by the running user.

The reference backend fails closed on hosts that do not meet these requirements. macOS and Windows are not supported by the reference backend.

### Credit

The design flaw addressed by this release was reported by @dengluozhang on issue #223. The proof-of-concept in that thread is included verbatim as a regression test in the v1.1 test suite.

---

## [1.0.0] â€” 2026-04-06

Initial public release under the MIT license.

### Added

- Statically-typed AI/ML pipeline programming language compiling to native code via LLVM.
- Hindley-Milner type inference extended to tensor shapes.
- `varek_warden.py` â€” PEP 578 audit hook-based runtime intercept for OS-level syscalls spawned from agentic execution contexts.
- `enforce_strict_mode()` â€” parent-interpreter audit hook arming for code-interpreter tool containment.

### Known limitations (addressed in 1.1)

The v1.0 containment model assumed the parent interpreter could observe and deny syscalls made by untrusted code. This assumption did not hold for child processes spawned via `subprocess`, and the accompanying string-based signature denylist was not adequate against adaptive adversaries. See the 1.1 security note above.
