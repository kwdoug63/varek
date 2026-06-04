# 1. Syscall Enforcement Layer: libseccomp vs. Raw ctypes Filter Construction

- Status: Accepted
- Date: 2026-06-03
- Deciders: Warden maintainers
- Tags: warden, seccomp, kernel-enforcement, audit-scope, primitive

## Context

The Warden supervisor enforces a deny-by-default syscall policy on supervised
processes using seccomp-bpf. The syscall enforcement layer is the component that
constructs the BPF filter program and installs it into the kernel
(`seccomp(2)` / `prctl(PR_SET_SECCOMP)`). Every higher-level guarantee in Warden
reduces, at the bottom, to this filter being correct and failing closed.

Two construction strategies were prototyped:

- **Option A — libseccomp.** Bind to the system `libseccomp` shared object and
  build filters through its high-level API (`seccomp_init`, `seccomp_rule_add`,
  `seccomp_load`). The library emits the BPF bytecode and handles architecture
  multiplexing and ABI detail.
- **Option B — raw ctypes.** Hand-assemble the BPF program in Python: pack
  `sock_filter` instructions, lay out the `seccomp_data` offsets by hand, build
  the `sock_fprog`, and invoke the syscall through `ctypes`. Zero non-stdlib
  runtime dependency.

The original lean toward Option B was driven by a zero-dependency goal. During
review, the hand-assembled filter path was flagged as fragile in precisely the
struct-packing and flag-combination dimensions where seccomp filters fail open
rather than fail closed.

This layer is also the primary scope of external security review. Whatever sits
here is what an auditor reads first and hardest.

## Decision

**Use `libseccomp` for seccomp-bpf filter construction.** Warden binds to the
system `libseccomp` shared object for building and loading filters. Filter
bytecode is not hand-assembled in Python.

The raw-ctypes prototype is retained, but only for (1) the thin load-path binding
where a direct syscall is unavoidable and (2) as a conformance-test oracle that
validates the bytecode `libseccomp` produces. It is not the production filter
constructor.

## Prototype Findings

### Prototype A — libseccomp integration

- **Dependency weight.** `libseccomp` ships as a small shared object:
  123 KB (`libseccomp.so.2.5.5`, Ubuntu base). It is already resident on
  essentially all target platforms because it is a dependency of `systemd` and
  of the common container runtimes (Docker/Podman/containerd). Net new install
  cost on supported platforms is effectively zero.
- **Build complexity.** Binding via `ctypes` to the system `.so` requires no
  build-time toolchain and no Cython — no compiler is invoked at install time.
  The alternative `python3-seccomp` bindings exist but pull a build dependency;
  rejected in favor of the `ctypes`-to-`.so` binding to keep the install path
  pure-Python with a single native runtime requirement.
- **Distro packaging.** Present in the base package set of every supported
  distro: `libseccomp2` (Debian/Ubuntu), `libseccomp` (Fedora/RHEL),
  `libseccomp` (Alpine). Development headers, where needed, are
  `libseccomp-dev` / `libseccomp-devel`. Minimum version pinned to 2.5.5
  (version present on the validation host; 2.5 series baseline).

### Prototype B — raw ctypes filter construction

- **Differential harness, not golden bytecode.** The prototype's durable
  artifact is a differential test harness, not a captured bytecode fixture:
  `tests/seccomp_toctou_harness.c` reproduces the TOCTOU race on
  pointer-argument syscalls under seccomp-unotify and compares a naive
  supervisor against a mitigated one that resolves paths with `openat2()`
  under `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`. This is the conformance
  value the ctypes prototype was meant to provide — it validates supervisor
  behavior against a known race rather than freezing a specific instruction
  sequence.
- **Construction lives in C, not Python.** Filter construction in the shipped
  tree is C (`varek/v1_4/warden.c`), not hand-packed Python `ctypes` structs.
  The struct-packing fragility the original framing worried about does not apply
  to the committed code; the concern is retained here only as the reason a
  hand-rolled Python path was rejected.
- **Failure mode.** A hand-assembled path concentrates the highest-risk code
  (manual jump targets, offset arithmetic, action-mask combinations) in the one
  component where a single wrong value fails open. This is the fragility the
  reviewer flagged and the reason Option B is not the production constructor.

## Tradeoff Matrix

| Axis                | Raw ctypes (Option B)                                                                 | libseccomp (Option A)                                                              |
|---------------------|---------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
| Correctness risk    | High. Hand-assembled BPF; manual offsets/jumps/action masks; ctypes packing must be exact and stable per CPython release; fail-open failure modes. | Low. Construction delegated to a widely deployed, continuously fuzzed/audited library; arch multiplexing and ABI quirks handled upstream. |
| Dependency cost     | Zero new runtime dependency (stdlib `ctypes` only).                                   | One native shared object, ubiquitous on Linux via `systemd`/container runtimes; no build toolchain when bound via `ctypes`. |
| Audit surface       | Large and novel. Auditor must independently verify bespoke bytecode is correct and fails closed — the hardest-to-review code sits where review is most intense. | Small and familiar. Auditor verifies API usage against a library already in their trust base; filter-construction correctness is inherited. |
| Maintenance burden  | High. Golden fixtures + struct-packing tests maintained across CPython versions; kernel ABI drift and new-arch support land on the project. | Low. ABI abstraction and arch support tracked upstream; maintenance is keeping a thin binding current and pinning a minimum version. |

## Rationale

The zero-dependency framing was aesthetic, not a security requirement. For a
security primitive that the entire enforcement guarantee rests on, and that is
the first thing an external reviewer scopes against, correctness and audit
surface dominate dependency minimalism.

The dependency being accepted is, in practice, not a dependency at all on the
target platforms — `libseccomp` is already present as a transitive requirement of
`systemd` and container tooling — and binding to the system `.so` via `ctypes`
keeps the install path free of a compiler. Against that near-zero marginal cost,
Option B asks the project to own a hand-rolled BPF assembler whose failure mode is
fail-open and whose fragility was already identified in review.

Delegating filter construction to `libseccomp` collapses the highest-risk,
highest-scrutiny code path into "call a trusted library correctly," which both
reduces real correctness risk and reduces the cost and risk of external review.

The ctypes prototype is not discarded: its differential TOCTOU harness becomes the
conformance artifact that proves the supervisor behaves correctly against a known
race, and the load path retains a direct syscall binding where required.

## Consequences

**Positive**

- Smaller, more familiar external-review surface for the enforcement primitive.
- Correctness of filter bytecode inherited from an audited, widely deployed library.
- Lower long-term maintenance; kernel ABI and new-arch support tracked upstream.
- Removes the fail-open class of bug flagged in review.

**Negative**

- `libseccomp` enters the runtime trust base. Mitigated by its ubiquity and
  audit/fuzzing history.
- Native shared object must be present and loadable at runtime. Requires an
  explicit, fail-closed startup check: if `libseccomp` is missing or older than
  the pinned minimum, Warden refuses to start rather than running unsupervised.
- A minimum `libseccomp` version must be pinned and documented.

**Neutral**

- The ctypes path survives as the differential-test artifact and the load-path
  binding; it is no longer the production constructor.
- The TOCTOU harness in `tests/seccomp_toctou_harness.c` is the conformance
  reference for supervisor behavior under seccomp-unotify.

## Related

- Subsequent ADRs covering the Warden policy model and the filter conformance
  suite.
- External security review scopes this layer as primary; the decision is made
  with that review in mind.
