# 1. Syscall Enforcement Layer: libseccomp vs. Raw ctypes Filter Construction

- Status: Accepted (decision made; implementation pending — see Implementation Status)
- Date: 2026-06-03
- Deciders: Warden maintainers
- Tags: warden, seccomp, kernel-enforcement, audit-scope, primitive

## Context

The Warden supervisor enforces a deny-by-default syscall policy on supervised
processes using seccomp-bpf. The syscall enforcement layer is the component that
constructs the BPF filter program and installs it into the kernel
(`seccomp(2)` / `prctl(PR_SET_SECCOMP)`). Every higher-level guarantee in Warden
reduces, at the bottom, to this filter being correct and failing closed.

Two construction strategies were evaluated:

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

**Use `libseccomp` for seccomp-bpf filter construction.** Warden will bind to the
system `libseccomp` shared object for building and loading filters. Filter
bytecode will not be hand-assembled in Python.

This ADR records the decision and its rationale. It does not assert that the
integration is built; see Implementation Status for the current state of the
tree.

## Implementation Status

This is a forward decision. As of this ADR:

- **Present in the committed tree:** the seccomp prerequisite
  `prctl(PR_SET_NO_NEW_PRIVS, ...)` is installed in `sandbox.py` (ctypes-to-libc
  binding) and in `varek/v1_4/warden.c`. A differential TOCTOU harness,
  `tests/seccomp_toctou_harness.c`, exercises supervisor behavior under
  seccomp-unotify.
- **Not yet present in the committed tree:** the libseccomp construction path
  itself. No calls to `seccomp_init`, `seccomp_rule_add`, `seccomp_load`, or the
  `SCMP_ACT_*` actions exist in the tree at the time of this decision. Building
  that binding is the implementation work this ADR authorizes.

This section is the single source of truth for what is and is not built; the
Evaluation below concerns the merits of the options, not shipped code.

## Evaluation

### Option A — libseccomp

- **Dependency weight (measured on the validation host).** `libseccomp` ships as
  a small shared object: 123 KB (`libseccomp.so.2.5.5`, Ubuntu base). It is
  already resident on essentially all target platforms because it is a dependency
  of `systemd` and of the common container runtimes (Docker/Podman/containerd).
  Net new install cost on supported platforms is effectively zero.
- **Build complexity (property of the chosen binding approach).** Binding via
  `ctypes` to the system `.so` requires no build-time toolchain and no Cython —
  no compiler is invoked at install time. The alternative `python3-seccomp`
  bindings exist but pull a build dependency; rejected in favor of the
  `ctypes`-to-`.so` binding to keep the install path pure-Python with a single
  native runtime requirement.
- **Distro packaging.** Present in the base package set of every supported
  distro: `libseccomp2` (Debian/Ubuntu), `libseccomp` (Fedora/RHEL),
  `libseccomp` (Alpine). Development headers, where needed, are
  `libseccomp-dev` / `libseccomp-devel`. Minimum version to pin: 2.5.5 (version
  present on the validation host; 2.5 series baseline).

### Option B — raw ctypes

- **What exists today is a differential harness, not a golden bytecode fixture.**
  `tests/seccomp_toctou_harness.c` reproduces the TOCTOU race on pointer-argument
  syscalls under seccomp-unotify and compares a naive supervisor against a
  mitigated one that resolves paths with `openat2()` under
  `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`. This is genuine conformance
  value, but it is not the hand-packed Python ctypes filter constructor that
  Option B would require — that constructor was never built, which is consistent
  with rejecting Option B.
- **Failure mode that drove the rejection.** A hand-assembled path concentrates
  the highest-risk code (manual jump targets, offset arithmetic, action-mask
  combinations) in the one component where a single wrong value fails open. This
  is the fragility the reviewer flagged.

## Tradeoff Matrix

| Axis                | Raw ctypes (Option B)                                                                 | libseccomp (Option A)                                                              |
|---------------------|---------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
| Correctness risk    | High. Hand-assembled BPF; manual offsets/jumps/action masks; ctypes packing must be exact and stable per CPython release; fail-open failure modes. | Low. Construction delegated to a widely deployed, continuously fuzzed/audited library; arch multiplexing and ABI quirks handled upstream. |
| Dependency cost     | Zero new runtime dependency (stdlib `ctypes` only).                                   | One native shared object, ubiquitous on Linux via `systemd`/container runtimes; no build toolchain when bound via `ctypes`. |
| Audit surface       | Large and novel. Auditor must independently verify bespoke bytecode is correct and fails closed — the hardest-to-review code sits where review is most intense. | Small and familiar. Auditor verifies API usage against a library already in their trust base; filter-construction correctness is inherited. |
| Maintenance burden  | High. Bespoke fixtures + struct-packing tests maintained across CPython versions; kernel ABI drift and new-arch support land on the project. | Low. ABI abstraction and arch support tracked upstream; maintenance is keeping a thin binding current and pinning a minimum version. |

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

## Consequences

**Positive**

- Smaller, more familiar external-review surface for the enforcement primitive.
- Correctness of filter bytecode inherited from an audited, widely deployed library.
- Lower long-term maintenance; kernel ABI and new-arch support tracked upstream.
- Removes the fail-open class of bug flagged in review.

**Negative**

- `libseccomp` will enter the runtime trust base. Mitigated by its ubiquity and
  audit/fuzzing history.
- The native shared object must be present and loadable at runtime. The
  implementation must include an explicit, fail-closed startup check: if
  `libseccomp` is missing or older than the pinned minimum, Warden refuses to
  start rather than running unsupervised.
- A minimum `libseccomp` version must be pinned and documented.

**Neutral**

- The TOCTOU harness in `tests/seccomp_toctou_harness.c` is the conformance
  reference for supervisor behavior under seccomp-unotify.
- `prctl(PR_SET_NO_NEW_PRIVS, ...)` is already in place as the seccomp
  prerequisite; the libseccomp load path will build on it.

## Follow-up Work

- Implement the libseccomp construction binding (`seccomp_init` →
  `seccomp_rule_add` → `seccomp_load` via `ctypes` to `libseccomp.so.2.5.5`).
- Add the fail-closed availability and minimum-version check at Warden startup.
- Update the Implementation Status section above once the binding lands, and
  revise Status to remove the "implementation pending" qualifier.

## Related

- Subsequent ADRs covering the Warden policy model and the filter conformance
  suite.
- External security review scopes this layer as primary; the decision is made
  with that review in mind.
