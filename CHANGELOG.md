# Changelog

All notable changes to VAREK are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.5.0] - 2026-05-12

### Added

- `v1_5/fast_match.c`: Fast-path policy matcher using sorted prefix arrays with binary-search lookup. Three-state `ALLOW` / `DENY` / `UNKNOWN` decision procedure with symmetric suppression preserved from v1.4.
- `v1_5/smt_probe.c`, `v1_5/smt_probe2.c`: SMT decision-procedure feasibility benchmarks (fresh-context and context-reuse access patterns). Retained for richer policies — regex, integer ranges, multi-rule conjunctions — that the prefix matcher cannot express.
- `v1_5/bench_summarize.py`: Nanosecond-precision summarizer. Backward-compatible with v1.4 pathology logs.
- `v1_5/NOTES.md`: Design notes documenting the hybrid prefix-DFA + SMT architecture decision.
- `v1_5/bench_results_v1_5.txt`: Provenance record (host, kernel, CPU, memory) from the measured benchmark run.

### Performance

- `fast_match`: P50 = 93 ns, P99 = 271 ns, P99.9 = 526 ns across 10,000 decisions on DigitalOcean 1 vCPU / 512 MB. Three orders of magnitude faster than the v1.4 Warden's 57 µs P99 — policy-decision time is not the bottleneck in seccomp-unotify enforcement.
- SMT context-reuse probe: P50 = 465 µs, P99 = 51,959 µs (bimodal distribution). Disqualified from hot-path use; retained for the slow-path role on richer policies.
- Zero false negatives. Full `UNKNOWN` → `DENY` suppression across the benchmark.

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

- End-to-end Warden pipeline (seccomp-unotify + `/proc/<pid>/mem` + kernel injection): P99 = 57 µs measured.

## [1.3.0] - 2026-05-10

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

## [1.1.1] — 2026-04-24

### Added

- `varek_warden.py` — real implementation of the orchestration layer advertised in v1.1. Exposes `configure_backend()`, `execute_untrusted()`, and `subscribe_telemetry()` as callable module-level entry points over the sandbox primitives.
- `varek_guardrails/` package — public re-export surface. Existing intercept files and external code can now `pip install -e .` and `from varek_guardrails import ...` without resolving loose top-level modules by `sys.path` manipulation.
- `pyproject.toml` — PEP 621 package metadata. `pytest` is now an optional dev dependency; production installs no longer require it.

### Fixed

- `configure_backend()` now fails closed when `IsolationBackend.is_available()` returns a non-None unavailability reason string. The prior draft had the check inverted, which would have silently accepted unavailable backends — a fail-open bug in a security primitive.

### Moved

- Smoke tests previously resident in `varek_warden.py` relocated to `tests/security/test_warden_smoke.py`.

---

## [1.1.0] — 2026-04-20

### Security

**Resolves a subprocess-escape weakness in the v1.0 containment design** reported by @dengluozhang in issue #223. The v1.0 architecture used a PEP 578 audit hook to deny `subprocess.Popen`, `os.exec*`, and related events by matching against a string-based signature list. Review demonstrated two flaws:

1. `sys.addaudithook` installs a callback in the current interpreter only. Child processes spawned via `subprocess.run` execute in a fresh interpreter or a non-Python binary that never inherits the hook. Parent-side audit callbacks cannot observe syscalls in the child. The reporter's proof-of-concept exploited this directly — the malicious payload executed in the child process while the parent hook saw nothing.
2. String-signature denylists on command arguments (`nc -e`, `nmap`, known C2 hostnames) were trivially bypassable via absolute paths (`/bin/nc`), base64-encoded commands, renamed binaries, or any attacker tooling not enumerated in the list.

**Fix:** enforcement moved out of the interpreter and into the kernel. The new reference backend combines seccomp-bpf, cgroups v2, and user/mount/network/IPC/UTS/PID namespaces, loaded under `PR_SET_NO_NEW_PRIVS`. The filter is installed before untrusted code runs, inherited across every `fork` and `clone`, and cannot be dropped by any descendant. `execve` is denied by default, which structurally prevents the subprocess-escape class of bypass regardless of argv content.

Severity: **High**. Users running v1.0 with untrusted code should upgrade.

### Added

- `sandbox.py` — new module. Defines the `IsolationBackend` interface and ships `SeccompBpfBackend` as the reference implementation. Additional backends (gVisor, bubblewrap, Windows Job Objects) will implement the same interface in future releases.
- `ExecutionPayload`, `ExecutionPolicy`, `ExecutionOutcome`, `ResourceLimits` — typed policy and result primitives.
- `default_python_policy()` — safe defaults for untrusted Python execution: allowlisted-only syscall profile, killlist for high-risk syscalls, network denied, 512 MB / 50% CPU / 64 pids / 30 s wall-clock caps.
- `varek_warden.configure_backend()` — installs the active isolation backend. Fails closed if the backend reports unavailable; no silent downgrade.
- `varek_warden.execute_untrusted()` — the v1.1 entry point for running untrusted code. Requires a configured backend.
- `varek_warden.subscribe_telemetry()` — registers callbacks for PEP 578 audit events, now emitted as advisory telemetry only.
- `docs/security/threat-model.md` — explicit in-scope and out-of-scope threats for the containment layer.
- `tests/security/test_issue_223_regression.py` — the reporter's PoC is now a regression test. Must fail to execute under the default policy. Tests also cover subprocess escape via base64-encoded commands, renamed binaries, `os.execv`, plus network isolation, killlist triggers, resource caps, and fail-closed behavior.

### Changed

- **Binary enforcement inverted from denylist to allowlist.** Policy now specifies which interpreters are permitted to run (default: the current interpreter only). Attempts to exec anything outside the allowlist raise `IsolationError` before the child process is spawned.
- **PEP 578 audit hook demoted to telemetry.** The hook still fires and emits structured events to subscribers, but it never raises and never denies. Security no longer depends on it firing. If the hook is evaded, disabled, or crashed by untrusted code, the kernel-level boundary still holds.
- `enforce_strict_mode()` keeps its name and call signature for v1.0 compatibility, but its semantics now arm telemetry only. Callers must additionally call `configure_backend()` and route untrusted code through `execute_untrusted()` to get containment.

### Deprecated

- `KineticIntercept` — retained as an importable symbol so v1.0 code does not break at import time, but the audit hook no longer raises it. Enforcement failures now surface as `sandbox.IsolationError`. The symbol will be removed in v2.0.

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
exec(untrusted_code)  # relied on the audit hook to catch escapes — unsafe
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

## [1.0.0] — 2026-04-06

Initial public release under the MIT license.

### Added

- Statically-typed AI/ML pipeline programming language compiling to native code via LLVM.
- Hindley-Milner type inference extended to tensor shapes.
- `varek_warden.py` — PEP 578 audit hook-based runtime intercept for OS-level syscalls spawned from agentic execution contexts.
- `enforce_strict_mode()` — parent-interpreter audit hook arming for code-interpreter tool containment.

### Known limitations (addressed in 1.1)

The v1.0 containment model assumed the parent interpreter could observe and deny syscalls made by untrusted code. This assumption did not hold for child processes spawned via `subprocess`, and the accompanying string-based signature denylist was not adequate against adaptive adversaries. See the 1.1 security note above.
