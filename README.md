# VAREK

### Deterministic pre-execution verification of AI agent actions, enforced at the kernel.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/language-v1.0%20stable-blue.svg)](https://github.com/kwdoug63/varek/releases)
[![Runtime](https://img.shields.io/badge/runtime-v1.16.1-green.svg)](https://github.com/kwdoug63/varek/releases)
[![Verdict](https://img.shields.io/badge/verdict-SATISFIED%20%7C%20UNSATISFIED%20%7C%20UNKNOWN-7a5cff.svg)](#the-verdict-model)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **Reporting vulnerabilities:** [private vulnerability reporting](https://github.com/kwdoug63/varek/security/advisories/new) or [SECURITY.md](./SECURITY.md). Do not open public issues.

## What VAREK is

VAREK decides whether an AI agent's planned actions are allowed **before** they
execute, and enforces that decision at the kernel boundary.

An agent's intended actions are represented as an **action-graph** — a directed
acyclic graph of planned actions. An **SMT decision procedure** evaluates that graph against a policy. In the Warden it is a purpose-built procedure for a decidable fragment — bounded strings for the object (prefix, exact, suffix, contains and glob matching), bitvectors for the open flags — that decides in microseconds with bounded worst case, is cross-checked against an off-the-shelf SMT solver, and returns UNKNOWN for anything outside its fragment rather than guessing. Every SATISFIED verdict carries a certificate that a small, independently written checker must accept before the action takes effect. Every verdict is one of three — **SATISFIED**, **UNSATISFIED**, or **UNKNOWN** — and it fails closed. The **Warden** runtime carries that verdict to
the kernel (via `seccomp user-notify (seccomp-BPF)`) and refuses any disallowed syscall
before it lands. The check is pre-execution: an action that cannot be proven
allowed never runs.

The design premise is a clinical one: you do not deploy a system that is
*usually* right when the cost of being wrong is unbounded. UNKNOWN is therefore a
first-class verdict, not an error path — VAREK never coerces "cannot prove safe"
into a pass.

VAREK has two layers, developed in sequence:

1. **The Warden runtime** — the verification and enforcement layer. It is where
   active development lives and where the verification thesis above is realized.
   **Current release: v1.16.1.**
2. **VAREK the language** — a statically-typed, LLVM-compiled language for AI/ML
   pipelines, where unsafe operations are not expressible in the first place.
   **Stable at v1.0.**

The runtime can protect any agent stack (LangChain, AutoGen, CrewAI, custom
orchestrators), and it does not depend on the model provider or agent platform:
the decision is made and enforced outside the agent, at the kernel boundary, and
its evidence — the verdict stream and the CycloneDX 1.6 export — can be inspected
without relying on the agent's vendor. The language is for pipelines you write fresh. They are useful
independently and complementary together.

## The verdict model

Every decision is total and three-state. There is no fourth outcome and no
silent default.

| Verdict | Meaning | Disposition |
|---------|---------|-------------|
| **SATISFIED** | Provably allowed under the policy, within the decidable fragment. | Proceed. |
| **UNSATISFIED** | A concrete policy violation, identified. | Refuse. |
| **UNKNOWN** | Cannot be decided either way within bounds. | **Fail closed** — never coerced to a pass. |

A two-state allow/deny system must convert every UNKNOWN into a false allow or a
false block. VAREK refuses that conversion: UNKNOWN routes to a deterministic,
policy-declared disposition and never requires a human to break a loop (see
progress-safety, below). That refusal is what separates a verifier from a
heuristic — nothing is SATISFIED unless it is provably safe.

## Layer 1 — the Warden runtime

### What it does

Warden sits between an agent framework and the operating system. Before contained
code performs `execve`, `subprocess.run`, network egress, or other boundary
syscalls, the verdict for the corresponding action-graph is decided and enforced
at the kernel. This is structural containment — not a string-match denylist that
falls to absolute paths, base64 encoding, or renamed binaries.

The runtime line has progressed well beyond simple syscall containment:

- **v1.7 — cross-action data-flow verification.** Reasoning across edges of the
  action-graph, not just per-action checks.
- **v1.8.2 — bounded-refusal breaker.** A non-bypassable loop bound in the
  trusted boundary, keyed by `(session, action-signature)`, so a stuck or
  adversarial planner cannot resubmit a refused action-graph forever. Each verdict
  stays a pure function of `(plan, policy)`; the breaker only interprets the
  *sequence* of verdicts.
- **v1.9.0 — progress-safety / HOOTL.** A load-time liveness proof that certifies
  human-out-of-the-loop operation per policy: for every non-authorizing verdict,
  a deterministic, automated terminal outcome is reachable in finitely many steps.
  "Never requires a human" becomes certified rather than hoped.
- **v1.16.1 — deployment preflight.** `tools/varek_preflight.sh` checks a deployment before it runs: the build dependencies (libsodium is new in v1.16; `make deps` installs them), the build, the policy, and every location the Warden refuses at startup — the verdict stream file, the signing key, the anchor — checked with the Warden's own rules, plus an optional audited trial run. All seven shipped policies pass with the stream in `/var/log/varek/`. A CI job builds the Warden with libseccomp and libsodium. See [`RELEASE-v1.16.1.md`](./RELEASE-v1.16.1.md).
- **v1.16.0 — a verdict stream its holder cannot rewrite, and a bound on every decision.** Addresses the two limits v1.15.0 disclosed. Every record is hash-chained; with `--sign-key`, run_start, a checkpoint every 64 records and run_end are signed with Ed25519; with `--anchor`, each checkpoint is also appended to storage the log's holder cannot rewrite. `tools/varek_audit.py --pubkey --anchor` then catches any edit, insertion, removal or reordering before the last signature, and a stream cut short, by someone without the key, and any rewrite of anchored history even by someone with it; it verifies signatures with its own pure-Python RFC 8032 verifier. The Warden refuses to start if the policy would let the agent open the key, the anchor, the verdict stream itself or a raw disk. Globs are capped at 4,096 tokens per policy, which bounds the work of one decision; the worst case measured is about 26 ms median in the live Warden (v1.15's checker alone: 415 ms), and real policies are unchanged. See [`RELEASE-v1.16.0.md`](./RELEASE-v1.16.0.md).
- **v1.15.0 — certificates: every authorization independently checked.** Third release of the v1.10 verification program. Every SATISFIED verdict now carries a certificate — the deciding rule and a witness that its constant matches — and the Warden authorizes the action only if a separately written checker accepts it (`checker/vdp_checker.c`: about 540 lines, its own policy parser and matchers, no code shared with the decision procedure). A bug confined to the decision procedure can no longer authorize an action: a test build with a planted bug shows the checker refusing its wrong verdicts. Certificates and the policy's SHA-256 go into the verdict stream, and `tools/varek_audit.py` re-checks a saved run without trusting the Warden that made it. See [`RELEASE-v1.15.0.md`](./RELEASE-v1.15.0.md).
- **v1.14.0 — the bounded string fragment.** Second release of the v1.10 verification program. Path and exec rules take a matcher before the constant — `exact`, `prefix` (the default), `suffix`, `contains` or `glob` (`?`, `[...]`, `*`, `**`, and `/**/` for any number of segments) — so a policy can deny a kind of file wherever it appears under an allowed tree: private keys (`suffix .pem`), dotenv files at any depth (`glob /**/.env`), a patient's psychotherapy notes. Matching is on the resolved canonical path, so a symlink with an innocent name is decided as its target. Globs compile to a small automaton stepped word-parallel (well under a microsecond added per decision; bounded worst case). At load the Warden decides exactly, by an automaton search bounded at the 4095-byte length limit, whether each rule can ever fire, and `vdp_check analyze` prints a shortest witness for each rule that can. The cross-check adds an independent derivative-based procedure for reachability alongside the solver. Every v1.13 policy keeps its meaning (checked against the v1.13.0 build). The example sector policies now deny key material, dotenv files and `.ssh` under every allowed tree, plus sector-specific paths. See [`RELEASE-v1.14.0.md`](./RELEASE-v1.14.0.md).
- **v1.13.0 — the SMT decision procedure in the enforcement path.** First release of the v1.10 verification program. Every Warden decision is now made by an SMT decision procedure over a quantifier-free fragment of bounded strings (the object) and 32-bit bitvectors (the open flags), with a fragment boundary that returns UNKNOWN rather than guessing. Policies can now say read-only (`readonly`, `access=`, `+O_…`/`-O_…`); through v1.12 a path rule admitted every open flag, so the example sector policies' "(read)" rules and loader rules admitted writes by a root agent — they now enforce read-only. At load the Warden reports every rule that can never fire (it found one in four example policies). The procedure is cross-checked against an off-the-shelf SMT solver (zero disagreements over 26,624 checks, `make crosscheck`), and a verdict-distribution harness gates on `unsafe_satisfied == 0`: on its synthetic seed corpus v1.13 clears 85.4% of safe file opens with none unsafe authorized, where the policies as v1.12.4 shipped them cleared 75.6% and authorized 24 unsafe opens. Flag clauses constrain the flags passed to `openat()` (`readonly` is sound; `fcntl` can change `O_APPEND` and a few others later). Median latency unchanged. See [`RELEASE-v1.13.0.md`](./RELEASE-v1.13.0.md).
- **v1.12.4 — the `--plan` gate authorizes file opens again.** Optional pre-execution plan verification had rejected every plan that declared a `file_open` action since v1.12.0: the per-open decision moved to the resolved canonical path, but the plan decider (which runs before the agent is forked) never filled it, so every file-open node was UNKNOWN. The decider now decides on the lexically canonical form of the declared absolute path, so a plan opening a policy-allowed file verifies again; a `..` that lexically escapes, or a relative path, stays UNKNOWN. The gate does not follow symlinks (there is no agent yet) and remains an advisory pre-check — every open is still mediated per-syscall at runtime. Adds `make test-v1124`. See [`RELEASE-v1.12.4.md`](./RELEASE-v1.12.4.md).
- **v1.12.3 — dynamically linked agents.** Follows ordinary symlinks and decides policy on the object's canonical path, so a dynamically linked agent (CPython, a JVM, Node) can load its libraries — since v1.12.0 the resolver refused any path with a symlink, and on merged-`/usr` systems `/lib` and library SONAMEs are symlinks. The security property is unchanged: a symlink to a denied object is decided as that object and refused. `/proc/self` and `/proc/thread-self` are mapped to the agent's own process (never the Warden's), and any other process's `/proc`, or a procfs reached through a planted symlink, fails closed. Because the decision is on the canonical path, `allow path` prefixes name canonical locations (`/usr/lib/`, not `/lib/`). Adds `make test-v1123`. See [`RELEASE-v1.12.3.md`](./RELEASE-v1.12.3.md).
- **v1.12.2 — threads and child processes.** Agent code can now start threads, wait for its children and call `isatty()`. `clone3` answers `ENOSYS` instead of killing the process (glibc >= 2.34 creates every thread with it), so libc falls back to `clone()`, whose flags the filter checks; `clone3` still never runs and the namespace denials are unchanged. `wait4`/`waitid` are admitted, and `ioctl` is admitted for six read-or-own-descriptor requests (`TIOCSTI` and the rest stay refused). A filter-killed agent is now reported. Also closes an exec-allowlist bypass: the launch exec, answered with `CONTINUE`, was granted once per pid, so a thread could race its path; it is now granted once per run. Adds `make test-v1122`. Known issue: dynamically linked agents cannot yet load their libraries (symlinked paths are refused since v1.12.0); planned for v1.12.3. See [`RELEASE-v1.12.2.md`](./RELEASE-v1.12.2.md).
- **v1.12.1 — mediation-correctness follow-up.** Fixes three defects found in v1.12.0. A denied file open no longer has side effects: the Warden pins the object with `O_PATH`, decides, and only after ALLOW opens it with the agent's flags (v1.12.0 opened first, so a DENY could still truncate or create a file, and a FIFO could wedge the supervisor). The verdict stream is authenticated: the agent's stderr is relayed with an `[agent] ` prefix, every record carries a per-run id and a contiguous `seq`, and `varek_cyclonedx.py` refuses a stream holding a forged, missing or foreign record. Inbound networking is refused: `bind`/`listen`/`accept` are denied and the agent runs in its own network namespace. Adds `make test-v1121`. No verdict-semantics change. See [`RELEASE-v1.12.1.md`](./RELEASE-v1.12.1.md).
- **v1.12.0 — mediation correctness.** Closes five ways a supervised process could reach a denied object or corrupt the authorization record: `..` traversal and symlink/`/proc/self` escapes (the Warden now resolves the object once, decides policy on its canonical path, and injects that same fd — resolve-then-decide); audit-log forgery via a crafted pathname (all agent-controlled strings are JSON-escaped, records gain a `resolved` field); and datagram egress via `sendto`/`sendmsg` that bypassed the deny-only `connect` posture (both are now mediated as `net.send`). Adds a tool that exports authorization evidence in the CycloneDX 1.6 format (`tools/varek_cyclonedx.py`) and a `make test-v112` regression suite. No verdict-semantics change; v1.10/v1.11 remain reserved for the verification program below. See [`RELEASE-v1.12.0.md`](./RELEASE-v1.12.0.md).
- **v1.9.3 — lifecycle coupling in the live Warden.** If the supervisor stops, the agent stops, and so does everything it started: the agent runs in its own PID namespace and is killed on supervisor death, with a fork-race guard and a pidfd watch. The Warden now requires `CAP_SYS_ADMIN` and checks for it at startup. A crash test kills a live Warden and asserts no agent process survives. Also corrects the v1.9.2 record (bypass class 7 was partial at v1.9.2) and fixes conformance-target setup. See [`RELEASE-v1.9.3.md`](./RELEASE-v1.9.3.md).
- **v1.9.2 — mediation completeness.** Default-deny allowlist replacing allow-by-default; native-ABI lockdown (x32 bypass closed); hard-deny set; scalar-flag `CLONE_NEWUSER` denial; lifecycle-coupling module (integrated into the live Warden in v1.9.3). Default-deny baseline wired into the live Warden and validated by a conformance target; deny-only bootstrap-exec regression found and fixed. See [`RELEASE-v1.9.2.md`](./RELEASE-v1.9.2.md).
- **v1.9.1 — enforcement hardening, measured.** Closes an io_uring bypass (it
  dispatches I/O off the syscall path where seccomp can't see it), and removes the
  time-of-check-to-time-of-use (TOCTOU) race from file mediation: the supervisor
  resolves the approved path and injects the descriptor rather than letting the
  syscall re-read attacker-mutable memory. Measured against a race harness, the
  prior approve-then-continue strategy leaked the protected target 510 times in
  20,000 attempts; the resolve-and-inject strategy leaked 0. `connect`/`execve`
  are deny-only (fail closed) pending the v1.10 dial-and-inject path. See
  [`RELEASE-v1.9.1.md`](./RELEASE-v1.9.1.md).

See [`CHANGELOG.md`](./CHANGELOG.md) for the full v1.0–v1.16.1 history.

### Installation

```bash
# Linux host (kernel-enforced containment requires Linux; see requirements below)
git clone https://github.com/kwdoug63/varek.git
cd varek
pip install -e ".[dev]"
```

**Production requirements (for kernel-enforced containment):**

- Linux with cgroups v2 mounted
- `libseccomp` Python binding (`pyseccomp` or `python3-libseccomp`)
- Unprivileged user namespaces enabled
- `/sys/fs/cgroup/varek.slice` writable by the test user

The C Warden (`varek/v1_4`) additionally requires `CAP_SYS_ADMIN` (run it as
root or via `sudo`); it checks at startup and refuses to run without it. See
[`varek/v1_4/README.md`](./varek/v1_4/README.md).

The runtime **fails closed** if these are unmet. The package installs and imports
cleanly everywhere, but `SeccompBpfBackend.is_available()` returns an explanatory
string on non-Linux hosts or environments without kernel support. No silent
degradation.

### Verify your installation

```bash
# Linux host or Codespaces
python verify_guardrails.py
```

This exercises every public entry point through an eight-step verification. In
most environments (including GitHub Codespaces) steps 1, 2, 3, 5, 6 **PASS** and
steps 4, 7, 8 **SKIP** with `SeccompBpfBackend unavailable — cannot exercise
kernel boundary`. The SKIP pattern is itself a correctness property: the backend
refuses to initialize rather than run without containment. To convert the three
SKIPs to PASSes, run on a Linux host meeting the production requirements.

### Quick start

```python
import sys
from varek_guardrails import (
    SeccompBpfBackend,
    ExecutionPayload,
    IsolationError,
    default_python_policy,
    configure_backend,
    execute_untrusted,
    subscribe_telemetry,
)

# Arm the containment layer. Fails closed if kernel support is missing.
configure_backend(SeccompBpfBackend())

# Optional: stream PEP 578 audit events to your observability stack.
subscribe_telemetry(lambda event, args: print(f"[audit] {event}"))

# Run untrusted code under the default policy:
# 512 MB / 50% CPU / 64 pids / 30 s wall-clock / network denied / execve denied
payload = ExecutionPayload(
    interpreter_path=sys.executable,
    code="print(2 + 2)\n",
)

try:
    outcome = execute_untrusted(payload, default_python_policy())
    contained = (
        outcome.exit_code != 0
        or outcome.killed_by_signal is not None
        or outcome.violation is not None
    )
    print(
        f"contained={contained} "
        f"exit_code={outcome.exit_code} "
        f"wall_clock_s={outcome.wall_clock_s:.3f}s "
        f"stdout={outcome.stdout!r}"
    )
except IsolationError as e:
    # Raised only at the orchestration boundary (backend not configured,
    # policy malformed). Ordinary containment events surface on the outcome.
    print(f"orchestration error: {e}")
```

### Integration demos

Numbered demos apply Warden to popular agent frameworks. Each follows the same
`Target / Vector / Defense` pattern and runs end-to-end.

| File | Surface |
|------|---------|
| `04-huggingface-smolagents-sandbox.ipynb` | Hugging Face smolagents |
| `05-openai-gpt4o-varek-hardened.ipynb` | OpenAI GPT-4o tool-calling |
| `06-crewai-gemini-ast-intercept.ipynb` | CrewAI + Gemini |
| `07-bare-metal-mobile-intercept.py` | Edge inference |
| `08-autogen-local-executor-intercept.py` | Microsoft AutoGen |
| `09-prefect-task-intercept.py` | Prefect task orchestration |
| `16-wandb-pipeline-verification.py` | Weights & Biases / Weave evals |

These are engineering demonstrations of containment patterns, not statements of
customer relationships.

## Layer 2 — VAREK the language

### Why a new language

Modern AI pipelines stitch together four tools — Python for logic, YAML for
configuration, JSON Schema for validation, shell for orchestration. Each format
boundary erases type information; schema drift and silent coercion errors follow.
VAREK replaces all four with one statically-typed language. Unsafe operations
are not expressible, so a VAREK pipeline needs no runtime containment.

### Syntax at a glance

```varek
-- Complete pipeline: schema, logic, and config in one file

schema ImageInput {
    path: str,
    label: str?,
    width: int,
    height: int
}

pipeline classify_images {
    source: ImageInput[]
    steps:  [preprocess -> embed -> infer -> postprocess]
    output: ClassificationResult[]
    config { batch_size: 32, parallelism: 8 }
}

fn preprocess(img: ImageInput) -> Tensor {
    load_image(img.path)
        |> resize(224, 224)
        |> normalize(mean=[0.485, 0.456, 0.406])
}

async fn infer(tensor: Tensor) -> RawOutput {
    let model = load_model("resnet50.varekmodel")
    model.forward(tensor)
}
```

The equivalent Python requires four files in two languages. The full language
description is in the [spec paper](./varek-spec-paper-v1.12.md).

### Core language features

| Feature | Description |
|---------|-------------|
| **LLVM backend** | Native code generation via `ctypes` bindings to `libLLVM-20`. SSA form, phi nodes, full optimization passes. |
| **Hindley-Milner inference** | Algorithm W, Robinson unification with occurs check, let-polymorphism. Types inferred across module boundaries. |
| **Tensor types** | First-class `Tensor<T, D>` with symbolic dimension tracking and compile-time shape checking. |
| **Pipeline operator** | `\|>` for linear composition. `x \|> f \|> g` desugars to `g(f(x))`. |
| **Schema types** | Structural typing, optional fields, runtime `SchemaValidator`. Replaces JSON Schema and Pydantic. |
| **Result types** | `Result<T>` for errors-as-values. `?` propagates errors without hiding them. |
| **Native async** | First-class `async fn` with channels, futures, parallel_map, mutex, atomic. |
| **Python/C/Rust interop** | `import python::numpy as np` — typed FFI for the existing ML ecosystem. |

The `varek` CLI provides 20 commands (`new`, `build`, `run`, `check`, `test`,
`bench`, `repl`, `fmt`, `doc`, `install`, `publish`, `search`, `add`, `remove`,
`update`, `clean`, `init`, `info`, `registry update`, `version`). The standard
library is 261 functions across 7 modules: `var::io`, `var::tensor`, `var::http`,
`var::async`, `var::pipeline`, `var::model`, `var::data`.

## How the layers compose
Your AI workload
VAREK (.varek)                 Python agent code

typed, LLVM-compiled           (LangChain, AutoGen,

unsafe ops inexpressible        CrewAI, custom ...)

|                                |
```
|                          action-graph

|                                |

|                                v

|                    +-----------------------------------+

|                    | two-tier decision procedure       |

|                    |   decidable matcher (fast)        |

|                    |   + SMT for richer policy         | 

|                    |   -> SATISFIED /                  | 

|                    |      UNSATISFIED /                | 

|                    |      UNKNOWN                      |

|                    +-----------------------------------+

|                                |

|                                v

|                    +-----------------------------------+

|                    | Warden runtime                    |

|                    | kernel enforcement                |

|                    | seccomp user-notify (seccomp-BPF) |

|                    | fail closed                       |

|                    +-----------------------------------+

v
```
native binary (runs directly)

A VAREK pipeline is verified at compile time. Python agent code is verified
per-action at run time and bounded at the kernel. The two layers address
different risks at different points in the stack.

## Roadmap

### Runtime (verification + enforcement)

- [x] **v1.0–v1.5** — Warden supervisor, fail-closed semantics, linear rule evaluation, kernel-enforced containment
- [x] **v1.6** — C Warden adapter; public-repo cleanup; data room
- [x] **v1.7** — Cross-action data-flow verification
- [x] **v1.8.2** — Bounded-refusal breaker
- [x] **v1.9.0** — Progress-safety / HOOTL liveness proof
- [x] **v1.9.1** — Enforcement hardening: io_uring closed; TOCTOU-safe file mediation (510→0); `connect`/`execve` deny-only
- [x] **v1.9.2** — Mediation completeness: default-deny allowlist; native-ABI/x32 lockdown; hard-deny set; `CLONE_NEWUSER` denial; live-Warden integration + conformance validation
- [x] **v1.9.3** — Lifecycle coupling in the live Warden: PID-namespace isolation, death-signal coupling, fork-race guard, pidfd watch; crash test
- [x] **v1.12** — Mediation correctness: resolve-then-decide (traversal / symlink / `/proc/self`), audit-log integrity, datagram-egress mediation; authorization-evidence export in the CycloneDX 1.6 format
- [x] **v1.12.1** — Side-effect-free denials (resolve, decide, then open), authenticated verdict stream, inbound networking refused
- [x] **v1.12.2** — Threads and child processes: `clone3` answers `ENOSYS` (libc falls back to the filtered `clone`), `wait4`/`waitid`, narrow `ioctl` allowlist, kill report; bootstrap exec granted once per run
- [x] **v1.12.3** — Dynamically linked agents: follow symlinks and decide on the canonical path; `/proc/self` mapped to the agent
- [x] **v1.12.4** — The `--plan` gate authorizes file opens again (decide on the lexically canonical declared path)
- [x] **v1.13.0** — First release of the v1.10 verification program: SMT decision procedure in the enforcement path; open-flag (bitvector) fragment; load-time dead-rule analysis; solver cross-check; verdict-distribution harness
- [x] **v1.14.0** — Bounded string fragment: `exact` / `suffix` / `contains` / `glob` matchers; exact automaton-based rule reachability with witnesses; derivative-based reachability oracle in the cross-check
- [x] **v1.15.0** — Certificates: every authorization carries a certificate checked in-line by an independent checker; policy SHA-256 in the record; audit tool
- [x] **v1.16.0** — Verdict stream protected against its holder: hash chain, Ed25519-signed checkpoints, external anchor, audit with pinned key; glob size capped so one decision is bounded
- [x] **v1.16.1** — Deployment preflight (dependencies, build, stream/key/anchor locations, trial run); libsodium build check and CI job
- [~] **v1.10 program** — The UNKNOWN-shrinking program (below); shipped as v1.13.0, v1.14.0 and v1.15.0. Remaining: customer-derived corpus and measured baseline, a formally verified checker
- [ ] **v1.11 (candidate)** — Bounded sequence fragment for cross-action data-flow

### Language

- [x] **v0.1–v0.4** — Grammar + parser, HM type system, LLVM backend, standard library
- [x] **v1.0** — Stable release, package manager, RFC process

## The verification program (v1.10 / v1.11)

> **Partly shipped.** No v1.10 or v1.11 tag exists: the program's releases ship
> as v1.13.0, v1.14.0 and v1.15.0 so version numbers keep increasing (marked below); the
> rest is planned or candidate work. v1.12 (mediation correctness) shipped ahead
> of the program and does not touch it. Shipped behavior is in
> [`CHANGELOG.md`](./CHANGELOG.md).

The post-v1.9 program has a single goal: migrate cases out of the UNKNOWN verdict
into a provable verdict, raising the clear rate on safe agent actions — under a
hard invariant that **no extension may ever move a genuinely unsafe action into
SATISFIED.** "Cannot prove safe" stays UNSATISFIED/UNKNOWN.

The program proceeds by adding small, individually-auditable decidable fragments,
each with one named soundness obligation and the trusted code it introduces:

- **v1.10 step 1 — verdict-distribution harness + corpus.** The measurement
  baseline. Hard gate: zero unsafe authorizations across the corpus.
  *Shipped in v1.13.0 with a synthetic seed corpus; a customer-derived corpus
  is outstanding.*
- **v1.10 step 2 — bitvector fragment.** Decidable reasoning over fixed-width
  syscall flag/argument bits. Lowest audit cost. *Shipped in v1.13.0.*
- **v1.10 step 3 — bounded string fragment (headline).** Length-bounded
  path-prefix and host-allowlist predicates made provable instead of refused.
  *Shipped: prefix/equality in v1.13.0; suffix, contains and globs in v1.14.0.*
- **v1.11 candidate — bounded sequence fragment.** Element-level reasoning for the
  cross-action data-flow subsystem, composed on the fragments above.

Race-free network mediation (a supervisor-dials-and-injects path replacing the
v1.9.1 deny-only posture for `connect`) remains on the roadmap; the default-deny
syscall allowlist closing the alternate-ABI and variant-syscall bypass classes
shipped in v1.9.2, and supervisor/target lifecycle coupling shipped in the live
Warden in v1.9.3.

Design and auditor notes live in
[`docs/verification/`](./docs/verification/README.md): the harness spec, corpus
schema, and one note per fragment.

## Testing

Language test suite — 659 passing across versions:

| Component | Tests |
|-----------|------:|
| v0.1 — Lexer + Parser + AST | 109 |
| v0.2 — Type System + HM Inference | 163 |
| v0.3 — LLVM Codegen | 97 |
| v0.4 — Standard Library | 182 |
| v1.0 — Package Manager + REPL | 108 |
| **Total** | **659** |

Runtime test suites are version-scoped and run clean under
`-fsanitize=address,undefined` — e.g. the v1.8.2 breaker (19/19) and the v1.9
progress-safety verifier (10/10). v1.9.1 enforcement is measured directly by a
TOCTOU race harness (`tests/seccomp_toctou_harness.c`): 510 sentinel leaks in
20,000 attempts for approve-then-continue versus 0 for resolve-and-inject, with
io_uring denial checked under the Warden filter. Build and run with `make check`
in the relevant version directory. Containment verification: `python
verify_guardrails.py` (see above).

## Security

**Reporting vulnerabilities.** Do not open public issues. Use
[GitHub private vulnerability reporting](https://github.com/kwdoug63/varek/security/advisories/new)
or [SECURITY.md](./SECURITY.md). Reports receive acknowledgment within 72 hours.

**Threat model and trusted computing base.** Adversary models, in-scope
guarantees, and out-of-scope conditions are documented in
[`docs/security/threat-model.md`](./docs/security/threat-model.md); the
per-component trusted-vs-verified status of the verification chain is in
[`docs/security/TRUSTED-COMPUTING-BASE.md`](./docs/security/TRUSTED-COMPUTING-BASE.md).
The cross-action data-flow threat model is in
[`docs/security/threat-model-dataflow.md`](./docs/security/threat-model-dataflow.md).
The runtime fails closed on unsupported platforms and denies boundary syscalls at
the kernel, not via string matching or audit hooks. As of v1.12 the Warden
filter is default-deny (an explicit allowlist, native ABI only, with a hard-deny
set that includes io_uring); network egress (`connect`) is deny-only pending the
v1.10 dial-and-inject path; and the agent runs in its own PID namespace, so it
and everything it spawned die with the supervisor. The per-class status is in
[`docs/security/bypass-classes.md`](./docs/security/bypass-classes.md).

**v1.1.0 fix.** Resolved a subprocess-escape weakness in v1.0's audit-hook-based
containment (issue #223, reported by @dengluozhang). See
[`VAREK_v1.1_SECURITY_UPDATE.md`](./VAREK_v1.1_SECURITY_UPDATE.md).

**Architecture review.** External review by QEEK-AI addressed AST-gate framing
(documented as UX-only, not a security boundary), a libc-binding fallback bug, and
platform-gating CI coverage (now macOS, Windows, Linux).

## Documentation

- **Spec paper:** [`varek-spec-paper-v1.12.md`](./varek-spec-paper-v1.12.md) — language and runtime specification, design rationale, the verdict model
- **Security:** [`docs/security/threat-model.md`](./docs/security/threat-model.md), [`docs/security/TRUSTED-COMPUTING-BASE.md`](./docs/security/TRUSTED-COMPUTING-BASE.md), [`docs/security/bypass-classes.md`](./docs/security/bypass-classes.md), [`RELEASE-v1.12.1.md`](./RELEASE-v1.12.1.md), [`RELEASE-v1.12.0.md`](./RELEASE-v1.12.0.md), [`RELEASE-v1.9.3.md`](./RELEASE-v1.9.3.md), [`RELEASE-v1.9.2.md`](./RELEASE-v1.9.2.md), [`RELEASE-v1.9.1.md`](./RELEASE-v1.9.1.md)
- **Verification notes:** [`docs/verification/`](./docs/verification/README.md) — the v1.10/v1.11 program
- **Changelog:** [`CHANGELOG.md`](./CHANGELOG.md)
- **Website:** [varek-lang.org](https://varek-lang.org)

## Community

- **Discussions:** [github.com/kwdoug63/varek/discussions](https://github.com/kwdoug63/varek/discussions)
- **Issues:** [github.com/kwdoug63/varek/issues](https://github.com/kwdoug63/varek/issues)
- **Releases:** [github.com/kwdoug63/varek/releases](https://github.com/kwdoug63/varek/releases)

## License

VAREK is open-source software licensed under the [MIT License](LICENSE).
Copyright (c) 2026 Sober Agentic Infrastructure, Inc. See [NOTICE](./NOTICE).

### Trademarks

CycloneDX is a trademark of the OWASP Foundation. VAREK and Sober Agentic
Infrastructure, Inc. are not affiliated with, endorsed by, or certified by the
OWASP Foundation or the CycloneDX project. The CycloneDX name is used only to
describe interoperability with the openly published CycloneDX format
(standardized as ECMA-424, with Apache-2.0-licensed schemas). All other product
names and marks are the property of their respective owners.

## Examples

- [Sandboxing an agent that downloads media](examples/agent_media_sandbox/README.md) — Warden-supervised media fetch with a policy auto-generated by `setup.sh`. Framework-agnostic (Hermes Agent, LangChain, etc.) and LLM-agnostic.
