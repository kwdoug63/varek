# VAREK

### Deterministic pre-execution verification of AI agent actions, enforced at the kernel.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/language-v1.0%20stable-blue.svg)](https://github.com/kwdoug63/varek/releases)
[![Runtime](https://img.shields.io/badge/runtime-v1.9.0-green.svg)](https://github.com/kwdoug63/varek/releases)
[![Verdict](https://img.shields.io/badge/verdict-SATISFIED%20%7C%20UNSATISFIED%20%7C%20UNKNOWN-7a5cff.svg)](#the-verdict-model)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **Reporting vulnerabilities:** [private vulnerability reporting](https://github.com/kwdoug63/varek/security/advisories/new) or [SECURITY.md](./SECURITY.md). Do not open public issues.

## What VAREK is

VAREK decides whether an AI agent's planned actions are allowed **before** they
execute, and enforces that decision at the kernel boundary.

An agent's intended actions are represented as an **action-graph** — a directed
acyclic graph of planned actions. An **SMT decision procedure** evaluates that
graph against a policy and returns one of three verdicts: **SATISFIED**,
**UNSATISFIED**, or **UNKNOWN**. The **Warden** runtime carries that verdict to
the kernel (via `seccomp-unotify` / eBPF) and refuses any disallowed syscall
before it lands. The check is pre-execution: an action that cannot be proven
allowed never runs.

The design premise is a clinical one: you do not deploy a system that is
*usually* right when the cost of being wrong is unbounded. UNKNOWN is therefore a
first-class verdict, not an error path — VAREK never coerces "cannot prove safe"
into a pass.

VAREK has two layers, developed in sequence:

1. **The Warden runtime** — the verification and enforcement layer. It is where
   active development lives and where the verification thesis above is realized.
   **Current release: v1.9.0.**
2. **VAREK the language** — a statically-typed, LLVM-compiled language for AI/ML
   pipelines, where unsafe operations are not expressible in the first place.
   **Stable at v1.0.**

The runtime can protect any agent stack (LangChain, AutoGen, CrewAI, custom
orchestrators). The language is for pipelines you write fresh. They are useful
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

See [`CHANGELOG.md`](./CHANGELOG.md) for the full v1.0–v1.9 history.

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
description is in the [spec paper](./varek-spec-paper-v1.9.md).

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

```
  Your AI workload
  ----------------

  VAREK (.varek)                 Python agent code
  typed, LLVM-compiled           (LangChain, AutoGen,
  unsafe ops inexpressible        CrewAI, custom ...)
        |                                |
        |                          action-graph
        |                                |
        |                                v
        |                    +------------------------+
        |                    | SMT decision procedure |
        |                    | -> SATISFIED /         |
        |                    |    UNSATISFIED /        |
        |                    |    UNKNOWN              |
        |                    +-----------+------------+
        |                                |
        |                                v
        |                    +------------------------+
        |                    | Warden runtime         |
        |                    | kernel enforcement     |
        |                    | (seccomp-unotify/eBPF) |
        |                    | fail closed            |
        |                    +------------------------+
        v
  native binary (runs directly)
```

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
- [ ] **v1.10 (planned)** — The UNKNOWN-shrinking program (below)
- [ ] **v1.11 (candidate)** — Bounded sequence fragment for cross-action data-flow

### Language

- [x] **v0.1–v0.4** — Grammar + parser, HM type system, LLVM backend, standard library
- [x] **v1.0** — Stable release, package manager, RFC process

## The verification program (v1.10 / v1.11)

> **Planned and candidate work, not shipped.** No v1.10 or v1.11 tag exists. This
> documents direction; shipped behavior is in [`CHANGELOG.md`](./CHANGELOG.md).

The post-v1.9 program has a single goal: migrate cases out of the UNKNOWN verdict
into a provable verdict, raising the clear rate on safe agent actions — under a
hard invariant that **no extension may ever move a genuinely unsafe action into
SATISFIED.** "Cannot prove safe" stays UNSATISFIED/UNKNOWN.

The program proceeds by adding small, individually-auditable decidable fragments,
each with one named soundness obligation and the trusted code it introduces:

- **v1.10 step 1 — verdict-distribution harness + corpus.** The measurement
  baseline. Hard gate: zero unsafe authorizations across the corpus.
- **v1.10 step 2 — bitvector fragment.** Decidable reasoning over fixed-width
  syscall flag/argument bits. Lowest audit cost.
- **v1.10 step 3 — bounded string fragment (headline).** Length-bounded
  path-prefix and host-allowlist predicates made provable instead of refused.
- **v1.11 candidate — bounded sequence fragment.** Element-level reasoning for the
  cross-action data-flow subsystem, composed on the fragments above.

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
progress-safety verifier (10/10). Build and run with `make check` in the relevant
version directory. Containment verification: `python verify_guardrails.py` (see
above).

## Security

**Reporting vulnerabilities.** Do not open public issues. Use
[GitHub private vulnerability reporting](https://github.com/kwdoug63/varek/security/advisories/new)
or [SECURITY.md](./SECURITY.md). Reports receive acknowledgment within 72 hours.

**Threat model.** In-scope and out-of-scope threats are documented in
[`docs/security/threat-model.md`](./docs/security/threat-model.md), with the
cross-action data-flow threat model in
[`docs/security/threat-model-dataflow.md`](./docs/security/threat-model-dataflow.md).
The runtime fails closed on unsupported platforms and denies boundary syscalls at
the kernel, not via string matching or audit hooks.

**v1.1.0 fix.** Resolved a subprocess-escape weakness in v1.0's audit-hook-based
containment (issue #223, reported by @dengluozhang). See
[`VAREK_v1.1_SECURITY_UPDATE.md`](./VAREK_v1.1_SECURITY_UPDATE.md).

**Architecture review.** External review by QEEK-AI addressed AST-gate framing
(documented as UX-only, not a security boundary), a libc-binding fallback bug, and
platform-gating CI coverage (now macOS, Windows, Linux).

## Documentation

- **Spec paper:** [`varek-spec-paper-v1.9.md`](./varek-spec-paper-v1.9.md) — language and runtime specification, design rationale, the verdict model
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

## Examples

- [Sandboxing an agent that downloads media](examples/agent_media_sandbox/README.md) — Warden-supervised media fetch with a policy auto-generated by `setup.sh`. Framework-agnostic (Hermes Agent, LangChain, etc.) and LLM-agnostic.
