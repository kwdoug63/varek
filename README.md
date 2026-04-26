# VAREK

### A statically-typed AI pipeline language, with a Python runtime containment layer for agentic workloads.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Compiler: v1.0](https://img.shields.io/badge/compiler-v1.0-blue.svg)](https://github.com/kwdoug63/varek/releases)
[![Guardrails: v1.1.1](https://img.shields.io/badge/guardrails-v1.1.1-green.svg)](https://github.com/kwdoug63/varek/releases/tag/v1.1.1)
[![Tests: 659 passing](https://img.shields.io/badge/tests-659%20passing-brightgreen.svg)](#testing)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **Reporting vulnerabilities:** [private vulnerability reporting](https://github.com/kwdoug63/varek/security/advisories/new) or [SECURITY.md](./SECURITY.md). Do not open public issues.

VAREK consists of two things:

1. **VAREK the language** — a statically-typed, Hindley-Milner-inferred, LLVM-compiled programming language purpose-built for AI/ML pipelines. Schema, logic, pipeline, and configuration live in one file with one syntax. **Stable at v1.0.** 659 tests passing across versions.

2. **VAREK Guardrails** — a Python runtime containment layer that bounds untrusted code at the kernel. For any agentic workload that can't be rewritten in VAREK (most existing LangChain, AutoGen, Weave, CrewAI codebases), Guardrails sits between the agent framework and the OS, denying `execve` and other boundary syscalls at the kernel before a prompt-injected payload can act. **Current release v1.1.1.**

The two layers can be used independently or together. If you're starting a new AI pipeline, write it in VAREK. If you're protecting an existing Python-based agent stack, install Guardrails. If you're doing both, VAREK pipelines running alongside Guardrails-contained Python agents is the end-state architecture.

## Layer 1 — VAREK the language

### Why a new language

Modern AI pipelines stitch together four tools: Python for logic, YAML for configuration, JSON Schema for validation, and shell for orchestration. Each format boundary erases type information. Schema drift, silent coercion errors, and "works on my machine" failures follow. VAREK replaces all four with one typed language.

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

Equivalent Python requires four files in two languages. See the [spec paper](./VAREK-Spec-Paper-Douglas.pdf) for the full language description.

### Installing the compiler

The compiler is distributed as versioned release archives. Each zip is a self-contained milestone:

```bash
git clone https://github.com/kwdoug63/varek.git
cd varek
unzip varek-v1.0.zip -d compiler/
cd compiler/varek-v1.0
python varek_cli.py --help
```

Available versions: `varek-v0.1.zip` (lexer + parser), `varek-v0.2.zip` (type system + HM inference), `varek-v0.3.zip` (LLVM codegen), `varek-v0.4.zip` (standard library), `varek-v1.0.zip` (stable + package manager).

### The `varek` CLI (20 commands)

```
varek new <name>          Create a new VAREK project
varek build               Build the current project
varek run [script]        Run the project (default: main script)
varek check               Type-check without running
varek test                Run tests
varek bench               Run benchmarks
varek repl                Start the interactive REPL
varek fmt [path]          Format source files
varek doc                 Generate documentation
varek install [pkg]       Install dependencies
varek publish             Package and publish to registry
varek search <query>      Search the package registry
varek add <pkg>           Add a dependency
varek remove <pkg>        Remove a dependency
varek update              Update all dependencies
varek clean               Remove build artifacts
varek init                Initialize varek.toml
varek info <pkg>          Show package information
varek registry update     Refresh the registry index
varek version             Show version information
```

### Core language features

| Feature | Description |
|---------|-------------|
| **LLVM backend** | Native code generation via direct `ctypes` bindings to `libLLVM-20`. SSA form, phi nodes, full optimization passes. |
| **Hindley-Milner inference** | Algorithm W, Robinson unification with occurs check, let-polymorphism. Types inferred across module boundaries. |
| **Tensor types** | First-class `Tensor<T, D>` with symbolic dimension tracking and shape-compatibility checking at compile time. |
| **Pipeline operator** | `\|>` for linear composition. `x \|> f \|> g` desugars to `g(f(x))`. |
| **Schema types** | Structural typing, optional fields, runtime `SchemaValidator`. Replaces JSON Schema and Pydantic. |
| **Result types** | `Result<T>` for errors-as-values. The `?` operator propagates errors without hiding them. |
| **Native async** | First-class `async fn` with channels, futures, parallel_map, mutex, atomic. |
| **Python/C/Rust interop** | `import python::numpy as np` — typed FFI for the existing ML ecosystem. |

### Standard library (261 functions across 7 modules)

`var::io` (41 fns: files, paths, streams, env) · `var::tensor` (111 fns: linear algebra, activations, distance) · `var::http` (19 fns: client + server) · `var::async` (32 fns: channels, futures, mutex, atomic) · `var::pipeline` (15 fns: execution engine, combinators) · `var::model` (14 fns: inference, embeddings, tokenization) · `var::data` (29 fns: CSV/JSON/NPY, splits, metrics).

## Layer 2 — VAREK Guardrails

### Why a runtime containment layer

Most agentic code in production today is Python — LangChain, AutoGen, Weave, CrewAI, and the long tail of custom orchestrators. Rewriting those in VAREK is not realistic for most teams. But those systems are where prompt-injection attacks actually reach execution: an LLM emits code, a tool call, or a grading payload that then runs in your Python process with your environment variables in scope.

Guardrails bounds that execution at the kernel. When the contained code attempts `execve`, `subprocess.run`, or network egress, the kernel refuses before the syscall lands. This is structural containment — not a string-match denylist that can be bypassed with absolute paths, base64 encoding, or renamed binaries.

### Installation

```bash
git clone https://github.com/kwdoug63/varek.git
cd varek
pip install -e ".[dev]"
```

**Production requirements (for kernel-enforced containment):**

- Linux with cgroups v2 mounted
- `libseccomp` python binding (`pyseccomp` or `python3-libseccomp`)
- Unprivileged user namespaces enabled
- `/sys/fs/cgroup/varek.slice` writable by the test user

Guardrails will **fail closed** if these requirements are unmet. The package installs and imports cleanly everywhere, but `SeccompBpfBackend.is_available()` returns an explanatory string on non-Linux hosts or environments without kernel support. No silent degradation.

### Verify your installation

After installing, run:

```bash
python verify_guardrails.py
```

This exercises every public entry point through an eight-step verification. In most environments (including GitHub Codespaces), steps 1, 2, 3, 5, 6 will **PASS** and steps 4, 7, 8 will **SKIP** with the explanation `SeccompBpfBackend unavailable — cannot exercise kernel boundary`. The SKIP pattern is itself a correctness property — the backend refuses to initialize rather than silently running without containment. To convert the three SKIPs to PASSes, run on a Linux host meeting the production requirements above.

### Guardrails quick start

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
    # ExecutionOutcome surfaces containment via these three fields, not
    # via exception. stdout/stderr are bytes.
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
    # policy malformed). Ordinary containment events surface on the
    # ExecutionOutcome above, not as exceptions.
    print(f"orchestration error: {e}")
```

### Guardrails integration demos

Twenty numbered `.py` and `.ipynb` files demonstrate Guardrails applied to popular agent frameworks and production surfaces. Each demo follows the same `Target / Vector / Defense` pattern and is runnable end-to-end.

| File | Surface |
|------|---------|
| `04-huggingface-smolagents-sandbox.ipynb` | Hugging Face smolagents |
| `05-openai-gpt4o-varek-hardened.ipynb` | OpenAI GPT-4o tool-calling |
| `06-crewai-gemini-ast-intercept.ipynb` | CrewAI + Gemini |
| `07-bare-metal-mobile-intercept.py` | Edge inference |
| `08-autogen-local-executor-intercept.py` | Microsoft AutoGen |
| `09-prefect-task-intercept.py` | Prefect task orchestration |
| `15-xai-grok-firehose-intercept.py` | xAI Grok firehose |
| `16-wandb-pipeline-verification-intercept.py` | Weights & Biases + Weave evals |
| `17-meta-llama-agent-intercept.py` | Meta Llama agent loop |
| `18-palo-alto-xsoar-intercept.py` | Palo Alto XSOAR |
| `19-zscaler-ai-data-intercept.py` | Zscaler AI data plane |
| `24-nvidia-intercept.py` | NVIDIA inference pipeline |

Files numbered 10-14 and 20-23 illustrate Guardrails patterns for regulated-industry deployments (federal edge, enterprise financial, SOC triage). Those files are engineering demonstrations of containment patterns, not statements of customer relationships.

## How the layers compose

```
┌──────────────────────────────────────────────────────────────┐
│  Your AI pipeline                                            │
│                                                              │
│  ┌──────────────────────┐       ┌──────────────────────┐     │
│  │ VAREK (.varek files) │       │ Python agent code    │     │
│  │ Compiled via LLVM    │       │ (LangChain, AutoGen, │     │
│  │ Type-safe pipelines  │       │  Weave, CrewAI, ...) │     │
│  └──────────┬───────────┘       └──────────┬───────────┘     │
│             │                              │                 │
│             │                              ▼                 │
│             │                  ┌──────────────────────┐      │
│             │                  │ varek_guardrails     │      │
│             │                  │ (Python package)     │      │
│             │                  │ configure_backend,   │      │
│             │                  │ execute_untrusted,   │      │
│             │                  │ subscribe_telemetry  │      │
│             │                  └──────────┬───────────┘      │
│             │                             │                  │
│             │                             ▼                  │
│             │                  ┌─────────────────────────┐   │
│             │                  │ SeccompBpfBackend       │   │
│             │                  │ (kernel-level)          │   │
│             │                  └─────────────────────────┘   │
│             │                                                │
│             ▼                                                │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ Native binary via LLVM → runs directly               │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

VAREK pipelines are statically verified at compile time — they don't need runtime containment because unsafe operations aren't expressible. Python agent code needs containment because the language allows arbitrary dynamic behavior. The two layers address different kinds of risk at different points in the stack.

## Roadmap

### Language

- [x] **v0.1** — Formal grammar + reference parser (109 tests)
- [x] **v0.2** — Type system + Hindley-Milner inference (163 tests)
- [x] **v0.3** — LLVM compilation backend (97 tests)
- [x] **v0.4** — Standard library, 7 modules, 261 functions (182 tests)
- [x] **v1.0** — Stable release + package manager + RFC process (108 tests)

### Guardrails

- [x] **v1.0** — PEP 578 audit-hook enforcement
- [x] **v1.1.0** — Kernel-enforced containment via `SeccompBpfBackend`; fixes subprocess-escape weakness (issue #223)
- [x] **v1.1.1** — Warden orchestration layer (`configure_backend`, `execute_untrusted`, `subscribe_telemetry`), package wrapper, PEP 621 metadata
- [ ] **v1.2** — Policy composition and capability-type declarations
- [ ] **v1.3** — Additional backends (gVisor, bubblewrap, Windows Job Objects)

## Testing

659 tests passing across all versions:

| Component | Tests | Lines |
|-----------|------:|------:|
| v0.1 — Lexer + Parser + AST | 109 | 2,546 |
| v0.2 — Type System + HM Inference | 163 | 5,562 |
| v0.3 — LLVM Codegen | 97 | 7,792 |
| v0.4 — Standard Library | 182 | 11,097 |
| v1.0 — Package Manager + REPL | 108 | 13,006 |
| **Total** | **659** | **13,006** |

Guardrails verification: `python verify_guardrails.py` (see the section above).

## Security

**Reporting vulnerabilities.** Do not open public issues for security
issues. Use [GitHub private vulnerability reporting](https://github.com/kwdoug63/varek/security/advisories/new)
or follow the procedure in [SECURITY.md](./SECURITY.md). All reports
receive an acknowledgment within 72 hours.

**Threat model.** In-scope and out-of-scope threats are documented in
[`docs/security/threat-model.md`](./docs/security/threat-model.md).
The Guardrails layer is designed to fail closed on unsupported platforms
and to deny boundary syscalls (`execve`, network egress, file system
writes outside the working directory) at the kernel — not via string
matching or audit hooks.

**v1.1.0 fix.** Resolved a subprocess-escape weakness in v1.0's
audit-hook-based containment (issue #223, reported by @dengluozhang).
Regression tests in [`tests/security/test_issue_223_regression.py`](./tests/security/test_issue_223_regression.py)
must fail to execute under the default policy on a conforming host.
See [`VAREK_v1.1_SECURITY_UPDATE.md`](./VAREK_v1.1_SECURITY_UPDATE.md)
for full details.

**Architecture review.** External architecture review by QEEK-AI
addressed three items: AST-gate framing (now documented as UX-only,
not a security boundary), libc binding fallback (caught a real bug),
and platform-gating CI coverage (now running on macOS, Windows, Linux).

## Documentation

- **Spec paper:** [`VAREK-Spec-Paper-Douglas.pdf`](./VAREK-Spec-Paper-Douglas.pdf) — formal language specification, design rationale, grammar, type system
- **Data room:** [`varek-data-room.html`](./varek-data-room.html) — complete release archive with version history
- **Changelog:** [`CHANGELOG.md`](./CHANGELOG.md)
- **Website:** [varek-lang.org](https://varek-lang.org)

## Community

- **Discussions:** [github.com/kwdoug63/varek/discussions](https://github.com/kwdoug63/varek/discussions)
- **Issues:** [github.com/kwdoug63/varek/issues](https://github.com/kwdoug63/varek/issues)
- **Releases:** [github.com/kwdoug63/varek/releases](https://github.com/kwdoug63/varek/releases)

## License

MIT — see [LICENSE](./LICENSE). Copyright © 2025–2026 Kenneth Wayne Douglas, MD.
