# VAREK

### A statically-typed, LLVM-compiled gateway for deterministic AI execution.

## What is VAREK?
VAREK is an open-source, strictly-typed AI infrastructure gateway compiled via LLVM. It is designed to physically prevent rogue AI execution and hallucinated payloads at the consequence boundary. 

Where today's AI/ML workflows require stitching together probabilistic Python scripts, YAML configs, and dynamically-typed JSON payloads that fundamentally fail open, VAREK replaces them with a deterministic physics engine.

### The Consequence Boundary Problem
Modern enterprise pipelines execute high-stakes actions (database writes, financial trades, medical telemetry) using probabilistic LLM outputs serialized into JSON. This is an engineering dead end. You cannot secure probabilistic models with more probabilistic "LLM-as-a-judge" wrapper scripts. 

VAREK was built to enforce consequence boundaries. By utilizing strict Hindley-Milner type inference before the LLVM compilation step, VAREK mathematically validates AI payloads at the machine-code level. If an autonomous agent hallucinates a schema or a tensor shape, the circuit breaks. 

Physics, not probabilities.

## Core Design Principles

### 1. Speed by Default (Sub-50ms Latency)
VAREK compiles to native machine code via LLVM. Interpreted mode is available for rapid prototyping, but production pipelines run compiled. Benchmarks show 10–40x speedups over equivalent Python for data-heavy operations, ensuring boundary checks do not create pipeline bottlenecks.

### 2. Hindley-Milner Type Inference
Mathematically provable static typing without the syntactic bloat. Shape validation and memory safety are enforced *before* execution. 
* Memory safety enforced at compile time — no null pointer exceptions, no buffer overflows.
* Immutability by default; mutability is explicit and intentional.
* Checked error handling — errors cannot be silently ignored or dynamically bypassed.

### 3. Unified Boundary Syntax
VAREK syntax reads like structured English but compiles like C. The same file defines strict data schemas, pipeline logic, API contracts, and configuration. No context switching, no format translation, no JSON serialization vulnerabilities.

### 4. AI-Native Primitives
VAREK is the first compiled language designed with deterministic LLM collaboration in mind:
* Unambiguous grammar (no parsing edge cases for agent generation).
* Built-in tensor and matrix primitives.
* Native async/await for model inference backpressure.
* Pipeline operators (`|>`) for composing safe model chains.

## Syntax at a Glance

```varek
-- VAREK Sample: Safe Image Classification Pipeline

schema ImageInput {
    path: str,
    label: str?,
    resolution: (int, int)
}

pipeline classify_images {
    source: ImageInput[]
    steps: [
        preprocess -> normalize -> infer -> postprocess
    ]
    output: ClassificationResult[]
}

fn preprocess(img: ImageInput) -> Tensor {
    load_image(img.path)
        |> resize(224, 224)
        |> normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
}

fn infer(tensor: Tensor) -> RawOutput {
    model := load_model("resnet50.var")
    model.forward(tensor)
}

fn postprocess(raw: RawOutput) -> ClassificationResult {
    ClassificationResult {
        label: raw.top_class(),
        confidence: raw.softmax().max()
    }
}
```

*Compare this to the equivalent: a Python script, a YAML config, a JSON schema, and a shell script — VAREK replaces all four with mathematically provable boundaries.*

## Key Features

| Feature | Description |
| :--- | :--- |
| `pipeline` blocks | First-class pipeline definitions with statically-typed stages |
| `schema` types | Built-in data schema definitions (replaces JSON Schema, Pydantic) |
| `\|>` operator | Unix-style pipe chaining for data transformations |
| `async` inference | Native async model calls with strict backpressure support |
| `tensor` primitives | Built-in n-dimensional array type with shape validation |
| `safe` blocks | Explicit unsafe escape hatches (like Rust) |
| **Interop** | Import Python, C, and Rust libraries natively |
| **REPL** | Full interactive shell for pipeline exploration |

## Why Now?
The AI/ML tooling landscape is paralyzed by design debt. Tools built before the deep learning era were retrofitted to handle autonomous model pipelines. We are trusting trillion-parameter models to dynamically-typed glue code. 

JSON won because XML was bloated. Python won because C was inaccessible. VAREK wins because the current stack is a fail-open liability.

## Roadmap & Status
**659 tests passing • 13,006 lines of code • MIT License**

- [x] **v0.1** — Formal grammar spec + reference parser
- [x] **v0.2** — Type system + Hindley-Milner inference engine
- [x] **v0.3** — LLVM compilation backend + native code generation
- [x] **v0.4** — Standard library (`var::io`, `var::tensor`, `var::http`, `var::async`, `var::pipeline`)
- [x] **v1.0.0** — Stable release + `varek` package manager CLI + RFC governance process

## Community
[GitHub Discussions](https://github.com/kwdoug63/varek/discussions) is the official space for VAREK conversation.

---

## VAREK Security Command: CPython PEP 578 Intercept

While the core VAREK language compiles via LLVM, the deterministic runtime guardrails have been ported natively to Python via PEP 578 Audit Hooks to secure existing Agentic pipelines (e.g., xAI Grok, LangChain, AutoGen).

**Quick Start for Evaluation:**
To evaluate the PoCs in this repository, you do not need to install a full PyPI package. The keystone intercept logic is contained within the standalone `varek_warden.py` file.

1. Clone the repository and navigate to the root directory.
2. Ensure `varek_warden.py` is in the same directory as your execution script.
3. Arm the global runtime warden at the top of your agentic worker script:

```python
import sys
import varek_warden

# Arms the PEP 578 OS-Boundary Intercept
varek_warden.enforce_strict_mode()
\`\`\`
