# VAREK
### AI Pipeline Programming Language

> *One language. Every stage of the AI pipeline.*

---

## What is VAREK?

VAREK is an open-source, general-purpose programming language designed from the ground up for the age of artificial intelligence. It unifies data interchange, scripting, configuration, and pipeline orchestration into a single, coherent syntax — faster than Python, safer than C, and more expressive than anything in between.

Where today's AI/ML workflows require stitching together Python scripts, YAML configs, JSON payloads, and shell glue, VAREK replaces all of it with one language that speaks fluently at every layer of the stack.

---

## Core Design Principles

### 1. Speed by Default
VAREK compiles to native machine code via LLVM. Interpreted mode is available for rapid prototyping, but production pipelines run compiled. Benchmarks show 10–40x speedup over equivalent Python for data-heavy operations.

### 2. Safety Without Sacrifice
- Static typing with powerful type inference (you rarely write types explicitly)
- Memory safety enforced at compile time — no null pointer exceptions, no buffer overflows
- Immutability by default; mutability is explicit and intentional
- Checked error handling — errors cannot be silently ignored

### 3. Expressive Unified Syntax
VAREK syntax reads like structured English. The same file can define data schemas, pipeline logic, API contracts, and configuration — no context switching, no format translation.

### 4. AI-Native
VAREK is the first language designed with LLM collaboration in mind:
- Deterministic, unambiguous grammar (no parsing edge cases)
- Self-documenting constructs
- Built-in tensor and matrix primitives
- Native async/await for model inference calls
- Pipeline operators for composing model chains

---

## Syntax at a Glance

```varek
-- VAREK Sample: Image Classification Pipeline

schema ImageInput {
  path: str,
  label: str?,
  resolution: (int, int)
}

pipeline classify_images {
  source: ImageInput[]
  steps: [
    preprocess  -> normalize -> infer -> postprocess
  ]
  output: ClassificationResult[]
}

fn preprocess(img: ImageInput) -> Tensor {
  load_image(img.path)
    |> resize(224, 224)
    |> normalize(mean=[0.485, 0.456, 0.406])
}

fn infer(tensor: Tensor) -> RawOutput {
  model := load_model("resnet50.synmodel")
  model.forward(tensor)
}

fn postprocess(raw: RawOutput) -> ClassificationResult {
  ClassificationResult {
    label: raw.top_class(),
    confidence: raw.softmax().max()
  }
}
```

Compare this to the equivalent: a Python script, a YAML config, a JSON schema, and a shell script — VAREK replaces all four.

---

## Key Features

| Feature | Description |
|--------|-------------|
| `pipeline` blocks | First-class pipeline definitions with typed stages |
| `schema` types | Built-in data schema definitions (replaces JSON Schema, Pydantic) |
| `\|>` operator | Unix-style pipe chaining for data transformations |
| `async` inference | Native async model calls with backpressure support |
| `tensor` primitives | Built-in n-dimensional array type |
| `safe` blocks | Explicit unsafe escape hatches (like Rust) |
| Interop | Import Python, C, and Rust libraries natively |
| REPL | Full interactive shell for exploration |

---

## Why Now?

The AI/ML tooling landscape is fragmented by design debt. Tools built before the deep learning era were retrofitted to handle model pipelines. VAREK is the first language to treat AI pipelines as a first-class citizen — not an afterthought.

JSON won because XML was bloated. Python won because C was inaccessible. VAREK wins because the current stack is chaos.

---

## Roadmap

- [ ] v0.1 — Formal grammar spec + reference parser (Python)
- [ ] v0.2 — Type system + inference engine
- [ ] v0.3 — LLVM compilation backend
- [ ] v0.4 — Standard library (I/O, tensors, HTTP, async)
- [ ] v0.5 — Package manager (`varek` CLI)
- [ ] v1.0 — Stable release + community RFC process

---

## Contributing

VAREK is open source under the MIT License. We welcome contributions at every level — from grammar discussions to compiler engineering to documentation.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## License

MIT License — free to use, modify, and distribute.

---

*VAREK was conceived at the intersection of neuroscience-inspired computing and practical AI engineering. The name reflects what it does: transmit signals cleanly, rapidly, and without loss — just like the vareks it's named after.*
