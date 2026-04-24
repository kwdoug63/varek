# VAREK v1.0
### AI Pipeline Programming Language

> *One language. Every stage of the AI pipeline. Stable.*

[![License: MIT](https://img.shields.io/badge/License-MIT-00ffe0.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-7c3aed.svg)]()
[![Tests](https://img.shields.io/badge/tests-108%20passed-22c55e.svg)]()
[![RFC Process](https://img.shields.io/badge/RFC-process-f59e0b.svg)](rfcs/)

---

## What's in v1.0 — Stable Release

| Component | Description |
|-----------|-------------|
| **`varek` Package Manager** | `varek new` / `varek run` / `varek build` / `varek install` / `varek publish` |
| **Package Format** | `.varekpkg` gzip-tar archives, `varek.toml` manifests, `varek.lock` lockfiles |
| **Registry** | Local + remote registry with semver resolution and checksum verification |
| **Interactive REPL** | `varek repl` with type inference, `:type`, `:env`, `:bench`, `:ir`, coloured output |
| **Formatter** | `varek fmt` — opinionated, deterministic source formatter |
| **Doc Generator** | `varek doc` — Markdown + HTML + JSON API index from doc comments |
| **Governance** | RFC process, contributor ladder, stability guarantees (see `docs/`) |
| **3 RFCs** | RFC-0001 Pipeline Types, RFC-0002 Tensor Shapes, RFC-0003 Package Format |

---

## Quick Start

```bash
# Create a project
varek new my-pipeline
cd my-pipeline

# Run it
varek run

# Start the REPL
varek repl
```

---

## Package Manager

### varek new

```bash
varek new my-project       # scaffold a complete project
varek init                 # add varek.toml to an existing directory
```

Creates:
```
my-project/
├── varek.toml             ← manifest
├── src/main.syn
├── tests/test_main.syn
├── benchmarks/
├── docs/
└── README.md
```

### varek.toml

```toml
[package]
name        = "my-pipeline"
version     = "1.0.0"
authors     = ["Kenneth Wayne Douglas, MD"]
license     = "MIT"
description = "An AI/ML pipeline"
varek     = ">=1.0.0"

[dependencies]
"core-utils" = "^1.0.0"

[build]
target    = "interpret"    # or "native"
opt_level = 2

[scripts]
main  = "src/main.syn"
test  = "tests/run.syn"
```

### Build & Run

```bash
varek run                  # interpreted (fast startup)
varek build                # compile to LLVM IR / native object
varek check                # type-check only
varek test                 # run tests/
varek bench                # run benchmarks/
varek clean                # remove build artifacts
```

### Dependencies

```bash
varek add "core-utils"           # add dependency to varek.toml
varek add "test-helpers" --dev   # dev dependency
varek remove "core-utils"        # remove dependency
varek install                    # install all dependencies
varek update                     # update to latest compatible versions
```

### Registry

```bash
varek search "tensor"            # search the registry
varek info "core-utils"          # package details
varek publish                    # publish to registry
varek registry update            # refresh the index
```

---

## REPL

```
varek repl

VAREK v1.0.0 — AI Pipeline Programming Language
Kenneth Wayne Douglas, MD

Type :help for commands · :quit to exit

>>> let x = 42
  · x = 42
>>> fn double(n: int) -> int { n * 2 }
>>> double(x)
  = 84
>>> import var::tensor
>>> tensor.randn([3, 4])
  = Tensor[3×4, float64]
>>> :type tensor.zeros([768])
  tensor.zeros([768]) : Tensor<float, [768]>
>>> :bench fib(30)
  Benchmark (10 runs)
  mean: 1.234ms  best: 1.102ms
```

---

## Doc Comments

```varek
---
Compute the Fibonacci number for n.

Arguments:
  n: int — the input value (must be >= 0)

Returns: int — the nth Fibonacci number

Example:
  fib(10)   -- 55
  fib(20)   -- 6765
---
fn fib(n: int) -> int {
  if n <= 1 { n } else { fib(n-1) + fib(n-2) }
}
```

```bash
varek doc                        # generates docs/ with Markdown
varek doc --format html          # HTML documentation
varek doc --format both          # both formats + api.json
```

---

## RFC Process

Language changes go through the RFC process:

1. Open a GitHub Discussion in the RFC category
2. Copy `docs/RFC_TEMPLATE.md`, fill it out
3. File as `rfcs/NNNN-short-title.md`
4. 2-week review period
5. 1-week Final Comment Period
6. Core Team vote → Accepted / Rejected

See `docs/GOVERNANCE.md` for the full process.

**Implemented RFCs:**
- [RFC-0001](rfcs/0001-pipeline-type-verification.md) — Pipeline type verification
- [RFC-0002](rfcs/0002-tensor-shape-inference.md) — Tensor shape inference
- [RFC-0003](rfcs/0003-package-format.md) — Package format

---

## Complete Version History

| Version | Highlights |
|---------|-----------|
| **v0.1** | Formal grammar (EBNF), lexer, recursive-descent parser — 109 tests |
| **v0.2** | Hindley-Milner type inference, HM Algorithm W, schema validation — 163 tests |
| **v0.3** | LLVM IR codegen (libLLVM-20 via ctypes), native assembly/object emit — 97 tests |
| **v0.4** | Standard library: 7 modules, 261 functions (io/tensor/http/async/pipeline/model/data) — 182 tests |
| **v1.0** | Package manager (`varek` CLI), REPL, formatter, doc gen, governance — 108 tests |

**Cumulative test count: 659 tests across all versions.**

---

## Stability Guarantee (v1.0+)

VAREK v1.0 commits to:
- **No breaking syntax changes** without an RFC and a major version bump
- **Stable standard library API** (`syn::*` modules)
- **Stable package format** (`.varekpkg`, `varek.toml`, `varek.lock`)
- **Semver** for all versioned artifacts

See `docs/GOVERNANCE.md` for the full stability policy.

---

## License

MIT — *Kenneth Wayne Douglas, MD*

*"The language that treats AI pipelines as first-class citizens."*
