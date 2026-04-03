# VAREK Language Specification
## Version 0.1 — Draft

---

## 1. Overview

VAREK (Synthetic Neural API & Pipeline Scripting Engine) is a statically typed, compiled, general-purpose programming language optimized for AI/ML pipeline authoring. It provides a unified syntax for data schemas, transformation logic, pipeline orchestration, and system configuration.

---

## 2. Lexical Structure

### 2.1 Comments
```
-- Single line comment
--- Multi-line
    comment block
---
```

### 2.2 Identifiers
Identifiers begin with a letter or underscore, followed by letters, digits, or underscores.
```
identifier ::= [a-zA-Z_][a-zA-Z0-9_]*
```

### 2.3 Keywords
```
fn        schema    pipeline  let       mut
if        else      match     for       in
return    async     await     safe      import
from      as        true      false     nil
```

### 2.4 Literals
```
integer   ::= [0-9]+
float     ::= [0-9]+ '.' [0-9]+
string    ::= '"' [^"]* '"'
bool      ::= 'true' | 'false'
nil       ::= 'nil'
```

---

## 3. Type System

### 3.1 Primitive Types
| Type | Description | Example |
|------|-------------|---------|
| `int` | 64-bit signed integer | `42` |
| `float` | 64-bit IEEE 754 | `3.14` |
| `str` | UTF-8 string | `"hello"` |
| `bool` | Boolean | `true` |
| `nil` | Absence of value | `nil` |

### 3.2 Compound Types
```varek
-- Optional (nullable)
x: str?

-- Tuple
coords: (int, int, int)

-- Array
labels: str[]

-- Map
config: {str: float}

-- Tensor (AI-native)
weights: Tensor<float, [768, 512]>
```

### 3.3 Schema Types
Schemas are named, structured types with optional fields:
```varek
schema ModelConfig {
  name:        str,
  version:     str,
  max_tokens:  int,
  temperature: float,
  tags:        str[]?
}
```

### 3.4 Type Inference
VAREK infers types in most contexts. Explicit annotation is optional but encouraged for public APIs:
```varek
let x = 42          -- inferred: int
let y = "varek"   -- inferred: str
let z = [1, 2, 3]   -- inferred: int[]
```

---

## 4. Functions

### 4.1 Function Declaration
```varek
fn add(a: int, b: int) -> int {
  a + b   -- last expression is implicit return
}
```

### 4.2 Async Functions
```varek
async fn fetch_embedding(text: str) -> Tensor {
  result := await model.embed(text)
  result.normalize()
}
```

### 4.3 Anonymous Functions (Lambdas)
```varek
let square = |x: int| -> int { x * x }
let double = |x| x * 2   -- type inferred
```

---

## 5. Pipeline Operator

The `|>` operator passes the result of the left expression as the first argument to the right function:

```varek
"Hello World"
  |> tokenize()
  |> embed()
  |> normalize()
  |> store(db)
```

This is semantically equivalent to:
```varek
store(normalize(embed(tokenize("Hello World"))), db)
```

---

## 6. Pipeline Blocks

Pipeline blocks define named, typed data transformation workflows:

```varek
pipeline text_to_embedding {
  source: str[]
  steps: [tokenize -> embed -> normalize -> store]
  output: EmbeddingResult[]
  
  config {
    batch_size: 32,
    parallelism: 8
  }
}
```

Pipeline stages must be functions whose input type matches the output type of the preceding stage. Type mismatches are caught at compile time.

---

## 7. Control Flow

### 7.1 Conditionals
```varek
if score > 0.9 {
  "high confidence"
} else if score > 0.5 {
  "medium confidence"
} else {
  "low confidence"
}
```

### 7.2 Match Expressions
```varek
match status {
  "ok"    => process(data),
  "error" => log_error(data),
  _       => discard()
}
```

### 7.3 Iteration
```varek
for item in dataset {
  process(item)
}
```

---

## 8. Error Handling

Errors in VAREK are values, not exceptions. Functions that can fail return a `Result<T>` type:

```varek
fn load_model(path: str) -> Result<Model> {
  if not file_exists(path) {
    return Err("Model file not found: " + path)
  }
  Ok(Model.from_file(path))
}

-- Caller must handle the result
match load_model("resnet50.synmodel") {
  Ok(model)  => model.infer(input),
  Err(msg)   => log(msg)
}
```

The `?` operator propagates errors up the call stack:
```varek
fn run_pipeline(path: str) -> Result<Output> {
  let model = load_model(path)?   -- propagates Err if it occurs
  let result = model.infer(data)?
  Ok(result)
}
```

---

## 9. Memory Model

- All values are immutable by default
- `mut` keyword grants mutability within a scope
- No manual memory management; reference-counted with cycle detection
- `safe` blocks enforce strict ownership semantics (Rust-compatible FFI)

```varek
let x = 42          -- immutable
mut let y = 0       -- mutable
y = y + 1           -- allowed
```

---

## 10. Interoperability

### 10.1 Python Interop
```varek
import python::numpy as np
import python::transformers::AutoModel

let model = AutoModel.from_pretrained("bert-base-uncased")
```

### 10.2 C/Rust FFI
```varek
safe import c::libc::malloc
safe import rust::tokenizers::Tokenizer
```

---

## 11. Module System

```varek
-- math/stats.syn
export fn mean(xs: float[]) -> float {
  xs.sum() / xs.len() as float
}

-- main.syn
from math::stats import mean

let avg = mean([1.0, 2.0, 3.0])
```

---

## 12. Standard Library (Planned)

| Module | Contents |
|--------|----------|
| `var::io` | File, stream, network I/O |
| `var::tensor` | Tensor operations, linear algebra |
| `var::http` | HTTP client/server |
| `var::async` | Async runtime, channels, promises |
| `var::schema` | Schema validation, serialization |
| `var::pipeline` | Pipeline execution engine |
| `var::model` | Model loading, inference |
| `var::data` | Dataset loading, batching |

---

## 13. Grammar (EBNF Summary)

```ebnf
program     ::= statement*
statement   ::= fn_decl | schema_decl | pipeline_decl | let_stmt | expr_stmt
fn_decl     ::= 'async'? 'fn' ident '(' params ')' '->' type block
schema_decl ::= 'schema' ident '{' field* '}'
pipeline_decl ::= 'pipeline' ident '{' pipeline_body '}'
let_stmt    ::= 'mut'? 'let' ident (':' type)? '=' expr
expr        ::= literal | ident | call | pipe | block | if_expr | match_expr
pipe        ::= expr '|>' expr
block       ::= '{' statement* expr? '}'
type        ::= base_type ('?' | '[]' | '<' type_args '>')?
```

---

*This specification is a living document. Community RFCs are welcome via GitHub Discussions.*

*VAREK Language Specification — Draft v0.1*
*Open Source — MIT License*
