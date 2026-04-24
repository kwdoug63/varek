# RFC 0002 — Tensor Shape Inference

| Field       | Value |
|-------------|-------|
| RFC Number  | 0002 |
| Title       | Tensor Shape Inference with Symbolic Dimensions |
| Author(s)   | Kenneth Wayne Douglas, MD |
| Status      | Implemented |
| Created     | 2025-10-15 |
| Discussion  | https://github.com/varek-lang/varek/discussions/2 |

---

## Summary

Extend the type system with symbolic tensor dimensions so that shape
mismatches are caught at compile time without requiring all shapes to
be known as literal constants.

---

## Motivation

ML pipelines frequently pass tensors through functions where the exact shape
depends on runtime input (batch size, sequence length, etc.). Without symbolic
dimensions, the type checker must either accept any shape (unsound) or reject
all variable-shape programs (impractical).

```varek
-- Without symbolic dims: can't type-check this at all
fn preprocess(img: Tensor<float, [3, 224, 224]>) -> Tensor<float, [2048]>
fn infer(emb: Tensor<float, [2048]>) -> Tensor<float, [1000]>

-- Rank mismatch should be caught:
fn wrong(t: Tensor<float, [768]>) -> Tensor<float, [1000]>
pipeline bad {
  source: ImageInput[]
  steps: [preprocess -> wrong -> infer]   -- [2048] ≠ [768]
  output: ClassResult[]
}
```

---

## Detailed Design

Introduce `Dim` as a first-class concept with two variants:

```python
@dataclass(frozen=True)
class Dim:
    value: Optional[int] = None   # concrete: Dim(224)
    var:   Optional[str] = None   # symbolic: Dim(var="d0")
```

Unification rules:
- `concrete == concrete` → must match exactly
- `symbolic == anything` → bind the variable
- `symbolic == symbolic` → unify (both become the same)

Shape checking happens independently of type unification since dimensions
are not part of the HM type variable system.

### Grammar changes

None — `Tensor<float, [768]>` syntax already exists.
Symbolic dimensions are introduced internally during inference.

### Breaking changes

None — previously unchecked programs are now checked. Programs with shape
mismatches that were incorrectly accepted will now produce errors.

---

## Implementation

Implemented in `varek/types.py` (Dim, TensorType) and
`varek/unify.py` (unify_dims). Status: ✅ Implemented in v0.2
