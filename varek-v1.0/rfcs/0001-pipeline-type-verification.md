# RFC 0001 — Pipeline Type Verification

| Field       | Value |
|-------------|-------|
| RFC Number  | 0001 |
| Title       | Pipeline Type Verification |
| Author(s)   | Kenneth Wayne Douglas, MD |
| Status      | Implemented |
| Created     | 2025-10-01 |
| Updated     | 2025-11-15 |
| Discussion  | https://github.com/varek-lang/varek/discussions/1 |

---

## Summary

Introduce compile-time type checking for `pipeline` declarations, ensuring
that the output type of each step is compatible with the input type of the
next step before any code is executed.

---

## Motivation

Without type verification, a pipeline step returning `str` followed by a step
expecting `Tensor` would silently produce a runtime error deep inside the
pipeline. This is the primary pain point VAREK was built to solve.

```varek
-- Without this RFC: runtime error, not caught at compile time
fn step_a(x: int) -> str { str(x) }
fn step_b(t: Tensor<float, [768]>) -> bool { true }

pipeline bad {
  source: int[]
  steps: [step_a -> step_b]   -- str ≠ Tensor<float, [768]>  ← not caught!
  output: bool[]
}
```

---

## Detailed Design

The type checker walks the steps array in order:
1. Resolve `source_type` (unwrapping `T[]` to element type `T`)
2. For each step `f`: verify `f`'s first parameter type matches the current type
3. Update the current type to `f`'s return type
4. Verify the final type matches the declared `output_type` element

```varek
-- After this RFC: compile-time error
pipeline bad {
  source: int[]
  steps: [step_a -> step_b]
  output: bool[]
}
-- error: pipeline step `step_b`: input type mismatch —
--        expected `str`, found `Tensor<float, [768]>`
```

### Breaking changes

None — this makes previously-silent errors into compile-time errors.
Programs that relied on the broken behavior were already incorrect.

---

## Implementation

Implemented in `varek/infer.py` — `_infer_pipeline_decl()`.

Status: ✅ Implemented in v0.2
