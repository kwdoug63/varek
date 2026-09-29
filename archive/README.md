# Archive

Files kept for the record that nothing in the current code uses. They were
moved here from the repository root on 2026-09-29; their history is intact
(`git log --follow archive/<file>`).

| File | What it is |
|------|------------|
| `varek-v0.1.zip` | The VAREK language, v0.1: lexer, parser and AST |
| `varek-v0.2.zip` | v0.2: type system and Hindley–Milner inference |
| `varek-v0.3.zip` | v0.3: LLVM code generation |
| `varek-v0.4.zip` | v0.4: standard library |
| `varek_circuit_breaker.ipynb` | An early notebook on deterministic circuit breakers for LangChain agents; it predates the Warden and does not use it |

The language test counts in the root [README](../README.md#testing) for v0.1
to v0.4 come from unpacking these archives and running each one's own tests
(`python3 tests/test_*.py` inside the unpacked folder, Python 3.11). The v1.0
language is in [`varek-v1.0/`](../varek-v1.0/) and `varek-v1.0.zip` at the
root.
