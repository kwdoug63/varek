"""
varek/checker.py
──────────────────
Top-level type checker for VAREK v0.2.

Orchestrates the full pipeline:
  source → tokens → AST → [type check] → TypedProgram

Provides a clean public API:

    result = TypeChecker.check(source, filename)
    if result.ok:
        for name, ty in result.bindings:
            print(f"{name} : {ty}")
    else:
        print(result.errors.report(source.splitlines()))

Also provides:
  - check_expr()   for REPL-style single-expression checking
  - CheckResult    a rich result type with bindings and typed nodes
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from varek.lexer   import Lexer
from varek.parser  import Parser
from varek.errors  import ErrorBag, VarekError, Span
from varek.types   import Type, Scheme, Substitution
from varek.env     import TypeEnv, SchemaRegistry
from varek.infer   import Inferrer, ast_type_to_syn_type
from varek.builtins import build_global_env
import varek.ast as ast


# ══════════════════════════════════════════════════════════════════
# CHECK RESULT
# ══════════════════════════════════════════════════════════════════

@dataclass
class CheckResult:
    """
    The output of a type-checking run.

    ok       : bool          — True iff no errors were found
    errors   : ErrorBag      — collected lex, parse, and type errors
    env      : TypeEnv       — final environment (names -> schemes)
    schemas  : SchemaRegistry— all declared schemas
    subst    : Substitution  — the principal substitution
    node_types: dict         — AST node id -> inferred Type
    source   : str           — original source (for error display)
    """
    ok:         bool
    errors:     ErrorBag
    env:        TypeEnv
    schemas:    SchemaRegistry
    subst:      Substitution
    node_types: Dict[int, Type]
    source:     str
    filename:   str

    # ── Convenience accessors ─────────────────────────────────

    def bindings(self) -> Iterator[Tuple[str, Type]]:
        """Yield (name, instantiated type) for each top-level binding."""
        for name in self.env.local_names():
            scheme = self.env.lookup(name, Span(self.filename, 0, 0))
            yield name, scheme.type

    def get_type(self, node: ast.Node) -> Optional[Type]:
        return self.node_types.get(id(node))

    def report(self) -> str:
        """Return a formatted error report."""
        if self.ok:
            return "✓ Type check passed."
        return self.errors.report(self.source.splitlines())

    def pretty_bindings(self) -> str:
        """Return a pretty-printed list of all top-level types."""
        lines = []
        for name, ty in sorted(self.bindings(), key=lambda x: x[0]):
            lines.append(f"  {name} : {ty}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# TYPE CHECKER
# ══════════════════════════════════════════════════════════════════

class TypeChecker:
    """
    Stateless type checker. All methods are classmethods or staticmethods.
    Create a new instance if you need to hold state across multiple
    incremental checks (e.g. for a language server).
    """

    @classmethod
    def check(
        cls,
        source:    str,
        filename:  str = "<stdin>",
        env:       Optional[TypeEnv] = None,
    ) -> CheckResult:
        """
        Full pipeline: lex → parse → type-check.

        Returns a CheckResult regardless of whether errors occurred —
        callers should check result.ok.
        """
        errors = ErrorBag()

        # ── Lex ───────────────────────────────────────────────
        lexer  = Lexer(source, filename)
        tokens = lexer.tokenize()
        for e in lexer.errors:
            errors.add(e)

        # ── Parse ─────────────────────────────────────────────
        parser = Parser(tokens, filename)
        tree   = parser.parse()
        for e in parser.errors:
            errors.add(e)

        # ── Type check ────────────────────────────────────────
        schemas  = SchemaRegistry()
        root_env = env or build_global_env()
        inferrer = Inferrer(errors, schemas)

        try:
            subst, final_env = inferrer.infer_program(tree, root_env)
        except VarekError as e:
            errors.add(e)
            subst    = Substitution.EMPTY
            final_env = root_env

        ok = not errors.has_errors()
        return CheckResult(
            ok=ok,
            errors=errors,
            env=final_env,
            schemas=schemas,
            subst=subst,
            node_types=inferrer._types,
            source=source,
            filename=filename,
        )

    @classmethod
    def check_expr(
        cls,
        source:   str,
        filename: str = "<repl>",
        env:      Optional[TypeEnv] = None,
    ) -> Tuple[Optional[Type], ErrorBag]:
        """
        Infer the type of a single expression (REPL mode).

        Returns (type | None, errors).
        """
        errors   = ErrorBag()
        root_env = env or build_global_env()

        # Lex + parse as a let-expression wrapper
        wrapped = f"let __expr__ = {source}"
        result = cls.check(wrapped, filename, env=root_env)

        if result.ok:
            try:
                scheme = result.env.lookup(
                    "__expr__",
                    Span(filename, 1, 1)
                )
                return scheme.instantiate(), result.errors
            except Exception:
                pass

        return None, result.errors

    @classmethod
    def check_file(cls, path: str) -> CheckResult:
        """Load and check a .syn file."""
        with open(path, encoding="utf-8") as f:
            source = f.read()
        return cls.check(source, filename=path)


# ══════════════════════════════════════════════════════════════════
# SCHEMA VALIDATOR
# ══════════════════════════════════════════════════════════════════

class SchemaValidator:
    """
    Runtime schema validation helper.

    Validates that a Python dict (from JSON, API response, etc.)
    conforms to a VAREK schema type. Useful for testing and
    for the future runtime library.
    """

    @staticmethod
    def validate(
        data:   dict,
        schema: "SchemaType",
        path:   str = "$",
    ) -> List[str]:
        """
        Validate `data` against `schema`.
        Returns a list of error strings (empty = valid).
        """
        from varek.types import (
            SchemaType, PrimType, OptionalType, ArrayType,
            MapType, TupleType, T_INT, T_FLOAT, T_STR, T_BOOL, T_NIL,
        )
        errors: List[str] = []

        for field_def in schema.fields:
            key = field_def.name

            if key not in data:
                if not field_def.optional:
                    errors.append(
                        f"{path}.{key}: required field missing"
                    )
                continue

            val  = data[key]
            fty  = field_def.type_
            errs = SchemaValidator._check_value(
                val, fty, f"{path}.{key}"
            )
            errors.extend(errs)

        return errors

    @staticmethod
    def _check_value(val, ty, path: str) -> List[str]:
        from varek.types import (
            PrimType, OptionalType, ArrayType, MapType,
            TupleType, SchemaType, ResultType,
            T_INT, T_FLOAT, T_STR, T_BOOL, T_NIL,
        )
        errors: List[str] = []

        if isinstance(ty, PrimType):
            expected_py = {
                "int": int, "float": (int, float),
                "str": str, "bool": bool, "nil": type(None),
            }.get(ty.name)
            if expected_py and not isinstance(val, expected_py):
                errors.append(
                    f"{path}: expected {ty.name}, "
                    f"got {type(val).__name__}"
                )

        elif isinstance(ty, OptionalType):
            if val is not None:
                errors.extend(
                    SchemaValidator._check_value(val, ty.inner, path)
                )

        elif isinstance(ty, ArrayType):
            if not isinstance(val, list):
                errors.append(f"{path}: expected array, got {type(val).__name__}")
            else:
                for i, item in enumerate(val):
                    errors.extend(
                        SchemaValidator._check_value(
                            item, ty.element, f"{path}[{i}]"
                        )
                    )

        elif isinstance(ty, SchemaType):
            if not isinstance(val, dict):
                errors.append(
                    f"{path}: expected object, got {type(val).__name__}"
                )
            else:
                errors.extend(
                    SchemaValidator.validate(val, ty, path)
                )

        return errors

    @staticmethod
    def is_valid(data: dict, schema: "SchemaType") -> bool:
        return len(SchemaValidator.validate(data, schema)) == 0
