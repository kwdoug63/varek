"""
varek/printer.py
──────────────────
AST pretty-printer. Walks the tree and produces indented, readable
output suitable for debugging and specification documentation.
"""

from __future__ import annotations
from typing import Any
from varek.ast import ASTVisitor, Node
import varek.ast as ast


class ASTPrinter(ASTVisitor):
    """Prints a human-readable, indented AST representation."""

    def __init__(self):
        self._indent = 0
        self._lines: list[str] = []

    def _w(self, text: str) -> None:
        self._lines.append("  " * self._indent + text)

    def _block(self, label: str, children_fn):
        self._w(label)
        self._indent += 1
        children_fn()
        self._indent -= 1

    def render(self) -> str:
        return "\n".join(self._lines)

    @classmethod
    def print(cls, node: Node) -> str:
        p = cls()
        node.accept(p)
        return p.render()

    # ── Program ───────────────────────────────────────────────
    def visit_program(self, node: ast.Program) -> Any:
        self._w(f"Program ({len(node.statements)} statements)")
        self._indent += 1
        for s in node.statements:
            s.accept(self)
        self._indent -= 1

    # ── Import ────────────────────────────────────────────────
    def visit_import_stmt(self, node: ast.ImportStmt) -> Any:
        path = "::".join(node.path)
        alias = f" as {node.alias}" if node.alias else ""
        safe = "safe " if node.is_safe else ""
        self._w(f"ImportStmt {safe}{path}{alias}")

    # ── Schema ────────────────────────────────────────────────
    def visit_schema_decl(self, node: ast.SchemaDecl) -> Any:
        self._w(f"SchemaDecl `{node.name}`")
        self._indent += 1
        for f in node.fields:
            opt = "?" if f.optional else ""
            type_str = ASTPrinter.print(f.type_)
            self._w(f"field `{f.name}`: {type_str}{opt}")
        self._indent -= 1

    # ── Pipeline ──────────────────────────────────────────────
    def visit_pipeline_decl(self, node: ast.PipelineDecl) -> Any:
        self._w(f"PipelineDecl `{node.name}`")
        self._indent += 1
        self._w(f"source: {ASTPrinter.print(node.source_type)}")
        self._w(f"steps:  {' -> '.join(node.steps)}")
        self._w(f"output: {ASTPrinter.print(node.output_type)}")
        if node.config:
            self._w(f"config: {dict(node.config.fields)}")
        self._indent -= 1

    # ── Function ──────────────────────────────────────────────
    def visit_fn_decl(self, node: ast.FnDecl) -> Any:
        flags = []
        if node.is_export: flags.append("export")
        if node.is_async:  flags.append("async")
        prefix = " ".join(flags) + " " if flags else ""
        params = ", ".join(
            f"{p.name}: {ASTPrinter.print(p.type_)}" for p in node.params
        )
        ret = f" -> {ASTPrinter.print(node.return_type)}" \
              if node.return_type else ""
        self._w(f"{prefix}FnDecl `{node.name}`({params}){ret}")
        self._indent += 1
        node.body.accept(self)
        self._indent -= 1

    # ── Let ───────────────────────────────────────────────────
    def visit_let_stmt(self, node: ast.LetStmt) -> Any:
        mut = "mut " if node.mutable else ""
        ann = f": {ASTPrinter.print(node.type_ann)}" if node.type_ann else ""
        self._w(f"LetStmt {mut}`{node.name}`{ann}")
        self._indent += 1
        node.value.accept(self)
        self._indent -= 1

    # ── Return ────────────────────────────────────────────────
    def visit_return_stmt(self, node: ast.ReturnStmt) -> Any:
        self._w("ReturnStmt")
        if node.value:
            self._indent += 1
            node.value.accept(self)
            self._indent -= 1

    # ── ExprStmt ──────────────────────────────────────────────
    def visit_expr_stmt(self, node: ast.ExprStmt) -> Any:
        node.expr.accept(self)

    # ── Block ─────────────────────────────────────────────────
    def visit_block(self, node: ast.Block) -> Any:
        self._w(f"Block ({len(node.statements)} stmts"
                f"{', tail' if node.tail_expr else ''})")
        self._indent += 1
        for s in node.statements:
            s.accept(self)
        if node.tail_expr:
            self._w("[tail]")
            self._indent += 1
            node.tail_expr.accept(self)
            self._indent -= 1
        self._indent -= 1

    # ── Expressions ───────────────────────────────────────────
    def visit_literal(self, node: ast.Literal) -> Any:
        self._w(f"Literal {node.value!r}")

    def visit_ident(self, node: ast.Ident) -> Any:
        self._w(f"Ident `{node.name}`")

    def visit_binary_expr(self, node: ast.BinaryExpr) -> Any:
        self._w(f"BinaryExpr `{node.op}`")
        self._indent += 1
        node.left.accept(self)
        node.right.accept(self)
        self._indent -= 1

    def visit_unary_expr(self, node: ast.UnaryExpr) -> Any:
        self._w(f"UnaryExpr `{node.op}`")
        self._indent += 1
        node.operand.accept(self)
        self._indent -= 1

    def visit_pipe_expr(self, node: ast.PipeExpr) -> Any:
        self._w("PipeExpr |>")
        self._indent += 1
        node.left.accept(self)
        node.right.accept(self)
        self._indent -= 1

    def visit_call_expr(self, node: ast.CallExpr) -> Any:
        self._w(f"CallExpr")
        self._indent += 1
        self._w("callee:")
        self._indent += 1
        node.callee.accept(self)
        self._indent -= 1
        for a in node.args:
            kw = f"[{a.keyword}=]" if a.keyword else ""
            self._w(f"arg{kw}:")
            self._indent += 1
            a.value.accept(self)
            self._indent -= 1
        self._indent -= 1

    def visit_member_expr(self, node: ast.MemberExpr) -> Any:
        self._w(f"MemberExpr .{node.field}")
        self._indent += 1
        node.obj.accept(self)
        self._indent -= 1

    def visit_index_expr(self, node: ast.IndexExpr) -> Any:
        self._w("IndexExpr []")
        self._indent += 1
        node.obj.accept(self)
        node.index.accept(self)
        self._indent -= 1

    def visit_propagate_expr(self, node: ast.PropagateExpr) -> Any:
        self._w("PropagateExpr ?")
        self._indent += 1
        node.expr.accept(self)
        self._indent -= 1

    def visit_if_expr(self, node: ast.IfExpr) -> Any:
        self._w("IfExpr")
        self._indent += 1
        self._w("condition:")
        self._indent += 1
        node.condition.accept(self)
        self._indent -= 1
        self._w("then:")
        self._indent += 1
        node.then_block.accept(self)
        self._indent -= 1
        if node.else_branch:
            self._w("else:")
            self._indent += 1
            node.else_branch.accept(self)
            self._indent -= 1
        self._indent -= 1

    def visit_match_expr(self, node: ast.MatchExpr) -> Any:
        self._w("MatchExpr")
        self._indent += 1
        self._w("subject:")
        self._indent += 1
        node.subject.accept(self)
        self._indent -= 1
        for i, arm in enumerate(node.arms):
            self._w(f"arm {i}:")
            self._indent += 1
            arm.pattern.accept(self)
            self._w("=>")
            arm.body.accept(self)
            self._indent -= 1
        self._indent -= 1

    def visit_for_expr(self, node: ast.ForExpr) -> Any:
        self._w(f"ForExpr `{node.var}` in")
        self._indent += 1
        node.iterable.accept(self)
        node.body.accept(self)
        self._indent -= 1

    def visit_await_expr(self, node: ast.AwaitExpr) -> Any:
        self._w("AwaitExpr")
        self._indent += 1
        node.expr.accept(self)
        self._indent -= 1

    def visit_lambda_expr(self, node: ast.LambdaExpr) -> Any:
        params = ", ".join(p.name for p in node.params)
        ret = f" -> {ASTPrinter.print(node.return_type)}" \
              if node.return_type else ""
        self._w(f"LambdaExpr |{params}|{ret}")
        self._indent += 1
        node.body.accept(self)
        self._indent -= 1

    def visit_array_literal(self, node: ast.ArrayLiteral) -> Any:
        self._w(f"ArrayLiteral [{len(node.elements)} elements]")
        self._indent += 1
        for e in node.elements:
            e.accept(self)
        self._indent -= 1

    def visit_map_literal(self, node: ast.MapLiteral) -> Any:
        self._w(f"MapLiteral {{{len(node.entries)} entries}}")
        self._indent += 1
        for entry in node.entries:
            self._w("entry:")
            self._indent += 1
            entry.key.accept(self)
            entry.value.accept(self)
            self._indent -= 1
        self._indent -= 1

    def visit_tuple_literal(self, node: ast.TupleLiteral) -> Any:
        self._w(f"TupleLiteral ({len(node.elements)} elements)")
        self._indent += 1
        for e in node.elements:
            e.accept(self)
        self._indent -= 1

    def visit_wildcard_pattern(self, node: ast.WildcardPattern) -> Any:
        self._w("WildcardPattern _")

    # ── Types ─────────────────────────────────────────────────
    def visit_named_type(self, node: ast.NamedType) -> Any:
        self._w(f"NamedType `{node.name}`")

    def visit_optional_type(self, node: ast.OptionalType) -> Any:
        inner = ASTPrinter.print(node.inner)
        self._w(f"OptionalType {inner}?")

    def visit_array_type(self, node: ast.ArrayType) -> Any:
        elem = ASTPrinter.print(node.element)
        self._w(f"ArrayType {elem}[]")

    def visit_map_type(self, node: ast.MapType) -> Any:
        k = ASTPrinter.print(node.key_type)
        v = ASTPrinter.print(node.val_type)
        self._w(f"MapType {{{k}: {v}}}")

    def visit_tuple_type(self, node: ast.TupleType) -> Any:
        elems = ", ".join(ASTPrinter.print(e) for e in node.elements)
        self._w(f"TupleType ({elems})")

    def visit_tensor_type(self, node: ast.TensorType) -> Any:
        elem = ASTPrinter.print(node.element)
        dims = ", ".join(str(d) for d in node.dims)
        self._w(f"TensorType Tensor<{elem}, [{dims}]>")

    def visit_result_type(self, node: ast.ResultType) -> Any:
        ok = ASTPrinter.print(node.ok_type)
        self._w(f"ResultType Result<{ok}>")
