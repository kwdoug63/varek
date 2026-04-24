"""
varek/ast.py
──────────────
Abstract Syntax Tree node definitions for VAREK v0.1.

Every node is a frozen dataclass. Nodes carry their source Span
so diagnostics and future passes always have location information.
The visitor pattern is supported via the accept() method and the
ASTVisitor base class.

Node hierarchy:
    Node (base)
    ├── Program
    ├── Statements
    │   ├── ImportStmt
    │   ├── SchemaDecl
    │   ├── PipelineDecl
    │   ├── FnDecl
    │   ├── LetStmt
    │   ├── ReturnStmt
    │   └── ExprStmt
    ├── Expressions
    │   ├── Literal
    │   ├── Ident
    │   ├── BinaryExpr
    │   ├── UnaryExpr
    │   ├── PipeExpr
    │   ├── CallExpr
    │   ├── MemberExpr
    │   ├── IndexExpr
    │   ├── PropagateExpr  (?)
    │   ├── IfExpr
    │   ├── MatchExpr
    │   ├── ForExpr
    │   ├── AwaitExpr
    │   ├── LambdaExpr
    │   ├── ArrayLiteral
    │   ├── MapLiteral
    │   ├── TupleLiteral
    │   └── Block
    └── Types
        ├── NamedType
        ├── OptionalType
        ├── ArrayType
        ├── MapType
        ├── TupleType
        ├── TensorType
        └── ResultType
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Any, Tuple

from varek.errors import Span


# ══════════════════════════════════════════════════════════════════
# BASE NODE
# ══════════════════════════════════════════════════════════════════

@dataclass
class Node(ABC):
    span: Span

    @abstractmethod
    def accept(self, visitor: "ASTVisitor") -> Any:
        ...

    def __repr__(self) -> str:
        cls = type(self).__name__
        attrs = {k: v for k, v in self.__dict__.items()
                 if k != "span" and v is not None}
        inner = ", ".join(f"{k}={v!r}" for k, v in attrs.items())
        return f"{cls}({inner})"


# ══════════════════════════════════════════════════════════════════
# TYPE NODES
# ══════════════════════════════════════════════════════════════════

@dataclass
class TypeNode(Node, ABC):
    """Base class for all type expression nodes."""
    pass


@dataclass
class NamedType(TypeNode):
    """A simple named type: int, str, MySchema, etc."""
    name: str

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_named_type(self)


@dataclass
class OptionalType(TypeNode):
    """T? — nullable/optional wrapper."""
    inner: TypeNode

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_optional_type(self)


@dataclass
class ArrayType(TypeNode):
    """T[] — homogeneous array."""
    element: TypeNode

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_array_type(self)


@dataclass
class MapType(TypeNode):
    """{K: V} — key-value map."""
    key_type: TypeNode
    val_type: TypeNode

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_map_type(self)


@dataclass
class TupleType(TypeNode):
    """(A, B, C) — fixed-arity tuple."""
    elements: List[TypeNode]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_tuple_type(self)


@dataclass
class TensorType(TypeNode):
    """Tensor<T, [D0, D1, ...]> — n-dimensional typed tensor."""
    element: TypeNode
    dims:    List[int]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_tensor_type(self)


@dataclass
class ResultType(TypeNode):
    """Result<T> — success-or-error wrapper."""
    ok_type: TypeNode

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_result_type(self)


# ══════════════════════════════════════════════════════════════════
# STATEMENT NODES
# ══════════════════════════════════════════════════════════════════

@dataclass
class Program(Node):
    statements: List[Node]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_program(self)


@dataclass
class ImportStmt(Node):
    """import python::numpy as np  |  safe import rust::tokenizers::Tok"""
    path:     List[str]     # module path segments
    alias:    Optional[str]
    is_safe:  bool

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_import_stmt(self)


@dataclass
class SchemaField:
    name:     str
    type_:    TypeNode
    optional: bool
    span:     Span


@dataclass
class SchemaDecl(Node):
    name:   str
    fields: List[SchemaField]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_schema_decl(self)


@dataclass
class PipelineConfig:
    fields: List[Tuple[str, "Literal"]]
    span:   Span


@dataclass
class PipelineDecl(Node):
    name:        str
    source_type: TypeNode
    steps:       List[str]
    output_type: TypeNode
    config:      Optional[PipelineConfig]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_pipeline_decl(self)


@dataclass
class Param:
    name:  str
    type_: TypeNode
    span:  Span


@dataclass
class FnDecl(Node):
    name:        str
    params:      List[Param]
    return_type: Optional[TypeNode]
    body:        "Block"
    is_async:    bool
    is_export:   bool

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_fn_decl(self)


@dataclass
class LetStmt(Node):
    name:     str
    type_ann: Optional[TypeNode]
    value:    Node
    mutable:  bool

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_let_stmt(self)


@dataclass
class ReturnStmt(Node):
    value: Optional[Node]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_return_stmt(self)


@dataclass
class ExprStmt(Node):
    expr: Node

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_expr_stmt(self)


# ══════════════════════════════════════════════════════════════════
# EXPRESSION NODES
# ══════════════════════════════════════════════════════════════════

@dataclass
class Literal(Node):
    value: Any   # int | float | str | bool | None

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_literal(self)


@dataclass
class Ident(Node):
    name: str

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_ident(self)


@dataclass
class BinaryExpr(Node):
    op:    str
    left:  Node
    right: Node

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_binary_expr(self)


@dataclass
class UnaryExpr(Node):
    op:      str
    operand: Node

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_unary_expr(self)


@dataclass
class PipeExpr(Node):
    """left |> right — pipe-forward operator."""
    left:  Node
    right: Node

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_pipe_expr(self)


@dataclass
class Arg:
    value:   Node
    keyword: Optional[str]   # None for positional
    span:    Span


@dataclass
class CallExpr(Node):
    callee: Node
    args:   List[Arg]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_call_expr(self)


@dataclass
class MemberExpr(Node):
    """obj.field"""
    obj:   Node
    field: str

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_member_expr(self)


@dataclass
class IndexExpr(Node):
    """obj[index]"""
    obj:   Node
    index: Node

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_index_expr(self)


@dataclass
class PropagateExpr(Node):
    """expr? — error propagation operator."""
    expr: Node

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_propagate_expr(self)


@dataclass
class IfExpr(Node):
    condition:  Node
    then_block: "Block"
    else_branch: Optional[Node]  # Block | IfExpr

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_if_expr(self)


@dataclass
class MatchArm:
    pattern: Node    # Literal | Ident | WildcardPattern
    body:    Node    # expr or block
    span:    Span


@dataclass
class WildcardPattern(Node):
    """The _ wildcard in a match arm."""
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_wildcard_pattern(self)


@dataclass
class MatchExpr(Node):
    subject: Node
    arms:    List[MatchArm]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_match_expr(self)


@dataclass
class ForExpr(Node):
    var:      str
    iterable: Node
    body:     "Block"

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_for_expr(self)


@dataclass
class AwaitExpr(Node):
    expr: Node

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_await_expr(self)


@dataclass
class LambdaParam:
    name:  str
    type_: Optional[TypeNode]
    span:  Span


@dataclass
class LambdaExpr(Node):
    params:      List[LambdaParam]
    return_type: Optional[TypeNode]
    body:        Node

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_lambda_expr(self)


@dataclass
class ArrayLiteral(Node):
    elements: List[Node]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_array_literal(self)


@dataclass
class MapEntry:
    key:   Node
    value: Node
    span:  Span


@dataclass
class MapLiteral(Node):
    entries: List[MapEntry]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_map_literal(self)


@dataclass
class TupleLiteral(Node):
    elements: List[Node]

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_tuple_literal(self)


@dataclass
class Block(Node):
    statements: List[Node]
    tail_expr:  Optional[Node]   # implicit return value

    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_block(self)


# ══════════════════════════════════════════════════════════════════
# VISITOR BASE
# ══════════════════════════════════════════════════════════════════

class ASTVisitor(ABC):
    """
    Visitor base class. Implement this to walk or transform the AST.
    All methods have a default that recursively visits children.
    Override only the nodes you care about.
    """

    # ── Program ───────────────────────────────────────────────
    def visit_program(self, node: Program) -> Any:
        for s in node.statements:
            s.accept(self)

    # ── Statements ────────────────────────────────────────────
    def visit_import_stmt(self, node: ImportStmt) -> Any: pass

    def visit_schema_decl(self, node: SchemaDecl) -> Any:
        for f in node.fields:
            f.type_.accept(self)

    def visit_pipeline_decl(self, node: PipelineDecl) -> Any:
        node.source_type.accept(self)
        node.output_type.accept(self)

    def visit_fn_decl(self, node: FnDecl) -> Any:
        for p in node.params:
            p.type_.accept(self)
        if node.return_type:
            node.return_type.accept(self)
        node.body.accept(self)

    def visit_let_stmt(self, node: LetStmt) -> Any:
        if node.type_ann:
            node.type_ann.accept(self)
        node.value.accept(self)

    def visit_return_stmt(self, node: ReturnStmt) -> Any:
        if node.value:
            node.value.accept(self)

    def visit_expr_stmt(self, node: ExprStmt) -> Any:
        node.expr.accept(self)

    # ── Expressions ───────────────────────────────────────────
    def visit_literal(self, node: Literal) -> Any: pass
    def visit_ident(self, node: Ident) -> Any: pass
    def visit_wildcard_pattern(self, node: WildcardPattern) -> Any: pass

    def visit_binary_expr(self, node: BinaryExpr) -> Any:
        node.left.accept(self)
        node.right.accept(self)

    def visit_unary_expr(self, node: UnaryExpr) -> Any:
        node.operand.accept(self)

    def visit_pipe_expr(self, node: PipeExpr) -> Any:
        node.left.accept(self)
        node.right.accept(self)

    def visit_call_expr(self, node: CallExpr) -> Any:
        node.callee.accept(self)
        for a in node.args:
            a.value.accept(self)

    def visit_member_expr(self, node: MemberExpr) -> Any:
        node.obj.accept(self)

    def visit_index_expr(self, node: IndexExpr) -> Any:
        node.obj.accept(self)
        node.index.accept(self)

    def visit_propagate_expr(self, node: PropagateExpr) -> Any:
        node.expr.accept(self)

    def visit_if_expr(self, node: IfExpr) -> Any:
        node.condition.accept(self)
        node.then_block.accept(self)
        if node.else_branch:
            node.else_branch.accept(self)

    def visit_match_expr(self, node: MatchExpr) -> Any:
        node.subject.accept(self)
        for arm in node.arms:
            arm.pattern.accept(self)
            arm.body.accept(self)

    def visit_for_expr(self, node: ForExpr) -> Any:
        node.iterable.accept(self)
        node.body.accept(self)

    def visit_await_expr(self, node: AwaitExpr) -> Any:
        node.expr.accept(self)

    def visit_lambda_expr(self, node: LambdaExpr) -> Any:
        for p in node.params:
            if p.type_:
                p.type_.accept(self)
        if node.return_type:
            node.return_type.accept(self)
        node.body.accept(self)

    def visit_array_literal(self, node: ArrayLiteral) -> Any:
        for e in node.elements:
            e.accept(self)

    def visit_map_literal(self, node: MapLiteral) -> Any:
        for entry in node.entries:
            entry.key.accept(self)
            entry.value.accept(self)

    def visit_tuple_literal(self, node: TupleLiteral) -> Any:
        for e in node.elements:
            e.accept(self)

    def visit_block(self, node: Block) -> Any:
        for s in node.statements:
            s.accept(self)
        if node.tail_expr:
            node.tail_expr.accept(self)

    # ── Types ─────────────────────────────────────────────────
    def visit_named_type(self, node: NamedType) -> Any: pass
    def visit_optional_type(self, node: OptionalType) -> Any:
        node.inner.accept(self)
    def visit_array_type(self, node: ArrayType) -> Any:
        node.element.accept(self)
    def visit_map_type(self, node: MapType) -> Any:
        node.key_type.accept(self)
        node.val_type.accept(self)
    def visit_tuple_type(self, node: TupleType) -> Any:
        for e in node.elements:
            e.accept(self)
    def visit_tensor_type(self, node: TensorType) -> Any:
        node.element.accept(self)
    def visit_result_type(self, node: ResultType) -> Any:
        node.ok_type.accept(self)
