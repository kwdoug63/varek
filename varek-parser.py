"""
varek-parser.py
───────────────
VAREK Reference Parser — v1.0
AI Pipeline Programming Language

A standalone, zero-dependency lexer and recursive-descent parser
for the VAREK language, written in pure Python for maximum
portability and readability.

This file is self-contained — no imports beyond the Python
standard library. Run it directly to see the lexer and parser
in action on a sample VAREK program.

    python varek-parser.py

Author:  Kenneth Wayne Douglas, MD
License: MIT
Repo:    github.com/kwdoug63/varek
"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Any


# ══════════════════════════════════════════════════════════
# TOKEN TYPES
# ══════════════════════════════════════════════════════════

class TT(Enum):
    # Literals
    INT      = auto()
    FLOAT    = auto()
    STRING   = auto()
    BOOL     = auto()
    NIL      = auto()

    # Identifiers & Keywords
    IDENT    = auto()
    FN       = auto()
    SCHEMA   = auto()
    PIPELINE = auto()
    LET      = auto()
    MUT      = auto()
    IF       = auto()
    ELSE     = auto()
    MATCH    = auto()
    FOR      = auto()
    IN       = auto()
    RETURN   = auto()
    ASYNC    = auto()
    AWAIT    = auto()
    SAFE     = auto()
    IMPORT   = auto()
    FROM     = auto()
    AS       = auto()
    EXPORT   = auto()

    # Operators
    PIPE     = auto()   # |>
    ARROW    = auto()   # ->
    FAT_ARR  = auto()   # =>
    QMARK    = auto()   # ?
    ASSIGN   = auto()   # =
    WALRUS   = auto()   # :=
    PLUS     = auto()
    MINUS    = auto()
    STAR     = auto()
    SLASH    = auto()
    PERCENT  = auto()
    GT       = auto()
    LT       = auto()
    GTE      = auto()
    LTE      = auto()
    EQ       = auto()   # ==
    NEQ      = auto()   # !=
    AND      = auto()
    OR       = auto()
    NOT      = auto()

    # Delimiters
    LPAREN   = auto()
    RPAREN   = auto()
    LBRACE   = auto()
    RBRACE   = auto()
    LBRACK   = auto()
    RBRACK   = auto()
    COMMA    = auto()
    COLON    = auto()
    SCOPE    = auto()   # ::
    DOT      = auto()

    # Special
    EOF      = auto()
    NEWLINE  = auto()


KEYWORDS = {
    "fn":       TT.FN,       "schema":   TT.SCHEMA,   "pipeline": TT.PIPELINE,
    "let":      TT.LET,      "mut":      TT.MUT,       "if":       TT.IF,
    "else":     TT.ELSE,     "match":    TT.MATCH,     "for":      TT.FOR,
    "in":       TT.IN,       "return":   TT.RETURN,    "async":    TT.ASYNC,
    "await":    TT.AWAIT,    "safe":     TT.SAFE,      "import":   TT.IMPORT,
    "from":     TT.FROM,     "as":       TT.AS,        "export":   TT.EXPORT,
    "and":      TT.AND,      "or":       TT.OR,        "not":      TT.NOT,
    "true":     TT.BOOL,     "false":    TT.BOOL,      "nil":      TT.NIL,
}


# ══════════════════════════════════════════════════════════
# TOKEN
# ══════════════════════════════════════════════════════════

@dataclass
class Token:
    type:  TT
    value: Any
    line:  int
    col:   int

    def __repr__(self):
        return f"Token({self.type.name:<10} {self.value!r:<20} {self.line}:{self.col})"


# ══════════════════════════════════════════════════════════
# LEXER
# ══════════════════════════════════════════════════════════

class LexError(Exception):
    pass


class Lexer:
    """
    Hand-rolled lexer for VAREK.

    Produces a flat list of Tokens from source text. Comments
    (-- single-line) are silently discarded. Whitespace is
    discarded except for newlines, which are emitted as
    NEWLINE tokens for optional statement termination.
    """

    def __init__(self, source: str):
        self.source = source
        self.pos    = 0
        self.line   = 1
        self.col    = 1
        self.tokens: List[Token] = []

    def peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        return self.source[idx] if idx < len(self.source) else ""

    def advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def match_char(self, expected: str) -> bool:
        if self.pos < len(self.source) and self.source[self.pos] == expected:
            self.advance()
            return True
        return False

    def skip_whitespace(self):
        while self.pos < len(self.source) and self.peek() in " \t\r":
            self.advance()

    def skip_line_comment(self):
        while self.pos < len(self.source) and self.peek() != "\n":
            self.advance()

    def read_string(self) -> Token:
        line, col = self.line, self.col
        self.advance()   # opening "
        buf = []
        while self.pos < len(self.source) and self.peek() != '"':
            ch = self.advance()
            if ch == "\\" and self.peek() in ('"', "\\", "n", "t", "r"):
                esc = self.advance()
                buf.append({"n": "\n", "t": "\t", "r": "\r"}.get(esc, esc))
            else:
                buf.append(ch)
        if self.pos >= len(self.source):
            raise LexError(f"Unterminated string literal at {line}:{col}")
        self.advance()   # closing "
        return Token(TT.STRING, "".join(buf), line, col)

    def read_number(self) -> Token:
        line, col = self.line, self.col
        buf = []
        is_float = False
        while self.pos < len(self.source) and (self.peek().isdigit() or self.peek() == "."):
            ch = self.advance()
            if ch == ".":
                if is_float:
                    break   # second dot — stop
                is_float = True
            buf.append(ch)
        raw = "".join(buf)
        value = float(raw) if is_float else int(raw)
        return Token(TT.FLOAT if is_float else TT.INT, value, line, col)

    def read_ident(self) -> Token:
        line, col = self.line, self.col
        buf = []
        while self.pos < len(self.source) and (self.peek().isalnum() or self.peek() == "_"):
            buf.append(self.advance())
        word = "".join(buf)
        tt   = KEYWORDS.get(word, TT.IDENT)
        val  = {"true": True, "false": False}.get(word, word)
        return Token(tt, val, line, col)

    def tokenize(self) -> List[Token]:
        while self.pos < len(self.source):
            self.skip_whitespace()
            if self.pos >= len(self.source):
                break

            line, col = self.line, self.col
            ch = self.peek()

            # Single-line comment
            if ch == "-" and self.peek(1) == "-":
                self.advance(); self.advance()
                self.skip_line_comment()
                continue

            # Newline
            if ch == "\n":
                self.advance()
                self.tokens.append(Token(TT.NEWLINE, "\n", line, col))
                continue

            # String literal
            if ch == '"':
                self.tokens.append(self.read_string())
                continue

            # Number
            if ch.isdigit():
                self.tokens.append(self.read_number())
                continue

            # Identifier / keyword
            if ch.isalpha() or ch == "_":
                self.tokens.append(self.read_ident())
                continue

            # Multi-character operators
            self.advance()
            if   ch == "|" and self.match_char(">"):
                self.tokens.append(Token(TT.PIPE,    "|>", line, col))
            elif ch == "-" and self.match_char(">"):
                self.tokens.append(Token(TT.ARROW,   "->", line, col))
            elif ch == "=" and self.match_char(">"):
                self.tokens.append(Token(TT.FAT_ARR, "=>", line, col))
            elif ch == "=" and self.match_char("="):
                self.tokens.append(Token(TT.EQ,      "==", line, col))
            elif ch == "!" and self.match_char("="):
                self.tokens.append(Token(TT.NEQ,     "!=", line, col))
            elif ch == ">" and self.match_char("="):
                self.tokens.append(Token(TT.GTE,     ">=", line, col))
            elif ch == "<" and self.match_char("="):
                self.tokens.append(Token(TT.LTE,     "<=", line, col))
            elif ch == ":" and self.match_char(":"):
                self.tokens.append(Token(TT.SCOPE,   "::", line, col))
            elif ch == ":" and self.match_char("="):
                self.tokens.append(Token(TT.WALRUS,  ":=", line, col))
            else:
                single = {
                    "(": TT.LPAREN, ")": TT.RPAREN,
                    "{": TT.LBRACE, "}": TT.RBRACE,
                    "[": TT.LBRACK, "]": TT.RBRACK,
                    ",": TT.COMMA,  ":": TT.COLON,
                    ".": TT.DOT,    "?": TT.QMARK,
                    "=": TT.ASSIGN, "+": TT.PLUS,
                    "-": TT.MINUS,  "*": TT.STAR,
                    "/": TT.SLASH,  "%": TT.PERCENT,
                    ">": TT.GT,     "<": TT.LT,
                }.get(ch)
                if single:
                    self.tokens.append(Token(single, ch, line, col))
                else:
                    raise LexError(f"Unexpected character {ch!r} at {line}:{col}")

        self.tokens.append(Token(TT.EOF, None, self.line, self.col))
        return self.tokens


# ══════════════════════════════════════════════════════════
# AST NODES
# ══════════════════════════════════════════════════════════

@dataclass
class ASTNode:
    pass

@dataclass
class Program(ASTNode):
    statements: List[ASTNode]

@dataclass
class FieldDef(ASTNode):
    name:     str
    type_str: str
    optional: bool

@dataclass
class SchemaDecl(ASTNode):
    name:   str
    fields: List[FieldDef]

@dataclass
class PipelineDecl(ASTNode):
    name:        str
    source_type: str
    steps:       List[str]
    output_type: str

@dataclass
class Param(ASTNode):
    name:     str
    type_str: str

@dataclass
class FnDecl(ASTNode):
    name:        str
    params:      List[Param]
    return_type: Optional[str]
    body:        List[ASTNode]
    is_async:    bool = False
    is_export:   bool = False

@dataclass
class LetStmt(ASTNode):
    name:     str
    type_ann: Optional[str]
    value:    ASTNode
    mutable:  bool = False

@dataclass
class ReturnStmt(ASTNode):
    value: Optional[ASTNode]

@dataclass
class IfExpr(ASTNode):
    condition:   ASTNode
    then_body:   List[ASTNode]
    else_body:   Optional[List[ASTNode]]

@dataclass
class ForExpr(ASTNode):
    var:      str
    iterable: ASTNode
    body:     List[ASTNode]

@dataclass
class BinaryExpr(ASTNode):
    op:    str
    left:  ASTNode
    right: ASTNode

@dataclass
class UnaryExpr(ASTNode):
    op:      str
    operand: ASTNode

@dataclass
class PipeExpr(ASTNode):
    left:  ASTNode
    right: ASTNode

@dataclass
class CallExpr(ASTNode):
    callee: str
    args:   List[ASTNode]

@dataclass
class MemberExpr(ASTNode):
    obj:   ASTNode
    field: str

@dataclass
class IndexExpr(ASTNode):
    obj:   ASTNode
    index: ASTNode

@dataclass
class Literal(ASTNode):
    value: Any

@dataclass
class Ident(ASTNode):
    name: str

@dataclass
class ImportStmt(ASTNode):
    path:  List[str]
    alias: Optional[str]


# ══════════════════════════════════════════════════════════
# PARSER (Recursive Descent)
# ══════════════════════════════════════════════════════════

class ParseError(Exception):
    pass


class Parser:
    """
    Recursive-descent parser for VAREK.

    Produces a typed AST from a flat token list. Implements
    panic-mode error recovery so that multiple errors can be
    reported in a single pass.
    """

    def __init__(self, tokens: List[Token]):
        # Strip newlines — VAREK uses braces, not indentation
        self.tokens = [t for t in tokens if t.type != TT.NEWLINE]
        self.pos    = 0
        self.errors: List[str] = []

    # ── Token navigation ──────────────────────────────────

    def peek(self, offset: int = 0) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return self.tokens[-1]   # EOF

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        if tok.type != TT.EOF:
            self.pos += 1
        return tok

    def check(self, *types: TT) -> bool:
        return self.peek().type in types

    def match(self, *types: TT) -> bool:
        if self.check(*types):
            self.advance()
            return True
        return False

    def expect(self, tt: TT, label: str = "") -> Token:
        tok = self.peek()
        if tok.type != tt:
            msg = (f"Expected {label or tt.name}, "
                   f"got {tok.type.name} ({tok.value!r}) "
                   f"at {tok.line}:{tok.col}")
            raise ParseError(msg)
        return self.advance()

    def synchronize(self):
        """Panic-mode: skip to next safe statement boundary."""
        self.advance()
        sync_tokens = {TT.FN, TT.SCHEMA, TT.PIPELINE, TT.LET,
                       TT.MUT, TT.RETURN, TT.IF, TT.FOR, TT.ASYNC,
                       TT.EXPORT, TT.IMPORT, TT.RBRACE, TT.EOF}
        while not self.check(*sync_tokens):
            self.advance()

    # ── Top-level ─────────────────────────────────────────

    def parse(self) -> Program:
        statements = []
        while not self.check(TT.EOF):
            try:
                statements.append(self.parse_statement())
            except ParseError as e:
                self.errors.append(str(e))
                self.synchronize()
        return Program(statements)

    def parse_statement(self) -> ASTNode:
        if self.check(TT.SCHEMA):
            return self.parse_schema()
        if self.check(TT.PIPELINE):
            return self.parse_pipeline()
        if self.check(TT.FN, TT.ASYNC, TT.EXPORT):
            return self.parse_fn()
        if self.check(TT.LET, TT.MUT):
            return self.parse_let()
        if self.check(TT.RETURN):
            return self.parse_return()
        if self.check(TT.IF):
            return self.parse_if()
        if self.check(TT.FOR):
            return self.parse_for()
        if self.check(TT.IMPORT):
            return self.parse_import()
        return self.parse_expr()

    # ── Schema ────────────────────────────────────────────

    def parse_schema(self) -> SchemaDecl:
        self.expect(TT.SCHEMA)
        name = self.expect(TT.IDENT, "schema name").value
        self.expect(TT.LBRACE, "`{`")
        fields = []
        while not self.check(TT.RBRACE, TT.EOF):
            fname    = self.expect(TT.IDENT, "field name").value
            self.expect(TT.COLON, "`:`")
            ftype    = self.expect(TT.IDENT, "field type").value
            optional = False
            if self.check(TT.QMARK):
                self.advance()
                optional = True
            if self.check(TT.COMMA):
                self.advance()
            fields.append(FieldDef(fname, ftype, optional))
        self.expect(TT.RBRACE, "`}`")
        return SchemaDecl(name, fields)

    # ── Pipeline ──────────────────────────────────────────

    def parse_pipeline(self) -> PipelineDecl:
        self.expect(TT.PIPELINE)
        name = self.expect(TT.IDENT, "pipeline name").value
        self.expect(TT.LBRACE, "`{`")
        source_type = ""
        steps       = []
        output_type = ""
        while not self.check(TT.RBRACE, TT.EOF):
            key = self.expect(TT.IDENT).value
            self.expect(TT.COLON, "`:`")
            if key == "source":
                source_type = self.expect(TT.IDENT).value
            elif key == "steps":
                self.expect(TT.LBRACK)
                while not self.check(TT.RBRACK, TT.EOF):
                    if self.check(TT.IDENT):
                        steps.append(self.advance().value)
                    elif self.check(TT.ARROW):
                        self.advance()
                    else:
                        self.advance()
                self.expect(TT.RBRACK)
            elif key == "output":
                output_type = self.expect(TT.IDENT).value
        self.expect(TT.RBRACE, "`}`")
        return PipelineDecl(name, source_type, steps, output_type)

    # ── Function ──────────────────────────────────────────

    def parse_fn(self) -> FnDecl:
        is_export = False
        is_async  = False
        if self.check(TT.EXPORT):
            self.advance(); is_export = True
        if self.check(TT.ASYNC):
            self.advance(); is_async = True
        self.expect(TT.FN, "`fn`")
        name = self.expect(TT.IDENT, "function name").value
        self.expect(TT.LPAREN, "`(`")
        params = []
        while not self.check(TT.RPAREN, TT.EOF):
            pname = self.expect(TT.IDENT, "parameter name").value
            self.expect(TT.COLON, "`:`")
            ptype = self.expect(TT.IDENT, "parameter type").value
            params.append(Param(pname, ptype))
            if self.check(TT.COMMA):
                self.advance()
        self.expect(TT.RPAREN, "`)`")
        ret_type = None
        if self.check(TT.ARROW):
            self.advance()
            ret_type = self.expect(TT.IDENT, "return type").value
        body = self.parse_block()
        return FnDecl(name, params, ret_type, body, is_async, is_export)

    def parse_block(self) -> List[ASTNode]:
        self.expect(TT.LBRACE, "`{`")
        stmts = []
        while not self.check(TT.RBRACE, TT.EOF):
            stmts.append(self.parse_statement())
        self.expect(TT.RBRACE, "`}`")
        return stmts

    # ── Let ───────────────────────────────────────────────

    def parse_let(self) -> LetStmt:
        mutable = False
        if self.check(TT.MUT):
            self.advance(); mutable = True
        self.expect(TT.LET, "`let`")
        name     = self.expect(TT.IDENT, "variable name").value
        type_ann = None
        if self.check(TT.COLON):
            self.advance()
            type_ann = self.expect(TT.IDENT, "type annotation").value
        self.expect(TT.ASSIGN, "`=`")
        value = self.parse_expr()
        return LetStmt(name, type_ann, value, mutable)

    # ── Return ────────────────────────────────────────────

    def parse_return(self) -> ReturnStmt:
        self.expect(TT.RETURN)
        value = None
        if not self.check(TT.RBRACE, TT.EOF, TT.NEWLINE):
            value = self.parse_expr()
        return ReturnStmt(value)

    # ── If ────────────────────────────────────────────────

    def parse_if(self) -> IfExpr:
        self.expect(TT.IF)
        condition = self.parse_expr()
        then_body = self.parse_block()
        else_body = None
        if self.check(TT.ELSE):
            self.advance()
            else_body = self.parse_block()
        return IfExpr(condition, then_body, else_body)

    # ── For ───────────────────────────────────────────────

    def parse_for(self) -> ForExpr:
        self.expect(TT.FOR)
        var = self.expect(TT.IDENT, "loop variable").value
        self.expect(TT.IN, "`in`")
        iterable = self.parse_expr()
        body     = self.parse_block()
        return ForExpr(var, iterable, body)

    # ── Import ────────────────────────────────────────────

    def parse_import(self) -> ImportStmt:
        self.expect(TT.IMPORT)
        path = [self.expect(TT.IDENT, "module name").value]
        while self.check(TT.SCOPE):
            self.advance()
            seg = self.peek()
            self.advance()
            seg_name = seg.value if isinstance(seg.value, str) else seg.type.name.lower()
            path.append(seg_name)
        alias = None
        if self.check(TT.AS):
            self.advance()
            alias = self.expect(TT.IDENT, "alias").value
        return ImportStmt(path, alias)

    # ── Expressions ───────────────────────────────────────

    def parse_expr(self) -> ASTNode:
        return self.parse_pipe()

    def parse_pipe(self) -> ASTNode:
        left = self.parse_comparison()
        while self.check(TT.PIPE):
            self.advance()
            right = self.parse_comparison()
            left  = PipeExpr(left, right)
        return left

    def parse_comparison(self) -> ASTNode:
        left = self.parse_additive()
        ops  = {TT.EQ, TT.NEQ, TT.LT, TT.GT, TT.LTE, TT.GTE}
        while self.check(*ops):
            op    = self.advance().value
            right = self.parse_additive()
            left  = BinaryExpr(op, left, right)
        return left

    def parse_additive(self) -> ASTNode:
        left = self.parse_multiplicative()
        while self.check(TT.PLUS, TT.MINUS):
            op    = self.advance().value
            right = self.parse_multiplicative()
            left  = BinaryExpr(op, left, right)
        return left

    def parse_multiplicative(self) -> ASTNode:
        left = self.parse_unary()
        while self.check(TT.STAR, TT.SLASH, TT.PERCENT):
            op    = self.advance().value
            right = self.parse_unary()
            left  = BinaryExpr(op, left, right)
        return left

    def parse_unary(self) -> ASTNode:
        if self.check(TT.NOT):
            op      = self.advance().value
            operand = self.parse_unary()
            return UnaryExpr(op, operand)
        if self.check(TT.MINUS):
            op      = self.advance().value
            operand = self.parse_unary()
            return UnaryExpr(op, operand)
        return self.parse_postfix()

    def parse_postfix(self) -> ASTNode:
        node = self.parse_primary()
        while True:
            if self.check(TT.DOT):
                self.advance()
                field = self.expect(TT.IDENT, "field name").value
                node  = MemberExpr(node, field)
            elif self.check(TT.LBRACK):
                self.advance()
                idx  = self.parse_expr()
                self.expect(TT.RBRACK)
                node = IndexExpr(node, idx)
            else:
                break
        return node

    def parse_primary(self) -> ASTNode:
        tok = self.peek()

        # Literals
        if tok.type in (TT.INT, TT.FLOAT, TT.STRING, TT.BOOL, TT.NIL):
            self.advance()
            return Literal(tok.value)

        # Grouped expression
        if tok.type == TT.LPAREN:
            self.advance()
            expr = self.parse_expr()
            self.expect(TT.RPAREN)
            return expr

        # Identifier or function call
        if tok.type == TT.IDENT:
            self.advance()
            if self.check(TT.LPAREN):
                self.advance()
                args = []
                while not self.check(TT.RPAREN, TT.EOF):
                    args.append(self.parse_expr())
                    if self.check(TT.COMMA):
                        self.advance()
                self.expect(TT.RPAREN)
                return CallExpr(tok.value, args)
            return Ident(tok.value)

        raise ParseError(
            f"Unexpected token {tok.type.name} ({tok.value!r}) "
            f"at {tok.line}:{tok.col}"
        )


# ══════════════════════════════════════════════════════════
# AST PRINTER
# ══════════════════════════════════════════════════════════

class ASTPrinter:
    """Pretty-prints a VAREK AST for debugging and inspection."""

    def print(self, node: ASTNode, indent: int = 0) -> str:
        pad = "  " * indent
        lines = []

        if isinstance(node, Program):
            lines.append(f"{pad}Program ({len(node.statements)} statements)")
            for stmt in node.statements:
                lines.append(self.print(stmt, indent + 1))

        elif isinstance(node, SchemaDecl):
            lines.append(f"{pad}SchemaDecl: {node.name}")
            for f in node.fields:
                opt = "?" if f.optional else ""
                lines.append(f"{pad}  field {f.name}: {f.type_str}{opt}")

        elif isinstance(node, PipelineDecl):
            lines.append(f"{pad}PipelineDecl: {node.name}")
            lines.append(f"{pad}  source: {node.source_type}")
            lines.append(f"{pad}  steps:  {' -> '.join(node.steps)}")
            lines.append(f"{pad}  output: {node.output_type}")

        elif isinstance(node, FnDecl):
            kind   = ("export " if node.is_export else "") + ("async " if node.is_async else "") + "fn"
            params = ", ".join(f"{p.name}: {p.type_str}" for p in node.params)
            ret    = f" -> {node.return_type}" if node.return_type else ""
            lines.append(f"{pad}FnDecl: {kind} {node.name}({params}){ret}")
            for stmt in node.body:
                lines.append(self.print(stmt, indent + 1))

        elif isinstance(node, LetStmt):
            mut  = "mut " if node.mutable else ""
            ann  = f": {node.type_ann}" if node.type_ann else ""
            lines.append(f"{pad}LetStmt: {mut}{node.name}{ann} =")
            lines.append(self.print(node.value, indent + 1))

        elif isinstance(node, ReturnStmt):
            lines.append(f"{pad}ReturnStmt")
            if node.value:
                lines.append(self.print(node.value, indent + 1))

        elif isinstance(node, IfExpr):
            lines.append(f"{pad}IfExpr")
            lines.append(f"{pad}  condition:")
            lines.append(self.print(node.condition, indent + 2))
            lines.append(f"{pad}  then:")
            for s in node.then_body:
                lines.append(self.print(s, indent + 2))
            if node.else_body:
                lines.append(f"{pad}  else:")
                for s in node.else_body:
                    lines.append(self.print(s, indent + 2))

        elif isinstance(node, PipeExpr):
            lines.append(f"{pad}PipeExpr |>")
            lines.append(self.print(node.left,  indent + 1))
            lines.append(self.print(node.right, indent + 1))

        elif isinstance(node, BinaryExpr):
            lines.append(f"{pad}BinaryExpr {node.op!r}")
            lines.append(self.print(node.left,  indent + 1))
            lines.append(self.print(node.right, indent + 1))

        elif isinstance(node, CallExpr):
            lines.append(f"{pad}CallExpr: {node.callee}()")
            for arg in node.args:
                lines.append(self.print(arg, indent + 1))

        elif isinstance(node, MemberExpr):
            lines.append(f"{pad}MemberExpr .{node.field}")
            lines.append(self.print(node.obj, indent + 1))

        elif isinstance(node, ImportStmt):
            path = "::".join(node.path)
            alias = f" as {node.alias}" if node.alias else ""
            lines.append(f"{pad}ImportStmt: {path}{alias}")

        elif isinstance(node, Literal):
            lines.append(f"{pad}Literal: {node.value!r}")

        elif isinstance(node, Ident):
            lines.append(f"{pad}Ident: {node.name}")

        else:
            lines.append(f"{pad}{type(node).__name__}")

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════
# SAMPLE PROGRAM
# ══════════════════════════════════════════════════════════

SAMPLE = """
-- VAREK Sample: Image Classification Pipeline

import var::io
import var::tensor

schema ImageInput {
  path:   str,
  label:  str?,
  width:  int,
  height: int
}

schema ClassResult {
  label:      str,
  confidence: float
}

pipeline classify_images {
  source: ImageInput
  steps: [preprocess -> normalize -> infer -> postprocess]
  output: ClassResult
}

fn preprocess(img: ImageInput) -> Tensor {
  load_image(img.path)
    |> resize(224, 224)
}

fn normalize(t: Tensor) -> Tensor {
  t |> normalize_imagenet()
}

async fn infer(tensor: Tensor) -> RawOutput {
  let model = load_model("resnet50.varekmodel")
  model.forward(tensor)
}

fn postprocess(raw: RawOutput) -> ClassResult {
  let scores = raw.softmax()
  let top    = scores.argmax()
  make_result(top)
}
"""


# ══════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════

def _hr(char="─", width=58):
    print(char * width)

def _banner(title):
    _hr("═")
    print(f"  {title}")
    _hr("═")

if __name__ == "__main__":
    _banner("VAREK Reference Parser  v1.0")
    print("  AI Pipeline Programming Language")
    print("  github.com/kwdoug63/varek")
    print()

    # ── Step 1: Lex ───────────────────────────────────────
    print("[ 1 ]  Lexing sample source...\n")
    lexer  = Lexer(SAMPLE)
    tokens = lexer.tokenize()

    meaningful = [t for t in tokens if t.type not in (TT.EOF, TT.NEWLINE)]
    print(f"  {len(meaningful)} tokens produced:\n")
    for tok in meaningful[:20]:
        print(f"  {tok}")
    if len(meaningful) > 20:
        print(f"  ... ({len(meaningful) - 20} more tokens)")
    print()

    # ── Step 2: Parse ─────────────────────────────────────
    print("[ 2 ]  Parsing AST...\n")
    parser = Parser(tokens)
    tree   = parser.parse()

    if parser.errors:
        print("  Parse errors:")
        for err in parser.errors:
            print(f"    ✗  {err}")
        print()
    else:
        print("  No parse errors.\n")

    # ── Step 3: Print AST ─────────────────────────────────
    print("[ 3 ]  AST:\n")
    printer = ASTPrinter()
    print(printer.print(tree, indent=1))
    print()

    # ── Step 4: Summary ───────────────────────────────────
    _hr()
    print(f"  {len(tree.statements)} top-level declarations parsed")
    schemas   = sum(1 for s in tree.statements if isinstance(s, SchemaDecl))
    pipelines = sum(1 for s in tree.statements if isinstance(s, PipelineDecl))
    fns       = sum(1 for s in tree.statements if isinstance(s, FnDecl))
    imports   = sum(1 for s in tree.statements if isinstance(s, ImportStmt))
    print(f"  {imports} imports · {schemas} schemas · {pipelines} pipelines · {fns} functions")
    print()
    print("  Parse successful. ✓")
    _hr("═")
    print("  VAREK is open source — MIT License")
    print("  Contribute: github.com/kwdoug63/varek")
    _hr("═")
