"""
varek/parser.py
──────────────────
Recursive-descent parser for VAREK v0.1.

Consumes a token list (from the Lexer) and produces a typed AST
(from varek.ast). Errors are collected in self.errors so that
all syntax problems in a file are surfaced in one pass.

The parser attempts synchronisation ("panic-mode recovery") after
each error so that downstream nodes are still parsed where possible.

Usage:
    from varek.lexer import Lexer
    from varek.parser import Parser

    tokens = Lexer(source, "main.syn").tokenize()
    parser = Parser(tokens, "main.syn")
    tree   = parser.parse()

    if parser.errors.has_errors():
        print(parser.errors.report(source.splitlines()))
"""

from __future__ import annotations

from typing import List, Optional, Callable, TypeVar

from varek.lexer import Token, TT
from varek.errors import (
    Span, ErrorBag,
    UnexpectedTokenError, UnexpectedEOFError, InvalidSyntaxError,
)
from varek.ast import (
    # Program
    Program,
    # Statements
    ImportStmt, SchemaDecl, SchemaField,
    PipelineDecl, PipelineConfig,
    FnDecl, Param,
    LetStmt, ReturnStmt, ExprStmt,
    # Expressions
    Literal, Ident, BinaryExpr, UnaryExpr,
    PipeExpr, CallExpr, Arg, MemberExpr, IndexExpr, PropagateExpr,
    IfExpr, MatchExpr, MatchArm, WildcardPattern,
    ForExpr, AwaitExpr, LambdaExpr, LambdaParam,
    ArrayLiteral, MapLiteral, MapEntry, TupleLiteral, Block,
    # Types
    NamedType, OptionalType, ArrayType, MapType,
    TupleType, TensorType, ResultType,
    # Base
    Node, TypeNode,
)

T = TypeVar("T")


# ══════════════════════════════════════════════════════════════════
# PARSER
# ══════════════════════════════════════════════════════════════════

class Parser:
    """
    Recursive-descent parser for VAREK.

    Each `parse_*` method corresponds to a grammar production.
    The naming convention mirrors the EBNF grammar in grammar/VAREK.ebnf.
    """

    # ── Synchronisation anchor tokens ─────────────────────────
    # After a parse error we skip tokens until we see one of these.
    SYNC_TOKENS = frozenset({
        TT.FN, TT.SCHEMA, TT.PIPELINE, TT.IMPORT,
        TT.LET, TT.MUT, TT.RETURN, TT.IF, TT.FOR,
        TT.MATCH, TT.RBRACE, TT.EOF,
    })

    def __init__(self, tokens: List[Token], filename: str = "<stdin>"):
        # Strip bare newlines — they are not significant at parse level
        self._tokens:  List[Token] = [t for t in tokens
                                       if t.type != TT.NEWLINE]
        self._pos:     int         = 0
        self.filename: str         = filename
        self.errors:   ErrorBag    = ErrorBag()

    # ══════════════════════════════════════════════════════════
    # PUBLIC ENTRY POINT
    # ══════════════════════════════════════════════════════════

    def parse(self) -> Program:
        """Parse the entire token stream and return a Program node."""
        start = self._peek().span
        statements: List[Node] = []

        while not self._at_end():
            stmt = self._parse_statement()
            if stmt is not None:
                statements.append(stmt)

        return Program(statements=statements, span=start)

    # ══════════════════════════════════════════════════════════
    # TOKEN NAVIGATION
    # ══════════════════════════════════════════════════════════

    def _at_end(self) -> bool:
        return self._peek().type == TT.EOF

    def _peek(self, offset: int = 0) -> Token:
        idx = self._pos + offset
        if idx < len(self._tokens):
            return self._tokens[idx]
        return self._tokens[-1]  # EOF sentinel

    def _advance(self) -> Token:
        tok = self._tokens[self._pos]
        if not self._at_end():
            self._pos += 1
        return tok

    def _check(self, *types: TT) -> bool:
        return self._peek().type in types

    def _match(self, *types: TT) -> bool:
        if self._check(*types):
            self._advance()
            return True
        return False

    def _expect(self, tt: TT, description: str = "") -> Optional[Token]:
        """
        Consume the next token if it matches `tt`, otherwise record
        an error and return None (the parser keeps going).
        """
        if self._peek().type == tt:
            return self._advance()
        span = self._peek().span
        if self._at_end():
            self.errors.add(
                UnexpectedEOFError(
                    expected=description or tt.name,
                    span=span,
                )
            )
        else:
            got = repr(self._peek().value) if self._peek().value is not None \
                else self._peek().type.name
            self.errors.add(
                UnexpectedTokenError(
                    expected=description or tt.name,
                    got=got,
                    span=span,
                )
            )
        return None

    def _current_span(self) -> Span:
        return self._peek().span

    def _synchronise(self) -> None:
        """Panic-mode recovery: skip tokens until a likely statement boundary."""
        while not self._at_end():
            if self._peek().type in self.SYNC_TOKENS:
                return
            self._advance()

    # ══════════════════════════════════════════════════════════
    # STATEMENTS
    # ══════════════════════════════════════════════════════════

    def _parse_statement(self) -> Optional[Node]:
        try:
            tok = self._peek()

            if tok.type == TT.SAFE or (
                    tok.type == TT.IMPORT):
                return self._parse_import()

            if tok.type == TT.SCHEMA:
                return self._parse_schema()

            if tok.type == TT.PIPELINE:
                return self._parse_pipeline()

            if tok.type in (TT.FN, TT.ASYNC, TT.EXPORT):
                return self._parse_fn()

            if tok.type in (TT.LET, TT.MUT):
                return self._parse_let()

            if tok.type == TT.RETURN:
                return self._parse_return()

            # Expression statement
            expr = self._parse_expr()
            if expr is None:
                self._advance()   # skip unrecognised token
                return None
            return ExprStmt(expr=expr, span=expr.span)

        except Exception as exc:
            # Last-resort catch: record and recover
            self.errors.add(
                InvalidSyntaxError(
                    message=str(exc),
                    span=self._current_span(),
                )
            )
            self._synchronise()
            return None

    # ── Import ────────────────────────────────────────────────

    def _parse_import(self) -> Optional[ImportStmt]:
        span = self._current_span()
        is_safe = self._match(TT.SAFE)
        self._expect(TT.IMPORT, "`import`")

        path: List[str] = []
        name_tok = self._expect(TT.IDENT, "module name")
        if name_tok:
            path.append(name_tok.value)

        while self._check(TT.SCOPE):
            self._advance()
            # Accept any token as a module segment (async, pipeline, etc. are keywords
            # but valid module names in syn:: paths)
            seg = self._peek()
            if seg.type == TT.EOF:
                break
            self._advance()
            seg_name = seg.value if isinstance(seg.value, str) else seg.type.name.lower()
            path.append(seg_name)

        alias: Optional[str] = None
        if self._match(TT.AS):
            alias_tok = self._expect(TT.IDENT, "alias name")
            if alias_tok:
                alias = alias_tok.value

        return ImportStmt(path=path, alias=alias, is_safe=is_safe, span=span)

    # ── Schema ────────────────────────────────────────────────

    def _parse_schema(self) -> Optional[SchemaDecl]:
        span = self._current_span()
        self._advance()  # 'schema'

        name_tok = self._expect(TT.IDENT, "schema name")
        name = name_tok.value if name_tok else "<error>"

        self._expect(TT.LBRACE, "`{`")
        fields: List[SchemaField] = []

        while not self._check(TT.RBRACE) and not self._at_end():
            f = self._parse_schema_field()
            if f:
                fields.append(f)

        self._expect(TT.RBRACE, "`}`")
        return SchemaDecl(name=name, fields=fields, span=span)

    def _parse_schema_field(self) -> Optional[SchemaField]:
        span = self._current_span()
        name_tok = self._expect(TT.IDENT, "field name")
        if not name_tok:
            self._synchronise()
            return None
        self._expect(TT.COLON, "`:`")
        type_ = self._parse_type()
        # _parse_type() consumes trailing ? and wraps in OptionalType.
        # Unwrap it and mark the field optional for cleaner AST representation.
        if isinstance(type_, OptionalType):
            optional = True
            type_ = type_.inner
        else:
            optional = self._match(TT.QMARK)
        self._match(TT.COMMA)
        return SchemaField(
            name=name_tok.value, type_=type_, optional=optional, span=span
        )

    # ── Pipeline ──────────────────────────────────────────────

    def _parse_pipeline(self) -> Optional[PipelineDecl]:
        span = self._current_span()
        self._advance()  # 'pipeline'

        name_tok = self._expect(TT.IDENT, "pipeline name")
        name = name_tok.value if name_tok else "<error>"

        self._expect(TT.LBRACE, "`{`")

        source_type: Optional[TypeNode] = None
        steps:  List[str]               = []
        output_type: Optional[TypeNode] = None
        config: Optional[PipelineConfig]= None

        while not self._check(TT.RBRACE) and not self._at_end():
            key_tok = self._expect(TT.IDENT, "pipeline clause keyword")
            if not key_tok:
                break
            key = key_tok.value

            # "config" uses bare { } directly — no colon separator
            if key == "config":
                config = self._parse_pipeline_config()
                continue

            self._expect(TT.COLON, "`:`")

            if key == "source":
                source_type = self._parse_type()

            elif key == "steps":
                self._expect(TT.LBRACK, "`[`")
                while not self._check(TT.RBRACK) and not self._at_end():
                    step_tok = self._expect(TT.IDENT, "step function name")
                    if step_tok:
                        steps.append(step_tok.value)
                    if not self._match(TT.ARROW):
                        break
                self._expect(TT.RBRACK, "`]`")

            elif key == "output":
                output_type = self._parse_type()

            else:
                self.errors.add(InvalidSyntaxError(
                    message=f"unknown pipeline clause `{key}`; "
                            "expected source, steps, output, or config",
                    span=key_tok.span,
                ))

        self._expect(TT.RBRACE, "`}`")

        return PipelineDecl(
            name=name,
            source_type=source_type or NamedType(name="<error>",
                                                  span=span),
            steps=steps,
            output_type=output_type or NamedType(name="<error>",
                                                  span=span),
            config=config,
            span=span,
        )

    def _parse_pipeline_config(self) -> PipelineConfig:
        span = self._current_span()
        self._expect(TT.LBRACE, "`{`")
        fields = []
        while not self._check(TT.RBRACE) and not self._at_end():
            key_tok = self._expect(TT.IDENT, "config key")
            self._expect(TT.COLON, "`:`")
            val = self._parse_literal()
            self._match(TT.COMMA)
            if key_tok and val:
                fields.append((key_tok.value, val))
        self._expect(TT.RBRACE, "`}`")
        return PipelineConfig(fields=fields, span=span)

    # ── Function declaration ──────────────────────────────────

    def _parse_fn(self) -> Optional[FnDecl]:
        span = self._current_span()
        is_export = self._match(TT.EXPORT)
        is_async  = self._match(TT.ASYNC)
        self._expect(TT.FN, "`fn`")

        name_tok = self._expect(TT.IDENT, "function name")
        name = name_tok.value if name_tok else "<error>"

        self._expect(TT.LPAREN, "`(`")
        params = self._parse_param_list()
        self._expect(TT.RPAREN, "`)`")

        return_type: Optional[TypeNode] = None
        if self._match(TT.ARROW):
            return_type = self._parse_type()

        body = self._parse_block()

        return FnDecl(
            name=name,
            params=params,
            return_type=return_type,
            body=body,
            is_async=is_async,
            is_export=is_export,
            span=span,
        )

    def _parse_param_list(self) -> List[Param]:
        params: List[Param] = []
        while not self._check(TT.RPAREN) and not self._at_end():
            span = self._current_span()
            name_tok = self._expect(TT.IDENT, "parameter name")
            self._expect(TT.COLON, "`:`")
            type_ = self._parse_type()
            if name_tok:
                params.append(Param(name=name_tok.value,
                                    type_=type_, span=span))
            if not self._match(TT.COMMA):
                break
        return params

    # ── Let statement ─────────────────────────────────────────

    def _parse_let(self) -> Optional[LetStmt]:
        span = self._current_span()
        mutable = self._match(TT.MUT)
        self._expect(TT.LET, "`let`")

        name_tok = self._expect(TT.IDENT, "variable name")
        name = name_tok.value if name_tok else "<error>"

        type_ann: Optional[TypeNode] = None
        if self._match(TT.COLON):
            type_ann = self._parse_type()

        # Accept both = and :=
        if not self._match(TT.ASSIGN) and not self._match(TT.WALRUS):
            self._expect(TT.ASSIGN, "`=`")

        value = self._parse_expr()
        return LetStmt(
            name=name, type_ann=type_ann,
            value=value, mutable=mutable, span=span,
        )

    # ── Return ────────────────────────────────────────────────

    def _parse_return(self) -> ReturnStmt:
        span = self._current_span()
        self._advance()  # 'return'
        value: Optional[Node] = None
        if not self._check(TT.RBRACE, TT.EOF):
            value = self._parse_expr()
        return ReturnStmt(value=value, span=span)

    # ── Block ─────────────────────────────────────────────────

    def _parse_block(self) -> Block:
        span = self._current_span()
        self._expect(TT.LBRACE, "`{`")
        stmts:    List[Node]   = []
        tail_expr: Optional[Node] = None

        while not self._check(TT.RBRACE) and not self._at_end():
            # Peek ahead: if this looks like a bare expression at the
            # end of the block (no following statement keyword), treat
            # it as the tail (implicit return value).
            if self._is_tail_expr_position():
                tail_expr = self._parse_expr()
                break

            stmt = self._parse_statement()
            if stmt is not None:
                stmts.append(stmt)

        self._expect(TT.RBRACE, "`}`")
        return Block(statements=stmts, tail_expr=tail_expr, span=span)

    def _is_tail_expr_position(self) -> bool:
        """
        Heuristic: if the next two tokens suggest an expression NOT
        followed by a statement-opening keyword, treat as tail expr.
        This is deliberately conservative; the type checker can fix
        ambiguous cases later.
        """
        # If the very next token is a closing brace, there's no tail.
        if self._check(TT.RBRACE):
            return False
        # If the next token is a statement-opening keyword, it's a stmt.
        if self._check(TT.LET, TT.MUT, TT.FN, TT.ASYNC, TT.EXPORT,
                       TT.SCHEMA, TT.PIPELINE, TT.IMPORT, TT.SAFE,
                       TT.RETURN, TT.FOR, TT.IF, TT.MATCH):
            return False
        # Look ahead: if after a complete expression there's `}`, it's tail.
        # We use a simple lookahead heuristic.
        saved = self._pos
        try:
            self._parse_expr()
            is_tail = self._check(TT.RBRACE)
        except Exception:
            is_tail = False
        finally:
            self._pos = saved
        return is_tail

    # ══════════════════════════════════════════════════════════
    # EXPRESSIONS  (Pratt / precedence climbing)
    # ══════════════════════════════════════════════════════════

    def _parse_expr(self) -> Node:
        return self._parse_pipe()

    # ── Pipe: lowest precedence  left-assoc ──────────────────

    def _parse_pipe(self) -> Node:
        left = self._parse_or()
        while self._check(TT.PIPE_FWD):
            span = self._current_span()
            self._advance()
            right = self._parse_or()
            left = PipeExpr(left=left, right=right, span=span)
        return left

    # ── Boolean or ───────────────────────────────────────────

    def _parse_or(self) -> Node:
        left = self._parse_and()
        while self._check(TT.OR):
            span = self._current_span()
            op = self._advance().value
            right = self._parse_and()
            left = BinaryExpr(op=op, left=left, right=right, span=span)
        return left

    # ── Boolean and ──────────────────────────────────────────

    def _parse_and(self) -> Node:
        left = self._parse_not()
        while self._check(TT.AND):
            span = self._current_span()
            op = self._advance().value
            right = self._parse_not()
            left = BinaryExpr(op=op, left=left, right=right, span=span)
        return left

    # ── Logical not ──────────────────────────────────────────

    def _parse_not(self) -> Node:
        if self._check(TT.NOT):
            span = self._current_span()
            self._advance()
            operand = self._parse_not()
            return UnaryExpr(op="not", operand=operand, span=span)
        return self._parse_comparison()

    # ── Comparison ───────────────────────────────────────────

    COMPARISON_OPS = frozenset({TT.EQ, TT.NEQ, TT.LT, TT.GT, TT.LTE, TT.GTE})

    def _parse_comparison(self) -> Node:
        left = self._parse_add()
        if self._peek().type in self.COMPARISON_OPS:
            span = self._current_span()
            op = self._advance().value
            right = self._parse_add()
            return BinaryExpr(op=op, left=left, right=right, span=span)
        return left

    # ── Additive ─────────────────────────────────────────────

    def _parse_add(self) -> Node:
        left = self._parse_mul()
        while self._check(TT.PLUS, TT.MINUS):
            span = self._current_span()
            op = self._advance().value
            right = self._parse_mul()
            left = BinaryExpr(op=op, left=left, right=right, span=span)
        return left

    # ── Multiplicative ───────────────────────────────────────

    def _parse_mul(self) -> Node:
        left = self._parse_unary()
        while self._check(TT.STAR, TT.SLASH, TT.PERCENT):
            span = self._current_span()
            op = self._advance().value
            right = self._parse_unary()
            left = BinaryExpr(op=op, left=left, right=right, span=span)
        return left

    # ── Unary prefix ─────────────────────────────────────────

    def _parse_unary(self) -> Node:
        if self._check(TT.MINUS):
            span = self._current_span()
            self._advance()
            return UnaryExpr(op="-", operand=self._parse_unary(), span=span)
        if self._check(TT.NOT):
            span = self._current_span()
            self._advance()
            return UnaryExpr(op="not", operand=self._parse_unary(), span=span)
        return self._parse_postfix()

    # ── Postfix: . [] () ? ────────────────────────────────────

    def _parse_postfix(self) -> Node:
        expr = self._parse_primary()

        while True:
            if self._check(TT.DOT):
                span = self._current_span()
                self._advance()
                field_tok = self._expect(TT.IDENT, "field name")
                field = field_tok.value if field_tok else "<error>"
                expr = MemberExpr(obj=expr, field=field, span=span)

            elif self._check(TT.LBRACK):
                span = self._current_span()
                self._advance()
                index = self._parse_expr()
                self._expect(TT.RBRACK, "`]`")
                expr = IndexExpr(obj=expr, index=index, span=span)

            elif self._check(TT.LPAREN):
                span = self._current_span()
                self._advance()
                args = self._parse_arg_list()
                self._expect(TT.RPAREN, "`)`")
                expr = CallExpr(callee=expr, args=args, span=span)

            elif self._check(TT.QMARK):
                span = self._current_span()
                self._advance()
                expr = PropagateExpr(expr=expr, span=span)

            else:
                break

        return expr

    def _parse_arg_list(self) -> List[Arg]:
        args: List[Arg] = []
        while not self._check(TT.RPAREN) and not self._at_end():
            span = self._current_span()
            # Keyword arg: name = expr
            if (self._peek().type == TT.IDENT
                    and self._peek(1).type == TT.ASSIGN):
                kw = self._advance().value
                self._advance()  # '='
                val = self._parse_expr()
                args.append(Arg(value=val, keyword=kw, span=span))
            else:
                val = self._parse_expr()
                args.append(Arg(value=val, keyword=None, span=span))
            if not self._match(TT.COMMA):
                break
        return args

    # ── Primary expressions ───────────────────────────────────

    def _parse_primary(self) -> Node:
        tok = self._peek()
        span = tok.span

        # Literals
        if tok.type in (TT.INT, TT.FLOAT, TT.STRING, TT.BOOL, TT.NIL):
            return self._parse_literal()

        # Await
        if tok.type == TT.AWAIT:
            self._advance()
            expr = self._parse_unary()
            return AwaitExpr(expr=expr, span=span)

        # If expression
        if tok.type == TT.IF:
            return self._parse_if()

        # Match expression
        if tok.type == TT.MATCH:
            return self._parse_match()

        # For expression
        if tok.type == TT.FOR:
            return self._parse_for()

        # Block expression
        if tok.type == TT.LBRACE:
            return self._parse_block()

        # Grouped expression or tuple literal
        if tok.type == TT.LPAREN:
            return self._parse_paren_or_tuple()

        # Array literal
        if tok.type == TT.LBRACK:
            return self._parse_array_literal()

        # Lambda: |params| expr
        # Note: we check for | (PIPE_FWD starts with |, but | alone is lexed
        # as BANG with value '|' as fallback — handle lambda via BANG check)
        # Lambda syntax uses bare | so we special-case BANG with value '|'
        if tok.type == TT.BANG and tok.value == "|":
            return self._parse_lambda()

        # Identifier
        if tok.type == TT.IDENT:
            self._advance()
            return Ident(name=tok.value, span=span)

        # Unrecognised
        self.errors.add(UnexpectedTokenError(
            expected="expression",
            got=repr(tok.value) if tok.value is not None else tok.type.name,
            span=span,
        ))
        self._advance()
        # Return a sentinel so callers don't crash
        return Literal(value=None, span=span)

    # ── Literal ───────────────────────────────────────────────

    def _parse_literal(self) -> Literal:
        tok = self._advance()
        return Literal(value=tok.value, span=tok.span)

    # ── If expression ─────────────────────────────────────────

    def _parse_if(self) -> IfExpr:
        span = self._current_span()
        self._advance()  # 'if'
        condition = self._parse_expr()
        then_block = self._parse_block()

        else_branch: Optional[Node] = None
        if self._match(TT.ELSE):
            if self._check(TT.IF):
                else_branch = self._parse_if()
            else:
                else_branch = self._parse_block()

        return IfExpr(
            condition=condition,
            then_block=then_block,
            else_branch=else_branch,
            span=span,
        )

    # ── Match expression ──────────────────────────────────────

    def _parse_match(self) -> MatchExpr:
        span = self._current_span()
        self._advance()  # 'match'
        subject = self._parse_expr()
        self._expect(TT.LBRACE, "`{`")
        arms: List[MatchArm] = []

        while not self._check(TT.RBRACE) and not self._at_end():
            arm_span = self._current_span()
            pattern = self._parse_match_pattern()
            self._expect(TT.FAT_ARROW, "`=>`")
            if self._check(TT.LBRACE):
                body = self._parse_block()
            else:
                body = self._parse_expr()
            self._match(TT.COMMA)
            arms.append(MatchArm(pattern=pattern, body=body, span=arm_span))

        self._expect(TT.RBRACE, "`}`")
        return MatchExpr(subject=subject, arms=arms, span=span)

    def _parse_match_pattern(self) -> Node:
        tok = self._peek()
        if tok.type == TT.IDENT and tok.value == "_":
            self._advance()
            return WildcardPattern(span=tok.span)
        if tok.type in (TT.INT, TT.FLOAT, TT.STRING, TT.BOOL, TT.NIL):
            return self._parse_literal()
        if tok.type == TT.IDENT:
            self._advance()
            return Ident(name=tok.value, span=tok.span)
        # Fallback
        self.errors.add(UnexpectedTokenError(
            expected="match pattern",
            got=str(tok.value),
            span=tok.span,
        ))
        self._advance()
        return WildcardPattern(span=tok.span)

    # ── For expression ────────────────────────────────────────

    def _parse_for(self) -> ForExpr:
        span = self._current_span()
        self._advance()  # 'for'
        var_tok = self._expect(TT.IDENT, "loop variable")
        var = var_tok.value if var_tok else "<error>"
        self._expect(TT.IN, "`in`")
        iterable = self._parse_expr()
        body = self._parse_block()
        return ForExpr(var=var, iterable=iterable, body=body, span=span)

    # ── Parenthesised expr or tuple ───────────────────────────

    def _parse_paren_or_tuple(self) -> Node:
        span = self._current_span()
        self._advance()  # '('

        if self._check(TT.RPAREN):
            # Empty tuple ()
            self._advance()
            return TupleLiteral(elements=[], span=span)

        first = self._parse_expr()

        if self._check(TT.RPAREN):
            self._advance()
            return first   # just a grouped expression

        # Must be a tuple
        elements = [first]
        while self._match(TT.COMMA):
            if self._check(TT.RPAREN):
                break
            elements.append(self._parse_expr())
        self._expect(TT.RPAREN, "`)`")
        return TupleLiteral(elements=elements, span=span)

    # ── Array literal ─────────────────────────────────────────

    def _parse_array_literal(self) -> ArrayLiteral:
        span = self._current_span()
        self._advance()  # '['
        elements: List[Node] = []

        while not self._check(TT.RBRACK) and not self._at_end():
            elements.append(self._parse_expr())
            if not self._match(TT.COMMA):
                break

        self._expect(TT.RBRACK, "`]`")
        return ArrayLiteral(elements=elements, span=span)

    # ── Lambda ────────────────────────────────────────────────

    def _parse_lambda(self) -> LambdaExpr:
        span = self._current_span()
        self._advance()  # '|'
        params: List[LambdaParam] = []

        while not (self._check(TT.BANG) and self._peek().value == "|") \
                and not self._at_end():
            p_span = self._current_span()
            name_tok = self._expect(TT.IDENT, "parameter")
            name = name_tok.value if name_tok else "<error>"
            type_: Optional[TypeNode] = None
            if self._match(TT.COLON):
                type_ = self._parse_type()
            params.append(LambdaParam(name=name, type_=type_, span=p_span))
            if not self._match(TT.COMMA):
                break

        # Consume closing '|'
        if self._check(TT.BANG) and self._peek().value == "|":
            self._advance()

        return_type: Optional[TypeNode] = None
        if self._match(TT.ARROW):
            return_type = self._parse_type()

        if self._check(TT.LBRACE):
            body = self._parse_block()
        else:
            body = self._parse_expr()

        return LambdaExpr(
            params=params, return_type=return_type, body=body, span=span)

    # ══════════════════════════════════════════════════════════
    # TYPE EXPRESSIONS
    # ══════════════════════════════════════════════════════════

    def _parse_type(self) -> TypeNode:
        span = self._current_span()
        base = self._parse_base_type()

        # Postfix: ? and []
        while True:
            if self._check(TT.QMARK):
                self._advance()
                base = OptionalType(inner=base, span=span)
            elif self._check(TT.LBRACK) and self._peek(1).type == TT.RBRACK:
                self._advance()  # '['
                self._advance()  # ']'
                base = ArrayType(element=base, span=span)
            else:
                break

        return base

    def _parse_base_type(self) -> TypeNode:
        span = self._current_span()
        tok = self._peek()

        # Map type: {K: V}
        if tok.type == TT.LBRACE:
            self._advance()
            key = self._parse_type()
            self._expect(TT.COLON, "`:`")
            val = self._parse_type()
            self._expect(TT.RBRACE, "`}`")
            return MapType(key_type=key, val_type=val, span=span)

        # Tuple type: (A, B, ...)
        if tok.type == TT.LPAREN:
            self._advance()
            elements: List[TypeNode] = []
            while not self._check(TT.RPAREN) and not self._at_end():
                elements.append(self._parse_type())
                if not self._match(TT.COMMA):
                    break
            self._expect(TT.RPAREN, "`)`")
            return TupleType(elements=elements, span=span)

        # Named type — also accept nil/bool/int/float/str as type-position keywords
        if tok.type in (TT.IDENT, TT.NIL, TT.BOOL):
            self._advance()
            name = tok.value if tok.value is not None else tok.type.name.lower()

            if name == "Tensor" and self._check(TT.LT):
                return self._parse_tensor_type(span)

            if name == "Result" and self._check(TT.LT):
                self._advance()  # '<'
                inner = self._parse_type()
                self._expect(TT.GT, "`>`")
                return ResultType(ok_type=inner, span=span)

            return NamedType(name=name, span=span)

        # Fallback
        self.errors.add(UnexpectedTokenError(
            expected="type",
            got=str(tok.value) if tok.value else tok.type.name,
            span=span,
        ))
        return NamedType(name="<error>", span=span)

    def _parse_tensor_type(self, span: Span) -> TensorType:
        """Tensor<T, [D0, D1, ...]>"""
        self._advance()  # '<'
        element = self._parse_type()
        self._expect(TT.COMMA, "`,`")
        self._expect(TT.LBRACK, "`[`")
        dims: List[int] = []
        while not self._check(TT.RBRACK) and not self._at_end():
            dim_tok = self._expect(TT.INT, "dimension size")
            if dim_tok:
                dims.append(dim_tok.value)
            if not self._match(TT.COMMA):
                break
        self._expect(TT.RBRACK, "`]`")
        self._expect(TT.GT, "`>`")
        return TensorType(element=element, dims=dims, span=span)
