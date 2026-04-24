"""
varek/infer.py
────────────────
Hindley-Milner type inference for VAREK v0.2.

Implements Algorithm W (Damas-Milner, 1982) extended with:
  - Let-polymorphism
  - Optional/nullable inference
  - Tensor shape constraint propagation
  - Result<T> and ? propagation tracking
  - Recursive function support

Algorithm W summary:
  infer(Γ, e) = (S, T)
    S : Substitution   (what we learned about type variables)
    T : Type           (the type of expression e under S(Γ))

  infer is called recursively on sub-expressions, composing
  substitutions and applying them to the environment as we go.

References:
  Damas, L. & Milner, R. (1982). Principal type-schemes for
  functional programs. POPL 9.

  Heeren, B., Leijen, D., & van IJzendoorn, A. (2002). Generalizing
  Hindley-Milner type inference algorithms. UU Technical Report.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from varek.types import (
    Type, TypeVar, Scheme, Substitution,
    PrimType, OptionalType, ArrayType, MapType, TupleType,
    TensorType, ResultType, FunctionType, SchemaType,
    T_INT, T_FLOAT, T_STR, T_BOOL, T_NIL,
    Dim, fresh_var, fresh_dim,
)
from varek.env import TypeEnv, SchemaRegistry
from varek.unify import unify, unify_numeric, UnifyError
from varek.errors import Span, VarekError, ErrorBag
from varek.builtins import build_global_env, get_methods_for_type, BUILTIN_METHODS
import varek.ast as ast


# ══════════════════════════════════════════════════════════════════
# INFERENCE RESULT
# ══════════════════════════════════════════════════════════════════

class InferResult:
    """Bundles substitution + type returned from infer()."""
    def __init__(self, subst: Substitution, type_: Type):
        self.subst = subst
        self.type_ = type_

    def apply(self) -> "InferResult":
        return InferResult(self.subst, self.type_.apply(self.subst))

    def __repr__(self):
        return f"InferResult(type={self.type_})"


W = InferResult   # convenient alias


# ══════════════════════════════════════════════════════════════════
# TYPE ANNOTATION TRANSLATOR
# ══════════════════════════════════════════════════════════════════

def ast_type_to_syn_type(
    ann:      ast.TypeNode,
    schemas:  SchemaRegistry,
    span:     Span,
) -> Type:
    """
    Convert an AST type node (from the parser) into a runtime Type.

    This is called when the programmer writes an explicit type
    annotation. The result is used as a constraint during inference.
    """
    if isinstance(ann, ast.NamedType):
        name = ann.name
        # Primitive types
        if name == "int":   return T_INT
        if name == "float": return T_FLOAT
        if name == "str":   return T_STR
        if name == "bool":  return T_BOOL
        if name == "nil":   return T_NIL
        # Known schemas
        if schemas.contains(name):
            return schemas.lookup(name, span)
        # Unknown name — treat as a fresh type variable
        # (could be a forward reference or external type)
        return fresh_var(name)

    if isinstance(ann, ast.OptionalType):
        inner = ast_type_to_syn_type(ann.inner, schemas, span)
        return OptionalType(inner)

    if isinstance(ann, ast.ArrayType):
        elem = ast_type_to_syn_type(ann.element, schemas, span)
        return ArrayType(elem)

    if isinstance(ann, ast.MapType):
        k = ast_type_to_syn_type(ann.key_type, schemas, span)
        v = ast_type_to_syn_type(ann.val_type, schemas, span)
        return MapType(k, v)

    if isinstance(ann, ast.TupleType):
        elems = tuple(ast_type_to_syn_type(e, schemas, span)
                      for e in ann.elements)
        return TupleType(elems)

    if isinstance(ann, ast.TensorType):
        elem = ast_type_to_syn_type(ann.element, schemas, span)
        dims = tuple(
            Dim(value=d) if isinstance(d, int) else Dim(var=str(d))
            for d in ann.dims
        )
        return TensorType(elem, dims)

    if isinstance(ann, ast.ResultType):
        ok = ast_type_to_syn_type(ann.ok_type, schemas, span)
        return ResultType(ok)

    # Fallback
    return fresh_var("unknown")


# ══════════════════════════════════════════════════════════════════
# INFERRER
# ══════════════════════════════════════════════════════════════════

class Inferrer:
    """
    Walks the AST and infers types using Algorithm W.

    State:
      self.errors   — collected type errors (non-fatal path)
      self.schemas  — registry of declared schemas
      self._types   — maps AST node id -> inferred Type (for IDE use)
    """

    def __init__(self, errors: ErrorBag, schemas: SchemaRegistry):
        self.errors  = errors
        self.schemas = schemas
        self._types: dict[int, Type] = {}   # node id -> type

    # ── Public API ────────────────────────────────────────────

    def infer_program(
        self,
        program: ast.Program,
        env:     TypeEnv,
    ) -> Tuple[Substitution, TypeEnv]:
        """
        Infer types for a whole program.
        Returns the final substitution and the enriched environment.
        """
        subst = Substitution.EMPTY
        current_env = env

        for stmt in program.statements:
            try:
                s, new_env = self._infer_toplevel(stmt, current_env, subst)
                subst = subst.compose(s)
                current_env = new_env.apply(subst)
            except VarekError as e:
                self.errors.add(e)

        return subst, current_env

    # ── Top-level statements ──────────────────────────────────

    def _infer_toplevel(
        self,
        node: ast.Node,
        env:  TypeEnv,
        subst: Substitution,
    ) -> Tuple[Substitution, TypeEnv]:
        """Returns (substitution, updated_env)."""

        if isinstance(node, ast.ImportStmt):
            # Imports don't affect type inference in v0.2
            return subst, env

        if isinstance(node, ast.SchemaDecl):
            return self._process_schema(node, env, subst)

        if isinstance(node, ast.FnDecl):
            return self._infer_fn_decl(node, env, subst)

        if isinstance(node, ast.PipelineDecl):
            return self._infer_pipeline_decl(node, env, subst)

        if isinstance(node, ast.LetStmt):
            s, ty = self._infer_let(node, env, subst)
            scheme = env.apply(s).generalize(ty)
            new_env = env.extend(node.name, scheme)
            return s, new_env

        if isinstance(node, ast.ExprStmt):
            s, ty = self._infer_expr(node.expr, env, subst)
            return s, env

        if isinstance(node, ast.ReturnStmt):
            if node.value:
                s, _ = self._infer_expr(node.value, env, subst)
                return s, env
            return subst, env

        return subst, env

    # ── Schema processing ─────────────────────────────────────

    def _process_schema(
        self, node: ast.SchemaDecl, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, TypeEnv]:
        from varek.types import FieldDef, SchemaType

        fields = []
        for f in node.fields:
            ty = ast_type_to_syn_type(f.type_, self.schemas, f.span)
            fields.append(FieldDef(f.name, ty, f.optional))

        schema_ty = SchemaType(node.name, tuple(fields))
        self.schemas.register(schema_ty)

        # Bind the schema name in the environment as a type
        new_env = env.extend_mono(node.name, schema_ty)
        return subst, new_env

    # ── Function declaration ──────────────────────────────────

    def _infer_fn_decl(
        self, node: ast.FnDecl, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, TypeEnv]:
        # Build param types from annotations (or fresh vars if missing)
        param_types = []
        for p in node.params:
            ty = ast_type_to_syn_type(p.type_, self.schemas, p.span)
            param_types.append(ty)

        # Annotated return type (or fresh var)
        if node.return_type:
            ret_ann = ast_type_to_syn_type(
                node.return_type, self.schemas, node.span)
        else:
            ret_ann = fresh_var("r")

        # Build child env with params bound
        child_env = env
        for p, pt in zip(node.params, param_types):
            child_env = child_env.extend_mono(p.name, pt)

        # For recursion: pre-bind the function name with its expected type
        fn_type = FunctionType(tuple(param_types), ret_ann)
        child_env = child_env.extend_mono(node.name, fn_type)

        # Infer body
        try:
            s, body_ty = self._infer_block(node.body, child_env, subst)
        except VarekError as e:
            self.errors.add(e)
            s, body_ty = subst, ret_ann

        # Unify body type with declared return type
        try:
            s2 = unify(body_ty.apply(s), ret_ann.apply(s), node.span)
            s  = s.compose(s2)
        except UnifyError as e:
            self.errors.add(e)

        # Apply substitution to get final function type
        final_params = tuple(pt.apply(s) for pt in param_types)
        final_ret    = ret_ann.apply(s)
        final_fn     = FunctionType(final_params, final_ret)

        # Generalise for let-polymorphism
        scheme = env.apply(s).generalize(final_fn)
        new_env = env.extend(node.name, scheme)

        self._record(node, final_fn)
        return s, new_env

    # ── Pipeline declaration ──────────────────────────────────

    def _infer_pipeline_decl(
        self, node: ast.PipelineDecl, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, TypeEnv]:
        """
        Type-check a pipeline declaration.

        Rules:
          1. Resolve source and output types from annotations.
          2. For each step function in order, ensure the function
             exists in the environment and its input type is compatible
             with the output type of the previous stage.
          3. Verify the final step output matches the declared output type.
        """
        source_ty = ast_type_to_syn_type(
            node.source_type, self.schemas, node.span)
        output_ty = ast_type_to_syn_type(
            node.output_type, self.schemas, node.span)

        # Pipelines stream elements: source T[] -> steps operate on T
        # output T[] -> steps produce T (we wrap back at the end).
        if isinstance(source_ty, ArrayType):
            current_ty = source_ty.element
        else:
            current_ty = source_ty

        # Expected output element type (unwrap array if declared as array)
        if isinstance(output_ty, ArrayType):
            expected_out_elem = output_ty.element
        else:
            expected_out_elem = output_ty

        s = subst

        for step_name in node.steps:
            try:
                step_scheme = env.lookup(step_name, node.span)
            except VarekError as e:
                self.errors.add(e)
                current_ty = fresh_var("step")
                continue

            step_ty = step_scheme.instantiate().apply(s)

            if isinstance(step_ty, FunctionType):
                if step_ty.arity() == 0:
                    self.errors.add(VarekError(
                        message=(f"pipeline step `{step_name}` takes no arguments; "
                                 "expected a function of one argument"),
                        span=node.span,
                    ))
                    current_ty = step_ty.return_type
                    continue

                # Unify current_ty with the step's first param
                try:
                    s2 = unify(current_ty.apply(s),
                               step_ty.params[0].apply(s), node.span)
                    s = s.compose(s2)
                except UnifyError as e:
                    self.errors.add(VarekError(
                        message=(f"pipeline step `{step_name}`: "
                                 f"input type mismatch — "
                                 f"expected `{step_ty.params[0]}`, "
                                 f"found `{current_ty}`"),
                        span=node.span,
                    ))

                current_ty = step_ty.return_type.apply(s)
            else:
                self.errors.add(VarekError(
                    message=(f"`{step_name}` is not a function; "
                             "pipeline steps must be functions"),
                    span=node.span,
                ))

        # Verify final output element type
        try:
            s2 = unify(current_ty.apply(s), expected_out_elem.apply(s), node.span)
            s  = s.compose(s2)
        except UnifyError as e:
            self.errors.add(VarekError(
                message=(f"pipeline `{node.name}` output type mismatch: "
                         f"last step produces `{current_ty}`, "
                         f"declared element type `{expected_out_elem}`"),
                span=node.span,
            ))

        # Bind the pipeline name as a function in the environment
        pipeline_fn = FunctionType((source_ty,), output_ty)
        new_env = env.extend_mono(node.name, pipeline_fn)
        return s, new_env

    # ── Let statement ─────────────────────────────────────────

    def _infer_let(
        self, node: ast.LetStmt, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        s, ty = self._infer_expr(node.value, env, subst)

        if node.type_ann:
            ann_ty = ast_type_to_syn_type(
                node.type_ann, self.schemas, node.span)
            try:
                s2 = unify(ty.apply(s), ann_ty.apply(s), node.span)
                s  = s.compose(s2)
                ty = ann_ty.apply(s)
            except UnifyError as e:
                self.errors.add(e)

        self._record(node, ty.apply(s))
        return s, ty.apply(s)

    # ── Block ─────────────────────────────────────────────────

    def _infer_block(
        self, block: ast.Block, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        s = subst
        block_env = env.child()

        for stmt in block.statements:
            try:
                if isinstance(stmt, ast.LetStmt):
                    ls, ty = self._infer_let(stmt, block_env, s)
                    s = s.compose(ls)
                    scheme = block_env.apply(s).generalize(ty)
                    block_env.bind_local(stmt.name, scheme)

                elif isinstance(stmt, ast.ExprStmt):
                    es, _ = self._infer_expr(stmt.expr, block_env, s)
                    s = s.compose(es)

                elif isinstance(stmt, ast.ReturnStmt):
                    if stmt.value:
                        rs, rt = self._infer_expr(stmt.value, block_env, s)
                        s = s.compose(rs)
                    # Return stmts don't affect block type directly

                else:
                    ns, _ = self._infer_toplevel(stmt, block_env, s)
                    s = s.compose(ns)

            except VarekError as e:
                self.errors.add(e)

        # Tail expression is the block's type.
        # Also treat a terminal ExprStmt as the tail (covers if/match/for
        # as the last statement — the parser marks these as statements
        # when they appear at block-end, not as tail_expr).
        if block.tail_expr:
            try:
                ts, ty = self._infer_expr(block.tail_expr, block_env, s)
                s = s.compose(ts)
                return s, ty.apply(s)
            except VarekError as e:
                self.errors.add(e)
                return s, T_NIL

        # If the last statement is an expression statement, its type is
        # the block type (implicit return value).
        if block.statements:
            last = block.statements[-1]
            if isinstance(last, ast.ExprStmt):
                try:
                    ts, ty = self._infer_expr(last.expr, block_env, s)
                    s = s.compose(ts)
                    return s, ty.apply(s)
                except VarekError:
                    pass

        return s, T_NIL

    # ══════════════════════════════════════════════════════════
    # EXPRESSION INFERENCE  (the core of Algorithm W)
    # ══════════════════════════════════════════════════════════

    def _infer_expr(
        self,
        node:  ast.Node,
        env:   TypeEnv,
        subst: Substitution,
    ) -> Tuple[Substitution, Type]:
        """
        Infer the type of an expression node.
        Returns (substitution, type).

        The substitution is composed outward by the caller.
        """

        # ── Literal ───────────────────────────────────────────
        if isinstance(node, ast.Literal):
            ty = self._literal_type(node)
            self._record(node, ty)
            return subst, ty

        # ── Identifier ────────────────────────────────────────
        if isinstance(node, ast.Ident):
            scheme = env.lookup(node.name, node.span)
            ty     = scheme.instantiate().apply(subst)
            self._record(node, ty)
            return subst, ty

        # ── Binary expression ─────────────────────────────────
        if isinstance(node, ast.BinaryExpr):
            return self._infer_binary(node, env, subst)

        # ── Unary expression ──────────────────────────────────
        if isinstance(node, ast.UnaryExpr):
            return self._infer_unary(node, env, subst)

        # ── Pipe expression ───────────────────────────────────
        if isinstance(node, ast.PipeExpr):
            return self._infer_pipe(node, env, subst)

        # ── Call expression ───────────────────────────────────
        if isinstance(node, ast.CallExpr):
            return self._infer_call(node, env, subst)

        # ── Member access ─────────────────────────────────────
        if isinstance(node, ast.MemberExpr):
            return self._infer_member(node, env, subst)

        # ── Index access ──────────────────────────────────────
        if isinstance(node, ast.IndexExpr):
            return self._infer_index(node, env, subst)

        # ── Error propagation ? ───────────────────────────────
        if isinstance(node, ast.PropagateExpr):
            return self._infer_propagate(node, env, subst)

        # ── Await ─────────────────────────────────────────────
        if isinstance(node, ast.AwaitExpr):
            # await expr : type of expr (async effect is erased)
            return self._infer_expr(node.expr, env, subst)

        # ── If expression ─────────────────────────────────────
        if isinstance(node, ast.IfExpr):
            return self._infer_if(node, env, subst)

        # ── Match expression ──────────────────────────────────
        if isinstance(node, ast.MatchExpr):
            return self._infer_match(node, env, subst)

        # ── For expression ────────────────────────────────────
        if isinstance(node, ast.ForExpr):
            return self._infer_for(node, env, subst)

        # ── Lambda ────────────────────────────────────────────
        if isinstance(node, ast.LambdaExpr):
            return self._infer_lambda(node, env, subst)

        # ── Block ─────────────────────────────────────────────
        if isinstance(node, ast.Block):
            return self._infer_block(node, env, subst)

        # ── Array literal ─────────────────────────────────────
        if isinstance(node, ast.ArrayLiteral):
            return self._infer_array(node, env, subst)

        # ── Map literal ───────────────────────────────────────
        if isinstance(node, ast.MapLiteral):
            return self._infer_map_lit(node, env, subst)

        # ── Tuple literal ─────────────────────────────────────
        if isinstance(node, ast.TupleLiteral):
            return self._infer_tuple_lit(node, env, subst)

        # ── Expression statement ──────────────────────────────
        if isinstance(node, ast.ExprStmt):
            return self._infer_expr(node.expr, env, subst)

        # Fallback: unknown node kind
        tv = fresh_var("unknown")
        return subst, tv

    # ── Literals ──────────────────────────────────────────────

    def _literal_type(self, node: ast.Literal) -> Type:
        v = node.value
        if v is None:              return T_NIL
        if isinstance(v, bool):    return T_BOOL
        if isinstance(v, int):     return T_INT
        if isinstance(v, float):   return T_FLOAT
        if isinstance(v, str):     return T_STR
        return fresh_var("lit")

    # ── Binary expressions ────────────────────────────────────

    COMPARISON_OPS = frozenset({"==", "!=", "<", ">", "<=", ">="})
    BOOL_OPS       = frozenset({"and", "or"})
    ARITH_OPS      = frozenset({"+", "-", "*", "/", "%"})

    def _infer_binary(
        self, node: ast.BinaryExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        sl, tl = self._infer_expr(node.left,  env, subst)
        sr, tr = self._infer_expr(node.right, env, sl)
        s = sl.compose(sr)
        tl = tl.apply(s)
        tr = tr.apply(s)
        span = node.span

        if node.op in self.COMPARISON_OPS:
            try:
                s2 = unify(tl, tr, span)
                s  = s.compose(s2)
            except UnifyError as e:
                self.errors.add(e)
            self._record(node, T_BOOL)
            return s, T_BOOL

        if node.op in self.BOOL_OPS:
            for side, ty in [(node.left, tl), (node.right, tr)]:
                try:
                    s2 = unify(ty, T_BOOL, span)
                    s  = s.compose(s2)
                except UnifyError:
                    self.errors.add(VarekError(
                        message=(f"operands of `{node.op}` must be `bool`, "
                                 f"found `{ty}`"),
                        span=span,
                    ))
            self._record(node, T_BOOL)
            return s, T_BOOL

        if node.op in self.ARITH_OPS:
            # String concatenation: str + str -> str
            if node.op == "+":
                if isinstance(tl.apply(s), PrimType) and tl.apply(s) == T_STR:
                    try:
                        s2 = unify(tr, T_STR, span)
                        s  = s.compose(s2)
                        self._record(node, T_STR)
                        return s, T_STR
                    except UnifyError:
                        pass

            # Numeric widening
            try:
                result_ty, s2 = unify_numeric(tl, tr, span)
                s = s.compose(s2)
                self._record(node, result_ty)
                return s, result_ty
            except UnifyError as e:
                self.errors.add(e)
                self._record(node, T_FLOAT)
                return s, T_FLOAT

        # Unknown operator
        self._record(node, fresh_var("op"))
        return s, fresh_var("op")

    # ── Unary expressions ─────────────────────────────────────

    def _infer_unary(
        self, node: ast.UnaryExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        s, ty = self._infer_expr(node.operand, env, subst)
        ty = ty.apply(s)
        span = node.span

        if node.op == "not":
            try:
                s2 = unify(ty, T_BOOL, span)
                s = s.compose(s2)
            except UnifyError:
                self.errors.add(VarekError(
                    message=f"`not` requires `bool`, found `{ty}`",
                    span=span,
                ))
            self._record(node, T_BOOL)
            return s, T_BOOL

        if node.op == "-":
            if ty == T_INT:
                self._record(node, T_INT)
                return s, T_INT
            try:
                s2 = unify(ty, T_FLOAT, span)
                s = s.compose(s2)
                self._record(node, T_FLOAT)
                return s, T_FLOAT
            except UnifyError:
                self.errors.add(VarekError(
                    message=f"unary `-` requires numeric type, found `{ty}`",
                    span=span,
                ))
                return s, T_FLOAT

        return s, ty

    # ── Pipe expression ───────────────────────────────────────

    def _infer_pipe(
        self, node: ast.PipeExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        """
        left |> right

        The pipe desugars to right(left) — the left value is passed
        as the first argument to the right function.
        """
        sl, tl = self._infer_expr(node.left,  env, subst)
        sr, tr = self._infer_expr(node.right, env, sl)
        s = sl.compose(sr)
        tl = tl.apply(s)
        tr = tr.apply(s)

        # tr must be a function
        ret_var = fresh_var("pipe")
        expected_fn = FunctionType((tl,), ret_var)
        try:
            s2 = unify(tr, expected_fn, node.span)
            s  = s.compose(s2)
            result_ty = ret_var.apply(s)
        except UnifyError as e:
            self.errors.add(e)
            result_ty = fresh_var("pipe_result")

        self._record(node, result_ty)
        return s, result_ty

    # ── Call expression ───────────────────────────────────────

    def _infer_call(
        self, node: ast.CallExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        # Infer callee type
        sc, tc = self._infer_expr(node.callee, env, subst)
        tc = tc.apply(sc)
        s  = sc

        # Infer argument types
        arg_types = []
        for arg in node.args:
            sa, ta = self._infer_expr(arg.value, env, s)
            s = s.compose(sa)
            arg_types.append(ta.apply(s))

        # tc must be a function
        ret_var    = fresh_var("ret")
        expected   = FunctionType(tuple(arg_types), ret_var)

        try:
            s2 = unify(tc.apply(s), expected, node.span)
            s  = s.compose(s2)
            result_ty = ret_var.apply(s)
        except UnifyError as e:
            self.errors.add(e)
            result_ty = fresh_var("call_result")

        self._record(node, result_ty)
        return s, result_ty

    # ── Member access ─────────────────────────────────────────

    def _infer_member(
        self, node: ast.MemberExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        s, obj_ty = self._infer_expr(node.obj, env, subst)
        obj_ty = obj_ty.apply(s)
        field  = node.field
        span   = node.span

        # Schema field access
        if isinstance(obj_ty, SchemaType):
            fd = obj_ty.get_field(field)
            if fd is None:
                self.errors.add(VarekError(
                    message=(f"schema `{obj_ty.name}` has no field `{field}`; "
                             f"available: {', '.join(f.name for f in obj_ty.fields)}"),
                    span=span,
                ))
                result_ty = fresh_var("field")
            else:
                result_ty = fd.type_ if not fd.optional else OptionalType(fd.type_)
            self._record(node, result_ty)
            return s, result_ty

        # Method lookup on built-in types
        methods = get_methods_for_type(obj_ty)
        if field in methods:
            method_ty = methods[field].instantiate().apply(s)
            self._record(node, method_ty)
            return s, method_ty

        # Generic member (e.g. on opaque types or future user-defined types)
        result_ty = fresh_var(f"{field}")
        self._record(node, result_ty)
        return s, result_ty

    # ── Index access ──────────────────────────────────────────

    def _infer_index(
        self, node: ast.IndexExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        s, obj_ty = self._infer_expr(node.obj,   env, subst)
        s, idx_ty = self._infer_expr(node.index, env, s)
        obj_ty = obj_ty.apply(s)
        idx_ty = idx_ty.apply(s)
        span   = node.span

        # Array indexing: T[] [int] -> T
        if isinstance(obj_ty, ArrayType):
            try:
                s2 = unify(idx_ty, T_INT, span)
                s  = s.compose(s2)
            except UnifyError:
                self.errors.add(VarekError(
                    message=f"array index must be `int`, found `{idx_ty}`",
                    span=span,
                ))
            result_ty = obj_ty.element
            self._record(node, result_ty)
            return s, result_ty

        # Map indexing: {K: V} [K] -> V?
        if isinstance(obj_ty, MapType):
            try:
                s2 = unify(idx_ty, obj_ty.key_type, span)
                s  = s.compose(s2)
            except UnifyError:
                self.errors.add(VarekError(
                    message=(f"map key type mismatch: "
                             f"expected `{obj_ty.key_type}`, found `{idx_ty}`"),
                    span=span,
                ))
            result_ty = OptionalType(obj_ty.val_type)
            self._record(node, result_ty)
            return s, result_ty

        # Tuple indexing (if literal int)
        if isinstance(obj_ty, TupleType) and isinstance(node.index, ast.Literal):
            idx = node.index.value
            if isinstance(idx, int) and 0 <= idx < len(obj_ty.elements):
                result_ty = obj_ty.elements[idx]
                self._record(node, result_ty)
                return s, result_ty

        # Unknown — return a fresh var
        result_ty = fresh_var("idx")
        self._record(node, result_ty)
        return s, result_ty

    # ── Error propagation ? ───────────────────────────────────

    def _infer_propagate(
        self, node: ast.PropagateExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        """
        expr?

        If expr : Result<T>, the ? operator unwraps to T on success
        (short-circuits with Err on failure).
        """
        s, ty = self._infer_expr(node.expr, env, subst)
        ty = ty.apply(s)
        span = node.span

        if isinstance(ty, ResultType):
            result_ty = ty.ok_type
        else:
            # Attempt to unify with Result<'a>
            ok_var = fresh_var("ok")
            try:
                s2 = unify(ty, ResultType(ok_var), span)
                s  = s.compose(s2)
                result_ty = ok_var.apply(s)
            except UnifyError:
                self.errors.add(VarekError(
                    message=(f"the `?` operator requires `Result<T>`, "
                             f"found `{ty}`"),
                    span=span,
                    hint="only functions returning Result<T> can use ?",
                ))
                result_ty = fresh_var("propagate")

        self._record(node, result_ty)
        return s, result_ty

    # ── If expression ─────────────────────────────────────────

    def _infer_if(
        self, node: ast.IfExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        # Condition must be bool
        sc, tc = self._infer_expr(node.condition, env, subst)
        tc = tc.apply(sc)
        s  = sc
        try:
            s2 = unify(tc, T_BOOL, node.span)
            s  = s.compose(s2)
        except UnifyError:
            self.errors.add(VarekError(
                message=f"if condition must be `bool`, found `{tc}`",
                span=node.span,
            ))

        # Then branch
        st, tt = self._infer_block(node.then_block, env, s)
        s  = s.compose(st)
        tt = tt.apply(s)

        if node.else_branch is None:
            # No else: type is nil (or the then type wrapped as optional)
            result_ty = OptionalType(tt) if tt != T_NIL else T_NIL
            self._record(node, result_ty)
            return s, result_ty

        # Else branch
        if isinstance(node.else_branch, ast.IfExpr):
            se, te = self._infer_if(node.else_branch, env, s)
        else:
            se, te = self._infer_block(node.else_branch, env, s)
        s  = s.compose(se)
        te = te.apply(s)
        tt = tt.apply(s)

        # Both branches must agree on type
        try:
            s2 = unify(tt, te, node.span)
            s  = s.compose(s2)
            result_ty = tt.apply(s)
        except UnifyError:
            # Mismatched branches — make it optional of the then type
            result_ty = OptionalType(tt)
            self.errors.add(VarekError(
                message=(f"if/else branches have incompatible types: "
                         f"`{tt}` vs `{te}`"),
                span=node.span,
            ))

        self._record(node, result_ty)
        return s, result_ty

    # ── Match expression ──────────────────────────────────────

    def _infer_match(
        self, node: ast.MatchExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        s, subj_ty = self._infer_expr(node.subject, env, subst)
        subj_ty = subj_ty.apply(s)

        arm_types: List[Type] = []
        for arm in node.arms:
            # Infer pattern (for now: just check literal patterns)
            if isinstance(arm.pattern, ast.Literal):
                pat_ty = self._literal_type(arm.pattern)
                try:
                    s2 = unify(subj_ty.apply(s), pat_ty.apply(s), arm.span)
                    s  = s.compose(s2)
                except UnifyError:
                    pass   # pattern type mismatch is a warning, not error

            # Infer body
            if isinstance(arm.body, ast.Block):
                sa, ta = self._infer_block(arm.body, env, s)
            else:
                sa, ta = self._infer_expr(arm.body, env, s)
            s = s.compose(sa)
            arm_types.append(ta.apply(s))

        if not arm_types:
            result_ty = T_NIL
        else:
            # All arms must agree
            result_ty = arm_types[0]
            for ta in arm_types[1:]:
                try:
                    s2 = unify(result_ty.apply(s), ta.apply(s), node.span)
                    s  = s.compose(s2)
                    result_ty = result_ty.apply(s)
                except UnifyError:
                    result_ty = OptionalType(result_ty)
                    break

        self._record(node, result_ty)
        return s, result_ty

    # ── For expression ────────────────────────────────────────

    def _infer_for(
        self, node: ast.ForExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        s, iter_ty = self._infer_expr(node.iterable, env, subst)
        iter_ty = iter_ty.apply(s)

        # iterable must be an array
        elem_var = fresh_var("elem")
        try:
            s2 = unify(iter_ty, ArrayType(elem_var), node.span)
            s  = s.compose(s2)
            elem_ty = elem_var.apply(s)
        except UnifyError:
            self.errors.add(VarekError(
                message=f"`for` requires an array type, found `{iter_ty}`",
                span=node.span,
            ))
            elem_ty = fresh_var("elem")

        # Bind loop variable in child env
        loop_env = env.extend_mono(node.var, elem_ty)
        s, _ = self._infer_block(node.body, loop_env, s)

        self._record(node, T_NIL)
        return s, T_NIL

    # ── Lambda ────────────────────────────────────────────────

    def _infer_lambda(
        self, node: ast.LambdaExpr, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        param_types = []
        lambda_env  = env

        for p in node.params:
            if p.type_:
                pt = ast_type_to_syn_type(p.type_, self.schemas, p.span)
            else:
                pt = fresh_var(p.name)
            param_types.append(pt)
            lambda_env = lambda_env.extend_mono(p.name, pt)

        # Infer body
        if isinstance(node.body, ast.Block):
            s, ret_ty = self._infer_block(node.body, lambda_env, subst)
        else:
            s, ret_ty = self._infer_expr(node.body, lambda_env, subst)

        # Apply declared return type if present
        if node.return_type:
            ann_ret = ast_type_to_syn_type(
                node.return_type, self.schemas, node.span)
            try:
                s2 = unify(ret_ty.apply(s), ann_ret.apply(s), node.span)
                s  = s.compose(s2)
                ret_ty = ann_ret.apply(s)
            except UnifyError as e:
                self.errors.add(e)

        fn_ty = FunctionType(
            tuple(pt.apply(s) for pt in param_types),
            ret_ty.apply(s),
        )
        self._record(node, fn_ty)
        return s, fn_ty

    # ── Array literal ─────────────────────────────────────────

    def _infer_array(
        self, node: ast.ArrayLiteral, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        if not node.elements:
            elem_ty = fresh_var("elem")
            self._record(node, ArrayType(elem_ty))
            return subst, ArrayType(elem_ty)

        s = subst
        elem_ty = fresh_var("elem")
        for el in node.elements:
            se, te = self._infer_expr(el, env, s)
            s = s.compose(se)
            te = te.apply(s)
            try:
                s2 = unify(elem_ty.apply(s), te, node.span)
                s  = s.compose(s2)
                elem_ty = elem_ty.apply(s)
            except UnifyError as e:
                self.errors.add(VarekError(
                    message=(f"array elements must have the same type: "
                             f"expected `{elem_ty}`, found `{te}`"),
                    span=el.span,
                ))

        result = ArrayType(elem_ty.apply(s))
        self._record(node, result)
        return s, result

    # ── Map literal ───────────────────────────────────────────

    def _infer_map_lit(
        self, node: ast.MapLiteral, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        key_ty = fresh_var("k")
        val_ty = fresh_var("v")
        s = subst

        for entry in node.entries:
            sk, tk = self._infer_expr(entry.key,   env, s)
            sv, tv = self._infer_expr(entry.value, env, sk.compose(s))
            s = s.compose(sk).compose(sv)
            try:
                s2 = unify(key_ty.apply(s), tk.apply(s), entry.span)
                s  = s.compose(s2)
            except UnifyError as e:
                self.errors.add(e)
            try:
                s2 = unify(val_ty.apply(s), tv.apply(s), entry.span)
                s  = s.compose(s2)
            except UnifyError as e:
                self.errors.add(e)

        result = MapType(key_ty.apply(s), val_ty.apply(s))
        self._record(node, result)
        return s, result

    # ── Tuple literal ─────────────────────────────────────────

    def _infer_tuple_lit(
        self, node: ast.TupleLiteral, env: TypeEnv, subst: Substitution
    ) -> Tuple[Substitution, Type]:
        s = subst
        elem_types = []
        for el in node.elements:
            se, te = self._infer_expr(el, env, s)
            s = s.compose(se)
            elem_types.append(te.apply(s))

        result = TupleType(tuple(elem_types))
        self._record(node, result)
        return s, result

    # ── Node type recording ───────────────────────────────────

    def _record(self, node: ast.Node, ty: Type) -> None:
        self._types[id(node)] = ty

    def get_type(self, node: ast.Node) -> Optional[Type]:
        return self._types.get(id(node))

    def all_typed_nodes(self):
        return self._types.items()
