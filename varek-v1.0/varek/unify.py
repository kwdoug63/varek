"""
varek/unify.py
────────────────
Robinson's unification algorithm for VAREK types, extended with:
  - Occurs check (prevent infinite types)
  - Tensor shape unification (dimension tracking)
  - Nullable / Optional coercion rules
  - Structural schema subtype checking

The unifier takes two types and either returns a Substitution that
makes them equal, or raises a UnifyError describing the conflict.

References:
  Robinson, J.A. (1965). A Machine-Oriented Logic Based on the
  Resolution Principle. JACM 12(1).
"""

from __future__ import annotations

from typing import Optional, List, Tuple

from varek.errors import Span, VarekError
from varek.types import (
    Type, TypeVar, PrimType, OptionalType, ArrayType, MapType,
    TupleType, TensorType, ResultType, FunctionType, SchemaType,
    Dim, DimSubstitution, Substitution,
    T_NIL,
)


# ══════════════════════════════════════════════════════════════════
# UNIFICATION ERRORS
# ══════════════════════════════════════════════════════════════════

class UnifyError(VarekError):
    """Raised when two types cannot be unified."""

    def __init__(self, left: Type, right: Type, span: Span,
                 reason: str = ""):
        msg = f"type mismatch: expected `{left}`, found `{right}`"
        if reason:
            msg += f"\n  reason: {reason}"
        super().__init__(message=msg, span=span)
        self.left  = left
        self.right = right


class OccursError(UnifyError):
    """Infinite type: 'a occurs in T where T contains 'a."""

    def __init__(self, var: TypeVar, ty: Type, span: Span):
        super().__init__(
            left=var, right=ty, span=span,
            reason=(f"type variable `{var}` occurs in `{ty}` — "
                    "this would create an infinite type")
        )


class ArityError(UnifyError):
    """Function or tuple has wrong number of arguments."""

    def __init__(self, expected: int, got: int,
                 left: Type, right: Type, span: Span):
        super().__init__(
            left=left, right=right, span=span,
            reason=f"expected {expected} arguments, found {got}"
        )


class ShapeError(UnifyError):
    """Tensor shape mismatch."""

    def __init__(self, left: TensorType, right: TensorType, span: Span,
                 detail: str = ""):
        msg = f"shape mismatch: `{left.shape_str()}` vs `{right.shape_str()}`"
        if detail:
            msg += f" — {detail}"
        VarekError.__init__(self, message=msg, span=span)
        self.left  = left
        self.right = right


class FieldError(UnifyError):
    """Schema field type mismatch or missing field."""

    def __init__(self, schema_name: str, field_name: str,
                 expected: Type, got: Type, span: Span):
        VarekError.__init__(
            self,
            message=(f"field `{field_name}` of schema `{schema_name}`: "
                     f"expected `{expected}`, found `{got}`"),
            span=span,
        )
        self.left  = expected
        self.right = got


# ══════════════════════════════════════════════════════════════════
# OCCURS CHECK
# ══════════════════════════════════════════════════════════════════

def occurs(var: TypeVar, ty: Type) -> bool:
    """
    Return True if `var` appears free in `ty`.
    Used to prevent creation of infinite types during unification.

    Example: unifying 'a with List<'a> would loop forever without this.
    """
    if isinstance(ty, TypeVar):
        return ty.name == var.name
    return var.name in ty.free_vars()


# ══════════════════════════════════════════════════════════════════
# DIMENSION UNIFICATION
# ══════════════════════════════════════════════════════════════════

def unify_dims(
    left_dims:  Tuple[Dim, ...],
    right_dims: Tuple[Dim, ...],
    left_tensor:  TensorType,
    right_tensor: TensorType,
    span: Span,
) -> DimSubstitution:
    """
    Unify two sequences of tensor dimensions, returning a mapping
    from dimension variable names to concrete Dims (or other vars).

    Rules:
      concrete == concrete  →  must match exactly
      var      == anything  →  bind var to anything
      var      == var       →  bind first to second
    """
    if len(left_dims) != len(right_dims):
        raise ShapeError(
            left_tensor, right_tensor, span,
            detail=f"rank {len(left_dims)} vs rank {len(right_dims)}"
        )

    ds: DimSubstitution = {}

    for i, (ld, rd) in enumerate(zip(left_dims, right_dims)):
        # Resolve any already-bound variables
        ld = ld.apply_dim_subst(ds)
        rd = rd.apply_dim_subst(ds)

        if ld.is_concrete() and rd.is_concrete():
            if ld.value != rd.value:
                raise ShapeError(
                    left_tensor, right_tensor, span,
                    detail=(f"dimension {i}: "
                            f"{ld.value} ≠ {rd.value}")
                )
        elif not ld.is_concrete():   # ld is a variable
            ds[ld.var] = rd
        elif not rd.is_concrete():   # rd is a variable
            ds[rd.var] = ld

    return ds


# ══════════════════════════════════════════════════════════════════
# MAIN UNIFICATION
# ══════════════════════════════════════════════════════════════════

def unify(left: Type, right: Type, span: Span) -> Substitution:
    """
    Unify `left` and `right`, returning a Substitution S such that
    S(left) == S(right).

    Raises UnifyError (or a subclass) if unification fails.

    The algorithm:
      1. Apply the current substitution to both sides (done by caller).
      2. If either side is a TypeVar, bind it (with occurs check).
      3. If both sides are the same constructor, unify their arguments.
      4. Otherwise, fail.

    Extension — nullable coercion:
      T  unifies with T?   by treating T as Some(T)
      nil unifies with T?  by the None branch
    This lets Optional fields accept both present and absent values
    without requiring explicit wrapping at every call site.
    """
    return _unify(left, right, span, Substitution.EMPTY)


def _unify(
    left:  Type,
    right: Type,
    span:  Span,
    subst: Substitution,
) -> Substitution:
    # Apply current substitution before matching
    l = left.apply(subst)
    r = right.apply(subst)

    # ── Identical types ───────────────────────────────────────
    if l == r:
        return subst

    # ── Type variables ────────────────────────────────────────
    if isinstance(l, TypeVar):
        return _bind(l, r, span, subst)

    if isinstance(r, TypeVar):
        return _bind(r, l, span, subst)

    # ── Optional coercion ─────────────────────────────────────
    # nil is assignable to any T?
    if isinstance(r, OptionalType) and l == T_NIL:
        return subst

    if isinstance(l, OptionalType) and r == T_NIL:
        return subst

    # T is assignable to T? (implicit wrapping)
    if isinstance(r, OptionalType) and not isinstance(l, OptionalType):
        return _unify(l, r.inner, span, subst)

    if isinstance(l, OptionalType) and not isinstance(r, OptionalType):
        return _unify(l.inner, r, span, subst)

    # ── Primitive types ───────────────────────────────────────
    if isinstance(l, PrimType) and isinstance(r, PrimType):
        # Numeric widening: int is assignable to float
        if l == T_NIL or r == T_NIL:
            raise UnifyError(l, r, span)
        raise UnifyError(l, r, span)

    # ── Optional (both sides) ─────────────────────────────────
    if isinstance(l, OptionalType) and isinstance(r, OptionalType):
        return _unify(l.inner, r.inner, span, subst)

    # ── Array ─────────────────────────────────────────────────
    if isinstance(l, ArrayType) and isinstance(r, ArrayType):
        return _unify(l.element, r.element, span, subst)

    # ── Map ───────────────────────────────────────────────────
    if isinstance(l, MapType) and isinstance(r, MapType):
        s1 = _unify(l.key_type, r.key_type, span, subst)
        return _unify(l.val_type.apply(s1), r.val_type.apply(s1), span, s1)

    # ── Tuple ─────────────────────────────────────────────────
    if isinstance(l, TupleType) and isinstance(r, TupleType):
        if len(l.elements) != len(r.elements):
            raise ArityError(len(l.elements), len(r.elements), l, r, span)
        s = subst
        for le, re in zip(l.elements, r.elements):
            s = _unify(le.apply(s), re.apply(s), span, s)
        return s

    # ── Tensor ────────────────────────────────────────────────
    if isinstance(l, TensorType) and isinstance(r, TensorType):
        s1 = _unify(l.element, r.element, span, subst)
        # Unify shapes independently (dim substitution is separate)
        unify_dims(l.dims, r.dims, l, r, span)
        return s1

    # ── Result ────────────────────────────────────────────────
    if isinstance(l, ResultType) and isinstance(r, ResultType):
        return _unify(l.ok_type, r.ok_type, span, subst)

    # ── Function ──────────────────────────────────────────────
    if isinstance(l, FunctionType) and isinstance(r, FunctionType):
        if l.arity() != r.arity():
            raise ArityError(l.arity(), r.arity(), l, r, span)
        s = subst
        for lp, rp in zip(l.params, r.params):
            s = _unify(lp.apply(s), rp.apply(s), span, s)
        return _unify(
            l.return_type.apply(s),
            r.return_type.apply(s),
            span, s,
        )

    # ── Schema ────────────────────────────────────────────────
    if isinstance(l, SchemaType) and isinstance(r, SchemaType):
        return _unify_schemas(l, r, span, subst)

    # If one side is a schema, the other must match structurally
    # (handled via SchemaType == SchemaType above)

    raise UnifyError(l, r, span)


def _bind(var: TypeVar, ty: Type, span: Span,
          subst: Substitution) -> Substitution:
    """Bind a type variable to a type (with occurs check)."""
    # Already bound to itself — no-op
    if isinstance(ty, TypeVar) and ty.name == var.name:
        return subst
    # Occurs check
    if occurs(var, ty):
        raise OccursError(var, ty, span)
    return subst.extend(var.name, ty)


def _unify_schemas(
    left:  SchemaType,
    right: SchemaType,
    span:  Span,
    subst: Substitution,
) -> Substitution:
    """
    Unify two schema types.

    If names match: unify field-by-field.
    Otherwise: structural compatibility — right must have all
    required fields of left with compatible types.
    """
    if left.name == right.name:
        # Same schema — unify all fields
        s = subst
        for lf in left.fields:
            rf = right.get_field(lf.name)
            if rf is None:
                if not lf.optional:
                    raise VarekError(
                        message=(f"schema `{left.name}` missing required "
                                 f"field `{lf.name}`"),
                        span=span,
                    )
            else:
                try:
                    s = _unify(lf.type_.apply(s), rf.type_.apply(s), span, s)
                except UnifyError as e:
                    raise FieldError(
                        left.name, lf.name, lf.type_, rf.type_, span
                    ) from e
        return s

    # Different schema names — check structural compatibility
    # (right is assignable to left if it has all required fields)
    s = subst
    for lf in left.required_fields():
        rf = right.get_field(lf.name)
        if rf is None:
            raise VarekError(
                message=(f"value of type `{right.name}` cannot be used as "
                         f"`{left.name}`: missing required field `{lf.name}`"),
                span=span,
            )
        try:
            s = _unify(lf.type_.apply(s), rf.type_.apply(s), span, s)
        except UnifyError as e:
            raise FieldError(left.name, lf.name, lf.type_, rf.type_, span) from e
    return s


# ══════════════════════════════════════════════════════════════════
# NUMERIC WIDENING
# ══════════════════════════════════════════════════════════════════

def unify_numeric(left: Type, right: Type, span: Span) -> Tuple[Type, Substitution]:
    """
    Attempt numeric widening unification.

    int + float -> float (float wins)
    int + int   -> int
    float + float -> float

    Returns (resolved_type, substitution).
    """
    from varek.types import T_INT, T_FLOAT
    l = left
    r = right

    # Both numeric primitives
    if l in (T_INT, T_FLOAT) and r in (T_INT, T_FLOAT):
        result = T_FLOAT if (l == T_FLOAT or r == T_FLOAT) else T_INT
        return result, Substitution.EMPTY

    # Fall back to regular unification
    s = unify(l, r, span)
    return l.apply(s), s
