"""
varek/types.py
────────────────
Core type algebra for VAREK v0.2.

Every value in VAREK has a Type. Types form an algebraic structure:

  Primitive    int | float | str | bool | nil
  TypeVar      'a  (unification variable, used during inference)
  Optional     T?
  Array        T[]
  Map          {K: V}
  Tuple        (T1, T2, ...)
  Tensor       Tensor<T, [D0, D1, ...]>
  Result       Result<T>
  Function     (P1, P2, ...) -> R
  Schema       named structural type with fields
  Generic      forall 'a. T  (polymorphic/quantified type)

Design: types are immutable value objects. Substitution produces
new types — nothing is mutated in place.
"""

from __future__ import annotations

import itertools
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterator, List, Optional, Tuple, Set


# ══════════════════════════════════════════════════════════════════
# TYPE VARIABLE SUPPLY
# ══════════════════════════════════════════════════════════════════

_counter = itertools.count()

def fresh_var(hint: str = "t") -> "TypeVar":
    """Generate a globally unique type variable."""
    return TypeVar(f"'{hint}{next(_counter)}")

def reset_var_counter() -> None:
    """Reset for deterministic tests. Call before each test case."""
    global _counter
    _counter = itertools.count()


# ══════════════════════════════════════════════════════════════════
# BASE TYPE
# ══════════════════════════════════════════════════════════════════

class Type(ABC):
    """Base class for all VAREK types."""

    @abstractmethod
    def free_vars(self) -> FrozenSet[str]:
        """Return the set of free type variable names in this type."""
        ...

    @abstractmethod
    def apply(self, subst: "Substitution") -> "Type":
        """Apply a substitution, returning a (possibly new) type."""
        ...

    @abstractmethod
    def __str__(self) -> str: ...

    def __repr__(self) -> str:
        return str(self)

    def is_concrete(self) -> bool:
        """True if the type contains no free variables."""
        return len(self.free_vars()) == 0

    def contains_var(self, name: str) -> bool:
        return name in self.free_vars()


# ══════════════════════════════════════════════════════════════════
# PRIMITIVE TYPES
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class PrimType(Type):
    """A primitive built-in type: int, float, str, bool, nil."""
    name: str

    def free_vars(self) -> FrozenSet[str]:
        return frozenset()

    def apply(self, subst: "Substitution") -> "Type":
        return self

    def __str__(self) -> str:
        return self.name


# Singletons
T_INT   = PrimType("int")
T_FLOAT = PrimType("float")
T_STR   = PrimType("str")
T_BOOL  = PrimType("bool")
T_NIL   = PrimType("nil")


# ══════════════════════════════════════════════════════════════════
# TYPE VARIABLE
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class TypeVar(Type):
    """
    An inference variable. Written 'a, 'b, etc. in error messages.
    During inference, variables get unified and eventually resolved
    to concrete types via substitution.
    """
    name: str

    def free_vars(self) -> FrozenSet[str]:
        return frozenset({self.name})

    def apply(self, subst: "Substitution") -> "Type":
        return subst.lookup(self)

    def __str__(self) -> str:
        return self.name


# ══════════════════════════════════════════════════════════════════
# OPTIONAL (NULLABLE)
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class OptionalType(Type):
    """T? — value is either T or nil."""
    inner: Type

    def free_vars(self) -> FrozenSet[str]:
        return self.inner.free_vars()

    def apply(self, subst: "Substitution") -> "Type":
        applied = self.inner.apply(subst)
        return OptionalType(applied) if applied is not self.inner else self

    def __str__(self) -> str:
        inner = str(self.inner)
        # Add parens for compound inner types for readability
        if isinstance(self.inner, (FunctionType, OptionalType)):
            inner = f"({inner})"
        return f"{inner}?"


# ══════════════════════════════════════════════════════════════════
# ARRAY
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ArrayType(Type):
    """T[] — homogeneous array of T."""
    element: Type

    def free_vars(self) -> FrozenSet[str]:
        return self.element.free_vars()

    def apply(self, subst: "Substitution") -> "Type":
        applied = self.element.apply(subst)
        return ArrayType(applied) if applied is not self.element else self

    def __str__(self) -> str:
        return f"{self.element}[]"


# ══════════════════════════════════════════════════════════════════
# MAP
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class MapType(Type):
    """{K: V} — key-value map."""
    key_type: Type
    val_type: Type

    def free_vars(self) -> FrozenSet[str]:
        return self.key_type.free_vars() | self.val_type.free_vars()

    def apply(self, subst: "Substitution") -> "Type":
        k = self.key_type.apply(subst)
        v = self.val_type.apply(subst)
        return MapType(k, v) if (k is not self.key_type or
                                  v is not self.val_type) else self

    def __str__(self) -> str:
        return f"{{{self.key_type}: {self.val_type}}}"


# ══════════════════════════════════════════════════════════════════
# TUPLE
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class TupleType(Type):
    """(T1, T2, ...) — fixed-arity product type."""
    elements: Tuple[Type, ...]

    def free_vars(self) -> FrozenSet[str]:
        result: FrozenSet[str] = frozenset()
        for e in self.elements:
            result = result | e.free_vars()
        return result

    def apply(self, subst: "Substitution") -> "Type":
        applied = tuple(e.apply(subst) for e in self.elements)
        return TupleType(applied)

    def __str__(self) -> str:
        return "(" + ", ".join(str(e) for e in self.elements) + ")"


# ══════════════════════════════════════════════════════════════════
# TENSOR  (AI-native, with shape tracking)
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Dim:
    """
    A single tensor dimension.

    Can be:
      - A concrete integer: Dim(value=224)
      - A symbolic variable: Dim(var='d0')  — used during inference
    """
    value: Optional[int] = None
    var:   Optional[str] = None

    def __post_init__(self):
        assert (self.value is not None) ^ (self.var is not None), \
            "Dim must have exactly one of value or var"

    def is_concrete(self) -> bool:
        return self.value is not None

    def free_dim_vars(self) -> FrozenSet[str]:
        return frozenset({self.var}) if self.var else frozenset()

    def apply_dim_subst(self, subst: "DimSubstitution") -> "Dim":
        if self.var and self.var in subst:
            return subst[self.var]
        return self

    def __str__(self) -> str:
        return str(self.value) if self.value is not None else self.var


_dim_counter = itertools.count()

def fresh_dim() -> Dim:
    return Dim(var=f"d{next(_dim_counter)}")

def reset_dim_counter() -> None:
    global _dim_counter
    _dim_counter = itertools.count()


DimSubstitution = Dict[str, Dim]


@dataclass(frozen=True)
class TensorType(Type):
    """
    Tensor<T, [D0, D1, ...]>

    Element type T is a VAREK type (usually float or int).
    Dims is a tuple of Dim objects — each may be concrete or symbolic.

    Examples:
      Tensor<float, [3, 224, 224]>  — concrete image tensor
      Tensor<float, ['d0, 'd1]>     — unknown shape (inferred)
      Tensor<float, [768]>          — embedding vector
    """
    element: Type
    dims:    Tuple[Dim, ...]

    def rank(self) -> int:
        return len(self.dims)

    def is_fully_shaped(self) -> bool:
        return all(d.is_concrete() for d in self.dims)

    def free_vars(self) -> FrozenSet[str]:
        return self.element.free_vars()

    def free_dim_vars(self) -> FrozenSet[str]:
        result: FrozenSet[str] = frozenset()
        for d in self.dims:
            result = result | d.free_dim_vars()
        return result

    def apply(self, subst: "Substitution") -> "Type":
        applied_elem = self.element.apply(subst)
        return TensorType(applied_elem, self.dims)

    def apply_dim_subst(self, ds: DimSubstitution) -> "TensorType":
        applied = tuple(d.apply_dim_subst(ds) for d in self.dims)
        return TensorType(self.element, applied)

    def shape_str(self) -> str:
        return "[" + ", ".join(str(d) for d in self.dims) + "]"

    def __str__(self) -> str:
        return f"Tensor<{self.element}, {self.shape_str()}>"


# ══════════════════════════════════════════════════════════════════
# RESULT
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ResultType(Type):
    """Result<T> — either Ok(T) or Err(str)."""
    ok_type: Type

    def free_vars(self) -> FrozenSet[str]:
        return self.ok_type.free_vars()

    def apply(self, subst: "Substitution") -> "Type":
        applied = self.ok_type.apply(subst)
        return ResultType(applied) if applied is not self.ok_type else self

    def __str__(self) -> str:
        return f"Result<{self.ok_type}>"


# ══════════════════════════════════════════════════════════════════
# FUNCTION TYPE
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class FunctionType(Type):
    """
    (P1, P2, ...) -> R

    Async functions carry the same type — asyncness is tracked
    separately as an effect, not encoded in the type.
    """
    params:      Tuple[Type, ...]
    return_type: Type

    def free_vars(self) -> FrozenSet[str]:
        result: FrozenSet[str] = self.return_type.free_vars()
        for p in self.params:
            result = result | p.free_vars()
        return result

    def apply(self, subst: "Substitution") -> "Type":
        params = tuple(p.apply(subst) for p in self.params)
        ret    = self.return_type.apply(subst)
        return FunctionType(params, ret)

    def arity(self) -> int:
        return len(self.params)

    def __str__(self) -> str:
        params = ", ".join(str(p) for p in self.params)
        return f"({params}) -> {self.return_type}"


# ══════════════════════════════════════════════════════════════════
# SCHEMA TYPE
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class FieldDef:
    """A single field in a schema type."""
    name:     str
    type_:    Type
    optional: bool

    def __str__(self) -> str:
        opt = "?" if self.optional else ""
        return f"{self.name}: {self.type_}{opt}"


@dataclass(frozen=True)
class SchemaType(Type):
    """
    A named structural type defined by a schema declaration.

    schema ImageInput {
      path:  str,
      label: str?,
    }

    Structural subtyping: a value of type S is compatible with
    schema T if S has at least all the required fields of T with
    compatible types. Optional fields may be absent.
    """
    name:   str
    fields: Tuple[FieldDef, ...]

    # Convenience: field lookup by name
    def get_field(self, name: str) -> Optional[FieldDef]:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def required_fields(self) -> List[FieldDef]:
        return [f for f in self.fields if not f.optional]

    def field_names(self) -> FrozenSet[str]:
        return frozenset(f.name for f in self.fields)

    def free_vars(self) -> FrozenSet[str]:
        result: FrozenSet[str] = frozenset()
        for f in self.fields:
            result = result | f.type_.free_vars()
        return result

    def apply(self, subst: "Substitution") -> "Type":
        new_fields = tuple(
            FieldDef(f.name, f.type_.apply(subst), f.optional)
            for f in self.fields
        )
        return SchemaType(self.name, new_fields)

    def __str__(self) -> str:
        return self.name


# ══════════════════════════════════════════════════════════════════
# GENERIC / POLYMORPHIC TYPE  (∀ quantifier)
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Scheme:
    """
    A polymorphic type scheme: ∀ vars. type

    Used for let-polymorphism (the 'let' generalisation rule in HM).
    When a generic function is called, its quantified variables are
    instantiated with fresh type variables.

    Example:
      identity : ∀ 'a. ('a) -> 'a
      map      : ∀ 'a 'b. ('a[], ('a) -> 'b) -> 'b[]
    """
    vars: FrozenSet[str]   # quantified variable names
    type: Type

    def is_monotype(self) -> bool:
        return len(self.vars) == 0

    def instantiate(self) -> Type:
        """Replace each quantified variable with a fresh type variable."""
        subst = Substitution({v: fresh_var(v.lstrip("'")) for v in self.vars})
        return self.type.apply(subst)

    def free_vars(self) -> FrozenSet[str]:
        return self.type.free_vars() - self.vars

    def __str__(self) -> str:
        if not self.vars:
            return str(self.type)
        vs = " ".join(sorted(self.vars))
        return f"∀ {vs}. {self.type}"

    @classmethod
    def mono(cls, t: Type) -> "Scheme":
        """Wrap a monotype as a trivial scheme."""
        return cls(frozenset(), t)


# ══════════════════════════════════════════════════════════════════
# SUBSTITUTION
# ══════════════════════════════════════════════════════════════════

class Substitution:
    """
    A finite mapping from type variable names to types.

    Substitutions are the core data structure of HM inference.
    They are composed (via `compose`) and applied (via Type.apply)
    throughout the inference algorithm.

    Invariant: the mapping is fully applied — if 'a -> 'b -> int,
    then looking up 'a yields int, not 'b.
    """

    EMPTY: "Substitution"   # defined below

    def __init__(self, mapping: Optional[Dict[str, Type]] = None):
        self._map: Dict[str, Type] = dict(mapping or {})

    def lookup(self, var: TypeVar) -> Type:
        """Return the resolved type for a variable, or the variable itself."""
        t = self._map.get(var.name, var)
        # Walk chains: if 'a -> 'b -> int, resolve fully
        seen: Set[str] = set()
        while isinstance(t, TypeVar) and t.name in self._map:
            if t.name in seen:
                break   # cycle (occurs check should have caught this)
            seen.add(t.name)
            t = self._map[t.name]
        return t

    def extend(self, var_name: str, ty: Type) -> "Substitution":
        """Return a new substitution with var_name -> ty added."""
        new_map = {k: v.apply(self) for k, v in self._map.items()}
        new_map[var_name] = ty.apply(self)
        return Substitution(new_map)

    def compose(self, other: "Substitution") -> "Substitution":
        """
        Compose self with other: apply self to the range of other,
        then merge.  (self ∘ other)(x) = self(other(x))
        """
        new_map = {k: v.apply(self) for k, v in other._map.items()}
        for k, v in self._map.items():
            if k not in new_map:
                new_map[k] = v
        return Substitution(new_map)

    def apply_to_scheme(self, scheme: Scheme) -> Scheme:
        """Apply substitution to a scheme, avoiding capture of bound vars."""
        restricted = Substitution(
            {k: v for k, v in self._map.items() if k not in scheme.vars}
        )
        return Scheme(scheme.vars, scheme.type.apply(restricted))

    def __contains__(self, name: str) -> bool:
        return name in self._map

    def __len__(self) -> int:
        return len(self._map)

    def __repr__(self) -> str:
        items = ", ".join(f"{k} ↦ {v}" for k, v in self._map.items())
        return f"Subst({{{items}}})"

    def items(self):
        return self._map.items()


Substitution.EMPTY = Substitution()


# ══════════════════════════════════════════════════════════════════
# TYPE DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════

def pp_type(t: Type) -> str:
    """Pretty-print a type for error messages."""
    return str(t)


def types_equal(a: Type, b: Type) -> bool:
    """
    Structural equality of fully-applied types.
    Note: TypeVars compare by name, so two separate fresh vars
    are NOT equal even if they represent the same thing — use
    unification for that.
    """
    return a == b
