"""
varek/builtins.py
────────────────────
Built-in type definitions and the initial global TypeEnv for VAREK.

Every name available without an import is defined here:
  - Primitive types (int, float, str, bool, nil)
  - Built-in functions (print, len, file_exists, ...)
  - Type constructors (Ok, Err, Some)
  - Standard schema operations
  - Math, I/O, tensor ops (typed stubs for v0.2)

The build_global_env() function returns a TypeEnv pre-populated
with all built-ins. The type checker calls this once and uses it
as the root of every inference context.
"""

from __future__ import annotations

from varek.types import (
    Type, Scheme, TypeVar, Substitution,
    PrimType, OptionalType, ArrayType, MapType, TupleType,
    TensorType, ResultType, FunctionType,
    T_INT, T_FLOAT, T_STR, T_BOOL, T_NIL,
    Dim, fresh_var,
)
from varek.env import TypeEnv


# ══════════════════════════════════════════════════════════════════
# POLYMORPHIC SCHEME HELPERS
# ══════════════════════════════════════════════════════════════════

def _poly(vars_: list[str], ty: Type) -> Scheme:
    """Build a polymorphic scheme ∀ vars. ty."""
    return Scheme(frozenset(vars_), ty)

def _mono(ty: Type) -> Scheme:
    return Scheme.mono(ty)

def _fn(*param_types: Type, ret: Type) -> FunctionType:
    return FunctionType(tuple(param_types), ret)

def _generic_fn(var_names: list[str], params: list[Type],
                ret: Type) -> Scheme:
    """Create a polymorphic function scheme."""
    tv = {n: TypeVar(n) for n in var_names}
    resolved_params = tuple(
        tv.get(str(p), p) if isinstance(p, TypeVar) else p
        for p in params
    )
    resolved_ret = tv.get(str(ret), ret) if isinstance(ret, TypeVar) else ret
    fn = FunctionType(tuple(params), ret)
    return _poly(var_names, fn)


# ══════════════════════════════════════════════════════════════════
# COMMONLY USED TYPE ALIASES
# ══════════════════════════════════════════════════════════════════

T_STR_ARR    = ArrayType(T_STR)
T_INT_ARR    = ArrayType(T_INT)
T_FLOAT_ARR  = ArrayType(T_FLOAT)
T_BOOL_OPT   = OptionalType(T_BOOL)
T_STR_OPT    = OptionalType(T_STR)
T_INT_OPT    = OptionalType(T_INT)

# Generic float tensor (rank unknown — use for stubs)
_a = TypeVar("'a")
_b = TypeVar("'b")
_c = TypeVar("'c")


# ══════════════════════════════════════════════════════════════════
# BUILT-IN FUNCTION SIGNATURES
# ══════════════════════════════════════════════════════════════════

def _builtins() -> list[tuple[str, Scheme]]:
    """
    Return (name, scheme) pairs for every built-in function.
    This list is the authoritative definition of what names are
    available globally in VAREK without any import.
    """

    # ── I/O ───────────────────────────────────────────────────
    print_scheme   = _mono(_fn(T_STR, ret=T_NIL))
    println_scheme = _mono(_fn(T_STR, ret=T_NIL))

    # ── String ────────────────────────────────────────────────
    str_scheme   = _poly(["'a"], _fn(_a, ret=T_STR))
    len_scheme   = _poly(["'a"], _fn(ArrayType(_a), ret=T_INT))
    # str.split is a method — handled via member access
    # Global split stub:
    split_scheme = _mono(_fn(T_STR, T_STR, ret=T_STR_ARR))

    # ── Math ──────────────────────────────────────────────────
    abs_int    = _mono(_fn(T_INT,   ret=T_INT))
    abs_float  = _mono(_fn(T_FLOAT, ret=T_FLOAT))
    sqrt_scheme= _mono(_fn(T_FLOAT, ret=T_FLOAT))
    floor_sch  = _mono(_fn(T_FLOAT, ret=T_INT))
    ceil_sch   = _mono(_fn(T_FLOAT, ret=T_INT))
    round_sch  = _mono(_fn(T_FLOAT, ret=T_INT))
    min_int    = _mono(_fn(T_INT,   T_INT,   ret=T_INT))
    max_int    = _mono(_fn(T_INT,   T_INT,   ret=T_INT))
    min_float  = _mono(_fn(T_FLOAT, T_FLOAT, ret=T_FLOAT))
    max_float  = _mono(_fn(T_FLOAT, T_FLOAT, ret=T_FLOAT))

    # ── Numeric conversions ───────────────────────────────────
    int_of_float  = _mono(_fn(T_FLOAT, ret=T_INT))
    float_of_int  = _mono(_fn(T_INT,   ret=T_FLOAT))
    int_of_str    = _mono(_fn(T_STR,   ret=ResultType(T_INT)))
    float_of_str  = _mono(_fn(T_STR,   ret=ResultType(T_FLOAT)))

    # ── Collections ───────────────────────────────────────────
    # map : ∀ 'a 'b. ('a[], ('a) -> 'b) -> 'b[]
    map_scheme = _poly(
        ["'a", "'b"],
        _fn(ArrayType(_a), FunctionType((_a,), _b), ret=ArrayType(_b))
    )
    # filter : ∀ 'a. ('a[], ('a) -> bool) -> 'a[]
    filter_scheme = _poly(
        ["'a"],
        _fn(ArrayType(_a), FunctionType((_a,), T_BOOL), ret=ArrayType(_a))
    )
    # fold : ∀ 'a 'b. ('a[], 'b, ('b, 'a) -> 'b) -> 'b
    fold_scheme = _poly(
        ["'a", "'b"],
        _fn(ArrayType(_a), _b,
            FunctionType((_b, _a), _b), ret=_b)
    )
    # zip : ∀ 'a 'b. ('a[], 'b[]) -> ('a, 'b)[]
    zip_scheme = _poly(
        ["'a", "'b"],
        _fn(ArrayType(_a), ArrayType(_b),
            ret=ArrayType(TupleType((_a, _b))))
    )
    # range : (int) -> int[]  or  (int, int) -> int[]
    range_scheme = _mono(_fn(T_INT, ret=T_INT_ARR))
    enumerate_scheme = _poly(
        ["'a"],
        _fn(ArrayType(_a), ret=ArrayType(TupleType((T_INT, _a))))
    )

    # ── Result constructors ───────────────────────────────────
    # Ok : ∀ 'a. ('a) -> Result<'a>
    ok_scheme  = _poly(["'a"], _fn(_a, ret=ResultType(_a)))
    # Err : ∀ 'a. (str) -> Result<'a>
    err_scheme = _poly(["'a"], _fn(T_STR, ret=ResultType(_a)))

    # ── Option / nullable ─────────────────────────────────────
    # Some : ∀ 'a. ('a) -> 'a?
    some_scheme = _poly(["'a"], _fn(_a, ret=OptionalType(_a)))
    # is_nil : ∀ 'a. ('a?) -> bool
    is_nil_scheme = _poly(["'a"], _fn(OptionalType(_a), ret=T_BOOL))
    # unwrap : ∀ 'a. ('a?) -> Result<'a>
    unwrap_scheme = _poly(["'a"], _fn(OptionalType(_a), ret=ResultType(_a)))

    # ── File / system ─────────────────────────────────────────
    file_exists_scheme = _mono(_fn(T_STR, ret=T_BOOL))
    read_file_scheme   = _mono(_fn(T_STR, ret=ResultType(T_STR)))
    write_file_scheme  = _mono(_fn(T_STR, T_STR, ret=ResultType(T_NIL)))

    # ── Tensor operations ─────────────────────────────────────
    # These are generic stubs — the real tensor library is v0.4
    # load_image  : (str) -> Tensor<float, ['d0, 'd1, 'd2]>
    _d0, _d1, _d2 = Dim(var="d0"), Dim(var="d1"), Dim(var="d2")
    load_image_scheme = _mono(
        _fn(T_STR, ret=TensorType(T_FLOAT, (_d0, _d1, _d2)))
    )
    # Generic tensor ops use plain TypeVar for shape since we
    # can't express arbitrary-rank generics in v0.2 yet

    # ── Model / pipeline (typed stubs) ───────────────────────
    # load_model  : (str) -> Result<Model>  (Model is opaque)
    model_type = TypeVar("'Model")
    load_model_scheme = _poly(
        ["'Model"],
        _fn(T_STR, ret=ResultType(model_type))
    )
    load_dataset_scheme = _poly(
        ["'a"],
        _fn(T_STR, ret=ResultType(ArrayType(_a)))
    )
    load_labels_scheme = _mono(
        _fn(T_STR, ret=ResultType(T_STR_ARR))
    )

    # ── Type assertions (for debugging) ───────────────────────
    assert_scheme = _poly(["'a"], _fn(T_BOOL, T_STR, ret=T_NIL))

    return [
        # I/O
        ("print",           print_scheme),
        ("println",         println_scheme),
        # String
        ("str",             str_scheme),
        ("len",             len_scheme),
        ("split",           split_scheme),
        # Math
        ("abs",             abs_float),       # float version is default
        ("sqrt",            sqrt_scheme),
        ("floor",           floor_sch),
        ("ceil",            ceil_sch),
        ("round",           round_sch),
        ("min",             min_float),
        ("max",             max_float),
        # Conversions
        ("int",             int_of_float),
        ("float",           float_of_int),
        ("int_of_str",      int_of_str),
        ("float_of_str",    float_of_str),
        # Collections
        ("map",             map_scheme),
        ("filter",          filter_scheme),
        ("fold",            fold_scheme),
        ("zip",             zip_scheme),
        ("range",           range_scheme),
        ("enumerate",       enumerate_scheme),
        # Result
        ("Ok",              ok_scheme),
        ("Err",             err_scheme),
        # Option
        ("Some",            some_scheme),
        ("is_nil",          is_nil_scheme),
        ("unwrap",          unwrap_scheme),
        # File / system
        ("file_exists",     file_exists_scheme),
        ("read_file",       read_file_scheme),
        ("write_file",      write_file_scheme),
        # Tensor / image
        ("load_image",      load_image_scheme),
        # Model
        ("load_model",      load_model_scheme),
        ("load_dataset",    load_dataset_scheme),
        ("load_labels",     load_labels_scheme),
        # Assertions
        ("assert",          assert_scheme),
        # Built-in constants
        ("true",            _mono(T_BOOL)),
        ("false",           _mono(T_BOOL)),
        ("nil",             _mono(T_NIL)),
    ]


# ══════════════════════════════════════════════════════════════════
# BUILT-IN METHOD SIGNATURES  (for member access inference)
# ══════════════════════════════════════════════════════════════════

# Maps type-name -> { method-name -> Scheme }
# The type checker looks up method types here during MemberExpr inference.

BUILTIN_METHODS: dict[str, dict[str, Scheme]] = {

    "str": {
        # str.split(sep: str) -> str[]
        "split":  _mono(_fn(T_STR, ret=T_STR_ARR)),
        # str.len() -> int   (also available as global len())
        "len":    _mono(_fn(ret=T_INT)),
        # str.upper() / lower()
        "upper":  _mono(_fn(ret=T_STR)),
        "lower":  _mono(_fn(ret=T_STR)),
        # str.trim()
        "trim":   _mono(_fn(ret=T_STR)),
        # str.contains(sub: str) -> bool
        "contains": _mono(_fn(T_STR, ret=T_BOOL)),
        # str.starts_with(prefix: str) -> bool
        "starts_with": _mono(_fn(T_STR, ret=T_BOOL)),
        # str.ends_with(suffix: str) -> bool
        "ends_with":   _mono(_fn(T_STR, ret=T_BOOL)),
    },

    "int": {
        "to_float": _mono(_fn(ret=T_FLOAT)),
        "to_str":   _mono(_fn(ret=T_STR)),
        "abs":      _mono(_fn(ret=T_INT)),
    },

    "float": {
        "to_int":  _mono(_fn(ret=T_INT)),
        "to_str":  _mono(_fn(ret=T_STR)),
        "abs":     _mono(_fn(ret=T_FLOAT)),
        "sqrt":    _mono(_fn(ret=T_FLOAT)),
        "floor":   _mono(_fn(ret=T_INT)),
        "ceil":    _mono(_fn(ret=T_INT)),
    },

    # Array methods (generic — actual element type is resolved at call site)
    "[]": {
        # arr.len() -> int
        "len":    _poly(["'a"], _fn(ret=T_INT)),
        # arr.push(x: 'a) -> nil
        "push":   _poly(["'a"], _fn(_a, ret=T_NIL)),
        # arr.pop() -> 'a?
        "pop":    _poly(["'a"], _fn(ret=OptionalType(_a))),
        # arr.map(f: 'a -> 'b) -> 'b[]
        "map":    _poly(["'a", "'b"],
                        _fn(FunctionType((_a,), _b), ret=ArrayType(_b))),
        # arr.filter(f: 'a -> bool) -> 'a[]
        "filter": _poly(["'a"],
                        _fn(FunctionType((_a,), T_BOOL), ret=ArrayType(_a))),
        # arr.sum() -> float   (loose — real version is constrained)
        "sum":    _mono(_fn(ret=T_FLOAT)),
        # arr.sort() -> 'a[]
        "sort":   _poly(["'a"], _fn(ret=ArrayType(_a))),
        # arr.reverse() -> 'a[]
        "reverse": _poly(["'a"], _fn(ret=ArrayType(_a))),
        # arr.contains(x: 'a) -> bool
        "contains": _poly(["'a"], _fn(_a, ret=T_BOOL)),
        # arr.join(sep: str) -> str   (only valid for str[])
        "join":   _mono(_fn(T_STR, ret=T_STR)),
        # arr.first() -> 'a?
        "first":  _poly(["'a"], _fn(ret=OptionalType(_a))),
        # arr.last() -> 'a?
        "last":   _poly(["'a"], _fn(ret=OptionalType(_a))),
    },

    # Result methods
    "Result": {
        # result.unwrap() -> 'a   (panics on Err)
        "unwrap":  _poly(["'a"], _fn(ret=_a)),
        # result.unwrap_or(default: 'a) -> 'a
        "unwrap_or": _poly(["'a"], _fn(_a, ret=_a)),
        # result.is_ok() -> bool
        "is_ok":   _mono(_fn(ret=T_BOOL)),
        # result.is_err() -> bool
        "is_err":  _mono(_fn(ret=T_BOOL)),
        # result.map(f: 'a -> 'b) -> Result<'b>
        "map":     _poly(["'a", "'b"],
                         _fn(FunctionType((_a,), _b),
                             ret=ResultType(_b))),
    },

    # Tensor methods (typed stubs — full impl in v0.4)
    "Tensor": {
        # tensor.shape() -> int[]
        "shape":     _mono(_fn(ret=T_INT_ARR)),
        # tensor.rank() -> int
        "rank":      _mono(_fn(ret=T_INT)),
        # tensor.flatten() -> Tensor<float, ['n]>
        "flatten":   _mono(_fn(ret=TensorType(T_FLOAT, (Dim(var="n"),)))),
        # tensor.softmax() -> same tensor type
        "softmax":   _poly(["'a"], _fn(ret=TensorType(T_FLOAT, (Dim(var="n"),)))),
        # tensor.max() -> float
        "max":       _mono(_fn(ret=T_FLOAT)),
        # tensor.min() -> float
        "min":       _mono(_fn(ret=T_FLOAT)),
        # tensor.sum() -> float
        "sum":       _mono(_fn(ret=T_FLOAT)),
        # tensor.top_k(k: int) -> int[]
        "top_k":     _mono(_fn(T_INT, ret=T_INT_ARR)),
        # tensor.normalize() -> same shape
        "normalize": _mono(_fn(ret=TensorType(T_FLOAT, (Dim(var="n"),)))),
        # tensor.forward(x) -> Tensor (opaque return in v0.2)
        "forward":   _poly(["'a", "'b"],
                           _fn(TensorType(_a, (Dim(var="n"),)),
                               ret=TensorType(_b, (Dim(var="m"),)))),
    },
}


def get_methods_for_type(ty: Type) -> dict[str, Scheme]:
    """Return the method table for a given type (best-effort)."""
    from varek.types import (
        PrimType, ArrayType, ResultType, TensorType, SchemaType,
    )
    if isinstance(ty, PrimType):
        return BUILTIN_METHODS.get(ty.name, {})
    if isinstance(ty, ArrayType):
        return BUILTIN_METHODS.get("[]", {})
    if isinstance(ty, ResultType):
        return BUILTIN_METHODS.get("Result", {})
    if isinstance(ty, TensorType):
        return BUILTIN_METHODS.get("Tensor", {})
    return {}


# ══════════════════════════════════════════════════════════════════
# GLOBAL ENVIRONMENT BUILDER
# ══════════════════════════════════════════════════════════════════

def build_global_env() -> TypeEnv:
    """
    Build and return the initial global TypeEnv containing all
    built-in names. This is the root environment for every
    VAREK type-checking context.
    """
    env = TypeEnv.empty()
    for name, scheme in _builtins():
        env = env.extend(name, scheme)
    return env
