"""
varek/env.py
──────────────
Type environments for VAREK v0.2.

A TypeEnv maps names to type Schemes. It supports lexical scoping
via a linked-list structure: each child env has a reference to its
parent, and lookups walk the chain.

The environment is the Γ (gamma) context in HM type theory:
  Γ ⊢ e : T   reads "in environment Γ, expression e has type T"
"""

from __future__ import annotations

from typing import Dict, Iterator, Optional, List

from varek.types import Type, Scheme, Substitution, fresh_var
from varek.errors import Span, VarekError


# ══════════════════════════════════════════════════════════════════
# UNBOUND NAME ERROR
# ══════════════════════════════════════════════════════════════════

class UnboundNameError(VarekError):
    def __init__(self, name: str, span: Span, suggestions: List[str] = None):
        hint = None
        if suggestions:
            nearest = suggestions[0]
            hint = f"did you mean `{nearest}`?"
        super().__init__(
            message=f"unbound name `{name}`",
            span=span,
            hint=hint,
        )


# ══════════════════════════════════════════════════════════════════
# TYPE ENVIRONMENT
# ══════════════════════════════════════════════════════════════════

class TypeEnv:
    """
    A lexically-scoped type environment mapping names to Schemes.

    The generalize() method implements let-polymorphism: it closes
    over all type variables that appear free in a type but not in
    the ambient environment (i.e. they were introduced by this
    binding, not inherited from outer scope).

    Usage:
        env = TypeEnv.empty()
        child = env.extend("x", Scheme.mono(T_INT))
        scheme = child.lookup("x", span)
    """

    def __init__(
        self,
        bindings: Optional[Dict[str, Scheme]] = None,
        parent:   Optional["TypeEnv"] = None,
    ):
        self._bindings: Dict[str, Scheme] = dict(bindings or {})
        self._parent:   Optional["TypeEnv"] = parent

    # ── Factory ───────────────────────────────────────────────

    @classmethod
    def empty(cls) -> "TypeEnv":
        return cls()

    def child(self) -> "TypeEnv":
        """Return a new child scope with this env as parent."""
        return TypeEnv(parent=self)

    # ── Lookup ────────────────────────────────────────────────

    def lookup(self, name: str, span: Span) -> Scheme:
        """
        Look up `name` in this env and its ancestors.
        Raises UnboundNameError with suggestions if not found.
        """
        env: Optional["TypeEnv"] = self
        while env is not None:
            if name in env._bindings:
                return env._bindings[name]
            env = env._parent

        # Not found — gather suggestions
        suggestions = _fuzzy_match(name, list(self.all_names()))
        raise UnboundNameError(name, span, suggestions)

    def lookup_type(self, name: str, span: Span) -> Type:
        """Look up a name and instantiate its scheme."""
        return self.lookup(name, span).instantiate()

    def contains(self, name: str) -> bool:
        env: Optional["TypeEnv"] = self
        while env is not None:
            if name in env._bindings:
                return True
            env = env._parent
        return False

    # ── Extend ────────────────────────────────────────────────

    def extend(self, name: str, scheme: Scheme) -> "TypeEnv":
        """
        Return a new env with name bound to scheme.
        Does NOT mutate this env.
        """
        new_bindings = dict(self._bindings)
        new_bindings[name] = scheme
        return TypeEnv(new_bindings, self._parent)

    def extend_mono(self, name: str, ty: Type) -> "TypeEnv":
        """Convenience: bind name to a monomorphic type."""
        return self.extend(name, Scheme.mono(ty))

    def extend_many(self, pairs: List[tuple]) -> "TypeEnv":
        """Extend with multiple (name, scheme) pairs at once."""
        env = self
        for name, scheme in pairs:
            env = env.extend(name, scheme)
        return env

    def bind_local(self, name: str, scheme: Scheme) -> None:
        """Mutate this env's local bindings (used for recursive defs)."""
        self._bindings[name] = scheme

    # ── Generalisation (let-polymorphism) ────────────────────

    def generalize(self, ty: Type) -> Scheme:
        """
        Close over all type variables free in `ty` but not free
        in this environment (the let-generalisation rule).

        A variable is free in the environment if it appears in any
        scheme binding that is not yet fully generalised.

        This implements the ML-style polymorphism rule that allows
        `let f = |x| x` to get type ∀ 'a. ('a) -> 'a
        instead of ('t0) -> 't0 for some fixed fresh var 't0.
        """
        env_free = self._free_vars_in_env()
        ty_free  = ty.free_vars()
        gen_vars = ty_free - env_free
        return Scheme(frozenset(gen_vars), ty)

    def _free_vars_in_env(self) -> "frozenset[str]":
        """Collect all free type variables mentioned in this env chain."""
        from typing import FrozenSet
        result: FrozenSet[str] = frozenset()
        env: Optional["TypeEnv"] = self
        while env is not None:
            for scheme in env._bindings.values():
                result = result | scheme.free_vars()
            env = env._parent
        return result

    # ── Apply substitution ────────────────────────────────────

    def apply(self, subst: Substitution) -> "TypeEnv":
        """Apply a substitution to all bindings in this env."""
        new_bindings = {
            name: subst.apply_to_scheme(scheme)
            for name, scheme in self._bindings.items()
        }
        parent = self._parent.apply(subst) if self._parent else None
        return TypeEnv(new_bindings, parent)

    # ── Inspection ────────────────────────────────────────────

    def all_names(self) -> Iterator[str]:
        """Yield all names visible in this scope chain."""
        seen = set()
        env: Optional["TypeEnv"] = self
        while env is not None:
            for name in env._bindings:
                if name not in seen:
                    seen.add(name)
                    yield name
            env = env._parent

    def local_names(self) -> Iterator[str]:
        return iter(self._bindings.keys())

    def local_bindings(self) -> Iterator[tuple]:
        return iter(self._bindings.items())

    def depth(self) -> int:
        """Scope nesting depth (0 = global)."""
        d = 0
        env = self._parent
        while env is not None:
            d += 1
            env = env._parent
        return d

    def __repr__(self) -> str:
        names = list(self._bindings.keys())
        return f"TypeEnv({names}, depth={self.depth()})"


# ══════════════════════════════════════════════════════════════════
# SCHEMA REGISTRY
# ══════════════════════════════════════════════════════════════════

class SchemaRegistry:
    """
    Global registry of schema type declarations.

    Schemas are named structural types. When the type checker
    encounters a schema declaration, it registers the schema here
    so it can be looked up by name during field-access inference.
    """

    def __init__(self):
        self._schemas: Dict[str, "SchemaType"] = {}

    def register(self, schema: "SchemaType") -> None:
        self._schemas[schema.name] = schema

    def lookup(self, name: str, span: Span) -> "SchemaType":
        if name not in self._schemas:
            raise VarekError(
                message=f"unknown schema `{name}`",
                span=span,
                hint="declare the schema before using it",
            )
        return self._schemas[name]

    def contains(self, name: str) -> bool:
        return name in self._schemas

    def all_schemas(self) -> Iterator[tuple]:
        return iter(self._schemas.items())

    def __repr__(self) -> str:
        return f"SchemaRegistry({list(self._schemas.keys())})"


# ══════════════════════════════════════════════════════════════════
# FUZZY NAME MATCHING (for "did you mean?" hints)
# ══════════════════════════════════════════════════════════════════

def _fuzzy_match(target: str, candidates: List[str],
                 max_dist: int = 2) -> List[str]:
    """Return candidates within edit distance `max_dist` of target."""
    results = []
    for c in candidates:
        if _edit_distance(target, c) <= max_dist:
            results.append(c)
    results.sort(key=lambda c: _edit_distance(target, c))
    return results[:3]


def _edit_distance(a: str, b: str) -> int:
    """Standard Levenshtein edit distance."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            ins  = prev[j + 1] + 1
            del_ = curr[j] + 1
            sub  = prev[j] + (0 if ca == cb else 1)
            curr.append(min(ins, del_, sub))
        prev = curr
    return prev[-1]
