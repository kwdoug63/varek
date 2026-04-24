"""
varek/runtime.py
──────────────────
Tree-walking interpreter for VAREK v0.3.

This is the "interpreted mode" — available without compilation, useful
for rapid prototyping, scripting, and as a correctness reference for
the compiled backend.

Every VAREK value is represented as a Python object. The interpreter
walks the typed AST produced by the parser + type-checker, evaluating
each node in a lexical Environment.

Supported:
  - All literals and binary/unary expressions
  - Let bindings and mutable variables
  - Function declarations and calls (including recursion)
  - If / match / for expressions
  - Schema field access
  - Result<T> (Ok/Err) and ? propagation
  - Lambda expressions
  - Array, Map, Tuple literals and indexing
  - Pipe operator |>
  - Built-in functions
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Callable

import varek.ast as ast


# ══════════════════════════════════════════════════════════════════
# VAREK RUNTIME VALUES
# ══════════════════════════════════════════════════════════════════

class VarekValue:
    """Base class for all runtime values."""
    pass


@dataclass
class SynInt(VarekValue):
    value: int
    def __repr__(self): return str(self.value)

@dataclass
class SynFloat(VarekValue):
    value: float
    def __repr__(self): return str(self.value)

@dataclass
class SynStr(VarekValue):
    value: str
    def __repr__(self): return repr(self.value)

@dataclass
class SynBool(VarekValue):
    value: bool
    def __repr__(self): return "true" if self.value else "false"

@dataclass
class SynNil(VarekValue):
    def __repr__(self): return "nil"

SYN_NIL   = SynNil()
SYN_TRUE  = SynBool(True)
SYN_FALSE = SynBool(False)

@dataclass
class SynArray(VarekValue):
    elements: List[VarekValue]
    def __repr__(self): return f"[{', '.join(repr(e) for e in self.elements)}]"

@dataclass
class SynMap(VarekValue):
    entries: Dict[Any, VarekValue]
    def __repr__(self): return "{" + ", ".join(f"{k!r}: {v!r}" for k,v in self.entries.items()) + "}"

@dataclass
class SynTuple(VarekValue):
    elements: Tuple[VarekValue, ...]
    def __repr__(self): return f"({', '.join(repr(e) for e in self.elements)})"

@dataclass
class SynOk(VarekValue):
    value: VarekValue
    def __repr__(self): return f"Ok({self.value!r})"

@dataclass
class SynErr(VarekValue):
    message: str
    def __repr__(self): return f"Err({self.message!r})"

@dataclass
class SynTensor(VarekValue):
    """Simple tensor represented as nested list of floats."""
    data: List
    shape: Tuple[int, ...]
    dtype: str = "float"
    def __repr__(self): return f"Tensor<{self.dtype}, {list(self.shape)}>"

@dataclass
class SynFunction(VarekValue):
    """A user-defined function closure."""
    name:    str
    params:  List[str]
    body:    ast.Block
    env:     "Environment"
    is_async: bool = False
    def __repr__(self): return f"<fn {self.name}>"

@dataclass
class SynBuiltin(VarekValue):
    """A built-in function implemented in Python."""
    name: str
    impl: Callable
    def __repr__(self): return f"<builtin {self.name}>"

@dataclass
class SynSchema(VarekValue):
    """An instance of a schema type."""
    type_name: str
    fields:    Dict[str, VarekValue]
    def __repr__(self): return f"{self.type_name}({self.fields})"


# ══════════════════════════════════════════════════════════════════
# CONTROL FLOW EXCEPTIONS
# ══════════════════════════════════════════════════════════════════

class ReturnSignal(Exception):
    def __init__(self, value: VarekValue): self.value = value

class PropagateSignal(Exception):
    """Raised by ? on Err — propagates to enclosing Result-returning function."""
    def __init__(self, err: SynErr): self.err = err


# ══════════════════════════════════════════════════════════════════
# ENVIRONMENT
# ══════════════════════════════════════════════════════════════════

class Environment:
    """Lexically-scoped name→value mapping."""

    def __init__(self, parent: Optional["Environment"] = None):
        self._bindings: Dict[str, VarekValue] = {}
        self._parent = parent

    def get(self, name: str) -> VarekValue:
        if name in self._bindings:
            return self._bindings[name]
        if self._parent:
            return self._parent.get(name)
        raise RuntimeError(f"unbound name: {name!r}")

    def set(self, name: str, value: VarekValue) -> None:
        self._bindings[name] = value

    def set_existing(self, name: str, value: VarekValue) -> None:
        """Mutate an existing binding (walks parent chain)."""
        if name in self._bindings:
            self._bindings[name] = value
            return
        if self._parent:
            self._parent.set_existing(name, value)
        else:
            raise RuntimeError(f"assignment to undeclared name: {name!r}")

    def child(self) -> "Environment":
        return Environment(self)


# ══════════════════════════════════════════════════════════════════
# BUILT-IN FUNCTIONS
# ══════════════════════════════════════════════════════════════════

def _make_builtins() -> Dict[str, VarekValue]:
    def builtin(name: str):
        def decorator(fn: Callable):
            return SynBuiltin(name, fn)
        return decorator

    def bi(name, impl): return SynBuiltin(name, impl)

    def _print(args):
        print(" ".join(str(a.value if hasattr(a, "value") else a) for a in args))
        return SYN_NIL

    def _str(args):
        a = args[0]
        if isinstance(a, (SynInt, SynFloat, SynBool)):
            return SynStr(str(a.value))
        if isinstance(a, SynStr): return a
        if isinstance(a, SynNil): return SynStr("nil")
        return SynStr(repr(a))

    def _len(args):
        a = args[0]
        if isinstance(a, SynArray): return SynInt(len(a.elements))
        if isinstance(a, SynStr):   return SynInt(len(a.value))
        raise RuntimeError(f"len() expects array or str, got {type(a).__name__}")

    def _map_fn(args):
        arr, fn = args
        if isinstance(arr, SynArray):
            results = [_call_value(fn, [e]) for e in arr.elements]
            return SynArray(results)
        raise RuntimeError("map() expects array as first argument")

    def _filter_fn(args):
        arr, fn = args
        if isinstance(arr, SynArray):
            results = [e for e in arr.elements
                       if isinstance(_call_value(fn, [e]), SynBool) and _call_value(fn, [e]).value]
            return SynArray(results)
        raise RuntimeError("filter() expects array")

    def _range(args):
        if len(args) == 1:
            return SynArray([SynInt(i) for i in range(args[0].value)])
        return SynArray([SynInt(i) for i in range(args[0].value, args[1].value)])

    def _Ok(args):  return SynOk(args[0])
    def _Err(args): return SynErr(args[0].value if isinstance(args[0], SynStr) else str(args[0]))

    def _file_exists(args):
        import os
        return SynBool(os.path.exists(args[0].value))

    def _read_file(args):
        try:
            with open(args[0].value) as f:
                return SynOk(SynStr(f.read()))
        except Exception as e:
            return SynErr(str(e))

    def _float_fn(args):
        a = args[0]
        if isinstance(a, SynInt):   return SynFloat(float(a.value))
        if isinstance(a, SynFloat): return a
        raise RuntimeError(f"float() expects numeric, got {type(a).__name__}")

    def _int_fn(args):
        a = args[0]
        if isinstance(a, SynFloat): return SynInt(int(a.value))
        if isinstance(a, SynInt):   return a
        raise RuntimeError(f"int() expects numeric, got {type(a).__name__}")

    def _abs_fn(args):
        a = args[0]
        if isinstance(a, SynInt):   return SynInt(abs(a.value))
        if isinstance(a, SynFloat): return SynFloat(abs(a.value))
        raise RuntimeError("abs() expects numeric")

    def _sqrt(args):
        a = args[0]
        v = a.value if isinstance(a, (SynInt, SynFloat)) else 0.0
        return SynFloat(math.sqrt(float(v)))

    def _max_fn(args):
        a, b = args[0], args[1]
        av = a.value; bv = b.value
        if isinstance(a, SynFloat) or isinstance(b, SynFloat):
            return SynFloat(max(float(av), float(bv)))
        return SynInt(max(av, bv))

    def _min_fn(args):
        a, b = args[0], args[1]
        av = a.value; bv = b.value
        if isinstance(a, SynFloat) or isinstance(b, SynFloat):
            return SynFloat(min(float(av), float(bv)))
        return SynInt(min(av, bv))

    return {
        "print":       bi("print",       _print),
        "println":     bi("println",     _print),
        "str":         bi("str",         _str),
        "len":         bi("len",         _len),
        "map":         bi("map",         _map_fn),
        "filter":      bi("filter",      _filter_fn),
        "range":       bi("range",       _range),
        "Ok":          bi("Ok",          _Ok),
        "Err":         bi("Err",         _Err),
        "file_exists": bi("file_exists", _file_exists),
        "read_file":   bi("read_file",   _read_file),
        "float":       bi("float",       _float_fn),
        "int":         bi("int",         _int_fn),
        "abs":         bi("abs",         _abs_fn),
        "sqrt":        bi("sqrt",        _sqrt),
        "max":         bi("max",         _max_fn),
        "min":         bi("min",         _min_fn),
        "true":  SYN_TRUE,
        "false": SYN_FALSE,
        "nil":   SYN_NIL,
    }


def _call_value(fn: VarekValue, args: List[VarekValue],
                interp: Optional["Interpreter"] = None) -> VarekValue:
    """Call a VarekValue as a function."""
    if isinstance(fn, SynBuiltin):
        return fn.impl(args)
    if isinstance(fn, SynFunction):
        if interp is None:
            raise RuntimeError("Cannot call user function without interpreter")
        call_env = fn.env.child()
        for name, val in zip(fn.params, args):
            call_env.set(name, val)
        try:
            return interp._exec_block(fn.body, call_env)
        except ReturnSignal as r:
            return r.value
    raise RuntimeError(f"Cannot call {type(fn).__name__} as function")


# ══════════════════════════════════════════════════════════════════
# INTERPRETER
# ══════════════════════════════════════════════════════════════════

class Interpreter:
    """
    Tree-walking interpreter for VAREK.

    Usage:
        interp = Interpreter()
        result = interp.run(source)
        # or
        result = interp.eval_expr("1 + 2 * 3")
    """

    def __init__(self):
        self._global_env = Environment()
        for name, val in _make_builtins().items():
            self._global_env.set(name, val)
        self._schema_defs: Dict[str, List] = {}   # name -> [FieldDef, ...]

    # ── Public API ────────────────────────────────────────────

    def run(self, source: str, filename: str = "<stdin>") -> Optional[VarekValue]:
        """Parse and execute a full VAREK program. Returns last value."""
        import varek
        tree, errors = varek.parse(source, filename)
        if errors.has_errors():
            raise RuntimeError(errors.report(source.splitlines()))
        return self._exec_program(tree, self._global_env)

    def eval_expr(self, source: str) -> VarekValue:
        """Evaluate a single expression and return its value."""
        import varek
        tree, errors = varek.parse(f"let __result__ = {source}", "<repl>")
        if errors.has_errors():
            raise RuntimeError(errors.report(source.splitlines()))
        env = self._global_env.child()
        self._exec_program(tree, env)
        return env.get("__result__")

    def call(self, name: str, *args: VarekValue) -> VarekValue:
        """Call a named function from the global environment."""
        fn = self._global_env.get(name)
        return _call_value(fn, list(args), self)

    # ── Program ───────────────────────────────────────────────

    def _exec_program(self, program: ast.Program, env: Environment) -> Optional[VarekValue]:
        last = SYN_NIL
        for stmt in program.statements:
            result = self._exec_stmt(stmt, env)
            if result is not None:
                last = result
        return last

    # ── Statements ────────────────────────────────────────────

    def _exec_stmt(self, node: ast.Node, env: Environment) -> Optional[VarekValue]:
        if isinstance(node, ast.ImportStmt):
            # Resolve syn:: stdlib imports
            if node.path and node.path[0] == "syn":
                from varek.stdlib import resolve_import
                bindings = resolve_import(node.path, node.alias)
                for name, val in bindings.items():
                    env.set(name, val)
                # Wire interpreter reference into pipeline module for SynFunction steps
                if len(node.path) > 1 and node.path[1] == "pipeline":
                    try:
                        from varek.stdlib.pipeline import _set_interp
                        _set_interp(self)
                    except Exception: pass
            # python:: imports: attempt to import and wrap
            elif node.path and node.path[0] == "python":
                try:
                    mod_path = ".".join(node.path[1:])
                    import importlib
                    py_mod = importlib.import_module(mod_path)
                    bind_as = node.alias or node.path[-1]
                    env.set(bind_as, SynBuiltin(bind_as, lambda a, m=py_mod: m))
                except Exception:
                    pass  # silently skip failed imports
            return None

        if isinstance(node, ast.SchemaDecl):
            self._schema_defs[node.name] = node.fields
            # Register a constructor function
            fields = node.fields
            def make_schema_ctor(name, flds):
                def ctor(args):
                    d = {}
                    for f, v in zip(flds, args):
                        d[f.name] = v
                    return SynSchema(name, d)
                return SynBuiltin(name, ctor)
            env.set(node.name, make_schema_ctor(node.name, fields))
            return None

        if isinstance(node, ast.FnDecl):
            fn = SynFunction(
                name=node.name,
                params=[p.name for p in node.params],
                body=node.body,
                env=env,
                is_async=node.is_async,
            )
            env.set(node.name, fn)
            return None

        if isinstance(node, ast.PipelineDecl):
            # Pipelines become callable functions at runtime
            steps = node.steps
            def make_pipeline(step_names):
                def run_pipeline(args):
                    items = args[0]
                    if isinstance(items, SynArray):
                        results = []
                        for item in items.elements:
                            current = item
                            for step_name in step_names:
                                fn = env.get(step_name)
                                current = _call_value(fn, [current], self)
                            results.append(current)
                        return SynArray(results)
                    return SYN_NIL
                return run_pipeline
            env.set(node.name, SynBuiltin(node.name, make_pipeline(steps)))
            return None

        if isinstance(node, ast.LetStmt):
            value = self._eval(node.value, env)
            env.set(node.name, value)
            return value

        if isinstance(node, ast.ReturnStmt):
            value = self._eval(node.value, env) if node.value else SYN_NIL
            raise ReturnSignal(value)

        if isinstance(node, ast.ExprStmt):
            return self._eval(node.expr, env)

        return None

    # ── Block ─────────────────────────────────────────────────

    def _exec_block(self, block: ast.Block, env: Environment) -> VarekValue:
        block_env = env.child()
        last = SYN_NIL
        for stmt in block.statements:
            result = self._exec_stmt(stmt, block_env)
            if result is not None:
                last = result
        if block.tail_expr:
            return self._eval(block.tail_expr, block_env)
        # Last ExprStmt is implicit return
        if block.statements and isinstance(block.statements[-1], ast.ExprStmt):
            return last
        return last

    # ── Expression evaluation ─────────────────────────────────

    def _eval(self, node: ast.Node, env: Environment) -> VarekValue:

        if isinstance(node, ast.Literal):
            v = node.value
            if v is None:            return SYN_NIL
            if isinstance(v, bool):  return SYN_TRUE if v else SYN_FALSE
            if isinstance(v, int):   return SynInt(v)
            if isinstance(v, float): return SynFloat(v)
            if isinstance(v, str):   return SynStr(v)

        if isinstance(node, ast.Ident):
            return env.get(node.name)

        if isinstance(node, ast.BinaryExpr):
            return self._eval_binary(node, env)

        if isinstance(node, ast.UnaryExpr):
            return self._eval_unary(node, env)

        if isinstance(node, ast.PipeExpr):
            left  = self._eval(node.left,  env)
            right = self._eval(node.right, env)
            return _call_value(right, [left], self)

        if isinstance(node, ast.CallExpr):
            fn   = self._eval(node.callee, env)
            args = [self._eval(a.value, env) for a in node.args]
            return _call_value(fn, args, self)

        if isinstance(node, ast.MemberExpr):
            obj = self._eval(node.obj, env)
            return self._member_access(obj, node.field, env)

        if isinstance(node, ast.IndexExpr):
            obj = self._eval(node.obj, env)
            idx = self._eval(node.index, env)
            return self._index_access(obj, idx)

        if isinstance(node, ast.PropagateExpr):
            val = self._eval(node.expr, env)
            if isinstance(val, SynErr):
                raise PropagateSignal(val)
            if isinstance(val, SynOk):
                return val.value
            return val

        if isinstance(node, ast.AwaitExpr):
            return self._eval(node.expr, env)   # synchronous in interpreter

        if isinstance(node, ast.IfExpr):
            return self._eval_if(node, env)

        if isinstance(node, ast.MatchExpr):
            return self._eval_match(node, env)

        if isinstance(node, ast.ForExpr):
            return self._eval_for(node, env)

        if isinstance(node, ast.LambdaExpr):
            return SynFunction(
                name="<lambda>",
                params=[p.name for p in node.params],
                body=node.body if isinstance(node.body, ast.Block)
                     else ast.Block([], node.body, node.span),
                env=env,
            )

        if isinstance(node, ast.Block):
            return self._exec_block(node, env)

        if isinstance(node, ast.ArrayLiteral):
            return SynArray([self._eval(e, env) for e in node.elements])

        if isinstance(node, ast.MapLiteral):
            entries = {}
            for entry in node.entries:
                k = self._eval(entry.key, env)
                v = self._eval(entry.value, env)
                key = k.value if hasattr(k, "value") else str(k)
                entries[key] = v
            return SynMap(entries)

        if isinstance(node, ast.TupleLiteral):
            return SynTuple(tuple(self._eval(e, env) for e in node.elements))

        if isinstance(node, ast.ExprStmt):
            return self._eval(node.expr, env)

        return SYN_NIL

    # ── Binary operations ─────────────────────────────────────

    def _eval_binary(self, node: ast.BinaryExpr, env: Environment) -> VarekValue:
        op = node.op
        # Short-circuit boolean operators
        if op == "and":
            l = self._eval(node.left, env)
            if isinstance(l, SynBool) and not l.value: return SYN_FALSE
            return self._eval(node.right, env)
        if op == "or":
            l = self._eval(node.left, env)
            if isinstance(l, SynBool) and l.value: return SYN_TRUE
            return self._eval(node.right, env)

        l = self._eval(node.left,  env)
        r = self._eval(node.right, env)

        # Numeric
        if isinstance(l, (SynInt, SynFloat)) and isinstance(r, (SynInt, SynFloat)):
            lv = l.value; rv = r.value
            use_float = isinstance(l, SynFloat) or isinstance(r, SynFloat)
            if op == "+":  return (SynFloat if use_float else SynInt)(lv + rv)
            if op == "-":  return (SynFloat if use_float else SynInt)(lv - rv)
            if op == "*":  return (SynFloat if use_float else SynInt)(lv * rv)
            if op == "/":
                if rv == 0: raise RuntimeError("division by zero")
                return SynFloat(lv / rv) if use_float else SynInt(lv // rv)
            if op == "%":  return SynInt(int(lv) % int(rv))
            if op == "==": return SynBool(lv == rv)
            if op == "!=": return SynBool(lv != rv)
            if op == "<":  return SynBool(lv <  rv)
            if op == ">":  return SynBool(lv >  rv)
            if op == "<=": return SynBool(lv <= rv)
            if op == ">=": return SynBool(lv >= rv)

        # String concatenation
        if op == "+" and isinstance(l, SynStr) and isinstance(r, SynStr):
            return SynStr(l.value + r.value)

        # String + non-string (auto-coerce)
        if op == "+" and isinstance(l, SynStr):
            return SynStr(l.value + str(r.value if hasattr(r,"value") else r))

        # Equality for any type
        if op == "==":
            return SynBool(self._values_equal(l, r))
        if op == "!=":
            return SynBool(not self._values_equal(l, r))

        raise RuntimeError(f"unsupported operator {op!r} for {type(l).__name__}, {type(r).__name__}")

    def _values_equal(self, a: VarekValue, b: VarekValue) -> bool:
        if type(a) != type(b): return False
        if hasattr(a, "value"): return a.value == b.value
        return a is b

    def _eval_unary(self, node: ast.UnaryExpr, env: Environment) -> VarekValue:
        v = self._eval(node.operand, env)
        if node.op == "-":
            if isinstance(v, SynInt):   return SynInt(-v.value)
            if isinstance(v, SynFloat): return SynFloat(-v.value)
        if node.op == "not":
            if isinstance(v, SynBool):  return SynBool(not v.value)
        raise RuntimeError(f"unary {node.op!r} on {type(v).__name__}")

    def _eval_if(self, node: ast.IfExpr, env: Environment) -> VarekValue:
        cond = self._eval(node.condition, env)
        if isinstance(cond, SynBool) and cond.value:
            return self._exec_block(node.then_block, env)
        if node.else_branch:
            if isinstance(node.else_branch, ast.IfExpr):
                return self._eval_if(node.else_branch, env)
            return self._exec_block(node.else_branch, env)
        return SYN_NIL

    def _eval_match(self, node: ast.MatchExpr, env: Environment) -> VarekValue:
        subject = self._eval(node.subject, env)
        for arm in node.arms:
            if isinstance(arm.pattern, ast.WildcardPattern):
                matched = True
            elif isinstance(arm.pattern, ast.Literal):
                pat_val = self._eval(arm.pattern, env)
                matched = self._values_equal(subject, pat_val)
            elif isinstance(arm.pattern, ast.Ident):
                # Bind the subject to the pattern variable
                arm_env = env.child()
                arm_env.set(arm.pattern.name, subject)
                if isinstance(arm.body, ast.Block):
                    return self._exec_block(arm.body, arm_env)
                return self._eval(arm.body, arm_env)
            else:
                matched = False

            if matched:
                if isinstance(arm.body, ast.Block):
                    return self._exec_block(arm.body, env)
                return self._eval(arm.body, env)
        return SYN_NIL

    def _eval_for(self, node: ast.ForExpr, env: Environment) -> VarekValue:
        iterable = self._eval(node.iterable, env)
        if isinstance(iterable, SynArray):
            items = iterable.elements
        else:
            raise RuntimeError(f"for loop requires array, got {type(iterable).__name__}")
        for item in items:
            loop_env = env.child()
            loop_env.set(node.var, item)
            try:
                self._exec_block(node.body, loop_env)
            except ReturnSignal as r:
                raise r
        return SYN_NIL

    def _member_access(self, obj: VarekValue, field: str, env: Environment) -> VarekValue:
        # StdlibModule namespace access: io.read_file, tensor.zeros, etc.
        from varek.stdlib import StdlibModule
        if isinstance(obj, StdlibModule):
            val = obj.get(field)
            if val is not None:
                return val
            raise RuntimeError(f"syn::{obj.module_name} has no export: {field!r}")

        # Schema field access
        if isinstance(obj, SynSchema):
            if field in obj.fields:
                return obj.fields[field]
            raise RuntimeError(f"schema {obj.type_name!r} has no field {field!r}")

        # String methods
        if isinstance(obj, SynStr):
            if field == "len":     return SynBuiltin("len",     lambda a: SynInt(len(obj.value)))
            if field == "upper":   return SynBuiltin("upper",   lambda a: SynStr(obj.value.upper()))
            if field == "lower":   return SynBuiltin("lower",   lambda a: SynStr(obj.value.lower()))
            if field == "trim":    return SynBuiltin("trim",    lambda a: SynStr(obj.value.strip()))
            if field == "split":   return SynBuiltin("split",   lambda a: SynArray([SynStr(s) for s in obj.value.split(a[0].value)]))
            if field == "contains":return SynBuiltin("contains",lambda a: SynBool(a[0].value in obj.value))
            if field == "starts_with": return SynBuiltin("starts_with", lambda a: SynBool(obj.value.startswith(a[0].value)))

        # Array methods
        if isinstance(obj, SynArray):
            if field == "len":     return SynBuiltin("len",    lambda a: SynInt(len(obj.elements)))
            if field == "sum":     return SynBuiltin("sum",    lambda a: SynFloat(sum(e.value for e in obj.elements if hasattr(e,"value"))))
            if field == "first":   return SynBuiltin("first",  lambda a: obj.elements[0] if obj.elements else SYN_NIL)
            if field == "last":    return SynBuiltin("last",   lambda a: obj.elements[-1] if obj.elements else SYN_NIL)
            if field == "reverse": return SynBuiltin("reverse",lambda a: SynArray(list(reversed(obj.elements))))
            if field == "push":    return SynBuiltin("push",   lambda a: (obj.elements.append(a[0]), SYN_NIL)[1])
            if field == "map":
                def arr_map(a):
                    fn = a[0]
                    return SynArray([_call_value(fn, [e], self) for e in obj.elements])
                return SynBuiltin("map", arr_map)
            if field == "filter":
                def arr_filter(a):
                    fn = a[0]
                    return SynArray([e for e in obj.elements
                                     if isinstance(_call_value(fn,[e],self), SynBool)
                                     and _call_value(fn,[e],self).value])
                return SynBuiltin("filter", arr_filter)
            if field == "join":
                return SynBuiltin("join", lambda a: SynStr(a[0].value.join(
                    e.value for e in obj.elements if isinstance(e, SynStr))))

        # Result methods
        if isinstance(obj, SynOk):
            if field == "unwrap":   return SynBuiltin("unwrap",  lambda a: obj.value)
            if field == "is_ok":    return SynBuiltin("is_ok",   lambda a: SYN_TRUE)
            if field == "is_err":   return SynBuiltin("is_err",  lambda a: SYN_FALSE)
        if isinstance(obj, SynErr):
            if field == "is_ok":    return SynBuiltin("is_ok",   lambda a: SYN_FALSE)
            if field == "is_err":   return SynBuiltin("is_err",  lambda a: SYN_TRUE)
            if field == "unwrap":
                raise RuntimeError(f"unwrap() on Err: {obj.message}")

        raise RuntimeError(f"no field {field!r} on {type(obj).__name__}")

    def _index_access(self, obj: VarekValue, idx: VarekValue) -> VarekValue:
        if isinstance(obj, SynArray):
            if isinstance(idx, SynInt):
                i = idx.value
                if 0 <= i < len(obj.elements):
                    return obj.elements[i]
                raise RuntimeError(f"array index {i} out of bounds (len={len(obj.elements)})")
        if isinstance(obj, SynMap):
            key = idx.value if hasattr(idx, "value") else str(idx)
            return obj.entries.get(key, SYN_NIL)
        if isinstance(obj, SynTuple):
            if isinstance(idx, SynInt):
                return obj.elements[idx.value]
        raise RuntimeError(f"cannot index {type(obj).__name__} with {type(idx).__name__}")
