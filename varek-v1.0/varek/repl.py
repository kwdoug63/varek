"""
varek/repl.py
────────────────
Interactive REPL (Read-Eval-Print Loop) for VAREK.

Features:
  - Multi-line input with brace matching
  - Persistent environment across expressions
  - Type inference display (:t expr)
  - History (arrow keys via readline if available)
  - Stdlib imports available immediately
  - Coloured output
  - Special commands: :help :type :env :clear :quit :load :reset
  - Error recovery — REPL continues after any error
"""

from __future__ import annotations

import os
import sys
import traceback
from typing import Optional

# Readline for history/completion (optional)
try:
    import readline
    _HAS_READLINE = True
except ImportError:
    _HAS_READLINE = False


# ── ANSI colours ──────────────────────────────────────────────────

def _c(code, text):
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def cyan(t):   return _c("36", t)
def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def red(t):    return _c("31", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)
def magenta(t):return _c("35", t)


# ══════════════════════════════════════════════════════════════════
# REPL
# ══════════════════════════════════════════════════════════════════

BANNER = f"""
{bold(cyan('VAREK'))} {bold('v1.0.0')} — {dim('AI Pipeline Programming Language')}
{dim('Kenneth Wayne Douglas, MD')}

Type {cyan(':help')} for commands  ·  {cyan(':quit')} to exit
All syn:: stdlib modules are available. Example: {dim('import var::tensor')}
"""

HELP_TEXT = f"""
{bold('VAREK REPL Commands')}

  {cyan(':help')}            Show this help
  {cyan(':quit')}  {cyan(':q')}        Exit the REPL
  {cyan(':type')} {dim('<expr>')}    Show inferred type of expression
  {cyan(':env')}             List all names in the current environment
  {cyan(':clear')}           Clear the screen
  {cyan(':reset')}           Reset the environment to defaults
  {cyan(':load')} {dim('<path>')}     Load and execute a .syn file
  {cyan(':bench')} {dim('<expr>')}    Benchmark an expression (10 runs)
  {cyan(':ir')} {dim('<fn>')}         Show LLVM IR for a function

{bold('Examples')}
  {dim('>>>')} let x = 42
  {dim('>>>')} fn double(n: int) -> int {{ n * 2 }}
  {dim('>>>')} double(x)
  {dim('>>>')} import var::tensor
  {dim('>>>')} tensor.randn([3, 4])
  {dim('>>>')} :type tensor.zeros([10])
"""

PRELUDE = """
-- VAREK REPL prelude
"""


class Repl:
    """Interactive REPL session."""

    def __init__(self, prelude: str = PRELUDE):
        from varek.runtime import Interpreter
        from varek.checker import TypeChecker

        self._interp  = Interpreter()
        self._checker = TypeChecker
        self._history: list[str] = []
        self._session_source: list[str] = []

        if _HAS_READLINE:
            readline.parse_and_bind("tab: complete")
            readline.set_history_length(1000)

        # Run prelude silently
        try:
            if prelude.strip():
                self._interp.run(prelude, "<prelude>")
        except Exception:
            pass

    def run(self) -> None:
        """Start the interactive REPL loop."""
        print(BANNER)
        while True:
            try:
                src = self._read_input()
                if src is None:
                    break
                if not src.strip():
                    continue
                self._eval(src)
            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                break

        print(f"\n{dim('Goodbye.')}")

    def _read_input(self) -> Optional[str]:
        """Read potentially multi-line input with brace balancing."""
        prompt_main = f"{cyan('>>>')} "
        prompt_cont = f"{dim('...')} "

        lines = []
        depth = 0

        try:
            first = input(prompt_main)
        except EOFError:
            return None

        # Handle REPL commands
        if first.strip().startswith(":"):
            return first

        lines.append(first)
        depth += first.count("{") - first.count("}")

        # Continue reading if braces are unbalanced
        while depth > 0:
            try:
                cont = input(prompt_cont)
            except EOFError:
                break
            lines.append(cont)
            depth += cont.count("{") - cont.count("}")

        return "\n".join(lines)

    def _eval(self, src: str) -> None:
        """Evaluate one REPL input."""
        stripped = src.strip()

        # ── Commands ──────────────────────────────────────────────
        if stripped == ":help":
            print(HELP_TEXT)
            return

        if stripped in (":quit", ":q", ":exit"):
            raise EOFError

        if stripped == ":clear":
            os.system("clear" if os.name != "nt" else "cls")
            return

        if stripped == ":reset":
            from varek.runtime import Interpreter
            self._interp = Interpreter()
            self._session_source.clear()
            print(dim("  Environment reset."))
            return

        if stripped == ":env":
            self._show_env()
            return

        if stripped.startswith(":load "):
            path = stripped[6:].strip()
            self._load_file(path)
            return

        if stripped.startswith(":type "):
            expr = stripped[6:].strip()
            self._show_type(expr)
            return

        if stripped.startswith(":bench "):
            expr = stripped[7:].strip()
            self._benchmark(expr)
            return

        if stripped.startswith(":ir "):
            fn_src = stripped[4:].strip()
            self._show_ir(fn_src)
            return

        # ── Regular VAREK input ─────────────────────────────────
        self._exec(src)

    def _exec(self, src: str) -> None:
        """Execute VAREK source and print the result."""
        import varek
        from varek.runtime import (SynNil, SynInt, SynFloat, SynStr,
                                       SynBool, SynArray, SynTensor,
                                       SynOk, SynErr, SynFunction, SynBuiltin)
        from varek.stdlib import StdlibModule

        try:
            # Try as expression first (wrap in let)
            is_stmt = self._is_statement(src)

            if not is_stmt:
                # Wrap as expression to capture value
                wrapped = f"let __repl_result__ = {src}"
                tree, errors = varek.parse(wrapped, "<repl>")
                if not errors.has_errors():
                    self._interp.run(wrapped, "<repl>")
                    try:
                        val = self._interp._global_env.get("__repl_result__")
                        self._print_value(val)
                    except Exception:
                        pass
                    self._session_source.append(src)
                    return

            # Run as statement
            self._interp.run(src, "<repl>")
            self._session_source.append(src)

            # Check if a let binding was added
            if src.strip().startswith("let "):
                name = src.strip().split()[1].split(":")[0].split("=")[0].strip()
                try:
                    val = self._interp._global_env.get(name)
                    print(f"  {dim(name)} = {self._format_value(val)}")
                except Exception:
                    pass

        except Exception as e:
            self._print_error(str(e))

    def _is_statement(self, src: str) -> bool:
        kws = ("let ", "mut let", "fn ", "async fn", "export fn",
               "schema ", "pipeline ", "import ", "safe import",
               "for ", "return ", "if ")
        s = src.strip()
        return any(s.startswith(kw) for kw in kws)

    def _print_value(self, val) -> None:
        from varek.runtime import SynNil
        if isinstance(val, SynNil):
            return
        formatted = self._format_value(val)
        if formatted:
            print(f"  {green('=')} {formatted}")

    def _format_value(self, val) -> str:
        from varek.runtime import (SynNil, SynInt, SynFloat, SynStr,
                                       SynBool, SynArray, SynTensor,
                                       SynOk, SynErr, SynFunction, SynBuiltin)
        from varek.stdlib import StdlibModule
        import numpy as np

        if isinstance(val, SynNil):     return dim("nil")
        if isinstance(val, SynBool):    return cyan("true") if val.value else cyan("false")
        if isinstance(val, SynInt):     return yellow(str(val.value))
        if isinstance(val, SynFloat):   return yellow(f"{val.value:g}")
        if isinstance(val, SynStr):     return green(repr(val.value))
        if isinstance(val, SynOk):      return f"Ok({self._format_value(val.value)})"
        if isinstance(val, SynErr):     return red(f"Err({val.message!r})")
        if isinstance(val, SynFunction):return dim(f"<fn {val.name}>")
        if isinstance(val, SynBuiltin): return dim(f"<builtin {val.name}>")
        if isinstance(val, StdlibModule):return dim(f"<syn::{val.module_name}>")
        if isinstance(val, SynTensor):
            arr = val.data if isinstance(val.data, np.ndarray) else np.array(val.data)
            shape_str = "×".join(str(d) for d in arr.shape)
            dtype_str = str(arr.dtype)
            if arr.size <= 6:
                vals = " ".join(f"{v:.4g}" for v in arr.flatten())
                return magenta(f"Tensor[{shape_str}]") + f"({vals})"
            return magenta(f"Tensor[{shape_str}, {dtype_str}]")
        if isinstance(val, SynArray):
            if len(val.elements) <= 8:
                inner = ", ".join(self._format_value(e) for e in val.elements)
                return f"[{inner}]"
            inner = ", ".join(self._format_value(e) for e in val.elements[:6])
            return f"[{inner}, {dim(f'... {len(val.elements)} items')}]"
        return str(val)

    def _show_env(self) -> None:
        from varek.runtime import SynFunction, SynBuiltin
        from varek.stdlib import StdlibModule
        env = self._interp._global_env

        user_bindings = {}
        try:
            for name in env.local_names():
                try:
                    val = env.get(name)
                    if not isinstance(val, (SynBuiltin,)) or name in ("Ok", "Err", "Some"):
                        user_bindings[name] = val
                except Exception:
                    pass
        except Exception:
            pass

        if not user_bindings:
            print(dim("  (environment empty — only builtins loaded)"))
            return

        print(f"\n  {bold('Environment')} ({len(user_bindings)} bindings)\n")
        for name, val in sorted(user_bindings.items()):
            print(f"  {cyan(name):<20} {self._format_value(val)}")
        print()

    def _show_type(self, expr: str) -> None:
        import varek
        ty, errors = varek.check_expr(expr)
        if ty:
            print(f"  {dim(expr)} : {cyan(str(ty))}")
        else:
            print(red("  Type error:"))
            print(errors.report())

    def _load_file(self, path: str) -> None:
        try:
            with open(path, "r") as f:
                source = f.read()
            self._interp.run(source, path)
            print(green(f"  ✓ Loaded {path}"))
        except FileNotFoundError:
            print(red(f"  File not found: {path}"))
        except Exception as e:
            self._print_error(str(e))

    def _benchmark(self, expr: str) -> None:
        import time
        import varek
        runs = 10

        # Warm up
        try:
            self._interp.eval_expr(expr)
        except Exception as e:
            self._print_error(str(e))
            return

        times = []
        for _ in range(runs):
            t0 = time.perf_counter()
            try:
                self._interp.eval_expr(expr)
            except Exception:
                break
            times.append((time.perf_counter() - t0) * 1000)

        if times:
            mean = sum(times) / len(times)
            best = min(times)
            print(f"  {bold('Benchmark')} ({runs} runs)")
            print(f"  mean: {yellow(f'{mean:.3f}ms')}  best: {yellow(f'{best:.3f}ms')}")

    def _show_ir(self, fn_src: str) -> None:
        from varek.compiler import Compiler, CompileMode
        r = Compiler.compile(fn_src, "<repl>", mode=CompileMode.EMIT_IR)
        if r.ok and r.ir:
            for line in r.ir.splitlines():
                if line.strip() and not line.startswith(";") and \
                   not line.startswith("declare"):
                    print(f"  {dim(line)}")
        else:
            print(red("  IR generation failed"))
            if r.errors.has_errors():
                print(r.errors.report())

    def _print_error(self, msg: str) -> None:
        # Trim traceback to just the error message
        lines = msg.strip().splitlines()
        for line in lines[:5]:
            print(f"  {red('error:')} {line}")


def start_repl() -> None:
    """Entry point for `varek repl`."""
    repl = Repl()
    repl.run()
