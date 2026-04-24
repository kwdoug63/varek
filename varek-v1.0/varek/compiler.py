"""
varek/compiler.py
────────────────────
Compiler driver for VAREK v0.3.

Orchestrates the full compilation pipeline:

  source  →  [Lexer]  →  tokens
          →  [Parser] →  AST
          →  [TypeChecker] → typed AST
          →  [CodeGen] → LLVM IR
          →  [LLVM Target Machine] → native object / assembly
          →  (link) → executable or shared library

Usage modes:

  emit-ir     Just generate LLVM IR (.ll text)
  emit-asm    Generate native assembly (.s)
  emit-obj    Generate object file (.o)
  interpret   Run via the tree-walking interpreter (no compilation)
  compile     Full pipeline → native executable

The compiler retains the interpreter as a fallback and for use in
the REPL. Both modes share the same parser and type checker front-end.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, List

from varek.errors import ErrorBag
from varek.checker import TypeChecker, CheckResult


# ══════════════════════════════════════════════════════════════════
# COMPILATION MODE
# ══════════════════════════════════════════════════════════════════

class CompileMode(Enum):
    INTERPRET  = auto()   # tree-walking interpreter
    EMIT_IR    = auto()   # → LLVM IR text (.ll)
    EMIT_ASM   = auto()   # → native assembly (.s)
    EMIT_OBJ   = auto()   # → object file (.o)
    COMPILE    = auto()   # → native executable


# ══════════════════════════════════════════════════════════════════
# COMPILATION RESULT
# ══════════════════════════════════════════════════════════════════

@dataclass
class CompileResult:
    ok:         bool
    mode:       CompileMode
    errors:     ErrorBag
    ir:         Optional[str] = None        # LLVM IR text
    output_path: Optional[str] = None      # path to output file
    check_result: Optional[CheckResult] = None
    timings:    dict = field(default_factory=dict)  # stage → seconds

    def report(self) -> str:
        lines = []
        if self.ok:
            lines.append(f"✓ Compilation succeeded ({self.mode.name})")
            if self.output_path:
                lines.append(f"  output: {self.output_path}")
        else:
            lines.append(f"✗ Compilation failed ({self.mode.name})")
            if self.errors.has_errors():
                lines.append(self.errors.report())
        if self.timings:
            lines.append("\n  Timings:")
            for stage, t in self.timings.items():
                lines.append(f"    {stage:<20} {t*1000:.2f} ms")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# GLOBAL TARGET MACHINE SINGLETON
# ══════════════════════════════════════════════════════════════════
# LLVM x86 backend initialisation is not safe to call multiple times
# within the same process. We cache a single TargetMachine instance.

_GLOBAL_TM: "Optional[TargetMachine]" = None
_GLOBAL_TM_OPT: int = -1   # opt level of the cached machine

def _get_target_machine(opt_level: int = 2) -> "TargetMachine":
    global _GLOBAL_TM, _GLOBAL_TM_OPT
    if _GLOBAL_TM is None or _GLOBAL_TM_OPT != opt_level:
        if _GLOBAL_TM is not None:
            try: _GLOBAL_TM.dispose()
            except Exception: pass
        _GLOBAL_TM     = TargetMachine(opt_level=opt_level)
        _GLOBAL_TM_OPT = opt_level
    return _GLOBAL_TM

# ══════════════════════════════════════════════════════════════════
# TARGET MACHINE
# ══════════════════════════════════════════════════════════════════

class TargetMachine:
    """
    Wraps LLVM target machine creation and code emission.
    Uses the LLVM C API directly.
    """

    def __init__(self, opt_level: int = 2):
        from varek.llvm_api import (
            init_x86,
            LLVMGetDefaultTargetTriple, LLVMGetTargetFromTriple,
            LLVMCreateTargetMachine,
            LLVMTargetMachineEmitToFile,
            LLVM_OPT_DEFAULT, LLVM_OPT_NONE, LLVM_OPT_AGGRESSIVE,
            LLVM_RELOC_PIC, LLVM_CM_DEFAULT,
            LLVM_ASSEMBLY_FILE, LLVM_OBJECT_FILE,
        )

        init_x86()

        # Get the host triple
        self.triple = LLVMGetDefaultTargetTriple()

        # Get the target
        target_ref = ctypes.c_void_p()
        err_ptr    = ctypes.c_void_p()
        failed     = LLVMGetTargetFromTriple(
            self.triple.encode(),
            ctypes.byref(target_ref),
            ctypes.byref(err_ptr),
        )
        if failed:
            from varek.llvm_api import llvm_str
            msg = llvm_str(err_ptr.value) if err_ptr.value else "unknown"
            raise RuntimeError(f"Failed to get LLVM target: {msg}")

        # Map opt level
        llvm_opt = {0: LLVM_OPT_NONE, 1: 1, 2: LLVM_OPT_DEFAULT,
                    3: LLVM_OPT_AGGRESSIVE}.get(opt_level, LLVM_OPT_DEFAULT)

        # Create target machine
        self._machine = LLVMCreateTargetMachine(
            target_ref,
            self.triple.encode(),
            b"",                   # CPU (empty = host)
            b"",                   # features
            llvm_opt,
            LLVM_RELOC_PIC,
            LLVM_CM_DEFAULT,
        )

        # Get data layout string
        from varek.llvm_api import get_data_layout_string
        self.data_layout = get_data_layout_string(self._machine)

    def emit_to_file(self, module, path: str, kind: int) -> Optional[str]:
        """Emit module to file. Returns error message or None."""
        from varek.llvm_api import LLVMTargetMachineEmitToFile, llvm_str, P
        err_ptr = P()
        failed = LLVMTargetMachineEmitToFile(
            self._machine, module, path.encode(), kind,
            ctypes.byref(err_ptr)
        )
        if failed:
            return llvm_str(err_ptr.value) if err_ptr.value else "unknown error"
        return None

    def emit_assembly(self, module, path: str) -> Optional[str]:
        return self.emit_to_file(module, path, 0)  # LLVM_ASSEMBLY_FILE = 0

    def emit_object(self, module, path: str) -> Optional[str]:
        return self.emit_to_file(module, path, 1)  # LLVM_OBJECT_FILE = 1

    def dispose(self):
        from varek.llvm_api import LLVMDisposeTargetMachine
        try:
            if self._machine:
                LLVMDisposeTargetMachine(self._machine)
                self._machine = None
        except Exception: pass


# ══════════════════════════════════════════════════════════════════
# OPTIMIZER
# ══════════════════════════════════════════════════════════════════

def run_optimizations(module, target_machine: TargetMachine,
                      opt_level: int = 2) -> bool:
    """
    Run LLVM optimization passes on a module.

    Uses the new pass manager (LLVM 13+) via LLVMRunPasses if available,
    falls back to the legacy pass manager otherwise.
    """
    from varek.llvm_api import LLVMRunPasses, LLVMSetDataLayout, LLVMSetTarget

    # Set data layout and target triple before optimizing
    LLVMSetDataLayout(module, target_machine.data_layout.encode())
    LLVMSetTarget(module, target_machine.triple.encode())

    if LLVMRunPasses is not None and opt_level > 0:
        pipeline = {
            0: b"",
            1: b"default<O1>",
            2: b"default<O2>",
            3: b"default<O3>",
        }.get(opt_level, b"default<O2>")
        try:
            ret = LLVMRunPasses(module, pipeline, target_machine._machine, None)
            return ret == 0
        except Exception:
            pass

    # Legacy pass manager fallback
    from varek.llvm_api import (
        LLVMCreatePassManager, LLVMRunPassManager, LLVMDisposePassManager
    )
    pm = LLVMCreatePassManager()
    result = LLVMRunPassManager(pm, module)
    LLVMDisposePassManager(pm)
    return bool(result)


# ══════════════════════════════════════════════════════════════════
# COMPILER DRIVER
# ══════════════════════════════════════════════════════════════════

class Compiler:
    """
    Main compiler driver.

    Usage:
        result = Compiler.compile(source, mode=CompileMode.EMIT_IR)
        result = Compiler.compile(source, mode=CompileMode.EMIT_OBJ, output="out.o")
        result = Compiler.interpret(source)
    """

    @classmethod
    def compile(
        cls,
        source:     str,
        filename:   str       = "<stdin>",
        mode:       CompileMode = CompileMode.EMIT_IR,
        output:     Optional[str] = None,
        opt_level:  int       = 2,
    ) -> CompileResult:
        """
        Full compilation pipeline.
        """
        timings  = {}
        errors   = ErrorBag()

        # ── Stage 1: Type check ───────────────────────────────
        t0 = time.perf_counter()
        check_result = TypeChecker.check(source, filename)
        timings["type_check"] = time.perf_counter() - t0

        for e in check_result.errors:
            errors.add(e)

        if mode == CompileMode.INTERPRET:
            return CompileResult(
                ok=check_result.ok,
                mode=mode,
                errors=errors,
                check_result=check_result,
                timings=timings,
            )

        # ── Stage 2: Parse for AST (re-use from check) ────────
        import varek
        t0 = time.perf_counter()
        tree, parse_errors = varek.parse(source, filename)
        timings["parse"] = time.perf_counter() - t0

        # ── Stage 3: Code generation ──────────────────────────
        t0 = time.perf_counter()
        from varek.codegen import CodeGen
        gen = CodeGen(filename.replace(".syn", "").replace("<", "").replace(">", ""))
        try:
            ir_text = gen.generate(tree)
            timings["codegen"] = time.perf_counter() - t0
        except Exception as e:
            errors.add(type("CodeGenError", (Exception,),
                           {"message": str(e), "span": None,
                            "__str__": lambda s: s.message})(str(e)))
            return CompileResult(ok=False, mode=mode, errors=errors,
                                 timings=timings)

        if mode == CompileMode.EMIT_IR:
            out_path = output or filename.replace(".syn", ".ll")
            if output or filename.endswith(".syn"):
                with open(out_path, "w") as f:
                    f.write(ir_text)
            return CompileResult(
                ok=True, mode=mode, errors=errors,
                ir=ir_text, output_path=out_path,
                check_result=check_result, timings=timings,
            )

        # ── Stage 4: Target machine + native emission ─────────
        t0 = time.perf_counter()
        try:
            tm = _get_target_machine(opt_level)

            # Apply data layout to module
            from varek.llvm_api import LLVMSetDataLayout, LLVMSetTarget
            LLVMSetDataLayout(gen.ctx.module, tm.data_layout.encode())
            LLVMSetTarget(gen.ctx.module, tm.triple.encode())

            # Optimize
            if opt_level > 0:
                run_optimizations(gen.ctx.module, tm, opt_level)

            timings["optimize"] = time.perf_counter() - t0
            t0 = time.perf_counter()

            if mode == CompileMode.EMIT_ASM:
                out_path = output or filename.replace(".syn", ".s")
                err = tm.emit_assembly(gen.ctx.module, out_path)
                timings["emit"] = time.perf_counter() - t0
                if err:
                    from varek.errors import VarekError, Span
                    errors.add(VarekError(err, Span(filename, 0, 0)))
                    return CompileResult(ok=False, mode=mode, errors=errors,
                                        timings=timings)
                return CompileResult(ok=True, mode=mode, errors=errors,
                                     ir=ir_text, output_path=out_path,
                                     check_result=check_result, timings=timings)

            if mode == CompileMode.EMIT_OBJ:
                out_path = output or filename.replace(".syn", ".o")
                err = tm.emit_object(gen.ctx.module, out_path)
                timings["emit"] = time.perf_counter() - t0
                if err:
                    from varek.errors import VarekError, Span
                    errors.add(VarekError(err, Span(filename, 0, 0)))
                    return CompileResult(ok=False, mode=mode, errors=errors,
                                        timings=timings)
                return CompileResult(ok=True, mode=mode, errors=errors,
                                     ir=ir_text, output_path=out_path,
                                     check_result=check_result, timings=timings)

            if mode == CompileMode.COMPILE:
                # Emit object then link
                obj_path = output.replace(".out","").replace(".exe","")+".o" \
                           if output else filename.replace(".syn", ".o")
                err = tm.emit_object(gen.ctx.module, obj_path)
                if err:
                    from varek.errors import VarekError, Span
                    errors.add(VarekError(err, Span(filename, 0, 0)))
                    return CompileResult(ok=False, mode=mode, errors=errors,
                                        timings=timings)

                # Link with system linker
                exe_path = output or filename.replace(".syn", "")
                link_result = cls._link(obj_path, exe_path)
                timings["link"] = time.perf_counter() - t0
                return CompileResult(
                    ok=link_result.returncode == 0,
                    mode=mode, errors=errors,
                    ir=ir_text, output_path=exe_path,
                    check_result=check_result, timings=timings,
                )

        except Exception as e:
            from varek.errors import VarekError, Span
            errors.add(VarekError(str(e), Span(filename, 0, 0)))
            return CompileResult(ok=False, mode=mode, errors=errors,
                                 timings=timings)
        finally:
            gen.dispose()
            # tm is a singleton — do not dispose here

        return CompileResult(ok=False, mode=mode, errors=errors,
                             timings=timings)

    @classmethod
    def interpret(
        cls,
        source:   str,
        filename: str = "<stdin>",
    ) -> CompileResult:
        """Run in interpreted mode."""
        from varek.runtime import Interpreter
        errors = ErrorBag()
        timings = {}
        t0 = time.perf_counter()
        interp = Interpreter()
        try:
            result = interp.run(source, filename)
            timings["interpret"] = time.perf_counter() - t0
            return CompileResult(
                ok=True, mode=CompileMode.INTERPRET,
                errors=errors, timings=timings,
            )
        except Exception as e:
            from varek.errors import VarekError, Span
            errors.add(VarekError(str(e), Span(filename, 0, 0)))
            timings["interpret"] = time.perf_counter() - t0
            return CompileResult(
                ok=False, mode=CompileMode.INTERPRET,
                errors=errors, timings=timings,
            )

    @staticmethod
    def _link(obj_path: str, exe_path: str) -> subprocess.CompletedProcess:
        """Attempt to link an object file into an executable."""
        for linker in ["gcc", "clang", "cc", "ld"]:
            try:
                return subprocess.run(
                    [linker, obj_path, "-o", exe_path, "-lc", "-lm"],
                    capture_output=True, timeout=30,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        # Return a fake failure if no linker found
        import subprocess as sp
        result = sp.CompletedProcess([], 1)
        result.stderr = b"no system linker found"
        return result
