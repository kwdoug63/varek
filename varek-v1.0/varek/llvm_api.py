"""
varek/llvm_api.py
────────────────────
Raw ctypes bindings to the LLVM 20 C API.

CRITICAL: All LLVM functions returning char* use c_void_p as restype
(not c_char_p). Python's c_char_p auto-frees the pointer on garbage
collection, corrupting LLVM's heap. We read with ctypes.string_at()
and free with libc.free(). This is the correct pattern for LLVM C API.
"""

from __future__ import annotations
import ctypes
from typing import Optional

# ── Load libraries ────────────────────────────────────────────────

def _load(names):
    for name in names:
        try: return ctypes.CDLL(name)
        except OSError: continue
    raise RuntimeError(f"Could not load any of: {names}")

_lib  = _load(["libLLVM-20.so", "libLLVM.so.20.1", "libLLVM.so"])
_libc = _load(["libc.so.6", "libc.so"])

def llvm_free(ptr):
    """Free a char* returned by an LLVM function."""
    if ptr: _libc.free(ptr)

def llvm_str(ptr) -> str:
    """Read a char* returned by LLVM, then free it."""
    if not ptr: return ""
    s = ctypes.string_at(ptr).decode("utf-8")
    _libc.free(ptr)
    return s

# ── Opaque handle types ───────────────────────────────────────────

P = ctypes.c_void_p   # all LLVM opaque handles

LLVMContextRef       = P
LLVMModuleRef        = P
LLVMTypeRef          = P
LLVMValueRef         = P
LLVMBasicBlockRef    = P
LLVMBuilderRef       = P
LLVMTargetRef        = P
LLVMTargetDataRef    = P
LLVMTargetMachineRef = P
LLVMPassManagerRef   = P
LLVMMemoryBufferRef  = P

c_bool   = ctypes.c_bool
c_int    = ctypes.c_int
c_uint   = ctypes.c_uint
c_uint64 = ctypes.c_uint64
c_size_t = ctypes.c_size_t

def _fn(name, restype, *argtypes):
    f = getattr(_lib, name)
    f.restype  = restype
    f.argtypes = list(argtypes)
    return f

# ── Context ───────────────────────────────────────────────────────

LLVMContextCreate    = _fn("LLVMContextCreate",    P)
LLVMContextDispose   = _fn("LLVMContextDispose",   None, P)

# ── Module ────────────────────────────────────────────────────────

LLVMModuleCreateWithNameInContext = _fn("LLVMModuleCreateWithNameInContext", P, ctypes.c_char_p, P)
LLVMDisposeModule    = _fn("LLVMDisposeModule",    None, P)
LLVMSetDataLayout    = _fn("LLVMSetDataLayout",    None, P, ctypes.c_char_p)
LLVMSetTarget        = _fn("LLVMSetTarget",        None, P, ctypes.c_char_p)

# Returns char* — use c_void_p + llvm_str()
_LLVMPrintModuleToString = _fn("LLVMPrintModuleToString", P, P)

def module_to_ir_string(module) -> str:
    ptr = _LLVMPrintModuleToString(module)
    return llvm_str(ptr)

def LLVMVerifyModule(module) -> Optional[str]:
    fn = getattr(_lib, "LLVMVerifyModule")
    fn.restype  = c_bool
    fn.argtypes = [P, c_int, ctypes.POINTER(P)]
    msg = P()
    failed = fn(module, 1, ctypes.byref(msg))
    if failed and msg.value:
        s = ctypes.string_at(msg.value).decode()
        _libc.free(msg.value)
        return s
    return None

# ── Types ─────────────────────────────────────────────────────────

LLVMInt1TypeInContext    = _fn("LLVMInt1TypeInContext",    P, P)
LLVMInt8TypeInContext    = _fn("LLVMInt8TypeInContext",    P, P)
LLVMInt32TypeInContext   = _fn("LLVMInt32TypeInContext",   P, P)
LLVMInt64TypeInContext   = _fn("LLVMInt64TypeInContext",   P, P)
LLVMDoubleTypeInContext  = _fn("LLVMDoubleTypeInContext",  P, P)
LLVMVoidTypeInContext    = _fn("LLVMVoidTypeInContext",    P, P)
LLVMPointerType          = _fn("LLVMPointerType",          P, P, c_uint)
LLVMArrayType            = _fn("LLVMArrayType",            P, P, c_uint)
LLVMFunctionType         = _fn("LLVMFunctionType",         P, P, ctypes.POINTER(P), c_uint, c_bool)
LLVMStructTypeInContext  = _fn("LLVMStructTypeInContext",  P, P, ctypes.POINTER(P), c_uint, c_bool)

# ── Constants ─────────────────────────────────────────────────────

LLVMConstInt             = _fn("LLVMConstInt",             P, P, c_uint64, c_bool)
LLVMConstReal            = _fn("LLVMConstReal",            P, P, ctypes.c_double)
LLVMConstNull            = _fn("LLVMConstNull",            P, P)
LLVMConstStringInContext = _fn("LLVMConstStringInContext", P, P, ctypes.c_char_p, c_uint, c_bool)
LLVMGetUndef             = _fn("LLVMGetUndef",             P, P)

# ── Functions ─────────────────────────────────────────────────────

LLVMAddFunction          = _fn("LLVMAddFunction",          P, P, ctypes.c_char_p, P)
LLVMGetParam             = _fn("LLVMGetParam",             P, P, c_uint)
LLVMSetValueName2        = _fn("LLVMSetValueName2",        None, P, ctypes.c_char_p, c_size_t)
LLVMSetLinkage           = _fn("LLVMSetLinkage",           None, P, c_uint)
LLVMGetNamedFunction     = _fn("LLVMGetNamedFunction",     P, P, ctypes.c_char_p)
LLVMGetNamedGlobal       = _fn("LLVMGetNamedGlobal",       P, P, ctypes.c_char_p)

# ── Basic blocks ──────────────────────────────────────────────────

LLVMAppendBasicBlockInContext = _fn("LLVMAppendBasicBlockInContext", P, P, P, ctypes.c_char_p)
LLVMGetInsertBlock       = _fn("LLVMGetInsertBlock",       P, P)
LLVMGetBasicBlockParent  = _fn("LLVMGetBasicBlockParent",  P, P)

# ── Builder ───────────────────────────────────────────────────────

LLVMCreateBuilderInContext = _fn("LLVMCreateBuilderInContext", P, P)
LLVMDisposeBuilder         = _fn("LLVMDisposeBuilder",         None, P)
LLVMPositionBuilderAtEnd   = _fn("LLVMPositionBuilderAtEnd",   None, P, P)

# Stack
LLVMBuildAlloca  = _fn("LLVMBuildAlloca",  P, P, P, ctypes.c_char_p)
LLVMBuildLoad2   = _fn("LLVMBuildLoad2",   P, P, P, P, ctypes.c_char_p)
LLVMBuildStore   = _fn("LLVMBuildStore",   P, P, P, P)

# Integer arithmetic
LLVMBuildAdd     = _fn("LLVMBuildAdd",     P, P, P, P, ctypes.c_char_p)
LLVMBuildSub     = _fn("LLVMBuildSub",     P, P, P, P, ctypes.c_char_p)
LLVMBuildMul     = _fn("LLVMBuildMul",     P, P, P, P, ctypes.c_char_p)
LLVMBuildSDiv    = _fn("LLVMBuildSDiv",    P, P, P, P, ctypes.c_char_p)
LLVMBuildSRem    = _fn("LLVMBuildSRem",    P, P, P, P, ctypes.c_char_p)
LLVMBuildNeg     = _fn("LLVMBuildNeg",     P, P, P, ctypes.c_char_p)
LLVMBuildNot     = _fn("LLVMBuildNot",     P, P, P, ctypes.c_char_p)

# Float arithmetic
LLVMBuildFAdd    = _fn("LLVMBuildFAdd",    P, P, P, P, ctypes.c_char_p)
LLVMBuildFSub    = _fn("LLVMBuildFSub",    P, P, P, P, ctypes.c_char_p)
LLVMBuildFMul    = _fn("LLVMBuildFMul",    P, P, P, P, ctypes.c_char_p)
LLVMBuildFDiv    = _fn("LLVMBuildFDiv",    P, P, P, P, ctypes.c_char_p)
LLVMBuildFNeg    = _fn("LLVMBuildFNeg",    P, P, P, ctypes.c_char_p)

# Conversions
LLVMBuildSIToFP  = _fn("LLVMBuildSIToFP", P, P, P, P, ctypes.c_char_p)
LLVMBuildFPToSI  = _fn("LLVMBuildFPToSI", P, P, P, P, ctypes.c_char_p)
LLVMBuildZExt    = _fn("LLVMBuildZExt",   P, P, P, P, ctypes.c_char_p)
LLVMBuildTrunc   = _fn("LLVMBuildTrunc",  P, P, P, P, ctypes.c_char_p)
LLVMBuildBitCast = _fn("LLVMBuildBitCast",P, P, P, P, ctypes.c_char_p)

# Comparisons
LLVM_INT_EQ  = 32; LLVM_INT_NE  = 33
LLVM_INT_SLT = 40; LLVM_INT_SGT = 38
LLVM_INT_SLE = 41; LLVM_INT_SGE = 39

LLVM_REAL_OEQ = 1; LLVM_REAL_ONE = 6
LLVM_REAL_OLT = 4; LLVM_REAL_OGT = 2
LLVM_REAL_OLE = 5; LLVM_REAL_OGE = 3

LLVMBuildICmp = _fn("LLVMBuildICmp", P, P, c_uint, P, P, ctypes.c_char_p)
LLVMBuildFCmp = _fn("LLVMBuildFCmp", P, P, c_uint, P, P, ctypes.c_char_p)

# Control flow
LLVMBuildBr          = _fn("LLVMBuildBr",          P, P, P)
LLVMBuildCondBr      = _fn("LLVMBuildCondBr",      P, P, P, P, P)
LLVMBuildRet         = _fn("LLVMBuildRet",         P, P, P)
LLVMBuildRetVoid     = _fn("LLVMBuildRetVoid",     P, P)
LLVMBuildUnreachable = _fn("LLVMBuildUnreachable", P, P)

# PHI
LLVMBuildPhi   = _fn("LLVMBuildPhi",   P, P, P, ctypes.c_char_p)
LLVMAddIncoming = _fn("LLVMAddIncoming", None, P, ctypes.POINTER(P), ctypes.POINTER(P), c_uint)

# Calls
LLVMBuildCall2 = _fn("LLVMBuildCall2", P, P, P, P, ctypes.POINTER(P), c_uint, ctypes.c_char_p)

# GEP
LLVMBuildGEP2 = _fn("LLVMBuildGEP2", P, P, P, P, ctypes.POINTER(P), c_uint, ctypes.c_char_p)

# Globals
LLVMAddGlobal          = _fn("LLVMAddGlobal",          P, P, P, ctypes.c_char_p)
LLVMSetInitializer     = _fn("LLVMSetInitializer",     None, P, P)
LLVMSetGlobalConstant  = _fn("LLVMSetGlobalConstant",  None, P, c_bool)
LLVMSetUnnamedAddress  = _fn("LLVMSetUnnamedAddress",  None, P, c_uint)

# ── Target machine ────────────────────────────────────────────────

LLVMInitializeX86Target     = _fn("LLVMInitializeX86Target",     None)
LLVMInitializeX86TargetInfo = _fn("LLVMInitializeX86TargetInfo", None)
LLVMInitializeX86TargetMC   = _fn("LLVMInitializeX86TargetMC",   None)
LLVMInitializeX86AsmPrinter = _fn("LLVMInitializeX86AsmPrinter", None)
LLVMInitializeX86AsmParser  = _fn("LLVMInitializeX86AsmParser",  None)

# Returns char* — use c_void_p
_LLVMGetDefaultTargetTriple = _fn("LLVMGetDefaultTargetTriple", P)

def LLVMGetDefaultTargetTriple() -> str:
    ptr = _LLVMGetDefaultTargetTriple()
    return llvm_str(ptr)

LLVMGetTargetFromTriple = _fn("LLVMGetTargetFromTriple", c_bool,
    ctypes.c_char_p, ctypes.POINTER(P), ctypes.POINTER(P))

LLVMCreateTargetMachine = _fn("LLVMCreateTargetMachine", P,
    P, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, c_uint, c_uint, c_uint)

LLVMCreateTargetDataLayout    = _fn("LLVMCreateTargetDataLayout",    P, P)
LLVMCopyStringRepOfTargetData = _fn("LLVMCopyStringRepOfTargetData", P, P)

def get_data_layout_string(target_machine) -> str:
    layout_ref = LLVMCreateTargetDataLayout(target_machine)
    ptr = LLVMCopyStringRepOfTargetData(layout_ref)
    return llvm_str(ptr)

LLVMDisposeTargetMachine = _fn("LLVMDisposeTargetMachine", None, P)
LLVMTargetMachineEmitToFile = _fn("LLVMTargetMachineEmitToFile", c_bool,
    P, P, ctypes.c_char_p, c_uint, ctypes.POINTER(P))

LLVM_ASSEMBLY_FILE  = 0
LLVM_OBJECT_FILE    = 1
LLVM_OPT_NONE       = 0
LLVM_OPT_LESS       = 1
LLVM_OPT_DEFAULT    = 2
LLVM_OPT_AGGRESSIVE = 3
LLVM_RELOC_DEFAULT  = 0
LLVM_RELOC_STATIC   = 1
LLVM_RELOC_PIC      = 2
LLVM_CM_DEFAULT     = 0
LLVM_CM_SMALL       = 2

# ── Passes ────────────────────────────────────────────────────────

LLVMCreatePassManager  = _fn("LLVMCreatePassManager",  P)
LLVMRunPassManager     = _fn("LLVMRunPassManager",     c_bool, P, P)
LLVMDisposePassManager = _fn("LLVMDisposePassManager", None, P)

LLVMRunPasses = None
try:
    LLVMRunPasses = _fn("LLVMRunPasses", c_int, P, ctypes.c_char_p, P, ctypes.c_void_p)
except Exception:
    pass

# ── Helpers ───────────────────────────────────────────────────────

def init_x86():
    LLVMInitializeX86TargetInfo()
    LLVMInitializeX86Target()
    LLVMInitializeX86TargetMC()
    LLVMInitializeX86AsmPrinter()
    LLVMInitializeX86AsmParser()

def make_array(ref_type, items):
    if not items:
        return (ref_type * 1)()
    return (ref_type * len(items))(*items)
