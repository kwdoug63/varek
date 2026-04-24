"""
varek/stdlib/__init__.py
───────────────────────────
Standard library registry and import resolver for VAREK v0.4.

Maps `import var::module::name` paths to their Python implementations.
The registry is consulted by the runtime Interpreter when it encounters
an ImportStmt with a `syn::` prefix.

Usage in runtime.py:
    from varek.stdlib import resolve_import, STDLIB_MODULES

Supported module paths:
    var::io         → varek.stdlib.io.EXPORTS
    var::tensor     → varek.stdlib.tensor.EXPORTS
    var::http       → varek.stdlib.http.EXPORTS
    var::async      → varek.stdlib.async_.EXPORTS
    var::pipeline   → varek.stdlib.pipeline.EXPORTS
    var::model      → varek.stdlib.model.MODEL_EXPORTS
    var::data       → varek.stdlib.model.DATA_EXPORTS

Additionally, individual names can be imported:
    import var::tensor::zeros   → just the zeros function
    import var::io as io        → io.read_file, io.write_file, etc.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from varek.runtime import VarekValue, SynBuiltin, SynMap, SYN_NIL


# ── Lazy module loader ────────────────────────────────────────────

_MODULE_CACHE: Dict[str, Dict[str, VarekValue]] = {}

def _load_module(name: str) -> Dict[str, VarekValue]:
    """Load and cache a stdlib module by canonical name."""
    if name in _MODULE_CACHE:
        return _MODULE_CACHE[name]

    exports: Dict[str, VarekValue] = {}

    if name == "io":
        from varek.stdlib.io import EXPORTS
        exports = EXPORTS

    elif name == "tensor":
        from varek.stdlib.tensor import EXPORTS
        exports = EXPORTS

    elif name == "http":
        from varek.stdlib.http import EXPORTS
        exports = EXPORTS

    elif name in ("async", "async_"):
        from varek.stdlib.async_ import EXPORTS
        exports = EXPORTS

    elif name == "pipeline":
        from varek.stdlib.pipeline import EXPORTS
        exports = EXPORTS

    elif name == "model":
        from varek.stdlib.model import MODEL_EXPORTS
        exports = MODEL_EXPORTS

    elif name == "data":
        from varek.stdlib.model import DATA_EXPORTS
        exports = DATA_EXPORTS

    else:
        return {}

    _MODULE_CACHE[name] = exports
    return exports


# ── Module namespace wrapper ──────────────────────────────────────

class StdlibModule(VarekValue):
    """
    A loaded stdlib module — acts as a namespace.
    Accessed via member syntax: io.read_file, tensor.zeros, etc.
    """

    def __init__(self, module_name: str, exports: Dict[str, VarekValue]):
        self.module_name = module_name
        self._exports    = exports

    def get(self, name: str) -> Optional[VarekValue]:
        return self._exports.get(name)

    def all_names(self) -> List[str]:
        return list(self._exports.keys())

    def __repr__(self) -> str:
        return f"<syn::{self.module_name}>"


# ── Import resolver ───────────────────────────────────────────────

def resolve_import(
    path: List[str],
    alias: Optional[str],
) -> Dict[str, VarekValue]:
    """
    Resolve an import path to a dict of {name: value} bindings.

    Examples:
      path=["syn","io"]             → {"io": StdlibModule("io", ...)}
      path=["syn","io"], alias="fs" → {"fs": StdlibModule("io", ...)}
      path=["syn","tensor","zeros"] → {"zeros": <builtin zeros>}
      path=["python","numpy"]       → {}  (handled by Python interop)
    """
    if not path or path[0] != "syn":
        return {}   # Not a stdlib import

    if len(path) < 2:
        return {}

    module_name = path[1]
    exports     = _load_module(module_name)

    if not exports:
        return {}

    # import var::tensor::zeros  →  just that one name
    if len(path) >= 3:
        item_name = path[2]
        item      = exports.get(item_name)
        if item:
            bind_as = alias or item_name
            return {bind_as: item}
        return {}

    # import var::tensor  →  whole module as a namespace
    mod     = StdlibModule(module_name, exports)
    bind_as = alias or module_name
    return {bind_as: mod}


def get_module(name: str) -> Optional[StdlibModule]:
    """Get a stdlib module by name (without syn:: prefix)."""
    exports = _load_module(name)
    if not exports:
        return None
    return StdlibModule(name, exports)


# ── All available modules ─────────────────────────────────────────

STDLIB_MODULES = [
    "io",
    "tensor",
    "http",
    "async",
    "pipeline",
    "model",
    "data",
]

def list_modules() -> List[str]:
    return [f"syn::{m}" for m in STDLIB_MODULES]

def module_names(module: str) -> List[str]:
    """Return all exported names from a stdlib module."""
    exports = _load_module(module)
    return sorted(exports.keys())
