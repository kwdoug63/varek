"""
varek/stdlib/io.py
─────────────────────
var::io — File system, streams, paths, and standard I/O.

VAREK type signatures:
  read_file(path: str) -> Result<str>
  read_bytes(path: str) -> Result<int[]>
  write_file(path: str, content: str) -> Result<nil>
  write_bytes(path: str, data: int[]) -> Result<nil>
  append_file(path: str, content: str) -> Result<nil>
  file_exists(path: str) -> bool
  is_dir(path: str) -> bool
  list_dir(path: str) -> Result<str[]>
  make_dir(path: str) -> Result<nil>
  remove_file(path: str) -> Result<nil>
  copy_file(src: str, dst: str) -> Result<nil>
  file_size(path: str) -> Result<int>
  basename(path: str) -> str
  dirname(path: str) -> str
  join_path(a: str, b: str) -> str
  abs_path(path: str) -> str
  print(msg: str) -> nil
  println(msg: str) -> nil
  eprint(msg: str) -> nil       -- stderr
  input(prompt: str) -> str
  read_lines(path: str) -> Result<str[]>
  stdin_lines() -> str[]
"""

from __future__ import annotations

import gzip
import io
import os
import pathlib
import shutil
import sys
from typing import List, Optional

from varek.runtime import (
    VarekValue, SynStr, SynInt, SynBool, SynNil, SynArray,
    SynOk, SynErr, SynBuiltin, SYN_NIL, SYN_TRUE, SYN_FALSE,
)


# ── Helpers ───────────────────────────────────────────────────────

def _ok(v: VarekValue) -> SynOk:      return SynOk(v)
def _err(msg: str)       -> SynErr:     return SynErr(msg)
def _nil()               -> SynOk:      return SynOk(SYN_NIL)
def _bi(name, fn):                      return SynBuiltin(name, fn)
def _str(v: VarekValue) -> str:
    return v.value if isinstance(v, SynStr) else str(v)


# ── File read / write ─────────────────────────────────────────────

def _read_file(args):
    path = _str(args[0])
    try:
        with open(path, "r", encoding="utf-8") as f:
            return _ok(SynStr(f.read()))
    except Exception as e:
        return _err(str(e))

def _read_bytes(args):
    path = _str(args[0])
    try:
        with open(path, "rb") as f:
            data = f.read()
        return _ok(SynArray([SynInt(b) for b in data]))
    except Exception as e:
        return _err(str(e))

def _write_file(args):
    path, content = _str(args[0]), _str(args[1])
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return _nil()
    except Exception as e:
        return _err(str(e))

def _write_bytes(args):
    path = _str(args[0])
    data = [b.value for b in args[1].elements] if isinstance(args[1], SynArray) else []
    try:
        with open(path, "wb") as f:
            f.write(bytes(data))
        return _nil()
    except Exception as e:
        return _err(str(e))

def _append_file(args):
    path, content = _str(args[0]), _str(args[1])
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(content)
        return _nil()
    except Exception as e:
        return _err(str(e))

def _read_lines(args):
    path = _str(args[0])
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        return _ok(SynArray([SynStr(l) for l in lines]))
    except Exception as e:
        return _err(str(e))

def _read_gzip(args):
    path = _str(args[0])
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return _ok(SynStr(f.read()))
    except Exception as e:
        return _err(str(e))

def _write_gzip(args):
    path, content = _str(args[0]), _str(args[1])
    try:
        with gzip.open(path, "wt", encoding="utf-8") as f:
            f.write(content)
        return _nil()
    except Exception as e:
        return _err(str(e))


# ── File system operations ────────────────────────────────────────

def _file_exists(args):
    return SynBool(os.path.exists(_str(args[0])))

def _is_dir(args):
    return SynBool(os.path.isdir(_str(args[0])))

def _is_file(args):
    return SynBool(os.path.isfile(_str(args[0])))

def _list_dir(args):
    path = _str(args[0])
    try:
        entries = sorted(os.listdir(path))
        return _ok(SynArray([SynStr(e) for e in entries]))
    except Exception as e:
        return _err(str(e))

def _list_dir_recursive(args):
    path = _str(args[0])
    try:
        result = []
        for root, dirs, files in os.walk(path):
            for fname in files:
                result.append(SynStr(os.path.join(root, fname)))
        return _ok(SynArray(result))
    except Exception as e:
        return _err(str(e))

def _make_dir(args):
    path = _str(args[0])
    try:
        os.makedirs(path, exist_ok=True)
        return _nil()
    except Exception as e:
        return _err(str(e))

def _remove_file(args):
    path = _str(args[0])
    try:
        os.remove(path)
        return _nil()
    except Exception as e:
        return _err(str(e))

def _remove_dir(args):
    path = _str(args[0])
    try:
        shutil.rmtree(path)
        return _nil()
    except Exception as e:
        return _err(str(e))

def _copy_file(args):
    src, dst = _str(args[0]), _str(args[1])
    try:
        shutil.copy2(src, dst)
        return _nil()
    except Exception as e:
        return _err(str(e))

def _move_file(args):
    src, dst = _str(args[0]), _str(args[1])
    try:
        shutil.move(src, dst)
        return _nil()
    except Exception as e:
        return _err(str(e))

def _file_size(args):
    path = _str(args[0])
    try:
        return _ok(SynInt(os.path.getsize(path)))
    except Exception as e:
        return _err(str(e))

def _file_mtime(args):
    path = _str(args[0])
    try:
        import time
        return _ok(SynInt(int(os.path.getmtime(path))))
    except Exception as e:
        return _err(str(e))


# ── Path manipulation ─────────────────────────────────────────────

def _basename(args):
    return SynStr(os.path.basename(_str(args[0])))

def _dirname(args):
    return SynStr(os.path.dirname(_str(args[0])))

def _join_path(args):
    return SynStr(os.path.join(*[_str(a) for a in args]))

def _abs_path(args):
    return SynStr(os.path.abspath(_str(args[0])))

def _stem(args):
    return SynStr(pathlib.Path(_str(args[0])).stem)

def _extension(args):
    return SynStr(pathlib.Path(_str(args[0])).suffix)

def _parent(args):
    return SynStr(str(pathlib.Path(_str(args[0])).parent))

def _with_extension(args):
    p    = pathlib.Path(_str(args[0]))
    ext  = _str(args[1])
    return SynStr(str(p.with_suffix(ext if ext.startswith(".") else "." + ext)))

def _cwd(args):
    return SynStr(os.getcwd())

def _home(args):
    return SynStr(str(pathlib.Path.home()))


# ── Standard I/O ──────────────────────────────────────────────────

def _print_fn(args):
    parts = []
    for a in args:
        parts.append(a.value if hasattr(a, "value") and not isinstance(a, SynNil) else "nil")
    print(*[str(p) for p in parts])
    return SYN_NIL

def _println_fn(args):
    return _print_fn(args)

def _eprint_fn(args):
    parts = [a.value if hasattr(a, "value") else "nil" for a in args]
    print(*[str(p) for p in parts], file=sys.stderr)
    return SYN_NIL

def _input_fn(args):
    prompt = _str(args[0]) if args else ""
    try:
        return SynStr(input(prompt))
    except EOFError:
        return SynStr("")

def _stdin_lines(args):
    try:
        lines = sys.stdin.read().splitlines()
        return SynArray([SynStr(l) for l in lines])
    except Exception:
        return SynArray([])

def _env_var(args):
    name = _str(args[0])
    val  = os.environ.get(name)
    if val is None:
        return _err(f"env var ${name} not set")
    return _ok(SynStr(val))

def _env_var_or(args):
    name, default = _str(args[0]), _str(args[1])
    return SynStr(os.environ.get(name, default))

def _set_env(args):
    os.environ[_str(args[0])] = _str(args[1])
    return SYN_NIL

def _args(args):
    return SynArray([SynStr(a) for a in sys.argv[1:]])


# ── Temp files ────────────────────────────────────────────────────

def _temp_file(args):
    import tempfile
    suffix = _str(args[0]) if args else ""
    try:
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return _ok(SynStr(path))
    except Exception as e:
        return _err(str(e))

def _temp_dir(args):
    import tempfile
    try:
        path = tempfile.mkdtemp()
        return _ok(SynStr(path))
    except Exception as e:
        return _err(str(e))


# ── Module exports ────────────────────────────────────────────────

EXPORTS: dict[str, VarekValue] = {
    # Read
    "read_file":          _bi("read_file",          _read_file),
    "read_bytes":         _bi("read_bytes",         _read_bytes),
    "read_lines":         _bi("read_lines",         _read_lines),
    "read_gzip":          _bi("read_gzip",          _read_gzip),
    # Write
    "write_file":         _bi("write_file",         _write_file),
    "write_bytes":        _bi("write_bytes",        _write_bytes),
    "write_gzip":         _bi("write_gzip",         _write_gzip),
    "append_file":        _bi("append_file",        _append_file),
    # FS ops
    "file_exists":        _bi("file_exists",        _file_exists),
    "is_dir":             _bi("is_dir",             _is_dir),
    "is_file":            _bi("is_file",            _is_file),
    "list_dir":           _bi("list_dir",           _list_dir),
    "list_dir_recursive": _bi("list_dir_recursive", _list_dir_recursive),
    "make_dir":           _bi("make_dir",           _make_dir),
    "remove_file":        _bi("remove_file",        _remove_file),
    "remove_dir":         _bi("remove_dir",         _remove_dir),
    "copy_file":          _bi("copy_file",          _copy_file),
    "move_file":          _bi("move_file",          _move_file),
    "file_size":          _bi("file_size",          _file_size),
    "file_mtime":         _bi("file_mtime",         _file_mtime),
    # Paths
    "basename":           _bi("basename",           _basename),
    "dirname":            _bi("dirname",            _dirname),
    "join_path":          _bi("join_path",          _join_path),
    "abs_path":           _bi("abs_path",           _abs_path),
    "stem":               _bi("stem",               _stem),
    "extension":          _bi("extension",          _extension),
    "parent":             _bi("parent",             _parent),
    "with_extension":     _bi("with_extension",     _with_extension),
    "cwd":                _bi("cwd",                _cwd),
    "home":               _bi("home",               _home),
    # Stdio
    "print":              _bi("print",              _print_fn),
    "println":            _bi("println",            _println_fn),
    "eprint":             _bi("eprint",             _eprint_fn),
    "input":              _bi("input",              _input_fn),
    "stdin_lines":        _bi("stdin_lines",        _stdin_lines),
    # Env
    "env_var":            _bi("env_var",            _env_var),
    "env_var_or":         _bi("env_var_or",         _env_var_or),
    "set_env":            _bi("set_env",            _set_env),
    "args":               _bi("args",               _args),
    # Temp
    "temp_file":          _bi("temp_file",          _temp_file),
    "temp_dir":           _bi("temp_dir",           _temp_dir),
}
