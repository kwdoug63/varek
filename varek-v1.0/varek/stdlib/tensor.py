"""
varek/stdlib/tensor.py
─────────────────────────
var::tensor — N-dimensional array operations powered by NumPy.

Tensors are the primary data structure for AI/ML workloads. This module
provides a rich set of operations: creation, arithmetic, linear algebra,
reductions, reshaping, slicing, and statistical operations.

VAREK runtime representation: SynTensor wraps a numpy ndarray.
All operations return new SynTensor values (immutable semantics).

Key operations:
  zeros(shape: int[]) -> Tensor
  ones(shape: int[]) -> Tensor
  arange(start: int, stop: int, step: int) -> Tensor
  linspace(start: float, stop: float, n: int) -> Tensor
  rand(shape: int[]) -> Tensor
  randn(shape: int[]) -> Tensor
  from_list(data: float[]) -> Tensor
  shape(t: Tensor) -> int[]
  rank(t: Tensor) -> int
  numel(t: Tensor) -> int
  reshape(t: Tensor, shape: int[]) -> Tensor
  flatten(t: Tensor) -> Tensor
  transpose(t: Tensor) -> Tensor
  add(a: Tensor, b: Tensor) -> Tensor
  sub(a: Tensor, b: Tensor) -> Tensor
  mul(a: Tensor, b: Tensor) -> Tensor
  div(a: Tensor, b: Tensor) -> Tensor
  matmul(a: Tensor, b: Tensor) -> Tensor
  dot(a: Tensor, b: Tensor) -> float
  sum(t: Tensor) -> float
  mean(t: Tensor) -> float
  std(t: Tensor) -> float
  min(t: Tensor) -> float
  max(t: Tensor) -> float
  argmin(t: Tensor) -> int
  argmax(t: Tensor) -> int
  softmax(t: Tensor) -> Tensor
  relu(t: Tensor) -> Tensor
  sigmoid(t: Tensor) -> Tensor
  normalize(t: Tensor) -> Tensor
  clip(t: Tensor, lo: float, hi: float) -> Tensor
  slice(t: Tensor, start: int, end: int) -> Tensor
  concat(a: Tensor, b: Tensor, axis: int) -> Tensor
  stack(tensors: Tensor[]) -> Tensor
  split(t: Tensor, n: int) -> Tensor[]
  top_k(t: Tensor, k: int) -> int[]
  to_list(t: Tensor) -> float[]
  save(t: Tensor, path: str) -> Result<nil>
  load(path: str) -> Result<Tensor>
"""

from __future__ import annotations

import math
from typing import List, Optional

import numpy as np

from varek.runtime import (
    VarekValue, SynStr, SynInt, SynFloat, SynBool, SynNil,
    SynArray, SynOk, SynErr, SynTensor, SynBuiltin,
    SYN_NIL, SYN_TRUE, SYN_FALSE,
)


# ── Tensor ↔ numpy bridging ───────────────────────────────────────

def _to_np(v: VarekValue) -> np.ndarray:
    """Convert a VAREK value to a numpy array."""
    if isinstance(v, SynTensor):
        if isinstance(v.data, np.ndarray):
            return v.data
        return np.array(v.data, dtype=np.float64)
    if isinstance(v, SynArray):
        vals = []
        for e in v.elements:
            if isinstance(e, (SynInt, SynFloat)): vals.append(e.value)
            else: vals.append(float(e.value) if hasattr(e,"value") else 0.0)
        return np.array(vals, dtype=np.float64)
    if isinstance(v, (SynInt, SynFloat)):
        return np.array(v.value, dtype=np.float64)
    raise TypeError(f"Cannot convert {type(v).__name__} to tensor")

def _from_np(arr: np.ndarray) -> SynTensor:
    """Wrap a numpy array as a VAREK SynTensor."""
    shape = tuple(arr.shape)
    t = SynTensor(data=arr, shape=shape, dtype=str(arr.dtype))
    return t

def _shape_args(args, idx=1) -> tuple:
    """Extract shape from a SynArray argument."""
    shape_arg = args[idx]
    if isinstance(shape_arg, SynArray):
        return tuple(e.value for e in shape_arg.elements)
    if isinstance(shape_arg, SynInt):
        return (shape_arg.value,)
    return (int(shape_arg.value),)


# ── Creation ──────────────────────────────────────────────────────

def _zeros(args):
    shape = _shape_args(args, 0)
    return _from_np(np.zeros(shape, dtype=np.float64))

def _ones(args):
    shape = _shape_args(args, 0)
    return _from_np(np.ones(shape, dtype=np.float64))

def _full(args):
    shape = _shape_args(args, 0)
    val   = args[1].value if hasattr(args[1], "value") else 0.0
    return _from_np(np.full(shape, val, dtype=np.float64))

def _eye(args):
    n = args[0].value
    return _from_np(np.eye(n, dtype=np.float64))

def _arange(args):
    start = args[0].value; stop = args[1].value
    step  = args[2].value if len(args) > 2 else 1
    return _from_np(np.arange(start, stop, step, dtype=np.float64))

def _linspace(args):
    start = float(args[0].value); stop = float(args[1].value)
    n     = int(args[2].value)
    return _from_np(np.linspace(start, stop, n, dtype=np.float64))

def _rand(args):
    shape = _shape_args(args, 0)
    return _from_np(np.random.rand(*shape).astype(np.float64))

def _randn(args):
    shape = _shape_args(args, 0)
    return _from_np(np.random.randn(*shape).astype(np.float64))

def _rand_int(args):
    lo, hi = int(args[0].value), int(args[1].value)
    shape  = _shape_args(args, 2)
    return _from_np(np.random.randint(lo, hi, size=shape).astype(np.float64))

def _from_list(args):
    flat = []
    def _collect(v):
        if isinstance(v, SynArray):
            for e in v.elements: _collect(e)
        elif isinstance(v, (SynInt, SynFloat)):
            flat.append(float(v.value))
        elif isinstance(v, SynTensor):
            flat.extend(v.data.flatten().tolist())
    _collect(args[0])
    return _from_np(np.array(flat, dtype=np.float64))

def _seed(args):
    np.random.seed(int(args[0].value))
    return SYN_NIL


# ── Shape / metadata ──────────────────────────────────────────────

def _shape(args):
    arr = _to_np(args[0])
    return SynArray([SynInt(d) for d in arr.shape])

def _rank(args):
    arr = _to_np(args[0])
    return SynInt(arr.ndim)

def _numel(args):
    arr = _to_np(args[0])
    return SynInt(arr.size)

def _dtype(args):
    if isinstance(args[0], SynTensor):
        return SynStr(str(args[0].dtype))
    return SynStr("float64")


# ── Reshape / reorder ─────────────────────────────────────────────

def _reshape(args):
    arr   = _to_np(args[0])
    shape = _shape_args(args, 1)
    return _from_np(arr.reshape(shape))

def _flatten(args):
    arr = _to_np(args[0])
    return _from_np(arr.flatten())

def _transpose(args):
    arr = _to_np(args[0])
    return _from_np(arr.T)

def _permute(args):
    arr   = _to_np(args[0])
    axes  = tuple(e.value for e in args[1].elements)
    return _from_np(np.transpose(arr, axes))

def _squeeze(args):
    arr = _to_np(args[0])
    return _from_np(arr.squeeze())

def _unsqueeze(args):
    arr  = _to_np(args[0])
    axis = int(args[1].value)
    return _from_np(np.expand_dims(arr, axis))

def _broadcast_to(args):
    arr   = _to_np(args[0])
    shape = _shape_args(args, 1)
    return _from_np(np.broadcast_to(arr, shape).copy())


# ── Element-wise arithmetic ───────────────────────────────────────

def _add(args):     return _from_np(_to_np(args[0]) + _to_np(args[1]))
def _sub(args):     return _from_np(_to_np(args[0]) - _to_np(args[1]))
def _mul(args):     return _from_np(_to_np(args[0]) * _to_np(args[1]))
def _div(args):     return _from_np(_to_np(args[0]) / _to_np(args[1]))
def _pow(args):     return _from_np(_to_np(args[0]) ** _to_np(args[1]))
def _neg(args):     return _from_np(-_to_np(args[0]))
def _abs_fn(args):  return _from_np(np.abs(_to_np(args[0])))
def _sqrt(args):    return _from_np(np.sqrt(_to_np(args[0])))
def _exp(args):     return _from_np(np.exp(_to_np(args[0])))
def _log(args):     return _from_np(np.log(_to_np(args[0])))
def _log2(args):    return _from_np(np.log2(_to_np(args[0])))
def _log10(args):   return _from_np(np.log10(_to_np(args[0])))
def _sin(args):     return _from_np(np.sin(_to_np(args[0])))
def _cos(args):     return _from_np(np.cos(_to_np(args[0])))
def _tanh(args):    return _from_np(np.tanh(_to_np(args[0])))
def _floor(args):   return _from_np(np.floor(_to_np(args[0])))
def _ceil(args):    return _from_np(np.ceil(_to_np(args[0])))
def _round(args):   return _from_np(np.round(_to_np(args[0])))
def _clip(args):
    lo = float(args[1].value); hi = float(args[2].value)
    return _from_np(np.clip(_to_np(args[0]), lo, hi))

# Scalar arithmetic
def _scale(args):
    arr = _to_np(args[0]); s = float(args[1].value)
    return _from_np(arr * s)

def _add_scalar(args):
    arr = _to_np(args[0]); s = float(args[1].value)
    return _from_np(arr + s)


# ── Linear algebra ────────────────────────────────────────────────

def _matmul(args):
    a = _to_np(args[0]); b = _to_np(args[1])
    return _from_np(a @ b)

def _dot(args):
    a = _to_np(args[0]); b = _to_np(args[1])
    return SynFloat(float(np.dot(a.flatten(), b.flatten())))

def _outer(args):
    a = _to_np(args[0]).flatten(); b = _to_np(args[1]).flatten()
    return _from_np(np.outer(a, b))

def _norm(args):
    arr  = _to_np(args[0])
    ord_ = int(args[1].value) if len(args) > 1 else 2
    return SynFloat(float(np.linalg.norm(arr, ord_)))

def _inv(args):
    arr = _to_np(args[0])
    try:
        return SynOk(_from_np(np.linalg.inv(arr)))
    except np.linalg.LinAlgError as e:
        return SynErr(str(e))

def _det(args):
    arr = _to_np(args[0])
    return SynFloat(float(np.linalg.det(arr)))

def _svd(args):
    arr = _to_np(args[0])
    U, s, Vt = np.linalg.svd(arr, full_matrices=False)
    return SynArray([_from_np(U), _from_np(s), _from_np(Vt)])

def _eig(args):
    arr = _to_np(args[0])
    vals, vecs = np.linalg.eig(arr)
    return SynArray([_from_np(vals.real), _from_np(vecs.real)])

def _solve(args):
    A = _to_np(args[0]); b = _to_np(args[1])
    try:
        return SynOk(_from_np(np.linalg.solve(A, b)))
    except np.linalg.LinAlgError as e:
        return SynErr(str(e))


# ── Reductions ────────────────────────────────────────────────────

def _sum(args):
    arr  = _to_np(args[0])
    if len(args) > 1:
        axis = int(args[1].value)
        return _from_np(np.sum(arr, axis=axis))
    return SynFloat(float(np.sum(arr)))

def _mean(args):
    arr = _to_np(args[0])
    if len(args) > 1:
        return _from_np(np.mean(arr, axis=int(args[1].value)))
    return SynFloat(float(np.mean(arr)))

def _std(args):
    arr = _to_np(args[0])
    return SynFloat(float(np.std(arr)))

def _var(args):
    arr = _to_np(args[0])
    return SynFloat(float(np.var(arr)))

def _min(args):
    arr = _to_np(args[0])
    if len(args) > 1:
        return _from_np(np.min(arr, axis=int(args[1].value)))
    return SynFloat(float(np.min(arr)))

def _max(args):
    arr = _to_np(args[0])
    if len(args) > 1:
        return _from_np(np.max(arr, axis=int(args[1].value)))
    return SynFloat(float(np.max(arr)))

def _argmin(args):
    arr = _to_np(args[0])
    return SynInt(int(np.argmin(arr)))

def _argmax(args):
    arr = _to_np(args[0])
    return SynInt(int(np.argmax(arr)))

def _prod(args):
    return SynFloat(float(np.prod(_to_np(args[0]))))

def _cumsum(args):
    return _from_np(np.cumsum(_to_np(args[0])))

def _diff(args):
    return _from_np(np.diff(_to_np(args[0])))

def _any(args):
    return SynBool(bool(np.any(_to_np(args[0]))))

def _all(args):
    return SynBool(bool(np.all(_to_np(args[0]))))


# ── Neural network activations ────────────────────────────────────

def _relu(args):
    arr = _to_np(args[0])
    return _from_np(np.maximum(0, arr))

def _sigmoid(args):
    arr = _to_np(args[0])
    return _from_np(1.0 / (1.0 + np.exp(-np.clip(arr, -500, 500))))

def _softmax(args):
    arr  = _to_np(args[0])
    axis = int(args[1].value) if len(args) > 1 else -1
    e    = np.exp(arr - np.max(arr, axis=axis, keepdims=True))
    return _from_np(e / np.sum(e, axis=axis, keepdims=True))

def _log_softmax(args):
    arr  = _to_np(args[0])
    axis = int(args[1].value) if len(args) > 1 else -1
    e    = np.exp(arr - np.max(arr, axis=axis, keepdims=True))
    sm   = e / np.sum(e, axis=axis, keepdims=True)
    return _from_np(np.log(sm + 1e-10))

def _gelu(args):
    arr = _to_np(args[0])
    return _from_np(0.5 * arr * (1 + np.tanh(math.sqrt(2/math.pi) * (arr + 0.044715 * arr**3))))

def _leaky_relu(args):
    arr   = _to_np(args[0])
    alpha = float(args[1].value) if len(args) > 1 else 0.01
    return _from_np(np.where(arr > 0, arr, alpha * arr))

def _dropout(args):
    arr  = _to_np(args[0])
    rate = float(args[1].value) if len(args) > 1 else 0.5
    if rate <= 0: return _from_np(arr)
    mask = np.random.binomial(1, 1-rate, arr.shape) / (1-rate)
    return _from_np(arr * mask)


# ── Normalization ─────────────────────────────────────────────────

def _normalize(args):
    arr  = _to_np(args[0])
    norm = np.linalg.norm(arr)
    if norm < 1e-10:
        return _from_np(arr)
    return _from_np(arr / norm)

def _normalize_rows(args):
    arr   = _to_np(args[0])
    norms = np.linalg.norm(arr, axis=1, keepdims=True)
    return _from_np(arr / np.maximum(norms, 1e-10))

def _standardize(args):
    arr = _to_np(args[0])
    mu  = np.mean(arr, axis=0)
    sig = np.std(arr, axis=0) + 1e-10
    return _from_np((arr - mu) / sig)

def _layer_norm(args):
    arr = _to_np(args[0])
    mu  = np.mean(arr, axis=-1, keepdims=True)
    sig = np.std(arr, axis=-1, keepdims=True) + 1e-5
    return _from_np((arr - mu) / sig)

def _batch_norm(args):
    arr = _to_np(args[0])
    mu  = np.mean(arr, axis=0)
    sig = np.std(arr, axis=0) + 1e-5
    return _from_np((arr - mu) / sig)


# ── Slice / index ─────────────────────────────────────────────────

def _slice_fn(args):
    arr   = _to_np(args[0])
    start = int(args[1].value); stop = int(args[2].value)
    return _from_np(arr[start:stop])

def _index(args):
    arr = _to_np(args[0]); idx = int(args[1].value)
    val = arr[idx]
    if val.shape == ():
        return SynFloat(float(val))
    return _from_np(val)

def _gather(args):
    arr     = _to_np(args[0])
    indices = [int(e.value) for e in args[1].elements]
    return _from_np(arr[indices])


# ── Combine / split ───────────────────────────────────────────────

def _concat(args):
    a    = _to_np(args[0]); b = _to_np(args[1])
    axis = int(args[2].value) if len(args) > 2 else 0
    return _from_np(np.concatenate([a, b], axis=axis))

def _stack(args):
    tensors = [_to_np(t) for t in args[0].elements]
    axis    = int(args[1].value) if len(args) > 1 else 0
    return _from_np(np.stack(tensors, axis=axis))

def _vstack(args):
    tensors = [_to_np(t) for t in args[0].elements]
    return _from_np(np.vstack(tensors))

def _hstack(args):
    tensors = [_to_np(t) for t in args[0].elements]
    return _from_np(np.hstack(tensors))

def _split(args):
    arr = _to_np(args[0]); n = int(args[1].value)
    parts = np.array_split(arr, n)
    return SynArray([_from_np(p) for p in parts])

def _chunk(args):
    arr  = _to_np(args[0]); size = int(args[1].value)
    n    = math.ceil(len(arr) / size)
    return _split([args[0], SynInt(n)])


# ── Statistics ────────────────────────────────────────────────────

def _median(args):
    return SynFloat(float(np.median(_to_np(args[0]))))

def _percentile(args):
    arr = _to_np(args[0]); p = float(args[1].value)
    return SynFloat(float(np.percentile(arr, p)))

def _histogram(args):
    arr  = _to_np(args[0])
    bins = int(args[1].value) if len(args) > 1 else 10
    counts, edges = np.histogram(arr, bins=bins)
    return SynArray([
        _from_np(counts.astype(np.float64)),
        _from_np(edges),
    ])

def _cov(args):
    arr = _to_np(args[0])
    return _from_np(np.cov(arr, rowvar=False))

def _corr(args):
    arr = _to_np(args[0])
    return _from_np(np.corrcoef(arr, rowvar=False))


# ── Top-k / sorting ──────────────────────────────────────────────

def _top_k(args):
    arr = _to_np(args[0]).flatten()
    k   = int(args[1].value)
    k   = min(k, len(arr))
    idx = np.argsort(arr)[::-1][:k]
    return SynArray([SynInt(int(i)) for i in idx])

def _sort(args):
    arr = _to_np(args[0])
    return _from_np(np.sort(arr))

def _argsort(args):
    arr = _to_np(args[0])
    return SynArray([SynInt(int(i)) for i in np.argsort(arr)])


# ── Comparison ────────────────────────────────────────────────────

def _where(args):
    cond = _to_np(args[0]) > 0
    x    = _to_np(args[1]); y = _to_np(args[2])
    return _from_np(np.where(cond, x, y))

def _equal(args):
    a = _to_np(args[0]); b = _to_np(args[1])
    return SynBool(bool(np.allclose(a, b)))


# ── Conversion ────────────────────────────────────────────────────

def _to_list(args):
    arr = _to_np(args[0])
    return SynArray([SynFloat(float(v)) for v in arr.flatten()])

def _to_int_list(args):
    arr = _to_np(args[0])
    return SynArray([SynInt(int(v)) for v in arr.flatten()])

def _as_float(args):
    return _from_np(_to_np(args[0]).astype(np.float64))

def _as_int(args):
    return _from_np(_to_np(args[0]).astype(np.int64))

def _item(args):
    arr = _to_np(args[0])
    return SynFloat(float(arr.flat[0]))


# ── Distance metrics ──────────────────────────────────────────────

def _cosine_sim(args):
    a = _to_np(args[0]).flatten(); b = _to_np(args[1]).flatten()
    na = np.linalg.norm(a); nb = np.linalg.norm(b)
    if na < 1e-10 or nb < 1e-10: return SynFloat(0.0)
    return SynFloat(float(np.dot(a, b) / (na * nb)))

def _l2_dist(args):
    a = _to_np(args[0]).flatten(); b = _to_np(args[1]).flatten()
    return SynFloat(float(np.linalg.norm(a - b)))

def _l1_dist(args):
    a = _to_np(args[0]).flatten(); b = _to_np(args[1]).flatten()
    return SynFloat(float(np.sum(np.abs(a - b))))


# ── Padding / pooling ─────────────────────────────────────────────

def _pad(args):
    arr = _to_np(args[0]); pad = int(args[1].value)
    return _from_np(np.pad(arr, pad))

def _avg_pool1d(args):
    arr      = _to_np(args[0]).flatten()
    kernel   = int(args[1].value)
    stride   = int(args[2].value) if len(args) > 2 else kernel
    out_size = (len(arr) - kernel) // stride + 1
    result   = np.array([arr[i*stride:i*stride+kernel].mean() for i in range(out_size)])
    return _from_np(result)

def _max_pool1d(args):
    arr    = _to_np(args[0]).flatten()
    kernel = int(args[1].value)
    stride = int(args[2].value) if len(args) > 2 else kernel
    n      = (len(arr) - kernel) // stride + 1
    result = np.array([arr[i*stride:i*stride+kernel].max() for i in range(n)])
    return _from_np(result)


# ── Save / load ───────────────────────────────────────────────────

def _save(args):
    t    = args[0]; path = args[1].value if hasattr(args[1],"value") else str(args[1])
    try:
        arr = _to_np(t)
        np.save(path, arr)
        return SynOk(SYN_NIL)
    except Exception as e:
        return SynErr(str(e))

def _load(args):
    path = args[0].value if hasattr(args[0],"value") else str(args[0])
    try:
        arr = np.load(path, allow_pickle=False)
        return SynOk(_from_np(arr.astype(np.float64)))
    except Exception as e:
        return SynErr(str(e))

def _save_txt(args):
    t = args[0]; path = args[1].value
    try:
        np.savetxt(path, _to_np(t))
        return SynOk(SYN_NIL)
    except Exception as e:
        return SynErr(str(e))

def _load_txt(args):
    path = args[0].value
    try:
        return SynOk(_from_np(np.loadtxt(path, dtype=np.float64)))
    except Exception as e:
        return SynErr(str(e))


def _bi(name, fn): return SynBuiltin(name, fn)

EXPORTS: dict[str, VarekValue] = {
    # Creation
    "zeros": _bi("zeros", _zeros), "ones": _bi("ones", _ones),
    "full": _bi("full", _full), "eye": _bi("eye", _eye),
    "arange": _bi("arange", _arange), "linspace": _bi("linspace", _linspace),
    "rand": _bi("rand", _rand), "randn": _bi("randn", _randn),
    "rand_int": _bi("rand_int", _rand_int),
    "from_list": _bi("from_list", _from_list), "seed": _bi("seed", _seed),
    # Shape
    "shape": _bi("shape", _shape), "rank": _bi("rank", _rank),
    "numel": _bi("numel", _numel), "dtype": _bi("dtype", _dtype),
    # Reshape
    "reshape": _bi("reshape", _reshape), "flatten": _bi("flatten", _flatten),
    "transpose": _bi("transpose", _transpose), "permute": _bi("permute", _permute),
    "squeeze": _bi("squeeze", _squeeze), "unsqueeze": _bi("unsqueeze", _unsqueeze),
    "broadcast_to": _bi("broadcast_to", _broadcast_to),
    # Arithmetic
    "add": _bi("add", _add), "sub": _bi("sub", _sub),
    "mul": _bi("mul", _mul), "div": _bi("div", _div),
    "pow": _bi("pow", _pow), "neg": _bi("neg", _neg),
    "abs": _bi("abs", _abs_fn), "sqrt": _bi("sqrt", _sqrt),
    "exp": _bi("exp", _exp), "log": _bi("log", _log),
    "log2": _bi("log2", _log2), "log10": _bi("log10", _log10),
    "sin": _bi("sin", _sin), "cos": _bi("cos", _cos),
    "tanh": _bi("tanh", _tanh), "floor": _bi("floor", _floor),
    "ceil": _bi("ceil", _ceil), "round": _bi("round", _round),
    "clip": _bi("clip", _clip), "scale": _bi("scale", _scale),
    "add_scalar": _bi("add_scalar", _add_scalar),
    # Linear algebra
    "matmul": _bi("matmul", _matmul), "dot": _bi("dot", _dot),
    "outer": _bi("outer", _outer), "norm": _bi("norm", _norm),
    "inv": _bi("inv", _inv), "det": _bi("det", _det),
    "svd": _bi("svd", _svd), "eig": _bi("eig", _eig),
    "solve": _bi("solve", _solve),
    # Reductions
    "sum": _bi("sum", _sum), "mean": _bi("mean", _mean),
    "std": _bi("std", _std), "var": _bi("var", _var),
    "min": _bi("min", _min), "max": _bi("max", _max),
    "argmin": _bi("argmin", _argmin), "argmax": _bi("argmax", _argmax),
    "prod": _bi("prod", _prod), "cumsum": _bi("cumsum", _cumsum),
    "diff": _bi("diff", _diff),
    "any": _bi("any", _any), "all": _bi("all", _all),
    # Activations
    "relu": _bi("relu", _relu), "sigmoid": _bi("sigmoid", _sigmoid),
    "softmax": _bi("softmax", _softmax), "log_softmax": _bi("log_softmax", _log_softmax),
    "gelu": _bi("gelu", _gelu), "leaky_relu": _bi("leaky_relu", _leaky_relu),
    "dropout": _bi("dropout", _dropout),
    # Normalization
    "normalize": _bi("normalize", _normalize),
    "normalize_rows": _bi("normalize_rows", _normalize_rows),
    "standardize": _bi("standardize", _standardize),
    "layer_norm": _bi("layer_norm", _layer_norm),
    "batch_norm": _bi("batch_norm", _batch_norm),
    # Slice/index
    "slice": _bi("slice", _slice_fn), "index": _bi("index", _index),
    "gather": _bi("gather", _gather),
    # Combine
    "concat": _bi("concat", _concat), "stack": _bi("stack", _stack),
    "vstack": _bi("vstack", _vstack), "hstack": _bi("hstack", _hstack),
    "split": _bi("split", _split), "chunk": _bi("chunk", _chunk),
    # Statistics
    "median": _bi("median", _median), "percentile": _bi("percentile", _percentile),
    "histogram": _bi("histogram", _histogram),
    "cov": _bi("cov", _cov), "corr": _bi("corr", _corr),
    # Sort/topk
    "top_k": _bi("top_k", _top_k), "sort": _bi("sort", _sort),
    "argsort": _bi("argsort", _argsort),
    # Compare
    "where": _bi("where", _where), "equal": _bi("equal", _equal),
    # Convert
    "to_list": _bi("to_list", _to_list), "to_int_list": _bi("to_int_list", _to_int_list),
    "as_float": _bi("as_float", _as_float), "as_int": _bi("as_int", _as_int),
    "item": _bi("item", _item),
    # Distance
    "cosine_sim": _bi("cosine_sim", _cosine_sim),
    "l2_dist": _bi("l2_dist", _l2_dist),
    "l1_dist": _bi("l1_dist", _l1_dist),
    # Pooling
    "pad": _bi("pad", _pad),
    "avg_pool1d": _bi("avg_pool1d", _avg_pool1d),
    "max_pool1d": _bi("max_pool1d", _max_pool1d),
    # Save/load
    "save": _bi("save", _save), "load": _bi("load", _load),
    "save_txt": _bi("save_txt", _save_txt), "load_txt": _bi("load_txt", _load_txt),
}
