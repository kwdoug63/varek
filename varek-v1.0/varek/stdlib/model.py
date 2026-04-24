"""
varek/stdlib/model.py
────────────────────────
var::model — Model loading, inference, and format support.
var::data  — Dataset loading, streaming, batching, augmentation.

Both modules live here since they share heavy numpy dependencies
and are always used together in ML pipelines.

var::model:
  load(path: str) -> Result<Model>
  load_onnx(path: str) -> Result<Model>
  save(model: Model, path: str) -> Result<nil>
  infer(model: Model, input: Tensor) -> Result<Tensor>
  batch_infer(model: Model, inputs: Tensor[]) -> Result<Tensor[]>
  model_info(model: Model) -> ModelInfo
  list_formats() -> str[]
  from_weights(weights: Tensor[], biases: Tensor[]) -> Model
  linear(model: Model, input: Tensor) -> Tensor      (fully-connected layer)
  embedding(vocab_size: int, dim: int) -> Model
  lookup(embed_model: Model, indices: int[]) -> Tensor
  tokenize(text: str, vocab: {str: int}) -> int[]
  bpe_encode(text: str) -> int[]

var::data:
  load_csv(path: str) -> Result<{str: float[]}[]>
  load_json(path: str) -> Result<str>
  load_jsonl(path: str) -> Result<str[]>
  save_csv(data, path: str) -> Result<nil>
  save_json(data: str, path: str) -> Result<nil>
  shuffle(items: T[]) -> T[]
  split_train_test(data: T[], ratio: float) -> (T[], T[])
  batch(items: T[], size: int) -> T[][]
  flatten_batches(batches: T[][]) -> T[]
  normalize_dataset(data: float[][]) -> float[][]
  one_hot(labels: int[], n_classes: int) -> Tensor
  train_test_split(X: Tensor, y: Tensor, ratio: float) -> (Tensor, Tensor, Tensor, Tensor)
  augment_flip(images: Tensor) -> Tensor
  augment_noise(images: Tensor, std: float) -> Tensor
  kfold(data: T[], k: int) -> (T[], T[])[]
  vocab_from_corpus(texts: str[], max_size: int) -> {str: int}
  encode_texts(texts: str[], vocab: {str: int}, max_len: int) -> Tensor
  sliding_window(seq: T[], width: int, stride: int) -> T[][]
"""

from __future__ import annotations

import csv
import io
import json
import math
import os
import pickle
import random
import struct
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from varek.runtime import (
    VarekValue, SynStr, SynInt, SynFloat, SynBool, SynNil,
    SynArray, SynMap, SynOk, SynErr, SynSchema, SynTensor, SynBuiltin,
    SYN_NIL, SYN_TRUE, SYN_FALSE,
)
from varek.stdlib.tensor import _from_np, _to_np


# ══════════════════════════════════════════════════════════════════
# var::model
# ══════════════════════════════════════════════════════════════════

class _SynModel(VarekValue):
    """A VAREK runtime model — wraps weights and an inference function."""

    def __init__(self, name: str, weights: List[np.ndarray],
                 biases: List[np.ndarray], meta: dict):
        self.name    = name
        self.weights = weights   # list of numpy arrays
        self.biases  = biases
        self.meta    = meta      # arbitrary metadata

    def __repr__(self):
        layers = len(self.weights)
        return f"<Model '{self.name}' layers={layers}>"


# ── Model creation ────────────────────────────────────────────────

def _from_weights(args):
    """
    from_weights(weights: Tensor[], biases: Tensor[]) -> Model

    Build a simple feedforward model from weight matrices and bias vectors.
    """
    w_arr = args[0] if isinstance(args[0], SynArray) else SynArray([])
    b_arr = args[1] if isinstance(args[1], SynArray) else SynArray([])

    weights = [_to_np(w) for w in w_arr.elements]
    biases  = [_to_np(b) for b in b_arr.elements]

    return _SynModel(
        name="custom",
        weights=weights,
        biases=biases,
        meta={"layers": len(weights), "format": "dense"},
    )

def _linear_model(args):
    """
    linear(in_dim: int, out_dim: int) -> Model

    Create a random linear layer (for testing/demonstration).
    """
    in_d  = int(args[0].value)
    out_d = int(args[1].value)
    scale = math.sqrt(2.0 / in_d)   # He initialization
    W = np.random.randn(in_d, out_d) * scale
    b = np.zeros(out_d)
    return _SynModel("linear", [W], [b], {"in": in_d, "out": out_d})

def _embedding(args):
    """
    embedding(vocab_size: int, dim: int) -> Model

    Create an embedding lookup table.
    """
    vocab  = int(args[0].value)
    dim    = int(args[1].value)
    table  = np.random.randn(vocab, dim) * 0.01
    return _SynModel("embedding", [table], [], {"vocab": vocab, "dim": dim})

def _lookup(args):
    """
    lookup(embed_model: Model, indices: int[]) -> Tensor
    """
    model   = args[0]
    indices = args[1]
    if not isinstance(model, _SynModel) or not model.weights:
        return SynErr("lookup() requires an embedding model")
    table   = model.weights[0]
    idx_list= [int(e.value) for e in indices.elements] if isinstance(indices, SynArray) else [int(indices.value)]
    rows    = table[idx_list]
    return _from_np(rows)


# ── Inference ─────────────────────────────────────────────────────

def _infer(args):
    """
    infer(model: Model, input: Tensor) -> Result<Tensor>

    Run forward pass through a feedforward model:
    output = relu(W_n @ relu(... relu(W_0 @ input + b_0) ...)) + b_n
    """
    model = args[0]
    inp   = _to_np(args[1])

    if not isinstance(model, _SynModel):
        return SynErr("infer() requires a Model")

    try:
        current = inp.flatten()
        for i, (W, b) in enumerate(zip(model.weights, model.biases)):
            current = current @ W + b
            # ReLU on all but last layer
            if i < len(model.weights) - 1:
                current = np.maximum(0, current)
        return SynOk(_from_np(current))
    except Exception as e:
        return SynErr(f"infer() error: {e}")

def _batch_infer(args):
    """
    batch_infer(model: Model, inputs: Tensor[]) -> Result<Tensor[]>
    """
    model  = args[0]
    inputs = args[1]

    if not isinstance(model, _SynModel) or not isinstance(inputs, SynArray):
        return SynErr("batch_infer() requires Model and Tensor[]")

    results = []
    for inp_val in inputs.elements:
        r = _infer([model, inp_val])
        if isinstance(r, SynOk):
            results.append(r.value)
        else:
            results.append(r)
    return SynOk(SynArray(results))

def _model_forward(args):
    """Alias for infer — matches the .forward() method pattern."""
    return _infer(args)


# ── Model I/O ─────────────────────────────────────────────────────

def _save_model(args):
    model = args[0]; path = args[1].value
    if not isinstance(model, _SynModel):
        return SynErr("save() requires a Model")
    try:
        data = {
            "name":    model.name,
            "weights": [w.tolist() for w in model.weights],
            "biases":  [b.tolist() for b in model.biases],
            "meta":    model.meta,
        }
        with open(path, "w") as f:
            json.dump(data, f)
        return SynOk(SYN_NIL)
    except Exception as e:
        return SynErr(str(e))

def _load_model(args):
    path = args[0].value
    if not os.path.exists(path):
        return SynErr(f"Model file not found: {path}")
    try:
        # Try JSON format first
        with open(path, "r") as f:
            data = json.load(f)
        weights = [np.array(w) for w in data.get("weights", [])]
        biases  = [np.array(b) for b in data.get("biases",  [])]
        return SynOk(_SynModel(
            name=data.get("name", os.path.basename(path)),
            weights=weights, biases=biases,
            meta=data.get("meta", {}),
        ))
    except json.JSONDecodeError:
        pass
    try:
        # Try numpy format
        data = np.load(path, allow_pickle=True)
        if hasattr(data, "files"):
            weights = [data[k] for k in sorted(data.files)]
            return SynOk(_SynModel(os.path.basename(path), weights, [], {}))
    except Exception:
        pass
    return SynErr(f"Unsupported model format: {path}")

def _model_info(args):
    model = args[0]
    if not isinstance(model, _SynModel):
        return SynErr("model_info() requires a Model")
    return SynSchema("ModelInfo", {
        "name":    SynStr(model.name),
        "layers":  SynInt(len(model.weights)),
        "params":  SynInt(sum(w.size for w in model.weights) + sum(b.size for b in model.biases)),
        "format":  SynStr(model.meta.get("format", "dense")),
    })

def _list_formats(_args):
    return SynArray([SynStr(f) for f in ["varek-json", "numpy-npz", "dense"]])


# ── Tokenization ──────────────────────────────────────────────────

def _tokenize(args):
    """
    tokenize(text: str, vocab: {str: int}) -> int[]

    Simple whitespace tokenizer using a vocabulary dict.
    """
    text  = args[0].value
    vocab = args[1]

    unk_id = 1  # default UNK token
    result = []
    for word in text.lower().split():
        if isinstance(vocab, SynMap):
            token_id = vocab.entries.get(word)
            if isinstance(token_id, SynInt):
                result.append(SynInt(token_id.value))
            else:
                result.append(SynInt(unk_id))
    return SynArray(result)

def _char_tokenize(args):
    """Character-level tokenization."""
    text   = args[0].value
    result = [SynInt(ord(c)) for c in text]
    return SynArray(result)

def _bpe_encode(args):
    """
    bpe_encode(text: str) -> int[]

    Simplified BPE: character-level encoding mapping each char
    to its Unicode codepoint. Full BPE requires a trained vocabulary
    (available via var::data::vocab_from_corpus).
    """
    text = args[0].value
    return SynArray([SynInt(ord(c)) for c in text])


# ══════════════════════════════════════════════════════════════════
# var::data
# ══════════════════════════════════════════════════════════════════

# ── Loading ───────────────────────────────────────────────────────

def _load_csv(args):
    path = args[0].value
    try:
        with open(path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows   = list(reader)

        if not rows:
            return SynOk(SynArray([]))

        # Build column-oriented dict
        result = []
        for row in rows:
            schema_fields = {
                k: (SynFloat(float(v)) if _is_numeric(v) else SynStr(v))
                for k, v in row.items()
            }
            result.append(SynSchema("Row", schema_fields))
        return SynOk(SynArray(result))
    except Exception as e:
        return SynErr(str(e))

def _is_numeric(s: str) -> bool:
    try: float(s); return True
    except ValueError: return False

def _load_json(args):
    path = args[0].value
    try:
        with open(path, "r", encoding="utf-8") as f:
            return SynOk(SynStr(f.read()))
    except Exception as e:
        return SynErr(str(e))

def _load_jsonl(args):
    path = args[0].value
    try:
        lines = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    lines.append(SynStr(line))
        return SynOk(SynArray(lines))
    except Exception as e:
        return SynErr(str(e))

def _load_npy(args):
    path = args[0].value
    try:
        arr = np.load(path)
        return SynOk(_from_np(arr.astype(np.float64)))
    except Exception as e:
        return SynErr(str(e))

def _load_npz(args):
    path = args[0].value
    key  = args[1].value if len(args) > 1 and isinstance(args[1], SynStr) else None
    try:
        data = np.load(path, allow_pickle=False)
        if key:
            return SynOk(_from_np(data[key].astype(np.float64)))
        arrays = {k: _from_np(data[k].astype(np.float64)) for k in data.files}
        return SynOk(SynMap({k: v for k, v in arrays.items()}))
    except Exception as e:
        return SynErr(str(e))


# ── Saving ────────────────────────────────────────────────────────

def _save_csv(args):
    data = args[0]; path = args[1].value
    try:
        if isinstance(data, SynArray) and data.elements:
            first = data.elements[0]
            if isinstance(first, SynSchema):
                fieldnames = list(first.fields.keys())
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in data.elements:
                        if isinstance(row, SynSchema):
                            writer.writerow({
                                k: v.value for k, v in row.fields.items()
                                if hasattr(v, "value")
                            })
                return SynOk(SYN_NIL)
        return SynErr("save_csv() expects Schema[]")
    except Exception as e:
        return SynErr(str(e))

def _save_json(args):
    text = args[0].value if isinstance(args[0], SynStr) else str(args[0])
    path = args[1].value
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return SynOk(SYN_NIL)
    except Exception as e:
        return SynErr(str(e))

def _save_npy(args):
    arr  = _to_np(args[0]); path = args[1].value
    try:
        np.save(path, arr)
        return SynOk(SYN_NIL)
    except Exception as e:
        return SynErr(str(e))


# ── Splitting / batching ──────────────────────────────────────────

def _shuffle(args):
    items = list(args[0].elements) if isinstance(args[0], SynArray) else []
    seed  = int(args[1].value) if len(args) > 1 else None
    if seed is not None:
        random.seed(seed)
    random.shuffle(items)
    return SynArray(items)

def _split_train_test(args):
    items = args[0].elements if isinstance(args[0], SynArray) else []
    ratio = float(args[1].value) if len(args) > 1 else 0.8
    n     = len(items)
    split = int(n * ratio)
    return SynArray([SynArray(items[:split]), SynArray(items[split:])])

def _batch(args):
    items = args[0].elements if isinstance(args[0], SynArray) else []
    size  = int(args[1].value) if len(args) > 1 else 32
    batches = [SynArray(items[i:i+size]) for i in range(0, len(items), size)]
    return SynArray(batches)

def _flatten_batches(args):
    batches = args[0].elements if isinstance(args[0], SynArray) else []
    flat = []
    for b in batches:
        if isinstance(b, SynArray):
            flat.extend(b.elements)
        else:
            flat.append(b)
    return SynArray(flat)


# ── Tensor dataset operations ─────────────────────────────────────

def _normalize_dataset(args):
    """normalize_dataset(data: Tensor) -> Tensor — zero-mean unit-variance."""
    arr = _to_np(args[0])
    mu  = np.mean(arr, axis=0)
    sig = np.std(arr, axis=0) + 1e-10
    return _from_np((arr - mu) / sig)

def _one_hot(args):
    """one_hot(labels: int[], n_classes: int) -> Tensor"""
    labels   = [int(e.value) for e in args[0].elements] if isinstance(args[0], SynArray) else []
    n        = int(args[1].value)
    out      = np.zeros((len(labels), n), dtype=np.float64)
    for i, label in enumerate(labels):
        if 0 <= label < n:
            out[i, label] = 1.0
    return _from_np(out)

def _train_test_split(args):
    """train_test_split(X: Tensor, y: Tensor, ratio: float) -> (X_tr, X_te, y_tr, y_te)"""
    X     = _to_np(args[0]); y = _to_np(args[1])
    ratio = float(args[2].value) if len(args) > 2 else 0.8
    n     = len(X); split = int(n * ratio)

    idx = np.random.permutation(n)
    tr, te = idx[:split], idx[split:]

    return SynArray([
        _from_np(X[tr]), _from_np(X[te]),
        _from_np(y[tr]), _from_np(y[te]),
    ])

def _kfold(args):
    """kfold(data: Tensor, k: int) -> (Tensor, Tensor)[]"""
    data = _to_np(args[0]); k = int(args[1].value)
    n    = len(data)
    fold_size = n // k
    folds = []
    for i in range(k):
        test_idx  = list(range(i * fold_size, (i+1) * fold_size))
        train_idx = list(range(0, i*fold_size)) + list(range((i+1)*fold_size, n))
        folds.append(SynArray([
            _from_np(data[train_idx]),
            _from_np(data[test_idx]),
        ]))
    return SynArray(folds)


# ── Augmentation ──────────────────────────────────────────────────

def _augment_flip(args):
    """augment_flip(images: Tensor) -> Tensor — horizontal flip"""
    arr = _to_np(args[0])
    return _from_np(np.flip(arr, axis=-1).copy())

def _augment_noise(args):
    """augment_noise(images: Tensor, std: float) -> Tensor"""
    arr = _to_np(args[0])
    std = float(args[1].value) if len(args) > 1 else 0.01
    return _from_np(arr + np.random.randn(*arr.shape) * std)

def _augment_crop(args):
    """augment_crop(tensor: Tensor, crop_size: int) -> Tensor"""
    arr  = _to_np(args[0])
    size = int(args[1].value)
    if arr.ndim < 2: return _from_np(arr)
    h, w = arr.shape[-2], arr.shape[-1]
    top  = random.randint(0, max(0, h - size))
    left = random.randint(0, max(0, w - size))
    return _from_np(arr[..., top:top+size, left:left+size].copy())

def _augment_scale(args):
    """Scale pixel values to [0, 1]."""
    arr = _to_np(args[0])
    mn, mx = arr.min(), arr.max()
    if mx - mn < 1e-10: return _from_np(arr)
    return _from_np((arr - mn) / (mx - mn))


# ── Text processing ───────────────────────────────────────────────

def _vocab_from_corpus(args):
    """
    vocab_from_corpus(texts: str[], max_size: int) -> {str: int}
    """
    texts    = args[0].elements if isinstance(args[0], SynArray) else []
    max_size = int(args[1].value) if len(args) > 1 else 10000

    freq = {}
    for t in texts:
        if isinstance(t, SynStr):
            for word in t.value.lower().split():
                freq[word] = freq.get(word, 0) + 1

    sorted_words = sorted(freq.items(), key=lambda x: -x[1])
    vocab        = {"<PAD>": 0, "<UNK>": 1, "<BOS>": 2, "<EOS>": 3}
    for word, _ in sorted_words[:max_size - 4]:
        vocab[word] = len(vocab)

    return SynMap({k: SynInt(v) for k, v in vocab.items()})

def _encode_texts(args):
    """
    encode_texts(texts: str[], vocab: {str: int}, max_len: int) -> Tensor
    """
    texts   = args[0].elements if isinstance(args[0], SynArray) else []
    vocab   = args[1]
    max_len = int(args[2].value) if len(args) > 2 else 128

    unk_id  = 1
    pad_id  = 0

    rows = []
    for t in texts:
        if isinstance(t, SynStr):
            words = t.value.lower().split()
            ids   = []
            for w in words[:max_len]:
                if isinstance(vocab, SynMap):
                    tok = vocab.entries.get(w)
                    ids.append(tok.value if isinstance(tok, SynInt) else unk_id)
                else:
                    ids.append(unk_id)
            # Pad or truncate
            ids = ids[:max_len] + [pad_id] * max(0, max_len - len(ids))
            rows.append(ids)

    arr = np.array(rows, dtype=np.float64) if rows else np.zeros((0, max_len))
    return _from_np(arr)

def _sliding_window(args):
    """
    sliding_window(seq: T[], width: int, stride: int) -> T[][]
    """
    items  = args[0].elements if isinstance(args[0], SynArray) else []
    width  = int(args[1].value)
    stride = int(args[2].value) if len(args) > 2 else 1

    windows = []
    for i in range(0, len(items) - width + 1, stride):
        windows.append(SynArray(items[i:i+width]))
    return SynArray(windows)

def _ngrams(args):
    """ngrams(tokens: T[], n: int) -> T[][]"""
    tokens = args[0].elements if isinstance(args[0], SynArray) else []
    n      = int(args[1].value)
    grams  = []
    for i in range(len(tokens) - n + 1):
        grams.append(SynArray(tokens[i:i+n]))
    return SynArray(grams)


# ── Statistics / metrics ──────────────────────────────────────────

def _accuracy(args):
    """accuracy(predictions: int[], labels: int[]) -> float"""
    preds  = [int(e.value) for e in args[0].elements] if isinstance(args[0], SynArray) else []
    labels = [int(e.value) for e in args[1].elements] if isinstance(args[1], SynArray) else []
    if not labels: return SynFloat(0.0)
    correct = sum(p == l for p, l in zip(preds, labels))
    return SynFloat(correct / len(labels))

def _mse(args):
    """mse(predictions: Tensor, labels: Tensor) -> float"""
    pred = _to_np(args[0]); true = _to_np(args[1])
    return SynFloat(float(np.mean((pred - true) ** 2)))

def _mae(args):
    """mae(predictions: Tensor, labels: Tensor) -> float"""
    pred = _to_np(args[0]); true = _to_np(args[1])
    return SynFloat(float(np.mean(np.abs(pred - true))))

def _cross_entropy(args):
    """cross_entropy(logits: Tensor, labels: int[]) -> float"""
    logits = _to_np(args[0])
    labels = [int(e.value) for e in args[1].elements] if isinstance(args[1], SynArray) else []

    # Softmax
    e = np.exp(logits - logits.max(axis=-1, keepdims=True))
    probs = e / e.sum(axis=-1, keepdims=True)

    losses = []
    for i, label in enumerate(labels):
        if i < len(probs):
            p = max(probs[i][label], 1e-10)
            losses.append(-math.log(p))

    return SynFloat(float(np.mean(losses)) if losses else 0.0)

def _r2_score(args):
    """r2_score(predictions: Tensor, labels: Tensor) -> float"""
    pred = _to_np(args[0]); true = _to_np(args[1])
    ss_res = np.sum((true - pred) ** 2)
    ss_tot = np.sum((true - true.mean()) ** 2)
    r2 = 1 - ss_res / (ss_tot + 1e-10)
    return SynFloat(float(r2))


def _bi(name, fn): return SynBuiltin(name, fn)

# ── MODEL exports ──────────────────────────────────────────────────
MODEL_EXPORTS: dict[str, VarekValue] = {
    # Creation
    "from_weights":   _bi("from_weights",   _from_weights),
    "linear_model":   _bi("linear_model",   _linear_model),
    "embedding":      _bi("embedding",      _embedding),
    "lookup":         _bi("lookup",         _lookup),
    # Inference
    "infer":          _bi("infer",          _infer),
    "batch_infer":    _bi("batch_infer",    _batch_infer),
    "forward":        _bi("forward",        _model_forward),
    # I/O
    "save":           _bi("save",           _save_model),
    "load":           _bi("load",           _load_model),
    "model_info":     _bi("model_info",     _model_info),
    "list_formats":   _bi("list_formats",   _list_formats),
    # Tokenization
    "tokenize":       _bi("tokenize",       _tokenize),
    "char_tokenize":  _bi("char_tokenize",  _char_tokenize),
    "bpe_encode":     _bi("bpe_encode",     _bpe_encode),
}

# ── DATA exports ───────────────────────────────────────────────────
DATA_EXPORTS: dict[str, VarekValue] = {
    # Loading
    "load_csv":           _bi("load_csv",           _load_csv),
    "load_json":          _bi("load_json",           _load_json),
    "load_jsonl":         _bi("load_jsonl",          _load_jsonl),
    "load_npy":           _bi("load_npy",            _load_npy),
    "load_npz":           _bi("load_npz",            _load_npz),
    # Saving
    "save_csv":           _bi("save_csv",            _save_csv),
    "save_json":          _bi("save_json",           _save_json),
    "save_npy":           _bi("save_npy",            _save_npy),
    # Splits / batches
    "shuffle":            _bi("shuffle",             _shuffle),
    "split_train_test":   _bi("split_train_test",    _split_train_test),
    "batch":              _bi("batch",               _batch),
    "flatten_batches":    _bi("flatten_batches",     _flatten_batches),
    # Tensor ops
    "normalize_dataset":  _bi("normalize_dataset",   _normalize_dataset),
    "one_hot":            _bi("one_hot",             _one_hot),
    "train_test_split":   _bi("train_test_split",    _train_test_split),
    "kfold":              _bi("kfold",               _kfold),
    # Augmentation
    "augment_flip":       _bi("augment_flip",        _augment_flip),
    "augment_noise":      _bi("augment_noise",       _augment_noise),
    "augment_crop":       _bi("augment_crop",        _augment_crop),
    "augment_scale":      _bi("augment_scale",       _augment_scale),
    # Text
    "vocab_from_corpus":  _bi("vocab_from_corpus",   _vocab_from_corpus),
    "encode_texts":       _bi("encode_texts",        _encode_texts),
    "sliding_window":     _bi("sliding_window",      _sliding_window),
    "ngrams":             _bi("ngrams",              _ngrams),
    # Metrics
    "accuracy":           _bi("accuracy",            _accuracy),
    "mse":                _bi("mse",                 _mse),
    "mae":                _bi("mae",                 _mae),
    "cross_entropy":      _bi("cross_entropy",       _cross_entropy),
    "r2_score":           _bi("r2_score",            _r2_score),
}

# Combined exports (both accessible as top-level when needed)
EXPORTS = {**MODEL_EXPORTS, **DATA_EXPORTS}
