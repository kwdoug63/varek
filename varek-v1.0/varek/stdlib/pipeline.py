"""
varek/stdlib/pipeline.py
───────────────────────────
var::pipeline — Pipeline execution engine.

This module implements the runtime execution of VAREK pipeline
declarations. When a pipeline block is compiled and called, it
flows through this engine, which provides:

  - Sequential step execution with type-checked handoff
  - Batched processing (configurable batch_size)
  - Parallel execution across worker threads
  - Progress tracking and timing
  - Error collection and partial results
  - Backpressure via bounded channels
  - Caching of intermediate results

Operations:
  run(pipeline_fn, source: T[], config) -> R[]
  run_batch(pipeline_fn, source: T[], batch_size: int) -> R[]
  run_parallel(steps: fn[], source: T[], workers: int) -> R[]
  map_pipeline(steps: fn[], item: T) -> R
  benchmark(pipeline_fn, source: T[], runs: int) -> PipelineStats
  cache(pipeline_fn) -> CachedPipeline
  chain(step_a, step_b) -> fn
  filter_step(predicate, step) -> fn
  retry(step, attempts: int) -> fn
  log_step(step, label: str) -> fn
"""

from __future__ import annotations

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable, List, Optional

from varek.runtime import (
    VarekValue, SynStr, SynInt, SynFloat, SynBool, SynNil,
    SynArray, SynOk, SynErr, SynBuiltin, SynSchema,
    SYN_NIL, SYN_TRUE, SYN_FALSE,
    _call_value, Interpreter,
)


# ── Pipeline stats ────────────────────────────────────────────────

class _SynPipelineStats(VarekValue):
    def __init__(self, total, processed, errors, elapsed_ms, throughput):
        self.fields = {
            "total":       SynInt(total),
            "processed":   SynInt(processed),
            "errors":      SynInt(errors),
            "elapsed_ms":  SynFloat(elapsed_ms),
            "throughput":  SynFloat(throughput),    # items/sec
        }
    def __repr__(self):
        return (f"PipelineStats(processed={self.fields['processed'].value}, "
                f"elapsed={self.fields['elapsed_ms'].value:.1f}ms)")


class _SynCachedPipeline(VarekValue):
    def __init__(self, fn):
        self._fn    = fn
        self._cache = {}
        self._lock  = threading.Lock()
    def __repr__(self): return "<CachedPipeline>"


# ── Core execution ────────────────────────────────────────────────

def _run_step(fn, item: VarekValue, interp=None) -> VarekValue:
    """Execute a single pipeline step, unwrapping Result if needed."""
    from varek.runtime import SynFunction
    result = _call_value(fn, [item], interp)
    if isinstance(result, SynOk):
        return result.value
    if isinstance(result, SynErr):
        raise RuntimeError(result.message)
    return result

def _run_steps(fns: List, item: VarekValue, interp=None) -> VarekValue:
    """Execute a chain of step functions on a single item."""
    current = item
    for fn in fns:
        current = _run_step(fn, current, interp)
    return current

# Global interpreter reference for user-defined fn calls from pipeline
_CURRENT_INTERP = None

def _set_interp(interp):
    global _CURRENT_INTERP
    _CURRENT_INTERP = interp


# ── Primary pipeline operations ───────────────────────────────────

def _run(args):
    """
    run(steps: fn[], source: T[], config?) -> R[]

    Execute all steps on each item in source sequentially.
    """
    steps  = args[0]
    source = args[1]

    if not isinstance(source, SynArray):
        return SynErr("run() source must be an array")
    if not isinstance(steps, SynArray):
        return SynErr("run() steps must be an array of functions")

    fns     = steps.elements
    results = []
    errors  = []

    for item in source.elements:
        try:
            results.append(_run_steps(fns, item, _CURRENT_INTERP))
        except Exception as e:
            errors.append(SynErr(str(e)))

    return SynArray(results)

def _run_batch(args):
    """
    run_batch(steps: fn[], source: T[], batch_size: int) -> R[][]

    Execute steps in batches. Each batch is passed as a SynArray to
    the step functions. Useful for steps that support vectorisation.
    """
    steps      = args[0]
    source     = args[1]
    batch_size = int(args[2].value) if len(args) > 2 else 32

    if not isinstance(source, SynArray):
        return SynErr("run_batch() source must be an array")

    fns      = steps.elements if isinstance(steps, SynArray) else []
    items    = source.elements
    batches  = [items[i:i+batch_size] for i in range(0, len(items), batch_size)]
    results  = []

    for batch in batches:
        batch_input = SynArray(batch)
        try:
            batch_result = _run_steps(fns, batch_input)
            if isinstance(batch_result, SynArray):
                results.extend(batch_result.elements)
            else:
                results.append(batch_result)
        except Exception as e:
            results.append(SynErr(str(e)))

    return SynArray(results)

def _run_parallel(args):
    """
    run_parallel(steps: fn[], source: T[], workers: int) -> R[]

    Execute the pipeline over source items in parallel using a thread pool.
    """
    steps   = args[0]
    source  = args[1]
    workers = int(args[2].value) if len(args) > 2 else 4

    if not isinstance(source, SynArray) or not isinstance(steps, SynArray):
        return SynErr("run_parallel() requires arrays")

    fns     = steps.elements
    items   = source.elements
    results = [None] * len(items)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(_run_steps, fns, item): i
            for i, item in enumerate(items)
        }
        for fut in as_completed(future_map):
            idx = future_map[fut]
            try:
                results[idx] = fut.result()
            except Exception as e:
                results[idx] = SynErr(str(e))

    return SynArray(results)

def _map_pipeline(args):
    """
    map_pipeline(steps: fn[], item: T) -> R

    Apply a pipeline to a single item (no batching).
    """
    steps = args[0]
    item  = args[1]
    if not isinstance(steps, SynArray):
        return SynErr("map_pipeline() steps must be an array")
    try:
        return _run_steps(steps.elements, item)
    except Exception as e:
        return SynErr(str(e))


# ── Step combinators ──────────────────────────────────────────────

def _chain(args):
    """
    chain(step_a, step_b) -> fn

    Compose two step functions into one: chain(a, b)(x) = b(a(x))
    """
    step_a = args[0]; step_b = args[1]

    def composed(call_args):
        mid = _run_step(step_a, call_args[0])
        return _run_step(step_b, mid)

    return SynBuiltin("chain", composed)

def _chain_all(args):
    """
    chain_all(steps: fn[]) -> fn

    Compose all steps in the array into a single function.
    """
    if not isinstance(args[0], SynArray):
        return SynErr("chain_all() requires fn[]")
    fns = args[0].elements

    def composed(call_args):
        return _run_steps(fns, call_args[0])

    return SynBuiltin("chain_all", composed)

def _filter_step(args):
    """
    filter_step(predicate: T -> bool, step: T -> R) -> fn

    Only apply step to items where predicate returns true.
    Items that fail predicate pass through unchanged.
    """
    pred = args[0]; step = args[1]

    def filtered(call_args):
        item = call_args[0]
        test = _call_value(pred, [item])
        if isinstance(test, SynBool) and test.value:
            return _run_step(step, item)
        return item

    return SynBuiltin("filter_step", filtered)

def _retry(args):
    """
    retry(step, attempts: int) -> fn

    Wrap a step with retry logic. On failure, retries up to `attempts` times.
    """
    step     = args[0]
    attempts = int(args[1].value) if len(args) > 1 else 3

    def with_retry(call_args):
        item = call_args[0]
        last_err = None
        for attempt in range(attempts):
            try:
                result = _run_step(step, item)
                return result
            except Exception as e:
                last_err = e
                if attempt < attempts - 1:
                    time.sleep(0.1 * (2 ** attempt))  # exponential backoff
        return SynErr(f"failed after {attempts} attempts: {last_err}")

    return SynBuiltin("retry", with_retry)

def _log_step(args):
    """
    log_step(step, label: str) -> fn

    Wrap a step with timing and logging.
    """
    step  = args[0]
    label = args[1].value if isinstance(args[1], SynStr) else "step"

    def logged(call_args):
        t0 = time.perf_counter()
        try:
            result = _run_step(step, call_args[0])
            elapsed = (time.perf_counter() - t0) * 1000
            print(f"  [{label}] {elapsed:.2f}ms → {type(result).__name__}")
            return result
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            print(f"  [{label}] {elapsed:.2f}ms → ERROR: {e}")
            raise

    return SynBuiltin("log_step", logged)

def _tap(args):
    """
    tap(step, fn) -> fn

    Execute fn as a side effect without changing the value.
    Useful for logging, metrics, etc.
    """
    step   = args[0]
    side_fn= args[1]

    def tapped(call_args):
        result = _run_step(step, call_args[0])
        try: _call_value(side_fn, [result])
        except Exception: pass
        return result

    return SynBuiltin("tap", tapped)

def _map_err(args):
    """
    map_err(step, handler: Err -> any) -> fn

    Catch errors from a step and transform them.
    """
    step    = args[0]
    handler = args[1]

    def with_err_handler(call_args):
        try:
            return _run_step(step, call_args[0])
        except Exception as e:
            return _call_value(handler, [SynErr(str(e))])

    return SynBuiltin("map_err", with_err_handler)

def _cache_step(args):
    """
    cache_step(step) -> fn

    Memoize a step's results by input identity.
    """
    step  = args[0]
    cache = {}
    lock  = threading.Lock()

    def cached(call_args):
        item = call_args[0]
        key  = id(item)
        with lock:
            if key in cache:
                return cache[key]
        result = _run_step(step, item)
        with lock:
            cache[key] = result
        return result

    return SynBuiltin("cache_step", cached)


# ── Benchmarking ──────────────────────────────────────────────────

def _benchmark(args):
    """
    benchmark(steps: fn[], source: T[], runs: int) -> PipelineStats
    """
    steps  = args[0]
    source = args[1]
    runs   = int(args[2].value) if len(args) > 2 else 3

    if not isinstance(source, SynArray) or not isinstance(steps, SynArray):
        return SynErr("benchmark() requires fn[] and T[]")

    fns   = steps.elements
    items = source.elements
    total = len(items)

    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        processed = 0
        errors    = 0
        for item in items:
            try:
                _run_steps(fns, item)
                processed += 1
            except Exception:
                errors += 1
        elapsed = (time.perf_counter() - t0) * 1000
        times.append((elapsed, processed, errors))

    best_elapsed, best_processed, best_errors = min(times, key=lambda x: x[0])
    throughput = (best_processed / best_elapsed * 1000) if best_elapsed > 0 else 0.0

    return _SynPipelineStats(
        total=total,
        processed=best_processed,
        errors=best_errors,
        elapsed_ms=best_elapsed,
        throughput=throughput,
    )


# ── Streaming ─────────────────────────────────────────────────────

def _stream(args):
    """
    stream(steps: fn[], source: T[], buffer: int) -> Channel

    Process source items through steps in a background thread,
    pushing results to a bounded channel.
    """
    from varek.stdlib.async_ import _Channel, _SynChannel

    steps   = args[0]
    source  = args[1]
    buffer  = int(args[2].value) if len(args) > 2 else 16

    if not isinstance(source, SynArray) or not isinstance(steps, SynArray):
        return SynErr("stream() requires fn[] and T[]")

    ch   = _Channel(capacity=buffer)
    fns  = steps.elements
    items= source.elements

    def _worker():
        for item in items:
            try:
                result = _run_steps(fns, item)
                ch.send(SynOk(result), timeout=10)
            except Exception as e:
                ch.send(SynErr(str(e)), timeout=10)
        ch.close()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return _SynChannel(ch)

def _collect(args):
    """
    collect(channel: Channel) -> R[]

    Drain a streaming channel into an array.
    """
    from varek.stdlib.async_ import _SynChannel

    ch = args[0]
    if not isinstance(ch, _SynChannel):
        return SynErr("collect() requires a Channel")

    results = []
    while True:
        if ch.ch.is_closed() and ch.ch.size() == 0:
            break
        v = ch.ch.try_recv()
        if v is None:
            if ch.ch.is_closed():
                break
            time.sleep(0.001)
            continue
        if isinstance(v, SynOk):
            results.append(v.value)
        else:
            results.append(v)

    return SynArray(results)


def _bi(name, fn): return SynBuiltin(name, fn)

EXPORTS: dict[str, VarekValue] = {
    # Core execution
    "run":           _bi("run",           _run),
    "run_batch":     _bi("run_batch",     _run_batch),
    "run_parallel":  _bi("run_parallel",  _run_parallel),
    "map_pipeline":  _bi("map_pipeline",  _map_pipeline),
    # Combinators
    "chain":         _bi("chain",         _chain),
    "chain_all":     _bi("chain_all",     _chain_all),
    "filter_step":   _bi("filter_step",   _filter_step),
    "retry":         _bi("retry",         _retry),
    "log_step":      _bi("log_step",      _log_step),
    "tap":           _bi("tap",           _tap),
    "map_err":       _bi("map_err",       _map_err),
    "cache_step":    _bi("cache_step",    _cache_step),
    # Benchmarking
    "benchmark":     _bi("benchmark",     _benchmark),
    # Streaming
    "stream":        _bi("stream",        _stream),
    "collect":       _bi("collect",       _collect),
}
