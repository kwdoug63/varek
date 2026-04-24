"""
varek/stdlib/async_.py
─────────────────────────
var::async — Concurrency primitives for VAREK.

Provides synchronous wrappers over Python's threading and queue
machinery, plus an asyncio executor for truly async workloads.
VAREK's async/await desugars to these at the runtime level.

Operations:
  channel(capacity: int) -> Channel
  send(ch: Channel, value: any) -> Result<nil>
  recv(ch: Channel) -> Result<any>
  try_recv(ch: Channel) -> any?
  close(ch: Channel) -> nil
  select(channels: Channel[]) -> Result<any>

  spawn(fn) -> Future
  await_future(f: Future) -> Result<any>
  sleep(ms: int) -> nil
  timeout(ms: int, fn) -> Result<any>

  parallel_map(items: T[], fn: T -> R, workers: int) -> R[]
  parallel_for(items: T[], fn: T -> nil, workers: int) -> nil
  gather(futures: Future[]) -> any[]

  mutex() -> Mutex
  lock(m: Mutex, fn) -> any
  semaphore(n: int) -> Semaphore
  acquire(s: Semaphore) -> nil
  release(s: Semaphore) -> nil

  timer(ms: int, fn) -> TimerHandle
  cancel(handle: TimerHandle) -> nil
"""

from __future__ import annotations

import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future as ConcFuture, as_completed
from typing import Any, List, Optional

from varek.runtime import (
    VarekValue, SynStr, SynInt, SynFloat, SynBool, SynNil,
    SynArray, SynOk, SynErr, SynBuiltin, SynSchema,
    SYN_NIL, SYN_TRUE, SYN_FALSE,
    _call_value,
)


# ── Channel ───────────────────────────────────────────────────────

class _Channel:
    """Thread-safe bounded channel (queue)."""
    def __init__(self, capacity: int = 0):
        self._q      = queue.Queue(maxsize=capacity if capacity > 0 else 0)
        self._closed = threading.Event()
        self.capacity = capacity

    def send(self, v, timeout=None):
        if self._closed.is_set():
            raise RuntimeError("send on closed channel")
        try:
            self._q.put(v, timeout=timeout)
        except queue.Full:
            raise RuntimeError("channel is full")

    def recv(self, timeout=None):
        if self._closed.is_set() and self._q.empty():
            raise RuntimeError("recv on closed empty channel")
        try:
            return self._q.get(timeout=timeout if timeout else None)
        except queue.Empty:
            raise RuntimeError("channel empty (timeout)")

    def try_recv(self):
        try:
            return self._q.get_nowait()
        except queue.Empty:
            return None

    def close(self):
        self._closed.set()

    def is_closed(self):
        return self._closed.is_set()

    def size(self):
        return self._q.qsize()


class _SynChannel(VarekValue):
    def __init__(self, ch: _Channel): self.ch = ch
    def __repr__(self): return f"<Channel capacity={self.ch.capacity}>"


class _SynFuture(VarekValue):
    def __init__(self, future: ConcFuture): self.future = future
    def __repr__(self): return f"<Future done={self.future.done()}>"


class _SynMutex(VarekValue):
    def __init__(self): self.lock = threading.Lock()
    def __repr__(self): return "<Mutex>"


class _SynSemaphore(VarekValue):
    def __init__(self, n: int): self.sem = threading.Semaphore(n)
    def __repr__(self): return f"<Semaphore>"


class _SynTimerHandle(VarekValue):
    def __init__(self, t: threading.Timer): self.t = t
    def __repr__(self): return "<TimerHandle>"


# Global thread pool
_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix="varek-async")


# ── Channel operations ────────────────────────────────────────────

def _channel(args):
    cap = int(args[0].value) if args else 0
    return _SynChannel(_Channel(cap))

def _send(args):
    ch  = args[0]
    val = args[1]
    if not isinstance(ch, _SynChannel):
        return SynErr("send() requires a Channel")
    try:
        ch.ch.send(val, timeout=5.0)
        return SynOk(SYN_NIL)
    except Exception as e:
        return SynErr(str(e))

def _recv(args):
    ch = args[0]
    if not isinstance(ch, _SynChannel):
        return SynErr("recv() requires a Channel")
    timeout = float(args[1].value) / 1000.0 if len(args) > 1 else None
    try:
        v = ch.ch.recv(timeout=timeout)
        return SynOk(v)
    except Exception as e:
        return SynErr(str(e))

def _try_recv(args):
    ch = args[0]
    if not isinstance(ch, _SynChannel):
        return SYN_NIL
    v = ch.ch.try_recv()
    return v if v is not None else SYN_NIL

def _close_ch(args):
    ch = args[0]
    if isinstance(ch, _SynChannel):
        ch.ch.close()
    return SYN_NIL

def _ch_size(args):
    ch = args[0]
    if isinstance(ch, _SynChannel):
        return SynInt(ch.ch.size())
    return SynInt(0)

def _ch_closed(args):
    ch = args[0]
    if isinstance(ch, _SynChannel):
        return SynBool(ch.ch.is_closed())
    return SYN_TRUE

def _select(args):
    """
    Wait on the first channel that has a value ready.
    select(channels: Channel[]) -> Result<any>
    """
    channels = args[0]
    if not isinstance(channels, SynArray):
        return SynErr("select() requires Channel[]")
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        for ch_val in channels.elements:
            if isinstance(ch_val, _SynChannel):
                v = ch_val.ch.try_recv()
                if v is not None:
                    return SynOk(v)
        time.sleep(0.001)
    return SynErr("select() timeout: no channel ready")


# ── Future / spawn ────────────────────────────────────────────────

def _spawn(args):
    fn = args[0]
    fn_args = list(args[1:]) if len(args) > 1 else []
    try:
        future = _POOL.submit(_call_value, fn, fn_args)
        return _SynFuture(future)
    except Exception as e:
        return SynErr(str(e))

def _await_future(args):
    f = args[0]
    if not isinstance(f, _SynFuture):
        return SynErr("await_future() requires a Future")
    timeout = float(args[1].value) if len(args) > 1 else None
    try:
        result = f.future.result(timeout=timeout)
        return SynOk(result)
    except Exception as e:
        return SynErr(str(e))

def _future_done(args):
    f = args[0]
    return SynBool(isinstance(f, _SynFuture) and f.future.done())

def _gather(args):
    futures = args[0]
    if not isinstance(futures, SynArray):
        return SynArray([])
    results = []
    for f_val in futures.elements:
        if isinstance(f_val, _SynFuture):
            try:
                results.append(f_val.future.result(timeout=60))
            except Exception as e:
                results.append(SynErr(str(e)))
        else:
            results.append(f_val)
    return SynArray(results)

def _sleep(args):
    ms = int(args[0].value) if args else 0
    time.sleep(ms / 1000.0)
    return SYN_NIL

def _timeout(args):
    ms  = int(args[0].value)
    fn  = args[1]
    fn_args = list(args[2:]) if len(args) > 2 else []
    try:
        future  = _POOL.submit(_call_value, fn, fn_args)
        result  = future.result(timeout=ms / 1000.0)
        return SynOk(result)
    except TimeoutError:
        return SynErr(f"timeout after {ms}ms")
    except Exception as e:
        return SynErr(str(e))


# ── Parallel operations ───────────────────────────────────────────

def _parallel_map(args):
    items   = args[0]
    fn      = args[1]
    workers = int(args[2].value) if len(args) > 2 else 4

    if not isinstance(items, SynArray):
        return SynArray([])

    elements = items.elements
    results  = [None] * len(elements)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_call_value, fn, [el]): i
                   for i, el in enumerate(elements)}
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                results[idx] = fut.result()
            except Exception as e:
                results[idx] = SynErr(str(e))

    return SynArray(results)

def _parallel_for(args):
    items   = args[0]
    fn      = args[1]
    workers = int(args[2].value) if len(args) > 2 else 4

    if not isinstance(items, SynArray):
        return SYN_NIL

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_call_value, fn, [el]) for el in items.elements]
        for fut in as_completed(futures):
            try: fut.result()
            except Exception: pass

    return SYN_NIL

def _batch_process(args):
    """Process items in batches. batch_process(items, fn, batch_size, workers)"""
    items      = args[0]
    fn         = args[1]
    batch_size = int(args[2].value) if len(args) > 2 else 32
    workers    = int(args[3].value) if len(args) > 3 else 4

    if not isinstance(items, SynArray):
        return SynArray([])

    elements = items.elements
    batches  = [elements[i:i+batch_size] for i in range(0, len(elements), batch_size)]
    results  = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        batch_futures = [
            pool.submit(_call_value, fn, [SynArray(batch)])
            for batch in batches
        ]
        for fut in batch_futures:
            try:
                r = fut.result()
                if isinstance(r, SynArray):
                    results.extend(r.elements)
                else:
                    results.append(r)
            except Exception as e:
                results.append(SynErr(str(e)))

    return SynArray(results)


# ── Mutex ─────────────────────────────────────────────────────────

def _mutex(args):
    return _SynMutex()

def _lock_fn(args):
    m   = args[0]
    fn  = args[1]
    fn_args = list(args[2:]) if len(args) > 2 else []
    if not isinstance(m, _SynMutex):
        return _call_value(fn, fn_args)
    with m.lock:
        return _call_value(fn, fn_args)

def _try_lock(args):
    m = args[0]
    if not isinstance(m, _SynMutex):
        return SYN_FALSE
    acquired = m.lock.acquire(blocking=False)
    return SynBool(acquired)

def _unlock(args):
    m = args[0]
    if isinstance(m, _SynMutex):
        try: m.lock.release()
        except Exception: pass
    return SYN_NIL


# ── Semaphore ─────────────────────────────────────────────────────

def _semaphore(args):
    n = int(args[0].value) if args else 1
    return _SynSemaphore(n)

def _acquire(args):
    s = args[0]
    if isinstance(s, _SynSemaphore):
        timeout = float(args[1].value) / 1000.0 if len(args) > 1 else None
        acquired = s.sem.acquire(timeout=timeout)
        return SynBool(acquired)
    return SYN_FALSE

def _release(args):
    s = args[0]
    if isinstance(s, _SynSemaphore):
        s.sem.release()
    return SYN_NIL


# ── Timer ─────────────────────────────────────────────────────────

def _timer(args):
    ms  = int(args[0].value)
    fn  = args[1]
    fn_args = list(args[2:]) if len(args) > 2 else []
    t = threading.Timer(ms / 1000.0, _call_value, args=[fn, fn_args])
    t.daemon = True
    t.start()
    return _SynTimerHandle(t)

def _cancel_timer(args):
    h = args[0]
    if isinstance(h, _SynTimerHandle):
        h.t.cancel()
    return SYN_NIL

def _repeat(args):
    """repeat(ms, fn) — calls fn every ms milliseconds until cancelled."""
    ms  = int(args[0].value)
    fn  = args[1]
    fn_args = list(args[2:]) if len(args) > 2 else []
    stop_event = threading.Event()

    def _loop():
        while not stop_event.is_set():
            try: _call_value(fn, fn_args)
            except Exception: pass
            stop_event.wait(ms / 1000.0)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    class _RepeatHandle(VarekValue):
        def __repr__(self): return "<RepeatHandle>"
        def stop(self): stop_event.set()

    h = _RepeatHandle()
    return h


# ── Atomic counter ────────────────────────────────────────────────

class _SynAtomicInt(VarekValue):
    def __init__(self, v=0):
        self._lock = threading.Lock()
        self._val  = v
    def get(self): 
        with self._lock: return self._val
    def set(self, v):
        with self._lock: self._val = v
    def inc(self, by=1):
        with self._lock: self._val += by; return self._val
    def dec(self, by=1):
        with self._lock: self._val -= by; return self._val
    def __repr__(self): return f"<Atomic {self._val}>"

def _atomic_int(args):
    v = int(args[0].value) if args else 0
    return _SynAtomicInt(v)

def _atomic_get(args):
    a = args[0]
    return SynInt(a.get()) if isinstance(a, _SynAtomicInt) else SynInt(0)

def _atomic_set(args):
    a = args[0]; v = int(args[1].value)
    if isinstance(a, _SynAtomicInt): a.set(v)
    return SYN_NIL

def _atomic_inc(args):
    a  = args[0]
    by = int(args[1].value) if len(args) > 1 else 1
    return SynInt(a.inc(by)) if isinstance(a, _SynAtomicInt) else SynInt(0)

def _atomic_dec(args):
    a  = args[0]
    by = int(args[1].value) if len(args) > 1 else 1
    return SynInt(a.dec(by)) if isinstance(a, _SynAtomicInt) else SynInt(0)


def _bi(name, fn): return SynBuiltin(name, fn)

EXPORTS: dict[str, VarekValue] = {
    # Channel
    "channel":      _bi("channel",      _channel),
    "send":         _bi("send",         _send),
    "recv":         _bi("recv",         _recv),
    "try_recv":     _bi("try_recv",     _try_recv),
    "close":        _bi("close",        _close_ch),
    "ch_size":      _bi("ch_size",      _ch_size),
    "ch_closed":    _bi("ch_closed",    _ch_closed),
    "select":       _bi("select",       _select),
    # Future / spawn
    "spawn":        _bi("spawn",        _spawn),
    "await_future": _bi("await_future", _await_future),
    "future_done":  _bi("future_done",  _future_done),
    "gather":       _bi("gather",       _gather),
    "sleep":        _bi("sleep",        _sleep),
    "timeout":      _bi("timeout",      _timeout),
    # Parallel
    "parallel_map": _bi("parallel_map", _parallel_map),
    "parallel_for": _bi("parallel_for", _parallel_for),
    "batch_process":_bi("batch_process",_batch_process),
    # Mutex
    "mutex":        _bi("mutex",        _mutex),
    "lock":         _bi("lock",         _lock_fn),
    "try_lock":     _bi("try_lock",     _try_lock),
    "unlock":       _bi("unlock",       _unlock),
    # Semaphore
    "semaphore":    _bi("semaphore",    _semaphore),
    "acquire":      _bi("acquire",      _acquire),
    "release":      _bi("release",      _release),
    # Timer
    "timer":        _bi("timer",        _timer),
    "cancel":       _bi("cancel",       _cancel_timer),
    "repeat":       _bi("repeat",       _repeat),
    # Atomic
    "atomic_int":   _bi("atomic_int",   _atomic_int),
    "atomic_get":   _bi("atomic_get",   _atomic_get),
    "atomic_set":   _bi("atomic_set",   _atomic_set),
    "atomic_inc":   _bi("atomic_inc",   _atomic_inc),
    "atomic_dec":   _bi("atomic_dec",   _atomic_dec),
}
