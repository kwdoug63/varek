"""
=============================================================================
VAREK: CORE WARDEN (v1.1)
Architecture: OS-level isolation via pluggable IsolationBackend.
              PEP 578 audit hook demoted to telemetry-only.
Purpose: Containment of untrusted code execution in agentic LLM workflows.
         The kernel is the enforcement boundary; the interpreter is not.

-----------------------------------------------------------------------------
v1.1 CHANGES (closes llamastack/llama-stack-apps#223):

The v1.0 design used a PEP 578 audit hook to deny subprocess.Popen / os.exec*
events matching a string denylist. External review demonstrated two flaws:

  1. sys.addaudithook installs the hook in the current interpreter only.
     A child process spawned by subprocess.run executes in a separate
     interpreter (or a non-Python binary) that never inherits the hook.
     The parent-side hook cannot observe the child's syscalls. The issue
     #223 PoC exploits this directly.

  2. Substring matching on command args ("nc -e", "hostile-c2.net") is
     trivially bypassed via /bin/nc, base64, renamed binaries, or any
     tooling the author hadn't enumerated.

v1.1 response:

  - Enforcement moves out of the audit hook and into sandbox.IsolationBackend
    (see sandbox.py). The reference backend uses seccomp-bpf + cgroups v2 +
    user/mount/net/ipc/uts/pid namespaces, installed via PR_SET_NO_NEW_PRIVS
    before the interpreter's execve. The filter is inherited across fork
    and cannot be dropped — subprocess escapes are structurally prevented.

  - The denylist is replaced by a binary allowlist (enforced at the parent
    before execve) and a syscall allowlist + killlist (enforced by the
    kernel).

  - The PEP 578 audit hook is retained but demoted to telemetry. It emits
    structured records to subscribers; it never raises. Security no longer
    depends on it firing.

  - enforce_strict_mode() is retained for v1.0 API compatibility but its
    semantics have changed: it now arms telemetry only. Untrusted code
    MUST be executed via execute_untrusted() with a configured backend.
    Callers who don't configure a backend get IsolationError (fail-closed).

  - KineticIntercept is retained as a deprecated symbol for v1.0 imports.
    It is no longer raised by the hook. Enforcement failures surface as
    IsolationError from sandbox.
=============================================================================
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from typing import Callable, Optional

from sandbox import (
    IsolationBackend,
    SeccompBpfBackend,
    ExecutionPayload,
    ExecutionPolicy,
    ExecutionOutcome,
    IsolationError,
    default_python_policy,
)

logging.basicConfig(level=logging.INFO, format="[VAREK] %(message)s")
_log = logging.getLogger("varek.warden")


# =============================================================================
# Backward-compatible symbol (deprecated in v1.1)
# =============================================================================

class KineticIntercept(Exception):
    """
    DEPRECATED in v1.1. Retained so v1.0 imports don't break.

    The v1.0 semantics (raise from inside the audit hook to terminate the
    thread) were unsound because the hook doesn't cross the subprocess
    boundary. Enforcement failures now surface as sandbox.IsolationError.
    """


# =============================================================================
# Telemetry (PEP 578 audit hook — demoted, advisory only)
# =============================================================================

_telemetry_subscribers: "list[Callable[[dict], None]]" = []
_telemetry_lock = threading.Lock()


def _telemetry_hook(event: str, args: tuple) -> None:
    """
    PEP 578 audit hook. TELEMETRY ONLY — never raises, never denies.

    Known limitation (the whole point of the v1.1 redesign): this hook
    does NOT fire inside child processes spawned by subprocess / os.exec*.
    Containment of hostile child processes is provided by the sandbox
    IsolationBackend, not by this hook. Treat the events emitted here as
    observability on the parent's own behavior, not as a security signal.
    """
    try:
        record = {
            "ts": time.time(),
            "event": event,
            "args_repr": repr(args)[:1024],
        }
        _log.info("telemetry %s", json.dumps(record))
        for subscriber in list(_telemetry_subscribers):
            try:
                subscriber(record)
            except Exception:
                # Subscriber failures must never break the hook.
                pass
    except Exception:
        # Best-effort; audit hooks run in sensitive contexts and must not raise.
        pass


def subscribe_telemetry(callback: Callable[[dict], None]) -> None:
    """Register a callback for audit-hook telemetry events. Callbacks must
    not raise; exceptions are swallowed."""
    with _telemetry_lock:
        _telemetry_subscribers.append(callback)


def enforce_strict_mode() -> None:
    """
    Arms VAREK telemetry.

    BACKWARD-COMPATIBLE NAME, NEW SEMANTICS: this no longer enforces
    anything. It installs the PEP 578 telemetry hook. To actually contain
    untrusted code, call configure_backend() followed by execute_untrusted().

    Fails closed (sys.exit(1)) only if the hook itself cannot be installed
    — this matches the v1.0 behavior so existing init code is unchanged.
    """
    try:
        sys.addaudithook(_telemetry_hook)
        print("[+] VAREK v1.1 telemetry hook armed (PEP 578, advisory only).")
        print("[+] Enforcement is provided by sandbox.IsolationBackend.")
        print("[+] Call configure_backend() + execute_untrusted() for untrusted code.\n")
    except Exception as e:
        _log.error("failed to arm telemetry hook: %s", e)
        sys.exit(1)


# =============================================================================
# Enforcement (delegated to IsolationBackend)
# =============================================================================

_active_backend: Optional[IsolationBackend] = None
_backend_lock = threading.Lock()


def configure_backend(backend: Optional[IsolationBackend] = None) -> None:
    """
    Install the IsolationBackend used for all subsequent execute_untrusted()
    calls. If no backend is passed, SeccompBpfBackend is used.

    Fails closed: if the backend's is_available() returns a reason, this
    raises IsolationError. v1.1 does not silently downgrade to a weaker
    containment mode.
    """
    backend = backend or SeccompBpfBackend()
    reason = backend.is_available()
    if reason is not None:
        raise IsolationError(
            f"backend {backend.name()!r} unavailable: {reason}"
        )
    with _backend_lock:
        global _active_backend
        _active_backend = backend
    _log.info("isolation backend configured: %s", backend.name())


def get_active_backend() -> Optional[IsolationBackend]:
    with _backend_lock:
        return _active_backend


def execute_untrusted(
    payload: ExecutionPayload,
    policy: Optional[ExecutionPolicy] = None,
) -> ExecutionOutcome:
    """
    Execute untrusted code inside the configured isolation backend.

    Fails closed if no backend has been configured. This is the v1.1
    replacement for code paths that previously relied on the audit hook
    to catch subprocess escapes — which, per issue #223, it cannot.
    """
    with _backend_lock:
        backend = _active_backend
    if backend is None:
        raise IsolationError(
            "no isolation backend configured; call configure_backend() first. "
            "v1.1 fails closed by design — see docs/security/isolation.md"
        )
    return backend.execute(payload, policy or default_python_policy())


__all__ = [
    # v1.0 compat
    "KineticIntercept", "enforce_strict_mode",
    # v1.1 telemetry
    "subscribe_telemetry",
    # v1.1 enforcement
    "configure_backend", "get_active_backend", "execute_untrusted",
    # re-exports so callers don't need to import sandbox directly
    "ExecutionPayload", "ExecutionPolicy", "ExecutionOutcome",
    "IsolationBackend", "SeccompBpfBackend", "IsolationError",
    "default_python_policy",
]
