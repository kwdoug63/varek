# varek_warden.py — v1.1 orchestration layer over sandbox primitives
#
# Implements the three entry points advertised in the v1.1 CHANGELOG:
#   configure_backend(backend)   — install the active isolation backend
#   execute_untrusted(payload, policy) — run untrusted code under containment
#   subscribe_telemetry(callback) — register a PEP 578 advisory callback
#
# This module is pure orchestration. All kernel-level enforcement lives
# in sandbox.py (SeccompBpfBackend and the IsolationBackend interface).

from typing import Callable, Optional
from sandbox import (
    IsolationBackend,
    ExecutionPayload,
    ExecutionPolicy,
    ExecutionOutcome,
    IsolationError,
    default_python_policy,
)

_active_backend: Optional[IsolationBackend] = None
_telemetry_subscribers: list[Callable] = []
_audit_hook_installed: bool = False


def configure_backend(backend: IsolationBackend) -> None:
    """Install the active isolation backend.

    Fails closed: raises IsolationError if the backend reports any
    reason why it cannot enforce containment on this host. This is a
    security boundary — we do not silently downgrade.

    sandbox.IsolationBackend.is_available() returns None on success,
    or a human-readable string describing why the backend is unavailable
    (e.g. missing kernel support, wrong platform, missing libseccomp).
    """
    reason = backend.is_available()
    if reason is not None:
        raise IsolationError(
            f"{backend.__class__.__name__} unavailable: {reason}"
        )
    global _active_backend
    _active_backend = backend


def execute_untrusted(
    payload: ExecutionPayload,
    policy: ExecutionPolicy = None,
) -> ExecutionOutcome:
    """Run untrusted code under the configured backend's containment.

    Raises IsolationError if no backend has been configured — we never
    execute untrusted code without an installed containment layer.
    """
    if _active_backend is None:
        raise IsolationError(
            "No backend configured. Call configure_backend() before "
            "execute_untrusted()."
        )
    policy = policy or default_python_policy()
    return _active_backend.execute(payload, policy)


def subscribe_telemetry(callback: Callable[[str, tuple], None]) -> None:
    """Register a callback for PEP 578 audit events.

    In v1.1 the audit hook is advisory-only. Callbacks receive events
    for observability, but they cannot deny execution — kernel-level
    enforcement in the active backend is the authoritative boundary.

    The first call to subscribe_telemetry() installs the process-wide
    audit hook; subsequent calls simply append to the subscriber list.
    """
    global _audit_hook_installed
    _telemetry_subscribers.append(callback)
    if not _audit_hook_installed:
        import sys
        sys.addaudithook(_dispatch_telemetry)
        _audit_hook_installed = True


def _dispatch_telemetry(event: str, args: tuple) -> None:
    """Fan out an audit event to every registered subscriber.

    Subscriber exceptions are swallowed — telemetry callbacks must
    never affect enforcement. If a subscriber crashes, containment
    continues unaffected at the kernel level.
    """
    for cb in _telemetry_subscribers:
        try:
            cb(event, args)
        except Exception:
            pass