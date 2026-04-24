"""varek_guardrails — public package surface for VAREK containment."""

__version__ = "1.1.1"

from sandbox import (
    SeccompBpfBackend,
    ExecutionPayload,
    ExecutionPolicy,
    ExecutionOutcome,
    IsolationError,
    IsolationBackend,
    ResourceLimits,
    default_python_policy,
)

from varek_warden import (
    configure_backend,
    execute_untrusted,
    subscribe_telemetry,
)

__all__ = [
    "SeccompBpfBackend",
    "ExecutionPayload",
    "ExecutionPolicy",
    "ExecutionOutcome",
    "IsolationError",
    "IsolationBackend",
    "ResourceLimits",
    "default_python_policy",
    "configure_backend",
    "execute_untrusted",
    "subscribe_telemetry",
]
