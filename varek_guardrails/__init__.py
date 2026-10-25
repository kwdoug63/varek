"""varek_guardrails — public package surface for VAREK containment.

Legacy (v1.1), kept so existing copies keep working (v1.35, D10). It uses
none of the Warden (varek/v1_4). For an agent built on a framework, write
its plan with `varek plan generate` (varek/v1_4/adapters/README.md) and run
it under the Warden (`varek run --plan PLAN --hold-to-plan`).
"""

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
