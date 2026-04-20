"""
=============================================================================
VAREK REGRESSION TESTS — llamastack/llama-stack-apps#223
=============================================================================

These tests encode the load-bearing invariants of the v1.1 isolation layer.
If any test in this file fails, a security regression has been introduced
and v1.1's containment guarantees no longer hold.

The issue #223 PoC (by @dengluozhang) showed that v1.0's PEP 578 audit
hook could not observe subprocess-spawned children and that the v1.0
string denylist was bypassable. v1.1 moved enforcement to seccomp-bpf +
cgroups v2 + namespaces. These tests verify the new enforcement is real,
not theoretical.

Environment requirements (tests skip if unmet):
  - Linux with cgroups v2 mounted
  - libseccomp python binding installed (`pyseccomp` or `python3-libseccomp`)
  - Unprivileged user namespaces enabled
  - /sys/fs/cgroup/varek.slice writable by the test user
    (systemd: Delegate=yes on the running unit, or pre-created cgroup)

Run: pytest tests/security/test_issue_223_regression.py -v
=============================================================================
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid

import pytest

from sandbox import (
    SeccompBpfBackend,
    ExecutionPayload,
    ExecutionPolicy,
    ResourceLimits,
    IsolationError,
    default_python_policy,
)
import varek_warden
from varek_warden import (
    configure_backend,
    execute_untrusted,
    subscribe_telemetry,
    enforce_strict_mode,
)


# -----------------------------------------------------------------------------
# Module-level skip: if the backend cannot run on this host, skip everything.
# -----------------------------------------------------------------------------

_probe = SeccompBpfBackend()
_unavailable = _probe.is_available()
if _unavailable is not None:
    pytest.skip(
        f"SeccompBpfBackend unavailable on this host: {_unavailable}",
        allow_module_level=True,
    )


@pytest.fixture(scope="module", autouse=True)
def _configure_backend_once():
    configure_backend(SeccompBpfBackend())


def _canary_path(tag: str) -> str:
    """A path outside the sandbox that must never be written to. Using
    a UUID so repeated runs don't collide, and mktemp-free because we
    want the path NOT to exist."""
    return os.path.join(
        tempfile.gettempdir(), f"varek-canary-{tag}-{uuid.uuid4().hex}"
    )


# =============================================================================
# The issue #223 PoC family: subprocess escape must not execute the child.
# =============================================================================
#
# v1.0 behavior (broken):
#   - PEP 578 audit hook observes subprocess.Popen event in the parent
#   - Hook string-matches against "nc -e", "nmap", etc.
#   - Matches → raise → process killed
#   - Bypass: use /bin/nc instead of nc, or base64-encode, or rename binary
#   - Bypass: the hook doesn't observe inside the child; any binary-level
#     payload runs unobserved once subprocess.run starts its child
#
# v1.1 behavior (required):
#   - No string matching; no denylist
#   - Seccomp filter loaded inside the interpreter denies execve
#   - Any attempt to spawn a new binary fails with EPERM
#   - Attacker's choice of name / encoding / alias is irrelevant because
#     the kernel rejects the syscall itself
# -----------------------------------------------------------------------------

def test_issue_223_subprocess_run_cannot_exec_child():
    """
    The original PoC shape: untrusted code calls subprocess.run to launch
    a binary. In v1.0 the child executed before the audit hook could do
    anything about it. In v1.1, execve is denied and the binary never runs.

    The invariant under test: after running the hostile payload, the
    canary file must not exist on the host filesystem.
    """
    canary = _canary_path("subprocess")
    assert not os.path.exists(canary)

    payload = f"""
import subprocess
# Absolute path — v1.0 denylist miss. Irrelevant in v1.1 (execve denied).
try:
    subprocess.run(['/bin/touch', {canary!r}], check=False)
except Exception:
    pass
# Shell-mediated exec — another v1.0 denylist miss. Also denied in v1.1.
try:
    subprocess.run(['/bin/sh', '-c', 'echo pwn > {canary}'], check=False)
except Exception:
    pass
"""
    execute_untrusted(
        ExecutionPayload(interpreter_path=sys.executable, code=payload)
    )

    assert not os.path.exists(canary), (
        "SANDBOX ESCAPE: canary file was written despite seccomp filter. "
        "This is the exact v1.0 regression that v1.1 was designed to fix."
    )


def test_issue_223_base64_encoded_payload_also_blocked():
    """v1.0 was bypassable by base64-encoding the command string. v1.1
    does not inspect strings at all — execve is denied unconditionally."""
    canary = _canary_path("b64")
    assert not os.path.exists(canary)

    payload = f"""
import base64, subprocess
decoded = base64.b64decode(b'dG91Y2g=').decode()  # 'touch'
try:
    subprocess.run(['/bin/' + decoded, {canary!r}], check=False)
except Exception:
    pass
"""
    execute_untrusted(
        ExecutionPayload(interpreter_path=sys.executable, code=payload)
    )
    assert not os.path.exists(canary)


def test_issue_223_renamed_binary_also_blocked():
    """v1.0 was bypassable by copying a binary to a name not on the
    denylist. v1.1 denies ALL execve in the sandbox; renaming is moot."""
    canary = _canary_path("rename")
    assert not os.path.exists(canary)

    payload = f"""
import subprocess, shutil
try:
    shutil.copy('/bin/touch', '/tmp/varek-evade-{uuid.uuid4().hex}')
except Exception:
    pass
try:
    subprocess.run(['/tmp/varek-evade', {canary!r}], check=False)
except Exception:
    pass
"""
    execute_untrusted(
        ExecutionPayload(interpreter_path=sys.executable, code=payload)
    )
    assert not os.path.exists(canary)


def test_issue_223_os_exec_family_also_blocked():
    """The v1.0 denylist covered os.exec* events. v1.1 denies the execve
    syscall, which is what os.exec* calls under the hood."""
    canary = _canary_path("osexec")
    assert not os.path.exists(canary)

    payload = f"""
import os, sys
# os.execv would replace this process with /bin/touch if allowed.
# It's not, so execve returns EPERM and os.execv raises OSError.
try:
    os.execv('/bin/touch', ['/bin/touch', {canary!r}])
except OSError:
    sys.exit(0)
"""
    execute_untrusted(
        ExecutionPayload(interpreter_path=sys.executable, code=payload)
    )
    assert not os.path.exists(canary)


# =============================================================================
# Network isolation
# =============================================================================

def test_network_is_denied_by_default():
    """Default policy sets allow_network=False. Both the empty netns and
    the seccomp filter (which doesn't allowlist socket syscalls) should
    prevent any outbound network activity."""
    payload = """
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    s.connect(('1.1.1.1', 53))
    print('NETWORK_REACHED')
    sys.exit(0)
except OSError:
    sys.exit(42)
"""
    outcome = execute_untrusted(
        ExecutionPayload(interpreter_path=sys.executable, code=payload)
    )
    assert outcome.exit_code == 42, (
        f"Network was not denied. "
        f"exit={outcome.exit_code}, stdout={outcome.stdout!r}"
    )
    assert b"NETWORK_REACHED" not in outcome.stdout


# =============================================================================
# Syscall killlist: high-risk syscalls trigger SIGSYS
# =============================================================================

def test_ptrace_triggers_seccomp_kill():
    """ptrace is on the killlist. Any invocation must result in SIGSYS (31)
    and a 'seccomp_killlist_triggered' violation on the outcome."""
    payload = """
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace(0, 0, 0, 0)   # PTRACE_TRACEME — hits the killlist
"""
    outcome = execute_untrusted(
        ExecutionPayload(interpreter_path=sys.executable, code=payload)
    )
    assert outcome.killed_by_signal == 31, (
        f"Expected SIGSYS (31), got signal={outcome.killed_by_signal}, "
        f"exit={outcome.exit_code}, stderr={outcome.stderr!r}"
    )
    assert outcome.violation == "seccomp_killlist_triggered"


def test_bpf_syscall_triggers_seccomp_kill():
    """bpf(2) is on the killlist. eBPF program loading is a direct path to
    kernel-level escalation and must be killed on sight."""
    payload = """
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
# syscall number 321 is bpf on x86_64. Any invocation kills the process.
SYS_BPF = 321
libc.syscall(SYS_BPF, 0, 0, 0)
"""
    outcome = execute_untrusted(
        ExecutionPayload(interpreter_path=sys.executable, code=payload)
    )
    assert outcome.killed_by_signal == 31
    assert outcome.violation == "seccomp_killlist_triggered"


# =============================================================================
# Resource limits
# =============================================================================

def test_memory_limit_enforced():
    """cgroup memory.max kills the process when exceeded."""
    base = default_python_policy()
    policy = ExecutionPolicy(
        binary_allowlist=base.binary_allowlist,
        syscall_allowlist=base.syscall_allowlist,
        syscall_killlist=base.syscall_killlist,
        allow_network=False,
        resources=ResourceLimits(memory_mb=64, wall_clock_timeout_s=10.0),
    )
    payload = """
import sys
try:
    chunk = bytearray(512 * 1024 * 1024)  # 512MB — must be killed
    sys.stdout.write('OOM_NOT_TRIGGERED\\n')
except MemoryError:
    sys.exit(33)
"""
    outcome = execute_untrusted(
        ExecutionPayload(interpreter_path=sys.executable, code=payload),
        policy=policy,
    )
    assert b"OOM_NOT_TRIGGERED" not in outcome.stdout
    # SIGKILL (9) from cgroup OOM, or MemoryError → exit 33, or SIGSYS
    # if something unexpected. All three confirm memory was constrained.
    assert (
        outcome.killed_by_signal == 9
        or outcome.exit_code == 33
    ), (
        f"Memory limit not enforced. "
        f"signal={outcome.killed_by_signal}, exit={outcome.exit_code}, "
        f"stderr={outcome.stderr!r}"
    )


def test_wall_clock_timeout_enforced():
    """A payload that sleeps past the wall clock must be killed."""
    base = default_python_policy()
    policy = ExecutionPolicy(
        binary_allowlist=base.binary_allowlist,
        syscall_allowlist=base.syscall_allowlist,
        syscall_killlist=base.syscall_killlist,
        allow_network=False,
        resources=ResourceLimits(wall_clock_timeout_s=2.0),
    )
    payload = """
import time
time.sleep(30)
print('SHOULD_NEVER_PRINT')
"""
    outcome = execute_untrusted(
        ExecutionPayload(interpreter_path=sys.executable, code=payload),
        policy=policy,
    )
    assert outcome.timed_out is True
    assert outcome.violation == "wall_clock_timeout"
    assert b"SHOULD_NEVER_PRINT" not in outcome.stdout
    assert outcome.wall_clock_s < 5.0, (
        f"Timeout took too long to fire: {outcome.wall_clock_s}s"
    )


# =============================================================================
# Fail-closed behavior
# =============================================================================

def test_execute_without_backend_raises():
    """If no backend is configured, execute_untrusted must fail closed,
    not silently downgrade to 'no isolation'."""
    with varek_warden._backend_lock:
        saved = varek_warden._active_backend
        varek_warden._active_backend = None
    try:
        with pytest.raises(IsolationError, match="no isolation backend"):
            execute_untrusted(
                ExecutionPayload(interpreter_path=sys.executable, code="pass")
            )
    finally:
        with varek_warden._backend_lock:
            varek_warden._active_backend = saved


def test_interpreter_not_in_allowlist_raises():
    """The binary allowlist is enforced at the parent before any process
    is spawned. A path outside the allowlist must raise IsolationError."""
    payload = ExecutionPayload(interpreter_path="/bin/sh", code="echo hi")
    with pytest.raises(IsolationError, match="binary_allowlist"):
        execute_untrusted(payload)


def test_relative_interpreter_path_rejected():
    """Absolute-path requirement is a defense against PATH-based attacks
    on the parent."""
    payload = ExecutionPayload(interpreter_path="python3", code="pass")
    with pytest.raises(IsolationError, match="must be absolute"):
        execute_untrusted(payload)


# =============================================================================
# PEP 578 hook is telemetry-only (v1.1 semantics change)
# =============================================================================

def test_pep578_hook_does_not_deny_dangerous_events():
    """
    v1.1 regression test: the audit hook must observe dangerous events
    but never raise. Enforcement lives in the sandbox, not the hook.

    If this test ever fails (hook raises), the v1.0 behavior has returned
    and the semantics contract with downstream callers is broken.
    """
    enforce_strict_mode()

    observed = []
    subscribe_telemetry(lambda r: observed.append(r["event"]))

    import subprocess
    # This runs OUTSIDE the sandbox — we're testing the parent's own hook,
    # which in v1.0 would have raised KineticIntercept on this Popen.
    proc = subprocess.Popen(
        [sys.executable, "-c", "pass"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    proc.wait()

    # Hook fired (telemetry works)...
    assert any(
        "subprocess" in e or "os.exec" in e or "Popen" in e
        for e in observed
    ), f"Telemetry hook did not observe Popen. Events: {observed[:20]}"
    # ...and did not raise (enforcement removed from the hook).
    # Reaching this assertion without an exception is the test.


# =============================================================================
# Benign payload smoke test
# =============================================================================

def test_benign_payload_runs_and_returns_stdout():
    """Well-behaved code must actually run. A sandbox that breaks
    everything is not a sandbox; it's a deny-all."""
    payload = """
import sys
print('hello from sandbox', end='')
sys.exit(0)
"""
    outcome = execute_untrusted(
        ExecutionPayload(interpreter_path=sys.executable, code=payload)
    )
    assert outcome.exit_code == 0, (
        f"Benign payload failed. stderr={outcome.stderr!r}"
    )
    assert outcome.stdout == b"hello from sandbox"
    assert outcome.violation is None
    assert outcome.killed_by_signal is None
