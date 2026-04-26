"""
Platform-gating tests for VAREK fail-closed behavior.

These tests verify that VAREK refuses to execute untrusted code on
hosts where it cannot enforce containment. The fail-closed envelope
is documented in docs/development.md.

Coverage:
- configure_backend() raises IsolationError on non-Linux platforms
- SeccompBpfBackend.execute() defense-in-depth raises if called
  directly without going through configure_backend()
- The error message points users at docs/development.md
- On Linux, configure_backend() either succeeds or fails for a
  non-platform reason (missing libseccomp, missing cgroup v2, etc.)
"""

import sys
from unittest.mock import patch

import pytest

from sandbox import SeccompBpfBackend, IsolationError
from varek_warden import configure_backend


class TestPlatformGating:
    """configure_backend() must fail closed on non-Linux platforms."""

    def test_macos_raises_isolation_error(self):
        with patch.object(sys, "platform", "darwin"):
            backend = SeccompBpfBackend()
            with pytest.raises(IsolationError) as exc_info:
                configure_backend(backend)
            assert "unsupported platform" in str(exc_info.value)
            assert "darwin" in str(exc_info.value)
            assert "docs/development.md" in str(exc_info.value)

    def test_windows_raises_isolation_error(self):
        with patch.object(sys, "platform", "win32"):
            backend = SeccompBpfBackend()
            with pytest.raises(IsolationError) as exc_info:
                configure_backend(backend)
            assert "unsupported platform" in str(exc_info.value)
            assert "win32" in str(exc_info.value)
            assert "docs/development.md" in str(exc_info.value)

    def test_freebsd_raises_isolation_error(self):
        with patch.object(sys, "platform", "freebsd13"):
            backend = SeccompBpfBackend()
            with pytest.raises(IsolationError) as exc_info:
                configure_backend(backend)
            assert "unsupported platform" in str(exc_info.value)


class TestDefenseInDepth:
    """
    SeccompBpfBackend.execute() must also fail closed if called
    directly, bypassing varek_warden.configure_backend().
    """

    def test_direct_execute_raises_on_macos(self):
        with patch.object(sys, "platform", "darwin"):
            backend = SeccompBpfBackend()
            with pytest.raises(IsolationError) as exc_info:
                backend.execute(payload=None, policy=None)
            assert "unsupported platform" in str(exc_info.value)
            assert "docs/development.md" in str(exc_info.value)


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux-only test; verifies platform check does not over-block",
)
class TestLinuxBehavior:
    """
    On Linux, configure_backend() must either succeed or fail for a
    non-platform reason. The platform check itself must not raise.
    """

    def test_linux_does_not_fail_for_platform_reason(self):
        backend = SeccompBpfBackend()
        try:
            configure_backend(backend)
        except IsolationError as exc:
            assert "unsupported platform" not in str(exc), (
                f"Platform check incorrectly fired on Linux: {exc}"
            )