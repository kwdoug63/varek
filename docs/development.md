# Development Setup

VAREK enforces sandbox containment using Linux kernel features —
specifically `seccomp-bpf`, user namespaces, and cgroup v2. These are
not available on macOS or Windows. Rather than silently degrading to
unsandboxed execution on unsupported platforms, VAREK fails closed:
`configure_backend()` and `SeccompBpfBackend.execute()` both raise
`IsolationError` when the host cannot enforce containment.

This document describes the supported development paths.

## Why fail-closed

Silent fallback to unsandboxed execution would create a false sense of
security during development on macOS or Windows. Code tested locally
without a real sandbox would behave differently in production on Linux,
and developers might ship security-critical paths that were never
exercised under containment. The fail-closed default forces the issue
to surface during development, not during incident response.

## Supported development paths

### Native Linux (recommended for backend development)

Requirements:

- Linux kernel 5.8 or newer
- `libseccomp` Python bindings (`pip install pyseccomp` or
  `apt install python3-libseccomp`)
- cgroup v2 with delegation available to the user
- User namespaces enabled
  (`kernel.unprivileged_userns_clone=1` on distributions that gate this)

If any of these are missing, `is_available()` returns a string
describing the gap and `configure_backend()` raises `IsolationError`
with that string included.

### Docker (recommended for macOS and Windows)

A development Dockerfile provides a working VAREK environment on any
host that runs Docker.

```bash
docker build -t varek-dev -f Dockerfile.dev .
docker run -it --rm -v $(pwd):/workspace varek-dev
```

Inside the container, you have a Linux kernel with the required
features and can run the full test suite.

### GitHub Codespaces

Codespaces preconfigure a Linux environment with the kernel features
VAREK requires. To start one, click **Code → Codespaces → Create
codespace** on the repository page.

This is the path of least friction for contributors who do not run
Linux locally.

## Verifying your environment

A simple availability check:

```python
from sandbox import SeccompBpfBackend

backend = SeccompBpfBackend()
reason = backend.is_available()
if reason is None:
    print("Sandbox available.")
else:
    print(f"Sandbox unavailable: {reason}")
```

On a properly configured Linux host, this prints `Sandbox available.`
On macOS or Windows, it prints something like
`Sandbox unavailable: unsupported platform: darwin`.

## What happens on an unsupported platform

```python
from varek_warden import configure_backend, execute_untrusted
from sandbox import SeccompBpfBackend

configure_backend(SeccompBpfBackend())
# On macOS:
#   IsolationError: SeccompBpfBackend unavailable: unsupported platform: darwin.
#   See docs/development.md for supported platforms and required kernel features.
```

The error tells you exactly why the sandbox cannot run and points
back to this document. Use one of the supported development paths
above.

## Reporting environment issues

If you believe your Linux host meets all requirements but
`is_available()` still reports a gap, open an issue with the output
of:

```bash
uname -a
cat /etc/os-release
sysctl kernel.unprivileged_userns_clone 2>/dev/null
ls /sys/fs/cgroup/cgroup.controllers 2>/dev/null
python -c "import pyseccomp; print(pyseccomp.__version__)" 2>&1
```

This gives enough information to diagnose kernel, distribution, and
binding issues.