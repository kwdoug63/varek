# VAREK v1.1 — Subprocess Isolation Update

**Status:** Draft RFC
**Supersedes (in part):** v1.0 Architecture Proposal §PEP 578 OS-Boundary Intercepts
**Issue:** llamastack/llama-stack-apps#223
**Author:** Kenneth W. Douglas, MD
**Date:** April 20, 2026

---

## 1. Acknowledgement of the v1.0 Gap

The v1.0 proposal described PEP 578 audit hooks as the containment primitive for code interpreter tools. The critique in issue #223 is correct on all three points:

1. **PEP 578 hooks are interpreter-local.** `sys.addaudithook` registers a callback inside the CPython process that installed it. A child process spawned by `subprocess.run`, `os.execve`, `os.posix_spawn`, or a forked Python interpreter starts with no inherited hooks. The parent-side hook cannot observe syscalls, imports, or `subprocess` events that occur in that child. The PoC exploit demonstrates this directly.

2. **Command-string denylists are unsound.** Substring matching on `nc`, `nmap`, `curl`, or known C2 hostnames loses to absolute paths (`/bin/nc`), base64-encoded payloads, renamed binaries, LOLBins, and any bespoke attacker tooling. Denylists are a finite enumeration against an infinite adversary.

3. **Untrusted code execution requires OS-level isolation.** The correct containment boundary is the kernel, not the interpreter. seccomp-bpf, cgroups v2, Linux namespaces, Windows Job Objects, and purpose-built sandboxes (gVisor, nsjail, bubblewrap, firejail) exist precisely because language-level policy cannot contain hostile native code.

v1.1 accepts this framing. The containment boundary moves from the interpreter to the kernel. The PEP 578 hook is **repositioned from primary enforcement to a runtime visibility and advisory-interception layer** in a layered defense — not stripped of value, but no longer load-bearing for containment. The hook observes events the kernel layer cannot (imports, `compile` calls, `pickle` loads, `exec`/`eval` invocations) and fires *before* the syscall a given Python operation would dispatch, which makes conditional interception possible for in-process policy decisions and makes post-hoc triage of seccomp denials tractable. What it cannot do — and what v1.0 incorrectly asked it to do — is serve as the containment boundary for hostile code that reaches native execution or spawns a subprocess. That job now belongs to the isolation backend described in the following sections.

---

## 2. Design Principles for v1.1

- **Pluggable isolation interface, not a single mechanism.** Different deployments have different constraints: Linux servers, Windows hosts, air-gapped SCIFs, Kubernetes pods. A hardcoded dependency on any one sandbox is a deployment blocker.
- **Allowlist, not denylist, at the syscall and binary level.** The default posture for untrusted code is "nothing is allowed unless explicitly permitted."
- **Defense in depth.** Isolation layer is the containment boundary. PEP 578 remains in-process as a visibility and advisory-interception surface — useful for observing events below the kernel's resolution (imports, `compile`, `pickle`, `exec`/`eval`) and for making seccomp denials triageable — but carries no enforcement weight. Resource caps, filesystem restrictions, and network egress policy stack on top.
- **No silent fallback to a weaker mode.** If the configured isolation backend is unavailable at runtime, execution of untrusted code fails closed. A warning-level fallback to PEP 578–only containment is explicitly not offered.
- **Minimal v1.1 scope.** Ship the interface and one reference backend (seccomp-bpf on Linux). gVisor, bubblewrap, and Windows Job Objects are deferred to v1.2+ as additional backend implementations behind the same interface.

---

## 3. The `IsolationBackend` Interface

```varek
// varek/runtime/isolation/interface.vk

trait IsolationBackend {
    // Lifecycle
    fn name(&self) -> &'static str
    fn is_available(&self) -> Result<(), UnavailableReason>
    fn capabilities(&self) -> IsolationCapabilities

    // Execution
    fn execute(
        &self,
        payload: ExecutionPayload,
        policy: ExecutionPolicy,
    ) -> Result<ExecutionOutcome, IsolationError>
}

struct ExecutionPayload {
    interpreter: InterpreterKind,     // Python311, Python312, Native
    code: CodeSource,                  // File(path) | Inline(bytes)
    argv: Vec<String>,
    stdin: Option<Bytes>,
    env: EnvPolicy,                    // Inherit(allowlist) | Empty | Explicit(map)
}

struct ExecutionPolicy {
    binary_allowlist: BinaryAllowlist,
    syscall_policy: SyscallPolicy,
    filesystem: FilesystemPolicy,
    network: NetworkPolicy,
    resources: ResourceLimits,
    wall_clock_timeout_ms: u64,
}

struct IsolationCapabilities {
    enforces_syscall_policy: bool,
    enforces_fs_isolation: bool,
    enforces_network_isolation: bool,
    enforces_resource_limits: bool,
    supports_gpu_passthrough: bool,
}
```

Any backend that cannot honor a field in `ExecutionPolicy` must declare so in `capabilities()` and reject the policy at `execute()` time rather than silently ignoring it. `VarekRuntime` refuses to dispatch a policy that exceeds the declared capabilities of the selected backend.

---

## 4. Reference Backend: `SeccompBpfBackend` (Linux)

### 4.1 Process model

Every untrusted execution runs in a freshly spawned child that is:

1. Launched via `clone3(2)` with `CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUSER | CLONE_NEWCGROUP`.
2. Placed in a dedicated cgroup v2 slice with memory, CPU, and pids.max caps set from `ResourceLimits`.
3. Mounted with a read-only rootfs overlay plus a single writable tmpfs scratch dir (size-capped).
4. Re-execed into a minimal stub that installs a seccomp-bpf filter via `prctl(PR_SET_NO_NEW_PRIVS)` + `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC)` before `execve`-ing the target interpreter.

The seccomp filter is installed **before** the interpreter starts. It applies to the interpreter process and every descendant, across any `fork`/`clone`/`execve` the interpreter performs. This is the structural property that v1.0 lacked: the policy lives in the kernel, not in the Python interpreter, so subprocess escapes do not bypass it.

### 4.2 Default syscall allowlist

The default profile for `InterpreterKind::Python311` permits approximately 70 syscalls needed for interpreter startup, memory management, file I/O within the scratch dir, and basic stdlib operation. Everything else returns `EPERM` or, for the high-risk set below, `SIGSYS` (kill):

- `execve`, `execveat` → gated by `BinaryAllowlist` via an LSM hook or, where unavailable, a `ptrace`-based path check (see §4.4)
- `socket`, `connect`, `sendto`, `sendmsg` with `AF_INET`/`AF_INET6`/`AF_UNIX` → denied unless `NetworkPolicy::AllowEgress(...)` is set
- `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp` → denied unconditionally
- `bpf`, `perf_event_open`, `userfaultfd`, `io_uring_setup` → denied unconditionally
- `mount`, `pivot_root`, `chroot`, `unshare`, `setns` → denied (isolation is set up by the parent before handoff)
- `keyctl`, `add_key`, `request_key` → denied
- `clone`/`clone3` with flags that escape the existing namespace set → denied

The full default profile is versioned at `varek/runtime/isolation/seccomp/profiles/python.default.json` and is diffable across releases.

### 4.3 Binary allowlist

`BinaryAllowlist` is enforced by checking the resolved path of every `execve`/`execveat` target. The v1.1 default for untrusted Python is:

```
/usr/bin/python3.11
/usr/bin/python3.12
```

That is the entire list. `sh`, `bash`, `nc`, `curl`, `wget`, `/bin/*`, and `/usr/bin/*` are not on it. Users extend the allowlist explicitly per policy; VAREK ships no permissive defaults. This inverts the v1.0 posture (enumerate bad) to the v1.1 posture (enumerate good).

Enforcement preference:

1. **LSM path (preferred):** an eBPF LSM program attached to `bprm_check_security` that compares the resolved `linux_binprm->file` path against the allowlist. This is the clean, race-free implementation.
2. **Seccomp-notify path (fallback):** a user-space supervisor resolves the argv[0] via `/proc/<tid>/mem` + `readlink` on the user-namespaced fd and `ACK`s or `RET_ERRNO`s the syscall. Racier but dependency-free.
3. **Explicit opt-in path:** on kernels that support neither, `SeccompBpfBackend::is_available()` returns `UnavailableReason::KernelTooOld` and execution fails closed.

### 4.4 In-process visibility layer (PEP 578 repositioned)

Inside the child, a PEP 578 audit hook is installed at interpreter startup. In v1.1 this hook **does not deny at the enforcement boundary**; it emits structured events to a parent-side supervisor over a pre-opened unix socket fd and, where configured, makes advisory interception decisions on events the kernel cannot see. The hook is useful precisely because it observes at a different resolution than seccomp:

- It fires on events that have no direct syscall correspondent — `import` resolution, `compile()`, `exec()`/`eval()`, `pickle.find_class`, `marshal.loads`, `open_code` — which the kernel layer cannot distinguish from benign I/O.
- It fires *before* the syscall that a given Python operation would eventually dispatch, so when seccomp later denies that syscall, the audit event on the supervisor side explains *what Python-level operation produced it*. This turns `EPERM` from opaque into actionable.
- It supports conditional in-process policy (e.g. refusing a specific `import` in a context where the syscall-level policy would permit the subsequent file read). This is policy composition, not containment.

These events are written to the VAREK audit log and are used for:

- Post-hoc incident review and denial triage
- Anomaly detection on otherwise-benign code paths
- In-process advisory policy decisions that need Python-level semantics

What this layer is **not**: a containment boundary. The security guarantee does not depend on the hook firing. If a child evades, disables, or crashes the hook — or executes native code that bypasses the Python interpreter entirely — the kernel-enforced seccomp + cgroup + namespace boundary is still intact. The v1.1 architecture treats the hook as a useful layer above the boundary, never as the boundary itself.

---

## 5. Threat Model Revision

### In scope (v1.1 defends against)
- Hostile Python code attempting to spawn unauthorized binaries
- Hostile Python code attempting to open network connections (egress C2)
- Hostile native code loaded via `ctypes`, C extensions, or `os.exec*` — because the containment boundary is the kernel
- Resource exhaustion (forkbombs, memory bombs, CPU spinning) via cgroup caps
- Filesystem reconnaissance or tampering outside the scratch dir
- Kernel privilege escalation attempts via high-risk syscalls (`bpf`, `userfaultfd`, `ptrace`)

### Explicitly out of scope (v1.1 does **not** defend against)
- Kernel 0-days that bypass seccomp itself. Deployments requiring that threat model should select the gVisor backend when v1.2 ships it.
- Side-channel attacks (Spectre-class, timing, power). Mitigation is deployment-level (dedicated cores, CPU mitigations enabled).
- Data exfiltration via legitimate allowed channels. If a user's policy permits egress to `api.example.com`, hostile code can use that channel.
- Supply-chain compromise of the interpreter or VAREK itself.

---

## 6. Configuration Example

```yaml
# varek.policy.yaml
isolation:
  backend: seccomp_bpf           # seccomp_bpf | gvisor (v1.2) | job_object (v1.2)
  fail_closed: true              # no fallback to weaker backends

policy:
  binary_allowlist:
    - /usr/bin/python3.12
  syscall_profile: python.default
  filesystem:
    rootfs: readonly
    scratch_dir: /tmp/varek-scratch
    scratch_size_mb: 256
  network:
    egress: deny
  resources:
    memory_mb: 512
    cpu_quota_pct: 50
    pids_max: 64
    wall_clock_timeout_ms: 30000

telemetry:
  pep578_audit_hook: enabled     # visibility + advisory interception, not enforcement
  audit_log: /var/log/varek/audit.jsonl
```

---

## 7. Migration Path from v1.0

| v1.0 API | v1.1 replacement | Notes |
|----------|------------------|-------|
| `VarekInterpreter.add_deny_signature(s)` | **Removed.** Use `ExecutionPolicy.binary_allowlist`. | Denylists are unsound. |
| `VarekInterpreter.execute_with_audit_hook(...)` | `VarekRuntime.execute(payload, policy)` | Audit hook is now a visibility/advisory-interception layer; containment enforcement is in the backend. |
| `VarekInterpreter.register_audit_callback(cb)` | `VarekRuntime.subscribe_telemetry(cb)` | Signature preserved; semantics are now advisory. |

A shim maintains the v1.0 API surface for one minor version with a deprecation warning and a hard requirement that an `IsolationBackend` be configured. v1.0 code that relied on the audit hook for security will fail closed until a backend is set.

---

## 8. Deliverables for v1.1

- `varek/runtime/isolation/interface.vk` — trait + types
- `varek/runtime/isolation/seccomp/` — reference Linux backend
- `varek/runtime/isolation/seccomp/profiles/python.default.json` — versioned default profile
- `varek/runtime/audit_hook/pep578.vk` — repositioned audit hook (visibility + advisory interception, non-enforcement)
- `varek/runtime/runtime.vk` — `VarekRuntime::execute` dispatch
- PoC from issue #223 added to `tests/security/` as a regression test that **must fail to execute** under the default v1.1 policy
- `docs/security/isolation.md` — operator-facing documentation
- `docs/security/threat-model.md` — the in/out-of-scope table from §5

---

## 9. Deferred to v1.2+

- `GVisorBackend` — strongest isolation, adds runtime dependency
- `BubblewrapBackend` / `NsjailBackend` — middle-ground options for environments that can't run a custom seccomp filter
- `JobObjectBackend` — Windows support via Job Objects + AppContainer + Restricted Tokens
- GPU passthrough policy (required for ML code interpreter tools with legitimate accelerator needs)
- Fine-grained per-tool policy composition (e.g., "allow requests to api.openai.com only")

---

## 10. Credit

The v1.0 gap was identified by @dengluozhang in llamastack/llama-stack-apps#223. The PoC in that thread is being added to the VAREK regression suite verbatim.
