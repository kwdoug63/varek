# VAREK v1.9.2 — Mediation Completeness: Default-Deny Allowlist & ABI Lockdown

Released 2026-06-21 · MIT · github.com/kwdoug63/varek


## Summary

v1.9.2 is a hardening patch. It changes no verdict semantics and does not touch
the v1.9 progress-safety proof. It inverts the Warden baseline from
allow-plus-denylist to **default-deny allowlist**, locks the filter to the
**native ABI**, and couples the supervisor and target lifetimes. Together these
collapse most of the syscall-level bypass classes by construction rather than by
enumeration. The invariant is unchanged: **no extension may move a genuinely
unsafe action to SATISFIED.**

The companion `docs/security/bypass-classes.md` is the auditor-facing checklist:
every class, its status, and its mitigation. `docs/security/v1.10-architecture-
roadmap.md` records the model- and TCB-changing items that are deliberately *not*
in this patch (Landlock, acquisition-tier formalization, post-grant re-mediation,
the UNKNOWN escalation ladder, TCB shrink via proof-checking).

## Security

### Default-deny allowlist (replaces allow + denylist)

The baseline filter is now seeded with a denying default action; only an
explicit allowlist is admitted. Unknown syscalls, *variant* syscalls (`clone3`,
`openat2`, `faccessat2`, `pidfd_*`), and 32-bit multiplexers (`socketcall`,
`ipc`) are denied unless admitted — a bypass we did not enumerate becomes
"denied because we did not admit it." New: `v1_7/warden_seccomp_baseline.{c,h}`,
`v1_7/tests/test_v192_baseline_deny.c`.

### Native-ABI lockdown

The deny default applies across every architecture, and no secondary
architecture is added or admitted, so the same operation re-issued through the
32-bit compat ABI (`int 0x80`) or the x32 ABI (`__X32_SYSCALL_BIT`, 0x40000000)
hits the deny path. This is the most common real-world seccomp escape and is
invisible to a filter that reasons only in native syscall numbers. Asserted on
the live kernel by `v1_7/tests/test_v192_abi_lockdown.c` — **a failure there is
release-blocking.**

### Scalar-flag denial of unprivileged user namespaces

`clone`/`unshare` are filtered on the (scalar, race-free) flags argument to deny
`CLONE_NEWUSER` and the namespace-creation set — the root of a large fraction of
container escapes, because it grants `CAP_SYS_ADMIN` inside the new namespace.
`clone3` (pointer-flags, uninspectable at this layer) is hard-denied.

### Hard-deny set for never-admissible syscalls

`ptrace`, `bpf`, `userfaultfd`, `process_vm_readv/writev`, `pidfd_getfd`,
`setns`, the mount/FUSE family, the module/`kexec`/`perf_event_open`/`keyctl`
family, and `memfd_create` are denied with `SCMP_ACT_KILL_PROCESS` in strict mode
(demotable to `EPERM`). These map one-to-one to bypass classes 3–6.

### Supervisor/target lifecycle coupling

The target is SIGKILLed if the supervisor dies (`PR_SET_PDEATHSIG` plus a
re-parent re-check, with a cgroup.kill fallback); the supervisor watches the
target via pidfd. Injected fds carry `O_CLOEXEC` so a granted capability cannot
leak across `execve`. In-flight notifications are bounded; excess fails closed
and trips the v1.8.2 bounded-refusal breaker. New: `v1_7/warden_lifecycle.{c,h}`.

## Added

- `docs/security/bypass-classes.md` — bypass-class checklist and mediation-
  completeness argument (fold into / link from `THREAT-MODEL.md`).
- `docs/security/v1.9.2-baseline-allowlist.md` — allowlist rationale and
  class-to-syscall map.
- `docs/security/v1.10-architecture-roadmap.md` — the model/TCB-changing track.
- `v1_7/warden_landlock.c` — v1.10 skeleton (not wired into v1.9.2).

## Changed

- io_uring denial (v1.9.1) is retained inside the new allowlist's hard-deny set;
  it is now one instance of off-path dispatch handling, not a standalone rule.

## Notes

The standalone baseline, lifecycle module, and both tests **compile cleanly
against libseccomp and pass on a Linux x86_64 kernel** (`test_v192_abi_lockdown`:
native call admitted, x32 call killed; `test_v192_baseline_deny`: ptrace, bpf,
userfaultfd, process_vm_readv, pidfd_getfd, perf_event_open, and
clone/unshare(CLONE_NEWUSER) all denied). What remains before tagging is
**integration with the live `v1_7/` Warden init path** (wiring the builder ahead
of the unotify listener and seccomp_load) and a **run on your target kernel**,
since syscall availability and x32 support are kernel-version dependent. Treat an
x32 FAIL on the target kernel as release-blocking. The project is patent-pending;
nothing in this release is granted.
