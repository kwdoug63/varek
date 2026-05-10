# seccomp-unotify TOCTOU Reproducer

A minimal, self-contained harness that demonstrates the canonical
TOCTOU race on pointer-argument syscalls under `seccomp-unotify`, and
verifies that VAREK's Warden mitigation closes it.

The harness ships two supervisor implementations in one binary:

| Mode          | Strategy                                                                     | Expected outcome                |
|---------------|------------------------------------------------------------------------------|---------------------------------|
| `--naive`     | Read userspace path, allowlist check, return `SECCOMP_USER_NOTIF_FLAG_CONTINUE` | **Race wins** (sentinel leaks)  |
| `--mitigated` | Resolve path via `openat2(RESOLVE_NO_SYMLINKS \| RESOLVE_NO_MAGICLINKS)`, return resolved fd via `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND` | **Race loses** (zero leaks)     |

This is the supervisor pattern Warden uses in v1.3 for path-argument
syscalls. Whether it is *complete* against every variant of the race
is exactly the question we want external review to answer — see the
RFC issue thread.

## Threat model

- **Supervised process**: fully adversarial. May spawn `CLONE_VM`
  siblings (the harness uses `pthread_create`, which uses `CLONE_VM`)
  that share its address space and race to mutate the path buffer
  between supervisor read and kernel re-execution.
- **Supervisor**: privileged, isolated, **not co-resident** in the
  supervised process's `mm`.
- **Kernel**: trusted.

Out of scope for this harness: kernel exploits, side-channels,
`ptrace` from non-supervised privileged peers, `process_vm_writev`
from outside the seccomp domain, hypervisor escapes.

## Requirements

- Linux kernel **≥ 5.14** (for `SECCOMP_ADDFD_FLAG_SEND`)
- x86_64 (BPF arch check is hard-coded; trivially portable —
  patch `ARCH_NR` and rebuild)
- `CAP_SYS_ADMIN` or root (required to install seccomp filter and
  open `/proc/<pid>/mem`)
- `gcc` or `clang`, glibc with pthread

Quick check:

```sh
make check-kernel
```

## Build

```sh
make
```

## Run

```sh
sudo ./seccomp_toctou_harness --naive       50000
sudo ./seccomp_toctou_harness --mitigated   50000
```

The second argument is iteration count (default: 20000).
On a typical x86_64 box, a few thousand iterations is enough for the
naive path to leak; the mitigated path should report zero leaks at
any iteration count.

## Expected output

### Naive (race wins)

```
[super  ] mode=naive  notify_fd=4  pid=12345
[target ] iterations=50000  opens_succeeded=50000  sentinel_leaks=37
[result ] RACE WON  — sentinel observed; supervisor was bypassed.
```

The `sentinel_leaks` count is timing-sensitive. Higher iteration
counts, busier hosts, and higher core counts all increase the race
window. **Any non-zero count is a containment failure.**

### Mitigated (race loses)

```
[super  ] mode=mitigated  notify_fd=4  pid=12346
[target ] iterations=50000  opens_succeeded=50000  sentinel_leaks=0
[result ] RACE LOST — no sentinel observed.
```

`opens_succeeded` matches iterations because the supervisor resolves
the path itself and hands the kernel an fd via `ADDFD`; the kernel
never re-reads the userspace pathname pointer after notification.

## What this proves, and what it does not

**Proves**: For the specific class of pointer-argument race illustrated
here (string mutation by a `CLONE_VM` sibling), supervisor-side
resolution + `ADDFD` is sound where `CONTINUE`-based dispatch is not.

**Does not prove**:

1. That `ADDFD` re-issue is sound for *every* syscall class. Some
   syscalls have kernel-internal state that depends on the original
   calling thread's context (credentials at moment of call, mount
   propagation, audit context). The RFC issue calls this out
   explicitly as an open question.
2. That `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` covers every
   path-resolution attack. `RESOLVE_BENEATH` is also relevant for
   chroot-jailed targets but isn't always appropriate as a default.
3. That the `pidfd` + `/proc/<pid>/cwd` snapshot survives every
   namespace transition the target can perform. Namespace-transition
   completeness is question (3) in the RFC.

If you find a path the harness misses, please open an issue or send
a patch — that's the point of publishing this.

## Files

- `seccomp_toctou_harness.c` — the harness itself, ~400 lines, MIT.
- `Makefile`                   — build, run, and kernel-version check.
- `README.md`                  — this file.

## License

MIT. See SPDX headers.
