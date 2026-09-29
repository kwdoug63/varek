# VAREK Warden v1.4

Privileged seccomp-unotify supervisor for the VAREK runtime. Provides
kernel-level interception of selected syscalls in a supervised process,
supervisor-side path resolution, and structured decision logging.

## Overview

The Warden runs as a privileged parent process. It forks a child,
installs a seccomp filter in the child, and acquires the supervisor
side of the unotify channel via `SCM_RIGHTS`. Trapped syscalls in this
release: `openat`, `connect`, `execve`, `execveat`. Other syscalls are
allowed through the BPF filter.

For each notification, the Warden:

1. Materializes pointer arguments via `/proc/<pid>/mem`, guarded by
   `SECCOMP_IOCTL_NOTIF_ID_VALID`.
2. Derives a structured `Action {kind, target, parameters}` from the
   raw syscall number, arguments, and per-pid Execution Context.
3. Evaluates the Action against the configured policy, returning
   `ALLOW`, `DENY`, or `UNKNOWN`. `DENY` and `UNKNOWN` both surface
   to the kernel as `EPERM` (symmetric suppression).
4. For path-argument syscalls on `ALLOW`, resolves the path itself
   with `openat2(RESOLVE_NO_MAGICLINKS)` rooted at `/proc/<pid>/cwd`
   (ordinary symlinks followed since v1.12.3, deciding on the object's
   canonical path; `/proc/self` mapped to the agent), and returns the
   resolved descriptor through
   `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`. The
   kernel does not re-read the userspace pathname pointer.
5. Emits a JSON pathology record with `CLOCK_MONOTONIC` decision
   latency in microseconds.

## Layout

| File                  | Purpose                                                         |
|-----------------------|-----------------------------------------------------------------|
| `warden.c`            | Supervisor binary. Single-file C11.                             |
| `policy.txt`          | Sample policy in the rule format the Warden parses.             |
| `target_demo.c`       | Small workload exercising each trapped syscall path.            |
| `bench_target.c`      | Workload for driving N trapped syscalls under the supervisor.   |
| `bench_summarize.py`  | Parses pathology records into percentile latency statistics.    |
| `checker/`            | v1.15 independent certificate checker.                          |
| `tools/`              | `vdp_check`, `vdp_cert_check`, `varek_keygen` (v1.16), the audit, the CycloneDX exporter, the cross-check. |
| `Makefile`            | `make`, `make run-demo`, `make run-bench`, `make check-kernel`. |

## Requirements

- Linux kernel ≥ 5.14 (`SECCOMP_ADDFD_FLAG_SEND`).
- x86_64. The BPF arch check in `warden.c` is hardcoded; porting to
  another architecture requires updating `ARCH_NR`.
- `CAP_SYS_ADMIN` (run as root or via `sudo`). The Warden checks for it
  at startup and refuses to run without it, because it creates the
  target's PID namespace (see below). It also covers reading
  `/proc/<pid>/mem`.
- libseccomp and, from v1.16, libsodium development headers:
  `sudo apt-get install -y build-essential libseccomp-dev libsodium-dev`
  (Debian/Ubuntu) or `sudo dnf install -y gcc make libseccomp-devel
  libsodium-devel` (Fedora/RHEL). `make deps` runs the right one; `make`
  stops with that command if they are missing.

## Lifecycle coupling (v1.9.3)

The target runs as init (PID 1) of a dedicated PID namespace and is
SIGKILLed if the Warden dies, so the agent and every process it spawned
stop with the supervisor, whether the Warden exits normally or crashes.
The Warden refuses to start without `CAP_SYS_ADMIN` or if it cannot
create the namespace. Setting `VAREK_WARDEN_NO_PIDNS=1` skips the
namespace and the capability check (with a warning); in that mode the
agent itself still dies with the Warden, but processes it spawned are
not guaranteed to on a crash.

Inside the namespace the agent sees its own PID as 1 and `getppid()`
returns 0. Pathology records report the host PID.

```sh
make test-lifecycle
```

The test kills a live Warden (`SIGKILL`, then `SIGTERM`) while it
supervises an agent that has spawned a child, and fails if any agent
process survives.

For a screen recording, `sudo ./lifecycle_video.sh` runs the same crash
against the pre-fix Warden (built from git, `BEFORE_REF`, default
`v1.9.3^`) and against this one, with pacing and colour.

## Conformance target

```sh
make run-conformance
```

Builds `target_conformance` (static), creates its work directory
`/tmp/varek_conf`, and runs it under the Warden. The target cannot
create that directory itself under enforcement; if it is missing, the
target reports a `setup` failure rather than a boundary failure.

## Build

```sh
make deps            # once: libseccomp and libsodium headers (sudo)
make check-kernel
make
```

## Before you deploy: preflight (v1.16.1)

From v1.16 the Warden refuses to start when the policy would let the agent open
its own verdict stream file (the file its stderr goes to), its signing key, its
anchor or, with a key or anchor, a raw disk. Check a deployment without running
anything:

```sh
tools/varek_preflight.sh policies/finance.policy.txt --log /var/log/varek/verdicts.log \
    --sign-key /etc/varek/log.key --anchor /var/log/varek/anchor.log
```

It checks the build dependencies, builds, loads the policy, and decides each
location exactly as the Warden will (`tools/vdp_cert_check <policy> openable`).
Add `--run` for a real trial run (as root) whose stream is written next to the
log and audited. Put the verdict stream outside every path the policy allows:
`/var/log/varek/` works with every shipped policy; a stream in the agent's
scratch space (`/tmp/varek/` in the sector policies) is refused.

## Demo

```sh
sudo ./warden policy.txt -- ./target_demo
```

The target workload issues five trapped syscalls covering the three
syscall categories (file open, network connect, process exec). The
Warden emits one JSON pathology record per decision to stderr.

## Benchmark

```sh
sudo ./warden policy.txt -- ./bench_target 10000 2> bench.log
python3 bench_summarize.py bench.log
```

`bench_summarize.py` reads the JSON pathology records from the
Warden's stderr log and prints decision counts, percentile latencies,
and soundness metrics derived from the actual run.

## Policy format

One rule per line. First match wins. No match returns `UNKNOWN`,
which is suppressed.

```
require warden <major>.<minor>      (v1.13: an older Warden refuses the file)
<verb> <kind> [matcher] <constant> [flag-clause ...]
  verb     := allow | deny
  kind     := path | host | exec
  matcher  (path and exec only, v1.14):
          exact                    the whole string equals the constant
          prefix                   starts with it (the default for path)
          suffix                   ends with it
          contains                 contains it
          glob                     matches the glob (below), anchored
  constant := without a matcher: a prefix (path), "host:port" or "host"
          (host), an absolute path (exec)
  flag-clause (path only, v1.13):
          readonly                 access=ro -O_CREAT -O_TRUNC
          access=ro|wo|rw          the O_ACCMODE bits only
          +O_NAME | -O_NAME        bit must be set | clear
```

Glob syntax (v1.14), matched against the whole resolved path:

| Pattern | Matches |
|---|---|
| `?` | one byte other than `/` |
| `[abc]`, `[a-z]`, `[!a]` / `[^a]` | one byte from the set; never `/` (a `/` inside is refused) |
| `*` | zero or more bytes, none of them `/` |
| `**` | zero or more bytes of any value |
| `/**/` | a `/`, then zero or more whole segments: `/a/**/b` matches `/a/b` and `/a/x/y/b` |
| `\x` | the byte `x` literally |

At most 32 wildcards per glob; `***` is refused. Matching is byte-wise and
case-sensitive (`suffix .pem` does not match `KEY.PEM`; write `glob
**.[pP][eE][mM]`). A keyword is read as a matcher only when a constant
follows it that is not itself a flag clause, so every v1.13 policy keeps its
meaning.

```
require warden 1.14
deny  path suffix .pem                              # key material under any allowed tree
deny  path glob /**/.env                            # dotenv files at any depth
deny  path glob /var/lib/ehr/records/*/psychotherapy/**
allow path exact /etc/hosts readonly                # this file, not /etc/hosts.allow
allow path /var/lib/ehr/records/
```

Every rule is decided by the SMT decision procedure in `smt_decide.c`
(v1.13). A path rule is matched on the resolved canonical path, so name
canonical prefixes (`/usr/lib/`, not `/lib/`) and end directory prefixes
with `/`. Matchers judge that path's name, not the file's identity: a
pre-existing hard link under another name is decided by its own name. When
the Warden enforces, the agent itself cannot create links or rename files
(those syscalls are refused); in observe mode (`VAREK_WARDEN_OBSERVE=1`)
they are only logged, so name matchers are not a boundary there. `access=ro` alone is not read-only on Linux (`O_RDONLY|O_TRUNC`
truncates, `O_RDONLY|O_CREAT` creates); use `readonly`. A clause
constrains the flags passed to `openat()`: `readonly` is sound, but
`fcntl(F_SETFL)` can change `O_APPEND`, `O_NONBLOCK`, `O_ASYNC`,
`O_DIRECT` and `O_NOATIME` afterwards (the Warden notes such clauses).
Access mode 3 and unknown flag bits are refused. More than 256 rules,
an unknown or contradictory clause, a malformed glob, a matcher on a host
rule, a control byte in a constant, or an unmet `require` is a load error.
Start a policy that uses flag clauses with `require warden 1.13` (a v1.12
Warden would silently ignore them), and one that uses matchers with
`require warden 1.14`.

Lines beginning with `#` are comments, and `#` also starts a trailing
comment. See `policy.txt` and `policies/` for examples, and check a policy
with `tools/vdp_check <policy> lint`, which reports every rule that can
never fire (v1.14: `vdp_check <policy> analyze` also prints, for every
reachable rule, a shortest path and flags value on which it is the first
rule to hold).

## Certificates (v1.15)

Every SATISFIED verdict carries a certificate: the deciding rule's index and a
witness that its constant matches (none for prefix / exact / suffix / host, an
offset for `contains`, one span per `*`, `**` and `/**/` for a `glob`). Before a
file open is authorized, the independent checker in `checker/vdp_checker.c` —
its own policy parser and matchers, no code shared with `smt_decide.c` — must
accept it: the deciding rule is an allow rule whose flag clause holds, the
witness proves its constant matches, and no earlier rule holds. A refused
certificate denies the open (`"rule":"certificate_refused"`). The policy file is
read once and both parse the same bytes, whose SHA-256 goes in `run_start`.

```
tools/vdp_cert_check policy.txt digest       # the SHA-256 the Warden records
tools/varek_audit.py --policy policy.txt --checker tools/vdp_cert_check verdicts.log
```

The audit authenticates the stream, checks the policy file's SHA-256 against
`run_start`, and re-checks every authorization's certificate. The format and
the checking rules are specified in `checker/vdp_checker.h`.

A policy's globs may total at most 4,096 tokens (v1.16); with the 4,095-byte
length bound this bounds the work of one decision (tens of milliseconds for
adversarial policies, microseconds for real ones). `tools/vdp_check <policy> lint` reports the
policy's glob size.

## Log integrity (v1.16)

The verdict stream is hash-chained: every record of a run ends with
`"chain"`, SHA-256 of the previous chain value and the record's bytes. With a
signing key, run_start, a checkpoint every 64 records (and at least once a
second) and run_end are signed with Ed25519; with an anchor, each of those is
also appended to a file, FIFO or device that the log's holder cannot rewrite.

```
tools/varek_keygen /etc/varek/log.key        # log.key (0600) + log.key.pub
sudo ./warden policy.txt --sign-key /etc/varek/log.key --anchor /var/varek/anchor \
    -- ./agent 2> verdicts.log
tools/varek_audit.py --policy policy.txt --checker tools/vdp_cert_check \
    --pubkey /etc/varek/log.key.pub --anchor /var/varek/anchor verdicts.log
```

The Warden refuses to start if the policy would let the agent open the key,
the anchor, the verdict stream file or a raw disk. The audit's `integrity:` line says how far the stream is protected
against its holder (`none`, `chain`, `signed, key not pinned`, `signed`,
`signed, anchored`). See `RELEASE-v1.16.0.md` for what remains (a key holder
without an anchor, the unanchored tail of an unfinished run, root on the host
during the run).

## Threat model

- **Supervised process**: fully adversarial. May spawn `CLONE_VM`
  siblings that share its address space.
- **Supervisor**: privileged, isolated, not co-resident in the
  supervised `mm`.
- **Kernel**: trusted.

Out of scope for this implementation: kernel exploits, hypervisor
escapes, side-channels, `ptrace` from privileged peers outside the
seccomp domain.

A reproducer for the canonical seccomp-unotify TOCTOU race on
pointer-argument syscalls is at `test/seccomp_toctou_harness.c`.

## Scope

In scope:

- Privileged seccomp-unotify supervisor.
- Supervisor-side path resolution for `openat` via `openat2 + ADDFD`.
- Sockaddr inspection for `connect`.
- Path-based decisions for `execve` and `execveat`.
- JSON pathology records with measured decision latency.

Tracked separately, not part of this release:

- Workflow-graph (whole-plan) verification.
- BPF-LSM enforcement path.
- Compliance-framework mappings in pathology output.
- Multi-host coordination.

## References

- M. Sarai, *Adventures in implementing seccomp notify* (LWN, 2020).
- `seccomp_unotify(2)`, `openat2(2)` man pages.
- LKML threads on `SECCOMP_IOCTL_NOTIF_ADDFD` introduction.

## License

MIT. See SPDX headers in source files.

## Running the included demo

The default policy allows standard system binaries but not the test
programs in this directory. Append the demo binaries before running:

```sh
echo 'allow exec ./target_demo'  >> policy.txt
echo 'allow exec ./bench_target' >> policy.txt
sudo ./warden policy.txt -- ./target_demo
```
