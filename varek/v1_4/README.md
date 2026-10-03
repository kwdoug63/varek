# VAREK Warden v1.4

Privileged seccomp-unotify supervisor for the VAREK runtime. Provides
kernel-level interception of selected syscalls in a supervised process,
supervisor-side path resolution, and structured decision logging.

## Overview

The Warden runs as a privileged parent process. It forks a child,
installs a seccomp filter in the child, and acquires the supervisor
side of the unotify channel with `pidfd_getfd` (v1.12; through v1.9.3,
`SCM_RIGHTS`). The filter is default-deny (v1.9.2): the calls it routes to
the Warden are `openat`, `connect`, `execve`, `execveat`, the metadata
lookups (`newfstatat`, `statx`, `access`, `faccessat`, `faccessat2`,
`readlink`, `readlinkat`), `sendmsg`, `sendmmsg`, `bind`, and `sendto` when it
names a destination or sets `MSG_FASTOPEN` (v1.21); the rest are admitted or refused by the filter
itself (`warden_baseline_filter.c`). *(Correction, v1.21.0: through v1.20.0
this paragraph described the v1.4 prototype: four trapped calls, everything
else allowed, the listener passed with `SCM_RIGHTS`.)*

For each notification, the Warden:

1. Materializes pointer arguments via `/proc/<pid>/mem`, guarded by
   `SECCOMP_IOCTL_NOTIF_ID_VALID`.
2. Derives a structured `Action {kind, target, parameters}` from the
   raw syscall number, arguments, and per-pid Execution Context.
3. Evaluates the Action against the configured policy, returning
   `ALLOW`, `DENY`, or `UNKNOWN`. `DENY` and `UNKNOWN` both surface
   to the agent as `EACCES` (symmetric suppression), and the record's
   `kernel_verdict` says `EACCES`. A system call the filter neither
   admits nor mediates is handled by the filter itself and not recorded:
   most get `EPERM`, a hard-denied one (`ptrace`, `bpf`, `io_uring_enter`
   and the others in `warden_baseline_filter.c`) kills the agent, and
   `clone3` and (v1.21) `io_uring_setup` get `ENOSYS` so that libc falls
   back to `clone` and libuv to epoll. From v1.21 the filter also answers
   `setsockopt` with `EACCES` for the options that would route a connected
   socket's packets elsewhere (`IP_OPTIONS`, `IPV6_RTHDR`,
   `IPV6_2292RTHDR`, `IPV6_2292PKTOPTIONS`).
4. For path-argument syscalls on `ALLOW`, resolves the path itself
   with `openat2(RESOLVE_NO_MAGICLINKS)` rooted at `/proc/<pid>/cwd`
   (ordinary symlinks followed since v1.12.3, deciding on the object's
   canonical path; `/proc/self` mapped to the agent), and returns the
   resolved descriptor through
   `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`. The
   kernel does not re-read the userspace pathname pointer.
5. For `connect` on `ALLOW` (v1.21), dials the destination it decided on
   itself, from its own network namespace, with a socket of the agent's
   kind carrying the options the agent set, and puts the connected socket
   in place of the agent's descriptor (`SECCOMP_IOCTL_NOTIF_ADDFD` with
   `SECCOMP_ADDFD_FLAG_SETFD`). See "Decided connections" below.
6. Emits a JSON pathology record with `CLOCK_MONOTONIC` decision
   latency in microseconds.

## Quick start: the `varek` command (v1.22)

`tools/varek` wraps the Warden and its tools in one command and keeps their
shared settings in `/etc/varek/varek.conf`:

```sh
make deps && make && sudo make install     # /opt/varek, plus /usr/local/bin/varek
sudo varek doctor                          # is this host ready?
sudo varek init --pack healthcare          # settings, signing key, log directory
sudo varek preflight --run                 # a real trial run, then its audit
sudo varek run -- python3 agent.py         # supervise an agent
varek refusals                             # what the last run refused, and why
sudo varek audit                           # re-check certificates, chain, signatures
sudo varek export                          # signed CycloneDX 1.6 evidence
varek export --verify <file>.cdx.json      # anyone can check that evidence
sudo varek bench                           # what mediation costs per call on this host
```

`varek policy list|show|check|use|add` manages policies, `varek runs` and
`varek status` show history, and `--show-commands` prints the underlying tool
calls. `make test-cli` runs its tests (root, Linux).

### Measuring the cost: `varek bench`

`sudo varek bench` runs a fixed workload (`tools/bench_workload`) natively and
as the agent under the Warden, five times each, alternating, and reports for
six kinds of call (an allowed, a denied and an unmatched file open; an allowed
and a denied connect; a small whole request on loopback):

- the time the call took natively and under the Warden, as the agent timed it
  (p50 / p90 / p99), and the difference ("added");
- the Warden's own decision time, from its verdict records (`latency_us`;
  for a connect it includes dialing the destination, `dial_us`);
- checks on every verdict: each allowed call was certified and succeeded, each
  denied or unmatched call was refused with `EACCES`, and the listener behind
  the denied destination was never reached. A failed check makes it exit 1.

It decides with the active policy's rules followed by five rules of its own
(`--policy <pack or file>` for another policy, `--bare` for its own rules
only), so the cost of a real policy is in the numbers; if a rule of that
policy decides one of the bench's calls differently, the check names the line.
It signs its verdict streams when `varek init` set up signing (`--no-sign` to
skip), keeps them out of `/var/log/varek`, and removes everything it made
unless `--keep`. `-o results.json` saves every number and check;
`--max-added-p50 <us>` fails the run (exit 1) if any kind of call adds more
than that, for CI. The numbers are for the host they were measured on, and
its listeners are ordinary loopback ports: another local user connecting to
the bench's denied port during a run makes that check fail.
Results for v1.21.1: [`bench_results_v1_21_1.txt`](bench_results_v1_21_1.txt).

## Layout

| File                  | Purpose                                                         |
|-----------------------|-----------------------------------------------------------------|
| `warden.c`            | Supervisor binary. Single-file C11.                             |
| `policy.txt`          | Sample policy in the rule format the Warden parses.             |
| `target_demo.c`       | Small workload exercising each trapped syscall path.            |
| `bench_target.c`      | v1.4 workload for driving N trapped syscalls under the supervisor (`make run-bench-v14`). |
| `bench_summarize.py`  | Parses pathology records into percentile latency statistics.    |
| `tools/varek_bench.py`, `tools/bench_workload.c` | v1.22 `varek bench`: native vs Warden, per kind of call, every verdict checked (`make run-bench`). |
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
anchor or, with a key or anchor, a raw disk. Check a deployment before running
it:

```sh
tools/varek_preflight.sh policies/finance.policy.txt --log /var/log/varek/verdicts.log \
    --sign-key /etc/varek/log.key --anchor /var/log/varek/anchor.log
```

It checks the build (building only if the binaries are out of date), loads the
policy, and checks each location with the Warden's rules
(`tools/vdp_cert_check <policy> openable`). Add `--run` for a real trial run
(as root) whose stream is written next to the log and audited; that is the
definitive test. Put the verdict stream outside every path the policy allows:
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
  constant := without a matcher: a prefix (path), an absolute path
          (exec), or for host: a.b.c.d:port, a.b.c.d (any port),
          [IPv6]:port, [IPv6] (any port, v1.21) or unix:/path (exact),
          matched against the destination as the Warden spells it; a host
          name never matches (v1.21 stage 2), and lint says so
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
make                                         # builds tools/varek_keygen too
sudo mkdir -p /etc/varek                     # as root from here on
sudo tools/varek_keygen /etc/varek/log.key   # log.key (0600) + log.key.pub
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

## Off-host anchor (v1.16.2)

An anchor file on the Warden's own host does not protect against that host's
root, who also holds the signing key. To close that, send the anchor to a
second machine the Warden host's root cannot administer, as it is written:

1. **On the Warden host** (as root): make the forwarder's SSH key
   (`ssh-keygen -t ed25519 -N '' -f /etc/varek/anchor_ssh_key`).
2. **On the anchor host** (any small Linux server, as root):
   `tools/varek_anchor_receiver.sh --name <warden-host> --pubkey '<contents of
   anchor_ssh_key.pub>'`. It creates an account whose only access is to append
   well-formed anchor lines to an append-only (`chattr +a`) file, and prints
   the host key's fingerprint.
   Then, **on the Warden host**: pin the anchor host's key
   (`ssh-keyscan -t ed25519 <anchor-host> > /etc/varek/anchor_known_hosts`,
   and compare `ssh-keygen -lf` of it with the printed fingerprint), install
   `tools/systemd/varek-anchor-forward.service` with the anchor host's name,
   and `systemctl enable --now varek-anchor-forward`.
3. **Run the Warden** with `--anchor /run/varek/anchor.fifo`. The forwarder
   sends each checkpoint within about a second, spools through outages, and
   resends after restarts.
4. **Check it**: `tools/varek_preflight.sh <policy> --log ... --sign-key ...
   --anchor /run/varek/anchor.fifo --spool /var/lib/varek/anchor-spool --run`.
5. **Audit** with the anchor host's copy: copy
   `/srv/varek-anchor/<warden-host>.anchor.log` from the anchor host (not through
   the forwarder's key, which can only append) and pass it as `--anchor`.

Who can do what, afterwards:

- **Someone who holds the logs but not the key** can change nothing before the
  last signature.
- **This host's root, who holds the key,** can change nothing that reached the
  anchor host. What has not been delivered yet (the last second or so, or
  everything since the anchor host became unreachable) is still open to it.
- **The receive times** that the anchor host records make that visible.
  `varek_audit.py` prints the delay, `--max-anchor-delay` enforces a limit, and
  `--list-runs` shows every run the anchor holds, so pick the run to audit
  there.
- **The anchor host's root** can lift the append-only attribute, so keep that
  machine under separate control.

## Plan gate (v1.6, v1.18.0)

`--plan <plan.txt>` checks a declared action-graph before the agent starts; the
agent is not started unless it is SATISFIED. Each `file_open` step is decided
by the SMT decision procedure on its lexically canonical path. A
`process_exec` step is UNSATISFIED, since v1.18.0: the runtime refuses every
launch after the agent's own, whatever the policy says. A `net_connect` step is
decided like the connect it names (v1.21: `a.b.c.d:port`, `[IPv6]:port`, or
`unix:/path` lexically canonicalized); a host name is UNKNOWN until stage 2.
From v1.18.0 to v1.20.0 every `net_connect` step was UNSATISFIED.

`--flow-policy <cfg>` (v1.18.0) adds, with a label policy in the v1.7 format
(`v1_7/example_policy.cfg`):

- **the data-flow check (v1.7).** Steps reach the flow policy as actions named
  by their kind, with the argument `target` (for a `file_open`, the canonical
  path) and, since v1.20.0, every field the step declares after its target
  (`action r file_open /srv/in/msg contains="a customer record"`; see
  `v1_6/plan_parser.h`). A plan whose edges carry a sticky label to a step that
  denies it is refused, and `[warden] plan flow pathology:` names the flow.
- **declared fields (v1.20.0).** Fields reach the flow policy; the runtime
  sees the target alone, and so does the node check apart from one field,
  `open` (next item). The agent writes its plan, so
  declaring or omitting a field changes which rule applies: a rule that
  permits on a field is unlocked by declaring it, a rule that refuses on a
  field is avoided by leaving it out, and a field rule placed before a stricter
  one skips it. The Warden refuses to start with a flow policy whose rules match
  a field (anything but `target`) unless it declares `trust_declared_fields`.
  Fields help an honest planner say more about its steps; like the edges, they
  are not evidence. A changed value makes a new plan for the breaker (its own
  per-plan count), so the session limit is what bounds that.
- **how a file is opened (v1.21.1).** A step carries no open flags, so a
  `file_open` step whose path is allowed only by a rule with a flag clause
  (`readonly`, `access=ro`, `-O_TRUNC`, ...) was UNKNOWN at the gate although
  the runtime allowed the same open. A `file_open` step may declare its flags
  in an `open` field, which the node check reads: `open=read` (`O_RDONLY` and
  nothing else, what `readonly` allows) or an access mode followed by flags,
  `open=O_WRONLY|O_CREAT|O_TRUNC` (`O_RDONLY`, `O_WRONLY` or `O_RDWR` first,
  then any of `O_CREAT`, `O_EXCL`, `O_NOCTTY`, `O_TRUNC`, `O_APPEND`,
  `O_NONBLOCK`, `O_DSYNC`, `O_ASYNC`, `O_DIRECT`, `O_LARGEFILE`,
  `O_DIRECTORY`, `O_NOFOLLOW`, `O_NOATIME`, `O_CLOEXEC`, `O_SYNC`, `O_PATH`,
  `O_TMPFILE`, each once). The step is decided and certified with exactly
  those flags. A name has the value an agent's `open()` passes for it
  (`O_SYNC` and `O_TMPFILE` as glibc's composites); `O_LARGEFILE` is the
  kernel's bit, as in a policy's flag clauses. Like every declaration, the field does not bind the agent: an
  open with other flags is decided on its own flags at run time. A value in
  any other form, a repeated flag, or an `open` field on another kind of step
  makes the step UNKNOWN, with the reason logged. Without the field a step is
  decided as before. The field also reaches the flow policy like any other.
- **the refusal breaker (v1.8.2).** Each refused plan counts against
  (`--session <id>`, default `default`; the plan's signature). The signature
  covers the plan's steps and edges: reordering distinct steps or edges, or
  repeating an edge, does not start a new count (swapping two identical steps
  does), and distinct graphs never share one. After the
  policy's `refusal_budget` the outcome latches to its `on_exhaustion`
  disposition; an UNKNOWN goes straight to `unknown_disposition`.
- **the session's limit (v1.19.0).** Each refused plan also counts against its
  session, whatever the plan (an UNKNOWN counts; resubmitting a plan that is
  already terminal does not). The refusal that reaches the policy's
  `session_refusal_budget` is terminal, and so is every later refused plan in
  the session, whatever it is: they get `on_exhaustion` (a plan already
  terminal keeps its own outcome, and an UNKNOWN gets `unknown_disposition`). `refusal_budget` alone let a planner that
  changed one step each time start a new count every time. An authorized plan
  still runs in an exhausted session, and does not reset its count.
- **the progress-safety check (v1.9).** At startup: the Warden refuses to start
  unless every refusal ends in an automated outcome, and unless the policy
  declares a `refusal_budget` (the Warden's own policy can always refuse) and a
  `session_refusal_budget`.

The breaker's table lives in `--breaker-state <dir>/<name>` (default
`/var/lib/varek/breaker.state`). The Warden refuses to start unless `<dir>` is
owned by its user and writable by no one else, the table (if present) and
`<name>.lock` are regular files of its user writable by no one else, and the
policy lets the agent open none of them. The lock is held while the gate reads,
steps and writes the table, not while the agent runs. The table is written to
`<name>.tmp` and renamed into place, so an interrupted write leaves the previous
table; a table that does not read back (empty, cut short, altered) refuses the
plan with exit 1. Every file in the state directory, including a table a
concurrent Warden writes later, is refused to the agent by identity (the
directory's), like the signing key, whatever path through the directory
reaches it, a bind mount included.

Outcome: when the plan is refused, the agent never runs and the Warden exits 3
(the host may submit a different plan), 4 (terminal deny) or 5 (terminal: the
message names the pre-authorized action the host must run); 1 on an error. When
it is authorized, the Warden exits with the agent's status, which can also be 3,
4 or 5. A host that acts on the outcome reads `--gate-status <file>`, one line
written before the agent starts (`PASS`, `REFUSED_RETRYABLE n/budget session
m/limit`, `TERMINAL_DENY`, `TERMINAL_ACTION <name>` or `ERROR ...`; empty if
the gate never decided), or the `plan_gate` record in the verdict stream, which
also carries `session_refusals`, `session_budget` and `session_exhausted`. The status file
gets the state files' checks: its directory and the file must be private to the
Warden's user, and the policy must not reach it.

The counts are per session and per state file, and whoever starts the Warden
chooses both. It bounds a host that resubmits through a launcher it does not
control (a service unit or wrapper that fixes `--session` and
`--breaker-state`); a host that can choose them can start a new count.

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

## Decided connections (v1.21)

Through v1.20.0 every connect was refused whatever the policy said
(`deny_only_nonfile_v191`): letting an allowed connect continue in the kernel
would let a second thread change the destination after the check. From v1.21:

1. The destination is copied once from the agent's memory.
2. It is spelt as the decision is made: `a.b.c.d:port`, `[IPv6]:port` (an
   IPv4-mapped address as its IPv4 form), or, for a Unix socket named by a
   path, `unix:<canonical path>` after resolving it like a file open.
3. The SMT decision procedure decides it against the `host` rules; the
   independent checker must accept the certificate of an ALLOW.
4. The Warden makes a socket of the agent's kind in its own network namespace
   (the agent's has no working interface), copies over each option the agent
   set that differs from a fresh socket in the agent's namespace, for the 58
   options in the Warden's list (`k_sockopts` in `warden_net.inc.c`; the
   connect fails if one cannot be copied). An option outside the list set
   before the connect (`SO_TIMESTAMPING`, `TCP_QUICKACK`, a socket filter,
   `TCP_ULP`, ...) is not carried; options set after the connect apply to the
   connected socket as usual. It then connects the socket to the copy it
   decided on; a Unix connect is made with the agent's uid and gid, so the
   socket's permissions and the server's `SO_PEERCRED` see the agent, not
   root.
5. The connected socket replaces the agent's descriptor (same number, the
   agent's close-on-exec and non-blocking state), and the agent's connect
   returns what its own would have: 0, `EINPROGRESS` for a non-blocking socket,
   or the dial's errno.

A blocking connect that is still in progress is finished asynchronously: the
agent's thread waits while the Warden answers other requests, and is answered
when the socket connects, fails, or reaches the agent's `SO_SNDTIMEO`
(`EINPROGRESS`, as the kernel does). Records carry `"sock"` (tcp, udp,
unix-stream, ...) and `"dial_us"`; `latency_us` minus `dial_us` is the
Warden's own time.

Sends: `sendto` with no destination is admitted by the filter; `sendmsg` and
`sendmmsg` with no destination and no control data are sent by the Warden on
TCP and UDP sockets; a send naming a destination is refused. `bind` is
performed by the Warden for the wildcard address and port 0 only (libuv binds
UDP sockets so); `listen` and `accept` stay refused. Refused whatever the
policy says: abstract and unnamed Unix addresses, IPv6 scope ids, `AF_UNSPEC`,
other families and socket kinds, `MSG_FASTOPEN`, `IP_OPTIONS` and IPv6 routing
headers.

Known differences from a native connect: a descriptor `dup`'d from the socket
before the connect keeps the agent's original, unconnected socket; a Unix
server sees the Warden's pid in `SO_PEERCRED` (with the agent's uid and gid);
a blocking connect repeated while the first is still in progress gets
`EALREADY` at once rather than waiting.

`make test-v1210` runs the probe, the records and their audit, the plan gate,
curl, Python `requests` and Node.js as the agent, a live CDN fetch by address
where the host can reach one, and the per-connection latency.

## Scope

In scope:

- Privileged seccomp-unotify supervisor.
- Supervisor-side path resolution for `openat` via `openat2 + ADDFD`.
- Decided connections for `connect` (v1.21): TCP and connected UDP over IPv4
  and IPv6, Unix sockets by path; the Warden dials and hands over the socket.
  IPv6 dialing was not exercised on the release host (no IPv6 in its kernel;
  the test reports it SKIPPED).
- Path-based decisions for `execve` and `execveat`.
- JSON pathology records with measured decision latency.
- Whole-plan verification before launch (`--plan`), with the data-flow check,
  refusal breaker and progress-safety check under `--flow-policy` (v1.18.0).

Tracked separately, not part of this release:

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
