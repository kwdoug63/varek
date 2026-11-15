# macOS, natively: the Warden on Apple's Endpoint Security (design note)

Status: **draft, not scheduled** (started November 13, 2026). No release
number until it is decided; security operations is v1.39.0 and comes first
(`docs/roadmap/v1.36-v1.37.md`). Nothing below is built but the probe.
Facts about Apple's frameworks were from Apple's documentation as we
understood it; M1 to M4, and M6 in part, were measured on an EC2 Mac on
November 15, 2026 ("Measured", below), and three of them were not as we
understood: the design below is revised for them.

What starts it: on November 13, 2026, Apple assigned the Endpoint Security
entitlement (`com.apple.developer.endpoint-security.client`) to the
project's Apple Developer account, as a managed capability.

## Why

Since v1.37.0 an agent on a Mac runs inside a RHEL 9 VM, under the Linux
Warden (`docs/security/v1.30-macos.md`). That keeps one Warden and one set
of semantics, at a cost:

- the agent sees only the project, not the Mac: a Mac tool it is meant to
  use (Xcode, `swift`, Homebrew's tools, the Keychain through `security`,
  a GUI app's CLI) is not there;
- a VM to make, register with Red Hat, keep up to date and start (about a
  minute cold), 4 GiB of the Mac's memory, and a disk;
- the Mac's own processes are not under it at all (an agent run on the Mac
  directly, as most are today, is not supervised).

A Warden on the Mac itself would supervise the agent where it already
runs, with the Mac's own tools.

## What Endpoint Security gives

An Endpoint Security client (`es_new_client`) subscribes to events about
other processes. **AUTH** events hold the operation until the client
answers allow or deny, before a deadline; **NOTIFY** events report after the
fact. Among the AUTH events (macOS 13 to 15):

| The Warden decides on Linux | The AUTH event |
|---|---|
| a launch (`execve`) | `AUTH_EXEC` (the file, its signing information, argv, env) |
| an open, with its flags | `AUTH_OPEN` (answered with the flags allowed, `es_respond_flags_result`; but a read-write open answered read-only is refused whole, EPERM, not given a read-only descriptor: M3) |
| create, unlink, rename, link, truncate | `AUTH_CREATE`, `AUTH_UNLINK`, `AUTH_RENAME`, `AUTH_LINK`, `AUTH_TRUNCATE` |
| chmod, chown, utimes, xattrs | `AUTH_SETMODE`, `AUTH_SETOWNER`, `AUTH_UTIMES`, `AUTH_SETEXTATTR`, ... |
| chdir, readlink, readdir | `AUTH_CHDIR`, `AUTH_READLINK`, `AUTH_READDIR` |
| mmap / mprotect with exec | `AUTH_MMAP`, `AUTH_MPROTECT` |
| a signal, ptrace, another task's port | `AUTH_SIGNAL`, `AUTH_GET_TASK`, `AUTH_PROC_SUSPEND_RESUME` |
| a Unix socket's bind and connect | `AUTH_UIPC_BIND`, `AUTH_UIPC_CONNECT` |
| mount | `AUTH_MOUNT`, `AUTH_REMOUNT` |

The file in an event is the kernel's (`es_file_t`: its path and its
`stat`), the object the operation is on, so the decision is on what is
delivered, as on Linux, not on a name read twice. A process is named by
its audit token; NOTIFY_FORK and NOTIFY_EXIT give the tree. Muting, and
since macOS 13 inverted muting, let the client receive events for chosen
processes only; but an audit token changes at each exec, and a child's
first events can come before its fork is handled, so inverted muting loses
the agent's children (M2). A result may be cached by
the kernel (`cache`), which a policy that decides by flags and path can use
only where the answer cannot change.

## What it does not give

- **The network.** Endpoint Security has no event for a TCP or UDP
  connect. A Network Extension content filter (`NEFilterDataProvider`,
  entitlement `com.apple.developer.networking.networkextension`,
  `content-filter-provider`) sees each flow with the process's audit token
  and its remote endpoint, and can allow or drop it. Names: the Linux
  Warden resolves them itself and hands out synthetic addresses; on a Mac a
  DNS proxy provider (`NEDNSProxyProvider`) or the flow's
  `remoteHostname`, where the system gives it, would be the way. A second
  entitlement and a second extension.
- **Changing the call.** An AUTH event is answered allow or deny (or, for
  an open, the flags allowed). The Linux Warden can do more: open the file
  itself and hand the agent the descriptor (`SECCOMP_ADDFD`), answer with
  an error of its choosing, or dial a connect itself. Here the agent's own
  call goes ahead or fails with EPERM. Where VAREK relies on doing the call
  itself (credentials placed by `warden-secrets`, the MCP proxy, plans
  held), the design has to find another way, or say the Mac lacks it.
- **Every system call.** There is no allowlist of calls, as the Linux
  Warden's seccomp filter is: a call no event covers goes ahead. The
  default-deny is per event type, not per call.
- **A deadline missed.** Each AUTH message has a deadline (15 s on macOS
  26.7.2); a client that misses it is killed by the system (SIGKILL), and
  **the operation goes ahead**: missing the deadline fails open (M1). The
  SMT decision procedure, and its certificate, must fit inside it, every
  time, and the daemon must answer DENY itself before the deadline when a
  decision is not ready (D7).

## The design in one paragraph (proposed)

A daemon, `varek-esd`, runs as root, holds the Endpoint Security
entitlement and the user's Full Disk Access, and subscribes to the AUTH
events above, selecting the agent's process tree by pid (its pid, then
each fork's and each exec's, by parent: D6) and answering every other
process's events at once, cached. `varek
run` on the Mac starts the agent (its own user, as in the VM since v1.38),
tells the daemon its audit token and policy, and the daemon decides each
event with the same decision procedure and checker as the Linux Warden,
writing the same records to the same verdict stream, audited by the same
`varek audit`. A Network Extension decides the agent's flows the same way.
`varek vm` stays: it is where a policy needs what only the Linux Warden
does (above).

## The VM and native, side by side

| | `varek vm` (v1.37) | Native (proposed) |
|---|---|---|
| Where the agent runs | a RHEL 9 VM | the Mac |
| The Mac's tools | not there | there |
| Decided | every system call (seccomp), files, launches, network, MCP, credentials | files, launches, signals, memory, Unix sockets (ES); flows (NE) |
| Not decided | — | calls no event covers |
| The Warden does the call itself (descriptors, dialing, credentials) | yes | no: allow or deny only |
| The policy grammar | 1.35 | a subset; a policy naming what the Mac cannot decide refuses to start, as a Linux policy needing a newer Warden does |
| Records and audit | the Warden's | the same format, `"arch":"arm64"`, `"platform":"macos"` |
| What the user installs | vfkit, qemu, a RHEL image and a Red Hat login | a signed, notarized package; approve the extension and Full Disk Access |
| Root on the machine | root in the VM is outside the Warden | root on the Mac is outside it |

## Decisions to make (proposed answers)

- **D1. A launchd daemon or a system extension?** A system extension is
  what Apple recommends for an Endpoint Security client shipped in an app,
  and is updated with it; a daemon is simpler to build and test.
  Proposed: a daemon first (development and the checks), a system
  extension for what is shipped.
- **D2. One Warden source or two?** Proposed: the decision procedure, the
  checker, the policy parser and the record writer are shared C (as they
  are between x86-64 and arm64 since v1.30); the event loop is new
  (`warden_es.c`), as `warden_node.inc.c` is for the node agent.
- **D3. What a policy may say on a Mac.** Proposed: a policy names the
  platforms it is for only by its `require` lines; the Mac's Warden refuses
  to start under a line it cannot enforce (credentials injected, held
  plans, the MCP proxy, a launch decided by its descriptor), each with the
  reason, rather than run with less.
- **D4. The network.** Proposed: no network decision without the content
  filter: until it exists, a policy with any `host` rule refuses to start
  on the Mac, and the default is no network.
- **D5. Is the VM kept?** Proposed: yes, as the full path; native is for a
  policy within its subset.
- **D6. How the agent's processes are selected** (from M2). Proposed: by
  pid, not by inverted muting. Every process's AUTH events come; a process
  is the agent's when its pid, its parent's or its original parent's is
  (the agent's at first, then each NOTIFY_FORK's child), until NOTIFY_EXIT;
  another process's events are allowed at once and cached. Inverted muting
  by audit token lost every child in M2, and most of M1's work. The cost:
  the daemon is in every process's path on the Mac, so a stall in it holds
  the whole Mac (up to the deadline, then fails open); `es_mute_path` for
  the system's own paths is to be measured as a way to narrow it. Another
  process's answer is **never** cached: the kernel's cache is shared by
  every process running the same executable, and an allow cached for a
  process outside the tree answered the agent's same open, under a rule
  refusing it, with no event (M4c, run 1). Its cost, every process's
  events answered uncached, is to be measured.
- **D7. Fail closed at the deadline** (from M1). Proposed: every AUTH
  event is answered by the daemon before its deadline: a decision not ready
  by the deadline less a margin (a second, to be set from M1's worst) is
  answered DENY, recorded as such (`"rule":"deadline"`), from a timer
  separate from the decision. A missed deadline would kill the client and
  let the operation, and every later one until it restarts, go ahead.
- **D8. Paths are the real paths** (from M3). ES gives the resolved path:
  `/tmp`, `/etc` and `/var` are `/private/tmp`, `/private/etc`,
  `/private/var`. Proposed: the policy's paths are resolved (firmlinks and
  symlinks) when it is loaded on a Mac, and the records name both, so a
  rule for `/tmp/x` holds; a rule whose path cannot be resolved refuses to
  start.
- **D9. No read-only answer to a read-write open** (from M3). An open with
  write refused is refused whole (EPERM), not narrowed to a read. Proposed:
  the policy's `readonly` refuses a read-write open on the Mac, as on Linux
  without `SECCOMP_ADDFD`, and the docs say so.
- **D10. The cache** (from M4, M4b and M4c). A cached answer is the
  kernel's, for an executable and a file, not for a process: 5,000 `cat`s
  were answered once (M4); a refusal reached the client once and the next
  processes were refused from the cache (M4b); and **an allow cached for a
  process outside the agent's tree answered the agent's own read-write
  open, under a rule refusing it, with no event: the open succeeded**
  (M4c, run 1). A cached answer stands in for the policy for every process
  of that executable. Proposed:
  - **no answer is cached**, the agent's or another process's
    (`cache=false` on every response), until a case is measured where a
    cached answer cannot stand in for a decision the policy would make
    differently; the cost is measured first (every AUTH event answered by
    the daemon);
  - `es_clear_cache` when the daemon starts and at each run's start and
    end, so nothing cached before (by an earlier version, or a crash
    before a response) outlives it.

  Measured besides: within one process, allows cached before a rule did
  not outlive it, and the refusals after it came from the cache (M4c, run
  2); in M4b, the allows cached before a rule were not used after it,
  each first write after the rule being a new process. Not measured:
  whether another Endpoint Security client's cached answers (an antivirus,
  say) reach this client's processes.

## Measure first (on an EC2 Mac, before any decision above)

- **M1.** The time from an AUTH_OPEN to the answer, with the decision
  procedure and the checker, against the message's deadline: p50, p99 and
  the worst, over a build and a test run. And what happens at the deadline
  (the client killed; the operation allowed or denied).
- **M2.** Inverted muting by audit token: does a child the agent starts
  (fork, then exec) come under it before its first event, or is there a
  window?
- **M3.** `AUTH_OPEN`'s flags: are they the flags the caller passed, and is
  a read-only answer to a read-write open seen by the caller as EPERM or as
  a read-only descriptor?
- **M4.** The kernel's result cache: when is a cached answer reused, and
  can it outlive a policy's change or a run?
- **M5.** The content filter: is the flow's audit token the agent's (not a
  helper's, as for a URL session's `nsurlsessiond`), and is the remote host
  name there for a connect made by IP after the agent's own lookup?
- **M6.** What the user must approve, step by step (the extension, Full
  Disk Access, the filter), on macOS 15 without MDM, and on a Mac managed
  by MDM (where a profile can pre-approve all three).
- **M7.** CI: whether a GitHub-hosted macOS runner can load an Endpoint
  Security client at all (SIP, TCC, the entitlement). If not, the checks
  run on an EC2 Mac, as `mac_check.sh` does.

## Measured (EC2 Mac, November 15, 2026)

`mac2.metal`, us-east-2b, macOS 26.7.2, about 1:00 to 1:15 AM CST; the
probe (`varek/v1_4/tests/es_probe/`, at 7a2e27d) signed with the Developer
ID profile (team 6TRS8N9VX7, `com.apple.developer.endpoint-security.client`
true), run as root. The probe answers from a fixed rule: the times are
Endpoint Security's and the probe's, not the decision procedure's (the
Linux Warden decides an open in 73 µs p50, the v1.38.0 soak).

- **M1, the time to answer, and the deadline.**
  - Selected by pid (`--track-pids`), 5,000 `cat` runs: 60,030 answers,
    p50 9.5 µs, p99 56 µs, max 183 µs; a clone and a compile: 6,344
    answers, p50 8.7 µs, p99 21 µs. By inverted muting, the same runs gave
    1,557 and 21 answers: most of the work was not seen (M2).
  - The deadline (`budget_ms`): 15,000 ms on every event.
  - Each answer delayed 1 s: allowed, 14.0 s left; 10 s: allowed, 5.0 s
    left; 70 s: the client killed (SIGKILL) at 15 s, and **the open went
    ahead** (`cat` printed all of `/etc/hosts`). A missed deadline fails
    open (D7).
- **M2, children.** Three `cat`s (one in the shell, one in a background
  subshell, one in a nested shell): by inverted muting, **0 of 3 opens
  seen, in 11 runs of 11**: a child's exec, with its new audit token, comes
  before its fork's notice is handled. Selected by pid: 3 of 3 (78
  answers, 5 forks, 7 execs). Hence D6.
- **M3, writes refused.**
  - A rule for `/tmp/esw` never matched: ES reports `/private/tmp/esw`
    (D8).
  - With `/private/tmp/esw`, selected by pid: 5 refused, the file still
    `before`; `>`, `rm`, `mv` and `touch` saw "Operation not permitted".
    An `O_RDWR` open answered with read only was **refused whole (EPERM)**,
    not given a read-only descriptor (D9).
  - By inverted muting: only the shell's own write refused; its children's
    `rm` and `touch` went ahead, and the file was deleted (M2).
- **M4, the cache.** With `--cache`, the 5,000 opens of `/etc/hosts` were
  answered once (answers 60,030 to 5,032; p50 12.4 µs). With a rule
  refusing writes under `/private/etc` added, a write there was still
  refused, the cached reads unaffected.
- **M4b, a cached allow against a later rule** (at 3b0af80, `--track-pids
  --cache`). Three appends to a file by three `/bin/sh -c` processes,
  allowed and cached, then a rule refusing writes there, then three more
  appends, each its own process:

  | | The three appends after the rule | The file |
  |---|---|---|
  | The rule turned on in the same client (SIGUSR1) | all refused (EPERM) | `start a1 a2 a3` |
  | The same, `es_clear_cache` at the signal | all refused | `start a1 a2 a3` |
  | The rule in a new client, after the first cached the appends | all refused | `start a1 a2 a3` |

  In each, one refusal reached the client (`read_only`) and the next two
  came from the cache: refusals are cached, and a cached answer applies to
  another process of the same executable. The allows cached before the
  rule were not used. (D10)
- **M4c, the cache across processes** (at d22c150, `m4c.py`; `--track-pids
  --cache --deny-write /private/tmp/esc`, which caches every answer, the
  other processes' too). A read-write open of a file, closed unwritten:

  | | The agent's open | The log |
  |---|---|---|
  | Run 0, the control: the agent's open, nothing cached before | refused (EPERM) | 1 open, `read_only` |
  | Run 1: a process outside the tree opens it first (allowed, cached), then the agent, the same executable | **succeeded** | **no open of the file**: all 49 answers `allow` |
  | Run 2: one process, three appends, the rule, three more | before: ok ×3; after: EPERM ×3 | 1 open after the rule, `read_only` |

  Run 1 is a way around the policy: the kernel answered the agent's open
  from an allow cached for another process. (D6, D10)
- **M6, approvals.** Started as root from a Session Manager shell, the
  client was made with no approval asked: the responsible process is
  presumably the SSM agent, which EC2's macOS images give Full Disk Access.
  Not measured: from an ssh login, as a launchd job, or on a user's Mac
  (where Full Disk Access is approved in System Settings).
- **Signing**, from a Session Manager shell: only in ec2-user's own
  security session (`launchctl asuser 501`); `sudo -iu` keeps root's, and
  codesign finds no identity (`es_probe/README.md`).
- **M7, CI.** GitHub's macOS runner (macOS 26.7.2) builds the probe with
  no warnings; signed ad hoc, it stops at `es_new_client` as not entitled.
  A run with the entitlement needs the Developer ID profile and key, which
  stay off CI: the checks run on an EC2 Mac.
- **M5** (the content filter) is not measured: it needs the Network
  Extension.

## Prerequisites (Apple Developer account)

The entitlement is assigned to the account; it is used through an App ID
and a provisioning profile. In the Apple Developer portal (Certificates,
Identifiers & Profiles), by the account holder:

1. **Identifiers → + → App IDs → App**: a description (`VAREK Warden`) and
   an explicit bundle ID in reverse-DNS form under a domain the project
   holds. Under Capabilities, enable **Endpoint Security** (listed once
   the entitlement is assigned). **Done November 13, 2026:** `VAREK
   Warden`, `ai.soberagents.varek.warden`, Endpoint Security enabled. A
   bundle ID cannot be renamed, only deleted and made again.
2. **Certificates → + → Developer ID Application**: needed to sign what is
   shipped outside the Mac App Store, and to notarize it. Its request (CSR)
   is made with a private key kept by the account holder (Keychain Access
   on a Mac, or `openssl`); the key never goes in the repository or in a
   chat. To sign on a Mac later, the key and the certificate Apple returns
   are imported into that Mac's keychain (as a `.p12`), for `codesign` to
   find; a key left unencrypted on disk (`openssl -nodes`) is kept in a
   private place, or encrypted.
3. **Profiles → + → Developer ID**: for the App ID of step 1 and the
   certificate of step 2. The profile carries the entitlement; the daemon is
   signed with it.
4. Later, for the network: a second App ID, or the same, with **Network
   Extensions** (content filter); and **System Extension** if D1 goes that
   way.

Signing and notarizing need a Mac (`codesign`, `notarytool`), so they are
done on an EC2 Mac, as the checks are.

## Plan (once D1 to D5 are decided)

1. M1 to M7 on an EC2 Mac, with a minimal client
   (`varek/v1_4/tests/es_probe/`: its README is the run's steps): it
   supervises one command and its children (by inverted muting, or by pid
   with `--track-pids`), answers AUTH_OPEN, AUTH_EXEC, AUTH_CREATE,
   AUTH_UNLINK, AUTH_RENAME and AUTH_TRUNCATE from a fixed rule, and
   records each answer's time against its deadline. **Done November 15,
   2026** for M1 to M4, M4b, M4c, M6 in part and M7 ("Measured"); still
   to do: the cost of D6 and D10 together (every process's AUTH events
   answered uncached; with `es_mute_path` for the system's own paths),
   another client's cache, M6 on a user's Mac, and M5 with the content
   filter.
2. `warden_es.c`: the event loop, the decisions and the records for files
   and launches, under a policy with no `host` rules; the shared parts
   unchanged. Its suite runs on an EC2 Mac.
3. The Network Extension, if D4 is decided as proposed.
4. Packaging: a signed, notarized package; `varek run` on a Mac choosing
   native when the policy is within the Mac's subset, the VM otherwise.
5. A review, then a 24-hour soak on an EC2 Mac, as for every release.
