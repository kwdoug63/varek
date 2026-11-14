# macOS, natively: the Warden on Apple's Endpoint Security (design note)

Status: **draft, not scheduled** (started November 13, 2026). No release
number until it is decided; security operations is v1.39.0 and comes first
(`docs/roadmap/v1.36-v1.37.md`). Nothing below is built. Facts about
Apple's frameworks are from Apple's documentation as we understand it, and
each one we depend on is listed under "Measure first" to be checked on a
Mac before a decision rests on it.

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
| an open, with its flags | `AUTH_OPEN` (answered with the flags allowed, `es_respond_flags_result`: read but not write is expressible) |
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
processes only (the agent and what it starts). A result may be cached by
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
- **A deadline missed.** Each AUTH message has a deadline; a client that
  misses it is killed by the system (and the operation, we expect, allowed:
  to measure). The SMT decision procedure, and its certificate, must fit
  inside it, every time, or the client must answer from a cache.

## The design in one paragraph (proposed)

A daemon, `varek-esd`, runs as root, holds the Endpoint Security
entitlement and the user's Full Disk Access, and subscribes, with inverted
muting, to the AUTH events above for the agent's process tree only. `varek
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

1. M1 to M7 on an EC2 Mac, with a minimal client (`tests/es_probe/`):
   subscribe to AUTH_OPEN and AUTH_EXEC for one process, answer from a
   fixed rule, measure.
2. `warden_es.c`: the event loop, the decisions and the records for files
   and launches, under a policy with no `host` rules; the shared parts
   unchanged. Its suite runs on an EC2 Mac.
3. The Network Extension, if D4 is decided as proposed.
4. Packaging: a signed, notarized package; `varek run` on a Mac choosing
   native when the policy is within the Mac's subset, the VM otherwise.
5. A review, then a 24-hour soak on an EC2 Mac, as for every release.
