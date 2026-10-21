# VAREK v1.33.0 — macOS, Through a Linux VM

**Draft until the full sweep on the EC2 Mac** (the 24-hour soak there passed; `docs/security/v1.33-mac-runbook.md`).

> Reviewed by three AI review agents (October 19, 2026; the arm64 Warden, the
> VM path, and the tests, CI, tools and documentation), against the code; their
> findings are fixed or stated below as known limits
> (`docs/security/v1.30-macos.md`, Review). A human or third-party review has
> not been done.

MIT · github.com/kwdoug63/varek

## Summary

VAREK runs on a Mac with Apple silicon. The agent runs inside a Linux VM
under the Warden, as it does on Linux: the same policies, decisions,
records and audit. The Mac shares one directory with the VM, the project,
mounted at the same path inside; the Mac's other files are not in the VM
at all.

- **The Warden on arm64.** One source for x86-64 and arm64 (aarch64): the
  same policies, certificates and records on both. VAREK's encoding of open
  flags stays x86-64's, and the Warden translates arm64's where flags are
  decided, certified and recorded. `run_start` names the architecture
  (`"arch"`), and the audit checks it against the Warden's version. CI runs
  its suites on both architectures.
- **`varek vm`.** On the Mac: `varek vm init --image FILE --sha256 HEX` makes
  the VM from Red Hat's RHEL 9 aarch64 KVM guest image (downloaded and
  registered with the user's own Red Hat login; varek never asks for or
  holds a Red Hat password), on Apple's Virtualization framework through
  vfkit; `varek vm run ARGS -- CMD` runs `varek run` inside on the working
  directory and copies the run's verdict stream to `.varek/` in the
  project; `varek vm start`, `ssh`, `stop`, `status`.
- **Admitted under every policy:** `getpgid(0)`, which glibc's `getpgrp()`
  calls on arm64 (arm64 has no `getpgrp`), as `getpgrp` is on x86-64.

It is v1.32.1's Warden with the above; no policy line, rule or record
changes meaning.

## Tested

- Every suite on arm64 Linux (an AWS Graviton instance, RHEL 9.8) and on
  x86-64; CI on both (`ubuntu-24.04` and `ubuntu-24.04-arm`).
- On an EC2 Mac (`mac2.metal`, Macmini9,1, M1; macOS 15.8; vfkit 0.6.4;
  a RHEL 9.8 aarch64 guest, 4 vCPUs, 4 GiB), `tests/mac_check.sh`,
  October 20, 2026: every check passes (the Mac; the VM made from Red
  Hat's image, checked by its SHA-256, and registered; its cold start;
  `varek doctor` inside; one share, the project; root in the VM reaching
  no file of the Mac's by a link or `..`; an agent under the Warden in the
  VM reading and writing the project, refused the Mac's files, writes
  outside the project, `/etc/shadow`, the Mac (the VM's gateway) and the
  instance metadata service; its stream copied to the Mac, audited in the
  VM, the same file by its SHA-256). The full sweep inside the VM
  (October 21): every suite passes but these. test-v1130, test-v1140,
  test-v1150 and `make crosscheck`: the solver cross-check's reference,
  z3, was 4.15.4, the newest with a wheel for RHEL 9 on aarch64, and
  under every 4.x release (4.13 to 4.16, measured on x86-64) its regex
  queries time out, each counted a disagreement (87 s under z3 5.1.0,
  past 15 minutes under 4.x); the cross-check now needs z3 5.0 or later
  and says so, and the sweep builds it from source on RHEL 9 (its aarch64
  wheels need glibc 2.38). test-v1240: 6 of 106 checks, each an agent's
  connect to the VM's own address after a name the Warden resolved
  (`python: and connects`, `curl: fetches from an allowed name`, three
  reached-address checks); the name checks before them pass. Not yet
  explained (they pass on arm64 RHEL 9.8 on a Graviton instance); the
  logs went with the instance. A known limit until it is: below.
- **24 hours inside the VM on the Mac** (`tests/mac_soak.sh`, the shared
  soak), October 20 to 21, 2026, 9:47 pm to 9:47 pm CDT: `soak_check:
  PASS`.

  | | |
  |---|---|
  | Duration | 24.0 h, a turn every 60 s: 1,440 turns in each run; Warden 1.33.0 (aarch64) |
  | Run A | every task before the user's token expired worked (`tools/list` 259, `tools/call` 258, `fs` reads 258, `gh`'s calls 258, sub-agent launches 258); 144 probes, all held; the run revoked 0.02 s after the expiry, no turn after it working; the audit passing; OCSF: 12,217 events, the stream's, valid OCSF 1.9.0 |
  | Run B | 1,296 of 1,296 pieces of work done, 288 git commits; 144 probes, all refused; the stream signed, the audit passing |
  | Run C (dry run) | 1,440 of 1,440 done; 5,766 calls the narrower policy refuses let through and recorded; the audit: `VERIFIED: DRY RUN, NOT ENFORCED`; `varek policy suggest`: 41 exact rules; under the draft nothing let through |
  | The Warden's decisions | MCP calls p50 31 µs (p99 47); the agent's opens p50 143 µs (p99 523); `fs`'s opens p50 247 µs |
  | Memory | flat for 24 hours: each Warden 13 to 15 MB at most; the proxy, `warden-secrets` and the two MCP servers 8 to 19 MB |

  The first judging stopped at C's audit: the audit, holding C's stream
  (476,082 records) in memory, reached 1.86 GB, and the VM (4 GiB, no
  swap) ended it (out of memory). With 4 GiB of swap added, the same
  records were judged again (`soak.sh --check-only`): PASS. A known limit,
  below.

## Known limits

From the review (`docs/security/v1.30-macos.md`, Review):
- The project is trusted input for the Mac's own tools: an agent the policy
  lets write `.git/hooks/` or `.git/config` (the baseline does) writes code
  git on the Mac runs.
- The VM's network reaches the Mac (vmnet's NAT makes it the gateway): the
  agent's connections are the Warden's to decide; root in the VM is not
  under the Warden.
- The VM persists between runs, and stays up after `varek vm run` with the
  project shared, until `varek vm stop`.
- The agent runs as the VM's user, who has sudo; `no_new_privs` and the
  Warden keep it from the agent.
- A statically linked musl agent records `O_LARGEFILE` on arm64 and not on
  x86-64.
- The audit holds a run's whole stream in memory: about 1.9 GB for 24
  hours of a dry run's records (476,082). A long run's audit needs that
  much memory, or swap.
- test-v1240's connects to the machine's own address, after a name the
  Warden resolved, failed in the VM on the Mac (6 checks, above): not yet
  explained.
