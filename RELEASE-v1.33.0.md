# VAREK v1.33.0 — macOS, Through a Linux VM

**Draft until the 24-hour soak on an EC2 Mac** (`docs/security/v1.33-mac-runbook.md`).

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
- On an EC2 Mac (`tests/mac_check.sh`): *to be filled in from the run.*
- The 24-hour soak inside the VM on the Mac (`tests/mac_soak.sh`, the
  shared soak): *to be filled in.*

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
