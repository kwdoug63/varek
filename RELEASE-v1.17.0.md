# VAREK v1.17.0 — Closing Three Live Gaps

Released 2026-09-29 · MIT · github.com/kwdoug63/varek

## Summary

v1.17.0 closes three gaps a review of v1.16.3 found in the live Warden:

1. The signing key, the anchor and the verdict stream could be reached through
   a second path, such as a bind mount into an allowed tree.
2. `stat`, `access` and `readlink` were admitted outright and never logged.
3. The agent ran as root with every capability.

It changes no verdict *semantics*: the policy rules, the three-state verdict
with UNKNOWN suppressed to DENY, the certificates and the symmetric-suppression
invariant (**no extension may move a genuinely unsafe action to SATISFIED**)
are untouched. It does change defaults, so it is a minor release.

`make test-v1170` (36 checks) covers all three; 20 of its checks fail against
v1.16.3. Every earlier suite (v1.9.3 lifecycle, v1.12 to v1.16.2), the
conformance target, the v1.6 integration test and the v1.7 checks still pass.

## Security

### The Warden's own files, refused by identity

v1.16.0 made the Warden refuse to start if the policy would let the agent open
the signing key, the anchor or the verdict stream. It checked their real path
only. A second path to the same file defeated it: with the key's directory
bind-mounted under `/tmp/varek_allowed_kk/`, the agent opened
`/tmp/varek_allowed_kk/log.key`, the policy said ALLOW, and it read all 65
bytes of the private key.

Every file open and lookup is now checked after resolution, on the object
actually pinned and before the policy is asked, against the device and inode
of the signing key, the anchor and the verdict stream (a regular file or
FIFO). Any alias (bind mount, overlay, a hard link made after startup) has the
same identity and is refused, recorded as `protected_object`. The startup
checks stay, as an earlier and clearer error.

Raw storage and memory are refused the same way, whatever the policy says and
whatever path reaches them: block devices, `/dev/mem`, `/dev/kmem`, `/dev/port`
(character 1:1, 1:2, 1:4), the sg, bsg, nvme and nvme-generic command devices
(majors read from `/proc/devices`), and `/proc/kcore`. Each reads every file on
the machine below any path rule. Recorded as `raw_device`.

### stat, access and readlink, mediated

`newfstatat`, `statx`, `access`, `faccessat`, `faccessat2`, `readlink` and
`readlinkat` were admitted by the filter. An agent could learn whether any file
existed, its size, owner and times, and read where any link pointed, including
the Warden's own `/proc/<pid>/fd` entries, and none of it was recorded.

They are now sent to the Warden, which:

- **resolves** the name like an open: symlinks followed unless the call says
  not to (`lstat`, `readlink`), `/proc/self` mapped to the agent's own entry,
  another process's `/proc` entries refused;
- **refuses by identity** the Warden's own files, as above;
- **decides** with the SMT decision procedure as a read-only open of the same
  object (`access(W_OK)` as a write);
- **certifies** an ALLOW with the independent checker;
- **records** the decision, as `file.stat`, `file.access` or `file.readlink`;
- **answers** the call itself, writing the result into the agent's memory.

A name that does not exist is decided on where it would be: `ENOENT` inside the
policy, `EACCES` outside it, so a lookup no longer says what exists elsewhere.
`access(X_OK)` is refused, since nothing may be executed after the launch.

Two cases are answered without a decision:

- **A descriptor the agent already holds** (`fstat`, `statx` with
  `AT_EMPTY_PATH`): like `read()` on it, not recorded.
- **A directory an allow rule leads to.** For `allow path /usr/lib/python3/`
  that is `/`, `/usr`, `/usr/lib` and `/usr/lib/python3`: a read-type lookup is
  answered and recorded as `metadata_ancestor`. Without this, `realpath()` and
  the like fail on every allowed path.

`varek_audit.py` re-checks every certified lookup and checks each
`metadata_ancestor` record against the policy's allow rules.

### The agent runs unprivileged

Through v1.16.3 the agent ran as uid 0 with every capability (`CapEff
000001fffeffffff`), in the host's user and mount namespaces; only the seccomp
filter held it back.

It now runs as `nobody`, or the user `--run-as <user|uid[:gid]>` names. Before
the filter is loaded the Warden's child clears its supplementary groups,
empties the capability bounding and ambient sets, switches group and user, and
verifies that no capability remains. `PR_SET_PDEATHSIG` is set after the
switch, because a credential change clears it. `--run-as root` keeps the old
behaviour and prints a warning.

File access does not depend on the agent's own rights: the Warden opens and
looks up allowed files on its behalf, as root, only after the policy allows
it. What changes is what the agent can do with every call the filter does
admit, and with any kernel bug it reaches.

The program is opened by the Warden's code while still root and launched with
`execveat(fd, "", AT_EMPTY_PATH)`, so the unprivileged user needs execute
permission on the file only, not on every directory above it. The launch
approval accepts that `execveat` once, from the launched process only; the
descriptor is in a register, not memory, so answering it with CONTINUE is as
sound as before. A script (`#!`) is launched by its path.

## Compatibility

- **The agent is no longer root.** A program that the unprivileged user cannot
  execute is refused with a clear message (exit 127). For a script, every
  directory above it must also be searchable by that user. `--run-as root`
  restores the old behaviour.
- **Lookups are now decided by the policy.** A lookup outside the policy gets
  `EACCES` where it used to get a real answer; a missing name outside it gets
  `EACCES`, not `ENOENT`. `access(X_OK)` always gets `EACCES`.
- **Raw devices are refused** even if a policy names them.
- **Records** gain the actions `file.stat`, `file.access`, `file.readlink` and
  the rules `metadata_answered`, `metadata_not_found`, `metadata_failed`,
  `metadata_ancestor`, `protected_object`, `raw_device`. The status line gains
  `uid=` and `caps=`.
- **Speed.** Every `stat` and `fstat` is now a round trip to the Warden. Python
  3 startup (`import json, os, re, pathlib`) took about 39 ms under v1.17.0
  against 31 ms under v1.16.3 and 24 ms with no Warden, averaged over 5 runs on
  one host. Decision latency (`bench_target 10000`) was unchanged within
  run-to-run noise: P50 4–5 µs, P99 46–63 µs against 46–55 µs.
- No policy-file or plan-file format change.

## Known limits

- A lookup on a descriptor the agent already holds is answered but not
  recorded, like `read()` and `write()` on it.
- `metadata_ancestor` tells the agent that the directories leading to an allowed
  path exist. The policy already implies it.
- A `stat` of a raw device the policy allows is answered; opening it is not.
- Lookups are decided as reads, so a write-only rule (`access=wo`) refuses
  lookups under it.
- The deployment preflight (`varek_preflight.sh`) still checks the protected
  files by path, so it cannot see a bind mount. The runtime check now covers
  it.

## Requirements

Unchanged from v1.16.3: Linux ≥ 5.14 (≥ 5.8 for `faccessat2`), `pidfd_getfd`
(Linux ≥ 5.6), `CAP_SYS_ADMIN` for the PID and network namespaces, libsodium,
x86_64.
