# VAREK v1.31.1 — Calls glibc and bash Make

> **Draft.** Not yet released: the release date, the 24-hour soak's figures
> and the CHANGELOG entry come with the release commit, after the soak.

MIT · github.com/kwdoug63/varek

## Summary

A patch release of v1.31.0. The Warden admits four system calls that
glibc and bash make, which it refused under every policy. Nothing else
changes: no policy, rule, record or option.

- **`epoll_wait(2)` and `epoll_create(2)`** (x86_64). glibc on x86_64
  calls them for `epoll_wait()` and `epoll_create()`. Refused, they made
  Python's `select.epoll` fail with EPERM, and with it asyncio's default
  event loop: `asyncio.run()` failed under the Warden, whatever the
  policy. They do what `epoll_pwait` with no signal mask and
  `epoll_create1` with no flags do, both admitted already. arm64 has
  neither call, and its glibc uses those two, so it was not affected.
- **`pipe(2)`** (x86_64). glibc before 2.37 (RHEL 9's 2.34) calls it for
  `pipe()`, where later ones call `pipe2`; refused, a shell's command
  substitution failed there. It does what `pipe2` with no flags does.
- **`getpgrp(2)`**, the caller's own process group, under every policy.
  From 1.29 it was admitted with the calls 1.29 policies add; under an
  earlier policy (`require warden 1.28` or before, or no `require` line)
  bash exits at its start when it fails ("getpgrp failed"), so a bash
  agent, or RHEL's `/bin/sh`, which is bash, could not start.

**How they were found.** `pipe` and `getpgrp` by the suites on RHEL 9.8
(the v1.30 work, October 15 and 16, 2026); `epoll_wait` noted there, and
`epoll_create` with it when the fix was checked: on Ubuntu 24.04 (glibc
2.39), `asyncio.run()` failed under the v1.31.0 Warden, and ran on
`asyncio.SelectorEventLoop(selectors.PollSelector())`. Every release
before this one refuses these calls; `RELEASE-v1.29.0.md` and
`RELEASE-v1.31.0.md` list it under their known limits.

## Tested

- `make test-v1311` (new), as root, under a 1.31 policy (the agent as
  `nobody`) and under one with no `require` line: the Warden reports
  1.31.1; asyncio's default event loop runs; on x86_64 `epoll_create(2)`,
  `epoll_wait(2)`, `pipe(2)` and `getpgrp(2)`, each by its number, are
  admitted; bash starts and runs a command substitution. 11 checks; on the
  v1.31.0 build 9 fail (the 2 that pass are `getpgrp` and bash under the
  1.31 policy, admitted there since 1.29).
- The suites that cover the filter and the records, on this build in a
  4-vCPU container: `test-v1123`, `test-v1124`, `test-v1270`, `test-v1271`,
  `test-v1280`, `test-v1281`, `test-v1290` and `test-v1310` all pass. The
  release commit's build runs every suite again.

## 24 hours on a small host

To come: the shared soak (`tests/soak_shared`) on this build, as for
v1.31.0, once v1.31.0's run has freed the droplet.

## Compatibility

- Every v1.31.0 policy, option and record is unchanged. The grammar stays
  1.31; `run_start` and `varek version` name the Warden 1.31.1.
- An agent that called these four and failed now succeeds. None of them
  names a file, an address or another process: each makes or uses the
  caller's own descriptors, or reports its own process group.

## Known limits

Those of v1.31.0 (`RELEASE-v1.31.0.md`), less the calls above.

## Upgrading

1. Rebuild (`make`) and reinstall (`make install`). `varek version` reports
   the Warden 1.31.1.
2. Nothing else: no policy or option changes. An agent that ran asyncio on
   a `PollSelector` to work around this may go back to the default.
