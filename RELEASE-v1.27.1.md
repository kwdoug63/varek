# VAREK v1.27.1 — Nothing Written During the Run Is Mapped Executable

> The review was done by AI review agents; a human or third-party review
> has not been done.

Released 2026-10-12 · MIT · github.com/kwdoug63/varek

## Summary

v1.27.0 decides launches: under `require warden 1.27` the kernel's Landlock
domain lets the agent launch only the files of the launch set, so a file
written during the run is never launched. Landlock governs what the kernel
launches, not the executable mappings by which the dynamic loader maps
shared libraries. Where a policy let the agent both write and read a
directory, a library written there could still be mapped executable into an
allowed program (`LD_PRELOAD`, `dlopen`, a Python native extension).
v1.27.0 listed this as a known limit.

From v1.27.1, under the same `require warden 1.27`, every directory the
policy lets the agent write is mounted `noexec` where the Warden opens
files. A file under one can be neither launched nor mapped executable.

1. **Which directories.** A path rule is writable when an open its flag
   clause admits writes (an access mode of write or read-write, `O_TRUNC`
   or `O_CREAT`); `readonly` rules are not, `access=ro` alone is (it admits
   `O_TRUNC`). Each writable rule names a directory: a prefix ending in `/`,
   that directory; a prefix without one (`/work/out` admits `/work/out2`),
   its parent; a glob, the directory before its first wildcard; an exact
   path (or a glob with no wildcard), the file itself, or its directory if
   it is not there yet. The list is computed from each rule as both parsers
   read it, so they agree on it by construction. One directory inside
   another is dropped; at most 256.
2. **The mounts.** At startup, before the run starts, the resolver helper
   starts and the agent is forked, the Warden gives itself a private mount
   namespace (`unshare(CLONE_NEWNS)`, then the whole tree made private, so
   nothing reaches the host) and re-mounts each directory on itself with
   `MS_NOEXEC`, keeping the flags each mount already has, together with
   every mount beneath it. A second pass confirms each is `noexec`. The
   Warden opens every file it allows for the agent (`resolved_fd_injection`),
   so every file under those directories reaches the agent through a
   `noexec` mount; the agent inherits the same view. The host's mounts are
   untouched and the namespace ends with the run.
3. **What the agent sees.** `mmap` with `PROT_EXEC` of a file there fails
   with `EPERM`; `mprotect` adding `PROT_EXEC` to a mapping of it, `EACCES`;
   a launch of it is refused by the kernel even where the launch set holds
   it. A copied library cannot be loaded and the process goes on.
   Everything else is unchanged: reads and writes as the policy says, files
   elsewhere, pure-Python modules, anonymous executable memory (a JIT's), and
   `ctypes` callbacks.
4. **Fail closed.** Each descriptor the Warden hands over for a path under
   a listed directory must be on a `noexec` mount (`fstatvfs`), however the
   path was reached, or the open is refused. So a directory missing at
   start that the host makes during the run, or a file an exact rule names
   that the host replaces, is refused to the agent rather than left
   executable.
5. **Refused at start, each with its remedy:** a writable rule no directory
   bounds (`suffix`, `contains`, a glob starting with a wildcard); a
   writable `/`; the agent's own program, its interpreter or a loader a
   launch needs, under a writable directory; a descriptor the agent would
   inherit (its standard input, say) open for reading on a file there; a
   mount that fails. **Reported:** a directory not there at start (listed,
   nothing mounted); a launch-set file under a writable directory (it will
   not launch).
6. **The opt-out.** `--writable-exec` turns the mounts off for a run that
   must load compiled code it installs (a `venv` with native packages). It
   is the operator's choice, not the policy's: `run_start` records `noexec`
   as `null`, the Warden says so at start, and the audit notes it.
7. **Records, audit and tools.** `run_start` records `noexec`: each
   directory (or file) mounted, with the policy line that makes it writable
   and the rule's own directory (`target`), and `"missing": true` for one
   not there at start. `varek_audit.py` checks each entry against its rule
   (the certificate checker's new `matches` mode gives each rule's
   matcher), every writable rule against the list, and every write the
   stream records against the list. `varek policy show` lists the
   directories the Warden would mount on this host; `varek doctor` and the
   preflight check the Warden can make a mount namespace; the CycloneDX
   export carries `varek:noexec.*`. The Warden reports `1.27.1`.

## Tested

`make test-v1271` runs 73 checks, CI runs it as root:

- **The writable directories** (section 1, 23 checks): prefix, glob and
  exact rules with and without a trailing `/`; a glob with no wildcard; a
  relative glob; `readonly`, `access=ro` and deny rules; nested rules; a
  missing directory; the refused forms; `/`; the agent's own program and a
  script's interpreter under a writable directory.
- **The mounts** (2, 11): the agent's `/proc/self/mountinfo` shows each
  directory `noexec`, a mount beneath one too (including one whose
  `mountinfo` line is over 8 KB), a file; `nosuid` and `nosymfollow` kept; a
  read-only path untouched; the host's mounts unchanged; none with
  `--writable-exec` or without the opt-in.
- **What the agent sees** (3, 15): a probe run as the agent, using only
  copies of files already on the host (`libm.so.6`, Python's `_json`
  extension):

  | | mounts on | `--writable-exec` |
  |---|---|---|
  | `libm.so.6` at its own path | loads | loads |
  | a copy of it in a writable directory | refused | loads |
  | a copy of Python's `_json` extension there | refused | imports |
  | a pure-Python module written there | imports | imports |
  | `mmap` with `PROT_EXEC` of a file there | `EPERM` | maps |
  | `mprotect` adding `PROT_EXEC` to a mapping of it | `EACCES` | allowed |
  | anonymous memory made executable | maps | maps |
  | a `ctypes` callback (libffi) | works | works |

  Also: the same from a working directory inside the writable directory, by
  relative names; a launch-set file there (allowed, refused by the kernel);
  a directory the host makes during the run and a file it replaces (the
  agent's opens refused).
- **Records, audit and tools** (4, 24): `run_start`'s record, with and
  without `--writable-exec`; standard input on a file there refused at
  start; 13 forged and re-chained streams the audit must refuse, each for
  its own reason (a directory for a line that is not writable, another
  directory or a read-only one for a writable line, a path not spelled
  canonically, one directory inside another, a file for a directory rule,
  a record from a Warden before 1.27.1, an empty list beside a recorded
  write, and others); `policy show`, `doctor`, the export.

The earlier suites (`test-v1240` to `test-v1270`) and `make test-cli` (71
tests) pass unchanged. **Against v1.27.0** (its own tree, with this suite
and its probe copied in): 60 of the 73 checks fail, 13 pass (each checks
that something does not happen, or that ordinary behaviour is kept).

## 24 hours on a small host

`tests/soak_v1270` gains a fourth probe: a copy of `libm.so.6` written into
the work directory, which the agent then tries to load. The check requires
the loader's own words for the refusal ("failed to map segment from shared
object"), and `run_start`'s `noexec` must hold the work directory.

The reviewed build (c7849dc) ran for 24 hours on a 1 vCPU, 1 GB droplet
(Landlock ABI 4), 2026-10-12 to 2026-10-13: a task a minute in turn
(`git`, `python3`, a compile with gcc), every tenth a probe that must be
refused (a program no rule allows, one a deny rule refuses, a program
written during the run, a library written during the run). It passed:

| | |
|---|---|
| Duration | 24.00 h |
| `noexec` | 2 directories mounted, the work directory among them; Warden 1.27.1 |
| Tasks | 1,296, all ok (432 each; p50 10 ms git, 54 ms python3, 94 ms compile) |
| Probes | 144 (36 of each kind), each refused and recorded; every library copy refused by the loader ("failed to map segment") |
| Launches | 3,564 decided, 3,456 allowed, each with its `exec_result` `launched` |
| Records | 282,917; `varek_audit` passed, with its new checks over every write |
| The Warden's decision, an allowed launch | 106 to 199 us p50 by program (p99 164 to 455) |

The audit was first killed for lack of memory on the 1 GB host: it holds
the stream in memory (about 700 MB for these 282,917 records). With 4 GB
of swap it passed on the same stream. Before it, a 6-minute trial of the
build before the review passed on the same droplet, and a 3-minute trial
of the reviewed build in a container.

## Latency

The mounts change no decision. Their cost is at startup, and the
descriptor check adds an `fstatvfs` to an open under a writable directory.
Measured on the reviewed build, a 4-vCPU container:

| | mounts on | `--writable-exec` |
|---|---|---|
| startup, a run of `/usr/bin/true`, 1 writable directory (p50 of 15) | 21.6 ms | 18.1 ms |
| the same, 10 directories | 23.3 ms | 19.6 ms |
| the same, 50 directories | 28.1 ms | 18.5 ms |
| an open of a file under a writable directory, p50 over 6 rounds of 3,000 | 64.5 to 95.0 us | 64.6 to 95.6 us |

Each directory's mounts read `/proc/self/mountinfo` twice, so startup grows
with the number of directories, about 0.2 ms a directory at 50. The open's
cost is within the spread between rounds.

## Compatibility

- Every v1.27.0 policy loads unchanged. Under `require warden 1.27`, files
  in writable directories can no longer be mapped executable: a run that
  installs a package with compiled modules into one and imports it fails
  there, and `--writable-exec` restores v1.27.0's behaviour for that run.
  Without `require warden 1.27` nothing changes.
- New refusals at start under `require warden 1.27` (listed in the summary,
  item 5). An agent whose standard input is a file in a directory it may
  write must take it from elsewhere (`< /dev/null`, or a pipe).
- `allow path /dev/null` is a prefix rule (it admits `/dev/nullX`), so it
  names `/dev`, which is then mounted `noexec`; write `allow path exact
  /dev/null` to name the file. `varek policy show` lists what would be
  mounted.
- The grammar stays 1.27: `require warden 1.27` turns this on, `require
  warden 1.28` is still refused. `run_start` names the Warden `1.27.1`, as
  `varek version` does (`VDP_WARDEN_PATCH`).
- New field: `run_start`'s `noexec`. New option: `--writable-exec`.
  `vdp_cert_check` has a `matches` mode.
- The Warden needs to make a mount namespace (`CAP_SYS_ADMIN`, which it
  already needs for its PID namespace). `varek doctor` checks it.

## Found in review

Three AI review agents (Claude), separate from the session that wrote the
code, each reviewed one part of v1.27.1 and had to reproduce every finding
(a script and its output): the list and the mounts; coverage (what could
still reach executable memory from a written file); and the audit, tools
and soak. All three finished. The agents are the same kind of model that
wrote much of this code, so this is not an independent human review. It
found real defects, listed below, but it does not replace a human or
third-party review. Each finding was reproduced again before it was fixed,
and each fix has a check that fails on the build before it. The full list
is in the design note's step 7.

**High, fixed.** When the Warden was started from inside a writable
directory (as the soak harness does), its working directory, which the
agent inherits, still pointed at the exec-allowed mount beneath the new
one, so a copy opened by a relative name loaded, mapped executable and
launched. The Warden now enters its working directory again after the
mounts, and the descriptor check (summary, item 4) refuses any file under
a listed directory that does not come through a `noexec` mount. Each fix
closes it alone.

**Medium, fixed.**
- A glob with no wildcard, naming a file not there yet, got no mount.
- A mount beneath a writable directory whose `mountinfo` line was over
  8 KB was left exec-allowed (lines are now read whole, and a second pass
  confirms every mount).
- A writable directory missing at start and made by the host during the
  run, or a file an exact rule names and the host replaces, was writable
  and not `noexec`. The agent cannot do either itself (it has no `mkdir`,
  `rename` or `link`).
- The audit never checked an entry's path against its rule: a re-chained
  stream could list `/etc`, or a read-only directory, for a writable line.
- The audit passed a list that left a directory out, even when the stream
  recorded writes there.

**Low, fixed.** A descriptor the agent inherits from the operator's shell,
open for reading on a file there; the interpreter or loader a launch needs
under a writable directory (a note, then a misleading failure); a remount
dropping `nosymfollow`; a relative glob refused for the wrong reason; a
`noexec` record from a Warden before 1.27.1 accepted; `varek policy show`
saying the agent writes nowhere when a writable directory was missing; the
soak's library probe counting any load failure as refused; the Makefile
not rebuilding the Warden when its `noexec` source changed.

Before the review, the forged streams of step 4 found one more: the audit
read the checker's hex flag mask as decimal, so a `readonly` rule looked
writable. Fixed before it was committed.

## Known limits

- **Code written into memory is not covered.** The agent may still make
  anonymous memory executable (`mmap` and `mprotect` are admitted, as a JIT
  needs) and run code it writes there. This release covers files; it runs
  under the same seccomp filter, Landlock domain, file and network rules
  as the agent either way.
- **Another mount of a writable directory, made by the host before the
  run** (a bind of it elsewhere), is not under a listed directory, so a
  read through it is not checked. The policy must also allow that path.
- **A rule that names its directory through a link** (or `.` or `..`)
  matches no path the Warden resolves. The Warden mounts the real directory
  and says so at start; the audit refuses such a record, since it cannot
  repeat the Warden's `realpath`. Name the directory itself.
- **A directory missing at start** is not mounted; if it appears during the
  run the agent's opens under it are refused. Make it before the run.
- **The audit holds a run's stream in memory:** about 700 MB for a
  24-hour stream of 283,000 records. On a 1 GB host, give it swap.
- **Compiled packages installed during the run** cannot be loaded from a
  writable directory without `--writable-exec`.
- **Only with `require warden 1.27`.** A policy without it keeps v1.26.1
  behaviour, and a library written to a writable directory still loads.
- From v1.27.0, still: arguments are not decided; interpreters and shells
  are broad; a swap between allowed programs is killed, not prevented; with
  `VAREK_WARDEN_NO_PIDNS=1`, `kill` reaches any process of the agent's
  user. Linux only; Landlock and a mount namespace required.

## Upgrading

1. Rebuild (`make`) and reinstall (`make install`). Run `varek doctor`: it
   reports Landlock and whether the Warden can make a mount namespace.
2. Run `varek policy show <policy>` for each `require warden 1.27` policy:
   it lists the directories the Warden would mount `noexec` on this host,
   and whether it would start. Narrow a writable rule that names `/`, a
   suffix or a glob from a wildcard; make the directories it names before
   the run.
3. If a run installs compiled packages into a writable directory and loads
   them, either install them before the run, outside the directories the
   agent may write, or run it with `--writable-exec` (recorded).
4. A short run, then `varek audit` and `varek refusals`.
