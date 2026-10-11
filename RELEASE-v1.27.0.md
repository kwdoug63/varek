# VAREK v1.27.0 — Decided Program Launches

> The review was done by AI review agents; a human or third-party review
> has not been done.

Released 2026-10-11 · MIT · github.com/kwdoug63/varek

## Summary

Through v1.26.1 the agent's own launch, the program the operator names, is
allowed once, and every later `execve` or `execveat` is refused, whatever
the policy's `allow exec` rules say. Allowing one would let the kernel read
the path a second time, after the Warden decided, and another thread could
swap it in between. So a coding or tool-using agent could not run `git`,
`python3` or a compiler, even where the policy named them.

From v1.27.0 a policy can have those launches decided:

    require warden 1.27
    allow exec /usr/bin/git
    allow exec /usr/bin/python3
    allow exec /usr/bin/cc
    allow exec prefix /usr/libexec/gcc/x86_64-linux-gnu/13/
    allow exec /usr/bin/as
    allow exec /usr/bin/ld

The kernel holds the set, and the Warden decides and records each launch.

1. **Opt-in.** `require warden 1.27` turns launches on, in the decision
   procedure, the certificate checker and the cross-check oracle. Under any
   earlier `require`, or none, a policy behaves exactly as on v1.26.1: every
   later launch is refused (`deny_only_nonfile_v191`). The shipped policy
   packs do not turn it on. The grammar of `allow exec` and `deny exec` is
   unchanged.
2. **The launch set, held by Landlock.** At startup the Warden expands each
   `allow exec` rule to the files it admits: an exact path, or a prefix or
   glob expanded by a bounded walk, each candidate decided by the decision
   procedure (an earlier deny wins; a deny on a file's own path keeps it out
   whatever symlink reaches it). Only regular files with an execute bit go
   in, at most 256 per rule, and each dynamic program's loader (its
   `PT_INTERP`, read with a bounded ELF reader), the program the operator
   named and a script's `#!` interpreter. The set is held by device and
   inode, with each file's canonical path and SHA-256, and recorded in
   `run_start` (`exec_ruleset`, and `landlock` with the ABI). The agent runs
   in a Landlock domain that grants `LANDLOCK_ACCESS_FS_EXECUTE` on those
   files only, applied after it drops its privileges and before seccomp and
   its own launch. A rule the Warden cannot expand to files (`suffix`,
   `contains`, a glob starting with a wildcard, a path with `.` or `..`
   segments) refuses the start, and lint says so.
3. **Deciding a launch.** A launch is decided on its name: the path as
   written, made absolute (a relative one against the working directory or
   the `execveat` descriptor), with `.` dropped and `..` resolved, a final
   symlink keeping its name; `execveat(fd, "", AT_EMPTY_PATH)` on the
   descriptor's file. An allowed launch must name a file of the set: the
   Warden answers it with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and records it
   (`exec_allowed`, with the file's device, inode and startup hash). A
   launch the policy allows of a file not in the set (written or replaced
   after startup) is refused, `exec_not_in_ruleset`. Without Landlock every
   launch is refused, `exec_no_landlock`.
4. **The identity check.** If another thread swaps the path after the
   decision, the kernel checks the file it opens against the Landlock set,
   so a swap can reach only a file in the set. Before the Warden answers any
   call of a process that has launched, it checks that `/proc/<pid>/exe` is
   a program it decided to run; a process that is not is killed before its
   call is answered (`exec_identity_mismatch`), the run's end records it,
   and the Warden exits 1. Each allowed launch gets one `exec_result`:
   `launched`, `failed`, `gone` or `killed`.
5. **What a compile needs.** With the opt-in only: `access(X_OK)` answers
   whether a launch of that name would be allowed (a directory's, as the
   read the policy decided); a lookup whose parent is missing too is walked a
   name at a time, as the kernel does; an open (not creating) of a missing
   file the policy would let the agent read answers ENOENT, recorded
   `open_not_found` and certified. gcc compiles and links under the Warden,
   each of its launches decided.
6. **The filter.** `vfork` and `dup2` are admitted, and `kill` for a
   positive pid (CPython's `subprocess` needs them). `memfd_create` stays in
   the hard-deny set: Landlock does not govern a memfd. The build fails if
   it leaves that set.
7. **Audit and tools.** `varek_audit.py` checks the set against the policy,
   each launch and each refusal against the policy and the set, one
   `exec_result` per allowed launch, and fails a run in which a process was
   killed. `varek refusals` explains `NOT_IN_SET`, `NO_LANDLOCK` and
   `KILLED`; the CycloneDX export carries the launch facts
   (`varek:launches.*`) and each launched file's hash; `varek doctor` and the
   preflight report Landlock; `varek policy show` lists the set the Warden
   would build on this host; `varek bench --launches` measures launches.

## Tested

`make test-v1270` runs 164 checks, CI runs it as root:

- **The grammar and the opt-in** (section 1, 36 checks): the opt-in in the
  three parsers, `require warden 1.28` refused, lint's notes (an interpreter
  or the loader allowed, a file both launched and written) and its
  refusals.
- **The launch set** (2, 39): exact, prefix and glob rules, a deny before
  and after an allow, a deny on a file's real path, symlinks, files without
  an execute bit, directories, the loader, the 256-file cap, malformed ELF
  files, the refused rule forms, `run_start`'s record of each file, a run
  in the Landlock domain, no Landlock.
- **Deciding a launch** (3, 30): allowed, denied and unknown launches, a
  file written during the run (`exec_not_in_ruleset`), a script whose
  interpreter is not in the set, `execveat`, relative names, children of
  children, the certificate.
- **The identity check** (4, 11): one `exec_result` per launch; a failed
  launch; a process forced (by a test hook) to run what was not decided is
  killed before its call is answered and the agent goes on; two threads
  launching allowed programs at once, 100 times, none killed.
- **The audit and the tools** (5, 35): 22 forged and re-chained streams the
  audit must refuse, each for its own reason; `varek refusals`, the export,
  `policy show`, `doctor`.
- **What launching needs** (6, 11): `access(X_OK)`, missing names, a
  compile, with and without the opt-in.
- **The measured table** (7, 2): in a Landlock domain granting execute on
  one program, the kernel refuses a program not in the set, a file written
  during the run, an `O_TMPFILE` or unlinked file through `/proc/self/fd`
  or `execveat`, a file in `/dev/shm` and the loader given a written file;
  an agent under the Warden cannot make a memfd.

The earlier suites (`test-v1240` to `test-v1261`) and `make test-cli` (71
tests) pass unchanged. **Against v1.26.1**, the 134 checks `test-v1270` had
before the review: 123 fail, 11 pass (each checks that something does not happen,
or that v1.26 behaviour is kept).

## 24 hours on a small host

`tests/soak_v1270` ran for 24 hours on a 1 vCPU, 1 GB droplet (Landlock
ABI 4), 2026-10-10 to 2026-10-11: a task a minute in turn (`git`,
`python3`, a compile with gcc), every tenth a probe that must be refused (a
program no rule allows, one a deny rule refuses, a program written during
the run). It passed:

| | |
|---|---|
| Duration | 24.00 h |
| Tasks | 1,296, all ok (432 each; p50 9 ms git, 52 ms python3, 92 ms compile) |
| Probes | 144 (48 of each kind), each refused for its reason and recorded |
| Launches | 3,600 decided, 3,456 allowed, each with its `exec_result` `launched` |
| Killed by the identity check | none |
| Records | 282,662; `varek_audit` passed |
| The Warden's decision, an allowed launch | 104 to 195 us p50 by program (p99 156 to 381) |

The soak ran the build from before the review's fixes (below). On the same
droplet, the reviewed build (Warden 1.27.0) then ran 6 minutes with a task
every 5 seconds, on 2026-10-11, and passed: 65 tasks all ok (21 compiles,
22 `git`, 22 `python3`), 7 probes of all three kinds each refused and
recorded, 178 launches decided and 171 allowed, each seen running, no
process killed, 14,256 records, and `varek_audit` passed. The soak
found two things, fixed: `soak_check.py` held the whole stream in memory
and was killed on the 1 GB host (it now reads it a line at a time); and the
Warden named itself 1.26.1 in `run_start` (and `varek version` said 1.21.1).

## Latency

`make latency-v1270` (`tests/latency_v1.27.0.txt`), N=1000 a kind, three
rounds, a 4-vCPU container, Landlock ABI 7 (the record names the Warden
1.26.1: the version fault above):

| p50 / p99, us | native | launches off | launches on |
|---|---|---|---|
| a launch the policy allows (spawn, launch, wait) | 934 / 2321 | refused: 117 / 502 | 1258 / 2996 |
| a launch a deny rule refuses | 939 / 2173 | 116 / 462 | 306 / 1110 |

An allowed launch costs 324 us more than natively at p50; the Warden decides
it in 72 us (p99 203), a refused one in 46 us (p99 143). The identity check,
measured by `varek bench` under a `require warden 1.26` and a `1.27` base
policy, three rounds each, is within the spread between rounds: about 0 to
3 us a call.

## Compatibility

- Every v1.26.1 policy loads unchanged and behaves as on v1.26.1. Nothing
  changes without `require warden 1.27`; `require warden 1.28` is refused.
- Launches need Landlock (Linux 5.13 or later, `landlock` in the active
  LSM list). Without it a `require warden 1.27` run starts, records
  `landlock: null`, and refuses every launch after the agent's own, with
  `exec_no_landlock`. `varek doctor` says which.
- New rules: `exec_allowed`, and for refusals `exec_not_in_ruleset`,
  `exec_no_landlock`, `exec_unresolved`, `exec_identity_mismatch`,
  `exec_identity_unreadable`; `open_not_found` for an authorized open.
  New event: `exec_result`. New fields: `run_start`'s `landlock` and
  `exec_ruleset`, `run_end`'s `exec_identity_mismatch`, an allowed
  launch's `exec_dev`, `exec_ino` and `exec_sha256`.
- `run_start` names the Warden `1.27.0`, as `varek version` does.
- `vdp_check` and `vdp_cert_check` have a `launches` mode (`on` or `off`).
  Lint fails on an allow exec rule the Warden would refuse at start, with
  launches on.
- The agent may now call `vfork`, `dup2`, and `kill` for a positive pid.

## Found in review

Five AI review agents (Claude), separate from the session that wrote the
code, each reviewed one part of v1.27 and had to reproduce every finding
(a script and its output): the launch set and Landlock; deciding a launch
and the identity check; a race harness; the grammar and the three parsers;
the audit and the tools. A safety classifier stopped three of them
partway (the race harness, and the launch-decision review twice); their
work was not retried. The agents are the same kind of model that wrote
much of this code, so this is not an independent human review. It found
real defects, listed below, but it does not replace a human or third-party
review. The full list, with what is recorded and not fixed, is in the
design note's "The review".

**High, fixed.** A launch the policy denied passed the audit relabelled as
the agent's own launch: the audit accepted that record at any position.
It must now be the run's first record and the only one.

**Medium, fixed.**
- Two threads launching allowed programs at once got the process killed (9
  of 40 runs): the launch that won was a mismatch for the other's.
- The Warden never checked that its two parsers agree on the opt-in; a bug
  confined to the decision procedure could have turned launches on. It
  now refuses to start, and a launch needs the checker's own reading.
- A `#!` line ending at the end of the file, which the kernel runs,
  refused the start or got the process killed.
- A deny on a file's real path did not keep it out of the set when an
  allowed symlink reached it.
- The audit accepted 25 of 45 forged streams: among them a `killed`
  result without a kill, `open_not_found` where the Warden cannot write
  it, an unchecked Warden version, refusals the Warden cannot write.

**Reported, not a defect.** `kill` admitted for any pid, on the reading
that the agent has no PID namespace. It has one (v1.9.3) and its own
process group, so a kill reaches only its own processes. `kill` is now
admitted for a positive pid only all the same, which matters only with
`VAREK_WARDEN_NO_PIDNS=1`.

**Low, fixed.** A loader's own loader followed (a long chain crashed the
start); a FIFO or device a rule names opened to read; `.` and `..` in an
exec path; the 256-file cap counting a file twice; a loader made a
process's image; the killed program's name read after the kill; lint
silent on rules the Warden refuses; glibc's older loader name missed by
the interpreter note; `varek` summarizing a damaged stream as whole;
`varek policy show` claiming launches would work when the Warden would not
start.

The grammar review's fuzzer compared the three parsers over 250,000
policies and 1.7 million launch queries under ASan and UBSan: no
disagreement. The ELF and `#!` readers took 1,000,000 inputs: no report.

## Known limits

- **Libraries are not decided.** Landlock governs what the kernel
  launches, not the executable mappings of shared libraries. Where a policy
  lets the agent both write and read a directory, code it writes there as
  a shared library may run inside an allowed program (`LD_PRELOAD`,
  `dlopen`, a Python native extension); that program is still held by the
  file and network rules. Not verified under the Warden. Planned for
  v1.27.1: mount the policy's writable paths `noexec` in the agent's own
  mount namespace.
- **Arguments are not decided.** `allow exec /usr/bin/git` allows `git`
  with any arguments, and they are not recorded: they are in the agent's
  memory, and another thread may change them after the Warden reads them.
- **Interpreters and shells are broad.** `allow exec /usr/bin/python3` lets
  the agent run any Python it can read. Lint and the Warden say so.
- **A swap between allowed programs is killed, not prevented.** The program
  swapped in may run until its first mediated call. The race harness the
  design called for (20,000 swaps) was not built: the agent asked to build
  it was stopped by a safety classifier.
- **A file changed in place** after startup keeps its inode; the record's
  hash is the one taken at startup. Lint notes a file both launched and
  written.
- **With `VAREK_WARDEN_NO_PIDNS=1`** (no PID namespace) `kill` and
  `tgkill` reach, by pid, any process of the agent's user. Run each agent
  as its own user (`--run-as`).
- **Linux only, Landlock required** for launches.

## Upgrading

1. Rebuild (`make`) and reinstall (`make install`). Run `varek doctor`: it
   reports Landlock and its ABI.
2. In a policy whose agent must launch programs, add `require warden 1.27`
   and an `allow exec` rule for each program (an exact path; a prefix or
   glob for a directory of them, such as a compiler's). A script needs its
   interpreter allowed too.
3. Run `varek policy check <policy>` and `varek policy show <policy>`: the
   latter lists the files the Warden would hold on this host. Then a short
   run, and read `varek refusals` and `varek audit`.
