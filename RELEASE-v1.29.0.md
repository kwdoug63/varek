# VAREK v1.29.0 — Run an Agent With Nothing Set Up First

> v1.29.0 had a correctness review: the code read, GCC's static analyzer,
> and the suite under AddressSanitizer and UndefinedBehaviorSanitizer. The
> adversarial review by AI review agents the ship gates call for has not
> been done yet, and a human or third-party review has not been done.

**Draft.** Pending: the adversarial review, the shared 24-hour soak (with
v1.28.1 and v1.31.0) and the date.

MIT · github.com/kwdoug63/varek

## Summary

Through v1.28.1, running an agent under VAREK meant writing a policy first:
which files, which hosts, which programs. Most people do not know what
their agent touches, so they could not start.

From v1.29.0, `sudo varek run -- claude` (or `codex`, `gemini`, `aider`, a
Python or Node.js agent) runs with nothing set up: VAREK writes a policy
for the run from the host as it is, opens files as the agent's own user so
the kernel's permissions hold as well as the policy, and records every
decision as before. To find out what a narrower policy would refuse, a dry
run records it all and enforces nothing; `varek policy suggest` turns what
it recorded into a draft policy to review.

1. **Opening files as the agent (`require warden 1.29`).** Through v1.28.1
   the Warden opened every allowed file as root and handed the agent the
   descriptor, so a file the agent's user could not read was readable if
   the policy allowed it, and a file the agent made was root's. Under
   `require warden 1.29` the walk and the open are made by a Warden thread
   holding the agent's uid, gid and groups (setfsuid, setfsgid and
   setgroups on that thread only): a call needs the policy and the kernel's
   permissions both, and the agent's files are its own, with its mode and
   umask. `run_start` records whom files were opened as (`open_as`).
2. **Changing files by name.** unlink, rmdir, mkdir, rename (each name),
   chmod, utimes, truncate and chdir were refused outright (EPERM); now
   each is decided as a write on every name it touches and carried out as
   the agent. link and symlink stay refused (a second name is how a deny
   rule would be escaped), and a directory rename is answered EXDEV. Each
   is recorded with the flags its kind is decided as.
3. **The baseline policy, and the agents' profiles.** With no settings,
   `varek run` writes the policy for the run (root's, named by its SHA-256,
   under `/var/lib/varek/policies`, never rewritten): the credential stores
   and keys refused first, the system read-only, the working directory and
   a private temporary directory writable, the user's home closed but for
   the profile's directories, launches of the programs root owns by name,
   no network but the profile's hosts. A profile (`policies/agents/`) adds
   what one agent needs; it is chosen by the command's name (through
   `env`, `npx`, `uvx` and an interpreter) or `--profile`. The agent runs
   as the user who ran sudo (never root), with a clean environment and the
   variables named with `--env`. `varek run --show-policy` prints the
   policy; `run_start` records its header (`baseline`).
4. **The profiles come from evidence.** Each shipped profile (Claude Code,
   the Codex CLI, the Gemini CLI, Aider, Python, Node.js) was built from a
   dry run of the real agent and `varek policy suggest`, then checked by
   running the same commands enforcing against the same commands without
   VAREK: the same output, up to where each asks for an account or a key.
   `tests/profiles_v1290.sh` repeats that on a host with the network.
5. **A dry run (`--dry-run`, on the command line only).** Every call is
   decided and recorded; one the policy refuses is let through (the kernel
   carries it out as the agent, or the Warden dials it) and recorded
   `"enforced":false`, with the verdict the policy gave. The hard-denied
   system calls, the protected objects, Unix-socket connects and
   revocation still refuse, and a dry run is refused with a plan,
   credentials or sub-agents. `run_start` and `run_end` say `dry_run`;
   the Warden says `DRY RUN: NOT ENFORCING` at the start and the end.
6. **`varek policy suggest`.** Reads a run's stream and writes a draft: the
   policy as it was, then exact rules for what was refused (reads,
   writes, launches by the name used, hosts by the name the agent asked
   for), each re-decided by the decision procedure, and a directory rule,
   commented out, where five or more objects share one. Anything a deny
   rule refuses, a credential store or key, another user's home, a write
   under a system directory, a launch of sudo, su, doas or pkexec, and any
   program the agent wrote is commented out with the reason, never active.
7. **What the agents needed.** Running the four CLIs enforcing showed what
   no test had: under `require warden 1.29` the Warden now decides stat(2)
   and lstat(2) (musl calls them; the Codex CLI made thousands), admits
   getrusage, restart_syscall, process groups and sessions, timers, umask,
   flock, fadvise64, fstatfs, capget, mbind, pidfd_open and prctl for a
   short list of options; decides a lookup under a missing directory on
   the whole name asked for; answers a mkdir of a name that is there with
   EEXIST where the agent may look it up; and, inside a directory mounted
   noexec (v1.27.1), keeps exec where no rule that lets the agent write
   reaches, so an agent installed in the home can start (`noexec_exec` in
   `run_start`). The baseline reads the certificate authorities' bundles
   ahead of the `*.pem` key pattern, and what runtimes read at startup.
8. **Audit, export and tools.** `varek_audit.py` checks a dry run's stream
   (every record not enforced refuses, is in a dry run, is not one D2
   keeps refused, and none follows a revocation; `run_end` counts them)
   and verifies it with exit **3**, `VERIFIED: DRY RUN, NOT ENFORCED`,
   never 0; it checks `open_as`, the baseline's header, the changes by
   name and the places kept executable. The CycloneDX export marks a dry
   run's mode, counts what would have been refused, and says so in its
   attestation. `varek refusals` lists `WOULD_REFUSE` with `--enforced` and
   `--not-enforced`; `varek runs` has a MODE column; `varek status`,
   `varek policy show` and `varek doctor` say what a dry run and the
   baseline are. `varek bench --open-as` and `--baseline` measure them.

   The launch set (v1.27) is now hashed with OpenSSL's libcrypto, which
   uses the CPU's SHA extensions where it has them (libsodium's portable
   SHA-256 took about 0.6 s on a 123 MB Node.js at every start); it reads
   no OpenSSL configuration. The Warden reports `1.29.0`.

## Tested

`make test-v1290` runs 316 checks; CI runs it as root:

- **Opening as the agent** (section 1, 34): the agent's files are its own,
  with its mode and umask; a root-only file stays unreadable; a closed
  directory stays closed; the same under `require warden 1.28`, as before.
- **The baseline, the profiles and `varek run`** (2 with 6, 88): each
  profile chosen by each spelling of the command; the credential stores
  refused; the policy stored, recorded and audited; a Python and a Node.js
  agent reading their packages, writing in the working directory,
  launching git and sh, and reaching a stand-in model API; `--env`, the
  agent's user and its environment; the cross-check on a baseline.
- **Changes by name** (2b, 46): each change, its record and its flags;
  renames of both names; a directory rename; link and symlink refused.
- **The dry run** (3, 32): each kind let through and recorded; what D2
  keeps refused still refused; revocation; the refusals with a plan,
  credentials or sub-agents.
- **`varek policy suggest`** (4, 23): each kind of rule, each reason a rule
  is never active, determinism, the draft linting, and a second dry run
  under the draft no longer refusing what it allows.
- **Audit, export and tools** (5, 33): 13 forged streams the audit refuses,
  each for its own reason; exit 3; the export's marks; each tool's output.
- **What the agents needed** (7, 60): stat(2) and lstat(2); lookups under a
  missing directory; mkdir of an existing name; each admitted call and
  prctl's other options refused, and the same calls refused under 1.28;
  the agent's program inside a directory it may write, and five forged
  streams; the baseline's trust stores, runtime files, PATH directory and
  git helpers; the profiles' shape; libcrypto reading no configuration.

Every earlier suite (`make test-cli`, `test-lifecycle`, `test-v112` to
`test-v1281`) passes. `make crosscheck`: 0 disagreements;
`make crosscheck-profiles` (the baseline alone and with each profile): 0.
**Against v1.28.1** (its own tree, with this suite, its test program and
the profile files copied in; measured on the 313 checks of step 7): 290
fail, 23 pass. Of the 23, 2 check a refusal v1.28.1 shares, 9 that a
`require warden 1.28` policy behaves as before, 9 that something does not
happen (which holds when nothing runs), and 3 pass by coincidence (the
design note lists them).

## Latency

Measured in a 4-vCPU container without SHA extensions (`make
latency-v1290`, written to `tests/latency_v1.29.0.txt`), 3 rounds of 2000
calls of each kind; a decision moves by about 10 us from run to run here:

| | the Warden's decision, p50 | |
|---|---|---|
| an allowed open, opened as root (1.28) / as the agent (1.29) | 82 / 95 to 101 us | +11 to +19 us (five runs) |
| a refused open, 1.28 / 1.29 | 23 / 30 us | +5 to +7 us |
| a connect | unchanged | |
| under the baseline (205 rules) or a profile, against a 34-rule pack | no measurable difference | |

In a dry run, a system call outside the allowlist takes 51 us (0.3 us
natively, 0.4 us refused when enforcing); an allowed call costs what it
costs enforcing. Starting a run (wall time, p50, 20 runs): 57 to 61 ms under a
34-rule pack; 167 to 177 ms under the baseline (87 programs in the launch
set, each hashed at the start); 541 to 655 ms with the claude profile, which
adds Node.js (123 MB here). With libsodium's SHA-256 these were 229 and
917 ms; on a CPU with SHA extensions libcrypto is several times faster
still.

## Compatibility

- Every v1.28.1 policy loads unchanged and decides the same; nothing in 1
  to 7 above happens without `require warden 1.29`, and a dry run of an
  earlier policy records the calls its filter refuses as such.
- The Warden now links OpenSSL's libcrypto (already a build dependency for
  `warden-proxy` and `warden-secrets`).
- Under `require warden 1.29`: a file the agent's user cannot reach is not
  reached whatever the policy says, and files the agent makes are its
  own; the agent's working directory must not be `/`, a system directory
  or a home directory itself.
- New: `varek run --dry-run`, `--profile`, `--env`, `--show-policy`,
  `--baseline`, `--writable-exec`; `varek policy suggest`; `varek
  refusals --enforced/--not-enforced`; `varek bench --open-as/--baseline`;
  `warden --dry-run`. New `run_start` fields: `open_as`, `baseline`,
  `agent_env`, `mode`, `noexec_exec`; `run_end`: `mode`, `not_enforced`;
  records: `"enforced":false`. New rules: `change_done`, `change_failed`,
  `chdir_continued`, `mkdir_exists`, `mkdir_exists_ancestor`,
  `syscall_not_admitted`, `rename_directory_refused`. `varek audit` exits
  3 for a dry run.

## Found in review

The correctness review found one fix, made with a check: the baseline made
the directory the agent's PATH gained for its command readable, whatever
it was; for a command at `/home/x` that was every home on the host. Now
only a `bin` directory that is not a system directory, the home or the
working directory. GCC's static analyzer reported nothing, and the suite
under AddressSanitizer and UndefinedBehaviorSanitizer passed all 316 checks with no report.

Running the four agents found more than profile rules (7 above): none of
them started enforcing until the noexec places, stat(2) and the admitted
calls were in, and the audit read a dry run's stub questions wrongly; each
was fixed with checks (sections 5 and 7).

## Known limits

- **A dry run is not a sandbox.** It lets through what the policy refuses:
  the agent can do what its own user can, outside the D2 refusals.
- **A draft is a draft.** `suggest` proposes; a person reviews.
- **Programs root does not own** (Node.js under nvm) are not named by a
  profile, so launching them is refused; take a dry run and `suggest`.
- **Still refused under the baseline:** inotify, statfs(2) on a path, link
  and symlink, listening sockets (an OAuth sign-in that listens on a port:
  give the agent a key instead); the shell's start-up files and `.env`
  files. The Codex CLI's own sandbox needs user namespaces: run it with
  `--sandbox danger-full-access` under VAREK.
- **The certificate authorities' bundles** are read ahead of the key
  patterns: a key placed among them is readable.
- From v1.28.1, still: the chain is recorded, not enforced. From v1.28.0:
  a server that echoes a credential back. From v1.27.1: code written into
  memory is not covered; Linux only.

## Upgrading

1. Rebuild (`make all`, which now links libcrypto) and reinstall (`make
   install`).
2. To try it: `sudo varek run --dry-run -- <agent command>` in a project
   directory, then `varek refusals --not-enforced` and `varek policy
   suggest`. Then `sudo varek run -- <agent command>`.
3. To move a policy of your own to 1.29: `require warden 1.29`, a dry run
   of a typical session, and check what changes (the agent's user's
   permissions now hold; changes by name are decided).
4. Run `varek doctor`, then `varek audit` on a run (exit 0 enforcing, 3 for
   a dry run).
