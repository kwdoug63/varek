# Changelog

All notable changes to VAREK are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — the v1.10 / v1.11 verification program (continuing)

The program: **shrink the UNKNOWN region without weakening soundness.** Every
item moves cases out of UNKNOWN into a provable SATISFIED or UNSATISFIED, and is
admitted only under a soundness obligation that forbids it from ever turning a
genuinely unsafe action into SATISFIED. "v1.10" and "v1.11" name the program;
its first release shipped as **v1.13.0** (below) so version numbers keep
increasing. Shipped in v1.13.0: the SMT decision procedure in the enforcement
path, the bitvector flag fragment, the prefix/equality part of the bounded
string fragment, and the verdict-distribution harness (synthetic seed corpus).
Shipped in v1.14.0: the rest of the bounded string fragment (suffix, contains
and glob matchers, with exact load-time reachability). Shipped in v1.15.0:
certificates for every authorization, checked in-line by an independent
checker. v1.16.0 (outside the program) protects the verdict stream against its
holder and bounds the cost of one decision. Still planned: a customer-derived corpus and measured baseline, a
formally verified checker, and the v1.11 sequence fragment.

### Planned — v1.10 program (status as of v1.16.0)

- **Verdict-distribution harness.** Measurement and regression gating over a
  corpus of realistic agent action-graphs. Reports the four-cell outcome
  (SATISFIED/UNSATISFIED/UNKNOWN against ground-truth SAFE/UNSAFE), the
  safe-action clear rate, and a hard `unsafe_satisfied == 0` gate. Ground truth
  is the customer-authored policy; adversarial near-miss labels come from an
  independent oracle, never from SAI. Built first; a measured baseline is itself
  a shippable milestone.
- **Bitvector flag/argument fragment.** Decidable QF_BV reasoning over syscall
  flag/argument bits, aligned with the Warden kernel layer (provisional
  #64/059,592). Soundness obligation: ABI-faithful width/signedness, plus a
  conservative-mask rule (bits outside the policy's mask force UNKNOWN, never a
  silent SATISFIED). Lowest audit cost; lands first to prove the loop end to end.
- **Bounded string fragment.** *(Shipped: prefix/equality in v1.13.0;
  suffix, contains and globs — the fixed regular family chosen for the "fixed
  regex set" — in v1.14.0.)* A deliberately restricted, length-bounded string
  fragment (prefix/suffix/contains and membership in a fixed regex set) so the
  verifier can prove path-prefix and host-allowlist predicates instead of
  refusing them. The expected headline reduction in over-refusal. Soundness
  obligation: encoding faithfulness plus a length-guard (over-length strings
  escape to UNKNOWN; never truncate-then-check). No new decision procedure — the
  fragment lowers into procedures already in scope.

### Candidate — v1.11

- **Bounded sequence fragment.** Element-level reasoning for the cross-action
  data-flow subsystem, modeling collections as a fixed `N` slots plus a length.
  Composes on top of the bounded string/bitvector fragments (a sequence element
  is one of those). Soundness obligation adds a composition lemma and a
  bounded-length guard. Sequenced after strings because it inherits the element
  fragment's guarantee.

---

## [1.17.0] - 2026-09-29

v1.17.0 closes three live gaps found in the v1.16.3 review: the Warden's own
files could be reached through an alias, metadata and link lookups were
admitted and never logged, and the agent ran as root with every capability.
It changes defaults (the agent is no longer root; lookups are now decided by
the policy), so it is a minor release. No verdict *semantics* change.

### Security

- **The signing key, anchor and verdict stream are refused by identity.**
  Through v1.16.3 the Warden refused to start if the policy allowed these by
  their real path only. With the key's directory bind-mounted into an allowed
  tree, the agent read the private key. Every open and lookup is now checked,
  after resolution and before the policy, against their device and inode
  (`protected_object`), so any alias is refused.
- **Raw storage and memory are refused whatever the policy says.** Block
  devices, `/dev/mem`, `/dev/kmem`, `/dev/port`, the sg/bsg/nvme command
  devices and `/proc/kcore`, reached by any path (`raw_device`).
- **stat, statx, access and readlink are mediated.** They were admitted and
  unlogged, so an agent could learn whether any file existed, its size, owner
  and times, and where any link pointed (including the Warden's own
  `/proc/<pid>/fd` entries). They are now resolved like an open, decided as a
  read-only open of the same object (`access(W_OK)` as a write), certified,
  recorded and answered by the Warden. A missing name gives `ENOENT` inside the
  policy and `EACCES` outside it. `access(X_OK)` is refused.
- **The agent runs unprivileged.** It ran as root with every capability; it now
  runs as `nobody` (or `--run-as <user|uid[:gid]>`) with no supplementary
  groups, an empty capability bounding set and no capabilities. `--run-as
  root` keeps the old behaviour with a warning.

### Changed

- The program is opened by the Warden while still root and launched with
  `execveat(fd, "", AT_EMPTY_PATH)`, so the unprivileged user needs execute
  permission on the file only. A script (`#!`) is launched by its path, so its
  directories must be searchable by that user. PATH is searched as `execvp`
  does. The launch approval accepts that `execveat` once, from the launched
  process only.
- Answered without a decision: a lookup on a descriptor the agent already holds
  (not recorded, like `read()`), and a read-type lookup on a directory an allow
  rule's literal start leads to (recorded as `metadata_ancestor`), so
  `realpath()` works on allowed paths.
- Records gain the actions `file.stat`, `file.access` and `file.readlink` and
  the rules `metadata_answered`, `metadata_not_found`, `metadata_failed`,
  `metadata_ancestor`, `protected_object` and `raw_device`. The status line
  gains `uid=` and `caps=`.
- `varek_audit.py` re-checks the certificates of lookups and checks every
  `metadata_ancestor` record against the policy.
- Python 3 startup under the Warden: about 39 ms, from 31 ms (24 ms without
  the Warden). Decision latency unchanged within run-to-run noise.

### Added

- `varek/v1_4/tests/v1170_probe.c`, `tests/test_v1170.sh`,
  `tests/v1170_policy.txt`; `make test-v1170` (36 checks). Against v1.16.3,
  20 of them fail: the key, stream and anchor are read through a bind mount,
  lookups outside the policy succeed unrecorded, and the agent is uid 0.
- `RELEASE-v1.17.0.md`.

### Fixed

- `docs/security/bypass-classes.md`: classes 5 and 6 updated; new rows for
  metadata lookups (10) and aliases of the Warden's own files (11).

---

## [1.16.3] - 2026-09-29

The Verdict Service's plan checker, in the repository. The VAREK Verdict
Service (api.varek-lang.org) runs `plan_verify`, a small file-in / JSON-out
front end over the v1.6 plan evaluator, whose source had existed only on the
service host. It is now in the repository, builds with `make plan_verify`, and
its output is escaped. No change to how verdicts are decided; the Warden
changes only in the version it writes into `run_start`.

### Added
- `v1_6/plan_verify_cli.c` and `make -C v1_6 plan_verify`: reads a plan file,
  runs the v1.6 compositional evaluator with a small demonstration policy (and
  the caller-asserted `demo:SAT:` / `demo:UNSAT:` / `demo:UNK:` override), and
  prints one JSON verdict. It is a demonstration front end, not a production
  policy: whoever writes the plan can assert any verdict through the override.
- `v1_6/tests/test_plan_verify.sh` (`make -C v1_6 check-plan-verify`, 24
  checks), `v1_6/tests/compare_plan_verify.py` (old and new builds on random
  plans), and a CI step that builds and runs it with the v1.6 unit tests.

### Fixed
- Plan text could change the verdict fields of `plan_verify`'s JSON. Labels,
  kinds, targets and parse errors were written into the output unescaped, so a
  target such as `x"},"decision":"SATISFIED","authorized":true,"g":{"t":"`
  produced output that a parser keeping the last duplicate key (Python's
  `json` module, which the Verdict Service uses) read as SATISFIED and
  authorized, although the evaluator had decided UNSATISFIED (the same worked
  through the kind). A backslash, control character (other than DEL) or
  invalid UTF-8 in a target made the output invalid JSON. Every string is now
  escaped; invalid UTF-8 becomes U+FFFD.
- `plan_verify` exited 0 when its output could not be written; it now exits 3.

### Changed
- `plan_verify` reports `"version":"1.16.3"` (it said `"1.9.2"`, the release
  it was first built from). For every plan without those characters the
  output is otherwise byte-for-byte the same (3,000 random plans here; 23,000
  in the independent review).
- `run_start` reads `"warden":"1.16.3"`; the CycloneDX export's VAREK version
  is 1.16.3.

## [1.16.2] - 2026-09-28

The off-host anchor. An anchor file on the Warden's own host does not protect
against that host's root, who also holds the signing key; this release ships
the pieces to anchor on a second machine as records are written. No change to
decisions, records or the policy grammar.

### Added

- `tools/varek_anchor_forward.py`: reads the Warden's anchor FIFO (creating it,
  holding it open, and holding `FIFO.lock` as proof it is alive), spools every
  well-formed anchor line locally, and sends it off-host (`--ssh USER@HOST`
  with a dedicated key and pinned host key, or `--exec COMMAND`), retrying with
  backoff; at-least-once delivery, resumes after restarts; on a full disk it
  pauses reading and cuts partial writes back; refuses files owned by others
  or reached through symlinks.
- `tools/varek_anchor_receiver.sh`: sets up the anchor host: an account whose
  SSH key has one forced command appending well-formed anchor lines to a
  `chattr +a` file (no shell, forwarding or other command).
- `tools/systemd/varek-anchor-forward.service`.
- Preflight: a FIFO anchor must have a reader (FAIL otherwise); `--spool DIR`;
  a trial run with a FIFO anchor is audited against the spool; warnings for a
  local-file anchor and for a signing key with no off-host anchor.
- The receiver's forced command reads the whole batch before locking, stamps
  it with the receiver's clock (`"received_ns"`), closes a torn line, and fails
  (so the forwarder retries) when it cannot write; setup checks everything
  before creating anything and refuses a public key with more than one line,
  an existing account that is not its own, root, and a filesystem without
  `chattr +a` (unless `--allow-no-chattr`).
- Audit: `--list-runs`, `--max-anchor-delay` (measured from the stream's signed
  times), `--clock-slack` (default 5 s: a record received more than this before
  it was written fails the run, so both hosts need synchronised clocks; both
  options take only a finite number of seconds ≥ 0); a record is anchored if any validly signed line matches it;
  unsigned, conflicting and malformed lines are noted and ignored; a signed
  line for a record the stream lacks fails the run unless it arrived after the
  run's run_end was anchored.
- Preflight: forwarder liveness via its lock; with `--run --spool`, checks the
  trial run's own records were delivered off-host.
- `make test-v1162`.

### Fixed

- The command order in `RELEASE-v1.16.1.md` and `varek/v1_4/README.md`:
  `varek_keygen` was run before anything built it.

### Changed

- The Warden refuses a FIFO anchor whose forwarder lock (`FIFO.lock`) is free,
  holds the FIFO read-write after checking it has a reader, so records written
  while the forwarder restarts wait in the pipe, and at exit, if no forwarder
  runs, waits up to 10 s for one to read them.
- `run_start` reads `"warden":"1.16.2"`.

## [1.16.1] - 2026-09-28

Deployment preflight for v1.16.0's two new requirements: the verdict stream
check (the Warden refuses a stream file the agent could open) and libsodium.
No change to decisions, records or the policy grammar.

### Added

- `tools/varek_preflight.sh <policy> [--log] [--sign-key] [--anchor] [--run]
  [--install-deps]`: build dependencies, build, policy, every location the
  Warden refuses at startup (stream, key, anchor, raw disks), and with `--run`
  a trial run whose stream is audited.
- `tools/vdp_cert_check <policy> openable`: could the agent open this path
  (the Warden's own check, `vdpc_path_openable`, on the canonical path).
- `make deps`, `make deps-check` (a Warden build stops with the install command
  when the libseccomp or libsodium headers are missing; up-to-date binaries
  need none), `make preflight`.
- `make test-v1161`; CI job `.github/workflows/warden-build.yml` (installs
  `libseccomp-dev` and `libsodium-dev`, builds, lints and preflights the
  shipped policies).

### Changed

- `run_start` reads `"warden":"1.16.1"`.
- The Warden's raw-device check matches `/dev/bsg/` exactly.
- Sector policies: a header note on where to put the verdict stream
  (`/var/log/varek/`; comments only).
- `docs/development.md`, `varek/v1_4/README.md` and the video scripts list the
  libsodium build dependency.

## [1.16.0] - 2026-09-28

Addresses the two limits v1.15.0 disclosed. The verdict stream is hash-chained,
Ed25519-signed at checkpoints and optionally anchored off the log, so whoever
holds the log cannot rewrite it undetected; and a policy's globs are capped at
4,096 tokens, which bounds the work of one decision (on adversarial policies
about 26 ms median in the live Warden, 61 ms at most observed; v1.15's checker
alone took 415 ms).

### Added

- **Hash chain**: every record of a run ends with `"chain"`, SHA-256 of the
  previous chain value and the record's exact bytes; `chain_{-1}` =
  SHA-256("VAREK-LOG-CHAIN-1"). run_start carries `"log":"chain-1"`.
- **Signatures** (`--sign-key FILE`): run_start, a `checkpoint` record every 64
  decision records (`--checkpoint-every N`) and at least once a second while
  records are pending, and run_end carry `"sig"`, an Ed25519 signature over
  "VAREK-LOG-SIG-1" || chain (libsodium). run_start names the public key.
  Checkpoints are written between notifications. `tools/varek_keygen` makes a
  key pair (seed file 0600, `.pub`).
- **External anchor** (`--anchor PATH`, a file, FIFO or character device):
  each checkpoint-type record is appended as one line, non-blocking; a failed
  write becomes an `anchor_error` record.
- **Startup refusals**: a key file that is not a private regular file with one
  name, a malformed key, or a policy that would let the agent open the key or
  the anchor (decided by the certificate checker, `vdpc_path_openable`, on the
  path the kernel reports for the open file); with a key or anchor, a policy
  that would let the agent open a block device, `/dev/mem`, `/dev/kmem`,
  `/dev/port`, `/proc/kcore` or a disk command device; for every run, a
  verdict stream file the policy would let the agent open; a FIFO anchor with
  no reader. The key is kept in libsodium's guarded memory.
- **Audit**: `--pubkey` (the stream must be signed by that key) and `--anchor`
  (every signed record anchored and every anchored record present; any
  `anchor_error` fails); a complete signed stream must end in a signed
  run_end; at most `checkpoint_every` decision records between signatures;
  `--allow-incomplete` audits only up to the last signature; `--run ID`; the
  run's start time is printed; an `integrity:` line (`none`, `chain`,
  `signed, key not pinned`, `signed`, `signed, anchored`). Signatures are verified by
  `tools/varek_ed25519.py`, a pure-Python RFC 8032 verifier (canonical
  encodings, S < L, no small-order key), not by the signing library.
- The stream parser (exporter and audit) verifies the chain of v1.16 streams
  and refuses a 1.16+ stream whose chain was stripped; the BOM gains
  `varek:log.chain` and `varek:log.pubkey`.
- `vdp_check lint` reports the policy's glob size against the cap.
- `make test-v1160` with `tests/v1160_probe`; `tests/log_rechain.py` (test
  helper: recompute the chain, or re-sign, as a log holder would).

### Changed

- **Glob tokens per policy capped at 4,096** (was 65,536) in the decision
  procedure, the certificate checker and the cross-check's parser.
  `tests/v1140_bound2_policy.txt` split into `v1140_bound2` and `v1140_bound4`.
- The certificate checker matches `contains` with `memmem` (linear time), and
  its glob matcher computes each row in one pass (no per-byte clearing and
  copying).
- A rejected `--plan` ends the stream with run_end.
- If a record cannot be written to the verdict stream, the Warden stops
  supervising (the agent is killed) instead of running on unrecorded. With
  `--anchor`, SIGPIPE is ignored by the Warden (restored for the agent).
- `run_start` reads `"warden":"1.16.0"`; `require warden 1.16` is accepted.
- The Warden and `tools/varek_keygen` link libsodium.
- Regression tests that edit a stream to test the certificate audit
  (`test_v1150.sh`, `test_v1122.sh`) recompute the chain first.

### Fixed

- The report of an agent killed by a signal ("agent killed by signal 31") was
  lost about one run in four: the SIGCHLD handler could end the loop before the
  agent's exit was noticed.

## [1.15.0] - 2026-09-28

Third release of the v1.10 verification program: certificates. Every SATISFIED
verdict carries a certificate — the deciding rule and a witness that its
constant matches — and the Warden authorizes the action only if a separately
written checker accepts it. For authorizations, the decision procedure moves
from trusted to checked against logic bugs; the trusted decision code is now
the checker (about 540 lines of C, its own parser and matchers, no shared
source).

### Added

- **Certificate checker** `checker/vdp_checker.c` (with SHA-256) and its CLI
  `tools/vdp_cert_check` (`digest`, `batch`, `holds`). The glob matcher is a
  row-by-row dynamic program with literal prefix/suffix/length pre-filters. Checks that the action is
  in the fragment, that rule `r` is an allow rule of the kind whose flag clause
  holds, that the witness proves its constant matches (`contains`: an offset;
  `glob`: one span per `*`, `**`, `/**/`), and — deciding them itself — that no
  earlier rule holds. For the `--plan` gate's any-flags claims it enumerates
  every admissible value of the relevant flag bits.
- **Certificates from the procedure**: `vdp_certificate()` (glob witnesses by a
  backward walk over the automaton's state sets); `vdp_check batch` prints the
  witness of every SATISFIED verdict; `vdp_policy_load_mem()`.
- **In-line checking in the Warden**: the policy file is read once, both parsers
  parse the same bytes (the Warden compares the two parses rule by rule and
  refuses to start on any difference), and
  their SHA-256 is recorded in `run_start` as `policy_sha256`. A file open is
  authorized only after the checker accepts its certificate; records carry
  `open_flags`, `cert_rule`, `cert_witness` and `check` (flat fields). A
  refused certificate denies the open
  (`certificate_refused`, with `check_why`). The `--plan` gate certifies too.
- **Audit**: `tools/varek_audit.py` re-checks a saved verdict stream
  (authenticated against the agent as by the exporter, tied to the policy file
  by SHA-256, no authorization other than certified file opens and the launch
  exec, every certificate re-checked by the checker; test-build streams
  refused). It does not protect the log from whoever holds it. The CycloneDX export
  includes the policy SHA-256 and each authorization's certificate.
- **Cross-check `--cert`**: the checker's parser and digest against the
  procedure's and Python's; every emitted certificate accepted; forged,
  shadowed and mutated certificates judged correctly; the checker's per-rule
  matches against the oracle's languages.
- `make test-v1150`, with a test-only `warden_faultinject` whose procedure has a
  planted bug: the checker refuses its wrong verdicts.

### Changed

- `run_start` reads `"warden":"1.15.0"`; `require warden 1.15` is accepted.
- `bench_summarize.py` parses each record line as one JSON object (its regular
  expression for flat objects would drop a record with a nested value).

## [1.14.0] - 2026-09-28

Second release of the v1.10 verification program: the rest of the bounded
string fragment. Path and exec rules take a matcher before the constant —
`exact`, `prefix` (the path default), `suffix`, `contains` or `glob` — so a
policy can deny a kind of file wherever it appears under an allowed tree. Every
v1.13 policy keeps its meaning; three-state semantics and symmetric suppression
are unchanged.

### Added

- **Matchers** `exact | prefix | suffix | contains | glob` on path and exec
  rules. Globs: `?`, `[...]` sets (never `/`), `*` (no `/`), `**` (any bytes),
  the `/**/` unit (zero or more whole segments), `\x` escapes; anchored,
  byte-wise, case-sensitive, matched on the resolved canonical path. At most 32
  wildcards per glob and 65,536 glob tokens per policy (bounds the work of one
  decision); `***`, a `/` in a set, bad ranges, unterminated sets and matchers
  on host rules are load errors.
- **Glob matching** by a compiled token automaton with literal prefix/suffix
  and minimum-length rejection and a word-parallel step (cost independent of
  the number of active states). Worst case at the cap: 12 ms per decision on
  an adversarial policy; typical overhead about 0.1 µs.
- **Exact rule reachability for the new atoms**: breadth-first search over the
  product of the rules' subset-construction automata, bounded at depth 4095 so
  the length bound is decided exactly, with flag signatures enumerated and only
  inclusion-minimal shadow sets searched; UNKNOWN (never a guess) past a state
  or work budget. `vdp_check <policy> analyze` prints a shortest witness string
  and flags value for every reachable rule; `analyze automaton` forces the
  automaton search (testing).
- **Cross-check**: independent Python parser and glob translation; Z3 string
  and regex theories for verdicts and witness confirmation; a
  Brzozowski-derivative procedure (exact at the bound) for reachability, also
  checked against Z3's unbounded regex query where conclusive; UNKNOWN accepted
  only with a documented budget reason. Fixtures for the length bound,
  shadowing, the state budget and keyword compatibility.
- **Harness**: a "v1.13.0 shipped" view (`harness/baseline-v1.13.0/`) and 24
  corpus actions (17 UNSAFE, 7 SAFE near misses).
- `make test-v1140`: live-Warden enforcement of every matcher (including
  through a symlink), analysis, parser refusals, v1.13 compatibility against
  the v1.13.0 build, the `--plan` gate, cross-check and harness gate.

### Security

- The example sector policies deny `.pem` and `.key` files, dotenv files
  (`.env`, `.env.*`) and anything under a `.ssh` directory under every allowed
  tree; finance denies macro-capable workbooks in its read/write workpapers;
  healthcare denies psychotherapy notes (directory and files, any depth);
  national-defense denies compartmented products. On the synthetic corpus the
  17 unsafe opens v1.13.0's policies authorized (all added in this release) are
  refused, with no safe open lost (87.5% of safe opens cleared in both).
- Name matchers judge the path's name, not the file's identity; the agent
  cannot rename or link files while the Warden enforces (those syscalls are
  outside the allowlist), but can in observe mode.

### Changed

- After `require warden 1.14`, a matcher keyword with no constant (forgotten,
  or turned into a comment by `#`) is a load error rather than a prefix rule
  for the word.
- `require warden` takes `<digits>.<digits>` only (a sign, accepted by v1.13's
  `sscanf`, is refused).
- The Warden and `vdp_check lint` note a path/exec constant that can match no
  absolute path, and name the reason when reachability is not decided.
- `run_start` reads `"warden":"1.14.0"`; the CycloneDX exporter reports 1.14.0.

## [1.13.0] - 2026-09-28

First release of the v1.10 verification program. Every Warden decision is now
made by an SMT decision procedure (`smt_decide.c`) over a quantifier-free
fragment of bounded strings (the object) and 32-bit bitvectors (the open flags),
replacing v1.12's prefix/equality matching. Three-state semantics and the
symmetric-suppression invariant are unchanged; flag-free policies decide as
before, except that unknown flag bits and access mode 3 are now refused (fail
closed).

### Added

- **Open-flag policy clauses** on path rules: `readonly` (= `access=ro -O_CREAT
  -O_TRUNC`), `access=ro|wo|rw`, `+O_NAME`, `-O_NAME`. Through v1.12 a path rule
  admitted every open flag, so "read-only" could not be expressed.
- **Fragment boundary as soundness obligations:** a string over 4095 bytes, a
  flags value with a bit outside the x86_64 `open(2)` set, or access mode 3 is
  UNKNOWN (recorded as `fragment_escape_length` / `fragment_escape_flags`); a
  query over more than 16 relevant flag bits is UNKNOWN.
- **Flag clauses constrain the flags passed to `openat()`**, not the
  descriptor's later state: `readonly` is sound (access mode, `O_TRUNC`,
  `O_CREAT` are fixed at open), but `fcntl(F_SETFL)` can change `O_APPEND`,
  `O_NONBLOCK`, `O_ASYNC`, `O_DIRECT`, `O_NOATIME` afterwards, and the kernel
  forces `O_LARGEFILE`. The Warden and `vdp_check lint` print a note on such
  clauses.
- **`require warden <major>.<minor>`** directive: an older Warden refuses the
  file (v1.12 fails on the unknown verb instead of silently ignoring flag
  clauses). Control bytes in a constant are refused; non-ASCII bytes get a note.
- **Load-time analysis:** the Warden decides, for every rule, whether any action
  can reach it first, and warns on each rule that can never fire.
  `tools/vdp_check <policy> lint|analyze|batch` exposes the same procedure.
- **Symbolic flags in the `--plan` gate:** a planned `file_open` is SATISFIED
  only if every admissible flags value is.
- **Solver cross-check** (`tools/smt_crosscheck.py`, `make crosscheck`): an
  independent parser and encoding for an off-the-shelf SMT solver. Zero
  disagreements: 954 checks on the 14 repository policies and 25,670 on 600
  fuzzed policies (seeds 1-3; 398 accepted and 202 rejected by both parsers),
  including 83 hits of the enumeration bound. Mutation test: 6 of 7 planted
  bugs caught; the seventh is semantically equivalent in the current atom
  language.
- **Verdict-distribution harness** (`tools/verdict_harness.py`, `make harness`,
  `harness/corpus/`, `harness/baseline-v1.12.4/`): verdict by ground truth,
  clear rate, and the `unsafe_satisfied == 0` gate, against the policies as
  v1.12.4 shipped them. Seed corpus (synthetic, SAI-authored), file opens: v1.13
  clears 85.4% of safe opens with 0 unsafe SATISFIED; v1.12.4 as shipped 75.6%
  with 24 (16 distinct).
- Records gain `policy_line`. `tests/v1130_probe.c`, `tests/test_v1130.sh`,
  `tests/v1130_policy.txt`, `tests/crosscheck_bound_policy.txt`,
  `make test-v1130`. `RELEASE-v1.13.0.md`.

### Security

- **Example sector policies enforce the read-only access their comments
  claimed.** The loader rules (`/usr/lib/`, `/lib/`, `/lib64/`,
  `/etc/ld.so.cache`) admitted writes, so the root agent could overwrite
  `libc.so.6`; "(read)" rules (logs, detection rules, SCADA telemetry and
  setpoints, market snapshots, tasking, intelligence products) admitted writes
  too. They are now `readonly`, and each file begins `require warden 1.13`.
- **Dead rule fixed in four example policies:** `deny path /etc/` preceded
  `allow path /etc/ld.so.cache`, so the loader-cache allow never fired. Found by
  the new load-time analysis. (Being a prefix rule, the moved allow also
  admits read-only opens of names beginning `/etc/ld.so.cache`.)
- **The parser no longer drops rules silently.** v1.12 stopped at 256 rules
  without a word (a 257th deny was ignored) and ignored every token after the
  third. Over 256 rules, an unknown or contradictory flag clause, or a flag
  clause on a host/exec rule is now a load error.

### Changed

- `run_start` reads `"warden":"1.13.0"`; the policy loads as `v1.13`.
- `test_v1122.sh` and `test_v1123.sh` compare the Warden version with `sort -V`.
- Do not load a v1.13 policy into an older Warden: the v1.12 parser ignores flag
  clauses and admits every flag. `require warden 1.13` makes it refuse instead.
- `struct policy` in the Warden is static (about 1 MB; it was on the stack).

---

## [1.12.4] - 2026-09-28

v1.12.4 fixes the optional `--plan` pre-execution gate, which had rejected every
plan declaring a `file_open` action since v1.12.0. No runtime verdict *semantics*
change.

### Fixed

- **The `--plan` gate authorizes file opens again.** Since v1.12.0
  `policy_decide` has decided a file open on the resolved canonical path, but the
  plan decider — which runs before the agent is forked — never filled that field,
  so every `file_open` node was UNKNOWN and any plan that opened a file was
  rejected (including the shipped `sample_plan.txt` and the v1.6 integration
  test). The decider now fills it with the lexically canonical form of the
  declared absolute path (`.`, `..` and duplicate slashes collapsed, `..` clamped
  at `/`). A plan opening a policy-allowed file is SATISFIED again; a `..` that
  lexically escapes an allowed prefix, or a relative path, stays UNKNOWN. Plan
  verification does not follow symlinks (there is no agent yet) — it is an
  advisory pre-check, and every open is still mediated per-syscall at runtime.

### Added

- `varek/v1_4/tests/test_v1124.sh` and `make test-v1124`. Fails against v1.12.3
  (every file-open plan node is UNKNOWN).
- `RELEASE-v1.12.4.md`.

---

## [1.12.3] - 2026-09-28

v1.12.3 lets dynamically linked agents (CPython, a JVM, Node) run under the live
Warden. Since v1.12.0 the resolver set `RESOLVE_NO_SYMLINKS`, refusing any path
with a symlink; on merged-`/usr` systems `/lib` and library SONAMEs are
symlinks, so the loader could not open its libraries. No verdict *semantics*
change.

### Changed

- **Symlinks are followed and decided on the canonical path.** `openat2` follows
  symlinks to a single pinned object; policy is matched on that object's
  canonical path (`readlink` of the pinned fd) and the same fd is delivered. A
  symlink in an allowed directory pointing at a denied file is decided as the
  denied file and refused, exactly as before; a symlink to an allowed object is
  now followed and delivered. `RESOLVE_NO_MAGICLINKS` still set; `..` still
  decided on the post-collapse path.
- **Policies match canonical prefixes.** An `allow path` naming a symlinked
  location (e.g. `/lib/`) no longer matches; name the canonical target
  (`/usr/lib/`). The demo, benchmark and conformance policies already do.

### Security

- **`/proc/self` maps to the agent, not the supervisor.** A leading `/proc/self`
  or `/proc/thread-self` (a magic link `RESOLVE_NO_MAGICLINKS` would otherwise
  refuse) is rewritten to the agent's own `/proc/<tgid>` before resolution. A
  planted symlink pointing at `/proc/self/mem` is a magic link and is refused
  during resolution. A path or symlink reaching another process's numeric
  `/proc/<pid>/…` resolves, then fails the post-resolution check because it is
  not the agent's `/proc/<tgid>`. The agent's own entries are recorded as
  `/proc/self/…`. A non-process `/proc` entry (`/proc/kcore`, `/proc/sys/…`) is
  governed by policy, not by this check.
- **A trailing symlink opened `O_NOFOLLOW`** is refused (the agent's `O_NOFOLLOW`
  reaches the `O_PATH` resolve, which returns the link; a link is not an
  allowable object).

### Added

- `varek/v1_4/tests/v1123_probe.c` (built dynamically), `tests/test_v1123.sh`,
  `tests/v1123_policy.txt`; `make test-v1123`. Fails against v1.12.2 (its
  symlink and `/proc/self` opens are refused).
- `RELEASE-v1.12.3.md`.

### Known issue

- The `--plan` gate still refuses plans containing `file_open` (since v1.12.0).

---

## [1.12.2] - 2026-09-28

v1.12.2 lets agent code start threads, collect its children and call
`isatty()` under the live Warden. All three gaps date from the v1.9.2 default-deny
allowlist. (Dynamically linked agents such as CPython still cannot start until
v1.12.3; see Known issues.) It also closes an exec-allowlist bypass through the
bootstrap exec that threads would have made routine. No verdict *semantics*
change, and no namespace denial is weaker.

### Security

- **Bootstrap exec granted once per run.** The agent's launch exec is answered
  with `CONTINUE`, which is sound only for the single-threaded launching
  process. It was granted once per pid, so a new thread could `execve` the
  agent's binary while a sibling rewrote the path between the Warden's read and
  the kernel's, running a binary the exec policy never allowed (reachable before
  via raw `clone(CLONE_VM)`). It is now granted once per run, to the launched
  process only; every later exec is deny-only.

### Fixed

- **Threads.** `clone3` was hard-denied (KILL), and glibc >= 2.34 creates every
  thread with it, so an agent that started one thread was killed on the spot.
  `clone3` now answers `ENOSYS`; libc falls back to `clone()`, whose flags the
  filter checks. `clone3` still never executes, and `clone(CLONE_NEWUSER)` and
  the namespace set are still killed. A thread's opens are mediated exactly like
  the main thread's and are recorded under its own thread id.
- **Waiting for children.** `wait4` and `waitid` are admitted; `waitpid()`,
  `subprocess.run()` and `os.system()` failed with `EPERM` after the child ran.
- **ioctl.** Admitted for `TCGETS`, `TIOCGWINSZ`, `FIOCLEX`, `FIONCLEX`,
  `FIONBIO` and `FIONREAD` only (full 64-bit match). `isatty()` returned `EPERM`
  and CPython could not make a descriptor non-inheritable. `TIOCSTI`, `TCSETS`
  and every other request stay refused.
- **Removed-ABI calls kill the whole process.** The bad-architecture action is
  `KILL_PROCESS` in strict builds; libseccomp's default killed only the calling
  thread.
- **`unshare(CLONE_NEWTIME)`** is denied with the other namespace bits (it was
  admitted in observe mode).

### Changed

- The Warden prints `[warden] agent killed by signal N (...)` when the agent dies
  by a signal on its own; through v1.12.1 a filter kill left only exit status 1.
- `varek_cyclonedx.py` takes the Warden version for the BOM from the stream's
  `run_start` record, so a v1.12.1 log is labelled 1.12.1.
- `run_start` reads `"warden":"1.12.2"`.
- A thread or child can no longer re-execute the agent's own binary (e.g.
  Python `multiprocessing` in `spawn` mode); exec is deny-only after the launch.

### Added

- `varek/v1_4/tests/v1122_probe.c`, `tests/test_v1122.sh`,
  `tests/v1122_policy.txt`; `make test-v1122`, which also builds and runs the
  filter unit test `tests/test_v14_filter.c` (now with `clone3`, `wait4` and
  `ioctl` cases). Fails against v1.12.1: the probe is killed at its first
  `pthread_create`.
- `RELEASE-v1.12.2.md`.

### Known issues

- Dynamically linked agents (CPython included) still cannot start: since
  v1.12.0 resolution refuses symlinked paths, and `/lib` and library SONAME links
  are symlinks. Static targets are unaffected. Planned for v1.12.3.
- The `--plan` gate still refuses plans containing `file_open` (since v1.12.0).

---

## [1.12.1] - 2026-09-28

v1.12.1 fixes three defects found in v1.12.0: a denied file open could still
change the filesystem, the supervised agent could forge verdict records, and
inbound networking was left open. No verdict *semantics* change.

### Security

- **A DENY has no side effect.** v1.12.0 resolved a file open by opening the
  object with the agent's own flags, as root, *before* the policy decision. A
  denied `O_TRUNC` still emptied the file, a denied `O_CREAT` still created a
  root-owned file, and a blocking open (a FIFO with no peer) wedged the
  single-threaded Warden. The object is now pinned with an `O_PATH` descriptor
  (which opens nothing), the decision is made on its canonical path, and only
  after ALLOW is it opened with the agent's flags through the pinned descriptor,
  so the decided object is still the delivered one. `O_CREAT` of a new name pins
  the parent directory and decides on `<canonical parent>/<name>`; the file is
  created with `openat(parent, name, O_NOFOLLOW)` under the agent's umask.
- **Authenticated verdict stream.** The agent shared the Warden's stderr, so it
  could write a complete, well-formed record ("ALLOW /etc/shadow") that the
  CycloneDX exporter then listed as authorized. The agent's stderr is now a pipe
  the Warden relays with an `[agent] ` prefix (control bytes escaped). Records are
  written through a private close-on-exec descriptor, one `write()` per record,
  and carry a per-run id and a contiguous `seq`; `run_start`/`run_end` records
  frame the stream. `varek_cyclonedx.py` refuses a stream with a foreign run id,
  a `seq` gap or repeat, or no `run_end` (unless `--allow-incomplete`).
- **Inbound networking refused.** `bind`, `listen`, `accept` and `accept4` were
  admitted, so a root agent could open a listener or an abstract unix socket the
  host could reach. They now fall to the default EPERM, and the agent runs in its
  own network namespace (loopback only, down). Required with the PID namespace;
  a warning under `VAREK_WARDEN_NO_PIDNS=1`.

### Changed

- FIFOs: opening one for writing when no reader exists returns `ENXIO` instead
  of waiting, and opening one for reading when no writer exists returns at once
  (the Warden opens with `O_NONBLOCK`, then clears it).
- `O_TMPFILE` is decided on the directory it names and gets the agent's mode and
  umask (v1.12.0 gave mode 0000). Naming an allowed directory itself is denied
  when the rule has a trailing slash, as for any open of that directory.
- An ALLOW whose open then fails (`EEXIST`, `ENXIO`, ...) returns that errno to
  the agent. Records gain `run`, `seq` and `errno` fields, and `kernel_verdict`
  reads `ERRNO` in that case.
- The agent's stderr appears in the Warden's output prefixed `[agent] `.
- The status line reports `netns=on|off`.
- `varek_cyclonedx.py` refuses v1.12.0 logs (they carry no run id, so their
  records could have been forged). The BOM gains `varek:run.id` and
  `varek:run.complete`.
- `bench_summarize.py` and `bench_histogram.py` read only lines that begin with
  `{`.

### Added

- `varek/v1_4/tests/v1121_probe.c`, `tests/test_v1121.sh`,
  `tests/v1121_policy.txt`; `make test-v1121`. Fails against v1.12.0 (the denied
  file is truncated, a file appears in the denied directory, and the Warden hangs
  on the FIFO).
- `RELEASE-v1.12.1.md`.

### Fixed

- `docs/security/bypass-classes.md`: class 3 records inbound networking (closed
  in v1.12.1); the resolve-then-decide and audit-log-integrity sections describe
  the v1.12.0 defects and their fixes.

---

## [1.12.0] - 2026-09-17

v1.12 is a mediation-correctness release. It closes five ways a process under
the live Warden could reach a denied object or corrupt the authorization record,
and adds a tool that exports authorization evidence in the CycloneDX 1.6 format.
No verdict *semantics* change — the
three-state SMT decision procedure and the symmetric-suppression invariant are
untouched — but several decisions the Warden believed it was making soundly were
being made on the wrong object. The version jumps to v1.12: v1.10 and v1.11
remain **reserved** for the UNKNOWN-shrinking verification program (below), which
is unaffected by and orthogonal to this release.

### Security

- **Resolve-then-decide for file opens.** The Warden previously matched policy
  against the raw pathname string the agent supplied, then opened whatever that
  path resolved to. Two objects could therefore differ: an allow rule could
  match a benign prefix while the kernel opened a denied file. v1.12 opens the
  object **once**, canonicalizes it (`readlink` on the resolved fd), decides
  policy on that canonical path, and injects that same fd — decision and
  delivered capability now refer to the same inode. Closes:
  - **`..` traversal.** `/tmp/allowed/../../etc/shadow` matched the allowed
    prefix and was opened. Now the decision is made on the collapsed canonical
    path (`/etc/shadow`), which matches no allow rule.
  - **Symlink escape.** A symlink inside an allowed directory pointing at a
    denied object was followed. The resolver now sets
    `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` — the flags the header and
    threat model already claimed but the shipped code did not set (it set only
    `RESOLVE_NO_MAGICLINKS`). A symlink component now fails resolution and is
    denied.
  - **`/proc/self` context confusion.** `/proc/self/*` is a magic symlink the
    kernel resolves in the **caller's** context — the supervisor's, not the
    agent's — so `open("/proc/self/mem")` returned a handle on the Warden.
    `RESOLVE_NO_MAGICLINKS` now refuses it.
- **Audit-log integrity.** The agent-controlled pathname was written into the
  JSON pathology record unescaped, so a crafted path could inject a forged
  `"decision_final":"ALLOW"` record into the verdict stream. All
  agent-controlled strings are now JSON-escaped; every record is well-formed
  JSON for any byte sequence. Records also gain a `resolved` field carrying the
  canonical object the decision was made on.
- **Datagram egress mediation.** `sendto`/`sendmsg` were admitted unconditionally
  by the baseline filter, so an agent could reach the network with a datagram
  send and never call the (deny-only) `connect` — a hole inherited from the
  allow-by-default model and previously disclosed under bypass class 3. Both are
  now mediated as `net.send`; a send carrying an inet destination is refused
  under the same deny-only network posture as `connect`. Inbound
  `recvfrom`/`recvmsg` stay admitted.

### Changed

- **Bootstrap listener handoff uses `pidfd_getfd`.** Mediating `sendmsg` broke
  the old `SCM_RIGHTS` fd handoff (the child's own `sendmsg` trapped on its
  just-installed filter with no supervisor yet listening). The child now writes
  the listener fd *number* over the socketpair with `write()` (admitted) and the
  supervisor pulls the fd out of the child with `pidfd_open`/`pidfd_getfd`. No
  post-filter `sendmsg` is required, so both send syscalls can be mediated.

### Added

- `varek/v1_4/tests/v112_probe.c`, `tests/test_v112.sh`, `tests/v112_policy.txt`;
  `make test-v112`. An adversarial target exercises all five bypasses and one
  legitimate open; the harness asserts on both the agent's view and the Warden's
  verdict stream (including that the stream stays valid JSON with no forged
  record). Fails against the pre-v1.12 Warden.
- `varek/v1_4/tools/varek_cyclonedx.py` — exports a Warden pathology log as a
  Bill of Materials in the **CycloneDX 1.6** format: the Warden as a tool
  component (license + provisional-patent properties), the run as
  `metadata.component`, each distinct authorized object as a component, and an
  Authorization-Before-Execution attestation as a top-level annotation. Output
  validates against the published CycloneDX 1.6 JSON schema. Uses only stable
  1.6; the "pre-defined perspectives" proposal (specification PR #1067) is noted
  as a future 2.0 binding, not a dependency. CycloneDX is a trademark of the
  OWASP Foundation; VAREK is not affiliated with or endorsed by the OWASP
  Foundation or the CycloneDX project (see `NOTICE`).

### Fixed

- `docs/security/bypass-classes.md`: class 3 is **closed** for the datagram send
  path (`sendto`/`sendmsg` now mediated); class 4's symlink/magiclink resolution
  claim now matches the shipped resolver flags. Adds an audit-log-integrity row
  and a `/proc/self` context-confusion note.

---

## [1.9.3] - 2026-09-15

v1.9.3 wires the v1.9.2 supervisor/target lifecycle module into the live
Warden and corrects the v1.9.2 record: at v1.9.2, bypass class 7
(supervisor-as-target / lifecycle) was **partial**, not closed. No verdict
semantics change.

### Security

- **The agent dies with the supervisor.** The target sets
  `PR_SET_PDEATHSIG(SIGKILL)` before installing its filter (`prctl` is outside
  the allowlist, so the agent cannot clear it). A liveness pipe held only by the
  supervisor catches a supervisor that died before that call; the target
  refuses to run unmonitored. This replaces the `getppid()` re-check, which
  returns 0 inside a PID namespace; `wd_target_couple_to_supervisor()` now takes
  the pipe fd.
- **So does everything the agent spawned.** The target runs as init of a
  dedicated PID namespace, so the kernel kills all of its descendants when it
  dies. `PR_SET_PDEATHSIG` alone does not cover descendants.
- **Orderly shutdown kills the whole tree** (namespace + process group).
- **Target watched via pidfd** alongside the listener, closing a hang where the
  target exited just before the supervisor blocked in `NOTIF_RECV`.
- **`CAP_SYS_ADMIN` preflight.** The Warden checks for the capability at
  startup and refuses to run without it, with a clear message.
  `VAREK_WARDEN_NO_PIDNS=1` opts out of the namespace (and the requirement)
  with a warning; in that mode descendants are not guaranteed to die on a
  supervisor crash.

### Added

- `varek/v1_4/tests/test_v193_lifecycle.c` and `tests/lifecycle_target.c`;
  `make test-lifecycle`. SIGKILLs and SIGTERMs a live Warden supervising an
  agent that forks and asserts no agent process survives; exercises the
  fork-race guard. Fails against the pre-fix Warden (crash: 2 survivors;
  orderly shutdown: 1 survivor).
- `make target_conformance` and `make run-conformance` (creates
  `/tmp/varek_conf`, then runs the conformance target under the Warden).
- `RELEASE-v1.9.3.md`; spec paper updated to v1.9.3 (§2.9).

### Fixed

- **Conformance target setup.** `target_conformance` failed its
  `allowed_open` phase when `/tmp/varek_conf` did not exist (the target cannot
  create it under enforcement). It now reports a `setup` failure with the fix,
  and `make run-conformance` creates the directory.

### Changed

- The supervised agent sees itself as PID 1 and `getppid()` returns 0.
  Pathology records still report the host PID. Policy decisions are unchanged
  (verified identical on the demo, plan-verification, bench, and conformance
  workloads).
- `docs/security/bypass-classes.md`: class 7 is **closed as of v1.9.3**
  (partial in v1.9.2). `WD_MAX_INFLIGHT_NOTIFS` is documented as not enforced
  by the single-threaded v1.4 Warden (in-flight concurrency is 1).

---

## [1.9.2] - 2026-06-21

Hardening patch. No verdict-semantics changes; the v1.9 progress-safety proof is
untouched. The invariant is unchanged: no extension may move a genuinely unsafe
action to SATISFIED.

### Security

- **Default-deny allowlist.** The Warden baseline is inverted from
  allow-plus-denylist to default-deny allowlist: only an explicit allowlist is
  admitted, so unknown and variant syscalls (`clone3`, `openat2`, `faccessat2`,
  `pidfd_*`) and 32-bit multiplexers (`socketcall`, `ipc`) are denied by
  construction. New: `v1_7/warden_seccomp_baseline.{c,h}`,
  `v1_7/tests/test_v192_baseline_deny.c`.
- **Native-ABI lockdown.** The deny default applies across all architectures and
  no secondary ABI is admitted, so the 32-bit compat (`int 0x80`) and x32
  (`__X32_SYSCALL_BIT`) paths are denied. Asserted on the live kernel by
  `v1_7/tests/test_v192_abi_lockdown.c` (release-blocking).
- **Unprivileged-user-namespace denial.** `clone`/`unshare` are filtered on the
  scalar flags argument to deny `CLONE_NEWUSER` and the namespace set; `clone3`,
  `setns` hard-denied.
- **Hard-deny set** (`SCMP_ACT_KILL_PROCESS` in strict mode) for `ptrace`,
  `bpf`, `userfaultfd`, `process_vm_readv/writev`, `pidfd_getfd`, the mount/FUSE
  family, the module/`kexec`/`perf_event_open`/`keyctl` family, and
  `memfd_create` — mapping to bypass classes 3–6. io_uring denial (v1.9.1) is
  retained inside this set.
- **Supervisor/target lifecycle coupling.** Target SIGKILLed on supervisor death
  (`PR_SET_PDEATHSIG`); supervisor watches target via pidfd; injected fds carry
  `O_CLOEXEC`. New: `v1_7/warden_lifecycle.{c,h}`. **Correction (v1.9.3):**
  only the `O_CLOEXEC` part was enforced by the live Warden at this release;
  PDEATHSIG coupling and the pidfd watch were integrated in v1.9.3.

### Added

- `docs/security/bypass-classes.md` — bypass-class checklist and
  mediation-completeness argument.
- `docs/security/v1.9.2-baseline-allowlist.md` — allowlist rationale and
  class-to-syscall map.
- `docs/security/v1.10-architecture-roadmap.md` — model/TCB-changing track
  (Landlock, acquisition tiering, post-grant re-mediation, UNKNOWN escalation
  ladder, TCB shrink via proof-checking).
- `v1_7/warden_landlock.c` — v1.10 skeleton (not wired into v1.9.2).

### Changed

- The io_uring denial is now an entry in the default-deny allowlist's hard-deny
  set rather than a standalone denylist rule.

---

## [1.9.1] - 2026-06-20

Hardening and disclosure patch. No verdict-semantics changes; the v1.9
progress-safety proof is untouched. The invariant is unchanged: no extension may
move a genuinely unsafe action to SATISFIED.

### Security

- **io_uring bypass closed.** The Warden baseline policy now denies the io_uring
  submission interface (`io_uring_setup`, `io_uring_enter`, `io_uring_register`)
  with `EPERM`. io_uring dispatches operations off the syscall entry path, where
  seccomp — and therefore the Warden's user-notification mediation — cannot
  observe them; denying instance creation is the only sound mitigation at this
  layer. New: `v1_7/warden_seccomp_baseline.c`,
  `v1_7/tests/test_v191_io_uring.c`.
- **seccomp user-notification TOCTOU discipline.** Hardened the supervisor
  against time-of-check-to-time-of-use on pointer arguments:
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE` is no longer used to authorize any syscall
  whose decision depended on user-pointer contents; pointer-argument operations
  are performed by the supervisor on validated, copied arguments and the result
  is injected via `SECCOMP_IOCTL_NOTIF_ADDFD`; every notification is revalidated
  with `SECCOMP_IOCTL_NOTIF_ID_VALID` before the supervisor acts. New:
  `v1_7/warden_notify_hardening.{h,c}`.

### Added

- **UNKNOWN-reason diagnostics.** UNKNOWN verdicts now carry the undischarged
  predicate and the fragment that would resolve it. Additive; SATISFIED and
  UNSATISFIED are unchanged and soundness is unaffected.
  Spec: `docs/security/v1.9.1-verifier-notes.md`.
- **Deterministic resource bounds** on the decision procedure (max step / time
  ceilings, obligation memoization). A bound hit yields UNKNOWN (fail closed),
  never a coerced pass.
- `docs/security/threat-model.md`, `docs/security/TRUSTED-COMPUTING-BASE.md`.

### Changed

- Documented the per-component trusted-vs-verified status of the verification
  chain and the plan to shrink the trusted base (see TRUSTED-COMPUTING-BASE.md).

---

## [1.9.0] - 2026-05-30

### Added

- `v1_7/plan_progress.h`, `v1_7/plan_progress.c`: **Progress-safety
  verification.** A load-time liveness proof that turns human-out-of-the-loop
  (HOOTL) from a configuration choice into a property the verifier certifies per
  policy. v1.6–v1.8 prove safety (nothing unauthorized executes); v1.9 adds the
  complementary proof that the system always has a legal, automated next move, so
  "never requires a human" is certified rather than hoped.
- `v1_7/INTEGRATION-hotl.md`, `v1_7/warden_hotl_example.c`: integration guide and
  runnable reference for using the progress verifier as an unattended-startup
  gate.
- `v1_7/demo_hootl.c`: HOOTL demonstration.
- `v1_7/tests/test_v19_progress.c`: 10/10, clean under
  `-fsanitize=address,undefined`.

### The theorem certified

For every non-authorizing verdict (UNSATISFIED or UNKNOWN) the policy can
produce, the v1.8.2 breaker's deterministic resolution reaches an automated
terminal outcome in finitely many steps, with no point requiring human
intervention. Decomposed into four obligations: P1 bounded refusal, P2 disposed
UNKNOWN, P3 disposed exhaustion, P4 authorized fallback (the reachability proof,
discharged by composing the underlying decision procedure as its authorization
oracle).

### Result shape

Three-state, matching VAREK semantics: `SATISFIED` (certified progress-safe /
HOOTL), `UNSATISFIED` (a concrete gap, with the failing obligation named),
`UNKNOWN` (could not decide — fail closed, treated as not certified).

### Operational use

Call `plan_progress_verify()` at policy load and refuse to start unattended
unless it certifies. If no automated terminal is guaranteed, the system never
reaches run time.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check

---

## [1.8.2] - 2026-05-30

Point release. Adds a non-bypassable loop bound to the enforcement layer without
touching the decision procedure.

### Added

- `v1_7/plan_breaker.h`, `v1_7/plan_breaker.c`: **Bounded-refusal breaker.** The
  decision procedure answers "may this submission run?" purely and statelessly; a
  refused plan returns UNSATISFIED and what the agent does next is the host's
  business. Left unbounded, a stuck or adversarial planner can resubmit the same
  refused action-graph forever — a self-inflicted denial of service, and in an
  unattended deployment a hang only a human could break. The breaker closes that
  loop in the trusted boundary, keyed by `(session, action-signature)`, so the
  bound cannot be defeated by buggy or compromised harness code. Each individual
  verdict stays a pure function of `(plan, policy)`; the breaker only interprets
  the *sequence* of verdicts for one signature.
- `v1_7/tests/test_v18_2_breaker.c`: 19/19, clean under
  `-fsanitize=address,undefined`.

### Changed

- `v1_7/plan_policy_config.h`, `v1_7/plan_policy_config.c`: three optional
  top-level policy directives plus accessors. Fully backward compatible — a policy
  declaring none of them behaves exactly as pre-v1.8.2, and the v1.8.0
  declassification suite passes unchanged (16/0).

### Policy grammar additions

    refusal_budget N                 # N >= 1; absent => breaker disabled
    on_exhaustion deny               # default when absent
    on_exhaustion terminal NAME      # fire a pre-authorized safe action
    unknown_disposition deny         # default when absent
    unknown_disposition terminal NAME

### Semantics

- `SATISFIED` clears the signature's counter and latch (authorization always wins;
  a now-authorized action is never blocked by past refusals).
- `UNSATISFIED` increments. Below budget: retryable refusal (host may re-plan).
  At/over budget: fire `on_exhaustion`, latch.
- `UNKNOWN` routes immediately to `unknown_disposition` and latches — never
  retried, because re-running the same input reproduces UNKNOWN.
- A latched signature replays its terminal outcome idempotently. With the breaker
  disabled, UNSATISFIED is always retryable and never latches (pre-v1.8.2
  pass-through). Memory pressure interning a new entry fails closed to the
  exhaustion disposition.

### Boundaries

The decision procedure is untouched; the counter is enforcement state, not
decision state. The breaker never authors a corrected action — re-planning and
executing a named safe action remain the host's job.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check

---

## [1.8.1] - 2026-05-30

### Added

- `v1_7/varek_dataflow.h`: Public umbrella header. One include for the whole v1.7/v1.8 surface (plan, label, policy, dataflow kernel, adapter, pathology, binding, config).
- `v1_7/warden_integration_example.c` (`make example`): Runnable reference of the Warden's `--plan` gate over the full stack. Demonstrates sanitize-then-send authorizing and direct exfiltration refused with full pathology.
- `v1_7/varek_demo.c`, `v1_7/demo_policy.cfg`, `v1_7/demo/DEMO.md` (`make demo`): Narrated 8-scenario walkthrough exercising the real verifier against `demo_policy.cfg`. Exits 0 only if all scenarios behave as documented, so doubles as a full-stack smoke test.
- `docs/security/threat-model-dataflow.md`: Companion to `docs/security/threat-model.md`, scoped explicitly to the v1.7/v1.8 cross-action data-flow layer. Trust boundaries, security properties (each pinned to a test), eight stated limitations, recommended external-audit scope.

### Notes

- No behavior change, no API change. The v1.8.0 kernel, adapter, binding, pathology, and config source files are byte-identical. v1.8.1 turns the v1.8.0 tree into something a customer can adopt and a reviewer can sign off on.
- Why a patch release for documentation: a released tag should identify a fixed, reproducible state. Adding substantive artifacts under the existing v1.8.0 tag would mean v1.8.0 no longer identifies one specific state. v1.8.1 is the correct semver position; v1.8.0 stays immutable.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    make demo

### Verify

    git verify-tag v1.8.1

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.8.1

---

## [1.8.0] - 2026-05-30

### Added

- `v1_7/plan_dataflow.h`, `v1_7/plan_dataflow.c`: Operator-designated, audited declassification. `plan_dataflow_add_declassify()` populates a per-node declassify set; `plan_dataflow_node_declassified()` exposes the audit set (`inbound âˆ© declassify`) recoverable after verification.
- `v1_7/plan_label_policy.h`: `declassify` slot on `plan_label_class_t`.
- `v1_7/plan_policy_config.c`: `declassify NAME` rule-body statement.
- `v1_7/plan_label.h`: `plan_label_set_minus_into()` and `plan_label_set_intersect_into()` set primitives.
- `v1_7/tests/test_v18_0.c`: v1.8.0 safety properties (16 checks).

### Changed

- **Kernel propagation rule.** v1.7.x: `outbound = inbound âˆª origin` (monotone — labels only accumulate). v1.8.0: `outbound = (inbound \ declassify) âˆª origin`. Labels can now disappear from the flow. Backward compatible: with no labels declassified, behavior is byte-identical to v1.7.4.

### Security

This is the only mechanism in VAREK that can bypass the read-secret-then-exfiltrate guarantee. Four safety properties are pinned by tests:

1. **Operator-only.** The `declassify` set is populated by the policy, never by the plan or agent. An attacker cannot introduce a declassifying node.
2. **Two explicit assertions.** Declassification affects only outbound. A node is still policed on its full inbound, so a redactor of a sticky label must also carry `permit_in` for that label, or it fails closed to `UNKNOWN`. Both assertions are required to authorize a sanitize-then-send flow.
3. **Cannot be routed around.** A bypass edge from the secret's source straight to the denying sink still carries the raw label and is refused.
4. **Audited.** Every label dropped is recoverable via `plan_dataflow_node_declassified()` — which sensitive labels, at which node, on every plan submission.

**Stated limitation.** VAREK confirms a designated redactor was permitted to see a label and that the label was dropped during propagation. It does not prove the redactor's code sanitizes. Declassification is an operator trust assertion, audited but not verified. Same posture as CaMeL (Google DeepMind + ETH, arXiv 2503.18813) and FIDES (Microsoft Research, arXiv 2505.23643). See `docs/security/threat-model-dataflow.md` L1.

The minor-version bump signals operators to review their trust assumptions before enabling declassification. Polish releases should not carry that signal; this one should.

### Patent

- This is implementation of established information-flow control technique (Denning & Denning, 1977), substantially overlapping with concurrent prior art (CaMeL, FIDES). No claim of novelty on the data-flow verifier itself; the only narrow candidate for surviving claim language is the cross-layer integration of plan-level data-flow verification with kernel-boundary syscall enforcement (Provisional 64/059,592). Counsel evaluation is the operative path; no claim coverage is asserted in source.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check          # 207 checks across six test binaries

### Verify

    git verify-tag v1.8.0

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.8.0
- Discussion: https://github.com/kwdoug63/varek/discussions  (v1.8.0 — declassification: design, safety properties, and your review questions)

---

## [1.7.4] - 2026-05-30

### Added

- `v1_7/plan_label_policy.h`: `plan_action_arg_t` and `named_args`/`n_named_args` on the action descriptor; `plan_label_rule_match_t` and `matches`/`n_matches` on the rule.
- `v1_7/plan_dataflow_adapter.c`: Hand-rolled two-pointer `glob_match` (`*`, `?`, literals). Bounded, auditable, no ReDoS surface. Regex was deliberately not chosen for a security-policy matcher.
- `v1_7/plan_policy_config.c`: `match KEY PATTERN` rule-body statement.
- `v1_7/plan_dataflow_pathology.c`: `originators` array on suppression records. Traces an offending label back through the hops to where it entered the plan (the node whose `origin` set contains it).
- `v1_7/plan_dataflow.c`, `v1_7/plan_dataflow.h`: `plan_dataflow_node_origin()` read accessor for callers that need lineage outside the pathology emitter.
- `v1_7/tests/test_v17_4.c`: Argument matching + lineage tests (37 checks).

### Changed

- **Duplicate `action_name` rules now permitted (intentional behavior change).** v1.7.3 rejected them with `ERR_RULE_DUPLICATE`. v1.7.4 evaluates them in declaration order — first match wins. This is how the canonical internal-vs-external egress split is expressed: `rule send_http` with `match url *internal*` and `permit_in SECRET`, then a catch-all `rule send_http` with `deny_in SECRET`. Place specific rules before catch-alls. Configs that previously failed to load with the duplicate-rule error will now load and evaluate.
- **Pathology buffer NUL-terminated on success (snprintf semantics).** Previously the buffer was not NUL-terminated and a caller doing `printf("%s", buf)` read past the content into uninitialized memory. Returned length still excludes the NUL; effective capacity is `bufsz - 1`. Length-based callers (including `plan_warden_verify`) are unaffected. A regression test asserts `n == strlen(buf)`.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    ./tests/test_v17_4

### Verify

    git verify-tag v1.7.4

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.7.4

---

## [1.7.3] - 2026-05-30

### Added

- `v1_7/plan_policy_config.c`, `v1_7/plan_policy_config.h`: Line-oriented text policy config loader. Grammar: `varek_policy 1`, `strict`, `label NAME ID`, `sticky NAME`, `rule ACTION_NAME` blocks with `origin`/`deny_in`/`unknown_in`/`permit_in NAME` rule-body statements. Comments only at the start of a line.
- `v1_7/example_policy.cfg`: Canonical operator-facing reference.
- `v1_7/tests/test_v17_3.c`: Config grammar tests, 14 enumerated parse errors with 1-based line numbers and static error-message pointers (42 checks).

### Notes

- Load once at Warden startup; the loaded `plan_label_policy_config_t` is read-only after load and safe to share across threads. Free at shutdown. Allocation happens at load, never on the per-plan verification path.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    ./tests/test_v17_3

### Verify

    git verify-tag v1.7.3

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.7.3

---

## [1.7.2] - 2026-05-30

### Added

- `v1_7/plan_warden_binding.c`, `v1_7/plan_warden_binding.h`: `plan_warden_verify(req, resp)` — single-call entry point that wraps companion allocation, classification, two-axis verification, pathology emission, and cleanup. Companion lifetime is entirely inside the call. This is the supported entry point for the v1.4 Warden's `--plan` gate.
- `v1_7/plan_dataflow.h`: `plan_decision_join()` publicized; the lattice join is used in three places and the rank table is no longer duplicated.
- `v1_7/tests/test_v17_2.c`: Binding tests (50 checks).

### Notes

- Two-failure-mode contract documented at the API. `rc == 0` with non-`SATISFIED` verdict means refused plan (pathology in the buffer). `rc == -1` means verifier failure itself (verdict defaults to `UNKNOWN`). Both require refusal; `-1` is the stronger "something is wrong with the verifier" signal.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    ./tests/test_v17_2

### Verify

    git verify-tag v1.7.2

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.7.2

---

## [1.7.1] - 2026-05-30

### Added

- `v1_7/plan_dataflow.c`, `v1_7/plan_dataflow.h`: Per-label sticky model. `plan_dataflow_mark_sticky()` marks a label sticky; the kernel's sticky-unclassified path returns `UNKNOWN` (which suppresses) for any sticky label reaching a node without an explicit disposition. `plan_dataflow_add_permit_in()` is the explicit "this node may see this label" assertion that turns sticky off at a trusted carrier.
- `v1_7/plan_label_policy.h`: Classification surface — `plan_action_desc_t`, `plan_label_class_t`, policy-callback contract, reference table-driven policy.
- `v1_7/plan_dataflow_adapter.c`, `v1_7/plan_dataflow_adapter.h`: `plan_dataflow_populate()` walks an action array against a policy and writes label sets onto the data-flow companion.
- `v1_7/plan_dataflow_pathology.c`, `v1_7/plan_dataflow_pathology.h`: Deterministic JSON refusal output. Names the offending node, the kind of offense (`deny_in` / `unknown_in` / `sticky_unclassified`), the labels involved, and the immediate predecessor edges that carried each offending label.
- `v1_7/tests/test_v17_1.c`: Sticky posture, adapter populate, pathology emission tests (32 checks; cumulative 60).

### Changed

- **Kernel posture: deny-list â†’ per-label sticky (fail-safe).** With no labels marked sticky, behavior is byte-identical to v1.7.0. Production policies should mark sensitive labels sticky to engage the fail-safe path; the v1.7.0 deny-list default of passing unclassified labels silently is inconsistent with VAREK's discipline elsewhere.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    ./tests/test_v17_1

### Verify

    git verify-tag v1.7.1

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.7.1

---

## [1.7.0] - 2026-05-30

### Added

- `v1_7/plan_label.h`: Flat-set label primitive. Fixed-capacity bitset (`PLAN_MAX_LABELS = 128`), set-union semantics, allocation-free.
- `v1_7/plan_dataflow.c`, `v1_7/plan_dataflow.h`: Cross-action data-flow kernel. Kahn-topological forward propagation, per-node disposition slots (`origin`, `deny_in`, `unknown_in`), tri-state node-level flow decision.
- `v1_7/plan_dataflow.h`: `plan_decision_join()` — the lattice join over the v1.6 node-axis verdict and the new v1.7 flow-axis verdict. Same `SATISFIED < UNKNOWN < UNSATISFIED` lattice as v1.6, so symmetric suppression composes across both axes.
- `v1_7/v1_6_compat.h`: Read-only access to v1.6 internals via `execution_plan_internal.h`. Two static-inline helpers (`dataflow_plan_get_edge`, `dataflow_plan_get_node_label`) used by propagation and pathology. v1.6 source files are unchanged; tagged v1.6.x releases stay byte-identical.
- `v1_7/tests/test_dataflow.c`: Kernel tests covering canonical exfil, fanout poisoning, suppression precedence, cycle UNKNOWN, two-axis join, determinism, empty plan (28 checks).

### Notes

- **Pre-release / development snapshot.** v1.7.0 ships with a deny-list posture: unclassified inbound labels are SATISFIED by default. That posture is inconsistent with VAREK's fail-safe discipline elsewhere and is replaced in v1.7.1 with per-label sticky semantics. **Install v1.7.1+ instead.** v1.7.0 is published as a pre-release for tag continuity, not as a recommended starting point.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check
    ./tests/test_dataflow

### Verify

    git verify-tag v1.7.0

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.7.0 (pre-release)

---

## [1.6.2] - 2026-05-24

### Added

- `v1_6/plan_parser.c`, `v1_6/plan_parser.h`: Text plan-file format parser. Reads `action` and `edge` directives into an owning parsed-plan handle; reports errors with `file:line` precision.
- `v1_6/sample_plan.txt`: Example plan file demonstrating the format.
- `v1_6/warden_v1_4.patch`: Unified diff against `varek/v1_4/warden.c` and its Makefile. Adds a `--plan` CLI flag and a pre-fork plan-verification gate to the v1.4 Warden. On any non-`SATISFIED` plan the supervisor refuses to fork the target; behavior without `--plan` is preserved bit-for-bit.
- `v1_6/integration_test.sh`: End-to-end integration smoke test. Four cases: denied plan blocks the fork, authorized plan emits a `SATISFIED` record, absent `--plan` preserves v1.4 behavior, malformed plan surfaces a `file:line` parse error.
- `v1_6/demo/`: Recorded asciinema cast of the end-to-end demo, a reproducible cast generator (`make_cast.py`), a drop-on-server HTML player page (`index.html`), and an annotated transcript (`DEMO.md`).
- `v1_6/tests/test_plan_parser.c`: Parser unit tests.

### Changed

- `varek/v1_4/warden.c`, `varek/v1_4/Makefile` (on applying `warden_v1_4.patch`): `--plan <file>` flag verifies the declared action graph before `fork()`. Plan-level pathology records are emitted with a `pp-` prefix; the existing per-action records keep their `pr-` prefix, so both coexist in a single stderr stream and are filterable by prefix.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_6
    make check
    git apply warden_v1_4.patch        # from repo root: git apply v1_6/warden_v1_4.patch
    make -C ../varek/v1_4 warden
    ./integration_test.sh

### Verify

    git verify-tag v1.6.2

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.6.2

---

## [1.6.1] - 2026-05-24

### Added

- `v1_6/plan_spec.h`: Declarative plan-input type. Carries action kind, target, parameters, and edges; stable across per-action deciders.
- `v1_6/warden_adapter.c`, `v1_6/warden_adapter.h`: Callback-driven plan builder. `warden_build_and_verify()` takes a `plan_spec_t` and a `plan_decide_fn` callback, constructs an `exec_plan_t`, runs the v1.6.0 evaluator, optionally emits a pathology record, and returns the plan-level decision.
- `v1_6/pathology.c`, `v1_6/pathology.h`: JSON pathology record emission matching the v1.4 Warden's record style. Plan-level records use a `pp-` prefix. Suppression-reason classifier: `none`, `node`, `cycle`, `empty`, `capacity`, `edge_index`.
- `v1_6/adapter_demo.c`: Adapter demo with permissive and denying decider scenarios.
- `v1_6/tests/test_adapter.c`, `v1_6/tests/test_pathology.c`: Adapter dispatch and pathology-format unit tests.

### Notes

- The adapter is callback-driven by design: the v1.6.0 kernel stays independent of any specific per-action policy implementation. A thin shim wrapping the v1.4 `policy_decide()` lands in v1.6.2, not here.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_6
    make check
    make adapter-demo

### Verify

    git verify-tag v1.6.1

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.6.1

---

## [1.6.0] - 2026-05-24

### Added

- `v1_6/execution_plan.c`, `v1_6/execution_plan.h`, `v1_6/execution_plan_internal.h`: ExecutionPlan primitive. Fixed-capacity directed acyclic graph of Actions (1024 nodes, 4096 edges); no dynamic allocation past the plan struct.
- `v1_6/plan_evaluator.c`: Compositional evaluator. Iterative-DFS cycle detection plus per-node decision aggregation under the join over the lattice `SATISFIED < UNKNOWN < UNSATISFIED`. Three-state return with symmetric suppression preserved on both `UNSATISFIED` and `UNKNOWN` from the v1.4 per-action layer.
- `v1_6/plan_demo.c`: Kernel demo binary.
- `v1_6/tests/`: Five test binaries — evaluator basics, symmetric suppression, exhaustive order-invariance (960 permutations across three node-set shapes), fanout poisoning at every position, and cycle detection.
- `v1_6/README.md`, `v1_6/NOTES.md`: Documentation and design rationale.

### Patent

- Implements USPTO Provisional 64/062,549 (filed 2026-05-11): pre-execution verification of action graphs as compositional policy decisions. Lifts the per-Action decision of the v1.4 Warden to a plan-level decision over the whole action graph, evaluated before any node executes.

### Performance

- Verification is a single linear fold with a short-circuit at the top of the lattice, plus one DFS pass for cycle detection. No allocation on the verification path; cycle-detection scratch is in fixed-size thread-local arrays.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_6
    make check

### Verify

    git verify-tag v1.6.0

### Links
- Release: https://github.com/kwdoug63/varek/releases/tag/v1.6.0

## [1.5.0] - 2026-05-12

### Added

- `v1_5/fast_match.c`: Fast-path policy matcher using sorted prefix arrays with binary-search lookup. Three-state `ALLOW` / `DENY` / `UNKNOWN` decision procedure with symmetric suppression preserved from v1.4.
- `v1_5/smt_probe.c`, `v1_5/smt_probe2.c`: SMT decision-procedure feasibility benchmarks (fresh-context and context-reuse access patterns). Retained for richer policies — regex, integer ranges, multi-rule conjunctions — that the prefix matcher cannot express.
- `v1_5/bench_summarize.py`: Nanosecond-precision summarizer. Backward-compatible with v1.4 pathology logs.
- `v1_5/NOTES.md`: Design notes documenting the hybrid prefix-DFA + SMT architecture decision.
- `v1_5/bench_results_v1_5.txt`: Provenance record (host, kernel, CPU, memory) from the measured benchmark run.

### Performance

- `fast_match`: P50 = 93 ns, P99 = 271 ns, P99.9 = 526 ns across 10,000 decisions on DigitalOcean 1 vCPU / 512 MB. Two orders of magnitude (210x) faster than the v1.4 Warden's 57 Âµs P99 — policy-decision time is not the bottleneck in seccomp-unotify enforcement.
- SMT context-reuse probe: P50 = 465 Âµs, P99 = 51,959 Âµs (bimodal distribution). Disqualified from hot-path use; retained for the slow-path role on richer policies.
- Zero false negatives. Full `UNKNOWN` â†’ `DENY` suppression across the benchmark.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_5
    sudo apt install -y libz3-dev
    make
    ./fast_match 10000 ../v1_4/policy.txt 2> bench_fast.log
    python3 bench_summarize.py bench_fast.log

### Verify

    git verify-tag v1.5.0

### Links
- Pull request: [#11](https://github.com/kwdoug63/varek/pull/11)
- Design notes: [`v1_5/NOTES.md`](https://github.com/kwdoug63/varek/blob/v1.5.0/v1_5/NOTES.md)
- Provenance: [`v1_5/bench_results_v1_5.txt`](https://github.com/kwdoug63/varek/blob/v1.5.0/v1_5/bench_results_v1_5.txt)

---

## [1.4.0] - 2026-05-10

### Added

- `v1_4/warden.c`: Production seccomp-unotify Warden in C. Privileged parent process intercepting syscalls, performing cross-process `/proc/<pid>/mem` extraction, and injecting kernel verdicts.
- `v1_4/policy.txt`: Declarative policy file with `allow` / `deny` verbs across `path`, `host`, and `exec` rule kinds.
- `v1_4/bench_target.c`, `v1_4/target_demo.c`: Benchmark targets for end-to-end pipeline measurement.
- `v1_4/bench_summarize.py`: JSON pathology summarizer producing latency percentile reports.
- `v1_4/Makefile`: Build system for the Warden and its targets.
- `v1_4/README.md`, `v1_4/RFC_ISSUE.md`: Reference documentation.

### Changed

- Warden migrated from Python (`waren.py`) to C for seccomp-unotify call performance.
- Policy evaluation hosted in the supervisor process with cross-process memory extraction at the syscall trap boundary.

### Performance

- End-to-end Warden pipeline (seccomp-unotify + `/proc/<pid>/mem` + kernel injection): P99 = 57 Âµs measured.

### Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_4
    make
    ./warden ./bench_target 10000 2> bench.log
    python3 bench_summarize.py bench.log

### Verify

    git verify-tag v1.4.0

### Links
- Pull request: [#10](https://github.com/kwdoug63/varek/pull/10)
- Design RFC: [`docs/RFC_seccomp_unotify_design.md`](https://github.com/kwdoug63/varek/blob/v1.4.0/docs/RFC_seccomp_unotify_design.md)



## [1.3.0] - 2026-05-08

### Added

- `v1_3/`: Architecture scaffolding for the supervisor-based defense layer.
- High-speed visual benchmark script for measured rule evaluation.
- `RFC_TEMPLATE.md` and `VAREK_v1.2_RFC.md`: RFC infrastructure documenting fail-closed semantics and linear rule evaluation.
- `CONTRIBUTING.md` and Contributor License Agreement (CLA) details.
- `seccomp_toctou_harness.c`: TOCTOU harness for seccomp-unotify exploration.

### Changed

- Refactored VAREK defense layer and Ant Colony Optimization agent simulation.
- DARPA I2O whitepaper revised for v1.1 and v1.3 architectures.
- License unified to MIT across all source files (resolved earlier Apache 2.0 / MIT inconsistency).
- README consolidated (removed README2 / README3 iterations).

---

## [1.2.1] - 2026-05-03
### Added
- `waren.py`: Supervisor parent process to enforce out-of-band policy evaluation.
- `seccomp_bridge.py`: Kernel translation layer handling simulated OS traps and system call verdicts (`ALLOW` / `DENY`).
- "Warden/Agent" boundary architecture, strictly separating the AI execution space from the policy decision engine.

### Changed
- Moved evaluation logic out of the single-process agent simulator to prove true hard-enforcement capabilities.
- Audit logs are now securely written by the parent process, guaranteeing immutability from child process tampering.

## [1.2.0] - 2026-04-28
### Added
- Official VAREK v1.2 RFC publication detailing fail-closed semantics and linear rule evaluation.
- `evaluator.py`: Core policy decision engine with sub-millisecond execution times.
- `policy.py`: YAML loader for parsing human/AI-readable policy definitions.
- `decision_log.py`: Deterministic audit logging system for system call transitions.
- Simulator agent (`agent.py`) to test standard API access, exfiltration attempts, and fail-closed safety pathways.

---

## [1.1.1] — 2026-04-24

### Added

- `varek_warden.py` — real implementation of the orchestration layer advertised in v1.1. Exposes `configure_backend()`, `execute_untrusted()`, and `subscribe_telemetry()` as callable module-level entry points over the sandbox primitives.
- `varek_guardrails/` package — public re-export surface. Existing intercept files and external code can now `pip install -e .` and `from varek_guardrails import ...` without resolving loose top-level modules by `sys.path` manipulation.
- `pyproject.toml` — PEP 621 package metadata. `pytest` is now an optional dev dependency; production installs no longer require it.

### Fixed

- `configure_backend()` now fails closed when `IsolationBackend.is_available()` returns a non-None unavailability reason string. The prior draft had the check inverted, which would have silently accepted unavailable backends — a fail-open bug in a security primitive.

### Moved

- Smoke tests previously resident in `varek_warden.py` relocated to `tests/security/test_warden_smoke.py`.

---

## [1.1.0] — 2026-04-20

### Security

**Resolves a subprocess-escape weakness in the v1.0 containment design** reported by @dengluozhang in issue #223. The v1.0 architecture used a PEP 578 audit hook to deny `subprocess.Popen`, `os.exec*`, and related events by matching against a string-based signature list. Review demonstrated two flaws:

1. `sys.addaudithook` installs a callback in the current interpreter only. Child processes spawned via `subprocess.run` execute in a fresh interpreter or a non-Python binary that never inherits the hook. Parent-side audit callbacks cannot observe syscalls in the child. The reporter's proof-of-concept exploited this directly — the malicious payload executed in the child process while the parent hook saw nothing.
2. String-signature denylists on command arguments (`nc -e`, `nmap`, known C2 hostnames) were trivially bypassable via absolute paths (`/bin/nc`), base64-encoded commands, renamed binaries, or any attacker tooling not enumerated in the list.

**Fix:** enforcement moved out of the interpreter and into the kernel. The new reference backend combines seccomp-bpf, cgroups v2, and user/mount/network/IPC/UTS/PID namespaces, loaded under `PR_SET_NO_NEW_PRIVS`. The filter is installed before untrusted code runs, inherited across every `fork` and `clone`, and cannot be dropped by any descendant. `execve` is denied by default, which structurally prevents the subprocess-escape class of bypass regardless of argv content.

Severity: **High**. Users running v1.0 with untrusted code should upgrade.

### Added

- `sandbox.py` — new module. Defines the `IsolationBackend` interface and ships `SeccompBpfBackend` as the reference implementation. Additional backends (gVisor, bubblewrap, Windows Job Objects) will implement the same interface in future releases.
- `ExecutionPayload`, `ExecutionPolicy`, `ExecutionOutcome`, `ResourceLimits` — typed policy and result primitives.
- `default_python_policy()` — safe defaults for untrusted Python execution: allowlisted-only syscall profile, killlist for high-risk syscalls, network denied, 512 MB / 50% CPU / 64 pids / 30 s wall-clock caps.
- `varek_warden.configure_backend()` — installs the active isolation backend. Fails closed if the backend reports unavailable; no silent downgrade.
- `varek_warden.execute_untrusted()` — the v1.1 entry point for running untrusted code. Requires a configured backend.
- `varek_warden.subscribe_telemetry()` — registers callbacks for PEP 578 audit events, now emitted as advisory telemetry only.
- `docs/security/threat-model.md` — explicit in-scope and out-of-scope threats for the containment layer.
- `tests/security/test_issue_223_regression.py` — the reporter's PoC is now a regression test. Must fail to execute under the default policy. Tests also cover subprocess escape via base64-encoded commands, renamed binaries, `os.execv`, plus network isolation, killlist triggers, resource caps, and fail-closed behavior.

### Changed

- **Binary enforcement inverted from denylist to allowlist.** Policy now specifies which interpreters are permitted to run (default: the current interpreter only). Attempts to exec anything outside the allowlist raise `IsolationError` before the child process is spawned.
- **PEP 578 audit hook demoted to telemetry.** The hook still fires and emits structured events to subscribers, but it never raises and never denies. Security no longer depends on it firing. If the hook is evaded, disabled, or crashed by untrusted code, the kernel-level boundary still holds.
- `enforce_strict_mode()` keeps its name and call signature for v1.0 compatibility, but its semantics now arm telemetry only. Callers must additionally call `configure_backend()` and route untrusted code through `execute_untrusted()` to get containment.

### Deprecated

- `KineticIntercept` — retained as an importable symbol so v1.0 code does not break at import time, but the audit hook no longer raises it. Enforcement failures now surface as `sandbox.IsolationError`. The symbol will be removed in v2.0.

### Removed

- String-signature denylist in the audit hook (`threat_signatures = ["nc -e", "nmap", ...]`). Denylists are unsound against adaptive adversaries; this approach has been replaced entirely by the allowlist-based design above.

### Migration from v1.0

Code that called `enforce_strict_mode()` and then ran untrusted payloads in the same process must now:

1. Call `enforce_strict_mode()` as before (arms telemetry).
2. Additionally call `configure_backend()` at startup.
3. Route untrusted code through `execute_untrusted(payload, policy)` instead of executing it in-process.

A v1.0 call that previously looked like:

```python
varek_warden.enforce_strict_mode()
exec(untrusted_code)  # relied on the audit hook to catch escapes — unsafe
```

becomes:

```python
varek_warden.enforce_strict_mode()
varek_warden.configure_backend()
outcome = varek_warden.execute_untrusted(
    ExecutionPayload(interpreter_path=sys.executable, code=untrusted_code)
)
```

### Requirements

- Linux kernel 5.10 or later with cgroups v2 mounted
- Unprivileged user namespaces enabled
- `libseccomp` Python binding: `pip install pyseccomp` or distro equivalent
- Write access to a cgroup slice for the running process. Recommended: systemd unit with `Delegate=yes`, or a pre-created `/sys/fs/cgroup/varek.slice/` owned by the running user.

The reference backend fails closed on hosts that do not meet these requirements. macOS and Windows are not supported by the reference backend.

### Credit

The design flaw addressed by this release was reported by @dengluozhang on issue #223. The proof-of-concept in that thread is included verbatim as a regression test in the v1.1 test suite.

---

## [1.0.0] — 2026-04-06

Initial public release under the MIT license.

### Added

- Statically-typed AI/ML pipeline programming language compiling to native code via LLVM.
- Hindley-Milner type inference extended to tensor shapes.
- `varek_warden.py` — PEP 578 audit hook-based runtime intercept for OS-level syscalls spawned from agentic execution contexts.
- `enforce_strict_mode()` — parent-interpreter audit hook arming for code-interpreter tool containment.

### Known limitations (addressed in 1.1)

The v1.0 containment model assumed the parent interpreter could observe and deny syscalls made by untrusted code. This assumption did not hold for child processes spawned via `subprocess`, and the accompanying string-based signature denylist was not adequate against adaptive adversaries. See the 1.1 security note above.
