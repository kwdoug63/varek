# VAREK v1.13.0 — The SMT Decision Procedure in the Enforcement Path

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

v1.13.0 is the first release of the v1.10 verification program: **shrink the
UNKNOWN region without weakening soundness.** (The CHANGELOG reserved "v1.10"
and "v1.11" for this program. It ships as v1.13 so that version numbers keep
increasing.)

Every decision the live Warden makes is now made by an SMT decision procedure,
`smt_decide.c`. Through v1.12.4 the Warden decided by string prefix and equality
matching; the SMT layer existed only as a latency probe (v1.5). The new
procedure decides a quantifier-free fragment with two theories:

- **Bounded strings** for the object: the canonical path, `host:port`, or exec
  path (length ≤ 4095, bytes 1–255), with prefix, equality and host atoms.
- **32-bit bitvectors** for the open flags, with `(flags & mask) == value`
  atoms. The width matches the kernel ABI: `openat()` takes an `int`.

A policy compiles to one formula per action kind (ordered rules, first match
wins). The procedure returns SATISFIED, UNSATISFIED or UNKNOWN, and UNKNOWN is
still suppressed to DENY.

What the new fragment buys, in one line: **a policy can now say "read-only".**
Through v1.12 a path rule admitted every open flag. A rule written for reading
logs, telemetry or shared libraries therefore also admitted writes, truncation
and creation by a root agent.

No change to the three-state semantics or the symmetric-suppression invariant.
Flag-free policies decide exactly as they did in v1.12.4, and every earlier
regression suite passes unchanged.

## What "SMT decision procedure" means here

The procedure is purpose-built for the fragment above and runs inside the
Warden, with bounded worst-case work. It is not a general-purpose solver on the
hot path. v1.5 measured that option at 40–70 ms tail latency, from string-theory
state growth, and rejected it. The procedure answers three kinds of question:

- **A concrete action** (every syscall). Satisfiability of
  `policy ∧ s = v ∧ flags = w` reduces to evaluating the formula.
- **Symbolic flags** (the `--plan` gate, whose `file_open` actions carry no
  flags). SATISFIED only if *every* admissible flags value is SATISFIED,
  UNSATISFIED only if every value is UNSATISFIED, otherwise UNKNOWN.
- **Rule reachability** (at policy load). Is there *any* action for which rule
  *i* is the first rule that holds? This is decided exactly, from a finite
  witness set over the constants' prefix trie plus a bounded bitvector
  enumeration.

**Soundness obligations (fragment boundary).** An action outside the fragment
is UNKNOWN, never a guessed SATISFIED:

- *Length guard:* a string over 4095 bytes is UNKNOWN. The Warden also refuses
  to truncate such a string before reading it.
- *Conservative mask:* a flags value with any bit outside the x86_64 `open(2)`
  flag set is UNKNOWN, whatever the rules say. It is recorded as
  `fragment_escape_flags`.
- *Enumeration bound:* a symbolic query with more than 16 relevant flag bits is
  UNKNOWN rather than an unproved answer.

**Independent cross-check.** `tools/smt_crosscheck.py` re-parses each policy
independently of the C parser, encodes it for an off-the-shelf SMT solver, and
requires the solver and the procedure to agree on every item. That covers ground
verdicts, symbolic-flag verdicts and rule reachability, including parse
acceptance and rejection.

- **Results:** 677 checks over every policy in the repository, and 19,199 checks
  over 600 seeded random policies built from heavily overlapping prefixes and
  flag clauses (432 accepted and 168 rejected, identically, by both parsers).
  Zero disagreements.
- **Mutation test:** seven bugs were planted in the procedure. Six were caught.
  The seventh removed a class of reachability witnesses that turns out to be
  redundant in the current atom language: path atoms are upward-closed prefixes,
  and no host atom holds on `h` without also holding on `h:port`. So the output
  did not change. The witnesses stay, because the planned suffix/contains atoms
  will need them.
- **A lesson from the oracle itself:** the solver's string theory did not finish
  (a 20 s timeout) on reachability queries with many negated prefixes. The
  cross-check therefore encodes reachability as a length plus per-position
  bytevectors, which is an exact and equivalent encoding.

## Policy language

A path rule may now carry flag clauses after its constant:

| Clause | Meaning |
|---|---|
| `readonly` | `access=ro -O_CREAT -O_TRUNC` — reads only |
| `access=ro` / `access=wo` / `access=rw` | the `O_ACCMODE` bits only |
| `+O_NAME` / `-O_NAME` | bit must be set / clear (`O_TRUNC`, `O_CREAT`, `O_APPEND`, `O_EXCL`, `O_DIRECTORY`, `O_NOFOLLOW`, `O_CLOEXEC`, `O_TMPFILE`, `O_PATH`, `O_SYNC`, …) |

```
allow path /var/log/          readonly    # detection reads logs; never truncates them
allow path /var/lib/ehr/records/          # read/update
deny  path /var/lib/ledger/ +O_TRUNC      # never truncate the ledger
```

`access=ro` alone is **not** read-only on Linux: `O_RDONLY|O_TRUNC` truncates
the file, and `O_RDONLY|O_CREAT` creates one. `readonly` closes both.

## Security

- **The example sector policies now enforce the read-only access their own
  comments claimed.** In all five, the loader rules (`/usr/lib/`, `/lib/`,
  `/lib64/`, `/etc/ld.so.cache`) admitted writes, so the (root) agent could
  overwrite `libc.so.6`. Rules marked "(read)" admitted writes too: logs,
  detection rules, SCADA telemetry and setpoints, market snapshots, tasking and
  intelligence products. The utility policy's header says it "makes the agent
  read-only toward the process"; through v1.12 it did not. These rules are now
  `readonly`.
- **A dead rule in four of the five example policies.** `deny path /etc/`
  preceded `allow path /etc/ld.so.cache`, so the loader-cache allow could never
  fire. The new load-time analysis found it on first run. The allow now precedes
  the deny.
- **The policy parser no longer silently drops rules.** Through v1.12.4 the
  loader stopped reading at 256 rules, without a word, so a deny rule placed
  257th was ignored. It also ignored every token after the third. A policy over
  256 rules, an unknown or contradictory flag clause, or a flag clause on a
  host/exec rule is now a load error, and the Warden does not start.

## Load-time analysis

At startup the Warden decides, for every rule, whether any action can reach it
as the first matching rule, and warns on each rule that can never fire:

```
[warden] policy finance.policy.txt:29: WARNING: allow path rule can never fire: every action it matches is decided by an earlier rule
[warden] loaded policy default v1.13 with 14 rules (1 can never fire)
```

`tools/vdp_check <policy> lint` runs the same analysis without starting an
agent. It exits 1 if any rule is dead, so it can gate a policy change in CI.

## Verdict-distribution harness

`tools/verdict_harness.py` decides every action in a corpus with the procedure
and reports the verdict by ground truth: clear rate, over-refusal, and a hard
gate `unsafe_satisfied == 0`. It also decides the same actions under the two
policies v1.12 could have enforced from the same file: *permissive*, with flag
clauses removed, and *strict*, with every flag-constrained rule removed.

Results on the seed corpus (106 actions across the five sector policies):

| Policies decided as… | Safe actions proved SATISFIED | Unsafe actions proved SATISFIED |
|---|---|---|
| **v1.13** (flag clauses enforced) | **88.5%** | **0** |
| v1.12-permissive (flags ignored) | 88.5% | 28 |
| v1.12-strict (flag-constrained rules dropped) | 42.3% | 0 |

Under v1.12 a policy author could have the clear rate or the safety, not both.
The 28 are tampering actions: truncating a log, rewriting telemetry, replacing
libc, altering tasking orders. The five remaining over-refusals are reads the
policies do not name.

**These numbers are synthetic.** The seed corpus uses SAI's example policies
and SAI-written SAFE/UNSAFE labels. The program requires ground truth from
customer-authored policies and adversarial labels from an independent oracle.
Until that corpus exists, the harness is a regression gate and a demonstration,
not a measured baseline.

## Records

- File-open records carry `"policy_line"`, the line of the deciding rule (−1 if
  none).
- An UNKNOWN caused by the fragment boundary is recorded as
  `fragment_escape_flags` or `fragment_escape_length` rather than
  `default_deny_unknown`.
- `run_start` reads `"warden":"1.13.0"`.

## Compatibility

- **New syntax only.** Flag-free policies decide exactly as before.
- **Do not load a v1.13 policy into an older Warden.** The v1.12 parser ignored
  everything after the third token, so it accepts `readonly` without complaint
  and admits every flag. The shipped sector policies therefore need a v1.13
  Warden to mean what they say.
- **Stricter parser.** Anything after the constant must be a `#` comment or a
  flag clause; more than 256 rules is refused. Every policy in this repository
  already conforms.
- **`--plan` gate.** A planned `file_open` has no flags, so under a
  flag-constrained rule it is UNKNOWN (some flag values would be refused). Under
  a flag-free allow it is SATISFIED, as before.
- **Example sector policies are stricter.** An agent that wrote into a directory
  the policy's own comments describe as read-only is now refused there. Scratch
  and draft areas, and healthcare's read/update records, are unchanged.
- **Latency is unchanged** within run-to-run noise: P50 5–7 µs for both v1.12.4
  and v1.13; P99 54–94 µs before and 60–83 µs after (five interleaved runs of
  `bench_target 10000`).

## Not in this release

- String atoms beyond prefix/equality/host (suffix, contains, a fixed regex set):
  the rest of the bounded string fragment.
- The bounded sequence fragment (v1.11 candidate).
- Proof objects and an independent proof checker. Correctness is currently
  established by the differential cross-check and tests, not by per-verdict
  certificates.
- A customer-derived corpus and a measured baseline.
- Flags in the `--plan` file format.

## Testing

- `make test-v1130` exercises, against a live Warden:
  - `readonly` admits reads, and refuses `O_WRONLY`, `O_RDWR`, `O_APPEND`,
    `O_RDONLY|O_TRUNC`, `O_RDONLY|O_CREAT` and `O_TMPFILE`; the file is
    unchanged and nothing is created;
  - unknown flag bits are refused and recorded as `fragment_escape_flags`;
  - records name the deciding policy line;
  - the Warden warns on a rule that can never fire;
  - the parser refuses 257 rules and bad flag clauses;
  - all shipped policies lint clean;
  - the `--plan` gate treats flags as symbolic;
  - the solver cross-check shows zero disagreements;
  - the harness gate holds.

  Against v1.12.4 the probe's write attempts succeed and the suite fails.
- `make crosscheck` (200 fuzzed policies) and `make harness`.
- `make test-v1124`, `test-v1123`, `test-v1122`, `test-v1121`, `test-v112`,
  `test-lifecycle`, `run-conformance` and `v1_6/integration_test.sh` pass. The
  v1.12.2/v1.12.3 suites now compare the Warden's version with `sort -V`.
- A dynamically linked, multithreaded CPython agent runs under the updated
  utility policy. Its scratch writes are allowed, its write to `libz` is
  refused, and its read of `/etc/ld.so.cache` is allowed (that read could never
  be allowed before).

## Requirements

Runtime: unchanged from v1.12.4 (Linux ≥ 5.14, `pidfd_getfd`, `CAP_SYS_ADMIN`,
x86_64). The solver is **not** a runtime dependency. The cross-check and
`make test-v1130` additionally need `python3` and the `z3-solver` package.
