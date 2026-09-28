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
  path (length ≤ 4095), with prefix, equality and host atoms.
- **32-bit bitvectors** for the open flags, with `(flags & mask) == value`
  atoms. The model is faithful to the syscall argument (`openat()` takes an
  `int`). It is not a model of the file's effective mode after open; see "What
  a flag clause constrains".

A policy compiles to one formula per action kind (ordered rules, first match
wins). The procedure returns SATISFIED, UNSATISFIED or UNKNOWN, and UNKNOWN is
still suppressed to DENY.

What the new fragment buys, in one line: **a policy can now say "read-only".**
Through v1.12 a path rule admitted every open flag. A rule written for reading
logs, telemetry or shared libraries therefore also admitted writes, truncation
and creation by a root agent.

The three-state semantics and the symmetric-suppression invariant are
unchanged. Flag-free policies decide as in v1.12.4, with two exceptions, both
of which now fail closed. An `openat` carrying a flag bit outside the ABI set
(which the kernel ignores) is refused, and so is one with access mode 3. Every
earlier regression suite passes.

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
- **Rule reachability** (at policy load). Is there any action for which rule
  *i* is the first rule that holds? This is decided exactly over the abstract
  domain: any byte string up to the bound, and any in-fragment flags value. The
  procedure uses a finite witness set over the constants' prefix trie plus a
  bounded bitvector enumeration. Over the paths that really exist it errs toward
  REACHABLE, which is the safe direction for a warning.

**Soundness obligations (fragment boundary).** An action outside the fragment
is UNKNOWN, never a guessed SATISFIED:

- *Length guard:* a string over 4095 bytes is UNKNOWN. The Warden also refuses
  to truncate such a string before reading it.
- *Conservative mask:* a flags value with any bit outside the x86_64 `open(2)`
  flag set is UNKNOWN, whatever the rules say.
- *Access mode 3:* `O_WRONLY|O_RDWR` matches none of `access=ro|wo|rw`, yet the
  kernel still honours `O_TRUNC` and `O_CREAT` with it, so it is UNKNOWN.
- *Enumeration bound:* a query that would enumerate more than 16 relevant flag
  bits is UNKNOWN rather than an unproved answer.

Fragment escapes are recorded as `fragment_escape_flags` or
`fragment_escape_length`.

## What a flag clause constrains

A flag clause constrains **the flags the agent passes to `openat()`**, checked
when the Warden opens the object on the agent's behalf. That is exactly right
for `readonly`: the access mode, `O_TRUNC` and `O_CREAT` take effect at open and
cannot be changed afterwards (`O_TMPFILE` also requires write access). It is
**not** a persistent property of the descriptor for bits that change after the
open:

- `fcntl(F_SETFL)` can set or clear `O_APPEND`, `O_NONBLOCK`, `O_ASYNC`,
  `O_DIRECT` and `O_NOATIME` later. So `+O_APPEND` does not make a file
  append-only.
- The kernel forces `O_LARGEFILE` on every 64-bit open, and adds `O_DSYNC` to an
  open that sets the `O_SYNC` bit alone.

The Warden prints a note at load, and `vdp_check lint` reports every clause on
these bits. Persistent append-only or no-sync enforcement would need `fcntl`
mediation, which is not in this release.

## Independent cross-check

`tools/smt_crosscheck.py` re-parses each policy independently of the C parser,
encodes it for an off-the-shelf SMT solver, and requires the solver and the
procedure to agree on every item: ground verdicts, symbolic-flag verdicts, rule
reachability, and parse acceptance or rejection.

**Results** (the exact runs `make crosscheck` performs):

| Run | Checks | Disagreements |
|---|---|---|
| Every policy in the repository (14 files) | 954 | 0 |
| 200 fuzzed policies, seed 1 | 8,507 | 0 |
| 200 fuzzed policies, seed 2 | 8,185 | 0 |
| 200 fuzzed policies, seed 3 | 8,978 | 0 |

Of the 600 fuzzed policies, 398 were accepted and 202 rejected, identically by
both parsers. The fuzzer produces:

- overlapping prefix chains and host constants with and without a port;
- every flag clause, including rules with up to 19 relevant bits;
- constants near and over the 4095-byte bound, non-ASCII bytes, CRLF lines and
  trailing comments;
- `require` directives, and queries with unknown flag bits and access mode 3.

The procedure hit its enumeration bound 83 times. It never returned a definite
verdict that differed from the solver's. Five times it answered UNKNOWN where
the solver was definite, which is the documented conservative direction; these
cases come from a targeted fixture, `tests/crosscheck_bound_policy.txt`.

**What the cross-check can and cannot show.** It checks the implementation
against the specification the two parsers share. It cannot find a gap between
the specification and the kernel's behaviour. The `fcntl` and access-mode-3
limits above were found by review, not by the oracle.

**Mutation test:** seven bugs were planted in the procedure and six were caught.
The seventh removed a class of reachability witnesses that is redundant in the
current atom language: path atoms are upward-closed prefixes, and no host atom
holds on `h` without also holding on `h:port`. So the output did not change.
The witnesses stay, because the planned suffix/contains atoms will need them.

**Two lessons from the oracle itself:**

- The solver's string theory did not finish (a 20 s timeout) on reachability
  queries with many negated prefixes. The cross-check therefore encodes
  reachability exactly, as a length plus per-position bytevectors.
- The solver also timed out on the literal disjunction `s = c ∨ prefix(c:, s)`
  for a 4 KB host constant, but answers the equivalent factored form
  `prefix(c, s) ∧ (|s| = |c| ∨ s[|c|] = ':')` instantly.

## Policy language

A path rule may now carry flag clauses after its constant:

| Clause | Meaning |
|---|---|
| `readonly` | `access=ro -O_CREAT -O_TRUNC`: reads only |
| `access=ro` / `access=wo` / `access=rw` | the `O_ACCMODE` bits only (access mode 3 is refused) |
| `+O_NAME` / `-O_NAME` | bit must be set / clear in the flags passed to `openat()` |

```
require warden 1.13                        # an older Warden refuses to load this file
allow path /var/log/          readonly     # detection reads logs; never truncates them
allow path /var/lib/ehr/records/           # read/update
deny  path /var/lib/ledger/ +O_TRUNC       # never truncate the ledger
```

- `access=ro` alone is **not** read-only on Linux: `O_RDONLY|O_TRUNC` truncates
  the file, and `O_RDONLY|O_CREAT` creates one. `readonly` closes both.
- `require warden <major>.<minor>` makes a Warden older than that version refuse
  the file. A v1.12 Warden fails on it (unknown verb) rather than silently
  ignoring the flag clauses, which its parser did. Put it first in any policy
  that uses flag clauses.
- A constant may not contain control bytes (0x00–0x1f, 0x7f). A constant with
  non-ASCII bytes loads with a note, because a mistyped non-breaking space would
  otherwise make a deny rule silently match nothing.

## Security

- **The example sector policies now enforce the read-only access their own
  comments claimed.** In all five, the loader rules (`/usr/lib/`, `/lib/`,
  `/lib64/`, `/etc/ld.so.cache`) admitted writes, so the root agent could
  overwrite `libc.so.6`. Rules marked "(read)" admitted writes too: logs,
  detection rules, SCADA telemetry and setpoints, market snapshots, tasking and
  intelligence products. The utility policy's header says it "makes the agent
  read-only toward the process"; through v1.12 it did not. These rules are now
  `readonly`, and each file starts with `require warden 1.13`.
- **A dead rule in four of the five example policies.** `deny path /etc/`
  preceded `allow path /etc/ld.so.cache`, so the loader-cache allow could never
  fire. The new load-time analysis found it on first run. The allow now precedes
  the deny. Because path rules are prefixes, it also admits read-only opens of
  names that begin `/etc/ld.so.cache` (such as `/etc/ld.so.cache~`), which the
  v1.12.4 ordering denied.
- **The policy parser no longer silently drops rules.** Through v1.12.4 the
  loader stopped reading at 256 rules, without a word, so a deny rule placed
  257th was ignored. It also ignored every token after the third. The following
  are now load errors, and the Warden does not start: more than 256 rules, an
  unknown or contradictory flag clause, a flag clause on a host/exec rule, a
  control byte in a constant, or an unmet `require`.

## Load-time analysis

At startup the Warden decides, for every rule, whether any action can reach it
as the first matching rule, and warns on each rule that can never fire:

```
[warden] policy finance.policy.txt:29: WARNING: allow path rule can never fire: every action it matches is decided by an earlier rule
[warden] loaded policy default v1.13 with 14 rules (1 can never fire)
```

It also prints the flag-clause and non-ASCII notes described above.
`tools/vdp_check <policy> lint` runs the same analysis without starting an
agent. It exits 1 if any rule is dead, so it can gate a policy change in CI.

## Verdict-distribution harness

`tools/verdict_harness.py` decides every action in a corpus with the procedure
and reports the verdict by ground truth: clear rate, over-refusal, and a hard
gate `unsafe_satisfied == 0`. For comparison it also decides the same actions
under three other policies:

- the policy files **as v1.12.4 shipped them** (verbatim copies in
  `harness/baseline-v1.12.4/`);
- the v1.13 files with flag clauses removed;
- the v1.13 files with every flag-constrained rule removed.

Results on the seed corpus, 106 actions across the five sector policies (65
distinct; the loader actions appear in every policy). The table counts **file
opens only**: exec and connect SATISFIED verdicts are still refused at run time
(deny-only since v1.9.1), so file opens are the figures that describe what an
agent can actually do.

| Policies decided as… | Safe opens proved SATISFIED | Unsafe opens proved SATISFIED |
|---|---|---|
| **v1.13** | **85.4%** | **0** |
| v1.12.4 as shipped | 75.6% | 24 (16 distinct) |
| v1.13 files, flag clauses removed | 85.4% | 28 (16 distinct) |
| v1.13 files, flag-constrained rules removed | 26.8% | 0 |

Against what users actually had, v1.13 raises the clear rate on safe opens from
75.6% to 85.4% and cuts unsafe opens proved SATISFIED from 24 to 0. The 24 are
tampering actions: truncating a log, rewriting telemetry, replacing libc,
altering tasking orders. The last two rows show the choice v1.12 left a policy
author: keep the clear rate and admit writes, or drop the rules and refuse most
safe reads. Counting every action, the verdict clear rate is 88.5% (v1.13)
against 80.8% (v1.12.4 as shipped). The remaining over-refusals are reads the
policies do not name.

**These numbers are synthetic.** The seed corpus uses SAI's example policies
and SAI-written SAFE/UNSAFE labels. The program requires ground truth from
customer-authored policies and adversarial labels from an independent oracle.
Until that corpus exists, the harness is a regression gate and a demonstration,
not a measured baseline.

## Records

- File-open records carry `"policy_line"`, the line of the deciding rule (−1 if
  none, or if several rules agree on a symbolic query).
- An UNKNOWN caused by the fragment boundary is recorded as
  `fragment_escape_flags` or `fragment_escape_length` rather than
  `default_deny_unknown`.
- `run_start` reads `"warden":"1.13.0"`.

## Compatibility

- **New syntax.** Flag-free policies decide as in v1.12.4, except that unknown
  flag bits and access mode 3 are now refused (fail closed).
- **Do not load a v1.13 policy into an older Warden.** The v1.12 parser ignored
  everything after the third token, so it would accept `readonly` and admit
  every flag. Start such policies with `require warden 1.13`, which an older
  Warden refuses. The shipped sector policies do.
- **Stricter parser.** Anything after the constant must be a `#` comment or a
  flag clause. More than 256 rules, and control bytes in a constant, are
  refused. Every policy in this repository already conforms.
- **`--plan` gate.** A planned `file_open` has no flags, so under a
  flag-constrained rule it is UNKNOWN (some flag values would be refused). Under
  a flag-free allow it is SATISFIED, as before.
- **Example sector policies are stricter.** An agent that wrote into a directory
  the policy's own comments describe as read-only is now refused there. Scratch
  and draft areas, and healthcare's read/update records, are unchanged.
- **Latency:** median decision latency is unchanged (P50 5–7 µs for both v1.12.4
  and v1.13). The measurement was five interleaved runs of `bench_target 10000`
  on the same 2-vCPU cloud build host. P99 was 54–94 µs before and 60–83 µs
  after; P99 on this host is noisy and moves with load.

## Not in this release

- String atoms beyond prefix/equality/host (suffix, contains, a fixed regex set):
  the rest of the bounded string fragment.
- `fcntl(F_SETFL)` mediation, which persistent append-only would require.
- The bounded sequence fragment (v1.11 candidate).
- Proof objects and an independent proof checker. Correctness is currently
  established by the differential cross-check, mutation testing and the suites,
  not by per-verdict certificates.
- A customer-derived corpus and a measured baseline.
- Flags in the `--plan` file format.

## Testing

- `make test-v1130` exercises, against a live Warden:
  - `readonly` admits reads, and refuses `O_WRONLY`, `O_RDWR`, `O_APPEND`,
    `O_RDONLY|O_TRUNC`, `O_RDONLY|O_CREAT` and `O_TMPFILE`; the file is
    unchanged and nothing is created;
  - unknown flag bits and access mode 3 are refused and recorded as fragment
    escapes;
  - records name the deciding policy line;
  - the Warden warns on a rule that can never fire and notes a `+O_APPEND`
    clause;
  - the parser refuses 257 rules, bad flag clauses, control bytes and an unmet
    `require`;
  - all shipped policies lint clean;
  - the `--plan` gate treats flags as symbolic;
  - a short solver cross-check passes;
  - the harness gate holds.

  Against v1.12.4 the probe's write attempts succeed and the suite fails.
- `make crosscheck` (the table above) and `make harness`.
- `make test-v1124`, `test-v1123`, `test-v1122`, `test-v1121`, `test-v112`,
  `test-lifecycle`, `run-conformance` and `v1_6/integration_test.sh` pass. The
  v1.12.2 and v1.12.3 suites now compare the Warden's version with `sort -V`.
- A dynamically linked, multithreaded CPython agent runs under the updated
  utility policy. Its scratch writes are allowed, its write to `libz` is
  refused, and its read of `/etc/ld.so.cache` is allowed; that read was never
  allowed under v1.12.4's ordering.
- An independent review found no blocker. Its findings (the harness baseline,
  flag semantics, cross-check reproducibility and parser alignment) are
  addressed in this release.

## Requirements

Runtime: unchanged from v1.12.4 (Linux ≥ 5.14, `pidfd_getfd`, `CAP_SYS_ADMIN`,
x86_64). The solver is **not** a runtime dependency. The cross-check and
`make test-v1130` additionally need `python3` and the `z3-solver` package.
