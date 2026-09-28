# VAREK v1.15.0 — Certificates: Every Authorization Independently Checked

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

v1.15.0 is the third release of the v1.10 verification program. It changes who
has the last word on an authorization.

Through v1.14 the Warden authorized an action when its SMT decision procedure
said SATISFIED. The procedure (`smt_decide.c`) is about 1,400 lines of C with
fast paths, word-parallel automata and a reachability search, and it was
trusted: a bug in it could authorize an action the policy does not allow.

From v1.15, **every SATISFIED verdict carries a certificate, and the Warden
authorizes the action only if a separate, independently written checker
accepts it.**

- **The certificate.** It names the deciding rule and carries a witness that
  the rule's constant matches.
- **The checker.** `checker/vdp_checker.c` is about 540 lines including
  SHA-256. It has its own policy parser and its own matchers, shares no source
  with the procedure, and has none of its optimizations (word-parallel automata,
  bitset tricks, reachability search, enumeration pruning).
- **If the checker refuses,** the action is denied and recorded as
  `certificate_refused`.

For the property that matters most — no action is authorized that the policy
does not allow — the decision procedure moves from *trusted* to *checked*, and
the trusted decision code becomes the checker. That holds for logic bugs. The
two run in the same process, so a memory-safety bug in the procedure could in
principle corrupt the checker's state.

The same certificates go into the verdict stream, together with the SHA-256 of
the policy the Warden ran with. `tools/varek_audit.py` re-checks every
authorization in a saved run later, from the stream and the policy file alone.

A test build of the Warden with a deliberately planted bug in its decision
procedure shows the effect. The procedure wrongly says SATISFIED for a file
under an explicit deny rule, the checker refuses the certificate, and the open
is denied.

Policies and verdicts are otherwise unchanged. Building and checking a
certificate adds about 1 µs per authorized open on the example policies.

## What a certificate proves

An action is a kind (path, host or exec), a string (the resolved canonical
path, `host:port` or the exec path) and, for a path, the open flags. A
SATISFIED certificate claims that **rule *r* is the first rule of that kind that
holds on the action, and *r* is an allow rule.** It carries:

| Field (record) | Meaning |
|---|---|
| `r` (`cert_rule`) | the deciding rule's index (0-based, rules only, in file order) |
| `w` (`cert_witness`) | a witness that rule *r*'s constant matches: none for `prefix` / `exact` / `suffix` / host (the checker compares bytes), `c:<offset>` for `contains`, `g:<a>-<b>,…` for a `glob` — one span of the string per `*`, `**` and `/**/` unit, in pattern order |

The checker accepts only if all of these hold:

1. **In the fragment.** The action lies in the fragment: at most 4,095 bytes;
   for a path, no flag bit outside the x86_64 `open(2)` set and access mode not
   3.
2. **The deciding rule.** Rule *r* exists, is an allow rule of this kind, and
   its flag clause holds.
3. **The witness.** It shows that *r*'s constant matches. For a glob, the checker
   walks the tokens left to right:
   - each literal or set token takes the next byte;
   - each stretch token takes exactly its span, which must start where the walk
     is and fit the token (no `/` inside a `*`, and a `/**/` span empty or
     ending in `/`);
   - the walk must end at the end of the string.
4. **No earlier rule holds.** No earlier rule of this kind holds on the action.
   The checker decides this itself, with its own matchers.

For the `--plan` gate, whose file opens carry no flags, the claim is that
**every** admissible flags value is decided by an allow rule. The checker
enumerates every value of the flag bits the matching rules test. A certificate
that names a single deciding rule also carries that rule's witness.

**Why the earlier rules are re-decided rather than certified.** "No earlier
rule holds" is a universal claim, and a compact certificate for a glob *not*
matching would have to be a refutation, which checks no more simply than
matching does. The checker therefore decides those rules with its own simple
matchers, in a row-by-row dynamic program over the glob's tokens. Before running
it, the matcher rejects a path whose start, end or length the pattern's
literals already rule out.

**How independent the checker is.** The two share no source, and the checker
has none of the procedure's optimizations. They are not independent in design:

- both follow the grammar in `smt_decide.h`;
- the checker's glob parser mirrors the procedure's structure closely;
- its matcher runs the same automaton, one step at a time rather than
  word-parallel.

The diversity comes from elsewhere. The cross-check's Python oracle translates
each glob into a regular language and decides it by derivatives and by Z3, and
the independent review added its own regular-expression translation and a
harness comparing the two C parsers. None of them found a disagreement.

The one authorization without a certificate is the agent's own launch
(`execve` of the binary the operator named). The Warden grants it once per run
by starting the agent, not by a policy decision. Exec and connect verdicts are
still refused at run time (deny-only since v1.9.1), so they need no certificate
there. The `--plan` gate certifies them too.

## In the Warden

- **One policy text for both.** The policy file is read **once**. The decision
  procedure and the checker parse the same bytes, and the Warden refuses to
  start if they disagree on the number of rules or the checker cannot parse
  the file.
- **Hashed.** Their SHA-256 is printed at load and recorded in `run_start` as
  `policy_sha256`.
- **Checked before the open.** After a SATISFIED verdict on a file open, the
  procedure builds the certificate and the checker checks it before the file
  is opened.
- **Recorded.** Authorized file opens record `open_flags`,
  `"cert_rule":…`, `"cert_witness":"…"` and `"check":"ok"`. These are flat
  fields: a record stays a flat JSON object.
- **Refused if the checker says no.** A refused certificate denies the open,
  with `"rule":"certificate_refused"`, `"check":"refused"` and the checker's
  reason in `check_why`. That includes the case where the procedure could build
  no witness, recorded with the witness `"!"`. The Warden prints the refusal
  without echoing the agent's path; the path is in the record.
- **Both parses must agree.** The Warden compares the two parses rule by rule
  at load: verb, kind, matcher, constant, flag clause and line. It refuses to
  start on any difference.
- **Test builds are marked.** The test-only `warden_faultinject` build
  announces itself at startup and marks its `run_start` with
  `"build":"faultinject"`. The audit refuses such streams.
- **The `--plan` gate** authorizes a planned action only if its certificate is
  accepted.

## Audit

```
tools/varek_audit.py --policy policy.txt --checker tools/vdp_cert_check verdicts.log
```

The audit passes only if all of these hold:

1. **The stream is authentic against the agent.** The tool checks the run id,
   the gap-free sequence numbers and the `run_end` count, as the CycloneDX
   exporter does, so the supervised agent cannot have added, dropped or forged
   a record.
2. **The policy is the one used.** The policy file must hash to the
   `policy_sha256` in `run_start`, so the certificates are checked against
   exactly the text the Warden used.
3. **Nothing else was authorized.** The only authorizations in the stream are
   certified file opens and the agent's one launch exec. Any other record that
   reads ALLOW fails the audit.
4. **Every authorization re-checks.** Every authorized file open must carry its
   open flags and a certificate the in-line checker accepted, and each one is
   checked again by `tools/vdp_cert_check`, the same small checker, which links
   nothing from the decision procedure.
5. **Not a test build.** Streams from the test build are refused.

The audit does not protect the log from whoever holds it: anyone who can
rewrite the file can rewrite the records consistently. If that matters, keep
verdict logs on append-only storage or sign them.

The CycloneDX 1.6 export now includes the policy SHA-256 and each
authorization's certificate.

## Validation

**Cross-check** (`make crosscheck`, now with `--cert`). On top of the v1.14
checks of the procedure against the solver and the derivative oracle, it
requires the following:

- **Parsing.** The checker accepts exactly the policies the procedure and the
  oracle accept. Its SHA-256 equals Python's.
- **Completeness.** Every certificate the procedure emits is accepted, and every
  glob witness is valid by the definition in `vdp_checker.h`, implemented again
  in Python.
- **Forged claims are refused.** These name:
  - another allow rule, or any rule when the verdict is not SATISFIED;
  - a deny rule;
  - a rule of another kind;
  - a glob witness that is wrong in exactly one way (a `/` inside a `*` span,
    or a `/**/` span that does not end in `/`).
- **Shadowed claims are refused.** These name an allow rule that holds when an
  earlier rule also holds, so only the earlier-rule check can refuse them.
- **Mutated witnesses** are accepted exactly when they are still valid.
- **Every rule's match agrees with the oracle.** For every query string, and
  for strings drawn from each rule's language (some padded to exactly 4,095
  bytes), the checker's own "does this rule's constant match" agrees with the
  oracle's regular language, rule by rule.

| Run | Procedure checks | Certificates accepted | Forged / shadowed refused | Rule-match comparisons | Disagreements |
|---|---|---|---|---|---|
| Every policy in the repository (23 files) | 1,800 | 182 | 3,809 / 145 | 28,992 | 0 |
| 300 fuzzed policies, seed 1 | 17,576 | 1,591 | 28,785 / 1,907 | 162,766 | 0 |
| 300 fuzzed policies, seed 2 | 18,628 | 1,640 | 31,246 / 1,743 | 174,092 | 0 |
| 300 fuzzed policies, seed 3 | 18,211 | 1,722 | 31,625 / 1,286 | 165,324 | 0 |

In all:

- 56,215 checks of the procedure;
- 5,135 certificates emitted and accepted;
- 95,465 forged and 5,081 shadowed certificates refused;
- 457 mutated witnesses judged correctly;
- 531,174 rule-by-string match comparisons.

There were zero disagreements anywhere. Of the 900 fuzzed policies, 761 were
accepted and 139 refused, identically by all three parsers. One repository
fixture, a policy that requires Warden 1.16, is refused by all three.

**Mutation test of the checker.** Twenty-six bugs were planted in the checker and
all 26 were flagged. They covered:

- each glob construct;
- the pre-filters;
- the earlier-rule check (skipping a rule, ignoring flags, ignoring the kind);
- the deciding-rule checks;
- the fragment boundary;
- every witness rule;
- the symbolic enumeration;
- the host atom;
- the `readonly` clause;
- the parser's keyword and `require` rules;
- SHA-256.

Three of them survived the first version of the cross-check and led to
additions:

- **A `/**/` witness span not ending in `/`.** The cross-check now forges
  witnesses that are wrong in exactly one way.
- **Access mode 3 enumerated in a symbolic claim.** There is now a fixture
  where only the fragment boundary makes the claim true.
- **A newer `require` accepted.** There is now a fixture policy for Warden
  1.16.

One further mutant ("some flags value is decided by no rule" treated as a pass)
first showed up as a hang, because the loop no longer advanced. Rewritten to
terminate, it was flagged as a false acceptance.

**The live test** (`make test-v1150`) builds `warden_faultinject`, a test-only
Warden whose decision procedure says SATISFIED for any path ending in
`/.inject`. Under the test policy:

- a path under an explicit deny glob and a path under a denied directory are
  both refused by the checker;
- both are recorded as `certificate_refused` with the reason "an earlier rule
  holds";
- the one planted verdict that happens to be right is accepted;
- the `--plan` gate declines the wrong verdict.

The same test covers the audit: a tampered witness, a removed certificate and a
different policy file each fail it, and six hand-forged certificates are
refused.

## Latency

| Measure | v1.14.0 | v1.15.0 |
|---|---|---|
| Certificate built and checked, per authorized open (tight loop; `policy.txt` / healthcare / utility / finance) | — | 0.08 / 0.8–0.9 / 0.8–0.9 / 1.6–2.0 µs |
| Warden, all decisions, P50 (`bench_target 10000`, five interleaved runs) | 8 µs | 8 µs (8 µs with the five v1.14 hazard rules added) |
| Warden, authorized file opens only, P50 / P99 | 48 / 127 µs | 50 / 109 µs |

The finance policy costs the most because its `/**/.env.*` glob has no literal
suffix to reject on, so the checker runs its matcher on every path. P99 on this
2-vCPU host is noisy and moves with load: 78–95 µs for v1.14.0 and 81–104 µs
for v1.15.0 across all runs.

The checker's cost comes from re-deciding the earlier rules with its own simple
matchers. That price was chosen on purpose: a checker that repeated the
procedure's optimizations would share their bugs.

**Worst case.** The checker's work for one authorization is bounded by the
policy's total glob size (at most 65,536 tokens) times the path length (at most
4,095 bytes). The independent review built two adversarial cases:

| Case | Checker, per open | Procedure, per open |
|---|---|---|
| 16 globs of about 4,000 tokens, 4,095-byte path | 415 ms | 4 ms |
| 200 globs of the form `**/node_modules/**/secretN*.pem` | 47 ms | 0.23 ms |

Both used a path chosen to pass every pre-filter. Since then the checker
rejects on literal prefix, suffix and length, which removes the second case for
most paths but not the first.

The agent can only slow its own run: one Warden supervises one agent, and the
agent cannot create directories, so a deep path must already exist. Keep large
glob sets out of policies for latency-sensitive agents.

## Compatibility

- **Policies are unchanged.** The grammar is v1.14's. `require warden 1.15` is
  accepted, and `1.16` is refused.
- **Records gain `open_flags`, `cert_rule`, `cert_witness`, `check` and
  `check_why`**, and `run_start` gains `policy_sha256`. All are flat fields.
  The CycloneDX exporter and the audit tool read them. Consumers that ignore
  unknown fields are unaffected.
- **`bench_summarize.py` parses each record line as one JSON object.** It used
  a regular expression for flat objects, which would have silently dropped any
  record with a nested value.
- **A new denial reason:** `certificate_refused`. It appears only when the
  procedure and the checker disagree, which the cross-check has not produced on
  any policy.
- **Building.** `warden` now also links `checker/vdp_checker.c`.
  `tools/vdp_cert_check` is new. `warden_faultinject` is a test-only binary and
  must never be deployed.

## Not in this release

- A formally verified checker. The checker is small and simple enough to be the
  candidate, but it is not verified.
- Certificates for refusals (UNSATISFIED / UNKNOWN). A wrong refusal fails
  closed, so it is not a safety issue.
- Certificates for the load-time reachability analysis, which is advisory.
- A customer-derived corpus and measured baseline; `fcntl(F_SETFL)` mediation;
  flags in the `--plan` file format; the bounded sequence fragment (v1.11
  candidate).

## Testing

- `make test-v1150`: described above.
- `make crosscheck` (the table above) and `make harness`.
- **Earlier suites pass:** `make test-v1140`, `test-v1130`, `test-v1124`,
  `test-v1123`, `test-v1122`, `test-v1121`, `test-v112`, `test-lifecycle`,
  `run-conformance` and `v1_6/integration_test.sh`.
- **CPython.** A dynamically linked, multithreaded CPython agent runs under the
  utility policy. All 46 of its authorized opens carry an accepted certificate,
  its reads of `.env` and writes to `libz` are refused, and the audit of its
  stream passes.
- **Independent review.** It found no way to make the checker accept a false
  claim, including 248,000 random forged witnesses. It also found no
  disagreement between the two C parsers over 1.1 million random policies, or
  between the checker's matcher and its own regular-expression translation over
  1.3 million pairs. Its findings are addressed in this release:
  - the refusal status line echoed the agent's path;
  - the audit passed a stream with a denial rewritten as ALLOW;
  - the independence claims were overstated;
  - worst-case cost;
  - the test build could not be told apart from a real one;
  - lax CLI parsing;
  - thin coverage of the earlier-rule check in the cross-check.

## Requirements

Runtime: unchanged (Linux ≥ 5.14, `pidfd_getfd`, `CAP_SYS_ADMIN`, x86_64). The
checker needs nothing beyond libc. The cross-check and `make test-v1150` also
need `python3` and the `z3-solver` package.
