# VAREK v1.19.0 — A Refusal Limit per Session

Released 2026-09-29 · MIT · github.com/kwdoug63/varek

## Summary

The plan gate's refusal breaker (v1.8.2, in the Warden since v1.18.0) counted
refused plans per session *and per plan*. A planner that changed one step each
time — another output file name, one more read — got a fresh count every time,
so it was never stopped. v1.18.0 listed this as a known limit.

v1.19.0 adds a limit per session. A flow policy declares

```
session_refusal_budget 10
```

and the breaker counts every refused plan in a session, whatever the plan. The
refusal that reaches the limit is terminal, and so is every later refused plan
in that session. The Warden requires the directive with `--flow-policy`.

Per-call verdicts are unchanged: the policy rules, the three-state verdict with
UNKNOWN suppressed to DENY, the certificates and the symmetric-suppression
invariant (**no extension may move a genuinely unsafe action to SATISFIED**).
Each plan's verdict is still a pure function of the plan and the policy; the
breaker only reads the sequence of verdicts.

`make test-v1190` runs the v1.7 layer's new test (65 checks) and a Warden test
(22 checks); 21 of the 22 fail against the v1.18.0 Warden, and the v1.7 test
uses an interface v1.18.0 does not have. Every earlier suite still passes. An
independent review of this release's code found no way around the limit in
normal operation, and four smaller problems, fixed here and covered by the
tests: a damaged state file could reset a session's count (a count of `-1`
read as the largest number and wrapped to 0 on the next refusal; a table with
plans but no session line started the session at 0), an authorized plan's
record said an exhausted session was not exhausted, and an UNKNOWN that
reached the limit was untested.

## How the session limit works

- **What counts.** Every refused submission in a session: an UNSATISFIED plan,
  or an UNKNOWN one. Resubmitting a plan that is already terminal is not
  counted again.
- **At the limit.** The refusal that brings the session's count to
  `session_refusal_budget` is terminal: an UNSATISFIED plan gets the policy's
  `on_exhaustion` disposition, an UNKNOWN its `unknown_disposition`. The
  session then latches: every later refused plan in it gets `on_exhaustion` at
  once and is not counted, whether it is new or had per-plan budget left. A
  plan that was already terminal keeps its own outcome.
- **Before the limit.** A refused plan is retryable (exit 3) only while both
  its own count is under `refusal_budget` and the session's is under
  `session_refusal_budget`.
- **Authorized plans.** An authorized plan always runs, even in an exhausted
  session. It clears its own plan's count, as before, but not the session's:
  otherwise a planner could put an authorized plan between refused ones and
  reset the bound.
- **Where it applies.** Sessions are still named by `--session` (default
  `default`) and kept in `--breaker-state`, both chosen by whoever starts the
  Warden. The limit bounds a host that resubmits through a launcher it does not
  control; a host that can pick a new session name starts a new count.

The Warden refuses to start with a flow policy that has no
`session_refusal_budget`, and a policy with `session_refusal_budget` but no
`refusal_budget` is an error (the limit would never be applied). The value is
1 to 1,000,000.

## What the host sees

- `--gate-status` adds the session's count to a retryable refusal:
  `REFUSED_RETRYABLE 1/2 session 3/10`. The other lines are unchanged.
- The Warden's message names both counts ("refusal 1 of 2 for this plan and 3
  of 10 in session s1"), and a terminal outcome caused by the session's limit
  says so.
- The `plan_gate` record in the verdict stream adds `session_refusals`,
  `session_budget` and `session_exhausted`. `varek_audit.py` and the CycloneDX
  exporter accept it.

## The state file

The breaker's table moves to format 2 (`varek-breaker 2`): the plan lines as
before, then one line per session, `session <session in hex> <count> <latched>
<outcome> <action>`, and the trailer counts both kinds of line. The loader:

- still reads a v1.18.0 table (format 1). Each session starts from the refusals
  its plans hold, with a plan latched by an UNKNOWN counted as 1. That is never
  more than the session made, but can be fewer, since an authorized plan
  cleared its own count;
- starts a session with plans but no session line from the same sum, and
  refuses a session line whose count is less than the sum (the count only
  grows, and every plan's refusal was also counted for its session);
- reads counts as plain decimal digits up to 4,294,967,295 and refuses anything
  else; counts stop at that maximum rather than wrap.

A table that does not load refuses the plan with exit 1, as in v1.18.0.

## Library interface (`v1_7/`)

- `plan_label_policy_config_session_refusal_budget()` returns the declared
  limit, or 0.
- `plan_breaker_result_t` adds `session_refusals`, `session_budget` and
  `session_exhausted`.
- Without a `session_refusal_budget`, the breaker still counts each session and
  saves the count, but never latches it: library callers see v1.18.0 behavior.
- The v1.9 progress-safety check's obligation P1 still asks only for a
  `refusal_budget`, so policies certified before stay certified; the Warden's
  own startup check adds the session limit.

## Compatibility

- **Flow policies need `session_refusal_budget`.** A v1.18.0 flow policy stops
  the Warden at startup with a message naming the directive to add.
- **`--gate-status`:** a retryable refusal's line gains ` session m/limit`.
  Parsers that read the first two fields are unaffected.
- **State file:** written as format 2 from the first gated plan. A v1.18.0
  Warden cannot read it back; roll back by removing the table, which resets
  every count.
- **Upgrading a busy default session.** Runs without `--session` share the
  session `default`. If a v1.18.0 table already holds `session_refusal_budget`
  or more refusals in one session, across all its plans, the first refused plan
  in that session after the upgrade is terminal. Raising the limit later does
  not reopen a latched session; only removing the table does.
- **Records:** `run_start` says `"warden":"1.19.0"`; the `plan_gate` record has
  three new fields.
- No change to the Warden's policy format or the plan file format.

## Known limits

- The session is whatever `--session` names. A host that can choose it can
  start a new count; so can one that can choose `--breaker-state`.
- A plan the gate cannot read at all (a malformed plan file) is rejected with
  exit 1 before the breaker, and is not counted. The agent does not run.
- A latched session stays latched until the table is removed. There is no
  per-session reset short of that.
- Plan steps still carry one argument (`target`), so flow rules cannot see a
  request's body or headers.
- The deployment preflight does not check `--flow-policy` or the breaker state.
