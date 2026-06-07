# VAREK v1.8.2 — bounded-refusal breaker

Point release. Adds a non-bypassable loop bound to the enforcement layer
without touching the decision procedure.

## Why

The decision procedure answers "may this submission run?" purely and
statelessly. It has no control loop: a refused plan returns UNSATISFIED
and what the agent does next is the host's business. Left unbounded, a
stuck or adversarial planner can resubmit the same refused action-graph
forever — a self-inflicted denial of service, and in an unattended
deployment a hang that only a human could break. v1.8.2 closes that loop
in the trusted boundary so the bound cannot be defeated by buggy or
compromised harness code.

## What

A breaker that sits above `plan_warden_verify()`, keyed by
`(session, action-signature)`. Each individual verdict stays a pure
function of `(plan, policy)`; the breaker only interprets the *sequence*
of verdicts for one signature and, once the policy's refusal budget is
spent, latches to a deterministic terminal disposition declared in the
policy. Resolution is bounded — at most `budget` retryable refusals per
signature — and no outcome requires human intervention.

### New files
- `plan_breaker.h` / `plan_breaker.c`

### Modified files
- `plan_policy_config.h` / `plan_policy_config.c` — three optional
  top-level directives (below) plus accessors. Fully backward compatible:
  a policy with none of them behaves exactly as pre-v1.8.2 (the
  v1.8.0 declassification suite passes unchanged, 16/0).

### Policy grammar additions
```
refusal_budget N                 # N >= 1; absent => breaker disabled
on_exhaustion deny               # default when absent
on_exhaustion terminal NAME      # fire a pre-authorized safe action
unknown_disposition deny         # default when absent
unknown_disposition terminal NAME
```

### Semantics
- `SATISFIED` -> PASS; the signature's counter and latch clear
  (authorization always wins; a now-authorized action is never blocked
  by past refusals).
- `UNSATISFIED` -> increment. Below budget: `REFUSED_RETRYABLE` (host may
  re-plan). At/over budget: fire `on_exhaustion`, latch.
- `UNKNOWN` -> route immediately to `unknown_disposition` and latch.
  Never retried, because re-running the same input reproduces UNKNOWN.
- Latched signature -> replays its terminal outcome idempotently.
- Breaker disabled (no `refusal_budget`) -> `UNSATISFIED` always
  `REFUSED_RETRYABLE`, never latches (pre-v1.8.2 pass-through).
- Memory pressure interning a new entry -> fail closed to the exhaustion
  disposition.

The signature is FNV-1a over each node's action name and named args in
node-id order: deterministic, argument-sensitive (`$200` and `$284`
differ), allocation-free.

## Boundaries
- The decision procedure is untouched. The counter is enforcement state,
  not decision state.
- The breaker never authors a corrected action. Re-planning (the PASS
  path) and executing the named safe action (the TERMINAL_ACTION path)
  remain the host's job.
- The reference `(session, signature)` table is a flat vector, O(n) per
  step. A production Warden with many concurrent sessions should swap the
  lookup for a hash map; the semantics are the contract, not the data
  structure.

## Tests
`tests/test_v18_2_breaker.c` — 19/19, clean under
`-fsanitize=address,undefined`.
