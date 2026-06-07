# VAREK v1.9 — progress-safety verification

Adds a load-time liveness proof that turns "human-out-of-the-loop" from a
configuration choice into a property the verifier certifies per policy.

## Why

v1.6–v1.8 prove SAFETY: nothing unauthorized executes. They do not prove
LIVENESS: that the system always has a legal, automated next move.
A human-out-of-the-loop deployment needs both. Without a liveness proof,
"never requires a human" is a hope — a policy could admit a reachable
state in which an action is refused and no authorized fallback exists, a
deadlock only a human could break. v1.9 discharges that obligation once,
at policy load, before anything runs.

## The theorem certified

> For every non-authorizing verdict (UNSATISFIED or UNKNOWN) the policy
> can produce, the v1.8.2 breaker's deterministic resolution reaches an
> automated terminal outcome in finitely many steps, with no point
> requiring human intervention.

Decomposed into four obligations:

- **P1 — bounded refusal.** If the policy can refuse at all (non-empty
  sticky set, or any `deny_in`/`unknown_in`), a `refusal_budget >= 1`
  must be declared. An unbounded refusal is a potential infinite retry.
- **P2 — disposed UNKNOWN.** `unknown_disposition` must be terminal.
- **P3 — disposed exhaustion.** `on_exhaustion` must be terminal.
- **P4 — authorized fallback (the reachability proof).** Every terminal
  disposition that names a safe action must:
  - **(a)** name a declared rule;
  - **(b) static** — not deny/unknown a sticky label it may receive
    (such a fallback is refused the moment that label reaches it:
    refuse -> fallback -> refuse). Sound over-approximation of deadlock;
  - **(b) dynamic** — authorize as a standalone terminal under the flow
    policy. Discharged by submitting the fallback as a singleton plan to
    the pure decision procedure (`plan_warden_verify`) and requiring
    SATISFIED. The progress verifier composes the verifier it sits above
    as its authorization oracle.

`deny` is always a valid automated terminal sink (the host aborts the
task). Whether abort is operationally acceptable is the author's call;
the verifier guarantees only that *some* automated terminal always
exists, never a hang. A policy that cannot refuse is trivially
progress-safe.

## Result shape

Three-state, matching VAREK semantics:
- `SATISFIED` — certified progress-safe (human-out-of-the-loop).
- `UNSATISFIED` — a concrete gap; `finding.detail` names it and
  `finding.obligation` reports which of P1–P4 fired.
- `UNKNOWN` — the verifier could not decide (e.g. allocation failure);
  fail closed, treat as NOT certified.

### New files
- `plan_progress.h` / `plan_progress.c`

### Modified files
- `plan_policy_config.h` / `plan_policy_config.c` — two accessors used by
  P1 and P4(b)-static (`_can_refuse`, `_action_denies_sticky`,
  `_has_action`). Shared with v1.8.2's config changes.

## Scope boundary

P4 verifies the fallback authorizes under the **flow** policy. The
node-axis permit for the fallback (the Warden's `policy_decide`, e.g. a
numeric limit check) is the deployment's responsibility and is enforced
at submission exactly as for any action. The v1.7 flow kernel refuses
only on inbound labels, so the dynamic singleton oracle cannot by itself
catch a deadlock-prone fallback — the P4(b)-static sticky check carries
that obligation.

## Operational use

Call `plan_progress_verify()` at policy load and refuse to start
unattended unless it certifies. That startup gate is what makes
"no human at run time" provable rather than hoped: if no automated
terminal is guaranteed, the system never reaches run time. See
`INTEGRATION-hotl.md` and `warden_hotl_example.c`.

## Tests
`tests/test_v19_progress.c` — 10/10, clean under
`-fsanitize=address,undefined`.
