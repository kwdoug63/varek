<!-- SPDX-License-Identifier: MIT -->
# VAREK v1.9 — human-out-of-the-loop demo

`demo_hootl` runs an unattended agent against a certified policy and shows
every verdict path resolving with no human at run time. The progress
verifier runs for real at startup (its P4 check submits the declared
fallback to the decision procedure and requires SATISFIED), and the breaker
runs for real over real action-graph signatures. The closing line is the
property itself: zero human interventions.

## Run

C that links the v1_6 kernel, so it needs a compiler. Easiest on Linux
(Codespaces or the Droplet, where gcc is already present):

```bash
# Codespaces / Droplet (Linux), from the repo root
cd v1_7
bash run_demo.sh
```

`run_demo.sh` compiles `demo_hootl` and runs it against `hotl_policy.cfg`
(certifies) and `uncertified_policy.cfg` (rejected at boot). To run the
binary directly:

```bash
# Linux, from v1_7/
cc -std=c11 -O2 -I. -I../v1_6 demo_hootl.c \
   plan_dataflow.c plan_dataflow_adapter.c plan_dataflow_pathology.c \
   plan_warden_binding.c plan_policy_config.c plan_breaker.c \
   plan_progress.c ../v1_6/execution_plan.c ../v1_6/plan_evaluator.c \
   -o demo_hootl
./demo_hootl
```

On Windows it requires gcc/clang on PATH (e.g. mingw-w64); otherwise use
Codespaces. Color auto-disables when piped or under `NO_COLOR`.

## Expected output

```
VAREK v1.9 — human-out-of-the-loop demonstration
Certify the policy can always resolve without a human, then run unattended.

== STARTUP 1/2  reject a policy that is not progress-safe ==
    policy: uncertified_policy.cfg
    progress-safety: UNSATISFIED  (policy can refuse but declares no refusal_budget (unbounded retry is not human-out-of-the-loop safe))
    obligation P1 failed: add: refusal_budget N
    -> refusing to start unattended (exit 3).

== STARTUP 2/2  certify and boot the real policy ==
    policy: hotl_policy.cfg
    progress-safety: SATISFIED  (policy is progress-safe (human-out-of-the-loop certified))
    -> certified human-out-of-the-loop; starting unattended.

== RUN  scenario 1/4  in-policy action authorizes ==
  agent writes a check within its limit.
    step 1  write_check(amount=200)  verdict=SATISFIED  breaker=PASS
    -> authorized; check written. No human.

== RUN  scenario 2/4  refusal, re-planning harness resolves in-budget ==
  first proposal is over the limit; the harness re-plans monotonically (clamps toward the limit).
    step 1  write_check(amount=284)  verdict=UNSATISFIED  breaker=REFUSED_RETRYABLE
    step 2  write_check(amount=200)  verdict=SATISFIED  breaker=PASS
    -> authorized; check written. No human.

== RUN  scenario 3/4  stuck planner bounded to an automated fallback ==
  a stuck or adversarial planner resubmits the identical over-limit action; the budget (3) is spent, then the pre-authorized fallback fires.
    step 1  write_check(amount=284)  verdict=UNSATISFIED  breaker=REFUSED_RETRYABLE
    step 2  write_check(amount=284)  verdict=UNSATISFIED  breaker=REFUSED_RETRYABLE
    step 3  write_check(amount=284)  verdict=UNSATISFIED  breaker=TERMINAL_ACTION  -> run abort_txn
    -> pre-authorized abort_txn executed. No human.

== RUN  scenario 4/4  indeterminate verdict disposed without a human ==
  the decision procedure returns UNKNOWN (the binding's -1 maps here). UNKNOWN is never retried — a re-run reproduces it — so it goes straight to the policy's unknown_disposition.
    step 1  write_check(amount=999)  verdict=UNKNOWN  breaker=TERMINAL_DENY
    -> automated deny (task aborted). No human.

== RESULT ==
    unattended sessions ....... 4
    submissions ............... 7  (= 4 resolved + 3 bounded retries)
    authorized (executed) ..... 2
    automated terminals ....... 2
    human interventions ....... 0

    every session resolved automatically; no human in the loop
```

## What each line proves

- **Startup 1/2** — a policy that can refuse but cannot prove it always
  resolves is refused at boot (obligation P1). The system never reaches run
  time unless an automated terminal is guaranteed.
- **Scenario 1** — an in-policy action authorizes and executes.
- **Scenario 2** — a refusal is retryable; a re-planning harness resolves it
  inside the refusal budget.
- **Scenario 3** — a stuck or adversarial planner is bounded; once the budget
  is spent, the pre-authorized fallback (`abort_txn`) fires automatically.
- **Scenario 4** — an indeterminate (UNKNOWN) verdict is disposed
  immediately and never retried.
- **Result** — every session reached an automated terminal; human
  interventions: 0.

The recorded transcript of a real run is in `demo_hootl.out`. See
`INTEGRATION-hotl.md` for wiring this into a Warden, and for the honest
cost: the demo proves the system never hangs waiting for a human, not that
the policy is correct — policy coverage and fallback safety still have to be
tested.
