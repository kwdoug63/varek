# Integrating VAREK for a human-out-of-the-loop system

This wires v1.8.2 (bounded-refusal breaker) and v1.9 (progress-safety)
into a fully automated agent loop that never requires human oversight at
run time. The human's judgment is captured once, in the policy, and
audited offline; no human is in the execution loop.

The guarantee rests on a single property: **every refusal and every
UNKNOWN terminates deterministically in an authorized state.** v1.9
proves the property holds for a given policy; v1.8.2 enforces it at run
time.

## Two integration points

### 1. Startup gate (once, at load)

```c
plan_label_policy_config_t *cfg = /* load policy file */;

plan_progress_finding_t f;
plan_progress_verify(cfg, &f);
if (!plan_progress_certified(&f)) {
    log("policy not human-out-of-the-loop safe (P%d): %s",
        f.obligation, f.detail);
    refuse_to_start();          /* do NOT run unattended */
}
```

If the policy is not progress-safe, the system never reaches run time.
This is what converts "no human at run time" from a hope into a property:
an uncertified policy cannot start unattended.

### 2. Per-submission breaker (every action-graph)

```c
plan_breaker_t *b = plan_breaker_new();          /* per Warden, once */

uint64_t sig = plan_breaker_signature(actions, n_actions);

for (;;) {
    /* The pure decision procedure — unchanged, stateless. */
    plan_warden_response_t resp;
    int rc = plan_warden_verify(&req, &resp);
    plan_decision_t verdict = (rc == 0) ? resp.verdict : PLAN_DEC_UNKNOWN;

    plan_breaker_result_t r =
        plan_breaker_step(b, session_id, sig, verdict, cfg);

    switch (r.outcome) {
    case PLAN_BREAKER_PASS:
        execute(plan);                    /* authorized */
        goto done;
    case PLAN_BREAKER_REFUSED_RETRYABLE:
        plan = replan(plan, resp);        /* host's re-planning */
        sig  = plan_breaker_signature(/* new actions */);
        continue;
    case PLAN_BREAKER_TERMINAL_DENY:
        abort_task("automated terminal refusal");
        goto done;
    case PLAN_BREAKER_TERMINAL_ACTION:
        execute_safe_action(r.terminal_action);  /* pre-authorized */
        goto done;
    }
}
done: ;
```

The loop provably terminates: at most `refusal_budget` retryable
refusals per signature, then a latched terminal outcome. No branch waits
for a person.

## Division of responsibility

- **Decision procedure** — stateless, pure, unchanged. Never holds loop
  state. Each verdict is a pure function of `(plan, policy)`.
- **Breaker (Warden, trusted)** — owns the loop bound and the terminal
  transition. Non-bypassable because it lives in the boundary, not the
  harness.
- **Harness (untrusted, host)** — re-planning and retry-for-efficiency
  only. It can be buggy or hostile without defeating the bound: the worst
  it can do is burn the budget, after which the breaker resolves the task
  automatically.

## Policy authoring checklist

A progress-safe HOTL policy declares:

1. `refusal_budget N` (N >= 1) if the policy can refuse.
2. `unknown_disposition deny` or `... terminal NAME`.
3. `on_exhaustion deny` or `... terminal NAME`.
4. For any `terminal NAME`: `NAME` is a declared rule, does not deny or
   unknown a sticky label, and authorizes as a standalone action.

Run `plan_progress_verify()` and read `finding.obligation` /
`finding.detail` to locate any gap. See `hotl_policy.cfg` for a policy
that certifies, and `warden_hotl_example.c` for the full loop:

- **Scenario A (re-planning harness):** over-limit write refused once,
  re-plan within the limit, authorized. No human.
- **Scenario B (stuck planner):** same over-limit write resubmitted;
  bounded to 3 refusals, then the pre-authorized `abort_txn` fires
  automatically. No human.

## The honest cost

Removing the human from run time moves the entire safety burden onto two
things: policy completeness, and the safety of the terminal fallback in
every context it can fire. Any case the policy does not cover now resolves
to the fallback silently, with no human to catch it. v1.9 guarantees the
system never *hangs* waiting for a human; it does not guarantee the
policy is *correct*. Test the policy's coverage and the fallback's safety
as carefully as the code.

## Makefile fragment

Append to `v1_7/Makefile`. Mirrors the existing flags and the v1_6 kernel
link (`../v1_6/execution_plan.c`, `../v1_6/plan_evaluator.c`).

```make
# target: v1_7/Makefile
# --- human-out-of-the-loop: v1.8.2 breaker + v1.9 progress verifier ---
V16      := ../v1_6
HOTL_SRC := plan_dataflow.c plan_dataflow_adapter.c plan_dataflow_pathology.c \
            plan_warden_binding.c plan_policy_config.c \
            plan_breaker.c plan_progress.c
V16_SRC  := $(V16)/execution_plan.c $(V16)/plan_evaluator.c
HOTL_INC := -I. -I$(V16)

# CFLAGS/SAN as defined at the top of this Makefile:
#   CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow \
#            -Wstrict-prototypes -Wmissing-prototypes
#   SAN    = -fsanitize=address,undefined -g

test_v18_2_breaker: tests/test_v18_2_breaker.c $(HOTL_SRC) $(V16_SRC)
	$(CC) $(CFLAGS) $(SAN) $(HOTL_INC) $^ -o $@
	./$@

test_v19_progress: tests/test_v19_progress.c $(HOTL_SRC) $(V16_SRC)
	$(CC) $(CFLAGS) $(SAN) $(HOTL_INC) $^ -o $@
	./$@

warden_hotl_example: warden_hotl_example.c $(HOTL_SRC) $(V16_SRC)
	$(CC) $(CFLAGS) $(HOTL_INC) $^ -o $@

hotl-check: test_v18_2_breaker test_v19_progress
.PHONY: hotl-check
```

Build and verify:

```bash
# target: any POSIX build host (Droplet / Codespaces / local)
cd v1_7
make hotl-check                         # both suites under ASan/UBSan
make warden_hotl_example && ./warden_hotl_example
```
