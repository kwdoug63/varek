# VAREK v1.9.0 — Progress-Safety Verification (HOOTL)

Released 2026-05-30 · MIT · github.com/kwdoug63/varek

## Summary

v1.9.0 adds a **load-time liveness proof**. The v1.6–v1.8 line proves *safety* —
nothing unauthorized executes. v1.9 adds the complementary guarantee that the
system always has a legal, automated next move. Together they make
**human-out-of-the-loop (HOOTL)** operation a property the verifier certifies per
policy, rather than a configuration setting taken on faith.

Without a liveness proof, "never requires a human" is a hope: a policy could
admit a reachable state in which an action is refused and no authorized fallback
exists — a deadlock only a human could break. v1.9 discharges that obligation
once, at policy load, before anything runs.

## The theorem certified

> For every non-authorizing verdict (UNSATISFIED or UNKNOWN) the policy can
> produce, the deterministic refusal resolution reaches an automated terminal
> outcome in finitely many steps, with no point requiring human intervention.

Four obligations:

- **P1 — bounded refusal.** A policy that can refuse must declare a refusal
  budget; an unbounded refusal is a potential infinite retry.
- **P2 — disposed UNKNOWN.** The UNKNOWN disposition must be terminal.
- **P3 — disposed exhaustion.** The exhaustion disposition must be terminal.
- **P4 — authorized fallback.** Every terminal disposition that names a safe
  action must name a declared rule, must not refuse a sticky label it could
  receive (a static over-approximation of deadlock), and must authorize as a
  standalone terminal under the flow policy. P4 is discharged by composing the
  underlying decision procedure as the authorization oracle.

`deny` is always a valid automated terminal (the host aborts the task). The
verifier guarantees that *some* automated terminal always exists — never a hang.

## Result shape

Three-state, matching VAREK semantics throughout:

| Result      | Meaning                                  | Action                       |
|-------------|------------------------------------------|------------------------------|
| SATISFIED   | Certified progress-safe (HOOTL)          | May start unattended         |
| UNSATISFIED | A concrete gap; failing obligation named | Fix policy before unattended |
| UNKNOWN     | Could not decide                         | Fail closed; not certified   |

## Operational use

Call `plan_progress_verify()` at policy load and refuse to start unattended
unless it certifies. That startup gate is what makes "no human at run time"
provable rather than hoped: if no automated terminal is guaranteed, the system
never reaches run time. See `v1_7/INTEGRATION-hotl.md` and
`v1_7/warden_hotl_example.c`.

## Scope boundary

P4 verifies the fallback authorizes under the *flow* policy. The node-axis permit
for the fallback (the Warden's `policy_decide`, e.g. a numeric limit check)
remains the deployment's responsibility and is enforced at submission exactly as
for any action.

## Tests

`v1_7/tests/test_v19_progress.c` — 10/10, clean under
`-fsanitize=address,undefined`.

## Files

New: `plan_progress.h`, `plan_progress.c`, `INTEGRATION-hotl.md`,
`warden_hotl_example.c`, `demo_hootl.c`, `tests/test_v19_progress.c`.
Modified: `plan_policy_config.{h,c}` (two accessors used by P1 and P4).

## Reproduce

    git clone https://github.com/kwdoug63/varek.git
    cd varek/v1_7
    make check

## Licensing

MIT. Three provisional patent applications are on file (formal-verification
layer, Warden kernel architecture, action-graph compositional policy decision).
The project is patent-pending; nothing in this release is granted.
