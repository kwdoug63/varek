# VAREK v1.9.1 — Enforcement Hardening & Security Documentation

Released 2026-06-20 · MIT · github.com/kwdoug63/varek

*(Set the release date to your tag date.)*

## Summary

v1.9.1 is a hardening and disclosure patch. It changes no verdict semantics and
does not touch the v1.9 progress-safety proof. It closes two audit-critical gaps
in the enforcement boundary, makes UNKNOWN navigable, bounds the decision
procedure deterministically, and publishes the threat model and trusted-computing
-base status that the verification chain relies on. The invariant is unchanged:
**no extension may move a genuinely unsafe action to SATISFIED.**

## Security

### io_uring bypass closed

io_uring dispatches I/O from kernel worker threads off the normal syscall entry
path. seccomp filters the entry path, so the Warden's user-notification
mediation never observes operations issued through an io_uring instance — a
policy that mediates `openat`/`connect`/etc. is silently bypassed by an agent
that routes the same operations through io_uring. There is no sound way to
*mediate* io_uring at this layer, so the baseline policy now **denies io_uring
instance creation** (`io_uring_setup`, `io_uring_enter`, `io_uring_register`)
with `EPERM`. New: `v1_7/warden_seccomp_baseline.c`,
`v1_7/tests/test_v191_io_uring.c`.

### seccomp user-notification TOCTOU discipline

The unotify supervisor receives pointer arguments that reference the target's
memory; a second target thread can rewrite that memory between the supervisor's
check and the kernel's use of it. v1.9.1 enforces three rules:

- `SECCOMP_USER_NOTIF_FLAG_CONTINUE` is **never** used to authorize a syscall
  whose decision depended on user-pointer contents — CONTINUE cannot enforce a
  pointer-data decision.
- Pointer-argument operations (path-based opens, etc.) are performed by the
  **supervisor** on a validated, copied argument and the result is injected via
  `SECCOMP_IOCTL_NOTIF_ADDFD`; the target's original syscall does not run.
- Every notification is revalidated with `SECCOMP_IOCTL_NOTIF_ID_VALID`
  immediately before the supervisor acts.

New: `v1_7/warden_notify_hardening.{h,c}`. Decisions on scalar register
arguments remain safe (the kernel snapshots them); pointer-dereferenced data does
not, and is handled by the supervisor-performs pattern above.

## Added

- **UNKNOWN-reason diagnostics.** An UNKNOWN verdict now carries the undischarged
  predicate and the fragment that would resolve it. Additive metadata on a
  refusal; SATISFIED/UNSATISFIED are byte-for-byte unchanged and soundness is
  unaffected. Spec: `docs/security/v1.9.1-verifier-notes.md`.
- **Deterministic resource bounds.** Per-obligation step and time ceilings with
  an obligation memoization cache. A bound hit yields UNKNOWN (fail closed),
  never a coerced pass; the step ceiling is the authoritative, reproducible cut.
- **Security documentation.** `docs/security/THREAT-MODEL.md` and
  `docs/security/TRUSTED-COMPUTING-BASE.md`.

## Changed

- Documented the per-component trusted-vs-verified status of the verification
  chain, and the strategy to shrink the trusted base (proof objects + an
  independent checker). See `TRUSTED-COMPUTING-BASE.md`.

## Result shape

Unchanged from v1.9 — three-state throughout:

| Result      | Meaning                                  | Action                       |
|-------------|------------------------------------------|------------------------------|
| SATISFIED   | Provably compliant with policy           | May proceed                  |
| UNSATISFIED | Provably violates policy                 | Denied                       |
| UNKNOWN     | Not decidable within bounds              | Fail closed; now diagnosed   |

## Tests

- `v1_7/tests/test_v191_io_uring.c` — asserts `io_uring_setup` is denied with
  `EPERM` under the baseline filter.
- Run the full suite (`make check`) and confirm the existing verdict tests are
  unchanged before tagging — the verifier-side additions must not alter any
  SATISFIED/UNSATISFIED outcome.

## Upgrade notes

- No API or verdict-semantics changes. The io_uring denial is a behavioral change
  for any workload that legitimately used io_uring; such workloads must switch to
  synchronous I/O under the mediated path, by design.
- If you publish the limitations-and-mitigations document, update item 3 to
  reflect that io_uring is closed and the TOCTOU discipline is shipped.

## Licensing

MIT. Three provisional patent applications are on file (formal-verification
layer, Warden kernel architecture, action-graph compositional policy decision).
The project is patent-pending; nothing in this release is granted.
