# VAREK v1.12.4 — The --plan Gate Authorizes File Opens Again

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

v1.12.4 fixes the `--plan` pre-execution gate, which had rejected every plan
that declared a `file_open` action since v1.12.0. Optional plan verification
checks an agent's declared action graph against the policy before the agent is
forked, and refuses to launch it if any action is not authorized. Since v1.12.0
the per-open policy decision (`policy_decide` on a file open) has been made on
the object's **resolved canonical path**, not the raw pathname — but the plan
decider, which runs before there is any agent to resolve against, never filled
that field. So every `file_open` node came back UNKNOWN, and any plan that
opened a file was rejected, including the shipped `sample_plan.txt` and the v1.6
integration test's authorized-plan case.

v1.12.4 has the plan decider fill the resolved field with the **lexically
canonical** form of the declared path (`.`, `..` and duplicate slashes
collapsed). That is the pre-execution analog of the runtime canonical path, so a
plan that opens a policy-allowed file verifies as SATISFIED again, while a plan
whose `..` lexically escapes an allowed prefix does not.

No verdict *semantics* change at runtime. Every file open is still resolved and
decided per-syscall exactly as before; only the pre-fork plan check is fixed.

`make test-v1124` covers the gate, and `v1_6/integration_test.sh` passes again.
All other suites pass unchanged.

## The fix

Plan verification is inherently an **approximation**, and it is worth being
precise about what it can and cannot check:

- The runtime file-open decision follows every symlink and resolves the path
  against the live agent's cwd. A plan is verified **before** the agent exists,
  so there is no cwd and the named file may not exist yet — symlinks cannot be
  followed because there is nothing to follow.
- So the gate canonicalizes the declared path **lexically** (collapsing `.`,
  `..` and duplicate slashes) and decides policy on that. A `..` is clamped at
  `/`, never allowed to rise above it.
- Only **absolute** paths can be verified this way. A relative `file_open`
  target has no cwd to resolve against before the fork, so it stays UNKNOWN and
  the plan is not authorized, rather than being guessed.
- The gate is an **advisory pre-check**, not a substitute for enforcement. A
  plan that lexically clears the policy is still mediated per-syscall at runtime,
  where symlinks are followed and the real object is decided. A plan cannot use
  a symlink to smuggle an open past the gate, because at runtime that open is
  decided on the symlink's canonical target.

Concretely, under a policy allowing `/var/data/`:

- `file_open /var/data/input.json` → SATISFIED (was UNKNOWN → rejected).
- `file_open /var/data/sub/../input.json` → canonicalizes to
  `/var/data/input.json` → SATISFIED.
- `file_open /var/data/../etc/shadow` → canonicalizes to `/etc/shadow` → not
  under the allowed prefix → UNKNOWN → the plan is rejected.
- `file_open var/data/input.json` (relative) → UNKNOWN → the plan is rejected.

`net_connect` and `process_exec` plan actions are decided on their target
directly and were never affected.

## Compatibility

- A `--plan` file that declares a `file_open` under an allowed prefix now
  verifies as SATISFIED and the target is launched; through v1.12.3 it was
  rejected. Nothing that was previously authorized becomes rejected.
- Plan `file_open` targets should be **absolute**; a relative target cannot be
  verified before the fork and leaves the plan UNKNOWN.
- No policy-file, plan-file or record-format change. `run_start` reads
  `"warden":"1.12.4"`.
- Runtime enforcement, latency, and every non-plan path are unchanged.

## Testing

- `make test-v1124`: drives the Warden's `--plan` path with `/bin/true` as a
  harmless no-op target (it exits immediately when a plan authorizes and forks
  it) and checks that an allowed `file_open` is SATISFIED and launches; an unlisted one is UNKNOWN and a denied one is
  UNSATISFIED, both refusing to fork; `.`/`..` collapse before the decision; a
  `..` escape and a relative path stay UNKNOWN; and a `file_open` mixed with an
  allowed exec and connect is SATISFIED while a denied connect still rejects the
  whole plan. Against v1.12.3 every file-open case is UNKNOWN and the suite
  fails.
- `v1_6/integration_test.sh` passes (its authorized-plan case, broken since
  v1.12.0, is authorized again).
- `make test-v1123`, `make test-v1122`, `make test-v1121`, `make test-v112`,
  `make test-lifecycle` and `make run-conformance` pass unchanged.

## Requirements

Unchanged from v1.12.3: Linux ≥ 5.14, `pidfd_getfd` (Linux ≥ 5.6),
`CAP_SYS_ADMIN` for the PID and network namespaces, x86_64.
