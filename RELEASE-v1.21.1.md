# VAREK v1.21.1 — Plan Steps Say How They Open

Released 2026-09-29 · MIT · github.com/kwdoug63/varek

## Summary

A plan step has no open flags of its own, so through v1.21.0 the `--plan`
gate decided a `file_open` step with the flags unknown. A path allowed only by
a rule with a flag clause (`readonly`, `access=ro`, `-O_TRUNC`, ...) was
therefore UNKNOWN at the gate, although the runtime allowed the same open.
Under a flow policy with `unknown_disposition deny` that refusal was terminal
at once. All five shipped sector policies grant their libraries with
`readonly`, and four of them grant data that way too (finance's market
snapshots, utility's telemetry, for example), so a plan that declared reading them could not pass.

A `file_open` step may now declare how it opens its file in an `open` field:

```
action load  file_open  /srv/agent/reference/in.json  open=read
action save  file_open  /srv/agent/work/out.json      open=O_WRONLY|O_CREAT|O_TRUNC
edge   load  save
```

The node check decides and certifies the step with exactly those flags, as the
runtime decides an open with the flags the agent passes.

This release also corrects statements v1.21.0 left behind: the comment at the
top of `v1_6/sample_plan.txt` and a sentence in the data-flow threat model
still said every connect step is refused.

Per-call verdicts at run time are unchanged, and so is the
symmetric-suppression invariant (**no extension may move a genuinely unsafe
action to SATISFIED**).

## The `open` field

- `open=read`: `O_RDONLY` and nothing else, which is what a `readonly` rule
  allows.
- Otherwise an access mode, `O_RDONLY`, `O_WRONLY` or `O_RDWR`, then any of
  `O_CREAT`, `O_EXCL`, `O_NOCTTY`, `O_TRUNC`, `O_APPEND`, `O_NONBLOCK`,
  `O_DSYNC`, `O_ASYNC`, `O_DIRECT`, `O_LARGEFILE`, `O_DIRECTORY`,
  `O_NOFOLLOW`, `O_NOATIME`, `O_CLOEXEC`, `O_SYNC`, `O_PATH`, `O_TMPFILE`,
  each at most once, joined by `|`. A quoted value (`open="read"`) is read the
  same.
- A name has the value an agent's `open()` passes for it: `O_SYNC` and
  `O_TMPFILE` are glibc's composites (`O_SYNC` includes `O_DSYNC`,
  `O_TMPFILE` includes `O_DIRECTORY`). `O_LARGEFILE` is the kernel's bit,
  `0100000`, which is what the name means in a policy's flag clauses (glibc
  defines it as 0 on x86_64).
- Anything else makes the step UNKNOWN, never SATISFIED, and the Warden logs
  why: another word, a lowercase name, a flag first, an unknown or second
  access mode, a repeated flag, an empty value or a stray `|`, and an `open`
  field on a step that is not a `file_open`.
- Without the field a step is decided as in v1.21.0.

The field is a declaration, like the rest of a plan. It does not bind the
agent: an open with other flags is decided on its own flags at run time. What
changes is that the gate can now authorize a plan whose declared reads the
runtime would allow, instead of refusing it for want of flags. `open` is also
an ordinary field for the `--flow-policy` rules (a rule that matches it needs
`trust_declared_fields`, as for any field), and part of the plan's breaker
signature. The Verdict Service front end, `v1_6/plan_verify`, ignores it.

## Tests

`make test-v1211` (33 checks): without the field a read-only path is UNKNOWN
as before; `open=read` and `O_RDONLY|O_CLOEXEC` are authorized and the agent's
read is then allowed at run time; `O_RDWR`, `O_WRONLY`, `O_RDONLY|O_TRUNC` and
`O_RDONLY|O_CREAT` are decided and not authorized on a read-only path; a
denied path is UNSATISFIED for a valid declared read; a declared write is
authorized on a read-write path and not on a read-only one; `O_LARGEFILE` and
`O_SYNC` meet `+O_LARGEFILE` and `+O_DSYNC` denials as the runtime would;
twelve malformed forms and an `open` field on a `net_connect` or
`process_exec` step are UNKNOWN with their reason; with `--flow-policy` a
declared plan passes and a malformed one is refused before the agent runs;
`varek_audit` accepts the run. 23 of the 33 fail against the v1.21.0 Warden
(the others check behaviour that is unchanged). Every earlier suite still
passes.

## Found in review

An independent review of this release found, and this release fixes:

- As first written, `O_LARGEFILE` in a plan took glibc's value, 0 on x86_64,
  while the policy language gives the name the kernel's bit. A plan step
  declaring `O_RDONLY|O_LARGEFILE` was authorized past a `+O_LARGEFILE`
  denial that the runtime then applied to the same open. It now takes the
  kernel's bit, and the test covers it. No shipped policy has such a clause.
- The new refusal line printed the step's kind, which is the plan's own text,
  without escaping; it is now escaped like the target.
- `warden_verify_plan` read the plan's action count after freeing the plan
  (present since before v1.21.0; the number printed in "plan authorized (n
  actions)" came from freed memory). It is read before the free.
- `v1_6/README.md` still said every `net_connect` step is UNSATISFIED, and
  the spec paper and a filter comment still described connects as deny-only
  in the present tense; corrected. The test counts in the first draft of these
  notes were wrong, and the test did not check that refused flags were
  decided rather than rejected as malformed, nor the refusal path with
  `--flow-policy`; both are covered now.

## Compatibility

- **Plans:** a plan with no `open` field is decided exactly as before. A v1.20
  or v1.21.0 plan that already used a field named `open` for its own purposes
  now has it read by the node check; if its value is not one of the forms
  above, the step becomes UNKNOWN. Rename such a field.
- **Records:** `run_start` says `"warden":"1.21.1"`. No other record changes.
- No change to the policy grammar (still 1.21), the runtime, the breaker state
  file or the audit.
- The host-names plan (stage 2) now targets v1.21.2, with
  `require warden 1.21.2`, which v1.21.1 refuses as a malformed directive.

## Known limits

- The field is the agent's declaration; nothing compares the agent's later
  opens with it.
- A step declares one set of flags. A plan that opens the same file twice with
  different flags declares two steps.
- Symlinks are still not followed at plan time; the gate decides the lexically
  canonical path, and the runtime the object the path resolves to.
