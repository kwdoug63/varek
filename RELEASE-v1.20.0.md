# VAREK v1.20.0 — Fields on Plan Steps

Released 2026-09-29 · MIT · github.com/kwdoug63/varek

## Summary

Through v1.19.0 a plan step had one field, its target, so the data-flow
policy could see nothing else a step declared: what a file holds, what a
request carries, where a write is meant to go. v1.19.0 listed this as a known
limit.

A plan step can now carry fields after its target:

```
action read  file_open /srv/inbox/msg contains="a customer record"
action write file_open /srv/public/out
edge read write
```

and the Warden's `--flow-policy` rules match them like any named argument:

```
rule file_open
  match target /srv/inbox/*
  match contains *customer?record*
  origin SECRET
```

Fields are the agent's declarations, like the plan's edges. The node check
and the runtime still see only the target, and nothing compares the agent's
later calls with its fields. Because the agent chooses them, the Warden
refuses a flow policy whose rules match a field unless the policy says
`trust_declared_fields` (below).

Per-call verdicts are unchanged: the policy rules, the three-state verdict
with UNKNOWN suppressed to DENY, the certificates and the symmetric-suppression
invariant (**no extension may move a genuinely unsafe action to SATISFIED**).

`make test-v1200` runs the plan parser's field test (48 checks), the v1.7
layer's new test (14) and a Warden test (22); 21 of the 22 fail against the
v1.19.0 Warden. Every earlier suite still passes, and a plan without fields
has the same breaker signature as in v1.19.0, so existing counts carry over.

An independent review of this release's code found one real problem, fixed
here and covered by the tests: with the longer lines, a target could exceed
the Warden's 4096-byte path buffer, and the node check decided the truncated
path. A target of about 10 KB that collapses to a denied file was authorized
at the gate (every open was still decided at runtime). Targets are now limited
to 4095 bytes, and the node check calls a longer one UNKNOWN. The review also
led to `trust_declared_fields`, the refusal of NUL bytes, and an exact line
limit.

## The format

```
action <label> <kind> <target> [<key>=<value> ...]
```

- Up to 16 fields per step. A key is `[a-z][a-z0-9_]*`, at most 32
  characters, unique in the step, and not `target`. Keys cannot contain `.`,
  so a field never collides with a rule's URL component keys (`url.host`); a
  field named `url` can be matched by component.
- A value is bare (up to the next space or tab; no `"` or control character)
  or quoted, `"..."`, with the escapes `\"`, `\\`, `\n`, `\r`, `\t` and
  `\xHH` (not `\x00`). At most 4096 bytes after decoding.
- A line may hold 16383 bytes (it was 1022); a target at most 4095. A NUL
  byte anywhere refuses the file (a C reader would otherwise stop the line
  there and drop what followed).
- Every malformed form refuses the whole plan file with its line number: a
  bad key, a repeated key, `target=`, an unterminated quote, text after a
  closing quote, an unknown escape, a raw control character.
- Plans without fields read exactly as before.

In C, `plan_parser_fields(parsed, i, &n)` returns step `i`'s fields in file
order. `plan_spec_action_t` is unchanged, so existing initializers compile as
before.

## In the Warden

- The `--plan` gate hands each step's fields to the `--flow-policy` rules as
  named arguments beside `target`, in key order.
- The node check (the Warden's own policy) and the runtime see only the
  target, as before. A field cannot make a denied path pass.
- Fields are part of the plan's breaker signature: the same fields in another
  order are the same plan; a changed value is a different plan, with its own
  per-plan count. The session limit (v1.19.0) bounds that.
- `--plan` without `--flow-policy` reads plans with fields and ignores them.
  So does the Verdict Service front end, `v1_6/plan_verify`.
- Network and launch steps are still refused at the gate (the runtime refuses
  them, v1.18.0), whatever their fields say. Fields describing a request, such
  as its body or headers, reach the flow check, and decide a plan for a host
  that runs the v1.7 check itself (`plan_warden_verify()`); in the Warden they
  cannot make a network step pass.

## `trust_declared_fields`

The agent writes its plan, so declaring or omitting a field changes which
rule applies:

- a rule that **permits** on a field (`permit_in`, `declassify`) is unlocked
  by declaring the field;
- a rule that **refuses** on a field is avoided by leaving the field out;
- a rule on a field placed **before** a stricter rule skips it.

The Warden refuses to start with a flow policy that has any rule matching an
argument other than `target` (or a component of it), naming the rule and the
field, unless the policy declares

```
trust_declared_fields
```

The line says the operator accepts that trade-off. Fields help an honest
planner say more about its steps, so the gate can catch a flow the planner did
not mean; they are not evidence against one that lies. Policies whose rules
match only the target need no change. In the library,
`plan_label_policy_config_field_rule()` reports such a rule and
`plan_label_policy_config_trusts_declared_fields()` the directive.

## Compatibility

- **Plan files:** a step may carry fields. A plan that had a fourth token on
  an action line was refused before and is still refused unless the token is
  a valid `key=value`.
- **Line length:** up to 16383 bytes (was 1022). Targets are limited to 4095
  bytes, the most the Warden's 4096-byte path buffer holds; before, the line
  limit kept them under about 1 KB.
- **Flow policies** whose rules match an argument other than `target` need
  `trust_declared_fields` to start the Warden. In a v1.19.0 Warden such rules
  could never match (only `target` existed), so a policy that has them now
  stops the Warden until it declares the line or drops those rules. Policies
  whose rules match only the target are unaffected.
- **Records:** `run_start` says `"warden":"1.20.0"`; the default policy
  version is `1.20`. No record format changes.
- No change to the Warden's policy format, the breaker state file or the
  signature of a plan without fields.

## Known limits

- Fields are declarations. Nothing binds the agent's later calls to them, as
  nothing binds them to the plan's edges.
- A rule on a field can be unlocked, avoided or used to skip a stricter rule
  by the agent; `trust_declared_fields` accepts that rather than prevents it.
- In the Warden, network and launch steps are refused at the gate whatever
  their fields, so request fields matter there only to the flow check's
  verdict on the flow axis.
- The session is whatever `--session` names; a host that can choose it can
  start a new count.
- The deployment preflight does not check `--flow-policy` or the breaker
  state.
