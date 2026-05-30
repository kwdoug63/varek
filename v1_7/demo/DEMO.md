# VAREK demo (v1.8.1)

A narrated tour of cross-action data-flow verification. Every verdict
shown here is produced by the real verifier — the same
`plan_warden_verify` the Warden calls — against the policy in
`demo_policy.cfg`. Nothing is staged.

    make demo        # builds and runs varek_demo

The premise: an AI agent proposes a *plan* — a graph of actions — and
VAREK decides, before any action runs, whether the plan is safe. Every
action in every scenario below passes its own per-action policy check.
What VAREK adds is a verdict over how data flows **between** the
actions. That is the class of leak a per-action guardrail cannot see.

The verdict is three-valued: SATISFIED authorizes; UNSATISFIED and
UNKNOWN both refuse. Only SATISFIED runs.

---

## 1. A safe plan is not obstructed

    fetch_public_data → format_report → display

No sensitive data anywhere. **AUTHORIZED.** A verifier that cried wolf
on benign plans would never be deployed; the baseline matters.

## 2. The obvious leak

    read_secret → send_http

Read a secret, send it out. **REFUSED.** The evidence names the
offending action and traces the secret to its origin:

    send_http denied SECRET; originated at read_secret

## 3. The leak a per-action check misses

    read_secret → transform → enrich → send_http

This is the case that motivates the product. Every step is individually
permitted — `transform` and `enrich` are trusted internal processing
steps, `send_http` is a normal egress. No single action violates
policy. A guardrail that inspects calls one at a time sees nothing
wrong. The leak exists only in the *composition*.

**REFUSED.** And the evidence is actionable — the immediate carrier was
`enrich`, but the lineage traces the secret back to where it entered:

    send_http denied SECRET
      immediate source: enrich
      originated at:    read_secret

## 4. VAREK permits the legitimate workflow, too

    read_secret → redact → send_http

VAREK is not a blunt denier. A redactor explicitly trusted to observe a
secret *and* to cleanse it (declassification) lets the sanitized data
flow onward. **AUTHORIZED.** Sanitize-then-send — redact, hash,
aggregate, tokenize — is the central pattern in privacy-preserving
agent workflows, and it must be expressible without dropping the guard.

The trust is narrow and explicit: the redactor must be declared both
*permitted to see* the secret and *able to cleanse* it. Either alone
fails. And it is audited — the verifier records exactly which label was
dropped where.

## 5. You cannot route around the redactor

    read_secret → redact → send_http
    read_secret ───────────→ send_http     (a second, bypassing edge)

A plan that sends the raw secret straight to egress, around the
redactor. **REFUSED.** Declassification only cleanses the path that
actually passes through the redactor; the bypass edge still carries the
uncleansed secret to a denying sink.

## 6. The destination decides — argument-sensitive policy

Same action, same plan shape, different argument:

    read_secret → send_http(url = https://api.internal.acme.com/…)   AUTHORIZED
    read_secret → send_http(url = https://paste.evil.example/…)      REFUSED

Policy permits sensitive data to a trusted internal host and denies it
everywhere else. The verdict turns on the destination, matched by glob
pattern — not just the action's name.

## 7. Fail-safe on the unknown

    read_secret → mystery_plugin

A handler the policy has never classified receives a secret. VAREK does
not guess and does not default to allow. It returns **UNKNOWN**, which
suppresses. Unclassified is not the same as permitted — the safe answer
to "I don't know what this does with the secret" is to refuse.

---

## Why this is hard to fool

- The leak in #3 is invisible to per-action inspection by construction;
  it is a property of the path, decided over the whole plan at once.
- The escape hatch in #4 cannot be abused (#5): declassification is
  operator-designated, requires two explicit assertions, is audited,
  and cannot be routed around.
- The default is refusal (#7): anything the policy has not classified,
  reaching a sink with sensitive data, fails closed.

## What the verdict rests on (read before believing it)

The verifier decides over the plan the host hands it, using each
action's declared identity. Two preconditions bound the guarantee, both
documented in `THREAT_MODEL.md`:

- The action descriptors must reflect ground truth — what the operation
  actually does — not an agent's self-description. A lying descriptor
  fools classification.
- Declassification is a trusted assertion: VAREK confirms a redactor was
  *designated* to cleanse a label and audits that it ran, but cannot
  prove the redactor's code actually removes the secret.

These are stated plainly because a security claim is only as good as its
boundaries.

## Run it yourself

    make demo                    # uses demo_policy.cfg
    ./varek_demo my_policy.cfg   # against your own policy

The program exits 0 only if all scenarios behave as described, so it
doubles as a smoke test of the full stack. See `INTEGRATION.md` to wire
the same verifier into a host, and `THREAT_MODEL.md` for the trust model.
