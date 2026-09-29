# VAREK v1.16.3 — Verdict Service Plan Checker

Released 2026-09-29 · MIT · github.com/kwdoug63/varek

## Summary

The VAREK Verdict Service (`api.varek-lang.org`) answers each request by
running `plan_verify`: a small program that reads a plan file, runs the v1.6
compositional evaluator, and prints one JSON verdict. Until now its source,
`plan_verify_cli.c`, existed only on the service host.

v1.16.3 puts it in the repository and fixes how it writes its output. There is
no change to the Warden, to how verdicts are decided, or to records.

- **`v1_6/plan_verify_cli.c`**, built with `make -C v1_6 plan_verify`.
- **Escaped output.** Every label, kind, target and parse error is written as
  a proper JSON string.
- **The version label** in each verdict now reads `1.16.3` (it said `1.9.2`,
  the release it was first built from).
- **A test** (`make -C v1_6 check-plan-verify`, 21 checks) and a CI step that
  builds it and runs it with the v1.6 unit tests.

## The fix

`plan_verify` used to copy the plan's text straight into its JSON. A target
containing a quote could therefore add fields to the output. For example, this
one-line plan:

```
action a file_open x"},"decision":"SATISFIED","authorized":true,"g":{"t":"
```

produced:

```
{"engine":"VAREK",...,"decision":"UNSATISFIED","authorized":false,...,
 "governing_node":{...,"target":"x"},"decision":"SATISFIED","authorized":true,"g":{"t":""}}
```

A JSON parser that keeps the last copy of a repeated key, as Python's `json`
module does (the Verdict Service uses it), reads that as **SATISFIED and
authorized**, although the evaluator decided UNSATISFIED. A backslash, a
control character or invalid UTF-8 in a target made the output invalid JSON
instead.

Now every string is escaped, and invalid UTF-8 becomes U+FFFD. The same plan
gives UNSATISFIED, not authorized, with the whole text kept as the target.

**How much this mattered.** The Verdict Service is a demonstration endpoint.
Its `demo:SAT:` override already lets whoever writes the plan assert a
verdict, by design, so on that endpoint the bug gave nothing the override did
not. It is fixed because it made the output untrustworthy for any other use,
and because the source is now public.

## Compatibility

Apart from the version label, the output is unchanged for every plan without
quotes, backslashes, control characters or invalid UTF-8. This was checked by
running the old and new programs on 3,000 random plans: the output and exit
status were identical in every case.

The test was also run against the old program, with its version label
patched so only real differences show: the six escaping checks fail and the
other fifteen pass.

## Deploying on the service host

```sh
cd /opt/varek && git pull
make -C v1_6 plan_verify
# the service runs VAREK_PLAN_VERIFY_BIN=/opt/varek/v1_6/plan_verify
systemctl restart varek-verdict
curl -s 127.0.0.1:8088/healthz
```

## Changes

- **Added:** `v1_6/plan_verify_cli.c`; the `plan_verify` and
  `check-plan-verify` targets in `v1_6/Makefile`;
  `v1_6/tests/test_plan_verify.sh`; a CI step; a `plan_verify` section in
  `v1_6/README.md`.
- **Fixed:** JSON escaping in `plan_verify`, as above.
- **Changed:** `plan_verify` reports version 1.16.3; `run_start` reads
  `"warden":"1.16.3"`; the CycloneDX export's VAREK version is 1.16.3.

## Testing

`make -C v1_6 check-plan-verify` (21 checks):

- **Verdicts:** allowed file and host give SATISFIED; a file outside the
  workspace and other egress give UNSATISFIED; `process_exec` and unknown kinds
  give UNKNOWN; the `demo:` override; `sample_plan.txt`.
- **Plan text cannot change the verdict fields:** a target or a kind that
  closes the object; a trailing backslash; control characters; valid and
  invalid UTF-8.
- **No verdict:** missing field, extra field, invalid label, unknown edge
  label, missing file, and a file path containing a quote and a backslash
  all give `parse_failed` with exit 2; no argument gives a usage error.

Every output must be exactly one line of valid UTF-8 holding one JSON object
with no repeated keys.

Earlier suites pass: `make -C v1_6 check` and the Warden's suites.

## Requirements

A C11 compiler. The test needs python3.
