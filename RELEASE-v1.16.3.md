# VAREK v1.16.3 — Verdict Service Plan Checker

Released 2026-09-29 · MIT · github.com/kwdoug63/varek

## Summary

The VAREK Verdict Service (`api.varek-lang.org`) answers each request by
running `plan_verify`: a small program that reads a plan file, runs the v1.6
compositional evaluator, and prints one JSON verdict. Until now its source,
`plan_verify_cli.c`, existed only on the service host.

v1.16.3 puts it in the repository and fixes how it writes its output. How
verdicts are decided does not change, and the Warden changes only in the
version it writes into `run_start`.

- **`v1_6/plan_verify_cli.c`**, built with `make -C v1_6 plan_verify`.
- **Escaped output.** Every label, kind, target and parse error is written as
  a proper JSON string.
- **The version label** in each verdict now reads `1.16.3` (it said `1.9.2`,
  the release it was first built from).
- **Exit status 3** when the output cannot be written in full (it exited 0).
- **A test** (`make -C v1_6 check-plan-verify`, 24 checks), a comparison
  harness (`tests/compare_plan_verify.py`), and a CI step that builds it and
  runs it with the v1.6 unit tests.

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
authorized**, although the evaluator decided UNSATISFIED. The same worked
through the action's kind. A backslash, a control character (other than DEL)
or invalid UTF-8 in a target made the output invalid JSON instead.

Now every string is escaped, and invalid UTF-8 becomes U+FFFD. The same plan
gives UNSATISFIED, not authorized, with the whole text kept as the target.

**How much this mattered.** The Verdict Service is a demonstration endpoint.
Its `demo:SAT:` override already lets whoever writes the plan assert a
verdict, by design, so on that endpoint the bug gave nothing the override did
not. It is fixed because it made the output untrustworthy for any other use,
and because the source is now public.

## Compatibility

Apart from the version label, the output and exit status are unchanged for
every plan without quotes, backslashes, control characters or invalid UTF-8,
as long as the output can be written. `tests/compare_plan_verify.py OLD NEW`
checks this on random plans; on 3,000 plans the old and new programs agreed
in every case. The independent review repeated this on 23,000 plans,
including random bytes, with the same result for exit status and for
everything before the escaped fields.

The test was also run against the old program, with its version label
patched so only real differences show: the eight escaping checks and the
write-failure check fail, and the other fifteen pass.

## Known limitations (unchanged)

These are properties of the demonstration policy and the v1.6 plan parser,
not of this release. None of them can make the output misreport what the
evaluator decided.

- **The policy matches text, not resolved paths or hosts.** `/work/../etc/x`
  counts as under `/work/`. Any target *containing* `allowed.internal`
  (ignoring case) counts as allowed. The `demo:` prefix ignores case.
- **NUL bytes.** A NUL in a line makes the parser reject it as too long,
  except on a last line with no newline, where the text after the NUL is
  ignored. A line that begins with a NUL is skipped; if it is over 1,023
  bytes, its remainder is read as a new line.
- **Labels are at most 63 characters.** The parser rejects a 64-character
  label, although its header comment says 64.
- **Long file paths shorten parse errors.** Error text is limited to 256
  bytes, so a very long path can crowd out the line number and reason.

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
  `v1_6/tests/test_plan_verify.sh`; `v1_6/tests/compare_plan_verify.py`; a
  CI step; a `plan_verify` section in `v1_6/README.md`.
- **Fixed:** JSON escaping in `plan_verify`, as above; a failed write to
  stdout now exits 3 (it exited 0).
- **Changed:** `plan_verify` reports version 1.16.3; `run_start` reads
  `"warden":"1.16.3"`; the CycloneDX export's VAREK version is 1.16.3.

## Testing

`make -C v1_6 check-plan-verify` (24 checks):

- **Verdicts:** allowed file and host give SATISFIED; a file outside the
  workspace and other egress give UNSATISFIED; `process_exec` and unknown kinds
  give UNKNOWN; the `demo:` override; `sample_plan.txt`.
- **Plan text cannot change the verdict fields:** a target or a kind that
  closes the object; a trailing backslash; control characters; valid UTF-8
  including a 4-byte character and U+2028; invalid UTF-8 including overlong
  forms, code points above U+10FFFF and a sequence cut off at the end.
- **No verdict:** missing field, extra field, invalid label, unknown edge
  label, missing file, and a file path containing a quote and a backslash
  all give `parse_failed` with exit 2; no argument gives a usage error on
  stderr; a failed write to stdout gives exit 3.

Every output must be exactly one line of valid UTF-8 holding one JSON object
with no repeated keys. The test passes under dash, bash and `bash --posix`.

**Independent review.** It found no way to break the output:

- it checked the UTF-8 validator against a reference decoder on 284 million
  byte sequences;
- it fuzzed 23,000 plans against the old program, including random bytes and
  a sanitizer build.

It found these, all fixed:

- one check passed only when `sh` was dash;
- a failed write still exited 0;
- the notes were imprecise in places;
- the demo policy was described as tighter than it is.

Earlier suites pass: `make -C v1_6 check` and the Warden's suites.

## Requirements

A C11 compiler. The test needs python3.
