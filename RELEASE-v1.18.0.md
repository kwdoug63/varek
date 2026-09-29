# VAREK v1.18.0 — The Claims and the Code Agree

Released 2026-09-29 · MIT · github.com/kwdoug63/varek

## Summary

A review after v1.17.0 listed ten places where the published claims (the
README, release notes, CHANGELOG, spec paper and tool output) and the code
disagreed. v1.18.0 fixes all ten: in the code where the claim was the intent,
and in the claim where the code was right.

| # | Where they disagreed | Fixed in |
|---|---|---|
| 1 | The README said every Warden decision is made by the SMT decision procedure over the action-graph | the claim |
| 2 | The data-flow check, refusal breaker and progress-safety check were described as runtime features; the Warden never called them, and `make check` skipped their tests | the code |
| 3 | The plan gate authorized connect and launch steps the runtime always refuses | the code |
| 4 | The example "internal hosts only" URL rule also matched outside hosts | the code |
| 5 | The CycloneDX attestation was mostly fixed wording; the export was unsigned and never schema-tested | the code |
| 6 | Release notes listed code that was never committed | the claims |
| 7 | Two Python suites could not run; `pytest` stopped at collection | the code |
| 8 | Figures without a measurement behind them | the claims (re-measured where possible) |
| 9 | Release notes and the cross-check tool named the outside solver product | the claims |
| 10 | Refusal records said `EPERM` while the agent received `EACCES` | the code |

It adds options and changes what the `--plan` gate authorizes, so it is a minor
release. Per-call verdicts are unchanged: the policy rules, the three-state
verdict with UNKNOWN suppressed to DENY, the certificates and the
symmetric-suppression invariant (**no extension may move a genuinely unsafe
action to SATISFIED**).

`make test-v1180` has 48 checks, plus the v1.7 layer's new test (40) and the
live filter's io_uring probe. 28 of the 48 fail against the v1.17.0 Warden.
Every earlier suite still passes.

## The plan gate runs the whole v1.7–v1.9 pipeline

Through v1.17.0 the `--plan` gate checked each declared step against the
policy and nothing else. The data-flow check (v1.7–v1.8), the refusal breaker
(v1.8.2) and the progress-safety check (v1.9) existed in `v1_7/` with their
tests, and `plan_warden_binding.h` was written as "the single entry point for
the Warden's `--plan` gate", but the Warden never called it.

`--flow-policy <cfg>` (a label policy in the v1.7 format) now adds them:

- **At startup,** the Warden runs the progress-safety check on `<cfg>` and
  refuses to start unless every refusal ends in an automated outcome. It also
  requires a `refusal_budget`: the Warden's own policy can refuse a step even
  when the flow policy cannot, so without a budget a host could resubmit a
  refused plan forever.
- **Per plan,** it runs the node check and the flow check. Steps reach the flow
  policy as actions named by their kind (`file_open`, `net_connect`,
  `process_exec`) with one argument, `target`; for a `file_open` that is the
  lexically canonical path the node check decides on, so a flow rule cannot be
  stepped around with `..`.
- **The breaker** counts each refused plan against (`--session <id>`, the
  plan's signature). The signature now covers the plan's edges as well as its
  steps (`plan_breaker_signature_graph()`); with steps alone, authorizing the
  same steps without the leaking edge cleared the leaking plan's count. After
  the policy's `refusal_budget` the outcome latches to its `on_exhaustion`
  disposition; an UNKNOWN goes straight to `unknown_disposition`.
- **The breaker's counts persist.** The Warden gates one plan per launch, so an
  in-memory breaker would forget every refusal. The counts are kept in
  `--breaker-state` (default `/var/lib/varek/breaker.state`): opened without
  following symlinks, refused unless it is a regular file owned by the Warden's
  user and writable by no one else, locked while in use, and protected from the
  agent by identity, like the signing key (v1.17.0). A state file that cannot
  be read back refuses the plan rather than starting the counts again.

Exit status: 0, the agent ran; 3, refused, the host may submit a different
plan; 4, terminal deny; 5, terminal, and the message names the pre-authorized
action the host must run. A `plan_gate` record in the verdict stream (chained,
and sealed by the next signed checkpoint) holds both axes, the breaker's
outcome and the counts; `varek_audit.py` and the exporter accept it.

Without `--flow-policy`, `--plan` behaves as before apart from the next change.

## Connect and launch steps are UNSATISFIED at the gate

The runtime refuses every connect and every launch after the agent's own,
whatever the policy says (deny-only since v1.9.1). The gate still asked the
policy about those steps, so a plan whose connect or launch the policy allowed
was authorized, and the step was then refused once the agent ran it. The gate
now decides such steps UNSATISFIED and says why. `v1_6/sample_plan.txt`, which
declared both, now declares file opens only.

## URL host matching

The v1.7.4 example rule for "internal endpoints only" was
`match url https://*.internal.acme.com/*`. In a glob, `*` matches `/`, `?`, `#`
and `@`, so it also matched `https://evil.example/x.internal.acme.com/` and
`https://evil.example#.internal.acme.com/`. A match key of the form
`<arg>.host`, `<arg>.scheme`, `<arg>.port` or `<arg>.path` now parses the named
argument strictly as an absolute URL and matches the pattern against that one
component. A URL with userinfo (`@`), a backslash in the authority, a host with
anything but letters, digits, dots and hyphens (or a bracketed IPv6 literal),
or a port outside 1–65535 matches nothing. The examples now say:

```
rule send_http
  match url.scheme https
  match url.host *.internal.acme.com
  permit_in SECRET
```

A whole-URL glob still works as before; the header and the data-flow threat
model say not to use one for hosts.

## The CycloneDX export

- **An attestation derived from the stream.** Through v1.17.0 the text
  asserted, among other things, that "no action reached the kernel without a
  verdict", which is not true of the calls the filter admits without asking the
  Warden. Every sentence is now computed from the records: the counts, the
  UNKNOWN verdicts and that each was refused, how many authorized file
  decisions name a resolved object, how many authorizations carry an accepted
  certificate, the plan gate's decision, whether the stream is chained and
  signed, and which system calls the record covers. The same facts are
  properties on the run component. If an UNKNOWN was authorized, the exporter
  refuses to attest.
- **The policy is checked.** `--policy` defaulted to the label `policy.txt`,
  whatever the run used. It now defaults to the policy path the Warden recorded,
  and a readable policy file whose SHA-256 is not the one in `run_start` is
  refused.
- **A signature.** `--sign-key <key>` signs the BOM with the Warden's log key
  (from `varek_keygen`) in the JSON Signature Format that CycloneDX 1.6 defines:
  Ed25519 over the JCS-canonical BOM, made with libsodium.
  `--verify <bom> [--pubkey <key.pub>]` checks it with the audit's own
  pure-Python Ed25519, and says whether the key is the one that signed the
  run's stream.
- **Schema-tested.** `make test-v1180` and CI validate unsigned and signed BOMs
  against the CycloneDX 1.6 schema, using the OWASP CycloneDX project's
  validator (`varek/v1_4/tools/requirements-test.txt`).

## Records name the errno the agent received

A refused call's record said `"kernel_verdict":"EPERM"`. The Warden answers a
refused mediated call with `EACCES`, and the record now says `EACCES`. `EPERM`
is what the kernel filter returns for a system call it refuses outright; those
are not recorded. The Warden's README said the same thing wrongly and is
corrected.

## The Python suites run

- `varek/v1_2/__init__.py` and `varek/v1_3/__init__.py` re-exported a language
  front end from a `varek` package that is not in this repository (the language
  is in `varek-v1.0/`), so importing the v1.2 prototype failed and `pytest`
  stopped at collection. They now hold only the version; the 38 v1.2 tests
  pass.
- The v1.1 regression suite (`tests/security/test_issue_223_regression.py`)
  imported `enforce_strict_mode`, which the v1.1 CHANGELOG said was kept by
  name and signature. It was missing, and so was the deprecated
  `KineticIntercept`. Both are restored as the CHANGELOG described
  (`enforce_strict_mode()` arms the audit hook as telemetry only), and the
  test's telemetry callback now takes the documented `(event, args)`.

A plain `pytest` from the repository root now completes: 43 passed, 1 skipped.
The skipped suite needs cgroup v2 with the memory controller and libseccomp's
Python binding. It could not run end to end on this release's test host.

## Corrections to the record

- **Code that was never committed.** The v1.9.1 notes listed
  `v1_7/warden_notify_hardening.{h,c}`; the discipline it described is
  implemented inline in `varek/v1_4/warden.c`. The v1.9.1 UNKNOWN diagnostics
  and resource bounds were specified (`docs/security/v1.9.1-verifier-notes.md`)
  and never implemented. What exists from v1.13.0 is an UNKNOWN record's `rule`
  naming its cause, and bounds by construction (a length guard, a 16-bit flag
  enumeration bound, and from v1.16.0 a 4,096-token glob cap). The v1.9.2
  notes listed `v1_7/warden_landlock.c`, and the v1.1.1 CHANGELOG listed
  `tests/security/test_warden_smoke.py`; neither exists. Each place now carries
  a dated correction, and the spec paper has a corrections note.
- **Figures.** The language test table said 109 tests for v0.1 and 659 passing.
  Running each archive gives 641 tests with 629 passing: v0.1 has 91 tests, 2
  of which fail and 1 hangs; v0.4 has 9 failures from the unfinished `syn::` to
  `var::` rename. The v1.4 Warden's P99 was given as 57 µs; the recorded run
  (`bench_results_v1_4.txt`) says 44 µs, so the v1.5 fast path is about 160
  times faster, not 210 times or "three orders of magnitude". "Zero false
  negatives" is restated as what it is: a count of 0 in one benchmark. The
  TOCTOU harness's "510 leaks in 20,000 attempts" had no record. Three new
  runs on a 2-vCPU host gave 1,848 to 1,889 leaks for approve-then-continue and
  0 for resolve-and-inject (`tests/toctou_results_v1.18.0.txt`). The harness
  had been dropping its count line when stdout was not a terminal.
- **The solver.** Prose now says "the reference SMT solver". Its Python package
  is listed in `varek/v1_4/tools/requirements-crosscheck.txt`. The name remains
  only where software must use it: the import in `smt_crosscheck.py`, that
  requirements file, and the v1.5 latency probes' C API calls and link flag.
- **io_uring under the live filter.** The spec paper said
  `v1_7/tests/test_v191_io_uring.c` checks io_uring under the Warden filter. On
  its own that test reports INCONCLUSIVE. The live filter's test,
  `test_v14_filter`, now checks that `io_uring_setup` kills the process.

## Compatibility

- **`--plan` rejects connect and launch steps.** A plan that declared them and
  was authorized before is now rejected (exit 1). Declare file opens only.
- **New exit codes with `--flow-policy`:** 3, 4 and 5 (see above). Without it,
  exit codes are unchanged.
- **Exporter:** `--policy` defaults to the recorded policy path, and a
  mismatching policy file is refused. The attestation text and the run
  component's properties changed; the BOM structure did not.
- **Records:** a refusal's `kernel_verdict` is `EACCES` (was `EPERM`); a
  `plan_gate` event may appear before the first decision record.
- **Build:** the Warden links the v1.7 layer (no new library). The schema check
  needs `pip install -r varek/v1_4/tools/requirements-test.txt`.
- No policy-file or plan-file format change.

## Known limits

- The breaker bounds resubmissions of the same action-graph. A planner that
  submits a different graph each time is counted per graph, not in total.
- The plan gate still decides file opens on the lexically canonical declared
  path, without following symlinks; every open is still mediated at runtime.
- In the Warden, flow rules see one argument per step (`target`); the plan file
  has no field for others.
- The deployment preflight does not know about `--flow-policy` or the breaker
  state file.
- The breaker state is rewritten in place. If the Warden dies during that write,
  the file will not read back, and every plan is refused until an operator
  inspects the file or removes it (which resets every count).
- The Verdict Service's plan checker (`v1_6/plan_verify_cli.c`) is unchanged.
  It remains a demonstration with a built-in policy, as its v1.16.3 notes say.

## Requirements

Unchanged from v1.17.0: Linux ≥ 5.14 (≥ 5.8 for `faccessat2`), `pidfd_getfd`
(Linux ≥ 5.6), `CAP_SYS_ADMIN` for the PID and network namespaces, libsodium,
x86_64. Tests: `tools/requirements-crosscheck.txt` and
`tools/requirements-test.txt` (Python).
