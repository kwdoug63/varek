# Contributing to VAREK

Thank you for helping. This file says how to propose a change, what a change
needs before it can merge, and how VAREK is tested.

## Where to start

- **A bug:** open an issue at https://github.com/kwdoug63/varek/issues. Say
  what happened, what you expected, and how to reproduce it. Include the
  output of `varek version` and where it ran (distribution and kernel,
  container runtime, or Kubernetes distribution).
- **A security problem:** do not open an issue. Report it privately, as
  [SECURITY.md](./SECURITY.md) says.
- **A question or an idea:** start a discussion at
  https://github.com/kwdoug63/varek/discussions.
- **A large change** (a new policy rule, a new kind of call decided, a change
  to the stream's format or to what the Warden refuses): open a discussion or
  an RFC ([`docs/RFC_TEMPLATE.md`](./docs/RFC_TEMPLATE.md)) before writing the
  code, so the design can be agreed first.

## How to propose a change

1. Fork the repository and create a branch from `main`.
2. Make the change, with its tests and documentation (below).
3. Run the checks for what you changed (below) and make sure they pass.
4. Open a pull request against `main`. Say what the change does, why, and how
   you tested it, and link the issue or discussion it addresses.
5. Sign the CLA if the bot asks (below).
6. CI runs on every pull request. A change merges when CI passes and a
   maintainer has reviewed it.

## What a change needs before it can merge

- **It builds with no warnings.** The C code is compiled with `-Wall -Wextra
  -Wpedantic` (`varek/v1_4/Makefile`); a new warning is a failure. Go code is
  formatted with `gofmt` and passes `go vet`.
- **CI passes:** every workflow that runs on the pull request, including
  CodeQL. A CodeQL finding is fixed in the change, or, if it is a false
  positive, explained in the pull request.
- **It has tests** (see the test policy below).
- **It keeps the Warden fail-closed.** A call the policy does not cover, a
  verdict of UNKNOWN, an input that does not parse, and any error while
  deciding are refused, never allowed. A change that adds a way for a call to
  take effect without a decision will not be accepted.
- **Its records are checked.** A change to what the Warden records also
  changes `varek audit`, so the audit accepts the new records and refuses
  forged or altered ones.
- **It is documented.** A change users can see (a policy rule, a command, an
  option, a record) updates the README or the document that describes it, and
  adds a line under `## [Unreleased]` in [`CHANGELOG.md`](./CHANGELOG.md).
- **It matches the code around it:** the same style, naming and comments, and
  no unrelated changes in the same pull request.
- **Each commit's author has signed the CLA.** A `Co-authored-by:` trailer
  needs its co-author to sign it too.

## Test policy

**New functionality must come with tests, and a bug fix with a test that fails
without the fix.** Each change to the Warden or its tools adds checks to the
suite for its version, or a new suite:

- **The Warden and its tools** (`varek/v1_4`): each release's suite is
  `tests/test_vXYZ.sh`, run by `make test-vXYZ` (for example `make
  test-v1310`), and added as a step in `.github/workflows/warden-build.yml`.
  A suite covers the change's grammar (the policy lines it accepts and those
  it refuses), its decisions (calls allowed, refused and left UNKNOWN, with
  real programs where they apply), its records, and forged streams the audit
  must refuse.
- **Parsers of untrusted input** (C): tests under
  `-fsanitize=address,undefined`, and fuzzing where the parser takes input an
  agent controls (as `make fuzz-proxy-parse` and `make test-mcp-json` do).
- **The SMT decision procedure:** a rule it decides is cross-checked against
  the reference solver (`make crosscheck`;
  `tools/requirements-crosscheck.txt`).
- **Go** (`varek/v1_4/k8s`): unit tests with `go test ./...`.
- **Python** (the CLI, adapters and tools): pytest.
- **The v1.6 and v1.7 layers:** `make -C v1_6 check` and `make -C v1_7 check`.

To run the checks locally, see README "Testing" and
[`docs/development.md`](./docs/development.md). The Warden's suites need
Linux, and many need root (`sudo make -C varek/v1_4 test-vXYZ`).

## Writing about VAREK

In code comments, documents and release notes:

- Verdicts are written in capitals: SATISFIED, UNSATISFIED, UNKNOWN.
- The kernel mechanism is "seccomp-BPF and seccomp user-notify" (not eBPF).
- The decider is "the SMT decision procedure"; the solver it is checked
  against is not named in product text.
- A limit is stated as a limit, with the release that will address it if one
  is planned. A figure has a record behind it (a test, a log, a measurement).

## Contributor License Agreement (CLA)

To protect the VAREK ecosystem and our users, we require all contributors to sign a Contributor License Agreement (CLA) before we can merge any Pull Requests. 

This agreement ensures that you have the right to submit your code and that Sober Agentic Infrastructure, Inc. has the right to distribute it under the MIT license.

**How it works:**
1. Open a Pull Request.
2. Our CLA-Assistant bot will automatically comment on your PR.
3. If you haven't signed the CLA yet, the bot will provide a link.
4. Click the link, sign in with GitHub, and agree to the terms.
5. The bot will automatically update the PR status to green!
