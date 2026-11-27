# OpenSSF Best Practices: VAREK's answers

VAREK holds the OpenSSF Best Practices badge at the **passing** level:
project 16965, https://www.bestpractices.dev/projects/16965 (submitted
2026-11-21). This file records the answer given for each criterion, so a
change that makes one untrue can be caught in review. The badge site is the
record of what is submitted; if the two differ, the site is right and this
file is out of date.

**Keeping it true.** If a change makes a justification below wrong (a file
moves, a CI check is dropped, a count changes), say so in the pull request:
the maintainer updates the answer on bestpractices.dev, then this file.
Section 3 of this file records how open CodeQL findings were handled, which
the `static_analysis_fixed` answer depends on.

---

## 1. Project details

| Field | Value |
|---|---|
| Name | VAREK |
| Description | Kernel-enforced, proof-checked authorization for what an AI agent's process actually does. An SMT decision procedure returns SATISFIED, UNSATISFIED or UNKNOWN; each SATISFIED carries a certificate an independent checker verifies, and anything else is refused via seccomp-BPF and seccomp user-notify. Patent-pending, MIT-licensed. |
| Project home page URL | https://varek-lang.org |
| Repository URL | https://github.com/kwdoug63/varek |
| Implementation languages | C, Go, Python, Shell |
| License | MIT |

---

## 2. Answers by section

### Basics

| ID | Status | Justification |
|---|---|---|
| description_good | Met | The README's first section, "What VAREK is", says what it does: https://github.com/kwdoug63/varek#what-varek-is |
| interact | Met | The README says how to get it, give feedback and contribute ("Installation", "Quick start", "Community": Discussions, Issues, Releases): https://github.com/kwdoug63/varek#community |
| contribution | Met | https://github.com/kwdoug63/varek/blob/main/CONTRIBUTING.md#how-to-propose-a-change: fork, branch from main, open a pull request against main; CI runs, a maintainer reviews, and the CLA is signed through CLA-Assistant. Bugs go to Issues, security reports to SECURITY.md, ideas to Discussions, and large changes to an RFC first. |
| contribution_requirements | Met | https://github.com/kwdoug63/varek/blob/main/CONTRIBUTING.md#what-a-change-needs-before-it-can-merge: builds with no warnings (-Wall -Wextra -Wpedantic; gofmt and go vet), CI and CodeQL pass, tests, the Warden kept fail-closed, records checked by the audit, documentation and a CHANGELOG line, the existing style. |
| floss_license | Met | MIT: https://github.com/kwdoug63/varek/blob/main/LICENSE |
| floss_license_osi | Met | MIT is approved by the OSI. |
| license_location | Met | https://github.com/kwdoug63/varek/blob/main/LICENSE, at the repository's root. |
| documentation_basics | Met | README "Installation", "Verify your installation" and "Quick start" (https://github.com/kwdoug63/varek#installation); RHEL 9: https://github.com/kwdoug63/varek/blob/main/docs/install/rhel9.md; development: https://github.com/kwdoug63/varek/blob/main/docs/development.md |
| documentation_interface | Met | The policy language: https://github.com/kwdoug63/varek/blob/main/varek/v1_4/README.md#policy-format (also "Plan gate", "Certificates", "Log integrity"); the command line in each release's notes (e.g. https://github.com/kwdoug63/varek/blob/main/RELEASE-v1.40.0.md); the specification: https://github.com/kwdoug63/varek/blob/main/varek-spec-paper-v1.37.0.md |
| sites_https | Met | github.com and https://varek-lang.org are served over HTTPS; images and charts come from ghcr.io over HTTPS. |
| discussion | Met | GitHub Issues and Discussions: searchable, addressable by URL, open to anyone with a GitHub account. https://github.com/kwdoug63/varek/discussions |
| english | Met | Documentation, issues and code are in English. |
| maintained | Met | Eight releases from v1.36.0 to v1.40.0 between 2026-10-31 and 2026-11-20 (https://github.com/kwdoug63/varek/releases); Dependabot updates merged weekly. |

### Change control

| ID | Status | Justification |
|---|---|---|
| repo_public | Met | https://github.com/kwdoug63/varek |
| repo_track | Met | Git records every change with its author and date. |
| repo_interim | Met | Work between releases is pushed to public branches and pull requests before it merges to main. |
| repo_distributed | Met | Git. |
| version_unique | Met | Each release has a unique version: a vX.Y.Z tag, reported by `varek version`. |
| version_semver | Met | Semantic Versioning: e.g. v1.36.3 (fixes), v1.40.0 (features). |
| version_tags | Met | Each release is a git tag with a GitHub Release: https://github.com/kwdoug63/varek/releases |
| release_notes | Met | Each release has a RELEASE-vX.Y.Z.md (e.g. https://github.com/kwdoug63/varek/blob/main/RELEASE-v1.40.0.md) and a CHANGELOG entry: https://github.com/kwdoug63/varek/blob/main/CHANGELOG.md |
| release_notes_vulns | Met | SECURITY.md commits each fixed vulnerability to a Security section in its release's notes, an advisory with a CVE, and a CHANGELOG entry: https://github.com/kwdoug63/varek/blob/main/SECURITY.md#advisories. The one fixed so far is in https://github.com/kwdoug63/varek/blob/main/VAREK_v1.1_SECURITY_UPDATE.md |

### Reporting

| ID | Status | Justification |
|---|---|---|
| report_process | Met | GitHub Issues: https://github.com/kwdoug63/varek/issues (linked from the README's "Community" section). |
| report_tracker | Met | GitHub Issues. |
| report_responses | Met | No bug reports have come from outside the project in the last 2–12 months; every report filed in that time has been answered or closed (e.g. #17, fixed and closed the same day). Reports are triaged as they arrive. |
| enhancement_responses | Met | No enhancement requests have come from outside the project in the last 2–12 months. Requests are answered in Issues or Discussions; the README's roadmap says what is planned and for which release. |
| report_archive | Met | GitHub Issues are public and searchable: https://github.com/kwdoug63/varek/issues?q=is%3Aissue |
| vulnerability_report_process | Met | https://github.com/kwdoug63/varek/blob/main/SECURITY.md, linked from the README's first lines. |
| vulnerability_report_private | Met | GitHub private vulnerability reporting (https://github.com/kwdoug63/varek/security/advisories/new) or the email address in SECURITY.md. |
| vulnerability_report_response | Met | SECURITY.md commits to acknowledging a report within 48 hours and triaging it within 7 days. No reports have been received in the last 6 months. |

### Quality

| ID | Status | Justification |
|---|---|---|
| build | Met | `make -C varek/v1_4 all` (Makefile) and `go build` for varek/v1_4/k8s. CI builds on x86_64 and aarch64 for every pull request: https://github.com/kwdoug63/varek/blob/main/.github/workflows/warden-build.yml |
| build_common_tools | Met | GNU make, gcc/clang, Go, pip. |
| build_floss_tools | Met | All build tools and libraries (libseccomp, libsodium, OpenSSL) are FLOSS. |
| test | Met | 42 `make test-*` suites, `make crosscheck`, Go unit tests and pytest suites, documented in the README's "Testing" section: https://github.com/kwdoug63/varek#testing |
| test_invocation | Met | `make check` or `make test-vXYZ` in each version directory, `go test ./...`, `pytest`; see the README's "Testing" section. |
| test_most | Met | Every release adds its own suite (`make test-v1210` … `make test-v1390`), each covering the release's grammar, decisions, records and forged streams. The matrix runs them on Ubuntu, Rocky Linux 9 and Amazon Linux 2023, on x86_64 and arm64. |
| test_continuous_integration | Met | GitHub Actions on every pull request and push: warden-build, kubernetes, matrix, matrix-vm, container, codeql (https://github.com/kwdoug63/varek/tree/main/.github/workflows). main requires these checks to pass before a merge. |
| test_policy | Met | https://github.com/kwdoug63/varek/blob/main/CONTRIBUTING.md#test-policy: "New functionality must come with tests, and a bug fix with a test that fails without the fix", and where each kind of test goes. |
| tests_are_added | Met | Each feature release added its own suite: e.g. `make test-v1270` (164 checks, v1.27.0), `make test-v1290` (316 checks, v1.29.0), `make test-v1310` (317 checks, v1.31.0); see the README's "Testing" section. |
| tests_documented_added | Met | The test policy is in the contribution instructions: https://github.com/kwdoug63/varek/blob/main/CONTRIBUTING.md#test-policy |
| warnings | Met | C is compiled with `-Wall -Wextra -Wpedantic` (varek/v1_4/Makefile, line 6); Go is checked with `go vet` and `gofmt` in CI. |
| warnings_fixed | Met | The CI build of the Warden and its tools has no compiler warnings, and CONTRIBUTING.md treats a new warning as a failure. |
| warnings_strict | Met | `-Wall -Wextra -Wpedantic`; the parser tests are also built with `-fsanitize=address,undefined -fno-sanitize-recover=all`. |

### Security

| ID | Status | Justification |
|---|---|---|
| know_secure_design | Met | The design applies the secure-design principles throughout and documents them. **Least privilege:** a default-deny seccomp-BPF filter; the agent has an empty network namespace and can run as its own user (`--run-as`); the Warden dials the connections it allows. **Fail-safe defaults:** UNKNOWN, a parse failure or an error is refused. **Complete mediation:** each covered call is decided by the SMT decision procedure before the kernel carries it out, via seccomp user-notify. **Economy of mechanism:** a small, independently written certificate checker. The threat model and trusted computing base are written down: https://github.com/kwdoug63/varek/blob/main/docs/security/threat-model.md, https://github.com/kwdoug63/varek/blob/main/docs/security/TRUSTED-COMPUTING-BASE.md |
| know_common_errors | Met | The errors common to this kind of software are named and tested. Time-of-check-to-time-of-use races: the Warden decides on the copy it made, and a race harness (tests/seccomp_toctou_harness.c) measured 0 leaks in 60,000 attempts. Path and symlink tricks, descriptor and namespace escapes. Memory errors in parsers of untrusted input: fuzzed under ASan/UBSan. Forged or altered audit records: each suite includes forged streams the audit must refuse. Each class is listed with its mitigation in https://github.com/kwdoug63/varek/blob/main/docs/security/bypass-classes.md |
| crypto_published | Met | Only published algorithms: Ed25519 (stream and node signatures), SHA-256, ECDSA P-256, RSA (PKCS#1 v1.5 and PSS) for verifying tokens, TLS 1.2+, and HMAC-SHA256 (AWS SigV4). |
| crypto_call | Met | Cryptography is done by libsodium and OpenSSL; VAREK calls them and implements no primitive itself. |
| crypto_floss | Met | libsodium and OpenSSL are FLOSS. |
| crypto_keylength | Met | Ed25519 (128-bit security), P-256, SHA-256. RSA keys under 2048 bits are refused (warden_secrets_helper.c: "the issuer's RSA key is shorter than 2048 bits"). |
| crypto_working | Met | No MD5, SHA-1, DES or RC4. JWTs with `alg: none` or HMAC are refused (warden_secrets_helper.c). |
| crypto_weaknesses | Met | As above; TLS below 1.2 is refused (SSL_CTX_set_min_proto_version(TLS1_2_VERSION) in proxy_ca.c and warden_secrets_helper.c). |
| crypto_pfs | Met | Forward secrecy is supported and preferred. TLS 1.2 is the minimum, and TLS 1.3, which is always forward secret, is negotiated where the peer has it. Toward the agent, the inspecting proxy's certificates are ECDSA P-256 (proxy_ca.c), so only ECDHE or TLS 1.3 key exchange is possible. Toward upstream servers, the proxy and warden-secrets use OpenSSL's default list, which offers ECDHE first. |
| crypto_password_storage | N/A | VAREK stores no passwords for users to authenticate with. |
| crypto_random | Met | Keys and nonces come from libsodium's randombytes_buf and getrandom(2) (warden.c, warden_node.inc.c). |
| delivery_mitm | Met | Source over HTTPS (GitHub). Images and charts come from ghcr.io over HTTPS, signed with cosign (keyless, Sigstore). GitHub Releases carry SLSA provenance (multiple.intoto.jsonl) and a signature for each file. |
| delivery_unsigned | Met | No hash is fetched over HTTP. Hashes come with their signatures (SHA256SUMS.sig, .sigstore.json) over HTTPS. |
| vulnerabilities_fixed_60_days | Met | No unpatched vulnerability of medium or higher severity has been public for more than 60 days. Dependency vulnerabilities are fixed as Dependabot reports them, and OpenSSF Scorecard's Vulnerabilities check is 10/10 (0 known vulnerabilities). |
| vulnerabilities_critical_fixed | Met | As above. |
| no_leaked_credentials | Met | No private credentials are in the repository. CI signs keyless (OIDC), with no long-lived keys. |

### Analysis

| ID | Status | Justification |
|---|---|---|
| static_analysis | Met | CodeQL (C/C++, Go, Python) runs on every push to main, every pull request and weekly (https://github.com/kwdoug63/varek/blob/main/.github/workflows/codeql.yml); `go vet` runs in CI. main requires the CodeQL checks to pass before a merge. |
| static_analysis_common_vulnerabilities | Met | CodeQL's security queries (memory safety, injection, path traversal and others). |
| static_analysis_fixed | Met | CodeQL runs on every pull request, and main requires its checks to pass before a merge. Medium and higher findings are fixed in the change that introduces them, or explained as false positives (https://github.com/kwdoug63/varek/blob/main/CONTRIBUTING.md). Open findings are tracked in code scanning and fixed or dismissed with a reason. |
| static_analysis_often | Met | On every push and pull request, and weekly. |
| dynamic_analysis | Met | Fuzzing in CI: the proxy's TLS and HTTP parsers with 2 million generated inputs (`make fuzz-proxy-parse`, with a libFuzzer target), and the MCP JSON parser with 1 million mutated inputs (`make test-mcp-json`); a TOCTOU race harness; 24-hour soak runs before releases. |
| dynamic_analysis_unsafe | Met | The C parsers' tests and fuzzing run under AddressSanitizer and UndefinedBehaviorSanitizer (`-fsanitize=address,undefined -fno-sanitize-recover=all`, varek/v1_4/Makefile). |
| dynamic_analysis_enable_assertions | Met | Sanitizer builds abort on the first error (`-fno-sanitize-recover=all`). |
| dynamic_analysis_fixed | Met | CI fails on any sanitizer or fuzzer finding, so a pull request with one does not merge. |

---

## 3. CodeQL findings: triage of 2026-11-21

The `static_analysis_fixed` answer says open findings are fixed or dismissed
with a reason. These are the findings open when the badge was submitted, and
what was done with each. Line numbers are those on `main` at the time.

### Fixed (#216)

| Alert | Rule | Where | Fix |
|---|---|---|---|
| #43, #44 | Potentially overflowing call to snprintf | `varek/v1_4/proxy_ca.c` (the name-constraints buffer) | Each constraint is appended within the buffer's bounds, and one that does not fit refuses the CA; tested by `make test-proxy-ca` (`varek/v1_4/tests/proxy_ca_test.c`) under ASan and UBSan. |
| #48 | Use of insecure SSL/TLS version | `varek/v1_4/tools/bench_mcp_client.py:75` | `ctx.minimum_version = ssl.TLSVersion.TLSv1_2` |
| #49 | Use of insecure SSL/TLS version | `varek/v1_4/tools/bench_proxy_client.py:71` | `ctx.minimum_version = ssl.TLSVersion.TLSv1_2` |

### Dismissed: false positive

| Alert | Rule | Where | Reason |
|---|---|---|---|
| #42 | Failure to use HTTPS URLs | `varek/v1_4/warden_secrets_helper.c:1029` | The AWS instance metadata service (IMDSv2) at 169.254.169.254, which AWS serves only over plain HTTP on a link-local address. `http_do` refuses plain HTTP to any other non-loopback host (tested in `test_v1280.sh`). All other connections are TLS 1.2+. |
| #46 | Binding a socket to all network interfaces | `varek/v1_4/tools/varek_bench_mcp.py:97` | The bench server binds to `host_address()`, the host's own outbound IPv4 address, which raises rather than return "", 0.0.0.0 or a loopback address. |
| #47 | Binding a socket to all network interfaces | `varek/v1_4/tools/varek_bench_proxy.py:257` | As #46. |

### Dismissed: used in tests

| Alert | Rule | Where | Reason |
|---|---|---|---|
| #45 | Clear-text storage of sensitive information | `varek/v1_4/tests/v1280_stores.py:243` | A test stand-in for AWS Secrets Manager logs a request's access-key ID (a made-up test constant) so the suite can check which identity signed. No real credential. |
| #50 to #65 | Use of insecure SSL/TLS version | `varek/v1_4/tests/*.py`, `varek/v1_4/tests/soak_*/*.py` | Test and soak stand-ins (local servers or the suites' clients), using `ssl.SSLContext(PROTOCOL_TLS_SERVER)` or `ssl.create_default_context()`, whose minimum is TLS 1.2. Not shipped. |

Later findings are handled the same way: fixed in the change that brings
them, or dismissed in code scanning with the reason written on the alert.
