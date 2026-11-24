# VAREK v1.41.0 — VAREK Implements No Cryptography of Its Own

Every hash, signature, key and random byte the Warden and its tools use is now the host's OpenSSL 3, through one backend (`varek/v1_4/varek_fips.c`). libsodium is gone, and so is VAREK's own SHA-256 and Ed25519 code.

On a host in FIPS mode, the backend uses the FIPS provider. The new **Defense build** (`make DEFENSE=1`) goes further:
- it refuses to start unless the host is in FIPS mode and its FIPS 140-3 validated module handles every hash and signature;
- it leaves TLS-inspecting mode out entirely.

This is the statement the release is for: *"VAREK implements no cryptography of its own; all hashing and signing go through the host's FIPS 140-3 validated module."* Its scope is in `docs/security/v1.41-cryptography.md`, which lists every cryptographic call VAREK makes, its file and its library.

The release also:
- moves the sector packs to `require warden 1.29`;
- adds an export to CrowdStrike Falcon Next-Gen SIEM, tested against a stand-in.

CrowdStrike Falcon Foundry and Wiz, still waiting on their partner programs' tenants, move to v1.44.0. v1.42.0 is planned for the human-approval (STEP UP) and deferral (DEFER) decisions of the AARM specification, and v1.43.0 for Google Security Operations. The policy grammar stays 1.35.

> Not reviewed by a human or a third party, or by a separate review pass: the changes were tested as below.

MIT · github.com/kwdoug63/varek

## Summary

- **One crypto backend, OpenSSL 3** (#235). Every hash, signature, key and random byte goes through `varek_fips.c`, which uses OpenSSL's EVP interface with the library's default properties. Where it used to be done:

  | Was | Now |
  |---|---|
  | libsodium: the Warden's SHA-256 chain, Ed25519 signatures, random bytes, guarded memory | OpenSSL |
  | The certificate checker's own SHA-256 (the policy digest) | OpenSSL; the digest is unchanged |
  | The audit's pure-Python Ed25519 | Python's `cryptography` package, on the same OpenSSL |
  | `varek_cyclonedx.py`'s signing through libsodium (`ctypes`) | Python's `cryptography` package |

  The audit keeps v1.16's strictness checks in front of OpenSSL: canonical encodings, S < L, and no small-order key. OpenSSL alone accepted 506 of 4,096 small-order forgeries.
- **The verdict stream is format chain-2.**
  - **Chain and signatures:** a SHA-384 chain, with `run_start`, checkpoints and `run_end` signed with **ECDSA P-384**, a CNSA-aligned algorithm.
  - **`run_start` records:** `"log":"chain-2"`, `"sigalg":"ecdsa-p384-sha384"`, and `crypto_provider` (`fips` or `default`), inside the signed record.
  - **CycloneDX evidence** is signed with JSF **ES384**.
- **Old logs stay verifiable.**
  - **What still verifies:** chain-1 streams (SHA-256, Ed25519, from v1.16 to v1.40), their anchors and their Ed25519 evidence. `tests/v140_fixture` holds genuine v1.40.0 output, without its private key, as the check.
  - **Downgrades are refused:** a stream rewritten into chain-1 under a 1.41 Warden.
  - **On a FIPS-mode host:** Ed25519 isn't offered there, so the audit says such a log *cannot be checked here*, never that it's forged.
- **Signing keys are ECDSA P-384.**
  - **Format:** PKCS#8 PEM, with public keys written as the uncompressed point (194 hex characters) on every OpenSSL.
  - **Where:** `tools/varek_keygen` makes them, for `--sign-key` and the node agent's `--node-key`.
  - **Accepted by:** the VarekNodeKey CRD, the admission check, the anchor forwarder and the receiver, which take both forms.
  - **Checked by:** the deployment preflight, which checks the key's curve and that its `.pub` is its public half.
- **The Defense build, `make DEFENSE=1`** (#235). It uses two switches fixed at build time:
  - **Fail closed.** The Warden, `warden-secrets` and `varek_keygen` refuse to start unless the host is in FIPS mode and the FIPS provider handles SHA-384 and ECDSA. Off FIPS mode, the Warden won't even lint a policy.

    Red Hat's FIPS provider loads off FIPS mode too, but it is the validated module only on a host in FIPS mode. CI's Rocky Linux 9 cell found the Defense Warden starting there before this check was added.
  - **No TLS inspection.** Inspecting mode is compiled out, so the Defense egress proxy links no library but libc. A policy that needs inspection is refused at load: `proxy inspect`, request rules, MCP tool-call rules, credential release and passthrough hosts.

  `varek_audit.py --require-fips` fails a run whose signed `run_start` doesn't say `crypto_provider: fips`. `make fips-acceptance` runs the Defense build's acceptance on RHEL 9 in FIPS mode and keeps the evidence.
- **The user's token may be signed RS384, PS384 or ES384** (#237), as an identity provider limited to the CNSA algorithms signs it. RS256, PS256, ES256 and EdDSA are still accepted.
  - **Curve matching:** ES384 is checked against a P-384 key only, and ES256 against a P-256 key only. A key on the other curve is passed over, the same way a key of another type is.
  - **Run ID:** it now comes from the provider's random generator, which is the FIPS module's in FIPS mode.
- **Fixes in the move** (#235):
  - **FIPS bypass:** the launch set's SHA-256 fetched with `"provider=default"`, which in FIPS mode would have bypassed the module.
  - **Unchecked results:** `warden-secrets` ignored the result of a digest and an HMAC.
- **The sector packs say `require warden 1.29`** (#219, #220).
  - **Files are opened as the agent's own user,** so the kernel's permissions apply on top of the policy.
  - **Changes by name are decided as writes.** Remove, rename, make a directory, change a mode or a time, and truncate are each decided as a write on every name they touch, then carried out as the agent. Before, each was refused.
  - **Legacy calls:** the legacy `stat(2)` and `lstat(2)` are decided like a read-only open.
  - **Python in `/usr/local`:** it starts with no refusal, as does python-build-standalone (which uv installs).
  - **Diagnosis:** `varek doctor` and `varek run` name each writable directory the agent's user can't write, and say how to fix it.
- **CrowdStrike Falcon Next-Gen SIEM export, against a stand-in** (#215). `varek export --format falcon` sends a run's OCSF events, audited first, to a Next-Gen SIEM HTTP Event Collector data connector.
  - **What's sent:** sourcetype `varek:ocsf`, with the whole OCSF event in each.
  - **Live and resumed:** `--follow` sends a live run's events, and `--from-position` resumes a failed export.
  - **The API key** comes from the environment (`FALCON_HEC_API_KEY`), never the command line.

  It is checked against CrowdStrike's documentation, but not yet tested in a Falcon tenant.
- **Microsoft Sentinel** (#222, #223):
  - **A managed identity, tested live:** no role gave HTTP 403. With *Monitoring Metrics Publisher* on the one rule, every row arrived and the incident was raised.
  - **One alert per row:** each analytics rule now judges only the rows that arrived in its own 5-minute window, so a row raises one alert, not up to three. Deploy `sentinel-content.json` again to get the change.
- **Project:**
  - the OpenSSF Best Practices badge, passing, with the answers kept in `docs/security/openssf-best-practices.md` (#216, #232);
  - the test scripts' installs pinned by hash (#232);
  - a CodeQL finding fixed: the run CA's name constraints are assembled with each length checked (#216);
  - the threat model and trusted computing base brought up to date (#224);
  - the OpenSSF badge in the spec paper (#231);
  - a test race fixed (#218);
  - the bench's policies at `require warden 1.29` (#217);
  - `funding.json`'s wording corrected (#214).

### What changes for a user

| | Before | v1.41.0 |
|---|---|---|
| The verdict stream | chain-1: SHA-256, Ed25519 | chain-2: SHA-384, ECDSA P-384, recording its crypto provider |
| Signing keys | Ed25519 | ECDSA P-384 (PKCS#8 PEM) |
| CycloneDX evidence's signature | JSF Ed25519 | JSF ES384 (Ed25519 still verifies) |
| Build packages | libsodium (from EPEL on RHEL) | none beyond OpenSSL; no EPEL |
| Runtime packages | `python3` | also `python3-cryptography`, which the audit verifies with |
| `make DEFENSE=1` | — | the Defense build |
| `varek_audit.py --require-fips` | — | new |
| The user's token | RS256, PS256, ES256, EdDSA | also RS384, PS384, ES384 |
| `varek export --format` | … `sentinel` | also `falcon` |
| The sector packs | `require warden 1.27` | `require warden 1.29`: files opened as the agent |

**Upgrading:**
- **Run `sudo varek init` on a v1.40 host.** It replaces the Ed25519 key and keeps its public half as `log.key.v140.pub`, which `varek audit` and `varek export` use for the runs that key signed. The settings and the policy stay as they are. Until then, `varek run` refuses and `varek doctor` names the key.
- **A node agent's v1.40 key is refused,** with a message saying to remove it. A new key is made, and its VarekNodeKey changes.
- **Install `python3-cryptography`** where the audit runs (`varek audit`, and the check `varek export` runs first). The images and the RHEL 9 guide include it.
- **EPEL and libsodium are no longer needed;** you may remove them.
- **Each directory a pack lets the agent write must be writable by the agent's user** (`nobody` unless told otherwise). `varek doctor` says which aren't, and how to fix each.
- **Sentinel rules deployed before #223:** deploy `sentinel-content.json` again.

## Tested

- **CI** on every PR (#214 to #238), x86-64 and arm64. Each runs every job its files trigger, including:
  - the Warden build's suites (the v1.41 suite `test-v1410` among them);
  - the container image's sweep;
  - the node agent's suites;
  - the 24-hour harness's six-minute trial;
  - the CRI-O and containerd cells.

  The Rocky Linux 9 and Amazon Linux 2023 host suites run when C code, the charts or packaging change. They ran on #235 and #237, and they run on this release's PR.
- **Unit tests** (`make test-cli`): 253 passed, 1 skipped, including:
  - `tests/test_varek_v140_logs.py`, on genuine v1.40.0 output;
  - `tests/test_varek_falcon.py`, against a stand-in.
- **On a Linux 6.18 VM, not in FIPS mode,** with libsodium removed from the machine:
  - the core and Defense builds without a warning;
  - the Defense Warden and `varek_keygen` refusing to start;
  - every `make test-v*` suite from v1.12 to v1.35, plus v1.41.
- **RHEL 9.8 in FIPS mode, `sudo make fips-acceptance`: RESULT: PASS** at `8ea03ad`, the commit that changed the Defense check (November 22, 2026; it also passed at `bbd90b5`).
  - **Host:** a fresh EC2 t3.medium, kernel 5.14.0-687.45.1.el9_8, with FIPS mode enabled after installation.
  - **Module:** openssl-libs 3.5.9-1.el9_9, with openssl-fips-provider 3.0.7-11.el9_8 active (3.0.7-cda111b5812c30d4).
  - **What passed:**
    - the Defense build, without a warning, linking no libsodium, and with a proxy that links no crypto library;
    - `test_v1410`, 22 checks;
    - a Defense run audited with `--require-fips`;
    - `test_v1160`, 58 checks, with the Defense binaries; `run_start` says `crypto_provider: fips`;
    - `test_v1161`;
    - the audit's own crypto in FIPS mode: MD5 refused, ECDSA P-384 verifying RFC 6979's vector, and a v1.40 log reported as not checkable there.
  - **Evidence:** SHA-256 `0c9453c55e7d2b459ac589bd7b794c26dcacf9c4963d930c419ce91254d13de8`.
- **RHEL 9.8 not in FIPS mode,** with Red Hat's FIPS provider installed: `test_v1410` passed. The Defense build refused at start, refused to supervise or lint, and `varek_keygen` made no key.
- **The 24-hour soak on the release's code:** the shared soak, the packs and the export, and the Defense build's pack loop in FIPS mode. *Results to be added when it ends.*

## Known limits

- **What the FIPS statement covers** (`docs/security/v1.41-cryptography.md`, section 4):
  - **The Kubernetes components** (Go, built with `CGO_ENABLED=0`) use Go's own cryptography, not the host's module. They're outside the Defense build's statement until they're built with Red Hat's Go toolset or `GOFIPS140`, which is a decision still to be made.
  - **The Python audit tools** use the host's OpenSSL, but they run wherever an auditor runs them, in FIPS mode or not.
- **Verification is no longer independent of signing.** Through v1.40, the audit checked libsodium's Ed25519 with its own Python code. Now the Warden signs and the audit verifies with OpenSSL, as FIPS requires of both. The hash chain and the external anchor are unchanged.
- **EdDSA in FIPS mode:** Red Hat's FIPS provider offers no Ed25519. So in FIPS mode, `warden-secrets` refuses EdDSA-signed tokens, and v1.40 logs are checked on a host not in FIPS mode.
- **The Defense build leaves out inspecting mode,** and with it request rules, MCP tool-call rules, credential release and passthrough hosts. Bringing it back on the FIPS provider is a question for counsel.
- **Acceptance so far:** only on RHEL 9.8 on EC2, with FIPS mode enabled after installation rather than at install time.
- **Falcon:** tested against a stand-in only. Falcon Foundry and Wiz are v1.44.0.
- **From v1.40.0, unchanged:** the Sentinel and pack limits in `RELEASE-v1.40.0.md`.
