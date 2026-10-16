# VAREK v1.28.1 — Who Each Decision Was For

> The review was done by AI review agents; a human or third-party review
> has not been done.

Released 2026-10-15 · MIT · github.com/kwdoug63/varek

## Summary

Through v1.28.0 a verdict said what the agent did and which rule decided it,
but not on whose behalf. An agent acts for a user; it may start other agents
(sub-agents) that act for it; an auditor asking "who did this, for whom" had
the process id and nothing else.

From v1.28.1 every decision record says whom it was for: the user a trusted
identity provider vouched for, the agent, and the chain of sub-agents that
made the call. The user and the agent are verified at the start; each
sub-agent is held in a control group of its own from its launch, so its
calls, and those of everything it starts, are attributed to it whatever it
says about itself. Decisions do not depend on the chain (D6): this release
records and audits it.

1. **The policy.** After `require warden 1.28`:

   ```
   trust issuer https://login.example.com audience varek-agent
   trust spiffe example.org bundle /etc/varek/spiffe/example.org.pem
   require on-behalf-of
   allow exec /opt/agents/coder.py subagent=coder
   ```

   `trust issuer URL audience AUD [jwks URL]` names an issuer whose tokens
   the run accepts for the user (at most 8); `trust spiffe DOMAIN bundle
   PATH` a SPIFFE trust domain and its bundle; `require on-behalf-of` refuses
   a run with no verified user; `subagent=NAME` on an `allow exec` rule makes
   the program it launches a sub-agent. All three parsers (the SMT decision
   procedure, the certificate checker and the cross-check's oracle) read
   them alike. A v1.28.0 Warden refuses them (the grammar stays 1.28).
2. **The user: `--on-behalf-of FILE`.** A root-owned file holding one JWT,
   possibly from an OAuth 2.0 token exchange. `warden-secrets` (v1.28.0's
   helper, a sealed and hashed binary running as its own user) reads it as
   root, fetches the issuer's keys over verified HTTPS (its discovery
   document, or the policy's `jwks` URL), and checks:
   - the signature: RS256, PS256, ES256 or EdDSA; `none` and every HMAC
     algorithm refused, by name, before any key is fetched; keys a token
     carries or points to are never used;
   - the issuer, one the policy trusts; the audience, holding the policy's;
     the expiry at least 60 s ahead; `nbf` and `iat`;
   - an `act` claim as the actors of a delegation (RFC 8693), at most 8 deep.

   Only the verified claims reach the Warden; the token never leaves the
   helper, which wipes it.
3. **The agent: `--agent-svid FILE`.** An X.509-SVID and its key, checked
   against the bundle of its trust domain: one SPIFFE ID, a leaf that is not
   a CA, the chain, the key. Every bundle the policy trusts must be out of
   the agent's reach for writing.
4. **Sub-agents.** The Warden makes a control group (cgroup v2) for the run
   and one for each sub-agent at its launch (`NAME-<n>`, nested under its
   launcher's), and moves the launching process there before the launch is
   answered. Every call is attributed by its process's group, read through
   a pidfd where the kernel gives a cgroup id (Linux 6.13), from `/proc`
   otherwise. A launch counts only once the kernel's process events say it
   happened; a failed one is moved back to its launcher. Only a
   single-threaded process may launch a sub-agent. The agent cannot leave
   its group: it runs unprivileged, the Warden opens no control-group file
   for writing on its behalf, and a policy that lets it write one is
   refused.
5. **The token's expiry.** When the user's token expires during the run,
   the Warden records `on_behalf_of_expired` and revokes the run as `varek
   revoke` does (v1.28.0); `--on-behalf-of-expiry record` records it and
   lets the run go on.
6. **Records, audit and tools.**
   - `run_start` gains `on_behalf_of` (the user: issuer, subject, audience,
     expiry, `jti`, the token's SHA-256; the actors; the agent: the run,
     its SPIFFE ID and the SVID's SHA-256, its control group) and
     `operator` (the uid and login that started the run, as the host says:
     not verified). Every decision record gains `obo`: `["user", "agent",
     "subagent:coder#1"]`. A sub-agent's launch record names it and its
     group; `subagent_settled` says how each launch came out.
   - `varek_audit.py` checks the chain against the policy and every
     record's `obo` against the launches that started each sub-agent, and
     the expiry.
   - `varek runs` shows whom each run was for; `varek refusals` names the
     sub-agent that got each refusal and filters with `--subagent` and
     `--user`; `varek policy show` lists the issuers, trust domains and
     sub-agents; `varek doctor` checks cgroup v2 and fetches each issuer's
     keys; the CycloneDX export carries `varek:on_behalf_of.*`.
   - `varek bench --subagents` measures attribution's cost.

   The Warden reports `1.28.1`.

## Tested

`make test-v1281` runs 208 checks; CI runs it as root:

- **The grammar** (section 1, 48 checks): each form and each refusal in
  the decision procedure and the certificate checker, which must agree;
  lint; the version.
- **Verifying** (2, 84): a stand-in identity provider and SPIFFE authority
  (discovery and keys over HTTPS with a CA made for the test; tokens and
  SVIDs signed with Python's `cryptography`, apart from the C verifier):
  each algorithm verified; each check failing on its own (a signature by
  another key, `none`, an HMAC token signed with the public key, an
  unknown key id, the issuer, the audience, expired, under 60 s left,
  `nbf`, `iat`, no expiry, no subject, a control byte, `crit`, an `act`
  chain 9 deep, a non-canonical encoding, a member name over 255 bytes,
  keys whose `use` or `alg` cannot be read); token exchange with two
  actors; each SVID case (expired, another domain, another authority, a
  key that does not match, two URIs, a CA, no basicConstraints, a second
  key); the token in no output, stream, export or agent environment; the
  files and anchors out of the agent's reach (the token, the SVID, every
  bundle, the issuers' CA; second names; a FIFO); an issuer too slow.
- **Sub-agents** (3, 33): a sub-agent and its fork, a double fork that
  reparents, a thread, a nested sub-agent, a second launch of one program,
  the same program by a rule without `subagent=`, a threaded launcher, a
  launch the kernel refuses (E2BIG) and the child started after it, a
  launch of the image the launcher already runs (and, without process
  events, its refusal), the group read from `/proc`, a group-name with a
  quote, the groups out of the agent's reach, the start refusals.
- **The token's expiry** (4, 10): two 75 s runs with a token that expires
  65 s in, one revoked and one recorded, each audited.
- **Audit, export and tools** (5, 33): 17 forged streams the audit
  refuses, each for its own reason; malformed values without a traceback;
  each tool's output.

Every earlier suite (`test-v1240` to `test-v1280`) and `make test-cli` pass
(`test-v1210`, not run in CI, fails four checks for reasons that are not
this release's: its `requests` client cannot import `requests` in the
container these ran in, and one lint check has been out of date since
v1.27). The cross-check's generator writes the new lines, valid and
malformed: two batches of 400 policies, 0 disagreements among the three
parsers. **Against v1.28.0** (its own tree, with this suite, its stand-ins
and its test program copied in, and the v1.28.1 `warden-secrets` beside
it; the v1.28.0 Warden never asks it about identities): 197 of the 208 checks fail,
11 pass. Three pass for another reason: v1.28.0 also refuses a policy that
requires Warden 1.29, has no lint warning to give, and stops a run whose
policy it cannot read while printing its own warning about an agent that
runs as root. The other eight check that something does not happen: no
token, claim, signature or private key in an output or the export, no
helper left running or crashed, no call refused, no control group left
behind. With no identity verified and no sub-agent launched, they hold
trivially.

## 24 hours on a small host

The shared soak (`tests/soak_shared/`, on v1.31's branch) covers v1.28.1,
v1.29.0 and v1.31.0 on one build, as decided for the three releases: the
v1.31.0 Warden, which carries this release's code. Its run A is this
release's: an agent acting for a user, whose token the run verified, with
two sub-agents, one launched by the other, and the token expiring inside
the run. It ran for 24 hours on a 2 GB droplet, 2026-10-14 to 2026-10-15,
signed, and passed:

| | |
|---|---|
| Duration | 24.0 h, a turn every 60 s: 1,440 turns |
| The user | `alice@example.test`, a token from the stand-in issuer (ES256), verified at the start; `on expiry: revoke` |
| Records | 16,456; `varek_audit` passed, every record's chain checked against the launches and the policy |
| Calls before the expiry | 1,291 tasks, all succeeded (each kind 258 or 259), among them 258 that launched the `coder` sub-agent, which launched `tester` |
| Attribution | every one of `tester`'s 258 opens recorded with the chain `user → agent → subagent:coder#n → subagent:tester#n`; the audit counted each sub-agent's decisions (5 for each `coder`, 4 for each `tester`) |
| Probes | 144 (18 of each of 8 kinds), all held |
| The expiry | the run revoked 0.00 s after the user's token expired; the 5 turns after it all refused, none working |
| The stream's other uses | the OCSF export followed it (14,283 events, verified against the stream, valid OCSF 1.9.0) |

The same soak's other runs, and the fault in `varek run`'s summary it
found (not in this release), are in `RELEASE-v1.29.0.md`.

## Latency

Measured in a 4-vCPU container (`make latency-v1281`, written to
`tests/latency_v1.28.1.txt`), 3 rounds of 2000 calls of each kind:

| | the Warden's decision, p50 | added by sub-agents |
|---|---|---|
| an allowed open | 75 us | +4 us |
| a denied open | 21 us | +2 us |
| an allowed connect | 167 us | -1 us |
| a whole request (connect and reply) | 163 us | +0 us |

That is with the group read through a pidfd; from `/proc` (a kernel before
6.13) it adds 4 to 9 us. Starting a run (20 runs each, wall time, p50): 16
ms with no identity; 38 ms with a user's token (the helper started, the
stand-in issuer's keys fetched over HTTPS on the same host, the token
checked; a real issuer adds its round trips, and keys are not cached
between runs, D9); 21 ms with a sub-agent named.

## Compatibility

- Every v1.28.0 policy loads unchanged and decides the same. Without
  `trust`, `require on-behalf-of` or `subagent=` lines nothing new runs:
  no helper is started for identities, no control group is made, and no
  group is read.
- Every decision record gains `obo`, and every `run_start` gains
  `on_behalf_of` and `operator`, whatever the policy. A consumer that
  rejects unknown fields must allow them.
- `--on-behalf-of` and `--agent-svid` need the Warden to run as root, and a
  policy that trusts an issuer or a trust domain. A policy that names a
  sub-agent needs cgroup v2 (a hybrid host's `/sys/fs/cgroup/unified`
  serves), a kernel with `cgroup.freeze` (5.2), and the agent not running
  as root.
- **Changed from v1.28.0:** the CA files `warden-secrets`' configuration
  names (`vault_ca`, `aws_ca`, and the new `oidc_ca`) are now read as root
  and must be root-owned and writable by no group or other user, under
  directories no other user can write; the Warden refuses a policy that
  lets the agent write one.
- New options: `--on-behalf-of`, `--on-behalf-of-expiry`, `--agent-svid`.
  New records: `on_behalf_of_expired`, `subagent_settled`; the `revoked`
  record says `"by":"on_behalf_of_expiry"` when the expiry revoked the run.
  New rules: `subagent_unattributed`, `subagent_threaded`,
  `subagent_same_image`, `subagent_limit`, `subagent_depth`,
  `subagent_failed`. `vdp_check` and `vdp_cert_check` have an `identity`
  mode.

## Found in review

Five AI review agents (Claude), separate from the session that wrote the
code, each reviewed one part of v1.28.1 in a copy of its own and had to
reproduce every finding: the user's token, with the task of getting a
forged or expired one accepted; sub-agent attribution, with the task of
making a sub-agent's call count as the agent's (or the agent's as a
sub-agent's); the SVID, the trust bundles and the file guards; the records,
the audit and the expiry; and the new C code, built with AddressSanitizer
and UndefinedBehaviorSanitizer. The agents are the same kind of model that
wrote much of this code, so this is not an independent human review. Each
finding was reproduced again before it was fixed, and each fix has a check
that fails on the build before it (27 of 29; the other two hold there too).
The full list is in the design note's step 8.

**Held.** No forged, altered, expired or untrusted token or SVID was
accepted. The sanitizers found nothing.

**Medium (high in effect), fixed.** A failed launch of a program whose
image is the one its launcher already runs (a Python agent launching a
Python sub-agent script, which resolves to the same interpreter) looked
launched, and the agent's later calls counted as the sub-agent's
(reproduced). A launch now counts only when the kernel's process events
say it happened; where those cannot be used, such a launch is refused.

**High, fixed (the audit).** Forged streams that hid the token's expiry
(recorded late, or dropped from an incomplete stream) or a sub-agent's
failed launch passed the audit, and real streams in which a thread exited
during its call failed it. The audit now holds records to time order, the
expiry's revocation to come next, every decision after the expiry to be
refused (unless the run was told to go on), and every decision for a
sub-agent to follow the record that its launch happened.

**Medium, fixed.**
- A trust bundle was checked for the agent's writes only when this run's
  SVID used it; every bundle the policy trusts is now checked at the start.
- The CA the issuers' HTTPS is verified with was loaded with no check, as
  were v1.28.0's `vault_ca` and `aws_ca`: now read as root, checked and
  reported (see Compatibility).
- A stream claiming an older Warden skipped the chain's checks.
- A control group's path was written into a record unescaped.

**Low, fixed.** The helper crashed on a signed token with a member name
over 255 bytes (failing closed, with the wrong reason); a token could be
encoded several ways with one meaning; keys whose `use` or `alg` could not
be read were used; one key id on keys of two types refused a good token;
the decoded token sat in memory that was not locked; a FIFO where a bundle
should be held the root helper; a file was opened by the name given rather
than the directory checked; a slow issuer ran past the Warden's wait; an
SVID leaf with no basicConstraints, or a file with a second unreadable key,
was accepted; the Warden took any printable algorithm name from the helper;
the tools crashed on malformed values, read lines with no run id, and
called an unverified user verified.

## Found by the shared soak's trial

The harness for the shared 24-hour soak of v1.28.1, v1.29.0 and v1.31.0
(`tests/soak_shared/`, on v1.31's branch) found two faults in its first
short runs that are in this release too; both are fixed here, with checks:

- **A signed stream could fail its own audit.** Checkpoints were written
  only between calls, but one pass over the egress proxy's reports
  (a burst of requests) can write several records at once: 65 or more
  could stand between two signatures, and the audit, which reads more than
  `checkpoint_every` as checkpoints removed, failed the run. The checkpoint
  now comes before a record that would pass the bound (`test_v1280`
  section 3: requests in bursts of 32, signed, the audit passing).
- **The audit refused a run in which a launch came after the run was
  revoked.** The Warden refuses it with rule `revoked`, as every call after
  a revocation, but the audit did not know that rule for a launch. It does
  now, checked against the revocation like every other `revoked` record
  (`test_v1280` section 4: a launch after `varek revoke`).

## Known limits

- **The chain is recorded, not enforced.** No rule depends on the user, an
  issuer or a sub-agent (D6). A rule `allow ... for=subagent:NAME` is a
  release of its own.
- **The token is checked at the start.** A token revoked at its issuer
  during the run is not noticed; its expiry is.
- **The token's `typ` is not checked**: any JWT the issuer signs for the
  audience is accepted, an ID token included.
- **SPIFFE:** an X.509-SVID from a file only; a JWT-SVID and the SPIFFE
  Workload API are left for a later release (D2).
- **The operator** is recorded as the host says (the sudo user, else the
  process's), not verified (D1).
- **Sub-agents:** a threaded process cannot launch one; without the kernel's
  process events (some containers), a launch of the image the launcher
  runs is refused. Records that are not a process's call (resolutions,
  the stub's questions, `proxy_close`) carry no `obo`.
- **A CA file a run does not read** (as `oidc_ca` with no token) is not
  checked by that run: the helper's configuration is the operator's.
- From v1.28.0, still: a server that echoes a credential back; what was
  sent stays sent. From v1.27.1: code written into memory is not covered;
  Linux only.

## Upgrading

1. Rebuild (`make all`) and reinstall (`make install`).
2. For a user's token: add `trust issuer URL audience AUD` for each
   identity provider (the audience is the agent's own client id there);
   give the run the token in a root-owned file, `--on-behalf-of FILE`
   (mode 0600 or 0400); if the issuer's TLS is not in the host's store, set
   `oidc_ca` in `/etc/varek/secrets.conf`. Check `vault_ca` and `aws_ca` are
   root-owned and not writable by others (v1.28.1 refuses them otherwise).
3. For sub-agents: `subagent=NAME` on the `allow exec` rules of programs
   that are agents themselves; check `varek doctor` reports cgroup v2.
4. Run `varek doctor` as root (it fetches each issuer's keys), then a short
   run, `varek audit`, `varek runs` and `varek refusals --subagent NAME`.
