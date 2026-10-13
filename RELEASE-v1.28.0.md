# VAREK v1.28.0 — The Agent Holds Only Placeholders

> The review was done by AI review agents; a human or third-party review
> has not been done.

**Draft.** Pending: the 24-hour soak of the reviewed build and the date.

MIT · github.com/kwdoug63/varek

## Summary

An agent that calls an API needs the API's key. Through v1.27.1 the key had
to be in the agent's own memory (an environment variable, a file it reads),
where anything the agent runs can read it and send it anywhere a rule allows,
for as long as the process lives.

From v1.28.0 the agent can hold a placeholder instead. The real value is
fetched by a helper the agent cannot reach, held by the egress proxy, and
written into a request only where a rule names it, on a request the Warden
decided SATISFIED.

1. **The policy.** After `require warden 1.28`:

   ```
   credential github from vault:secret/data/agents/github#token
   allow request GET https://api.github.com/repos/** credential=github header=Authorization:Bearer
   ```

   `credential NAME from STORE:REF` names a credential (at most 32): `file:`
   an absolute path, `vault:PATH#FIELD`, or `aws-sm:ARN`. On an `allow
   request` rule, `credential=NAME header=HEADER[:SCHEME]` says where it
   goes. The rule must be `https://`; framing headers (`Host`,
   `Content-Length`, `Transfer-Encoding`, `Connection` and others) are
   refused. All three parsers (the decision procedure, the certificate
   checker and the cross-check's oracle) read it alike. The swap needs the
   proxy in inspecting mode (`proxy inspect`, v1.26.1).
2. **Fetching: `warden-secrets`.** A separate program, loaded into a sealed
   memfd and recorded by SHA-256 like `warden-proxy`. As root it reads only
   its configuration (`/etc/varek/secrets.conf` or `--secrets-conf`) and
   local stores, each a regular file owned by root and readable by no one
   else, under directories no other user can write. Then it runs as its own
   user (`--secrets-as`, default `varek-secrets` or 65531), with no
   capability, no new privileges and not dumpable, and fetches over
   verified HTTPS: Vault KV version 2 and 1, and leased secrets (renewed at
   two thirds of the lease); AWS Secrets Manager, signed with SigV4 from a
   key file or the instance's role (IMDSv2). A value is 1 to 8192 bytes
   with no CR, LF or NUL. The Warden learns each one's version and length,
   never the value, and refuses to start when a fetch fails, naming the
   credential and the reason.
3. **Placeholders and the swap.** The agent gets `VAREK_CRED_<NAME>`, a
   placeholder made for the run (`varek_ph_<name>_` and 32 random bytes).
   The values go from `warden-secrets` to `warden-proxy` over a socket the
   Warden passes on without reading; the proxy holds them in locked memory,
   out of any dump. On a request whose deciding rule names a credential,
   the header must occur once and hold exactly the placeholder (after the
   rule's scheme, if it names one); the proxy replaces it in place and
   sends the request. Anything else is refused with a 403 before a byte is
   sent, and recorded as `credential_refused` with why. A placeholder
   anywhere else (a query, a body, another header, a request no such rule
   allows) is sent as it is. Bytes that held a value are cleared once sent.
4. **Revocation.** The Warden opens a control socket for each run,
   `/run/varek/<run>.ctl`, that only root can reach. `varek revoke <run>`
   (or `--all`):
   - records `revoked` (who asked), and from then on every mediated call of
     the run is UNSATISFIED (rule `revoked`), including connects in
     progress and the stub resolver's answers;
   - has the proxy clear every value and placeholder and close every
     connection (`revocation_proxy`, with the value slots it still holds,
     which must be 0);
   - has `warden-secrets` revoke the run's Vault leases
     (`revocation_leases`).

   The run is not ended: the agent goes on, held to refusals, and its
   attempts are recorded. Leases are also revoked when the run ends.
5. **Records, audit and tools.**
   - `run_start` records each credential: its store, reference, version,
     length and the placeholder's SHA-256, and `warden-secrets`' SHA-256.
     Each request that carried one records its name and header.
   - `varek_audit.py` checks the credentials against the policy, every
     request that carried one against its deciding rule and header (and
     every request such a rule allowed carried it), each refused swap
     against its request, and the revocation: once, by root, its records
     in order, every decision after it UNSATISFIED.
   - `varek refusals` marks calls refused after a revocation `REVOKED` and
     lists refused swaps; `varek policy show` lists the credentials and the
     rules that carry each; the CycloneDX export carries
     `varek:credentials.*` and `varek:revocation.*`.
   - `warden --check-credentials` fetches each credential (keeping no
     value, revoking any lease it made) and stops; `varek doctor` and the
     preflight use it.
   - `varek bench --proxy` measures a request that carries a credential.

   The Warden reports `1.28.0`.

## Tested

`make test-v1280` runs 168 checks; CI runs it as root:

- **The grammar** (section 1, 46 checks): each form and each refusal in
  the decision procedure and the certificate checker, which must agree;
  lint notes a credential no rule carries; the version.
- **Fetching** (2, 30): stand-ins for Vault (KV version 2, version 1, a
  lease, a chunked answer), AWS Secrets Manager (checking each request's
  SigV4 signature with its own implementation) and IMDSv2, over HTTPS with
  a CA made for the test; the version recorded; no value in the Warden's
  output; 18 refusals (a store others can read or that root does not own,
  a value of two lines, a wrong token or key, plain HTTP, an unknown
  certificate, the helper as the agent's user, and others).
- **The swap** (3, 28): a TLS server that logs what it receives; a value
  longer and one shorter than its placeholder; the body after the head
  intact; five refused shapes; a placeholder elsewhere sent as it is; the
  server receiving a value only where a rule names it; no value in the
  agent's environment or the stream; the audit and 8 forged streams.
- **Revocation** (4, 32): a run revoked in mid-run; the connection the
  proxy held closed, a file open and a connect refused after it; the
  records; leases revoked at the stand-in; renewals, one that fails and is
  not retried, none after the revocation; root only; the audit and 7
  forged streams.
- **Records and tools** (5, 9): `--check-credentials` and the preflight,
  `varek policy show`, `varek refusals`, the export.
- **The review's fixes** (6, 23): see below.

The earlier suites (`test-v1240` to `test-v1271`) and `make test-cli` (72
tests) pass. The cross-check's generator writes credential policies, valid
and malformed: four batches of 400 before the review and two after it, 0
disagreements among the three parsers. **Against v1.27.1** (its own tree,
with this suite and its stand-ins copied in, and the v1.28 `warden-secrets`
beside it so the sections run rather than skip; the v1.27.1 Warden never
starts it): 155 of the 168 checks fail, 13 pass (each checks that something
does not happen: no value in an output, no helper or socket left behind, no
renewal after a revocation, no secret quoted; with nothing fetched they hold
trivially).

## 24 hours on a small host

`tests/soak_v1280`: an agent under the Warden, the proxy in inspecting
mode, holds placeholders for four credentials (a file, a Vault lease of 60 s
renewed every 40 s, Vault KV version 2, AWS Secrets Manager, from the
stand-ins) and once a minute calls a local API with one in turn; the API
answers 200 only when the header holds exactly the value. Every tenth turn
is a probe (a missing header, another credential's placeholder, a
placeholder where no rule names one, a read of the file store). Near the end
the run is revoked; every turn after must be refused.

A 6-minute trial of the build before the review passed on the 1 vCPU, 1 GB
droplet: 99 calls before the revocation, each with the value where its rule
names it; 11 probes held; 8 lease renewals; 10 turns after the revocation,
all refused; the proxy holding no value, the lease revoked; the audit
passed; memory flat. The 24-hour run of the reviewed build: (to come).

## Latency

`varek bench --proxy` gains a kind: a request on a kept-alive connection
that carries a credential (natively the client sends the value; in
inspecting mode it sends the placeholder and the proxy swaps it in, and the
server answers 200 only to the value). Measured on the reviewed build, a
4-vCPU container, 3 rounds of 200 requests of each kind after 20 warm-up:

| | native | inspecting mode | added (p50) |
|---|---|---|---|
| a request on a kept-alive connection | 106 us | 439 us | +334 us |
| the same, carrying a credential | 120 us | 507 us | +386 us |
| the Warden's decision on it (p50 / p99) | | 4 / 14 us; with a credential 5 / 18 us | |

So the swap adds about 50 us to a request at the median, on top of what
inspecting mode already adds; a real server's network time is not in these
numbers. All 45 of the bench's checks passed, among them every request with
a credential answered by the server only to its value.

## Compatibility

- Every v1.27.1 policy loads unchanged. Without `credential` lines nothing
  changes: no helper runs, and no control socket is needed.
- `credential` needs `require warden 1.28` and the Warden running as root.
  A credential reaches a request only through a request rule, which needs
  `proxy inspect`; without the proxy a run with credentials refuses to
  start. The grammar is 1.28; `require warden 1.29` is refused.
- New binary: `warden-secrets` (`make all` builds it; it links OpenSSL).
  New options: `--secrets-bin`, `--secrets-as`, `--secrets-conf`,
  `--check-credentials`. New command: `varek revoke`. New directory:
  `/run/varek/` (root's, 0700).
- New records: `credential_refused`, `revoked`, `revocation_proxy`,
  `revocation_leases`, `lease_renewed`, `lease_renewal_failed`;
  `run_start`'s `credentials` and `secrets_binary_sha256`; `credential` and
  `credential_header` on a request that carried one. Rule `revoked` on
  decisions after a revocation. `vdp_check` and `vdp_cert_check` have a
  `credentials` mode.
- When the Warden runs as root it opens a control socket for every run,
  credentials or not, so any run can be revoked.

## Found in review

Three AI review agents (Claude), separate from the session that wrote the
code, each reviewed one part of v1.28.0 and had to reproduce every finding
(a script and its output): `warden-secrets` and its start; the swap, with
the task of getting a value into the agent's process or the stream; and
revocation, the records, the audit, the tools and the three parsers. All
three finished. The agents are the same kind of model that wrote much of
this code, so this is not an independent human review. It found real
defects, listed below, but it does not replace a human or third-party
review. Each finding was reproduced again before it was fixed, and each fix
has a check in section 6 that fails on the build before it (22 of 23; the
23rd checks the helper's hardening, which held already). The full list is
in the design note's step 8.

**High, fixed.** A file `warden-secrets` reads (a file store, the Vault
token file, the AWS key file) could be read by the agent through a second
name: a hard link, or a bind mount of it or a directory above it, under a
path the policy lets the agent read. The Warden checked only the file's own
path, but the agent's allowed opens are made by the Warden, as root, so the
file's mode did not protect it (reproduced: an agent running as `nobody`
printed the value). Now each such file must have one name, no other mount
of its filesystem may show it where the agent may open, and every directory
above it must be root's and writable by no other user (unless sticky).

**Medium, fixed.**
- After `varek revoke`, the stub resolver still answered questions on a
  socket the agent had connected to it before the revocation (`send()` on
  it is not a mediated call), and names under a wildcard rule were still
  looked up upstream. It now refuses every question after a revocation,
  recorded with rule `revoked`, and the audit requires that.
- `warden-secrets` died of `SIGPIPE` when a store reset the connection;
  its leases were then neither renewed nor revoked, with nothing recorded.
  It now reports the failure and goes on.

**Low, fixed.** A store's version id could put lines into the Warden's
output; a malformed key-file line was quoted, secret and all; the Vault
token stayed in freed request buffers; plain HTTP went to any configured
metadata host; credentials from the metadata service or a key file were not
checked for CR or LF; a relative `--secrets-conf` failed with a misleading
message; `--check-credentials` could mistake a renewal report for the
answer; the audit's order checks could be met by an event placed right
before the record it must follow; refusals marked `revoked` without a
revocation passed; the certificate checker read a header name holding `|`
beside a framing name differently from the other parsers (fail-closed); the
audit and `varek refusals` crashed on malformed fields; `varek refusals`
showed another run's revocation; the export said every decision after a
revocation was refused without counting; a control socket left by a killed
Warden stayed. Three tests could pass with the property they name false;
they now cannot.

**Held.** No way was found to get a value into the agent's process or the
stream through the proxy: pipelined and chunked requests after a value
longer than its placeholder, placeholders in the query, the body and other
headers, every refused shape, redirects. The way in that remains is the
known limit below.

## Known limits

- **A server that echoes the value back.** A server the policy lets a
  credential reach can return the request's headers in a response the agent
  reads (reproduced in review against a test server). The policy must not
  allow such an endpoint with a credential. The proxy does not scan
  responses: a scan could not see through compression or an encoding, and
  would promise more than it holds.
- **What was sent stays sent.** Revocation stops what follows it. A
  connection the agent opened outside the proxy before it stays open (later
  connects are refused).
- **Leases.** A renewal Vault refuses is recorded and not retried; the value
  lapses when Vault says. The helper does not renew its own Vault token, so
  a token shorter-lived than a lease ends renewals early (Vault then
  revokes the lease).
- **The proxy holds the values** for the run, in locked, non-dumped memory,
  as its own user; a flaw in it that lets a server or the agent read its
  memory would reach them.
- **Only in inspecting mode**, and only for headers: a credential in a URL,
  a body or a form is not supported.
- **The on-behalf-of chain** (user → agent → sub-agent) moved to v1.28.1.
- From v1.27.1, still: code written into memory is not covered; Linux
  only.

## Upgrading

1. Rebuild (`make all`, which builds `warden-secrets`) and reinstall (`make
   install`). Make a user for the helper: `useradd --system --no-create-home
   varek-secrets` (or name one with `--secrets-as`).
2. Write `/etc/varek/secrets.conf` (root's, 0600): `vault_addr`,
   `vault_token_file`, `vault_ca`, `aws_region`, `aws_endpoint`, `aws_ca`,
   `aws_credentials_file` or nothing for the instance's role, `aws_imds`.
   Keep every file it names, and every file store, outside every path the
   policy allows, with one name each.
3. Add `require warden 1.28`, `proxy inspect`, a `credential` line for each
   secret and `credential=... header=...` on the request rules that need
   it; have the agent send `$VAREK_CRED_<NAME>` where it sent the key.
4. Run `varek doctor` as root: it fetches each credential. Then a short run,
   `varek audit` and `varek refusals`. `varek revoke <run>` stops a run's
   use of every credential at once.
