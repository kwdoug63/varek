# VAREK v1.31.0 — MCP Servers Confined, MCP Calls Decided, and an OCSF Export

> v1.31.0 had a review by AI review agents: six, each on one area (confined
> subjects, MCP calls over HTTP, MCP tokens, the grammar in the three
> parsers, the audit, export and tools, and the Agent Baseline mapping
> against the code); its findings are fixed (below). A human or
> third-party review has not been done.

Released 2026-10-16 · MIT · github.com/kwdoug63/varek

## Summary

Through v1.29.0, an MCP server the agent launched was decided by the
agent's rules: a filesystem server could read whatever the agent could, and
a GitHub server could reach every host the agent could. A call to a remote
MCP server was one `POST` to one URL, so a policy could not allow one tool
and refuse another on the same server. And VAREK's evidence was its own
stream and a CycloneDX summary, which no SIEM reads.

From v1.31.0, under `require warden 1.31`:

1. **MCP servers confined to their own rules.** `mcp server NAME exec PATH
   [sha256=HEX]` declares a program as an MCP server. When the agent
   launches it, it runs as a sub-agent (v1.28.1) in its own control group,
   and every call it makes, and every call of every process it starts, is
   decided against the rules written for it (`for=NAME`) and no others
   (D3): the agent's rules do not apply to it, and its rules do not apply
   to the agent. The hard-denied system calls, the Warden's own files,
   revocation and the user's token expiry hold for it as for the agent.
   `subagent=NAME confined` does the same for a v1.28.1 sub-agent. Each
   allowed decision's certificate names the subject, and the checker
   replays it under that subject only. The start is refused when a
   server's file, or a directory above it, is one any subject's rules let
   be written, when it is not launchable, or when its SHA-256 is not its
   `sha256=`; lint refuses an interpreter or a launcher (`node`, `npx`,
   `uvx`, `docker`, ...) as a server's file (D4). Up to 32 confined
   subjects.
2. **MCP calls over HTTP decided by method and tool.** Under `proxy
   inspect`, `allow|deny mcp URL METHOD [NAME]` makes URL an MCP endpoint.
   The proxy holds each `POST` to it, reads the whole body (up to the
   deciding rule's `max_body=`, 1 MiB by default), parses it with a strict
   JSON parser as one JSON-RPC message, refuses one whose `Mcp-Method` or
   `Mcp-Name` header disagrees with it, and the Warden decides the object
   `<canonical URL>#METHOD#NAME` (a tool, resource or prompt name, as a
   glob). Nothing of the request is sent before the call is decided. A
   refused call gets a JSON-RPC error (code -32000) in a 403, and the
   connection takes no more requests. Each call is recorded (`net.mcp`):
   method, name, id, the body's length and SHA-256, the protocol version
   and the `traceparent` from `_meta`. Revisions 2025-06-18 and 2026-07-28
   are read.
3. **MCP tokens.** A v1.28.0 credential with `audience=URL` is an MCP
   token: at fetch, warden-secrets checks that it is a JWT whose `aud` is
   that server's canonical URL (or one of its accepted spellings) and that
   it has not expired, and it is released only into calls to that server.
   A token that is not a JWT is refused unless the line says `opaque` (D7).
   A token released after its expiry is refused. On every MCP call the
   bearer token the agent sends itself is checked (D6): refused if it is
   the run's user token, if it is a JWT for another audience, if it has
   expired, or if it cannot be read; an opaque one is left to the rules.
   `trust mcp-resource URL audience X` lets the run's user (v1.28.1
   `--on-behalf-of`) be named by a token whose issuer is found through
   that server's protected resource metadata (RFC 9728). Tokens come from
   stores, as v1.28.0's credentials do; VAREK does not run an OAuth flow
   (D8).
4. **An OCSF 1.9.0 export.** `varek export --format ocsf` writes each
   record of a stream as an OCSF 1.9.0 event (JSON Lines): file, process,
   network, HTTP, DNS and API (MCP) activity, with the decision in the
   `security_control` profile, the agent, its user and its sub-agents in
   the `ai_operation` profile, and each event's record report id, sequence
   number and chain hash in `unmapped.varek` (D1). A dry run's would-be
   refusals are Denied and Detected, never Blocked (D2). `--follow` writes
   events as the Warden writes records (D5); `--verify` checks a file of
   events against the stream it was exported from, and finds an event
   edited, dropped, reordered or cut. A stream the audit refuses is not
   exported. The schema is vendored (`schemas/ocsf-1.9.0`, Apache-2.0, see
   NOTICE).
5. **Audit and tools.** `varek_audit.py` checks that every decision that
   names a policy line names a rule of the subject it was decided as, that
   an MCP token is released only on an MCP call to its own server, and
   that no token value appears in any record outside what echoes the
   agent's own requests; it re-checks each `net.mcp` record's endpoint and
   certificate. `varek policy show` lists each server, its pin and its
   rules; `varek refusals --for NAME` lists a server's refusals, MCP calls
   included; `varek doctor` checks each server's file; `varek policy
   suggest --for NAME` drafts rules for one subject only; `varek run --mcp
   NAME=PATH` declares a server with the baseline, pinned, with its own
   copy of the baseline's system rules. The CycloneDX export lists MCP
   servers as components and remote MCP endpoints as services. `varek
   bench --for` and `--mcp` measure the new decisions.
6. **The rule cap is 512** (was 256): a server's own copy of the baseline
   is about 67 rules. The work of one decision stays bounded by the
   4,096 glob tokens of a policy, as before. The Warden reports `1.31.0`.

The Agent Baseline mapping (`docs/standards/agent-baseline.md`, against
the v1.0-draft) is published with this release (D11).

It does not decide the calls an agent makes to a stdio MCP server (D4), a
call's arguments, or a server's responses; no extension may move a
genuinely unsafe action to SATISFIED, and none does here.

## Tested

`make test-v1310` runs 317 checks; CI runs it as root:

- **The grammar** (section 1, 127): each new form and each refusal in the
  decision procedure, the certificate checker and the oracle; lint.
- **Confined subjects** (2, 31): a server allowed what its rules allow and
  refused what only the agent's do, and the reverse; a server's fork,
  double fork and launched program decided as the server; the agent's
  `/proc` entries closed to the server; the start refused for a pin that
  does not match, a server file any subject may write, or under a
  directory one may; forged streams the audit refuses.
- **MCP calls over HTTP** (3, 59): allowed and refused calls; both
  revisions; chunked bodies; a call that cannot be read, a batch, a
  duplicate key, mismatched headers, a body over `max_body`, a query on the
  endpoint; nothing refused reaching the server; the credential only in
  the calls its rule allows; the records.
- **MCP tokens** (4, 41): an audience-bound token released to its server
  only; each accepted spelling of its audience and the ones refused; an
  expired or opaque token; the agent's own tokens; the user found through
  a server's protected resource metadata.
- **The OCSF export** (5, 27): every event validated against the vendored
  schema (profiles, required attributes, types, enumerations); the mapping
  of each kind; a dry run; `--verify` on edited, removed, reordered and cut
  events; `--follow` against the batch export.
- **Audit and tools** (6, 32): thirteen forged streams the audit refuses; each
  tool's output; the baseline with `--mcp` linting and accepted by the
  Warden.

Every earlier suite passes, except `test-v1210`, which fails the same four
checks on v1.29.0 on the test host (its sample policy's lint note, Python
`requests`, and its latency run). `make crosscheck` with v1.31 policies
(three seeds; 69 with `mcp` rules, 75 with confined subjects): 0
disagreements. **Against v1.29.0** (its own tree, with this suite and its
helpers copied in): 263 fail, 8 pass. Of the 8, one checks a refusal v1.29.0
shares, two that no value reached a stream (nothing ran), and five that
edited streams are refused (v1.29.0 has no OCSF exporter, so they hold
trivially).

## 24 hours on a small host

The shared soak (`tests/soak_shared/`, on this branch) covers v1.28.1,
v1.29.0 and v1.31.0 on this release's Warden. Its run A is this
release's: an agent acting for a verified user, the egress proxy
inspecting, two confined MCP servers launched once and kept the whole run
(`fs` reading project files under its own rules, `gh` calling a remote MCP
server with the run's MCP token, which the proxy puts in only where a rule
written `for=gh` names it), the agent's own MCP calls, two sub-agents, and
the user's token expiring near the end; the OCSF export following the
stream throughout. The first 24-hour run (2026-10-14 to 2026-10-15) found
the fault in `varek run`'s summary below; the review's fixes came after
it, so the soak ran again on the reviewed build, for 24 hours on a 2 GB
droplet, 2026-10-15 to 2026-10-16. It passed:

| | |
|---|---|
| Duration | 24.0 h, a turn every 60 s: 1,440 turns; Warden 1.31.0 |
| Tasks before the expiry | 1,291, all succeeded: the agent's `tools/list` 259 and `tools/call search_code` 258, `fs` reads 258, `gh`'s `get_issue` on the remote server 258, sub-agent launches 258 |
| Probes | 144 (18 of each of 8 kinds), all held: the agent's `delete_repo`, an unlisted tool and `get_issue` itself refused (403); `fs` reading the agent's file and the token's store refused; `gh`'s `delete_repo` refused; the agent opening `fs`'s file refused; a second `fs` launched with `PYTHONPATH` refused at the launch |
| Confined servers | `fs` and `gh`, each confined, each call decided for its own subject and certified under it |
| The remote MCP server | 775 requests, the MCP token in exactly `gh`'s 258 allowed calls and in none other, 0 errors |
| The expiry | the run revoked 0.00 s after the user's token expired; the 5 turns after it all refused |
| Records | 13,891; `varek_audit` passed (the token released on 258 requests, none refused, the run revoked) |
| OCSF | 11,719 events followed live, verified against the stream (`--verify`), valid OCSF 1.9.0 |
| Time | an MCP call at the agent p50 71 to 73 ms (p99 85 ms), through the proxy and back; the Warden's decision on it p50 26 us (p99 73), on `gh`'s p50 30 us (p99 59) |
| Memory | the Warden 12.5 to 13.2 MB, `warden-proxy` 8.7 MB, `warden-secrets` 9.1 MB, `fs` 11.4 MB, `gh` 20.3 to 21.3 MB, flat |

Runs B and C (v1.29.0) passed in the same soak (`RELEASE-v1.29.0.md`).

## Latency

Measured in a 4-vCPU container (`make latency-v1310`, written to
`tests/latency_v1.31.0.txt`), 5 rounds:

| the Warden's own decision, p50 | open allowed | open refused | connect allowed |
|---|---|---|---|
| the agent, after the baseline (210 rules) | 126 us | 46 us | 180 us |
| a confined server, its own rules only (5) | 103 us | 38 us | 174 us |
| a server with its own copy of the baseline (72) | 130 us | 46 us | 186 us |

A server's call is decided against its own rules only, so it costs no
more than the agent's.

| a `tools/call`, p50 | 1 KiB | 16 KiB | 256 KiB | 1 MiB |
|---|---|---|---|---|
| natively | 127 us | 176 us | 581 us | 2.1 ms |
| added under a request rule (the body streamed) | +364 us | +456 us | +1.7 ms | +6.0 ms |
| added under an MCP rule (the body held) | +357 us | +631 us | +4.0 ms | +15.6 ms |
| the Warden's own decision of the call | 8 us | 10 us | 26 us | 29 us |

Holding the body costs nothing on a small call and about 9.6 ms per MiB
on a large one: the proxy reads all of it from the agent before it sends
any of it to the server. Starting a run (wall time, p50 of 20): 168 ms
under the baseline; 252 ms with one MCP server; 416 ms with four (each
adds its rules and its file's check). The OCSF export is offline or a tail
of the stream and adds nothing to a decision.

## Compatibility

- Every v1.29.0 policy loads unchanged and decides the same; nothing above
  happens without `require warden 1.31`, and a v1.29.0 Warden refuses the
  new lines as unknown.
- A policy may have up to 512 rules (256 before).
- New lines and options: `mcp server`, `for=`, `subagent=NAME confined`,
  `allow|deny mcp`, `audience=` and `opaque` on `credential`, `trust
  mcp-resource`. New CLI: `varek export --format ocsf` (`--follow`,
  `--verify`, `--policy`), `varek refusals --for`, `varek policy suggest
  --for`, `varek run --mcp`, `varek bench --for` and `--mcp`.
- New records and fields: `net.mcp` (`mcp_method`, `mcp_name`, `rpc_id`,
  `notification`, `body_len`, `body_sha256`, `protocol_version`,
  `traceparent`, `max_body`); `cert_subject` on a decision not the
  agent's; `mcp_server` and `confined` on a server's launch; in
  `run_start`, each credential's `audience`, `opaque` and expiry, and the
  `on_behalf_of` user's `mcp_resource`. New rules: `mcp_allowed`,
  `mcp_unreadable`, `mcp_header_mismatch`, `mcp_query`, `mcp_token_user`,
  `mcp_token_audience`, `mcp_token_expired`, `mcp_token_malformed`,
  `credential_expired`, `mcp_endpoint_variant`, `subagent_env`. A
  confined server is launched only with an environment that names no code
  (`varek run` gives the agent a clean one; under a bare `warden`, the
  agent's own environment must not carry such a variable). An MCP call's
  body must be `application/json` in UTF-8.

## Found in review

Six AI review agents each reviewed one area, reading the code and running
experiments; every finding below was confirmed and fixed, with checks
(test_v1310 grew from 271 to 317).

- **A confined server ran code its launcher chose** (high). A launch was
  decided on the file alone, so the agent could start a `#!` server with
  `PYTHONPATH` (or `NODE_OPTIONS`, `LD_PRELOAD`, `BASH_ENV`, ...) naming a
  directory it writes, and the server's interpreter ran the agent's code
  under the server's rules. A confined launch whose environment sets a
  variable that names code is now refused (`subagent_env`): checked in the
  launcher's memory at the decision and again in the new image's own copy
  before any of its calls is answered. Settings that name no code
  (`PYTHONUNBUFFERED`, a `NODE_OPTIONS` heap size, the Warden's own
  `JAVA_TOOL_OPTIONS` trust store) are allowed.
- **An MCP call's body read one way and decoded another** (high, for a
  server that honours a charset). The body must now be sent as UTF-8 JSON:
  one Content-Type, `application/json` with no charset but UTF-8, and no
  Content-Encoding.
- **Another spelling of an MCP endpoint** (`/MCP`, `/mcp/`) was decided by
  request rules, its body unread. A POST to it is now refused
  (`mcp_endpoint_variant`).
- **Bearer tokens in a lenient form** (padding, a tab after the scheme)
  were taken for opaque tokens and decided by the rules alone, and the
  run's user token signed again (ECDSA's other `s`, which needs no key)
  passed as another token. A token in a JWT's form must now be a strict
  compact JWS, the scheme is read with any whitespace (and DPoP's), and
  the user's token is also recognized by its signing input.
- **The OCSF `--verify`** checked only the chain and that the last event
  said "passed": a forged stream followed, its failed verdict edited to
  passed, verified. It now audits the stream and compares the verdict
  event; the export and `--verify` read the stream once; a decision record
  that names an event is refused.
- **The audit** let a decision cite a policy line by a string or another
  rule of its subject; refused MCP calls with no object decided were not
  asked of the checker; two malformed shapes crashed it. Each is checked.
- **Smaller:** a server file that is a symlink to an interpreter; more
  launchers refused as a server's file (`time`, `strace`, `bwrap`, `tsx`,
  ...); lint fails a server file the agent may write, and notes a METHOD
  glob `*` (which matches no method with a '/'); a `#` in an mcp rule's
  NAME; a long `audience=` that crashed the certificate checker; an empty
  body, chunked trailers, a duplicate empty member name; discovery of an
  identifier ending in '/', an authorization server two resources share,
  an `opaque` line whose value is a JWT; `--follow` stopping on a quiet
  run; `refusals --for`, `doctor` on a symlink, and the export's DNS and
  dry-run outcomes.
- **The Agent Baseline mapping** said v1.31.0 was planned, claimed a lint
  note that did not exist (AUT-03), and stated several limits too
  narrowly; corrected (13 items).

Not changed, and stated as limits below: a server program that reads code
from a file it may read that another subject may write (a `.git/config`
in the project, a script); the environment check is a list of variables
that name code, not an allowlist.

## Found by the shared soak's trial

The harness for the shared 24-hour soak (`tests/soak_shared/`, with
v1.28.1 and v1.29.0) found two faults in its first short runs, both
older than v1.31; each is fixed, with a check:

- **A signed stream that renames files could fail its own audit.** A
  rename is decided on both its names, two records from one call, and
  checkpoints were written only between calls (as one pass over the
  proxy's reports can write several records too): when a rename's first
  record was the 64th since the last checkpoint, 65 stood between two
  signatures, and the audit, which reads more than `checkpoint_every` as
  checkpoints removed, failed the run. A run of `git commit` under `varek
  run` (signed with the key made on first use) was enough, and so was a
  burst of requests through the inspecting proxy (reproduced on v1.28.0's
  build: 65 to 73 records between signatures). The checkpoint now comes
  before a record that would pass the bound (`test_v1290` section 2b: 300
  renames, signed; `test_v1280` section 3: requests in bursts of 32,
  signed; the audit passing). The fix is ported to the v1.28.0, v1.28.1
  and v1.29.0 branches, and to v1.27.1 as v1.27.2 (the fault is in v1.26.1
  to v1.27.1 too, reproduced on v1.27.1).
- **The audit refused a run in which a launch came after the run was
  revoked.** The Warden refuses it with rule `revoked`, as every call
  after a revocation, but that rule was not among the launch refusals the
  audit knows, so `varek_audit` (and the OCSF export's `--verify`) failed
  a genuine stream. It is now, checked like every other `revoked` record
  against the revocation before it (`test_v1280` section 4: a launch after
  `varek revoke`). Ported to the same three branches.

With both fixed, the harness's 6-minute trial on the test host (a turn
every 3 s, signed) passes: in run A, every task and probe before the
user's token expired, the token only in `gh`'s allowed calls, nothing
after the revocation, the audit, and the OCSF events verified and valid;
B's work and probes, and its audit; C's dry run, draft and second dry run.

## Found by the first 24-hour run

The first 24-hour run of the shared soak (2026-10-14 to 2026-10-15, on a
2 GB droplet with no swap) ran all three runs to their end: each agent
finished, and run C's stream ends in its signed `run_end`, exit status 0.
After them, `varek run`'s wrapper for run C was killed for memory while it
printed its summary, and then the soak's checker was too. The wrapper read
the whole verdict stream into memory, and under the baseline a day's
stream is about 250 MB, about 1.2 GB as objects; runs B and C finished at
once. **Fixed:** `varek run`, `status`, `refusals`, `export` and `policy
suggest` read a stream as they go, holding only what they count, with the
same check that refuses a damaged stream (`test_varek_cli.py`: a 16 MB
stream summarized under 4 MB of peak memory, 74 MB before). The audit
still reads a stream whole (a known limit since v1.27.1): on a small host
give it swap.

## Known limits

- **The agent's calls to a stdio MCP server are not decided** (D4): they
  are bytes on a pipe between two supervised processes. A confined server
  bounds what any call to it can do; its tools remain the agent's to call.
- **A call's arguments and a server's responses are not decided** (a tool
  list that changes, a result that carries an injected instruction).
- **Tokens come from stores.** VAREK does not run the OAuth flow, register
  clients or refresh tokens; something outside it keeps the token in its
  store current (D8). Token introspection (RFC 7662) is not used (D7).
- **A confined server shares what both subjects' rules let them reach.**
  A server that reads code or settings from a file the agent may write
  (`varek run --mcp` gives a server the working directory read-only, which
  holds `.git/config`) runs what the agent wrote there, under the server's
  rules. Its launch environment is checked against a list of variables
  that name code; a program that takes code from another variable is the
  operator's to know.
- **A large MCP call is held whole**, up to `max_body=` (1 MiB by default),
  before it is sent.
- **The OCSF export is 1.9.0 only** (D9). It carries no `record_integrity`
  attestation; the stream is the evidence (D1).
- **The Agent Baseline mapping is against a draft** whose identifiers may
  change until its v1.0.
- **Calls glibc and bash make that the Warden refuses** (fixed in v1.31.1,
  in every release before it): on x86_64, `epoll_wait(2)` and
  `epoll_create(2)`, which glibc calls for `epoll_wait()` and
  `epoll_create()`, so Python's `select.epoll` and asyncio's default event
  loop fail with EPERM under every policy (an agent can run asyncio on
  `asyncio.SelectorEventLoop(selectors.PollSelector())`; arm64 is not
  affected); on RHEL 9 (glibc 2.34), `pipe(2)`, which its `pipe()` calls,
  so a shell's command substitution fails, and under a policy before 1.29
  `getpgrp(2)`, without which bash, RHEL's `/bin/sh`, does not start.
- From v1.29.0: a dry run is not a sandbox. From v1.28.1: the chain is
  recorded, not enforced. From v1.28.0: a server that echoes a credential
  back. From v1.27.1: code written into memory is not covered; Linux only.

## Upgrading

1. Rebuild (`make all`) and reinstall (`make install`).
2. To confine a local MCP server: `require warden 1.31`, `mcp server NAME
   exec PATH sha256=...` before the agent's exec rules, and its rules
   `for=NAME` (or `sudo varek run --mcp NAME=PATH -- <agent command>` with
   the baseline). A dry run and `varek policy suggest --for NAME` draft what
   it needs.
3. To decide a remote server's calls: `proxy inspect`, `allow host` for
   it, and `allow mcp URL METHOD [NAME]` for each call to allow (a
   credential with `audience=URL` for its token).
4. To send events to a SIEM: `varek export --format ocsf RUN` (or
   `--follow` on a live run), and `--verify` on what was sent.
5. Run `varek doctor`, then `varek audit` on a run.
