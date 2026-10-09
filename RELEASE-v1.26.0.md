# VAREK v1.26.0 — The Egress Proxy, SNI Mode

> **DRAFT, not released.** Still to come before tagging: the release date.
>
> The review was done by AI review agents; a human or third-party review
> has not been done.

Released PENDING · MIT · github.com/kwdoug63/varek

## Summary

v1.24 and v1.25 decide a connect on the address dialed and the names that
address belongs to. On a shared CDN address that is not enough: every site
on the address shares its names' fate, and a client can reach another site
there while the Warden's decision holds. The agent's own lookups also left
the host under a wildcard rule (v1.25's name channel, bounded but open).

From v1.26.0 a policy can turn on the egress proxy:

    require warden 1.26
    proxy on
    allow host api.example.com:443
    allow host *.svc.example.com:443 acknowledge=dns-channel

The Warden then decides on the name the client sends, the TLS SNI or the
HTTP `Host`, not on the address. A separate, unprivileged proxy reads that
name; the Warden decides, records and dials; the proxy relays.

1. **Grammar.** `proxy on`, `proxy ports P...` (default 80 and 443, at
   most 16) and `proxy upstream http://HOST:PORT`, after `require warden
   1.26`, in the decision procedure, the certificate checker and the
   cross-check oracle. The Warden refuses to start if its two C parsers read
   them differently. `proxy inspect` (inspecting mode) is refused until
   v1.26.1. The policy-grammar version is now 1.26.
2. **The proxy process.** A mode of the Warden's own binary, started before
   the agent as its own user (`--proxy-as`, default `varek-proxy` or
   65532:65532; never root, never the agent's user), with no capabilities,
   no-new-privileges, and only its control socket and its listener open. It
   proves its user to the Warden with `SCM_CREDENTIALS`, listens on
   127.0.0.1 in the host's network namespace, and exits with the Warden. The
   Warden refuses to run a `proxy on` policy when it cannot start it (not as
   root), rather than run the policy without it.
3. **Synthetic addresses.** A name that host rules allow only on proxied
   ports is never resolved for the agent. The hosts view and the stub
   (which now runs with the proxy on, wildcard or not) give it a stable
   address from 198.18.0.0/15, A only (AAAA gets no data, so clients use
   IPv4), from 198.18.0.1 in order, recorded once each
   (`synthetic_address`). Nothing is looked up and no wildcard budget is
   charged when the agent asks. A name also allowed on another port keeps
   its real addresses.
4. **The hand-off.** A TCP connect on a proxied port is handed to the proxy
   unless a numeric rule allows the address itself (dialed directly, as in
   v1.21) or a rule denies it (refused). A synthetic address is always handed
   over. The Warden binds a socket of the agent's kind to 127.0.0.1, tells
   the proxy the local port, then connects it to the listener and gives the
   agent that socket. The proxy closes any connection the Warden did not
   announce. A UDP connect on a proxied port (QUIC) that a name allows is
   refused (`proxy_tcp_only`); clients fall back to TCP.
5. **What the proxy reads.** Bounded parsers that allocate nothing: a TLS
   ClientHello's SNI (at most 16 KB over 64 records), an HTTP/1.x request's
   one `Host` (headers within 8 KB, CRLF only), and a `CONNECT host:port`,
   answered 200, whose ClientHello must name the same host. Refused: no SNI,
   two names, an IP literal, a trailing dot on an SNI, Encrypted Client Hello
   and ESNI, an extension given twice, a `Host` port other than the one
   connected to, and anything malformed. The proxy refuses the client itself
   (a TLS `handshake_failure` alert, or a 403) and tells the Warden why. Only
   the connection id, the kind, the name and the port reach the Warden.
6. **The decision.** The Warden decides `name:port` with the SMT decision
   procedure, and the certificate checker must accept its certificate. It
   finds the name's addresses in the resolution table (a wildcard's name is
   looked up on demand, each lookup charged to the wildcard's budgets as the
   stub charges a question), skips special, synthetic and denied addresses,
   dials without blocking, and passes the connected socket to the proxy
   (`SCM_RIGHTS`), which relays both ways. One `net.proxy` record per
   request, with the decision, the certificate, the kind and the address
   dialed.
7. **Close records.** When a relayed connection ends, the proxy reports the
   bytes each way and how long it relayed; the Warden writes a chained
   `proxy_close`. At run end the Warden has the proxy close everything and
   report, and records any connection it never heard about as `unreported`.
   If the proxy dies mid-run, the run stops.
8. **The audit.** `varek_audit.py` checks every v1.26 record against the
   policy: each synthetic address and answer; each hand-off asked of the
   policy again (no rule denies it, no numeric rule allows it by its
   address); each `net.proxy` decision for its hand-off, once, certified
   when allowed, dialing only an address the name had; a close for every
   connection passed on; `run_start`'s proxy as the policy has it; and no
   connect on a proxied port dialed directly except by a numeric rule.
9. **A customer's proxy.** `proxy upstream http://HOST:PORT` chains the
   proxy to an existing egress proxy or DLP tool after the Warden decides,
   so both apply and a refusal never reaches the upstream. The proxy asks it
   with `CONNECT name:port` and relays on a 2xx; its own refusal reaches the
   client and is recorded with its status (`upstream_refused`). An upstream
   named by host name is resolved by the Warden and kept out of the agent's
   views.

Per-call verdicts on file opens, lookups and launches are unchanged, and so
is the symmetric-suppression invariant (**no extension may move a
genuinely unsafe action to SATISFIED**). Without `proxy on`, every v1.25
policy behaves as on v1.25.0.

## Tested with real clients

`make test-v1260` runs 156 checks; CI runs it, with the Warden as root and
Squid installed. Each run uses its own scratch paths and finds its own
proxy by the pid `run_start` records, so two runs on one host do not
collide (two at once were run to show it).

- **Grammar:** 38 checks, each in both C parsers, and `varek policy show`: the three directives,
  their refused forms (before 1.26, twice, bad or repeated ports, more than
  16, `proxy inspect`, an https upstream, credentials, a path, an IPv6
  address, ports or an upstream without `proxy on`).
- **The proxy process:** 10 checks. Its user, capabilities, bounding set,
  no-new-privileges and open descriptors; that the agent cannot reach its
  listener; gone when the run ends and when the Warden is killed; never the
  agent's user, never root.
- **Synthetic addresses:** 20 checks, including a wildcard name past its
  `names=1` budget (no charge), nothing asked upstream, and four forged
  streams the audit refuses.
- **The hand-off:** 15 checks: synthetic and unallowed addresses on both
  proxied ports, a denied address, a numeric rule dialed directly, an
  unproxied port, UDP, an unannounced connection, and six forged streams.
- **What the proxy reads:** 18 checks, with real ClientHellos from Python,
  `openssl s_client`, curl and Node, each outcome through the proxy, and a
  client sending a byte at a time.
- **The decision:** 20 checks against real TLS and HTTP servers: urllib,
  TLS by an exact and a wildcard name (the server sees the SNI), TLS inside
  CONNECT, pipelined HTTP requests (one for another host is not sent); a
  `Host` the policy refuses, a name that does not resolve, one past its
  budget, one resolving only to loopback, one whose address a rule denies,
  two whose only answers are IPv4-mapped; seven forged streams.
- **Close records:** 11 checks, including a relay held open past the run's
  end, the proxy killed mid-relay, and four forged streams.
- **The audit's cross-checks:** 9 checks, including a UDP connect a name
  allows (refused) and one a numeric rule allows (dialed), the Warden
  refusing `proxy on` unprivileged, and five forged streams.
- **The upstream:** 15 checks chained to Squid 6: TLS and HTTP through the
  tunnel, Squid's own 403, a name the policy refuses that Squid never sees,
  an upstream by host name, and five forged streams.

**The parsers under sanitizers.** `make fuzz-proxy-parse` runs 65 vector checks
and 4,000,000 mutated inputs (ClientHellos, HTTP requests, CONNECTs,
chunked bodies and upstream replies, cut at random lengths) under ASan and UBSan with no fault;
CI runs it. A coverage-guided libFuzzer target is included for hosts whose
clang has the runtime.

**Regression.** Against the v1.25.0 Warden, parsers and audit, the suite
fails 147 of its 156 checks. Seven are not run: they test the proxy's
parsers, which v1.25.0 does not have. The other 2 pass trivially, because
the old Warden refuses every `require warden 1.26` policy, so nothing in
that run is asked upstream. Of the failures, 26 are grammar checks of
refused forms: v1.25.0 refuses them too, but as a policy needing a newer
Warden or a bad rule, not for the reason the check names.

`make crosscheck` passes with 0 disagreements, with the proxy directives,
upstreams among them, valid and malformed, in the fuzzed policies.

## 24 hours against three CDNs

Passed. `tests/soak_v1260/soak.sh` fetches, one request a minute for 24
hours, PyPI's JSON API (Fastly), Cloudflare's IP list API and trace endpoint
over HTTPS (one by a wildcard rule) and plain HTTP (Cloudflare), and AWS's IP
ranges (CloudFront). The third fetch, and every tenth after it, is a probe:
`pypi.org`'s address with SNI `example.org`, which must be refused.
`soak_check.py` matches every fetch to its decision and close, and runs the
audit. A 3-minute trial on the droplet fetched each API through the proxy
and passed the audit; the harness's probe schedule was fixed after it, and
a second trial passed (2 fetches, 1 probe refused and recorded). The
24-hour run started 2026-10-08 from commit 54e1b68, which reports itself
as `1.25.0` (the version was raised to `1.26.0` after it started). It is the
code before the review's fixes; its request gate on plain HTTP, the
mapped-address refusal and the proxy's hardening are not in it.

It ran 24.00 hours on a 1-vCPU, 1 GB droplet and `soak_check.py` passed:

- 1,296 fetches, all 1,296 succeeded; 21,245 records.
- No fetch the policy allows was refused, and none lacks its decision or
  its close: 1,440 hand-offs and 1,440 proxied decisions, 1,296 closes
  (all `closed`), relaying 956,561 bytes up and 27,129,035 down.
- 144 probes (`pypi.org`'s address, SNI `example.org`): all 144 refused and
  recorded.
- `varek_audit.py` passed on the whole stream.

Per name, the Warden's time from the proxy's report to the socket passed
back (the decision, the certificate, and the dial to the CDN, which the
local latency test below does not include) and the agent's whole request,
p50 / p99:

| Name | Fetches | Warden, decision and dial | Agent's request |
|---|---|---|---|
| `api.cloudflare.com:443` | 259 | 2,891 / 7,782 µs | 88 / 215 ms |
| `ip-ranges.amazonaws.com:443` | 259 | 2,912 / 7,981 µs | 54 / 70 ms |
| `pypi.org:443` | 260 | 2,324 / 7,737 µs | 52 / 67 ms |
| `www.cloudflare.com:443` (wildcard rule) | 259 | 2,857 / 6,344 µs | 60 / 79 ms |
| `www.cloudflare.com:80` (plain HTTP) | 259 | 2,803 / 7,109 µs | 8 / 20 ms |

## Latency

`make latency-v1260` (`tests/latency_v1260.sh`) times 1,000 whole requests
of each kind, one after another, each a new connection (TLS: a full
handshake with RSA 2048), against servers on the machine's own address, on
a 4-vCPU cloud container (`varek/v1_4/tests/latency_v1.26.0.txt`),
microseconds, measured by the client.

| Request | p50 | p90 | p99 |
|---|---|---|---|
| TLS, no Warden | 3,852 | 5,164 | 9,484 |
| TLS under the Warden, dialed directly (numeric rule) | 4,310 | 5,629 | 10,472 |
| TLS through the proxy, by name | 5,277 | 6,881 | 9,405 |
| TLS through the proxy and a Squid upstream | 6,180 | 8,092 | 16,431 |
| HTTP, no Warden | 524 | 715 | 1,329 |
| HTTP through the proxy, by name | 875 | 1,192 | 2,724 |
| A connect handed to the proxy, nothing sent | 272 | 390 | 564 |

The proxy adds about 1.0 ms to a TLS request over a direct dial at the
median, and 0.35 ms to an HTTP request. From the Warden's records: deciding,
certifying and dialing take 105 µs at the median (p99 234 µs), and the
hand-off 275 µs. The rest is the proxy reading the first flight and
relaying.

## Compatibility

- Every v1.25 policy loads unchanged and behaves as on v1.25.0. Nothing
  changes without `proxy on`.
- With `proxy on`, the Warden must run as root (the proxy runs as its own
  user). New options: `--proxy-as USER|UID:GID`.
- New records: `synthetic_address`, `proxy_close`, and decision records with
  `"action":"net.proxy"`. New rules: `synthetic_address`, `proxy_handoff`
  (`_in_progress`, `_failed`), `proxy_tcp_only`, `proxy_dialed`,
  `proxy_dial_failed`, `address_refused`, `run_ended`.
- New fields: `run_start`'s `proxy` (mode, listener, user, ports,
  upstream); on hand-offs `proxy_handoff`, `proxy_conn` and `proxy_from`;
  on decisions `proxy_conn`, `proxy_kind`, `dialed` and `upstream`;
  `dns_question`'s `synthetic`, and `"transport":"proxy"` for a lookup the
  Warden made to dial a proxied request.
- `vdp_cert_check` has a `proxy` mode: `off`, or `on` with the proxied
  ports and the upstream.
- `varek policy show` names the proxy, its ports and its upstream, and says
  when a wildcard's names leave the host with the proxy on.
- `run_start`'s `proxy` carries the proxy's `pid`.
- `run_start` reports the Warden as `1.26.0` (so does `varek version`),
  and the startup message reports the policy grammar as v1.26.

## Found in review

Four AI review agents (Claude), separate from the session that wrote the
code, each reviewed one part of v1.26 at commit 54e1b68 and had to
reproduce every finding:
- the proxy process and its parsers;
- the Warden's decision path and the hand-off;
- the three policy parsers and the audit;
- the design's stated protections, end to end.

The agents are the same kind of model that wrote much of this code, so this
is not an independent human review. It found real defects, listed below,
but it does not replace a human or third-party review.

Every finding below is fixed unless it says otherwise. `make test-v1260` or
`make fuzz-proxy-parse` covers each where a test can, and each was re-run
against the reviewers' own harnesses after the fix. The three it cannot
easily stage (a proxy that misbehaves, one that stops reading, a relay that
spins) were checked with those harnesses.

**Reaching what the policy refuses.**
- **An IPv4-mapped AAAA answer passed every address check (high; found by
  two agents).** A name whose AAAA answer is `::ffff:a.b.c.d` was dialed
  over an IPv6 socket, which reaches the IPv4 address, after the loopback,
  metadata and deny-rule checks had looked at the IPv6 form. Whoever
  controls an allowed name's DNS (any name under a wildcard) could have
  pointed the Warden at the host's loopback or the metadata service.
  IPv4-mapped and IPv4-translated addresses are now special: a name never
  leads to them, and the audit refuses a dial to one.
- **Plain HTTP was checked on its first request only (high).** Later
  requests on the same connection, pipelined or kept alive, reached the
  server with any `Host`. The proxy now reads every request: each head must
  name the host and port decided, and each body is passed as its framing
  says (`Content-Length` or chunked; both, either twice, another transfer
  coding, or a protocol upgrade is refused). At a request for another host
  the proxy stops: what came before is answered, nothing after is sent, and
  the close is recorded `refused_request`.

**The proxy, which the Warden trusts less than itself.**
- **One report could be decided many times (medium).** The Warden checked
  only that a report's connection id had been given out, so a misbehaving
  proxy could make it decide and dial one hand-off over and over (2,035
  dials in 30 s in the reviewer's run). The Warden now keeps each hand-off's
  state and port: one report each, on the port the agent connected to (a
  CONNECT names its own); anything else stops the run.
- **The run-end flush could hang the Warden (medium).** It was the one send
  to the proxy that blocked; a proxy that stopped reading held the run's
  end forever. It no longer blocks; on failure the open relays are recorded
  `unreported`.
- **A busy loop (medium).** A relay whose server had closed or reset, with
  a client not reading, woke the proxy's loop again and again, for up to an
  hour. A side that can make no progress is no longer polled.
- **Descriptors (medium).** The proxy kept the inherited limit, often
  1,024, below the two each relay needs; at the limit it spun and agents'
  connects hung. It now raises its own limit (and holds fewer connections
  if it cannot), and refuses a connection it has no descriptor for, using
  one held in reserve, so the agent's connect fails rather than hangs.
- **A byte at a time defeated the 10 s limit (low).** The deadline is now
  checked on every pass.
- **Reports dropped (low).** A report the control socket had no room for
  was dropped, and its connection waited unrecorded. Reports now block, as
  close reports do; the Warden reads them on every pass of its loop and
  never blocks sending to the proxy.
- **An allowed connection whose client had gone left no close (low).** It
  was recorded `unreported` at the end, as if the proxy had failed; it is
  now reported `client_gone`.

**Budgets.**
- **A wildcard's name could be charged twice (low).** The stub and the
  upstream path kept separate lists of the names charged, so a name charged
  by one was charged again as new by the other. It failed closed. They now
  share one.

**The audit accepted forged streams.** These are streams edited by someone
who can recompute the chain, as in the v1.25 review.
- **A refused decision recorded as dialed (high).** A `net.proxy` record
  that said DENY, with the rule and close of a dialed connection, passed.
  The decision and its rule must now agree, and only an allowed decision
  counts as passed on.
- **A dial to an address a rule denies (high).** Each address a proxied
  connection dialed is now asked of the policy.
- **A wildcard's name sent to an upstream uncharged (high).** With an
  upstream there is no resolution record to tie a name to its question;
  each such name must now have been charged before its decision.
- **An upstream given as an address, "resolved" to another (medium).** It
  must be dialed as given.
- **A hand-off without its candidates (medium).** The policy could not be
  asked again; candidates are now required.
- **Smaller:** a malformed connection id crashed the audit; a decision on
  another port than its hand-off's, and hand-offs with a rule or address the
  Warden does not write, passed. All are refused now.

**The parsers: no disagreement.** The decision procedure, the certificate
checker and the cross-check oracle agreed on 230,000 mutated policies
(about 6,000 accepted, the upstream forms among them), under ASan and
UBSan.

**Documented, not changed.**
- With an upstream, the address checks are the upstream's (Known limits).
- The proxy decides on the `Host` (or SNI) the client sends, not on the
  name the agent looked up. The design said a differing `Host` was refused.
  The name decided is the name dialed, so no other host is reached; the
  design now says so.
- The shared-address gap is closed on proxied ports only (Known limits).
- A hand-off recorded with hashed candidates is still not asked of the
  policy again by the audit (Known limits).

**The test suite.** Two agents' runs collided with each other's on the
shared host, through `test_v1260.sh`'s fixed paths and its search for the
proxy by its user. Both were fixed before the review ended (85d67c6).

## Known limits

- **Inside TLS, SNI mode reads only the ClientHello.** A request inside
  TLS can carry a `Host` for another site on the same content network
  (domain fronting), and later requests on a kept-open TLS connection can
  name another host. Both reach only the server the allowed name resolved
  to. Most CDNs refuse a `Host` that does not match the SNI; inspecting mode
  (v1.26.1) decides every request. Plain HTTP is read request by request
  (each must name the host decided), and a protocol upgrade (WebSocket,
  h2c) over plain HTTP is refused.
- **The shared-address gap is closed on proxied ports only.** On other ports
  connects are decided on addresses, as in v1.24.
- **QUIC is refused on proxied ports** unless a numeric rule allows the
  address; only TCP is handed to the proxy. Clients fall back to TCP.
- **Encrypted Client Hello is refused**: the proxy cannot see the name. So
  is a ClientHello without SNI.
- **The byte counts are the proxy's report**, not measured by the Warden.
  They say how much was relayed, not what.
- **The upstream is `http://` only, without credentials**: the hop to it is
  not encrypted, and an upstream that needs authentication must allow the
  host by address. Every kind goes through `CONNECT`, so the upstream must
  allow `CONNECT` to the proxied ports (Squid's default allows only 443).
- **With an upstream, address checks are the upstream's.** The Warden
  never sees the address the upstream dials, so its refusal of loopback,
  link-local and metadata addresses, and deny rules on addresses, do not
  apply to names sent to an upstream; the decision on the name and every
  deny on a name do. Configure the upstream to refuse those addresses.
- **With an upstream, exact names are still resolved by the Warden at
  startup** (direct connects and deny rules use them). Where only the
  upstream can resolve them, the Warden reports them as not resolving and
  goes on.
- **A hand-off recorded with hashed candidates** (an address with more than
  16 names) is not asked of the policy again by the audit. It reaches only
  the proxy's listener; the decision on the name it asks for is certified on
  its own.
- **Synthetic addresses are IPv4**, 131,070 names a run; past that, a new
  proxied-only name gets SERVFAIL.
- **Shared-domain lists, deny wildcards and the name channel** are as in
  v1.25.0. With the proxy on, a wildcard's names reach the upstream DNS only
  when the Warden dials a request the policy allowed, charged to the same
  budgets.

## Upgrading

1. Add `require warden 1.26` and `proxy on` to the policy. Set `proxy
   ports` if the agent uses ports other than 80 and 443.
2. Create the proxy's user (`useradd --system varek-proxy`), or pass
   `--proxy-as`. Run the Warden as root.
3. To chain to an existing proxy, add `proxy upstream http://HOST:PORT`,
   and allow `CONNECT` to the proxied ports there.
4. Run `varek policy check <policy>` and a short run, and read the
   `net.proxy` records and `varek audit`.
