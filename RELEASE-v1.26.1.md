# VAREK v1.26.1 — The Egress Proxy's Inspecting Mode

> The review was done by AI review agents; a human or third-party review
> has not been done.

Released 2026-10-10 · MIT · github.com/kwdoug63/varek

## Summary

v1.26.0 decides a proxied connection on the name the client asks for, but
inside TLS it reads only the ClientHello. Once a name is allowed, any
request on the connection goes through: any method, any path, and (domain
fronting) a `Host` for another site on the same content network.

From v1.26.1 a policy can have every request decided:

    require warden 1.26
    proxy inspect
    allow host api.example.com:443
    deny  request * https://api.example.com/v1/admin/**
    allow request GET https://api.example.com/v1/models
    allow request GET https://api.example.com/v1/files?limit=*
    allow request POST https://api.example.com/v1/chat/completions max_body=256k

The connection is decided on its name as in SNI mode. Then the proxy
verifies the server, answers the agent with a certificate from a CA made for
the run, and holds each request until the Warden has decided it.

1. **Grammar.** `proxy inspect` (in place of `proxy on`), `allow|deny
   request METHOD URL [max_body=N]` and `proxy passthrough host NAME`, after
   `require warden 1.26`, in the decision procedure, the certificate checker
   and the cross-check oracle. A request rule is a glob over the object
   `METHOD scheme://host:port/path?query`: a `*` method is any method, a
   `*.suffix` host a wildcard, the port filled in, `*`, `**` and `[...]` in
   the path wildcards, `?` the query's literal `?`. An allow rule without a
   `?` allows no query; to allow one, name it (`?limit=*`, or `?*` for any).
   A deny rule without a `?` denies its path with any query. A rule's path
   is held to the forms the proxy accepts (below). `max_body=N` (with `k` or
   `m`, at most 1 GiB) bounds an allowed request's body. Request rules need
   `proxy inspect`, a proxied port, and a host that is not a passthrough
   host; `vdp_check lint` and the Warden report a request rule no host rule
   reaches.
2. **`warden-proxy`, its own binary.** The proxy, its parsers and its TLS
   are now a separate program that links OpenSSL; the Warden does not. The
   Warden finds it beside its own binary or at `--proxy-bin PATH`, refuses
   one that is not a regular ELF file or is writable by others, copies it
   into a sealed memfd while hashing it, and starts it from there with
   `fexecve`, so what runs is what `run_start` names
   (`proxy_binary_sha256`). It drops to its own user itself and runs only
   when the Warden starts it.
3. **The run's CA.** Made in the proxy before the agent starts: ECDSA P-256,
   `CN=VAREK run CA <run id>`, CA with path length 0, and critical name
   constraints that permit the names the policy lets the agent reach on
   proxied ports (a wildcard's suffix) and exclude the passthrough hosts and
   every IP address. Valid from five minutes before the run for seven days.
   Its key is in OpenSSL's secure heap where the memory-lock limit allows
   (`run_start` says whether it was), the proxy is not dumpable, and nothing
   is written to disk.
4. **The agent trusts it.** The Warden serves, read-only, the host's bundle
   with the run's CA after it at the four system bundle paths and
   `/etc/varek/run-bundle.pem`, the CA alone at `/etc/varek/run-ca.pem`, and
   a PKCS#12 trust store for Java at `/etc/varek/run-trust.p12`, whether or
   not those files exist on the host; `stat` and `access` on them answer for
   the view (a read-only file of its size). The agent's environment names
   them (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
   `NODE_EXTRA_CA_CERTS`, and `JAVA_TOOL_OPTIONS` after any options already
   there). Python, curl, Node.js and Java trust the CA without changes.
5. **Terminating TLS.** The proxy first verifies the server, over the socket
   the Warden dialed (or inside an upstream's `CONNECT` tunnel): TLS 1.2 or
   later, the name decided checked in the certificate's subject alternative
   name (no partial wildcards, never the CN), against the host's bundle or
   `--trust-bundle PATH` (for example with a corporate CA). A server that
   fails is refused before the agent's handshake is answered (`server_tls`,
   with OpenSSL's reason). Then the agent's handshake, with a leaf for the
   name: TLS 1.2 or later, ALPN `http/1.1` only, no session tickets or
   cache, no renegotiation. A server whose TLS ends without close_notify
   ends the agent's without one too.
6. **Each request decided.** The proxy reads each request's head (8 KB),
   refuses what a server could read another way, and reports the object;
   nothing of the request is sent until the verdict. Refused targets: `.`
   and `..` segments, `//`, `\`, `;`, `#`, bytes outside 0x21 to 0x7e,
   percent-encoded `/`, `\` or unreserved bytes, bad escapes, a second `?`,
   any form but origin-form (or absolute-form for the connection's own
   authority), a `Host` other than the connection's name and port, objects
   over 4,095 bytes, and ambiguous framing. The Warden checks the object's
   form again itself, decides it with the SMT decision procedure, and the
   certificate checker must accept the certificate. A refusal ends the
   connection: the answers to earlier requests are relayed, then the agent
   gets `403` with a one-line reason. Pipelined and kept-alive requests are
   each decided in turn. Plain HTTP to an inspected host is decided the same
   way, on its `http://` object.
7. **Bodies.** A declared length over the allowing rule's `max_body` is
   refused before a byte is sent; a chunked body is sent up to the limit and
   the connection cut there. Each allowed body's length and SHA-256 (as
   sent, a chunked body's framing included) are recorded; one cut short by
   the agent's close is recorded as `incomplete`. Bodies are never stored.
8. **Passthrough hosts.** `proxy passthrough host NAME` keeps a host in SNI
   mode, for clients that pin its certificate: decided on its name,
   relayed, not inspected, and recorded so.
9. **Records and the audit.** One chained `net.request` record per request
   (the connection, its number, the object, the decision, the rule line,
   the certificate, the body's framing), one `request_body` per allowed
   body, and each `proxy_close` of an inspected connection says how many
   requests it carried, the server certificate's SHA-256 and any TLS or
   request error. `run_start` records the trust setup (the host's bundle and
   its SHA-256, the CA's and the trust store's SHA-256, how many names the
   CA may sign for, whether its key was locked) and `warden-proxy`'s
   SHA-256. `varek_audit.py` checks each request belongs to a connection
   passed on to be inspected, in order, before its close, in a form the
   proxy must accept, an object of that connection; re-checks each allowed
   request's certificate and asks each refused one of the policy again;
   checks each body against its rule and its declared length, each close's
   count, and each trust view and record in `run_start` against the policy.
10. **Tools.** `varek refusals` explains a refused request with its rule
    line (`UNSATISFIED`, `UNKNOWN`, `MAX_BODY`) and lists the connections
    the proxy ended itself (its parser, a server failing verification, the
    agent's failed handshake, a body cut at `max_body`). The CycloneDX
    export names the proxy's mode, `warden-proxy`'s and the CA's SHA-256,
    and the request and body counts, and lists each allowed request as an
    authorized object. `varek bench --proxy` measures HTTPS requests
    natively, in SNI mode and in inspecting mode. `varek policy show` names
    inspecting mode, passthrough hosts and request rules; `varek doctor`
    checks for `warden-proxy`.

Per-call verdicts on file opens, lookups, launches and connects are
unchanged, and so is the symmetric-suppression invariant (**no extension
may move a genuinely unsafe action to SATISFIED**). Every v1.26.0 policy
behaves as on v1.26.0; `proxy on` is SNI mode, as before.

## Tested with real clients

`make test-v1261` runs 193 checks; CI runs it, with the Warden as root. It
uses local TLS and HTTP servers that log and hash what reaches them, so each
check compares what the policy decided with what the server got:

- **Grammar** (section 1): each form and refusal in both C parsers, the
  globs, decisions with their certificates re-checked by the checker
  (among them the review's: a wildcard reaching across the query's `?`, a
  deny rule passed with a query), lint, `varek policy show`.
- **`warden-proxy`** (2): the program refusing to run by hand, its
  libraries, its hash in `run_start` equal to the file's, the file replaced
  mid-run without effect, each refused binary.
- **The CA and the trust views** (3): the proxy's memory, each view and its
  read-only answers, the environment, the CA's form, name constraints and
  validity, Python trusting it, Java opening the store.
- **Terminating TLS** (4): a verifying Python client, the leaf and its
  reuse, ALPN, a client that pins its own root, TLS inside `CONNECT`, a
  server of the wrong name and a self-signed one, a passthrough host, plain
  HTTP, curl, Node.js and Java with no settings of their own, a Squid
  upstream.
- **Request decisions** (5): a kept-alive connection (two allowed, one
  denied, one never sent), pipelining, a request no rule allows, a query, a
  later request for another `Host`, bodies within, declared over, and
  chunked past `max_body` (the recorded SHA-256 equal to the server's),
  plain HTTP.
- **The audit and tools** (6): close counts, `varek refusals`, the export.
- **The review's fixes** (7): a server's TLS dropped without close_notify, a
  CN-only server certificate, the views' mode, a cut body's bytes as the
  server got them, a half-closing agent, an incomplete body, a second `?`.
- **The bench** (8): `varek bench --proxy`, with a bound on the time a new
  inspected connection adds.

Forged streams, in sections 2 to 7: 25 of them, 23 the audit must refuse (an
allowed request the policy refuses, a body over its rule, a request out of
order or after its close or on an uninspected connection, a close whose
count disagrees, a refusal at the wrong line, a trust view outside
inspecting mode, a `view_metadata` answer to `access(W_OK)`, a CA claiming
names the policy does not give it, and more), one the export must refuse
(trust views in a run not in inspecting mode), and one malformed record the
audit and `varek refusals` must refuse without a traceback.

The suite passes with `warden-proxy` built under ASan and UBSan.

**The parsers under sanitizers.** `make fuzz-proxy-parse` runs 66 vector
checks (the request targets of section 2 among them) and 4,000,000 mutated
inputs, about 18,000 of them read as whole requests inside TLS, under ASan
and UBSan with no fault.

**The three policy parsers agree.** `make crosscheck` passes with 0
disagreements, with request rules (valid and malformed, queries among them)
in the fuzzed policies; its SMT encoding states the query rules above. The
Warden's own target check, the proxy's and the audit's agree on 200,000
random targets.

**Regression.** Against the v1.26.0 Warden, parsers and audit (with this
release's `warden-proxy` beside it, so that no section is skipped), the
suite fails 188 of its 193 checks. v1.26.0 refuses every `proxy inspect`
policy, so nothing is decided, no CA is made and no view is served. 51 of
the failures are grammar checks of refused forms, which v1.26.0 refuses as
an unknown kind or directive rather than for the reason the check names.
Two pass: section 2's run is in SNI mode, as v1.26.0 has it, and "the
refused request never reached the server" holds trivially. Three test
`warden-proxy` itself and are not counted. `make test-v1260`, `test-v1250`,
`test-v1240`, `test-cli` and `fuzz-proxy-parse` pass unchanged.

## 24 hours against three CDNs

Passed. `tests/soak_v1261/soak.sh` runs v1.26.0's soak in inspecting mode:
one request a minute for 24 hours to PyPI's JSON API (Fastly), Cloudflare's
IP list API and trace endpoint over HTTPS (one by a wildcard host and a
wildcard request rule) and plain HTTP (Cloudflare), and AWS's IP ranges
(CloudFront), each with its own request rule. The third fetch, and every
tenth after it, is a probe, five kinds in turn, each of which must be
refused: a fronted SNI, a fronted `Host`, the allowed path with a `/./`
segment, a path a deny rule refuses, and a path no rule allows.
`soak_check.py` requires each fetch's connection, certified request and
close with its count, and runs the audit. A local trial (the same URLs,
policy and probes, served by local servers) passed: 32 fetches, 4 probes
refused, the audit passed. A 3-minute trial on the droplet passed (2
fetches, 1 probe refused and recorded). The 24-hour run started 2026-10-09
from the branch at aafcd68, which reports itself as `1.26.1`, with
`warden-proxy` SHA-256 `f8d5a945...`.

It ran 24.00 hours on a 1-vCPU, 1 GB droplet and `soak_check.py` passed:

- 1,296 fetches, all 1,296 succeeded; 19,658 records.
- No fetch the policy allows was refused, and none lacks its connection,
  its certified request, or its close and count: 1,440 proxied decisions,
  1,353 request decisions, 1,411 closes (1,296 `closed`, 115
  `refused_request`) counting 1,353 requests, relaying 290,562 bytes up and
  23,180,862 down.
- 144 probes, all refused and recorded where they must be: 29 fronted
  SNIs (the name refused), 29 fronted `Host`s and 29 `/./` paths (refused
  by the proxy's parser, nothing decided), 29 paths the deny rule refuses
  (`policy_match`) and 28 paths no rule allows (`default_deny_unknown`).
- `varek_audit.py` passed on the whole stream.

Per name, the Warden's time on the connection (the decision, the
certificate, and the dial to the CDN) and on the request (decided and
certified), and the agent's whole fetch, p50 / p99:

| Name | Fetches | Warden, connection | Warden, request | Agent's fetch |
|---|---|---|---|---|
| `api.cloudflare.com:443` | 259 | 2,739 / 5,430 µs | 15 / 38 µs | 41 / 76 ms |
| `ip-ranges.amazonaws.com:443` | 259 | 2,823 / 4,387 µs | 17 / 36 µs | 17 / 23 ms |
| `pypi.org:443` | 260 | 2,254 / 4,213 µs | 16 / 35 µs | 15 / 26 ms |
| `www.cloudflare.com:443` (wildcard rules) | 259 | 2,715 / 5,819 µs | 18 / 36 µs | 19 / 27 ms |
| `www.cloudflare.com:80` (plain HTTP) | 259 | 2,607 / 4,503 µs | 15 / 35 µs | 8 / 12 ms |

## Latency

`make latency-v1261` (`tests/latency_v1261.sh`) repeats v1.26.0's table in
SNI and inspecting mode, 1,000 requests of each kind one after another,
against servers on the machine's own address (RSA 2048 at the server), on
a 4-vCPU cloud container (`varek/v1_4/tests/latency_v1.26.1.txt`),
microseconds, measured by the client.

| Request | No Warden | SNI mode | Inspecting mode |
|---|---|---|---|
| TLS, a new connection (p50) | 3,722 | 5,829 | 6,648 |
| TLS, a new connection (p99) | 13,248 | 11,305 | 11,970 |
| TLS, kept alive, per request (p50) | 101 | 161 | 369 |
| HTTP, a new connection (p50) | 500 | 921 | 846 |
| HTTP, kept alive, per request (p50) | 56 | 120 | 217 |
| TLS through a Squid upstream (p50) | — | 7,193 | 8,028 |

Inspecting mode adds a second handshake to a new connection, about 0.8 ms
over SNI mode here, and about 0.2 ms to each request on a kept-alive
connection. From the Warden's records, deciding and certifying a request
takes 3 to 13 µs at the median (p99 at most 57 µs).
`varek bench --proxy` on the same host gave the same picture: a new
connection adds 1.1 ms in SNI mode and 3.0 ms in inspecting mode over
native, a kept-alive request 0.1 ms and 0.26 ms.

Found by the bench, before the review: a new inspected connection first
took about 45 ms more than in SNI mode. With TLS 1.3 a client sends its
Finished and then its request in a second small write; the proxy sends no
session tickets, so nothing went back after the Finished, its ACK waited the
delayed-ACK time, and the client's Nagle held the request until it came. The
proxy now asks for quick ACKs on the agent's socket during its handshake and
sends its own records at once; tickets stay off.

## Compatibility

- Every v1.26.0 policy loads unchanged and behaves as on v1.26.0. Nothing
  changes without `proxy inspect`.
- The proxy is now `warden-proxy`, installed beside `warden` (`make install`
  does it). Building it needs OpenSSL's headers (`libssl-dev` or
  `openssl-devel`); `make deps-check-ssl` says if they are missing. New
  Warden options: `--proxy-bin PATH`, `--trust-bundle PATH`.
- With `proxy inspect`, the agent's TLS clients must trust the run's CA:
  those that read the system bundle, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`
  or Java's trust store do. One that pins a certificate or brings its own
  store needs its host to be a passthrough host.
- New records: `net.request` decisions and `request_body`. New rules:
  `request_allowed`, and for refusals `policy_match`,
  `default_deny_unknown`, `certificate_refused` and `max_body`.
- New fields: `run_start`'s `proxy_binary_sha256` and `trust`, and `proxy`
  mode `inspect`; on `net.proxy`, `inspected`; on `proxy_close`,
  `inspected`, `requests`, `server_cert_sha256`, `tls_error` and
  `request_error`, with the reasons `server_tls`, `client_tls`,
  `tls_timeout` and `max_body`; `run_end`'s `proxy_failed`; the trust
  views' `trust_view`, `run_ca_view`, `trust_store_view` and
  `view_metadata` rules.
- `run_start` reports the Warden as `1.26.1` (so does `varek version`).
  The policy grammar is still 1.26: inspecting mode needs `require warden
  1.26`, as SNI mode does.
- `vdp_cert_check`'s `proxy` mode prints `inspect` and the passthrough
  hosts; its `rules` mode has an eleventh field, a request rule's
  `max_body` (kind `r`).

## Found in review

Four AI review agents (Claude), separate from the session that wrote the
code, each reviewed one part of v1.26.1 at commit 20533cf and had to
reproduce every finding (a script and its output):
- TLS termination and the run's CA;
- the request parser and the proxy's gate;
- the grammar and the Warden's request decisions;
- the audit and the tools.

The agents are the same kind of model that wrote much of this code, so this
is not an independent human review. It found real defects, listed below,
but it does not replace a human or third-party review. Every finding is
fixed unless it says otherwise, and `make test-v1261` checks each (sections 1
and 7). The full list is in the design note's "The review".

**Reaching what the policy refuses (critical).**
- *A rule's wildcard stretched across the query's `?`.* `allow request
  DELETE https://h/v1/items/*/tag` allowed `DELETE /v1/items/42?/tag`,
  which a server reads as `/v1/items/42`; `[!s]` and `/**/` did the same.
  A request now has at most one `?`, so has a rule, and an allow rule
  without a `?` holds on no request with one, in all three parsers and in
  the cross-check's SMT encoding.
- *A deny rule for a path was passed with a query.* `/v1/secret?x=1` got
  past `deny request GET https://h/v1/secret` to a broader allow. A deny
  rule without a `?` now holds on its path whatever the query.

**The audit accepted forged streams (critical and high).** An allowed
request declaring a body over its rule's `max_body`; one in a path form the
proxy must refuse (`%61dmin`, `/./`, `//`), which the Warden now also
checks itself rather than taking the proxy's word; an allowed body with no
`request_body` (the proxy now reports what was sent of a body when the
connection ends first, and the Warden requires a report for every allowed
body); a request after its connection's close; `view_metadata` where a deny
rule holds or for `access(W_OK)`; a CA claiming more names than the policy
gives it.

**TLS and the CA (medium and low).** A server's TLS ending without
close_notify reached the agent as a clean close; the name constraints left
IP addresses and the passthrough hosts under a wildcard's suffix permitted;
a chunked body cut at `max_body` sent the server nothing while the record
said it got the limit; an agent's TCP half-close lost the answer; the
views stated mode 0777; a server's name was accepted from its CN alone.

**The Warden and the tools (low).** A request after a body cut at
`max_body`, and a malformed report while the run ends (now `run_end`'s
`proxy_failed` and exit 1), were accepted; lint missed a wildcard request
rule no host rule reaches; the export counted trust views outside
inspecting mode; tracebacks on malformed fields in the audit, the export,
`varek refusals` and the soak checker.

**The parser and gate: nothing found.** The proxy's reading of smuggling
and framing vectors (Content-Length and chunked together, chunk extensions,
a body that is itself a request, pipelining) was compared with a Python and
a Go server: each executed exactly the requests the Warden allowed.

**Stated, not changed.** A chunked body's framing counts against
`max_body`; `run_start`'s `host_roots` and `ca_key_locked` are the Warden's
reports of its host, which the audit cannot recompute.

**Found by the cross-check, after the review.** With the review's query
rules, the reachability analysis (`vdp_check analyze`, lint's "can never
fire") still read each request rule as its glob alone, so it called a deny
rule dead behind an allow rule of the same glob, though the deny holds on
the path with a query and the allow on no query. Decisions and certificates
were not affected; lint could have told an operator a deny rule was dead.
The analysis now searches each rule's actual language (a rule without a `?`
as the glob's strings without one, and a deny rule also with a query
after), and `make test-v1261` checks the case.

## Known limits

- **The request line is decided, not its contents.** Headers are not
  decided (beyond `Host` and framing), and bodies only by length. What the
  agent puts in an allowed request's headers, query or body reaches the
  server the policy allows. A DLP tool behind `proxy upstream` sees only
  TLS.
- **The path and query are recorded as sent.** An API key in a query is in
  the verdict stream (bodies are never recorded).
- **The proxy sees plaintext** and holds the run's CA key. It runs as its
  own user, not dumpable; the CA lives seven days and signs only the
  policy's names.
- **Clients with their own trust** (pinned certificates, a `CApath`
  directory instead of a bundle file, an application-bundled store) fail
  their handshake unless their host is a passthrough host.
- **HTTP/1.1 only.** A client offering only h2 is refused; WebSocket and
  other upgrades are refused.
- **Passthrough hosts are not inspected**: a fronted `Host` for an
  inspected name on the same content network passes through them.
- **The trust bundle is believed**: a server any of its roots vouches for is
  taken to be the name decided.
- **Runs longer than seven days** get new leaf certificates refused once
  the CA expires.
- **The byte counts and body hashes are the proxy's report**, not measured
  by the Warden.
- SNI mode's limits (proxied ports only, QUIC and Encrypted Client Hello
  refused, an upstream's own address checks) hold as in v1.26.0.

## Upgrading

1. Install OpenSSL's headers and rebuild (`make`); install `warden-proxy`
   beside `warden` (`make install`). `varek doctor` checks for it.
2. In the policy, replace `proxy on` with `proxy inspect`, and add an
   `allow request` rule for each request the agent makes (and `deny
   request` rules ahead of broader allows). A query must be named to be
   allowed (`?*` for any).
3. For a host whose client pins its certificate, add `proxy passthrough
   host NAME`. If the host's outbound HTTPS passes through an inspecting
   proxy of its own, give its CA with `--trust-bundle`.
4. Run `varek policy check <policy>` and a short run, then read
   `varek refusals` and `varek audit`.
