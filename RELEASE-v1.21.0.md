# VAREK v1.21.0 — Decided Connections

Released 2026-09-29 · MIT · github.com/kwdoug63/varek

## Summary

Through v1.20.0 a supervised agent had no network. Every `connect` was
refused, whatever the policy said (`deny_only_nonfile_v191`), because letting
an allowed connect continue in the kernel would let a second thread change the
destination between the Warden's check and the kernel's read of it. The
sector policies' `allow host` lines were accepted and never took effect.

From v1.21.0 the Warden decides each outbound connect and carries it out
itself, the way it has handled file opens since v1.12:

1. The destination is copied once from the agent's memory.
2. It is spelt canonically: `a.b.c.d:port`, `[IPv6]:port` (an IPv4-mapped
   address as its IPv4 form), or `unix:<canonical path>` for a Unix socket
   named by a path, resolved like a file open.
3. The SMT decision procedure decides it against the policy's `host` rules;
   the independent certificate checker must accept the certificate of any
   ALLOW.
4. The Warden, which runs in the host's network namespace, makes a socket of
   the agent's kind, copies over the socket options the agent set (from a list
   of 58), and connects it to the copy it decided on. A Unix connect is made
   with the agent's uid and gid.
5. `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SETFD` puts the
   connected socket in place of the agent's descriptor (same number, the
   agent's close-on-exec and non-blocking state), and the agent's connect
   returns what its own would have.

The kernel never reads the agent's sockaddr, so the race stays closed: in
`make test-v1210`, 2,000 attempts to swap the destination from an allowed one
to a denied one after the check reached the denied side 0 times. The agent's
own network namespace stays empty; the only way out is a socket the Warden
made.

Covered: TCP and connected UDP over IPv4 and IPv6, and Unix stream, datagram
and seqpacket sockets named by a path. IPv6 decisions are tested; IPv6
**dialing was not exercised** on the release host, whose kernel has no IPv6
(the test reports that case as SKIPPED, and the summary line says so).

The plan gate decides `net_connect` steps like the connect they name instead of
refusing them all. Host names (`allow host api.example.com:443`) are the next
stage of this release line; the design is in
[`docs/security/v1.21-stage2-host-names.md`](./docs/security/v1.21-stage2-host-names.md).

Per-call verdicts on file opens, lookups and launches are unchanged, and so is
the symmetric-suppression invariant (**no extension may move a genuinely
unsafe action to SATISFIED**).

## Tested with real clients

`make test-v1210` (90 checks) runs, as the agent under the Warden:

- a probe (`tests/v1210_probe.c`) covering TCP, UDP, Unix, IPv6 decisions,
  non-blocking and slow connects, `EISCONN`/`EALREADY`, a descriptor replaced
  while its connect waited, sends, binds, socket options and the swap race;
- `curl`, Python `requests` (HTTP and verified TLS), raw Python TLS, Python
  Unix and UDP sockets, and Node.js `http`, `https`, `tls`, `net` and `dgram`;
- a live CDN fetch by address (pypi.org) with curl, Python and Node, where the
  host can reach it;
- the records and their audit: every ALLOW carries a certificate the checker
  accepted, `varek_audit.py` re-checks each connect's certificate, and a
  record rewritten to name another destination fails the audit;
- the plan gate, the sector policies' new rules (4b) and the preflight's new
  checks (4c);
- the per-connection latency, below.

## Latency

One connect after another to a local listener, natively and as the agent, on a
2-vCPU host where the clients and servers share the CPUs
(`varek/v1_4/tests/connect_latency_v1.21.0.txt`). Microseconds.

| Client | native p50 | Warden p50 | Warden p99 | Warden's own time p50 (record, minus the dial) |
|---|---:|---:|---:|---:|
| C, blocking TCP (n=3000) | 7 | 93 | 170 | 59 |
| C, non-blocking TCP (n=3000) | 8 | 85 | 171 | 54 |
| C, Unix stream (n=3000) | 2 | 98 | 201 | 55 |
| Python `socket.create_connection` (n=500) | 30 | 112 | 217 | 62 |
| Python `requests.get`, whole request (n=200) | 1,209 | 1,379 | 2,382 | 250 |
| Node.js `net.connect` (n=500) | 44 | 168 | 1,509 | 84 |

At the median a connect took about 75 to 125 µs longer than a native one, and
more at p99; a whole `requests.get` to a local server took 0.17 ms longer. The
figures vary by about a third from run to run on this host (an earlier run
measured 88 µs for C blocking TCP and 67 µs for Unix). A profile of the
Warden's part put about 2 µs in the decision and certificate check, 6 in
reading and copying socket options, 8 in the dial itself (loopback), 10 in the
handover and 3 in the record; the rest is the notification round trip and
scheduling. A connection that crosses a real network adds the same fixed cost
to a much larger dial.

## Sends, binds and the filter

- **Sends.** A send that names a destination (`sendto` with an address,
  `sendmsg`/`sendmmsg` with `msg_name`) is still refused whatever the policy
  says: an unconnected datagram cannot be decided without a race on its
  address. A send with no destination goes to the peer of a connect the Warden
  decided. `sendto` with a NULL address is admitted by the filter (the address
  is a register) unless it sets `MSG_FASTOPEN`; `sendmsg`/`sendmmsg` carry
  their address in the agent's memory, so the Warden reads each message once
  and sends it itself, with no address and no control data, on TCP and UDP
  sockets. Through v1.20.0 every `sendto` was refused.
- **Bind.** libuv, so Node.js, binds every UDP socket to the wildcard address
  and port 0 before connecting it. That one form is performed by the Warden on
  the agent's socket from the copy it read; it is not recorded. Every other
  `bind` is refused (`EPERM`) and recorded; `listen` and `accept` stay
  refused.
- **Routing options.** `setsockopt` of `IP_OPTIONS` (source routing),
  `IPV6_RTHDR`, `IPV6_2292RTHDR` and `IPV6_2292PKTOPTIONS` is refused
  (`EACCES`) by the filter on every socket: each could send a connected
  socket's packets to an address other than the decided peer. The rules
  compare only the low 32 bits of `level` and `optname`, as the kernel reads
  them; libseccomp's 32-bit argument macros truncate only the constant, so an
  ordered 64-bit comparison would have let `41 | 1 << 40` through (found in
  development, tested by `rthdr_hibits`).
- **io_uring.** `io_uring_setup` answers `ENOSYS` instead of killing the agent,
  so libuv (Node.js 20 and later) falls back to epoll. No ring can be created,
  so `io_uring_enter` and `io_uring_register` stay in the hard-deny set.

## Records

A `net.connect` record carries `"target"` (as the agent spelt it),
`"resolved"` (the canonical destination decided and dialed), `"sock"` (tcp,
udp, unix-stream, unix-dgram, unix-seqpacket), `"dial_us"` and, for an ALLOW,
the certificate and `"check":"ok"`. `latency_us` minus `dial_us` is the
Warden's own time. New rules: `dialed_fd_injection`, `dialed_in_progress`,
`dial_failed`, `socket_option_failed`, `too_many_pending`, `already_connected`,
`dialed_descriptor_replaced`, `requester_gone`, `injection_failed` (ALLOWs
that did or did not deliver a socket), and the refusals `bad_address`,
`unspec_refused`, `family_refused`, `not_a_socket`, `socket_kind_refused`,
`scope_id_refused`, `unix_abstract_refused`, `resolution_failed`,
`bind_refused`. `varek_audit.py` accepts certified connects as authorizations
and re-checks their certificates; the CycloneDX export lists the connected
destinations.

## Open items closed

From the "Every limit, sorted" list:

- **Sector policies, case.** The key and credential rules in all five sector
  policies spell each letter as a class of both cases and are anchored:
  `server.PEM`, `x.pem.bak`, `x.key~`, `.ENV.local` and `id_rsa` outside
  `.ssh` were allowed and are now refused; `serverpem`, `x_pem` and
  `j.pemberton.json` are not refused (an earlier draft's unanchored patterns
  refused patient files such as `records/j.pemberton.json`). The healthcare
  policy's psychotherapy and decedent directories match in any case.
- **Descriptor provenance.** `bypass-classes.md` credited an fd-provenance
  invariant the code does not implement. Rows 3 and 8 and the v1.10 roadmap
  are corrected, a "Descriptor provenance" section says what holds (every
  descriptor on a file and every connected socket is acquired through a
  mediated call, and the agent cannot send descriptors) and what does not
  (receiving one from a peer the policy allows is not checked), and the
  comments in `warden.c` and `v1_7/warden_seccomp_baseline.c` now point there.
- **`allow host` lines.** Marked in the sector policies as taking effect from
  v1.21. The sample `deny host evil.example.com` in `policy.txt`, which never
  fired, is a numeric rule, and the v1.6 integration test, the demo cast and
  `test_v1124.sh` use numeric rules. A host rule naming a host is reported at
  load as one that can never match, and `vdp_check lint` counts it.
- **`pyproject.toml`.** The description names what the package is, and the
  `seccomp_bridge` module, never in the repository, is removed.
- **Breaker header.** "N" versus "N−1": the header, the config header, the
  sample configuration and the v1.8.2 changelog say that the Nth refusal is
  terminal.
- **`RESOLVE_NO_MAGICLINKS`.** `/proc/self` is an ordinary symlink, not a magic
  link. Corrected with dated notes in `RELEASE-v1.12.0.md`,
  `RELEASE-v1.12.3.md`, `CHANGELOG.md`, the threat model, `bypass-classes.md`,
  the spec paper, `warden.c` and the tests' comments: `RESOLVE_NO_SYMLINKS`
  refused it in v1.12.0 to v1.12.2, and from v1.12.3 a leading `/proc/self` is
  mapped to the agent and any other process's `/proc/<pid>` is refused after
  resolution.
- **Preflight.** `tools/varek_preflight.sh` takes `--flow-policy`,
  `--breaker-state`, `--gate-status` and `--session` and checks them with the
  Warden's own startup code (`warden <policy> --check-startup ...`), so a
  deployment it passes no longer refuses to start over the plan gate's
  configuration or count file.

## Compatibility

- **Policies.** `allow host` rules now take effect. A policy that allowed
  hosts on the assumption that nothing could connect now lets the agent reach
  them. Review every `allow host` line before upgrading.
- **Portless host rules.** A host constant without a port (`allow host
  127.0.0.1`) matches any port only when it is a dotted-quad IPv4 address or a
  bracketed IPv6 one. Through v1.20.0 any colon-free constant did, so
  `allow host unix` would have matched every Unix socket. The grammar version
  is 1.21 (`require warden 1.21`).
- **Plans.** An allowed `net_connect` step is now SATISFIED; a step no rule
  matches is UNKNOWN (it was UNSATISFIED); a host-name step is UNKNOWN with the
  reason.
- **Filter.** `sendto` with no address and `setsockopt` of ordinary options
  work; the four routing options above get `EACCES`; `io_uring_setup` gets
  `ENOSYS`; a wildcard, port-0 bind succeeds.
- **Records.** `run_start` says `"warden":"1.21.0"`; the default policy version
  is `1.21`. Connect records gain `"sock"` and `"dial_us"`.
- **Warden.** `--check-startup` checks the startup conditions and exits. The
  Warden raises its own descriptor limit after forking the agent.
- **Lint.** `vdp_check lint` exits 1 when a host rule can never match a
  connect.

## Found in review

Two independent reviews read this release before publication: one of the code
for security, one of every claim against the code. Both ran the suites.
Everything they confirmed is fixed here and covered by a test where it could
be.

Security review. No breakout, egress to an undecided destination, credential
escalation, filter bypass or record forgery was found. It found:

- A connect or send waiting in the Warden holds a socket, and a send its data;
  the table was bounded by count only. It is now bounded by count (1,024, and
  an agent thread waits in one call at a time) and by bytes held (32 MiB);
  past either the call gets `ENOBUFS` (`too_many_pending`).
- A blocking connect that reaches `SO_SNDTIMEO` returns `EINPROGRESS` and keeps
  connecting, to the decided destination, as the kernel does. Documented in the
  threat model.
- Buffer sizes are applied as the kernel clamps them, not refused; the comment
  that said otherwise is corrected. The socket's kind, options and flags and
  the agent's uid and gid are read after the decision; none can change the
  destination, and the header now says so.
- The credential switch around a Unix connect runs no other work; a comment
  states that invariant for future changes.

Claims review. It found:

- `allow host unix` was reported as a rule that "can never match" while it
  matched every Unix socket (and the plan gate authorized
  `net_connect unix:/var/run/docker.sock` under it). Fixed in both parsers and
  the cross-check oracle as above, with tests.
- `IPV6_2292PKTOPTIONS` was admitted; it can install a type 2 routing header.
  Now refused with the other routing options.
- A second blocking connect on a socket whose first was still waiting in the
  Warden was dialed, and the first connect's handover then replaced the
  second's socket. It now gets `EALREADY`, and a connect whose descriptor was
  replaced while it waited leaves the new descriptor alone
  (`dialed_descriptor_replaced`); `varek_audit.py` accepts that rule.
- The first draft of the sector-policy globs matched only names extended
  after the extension and refused unrelated names (`j.pemberton.json`); now
  anchored, with tests of both sides. The healthcare decedent directory was
  still case-sensitive; fixed.
- The v1.6 integration test failed (it used a host-name rule and expected the
  old refusal), as did the claim of socket options "carried over or the
  connect fails" (only the listed ones are compared; the list grew from about 45 to
  58 and the docs say what is not carried).
- Stale statements: connects called deny-only in the verdict harness, the spec
  paper, the threat model and `target_conformance.c`; the trusted computing
  base missing the new Warden code and the audit's connects; the stage-2 plan's
  `require warden 1.21.1` (v1.21.0 refuses it as malformed, which is the
  refusal wanted; now stated) and `nameserver 127.0.0.1` (the Warden dials in
  the host's namespace, where that may be a real resolver; the plan now names
  an address reserved for documentation and refuses port 53); IPv6 dialing
  claimed but untested here; the release notes cited before they existed; the
  preflight header, usage text, examples and test comments.

## Known limits

- **Where, not what.** VAREK decides where an agent may connect. An allowed
  host is a channel: the agent may send it anything, including data it may
  read. What it sends is for the service, or an egress proxy or DLP tool in
  front of it.
- **Addresses, not names.** Rules match the numeric address dialed. Names are
  stage 2. On a shared CDN address, allowing one address allows every site
  served from it.
- **IPv6 dialing** is untested on the release host.
- **Socket options** outside the Warden's list of 58, set before the connect
  (`SO_TIMESTAMPING`, `TCP_QUICKACK`, a socket filter, `TCP_ULP`, ...), are not
  carried to the connected socket.
- **Known differences from a native connect.** A descriptor `dup`'d from the
  socket before the connect keeps the original, unconnected socket. A Unix
  server sees the Warden's pid in `SO_PEERCRED` (with the agent's uid and
  gid). A repeated connect while the first is still waiting gets `EALREADY` at
  once rather than waiting.
- **Pending connects** are bounded per agent, not per thread: one agent with
  many threads blocked in slow connects can fill the table, and its own later
  connects get `ENOBUFS` until they finish or time out.
- **urllib3** decides whether the host has IPv6 by binding a socket to `::1`,
  which the Warden refuses, so under the Warden it resolves IPv4 only.
- **The CDN check** in the test ran through this build host's TLS-intercepting
  egress, so it shows that a real client reaches a CDN address through the
  Warden, not how a given CDN behaves.
- **The plan gate** canonicalizes a `unix:` step lexically; the runtime decides
  the socket the path resolves to.
- Receiving a descriptor from a Unix peer the policy allows is not checked.

## Upgrading

1. Read every `allow host` line in your policies: they now let the agent
   connect.
2. Run `tools/varek_preflight.sh <policy> ...` with the same options you give
   the Warden, including `--flow-policy` if you use the plan gate.
3. `make test-v1210` on the deployment host shows what it can dial (IPv6
   included, where the host has it).
