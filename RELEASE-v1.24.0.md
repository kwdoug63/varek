# VAREK v1.24.0 — Host Names Without Agent DNS

> The second 24-hour soak passed. The review was done by AI review agents; a
> human or third-party review has not been done.

Released 2026-10-09 · MIT · github.com/kwdoug63/varek

## Summary

Through v1.23 a host rule matched only a numeric address. A buyer who meant
"allow the Salesforce API" had two bad options. One was to hard-code addresses,
which break whenever AWS or a content network moves them. The other was to let
the agent reach a DNS server, which lets it send data out in the questions it
asks.

From v1.24.0 a policy names hosts:

    require warden 1.24
    allow host api.salesforce.com:443

The Warden resolves every allowed name itself, and the agent never sends a DNS
query:

1. **Grammar.** A host name is lowercase, written as A-labels, with no trailing
   dot, labels of at most 63 bytes and at most 253 bytes in all. A name without
   a port matches every port. Wildcards are refused; they are planned for
   v1.25. Name rules take effect only after `require warden 1.24`, so an older
   Warden refuses the policy instead of loading rules it cannot match. The
   decision procedure and the certificate checker parse names independently and
   must agree rule by rule. The policy-grammar version is now 1.24.
2. **Resolution table.** Before the agent runs, the Warden resolves every name
   an allow rule names, A and AAAA, through the host's resolver. It refreshes
   each entry at its TTL, clamped to [30 s, 1 h]. An address that drops out of
   an answer stays valid for the old TTL, at most 5 minutes. Each lookup is a
   chained `resolution` record, signed at the next checkpoint. Lookups run in a
   resolver helper process, so the supervisor never waits on DNS while an agent
   thread waits on an answer.
3. **Views.** The agent reads `/etc/hosts`, `/etc/resolv.conf`,
   `/etc/nsswitch.conf` and `/etc/host.conf` from sealed memfds that the Warden
   writes. Its `/etc/hosts` lists localhost and the allowed names' current
   addresses, IPv4 before IPv6, and nothing else. Its `/etc/host.conf` says
   `multi on`, so glibc returns every address of a name. Its resolver configuration names a server that no one answers.
   Every connect to port 53 is refused (`dns_refused`), whatever the numeric
   rules say.
4. **Connects decided on names.** A connect is decided on its address and on
   `name:port` for every allowed name that address belongs to, current or in
   grace. The first rule, in policy order, that holds on any of them decides.
   The certificate covers the deciding name. The checker also confirms that no
   earlier rule holds on any other candidate. The record carries the address
   dialed, every candidate and the table generation.
5. **Audit.** `varek_audit.py` checks that each name was bound to the address
   dialed by the resolution records, that no name of that address was left
   out, and that no earlier rule held on another candidate. A stream edited to
   leave a name out fails, even with its hash chain recomputed.

The plan gate decides `net_connect api.example.com:443` steps on the name.

Per-call verdicts on file opens, lookups and launches are unchanged, and so is
the symmetric-suppression invariant (**no extension may move a genuinely
unsafe action to SATISFIED**).

## Tested with real clients

`make test-v1240` runs 113 checks; CI runs it, with the Warden as root. On a
host without IPv6, one of them (three IPv6 cases end to end) is skipped; the
table's unit test checks those addresses instead.

- **Grammar:** 28 accepted and refused forms, each in both parsers.
- **Resolution table:** 110 checks against a local authoritative test server
  (`tests/dns_test_server.py`) that rotates answers, follows CNAME chains,
  returns NXDOMAIN and SERVFAIL, and drops queries.
- **Clients as the agent**, each resolving an allowed name through the views and
  connecting, decided on the name, while other names fail within 100 ms:
  - glibc: Python, curl and Node's `dns.lookup`
  - a static musl binary
  - Go's own resolver
  - Java

  Node's `dns.resolve4`, which sends a DNS query itself, fails at once. A
  resolver listening on 127.0.0.1:53 receives nothing, even with
  `allow host 127.0.0.1:53`.
- **Rule order:** a deny on a name wins over a later numeric allow of its
  address, and an earlier numeric deny wins over a name allow.
- **Grace:** an address that left the answer is reached during its grace and
  refused after it.
- **Other cases:** a deny on `/etc/hosts`, a Unix-socket connect, the plan gate,
  and a forged stream that the audit refuses.

**Regression.** Against the v1.23.1 Warden, parsers and audit, the same suite
fails 104 of its 113 checks (one is skipped there, as here). The 8 it passes do not test host names: a v1.21
compatibility case, the table's unit test (which does not involve the Warden),
and checks that pass trivially because the old Warden refuses the policy
outright.

`make crosscheck` passes with 0 disagreements. It runs every policy in the
repository and 300 fuzzed policies for each of seeds 1, 2 and 3, now including
name rules.

## 24 hours against CDN-hosted APIs

`tests/soak_v1240/soak.sh` fetched each URL by name once a minute for 24
hours on a DigitalOcean droplet (Ubuntu 24.04, kernel 6.8, 1 vCPU, 1 GB). It
ran twice. The first run found a bug (see "Found in the soak" below). The
second ran on the Warden with that bug fixed, from 2026-10-06 19:50 to
2026-10-07 19:50 UTC, and passed with nothing failed:

| Network | URL | Fetches | OK |
|---|---|---|---|
| Fastly | `https://pypi.org/robots.txt` | 1,440 | 1,440 |
| Cloudflare | `https://www.cloudflare.com/cdn-cgi/trace` | 1,440 | 1,440 |
| CloudFront | `https://aws.amazon.com/robots.txt` | 1,440 | 1,440 |

- **Refused connects to the soak ports: 0.** No fetch failed, for any reason.
- **Resolution:**

  | Name | Resolution records | Refresh interval | Answer changes | Worst lateness |
  |---|---|---|---|---|
  | `aws.amazon.com` | 2,812 | 30–59 s | 2,034 | 0.2 s |
  | `www.cloudflare.com` | 1,470 | 30–284 s | 0 | 0.1 s |
  | `pypi.org` | 37 | 30–3,600 s | 0 | 0.0 s |

  CloudFront changed `aws.amazon.com`'s answer 2,034 times in 24 hours, and
  every fetch still reached an address the table held.
- **Peers:** every peer the agent reached appears in the resolution records.
  No fetch needed an address in its grace period.
- **Each URL was served by the expected network**, judged from its response
  headers.
- **Audit:** `varek_audit.py` PASS on the 114,279-record stream, with the hash
  chain intact. `soak_check` PASS.

**The first run** (2026-10-05 to 2026-10-06) had the same shape:
- 4,320 fetches, 0 refused connects, 2,015 answer changes for
  `aws.amazon.com`, and the audit passing.
- 4 fetches to `aws.amazon.com` failed with
  `OSError: [Errno 101] Network is unreachable`. The checker counted them as
  outside the Warden, but they were a Warden bug, fixed before the second
  run.

The second run used the Warden as of the `host.conf` fix, before the review's
fixes. Those fixes do not change what the soak exercises (CDN addresses are
not special addresses). A short soak trial on the final Warden was planned
to confirm it; it is not recorded here.

## Latency

Deciding a connect on host names costs no time that can be measured end to
end. `make latency-v1240` (`tests/latency_v1240.sh`) times 3,000 blocking TCP
connects, one after another, to a listener on the machine's own address. It
does this natively and under the Warden, with the connect allowed in three
ways:
- by a numeric rule;
- by a rule on one name that resolves to the address (2 candidates);
- with 15 allowed names all resolving to the address (16 candidates, the most
  a v1.24 connect carries).

The Warden's own time is its latency per connect minus the dial, read from its
records. Results from three runs on a 4-vCPU cloud container
(`varek/v1_4/tests/connect_latency_v1.24.0.txt`), microseconds:

| Connect allowed by | Client p50 | Client p99 | Warden's own p50 | Warden's own p99 |
|---|---|---|---|---|
| Native (no Warden) | 13–16 | 88–171 | | |
| A numeric rule | 179–206 | 456–524 | 105–124 | 289–317 |
| One name (2 candidates) | 172–209 | 467–534 | 103–127 | 296–345 |
| 15 names (16 candidates) | 166–194 | 322–486 | 102–116 | 215–328 |

The three rows under the Warden overlap: run-to-run noise (about ±10 µs at
p50) is larger than the difference.

The decision procedure, timed on its own with the same 16-rule policy, takes
about 0.5 µs per decision, including the batch tool's own input and output.
So deciding over 16 candidates adds at most about 8 µs, and one name about
1 µs.

These figures are from a shared cloud container, not the dedicated 2-vCPU VM
of the v1.22 table. They compare the three cases with each other, not with
earlier releases.

## Also in this release

- **musl agents can open files.** The legacy `open(2)`, which static musl
  programs use instead of `openat`, is now mediated as
  `openat(AT_FDCWD, …)`. Through v1.23 it fell to the filter's default deny,
  so a musl agent could open no file at all.

## Compatibility

- Every v1.21 policy loads unchanged. Without `require warden 1.24`, a host
  name keeps its v1.21 meaning: it matches nothing, and lint says so. A
  `require warden 1.24` that follows such a name is refused, so one policy
  cannot hold names under both meanings.
- The Warden needs to reach the host's resolver; the agent needs none. Use
  `--dns-server a.b.c.d[:port]` to resolve through a particular server, such
  as a validating one.
- New options: `--dns-ttl-min`, `--dns-ttl-max` and `--dns-grace-max`.
  `--check-startup` reports each allowed name that does not resolve.
- New record fields: `host_name_rules`, `host_names` and `resolver` in
  `run_start`; `resolution` records; and `dialed`, `candidates`,
  `resolution_generation` and `special_address` on connects.
- New record rules: `hosts_view`, `resolv_view`, `nsswitch_view`,
  `hostconf_view`, `view_write_refused`, `dns_refused` and
  `too_many_names`.
- New `vdp_cert_check` modes: `kinds` and `rules`.
- `run_start` reports the Warden as `1.24.0`, and the startup message reports
  the policy grammar as v1.24.

## Found in the soak

**The agent got one address per name, sometimes an unreachable one.** Each
of the 4 failures dialed an IPv6 address, and the droplet has no IPv6 route.
The resolution records show the table held the IPv4 addresses throughout. The
cause was in the views:
- The soak policy did not let the agent read `/etc/host.conf`. Without its
  `multi on`, glibc returns only the first `/etc/hosts` line for a name.
- The table appends a new address after the ones it keeps. When CloudFront
  rotated its IPv4 addresses, an IPv6 address came first in the view.

The Warden now serves `/etc/host.conf` as a fourth view (`multi on`,
`hostconf_view`), and the hosts view lists each name's IPv4 addresses before
its IPv6 ones. `make test-v1240` recreates the failure, with the A record
appearing after the AAAA one: against the earlier v1.24 code the agent
resolves only `2001:db8::10` and its fetch fails; with the fix it resolves
both and connects. `soak_check.py` now reports failures by their full message
rather than the exception type alone.

## Found in review

Four AI review agents (Claude), separate from the session that wrote the
code, each reviewed one part of the change (v1.23.1 to this release) and had
to reproduce every finding:
- the resolver and the resolution table;
- what the agent can do;
- the three policy parsers;
- the audit.

The agents are the same kind of model that wrote much of this code, so this
is not an independent human review. It found real defects, listed below, but
it does not replace a human or third-party review.

Every finding below is fixed, and `make test-v1240` covers it: section 5 of the suite, plus 5 new
checks in the resolution table's unit test.

**The audit accepted forged streams.** These are streams edited by someone
who holds the log but not the signing key, with the hash chain recomputed.
Two of them turned a refused connect into an allowed one.
- **The name check could be skipped.** It ran only when a connect carried
  `candidates`, so deleting that field skipped it. Now every connect in a run
  whose policy has name rules must carry `dialed`, `candidates` and
  `resolution_generation`. Whether the policy has name rules is read from the
  policy file through the checker's new `rules` mode, no longer from
  `run_start`.
- **Names held in grace could be dropped.** Names bound to the address only
  by their grace period could be left out of the candidates. They now count,
  allowing for grace being rounded to whole seconds.
- **Ports could be spelt otherwise.** A port written `07002` is matched by a
  portless allow rule and by no rule written with the port. The dialed
  address and every candidate must now be spelt as the Warden spells them,
  and the dialed address must be the connect's target.
- **The table generation was not checked**, so a resolution record could be
  deleted. A connect's `resolution_generation` must now be the latest
  resolution record's.
- **A view could be forged against a deny.** A view could be claimed for a
  path the policy explicitly denies. The checker now answers which path rules
  hold on the view's path.
- **Malformed fields crashed the audit** (`addresses`, `grace` or `resolved`
  not of their type), so it gave no verdict. They are now problems in the
  report.

**The Warden.**
- **A name could lead to the host's own services (medium).** Whoever
  controls an allowed name's DNS could answer `127.0.0.1` or
  `169.254.169.254`, and the Warden dials from the host's network namespace.
  A review agent read a secret from a listener on the host's loopback that way.
  - A connect to a loopback, link-local, unspecified or multicast address
    is now decided on the address alone (`"special_address": true`), so only
    a numeric rule can allow it.
  - Private ranges stay reachable by name; see "Known limits".
- **Writable opens reached the real resolver files (medium).** An open of
  `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf` or `/etc/host.conf`
  that could write was not served a view. It went to the policy, so a policy
  allowing `/etc/` let the agent write the host's `resolv.conf`. The
  resolver helper reads that file on every lookup, so the agent could then
  choose where allowed names lead.
  - Such opens are now refused (`view_write_refused`), whatever the policy
    says. That covers each of the four paths and what each resolved to at
    startup.
- **Oversized answers were read past the buffer (medium).** glibc retries a
  truncated UDP answer over TCP and returns the answer's full length, even
  past the buffer. The table's parser then read past its 8 KB buffer.
  - Reproduced here: 60,834 bytes reported for an 8,192-byte buffer.
  - Such an answer is now a failed lookup.
  - The startup lookups ran inside the Warden itself. They now go through
    the resolver helper like every refresh, so the process holding the
    signing key never parses network data.
- **A deny on a name no allow rule named did nothing (low–medium).** Only
  allowed names were resolved. Deny rules' names are now resolved too, kept
  out of the hosts view, so `deny host evil.example.com` holds on that
  name's addresses.
- **A v4-mapped AAAA answer never matched (low).** An answer
  `::ffff:a.b.c.d` did not bind `a.b.c.d`, so a deny on that name was
  skipped. It now binds `a.b.c.d`.
- **Grace shrank after a failed refresh (low).** A failed refresh gave the
  next rotated-out address 30 s of grace instead of its last TTL. Grace now
  comes from the last answer's TTL.
- **The Warden spun the CPU (low).** It ran at 100% CPU when the resolver
  helper's request queue was full. It now waits for the helper's answers.
- **The version.** `run_start` said `1.23.1`; it now says `1.24.0`.

**Found later, in the v1.25 review.** The same kind of review of v1.25 found
two defects that v1.24.0 has too. Both are fixed here, before the tag:
- **The exporter refused honest streams (medium).** A view is answered
  with no rule, so its raw verdict is UNKNOWN and its final verdict ALLOW.
  `varek_cyclonedx.py` took that as a broken symmetric-suppression invariant
  and refused to export any run in which a glibc agent resolved a name,
  unless the policy also allowed the resolver files. The audit passed the
  same streams. The exporter now reports view answers apart from the
  decisions ("answered with the Warden's views"), checks each is a
  read-only open of its own path, and no longer lists `/etc/hosts` as an
  authorized object.
- **More addresses a name must not lead to (medium).** The special
  addresses lacked cloud metadata services outside link-local (Alibaba
  Cloud's `100.100.100.200`, AWS's IPv6 `fd00:ec2::254`), IPv4-compatible
  addresses (`::/96`), and the NAT64 prefixes `64:ff9b::/96` and
  `64:ff9b:1::/48` holding a special IPv4 address. Whoever controls an
  allowed name's DNS could answer with one of them; each is now decided on
  the address alone. `make test-v1240` checks
  `100.100.100.200` end to end and every case in the table's unit test, and
  that the audit's list is the Warden's.

**The parsers: no disagreement.** The decision procedure, the certificate
checker and the cross-check oracle agreed on:
- about 200,000 name strings, covering every boundary of the name and port
  rules;
- 12,000 fuzzed policies;
- the oracle's own run with the SMT decision procedure.

**Not fixed in v1.24, for its own release.** The Warden opens a file as root
for the agent. So a path the policy lets the agent write is writable even
when the file is root-owned and mode 0644. This is older than v1.24, and
changing it affects every file policy. It will be designed and released on
its own, with the Warden opening files with the agent's uid and gid.

## Known limits

- **Shared CDN addresses.** Allowing `api.example.com` also reaches every other
  site served from the same address, by sending another name in TLS SNI or the
  HTTP `Host` header. v1.24 decides on the address a name resolves to, not on
  the name the agent sends to the server. The v1.26 egress proxy closes this.
- **Deny wins on a shared address.** When a denied name and an allowed name
  share an address, a connect to that address is refused. This fails safe.
- **Wildcards** (`*.example.com`) are refused at load; they are planned for
  v1.25.
- **DNSSEC.** The Warden trusts the host's resolver and does not validate
  DNSSEC itself. Use `--dns-server` to point it at a validating resolver.
- **Metadata on the view paths.** `stat` and `access` on the four view paths
  are decided as before; only opens get the views. So `stat("/etc/hosts")`
  reports the host's file, not the view. Every client tested resolves without
  them.
- **Private addresses.** A name may lead to a private address (10/8,
  172.16/12, 192.168/16, fc00::/7). That is how internal APIs are reached by
  name, so whoever controls an allowed name's DNS can point it at a private
  address the Warden's host can reach. Loopback, link-local, unspecified,
  multicast and cloud metadata addresses (and their IPv4-compatible and
  NAT64 forms) are reached only by numeric rules.
- **Local resolvers over Unix sockets.** A policy that allows nscd's socket,
  systemd-resolved's or D-Bus gives the agent a resolver that sends DNS
  itself. Allow such sockets only with that in mind.
- **Refresh changes and checkpoints.** A refresh that changes a name's
  addresses is signed at the next scheduled checkpoint, not at once.

## Upgrading

1. Add `require warden 1.24` before your first host-name rule. Run `lint` to
   find names that have no effect without it.
2. Run `tools/varek_preflight.sh <policy>`. The Warden's `--check-startup`
   resolves each name and reports any that fail.
3. Remove any `allow host <resolver>:53` rules. Under v1.24 they have no
   effect.
