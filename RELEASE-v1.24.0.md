# VAREK v1.24.0 — Host Names Without Agent DNS

> **DRAFT, not released.** Three things stay open before this is tagged: the
> 24-hour soak run (§5 of the design), the independent review, and the latency
> figures. Each is marked **PENDING** below.

Released PENDING · MIT · github.com/kwdoug63/varek

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
3. **Views.** The agent reads `/etc/hosts`, `/etc/resolv.conf` and
   `/etc/nsswitch.conf` from sealed memfds that the Warden writes. Its
   `/etc/hosts` lists localhost and the allowed names' current addresses, and
   nothing else. Its resolver configuration names a server that no one answers.
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

`make test-v1240` runs 88 checks; CI runs it, with the Warden as root.

- **Grammar:** 28 accepted and refused forms, each in both parsers.
- **Resolution table:** 81 checks against a local authoritative test server
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

**Regression.** Against the v1.23.1 Warden and parsers, the same suite fails
81 of its 88 checks. The 7 it passes do not test host names: a v1.21
compatibility case, the table's unit test (which does not involve the Warden),
and checks that pass trivially because the old Warden refuses the policy
outright.

`make crosscheck` passes with 0 disagreements. It runs every policy in the
repository and 300 fuzzed policies for each of seeds 1, 2 and 3, now including
name rules.

## 24 hours against CDN-hosted APIs

**PENDING.** `tests/soak_v1240/soak.sh` fetches by name every minute for 24
hours, against these targets:

| Network | URL |
|---|---|
| Fastly | `https://pypi.org/robots.txt` |
| Cloudflare | `https://www.cloudflare.com/cdn-cgi/trace` |
| CloudFront | `https://d1.awsstatic.com/robots.txt` |

The results to fill in from `report.txt`:
- refused connects caused by a stale table (must be 0)
- resolution records per name, and how many times each answer changed
- fetches that used an address in its grace period
- failures outside the Warden
- the audit result

## Latency

**PENDING.** Run `varek bench` on a name-decided connect against a numeric
one. Deciding over the candidates adds one decision per name that the address
belongs to.

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
  `run_start`; `resolution` records; and `dialed`, `candidates` and
  `resolution_generation` on connects.
- New record rules: `hosts_view`, `resolv_view`, `nsswitch_view`,
  `dns_refused` and `too_many_names`.
- New `vdp_cert_check` mode: `kinds`.

## Found in review

**PENDING**: the independent review's findings.

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
- **Metadata on the view paths.** `stat` and `access` on the three view paths
  are decided as before; only opens get the views. Every client tested
  resolves without them.
- **Refresh changes and checkpoints.** A refresh that changes a name's
  addresses is signed at the next scheduled checkpoint, not at once.

## Upgrading

1. Add `require warden 1.24` before your first host-name rule. Run `lint` to
   find names that have no effect without it.
2. Run `tools/varek_preflight.sh <policy>`. The Warden's `--check-startup`
   resolves each name and reports any that fail.
3. Remove any `allow host <resolver>:53` rules. Under v1.24 they have no
   effect.
