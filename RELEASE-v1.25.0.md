# VAREK v1.25.0 — Wildcard Host Names, Opt-In

> **DRAFT, not released.** The review was done by AI review agents; a human
> or third-party review has not been done. Still to come before tagging:
> - the release date.

Released PENDING · MIT · github.com/kwdoug63/varek

## Summary

v1.24 let a policy name hosts exactly (`allow host api.salesforce.com:443`).
The Warden resolved every name before the agent ran, and the agent sent no
DNS at all. That works only when the names are known in advance. An agent
that reaches per-tenant names, such as `acme.api.example.com` and
`globex.api.example.com`, cannot list them.

From v1.25.0 a policy can allow every name under a domain:

    require warden 1.25
    allow host *.example.com:443 acknowledge=dns-channel

With a wildcard, the agent's lookups have to leave the host: the names are
known only when the agent asks for one. v1.25 therefore makes a wildcard an
opt-in rule form, refuses wildcards over domains where anyone can create a
name, answers every lookup itself, and bounds and records them all.

1. **Grammar.** `*.` is the whole leftmost label, over a suffix of at least
   two labels that follows the v1.24 name rules. `*.example.com` matches
   `a.example.com` and `a.b.example.com`, never `example.com` itself. A
   wildcard needs `require warden 1.25`. The decision procedure, the
   certificate checker and the cross-check oracle each read it as a glob, so
   it is decided, certified and fuzzed like any glob. The policy-grammar
   version is now 1.25.
2. **The acknowledgment.** Every wildcard allow rule must carry
   `acknowledge=dns-channel`, or the policy is refused. A reviewer reading
   the policy sees that the agent's lookups under that rule leave the host.
3. **Shared domains refused at load.** An allow wildcard over a domain
   where anyone can register a name would allow an attacker's endpoint. The
   policy is refused, naming the entry, when the suffix is:
   - a public suffix (`*.com`, `*.co.uk`);
   - an entry of the Public Suffix List's private section or under one
     (`*.s3.amazonaws.com`, `*.myorg.github.io`);
   - on the VAREK list of 56 multi-tenant domains the Public Suffix List
     lacks (`*.my.salesforce.com`, `*.slack.com`, `*.vault.azure.net`), or
     under one;
   - above any of these, which the wildcard would cover too
     (`*.salesforce.com` covers `my.salesforce.com`).

   Both lists ship pinned with the release: the Warden refuses lists in its
   `data/` directory that are not the release's, and `run_start` records
   their SHA-256 and whether they are.
4. **The stub resolver.** With a wildcard allow rule, the agent's
   `resolv.conf` view names `127.53.53.53`. That is a UDP and TCP resolver the
   Warden runs inside the agent's own network namespace.
   - A name no allow rule can reach gets NXDOMAIN at once, and no question
     leaves the host.
   - A name a wildcard allows is looked up by the Warden's resolver helper
     when the agent asks, and recorded as a `resolution` record.
   - Every other connect to port 53 is still refused.
5. **Budgets on the name channel.** Each wildcard allow rule has a budget
   of new names a run (`names=`, default 256), of lookups sent upstream a
   minute (`rate=`, default 30, counting a name asked again after its TTL),
   and at most 63 bytes before the suffix. A question past a budget gets
   NXDOMAIN and is not looked up. At the defaults the new names an agent
   chooses carry at most about 10.5 KB a rule a run; after that, which
   names it asks again carries at most about 30 bytes a minute.
6. **Every question recorded.** Each question the stub receives is a
   chained `dns_question` record: the name, the rule that matched, the
   budget charged and the answer. `varek_audit.py` checks every charge
   against the policy's budgets, and that every name looked up was asked
   for.
7. **Many names on one address.** Per-tenant names behind one CDN share
   addresses. A connect is now decided over every name its address belongs
   to, with no limit; through v1.24 a 16th name refused the connect. Past
   15 names the record carries their count and SHA-256, and the audit
   rebuilds them from the resolution records.

Connects are decided as in v1.24, on the address and every name it belongs
to. Per-call verdicts on file opens, lookups and launches are unchanged, and
so is the symmetric-suppression invariant (**no extension may move a
genuinely unsafe action to SATISFIED**).

## Tested with real clients

`make test-v1250` runs 161 checks; CI runs it, with the Warden as root.

- **Grammar:** 52 checks of accepted and refused forms, each in both
  parsers, including the acknowledgment and the budgets.
- **Shared domains:** 44 checks. `shared_domains.c` agrees with an
  independent Python statement of the rule on 18,293 suffixes, every parent
  of a list entry among them, and encodes all 440 Unicode labels in the list
  as Python does. The pinned lists, a list in `data/` that is not the
  release's, a list named on the command line, a cut-off list, and the
  audit's own check of each wildcard.
- **The stub, with real clients as the agent:** 34 checks.
  - Clients: Python, curl, Node (`dns.lookup` and `dns.resolve4`), Go,
    Java and a static musl binary.
  - Each resolves a name a wildcard allows through the stub and connects,
    decided on the name.
  - A name outside every rule fails within 50 ms, and a recording upstream
    server receives no question for it.
  - TXT questions, TCP fallback and a connect to 127.0.0.1:53 are covered.
  - A TCP connect to the stub that never completes does not hold up the
    Warden.
- **Budgets:** 21 checks. A DNS-tunnel style client is held to `names=`,
  `rate=` and the label budget, names re-asked after their TTL are held to
  `rate=`, every refusal is recorded, and ten kinds of edited stream fail
  the audit.
- **Many names on one address:** 10 checks. 40 names on one address all
  fetch, their connects are recorded hashed, and the audit accepts the run.
  A forged resolution record fails the audit. A name that expires unasked
  is recorded as retired, and a later connect to its address under another
  name is accepted. 20 names whose grace ends together just before a
  connect leave an honest run that passes the audit.

**Regression.** Against the v1.24.0 Warden, parsers and audit, the suite
fails 129 of its 161 checks. Of the 32 it passes, 28 test the shared-domain
lists and code, which do not involve the Warden. The other 4 pass trivially
because the old Warden refuses the policy: the oracle agrees on refusing it,
a lint check on an ordinary wildcard, and two checks that no question left
the host.

`make crosscheck` passes with 0 disagreements, with wildcards, budgets and
the acknowledgment in the fuzzed policies (present, missing, misspelt,
twice and misplaced).

## 24 hours against Wikipedia

`tests/soak_v1250/soak.sh` fetched the Wikipedia API of 40 language
editions, `https://<lang>.wikipedia.org/`, one fetch a minute in turn, for
24 hours, under `allow host *.wikipedia.org:443` at the default budgets.
Every edition is served from the same addresses, as per-tenant names behind
a CDN are, so connects are decided over several names on one address. It
ran on the same DigitalOcean droplet as the v1.24 soak (Ubuntu 24.04,
kernel 6.8, 1 vCPU, 1 GB), from 2026-10-07 01:28 to 2026-10-08 01:28 UTC.

| | |
|---|---|
| Fetches | 1,440 of 1,440 OK, 0 failed |
| Refused connects to port 443 | 0 |
| Questions to the stub | 2,880, every one recorded; no fetch without its question |
| Budget refusals | 0 |
| Names charged | 40 of 256; at most 2 in any minute, of 30 |
| Lookups on demand | 1,440, and 1,440 retirements |
| Connects decided | 4,320; at most 5 candidates (4 names on one address) |
| Peers | every peer the agent reached is in the resolution records |

The defaults are far from the run's use: 40 of 256 names, and at most 2 a
minute of 30. Names expired between fetches, 40 minutes apart, so at most 4
were current on one address at once; the hashed form for more than 15 names
is exercised by `make test-v1250` (40 names on one address), not here.

**The run used the Warden before the review.** It was built from the v1.25
branch as of section 5 (5ef3046), before the acknowledgment, the review's
fixes and the version bump (its `run_start` says 1.23.1). Its policy has no
`acknowledge=dns-channel`. A 3-minute trial on the final Warden, on the same
droplet, passed: 3 fetches over 3 names, 0 refused, every question
recorded, no budget refusal, and `varek_audit.py` PASS.

## Found in the soak

**The audit failed an honest stream (low).** `soak_check` reported FAIL:
`varek_audit.py` refused 3 of the 4,320 connects, each because a name
"did not resolve to 208.80.154.224". The stream shows why:
- each name had been retired 30 or 60 s before, with that much grace, and
  the connect was decided about 1 ms before the grace ended, so the Warden
  rightly counted the name;
- the record gives grace in whole seconds from the retirement record's
  time, and the audit compared that with the connect record's time, written
  3 to 5 ms after the decision (the dial), so it found the grace ended.

The soak's checkout had the audit from before the v1.24 review, which allows
for the rounding; the same stream passes the audit as of 9858835: `PASS`,
24,969 decision records, the chain intact, 13,371 certificates re-checked.
From the v1.25 review the Warden also records when each grace ends
(`grace_end`), so the audit no longer works from rounded times at all.

## Latency

`make latency-v1250` (`tests/latency_v1250.sh`) times 1,000 lookups and
1,000 blocking TCP connects of each kind, one after another, on a 4-vCPU
cloud container with nothing else running. Results from three runs
(`varek/v1_4/tests/latency_v1.25.0.txt`), microseconds, measured by the
client.

**Lookups.** The upstream server is `tests/dns_test_server.py`, which re-reads
a zone of about 3,000 names on every question, so one upstream question
costs about 3.1 to 3.3 ms here, much more than a real resolver's cache hit.

| Lookup | p50 | p99 |
|---|---|---|
| One A question straight to the test server (no Warden) | 3,078–3,339 | 6,456–8,080 |
| A new wildcard name, asked of the stub | 7,094–7,760 | 13,218–15,322 |
| The same name again, answered from the table | 51–52 | 115–137 |
| `getaddrinfo` of an exact name (the hosts view, as in v1.24) | 358–410 | 645–755 |
| `getaddrinfo` of a new wildcard name | 8,392–8,508 | 14,899–17,237 |
| `getaddrinfo` of the same wildcard name again | 515–558 | 896–1,054 |

- A new name costs two upstream questions, since the resolver helper asks A
  and AAAA one after the other, plus 0.7 to 1.2 ms of its own: the hand-off
  to the helper and back, and the records.
- A name already in the table is answered in about 50 µs. Through
  `getaddrinfo` that is 120 to 200 µs more than an exact name, because glibc
  reads the views and then asks the stub.

**Connects** to a listener on the machine's own address. The Warden's own
time is its latency per connect minus the dial, read from its records.

| Connect allowed by | Client p50 | Client p99 | Warden's own p50 | Warden's own p99 |
|---|---|---|---|---|
| Native (no Warden) | 16–20 | 68–323 | | |
| A numeric rule | 166–172 | 352–443 | 97–104 | 231–259 |
| A wildcard, 1 name on the address (2 candidates) | 176–213 | 421–438 | 106–129 | 226–300 |
| A wildcard, 40 names on the address (41 candidates, hashed) | 207–273 | 354–630 | 134–183 | 245–374 |

Deciding over 41 candidates, hashing them for the record and checking each
name's grace adds 34 to 79 µs at the median over a numeric rule, about 1 to
2 µs a name. With 2 candidates the difference is within run-to-run
noise.

## Compatibility

- Every v1.24 policy loads unchanged and behaves as on v1.24.0. Without a
  wildcard allow rule there is no stub, and the agent sends no DNS.
- One v1.24 refusal is lifted: a connect to an address that more than 15
  allowed names resolve to was refused (`too_many_names`). It is now
  decided over all of them, and the first rule over all of them decides, as
  for any connect.
- New options: `--psl` and `--shared-domains`, the two lists' paths. By
  default the Warden looks in its `data/` directory. A policy with a
  wildcard rule is refused when the lists cannot be read.
- New record fields:
  - in `run_start`: `dns_stub`, `wildcard_budgets`, `psl_sha256` and
    `shared_domains_sha256`;
  - on resolution records: `dynamic`, and `"a":"retired"` for a name that
    expired unasked;
  - on connects: `candidates_n` and `candidates_sha256`, past 15 candidates.
- New records and rules: `dns_question` (with `new`, `upstream` and
  `mono_ms`), and the rules `dns_stub`, `wildcard_budget`, `netsvc_view` and
  `svc_view`. Resolution records may say `retired`, `grace_end` or
  `unanswered`. `run_start` adds `shared_lists_pinned`.
- `vdp_cert_check rules` prints five more columns: wildcard, policy line,
  `names=`, `rate=` and the rule's constant.
- `varek refusals` lists budget refusals as BUDGET. `varek policy show`
  lists each wildcard rule's budgets, and says the agent's lookups under
  it leave the host.
- `run_start` reports the Warden as `1.25.0`, and the startup message
  reports the policy grammar as v1.25.

## Found in review

Four AI review agents (Claude), separate from the session that wrote the
code, each reviewed one part of the change (v1.24 to this release) and had
to reproduce every finding:
- the stub resolver and the resolution table;
- what a malicious agent can do;
- the three policy parsers and the shared-domain lists;
- the audit.

The agents are the same kind of model that wrote much of this code, so this
is not an independent human review. It found real defects, listed below, but
it does not replace a human or third-party review. The stub reviewer's
end-to-end tests were cut short; its one finding was reproduced here.

Every finding below is fixed, and `make test-v1250` covers it. Against the
code the review was given, 25 of its checks fail (one of them only because
an audit message was reworded).

**The shared-domain refusal.**
- **A wildcard over the parent of a shared domain loaded (high).** Two
  reviewers found it. `*.salesforce.com` covers `evil.my.salesforce.com`,
  `*.core.windows.net` an attacker's blob account, `*.on.aws` anyone's
  Lambda URL. 276 such parents were accepted, and the bases of the Public
  Suffix List's `*.x` rules (`*.kawasaki.jp`). A suffix with any list entry
  under it is now refused, naming the entry.
- **The lists were not pinned (medium).** A cut-off or substituted list
  quietly refused less, and nothing downstream noticed. The release's
  SHA-256 values are now in the Warden: lists in `data/` that differ stop
  it, lists named with `--psl` or `--shared-domains` are used and recorded
  as not pinned, and a Public Suffix List without its end marker is
  refused. The audit checks each wildcard again against the release's lists.
- **Missing multi-tenant domains (medium).** The VAREK list gains 25: Azure
  storage, key vault and OpenAI endpoints, Databricks, Snowflake, MongoDB
  Atlas, Firebase, R2, B2, Wasabi, `onmicrosoft.com`, Okta previews,
  tunnels such as `loca.lt`, and `amazonaws.com.cn`.

**The Warden.**
- **Re-asked names were an unbounded channel (medium).** A name asked again
  after its TTL went upstream with no charge, so which names an agent
  re-asked, and when, carried data out without end. A reviewer sent
  `SECRET-KEY=hunter2` through a `names=4` rule this way. Every lookup sent
  upstream now counts against `rate=`.
- **The agent could stall the Warden (medium).** A TCP connect to the stub
  was made on the agent's own blocking socket in the Warden's loop. With
  `TCP_MD5SIG` (the stub's listener drops every SYN) and a long
  `TCP_SYNCNT`, every other decision waited: 6.6 s here, hours with
  `TCP_SYNCNT=127`. It failed closed. The connect is now non-blocking and,
  if still in progress, finished as a pending operation, answered as the
  kernel would.
- **The agent could make an honest run fail the audit (low).** Grace was
  recorded in whole seconds, so names ending their grace together near a
  connect could not be told in or out. The Warden now records each end of
  grace (`grace_end`) before the connect decided at that time, and a lookup
  still out at the end of the run (`unanswered`).
- **A spent budget on a failed add (low).** A new name the table could not
  add kept its charge; it is now undone.

**The audit accepted forged streams.** These are streams edited by someone
who holds the log but not the signing key, with the hash chain recomputed.
- **A connect forged as a stub connect passed (high).** The audit accepted
  `dns_stub` to whatever address `run_start` named, with no certificate,
  even in a policy with no wildcard. It is now accepted only with a wildcard
  allow rule, and only to `127.53.53.53:53`.
- **A denied name could be shown answered (medium).** The audit trusted
  each question's rule and line; they are now asked of the checker, as the
  stub decides them.
- **A question and its charge could be hidden (medium)** by deleting the
  questions and the resolution's `dynamic` mark. A resolution that is not
  dynamic must now be of a name a host rule names.
- **Rate refusals could become charges (medium)** by moving their
  timestamps. The rate window is now counted on the Warden's own monotonic
  time, which may not go back.
- **Hostile streams took hours (medium).** The rate window was quadratic,
  and hashed candidates tried up to 4,096 subsets each. Both are now linear.
- **A lookup's answer could be dropped (low).** Every lookup sent upstream
  must now be answered before `run_end`.
- **A bare carriage return (low).** The audit and `varek policy show` split
  policy lines on `\r` where the Warden does not, so they read different
  budgets. Both now take the rules from the checker.
- **Malformed fields crashed the audit (low)** and `varek refusals`; they
  are now problems in the report.

**Also fixed in v1.24.0.** Two defects the review found are in v1.24.0
too, and are fixed there before its tag:
- `varek_cyclonedx.py` refused every honest stream with host views (they
  are now reported apart from the decisions);
- the special addresses lacked cloud metadata services outside link-local
  (`100.100.100.200`, `fd00:ec2::254`), `::/96` and NAT64 forms.

**The parsers: no disagreement.** The decision procedure, the certificate
checker and the cross-check oracle agreed on about 1,700 hand-written
policies at every boundary of the grammar, and on 600 more fuzzed ones; an
ASan/UBSan build of `shared_domains.c` read 300 hostile list files cleanly.

**Not fixed, and stated.** A deny wildcard holds on names only (see Known
limits). Two smaller notes were left as they are: each question scans up to
4,096 dynamic names, and nothing limits how fast an agent adds question
records (it can add records as fast with file opens).

## Known limits

- **The name channel is bounded, not closed.** Within its budgets, the
  labels an agent chooses reach the domain's DNS servers and the host's
  resolver. The domain's DNS may be run by a provider other than the
  party behind the API. At the defaults, per rule:
  - new names carry at most about 10.5 KB a run, at most 1.2 KB a minute;
  - after that, the choice of names asked again carries at most about 30
    bytes a minute (8 bits a lookup, 30 lookups a minute), about 43 KB a
    day;
  - the timing of each lookup can carry a few bits more.

  The v1.26 egress proxy decides on the name without a lookup by the agent.
- **A deny wildcard holds on names only.** `deny host *.internal.example.com`
  refuses names under it that the agent asks for, but its hosts cannot be
  resolved in advance. So an allowed name that is a CNAME to one of them, or
  shares an address with one, still connects. An exact deny holds on
  addresses. For an address-level deny, write the names exactly, or deny the
  addresses.
- **Shared CDN addresses**, as in v1.24: a name decides which addresses
  the agent may reach, not which site it asks for there.
- **The shared-domain lists are snapshots.** A domain where anyone can
  register names, and which neither list holds, is not refused. The VAREK
  list is reviewed each release. Lists named with `--psl` or
  `--shared-domains` are the operator's; `run_start` says so, and the
  audit checks each wildcard against the release's lists anyway.
- **Without a network namespace of its own** for the agent there is no
  stub, and names that only a wildcard allows do not resolve. The Warden
  says so at startup.
- **A port that only a glob over ports allows** is not tried when the stub
  decides whether to answer a name. Such a name gets NXDOMAIN, the safe
  side.

## Upgrading

1. To allow a domain's names, add `require warden 1.25` and
   `allow host *.<domain>:<port> acknowledge=dns-channel`. Set `names=` and
   `rate=` if the defaults do not fit.
2. Run `varek policy check <policy>`. It names any wildcard refused as a
   shared domain, and any wildcard missing the acknowledgment.
3. Install the lists with `make install`, or point the Warden at them with
   `--psl` and `--shared-domains`.
4. Watch `varek refusals` for BUDGET lines in the first runs.
