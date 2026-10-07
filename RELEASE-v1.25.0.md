# VAREK v1.25.0 — Wildcard Host Names, Opt-In

> **DRAFT, not released.** Still to come before tagging:
> - the 24-hour soak report (Wikipedia, 40 names on one address);
> - a review of the change;
> - the latency of a lookup through the stub;
> - the README, threat model and spec paper updates.

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
   - on the VAREK list of 31 multi-tenant domains the Public Suffix List
     lacks (`*.my.salesforce.com`, `*.slack.com`, `*.wordpress.com`).

   Both lists ship pinned with the release, and their SHA-256 is in
   `run_start`.
4. **The stub resolver.** With a wildcard allow rule, the agent's
   `resolv.conf` view names `127.53.53.53`. That is a UDP and TCP resolver the
   Warden runs inside the agent's own network namespace.
   - A name no allow rule can reach gets NXDOMAIN at once, and no question
     leaves the host.
   - A name a wildcard allows is looked up by the Warden's resolver helper
     when the agent asks, and recorded as a `resolution` record.
   - Every other connect to port 53 is still refused.
5. **Budgets on the name channel.** Each wildcard allow rule has a budget
   of new names a run (`names=`, default 256) and a minute (`rate=`, default
   30), and at most 63 bytes before the suffix. A new name past a budget
   gets NXDOMAIN and is not looked up. At the defaults, the names an agent
   chooses can carry at most about 10.5 KB a rule a run.
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

`make test-v1250` runs 132 checks; CI runs it, with the Warden as root.

- **Grammar:** 52 checks of accepted and refused forms, each in both
  parsers, including the acknowledgment and the budgets.
- **Shared domains:** 29 checks. `shared_domains.c` agrees with an
  independent Python statement of the rule on 17,840 suffixes, and encodes
  all 440 Unicode labels in the list as Python does.
- **The stub, with real clients as the agent:** 32 checks.
  - Clients: Python, curl, Node (`dns.lookup` and `dns.resolve4`), Go,
    Java and a static musl binary.
  - Each resolves a name a wildcard allows through the stub and connects,
    decided on the name.
  - A name outside every rule fails within 50 ms, and a recording upstream
    server receives no question for it.
  - TXT questions, TCP fallback and a connect to 127.0.0.1:53 are covered.
- **Budgets:** 12 checks. A DNS-tunnel style client is held to `names=`,
  `rate=` and the label budget, every refusal is recorded, and edited
  streams fail the audit.
- **Many names on one address:** 7 checks. 40 names on one address all
  fetch, their connects are recorded hashed, and the audit accepts the run.
  A forged resolution record fails the audit. A name that expires unasked
  is recorded as retired, and a later connect to its address under another
  name is accepted.

**Regression.** Against the v1.24 Warden, parsers and audit, the suite fails
108 of its 132 checks. Of the 24 it passes, 20 are the shared-domain unit
test, which does not involve the Warden. The other 4 pass trivially because
the old Warden refuses the policy: the oracle agrees on refusing it, a
lint check on an ordinary wildcard, and two checks that no question left
the host.

`make crosscheck` passes with 0 disagreements, with wildcards, budgets and
the acknowledgment in the fuzzed policies (present, missing, misspelt,
twice and misplaced).

## 24 hours against Wikipedia

PENDING. `tests/soak_v1250/soak.sh` fetches the Wikipedia API of 40
language editions, `https://<lang>.wikipedia.org/`, one fetch a minute in
turn, under `allow host *.wikipedia.org:443 acknowledge=dns-channel` at the
default budgets. Every edition is served from the same addresses, as
per-tenant names behind a CDN are, so each connect is decided over many
names on one address. The run must show:
- no refused connect caused by a stale table;
- every question to the stub recorded;
- no budget hit at the default budgets.

## Latency

PENDING: the time a lookup through the stub adds, and a connect decided
over 40 names on one address.

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
- New records and rules: `dns_question`, and the rules `dns_stub`,
  `wildcard_budget`, `netsvc_view` and `svc_view`.
- `varek refusals` lists budget refusals as BUDGET. `varek policy show`
  lists each wildcard rule's budgets, and says the agent's lookups under
  it leave the host.
- `run_start` reports the Warden as `1.25.0`, and the startup message
  reports the policy grammar as v1.25.

## Found in review

PENDING.

## Known limits

- **The name channel is bounded, not closed.** Within its budgets, the
  labels an agent chooses reach the domain's DNS servers and the host's
  resolver. The domain's DNS may be run by a provider other than the
  party behind the API. At the defaults this is at most about 10.5 KB a
  rule a run, and 1.2 KB a minute. The v1.26 egress proxy decides on the
  name without a lookup by the agent.
- **Shared CDN addresses**, as in v1.24: a name decides which addresses
  the agent may reach, not which site it asks for there.
- **The shared-domain lists are snapshots.** A domain where anyone can
  register names, and which neither list holds, is not refused. The VAREK
  list is reviewed each release.
- **Without a network namespace of its own** for the agent there is no
  stub, and names that only a wildcard allows do not resolve. The Warden
  says so at startup.
- **A port that only a glob over ports allows** is not tried when the stub
  decides whether to answer a name. Such a name gets NXDOMAIN, the safe
  side.
- **Timing.** Re-asking a name already charged costs nothing against the
  budgets. Its timing can carry a few bits, which no budget bounds.

## Upgrading

1. To allow a domain's names, add `require warden 1.25` and
   `allow host *.<domain>:<port> acknowledge=dns-channel`. Set `names=` and
   `rate=` if the defaults do not fit.
2. Run `varek policy check <policy>`. It names any wildcard refused as a
   shared domain, and any wildcard missing the acknowledgment.
3. Install the lists with `make install`, or point the Warden at them with
   `--psl` and `--shared-domains`.
4. Watch `varek refusals` for BUDGET lines in the first runs.
