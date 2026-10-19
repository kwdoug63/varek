# VAREK

### Kernel-enforced, proof-checked authorization for what an AI agent's process actually does.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/language-v1.0%20stable-blue.svg)](https://github.com/kwdoug63/varek/releases)
[![Runtime](https://img.shields.io/badge/runtime-v1.32.1-green.svg)](https://github.com/kwdoug63/varek/releases)
[![Verdict](https://img.shields.io/badge/verdict-SATISFIED%20%7C%20UNSATISFIED%20%7C%20UNKNOWN-7a5cff.svg)](#the-verdict-model)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **Reporting vulnerabilities:** [private vulnerability reporting](https://github.com/kwdoug63/varek/security/advisories/new) or [SECURITY.md](./SECURITY.md). Do not open public issues.

## What VAREK is

VAREK decides whether an AI agent's planned actions are allowed **before** they
execute, and enforces that decision at the kernel boundary.

An agent's intended actions are represented as an **action-graph** — a directed
acyclic graph of planned actions. Before the agent starts, the Warden's optional
`--plan` gate checks a declared action-graph: every step against the policy and,
with `--flow-policy`, the data flowing along its edges. While the agent runs, the
**Warden** pauses each file open, file lookup (`stat`, `access`, `readlink`),
connect, program launch and datagram send at the kernel (via seccomp-BPF and
seccomp user-notify) and decides it before the kernel carries it out. File opens, lookups and
connects are decided by an **SMT decision procedure**: in the Warden, a
purpose-built procedure for a decidable fragment — bounded strings for the object
(prefix, exact, suffix, contains and glob matching), bitvectors for the open
flags — that decides in microseconds with bounded worst case, is cross-checked
against an off-the-shelf SMT solver, and returns UNKNOWN for anything outside its
fragment rather than guessing. Every file open and connect it authorizes, and
every lookup it decides, carries a certificate that a small, independently
written checker must accept before the call takes effect. Lookups of the
directories leading to an allowed path, and of descriptors the agent already
holds, are answered without a decision. Since v1.21.0 a connect is decided on the
destination the Warden copied once, and an allowed one is dialed by the Warden
and handed to the agent as a connected socket; the agent's own network namespace
stays empty. A datagram send that names a destination is refused whatever the
policy says; a send with no destination goes to the peer of a connect the Warden
decided. Every launch after the agent's own is refused too, unless the policy
opts in with `require warden 1.27` (v1.27.0): then each is decided, and the
kernel's Landlock holds the agent to the programs the policy allows; from
v1.27.1 the directories it may write are also mounted `noexec`, so nothing
written during the run is launched or mapped executable. From v1.28.0 the agent
can hold only placeholders for the credentials it uses: the egress proxy puts
the value into a request only in the header an allowing rule names, on a
request the Warden decided SATISFIED, and `varek revoke` refuses every later
call of a run. From v1.28.1 every decision record says whom it was for: the
user an identity provider vouched for, the agent, and the sub-agent that made
the call, each sub-agent held in a control group of its own from its launch.
From v1.29.0, `sudo varek run -- claude` (or another agent) runs with nothing
set up first: VAREK writes a policy for the run, opens files as the agent's own
user so the kernel's permissions hold as well as the policy, and a dry run
records what a narrower policy would refuse, for `varek policy suggest` to draft
from. From v1.31.0 a local MCP server is held to the rules written for it and
none of the agent's, a call to a remote MCP server is decided by its method and
tool, an MCP token reaches only the server it was issued for, and the verdict
stream exports as OCSF events a SIEM can read. Every verdict is one of three — **SATISFIED**,
**UNSATISFIED**, or **UNKNOWN** — and it fails closed: a paused call that cannot
be proven allowed never runs. System calls the kernel filter admits without
asking (memory, time, threads, and reads and writes on descriptors the agent
already holds, whether the Warden opened them or the agent made them, such as
sockets and pipes) run undecided, and the rest are refused outright.

The design premise is a clinical one: you do not deploy a system that is
*usually* right when the cost of being wrong is unbounded. UNKNOWN is therefore a
first-class verdict, not an error path — VAREK never coerces "cannot prove safe"
into a pass.

VAREK has two layers, developed in sequence:

1. **The Warden runtime** — the verification and enforcement layer. It is where
   active development lives and where the verification thesis above is realized.
   **Current release: v1.32.1.**
2. **VAREK the language** — a statically-typed, LLVM-compiled language for AI/ML
   pipelines, where unsafe operations are not expressible in the first place.
   **Stable at v1.0.**

The runtime can protect any agent stack (LangChain, AutoGen, CrewAI, custom
orchestrators), and it does not depend on the model provider or agent platform:
the decision is made and enforced outside the agent, at the kernel boundary, and
its evidence — the verdict stream and the CycloneDX 1.6 export — can be inspected
without relying on the agent's vendor. The language is for pipelines you write fresh. They are useful
independently and complementary together.

## The verdict model

Every decision is total and three-state. There is no fourth outcome and no
silent default.

| Verdict | Meaning | Disposition |
|---------|---------|-------------|
| **SATISFIED** | Provably allowed under the policy, within the decidable fragment. | Proceed. |
| **UNSATISFIED** | A concrete policy violation, identified. | Refuse. |
| **UNKNOWN** | Cannot be decided either way within bounds. | **Fail closed** — never coerced to a pass. |

A two-state allow/deny system must convert every UNKNOWN into a false allow or a
false block. VAREK refuses that conversion. In the running agent an UNKNOWN is
refused, like an UNSATISFIED (symmetric suppression). At the `--plan` gate with a
`--flow-policy`, it goes to the deterministic disposition that policy declares,
and the Warden refuses to start unless a check at load time certifies that every
refusal ends in an automated outcome, so none needs a human to break a loop (see
progress-safety, below). That refusal is what separates a verifier from a
heuristic — nothing is SATISFIED unless it is provably safe.

## Layer 1 — the Warden runtime

### What it does

Warden sits between an agent framework and the operating system. Before contained
code opens or looks up a file, connects, sends a datagram or launches a program,
the Warden decides that call and enforces the verdict at the kernel; with
`--plan`, the whole declared action-graph is also checked before the agent
starts. Since v1.21 an allowed connect is dialed by the Warden itself and the
connected socket handed to the agent, the way allowed files have been handed
over since v1.12. This is structural containment — not a string-match denylist that
falls to absolute paths, base64 encoding, or renamed binaries.

The runtime line has progressed well beyond simple syscall containment:

- **v1.7 — cross-action data-flow verification.** Reasoning across edges of the
  action-graph, not just per-action checks. Run by the Warden's `--plan` gate
  with `--flow-policy` since v1.18.0; through v1.17.0 it was a library with tests
  that the Warden did not call. Since v1.20.0 a plan step can declare fields
  besides its target, which the flow rules can match.
- **v1.8.2 — bounded-refusal breaker.** A loop bound in the trusted boundary,
  keyed by `(session, action-graph signature)`, so a stuck planner cannot
  resubmit the same refused action-graph forever: after the policy's refusal
  budget, the outcome is a declared terminal (deny, or a pre-authorized action).
  Each verdict stays a pure function of `(plan, policy)`; the breaker only
  interprets the *sequence* of verdicts. In the Warden since v1.18.0, with its
  counts kept across runs in a state file the agent cannot reach. Since v1.19.0
  it also bounds each session (`session_refusal_budget`), so a planner that
  submits a different graph each time is stopped too.
- **v1.9.0 — progress-safety / HOOTL.** A load-time liveness proof that certifies
  human-out-of-the-loop operation per policy: for every non-authorizing verdict,
  a deterministic, automated terminal outcome is reachable in finitely many steps.
  "Never requires a human" becomes certified rather than hoped. Since v1.18.0 the
  Warden runs it on the `--flow-policy` at startup and refuses to start if it
  fails.
- **v1.32.1 — rootless Podman without `--systemd=always` (a patch release of v1.32.0).** Podman mounts a rootless container's cgroup filesystem read-only; through v1.32.0 the Warden then refused sub-agents and confined MCP servers there unless the container ran with `--systemd=always`. Measured on rootless Podman, the bind remount it makes elsewhere works in a user namespace too, so from v1.32.1 it makes it there, and refuses, naming that flag or the missing cgroup delegation, only where the kernel or the delegation does not allow it. Every suite passes rootless without `--systemd=always`. See [`RELEASE-v1.32.1.md`](./RELEASE-v1.32.1.md).
- **v1.32.0 — containers: an official image, Docker and Podman.** Through v1.31.1 the Warden ran as root on a host, and under Docker's or Podman's defaults it refused to start. `ghcr.io/kwdoug63/varek` carries the Warden, its helpers and `varek` on UBI 9 minimal, its entrypoint `varek run --`, so the agent is the Warden's child in namespaces it makes inside the container. The documented settings, never `--privileged`: `--cap-drop ALL` and ten capabilities, each shown needed, `--cgroupns=private`, the runtime's default seccomp profile, VAREK's AppArmor profile or SELinux module (`container_init_t`), and rootless Podman with `--systemd=always`. Sub-agents and confined MCP servers run in a container: the Warden bind-remounts the container's own cgroup view read-write in its own mount namespace, and, with no process events there, tells a sub-agent of its launcher's image by its memory layout. `varek doctor` checks each setting and names the flag for a missing one; `varek run` refuses a container that cannot carry the run. Each tag's image is signed with cosign and carries a CycloneDX SBOM as a signed attestation. Every suite passes inside the container on Docker with AppArmor and on rootful and rootless Podman with SELinux; a 24-hour soak in a container. Reviewed by AI review agents. See [`RELEASE-v1.32.0.md`](./RELEASE-v1.32.0.md).
- **v1.31.1 — calls glibc and bash make (a patch release of v1.31.0).** The Warden refused `epoll_wait(2)` and `epoll_create(2)` on x86_64, so asyncio's default event loop failed under every policy; `pipe(2)`, so a shell's command substitution failed on RHEL 9; and, under a policy before 1.29, `getpgrp(2)`, so bash did not start. All four are admitted. See [`RELEASE-v1.31.1.md`](./RELEASE-v1.31.1.md).
- **v1.31.0 — MCP servers confined, MCP calls decided, MCP tokens bound, and an OCSF export.** Through v1.29.0 an MCP server the agent launched was decided by the agent's rules, a call to a remote MCP server was one `POST` to one URL, and no SIEM read VAREK's evidence. Under `require warden 1.31`, `mcp server NAME exec PATH [sha256=HEX]` declares a server: launched by the agent, it runs in a control group of its own and every call it and its children make is decided against the rules written `for=NAME` and no others, with the subject named in each certificate. The start is refused for a server file any subject may write, one whose SHA-256 is not its pin, or one that is or reaches an interpreter or a launcher; a confined launch whose environment names code (`PYTHONPATH`, `NODE_OPTIONS --require`, `LD_PRELOAD`, ...) is refused. Under `proxy inspect`, `allow|deny mcp URL METHOD [NAME]` decides each JSON-RPC call to a remote server on its method and the tool, resource or prompt it names, read by a strict parser from the body the server will act on, before any of it is sent. A credential with `audience=URL` is an MCP token, checked at fetch and released only into calls to that server; a token the agent sends that is the user's, for another audience, expired, or not a strict compact JWT is refused; `trust mcp-resource` finds the user's issuer through a server's protected resource metadata. `varek export --format ocsf` writes OCSF 1.9.0 events (`--follow` on a live run, `--verify` against the stream); the audit checks each decision against its subject's rules; `docs/standards/agent-baseline.md` maps the Agent Baseline's 35 controls. The rule cap is 512. Reviewed by AI review agents. See [`RELEASE-v1.31.0.md`](./RELEASE-v1.31.0.md).
- **v1.29.0 — `varek run` with nothing set up first, a dry run, and `varek policy suggest`.** Through v1.28.1 an agent ran under VAREK only after someone wrote a policy for it. With no settings, `varek run` now writes one for the run (root's, stored by its SHA-256, shown by `--show-policy`): the credential stores and keys refused first, the system read-only, the working directory and a private temporary directory writable, the home closed but for the agent's profile, launches of root's programs by name, no network but the profile's hosts. Profiles for Claude Code, the Codex CLI, the Gemini CLI, Aider, Python and Node.js were built from dry runs of the real agents and checked by running each enforcing against the same command without VAREK. Under `require warden 1.29` files are opened, and changed by name (unlink, mkdir, rename, chmod and the rest, each decided as a write), as the agent's own user, so a call needs the policy and the kernel's permissions both. `--dry-run` decides and records every call and lets through what the policy refuses (`"enforced":false`), except the hard-denied calls, the protected objects, Unix-socket connects and revocation; the audit verifies such a stream with exit 3, never 0, and every tool and the export say it was not enforced. `varek policy suggest` drafts exact rules from a run's refusals, each re-decided, and never makes active one for a credential store, another user's home, a deny rule's object or a program the agent wrote. See [`RELEASE-v1.29.0.md`](./RELEASE-v1.29.0.md).
- **v1.28.1 — who each decision was for: the on-behalf-of chain.** Through v1.28.0 a verdict said what the agent did and which rule decided it, but not on whose behalf. After `require warden 1.28`, `trust issuer URL audience AUD` names an identity provider and `--on-behalf-of FILE` gives the run the user's token (a JWT, possibly from an OAuth 2.0 token exchange): `warden-secrets` verifies its signature against the issuer's keys fetched over verified HTTPS (RS256, PS256, ES256 or EdDSA; `none` and HMAC refused), its issuer, audience and times, and its `act` chain, and only the verified claims reach the Warden. `trust spiffe DOMAIN bundle PATH` and `--agent-svid FILE` verify the agent's X.509-SVID. `subagent=NAME` on an `allow exec` rule makes the program it launches a sub-agent: the Warden gives it a control group (cgroup v2) of its own at its launch and attributes every call by its process's group, so a sub-agent's calls, and those of everything it starts, count as its own whatever it says about itself. Every decision record carries `obo` (`["user", "agent", "subagent:coder#1"]`) and `run_start` the verified chain; when the user's token expires the run is revoked (or, with `--on-behalf-of-expiry record`, recorded). The audit checks every record's chain against the launches and the policy; `varek runs`, `varek refusals --subagent/--user`, `varek policy show`, `varek doctor` and the CycloneDX export show it. The chain is recorded, not enforced: no rule depends on it yet. A 24-hour soak passed, every sub-agent's calls attributed to it and the run revoked when the user's token expired. Reviewed by AI review agents. See [`RELEASE-v1.28.1.md`](./RELEASE-v1.28.1.md).
- **v1.28.0 — credential release: the agent holds only placeholders.** An agent that calls an API needed the API's key in its own memory, where anything it ran could read it and send it anywhere a rule allowed. With `credential NAME from STORE:REF` (after `require warden 1.28`), a separate helper, `warden-secrets` (its own binary, recorded by hash, running as its own user), fetches each credential at startup from a file, HashiCorp Vault (KV, or a leased secret it renews) or AWS Secrets Manager, and hands the values to the egress proxy, never to the Warden. The agent gets a placeholder in `VAREK_CRED_<NAME>`. In inspecting mode, on a request an `allow request ... credential=NAME header=HEADER[:SCHEME]` rule decides SATISFIED (an `https://` rule only), the proxy puts the value in place of the placeholder in that header, and refuses the request if the header does not hold exactly the placeholder; a placeholder anywhere else is sent as it is. `varek revoke <run>` refuses every later call of the run, has the proxy clear every value and close every connection, and revokes the run's Vault leases. `run_start` records each credential's source, version and placeholder's SHA-256 (never a value), and the audit checks every request that carried one against its rule. A server the policy allows that echoes request headers back would hand the value to the agent: the policy must not allow such an endpoint. A 24-hour soak passed, every value only where its rule names it and the revocation honored. Reviewed by AI review agents. See [`RELEASE-v1.28.0.md`](./RELEASE-v1.28.0.md).
- **v1.27.2 — checkpoints within their bound (a patch release of v1.27.1).** A signed stream with the inspecting proxy could hold more than `checkpoint_every` records between two signatures when the agent made requests in bursts, and fail its own audit; a checkpoint is now written before any record that would pass the bound. Decisions were never affected; the fix was already in v1.28.0 and later. See [`RELEASE-v1.27.2.md`](./RELEASE-v1.27.2.md).
- **v1.27.1 — nothing written during the run is mapped executable.** v1.27.0 kept the agent from launching a file it wrote, but Landlock does not govern the executable mappings of shared libraries, so a library the agent wrote could still be loaded into an allowed program. Under the same `require warden 1.27`, the Warden now mounts every directory the policy lets the agent write `noexec` in its own private mount namespace, where it opens every file it hands the agent: a file there can be neither launched nor mapped executable (`EPERM`, `EACCES`), and a file that does not reach the agent through such a mount is refused. Anonymous executable memory (a JIT's) is unchanged, and this release does not claim to cover code written into memory. The operator can turn it off for a run with `--writable-exec`, which is recorded. `run_start` records each directory and the audit checks it against the policy. A 24-hour soak passed, every library the agent wrote refused. Reviewed by AI review agents. See [`RELEASE-v1.27.1.md`](./RELEASE-v1.27.1.md).
- **v1.27.0 — decided program launches.** Through v1.26.1 every launch after the agent's own was refused, so an agent could not run `git`, `python3` or a compiler even where the policy named them. With `require warden 1.27`, `allow exec` rules take effect: at startup the Warden expands them to the files they admit (with each dynamic program's loader) and the agent runs in a Landlock domain that lets it launch those files and no others; each launch is decided on its name by the SMT decision procedure, with a certificate, and recorded with the file's startup hash; before the Warden answers any call of a launched process it checks the process runs a program it decided to run, and kills it otherwise. Without Landlock, launches stay refused. gcc compiles and links under the Warden; a 24-hour soak passed. Libraries are not decided (planned for v1.27.1). See [`RELEASE-v1.27.0.md`](./RELEASE-v1.27.0.md).
- **v1.26.1 — the egress proxy's inspecting mode.** In SNI mode the Warden decides which site the agent connects to, but not what it asks there: inside TLS a request for any path, or with a `Host` for another site on the same CDN, went through. With `proxy inspect`, the proxy (now its own binary, `warden-proxy`, loaded into a sealed memfd and recorded by hash) verifies each server, terminates the agent's TLS with a CA made for the run and name-constrained to the policy's names, and reports every request; the Warden decides its method, path and query against `allow|deny request METHOD URL [max_body=N]` rules with the SMT decision procedure and certifies it before a byte of it is sent. Requests a server could read as another path are refused, bodies are bounded by `max_body` and recorded by length and SHA-256 (never stored), and hosts whose clients pin certificates can stay in SNI mode (`proxy passthrough host`). The agent's usual clients (Python, curl, Node.js, Java) trust the run's CA without changes. Every request is a chained record the audit asks of the policy again; `varek refusals`, the CycloneDX export and `varek bench --proxy` cover it. Reviewed by AI review agents. See [`RELEASE-v1.26.1.md`](./RELEASE-v1.26.1.md).
- **v1.26.0 — the egress proxy, SNI mode.** v1.24 and v1.25 decide a connect on its address, so an allowed name on a shared CDN address also reached every other site there. With `proxy on` (after `require warden 1.26`), connects on ports 80 and 443 (or `proxy ports`) are decided on the name the client asks for: a separate, unprivileged proxy reads the TLS SNI, the HTTP `Host` or a `CONNECT`, and the Warden decides that name with the SMT decision procedure, certifies it, dials only an address the name resolves to, and passes the socket to the proxy to relay. Names allowed only on proxied ports get synthetic addresses, so the agent sends no DNS for them. Plain HTTP is checked request by request; Encrypted Client Hello and QUIC on proxied ports are refused. `proxy upstream http://HOST:PORT` chains to a customer's egress proxy after the Warden decides. Every hand-off, decision and close is a chained record the audit checks. Reviewed by AI review agents. See [`RELEASE-v1.26.0.md`](./RELEASE-v1.26.0.md).
- **v1.25.0 — wildcard host names, opt-in.** v1.24 needed every name listed in advance, so an agent that reaches per-tenant names (`acme.api.example.com`) could not be supported. A policy can now allow every name under a domain: `allow host *.example.com:443 acknowledge=dns-channel`, after `require warden 1.25`. Under a wildcard the agent's lookups have to leave the host, so the rule is opt-in and says so: without `acknowledge=dns-channel` the policy is refused. A wildcard over a domain where anyone can create a name (a public suffix, the Public Suffix List's private section, or a VAREK list of 56 multi-tenant domains such as `my.salesforce.com` and `slack.com`, or a domain above one of these) is refused at load. The agent's lookups go to a stub resolver the Warden runs in the agent's own network namespace: a name no rule allows gets NXDOMAIN and nothing leaves the host, and a name a wildcard allows is looked up by the Warden and recorded. Each wildcard rule has budgets (256 new names a run and 30 lookups upstream a minute by default), every question is a chained record, and the audit checks every charge. A connect is decided over every name its address belongs to, with no limit. See [`RELEASE-v1.25.0.md`](./RELEASE-v1.25.0.md).
- **v1.24.0 — host names without agent DNS.** Through v1.23 a host rule matched only a numeric address, so a policy either hard-coded addresses that a cloud provider or content network moves, or let the agent reach a DNS server, through which it can send data out in its questions. A policy can now name hosts (`allow host api.salesforce.com:443`, after `require warden 1.24`). The Warden resolves every named host itself, through a resolver helper process, refreshes each at its TTL and records every lookup in the verdict stream; the agent reads `/etc/hosts`, `resolv.conf`, `nsswitch.conf` and `host.conf` views the Warden writes, and every connect to port 53 is refused. A connect is decided on its address and on each allowed name that address belongs to, the certificate covers the deciding name, and `varek_audit.py` checks every name binding against the lookup records. It ran 24 hours against Fastly, Cloudflare and CloudFront with 4,320 of 4,320 fetches succeeding while CloudFront changed its answer 2,034 times. An AI review found and fixed names that could lead to the host's own loopback services, forged streams the audit accepted, and writable opens of the resolver files. See [`RELEASE-v1.24.0.md`](./RELEASE-v1.24.0.md).
- **v1.22.0 — the `varek` command and `varek bench`.** One command runs and checks the Warden with shared settings in `/etc/varek/varek.conf`: `doctor`, `init`, `policy`, `preflight`, `run`, `refusals`, `audit`, `export` (signed CycloneDX 1.6) and `bench`; `sudo make install` puts it in `/usr/local/bin`. `varek bench` measures what mediation costs per call on the host it runs on, natively and under the Warden, and checks every verdict: on a 2-vCPU host an authorized open takes 70–80 µs under the Warden (2.4 natively), a refused open 53–57 µs, an allowed connect 143–148 µs (23–24 natively); the Warden's own time is 13–17, 56–66 and 114–118 µs ([results](./varek/v1_4/bench_results_v1_22_0.txt)). The "8 µs" median published with v1.14–v1.16 was the Warden's own time over a mix with no dialed connects, not what the agent waits. Also: the Core packs allow `/usr/lib64/` read-only (RHEL, Fedora, Amazon Linux), and the Warden builds on glibc 2.34. The Warden's decisions are unchanged. See [`RELEASE-v1.22.0.md`](./RELEASE-v1.22.0.md).
- **v1.21.1 — plan steps say how they open.** A plan step had no open flags, so the `--plan` gate decided a `file_open` step with the flags unknown, and a path the policy allows only read-only (every shipped sector policy's libraries, and data in four of them) was UNKNOWN at the gate although the runtime allowed the read. A `file_open` step may now declare `open=read`, or an access mode and flags (`open=O_WRONLY|O_CREAT|O_TRUNC`), and the gate decides it with those flags; anything it does not understand is UNKNOWN. Also corrects the sample plan and the data-flow threat model, which still said every connect step is refused. See [`RELEASE-v1.21.1.md`](./RELEASE-v1.21.1.md).
- **v1.21.0 — decided connections.** Through v1.20.0 a supervised agent had no network: every connect was refused, whatever the policy said, because letting an allowed connect continue in the kernel would let a second thread change the destination after the check. The Warden now decides each connect on the destination it copied once (the independent checker confirms any ALLOW), dials it itself from outside the agent's empty network namespace, and hands over the connected socket with `SECCOMP_IOCTL_NOTIF_ADDFD`, carrying over the socket options the agent set (the 58 the Warden knows; others set before the connect are not carried). TCP and connected UDP over IPv4 and IPv6, and Unix sockets decided on their canonical path (IPv6 decisions are tested; IPv6 dialing was not exercised on the release host, whose kernel has no IPv6, and the test reports it as SKIPPED there). The plan gate decides `net_connect` steps instead of refusing them. Tested with curl, Python `requests` and Node.js, and with a 2,000-attempt destination-swap race that reached the denied side 0 times. On a 2-vCPU test host a connect took about 75 to 125 µs longer than a native one at the median, and more at p99; a `requests.get` to a local server about 0.17 ms longer (1.21 → 1.38 ms). Figures in the release notes. Also: the sector policies' key and credential rules match in any case (`server.PEM`, `x.pem.bak`, `id_rsa` outside `.ssh` were allowed), Node.js runs under the Warden at all (`io_uring_setup` answers `ENOSYS`), and the preflight checks the plan gate's flow policy and count file. See [`RELEASE-v1.21.0.md`](./RELEASE-v1.21.0.md).
- **v1.20.0 — fields on plan steps.** A plan step had one field, its target, so flow rules could see nothing else it declared. A step can now carry up to 16 `key=value` fields after its target (quoted values may hold spaces: `contains="a customer record"`), and the Warden's `--flow-policy` rules match them like any named argument. The node check and the runtime still see only the target. Fields are the agent's declarations, so the Warden refuses a flow policy whose rules match them unless it declares `trust_declared_fields`. The plan file's lines may be 16383 bytes (were 1022); targets stay under 4096 bytes. See [`RELEASE-v1.20.0.md`](./RELEASE-v1.20.0.md).
- **v1.19.0 — a refusal limit per session.** The plan gate's breaker counted refusals per (session, plan), so a planner that changed one step each time got a fresh count every time and was never stopped. A flow policy now declares `session_refusal_budget N`, which the Warden requires: the Nth refused plan in a session, and every refused plan after it, is terminal, whatever the plans were. Authorized plans still run and do not reset the count. `--gate-status` and the `plan_gate` record report the session's count; the state file moves to format 2 and v1.18.0 tables still load. See [`RELEASE-v1.19.0.md`](./RELEASE-v1.19.0.md).
- **v1.18.0 — the claims and the code agree.** A review listed ten places where the published claims and the code disagreed; each is fixed in the code or in the claim. The `--plan` gate now runs the v1.7 data-flow check, the v1.8.2 refusal breaker and the v1.9 progress-safety check (`--flow-policy`; the breaker's counts persist across runs in a state file the agent cannot reach), which through v1.17.0 were a library the Warden did not call, and it refuses connect and launch steps the runtime would refuse. Flow rules can match a URL's host (`match url.host`) instead of a whole-URL glob that matched outside hosts. The CycloneDX export's attestation is derived from the stream, checks the policy file, can be signed (JSF, Ed25519) and is tested against the CycloneDX 1.6 schema. Refusal records name `EACCES`, the errno sent. Release notes, CHANGELOG and the spec paper are corrected where they described code that was never committed, and figures without a record are re-measured or restated. See [`RELEASE-v1.18.0.md`](./RELEASE-v1.18.0.md).
- **v1.17.0 — closing three live gaps.** The signing key, the anchor and the verdict stream are refused by identity (device and inode) on every open and lookup, so a bind mount or hard link into an allowed tree no longer reaches them; raw storage and memory devices are refused the same way whatever the policy says. `stat`, `statx`, `access` and `readlink` are mediated like opens: decided, certified, recorded and answered by the Warden, where they were admitted and unlogged. The agent runs as an unprivileged user with no capabilities (`--run-as`, default `nobody`), where it ran as root with every capability. Adds `make test-v1170` (48 checks). See [`RELEASE-v1.17.0.md`](./RELEASE-v1.17.0.md).
- **v1.16.3 — the Verdict Service's plan checker, in the repository.** `v1_6/plan_verify_cli.c` (`make -C v1_6 plan_verify`) is the file-in / JSON-out front end the VAREK Verdict Service runs; its source had existed only on the service host. Its JSON output is now escaped: before, a crafted target could make the output read as SATISFIED when the evaluator had decided UNSATISFIED. See [`RELEASE-v1.16.3.md`](./RELEASE-v1.16.3.md).
- **v1.16.2 — off-host anchor.** An anchor on the Warden's own host does not protect against that host's root, who also holds the signing key. `tools/varek_anchor_forward.py` sends each checkpoint off the host within about a second (spooling through outages) to an append-only receiver set up by `tools/varek_anchor_receiver.sh` — an SSH account that can only append well-formed anchor lines to a `chattr +a` file — or to any command. The preflight now checks the forwarder is running and warns when the anchor or the key leave that gap open. See [`RELEASE-v1.16.2.md`](./RELEASE-v1.16.2.md).
- **v1.16.1 — deployment preflight.** `tools/varek_preflight.sh` checks a deployment ahead of its first run: the build dependencies (libsodium is new in v1.16; `make deps` installs them), the build, the policy, and every location the Warden refuses at startup — the verdict stream file, the signing key, the anchor — checked with the Warden's own rules, plus an optional audited trial run. All seven shipped policies pass with the stream in `/var/log/varek/`. A CI job builds the Warden with libseccomp and libsodium. See [`RELEASE-v1.16.1.md`](./RELEASE-v1.16.1.md).
- **v1.16.0 — a verdict stream its holder cannot rewrite, and a bound on every decision.** Addresses the two limits v1.15.0 disclosed. Every record is hash-chained; with `--sign-key`, run_start, a checkpoint every 64 records and run_end are signed with Ed25519; with `--anchor`, each checkpoint is also appended to storage the log's holder cannot rewrite. `tools/varek_audit.py --pubkey --anchor` then catches any edit, insertion, removal or reordering before the last signature, and a stream cut short, by someone without the key, and any rewrite of anchored history even by someone with it; it verifies signatures with its own pure-Python RFC 8032 verifier. The Warden refuses to start if the policy would let the agent open the key, the anchor, the verdict stream itself or a raw disk. Globs are capped at 4,096 tokens per policy, which bounds the work of one decision; the worst case measured is about 26 ms median in the live Warden (v1.15's checker alone: 415 ms), and real policies are unchanged. See [`RELEASE-v1.16.0.md`](./RELEASE-v1.16.0.md).
- **v1.15.0 — certificates: every authorization independently checked.** Third release of the v1.10 verification program. Every SATISFIED verdict now carries a certificate — the deciding rule and a witness that its constant matches — and the Warden authorizes the action only if a separately written checker accepts it (`checker/vdp_checker.c`: about 540 lines, its own policy parser and matchers, no code shared with the decision procedure). A bug confined to the decision procedure can no longer authorize an action: a test build with a planted bug shows the checker refusing its wrong verdicts. Certificates and the policy's SHA-256 go into the verdict stream, and `tools/varek_audit.py` re-checks a saved run without trusting the Warden that made it. See [`RELEASE-v1.15.0.md`](./RELEASE-v1.15.0.md).
- **v1.14.0 — the bounded string fragment.** Second release of the v1.10 verification program. Path and exec rules take a matcher before the constant — `exact`, `prefix` (the default), `suffix`, `contains` or `glob` (`?`, `[...]`, `*`, `**`, and `/**/` for any number of segments) — so a policy can deny a kind of file wherever it appears under an allowed tree: private keys (`suffix .pem`), dotenv files at any depth (`glob /**/.env`), a patient's psychotherapy notes. Matching is on the resolved canonical path, so a symlink with an innocent name is decided as its target. Globs compile to a small automaton stepped word-parallel (well under a microsecond added per decision; bounded worst case). At load the Warden decides exactly, by an automaton search bounded at the 4095-byte length limit, whether each rule can ever fire, and `vdp_check analyze` prints a shortest witness for each rule that can. The cross-check adds an independent derivative-based procedure for reachability alongside the solver. Every v1.13 policy keeps its meaning (checked against the v1.13.0 build). The example sector policies now deny key material, dotenv files and `.ssh` under every allowed tree, plus sector-specific paths. See [`RELEASE-v1.14.0.md`](./RELEASE-v1.14.0.md).
- **v1.13.0 — the SMT decision procedure in the enforcement path.** First release of the v1.10 verification program. Every file-open decision (correction, v1.18.0: through v1.13.0 this said every Warden decision; datagram sends and the agent's own launch are not decided by it, and connects and later launches are refused whatever it says) is now made by an SMT decision procedure over a quantifier-free fragment of bounded strings (the object) and 32-bit bitvectors (the open flags), with a fragment boundary that returns UNKNOWN rather than guessing. Policies can now say read-only (`readonly`, `access=`, `+O_…`/`-O_…`); through v1.12 a path rule admitted every open flag, so the example sector policies' "(read)" rules and loader rules admitted writes by a root agent — they now enforce read-only. At load the Warden reports every rule that can never fire (it found one in four example policies). The procedure is cross-checked against an off-the-shelf SMT solver (zero disagreements over 26,624 checks, `make crosscheck`), and a verdict-distribution harness gates on `unsafe_satisfied == 0`: on its synthetic seed corpus v1.13 clears 85.4% of safe file opens with none unsafe authorized, where the policies as v1.12.4 shipped them cleared 75.6% and authorized 24 unsafe opens. Flag clauses constrain the flags passed to `openat()` (`readonly` is sound; `fcntl` can change `O_APPEND` and a few others later). Median latency unchanged. See [`RELEASE-v1.13.0.md`](./RELEASE-v1.13.0.md).
- **v1.12.4 — the `--plan` gate authorizes file opens again.** Optional plan-time verification had rejected every plan that declared a `file_open` action since v1.12.0: the per-open decision moved to the resolved canonical path, but the plan decider (which runs before the agent is forked) never filled it, so every file-open node was UNKNOWN. The decider now decides on the lexically canonical form of the declared absolute path, so a plan opening a policy-allowed file verifies again; a `..` that lexically escapes, or a relative path, stays UNKNOWN. The gate does not follow symlinks (there is no agent yet) and remains an advisory pre-check — every open is still mediated per-syscall at runtime. Adds `make test-v1124`. See [`RELEASE-v1.12.4.md`](./RELEASE-v1.12.4.md).
- **v1.12.3 — dynamically linked agents.** Follows ordinary symlinks and decides policy on the object's canonical path, so a dynamically linked agent (CPython, a JVM, Node) can load its libraries — since v1.12.0 the resolver refused any path with a symlink, and on merged-`/usr` systems `/lib` and library SONAMEs are symlinks. The security property is unchanged: a symlink to a denied object is decided as that object and refused. `/proc/self` and `/proc/thread-self` are mapped to the agent's own process (never the Warden's), and any other process's `/proc`, or a procfs reached through a planted symlink, fails closed. Because the decision is on the canonical path, `allow path` prefixes name canonical locations (`/usr/lib/`, not `/lib/`). Adds `make test-v1123`. See [`RELEASE-v1.12.3.md`](./RELEASE-v1.12.3.md).
- **v1.12.2 — threads and child processes.** Agent code can now start threads, wait for its children and call `isatty()`. `clone3` answers `ENOSYS` instead of killing the process (glibc >= 2.34 creates every thread with it), so libc falls back to `clone()`, whose flags the filter checks; `clone3` still never runs and the namespace denials are unchanged. `wait4`/`waitid` are admitted, and `ioctl` is admitted for six read-or-own-descriptor requests (`TIOCSTI` and the rest stay refused). A filter-killed agent is now reported. Also closes an exec-allowlist bypass: the launch exec, answered with `CONTINUE`, was granted once per pid, so a thread could race its path; it is now granted once per run. Adds `make test-v1122`. Known issue: dynamically linked agents cannot yet load their libraries (symlinked paths are refused since v1.12.0); planned for v1.12.3. See [`RELEASE-v1.12.2.md`](./RELEASE-v1.12.2.md).
- **v1.12.1 — mediation-correctness follow-up.** Fixes three defects found in v1.12.0. A denied file open no longer has side effects: the Warden pins the object with `O_PATH`, decides, and only after ALLOW opens it with the agent's flags (v1.12.0 opened first, so a DENY could still truncate or create a file, and a FIFO could wedge the supervisor). The verdict stream is authenticated: the agent's stderr is relayed with an `[agent] ` prefix, every record carries a per-run id and a contiguous `seq`, and `varek_cyclonedx.py` refuses a stream holding a forged, missing or foreign record. Inbound networking is refused: `bind`/`listen`/`accept` are denied and the agent runs in its own network namespace. Adds `make test-v1121`. No verdict-semantics change. See [`RELEASE-v1.12.1.md`](./RELEASE-v1.12.1.md).
- **v1.12.0 — mediation correctness.** Closes five ways a supervised process could reach a denied object or corrupt the authorization record: `..` traversal and symlink/`/proc/self` escapes (the Warden now resolves the object once, decides policy on its canonical path, and injects that same fd — resolve-then-decide); audit-log forgery via a crafted pathname (all agent-controlled strings are JSON-escaped, records gain a `resolved` field); and datagram egress via `sendto`/`sendmsg` that bypassed the deny-only `connect` posture (both are now mediated as `net.send`). Adds a tool that exports authorization evidence in the CycloneDX 1.6 format (`tools/varek_cyclonedx.py`) and a `make test-v112` regression suite. No verdict-semantics change; v1.10/v1.11 remain reserved for the verification program below. See [`RELEASE-v1.12.0.md`](./RELEASE-v1.12.0.md).
- **v1.9.3 — lifecycle coupling in the live Warden.** If the supervisor stops, the agent stops, and so does everything it started: the agent runs in its own PID namespace and is killed on supervisor death, with a fork-race guard and a pidfd watch. The Warden now requires `CAP_SYS_ADMIN` and checks for it at startup. A crash test kills a live Warden and asserts no agent process survives. Also corrects the v1.9.2 record (bypass class 7 was partial at v1.9.2) and fixes conformance-target setup. See [`RELEASE-v1.9.3.md`](./RELEASE-v1.9.3.md).
- **v1.9.2 — mediation completeness.** Default-deny allowlist replacing allow-by-default; native-ABI lockdown (x32 bypass closed); hard-deny set; scalar-flag `CLONE_NEWUSER` denial; lifecycle-coupling module (integrated into the live Warden in v1.9.3). Default-deny baseline wired into the live Warden and validated by a conformance target; deny-only bootstrap-exec regression found and fixed. See [`RELEASE-v1.9.2.md`](./RELEASE-v1.9.2.md).
- **v1.9.1 — enforcement hardening, measured.** Closes an io_uring bypass (it
  dispatches I/O off the syscall path where seccomp can't see it), and removes the
  time-of-check-to-time-of-use (TOCTOU) race from file mediation: the supervisor
  resolves the approved path and injects the descriptor rather than letting the
  syscall re-read attacker-mutable memory. Measured against a race harness, the
  prior approve-then-continue strategy leaked the protected target (1,848 to
  1,889 times in 20,000 attempts on a 2-vCPU host, re-measured for v1.18.0; the
  510 quoted here before has no record); the resolve-and-inject strategy leaked 0. `connect`/`execve`
  are deny-only (fail closed) pending the v1.10 dial-and-inject path
  (connects: shipped in v1.21.0; launches, opt-in, in v1.27.0). See
  [`RELEASE-v1.9.1.md`](./RELEASE-v1.9.1.md).

See [`CHANGELOG.md`](./CHANGELOG.md) for the full v1.0–v1.17.0 history.

### Network

A supervised agent's network is decided connection by connection (v1.21).
When it calls `connect`, the Warden copies the destination once, decides it
against the policy's `host` rules with the SMT decision procedure (the
independent checker must accept any ALLOW), dials it itself from outside the
agent's network namespace, which has no working interface, and hands the agent
the connected socket in place of its own, the way it hands over files. The
kernel never reads the agent's copy of the destination, so a second thread
cannot change it after the check. Every connection is logged, chained and
signed like a file open.

```
allow host 10.20.0.15:443              # an address and port
allow host [2001:db8::15]:443          # IPv6
allow host 127.0.0.1                   # any port on this address
allow host unix:/run/fhir/gw.sock      # a Unix socket, by its canonical path
allow host api.salesforce.com:443      # a host name (v1.24, after `require warden 1.24`)
```

Covered: TCP and connected UDP over IPv4 and IPv6, Unix stream, datagram and
seqpacket sockets named by a path. IPv6 destinations are decided and certified
like IPv4 ones; dialing them was not exercised on the v1.21.0 release host (its
kernel has no IPv6), where `make test-v1210` reports that case as SKIPPED. Refused whatever the policy says: sends that
name their own destination (an unconnected datagram), inbound connections,
abstract Unix addresses, raw and other socket kinds.

Host rules may name hosts (v1.24). The Warden resolves every name a host
rule names itself, refreshes each at its TTL, and records every lookup in the
verdict stream. The agent reads an `/etc/hosts` view that lists only the
allowed names, and every connect to port 53 is refused, so the agent sends no
DNS of its own. A connect is decided on its address and on each allowed name
that address belongs to; a loopback, link-local, unspecified, multicast
or cloud metadata address is decided on the address alone, so only a numeric rule can allow it.
A name decides where the agent connects, not which site it asks for there:
an address on a shared content network also serves other sites, which the
v1.26 egress proxy closes on the ports it proxies. See
[`RELEASE-v1.24.0.md`](./RELEASE-v1.24.0.md).

A rule may also allow every name under a domain (v1.25):
`allow host *.example.com:443 acknowledge=dns-channel`. Those names are known
only when the agent asks for one, so its lookups go to a stub resolver the
Warden runs, and from there out of the host: the acknowledgment is required
so the policy says so. Wildcards over domains where anyone can create a name
are refused at load, each rule's names and lookups are budgeted (256 new
names a run and 30 lookups upstream a minute by default, `names=` and `rate=`
to change them), and every question is recorded. See [`RELEASE-v1.25.0.md`](./RELEASE-v1.25.0.md).

With `proxy on` (v1.26), connects on the proxied ports (80 and 443 by
default) go to an unprivileged egress proxy, and the Warden decides each on
the name the client sends (TLS SNI, HTTP `Host`), not on the address. Names
allowed only on those ports get synthetic addresses from 198.18.0.0/15, so
the agent looks nothing up for them. A numeric rule still dials its address
directly. `proxy upstream http://HOST:PORT` chains to your own egress proxy
after the Warden has decided. In this mode only the ClientHello is read
inside TLS. See [`RELEASE-v1.26.0.md`](./RELEASE-v1.26.0.md).

With `proxy inspect` (v1.26.1), every request is decided too:

```
require warden 1.26
proxy inspect
allow host api.example.com:443
deny  request * https://api.example.com/v1/admin/**
allow request GET https://api.example.com/v1/models
allow request GET https://api.example.com/v1/files?limit=*
allow request POST https://api.example.com/v1/chat/completions max_body=256k
```

The proxy verifies the server, answers the agent with a certificate from a
CA made for the run (added to the host's roots at the system bundle's paths,
and named in `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` and `JAVA_TOOL_OPTIONS`), and
holds each request until the Warden has decided `METHOD
scheme://host:port/path?query`. A request no rule allows is refused with a
403, an allow rule without a `?` allows no query, and a deny rule without one
holds whatever the query. See [`RELEASE-v1.26.1.md`](./RELEASE-v1.26.1.md).

VAREK decides *where* an agent may connect and, in inspecting mode, *which
requests* it makes there. *What* it sends in them (headers, bodies beyond
their length) is for your DLP tooling, which VAREK works alongside: an
allowed request is a channel.

### Installation

```bash
# Linux host (kernel-enforced containment requires Linux; see requirements below)
git clone https://github.com/kwdoug63/varek.git
cd varek
pip install -e ".[dev]"
```

**Production requirements (for kernel-enforced containment):**

- Linux with cgroups v2 mounted
- `libseccomp` Python binding (`pyseccomp` or `python3-libseccomp`)
- Unprivileged user namespaces enabled
- `/sys/fs/cgroup/varek.slice` writable by the test user

The C Warden (`varek/v1_4`) additionally requires `CAP_SYS_ADMIN` (run it as
root or via `sudo`); it checks at startup and refuses to run without it. See
[`varek/v1_4/README.md`](./varek/v1_4/README.md).

The runtime **fails closed** if these are unmet. The package installs and imports
cleanly everywhere, but `SeccompBpfBackend.is_available()` returns an explanatory
string on non-Linux hosts or environments without kernel support. No silent
degradation.

### Verify your installation

```bash
# Linux host or Codespaces
python verify_guardrails.py
```

This exercises every public entry point through an eight-step verification. In
most environments (including GitHub Codespaces) steps 1, 2, 3, 5, 6 **PASS** and
steps 4, 7, 8 **SKIP** with `SeccompBpfBackend unavailable — cannot exercise
kernel boundary`. The SKIP pattern is itself a correctness property: the backend
refuses to initialize rather than run without containment. To convert the three
SKIPs to PASSes, run on a Linux host meeting the production requirements.

### Quick start

```python
import sys
from varek_guardrails import (
    SeccompBpfBackend,
    ExecutionPayload,
    IsolationError,
    default_python_policy,
    configure_backend,
    execute_untrusted,
    subscribe_telemetry,
)

# Arm the containment layer. Fails closed if kernel support is missing.
configure_backend(SeccompBpfBackend())

# Optional: stream PEP 578 audit events to your observability stack.
subscribe_telemetry(lambda event, args: print(f"[audit] {event}"))

# Run untrusted code under the default policy:
# 512 MB / 50% CPU / 64 pids / 30 s wall-clock / network denied / execve denied
payload = ExecutionPayload(
    interpreter_path=sys.executable,
    code="print(2 + 2)\n",
)

try:
    outcome = execute_untrusted(payload, default_python_policy())
    contained = (
        outcome.exit_code != 0
        or outcome.killed_by_signal is not None
        or outcome.violation is not None
    )
    print(
        f"contained={contained} "
        f"exit_code={outcome.exit_code} "
        f"wall_clock_s={outcome.wall_clock_s:.3f}s "
        f"stdout={outcome.stdout!r}"
    )
except IsolationError as e:
    # Raised only at the orchestration boundary (backend not configured,
    # policy malformed). Ordinary containment events surface on the outcome.
    print(f"orchestration error: {e}")
```

### Integration demos

Numbered demos apply Warden to popular agent frameworks. Each follows the same
`Target / Vector / Defense` pattern and runs end-to-end.

| File | Surface |
|------|---------|
| `04-huggingface-smolagents-sandbox.ipynb` | Hugging Face smolagents |
| `05-openai-gpt4o-varek-hardened.ipynb` | OpenAI GPT-4o tool-calling |
| `06-crewai-gemini-ast-intercept.ipynb` | CrewAI + Gemini |
| `07-bare-metal-mobile-intercept.py` | Edge inference |
| `08-autogen-local-executor-intercept.py` | Microsoft AutoGen |
| `09-prefect-task-intercept.py` | Prefect task orchestration |
| `16-wandb-pipeline-verification.py` | Weights & Biases / Weave evals |

These are engineering demonstrations of containment patterns, not statements of
customer relationships.

## Layer 2 — VAREK the language

### Why a new language

Modern AI pipelines stitch together four tools — Python for logic, YAML for
configuration, JSON Schema for validation, shell for orchestration. Each format
boundary erases type information; schema drift and silent coercion errors follow.
VAREK replaces all four with one statically-typed language. Unsafe operations
are not expressible, so a VAREK pipeline needs no runtime containment.

### Syntax at a glance

```varek
-- Complete pipeline: schema, logic, and config in one file

schema ImageInput {
    path: str,
    label: str?,
    width: int,
    height: int
}

pipeline classify_images {
    source: ImageInput[]
    steps:  [preprocess -> embed -> infer -> postprocess]
    output: ClassificationResult[]
    config { batch_size: 32, parallelism: 8 }
}

fn preprocess(img: ImageInput) -> Tensor {
    load_image(img.path)
        |> resize(224, 224)
        |> normalize(mean=[0.485, 0.456, 0.406])
}

async fn infer(tensor: Tensor) -> RawOutput {
    let model = load_model("resnet50.varekmodel")
    model.forward(tensor)
}
```

The equivalent Python requires four files in two languages. The full language
description is in the [spec paper](./varek-spec-paper-v1.12.md).

### Core language features

| Feature | Description |
|---------|-------------|
| **LLVM backend** | Native code generation via `ctypes` bindings to `libLLVM-20`. SSA form, phi nodes, full optimization passes. |
| **Hindley-Milner inference** | Algorithm W, Robinson unification with occurs check, let-polymorphism. Types inferred across module boundaries. |
| **Tensor types** | First-class `Tensor<T, D>` with symbolic dimension tracking and compile-time shape checking. |
| **Pipeline operator** | `\|>` for linear composition. `x \|> f \|> g` desugars to `g(f(x))`. |
| **Schema types** | Structural typing, optional fields, runtime `SchemaValidator`. Replaces JSON Schema and Pydantic. |
| **Result types** | `Result<T>` for errors-as-values. `?` propagates errors without hiding them. |
| **Native async** | First-class `async fn` with channels, futures, parallel_map, mutex, atomic. |
| **Python/C/Rust interop** | `import python::numpy as np` — typed FFI for the existing ML ecosystem. |

The `varek` CLI provides 20 commands (`new`, `build`, `run`, `check`, `test`,
`bench`, `repl`, `fmt`, `doc`, `install`, `publish`, `search`, `add`, `remove`,
`update`, `clean`, `init`, `info`, `registry update`, `version`). The standard
library is 261 functions across 7 modules: `var::io`, `var::tensor`, `var::http`,
`var::async`, `var::pipeline`, `var::model`, `var::data`.

## How the layers compose
Your AI workload
VAREK (.varek)                 Python agent code

typed, LLVM-compiled           (LangChain, AutoGen,

unsafe ops inexpressible        CrewAI, custom ...)

|                                |
```
|                          action-graph

|                                |

|                                v

|                    +-----------------------------------+

|                    | two-tier decision procedure       |

|                    |   decidable matcher (fast)        |

|                    |   + SMT for richer policy         | 

|                    |   -> SATISFIED /                  | 

|                    |      UNSATISFIED /                | 

|                    |      UNKNOWN                      |

|                    +-----------------------------------+

|                                |

|                                v

|                    +-----------------------------------+

|                    | Warden runtime                    |

|                    | kernel enforcement                |

|                    | seccomp user-notify (seccomp-BPF) |

|                    | fail closed                       |

|                    +-----------------------------------+

v
```
native binary (runs directly)

A VAREK pipeline is verified at compile time. Python agent code is verified
per-action at run time and bounded at the kernel. The two layers address
different risks at different points in the stack.

## Roadmap

### Runtime (verification + enforcement)

- [x] **v1.0–v1.5** — Warden supervisor, fail-closed semantics, linear rule evaluation, kernel-enforced containment
- [x] **v1.6** — C Warden adapter; public-repo cleanup; data room
- [x] **v1.7** — Cross-action data-flow verification
- [x] **v1.8.2** — Bounded-refusal breaker
- [x] **v1.9.0** — Progress-safety / HOOTL liveness proof
- [x] **v1.9.1** — Enforcement hardening: io_uring closed; TOCTOU-safe file mediation (race-harness leaks → 0); `connect`/`execve` deny-only
- [x] **v1.9.2** — Mediation completeness: default-deny allowlist; native-ABI/x32 lockdown; hard-deny set; `CLONE_NEWUSER` denial; live-Warden integration + conformance validation
- [x] **v1.9.3** — Lifecycle coupling in the live Warden: PID-namespace isolation, death-signal coupling, fork-race guard, pidfd watch; crash test
- [x] **v1.12** — Mediation correctness: resolve-then-decide (traversal / symlink / `/proc/self`), audit-log integrity, datagram-egress mediation; authorization-evidence export in the CycloneDX 1.6 format
- [x] **v1.12.1** — Side-effect-free denials (resolve, decide, then open), authenticated verdict stream, inbound networking refused
- [x] **v1.12.2** — Threads and child processes: `clone3` answers `ENOSYS` (libc falls back to the filtered `clone`), `wait4`/`waitid`, narrow `ioctl` allowlist, kill report; bootstrap exec granted once per run
- [x] **v1.12.3** — Dynamically linked agents: follow symlinks and decide on the canonical path; `/proc/self` mapped to the agent
- [x] **v1.12.4** — The `--plan` gate authorizes file opens again (decide on the lexically canonical declared path)
- [x] **v1.13.0** — First release of the v1.10 verification program: SMT decision procedure in the enforcement path; open-flag (bitvector) fragment; load-time dead-rule analysis; solver cross-check; verdict-distribution harness
- [x] **v1.14.0** — Bounded string fragment: `exact` / `suffix` / `contains` / `glob` matchers; exact automaton-based rule reachability with witnesses; derivative-based reachability oracle in the cross-check
- [x] **v1.15.0** — Certificates: every authorization carries a certificate checked in-line by an independent checker; policy SHA-256 in the record; audit tool
- [x] **v1.16.0** — Verdict stream protected against its holder: hash chain, Ed25519-signed checkpoints, external anchor, audit with pinned key; glob size capped so one decision is bounded
- [x] **v1.16.1** — Deployment preflight (dependencies, build, stream/key/anchor locations, trial run); libsodium build check and CI job
- [x] **v1.16.2** — Off-host anchor: forwarder (FIFO → spool → SSH or any command), append-only receiver, systemd unit; preflight checks
- [x] **v1.16.3** — Verdict Service plan checker (`plan_verify`) in the repository; JSON output escaped
- [x] **v1.17.0** — Protected files refused by identity; stat/access/readlink mediated; agent unprivileged
- [x] **v1.18.0** — Claims and code agree: data-flow, breaker and progress checks in the Warden's plan gate; URL host matching; derived, signed, schema-tested CycloneDX export; corrected records and figures
- [x] **v1.19.0** — A refusal limit per session for the plan gate's breaker (`session_refusal_budget`)
- [x] **v1.20.0** — Fields on plan steps (`key=value` after the target) for the flow policy; `trust_declared_fields`
- [x] **v1.21.0** — Decided connections: the Warden decides each connect, dials it outside the agent's network namespace and hands over the socket (TCP, connected UDP, IPv4/IPv6 (IPv6 dialing untested on the release host), Unix); the plan gate decides connect steps
- [x] **v1.21.1** — Plan steps declare how they open a file (`open=read`, `open=O_WRONLY|O_CREAT|…`), so the gate authorizes declared reads of read-only paths
- [x] **v1.22.0** — The `varek` command (run, refusals, audit, signed export, policy packs) and `varek bench` (per-call cost of mediation on the host, every verdict checked)
- [x] **v1.23.0** — VAREK Enterprise on AWS Marketplace (AMI with Enterprise policy packs and a License Manager check)
- [x] **v1.23.1** — The Enterprise license check works with Marketplace contract entitlements; deployment guide for AWS
- [x] **v1.24.0** (v1.21 stage 2) — Host names without agent DNS: the Warden resolves allowed names and serves a hosts view ([design](./docs/security/v1.21-stage2-host-names.md))
- [x] **v1.25.0** — Wildcard host names, opt-in (`allow host *.example.com:443 acknowledge=dns-channel`): shared domains where anyone can register names refused at load, lookups answered by the Warden and bounded per rule ([design](./docs/security/v1.25-wildcard-host-names.md))
- [x] **v1.26.0** (v1.21 stage 3) — The egress proxy, SNI mode (`proxy on`): decisions on the name the agent asks for (TLS SNI, HTTP Host), closing the shared-CDN gap on proxied ports with no agent DNS; chaining to a customer proxy (`proxy upstream`) ([design](./docs/security/v1.26-egress-proxy.md))
- [x] **v1.26.1** — The egress proxy's opt-in inspecting mode (`proxy inspect`): TLS terminated with a name-constrained CA made for the run, servers verified, every request's method, path and query decided by request rules before it is sent, `max_body`, passthrough hosts for pinned clients ([design](./docs/security/v1.26.1-inspecting-mode.md))
- [x] **v1.27.0** — Decided program launches, opt-in with `require warden 1.27`: `allow exec` rules take effect, enforced by a Landlock execute ruleset built from the policy, each launch decided and recorded by the Warden and checked against the file decided ([design](./docs/security/v1.27-program-launches.md))
- [x] **v1.27.1** — Nothing written during the run is mapped executable: under `require warden 1.27` the policy's writable directories are mounted `noexec` where the Warden opens files, so a library the agent writes can be neither loaded nor launched ([design](./docs/security/v1.27.1-writable-noexec.md))
- [x] **v1.27.2** — A patch release of v1.27.1: in a signed stream, a checkpoint before any record that would pass `checkpoint_every`, so requests in bursts under the inspecting proxy no longer fail the stream's own audit ([release notes](./RELEASE-v1.27.2.md)).
- [x] **v1.28.0** — Credential release: the agent holds only placeholders, and the egress proxy puts the real credential (from a file, HashiCorp Vault or AWS Secrets Manager) into a request only where a rule names it and only on a request the Warden decided SATISFIED; `varek revoke` ([design](./docs/security/v1.28-credential-release.md))
- [x] **v1.28.1** — The on-behalf-of chain (user → agent → sub-agent) in every verdict: the user's token and the agent's SPIFFE ID verified at the start, each sub-agent attributed by a control group of its own ([design](./docs/security/v1.28.1-delegation-chain.md))
- [x] **v1.29.0** — `varek run -- <agent>` with nothing set up first (a baseline policy and agent profiles), files opened and changed as the agent's own user, a dry run that records what a policy would refuse without enforcing it, and `varek policy suggest` ([design](./docs/security/v1.29-varek-run.md))
- [x] **v1.31.0** — Standards: authorization events in OCSF beside CycloneDX; MCP servers confined to their own rules, MCP calls decided by method and tool, MCP tokens bound to their server; a mapping to Agent Baseline ([design](./docs/security/v1.31-standards.md))
- [x] **v1.31.1** — A patch release of v1.31.0: `epoll_wait`, `epoll_create`, `pipe` and `getpgrp` admitted under every policy, so asyncio, a shell's command substitution and bash work under the Warden ([release notes](./RELEASE-v1.31.1.md)).
- [x] **v1.32.1** — A patch release of v1.32.0: rootless Podman without `--systemd=always`
- [x] **v1.32.0** — Containers: an official image (`ghcr.io/kwdoug63/varek`, signed, with an SBOM), Docker and Podman, rootless included, under a published minimal set of settings, never `--privileged` ([design](./docs/security/v1.32-containers.md))
- [ ] **v1.33.0** (in progress; planned as v1.30.0) — macOS: the agent and the Warden in a lightweight Linux VM, with the same guarantees as on Linux ([plan](./docs/roadmap/v1.28-v1.31.md))
- [ ] **v1.34.0** (planned) — Kubernetes: a node agent, a Helm chart, OpenShift, an Amazon EKS add-on ([plan](./docs/roadmap/v1.32-v1.35.md))
- [ ] **v1.35.0** (planned) — Agent frameworks: plans generated from the framework, Amazon Bedrock AgentCore first ([plan](./docs/roadmap/v1.32-v1.35.md))
- [ ] **v1.36.0** (planned) — Security operations: Splunk, Microsoft Sentinel, OpenTelemetry ([plan](./docs/roadmap/v1.32-v1.35.md))
- [~] **v1.10 program** — The UNKNOWN-shrinking program (below); shipped as v1.13.0, v1.14.0 and v1.15.0. Remaining: customer-derived corpus and measured baseline, a formally verified checker
- [ ] **v1.11 (candidate)** — Bounded sequence fragment for cross-action data-flow

### Language

- [x] **v0.1–v0.4** — Grammar + parser, HM type system, LLVM backend, standard library
- [x] **v1.0** — Stable release, package manager, RFC process

## The verification program (v1.10 / v1.11)

> **Partly shipped.** No v1.10 or v1.11 tag exists: the program's releases ship
> as v1.13.0, v1.14.0 and v1.15.0 so version numbers keep increasing (marked below); the
> rest is planned or candidate work. v1.12 (mediation correctness) shipped ahead
> of the program and does not touch it. Shipped behavior is in
> [`CHANGELOG.md`](./CHANGELOG.md).

The post-v1.9 program has a single goal: migrate cases out of the UNKNOWN verdict
into a provable verdict, raising the clear rate on safe agent actions — under a
hard invariant that **no extension may ever move a genuinely unsafe action into
SATISFIED.** "Cannot prove safe" stays UNSATISFIED/UNKNOWN.

The program proceeds by adding small, individually-auditable decidable fragments,
each with one named soundness obligation and the trusted code it introduces:

- **v1.10 step 1 — verdict-distribution harness + corpus.** The measurement
  baseline. Hard gate: zero unsafe authorizations across the corpus.
  *Shipped in v1.13.0 with a synthetic seed corpus; a customer-derived corpus
  is outstanding.*
- **v1.10 step 2 — bitvector fragment.** Decidable reasoning over fixed-width
  syscall flag/argument bits. Lowest audit cost. *Shipped in v1.13.0.*
- **v1.10 step 3 — bounded string fragment (headline).** Length-bounded
  path-prefix and host-allowlist predicates made provable instead of refused.
  *Shipped: prefix/equality in v1.13.0; suffix, contains and globs in v1.14.0.*
- **v1.11 candidate — bounded sequence fragment.** Element-level reasoning for the
  cross-action data-flow subsystem, composed on the fragments above.

Race-free network mediation (a supervisor-dials-and-injects path replacing the
v1.9.1 deny-only posture for `connect`) shipped in v1.21.0 and host names (stage 2)
in v1.24.0, wildcard names in v1.25.0, and the egress proxy in SNI mode
(stage 3) in v1.26.0, and its inspecting mode, with rules on each request's
method, path and query, in v1.26.1. Decided program launches, held by a
Landlock execute ruleset built from the policy, follow in v1.27.0, and the
policy's writable directories mounted `noexec` in v1.27.1. Credential release,
with the agent holding only placeholders, and revocation follow in v1.28.0, and
the on-behalf-of chain in every decision record in v1.28.1. The default-deny
syscall allowlist closing the alternate-ABI and variant-syscall bypass classes
shipped in v1.9.2, and supervisor/target lifecycle coupling shipped in the live
Warden in v1.9.3.

Design and auditor notes live in
[`docs/verification/`](./docs/verification/README.md): the harness spec, corpus
schema, and one note per fragment.

## Testing

Language test suites, as each archived release runs them (counted for v1.18.0,
Python 3.11; through v1.17.0 this table said 109 tests for v0.1 and 659 passing
in all). The v0.1–v0.4 releases are zip files in [`archive/`](./archive/README.md);
v1.0 is in [`varek-v1.0/`](./varek-v1.0/):

| Component | Tests | Passing |
|-----------|------:|--------:|
| v0.1 — Lexer + Parser + AST | 91 | 88 (2 fail; 1 hangs) |
| v0.2 — Type System + HM Inference | 163 | 163 |
| v0.3 — LLVM Codegen | 97 | 97 |
| v0.4 — Standard Library | 182 | 173 (9 fail: unfinished `syn::` to `var::` rename) |
| v1.0 — Package Manager + REPL | 108 | 108 |
| **Total** | **641** | **629** |

Runtime test suites are version-scoped and run clean under
`-fsanitize=address,undefined` — e.g. the v1.8.2 breaker (19/19) and the v1.9
progress-safety verifier (10/10), both in `make -C v1_7 check` since v1.18.0.
v1.9.1 enforcement is measured directly by a TOCTOU race harness
(`tests/seccomp_toctou_harness.c`): in three runs of 20,000 attempts on a 2-vCPU
host, approve-then-continue leaked the protected file 1,848 to 1,889 times and
resolve-and-inject leaked it 0 times (`tests/toctou_results_v1.18.0.txt`; the
count depends on the host). io_uring is denied by the live Warden filter
(`varek/v1_4/tests/test_v14_filter`, v1.18.0; from v1.21 its creation
answers `ENOSYS` rather than killing, so Node.js runs). Decided connections
(v1.21) are tested with real clients (curl, Python `requests`, Node.js) and a
destination-swap race: 2,000 attempts, 0 reached the denied side (`make
test-v1210`). Inspecting mode (v1.26.1) is tested with Python, curl, Node.js
and Java against servers that log what reaches them, and with forged
streams the audit must refuse (`make test-v1261`, 193 checks). Decided launches
(v1.27.0) are tested with real launches, a compile, a measured table of what the
kernel's Landlock refuses, two threads launching at once, and forged streams
(`make test-v1270`, 164 checks). The `noexec` mounts (v1.27.1) are tested with
copies of host libraries the agent must fail to load, the agent's own view of
its mounts, the host changing a writable path during the run, and forged
streams (`make test-v1271`, 73 checks). Credential release (v1.28.0) is tested
against stand-ins for Vault and AWS Secrets Manager (which check each request's
signature), a TLS server that logs what reaches it, a run revoked mid-run, a
hard link and a bind mount of a credential file, and forged streams (`make
test-v1280`, 168 checks). The on-behalf-of chain (v1.28.1) is tested against a
stand-in identity provider and SPIFFE authority (each check of a token or SVID
failing on its own), sub-agents that fork, double-fork, use threads, nest and
fail to launch, a token expiring mid-run, and forged streams (`make
test-v1281`, 208 checks). `varek run` (v1.29.0) is tested with agents opening
and changing files as their own user, the baseline and each profile, dry runs
of every kind of call and of what stays refused, drafts `varek policy suggest`
writes and runs under them, and forged streams (`make test-v1290`, 316
checks); `make crosscheck-profiles` cross-checks the baseline with each profile,
and `tests/profiles_v1290.sh` runs the real agents' CLIs against their
profiles. MCP servers, calls and tokens and the OCSF export (v1.31.0) are
tested with confined servers and their children, a stand-in MCP server and
authorization server, every call and token form the review found, the events
validated against the vendored OCSF schema, and forged streams (`make
test-v1310`, 317 checks). Build and run with `make check`
in the relevant version directory. Containment verification: `python
verify_guardrails.py` (see above).

## Security

**Reporting vulnerabilities.** Do not open public issues. Use
[GitHub private vulnerability reporting](https://github.com/kwdoug63/varek/security/advisories/new)
or [SECURITY.md](./SECURITY.md). Reports receive acknowledgment within 72 hours.

**Threat model and trusted computing base.** Adversary models, in-scope
guarantees, and out-of-scope conditions are documented in
[`docs/security/threat-model.md`](./docs/security/threat-model.md); the
per-component trusted-vs-verified status of the verification chain is in
[`docs/security/TRUSTED-COMPUTING-BASE.md`](./docs/security/TRUSTED-COMPUTING-BASE.md).
The cross-action data-flow threat model is in
[`docs/security/threat-model-dataflow.md`](./docs/security/threat-model-dataflow.md).
The runtime fails closed on unsupported platforms and denies boundary syscalls at
the kernel, not via string matching or audit hooks. As of v1.12 the Warden
filter is default-deny (an explicit allowlist, native ABI only, with a hard-deny
set that includes `io_uring_enter` and `io_uring_register`, while `io_uring_setup`
answers `ENOSYS` from v1.21 so that Node.js falls back to epoll); since v1.21 each outbound connect is decided and
dialed by the Warden, which hands the agent the connected socket (an agent's own
network namespace stays empty); and the agent runs in its own PID namespace, so it
and everything it spawned die with the supervisor. The per-class status is in
[`docs/security/bypass-classes.md`](./docs/security/bypass-classes.md).

**v1.1.0 fix.** Resolved a subprocess-escape weakness in v1.0's audit-hook-based
containment (issue #223, reported by @dengluozhang). See
[`VAREK_v1.1_SECURITY_UPDATE.md`](./VAREK_v1.1_SECURITY_UPDATE.md).

**Architecture review.** External review by QEEK-AI addressed AST-gate framing
(documented as UX-only, not a security boundary), a libc-binding fallback bug, and
platform-gating CI coverage (now macOS, Windows, Linux).

## Documentation

- **Spec paper:** [`varek-spec-paper-v1.32.0.md`](./varek-spec-paper-v1.32.0.md) — language and runtime specification, design rationale, the verdict model
- **VAREK Enterprise on AWS:** [`docs/aws-deployment-guide.md`](./docs/aws-deployment-guide.md) — deploying and operating the [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-6fdmjpuimvx64) image
- **Security:** [`docs/security/threat-model.md`](./docs/security/threat-model.md), [`docs/security/TRUSTED-COMPUTING-BASE.md`](./docs/security/TRUSTED-COMPUTING-BASE.md), [`docs/security/bypass-classes.md`](./docs/security/bypass-classes.md), [`RELEASE-v1.31.0.md`](./RELEASE-v1.31.0.md), [`RELEASE-v1.29.0.md`](./RELEASE-v1.29.0.md), [`RELEASE-v1.28.1.md`](./RELEASE-v1.28.1.md), [`RELEASE-v1.28.0.md`](./RELEASE-v1.28.0.md), [`RELEASE-v1.27.1.md`](./RELEASE-v1.27.1.md), [`RELEASE-v1.27.0.md`](./RELEASE-v1.27.0.md), [`RELEASE-v1.26.1.md`](./RELEASE-v1.26.1.md), [`RELEASE-v1.26.0.md`](./RELEASE-v1.26.0.md), [`RELEASE-v1.25.0.md`](./RELEASE-v1.25.0.md), [`RELEASE-v1.24.0.md`](./RELEASE-v1.24.0.md), [`RELEASE-v1.17.0.md`](./RELEASE-v1.17.0.md), [`RELEASE-v1.12.1.md`](./RELEASE-v1.12.1.md), [`RELEASE-v1.12.0.md`](./RELEASE-v1.12.0.md), [`RELEASE-v1.9.3.md`](./RELEASE-v1.9.3.md), [`RELEASE-v1.9.2.md`](./RELEASE-v1.9.2.md), [`RELEASE-v1.9.1.md`](./RELEASE-v1.9.1.md)
- **Standards:** [`docs/standards/agent-baseline.md`](./docs/standards/agent-baseline.md) — the Agent Baseline's controls, what in VAREK addresses each and how far
- **Verification notes:** [`docs/verification/`](./docs/verification/README.md) — the v1.10/v1.11 program
- **Changelog:** [`CHANGELOG.md`](./CHANGELOG.md)
- **Website:** [varek-lang.org](https://varek-lang.org)

## Community

- **Discussions:** [github.com/kwdoug63/varek/discussions](https://github.com/kwdoug63/varek/discussions)
- **Issues:** [github.com/kwdoug63/varek/issues](https://github.com/kwdoug63/varek/issues)
- **Releases:** [github.com/kwdoug63/varek/releases](https://github.com/kwdoug63/varek/releases)

## License

VAREK is open-source software licensed under the [MIT License](LICENSE).
Copyright (c) 2026 Sober Agentic Infrastructure, Inc. See [NOTICE](./NOTICE).

### Trademarks

CycloneDX is a trademark of the OWASP Foundation. VAREK and Sober Agentic
Infrastructure, Inc. are not affiliated with, endorsed by, or certified by the
OWASP Foundation or the CycloneDX project. The CycloneDX name is used only to
describe interoperability with the openly published CycloneDX format
(standardized as ECMA-424, with Apache-2.0-licensed schemas). All other product
names and marks are the property of their respective owners.

## Examples

- [Sandboxing an agent that downloads media](examples/agent_media_sandbox/README.md) — Warden-supervised media fetch with a policy auto-generated by `setup.sh`. Framework-agnostic (Hermes Agent, LangChain, etc.) and LLM-agnostic.
