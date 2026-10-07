# VAREK — Threat Model

Version: current as of v1.25.0 · MIT · github.com/kwdoug63/varek

This document states what VAREK defends, against whom, and what it explicitly
does not defend. It is deliberately conservative: where a guarantee is
conditional, the condition is named. VAREK relocates trust rather than
eliminating it — from "trust the model's judgment" to "trust the policy, the
decision procedure, and the enforcement boundary" — and the boundaries below are
where that relocated trust lives.

## 1. What VAREK is

VAREK decides, before an action takes effect, whether that action complies with
an explicit, human-authored policy, and enforces the decision at the system
boundary. Every action resolves to SATISFIED (provably compliant, may proceed),
UNSATISFIED (provably non-compliant, denied), or UNKNOWN (not decidable within
bounds, fails closed). The runtime proceeds only on a provable SATISFIED.

## 2. Assets and trust boundaries

- **Asset:** the integrity of the authorization decision — that no action takes
  effect unless it is SATISFIED under the active policy.
- **Asset:** the integrity of the authorization record — that the verdict stream
  (and any evidence exported from it) reflects the decisions actually made and
  cannot be forged by the supervised process (v1.12), nor rewritten afterwards
  by whoever holds the log, within what the signing key and the external
  anchor cover (v1.16).
- **Trust boundary 1:** the policy author (trusted to express intent correctly —
  see §5, non-goal 1).
- **Trust boundary 2:** the verification chain — surface-language compiler,
  obligation encoder, and the SMT decision procedure (see the Trusted Computing
  Base document for per-component status).
- **Trust boundary 3:** the enforcement layer — the Warden supervisor and the
  kernel mechanisms it relies on (seccomp user-notification and seccomp-BPF,
  PID namespaces, and capability restrictions). Landlock is on the v1.10 roadmap
  and is not wired into the current Warden.
- **Trust boundary 4 (v1.24):** the host's DNS resolver, or the server named by
  `--dns-server`. The Warden trusts its answers for the names a policy names
  and does not validate DNSSEC itself. Whoever controls an allowed name's DNS
  chooses which addresses the name allows (see §4, *Host names*, and §6).
  From v1.25, under a wildcard rule, the agent's lookups reach that resolver
  and the domain's DNS servers, which may be run by a DNS provider rather
  than the party behind the API (see §4, *Wildcard host names*).
- **Trust boundary 5 (v1.25):** the shared-domain lists shipped with the
  release (the Public Suffix List and the VAREK list), which decide which
  wildcard rules are refused at load.

## 3. Adversary models

VAREK is specified against two adversaries. The default deployment posture is
Model A; Model B is the hardened posture and is named wherever a guarantee
depends on it.

**Model A — capable but non-adversarial agent (default).** An autonomous agent
that may be mistaken, misaligned, or manipulated into *attempting* actions
outside policy, but is not assumed to be actively exploiting the sandbox
implementation. VAREK's purpose under Model A is to ensure that attempted
out-of-policy actions are denied before they take effect.

**Model B — adversarial co-resident process (hardened).** A process that
actively tries to defeat enforcement: racing argument memory, routing operations
off the mediated path, or probing for an action that is SATISFIED-but-harmful
near a policy boundary. VAREK's enforcement layer is hardened against the known
Model-B techniques below, with the residual limits stated honestly.

## 4. In-scope guarantees

- **Authorization before execution.** No mediated action takes effect without a
  SATISFIED verdict under the active policy. UNKNOWN and UNSATISFIED both fail
  closed.
- **Compositional plan safety (action-graph).** A planned directed acyclic graph
  of actions is verified before its first action runs, and re-verified as the
  agent revises it.
- **Cross-action data-flow bounds.** A source labeled secret cannot reach a sink
  forbidden by policy, across actions, with declassification only where audited.
- **Progress-safety / liveness (v1.9).** At policy load the verifier certifies
  that every refusal resolves to an automated terminal in finitely many steps —
  human-out-of-the-loop is a certified property, not a setting.
- **Enforcement-layer hardening (v1.9.1).**
  - *io_uring is denied in the baseline policy.* io_uring dispatches operations
    off the syscall entry path, where seccomp cannot observe them; instance
    creation is refused so the mediated path cannot be bypassed.
  - *Scalar vs. pointer arguments.* Decisions on scalar register arguments
    (flags, fd numbers, integer modes) are TOCTOU-safe because the kernel
    snapshots them. Decisions on pointer-dereferenced data are not made by
    letting the syscall continue; the supervisor performs the action on copied,
    validated arguments and injects the result, or denies.
  - *Stale-notification safety.* Every notification is revalidated immediately
    before the supervisor acts.
- **Mediation completeness (v1.9.2).** The baseline filter is a default-deny
  allowlist: unknown and variant syscalls are denied by construction. No
  secondary ABI is admitted (32-bit compat and x32 paths are denied). Unprivileged
  user namespaces are denied on the scalar flags argument. A hard-deny set covers
  `ptrace`, `bpf`, `userfaultfd`, `process_vm_readv/writev`, `pidfd_getfd`, the
  mount/FUSE family, the module/`kexec`/`perf_event_open`/`keyctl` family,
  `memfd_create`, and io_uring (v1.21: `io_uring_setup` answers `ENOSYS`, so
  libuv falls back to epoll; no ring can be created, and `io_uring_enter` and
  `io_uring_register` still kill).
- **Supervisor/target lifecycle coupling (v1.9.3).** The agent runs as init of its
  own PID namespace and is killed if the supervisor stops, so neither the agent
  nor anything it spawned keeps running without oversight. The Warden requires
  `CAP_SYS_ADMIN` and refuses to start without it. With `VAREK_WARDEN_NO_PIDNS=1`
  the namespace is disabled and descendants are not guaranteed to die on a
  supervisor crash.
- **Mediation correctness (v1.12).**
  - *Resolve-then-decide.* File opens are resolved once with
    `RESOLVE_NO_MAGICLINKS`; policy is decided on the canonical path of the
    resolved descriptor, and that same descriptor is injected. Decision and
    delivered capability refer to the same object, closing `..` traversal,
    symlink escapes, and `/proc/self` context confusion. Ordinary symlinks are
    **followed** (v1.12.3) and decided on their canonical target — a symlink to a
    denied object is refused, and dynamically linked agents' loaders work;
    v1.12.0–v1.12.2 instead refused any symlinked path (`RESOLVE_NO_SYMLINKS`). A
    leading `/proc/self`/`thread-self` is mapped to the agent's own process
    before resolution; a numeric `/proc/<pid>` object that is not the agent's
    own fails a post-resolution check, and that check is also what refuses a
    planted symlink to `/proc/self/mem` (it resolves to the Warden's own
    `/proc/<pid>/mem`). `/proc/self` is an ordinary symlink, which
    `RESOLVE_NO_MAGICLINKS` follows; that flag refuses the kernel's magic links
    (`/proc/<pid>/fd/N`, `cwd`, `exe`, `root`, `ns/`). *(Correction, v1.21.0:
    through v1.20.0 this credited `RESOLVE_NO_MAGICLINKS` with refusing
    `/proc/self/mem`.)* Non-process `/proc` entries remain governed by policy.
  - *Authorization-record integrity.* Every agent-controlled string is escaped, so
    no input can begin, end, or forge a record in the verdict stream. Records
    carry the resolved object the decision was made on. From v1.16 records are
    hash-chained, checkpoints are Ed25519-signed (`--sign-key`) and optionally
    appended to an external anchor (`--anchor`), so the log's holder cannot
    alter, insert, remove, reorder or truncate records undetected before the
    last signature (without the key) or before the last anchored checkpoint
    (with it). The Warden refuses a policy that would let the agent open the
    key, the anchor, its own verdict stream file or a raw disk or memory
    device.
  - *Datagram egress.* `sendto`/`sendmsg` are mediated as network sends and
    were refused for an inet destination under the deny-only network posture
    through v1.20.0. From v1.21 a send that names a destination is still
    refused whatever the policy says; a send with none goes to the peer of a
    connect the Warden decided (see below).
- **Decided connections (v1.21).** Each outbound `connect` is decided on the
  destination the Warden will dial, copied once from the agent's memory and
  spelt canonically (`a.b.c.d:port`, `[IPv6]:port` with an IPv4-mapped address
  as its IPv4 form, or `unix:<canonical path>` for a path socket resolved like
  a file open); the independent checker must accept the certificate of any
  ALLOW. (IPv6 decisions are tested; IPv6 dialing was not exercised on the
  v1.21.0 release host, whose kernel has no IPv6.) The Warden then dials the destination itself, from outside the
  agent's empty network namespace, and puts the connected socket in place of
  the agent's descriptor (`SECCOMP_IOCTL_NOTIF_ADDFD`); the kernel never reads
  the agent's sockaddr, so a second thread cannot change the destination after
  the check (a 2,000-attempt swap race in `make test-v1210` reaches the
  denied side 0 times). Options the agent set on its socket before the
  connect are carried over if they are among the 58 the Warden knows (buffer
  sizes, timeouts, keepalive, `TCP_NODELAY`, congestion control, TOS and TTL,
  and the like), or the connect fails; options outside that list set before
  the connect (for example `SO_TIMESTAMPING`, `TCP_QUICKACK`, a socket filter,
  `TCP_ULP`) are silently not carried. Options set after the connect apply to
  the connected socket as usual. A Unix connect is made with the agent's uid and gid.
  Every connect the Warden decides is recorded, chained and signed, like a
  file open; every ALLOW carries a certificate that the checker accepted
  before the dial and that `varek_audit.py` re-checks. A blocking connect that
  reaches the agent's `SO_SNDTIMEO` returns `EINPROGRESS` and, as in the
  kernel, keeps connecting: the socket the agent holds may connect later, to
  the destination that was decided. Refused whatever the policy says: sends
  that name a destination, abstract and unnamed Unix addresses, IPv6 scope
  ids, raw and other socket kinds, `MSG_FASTOPEN`, source routing
  (`IP_OPTIONS`, IPv6 routing headers), and inbound calls (`listen`, `accept`;
  `bind` is allowed only for a TCP or UDP socket to the wildcard address and
  port 0, which the Warden performs and does not record).
- **Where, not what (v1.21).** VAREK decides *where* an agent may connect.
  Once a destination is allowed, the agent may send it anything: an allowed
  host is a channel, and data the agent may read may leave through it. What an
  agent sends is for the service, or an egress proxy or DLP tool in front of
  it, which VAREK works alongside. Allowing a Unix socket also grants whatever
  its server does for the agent's uid, including descriptors it passes back.
- **Host names without agent DNS (v1.24).** A host rule may name a host
  (`allow host api.example.com:443`, after `require warden 1.24`).
  - *The agent sends no DNS.* The Warden resolves every name a host rule names,
    allow or deny, itself, A and AAAA, through a resolver helper process, so
    the process holding the signing key never parses network data. It
    refreshes each name at its TTL, clamped to [30 s, 1 h]; an address that
    leaves an answer stays valid for its last TTL, at most 5 minutes. Every
    lookup is a chained `resolution` record. The agent reads `/etc/hosts`,
    `/etc/resolv.conf`, `/etc/nsswitch.conf` and `/etc/host.conf` from sealed
    views the Warden writes; its hosts view lists only localhost and the
    allowed names. Every connect to port 53 is refused (`dns_refused`), and a
    writable open of any of the four paths is refused
    (`view_write_refused`), whatever the policy says.
  - *Decided on every name of the address.* A connect is decided on its
    address and on `name:port` for every name, allowed or denied, that the
    address belongs to, current or in grace; the first rule in policy order
    that holds on any of them decides, so a deny on a name holds on its
    addresses. The certificate covers the deciding name, and the checker
    confirms that no earlier rule holds on another candidate. A loopback,
    link-local, unspecified or multicast address is decided on the address
    alone (`special_address`), so DNS cannot lead an allowed name to the
    host's own services.
  - *Audited.* `varek_audit.py` checks that each candidate was bound to the
    address dialed by the resolution records, that no name of that address was
    left out (grace included), that each connect names the latest table
    generation, and that the dialed address and candidates are spelt as the
    Warden spells them. A stream edited to drop a name fails, even with its
    hash chain recomputed.
  - *What a name does not decide.* A name decides which addresses the agent
    may reach, not which site it asks for there (see §6).
- **Wildcard host names, opt-in (v1.25).** A host rule may allow every name
  under a domain (`allow host *.example.com:443 acknowledge=dns-channel`,
  after `require warden 1.25`).
  - *Opt-in, in the policy text.* Every wildcard allow rule must carry
    `acknowledge=dns-channel`, or the policy is refused, so a reviewer
    reading the policy sees that the agent's lookups under it leave the host.
  - *Shared domains refused.* A wildcard allow over a public suffix, an entry
    of the Public Suffix List's private section or under one, or an entry of
    the VAREK list is refused at load, naming the entry. Both lists are
    pinned, and their SHA-256 is in `run_start`.
  - *One way to DNS.* The agent's lookups go to a stub resolver the Warden
    runs at `127.53.53.53:53` in the agent's own network namespace. A name no
    allow rule can reach gets NXDOMAIN, and no question leaves the host. A
    name a wildcard allows is looked up by the Warden's resolver helper
    when the agent asks, never on its own. Every other connect to port 53 is
    refused, as in v1.24.
  - *Bounded.* Each wildcard allow rule has budgets of new names a run and a
    minute (defaults 256 and 30) and 63 bytes before the suffix. A new name
    past a budget gets NXDOMAIN and is not looked up.
  - *Recorded and audited.* Every question to the stub is a chained
    `dns_question` record. `varek_audit.py` checks the budgets against the
    policy file, every charge against them, and that every name looked up
    was asked for.
  - *Decided as in v1.24.* A connect is decided on its address and every
    name it belongs to, with no limit on their number; past 15 the record
    carries their count and SHA-256, and the audit rebuilds them from the
    resolution records.

The per-class status of every known bypass class is maintained in
`docs/security/bypass-classes.md`.

## 5. Out of scope / non-goals

These are real limits, not omissions. Several are addressed on the roadmap; none
are claimed as solved.

1. **Policy validity.** VAREK proves compliance with the policy as written. It
   does not prove the policy is correct or complete. A catastrophic action can be
   SATISFIED if the policy failed to forbid it. Validation of policy intent is
   the operator's responsibility.
2. **Application-level semantics beyond the mediated boundary.** Where harm is
   indistinct at the syscall layer (e.g. "send funds" is a socket write), policy
   must be expressed at the tool-call / function-call interceptor layer; syscall
   mediation alone under-constrains such actions.
3. **Kernel and hardware integrity.** A kernel zero-day, a hypervisor escape, a
   hardware/microarchitectural side channel, or a fault-injection attack is below
   VAREK's enforcement layer and out of scope. Defense in depth (Landlock,
   capability drops, namespaces, seccomp) reduces but does not eliminate exposure.
4. **Covert/side channels.** VAREK bounds explicit data flow across mediated
   actions; it does not claim to close timing or other covert channels.
5. **Availability under forced UNKNOWN.** An adversary who can force decision
   timeouts forces UNKNOWN — which is safe (fail closed) but is an availability
   concern, not an authorization breach. Bounded deterministically in v1.9.1.
6. **Soundness of the trusted chain.** Until proof objects are independently
   checked, the SMT decision procedure and the compilation to obligations are
   trusted, not verified. See the Trusted Computing Base document.

## 6. Residual risks (acknowledged)

- Pointer-argument operations rely on the supervisor-performs-and-inject pattern.
  Path resolution is performed once by the supervisor (v1.12), but in-kernel,
  race-free filesystem restriction via Landlock remains roadmap (v1.10).
- Network access (v1.21): outbound connects are decided and dialed by the
  Warden; unconnected datagram sends stay refused. *(Through v1.20.0 this
  read: network access is deny-only; a mediated allow path is roadmap.)*
- Host names (v1.24, `v1.21-stage2-host-names.md`):
  - *Shared addresses.* A name is decided by the addresses it resolves to. An
    allowed name on a shared content network also reaches every other site
    served from those addresses, by another name in TLS SNI or the HTTP `Host`
    header. Deciding on the name the agent asks the server for, and rules on
    request contents (method, path, body), are stage 3, through the v1.26.0
    egress proxy (`v1.26-egress-proxy.md`).
  - *DNS is trusted.* Whoever controls an allowed name's DNS, or the host's
    resolver, chooses its addresses within what §4 allows: a private address
    (10/8, 172.16/12, 192.168/16, fc00::/7) the Warden's host can reach is
    reachable by name. Point `--dns-server` at a validating resolver where
    that matters.
  - *Unix-socket resolvers.* A policy that allows nscd's, systemd-resolved's
    or D-Bus's socket gives the agent a resolver that sends DNS itself.
  - *Metadata.* `stat` and `access` on the four view paths report the host's
    files, not the views.
  - *Signatures.* A refresh that changes a name's addresses is signed at the
    next scheduled checkpoint, not at once.
- Wildcard host names (v1.25, `v1.25-wildcard-host-names.md`):
  - *The name channel is bounded, not closed.* Within a rule's budgets, the
    labels an agent chooses reach the host's resolver and the domain's DNS
    servers. At the defaults that is at most about 41 bytes a name: about
    10.5 KB a rule a run, and 1.2 KB a minute. Re-asking a name already
    charged costs nothing, and its timing can carry a few bits that no
    budget bounds. The v1.26 egress proxy decides on the name without a
    lookup by the agent.
  - *The lists are snapshots.* A domain where anyone can create a name, and
    that neither list holds, is not refused; such a wildcard allows the
    names an attacker registers there. The VAREK list is reviewed each
    release.
  - *No stub without a network namespace.* Without one of its own for the
    agent, names that only a wildcard allows do not resolve.
- File opens run as root (pre-dates v1.24, found in the v1.24 review). The
  Warden opens a file for the agent with its own credentials, so a path the
  policy lets the agent write is writable even when the file is root-owned
  and mode 0644. Opening with the agent's uid and gid is planned as its own
  release; until then, allow writes only where the agent may write any file.
- Some bypass classes remain partial; see `docs/security/bypass-classes.md`.
- The verification chain's soundness rests on components currently trusted (§5.6).
- An agent may probe for SATISFIED-but-harmful actions near a policy boundary;
  this is a policy-tightness question (§5.1), not an enforcement bypass.

## 7. Versioning

This threat model tracks the released runtime. Guarantees attributed to a version
hold only at or after that tag. Statements of roadmap intent are marked as such
and are not guarantees.
