# VAREK — Threat Model

Version: current as of v1.27.1 · MIT · github.com/kwdoug63/varek

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
  PID namespaces, and capability restrictions; from v1.27, under `require
  warden 1.27`, Landlock, which holds the set of files the agent may
  launch; from v1.27.1, under the same opt-in, the Warden's own mount
  namespace, whose `noexec` mounts hold the files the agent may write).
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
- **Trust boundary 6 (v1.26):** the egress proxy process. It parses what the
  agent sends, so the Warden trusts it less than itself: it runs as its own
  unprivileged user with no capabilities, and tells the Warden only a
  connection id, a kind, a name and a port. The Warden validates each report
  (one per hand-off, on the hand-off's port) and stops the run on anything
  else. The proxy can refuse or drop a connection the Warden would allow; it
  cannot make the Warden dial a name the policy refuses. Its byte counts in
  close records are its own claims. From v1.26.1 it is its own binary,
  `warden-proxy`, which the Warden copies into a sealed memfd, hashes into
  `run_start` and starts with `fexecve`, so what runs is what was hashed.
  In inspecting mode it holds the run's CA key, sees the plaintext of every
  inspected connection, and reports each request's object; the Warden checks
  the object's form again itself, decides it, and requires a report for every
  allowed body. The proxy cannot make the Warden allow a request the policy
  refuses; the lengths and SHA-256s of bodies are its claims.
- **Trust boundary 7 (v1.26):** the customer's upstream proxy, when the
  policy names one (`proxy upstream`). It dials the names the Warden allowed,
  so the address checks for those names are its own (see §6).
- **Trust boundary 8 (v1.26.1):** in inspecting mode, the trust the agent and
  the proxy are given. The agent trusts a CA made for the run (its trust
  views and environment); the proxy verifies servers against the host's
  bundle, or a bundle the operator names (`--trust-bundle`, for example with
  a corporate CA), and a server any root in that bundle vouches for is
  believed. The CA's name constraints permit only the names the policy lets
  the agent reach on proxied ports, and exclude the passthrough hosts and
  every IP address.
- **Trust boundary 9 (v1.27):** under `require warden 1.27`, the files the
  launch set holds, as they are at startup. The Warden decides which files
  the policy allows and records each one's device, inode and SHA-256; the
  kernel's Landlock then lets the agent launch those files and no others.
  A file in the set that is changed in place keeps its inode, and the
  record's hash is the one taken at startup. The dynamic loader is in the
  set whenever a dynamic program is, though the policy need not allow it.

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
    link-local, unspecified, multicast or cloud metadata address (including
    IPv4-compatible and NAT64 forms) is decided on the address alone
    (`special_address`), so DNS cannot lead an allowed name to the host's
    own services.
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
    the VAREK list, or a domain above any of these, is refused at load,
    naming the entry. Both lists are pinned, and their SHA-256 is in
    `run_start`.
  - *One way to DNS.* The agent's lookups go to a stub resolver the Warden
    runs at `127.53.53.53:53` in the agent's own network namespace. A name no
    allow rule can reach gets NXDOMAIN, and no question leaves the host. A
    name a wildcard allows is looked up by the Warden's resolver helper
    when the agent asks, never on its own. Every other connect to port 53 is
    refused, as in v1.24.
  - *Bounded.* Each wildcard allow rule has budgets of new names a run
    (default 256), of lookups sent upstream a minute (default 30, a name
    re-asked after its TTL included) and 63 bytes before the suffix. A
    question past a budget gets NXDOMAIN and is not looked up.
  - *Recorded and audited.* Every question to the stub is a chained
    `dns_question` record. `varek_audit.py` checks the budgets against the
    policy file, every charge against them, and that every name looked up
    was asked for.
  - *Decided as in v1.24.* A connect is decided on its address and every
    name it belongs to, with no limit on their number; past 15 the record
    carries their count and SHA-256, and the audit rebuilds them from the
    resolution records.

- **Egress proxy, SNI mode (v1.26).** With `proxy on` (after `require
  warden 1.26`), connects on the proxied ports (default 80 and 443) are
  decided on the name the client sends, not on the address.
  - *Decided on the name asked for.* The proxy reads the TLS ClientHello's
    SNI, the HTTP `Host`, or a `CONNECT host:port` (whose ClientHello must
    carry the same name). The Warden decides `name:port` with the SMT
    decision procedure, the certificate checker must accept the
    certificate, and the Warden dials only an address that name resolves
    to. Another site on a shared content network is not reached by naming
    it, which closes v1.24's shared-address gap on the proxied ports.
  - *No agent DNS for proxied names.* A name allowed only on proxied ports
    is given a synthetic address from 198.18.0.0/15, recorded once; nothing
    is looked up when the agent asks, and no wildcard budget is charged.
  - *Only through the proxy.* A TCP connect on a proxied port is handed to
    the proxy unless a numeric rule allows the address (dialed directly) or
    a rule denies it (refused). The proxy closes any connection the Warden
    did not announce, and the agent cannot reach its listener. A UDP connect
    on a proxied port that only a name allows is refused (QUIC).
  - *Bounded parsers.* The parsers allocate nothing and read at most 16 KB
    of ClientHello in 64 records, or 8 KB of request headers. They refuse
    what they cannot read exactly: no SNI, two names, an IP literal,
    Encrypted Client Hello and ESNI, a repeated extension, a `Host` port
    other than the one connected to. Fuzzed under ASan and UBSan in CI.
  - *Addresses the Warden refuses.* Special addresses (loopback,
    link-local, unspecified, multicast, cloud metadata, IPv4-mapped and
    IPv4-translated IPv6), synthetic addresses and addresses a rule denies
    are never dialed for a name.
  - *Plain HTTP request by request.* Every request on a connection must name
    the host and port decided, and each body is passed as its framing says;
    ambiguous framing and protocol upgrades are refused. At a request for
    another host the proxy stops.
  - *A less trusted proxy.* See trust boundary 6. The proxy is started
    before the agent, proves its user with `SCM_CREDENTIALS`, and exits with
    the Warden; if it dies mid-run, the run stops. The Warden never blocks
    sending to it.
  - *Recorded and audited.* Each hand-off, decision (`net.proxy`) and close
    (`proxy_close`) is a chained record. `varek_audit.py` asks each hand-off
    and each dialed address of the policy again, checks one certified
    decision per hand-off and a close for each connection passed on, and
    that no connect on a proxied port was dialed directly except by a
    numeric rule.
  - *Chained to a customer's proxy.* With `proxy upstream`, the Warden
    decides first, so a refused name never reaches the upstream; the
    upstream's own refusal is recorded (`upstream_refused`).

- **Egress proxy, inspecting mode (v1.26.1).** With `proxy inspect`, a
  connection is decided on its name as in SNI mode, then every request on it
  is decided before any of it is sent.
  - *Each request decided.* The object `METHOD scheme://name:port/path?query`
    (the name and port the connection's, never the request's `Host`, which
    must equal them) is decided against `allow|deny request METHOD URL`
    rules with the SMT decision procedure, first match, and the certificate
    checker must accept the certificate. A request no request rule allows is
    refused. An allow rule without a `?` allows no query; a deny rule without
    one denies its path with any query; a request has at most one `?`, so a
    rule's wildcards never stretch from the path into the query.
  - *Read one way.* The proxy refuses a target a server could read as
    another path (`.` and `..` segments, `//`, `\`, `;`, control and
    non-ASCII bytes, percent-encoded `/`, `\` or unreserved bytes, bad
    escapes, a second `?`), anything but origin-form or absolute-form for
    the connection's own authority, and ambiguous framing; the Warden checks
    the object's form again before deciding.
  - *Nothing before the verdict.* The proxy's gate lets no byte of a request
    through until the Warden allows it; after a refusal nothing more of the
    connection is sent, and the agent gets a 403.
  - *Servers verified first.* TLS 1.2 or later to the server, its name
    checked against the subject alternative name (no partial wildcards, no
    CN), before the agent's handshake is answered; a server that fails is
    refused and recorded (`server_tls`). A server's TLS that ends without
    close_notify ends the agent's without one too.
  - *The run's CA.* ECDSA P-256, made in the proxy for this run, its key in
    OpenSSL's secure heap where the memory-lock limit allows, the proxy not
    dumpable, nothing written to disk; valid seven days; name-constrained as
    in trust boundary 8. Leaf certificates are made per name, no session
    tickets, ALPN `http/1.1` only.
  - *Bodies bounded and hashed, not stored.* `max_body` bounds what is sent
    (a declared length over it is refused before a byte is sent; a chunked
    body is cut at it); each body's length and SHA-256 are recorded.
  - *Passthrough hosts* (`proxy passthrough host NAME`, for clients that pin
    certificates) stay in SNI mode and are recorded as not inspected.
  - *Recorded and audited.* Each request is a chained `net.request` record,
    each body a `request_body`, each close counts its requests; `run_start`
    records the CA's, trust store's and `warden-proxy`'s SHA-256.
    `varek_audit.py` checks each request belongs to an inspected connection,
    in order, in a form the proxy must accept, certified again when
    allowed and asked of the policy again when refused, each body within its
    rule, and each close's count.

- **Decided program launches (v1.27).** With `require warden 1.27`, each
  launch after the agent's own is decided before it happens; without it,
  every later launch is refused as before.
  - *Decided on its name.* An `execve` or `execveat` is decided on the path
    as written, made absolute, with `.` and `..` resolved and a final
    symlink keeping its name (`execveat(fd, "", AT_EMPTY_PATH)` on the
    descriptor's file), by the SMT decision procedure, with a certificate
    the checker must accept; the checker's own reading of the opt-in must
    also turn launches on.
  - *Only the set can launch.* An allowed launch must name a file of the
    launch set built at startup (same device and inode); the kernel's
    Landlock domain, applied to the agent before its own launch and
    inherited by every process it starts, refuses any other file: one not
    in the set, one written during the run, an `O_TMPFILE` or unlinked file
    through `/proc/self/fd` or `execveat`, a file in `/dev/shm`. The agent
    cannot make a memfd (`memfd_create` is in the hard-deny set; a build
    check keeps it there), which Landlock would not govern.
  - *What runs is what was decided.* A swap of the path after the decision
    can reach only a file in the set; before the Warden answers any call
    of a process that has launched, `/proc/<pid>/exe` must be a program it
    decided to run (a file in the set only as a loader never is), and a
    process that is not is killed before its call is answered, recorded,
    and fails the run.
  - *Fail closed.* Without Landlock, every launch after the agent's own is
    refused (`exec_no_landlock`), as before. A policy the Warden cannot turn
    into a set of files (a rule it cannot expand, a malformed program, more
    than 256 files a rule) refuses the start.
  - *Recorded and audited.* `run_start` records Landlock's ABI and each
    file of the set; each allowed launch records the file and its startup
    hash, and has one `exec_result`. `varek_audit.py` asks the policy again
    about the set and each launch and refusal, and fails a run in which a
    process was killed.
- **Nothing written during the run is mapped executable (v1.27.1).** Under
  `require warden 1.27`, unless the operator runs the Warden with
  `--writable-exec`:
  - *Every writable directory is `noexec` where the Warden opens.* At
    startup, before it starts any helper or the agent, the Warden makes a
    private mount namespace and re-mounts each directory a path rule lets
    the agent write (its prefix, the directory before a glob's first
    wildcard, an exact rule's file or its directory) on itself `noexec`,
    with every mount beneath it, and confirms each. The Warden opens every
    file it allows for the agent, so a file under one can be neither
    launched nor mapped executable (`mmap` with `PROT_EXEC`: `EPERM`;
    `mprotect` adding it: `EACCES`). The host's mounts are untouched.
  - *Fail closed.* A descriptor for a path under a listed directory that
    does not come through a `noexec` mount is refused (a directory the
    host makes during the run, a file the host replaces, a lookup from an
    old working directory). A writable rule no directory bounds, a writable
    `/`, the agent's own program, its interpreter or a loader under a
    writable directory, an inherited descriptor open for reading on a file
    there, and a mount that fails each refuse the start.
  - *Recorded and audited.* `run_start` records each directory, its policy
    line and its rule's directory, or `null` with `--writable-exec`;
    `varek_audit.py` checks each entry against its rule, every writable
    rule against the list, and every recorded write against the list.

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
    header. From v1.26.0, `proxy on` closes this on the proxied ports (§4,
    *Egress proxy*); on other ports, and without the proxy, it holds. From
    v1.26.1, `proxy inspect` also decides each request's method, path and
    query (§4, *Egress proxy, inspecting mode*).
  - *DNS is trusted.* Whoever controls an allowed name's DNS, or the host's
    resolver, chooses its addresses within what §4 allows: a private address
    (10/8, 172.16/12, 192.168/16, fc00::/7) the Warden's host can reach is
    reachable by name. Point `--dns-server` at a validating resolver where
    that matters.
  - *Unix-socket resolvers.* A policy that allows nscd's, systemd-resolved's
    or D-Bus's socket gives the agent a resolver that sends DNS itself.
  - *Metadata.* `stat` and `access` on the four view paths report the host's
    files, not the views. (The v1.26.1 trust views answer read-type lookups
    from the view: a read-only file of the view's size.)
  - *Signatures.* A refresh that changes a name's addresses is signed at the
    next scheduled checkpoint, not at once.
- Wildcard host names (v1.25, `v1.25-wildcard-host-names.md`):
  - *The name channel is bounded, not closed.* Within a rule's budgets, the
    labels an agent chooses reach the host's resolver and the domain's DNS
    servers. At the defaults that is at most about 41 bytes a new name: about
    10.5 KB a rule a run, at most 1.2 KB a minute. A name asked again after
    its TTL goes upstream again and counts against `rate=`, so the choice of
    names re-asked carries at most about 30 bytes a minute after that (about
    43 KB a day a rule), and the timing of each lookup a few bits more. The
    With the v1.26 egress proxy on, a name the proxy decides is looked up by
    the Warden only when it dials a request the policy allowed, charged to
    the same budgets; names the agent asks the stub for get synthetic
    addresses and are not looked up.
  - *A deny wildcard holds on names only.* Its hosts cannot be resolved in
    advance, so an allowed name that is a CNAME to one, or shares its
    address, still connects. An exact deny holds on addresses.
  - *The lists are snapshots.* A domain where anyone can create a name, and
    that neither list holds, is not refused; such a wildcard allows the
    names an attacker registers there. The VAREK list is reviewed each
    release. The lists are pinned: lists in the Warden's `data/` that are
    not the release's stop it, and lists an operator names are recorded as
    such and checked again by the audit against the release's.
  - *No stub without a network namespace.* Without one of its own for the
    agent, names that only a wildcard allows do not resolve.
- Egress proxy, SNI mode (v1.26, `v1.26-egress-proxy.md`):
  - *Inside TLS only the ClientHello is read.* A request inside TLS can carry
    a `Host` for another site on the same content network (domain fronting),
    and later requests on a kept-open TLS connection can name another host.
    Both reach only the server the allowed name resolved to; most CDNs refuse
    a `Host` that does not match the SNI. Inspecting mode (v1.26.1) decides
    every request, except on passthrough hosts.
  - *Proxied ports only.* On other ports connects are decided on addresses,
    as in v1.24.
  - *With an upstream, address checks are the upstream's.* The Warden never
    sees the address the upstream dials, so its refusal of special addresses
    and its deny rules on addresses do not apply to names sent there; the
    decision on the name and every deny on a name do. The hop to the
    upstream is `http://` and unencrypted. Configure the upstream to refuse
    those addresses.
  - *Byte counts are claims.* The close records' counts are the proxy's
    report, not measured by the Warden, and say how much was relayed, not
    what.
  - *Refused, not decided.* Encrypted Client Hello, a ClientHello without
    SNI and QUIC on proxied ports are refused; clients that cannot fall back
    fail.
  - *Hashed candidates.* A hand-off whose address has more than 16 names is
    recorded with their hash, and the audit does not ask it of the policy
    again; it reaches only the proxy's listener, and the decision on the name
    it asks for is certified on its own.
  - *Review.* v1.26 was reviewed by AI review agents, not by a human or
    third party.
- Egress proxy, inspecting mode (v1.26.1, `v1.26.1-inspecting-mode.md`):
  - *What is decided is the request line.* Method, path and query are
    decided; headers are not (beyond `Host` and framing), and bodies only
    by length. Data the agent puts in an allowed request's headers, query
    or body reaches the server the policy allows; a DLP tool behind
    `proxy upstream` sees only TLS, so inspecting mode does not replace one
    that terminates TLS itself.
  - *The proxy sees plaintext.* It holds the run's CA key and every
    inspected request and response in memory. It runs as its own user, not
    dumpable, and exits with the run; the CA is name-constrained and lives
    seven days, so a key taken from it signs only for the policy's names.
  - *Secrets in URLs are recorded.* The path and query are recorded as
    sent, as file paths are; an API key in a query is in the stream. Bodies
    are never recorded.
  - *Clients that do not trust the run's CA fail.* A client with its own
    trust store (a pinned certificate, a `CApath` directory instead of a
    bundle file, an application-bundled store) fails its handshake
    (`client_tls`), unless its host is a passthrough host.
  - *HTTP/1.1 only.* A client that offers only h2 is refused; one that
    offers both is answered in HTTP/1.1. WebSocket and other upgrades are
    refused.
  - *Passthrough hosts are not inspected.* Their requests, including a
    fronted `Host` for an inspected name on the same content network, are
    relayed as in SNI mode.
  - *The trust bundle is believed.* A server that any root in the host's
    bundle, or in `--trust-bundle`, vouches for is believed to be the name
    decided.
  - *Framing counts.* `max_body` bounds a body as sent, so a chunked body's
    framing counts against it.
  - *Runs longer than seven days* get their new leaf certificates refused
    once the CA expires.
  - *Review.* v1.26.1 was reviewed by AI review agents, not by a human or
    third party; its findings are listed in the design note.
- Decided program launches (v1.27):
  - *Libraries* written during the run cannot be mapped executable from
    v1.27.1 (below). Through v1.27.0, and from v1.27.1 with
    `--writable-exec` or without `require warden 1.27`, a shared library
    the agent writes to a directory it may also read may run inside an
    allowed program (`LD_PRELOAD`, `dlopen`, an interpreter's native
    extension), held still by the file and network rules.
  - *Arguments are not decided* or recorded: `allow exec /usr/bin/git`
    allows `git` with any arguments.
  - *Interpreters and shells are broad.* Allowing one lets the agent run any
    code it can read with it; lint and the Warden say so.
  - *A swap between allowed programs is killed, not prevented.* The program
    swapped in may run until its first mediated call. The planned
    20,000-swap race test was not built.
  - *A file changed in place* after startup is launched as it now is; the
    record's hash is the one from startup.
  - *Review.* v1.27 was reviewed by AI review agents, not by a human or
    third party; three of the five were stopped partway by a safety
    classifier. Its findings are listed in the design note.
- Writable directories mounted `noexec` (v1.27.1,
  `v1.27.1-writable-noexec.md`):
  - *Code written into memory is not covered.* The agent may still make
    anonymous memory executable (as a JIT needs) and run code it writes
    there, under the same filter, Landlock domain and rules.
  - *Another mount of a writable directory made by the host before the
    run* is not under a listed directory, so a read through it is not
    checked; the policy must also allow that path.
  - *A rule naming its directory through a link* matches no path the
    Warden resolves; the Warden mounts the real directory and says so, and
    the audit, which cannot repeat the Warden's `realpath`, refuses the
    record.
  - *`--writable-exec`* turns the mounts off for a run (recorded, noted by
    the audit); compiled packages installed during a run need it.
  - *Review.* v1.27.1 was reviewed by AI review agents, not by a human or
    third party. Its findings are listed in the design note.
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
