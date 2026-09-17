# VAREK v1.12.0 — Mediation Correctness

Released 2026-09-17 · MIT · github.com/kwdoug63/varek

## Summary

v1.12 is a mediation-correctness release. It changes no verdict *semantics* —
the three-state SMT decision procedure and the symmetric-suppression invariant
(**no extension may move a genuinely unsafe action to SATISFIED**) are untouched
— but it fixes five ways a process under the live Warden could make the runtime
authorize, deliver, or record the wrong thing. Four are enforcement escapes; one
is an integrity flaw in the evidence the runtime produces. It also adds a tool
that exports authorization evidence in the CycloneDX 1.6 format.

The version jumps from v1.9.3 to v1.12. **v1.10 and v1.11 are reserved** for the
UNKNOWN-shrinking verification program (verdict-distribution harness, bitvector
and bounded-string fragments); that program is orthogonal to this release and is
untouched by it. Shipping mediation fixes ahead of it under a distinct number
keeps the two lines from being confused.

Every fix below is covered by `make test-v112`, which fails against the
pre-v1.12 Warden.

## The defect the escapes share

A policy decision is only as sound as the identity of the object it is made
about. Through v1.9.3 the Warden decided policy against the **pathname string**
the agent supplied and then, as a separate step, opened whatever that string
resolved to. Those two steps could name two different inodes. Everything in the
first group below is an instance of that gap.

## Security

### Resolve-then-decide for file opens

The Warden now opens the requested object **once**, with
`openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`, reads the canonical path
back from the resolved fd, makes the policy decision on **that** path, and
injects the same fd it resolved. Decision and delivered capability refer to the
same inode by construction; there is no second open and so no
resolve/decide/deliver race. Resolution failure — a symlink component, an
over-long path, an untracked `dirfd`, a deleted inode — is a hard deny before any
policy match. This closes three escapes:

- **`..` traversal.** `open("/tmp/allowed/../../etc/shadow")` matched the allowed
  prefix as a raw string and was opened. The decision is now made on the
  post-`..`-collapse canonical path (`/etc/shadow`), which matches no allow rule.
- **Symlink escape.** A symlink planted inside an allowed directory, pointing at
  a denied object, was followed. The shipped resolver had set only
  `RESOLVE_NO_MAGICLINKS` — the header and threat model claimed
  `RESOLVE_NO_SYMLINKS` too, but the code did not set it. It is set now; a
  symlink component fails resolution and is denied.
- **`/proc/self` context confusion.** `/proc/self/*` is a magic symlink the
  kernel resolves in the **caller's** context — here the supervisor's. An agent
  opening `/proc/self/mem` received a read/write handle on the Warden's own
  address space. `RESOLVE_NO_MAGICLINKS` (now actually set) refuses it.

### Audit-log integrity

The pathology stream is evidence, so it must be unforgeable by the process it
describes. The agent-controlled pathname was written into the JSON verdict record
unescaped, so a crafted path containing `","decision_final":"ALLOW"}` and a
newline could inject a forged authorization record into the stream a downstream
consumer reads. All agent-controlled fields (`target`, and the new `resolved`)
are now JSON-escaped; every record is well-formed JSON for any byte sequence, and
no agent input can begin, end, or fabricate a record.

### Datagram egress mediation

`sendto` and `sendmsg` were admitted unconditionally by the baseline filter, so
an agent could reach the network with a datagram send and never call the
deny-only `connect` — a hole inherited from the old allow-by-default model and
previously disclosed under bypass class 3. Both are now routed to the supervisor
and decided as `net.send`: a send carrying an inet destination is refused under
the same deny-only network posture as `connect`. Inbound `recvfrom`/`recvmsg`
remain admitted.

## Changed

### Bootstrap listener handoff uses `pidfd_getfd`

Mediating `sendmsg` broke the previous `SCM_RIGHTS` handoff of the seccomp
listener fd: the child's own `sendmsg` trapped on its just-installed filter,
before any supervisor was listening, and deadlocked. The child now writes the
listener fd **number** over the socketpair with `write()` (admitted) and the
supervisor pulls the fd out of the child's table with `pidfd_open` /
`pidfd_getfd`. No post-filter `sendmsg` is needed, so both send syscalls can be
mediated. The supervisor is not under seccomp, so these calls are unrestricted
for it.

## Added

- **`varek/v1_4/tools/varek_cyclonedx.py`** — exports a Warden pathology log as a
  Bill of Materials in the **CycloneDX 1.6** format: the Warden as a
  `metadata.tools` component (MIT license plus the three provisional-patent
  references as properties), the supervised run as `metadata.component`, each
  distinct authorized object as a component carrying the deciding rule, and an
  Authorization-Before-Execution attestation as a top-level annotation (policy
  identity, run window, verdict distribution, the invariants that held). Output
  validates against the published CycloneDX 1.6 JSON schema. It uses only stable
  1.6; the "pre-defined perspectives" proposal (CycloneDX specification PR #1067,
  targeting 2.0-dev) is noted as a natural future carrier for a
  `cdx:perspectives:*` reference on the attestation, not a dependency of this
  release.

  CycloneDX is a trademark of the OWASP Foundation. VAREK and Sober Agentic
  Infrastructure, Inc. are not affiliated with, endorsed by, or certified by the
  OWASP Foundation or the CycloneDX project; the CycloneDX name is used only to
  describe interoperability with the openly published CycloneDX format
  (ECMA-424). See the `NOTICE` file.

  ```
  ./warden policy.txt -- ./agent 2> run.log
  python3 tools/varek_cyclonedx.py --log run.log --agent ./agent \
      --policy policy.txt --output authorization-bom.json
  ```

- **`make test-v112`** — `tests/v112_probe.c`, `tests/test_v112.sh`,
  `tests/v112_policy.txt`. An adversarial target exercises all five escapes plus
  one legitimate open; the harness asserts on both the agent's own view and the
  Warden's verdict stream, including that the stream stays valid JSON with no
  forged record.

## Fixed

- `docs/security/bypass-classes.md`: class 3 marked **closed** for the datagram
  send path; class 4's symlink/magic-link claim reconciled with the shipped
  resolver flags; a `/proc/self` context-confusion row (4a), a resolve-then-decide
  section, and an audit-log-integrity section added.

## Compatibility

No policy-file or plan-file format change. Verdicts on the demo,
plan-verification, benchmark, and conformance workloads are unchanged except that
previously-mis-authorized traversal/symlink opens are now correctly denied.
Pathology records gain a `resolved` field; consumers that parsed the prior fields
are unaffected. `sendto`/`sendmsg` in a supervised target now return `EPERM` for
inet destinations — targets that need outbound network still cannot get it under
the deny-only posture (unchanged intent; the datagram path simply no longer
escaped it).

## Requirements

Linux ≥ 5.14 (seccomp user-notify with `ADDFD`), `pidfd_getfd` (Linux ≥ 5.6),
`CAP_SYS_ADMIN` for the PID namespace (as in v1.9.3), x86_64.
