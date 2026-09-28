# VAREK v1.12.1 — Mediation-Correctness Follow-up

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

v1.12.1 fixes three defects in v1.12.0. A denied file open could still change
the filesystem; the supervised agent could forge verdict records; and inbound
networking was left open to a root agent. It changes no verdict *semantics*: the
policy rules, the three-state verdict with UNKNOWN suppressed to DENY, and the
symmetric-suppression invariant (**no extension may move a genuinely unsafe
action to SATISFIED**) are untouched.

Every fix is covered by `make test-v1121`, which fails against v1.12.0. The
v1.12.0 suite (`make test-v112`) and the v1.9.3 lifecycle suite still pass.

The three fixes ship as one patch release. They touch the same mediation code,
were found in the same review, and a deployment needs all three.

## Security

### A DENY has no side effect

v1.12.0 made the policy decision on the object actually delivered, which closed
the traversal, symlink and `/proc/self` escapes. But it found that object by
opening it, with the agent's own flags and as root, **before** deciding. So a
denied open still did whatever its flags asked:

- `open("/denied/secret", O_WRONLY | O_TRUNC)`: logged DENY, and the file was
  emptied.
- `open("/denied/new", O_CREAT)`: logged DENY, and a root-owned file appeared.
- `open("/allowed/fifo", O_WRONLY)` with no reader: the single-threaded Warden
  blocked inside the open and stopped answering every other request.

v1.12.1 splits the step. The object is pinned with an `O_PATH` descriptor, which
opens nothing, and the decision is made on its canonical path. Only after ALLOW
is it opened with the agent's flags, through the pinned descriptor rather than
the agent's pathname, so the decided object is still the delivered one.

- **Creating a file.** `O_CREAT` of a name that does not exist pins the parent
  directory instead, and decides on `<canonical parent>/<name>`. After ALLOW the
  file is created with `openat(parent_fd, name, O_NOFOLLOW)`, so a symlink raced
  into the name is refused. The agent's umask is applied.
- **FIFOs and devices.** The real open adds `O_NONBLOCK` and clears it
  afterwards unless the agent asked for it, so nothing can block the supervisor.
  One visible difference: opening a FIFO for writing with no reader returns
  `ENXIO` instead of waiting.
- **Errors after ALLOW.** An allowed open that fails for an ordinary reason
  (`EEXIST` for `O_CREAT | O_EXCL` on an existing file, `ENXIO` above) returns
  that errno to the agent. The record says `"kernel_verdict":"ERRNO"` and carries
  the new `errno` field.

### An authenticated verdict stream

v1.12.0 escaped every agent-controlled string inside a record, so a crafted path
could no longer break a record open. But the agent shared the Warden's stderr,
so it could write a whole, well-formed record of its own. A fake
`"decision_final":"ALLOW"` record for `/etc/shadow` looked exactly like a real
one, and `varek_cyclonedx.py` listed `/etc/shadow` as an authorized object.

v1.12.1:

- **The agent no longer writes to the stream.** Its stderr is a pipe the Warden
  relays line by line with an `[agent] ` prefix, escaping control bytes, so no
  agent byte can begin a line of the verdict stream and a `\r` cannot split one.
- **One write per record.** Records go through a private close-on-exec
  descriptor, fully buffered and flushed once per record, so nothing else writing
  to the same file can land inside a record.
- **Run id and sequence.** Every record carries `run`, 128 random bits the agent
  never sees, and `seq`, counting up from 0. `run_start` and `run_end` records
  frame the stream.
- **The exporter verifies.** `varek_cyclonedx.py` refuses to emit a BOM when the
  stream has no `run_start`, holds a record with a foreign run id (for example
  the agent's stdout merged in with `2>&1`), has a `seq` gap or repeat, or has
  no `run_end` (a killed Warden or a cut log; `--allow-incomplete` attests the
  part present and marks it). The BOM gains `varek:run.id` and
  `varek:run.complete`.

The stream is authenticated against the supervised agent, not signed: someone
who can edit the log file after the run can still alter it. Signed or
hash-chained records for third-party verification remain future work.

### Inbound networking refused

The deny-only network posture covered outbound traffic only. `bind`, `listen`,
`accept` and `accept4` were admitted, and the agent runs as root in the host
network namespace, so it could accept TCP connections or bind an abstract unix
socket the host could reach. A pathname unix-socket `bind` also created a file
outside `open()` mediation.

- The four calls are no longer admitted and fall to the default EPERM. `socket`,
  `socketpair` and socket options stay admitted, so targets start normally and
  outbound attempts still reach the Warden and are logged.
- The agent runs in its own network namespace, holding only a loopback interface
  that is down. With the PID namespace (`CAP_SYS_ADMIN` held) failure to create
  it is fatal; with `VAREK_WARDEN_NO_PIDNS=1` it is a warning.
- The status line reports `netns=on|off`, found by comparing namespace
  identities rather than trusting the child.

## Compatibility

- No policy-file or plan-file format change. Verdicts on the demo, benchmark and
  conformance workloads are unchanged.
- The agent's stderr is prefixed `[agent] ` in the Warden's output.
- Records gain `run`, `seq` and `errno`. Consumers that read the prior fields are
  unaffected; `run_start` and `run_end` are new record types.
- `varek_cyclonedx.py` no longer accepts v1.12.0 logs.
- Targets that listen for connections now get `EPERM` from `bind`/`listen`.
- Decision latency is unchanged within run-to-run noise (P50 5 µs; P99 43–53 µs
  before and 46–50 µs after, three runs each of `bench_target 10000` on the same
  host).

## Known issue, not addressed here

The `--plan` gate still refuses any plan that contains a `file_open` action, as
it has since v1.12.0: the plan decider fills in the raw path but policy now
decides on the resolved one. The v1.6 integration test fails identically before
and after this release.

## Requirements

Unchanged from v1.12.0: Linux ≥ 5.14, `pidfd_getfd` (Linux ≥ 5.6),
`CAP_SYS_ADMIN` for the PID and network namespaces, x86_64.
