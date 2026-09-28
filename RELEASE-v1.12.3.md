# VAREK v1.12.3 — Dynamically Linked Agents

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

v1.12.3 lets dynamically linked agents run under the live Warden. Since v1.12.0
the Warden resolved a file open with `RESOLVE_NO_SYMLINKS`, which refused any
path containing a symlink anywhere. On a merged-`/usr` system `/lib` is a
symlink and shared-library SONAMEs (`libz.so.1` → `libz.so.1.3`) are symlinks,
so the dynamic loader could not open its libraries and any dynamically linked
program — CPython, a JVM, Node — failed before `main()`. Only static agents ran.

v1.12.3 follows ordinary symlinks and decides policy on the **canonical path**
of the object the resolution reaches. The security property is unchanged: a
symlink in an allowed directory that points at a denied file is decided as the
denied file and refused. What changes is that a symlink pointing at an *allowed*
object is now followed and delivered, so the loader works.

No verdict *semantics* change. The policy rules, the three-state verdict with
UNKNOWN suppressed to DENY, and the symmetric-suppression invariant (**no
extension may move a genuinely unsafe action to SATISFIED**) are untouched.

`make test-v1123` covers the change and fails against v1.12.2. The v1.12.2,
v1.12.1, v1.12.0 and v1.9.3 lifecycle suites and the conformance target still
pass.

## Security

The resolve-then-decide-then-inject design is what keeps symlink following safe,
and it is unchanged: the Warden pins the object with an `O_PATH` descriptor
(opening nothing), decides on that descriptor's canonical path, and on ALLOW
delivers that same descriptor. So the object decided on is the object delivered,
and a symlink swapped after the decision cannot change which inode the agent
receives.

### Symlinks are decided on their canonical target

`openat2` follows symlinks inside the kernel to a single pinned object.
`readlink` of the pinned descriptor gives its canonical path, and policy is
matched on that. So:

- A symlink in an allowed directory pointing at a denied file (or `/etc/shadow`,
  or through a chain of symlinks) resolves to the denied object and is refused.
- `..` is still defanged by deciding on the post-collapse canonical path.
- `RESOLVE_NO_MAGICLINKS` is still set, so `/proc/<pid>/fd/N`, `/proc/<pid>/cwd`,
  `exe` and `root` do not resolve.
- A trailing symlink opened `O_NOFOLLOW` is refused (the agent's `O_NOFOLLOW` is
  passed to the `O_PATH` resolve, which returns the link itself; the Warden
  refuses a link object). A normal open would return `ELOOP`.

Because the decision is now on the canonical path, an operator's `allow path`
prefixes must name canonical locations. On a merged-`/usr` system that means
`/usr/lib/`, not `/lib/` (the loader's `/lib/...` opens resolve to `/usr/lib/...`).
The demo, benchmark and conformance policies already use canonical prefixes.

### /proc/self maps to the agent, never the supervisor

`/proc/self` is an ordinary symlink, so following it matters: resolved by the
Warden it would name the *Warden's* process. v1.12.3 handles `/proc` in two
places:

- **Before resolution**, a leading `/proc/self` or `/proc/thread-self` in the
  agent's path is rewritten to the agent's own `/proc/<tgid>` (or
  `/proc/<tgid>/task/<tid>`), so it resolves to the agent, not the supervisor.
- **After resolution**, any object that lands on a procfs mount must be either
  the agent's own `/proc/<tgid>/…` or a non-process entry (`/proc/cpuinfo`,
  `/proc/sys/…`). The Warden's own `/proc/<pid>/…` and any other process's
  `/proc/<pid>/…` — reached directly or through a symlink — fail closed.

Two distinct guards cover `/proc`, and it is worth being precise about which
does what:

- `/proc/self`, `/proc/thread-self` and `/proc/<pid>/fd/N` are **magic links**.
  `RESOLVE_NO_MAGICLINKS` refuses to follow them during resolution, so a *planted
  symlink* pointing at `/proc/self/mem` (which would resolve in the Warden's
  context) fails at resolution, before any policy or `/proc` check. This is why a
  *leading* `/proc/self` in the agent's own path has to be rewritten to
  `/proc/<tgid>` first — otherwise the agent could not name its own `/proc` at
  all.
- A path or symlink that reaches another process's **numeric** `/proc/<pid>/…`
  (the Warden's own, or any other process's) is an ordinary path that resolves
  fine; the post-resolution check refuses it because `<pid>` is not the agent's
  `tgid`.

An object that is the agent's own is decided and recorded as `/proc/self/…`,
which is how policies name it. A non-process procfs entry (`/proc/kcore`,
`/proc/sysrq-trigger`, `/proc/sys/…`) is not refused by this check — it is
governed by policy like any other path, so a broad `allow path /proc/` would
expose it; name the specific entries an agent needs.

## Compatibility

- **Policies match canonical paths.** An `allow path` prefix that named a
  symlinked location (for example `/lib/` on a merged-`/usr` system) no longer
  matches; use the canonical target (`/usr/lib/`). This was already true for the
  target of a `..` or symlink before v1.12.3; it now also applies to the loader
  search path. Policies that already name canonical prefixes are unaffected.
  Prefix matching is literal, so end a directory prefix with `/` (`/usr/lib/`,
  not `/usr/lib`, which would also match `/usr/libexec`); the shipped policies
  do.
- To open a symlink *as a link* rather than its target, an agent passes
  `O_NOFOLLOW`; the Warden refuses it (a link is not an allowable object).
- `/proc/self/…` and `/proc/thread-self/…` opened by the agent now resolve to
  the agent's own process and are recorded as `/proc/self/…`.
- No policy-file, plan-file or record-format change. `run_start` reads
  `"warden":"1.12.3"`.
- Decision latency is unchanged within run-to-run noise. A successful resolve
  adds an `fstat` and an `fstatfs` on the pinned descriptor (an `O_CREAT` that
  pins the parent adds one `fstatfs`); the requester's `tgid` is looked up
  (`/proc/<tid>/status`) only for a `/proc/self` path or an object that lands on
  procfs, so an ordinary open reads no extra `/proc` file. P50 5–8 µs before and
  after; P99 59–90 µs before and 55–94 µs after, five interleaved runs of
  `bench_target 10000`.

## Testing

- `make test-v1123`: the probe is built **dynamically** on purpose, so its own
  loader opens exercise symlink following; reaching `done` is the headline fix.
  It also checks, against a live Warden, that a symlink to an allowed file is
  followed and delivered (plain, relative, and via a symlinked directory
  component); that a symlink escaping to a denied file, an absolute-denied
  symlink and a symlink chain are refused and leave the denied file unchanged;
  that a trailing symlink opened `O_NOFOLLOW` is refused; that `/proc/self` and
  `/proc/thread-self` read back the agent's own `cmdline`; and that a planted
  symlink to `/proc/self/mem`, another process's `/proc/1/mem`, and `/proc/kcore`
  are all refused. Against v1.12.2 the symlink and `/proc/self` opens are refused
  and the suite fails.
- A dynamically linked, multithreaded CPython agent (thread pool, `fork`/`wait`,
  a denied open) runs correctly end to end.
- `make test-v1122`, `make test-v1121`, `make test-v112`, `make test-lifecycle`
  and `make run-conformance` pass unchanged.

## Known issue, not addressed here

- The `--plan` gate still refuses any plan that contains a `file_open` action,
  as it has since v1.12.0.

## Requirements

Unchanged from v1.12.2: Linux ≥ 5.14, `pidfd_getfd` (Linux ≥ 5.6),
`CAP_SYS_ADMIN` for the PID and network namespaces, x86_64.
