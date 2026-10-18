# VAREK v1.32.1 — Rootless Podman Without `--systemd=always`

**Draft.** Pending: v1.32.0's release, review, and the date.

MIT · github.com/kwdoug63/varek

## Summary

A patch release of v1.32.0. Rootless Podman runs sub-agents and confined
MCP servers without `--systemd=always`. Nothing else changes: no policy,
rule, record or option.

Podman mounts a rootless container's cgroup filesystem read-only. The
Warden needs it read-write for the groups it gives sub-agents, so since
v1.32's review it bind-remounts it read-write in its own mount namespace,
for itself only. Through v1.32.0 it refused to start in a user namespace
instead (`subagent`: "a user namespace (rootless), where the Warden does
not remount it"), naming `--systemd=always`, whose mount of the
container's own groups is read-write already: v1.32's D10 had measured the
plain remount, which the kernel refuses there.

Measured on rootless Podman after v1.32's second review (October 18,
2026, Central; RHEL 9.8, kernel 5.14.0-687, Podman 5.8.2 as ec2-user,
VAREK's SELinux module; `tests/rootless_remount.sh`): without
`--systemd=always`, the plain remount is refused and the bind remount is
made, and a group is then made and a process moved into it. So from
v1.32.1 the Warden makes the bind remount in a user namespace too, and
`varek doctor` and `varek run` no longer fail a rootless container whose
cgroup filesystem is read-only; their mount test tries the remount there.
Where the kernel refuses it (a mount locked read-only by a more privileged
namespace, which rootless Podman does not make), the Warden refuses to
start, naming `--systemd=always` with the kernel's reason.

`--systemd=always` still works, and is no longer needed.

## Tested

`make test-v1321`:

- the Warden reports 1.32.1;
- in a user namespace with a read-only cgroup filesystem of its own,
  `--check-startup` tries the remount and says a run makes it;
- one locked read-only before the user namespace was made: refused,
  naming `--systemd=always` and "Operation not permitted".

`test-v1281`'s container checks run the same in a user namespace as
outside one; `tests/test_varek_container.py` checks that a rootless
read-only cgroup filesystem is no longer a failure, and that a refused
remount there names `--systemd=always` first. `tests/container_sweep.sh`
runs rootless without `--systemd=always` (`--systemd` adds it).

**The rootless sweep** (October 18, 2026, 10:38 CDT; `5b59920`; RHEL
9.8, kernel 5.14.0-687, Podman 5.8.2 as ec2-user, subordinate IDs
`100000:65536`, SELinux enforcing, `container_init_t`, the ten
capabilities, `--cgroupns=private`, **without `--systemd=always`**): every
suite passes, 32 of 32 (`test-v1321`'s section 2, which makes a user
namespace of its own, skips inside a container, where it cannot; it runs
on the host). In the container's user namespace, `test-v1281` found the
cgroup filesystem read-only, `--check-startup` tried the remount and said
a run makes it, and a run made it and attributed its sub-agent: the two
checks v1.32.0 refused there. v1.32.0's rootless sweep was run with
`--systemd=always`.

## Upgrading

Rootless Podman: drop `--systemd=always` from the run, or keep it. Nothing
else changes.
