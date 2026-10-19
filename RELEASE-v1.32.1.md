# VAREK v1.32.1 — Rootless Podman Without `--systemd=always`

Released 2026-10-19 · MIT · github.com/kwdoug63/varek

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
VAREK's SELinux module; `tests/rootless_remount.sh` on the roadmap
branch): without
`--systemd=always`, the plain remount is refused and the bind remount is
made, and a group is then made and a process moved into it. So from
v1.32.1 the Warden makes the bind remount in a user namespace too, and
`varek doctor` and `varek run` no longer fail a rootless container whose
cgroup filesystem is read-only; their mount test tries the remount there.
Where the kernel refuses it (a mount locked read-only by a more privileged
namespace, which rootless Podman does not make), the Warden refuses to
start, naming `--systemd=always` with the kernel's reason. Where the
container's control group is not delegated to its user (rootless Podman
without the systemd cgroup manager in the user's systemd session), the
remount is made but no group can be: `--check-startup` and `varek doctor`
now say so, as a run does, naming the delegation.

`--systemd=always` still works, and is no longer needed.

## Tested

`make test-v1321`:

- the Warden reports 1.32.1;
- in a user namespace whose root is a user outside (uid 100000), with a
  fresh read-only cgroup filesystem in a group delegated to that user, as
  rootless Podman makes it: `--check-startup` tries the remount and says a
  run makes it, and a run makes it, its sub-agent launched and attributed;
- the same in a group not delegated: refused at `--check-startup` and at a
  run alike, naming the delegation;
- one locked read-only before the user namespace was made: refused,
  naming `--systemd=always` and "Operation not permitted";
- from any group the suite starts in (each case makes its own).

`test-v1281`'s container checks run the same in a user namespace as
outside one; `tests/test_varek_container.py` checks that a rootless
read-only cgroup filesystem is no longer a failure, and that a refused
remount there names `--systemd=always` first. `tests/container_sweep.sh`
runs rootless without `--systemd=always` (`--systemd` adds it).

**The rootless sweep** (October 18, 2026, 10:38 CDT; `5b59920`; RHEL
9.8, kernel 5.14.0-687, Podman 5.8.2 as ec2-user, subordinate IDs
`100000:65536`, SELinux enforcing, `container_init_t`, the ten
capabilities, `--cgroupns=private`, **without `--systemd=always`**): every
suite passes, 32 of 32 (`test-v1321`'s user-namespace cases, which make
namespaces of their own, skip inside a container, where they cannot; they
run on the host). In the container's user namespace, `test-v1281` found the
cgroup filesystem read-only, `--check-startup` tried the remount and said
a run makes it, and a run made it and attributed its sub-agent: the two
checks v1.32.0 refused there. v1.32.0's rootless sweep was run with
`--systemd=always`. The review's fixes (below) came after the sweep; they
add the check that groups can be made, which the sweep's runs made.

## Found in review

One AI review agent reviewed the patch (October 18, 2026); it found no way
past the Warden. The agent's reach is as rootful: the cgroup files are the
container root's, which the agent is not, and its filter refuses mounts.
Fixed: in a user namespace whose group was not delegated, the remount
succeeded but no group could be made, so `--check-startup` and `varek
doctor` passed and the run refused; both now test that groups can be made,
and every refusal there names the delegation. `test-v1321` failed when run
from a group other than the hierarchy's root; it now makes its own. The
user-namespace refusal names AppArmor as well as SELinux; stale comments.

## Upgrading

Rootless Podman: drop `--systemd=always` from the run, or keep it. Nothing
else changes.
