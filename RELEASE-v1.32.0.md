# VAREK v1.32.0 — An Official Image, for Docker and Podman

> v1.32.0 had a review by AI review agents: six, each on one area (the
> Warden's changes, the image and its AppArmor and SELinux confinement, the
> CI and release workflows, the container checks in `varek doctor` and
> `varek run`, the tests and the container sweep, and the documentation
> against the code); its findings are fixed (below). A human or
> third-party review has not been done.

**Draft.** Pending: the 24-hour soak inside a container, and the date.

MIT · github.com/kwdoug63/varek

## Summary

Most production agents run in containers. Through v1.31.1 the Warden ran
as root on a host: under Docker's or Podman's defaults it refuses to start,
and the usual answer, `--privileged`, grants everything and turns off the
container's own seccomp profile and its AppArmor or SELinux confinement.

From v1.32.0:

1. **An official image.** `ghcr.io/kwdoug63/varek` carries the Warden,
   `warden-proxy`, `warden-secrets`, the `varek` command and the shipped
   policies and profiles, on Red Hat's Universal Base Image 9 minimal, with
   no compiler. Its entrypoint is `varek run --`: the container's first
   process is the Warden and the agent is its child, in PID, network and
   mount namespaces the Warden makes inside the container, as on a host.
   An agent runs under VAREK by building `FROM` the image and naming its
   command (`packaging/container/README.md`).
2. **A published, minimal set of settings, never `--privileged`.**
   `--cap-drop ALL` and ten capabilities added back (SYS_ADMIN,
   SYS_PTRACE, SETPCAP, SETUID, SETGID, DAC_OVERRIDE, KILL, NET_ADMIN,
   NET_BIND_SERVICE, CHOWN), each with the reason the Warden needs it and
   each shown needed by a suite that fails without it; `--cgroupns=private`;
   the runtime's default seccomp profile, unchanged. The agent holds none
   of the capabilities: the Warden empties its bounding set and drops it to
   its own user, as on a host.
3. **AppArmor and SELinux kept on.** Docker's `docker-default` denies every
   mount, and the Warden mounts the agent's writable directories noexec.
   `packaging/container/apparmor/varek-container` is Docker's current
   `docker-default` with the Warden's three kinds of mount allowed (its
   mount namespace made private, a directory bound, a bind mount's flags
   changed) and no other. On SELinux the container
   runs as `container_init_t`, the distribution's type for containers that
   manage their control groups, with
   `packaging/container/selinux/varek_container.cil`'s four rules (the
   cgroup filesystem's remount; mounting on the container's `/dev/null` and
   on the host's `/dev/null` and `/dev/tty`, which rootless Podman binds
   in). Other containers keep `container_t`.
4. **Sub-agents and confined MCP servers in a container.** Docker and
   Podman mount the cgroup filesystem read-only. With `--cgroupns=private`
   the Warden sees only the container's own groups and bind-remounts that
   view read-write in a mount namespace of its own; the container's mount
   stays read-only, the filesystem's own options are untouched, and the
   agent can write none of it. Without
   `--cgroupns=private` it refuses to start and says so.
5. **Rootless Podman**, with `--systemd=always`: in a user namespace the
   kernel keeps the cgroup filesystem read-only, and Podman's systemd mode
   mounts the container's own, delegated, groups read-write. Without it, a
   policy with sub-agents is refused at `--check-startup` and at a run,
   naming the flag.
6. **`varek doctor` in a container** checks each setting (the
   capabilities, seccomp, the AppArmor profile or SELinux type, the cgroup
   namespace, rootless) and makes the Warden's mounts in a child, naming
   the flag that supplies anything missing (`--cap-add SYS_PTRACE`,
   `--cgroupns=private`, ...). `varek run` refuses, before the agent
   starts, a container that cannot carry the run (a missing capability
   always; the profile, the mount test and the control groups when the
   policy needs them), and the preflight (`tools/varek_preflight.sh`) has
   the same checks as its section 2b.
7. **Signed, with a bill of materials.** On each release tag
   (`.github/workflows/container-release.yml`) the image is built, checked
   as CI checks it, pushed, signed with cosign keyless (the workflow's own
   GitHub identity, in Sigstore's public log) and given a CycloneDX SBOM as
   a signed attestation; both are verified, and only then are `:1.32` and
   `:latest` moved to it. Only a tag on main is released; every action the
   workflow runs is pinned by its commit. No key or password is kept.

8. **A sub-agent of the image its launcher runs, without process events.**
   In a container the kernel's process events do not reach the Warden
   (RHEL 9, Ubuntu 24.04), and through v1.31 the Warden then refused a
   sub-agent of the image its launcher runs (`subagent_same_image`): a
   Python agent could not launch a Python MCP server confined. The Warden
   now tells such a launch from a failed one by the process's memory
   layout (`/proc/<pid>/stat`: where its code, stack, heap, arguments and
   environment begin and end), which every new program gets anew,
   randomized, and which the process cannot change but by a launch (the
   agent's filter refuses `prctl(PR_SET_MM)`, under every policy). The
   settling is recorded `"how":"layout"`. On a host without process events
   the same holds.

It changes no policy line: the Warden inside a container is the Warden on
a host. The one decision that changes is the last above: a launch the
Warden refused without process events is now made where it can be told. The Warden reports 1.32.0; the grammar
stays 1.31 (`require warden 1.32` is refused).

## Tested

`make test-v1320` runs 22 checks; CI runs it as root:

- **The version** (section 1): the Warden reports 1.32.0 and `run_start`
  names it; `require warden 1.32` refused, `require warden 1.31` loads.
- **`varek doctor` in a container** (2): its container section, the
  capabilities, and the Warden's mounts made in a child; no section on a
  host.
- **The preflight's share** (3): `varek run` goes ahead with the
  capabilities; without SYS_PTRACE (taken from the bounding set with
  `setpriv`) it is refused before the agent starts, naming `--cap-add
  SYS_PTRACE`; the preflight's section 2b says the same, and is absent on a
  host.
- **The packaging** (4): the AppArmor profile compiles, its mount rules
  exactly the Warden's three, with `docker-default`'s denials; the SELinux
  module exactly its four rules; the Containerfile's stages and entrypoint;
  the CI and release workflows (the release's pins and gates).

`tests/test_varek_container.py` (14 tests, in `make test-cli`) checks each
of doctor's rules from a container's state as text, and the mount probe.
`make test-v1281` gains three checks, on any host with the process events
turned off for them: a sub-agent of the image its launcher runs, launched
and told by its layout; a failed one (E2BIG), the agent's; and the refusal
where layouts are not randomized. Every earlier suite passes on the test host, except `test-v1210`'s three Python `requests`
checks, which fail the same way on v1.31.1 there (the host reaches no
network they need): no regression.

**Inside containers** (`tests/container_sweep.sh`, the image's `test`
stage, every suite under the documented settings):

| Host | Confinement | Result |
|---|---|---|
| Ubuntu 24.04, kernel 6.8, Docker 29.1.3, cgroup v2 | AppArmor, `varek-container` | 31 of 31 |
| RHEL 9.8, kernel 5.14, Podman 5.8.2 rootful, cgroup v2 | SELinux enforcing, `container_init_t` and `varek_container.cil` | 31 of 31 |
| RHEL 9.8, Podman 5.8.2 rootless (as a user, subordinate IDs), `--systemd=always` | SELinux enforcing, as above | 31 of 31 |

With the review's fixes and the memory layout (2026-10-17 and 18,
Central): every suite on commit `f37d9ae`, and `test-v1281` again on
`fc6f4c4` (Docker) and `63a9511` (rootless), after its own setup and the
order of two refusals were fixed (below).

With `--drop-each`, each of the ten capabilities is needed by at least one
suite. The skips are those a container explains (Known limits, below), and
those that need a test user or a raw device.

**The runtime image** (Docker on Ubuntu 24.04, the AppArmor profile):
`varek doctor`'s container section all OK, the mount test and the cgroup
remount among them; `/bin/echo` run as the agent under the baseline, as
`nobody`, 16 calls allowed and 0 refused.

## 24 hours in a container

Running: started 2026-10-18 02:29 CDT on a 2 GB droplet (Ubuntu 24.04,
kernel 6.8, Docker 29.1.3), the shared soak in the test image under the
documented settings and the AppArmor profile as shipped
(`tests/soak_shared/container.sh`, commit `54584a4`). Its 6-minute trial
passed, run A's two Python servers settled by their layout.

## Compatibility

- Every v1.31 policy loads unchanged and decides the same, but for one
  launch: without the kernel's process events (in a container, or a host
  without them), a sub-agent of the image its launcher runs, refused
  through v1.31 (`subagent_same_image`), is now made where layouts are
  randomized, its settling recorded `"how":"layout"`. The grammar is
  1.31's; a policy naming `require warden 1.32` is refused.
- The Warden, on a host or in a container: a read-only cgroup filesystem
  at its cgroup namespace's root is remounted read-write in the Warden's
  own mount namespace when the policy names a sub-agent or an MCP server
  (before, the Warden refused to start); a mount already noexec is left as
  it is when the Warden mounts the agent's writable directories noexec.
- New: the image (`packaging/container/`), `tools/varek_container.py`
  (installed with the tools), `varek doctor`'s container section, `varek
  run`'s container refusal, the preflight's section 2b, `make test-v1320`,
  `tests/container_sweep.sh`, and the workflows `container.yml` and
  `container-release.yml`.

## Found by the sweeps after the review

- **test-v1281 stopped at its own setup under the AppArmor profile.**
  Where the cgroup filesystem is read-only, the suite re-runs itself with
  it remounted read-write, by a plain remount, which the profile no longer
  allows; it now bind-remounts it, as the Warden does.
- **Rootless, the refusal named the wrong setting first.** A read-only
  cgroup filesystem not at its cgroup namespace's root was refused for
  the user namespace; the Warden now names `--cgroupns=private` first,
  the setting every container needs, as `varek doctor` orders them.

## Found in review

Six AI review agents each reviewed one area, reading the code and running
what they could; each finding was checked against the code before it was
fixed (commit `b8d7a71`).

- **The Warden's cgroup remount reconfigured the shared filesystem.** It
  was a plain remount, which reconfigures the cgroup2 filesystem itself,
  shared by every cgroup2 mount on the machine; in the initial cgroup
  namespace that resets its options (`nsdelegate` and others) host-wide.
  It is now a bind remount: that one mount's flags, in the Warden's own
  mount namespace, noexec and the others kept, read-write checked after.
  A user namespace is told by its inode, not by an identity `uid_map`,
  and `--check-startup` tries the remount in a child, so it says what a
  run will find.
- **The release workflow's check could not fail.** `grep ... && ! grep
  FAIL` ends in a negated command, which `bash -e` never stops on. Fixed,
  and the workflow hardened: every action pinned by its commit (the job
  holds the token that publishes and the identity that signs), cosign and
  syft by version and installed before the registry login, permissions
  per job, only a tag on main, Docker's defaults
  checked refused, the version compared exactly, a pre-release published
  under its own tag only, `:1.32` and `:latest` moved only after signing
  and verifying and only to the highest release, and no expression
  pasted into a script. CI's token is read-only.
- **The image could ship a binary built on the host.** The build context
  took the checkout's built files, newer than their sources, so `make`
  installed them. Each stage now runs `make clean` first, and
  `.dockerignore` keeps built and private files out. EPEL's release
  package is installed only when signed by EPEL 9's key, kept with the
  image (fingerprint `FF8A D134 4597 106E CE81 3B91 8A38 72BF 3228 467C`).
- **`varek run` refused every run under `docker-default`**, a run that
  mounts nothing included. The profile is now refused only for a run
  that mounts or makes control groups, and warned of otherwise; the
  preflight counts the policy's needs as `varek run` does, and fails if
  its checks do not run.
- **test-v1281's process-event skip was decided by the Warden under
  test**, so a Warden that lost them would skip, not fail, on any host. It
  skips only in a container now.
- **The AppArmor profile** lacked `docker-default`'s newer denials
  (AF_ALG, AF_VSOCK, obsolete socket families) and its signals from runc
  and crun; resynced with moby/profiles. Its mount rules are three, the
  cgroup rule now the bind remount, and its comment and the README say
  what AppArmor cannot bound: a bind's target, and a remount's kept flags.
- **Smaller**: the mount probe's directory made and removed by the parent
  (another probe's could be removed), its child never returning to the
  caller; the effective capabilities counted as root; test-v1320 compares
  the profile's and the module's rules exactly; the sweep tags its image
  by commit and records it, removes a container a stopped run leaves,
  says a capability no suite needed, and stops if it finds too few
  suites; `test-v1170` counts its skip.
- **Documentation**: the SELinux module's rules (four) and what
  `container_init_t` grants; the AppArmor mounts; the capability count
  (ten); the rootless status; the TCB row (a missing setting can leave
  the Warden running with less, never the agent less confined); the agent
  holds no capability unless run `--run-as root`; the cosign check by the
  version's exact identity and the image run by digest; D6's CI.

Not changed: the base images are named by tag, not digest, so each build
takes their current fixes; the SBOM attestation records every package
that went in. Container detection does not cover a runtime that leaves
neither `/.dockerenv` nor `/run/.containerenv` (Kubernetes' containerd):
`varek doctor` and `varek run` treat it as a host, and the Warden refuses
by itself what it cannot do.

## Known limits

- **The Warden needs CAP_SYS_ADMIN in the agent's container** (D3): it
  makes the agent's PID, network and mount namespaces and the noexec
  mounts. The agent never holds it. Running the Warden outside the agent's
  container is v1.34's node agent.
- **Process events**: on RHEL 9's kernel 5.14 and Ubuntu 24.04's 6.8 the
  kernel's process events do not reach a listener in a container's own
  network namespace. The Warden says so and falls back, as on a host
  without them: a launch is known by the image a process runs, and one of
  the image its launcher runs by the process's memory layout (above).
  Where layouts are not randomized (`kernel.randomize_va_space` not 2),
  such a launch is refused (`subagent_same_image`).
- **`O_TMPFILE`**: the container's overlayfs `/tmp` has none on either
  host; an agent that needs it should be given a `--tmpfs` or a volume.
- **A tmpfs the container mounts itself** is `tmpfs_t` under SELinux,
  which the container may not remount, so the Warden cannot mount it
  noexec and refuses to start, naming it. A tmpfs the runtime mounts
  (`--tmpfs`) is mounted noexec.
- **Rootless Podman needs `--systemd=always`** for sub-agents and confined
  MCP servers.
- **The AppArmor profile bounds what is mounted, not where.** The Warden,
  or a root shell started in the container with the same capabilities,
  may bind any path and make a bind mount read-write. The agent holds no
  capability and cannot.
- **Container detection** knows Docker and Podman (`/.dockerenv`,
  `/run/.containerenv`); elsewhere `varek doctor` and `varek run`'s
  container checks do not run.
- **The image is x86_64 only** in this release, and is published to the
  GitHub Container Registry only (Red Hat's registry with its
  certification later).
- From v1.31.0: the agent's calls to a stdio MCP server are not decided.
  From v1.29.0: a dry run is not a sandbox. From v1.28.1: the chain is
  recorded, not enforced. From v1.28.0: a server that echoes a credential
  back. From v1.27.1: code written into memory is not covered; Linux only.

## Upgrading

1. On a host, nothing changes: rebuild (`make all`) and reinstall (`make
   install`).
2. In a container: `docker pull ghcr.io/kwdoug63/varek:1.32` and check it
   with `cosign verify` (`packaging/container/README.md`), or build it
   (`docker build -f packaging/container/Containerfile -t varek .`).
3. On an AppArmor host, load `varek-container` once and run with
   `--security-opt apparmor=varek-container`; on an SELinux host, load
   `varek_container.cil` once and run with `--security-opt
   label=type:container_init_t`; rootless Podman adds `--systemd=always`.
4. Run with the documented settings, and `varek doctor` in the container
   to check them.
5. Build your agent's image `FROM` it and name its command.
