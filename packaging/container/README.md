# VAREK in a container (v1.32, in progress)

The image runs the Warden as the container's entrypoint; the agent is its
child, in PID, network and mount namespaces the Warden makes inside the
container, exactly as on a host. The design and its decisions are in
`docs/security/v1.32-containers.md`.

> **In progress.** The settings below are measured on real hosts: every
> suite passes under them with Docker on Ubuntu 24.04 (AppArmor, cgroup
> v2), and rootful and rootless Podman on RHEL 9.8 (SELinux enforcing,
> cgroup v2). In a
> container the kernel gives no process events (RHEL 9, Ubuntu 24.04): the
> Warden then tells a sub-agent's launch by the image it runs and, for one
> of the image its launcher runs (a Python agent launching a Python MCP
> server), by its memory layout.

## Get the image

From v1.32.0, each release is published to the GitHub Container Registry,
signed with cosign (keyless: the release workflow's own GitHub identity,
recorded in Sigstore's public log) and with a CycloneDX software bill of
materials attached as a signed attestation
(`.github/workflows/container-release.yml`):

```
docker pull ghcr.io/kwdoug63/varek:1.32.0
```

(Until the first release's package is made public, a pull needs a GitHub
login.) Check that it is the one the release workflow built for that
version's tag, by its exact identity:

```
cosign verify ghcr.io/kwdoug63/varek:1.32.0 \
  --certificate-identity https://github.com/kwdoug63/varek/.github/workflows/container-release.yml@refs/tags/v1.32.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

and its bill of materials, with `cosign verify-attestation --type cyclonedx`
and the same two options. `cosign verify` prints the digest it checked
(`"docker-manifest-digest"`); run that digest
(`ghcr.io/kwdoug63/varek@sha256:...`), not the tag, which can be moved.
`:1.32` and `:latest` follow the newest release; verify the version they
point to as above.

## Build

Or build it yourself, from the repository's root:

```
docker build -f packaging/container/Containerfile -t varek .
```

`podman build` takes the same arguments.

## Run

Never `--privileged`. Drop every capability, then add only these:

```
docker run --rm \
  --cap-drop ALL \
  --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add SETPCAP \
  --cap-add SETUID --cap-add SETGID --cap-add DAC_OVERRIDE --cap-add KILL \
  --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add CHOWN \
  --cgroupns=private \
  -v "$PWD":/work -v varek-log:/var/log/varek \
  varek python3 agent.py
```

| Capability | Why the Warden needs it |
|---|---|
| SYS_ADMIN | the agent's PID, network and mount namespaces; the writable directories mounted noexec |
| SYS_PTRACE | taking the agent's listener and sockets (`pidfd_getfd`) and reading paths from its memory |
| SETPCAP | emptying the agent's capability bounding set at its launch |
| SETUID, SETGID | dropping the agent and the helpers to their own users; opening files as the agent |
| DAC_OVERRIDE | opening, as root, the files the policy lets the agent reach |
| KILL | ending the agent's processes, which run as another user |
| NET_ADMIN | bringing the loopback up in the agent's network namespace, for the DNS stub |
| NET_BIND_SERVICE | binding the stub on port 53 there |
| CHOWN | `varek run` giving the agent its temporary directory |

The agent itself holds none of them: the Warden empties its bounding set
and drops it to its own user before its filter is installed (unless run
`--run-as root`, which the Warden warns of). The runtime's default
seccomp profile stays on.

### On a host with AppArmor (Ubuntu, Debian, SUSE)

Docker's `docker-default` profile denies every mount, and the Warden
mounts the agent's writable directories noexec (policies from 1.27), so
under it the Warden refuses to start ("cannot make the mount namespace
private (Permission denied)"). Load VAREK's profile, `apparmor/varek-container`,
once, as root:

```
install -m 644 packaging/container/apparmor/varek-container /etc/apparmor.d/varek-container
apparmor_parser -r -W /etc/apparmor.d/varek-container
```

and add `--security-opt apparmor=varek-container` to the run (AppArmor 3.0
or later: Ubuntu 22.04, Debian 12). It is Docker's current
`docker-default` with the Warden's mounts allowed (its own mount namespace
made private, a directory bound, a bind mount's flags changed: noexec, and
the container's cgroup filesystem read-write) and no other; never
`apparmor=unconfined`. AppArmor cannot tie a bind's target to its source,
so a process holding CAP_SYS_ADMIN in the container (the Warden, or a root
shell `docker exec` starts with the same capabilities) may bind any path
and make a bind mount read-write, a read-only volume's included; the agent
holds no capability and cannot.

### On a host with SELinux (RHEL, Fedora)

The container's own type, `container_t`, may not make control groups, which
a policy with sub-agents or confined MCP servers needs. Run it as
`container_init_t`, the distribution's type for containers that manage
their control groups (systemd in a container: beyond `container_t`, it may
manage, mount on and unmount the cgroup filesystem, mount on sysfs and
`/proc`, and its network is unconfined), and load VAREK's module,
`selinux/varek_container.cil` (four rules: that type may also remount the
cgroup filesystem, and mount on the container's character devices for the
noexec mount of `/dev/null`; two more for rootless, below), once, as root:

```
semodule -i packaging/container/selinux/varek_container.cil
```

and add `--security-opt label=type:container_init_t` to the run. Other
containers keep `container_t`. Never `label=disable`.

### Rootless Podman

As a user, with the same settings, the SELinux type above, and
`--systemd=always`:

```
podman run --rm <the settings above> --security-opt label=type:container_init_t \
  --systemd=always -v "$PWD":/work varek python3 agent.py
```

In the user namespace a rootless container runs in, the kernel keeps the
cgroup filesystem read-only, so the Warden cannot remount it; Podman's
systemd mode mounts the container's own groups read-write instead, which
sub-agents and confined MCP servers need (without them, `--systemd=always`
may be left out). Root loads the SELinux module once, as above; its last
two rules are for rootless, where Podman binds the host's `/dev/null` and
`/dev/tty` into the container.

### Sub-agents and confined MCP servers

They need a control group for the run and one for each sub-agent's launch.
Docker and Podman mount the container's cgroup filesystem read-only; with
`--cgroupns=private` (in the command above) the container sees only its own
groups, and the Warden remounts that view read-write in a mount namespace of
its own. Without `--cgroupns=private` it refuses to start and says so.

## Checking a container's settings

`varek doctor` in the container checks each setting above: the
capabilities, the seccomp profile, the AppArmor profile or SELinux type,
the cgroup namespace, and a test of the Warden's own mounts. It names the
flag that supplies any that is missing (`--cap-add SYS_PTRACE`,
`--cgroupns=private`, ...):

```
docker run --rm <the settings above> --entrypoint varek varek doctor
```

## Your agent in the image

Build on the image and name your agent's command (`example/` holds this
Dockerfile with a small agent; CI builds it on each change and runs it
under the settings above):

```
FROM ghcr.io/kwdoug63/varek:1.32.0
RUN microdnf -y install python3-pip && pip3 install --no-cache-dir requests && microdnf clean all
COPY agent.py /work/agent.py
CMD ["python3", "/work/agent.py"]
```

The entrypoint is `varek run --`, so the command runs under the baseline
policy with the profile its name chooses (v1.29). To use your own policy,
mount it and override the entrypoint:

```
docker run ... -v ./policy.txt:/etc/varek/policy.txt:ro \
  --entrypoint varek varek run --policy /etc/varek/policy.txt -- python3 agent.py
```

## Testing in a container

`varek/v1_4/tests/container_sweep.sh` runs the suites inside the image's
`test` stage under these settings, and with `--drop-each` once more per
capability with that one left out, to show each is needed; with
`--apparmor` or `--selinux`, under the profile or module above.
