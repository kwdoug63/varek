# VAREK in a container (v1.32, in progress)

The image runs the Warden as the container's entrypoint; the agent is its
child, in PID, network and mount namespaces the Warden makes inside the
container, exactly as on a host. The design and its decisions are in
`docs/security/v1.32-containers.md`.

> **In progress.** The settings below are those measured so far (Docker
> 29.6, Ubuntu 24.04 image, no AppArmor, cgroup v1). Step 1 of the plan
> settles the final list on real hosts: Docker on Ubuntu (AppArmor,
> cgroup v2) and Podman on RHEL 9 (SELinux, rootful and rootless).

## Build

From the repository's root:

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
| SETPCAP | emptying the agent's capability bounding set before it runs |
| SETUID, SETGID | dropping the agent and the helpers to their own users; opening files as the agent |
| DAC_OVERRIDE | opening, as root, the files the policy lets the agent reach |
| KILL | ending the agent's processes, which run as another user |
| NET_ADMIN | bringing the loopback up in the agent's network namespace, for the DNS stub |
| NET_BIND_SERVICE | binding the stub on port 53 there |
| CHOWN | `varek run` giving the agent its temporary directory |

The agent itself holds none of them: the Warden empties its bounding set
and drops it to its own user before its filter is installed. The
runtime's default seccomp profile stays on.

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

and add `--security-opt apparmor=varek-container` to the run. It is
`docker-default` with the Warden's mounts allowed (its own mount namespace
made private, a directory bound onto itself, that mount remounted noexec,
and the container's cgroup filesystem remounted read-write) and no other;
never `apparmor=unconfined`.

### On a host with SELinux (RHEL, Fedora)

The container's own type, `container_t`, may not make control groups, which
a policy with sub-agents or confined MCP servers needs. Run it as
`container_init_t`, the distribution's type for containers that manage
their control groups, and load VAREK's one-rule module,
`selinux/varek_container.cil` (that type may also remount the cgroup
filesystem), once, as root:

```
semodule -i packaging/container/selinux/varek_container.cil
```

and add `--security-opt label=type:container_init_t` to the run. Other
containers keep `container_t`. Never `label=disable`.

### Sub-agents and confined MCP servers

They need a control group for the run and one for each sub-agent's launch.
Docker and Podman mount the container's cgroup filesystem read-only; with
`--cgroupns=private` (in the command above) the container sees only its own
groups, and the Warden remounts that view read-write in a mount namespace of
its own. Without `--cgroupns=private` it refuses to start and says so.

## Your agent in the image

Build on the image and name your agent's command:

```
FROM varek
RUN microdnf -y install python3-pip && pip3 install --no-cache-dir requests
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
