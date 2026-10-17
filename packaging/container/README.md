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
  --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
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

The agent itself holds none of them: the Warden empties its bounding set
and drops it to its own user before its filter is installed. The
runtime's default seccomp profile stays on.

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
capability with that one left out, to show each is needed.
