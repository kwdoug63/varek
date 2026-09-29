<!--
README section for the v1.5 release. Drop under existing examples / use-cases.
Repo layout assumed:
  examples/agent_media_sandbox/
    agent.py
    setup.sh
-->

## Sandboxing an Agent That Downloads Media

When an agent fetches external content — images, audio, video, documents — the download step is one of the largest attack surfaces in the stack. A poisoned URL, a MIME-confusion payload, or a misrouted write can compromise the host even when the agent's reasoning is sound.

VAREK contains the fetch at the **seccomp-unotify** boundary. The agent runs unmodified as a child process; the privileged Warden supervisor traps `openat`, `connect`, and `execve` (and the lookups and sends that go with them), decides each one against a text policy file, and either denies it with `EACCES` or carries it out itself: for `openat` it resolves the path and hands over that descriptor, closing the path-traversal window; for `connect` (from v1.21) it dials the destination it decided on and hands over the connected socket, so a second thread cannot change the address after the check. `execve` other than the agent's own launch is refused whatever the policy says, since letting it continue in the kernel would race on its path. The agent's source imports nothing from VAREK. The sandbox is the wrapping invocation.

The same policy file holds whether the agent is built on Hermes Agent, LangChain, LlamaIndex, the OpenAI Agents SDK, or a hand-rolled loop. LLM choice is independent: a Qwen3-class model or a free-tier Gemini key works the same as a frontier model.

### Three constraint dimensions

A media-sink policy is the intersection of three orthogonal constraints:

| Dimension | Mechanism | Failure mode |
|---|---|---|
| **Network egress** | `allow host <ip>:<port>` rules | Connect to non-allowlisted address → `EACCES` at `connect()`, JSON pathology record |
| **Filesystem writes** | `allow path /tmp/agent-example/` rule, default-deny | Write outside sink → `EACCES` at `openat()` |
| **MIME-type guard** | App-level check in the agent | Wrong content-type → agent closes fd, raises |

Decisions outside the allowlist resolve to **UNKNOWN**, which Warden suppresses to **DENY** per the symmetric-suppression invariant — fail-closed by construction. The first two are enforced below the Python layer; the third is application-level.

### Run it

The example ships with a `setup.sh` that resolves your Python's actual `sys.path` and the origin host's IP, then writes a complete policy file to `/tmp/agent-example/policy.txt`. No paths to substitute, no IP to pin by hand:

```sh
cd examples/agent_media_sandbox/
./setup.sh
```

The default origin is **httpbin.org**, a public HTTP testing service whose `/image/jpeg` endpoint returns a real JPEG directly (no redirect chain to chase). This exercises the agent's MIME-type guard on a real code path. Override with `ORIGIN_HOST` for any other origin:

```sh
ORIGIN_HOST=images.unsplash.com ./setup.sh
```

Then run the agent under Warden using the command `setup.sh` prints. *(The
fetch works from Warden v1.21, which dials each allowed connect and hands the
agent the socket. Through v1.20.0 every connect was refused whatever the
policy said, so this example's fetch failed; correction, v1.21.0.)*

```sh
sudo ./varek/v1_4/warden \
    /tmp/agent-example/policy.txt \
    -- python3 /tmp/agent-example/agent.py \
       https://httpbin.org/image/jpeg
```

### What a denied call looks like

If the agent — or anything operating through it — attempts to fetch from a non-allowlisted address, the `connect()` call fails before any bytes leave the host. Warden emits a JSON pathology record to stderr:

```json
{"report_id":"pr-1747100000.000000000-42",
 "run":"…", "seq":42,
 "agent_pid":12345,
 "action":"net.connect",
 "target":"203.0.113.99:443",
 "resolved":"203.0.113.99:443",
 "decision_raw":"UNKNOWN",
 "decision_final":"DENY",
 "rule":"default_deny_unknown",
 "policy_line":0,
 "sock":"tcp",
 "dial_us":0,
 "kernel_verdict":"EACCES",
 "errno":13,
 "latency_us":71,
 "timestamp_ns":1747100000000000000}
```

The agent's reasoning never proceeded on tampered input, because the input never arrived.

### Iterating the policy

First runs usually surface one or two paths the agent touches that `setup.sh` didn't predict — a config file under `/etc/`, a cache directory under `$HOME`, a font for a media library. Each denial emits a pathology record naming the exact target. Add an `allow path` rule for it and re-run. The policy converges quickly because the calls the Warden decides are few (file opens and lookups, connects, launches).

### Framework drop-in

Because enforcement happens at the syscall boundary, the agent framework lives **outside** the sandbox. Register `download_media` as a tool with Hermes Agent, LangChain, or whatever else exactly as you would without VAREK; the difference is the entire agent process is launched under Warden. No framework-specific adapter is required.

### DNS caveat

Warden matches `connect()` calls against resolved IPs. `setup.sh` handles this by resolving the origin once at setup time and pinning the IP in the policy, plus allowing the system DNS resolver (`127.0.0.53:53` on systemd-resolved hosts) so the agent's own `getaddrinfo` succeeds at runtime. Allowing the resolver also lets the agent send whatever it likes to it inside DNS queries; host names without agent DNS are the planned v1.21 stage 2 ([design](../../docs/security/v1.21-stage2-host-names.md)).

For higher-assurance setups, pre-resolve in code and drop the DNS-resolver allow rule entirely. The agent then connects only to a pinned IP and the resolver path is dead.
