# Plan adapters (v1.35)

`varek plan generate --from FRAMEWORK PROJECT` writes an agent's plan from
what its framework already says of it: its tools, its MCP servers, its
sub-agents, the hosts and files it is configured with. The design and its
decisions are in `docs/security/v1.35-frameworks.md` (D1 to D11).

```sh
sudo varek plan generate -o agent.plan --from agentcore ./my-project
sudo varek plan generate -o agent.plan --policy agent.policy --from agentcore ./my-project \
    --runtime my_agent --model-host bedrock-runtime.us-east-1.amazonaws.com:443
sudo varek run --plan agent.plan --hold-to-plan -- python3 main.py
```

Options after `PROJECT` go to the adapter. With `--policy`, the plan is also
decided under that policy as `varek run --plan` would decide it, each step
with its reason (`varek policy check --plan` does the same for a plan file).

## What an adapter is

One program per framework, `adapters/NAME.py`, MIT-licensed, Python's
standard library only:

- **Input:** the project's directory, and options of its own. It reads the
  framework's files as data where they say enough; where the framework
  describes an agent only in code, it imports that code (step 6's
  adapters), which is why it runs confined.
- **Output:** a plan in the plan format (`v1_6/plan_parser.h`), `plan 1.35`
  first, on standard output; anything it could not read or did not write
  on standard error. Exit 0 with a plan, 1 without one, 2 on usage.
- **Confinement (D5):** `varek plan generate` runs it under the Warden as
  the user who ran sudo, with the system and the project read-only, the
  credential stores refused, no host (so no network) and no launch after
  its own (`python3 -I -S`). An adapter that reads data only may be run
  without the Warden (`--no-confine`, no root needed); one that imports the
  agent's code may not.
- **What it writes is a description, not a grant.** A plan can only narrow
  what the policy allows: each step is decided by the policy when the run
  starts, and a held run is refused what no step covers.

## agentcore: Amazon Bedrock AgentCore

`agentcore.py` reads an AgentCore CLI project (CLI 0.31): `agentcore/agentcore.json`,
`agentcore/aws-targets.json` (the target's region) and
`agentcore/.cli/deployed-state.json` (each gateway's URL), and the files a
gateway target names. For one runtime (`--runtime`, if there are several):

| The project gives the runtime | The plan's steps |
| --- | --- |
| a gateway (MCP) | `mcp_call` its URL: `initialize`, `notifications/initialized`, `tools/list`, and `tools/call` of each tool by the gateway's name for it, `TARGET___TOOL`, from the target's tool definitions, a Lambda target's tool schema file or an inline OpenAPI schema (JSON) |
| a target whose tools the gateway lists from the live server (an MCP server, a Smithy model, an API Gateway stage, a connector) | one `tools/call` step naming no tool, which covers every tool of that gateway (the plan says so) |
| semantic search on the gateway | `tools/call` of `x_amz_bedrock_agentcore_search` |
| an MCP server hosted on AgentCore Runtime and bound to it | its `mcp_call` steps, at its deployed endpoint |
| credentials, memory, a browser, a code interpreter, another runtime | `net_connect` AgentCore's data plane in the region (Identity's credentials are released to the agent by AWS from there, not by the Warden: they are comments, not `credential` steps) |
| OpenTelemetry (on by default) | `net_connect` X-Ray and CloudWatch Logs in the region |
| session storage, EFS, S3 Files, a capacity provider's volume | `file_open` the mount, read and written |
| its language runtime | `file_open` the system read-only, `/proc/self/`, `/dev/null`, `/dev/urandom`, `/tmp/`, and its code (the Dockerfile's `WORKDIR`, or `/var/task` for CodeZip; `--app-dir`), unless `--no-runtime` |

Not in the project's files, so not in the plan: the agent's own tools and
its model provider, which are its framework's (Strands, LangGraph, the
OpenAI Agents SDK); `--model-host HOST:PORT` names the model's host, and the
framework's adapter (v1.35 step 6) writes the rest.

## Samples

`samples/agentcore-weather` and `samples/agentcore-travel` are AgentCore
CLI projects, each with a policy. The weather agent's plan is authorized
under `weather.policy`; the travel agent's is refused under `travel.policy`,
since its gateway's hotels target lists its tools from the live server, so
the plan's step for the gateway's tools names none, which the policy (only
`flights___search_*`) does not allow:

```sh
varek plan generate --no-confine --policy samples/agentcore-travel/travel.policy \
    --from agentcore samples/agentcore-travel > /dev/null
```
