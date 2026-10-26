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

| `--from` | Framework | Reads | Runs |
| --- | --- | --- | --- |
| `agentcore` | Amazon Bedrock AgentCore | the AgentCore CLI project's `agentcore/` | as data |
| `watsonx` | IBM watsonx Orchestrate | the ADK's agent and toolkit specs | as data |
| `langgraph` | LangGraph | the graph `langgraph.json` names | imports it, in `--python` |
| `openai-agents` | the OpenAI Agents SDK | the Agent `--entry FILE.py:ATTR` names | imports it, in `--python` |
| `claude` | the Claude Agent SDK, Claude Code | `.claude/settings.json`, `.mcp.json`, `.claude/agents/` | as data |

`varek plan merge A.plan B.plan -o agent.plan` writes one plan from several
(an AgentCore runtime's and its framework's): every step of each, a step the
same in two written once, a label taken twice renamed.

Options after `PROJECT` go to the adapter. With `--policy`, the plan is also
decided under that policy as `varek run --plan` would decide it, each step
with its reason (`varek policy check --plan` does the same for a plan file).

## What an adapter is

One program per framework in `adapters/` (its file named so it hides no
framework's package), MIT-licensed, with what they share in
`varek_plan.py`, which each loads by its path:

- **Input:** the project's directory, and options of its own. It reads the
  framework's files as data where they say enough (Python's standard
  library only; watsonx's YAML with the system's PyYAML); where the
  framework describes an agent only in code (LangGraph, the OpenAI Agents
  SDK), it imports that code, in the agent's own Python (`--python`, its
  virtual environment's `python3`), which is why it runs confined. Each
  provider's key is set to a placeholder: the clients are built, none is
  called.
- **Output:** a plan in the plan format (`v1_6/plan_parser.h`), `plan 1.35`
  first, on standard output; anything it could not read or did not write
  on standard error. Exit 0 with a plan, 1 without one, 2 on usage.
- **Confinement (D5):** `varek plan generate` runs it under the Warden as
  the user who ran sudo, with the system and the project read-only, the
  credential stores refused, no host (so no network) and no launch after
  its own (`python3 -I -B -S`; `-I -B` for watsonx's and the code
  adapters, with the agent's virtual environment read-only). An adapter that reads data only may be run
  without the Warden (`--no-confine`, no root needed); one that imports the
  agent's code may not.
- **The runtime's reads.** Every adapter writes the steps a language
  runtime needs as it starts (the system read-only, `/proc/self/`, the
  machine's CPU and control-group files, `/tmp/`, the agent's code), unless
  `--no-runtime`; a code adapter also names the agent's own Python
  environment (its virtual environment, read-only), since it runs in it. A
  policy that holds the run to the plan must allow those too: the samples'
  policies do for the system, and `tests/test_v1350.sh` adds the
  environment's directory to a copy of each, as an operator would.
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
| its language runtime | `file_open` the system read-only, `/proc/self/`, `/dev/null`, `/dev/urandom`, `/tmp/`, what a runtime reads of the machine as it loads (`/proc/stat`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/sys/crypto/fips_enabled`, `/sys/devices/system/cpu/`, `/sys/fs/cgroup/`), and its code (the Dockerfile's `WORKDIR`, or `/var/task` for CodeZip; `--app-dir`), unless `--no-runtime` |

Not in the project's files, so not in the plan: the agent's own tools and
its model provider, which are its framework's (Strands, LangGraph, the
OpenAI Agents SDK); `--model-host HOST:PORT` names the model's host, and the
framework's adapter (v1.35 step 6) writes the rest.

## watsonx: IBM watsonx Orchestrate

`watsonx.py` reads an Agent Development Kit project (ADK 2.19) as data: the
agent's spec (`kind: native`, `--agent` if there are several) and the
toolkits it names (`kind: mcp`), anywhere in the project.

| The project gives the agent | The plan's steps |
| --- | --- |
| a toolkit over HTTP (`url`) | `mcp_call` its opening methods, and `tools/call` of each tool in `tools`; `tools: ["*"]` or none listed: one step naming no tool, said so |
| a toolkit the platform launches (`command`) | a `subagent` step naming the toolkit |
| `llm: watsonx/...` | `net_connect` watsonx.ai in `--watsonx-region` (default `us-south`); another provider's host, or `--model-host` |
| collaborators in the project | their toolkits and models, each said so |
| tools the platform runs (Python, OpenAPI, flows) | comments |

A native agent runs on watsonx Orchestrate: its plan can be checked against
a policy anywhere; a run is held to it only where the agent runs beside the
Warden (the Developer Edition, or an agent served by the team).

## langgraph: LangGraph

`langgraph_plan.py` imports the graph `langgraph.json` names (`--graph` if
there are several; a factory is called), or `--entry FILE.py:ATTR`, and
walks it: its nodes, the models and tools bound to them, its subgraphs.

| The graph has | The plan's steps |
| --- | --- |
| a chat model | `net_connect` its host: the client's base URL, or the provider's API (`--region` for Bedrock) |
| a `MultiServerMCPClient` connection over HTTP | `mcp_call` its opening methods and one `tools/call` step naming no tool (the client lists the server's tools when it connects), said so |
| one over stdio | a `subagent` step for its program |
| a file tool (`root_dir`), a search tool | `file_open` the directory, `net_connect` the search API |
| a tool of its own | a comment: what it opens and dials is decided by the policy (`--host`, `--file` name it) |

A loop's steps are written once: a plan names what may happen, not how
often.

## openai-agents: the OpenAI Agents SDK

`openai_agents.py` imports the Agent `--entry FILE.py:ATTR` names (or a
function returning it) and every agent its handoffs reach. A handoff runs
in the same process, so its agent's tools and servers are the run's steps.

| The agents have | The plan's steps |
| --- | --- |
| a model | `net_connect` its host: OpenAI's API for a model named by a string, the client's base URL, a LiteLLM model's provider |
| tracing (on by default) | `net_connect` OpenAI's API, unless `--no-traces` |
| `MCPServerStreamableHttp`, `MCPServerSse` | `mcp_call` its opening methods, and `tools/call` of each tool its static filter allows (`allowed_tool_names`); no filter, a blocked list only or a callable filter: one step naming no tool, said so |
| `MCPServerStdio` | a `subagent` step for its program |
| hosted tools (web search, file search, code interpreter, hosted MCP) | comments: they run at OpenAI, in the model's request |
| function tools, shell and computer tools | comments: decided by the policy as their calls (`--host`, `--file` name them) |

## claude: the Claude Agent SDK and Claude Code

`claude_agent.py` reads the project's settings the SDK loads with
`setting_sources=["project"]`, as data. The options an agent passes in code
(`allowed_tools`, `mcp_servers`) are not data: `--allow RULE` names them.

| The settings give | The plan's steps |
| --- | --- |
| `Read(PATH)`, `Grep(PATH)`, `Glob(PATH)` | `file_open` the directory before the first wildcard, read (a relative path where the agent runs: `--app-dir`) |
| `Edit(PATH)`, `Write(PATH)` | `file_open` it, read and written |
| `WebFetch(domain:HOST)` | `net_connect` the host |
| `Bash(PROGRAM ...)` | `process_exec` the program, as its launch would be decided |
| `mcp__SERVER__TOOL` | `tools/call` of the tool on the server `.mcp.json` names (as `enabledMcpjsonServers` filters it); `mcp__SERVER` alone, or none named: one step naming no tool, said so |
| the model (`env`) | `net_connect` Anthropic's API, `ANTHROPIC_BASE_URL`, Bedrock (`CLAUDE_CODE_USE_BEDROCK`) or Vertex AI (`CLAUDE_CODE_USE_VERTEX`) |
| the CLI | `process_exec` the CLI the SDK runs (`--cli`, or `claude` on the PATH), `file_open` its state (`~/.claude/`, `~/.claude.json`, under `--home`), its telemetry unless `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` |
| `.claude/agents/*.md` | comments: a sub-agent runs in the agent's process, with the agent's steps |

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

(run from `adapters/`; deciding the plan resolves the AWS host names the
policy names, so the host needs DNS, as `make test-v1350` does for these
checks.)

The others, one authorized and one refused under each sample's policy:

| Sample | Authorized | Refused, and why |
| --- | --- | --- |
| `watsonx-banking` (`banking.policy`) | `--agent banking_agent` | `--agent payments_agent`: its toolkit allows every tool (`tools: ["*"]`) |
| `langgraph-research` (`research.policy`) | `--graph researcher` | `--graph publisher`: it launches an MCP server over stdio, and no rule launches that sub-agent |
| `openai-support` (`support.policy`) | `--entry support.py:triage` | `--entry support.py:ops`: its MCP server has no tool filter |
| `claude-reviewer` (`reviewer.policy`), `claude-deployer` (`deployer.policy`) | the reviewer | the deployer: `mcp__deploy` allows the server's every tool |

```sh
sudo varek plan generate --python /srv/agent/venv/bin/python3 --policy samples/langgraph-research/research.policy \
    --from langgraph samples/langgraph-research --graph researcher --app-dir /srv/research > /dev/null
```

The framework versions the adapters were tested with are pinned in
`requirements-frameworks.txt`; `tests/test_v1350.sh` runs the code adapters
where `VAREK_FW_PYTHON` names a Python that has them, which the user
`nobody` can read.

`harness/plans/` is the plan corpus of v1.35 step 8: the adapters run on
the frameworks' own published examples (131 agents, five frameworks, at
pinned commits), each plan decided under a policy that names everything
the plan names (`tools/plan_corpus.py`); its README says how, and
`results/` what came of it.
