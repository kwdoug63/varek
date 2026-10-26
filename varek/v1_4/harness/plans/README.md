# The plan corpus (v1.35 step 8)

Plans the v1.35 adapters generate from public example agents, decided by
the Warden's plan gate, to measure v1.11's condition
(`docs/roadmap/v1.36-v1.37.md`): of plans generated from at least 20 agents
across at least three frameworks, the share refused only because of steps
UNKNOWN on the collection stratum, that is, plans v1.11 could let start.
Counted per plan. v1.11 is built at 10% or more.

## What is in it

`manifest.json` names each agent: its framework, its repository and
commit (pinned), its path, and the adapter's options. The agents are the
frameworks' own published examples, taken by a stated rule, not chosen:

| Framework | Source | Rule |
| --- | --- | --- |
| Amazon Bedrock AgentCore | `awslabs/amazon-bedrock-agentcore-samples` | every AgentCore CLI project with a runtime (`agentcore/agentcore.json`), once each; a gateway not deployed is given a stand-in URL (`--gateway-url`), its tools read from the project's tool schemas |
| IBM watsonx Orchestrate | `IBM/ibm-watsonx-orchestrate-adk` | one agent per example project (the first by name), and the one example agent with an MCP toolkit (`experimental/.../customer_care_style`) |
| LangGraph | `langchain-ai/{react-agent, memory-agent, retrieval-agent-template, data-enrichment, new-langgraph-project}` | every graph `langgraph.json` names |
| OpenAI Agents SDK | `openai/openai-agents-python`, `examples/` | every module-level `Agent` no other agent's handoffs or tools reach (a root); and each MCP example whose agent is built inside `main()`, through a shim |
| Claude Agent SDK | `anthropics/claude-agent-sdk-python` | the repository's own `.claude/` settings; each example's options in code, given with `--allow` |

A **shim** (`shims/openai/`) is the example's own server and agent, as its
`main()` builds them, at module level, so the adapter can read them; the
arguments that make the plan are the example's (where the example picks a
free port at run time, the shim names 8000).

## How each plan is decided

Under the policy an operator would write who names everything the plan
names, the **named** rule, the same for every agent (`tools/plan_corpus.py`):
each `file_open`, `net_connect` and `process_exec` step allowed as it is
named; each MCP call allowed by its server's host and the method and tool
it names; a sub-agent's program allowed as that sub-agent where its step
names the program (`exec=`; a stdio server started by `npx` or `uvx` has
none, so it gets no rule). It never grants a server whole: a `tools/call`
step that names no tool gets no rule. And an `mcp` rule names its server by
host name (v1.31), so a server at an address (`127.0.0.1`) gets none. So a
plan is refused for what the rule does not write: a server's tools as a
whole, a server at an address, a sub-agent with no program named.

Each step the gate does not find SATISFIED is put on a stratum
(`docs/verification/corpus-v1-schema.md`) by what the plan's own step names
(its kind, `method=` and `name=`; the decision's object would not do, as
for a server at an address it is the URL alone):

| Step | Stratum |
| --- | --- |
| `file_open` | string-path |
| `net_connect`; `mcp_call` naming a tool, or another method | string-host |
| `mcp_call` `tools/call` naming no tool | unlisted-tools: every tool of the server, which the plan does not list |
| `process_exec`, `subagent` | launch |
| `credential` | credential |
| (refused for its certificate) | certificate |

None is on the collection stratum (an element of a payload crossing a
boundary): a plan 1.35 step names one object, or a server's tools as a set
the plan does not list, which a policy granting the server, or an adapter
listing its tools, allows without v1.11. v1.11's fragment decides
predicates over the elements of a payload given at decision time, at most N
long (`docs/verification/bounded-sequence-fragment.md`, section 2), and a
plan step gives it none. **So with plan 1.35 the plan gate cannot meet
v1.11's condition, whatever the corpus**: the two columns that would show
it are 0 by construction, not by measurement. The measurement says what
the refusals are instead, and that the figure would need a plan format
whose steps carry a payload's elements (or v1.11's need is shown elsewhere:
data-flow payloads, the v1.10 corpus).

## Reproducing it

On a host with the Warden built, as root, from `varek/v1_4` in a checkout
`nobody` can read, with a Python that has the frameworks (the venv
`adapters/requirements-frameworks.txt` builds at `/var/tmp/varek-fw`, plus
each LangGraph template's own dependencies and the template installed) and
that `nobody` can read:

```sh
python3 tools/plan_corpus.py fetch --manifest harness/plans/manifest.json --src /var/tmp/corpus-src
python3 tools/plan_corpus.py run --manifest harness/plans/manifest.json --src /var/tmp/corpus-src \
    --out /var/tmp/varek-plan-corpus --python /var/tmp/varek-fw/bin/python3 --varek-home "$PWD"
```

The data adapters (AgentCore, watsonx, Claude) run with `--no-confine`; the
code adapters (LangGraph, the OpenAI Agents SDK) under the Warden in that
Python, as `varek plan generate` runs them. `results/` holds this run's
`summary.md`, `results.json`, and each plan, policy and decision.

## Provenance

The agents are published examples, not customer agents; the policies are
written by the rule above, by SAI, not by the agents' operators. What is
measured is what the adapters write from the frameworks' own examples and
what a policy naming each object refuses of it. A larger corpus can change
those figures, not v1.11's column: with plan 1.35 it is 0 by construction
(above), so the condition is not yet judged on the deployed agents it names.
