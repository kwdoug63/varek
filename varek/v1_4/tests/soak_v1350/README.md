# The v1.35 soak: a framework agent held to its plan

Step 10 of `docs/security/v1.35-frameworks.md`. One run, D, for 24 hours:

- **The agent** (`agent_d.py`) is an OpenAI Agents SDK agent run by the
  SDK's own loop (`Runner`), with its MCP client (Streamable HTTP, a static
  tool filter) and a function tool that reads `docs/` and writes `notes/`.
  Its model is scripted (`ScriptedModel`): each turn it asks for the docs
  server's `search_docs` and `get_doc` and its own `word_count`, then
  answers. Nothing reaches a model provider, so no API key is needed.
- **Its plan** is written by `varek plan generate --from openai-agents`, the
  adapter under the Warden in the agent's own Python.
- **The run** is under a policy that says `require plan`, held to that plan
  (`--hold-to-plan`). The docs server (`mcp_docs.py`) is reached over HTTPS
  through the egress proxy in inspecting mode; DNS is the test server's.
- **Every tenth turn** three probes run, each a call the policy allows and
  the plan does not name: reading `outside/secret.txt`, connecting to
  `status.example.com`, and calling the docs server's `get_secret`, past the
  agent's tool filter, as a compromised agent would. Each must be refused as
  outside the plan, and `get_secret` must never reach the server.

`soak_check.py` judges the run when it ends: the turns, the probes, the
stream's refusals, the server's log, the audit with `--plan`, the OCSF
export, and each process's memory. `DIR/report.txt` holds the verdict.

## Running it

On a Linux host as root (the droplet), from a checkout of this branch with
the Warden built, a Python that has the OpenAI Agents SDK and that `nobody`
can read, then the soak in the background. Each line runs on the host, as
root:

```sh
make -C varek/v1_4 all # end
python3 -m venv /opt/varek-fw && /opt/varek-fw/bin/python3 -m pip install -r varek/v1_4/adapters/requirements-frameworks.txt && chmod -R a+rX /opt/varek-fw # end
setsid nohup varek/v1_4/tests/soak_v1350/soak.sh --python /opt/varek-fw/bin/python3 --out /var/tmp/varek-soak-v1350 > /var/tmp/varek-soak-v1350.out 2>&1 < /dev/null & # end
```

Progress: `tail -3 /var/tmp/varek-soak-v1350/d/agent.jsonl` (a turn a
minute). At the end: `cat /var/tmp/varek-soak-v1350/report.txt`. A short
trial: add `--hours 0.25 --interval 10`.
