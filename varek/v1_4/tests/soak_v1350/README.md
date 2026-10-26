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

`soak_check.py` judges the run when it ends: the turns (each done when the
model's answer came and `word_count`'s note names the turn), the probes
(each refused by its exact target, once per probe turn, during that turn's
probes), the stream's refusals (none other but the MCP client's GET and
DELETE and glibc's nscd, refused in every run), reconnects to the docs
server (a few at most), the server's log, the audit with `--plan`, the OCSF
export, and each process's memory (the last quarter's median at most 16 MB,
or a fifth, above the second quarter's). `DIR/report.txt` holds the verdict.

## Running it

On a Linux host as root (the droplet), from the top of a checkout of this
branch that `nobody` can read, with the Warden built, a Python that has the
OpenAI Agents SDK and that `nobody` can read, then the soak in the
background. Each line runs on the host, as root, from the checkout's top:

```sh
make -C varek/v1_4 all # end
python3 -m venv /var/tmp/varek-fw && /var/tmp/varek-fw/bin/python3 -m pip install -r varek/v1_4/adapters/requirements-frameworks.txt && chmod -R a+rX /var/tmp/varek-fw # end
setsid nohup bash varek/v1_4/tests/soak_v1350/soak.sh --python /var/tmp/varek-fw/bin/python3 --out /var/tmp/varek-soak-v1350 > /var/tmp/varek-soak-v1350.out 2>&1 < /dev/null & # end
```

Progress: `tail -3 /var/tmp/varek-soak-v1350/d/agent.jsonl` (a turn a
minute). At the end: `cat /var/tmp/varek-soak-v1350/report.txt`. A short
trial: add `--hours 0.25 --interval 10`.
