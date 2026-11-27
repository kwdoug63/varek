# VAREK for Palantir Ontology MCP

v1.43 (`docs/security/v1.43-palantir-ontology-mcp.md`). Palantir's
Ontology MCP (OMCP) exposes an application's object types, action types and
query functions as MCP tools, so an outside AI agent can read and write
ontology data. VAREK sits between the agent and that server and decides
each tool call before it runs: reads the server marks read-only are
allowed, actions that write are held for a person, and a tool the policy
does not name is refused. The agent never holds the application's token.

**Status (November 27, 2026).** Built and tested against a stand-in OMCP
server (`tests/v1430_omcp_server.py`, `make test-v1430` and
`tests/test_palantir_integration.py`). **Not yet run against a live
Palantir enrollment**: the tool names, their annotations, the server URL's
form and the token's form below are a model, from Palantir's documentation,
until step 1 of the plan measures one. VAREK is not affiliated with
Palantir Technologies Inc.

What is here:

| File | What it is |
|---|---|
| `omcp_measure.py` | Read-only measurement of an enrollment: the token's form, discovery, `tools/list` |
| `omcp_token.py` | The token refresher: client credentials grant, written to a VAREK file store |
| `varek-omcp-token.service` | A systemd unit that keeps the token current |
| `omcp.policy.example` | A policy for the stand-in, as `varek mcp tools --gateway` writes it |
| `clients/vscode-mcp.json` | VS Code's MCP configuration, pointed at the gateway |
| `clients/claude_agent_sdk.py` | A Claude Agent SDK agent, pointed at the gateway |
| `clients/omcp_agent.py` | A headless MCP client for scripts |
| `demo_d5.py` | The recorded run's agent: a read, and writes approved, refused and timed out |

Commands below run **on the Linux host that runs VAREK**, as root where
they say `sudo`. Installed, these files are in `/opt/varek/integrations/palantir/`.

## 1. Turn on Ontology MCP for an application

In the enrollment's **Developer Console**, open the application whose
ontology the agent will use and turn on its **MCP** page. The server's URL
is shown there and in **MCP Hub → Ontology MCP**. The application needs a
client that can use the **client credentials grant** (a service user):
note its client ID and secret. Give that service user only the object
types and actions the agent needs; VAREK decides calls, it does not widen
or narrow what the token itself may do.

Use test data only (plan, D8): a small ontology made for the purpose, such
as Palantir's OSDK to-do example. No CUI, government data or
export-controlled data.

## 2. Measure it

```
FOUNDRY_HOST=NAME.palantirfoundry.com OMCP_URL='THE MCP URL' OMCP_CLIENT_ID=ID \
  python3 /opt/varek/integrations/palantir/omcp_measure.py # end
```

It asks for the secret (not echoed), fetches a token, and lists the tools
without calling any. Its report says whether the token is a JWT whose `aud`
names the server's URL (then the policy checks the audience) or opaque
(then the policy says `--opaque`), and how long it lives.

## 3. Keep a token in a file store

The secret goes in a file only root can read; the token goes in a file
store VAREK reads (root's, mode 600, in directories only root can write):

```
sudo install -d -m 0700 /etc/varek/palantir
sudo sh -c 'umask 077; cat > /etc/varek/palantir/client_secret'    # paste the secret, Enter, Ctrl-D
sudo python3 /opt/varek/integrations/palantir/omcp_token.py --foundry-host NAME.palantirfoundry.com \
  --client-id ID --secret-file /etc/varek/palantir/client_secret --out /etc/varek/palantir/omcp.token --once # end
```

It prints the token's form and life, never the token. To keep it current,
put `FOUNDRY_HOST=...` and `OMCP_CLIENT_ID=...` in
`/etc/varek/palantir/omcp-token.env` (mode 600), then:

```
sudo cp /opt/varek/integrations/palantir/varek-omcp-token.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now varek-omcp-token # end
```

It fetches a new token at half the old one's life and replaces the file in
one step. A run reads the token when it starts, so a run that outlives the
token sees the server refuse its later calls; start long runs fresh.

## 4. Write the policy from the server's own tool list

```
sudo varek mcp tools 'THE MCP URL' --token-file /etc/varek/palantir/omcp.token --gateway \
  --credential omcp --credential-from file:/etc/varek/palantir/omcp.token \
  --approvers ontology-approvers -o /etc/varek/omcp.policy # end
```

Add `--opaque` if step 2 found the token opaque. The file has one exact
rule per tool: a tool the server marks read-only (`readOnlyHint`, not
`destructiveHint`) is allowed; every other tool, an unannotated one
included, is held for a member of `ontology-approvers` (`step_up ...
mode=hold`); a tool whose name no rule can name exactly gets no rule and is
refused. An annotation is the server's claim about itself, so it can send a
tool to a person, never past one. **Read the file before using it.**

These are the MCP rules only. Add the rules the agent itself needs (its
programs and files), then check the whole policy:

```
sudo varek policy check /etc/varek/omcp.policy # end
```

`omcp.policy.example` is this command's output for the stand-in, so you
can see the shape before you have an enrollment.

Gateway mode means no TLS interception: the agent's MCP client talks plain
HTTP on port 80 to `http://HOST/PATH`, VAREK decides each call against
`https://HOST/PATH`, and the proxy itself speaks TLS to the server,
verified against the host's trust store. No certificate is minted and the
agent trusts no extra CA. Any other way to reach that host (TLS, CONNECT,
another port) is refused.

## 5. Point the agent's MCP client at the gateway

Use the server's URL with `http://` in place of `https://`, and send
`$VAREK_CRED_OMCP` as the bearer token: under VAREK it holds only a
placeholder, and the proxy puts the real token into the calls the policy
allows.

- **VS Code:** `clients/vscode-mcp.json` as the workspace's `.vscode/mcp.json`.
- **Claude Agent SDK:** `clients/claude_agent_sdk.py`.
- **A script:** `clients/omcp_agent.py list` and `clients/omcp_agent.py call NAME '{"k": "v"}'`,
  with `OMCP_GATEWAY_URL` set.

## 6. Run, and answer held calls

```
sudo varek run --policy /etc/varek/omcp.policy --env OMCP_GATEWAY_URL -- python3 agent.py # end
```

A held action waits for an approver, in another terminal:

```
varek pending                        # the held calls you may answer
varek approve RUN ID --reason '...'  # allow it (a v1.42 grant: this tool, this many times, until this time)
varek deny RUN ID --reason '...'     # refuse it
```

The held rule names the token too (`credential=omcp`): it goes into the
call only once a person approves it, never while it is held or after a
refusal. Unanswered, it is refused when the rule's `timeout=` passes. Afterwards,
`varek refusals` lists what was refused and why, and the run's verdict
stream audits as every run's does.

To show all of it in one run (the plan's D5, for a recording):

```
sudo varek run --policy /etc/varek/omcp.policy --env OMCP_GATEWAY_URL -- \
  python3 /opt/varek/integrations/palantir/demo_d5.py # end
```

It makes five calls in turn: a read (allowed), a create (approve it), a
status change (deny it), a delete (leave it until its timeout) and a tool
no rule names (refused at once), printing each outcome and how long it
took. `--tools` names an enrollment's own five tools.

## 7. Notice when the server's tools change

```
sudo varek mcp tools 'THE MCP URL' --token-file /etc/varek/palantir/omcp.token --check /etc/varek/omcp.policy # end
```

It exits 1 and names the tools added, removed and changed when the
server's list differs from the one the policy was written from. A new tool
has no rule, so it is refused until the policy is rewritten and reviewed.

## Known limits

- **Arguments are not decided** (plan, D6): a rule names the method and
  the tool, not which object an action changes. The approver sees the tool;
  `--intent` (v1.42) gives them the user's request.
- **A Host header with a port** (`HOST:80`) is refused; MCP clients send
  the name alone for the default port.
- **The Defense build** refuses a policy with a gateway until the plan's
  step 7.
