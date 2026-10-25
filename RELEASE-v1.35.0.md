# VAREK v1.35.0 — Agent Frameworks: Plans from the Framework

> **Draft** until the 24-hour soak (`varek/v1_4/tests/soak_v1350/`) has
> passed. The release takes its number when it is tagged
> (`docs/roadmap/v1.32-v1.35.md`). v1.35.0 had a review by AI review
> agents, six, each on one part (below). A human or third-party review has
> not been done.

MIT · github.com/kwdoug63/varek

## Summary

Through v1.34 a plan (the steps an agent says it will take) was a file
nothing outside the tests wrote, decided once at the start and never held
to. From v1.35.0 the plan comes from the agent's framework, and a run can be
held to it:

1. **`varek plan generate --from FRAMEWORK PROJECT`** writes an agent's plan
   from what its framework already says of it: Amazon Bedrock AgentCore
   (`agentcore`), IBM watsonx Orchestrate (`watsonx`), LangGraph
   (`langgraph`), the OpenAI Agents SDK (`openai-agents`) and the Claude
   Agent SDK and Claude Code (`claude`). The adapter runs under the Warden
   as the user who ran sudo: the system and the project read-only, the
   credential stores refused, no network, no launch after its own. The
   data adapters (AgentCore, watsonx, Claude) read files; the code adapters
   (LangGraph, the OpenAI SDK) import the agent in its own Python
   (`--python`), each provider's key a placeholder. `--policy` decides the
   plan as the run would, each step with its reason; `varek plan merge`
   makes one plan from several.
2. **Plan 1.35.** A plan whose first line is `plan 1.35` may name MCP calls
   (`mcp_call URL method= name=`), sub-agents (`subagent NAME exec=`) and
   credentials, and any step may be decided under a confined subject
   (`as=`). A plan without `plan 1.35` is read as through v1.34.
3. **A run held to its plan** (`varek run --plan PLAN --hold-to-plan`): a
   call the policy allows that no step covers is refused (`outside_plan`),
   for files, connections, launches, MCP calls and credentials alike. The
   hold can only refuse. A policy line `require plan` refuses a run that is
   not held to a plan.
4. **Plans under the node agent** (Kubernetes): a pod names its plan by
   annotation (`varek.dev/plan`, its SHA-256 in `varek.dev/plan-sha256`) or
   a `VarekPlan`; the admission webhook checks it, the node agent decides
   it in the container's view and holds the container to it, and `require
   plan` is enforced at admission and by the node agent.
5. **The plan's evidence.** The plan gate's refusals are chained records
   (`plan_step`, `plan_gate`, the plan named by its SHA-256); `varek
   refusals` explains a refused plan step by step; `varek policy check
   --plan` decides a plan with no agent run; the audit checks the gate's
   records with each other, the run and its hold (`varek audit --plan`
   checks the plan file); the OCSF export has the gate as an event with its
   refused steps; the CycloneDX evidence names the plan, its verdict and the
   calls refused outside it.

And: a plan's `process_exec` step is decided as the launch would be (through
v1.34 it was always refused), and the Warden builds for arm64 (from the
macOS branch), as AgentCore Runtime's default compute is.

## v1.11's condition, measured

The roadmap (`docs/roadmap/v1.36-v1.37.md`) builds v1.11, the bounded
sequence fragment, if at least 10% of plans generated from at least 20
agents across three frameworks are refused only for steps UNKNOWN on the
collection stratum, that is, plans v1.11 could let start. Measured on 130
plans from 131 of the frameworks' own published examples across all five
frameworks (`varek/v1_4/harness/plans/`), each decided under a policy that
names everything the plan names: 7 refused, none refused only for
collection steps and none that v1.11 could let start. Both are 0 by
construction, not by measurement: no step of plan 1.35 carries a payload's
elements, so with plan 1.35 the plan gate cannot meet the condition at all
(found in review: step 8 had counted a server's unlisted tools as
collection, 2 plans, 1.5%). **v1.11 stays a candidate**, its need to be
shown on data-flow payloads instead; and the corpus is published examples,
not deployed agents. What the refusals did call for: a live-listed MCP
server's tools named when the plan is written (2 plans), MCP servers at an
address (an `mcp` rule names its server by host name), and stdio servers
whose program is on the agent's PATH, not the system's.

## Tested

- **`make test-v1350`** (as root): the plan gate's records, refusals and
  checks, plan 1.35's kinds, the hold, `require plan`, `varek plan
  generate` for each framework on its samples (one plan authorized and one
  refused under each sample's policy), merge, and the audit and exports of
  the plan's records (eleven forgeries of the gate's records each refused).
  133 checks pass with the frameworks installed (`VAREK_FW_PYTHON`); the
  code adapters' checks are not tried without them.
- **`make test-v1340`**: plans under the node agent (section 9); **the
  cluster** (`tests/v1340_apiserver.sh`, `tests/v1340_crio.sh` pod G under
  runc), the Go tests and the chart tests.
- **The regression count**: the host half of the sweep, 33 of 35 suites in
  the full run; `test-v1210`'s three Python `requests` checks fail in the
  test container as before v1.35, and `test-v1250`, which failed once under
  the sweep's load, waits for its test servers now and passes.
- **The CLI tests**: 113 passed, 1 skipped.
- **The soak's harness** (`tests/soak_v1350/`): a 6-minute trial passed
  on the harness as revised in review (36 turns, the 9 probes each refused
  outside the plan, nothing else refused but what every run refuses). The
  first trial on the soak's host (Ubuntu, systemd-resolved) found the
  Warden refusing glibc's `stat` of `/etc/resolv.conf` on every lookup:
  there it is a symlink into `/run/systemd/resolve/`, and the stat was
  decided on that target, which no policy names, while the file's open was
  answered by the name view. A metadata call on a name view's host target
  is now decided as the view's own path (a deny rule over it still
  refuses). The 24-hour run: _to be filled in_.

## Compatibility

- Every v1.34 policy and plan loads unchanged. `require plan` needs
  `require warden 1.35`.
- New in the plan gate's records: `plan_sha256` on `plan_gate`. An audit
  of a 1.35 stream requires it.
- New: `varek plan generate`, `varek plan merge`, `varek run
  --hold-to-plan`, `varek audit --plan`, `varek policy check --plan`, the
  adapters in `adapters/` (installed with `make install`), the `VarekPlan`
  CRD.

## Found in review

Six AI review agents read v1.35, each one part: the Warden's plan gate and
hold; `varek plan generate` and the adapters; the audit and the exports;
the node agent and the cluster; the corpus and the soak's harness; the
docs. None found a way for a plan to widen what the policy allows. What
they found, and what was done (step 9):

- **The Warden.**
  - A `process_exec` step was decided on its path with every link
    followed, the launch on the name given (a final symlink's own): the
    gate could authorize a step the launch then refused. Both are now
    decided on the launch's name.
  - A field a step's kind does not take (`opne=read`, `nmae=`) was passed
    over, leaving the step wider than written; in a `plan 1.35` plan it
    is now UNKNOWN, the field named.
  - The plan file was read three times (the hold's hash, the parse, the
    gate's hash): a plan rewritten between them was decided on one
    content and named by another's SHA-256. It is now read once, and that
    copy is hashed and parsed for the hold and the gate alike.
  - A call of a kind the hold does not narrow (a request, a bind) was
    refused when no step had its subject; `mkdir` of an existing
    directory above a step's path was answered without asking the hold;
    the hold's refusal of such a directory's metadata was recorded as the
    policy's; `file_open /` was not a directory step; `chdir` above a
    step's path was refused; a long plan path could be cut inside its JSON
    escape. Each fixed.
  - The basic gate's pathology report went into the stream as a JSON line
    with no run id, which `varek_ocsf.py --follow` took for another run's
    record (every run with a plan, so every run under `require plan`); it
    is prefixed now, and a plan refused for its structure (a cycle) says
    so on its `plan_gate` record (`why`).
- **The adapters and `varek plan generate`.**
  - `--python` was run as root, unconfined, to learn the agent's Python
    environment (its `.pth` files would run as root); it now runs as the
    adapter's user with `-I -S`, nothing of the operator's environment,
    and its answer is refused if it is not two plain paths or names a
    directory as wide as `/home` or `/opt`.
  - A name or description from the framework's files could hold a
    newline and end a plan comment, starting a step of its own; comments
    and fields now escape every control character and Unicode line
    break, and `plan generate` refuses a plan with such a line.
  - `plan merge` split lines as the Warden does not, dropped comments, and
    took self-edges, duplicate edges and cycles; fixed. The plan is written
    beside its target and renamed into place.
  - LangGraph: a relative `root_dir` was resolved against the adapter's
    directory, not the agent's; and the adapter walked everything the
    graph's module defined, so a model the file built and no node used was
    in the plan. It now walks the graph and the module names its nodes'
    code uses, plus the module's MCP clients (whose tools the agent gets
    when it runs), and says so in the plan.
  - An empty or non-text tool name could become a step naming no tool
    (every tool of a server); it is left out, said. Smaller: a URL with a
    bad port, non-object JSON values, a relative `--app-dir`, root's home
    taken as the agent's (Claude).
- **The audit and the exports.**
  - Every stream of the flow gate with a refused step, and every run held
    under `--flow-policy`, failed the audit (it read only gate `plan`);
    a held run refusing a launch outside its plan failed it too
    (`outside_plan` was not a launch refusal it knew). Both pass now.
  - A plan record placed before `run_start` (unchained) passed the audit
    and the OCSF export took it as the run's: a forged gate verdict
    needing no key. The parser refuses any record of the run before its
    `run_start`, and the exporter takes only what it chained.
  - The CycloneDX text said an agent started when the flow gate's
    breaker had refused it, and that a refused plan's run was held; the
    OCSF event said Allowed on the verdict alone; a cut stream's lone
    steps shared one uid; a malformed `plan_sha256` crashed the summary.
    Each fixed.
- **The node agent and the cluster.**
  - During an upgrade, a pod naming a plan under a policy older than 1.35
    could run on a node still on 1.34, under its policy alone, not held.
    The webhook now admits a pod naming a plan only under a policy that
    says `require warden 1.35`, which such a node refuses.
  - The plan syncer moved past a watch event before it was applied, and a
    failed write or removal was only logged, so a node could keep a wider
    plan until the next list; failures are retried now (listed again).
    Plan annotations a pod naming no plan came with are removed.
  - A plan is bound by its name, as a policy is: said in the chart's
    README and the design note.
- **The corpus.** The figure "plans v1.11 could let start" was 0 by
  construction, not measured, and the two steps counted as collection
  were a server's tools as a set the plan does not list, which no
  payload's elements are. Relabelled (unlisted tools), and the write-up
  says that with plan 1.35 the plan gate cannot meet v1.11's condition.
  Strata are taken from the plan's own steps; one adapter's timeout no
  longer ends the run.
- **The soak's harness.** Probes are now matched by their exact targets,
  once each per probe turn and within it; memory growth fails the soak
  (it was a note); the agent reconnects to the docs server after a lost
  session, and the check bounds reconnects; a turn is done only when
  `word_count` wrote its note; processes are sampled by the Warden's PID
  and session, not by a pattern; `soak.sh` is executable. The 6-minute
  trial was run again on the new harness and passed.
- **The docs.** Stale status lines and sections, the adapters' file names,
  the hold's limits stated where the hold is described, D10 (the v1.1
  integrations marked legacy, which no step had done), and the dates.

## Known limits

- **A plan names only what the framework says.** A tool that runs in the
  agent's process (a function tool) is not in the plan unless named with
  `--host` or `--file`; held, its other calls are refused. A model built
  inside a node at run time (as LangGraph's templates do) has no host in
  the plan.
- **A server whose tools are listed when the agent connects** gets one step
  naming no tool, which covers every tool of that server; a policy that
  names its tools refuses it.
- **MCP over HTTP to an address** cannot be allowed by an `mcp` rule (it
  names its server by host name). The MCP client's own GET (to open the
  server's stream) and DELETE (to end its session) are refused in every
  run: no `mcp` rule decides them and no step kind names them; the clients
  tested go on without them.
- **A stdio MCP server** is a sub-agent step for its program; its calls are
  not decided (from v1.31.0). Its program is looked up on the system's
  PATH, so one started by `npx` or `uvx` elsewhere gets a step naming no
  program, which no rule launches.
- **The node agent does not carry** `mcp_call`, `subagent` or `credential`
  steps yet (a plan with one is refused at deploy); v1.36.
- **The code adapters import the agent's code**: confined as above, it can
  still make the adapter write a plan broader than the framework's objects
  would give; the plan is checked against the policy, which bounds it.
- **A launch is held by the file launched by that name**, not by what it
  does: a multi-call binary (busybox) picks its applet from `argv[0]`,
  which the agent chooses.
- **A plan bound by its name**, under the node agent: each container start
  takes the `VarekPlan` of that name as it then is (`run_start` names it by
  its SHA-256).
- **A host-name step is matched as written**: a run whose names are spelt
  otherwise (another case) is refused its connection, never allowed one.
- **The credential hold** (a request carrying a credential no step names)
  is built as the others are and not yet tested; the MCP call hold is
  exercised by the soak.
- **The plan's records are chained, not sealed**: without a signing key
  (`--sign-key`), anyone who can rewrite and re-chain the stream can make a
  refused plan read as authorized, and `varek audit --plan` checks only the
  plan's hash. Sign the stream for evidence that holds.

## Upgrading

1. Rebuild (`make all`) and reinstall (`make install`): the adapters go to
   `$(PREFIX)/adapters/`.
2. For a code adapter, a Python with the agent's framework (the versions
   tested are in `adapters/requirements-frameworks.txt`) that the adapter's
   user can read: `sudo varek plan generate --python PATH ...`.
3. Write the plan, check it (`varek plan generate ... --policy POLICY`),
   then hold the run to it (`varek run --plan PLAN --hold-to-plan`), and
   add `require plan` to the policy when every run should be.
