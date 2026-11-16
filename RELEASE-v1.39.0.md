# VAREK v1.39.0 — Security Operations: OpenTelemetry and Splunk

A run's evidence, where security teams already look. The OCSF events
v1.31.0 made of a run's verdict stream, audited first, now go to an
OpenTelemetry collector and to Splunk, finished runs or live ones, each
refusal with the policy line that decided it. This is the first part of
security operations (`docs/security/v1.39-security-operations.md`);
Microsoft Sentinel, CrowdStrike Falcon and Wiz, each waiting on an
instance of its tool, are v1.40.0. The Warden decides nothing differently,
and the policy grammar stays 1.35.

> Not reviewed by a human or a third party, or by a separate review pass:
> the changes were tested as below.

MIT · github.com/kwdoug63/varek

## Summary

- **OpenTelemetry export** (#187). `varek export --format otlp [LOG]` sends
  a run's OCSF events to an OpenTelemetry collector as OTLP log records,
  over OTLP/HTTP with JSON (the standard library only: no SDK, no
  protobuf); `--follow STREAM` sends a live run's as they are decided.
  - A record's body names the decision, the object and the policy line
    with its text: `Blocked: File System Activity: Open /etc/shadow
    (policy line 91: deny  path /etc/shadow)`.
  - Its severity is OCSF's, with OpenTelemetry's names (a refusal WARN, a
    failed audit ERROR), so a backend shows the level.
  - Its attributes carry the decision (`varek.decision`, ALLOW or DENY),
    the three-state verdict, the rule, the policy line, its text, the
    policy's name and SHA-256, the run, the agent, the process and user,
    and the whole OCSF event (`ocsf.event`).
  - The endpoint and headers follow `OTEL_EXPORTER_OTLP_*`;
    `--otlp-header NAME=ENVVAR` takes a key from the environment, never
    the command line.
- **Splunk export and app** (#188). `varek export --format splunk` sends
  the events to a Splunk HTTP Event Collector (HEC), sourcetype
  `varek:ocsf`, the whole OCSF event as each event's body, the decision's
  time as its time, the run and the decision indexed fields.
  - The token comes from the environment (`--hec-token-env`, default
    `SPLUNK_HEC_TOKEN`); the HEC's certificate is always checked, its
    name too (`--ca` for a private CA); `--hec-ack` waits for Splunk to
    acknowledge each batch as indexed.
  - The app (`integrations/splunk/varek`, installed in
    `/opt/varek/integrations`) names the fields (`varek_decision`,
    `varek_policy_line`, `varek_decided_by`, `varek_target`, ...) and
    gives a dashboard: refusals by policy line, agent and run, over time;
    the latest refusals; what dry runs let through, counted apart from
    refusals; failed audits.
- **Both exports fail loudly.** A batch refused for a reason a retry can
  mend (429, 502, 503, 504, no answer) is sent again, backing off; any
  other refusal, or a partial rejection, ends the export with exit 1,
  naming what was not taken.
- **The adapters' framework pins install again** (#189). Dependabot's mcp
  2.3.0 left `adapters/requirements-frameworks.txt` impossible to install
  (langchain-mcp-adapters needs mcp < 2); mcp is back at 1.30.0, with
  five framework updates, and CI now installs the file. `varek plan
  generate` lets the adapter's Python read
  `/proc/sys/vm/overcommit_memory`, as the baseline does.

### What changes for a user

| | Before | v1.39.0 |
|---|---|---|
| `varek export --format` | `cyclonedx`, `ocsf` | also `otlp` and `splunk` |
| A live run's refusals in a collector or Splunk | export the file, then ship it yourself | `--follow`: within about a second of each decision |
| `varek export --endpoint`, `--otlp-header`, `--hec-token-env`, `--splunk-index`, `--ca`, `--hec-ack` | — | new |
| `/opt/varek/integrations/splunk` | — | the Splunk app |

## Tested

- **CI** on every PR (#187 to #189): every job, x86-64 and arm64,
  including the container image's sweep, the node agent's suites and the
  soak harness's six-minute trial; the adapters' framework pins
  installed and imported.
- **Unit tests** (`make test-cli`): `tests/test_varek_otel.py` and
  `tests/test_varek_splunk.py`, 8 each, against a stand-in collector and a
  stand-in HEC: the mapping; batches; keys from the environment and never
  in the output; retries; refusals and partial rejections ending the
  export; Splunk's indexer acknowledgement; TLS with a private CA, without
  it, and with a certificate naming another host.
- **The OpenTelemetry Collector** (contrib 0.120.0, an OTLP/HTTP receiver
  and a file exporter): a run's 219 events all accepted and written as
  sent; a live run's refusals read 0.02 to 0.08 s after each decision and
  at the collector within its one-second batch.
- **Grafana Cloud's OTLP endpoint** (Loki), November 14, 2026: a live
  run's 228 records accepted, its six refusals (three opens of
  `/etc/shadow`, policy line 91; three connects refused by the default
  deny) in Grafana with their fields, each sent within about a second;
  found there and fixed, the level and the final decision; confirmed
  after the fix (`varek_decision="DENY"`, each at level warn).
- **Splunk Enterprise 10.4.5** (its image, on the trial license), November
  15, 2026, the HEC over TLS with a certificate from a CA of our own, the
  app installed:
  - a run's 219 events, acknowledged as indexed;
  - a live run with `--follow --hec-ack`: 228 events acknowledged, each
    refusal indexed within 2 s of its decision;
  - a dry run's let-through call counted under dry runs, not as a
    refusal;
  - every dashboard search right over the three runs, and the dashboard
    drawn in Splunk Web with no error.
- **test_v1350** with the new framework pins: 137 of 137, the langgraph
  and openai-agents adapters under the Warden included.
- **24 hours** (`tests/soak_shared/soak.sh`, the shared soak), November 15
  to 16, 2026, from 3:00 AM CST, on #191's head (`c6fe24e`): an EC2
  `t3.medium`, Ubuntu 24.04, us-east-1. Its six-minute trial passed first.
  `soak_check: PASS`. The tagged code adds CI, tests, documentation and the
  Splunk app's `app.conf` (#192, #179, #194), no Warden code.

  | | |
  |---|---|
  | Duration | 24.0 h, a turn every 60 s: 1,440 turns in each run; Warden 1.39.0 (x86-64) |
  | Run A | every task before the user's token expired worked (`tools/list` 259, `tools/call` 258, `fs` reads 258, `gh`'s calls 258, sub-agent launches 258); 144 probes, all held; the run revoked 0.00 s after the expiry, no turn after it working (5); 258 requests carried the credential, 0 swaps refused; the audit passing; OCSF: 11,719 events followed, 11,718 of them the stream's (14,405 records, the chain intact), all valid OCSF 1.9.0 |
  | Run B (the baseline, with its git rules) | 1,296 of 1,296 pieces of work done, 288 git commits; 144 probes, all refused; the stream signed (436,188 records), the audit passing |
  | Run C (dry run) | 1,440 of 1,440 done; 4,324 calls the narrower policy refuses let through and recorded; the audit (463,655 records): `VERIFIED: DRY RUN, NOT ENFORCED`; `varek policy suggest`: 39 exact rules; under the draft, 12 of 12 done and nothing let through |
  | The Warden's decisions | the agent's MCP calls p50 23 µs (p99 33); `gh`'s MCP calls p50 26 µs (p99 62); the agent's opens p50 72 µs (p99 1,166); `fs`'s opens p50 206 µs (p99 1,999) |
  | Memory | each Warden 12.4 to 12.8 MB at the start and 12.7 to 13.0 MB at most; the proxy, `warden-secrets` and the two MCP servers 8.6 to 21.1 MB, flat (144 samples each) |

## Known limits

- **OpenTelemetry:** OTLP/HTTP with JSON only (no gRPC, no protobuf);
  logs only, no spans or metrics; no trace context from an agent
  framework. A vendor key by `--otlp-header` was tested against the
  stand-in collector; Grafana Cloud's was added by the session's proxy.
- **Splunk:** tested on Splunk Enterprise on one host, not Splunk Cloud,
  and with a private CA's certificate on the HEC, not a public CA's.
  Splunk's default HEC certificate names no host, so the HEC needs a
  certificate of its own. The app passes Splunk AppInspect 4.4.0 (every
  check, and Splunk Cloud's: no failure, no warning), but is not yet on
  Splunkbase.
- **Both:** an export that fails mid-run ends; the events after it stay in
  the verdict stream, and exporting the run again sends all of its events
  again, so the tool holds those sent before twice (the OCSF event's
  `metadata.uid`, the record's id, tells them apart). Nothing is buffered on disk between
  attempts.
- From v1.38.0, unchanged: the baseline's git rules do not cover a nested
  submodule's settings; the Mac's packet filter names the Mac's addresses
  when it loads; on a VM's first boot there are a few seconds before the
  rules load, with no project mounted.
