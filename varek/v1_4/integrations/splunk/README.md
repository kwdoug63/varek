# VAREK for Splunk

v1.39 (`docs/security/v1.39-security-operations.md`, section 2). The
Warden's decisions in Splunk: `varek export --format splunk` sends a run's
OCSF 1.9.0 events, audited first, to the HTTP Event Collector (HEC),
sourcetype `varek:ocsf`; the app `varek/` names their fields and gives an
overview: refusals by policy line, by agent and by run, what dry runs let
through, and failed audits.

Tested with Splunk Enterprise 10.4.5 (the `splunk/splunk:10.4.5` image, on
its trial license).

## 1. The app

Copy `varek/` to `$SPLUNK_HOME/etc/apps/varek` (on a search head and on the
indexers, as the sourcetype's settings are read at search time), then
restart Splunk. Installed with VAREK, it is in
`/opt/varek/integrations/splunk/varek`.

```
sudo cp -r /opt/varek/integrations/splunk/varek $SPLUNK_HOME/etc/apps/ && sudo chown -R splunk: $SPLUNK_HOME/etc/apps/varek && sudo -u splunk $SPLUNK_HOME/bin/splunk restart # end
```

It adds:

- **the sourcetype `varek:ocsf`**: JSON, one event each, its time the
  decision's (set by the sender);
- **the field names** (the OCSF ones keep theirs: `file.path`,
  `dst_endpoint.ip`, `disposition`, ...):

  | Field | |
  |---|---|
  | `varek_decision` | ALLOW or DENY (indexed: `tstats` reads it); a dry run records DENY for what it lets through, with `varek_mode` `dry_run` |
  | `varek_verdict` | SATISFIED, UNSATISFIED or UNKNOWN |
  | `varek_policy_line`, `varek_policy_text` | the policy line that decided, and its text |
  | `varek_rule` | the rule (`policy_match`, `default_deny_unknown`, ...) |
  | `varek_decided_by` | `line 91: deny  path /etc/shadow`, or the rule, for a default deny |
  | `varek_target` | what the decision was about: the file, the process, the endpoint, the MCP call |
  | `varek_run` | the run (indexed) |
  | `varek_report_id`, `varek_seq` | the record in the run's verdict stream |
  | `varek_agent`, `varek_agent_type` | the agent or sub-agent |
  | `varek_policy_name`, `varek_policy_sha256` | the policy |
  | `varek_mode` | `dry_run` for what a dry run let through |
  | `varek_event`, `varek_audit_passed` | lifecycle events (`run_start`, `run_end`, `audit`) and the audit's result |

- **the macros `varek_events`** (`index=varek sourcetype="varek:ocsf"`),
  which the dashboard reads: change it if the events go to another index;
  **and `varek_refused`** (`varek_decision=DENY NOT varek_mode=dry_run`): a
  refusal, not what a dry run let through;
- **the dashboard *VAREK: the Warden's decisions***.

## 2. An index and an HEC token

In Splunk Web: Settings → Indexes → New Index, `varek`. Then Settings →
Data inputs → HTTP Event Collector → New Token: name `varek`, source type
`varek:ocsf`, allowed index `varek`, default index `varek`. Turn on
indexer acknowledgement to use `--hec-ack`. Keep the token out of chats,
command lines and the repository: put it in the environment of the shell
that exports (`read -rs SPLUNK_HEC_TOKEN && export SPLUNK_HEC_TOKEN`), or
in the service's environment file.

## 3. Export

A finished run:

```
varek export --format splunk --endpoint https://splunk.example.com:8088 # end
```

A live run, each event as it is decided, acknowledged as indexed:

```
varek export --format splunk --follow /var/log/varek/run.log --endpoint https://splunk.example.com:8088 --hec-ack # end
```

- `--endpoint`: the HEC's URL (default: `SPLUNK_HEC_URL`);
  `/services/collector/event` is added to a URL without a path.
- `--hec-token-env ENVVAR`: the variable holding the token (default
  `SPLUNK_HEC_TOKEN`). A token is never taken from the command line.
- `--splunk-index INDEX`: the index (default: the token's).
- `--ca FILE`: the certificate authorities that signed the HEC's
  certificate, if not the system's. The certificate's name is checked
  against the URL's host; there is no option to skip the check. (Splunk's
  default HEC certificate, `SplunkServerDefaultCert`, names no host, so
  give the HEC a certificate of its own: `serverCert` under `[http]` in
  `inputs.conf`.)
- `--hec-ack`: wait for each batch to be acknowledged as indexed; one not
  acknowledged within 120 s ends the export with exit 1.

A batch the HEC refuses for a reason a retry can mend (503, "server is
busy"; 429, 502, 504; no answer) is sent again, backing off; any other
refusal ends the export with exit 1, naming the first event not taken.
The message also says where the events not sent begin (with `--hec-ack`,
the first not acknowledged as indexed), and the same export with
`--from-position N` sends them (`docs/security/v1.39-security-operations.md`,
section 5).

## 4. Searches

```
`varek_events` `varek_refused` | stats count by varek_decided_by
| tstats count where index=varek by varek_run varek_decision
`varek_events` varek_run=RUN | table _time varek_decision varek_target varek_decided_by
```
