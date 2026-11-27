# VAREK for Microsoft Sentinel

v1.40 (`docs/security/v1.39-security-operations.md`, section 3). The
Warden's decisions in Microsoft Sentinel: `varek export --format sentinel`
sends a run's OCSF 1.9.0 events, audited first, as rows of the custom
table `VarekOCSF_CL` in Sentinel's Log Analytics workspace, through the
Azure Monitor Logs Ingestion API and a data collection rule. Analytics
rules raise an incident for a refusal and for a failed audit, and a
workbook gives an overview.

**Tested in a real workspace** (November 16, 2026): both templates
deployed unchanged; a live run's 142 events in `VarekOCSF_CL`; each
refusal there within 25 s of its decision, with its policy line; the
refusal rule's incident raised and the workbook drawn
(`docs/security/v1.39-security-operations.md`, section 3). And against a
stand-in Azure (`tests/test_varek_sentinel.py`): Entra ID's token
endpoint, a VM's metadata service and the Logs Ingestion API.

## 1. The table and the data collection rule

`azuredeploy.json`, in the workspace's resource group, makes:

- the table `VarekOCSF_CL` (30 columns, below);
- the data collection rule `varek-ocsf` (kind Direct, so it has its own
  logs ingestion endpoint), its stream `Custom-VarekOCSF` passed to the
  table unchanged;
- given `principalId`, that identity's **Monitoring Metrics Publisher**
  role on the rule: the right to send to it, and nothing else.

```
az deployment group create -g RESOURCE_GROUP --template-file /opt/varek/integrations/sentinel/azuredeploy.json -p workspaceName=WORKSPACE principalId=OBJECT_ID # end
```

Its outputs are the two values the export needs: `logsIngestionEndpoint`
and `dataCollectionRuleImmutableId` (`dcr-...`).

## 2. An identity to send as

One of:

- **An app registration** (Microsoft Entra ID → App registrations → New
  registration), with a client secret. Its service principal's object id
  is `principalId` above. The export reads the secret from the
  environment (`AZURE_CLIENT_SECRET`, or the variable `--azure-secret-env`
  names), never the command line, and the tenant and client ids from
  `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` or `--azure-tenant` and
  `--azure-client-id`.
- **A managed identity**, on an Azure VM that runs the agents
  (`--azure-auth managed-identity`; `--azure-client-id` for a
  user-assigned one). No secret at all.

A new role assignment can take up to about half an hour to apply (23
minutes in the managed-identity live test, November 21, 2026); until it
does, the API answers 403.

## 3. Export

```
varek export --format sentinel --endpoint ENDPOINT --dcr dcr-ID # end
```

A live run, each event as it is decided:

```
varek export --format sentinel --follow /var/log/varek/run.log --endpoint ENDPOINT --dcr dcr-ID # end
```

`--endpoint` and `--dcr` default to `AZURE_LOGS_INGESTION_ENDPOINT` and
`AZURE_DCR_IMMUTABLE_ID`. Rows are sent gzipped, in batches under the
API's 1 MB. A batch refused for a reason a retry can mend (429, 500, 502,
503, 504, no answer) is sent again, backing off; one too large (413) is
split; a 401 gets a new token once; any other refusal ends the export with
exit 1. Its message says where the rows not sent begin, and the same export
with `--from-position N` sends them (the stream is audited whole all the
same; `docs/security/v1.39-security-operations.md`, section 5).

**The first rows to a new table take minutes.** Azure Monitor sets up a
new table and data collection rule on their first rows: in the live test,
the first run's rows reached the workspace five to six minutes after they
were sent, all at once; from the next run, within 25 s. Judge how soon a
refusal arrives after the first run.

What a run sent:

```
VarekOCSF_CL | summarize Rows=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by RunId
```

## 4. The analytics rules and the workbook

`sentinel-content.json`, after `azuredeploy.json`, in the same resource
group:

```
az deployment group create -g RESOURCE_GROUP --template-file /opt/varek/integrations/sentinel/sentinel-content.json -p workspaceName=WORKSPACE # end
```

- **VAREK: an agent's action refused** (Medium; an incident): one alert
  for each run, agent and policy line (or rule) among the rows that
  arrived since the rule last ran, with what was refused.
- **VAREK: a run's audit failed** (High; an incident): the run's verdict
  stream is not as the Warden wrote it. Only a live export (`--follow`)
  sends one: a run exported whole is audited first, and a stream the audit
  refuses sends nothing. In the live test (November 19, 2026) the incident
  came 10 minutes after the run.
- **VAREK: a dry run let through what its policy refuses**
  (Informational; no incident).
- **VAREK: an approval nobody gave in time** (v1.42; Medium; an
  incident): a call a `step_up` rule held or proposed was refused at its
  timeout, with no approver's answer, or a deferral's context (its marker,
  or a plan extension) did not come in time. One alert for each run, agent
  and policy line, with the calls that waited. It reads the row's
  `EventName` (`varek.step_up_end`, `varek.defer_end`) and the ending in
  `OcsfEvent`, so the table needs no new column. An approval abandoned
  because its call or its run ended first (usual for `mode=grant` at a
  run's end) raises nothing.
- **The workbook, *VAREK: the Warden's decisions***: counts; refusals over
  time, by policy line and by agent; runs; the latest refusals; dry runs;
  failed audits.

**Where to find them: Sentinel is moving to the Defender portal.** In the
live test (November 16, 2026), Sentinel → Workbooks in the Azure portal
said the page had moved to the Microsoft Defender portal, and that after
March 31, 2027 Sentinel is in the Defender portal only. The template's
workbook is an Azure Monitor workbook (`microsoft.insights/workbooks`), so
it still opens in the Azure portal: the resource group → the workbook
resource → Open workbook, or Monitor → Workbooks. In the Defender portal
(`security.microsoft.com`), the workspace's rules, incidents and
workbooks appear once the workspace is connected there, in its Microsoft
Sentinel settings; the live test did not do that step.

The rules run every 5 minutes and judge the rows that arrived in their own
5 minutes (`ingestion_time() > ago(5m) and ingestion_time() <= now()`),
whenever their decisions were made, up to a day before: a run exported
within a day of its decisions raises its incidents. One exported later
reaches the table and the workbook but raises none. (A day: Sentinel runs
a rule that looks back 2 days or more at most hourly.) In a rule, `now()`
is the end of the run's query window, and the windows end exactly 5
minutes apart, so each row is judged once and raises one alert, about 5
to 10 minutes after it arrives (8 to 9 in the live test, November 21,
2026). An alert's time is its rows', the latest decision. Rules deployed before
v1.40.0 looked back 5 minutes by the decision's time, and v1.40.0's took
the last 6 minutes of arrivals with no upper bound, so a row could raise
the same alert up to three times; deploy `sentinel-content.json` again
to replace them.

A run's refusal and failed-audit alerts carry its id in their custom
details (the dry-run rule's do not):

```kusto
SecurityAlert
| where TimeGenerated > ago(1d) and AlertName startswith "VAREK"
| extend RunId = tostring(parse_json(tostring(parse_json(ExtendedProperties)["Custom Details"])).RunId[0])
| where RunId == "RUNID"
| project TimeGenerated, AlertSeverity, AlertName, SystemAlertId
```

Sentinel is moving to the Microsoft Defender portal (after March 31, 2027,
Sentinel is in Defender only), and the Azure portal's Sentinel →
Workbooks page now points there. The workbook is an Azure Monitor
workbook in the resource group either way: open it from the resource
group (type *Azure Workbook*), or onboard the workspace to Defender and
find it under Microsoft Sentinel → Threat management → Workbooks.

## The table

| Column | |
|---|---|
| `TimeGenerated` | the decision's time |
| `Decision` | ALLOW or DENY (a dry run records DENY for what it lets through, with `Mode` `dry_run`) |
| `Verdict` | SATISFIED, UNSATISFIED or UNKNOWN |
| `PolicyLine`, `PolicyText` | the policy line that decided, and its text |
| `Rule` | the rule (`policy_match`, `default_deny_unknown`, ...) |
| `Target` | what the decision was about: a file, a process, an endpoint, an MCP call |
| `RunId`, `ReportId`, `Seq` | the run, and the record in its verdict stream |
| `Agent`, `AgentType`, `Computer`, `ProcessId`, `UserId` | who and where |
| `PolicyName`, `PolicySha256`, `WardenVersion` | the policy and the Warden |
| `EventName`, `AuditPassed` | lifecycle events (`varek.run_start`, `varek.audit`, ...) and an audit's result |
| `ClassUid`, `ClassName`, `ActivityName`, `Action`, `Disposition`, `Status`, `SeverityId`, `Severity` | OCSF's |
| `OcsfEvent` | the whole OCSF event (dynamic) |

```
VarekOCSF_CL | where Decision == "DENY" and Mode != "dry_run" | summarize count() by PolicyLine, PolicyText, Rule
```
