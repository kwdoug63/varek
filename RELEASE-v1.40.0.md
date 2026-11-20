# VAREK v1.40.0 — Security Operations: Microsoft Sentinel

A run's evidence in Microsoft Sentinel. The OCSF events v1.39.0 sent to
OpenTelemetry and Splunk now go to Sentinel's workspace too, finished runs
or live ones:
- a refusal raises an incident naming the policy line that decided it;
- a tampered verdict stream raises a High one.

An export that fails partway can now send just the rest. And the sector
packs now decide which programs an agent may launch, and start an agent
with no refusals.

This is the second part of security operations
(`docs/security/v1.39-security-operations.md`). CrowdStrike Falcon and
Wiz, each waiting on its partner program's tenant, move to v1.41.0.

v1.40.0 includes v1.39.1's license check for AWS Marketplace's hourly
evaluation listing (`RELEASE-v1.39.1.md`), which was never tagged on its
own. The Warden's code is unchanged since v1.39.0, and the policy grammar
stays 1.35.

> Not reviewed by a human or a third party, or by a separate review pass:
> the changes were tested as below.

MIT · github.com/kwdoug63/varek

## Summary

- **Microsoft Sentinel export** (#193). `varek export --format sentinel
  [LOG]` sends a run's OCSF events, audited first, as rows of a custom
  table, `VarekOCSF_CL`, in Sentinel's Log Analytics workspace. It goes
  through the Azure Monitor Logs Ingestion API and a data collection rule.
  `--follow STREAM` sends a live run's events as they are decided.
  - **A row:**
    - the decision, the three-state verdict and the rule;
    - the policy line and its text;
    - what was decided, the run, the agent and the host;
    - the whole OCSF event.
  - **The token is Microsoft Entra ID's,** one of:
    - a client secret, from the environment, never the command line;
    - an Azure VM's managed identity;
    - a token already had.
  - **Sending:** rows go gzipped, under the API's 1 MB a request. A busy
    API is retried and a batch too large is split; any other refusal ends
    the export with exit 1.
  - **`integrations/sentinel`** (installed in `/opt/varek/integrations`)
    holds two deployment templates:
    - **`azuredeploy.json`:** the table, the data collection rule, and the
      sending identity's role on that rule and nothing else.
    - **`sentinel-content.json`:** three analytics rules and a workbook.
      The rules:
      - an agent's action refused (Medium, an incident);
      - a run's audit failed (High, an incident);
      - a dry run's let-through calls (Informational).
- **The rules judge a row when it arrives** (#211, #212). Each rule runs
  every 5 minutes over a day of decisions, and keeps the rows that arrived
  in the last 6 minutes (`ingestion_time()`). So a run exported up to a day
  after its decisions still raises its incidents, not only one exported
  live.
  - The window is a minute longer than the period because Sentinel's runs
    aren't exactly 5 minutes apart. No row falls between two runs.
  - A row both runs see raises a second alert, in the same incident: each
    incident rule groups its alerts by run.
  - An alert's time is its latest decision's.
- **A failed export resumed** (#209). When an export to OpenTelemetry,
  Splunk or Sentinel fails partway, the sender's message names where the
  events it didn't send begin. The same export with `--from-position N`
  sends the rest:

  ```
  varek_sentinel: HTTP 400 ... (500 rows sent before; those not sent begin at position 512: `varek export --from-position 512` sends them)
  ```

  - The position is the record's (`unmapped.varek.position`, on every
    OCSF event).
  - The stream is still audited whole, and the audit's verdict is always
    sent.
  - Events come out in their records' order, so nothing from that
    position on is left out.
  - With `--hec-ack`, Splunk's resume point is the earliest batch not
    acknowledged as indexed.
- **A refused stream: the export says why, and what was sent** (#193,
  #210).
  - With `--follow`, the reason (the broken line) is printed on screen as
    well as sent in the audit's verdict.
  - The audit names the file given, not a temporary copy.
  - `varek export` says "nothing was sent" or "the events it wrote before
    it stopped were sent".
  - A sender that fails (Entra ID refusing a secret, say) is named as the
    failure, with no traceback, and the audit isn't blamed.
- **The sector packs decide program launches** (#207). The five packs say
  `require warden 1.27`, up from 1.14. Under 1.14 every launch after the
  agent's own was refused, whatever the packs' `allow exec` lines said;
  now those lines take effect.
  - **healthcare, finance, utility and national-defense** let the agent
    start `python3`, a general-purpose interpreter.
  - **cybersecurity** names `yara` alone, keeping its "no shell" intent.
  - **Any program not named** is refused, held by Landlock.
  - **Writable directories:** every directory a pack lets the agent write
    is mounted `noexec` for the run (`--writable-exec` turns this off for
    a run).
- **A run under a sector pack starts with no refusals** (#208). The packs
  allow, read-only, what the loader, the C library and Python read as a
  program starts:
  - `/etc/ld.so.preload` and locale names;
  - Python's own links and home-finding files, most of them absent;
  - the site-wide packages.

  A Python agent's start-up went from 19 refusals to none, so a refusal in
  Sentinel, Splunk or OpenTelemetry is the agent's.
- **GKE Standard, tested** (#204, #205). The 24-hour Kubernetes soak passed
  on GKE with Ubuntu nodes, amd64 and Axion arm64.
  - The chart now ships a ResourceQuota for its critical priority class.
    GKE admits such a pod only in a namespace that holds one, so before
    this the DaemonSet made no pod there.
  - The soak's pods tolerate GKE's Arm taint (#203, #204).
- **v1.39.1's license check** (#196, #197). An AMI built with
  `build.sh --product-code` counts an instance as licensed when its listing's
  product code is in instance metadata, so an hourly AWS Marketplace
  listing (the 30-day evaluation) can offer the Enterprise packs.
  `packaging/aws-marketplace/add_free_trial.py` sets that listing's free
  trial.
- **Project:**
  - `CONTRIBUTING.md` (#199);
  - CI installs the adapters' framework pins, hash-pinned (#200, #202,
    #190);
  - the arm64 sweep's packages at exact versions (#195, #198);
  - a Go test that waits for its log (#201);
  - CI's Kubernetes cells take the Kubernetes project's own packages
    (#206).

### What changes for a user

| | Before | v1.40.0 |
|---|---|---|
| `varek export --format` | `cyclonedx`, `ocsf`, `otlp`, `splunk` | also `sentinel` |
| `varek export --dcr`, `--stream`, `--azure-auth`, `--azure-tenant`, `--azure-client-id`, `--azure-secret-env` | — | new, for `sentinel` |
| An export that fails partway | export the whole run again | `--from-position N`, the position the failure names |
| `/opt/varek/integrations/sentinel` | — | the deployment templates |
| A sector pack's `allow exec` lines | no effect: every launch after the agent's own refused | each one allows its program; any other refused |
| A sector pack's writable directories | executable | mounted `noexec` for the run; each must exist when it starts |
| A Python agent's start under a pack | about 19 refusals | none |
| The chart on GKE | no node agent pod | runs (Ubuntu node pools) |

**Upgrading:**
- **A pack's writable directories must exist when the run starts,** and
  the agent's program and its standard input must not be in one.
- **A Warden before 1.27 refuses the packs.**
- **Sentinel rules deployed from an earlier main** need
  `sentinel-content.json` deployed again; the rules are replaced in place.

## Tested

- **CI** on every PR (#193 to #212): every job the PR's files trigger,
  x86-64 and arm64. On every PR that includes:
  - the container image's sweep;
  - the node agent's suites;
  - the 24-hour harness's six-minute trial;
  - the CRI-O and containerd cells.

  The Rocky Linux 9 and Amazon Linux 2023 host suites run only when C
  code, the charts, packaging or the sweep's requirements change; they
  ran on #205, #206 and #209, and run on this release's PR.
- **Unit tests** (`make test-cli`: 221 passed, 1 skipped):
  - **`tests/test_varek_sentinel.py`,** against a stand-in Azure: the row
    mapping, the templates' table, rule and queries, Entra ID tokens and
    managed identity, retries, 413 splits, refusals, and the rules'
    windows.
  - **`tests/test_varek_export_resume.py`:** `--from-position` on a real
    run's stream, by `--log` and `--follow`, equal to the full export's
    events from there; a record before the position edited, and nothing
    written; the refusal messages.
  - **The pack tests:**
    - each pack's launches decided, by both parsers;
    - a bare Python agent starting under each pack with no refusal, in
      CI on Ubuntu 24.04 (the host, Python 3.12, and the container image)
      and on Python 3.13 by hand. Rocky Linux 9 and Amazon Linux 2023
      (Python 3.9) run it in this release's CI: VERIFY BEFORE TAGGING.
  - `smt_crosscheck` on the five packs: 0 disagreements.
- **Microsoft Sentinel, live,** in a Log Analytics workspace with
  Sentinel, East US, from a RHEL 9 host (Amazon EC2):
  - **November 16:** both templates deployed unchanged. A live run's 142
    events reached the table, each refusal within 25 s with its policy
    line. The refusal rule raised its incident, and the workbook's eight
    panels were drawn with no query failing. Azure's delay on a new table
    was 6 minutes for the first run, under 25 s after.
  - **November 19:**
    - **Tampering:** a run's first refusal was edited into an allow and
      the stream sent with `--follow`. The events before the edit arrived,
      then the audit's failed verdict, which raised the High incident.
    - **The control:** the same stream sent whole sent nothing.
    - **Resuming:** a send Azure refused named position 1. A run of 58
      events sent `--from-position 30` left exactly 29 rows in the table,
      the first at position 30.
  - **November 20:**
    - **Late exports:** the rules were deployed again; two runs exported
      8 minutes after their decisions raised their incidents, High and
      Medium.
    - **Again after #212:** each alert's time was its latest decision
      (within 2 ms), and there was one incident per rule and run.
- **GKE Standard, 24 hours,** November 17 to 18, 2026. GKE 1.37 with one
  n2-standard-2 (amd64) and one Axion c4a-standard-2 (arm64) Ubuntu node;
  the v1.39.0 node image and this release's chart. `soak_check: PASS`:
  - 2,592 turns, 576 probes held;
  - the token on all 3,456 allowed requests and in none of 565 files;
  - 100 streams and 4,041,182 records, all audited and each in the
    exporter's log;
  - 8 VAREK containers, none restarted;
  - the node agent's memory flat.
- **v1.39.1's license check:** `tests/test_varek_license.py`, with and
  without an instance metadata service answering
  (`RELEASE-v1.39.1.md`).
- **The Warden** is v1.39.0's, whose 24-hour soak passed on November 15 to
  16 (`RELEASE-v1.39.0.md`).

## Known limits

- **Sentinel:**
  - Tested in one workspace (East US), with a client secret; a managed
    identity was tested only against the stand-in.
  - The rules judge rows that arrive within a day of their decisions; a
    run exported later reaches the table and the workbook but raises no
    incident.
  - A row both of two rule runs see raises a second alert, in the same
    incident.
  - The workbook is an Azure Monitor workbook. Sentinel moves into the
    Microsoft Defender portal after March 31, 2027, and the workbook was
    not tested there.
  - Not yet in Sentinel's Content hub.
- **`--from-position`:**
  - Events the tool already holds may be sent again: a Sentinel batch
    split after a 413, or a run's last event, which shares its position
    with the audit's verdict.
  - A sender that failed before reading anything names no position; the
    run is then exported again whole.
- **The packs:**
  - `python3` is a general-purpose interpreter: any code it can read
    runs, under the pack's file and network rules.
  - The start-up reads were checked with Python 3.12 (Ubuntu 24.04) and
    3.13. Another distribution's Python may read something else at start.
- **GKE:** Container-Optimized OS nodes can't run the node agent (their
  kernel has no Landlock), nor can Autopilot or GKE Sandbox.
- From v1.38.0, unchanged:
  - the baseline's git rules don't cover a nested submodule's settings;
  - the Mac's packet filter names the Mac's addresses when it loads;
  - on a VM's first boot there are a few seconds before the rules load,
    with no project mounted.
