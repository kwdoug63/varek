# VAREK for Google Security Operations

v1.43 (`docs/security/v1.39-security-operations.md`, section 6). The
Warden's decisions in Google Security Operations (SecOps):
`varek export --format secops` sends a run's OCSF 1.9.0 events, audited
first, as UDM events to the instance's Chronicle API (`events:import`).
Four YARA-L rules raise a detection for a refusal, a failed audit, a dry
run's let-through and an approval nobody gave in time, and a dashboard
gives an overview.

**Built against a stand-in, not yet tested in an instance.** The export is
tested against a stand-in Google (`tests/test_varek_secops.py`). The rules
and the dashboard are checked against what the export writes
(`tests/test_varek_secops_content.py`). The ship gate, in Google's
development instance, comes before v1.43.0 ships; see section 6 below.

What's here:

| File | What it is |
|---|---|
| `rules/varek_action_refused.yaral` | An agent's action refused (Medium), naming its policy line |
| `rules/varek_audit_failed.yaral` | A run's audit failed (High): its verdict stream doesn't verify |
| `rules/varek_dry_run_let_through.yaral` | A dry run let through what its policy refuses (Informational) |
| `rules/varek_approval_timeout.yaral` | v1.42: a `step_up` approval or a deferral nobody gave in time (Medium) |
| `varek-dashboard.json` | A draft of the dashboard: refusals by policy line, agent and run, over time and the latest; dry runs; failed audits; approvals timed out |

These are Sentinel's four analytics rules and its workbook's panels, in
YARA-L (`integrations/sentinel/`).

## 1. An identity to send as

The export signs in as one of these, never with a secret on the command
line (G3):

- **The VM's own service account** (`--secops-auth metadata`, or `auto`
  with no key file). It uses the Compute Engine metadata server, so there's
  no secret on the host. Use this one on a VM in the instance's project.
  The soberagents.ai organization forbids creating service-account keys,
  so on our own hosts it's the only one.
- **A service account's key file**, the one `GOOGLE_APPLICATION_CREDENTIALS`
  names (`--secops-auth key-file`, or `auto`).
- **A token from the environment**, `GOOGLE_OAUTH_ACCESS_TOKEN`
  (`--secops-auth token`).

The identity needs one permission on the instance: `chronicle.events.import`.
The least is a custom role with only that permission, granted to the
service account on the instance's project.

## 2. Send a run

```
SECOPS_PROJECT=PROJECT SECOPS_CUSTOMER_ID=CUSTOMER_ID varek export --format secops /var/log/varek/RUN.jsonl # end
```

- `--secops-project`, `--secops-customer-id` and `--secops-region` take
  the place of `SECOPS_PROJECT`, `SECOPS_CUSTOMER_ID` and `SECOPS_REGION`.
  The region defaults to `us`.
- `--follow` sends a live run's events as they're decided.
- `--from-position N` sends the rest of a run whose export stopped at
  position N.
- A refusal or a lost batch ends the export with exit 1, naming the
  position the events not sent begin at.

## 3. The rules

Each rule reads only what the export writes (G6): UDM fields, and the
`varek_*` keys in `additional.fields`. They are:

| Rule | Matches | Groups by | Outcome |
|---|---|---|---|
| `varek_action_refused` | `security_result.action` `BLOCK` | run, host, deciding line, over 1 h | refusals counted; agent, the line's text, policy, verdicts, files and hosts reached; first and last seen |
| `varek_audit_failed` | `varek_event` `audit`, `varek_audit_passed` `false` | each failed audit | run, host, the audit's mode and problems |
| `varek_dry_run_let_through` | `varek_mode` `dry_run`, `varek_decision` `DENY` | run, host, deciding line, over 1 h | calls let through; agent, the line's text, files and hosts reached |
| `varek_approval_timeout` | `varek_event` `step_up_end` or `defer_end`, `varek_ending` `timeout` | run, host, policy line, over 1 h | approvals timed out; which kind, agent, policy; first and last seen |

**To install a rule:**

1. In Google SecOps, open **Detection** → **Rules & Detections** →
   **Rules Editor**.
2. Choose **New**, and paste the rule file.
3. Save it, then turn on **Live Rule**. For the refusal, audit and
   timeout rules, also turn on **Alerting**. Leave the dry run's off, as
   its Sentinel rule raises no incident.

The Chronicle API's rule methods (`projects.locations.instances.rules`)
take the same text, for installing them as code.

**Writing rules needs** the Chronicle API Editor role
(`roles/chronicle.editor`); reading detections, Chronicle API Viewer
(`roles/chronicle.viewer`).

## 4. The dashboard

`varek-dashboard.json` is a draft. Its eight panels are YARA-L 2.0
queries:
- refusals by policy line, by agent and by run;
- refusals over time, and the latest refusals;
- dry runs' let-throughs, counted apart from refusals;
- failed audits;
- approvals nobody gave in time.

It's imported, drawn and exported from the development instance at the
ship gate, as Google's partner guide asks, and that export replaces this
file. Until then, build it by hand: **Dashboards** → **New**, with one
chart per panel, its query pasted in.

## 5. Not through Google's OCSF parser

Google SecOps has a default parser for raw logs of the type `OCSF`, so
VAREK's OCSF events could go in as they are. But Google says a default
parser "might map a subset of core values from the raw log". A value it
doesn't map stays in the raw log, where no rule or dashboard can read it
(G1). The values most likely to be left out are:
- the policy line and its text;
- the three-state verdict;
- the policy's SHA-256.

So the export writes the UDM itself, and these rules need it. The exact
list of what the default parser fills gets measured in the development
instance, by sending the same run both ways.

## 6. Checked only at the ship gate

In Google's development instance, before v1.43.0 ships:
- **The export:**
  - `events:import`'s endpoint and body, and its permission (G2);
  - the UDM field names, and whether `additional` takes plain string
    values (G4);
  - the size and rate limits.
- **The rules:** each one's YARA-L syntax and field paths, in the Rules
  Editor, and each raising its detection live.
- **A refusal** searchable within a minute, with its policy line.
- **The dashboard,** imported and showing a live run.
