# VAREK v1.42.0 — STEP UP and DEFER: Approvals as Grants

Until v1.42, every call the Warden mediates was allowed or refused at once. A call a policy can't settle on its own can now wait:
- **STEP UP:** a person decides. The call's narrowest grant is proposed, and an approver answers it on the run's approvers' socket.
- **DEFER:** the context it needs decides. The call waits until a root-owned marker releases it, or until a person does.

An approval is a **grant**: a precise permission, within the policy's `step_up` rule, limited in count, time and scope. The machine checks it, as it checks any authorization: the decision procedure decides the call under the policy plus the grant, and the independent checker must accept both halves of its certificate. Every proposal, grant, use and ending is recorded in the signed stream, and the audit replays them.

With STEP UP and DEFER, VAREK has four of the five decisions the AARM specification requires (ALLOW, DENY, STEP_UP, DEFER; MODIFY remains the credential swap). AARM's own minimum tests for R1 to R6 run in `mode=hold` in `make test-v1420`. All pass but the two data-flow tests VAREK does not claim (`docs/security/aarm-mapping.md`). That is a claim of partial conformance in VAREK's own reading, not the CSA's evidence package.

The policy grammar moves to 1.42: the new lines need `require warden 1.42`, and an older Warden refuses them (it fails closed). A policy without them decides as before.

> Not reviewed by a human or a third party, or by a separate review pass: the changes were tested as below.

MIT · github.com/kwdoug63/varek

## Summary

- **The grammar and the decision, in both parsers** (#241).
  - **`step_up KIND MATCHERS...`**, with the matchers of `allow` and `deny`. Its options are `mode=grant|hold`, `approvers=GROUP`, `timeout=N`, `scope=thread|run` and `notify=URL`, last on the line. `max_held N` and `max_pending N` bound what a run holds and proposes.
  - **A grant** names its `step_up` line, one or more `allow` rules, a `count`, an `until`, and optionally a run, user or sub-agent. Both parsers read it, and each malformed or overreaching grant is refused by both.
  - **The certificate has two parts:** the policy's half (the `step_up` rule holds) and the grant's half (one of its rules holds, within its count and time). The checker accepts both, or the call is refused.
- **Runtime grants, `mode=grant`** (#242). This is the default.
  - **The proposal:** a call a `step_up` rule decides is refused at once, as UNSATISFIED, and the narrowest grant for it is proposed: the exact object, the call's own access, count 1, until the rule's timeout, for this run.
  - **The answer:** `varek pending` lists what waits, and `varek approve RUN ID [--narrow ...] [--reason ...]` or `varek deny RUN ID` answers it, on the run's approvers' socket (`/run/varek-approve/<run>.sock`). The agent's retry is then allowed under the grant.
  - **Who may answer:** the peer the kernel names (`SO_PEERCRED`). That is a member of the rule's `approvers=` group, or root where the rule names none. The agent's own user is never an approver, and a user sees only the proposals they may answer.
  - **Narrowed, never widened:** an approver may narrow a grant. One whose count, time or scope is wider than the proposal's is refused.
- **Held calls, `mode=hold`** (#243, #244). The call waits for its answer:
  - at the kernel, its seccomp notification unanswered;
  - at the egress proxy, a request or MCP tool call not forwarded.

  When approved, the same call is decided again within the grant. When denied, or past its timeout, it is refused.
  - **`max_held`** refuses one more at once.
  - **A call whose caller is gone** ends `abandoned`.
  - **Signals:** on Linux 5.19 and later, a held call waits through every signal but a fatal one (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`). With libseccomp before 2.6, the Warden loads libseccomp's own program with the flag.
- **`scope=run`** (#245) freezes the run's control group (cgroup v2, `cgroup.freeze`) while a call is held. That covers dependencies across threads that VAREK can't see. Where the run can't be frozen, such a call is refused at once with a proposal, never held: the cause is no delegated cgroup v2, a kernel before 5.19, `--run-as root`, or a policy letting the agent write the control groups.
- **DEFER** (#246, #247).
  - **`defer KIND MATCHERS... until=FILE`** allows the call while its marker passes, and holds it otherwise, until its timeout. A marker must be root-owned (or owned by the rule's approvers), reached without a symbolic link, writable by its owner alone, and must name this run. A policy that lets the agent write the marker is refused at start. With `escalate`, the timeout turns the deferral into a proposal to a person.
  - **`on unknown defer escalate`:** a call no rule names (UNKNOWN) is held and proposed to a person at once, instead of refused. A grant under it is checked to hold where no rule of the policy does.
  - **`on outside_plan defer`:** under `--hold-to-plan`, a call the policy allows but the plan doesn't cover waits for `varek plan extend`. The extension is authorized through the plan gate itself.
- **Signed approvals** (#248).
  - **`approver key=HEX group=GROUP [name=NAME]`** pins an approver's ECDSA P-384 key.
  - **Standing grants** (`varek run --grants DIR`): each one is signed ahead of time by an approver of its rule's group, checked at the start, and recorded with its signer. Any grant that fails the check refuses the start.
  - **Plans:** `varek plan approve PLAN --key KEY` signs a plan, and `--require-approved-plan` runs only a plan so signed.
  - **Runtime approvals:** `varek approve --sign-key KEY` signs the very text approved. A signature adds to who may approve; it never replaces the peer-credential check.
- **The user's request, and a webhook** (#250).
  - **`varek run --intent FILE`** (or `--intent-text TEXT`) records the user's original request in `run_start`: its SHA-256, and its text up to 4 KiB or a file beside the stream. `varek pending` shows it to approvers, and the export carries it. No rule matches on it.
  - **`notify=URL`** posts each proposal of the rule to a webhook (Slack, Teams, a ticketing system) through a new helper, `warden-notify`. The post holds the grant's exact text and nothing of the call beyond its object. It is notification only: a failed post is retried once and recorded, and nothing else depends on it. A record names the URL's host and SHA-256, never the URL, since a Slack URL is a secret.
- **The exports and the documents** (#251).
  - **OCSF:** every v1.42 record is an OCSF event (Application Lifecycle, 6002), with its call, `obo`, policy line and outcome. OpenTelemetry, Splunk, Sentinel and Falcon carry them.
  - **Sentinel** gains a fourth analytics rule, *an approval nobody gave in time*; Splunk gains the fields and a macro.
  - **Documents:** the threat model has trust boundaries 22 (the approvers) and 23 (the webhook), and the trusted computing base and the AARM mapping are brought up to date.
  - **Fixes found writing them:**
    - `varek pending` escapes control and bidirectional characters, so agent text can't redraw an approver's terminal;
    - the webhook's line escapes Slack's mrkdwn;
    - an exported policy line names a `notify=` URL by its host only;
    - a run whose request is over 4 KiB can be exported.
- **The release** (this PR).
  - **`make test-v1420` is complete.** Section 14 adds:
    - order within a process and across processes, and `max_pending`;
    - a signal during a hold;
    - the caller killed, and the Warden stopped or killed, during a hold;
    - 70 approvals in one run;
    - the audit's remaining forgeries.

    Section 15 runs AARM's conformance tests for R1 to R6 in `mode=hold`.
  - **`make latency-v1420`** checks that calls not held are decided no slower than in v1.41.
  - **The shared soak's run D** covers v1.42's approvals.
  - **Three fixes the new tests found:**
    - **The run's live grants never shrank.** At most 64 at once was in effect 64 for the whole run, so a run's 65th approval would have been refused. A grant whose count is used or whose time has passed now leaves them.
    - **The checker read at most 64 grant files a batch,** so a run with more grants couldn't be audited. `vdp_cert_check POLICY batch @LIST` names them in a file, and the audit uses it past 64.
    - **The audit refused two grants with the same text,** as "recorded twice". That happens when two proposals of one call are made within the same second, since a grant's id is the SHA-256 of its text. A second approval of the same text for another open proposal is now one grant, its counts summed. A grant record repeated for its own proposal is still refused.
- **Also in this release:**
  - the 510 TOCTOU figure's run record, committed (#249);
  - the threat model's list of the user's token algorithms, corrected to include v1.41's RS384, PS384 and ES384.

### What changes for a user

| | Before | v1.42.0 |
|---|---|---|
| Decisions | ALLOW, DENY (MODIFY only for credentials) | also STEP_UP and DEFER |
| The policy grammar | 1.35 | 1.42: `require warden 1.42` for the new lines |
| New policy lines | — | `step_up`, `defer`, `on unknown defer escalate`, `on outside_plan defer`, `approver`, `max_held`, `max_pending` |
| `varek` | … | `pending`, `approve`, `deny`, `plan approve`, `plan extend`; `run --intent`, `--intent-text`, `--grants`, `--require-approved-plan` |
| `varek_keygen` | makes keys | also `--sign KIND KEY FILE` and `--verify KIND PUBHEX FILE` |
| Binaries | `warden`, `warden-proxy`, `warden-secrets` | also `warden-notify` (only for `notify=`) |
| Records | … | `step_up`, `step_up_end`, `grant`, `defer`, `defer_end`, `run_frozen`, `run_thawed`, `plan_extended`, `notify`; `run_start`'s `intent`, `scope_run`, `plan_approved_by` |
| Exports | … | the records above as OCSF events; Sentinel's fourth rule; Splunk's fields and `varek_approval_expired` |

**Upgrading:**
- **Nothing changes for a policy without the new lines.** A policy that uses them says `require warden 1.42`, and a Warden before 1.42 refuses it.
- **`make install` installs `warden-notify`.**
  - **Its user:** it runs as the user `varek-notify` where that exists, and otherwise as 65530:65530, never the agent's. For a named user: `useradd --system --no-create-home --shell /sbin/nologin varek-notify`.
  - **A `notify=` URL that carries a secret,** as Slack's does, belongs in a policy the agent can't read.
- **Holds and the freeze need a newer kernel.** For a held call to wait through ordinary signals, and for `scope=run`, the kernel must be Linux 5.19 or later. On RHEL 9's 5.14:
  - a signal ends a held call's wait (`abandoned`);
  - a `scope=run` call is refused at once with a proposal, never held.

  `scope=run` also needs a delegated cgroup v2.
- **Sentinel:** deploy `sentinel-content.json` again for the fourth rule.
- **Splunk:** update the app for the new fields and the macro.

## Tested

- **CI** on every PR (#241 to #251, and this release's PR), x86-64 and arm64, each running every job its files trigger. That includes:
  - the Warden build's suites, with `test-v1420`;
  - the Rocky Linux 9 and Amazon Linux 2023 host suites;
  - the container image's sweep;
  - the node agent's suites;
  - the CRI-O and containerd cells;
  - CodeQL.
- **`make test-v1420`: PASS, 411 checks,** three runs in a row on Linux 6.18, nothing skipped. In order:
  - the grammar in both parsers;
  - the decision and its two-part certificate;
  - runtime grants;
  - holds at the kernel and at the proxy;
  - the freeze;
  - DEFER and its marker, escalation and `on unknown`;
  - `on outside_plan` and `varek plan extend`;
  - signed approvals, standing grants and plan approval;
  - `--intent` and the webhook (a stand-in, over HTTP and HTTPS);
  - the exports of every stream the suite made;
  - order, `max_pending`, signals, the endings, 70 approvals in one run and the audit's remaining forgeries;
  - AARM's conformance tests for R1 to R6, in `mode=hold`.
- **The cross-check** (`tools/smt_crosscheck.py --fuzz-v142`): the shipped policies, then `--fuzz 300` with seeds 1, 2 and 3, which write the v1.42 forms: PASS, 0 disagreements.
- **`make test-cli`:** 264 passed, 1 skipped.
- **Other suites:** `test-v1160`, `test-v1240` (2 skipped), `test-v1260`, `test-v1261`, `test-v1270`, `test-v1271`, `test-v1281`, `test-v1290`, `test-v1310` (1 skipped), `test-v1340` (1 skipped) and `test-v1350` (with `PATH` starting at `/usr/bin` in this container): each PASS. The handoff's pack loop: a short trial, 12 runs, all as expected.
- **Latency** (`make latency-v1420`, recorded in `tests/latency_v1.42.0.txt`): calls not held are decided no slower than in v1.41. Opens allowed, denied by a rule and named by no rule were timed under the v1.41.0 Warden (built from its tag), this one, and this one with `step_up` and `defer` rules that don't fire. Across three runs, with the same policy, the Warden's own time per decision was never more than 1 us slower than v1.41's (p50 40 to 46 us for an allowed open, 11 to 12 us for a refused one). With the rules that don't fire, it was at most 3 us more, within the runs' spread. As the agent sees the call (p50 about 42 to 56 us), the same column moves by up to 9 us from run to run, with no order between the columns. Host: this release's cloud container, not dedicated hardware.
- **The shared soak's six-minute trial,** in the release's container: `soak_check: PASS` (0.1 h, a turn every 3 s). Run D: 120 turns, 120 held reads approved, 120 reads under the standing grant, 12 deferrals refused at their timeout, and its audit passing with 121 grants in the run, past the old limit of 64. Runs A, B and C as before.
- **The 24-hour soak's results follow when it ends.**

## Known limits

- **Decisions VAREK still lacks:**
  - **A general MODIFY:** only the credential swap (v1.28) rewrites a call.
  - **Semantic drift** (AARM R7).
  - **Context across runtime calls**, such as a read of sensitive data refusing a later send. That is v1.11's candidate.
- **Approvers:**
  - **A Unix group only.** Approvers from an identity provider, and approval on Kubernetes, are later work. Under the node agent, `notify=`, `--intent`, `--grants` and `--require-approved-plan` are refused.
  - **The approver can be deceived or coerced.** What they read comes from the agent: the escapes stop it from redrawing their terminal or their channel, not from persuading them. The `step_up` rule bounds what any approval can allow (the threat model, trust boundary 22).
  - **An approver may widen a grant's object** within its `step_up` rule, but not its count, time or scope. The rule is the envelope.
- **Kernels before Linux 5.19:** a signal ends a held call's wait, and `scope=run` calls are refused rather than held.
- **Not tested:**
  - a post to a real Slack or Teams webhook (Teams' Markdown is not escaped);
  - Sentinel's new rule in a real workspace, and Splunk's macro on a real Splunk;
  - `notify=` to `[::1]` at run time;
  - a deferral escalated at the egress proxy (holds at the proxy are tested; deferrals at the kernel);
  - `warden-notify` in the Defense build in FIPS mode.
- **Unchanged from v1.41.0:** the limits in `RELEASE-v1.41.0.md`.
