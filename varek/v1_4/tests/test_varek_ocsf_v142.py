# SPDX-License-Identifier: MIT
"""v1.42 step 8 (docs/security/v1.42-step-up-defer.md): the records of
approvals, deferrals, the freeze and the approvers' webhook in the OCSF export
(tools/varek_ocsf.py) and the exports built on it (OpenTelemetry, Splunk,
Sentinel, Falcon), and Sentinel's rule for an approval nobody gave in time.
The records here have the Warden's shapes (warden_grant.inc.c,
warden_signed.inc.c, warden_notify.inc.c); test_v1420.sh section 13 exports
the Warden's own streams, audited."""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ocsf_validate  # noqa: E402
import varek_falcon as fal  # noqa: E402
import varek_ocsf as ocsf  # noqa: E402
import varek_otel as otel  # noqa: E402
import varek_sentinel as sen  # noqa: E402
import varek_splunk as spl  # noqa: E402

RUN = "run-v142"
T0 = 1795669995000000000
URL_SHA = "5b3b12d0e1d34684d84c9b49e7416803dd357bccbf46b828f5adae55cf8924ea"
KEY = "04" + "ab" * 96
POLICY = "\n".join([
    "require warden 1.42",                                          # 1
    "allow path /usr/lib/ readonly",                                # 2
    "approver key=" + KEY + " group=ops name=ops1",                 # 3
    "allow path /etc/ readonly",                                    # 4
    "allow exec /bin/bash",                                         # 5
    "allow path /w/bin/ readonly",                                  # 6
    "on unknown defer escalate timeout=20",                         # 7
    "defer path /w/m/ until=/w/m/ok timeout=20 scope=run",          # 8
    "step_up path /w/data/ timeout=30 approvers=ops notify=https://hooks.example.test/T0/B0/s3cret",  # 9
    "step_up path /w/out/ mode=hold timeout=2",                     # 10
    "",
])

t = iter(range(1, 10000))


def ts():
    return T0 + next(t) * 1000000


def dec(seq, action, target, final="ALLOW", pid=7, obo=("agent",), **k):
    r = {"report_id": f"pr-{seq}", "run": RUN, "seq": seq, "agent_pid": pid, "obo": list(obo), "action": action,
         "target": target, "resolved": target, "decision_raw": "ALLOW" if final == "ALLOW" else "UNSATISFIED",
         "decision_final": final, "rule": "resolved_fd_injection" if final == "ALLOW" else "policy_match",
         "policy_line": k.pop("policy_line", 9), "kernel_verdict": "ALLOW" if final == "ALLOW" else "EACCES",
         "errno": 0 if final == "ALLOW" else 13, "timestamp_ns": ts(), "chain": f"c{seq}"}
    r.update(k)
    return r


def ev(event, **k):
    r = {"event": event, "run": RUN}
    r.update(k)
    r["timestamp_ns"] = ts()
    r["chain"] = f"x{next(t)}"
    return r


GRANT_TEXT = "grant\nstep_up line 9\nallow path exact /w/data/r.csv readonly\nfor run=run-v142\ncount 1\n"
STANDING_TEXT = "grant\nstep_up line 9\nallow path exact /w/data/s.csv readonly\ncount 2\nuntil 2026-12-01T00:00:00Z\n"
SUB = ("user", "agent", "subagent:fetch#1")


def records():
    return [
        {"event": "run_start", "run": RUN, "warden": "1.42.0", "policy_sha256": None, "log": "chain-2",
         "intent": {"sha256": "02" * 32, "bytes": 22, "text": "Review r.csv, résumé"},
         "scope_run": {"freeze": True, "cgroup": "/varek-run-v142"},
         "notify": {"helper_sha256": "d2" * 32, "uid": 65530, "gid": 65530},
         "plan_approved_by": {"key": KEY, "name": "ops1", "group": "ops", "sig": "30", "plan_sha256": "72" * 32},
         "timestamp_ns": T0, "chain": "c-start"},
        ev("grant", id="9e" * 32, standing=True, file="a.grant",
           signed_by={"key": KEY, "name": "ops1", "group": "ops"}, sig="3064", text=STANDING_TEXT),
        # mode=grant: refused, with a proposal; the webhook told; approved; the retry allowed under the grant
        dec(0, "file.open", "/w/data/r.csv", "DENY", step_up="p1"),
        ev("step_up", id="p1", decision_seq=0, mode="grant", state="proposed", rule_line=9, timeout=30,
           approvers="ops", proposal=GRANT_TEXT),
        ev("notify", id="p1", rule_line=9, outcome="sent", host="hooks.example.test", url_sha256=URL_SHA, status=200,
           attempts=1),
        ev("grant", id="6e" * 32, proposal="p1", approver_uid=1001, approver="alice", approvers="ops",
           reason="the review", signed_by={"key": KEY, "name": "ops1", "group": "ops"}, sig="3065", text=GRANT_TEXT),
        ev("step_up_end", id="p1", ending="approved", grant="6e" * 32, approver_uid=1001, approver="alice",
           reason="the review"),
        dec(1, "file.open", "/w/data/r.csv", cert_rule=7, cert_witness="-", check="ok", cert_grant="6e" * 32,
            cert_grant_rule=0, cert_grant_witness="-"),
        # mode=hold, a sub-agent's call: held, nobody answers, refused at the timeout
        dec(2, "file.stat", "/w/bin/one.sh", pid=9, obo=SUB, policy_line=6),
        ev("step_up", id="p2", mode="hold", state="held", rule_line=10, timeout=2, approvers="", agent_pid=9,
           action="file.open", resolved="/w/out/o.txt", proposal="grant\nstep_up line 10\n", held=1, scope="thread"),
        ev("step_up_end", id="p2", ending="timeout"),
        dec(3, "file.open", "/w/out/o.txt", "DENY", pid=9, obo=SUB, policy_line=10, step_up="p2", held=True),
        # a deferral its marker resolves, the run frozen meanwhile
        ev("defer", id="d1", state="held", rule_line=8, until="/w/m/ok", timeout=20, scope="run", escalate=False,
           agent_pid=7, action="file.open", resolved="/w/m/x", held=1),
        ev("run_frozen", step_up="d1", cgroup="/varek-run-v142"),
        ev("defer_end", id="d1", ending="resolved", marker_sha256="33" * 32),
        ev("run_thawed", frozen_ms=1002, cgroup="/varek-run-v142"),
        dec(4, "file.open", "/w/m/x", policy_line=8, cert_rule=6, cert_witness="-", check="ok", cert_defer=True,
            defer_marker={"path": "/w/m/ok", "sha256": "33" * 32}, defer="d1"),
        # on unknown: escalated at once, then denied
        ev("defer", id="d2", unknown=True, state="held", rule_line=7, until="", timeout=20, scope="thread",
           escalate=True, agent_pid=7, action="file.open", resolved="/dev/tty", held=1),
        ev("defer_end", id="d2", ending="escalated", step_up="p3"),
        ev("step_up", id="p3", mode="hold", state="held", rule_line=7, timeout=20, approvers="", agent_pid=7,
           action="file.open", resolved="/dev/tty", proposal="grant\n", held=1, scope="thread", defer="d2"),
        ev("step_up_end", id="p3", ending="denied", approver_uid=0, approver="root"),
        dec(5, "file.open", "/dev/tty", "DENY", policy_line=7, step_up="p3", held=True),
        # outside the plan: a plan extension, through the plan gate
        ev("defer", id="d3", outside_plan=True, state="held", rule_line=6, until="", timeout=20, scope="thread",
           escalate=False, agent_pid=7, action="file.open", resolved="/w/bin/two.sh", held=1),
        ev("plan_extended", sha256="c4" * 32, actions=1, verdict="SATISFIED", entries=1, approver_uid=0,
           approver="root"),
        ev("defer_end", id="d3", ending="resolved", plan_extension="c4" * 32),
        # a deferral timed out, a webhook failed, an approval abandoned at the run's end
        ev("defer", id="d4", state="held", rule_line=8, until="/w/m/ok", timeout=2, scope="thread", escalate=False,
           agent_pid=7, action="file.open", resolved="/w/m/y", held=1),
        ev("defer_end", id="d4", ending="timeout"),
        dec(6, "file.open", "/w/data/q.csv", "DENY", step_up="p4"),
        ev("step_up", id="p4", decision_seq=6, mode="grant", state="proposed", rule_line=9, timeout=30,
           approvers="ops", proposal="grant\n"),
        ev("notify", id="p4", rule_line=9, outcome="failed", host="hooks.example.test", url_sha256=URL_SHA,
           status=500, attempts=2, why="HTTP 500"),
        ev("step_up_end", id="p4", ending="abandoned"),
        {"event": "run_end", "run": RUN, "records": 7, "exit_status": 0, "timestamp_ns": ts(), "chain": "c-end"},
    ]


def exported(tmp_path):
    pol = tmp_path / "p.txt"
    pol.write_text(POLICY)
    ex = ocsf.Exporter(str(pol), "node-1")
    out = []
    for r in records():
        out += ex.feed(r)
    return out + ex.finish()


def by(evs, name):
    return [e for e in evs if e["unmapped"]["varek"].get("event") == name]


def test_every_record_is_an_event_and_valid_ocsf(tmp_path):
    evs = exported(tmp_path)
    assert len(evs) == len(records())                             # none dropped, none folded
    ck = ocsf_validate.Checker()
    for e in evs:
        assert ck.event(e) == [], (e["unmapped"]["varek"].get("event"), ck.event(e))
    for name in ocsf.V142_EVENTS:
        assert by(evs, name), name
        for e in by(evs, name):                                   # Application Lifecycle, Other
            assert (e["class_uid"], e["activity_id"], e["type_uid"]) == (6002, 99, 600299)
            assert e["metadata"]["correlation_uid"] == RUN and e["unmapped"]["varek"]["chain"]
            assert e["message"]
    assert [e["unmapped"]["varek"]["position"] for e in evs] == list(range(1, len(evs) + 1))


def test_the_outcomes(tmp_path):
    evs = exported(tmp_path)
    got = {(e["unmapped"]["varek"]["event"], e["unmapped"]["varek"].get("state") or
            e["unmapped"]["varek"].get("ending") or (e["unmapped"]["varek"].get("notify") or {}).get("outcome")):
           (e.get("disposition"), e.get("status"), e["severity"]) for e in evs if e["unmapped"]["varek"].get("event")
           in ocsf.V142_EVENTS}
    assert got[("step_up", "proposed")] == ("Challenge", None, "Informational")
    assert got[("step_up", "held")] == ("Delayed", None, "Informational")
    assert got[("step_up_end", "approved")] == ("Approved", "Success", "Informational")
    assert got[("step_up_end", "denied")] == ("Rejected", "Failure", "Informational")
    assert got[("step_up_end", "timeout")] == ("Blocked", "Failure", "Low")
    assert got[("step_up_end", "abandoned")] == ("No Action", "Failure", "Informational")
    assert got[("defer", "held")] == ("Delayed", None, "Informational")
    assert got[("defer_end", "resolved")] == (None, "Success", "Informational")
    assert got[("defer_end", "escalated")] == ("Challenge", "Other", "Informational")
    assert got[("defer_end", "timeout")] == ("Blocked", "Failure", "Low")
    assert got[("notify", "sent")] == (None, "Success", "Informational")
    assert got[("notify", "failed")] == (None, "Failure", "Low")
    assert got[("grant", None)] == ("Approved", "Success", "Informational")
    assert got[("plan_extended", None)] == ("Approved", "Success", "Informational")
    end = [e for e in by(evs, "step_up_end") if e["unmapped"]["varek"]["ending"] == "timeout"][0]
    rs = records()                                                 # its wait, from the hold's record to its end's
    t0 = [r for r in rs if r.get("event") == "step_up" and r["id"] == "p2"][0]["timestamp_ns"]
    t1 = [r for r in rs if r.get("event") == "step_up_end" and r["id"] == "p2"][0]["timestamp_ns"]
    assert end["duration"] == (t1 - t0) // 1000000 > 0 and end["status_detail"].startswith("timeout")
    assert by(evs, "run_thawed")[0]["duration"] == 1002


def test_each_carries_its_call_its_obo_and_its_policy_line(tmp_path):
    evs = exported(tmp_path)
    held = [e for e in by(evs, "step_up") if e["unmapped"]["varek"]["step_up"] == "p2"][0]
    v = held["unmapped"]["varek"]
    # the held call's record names its process; the obo is its process's (the sub-agent's)
    assert v["obo"] == list(SUB) and held["ai_agent"]["name"] == "fetch" and held["ai_agent"]["type"] == "sub_agent"
    assert held["actor"]["process"]["pid"] == 9 and v["object"] == "/w/out/o.txt" and v["call_action"] == "file.open"
    assert v["policy_line"] == 10 and held["policy"]["desc"] == "step_up path /w/out/ mode=hold timeout=2"
    assert v["rule"] == "step_up" and v["step_up_mode"] == "hold" and v["scope"] == "thread"
    end = [e for e in by(evs, "step_up_end") if e["unmapped"]["varek"]["step_up"] == "p2"][0]
    assert end["unmapped"]["varek"]["obo"] == list(SUB) and end["unmapped"]["varek"]["object"] == "/w/out/o.txt"
    assert end["unmapped"]["varek"]["policy_line"] == 10
    # a proposal in mode=grant: its call is the refused decision before it
    prop = [e for e in by(evs, "step_up") if e["unmapped"]["varek"]["step_up"] == "p1"][0]
    assert prop["unmapped"]["varek"]["decision_seq"] == 0 and prop["unmapped"]["varek"]["object"] == "/w/data/r.csv"
    assert prop["unmapped"]["varek"]["proposal"] == GRANT_TEXT and prop["unmapped"]["varek"]["approvers"] == "ops"
    rules = {e["unmapped"]["varek"]["defer"]: e["unmapped"]["varek"]["rule"] for e in by(evs, "defer")}
    assert rules == {"d1": "defer", "d2": "on_unknown", "d3": "outside_plan", "d4": "defer"}
    assert [e["unmapped"]["varek"]["rule"] for e in by(evs, "defer_end")] == ["defer", "on_unknown", "outside_plan",
                                                                             "defer"]
    fr = by(evs, "run_frozen")[0]["unmapped"]["varek"]
    assert fr["defer"] == "d1" and fr["object"] == "/w/m/x" and "step_up" not in fr


def test_grants_and_approvals_name_the_approver(tmp_path):
    evs = exported(tmp_path)
    g = [e for e in by(evs, "grant") if not e["unmapped"]["varek"].get("standing")][0]
    assert g["actor"] == {"user": {"uid": "1001", "uid_numeric": 1001, "name": "alice", "type_id": 1, "type": "User",
                                   "groups": [{"name": "ops"}]}}
    v = g["unmapped"]["varek"]
    assert v["grant_text"] == GRANT_TEXT and v["step_up"] == "p1" and v["signed_by"]["name"] == "ops1"
    assert v["sig"] == "3065" and v["reason"] == "the review" and v["object"] == "/w/data/r.csv"
    s = [e for e in by(evs, "grant") if e["unmapped"]["varek"].get("standing")][0]
    assert s["actor"]["user"]["name"] == "ops1" and s["actor"]["user"]["uid"] == KEY
    assert s["unmapped"]["varek"]["file"] == "a.grant" and "obo" not in s["unmapped"]["varek"]
    ok = [e for e in by(evs, "step_up_end") if e["unmapped"]["varek"]["ending"] == "approved"][0]
    assert ok["actor"]["user"]["name"] == "alice" and ok["unmapped"]["varek"]["grant"] == "6e" * 32
    assert ok["message"] == "approved by alice: /w/data/r.csv"
    pe = by(evs, "plan_extended")[0]
    assert pe["actor"]["user"]["name"] == "root" and pe["unmapped"]["varek"]["plan_extension"]["entries"] == 1


def test_decisions_name_their_grant_marker_and_proposal(tmp_path):
    evs = exported(tmp_path)
    d = {e["unmapped"]["varek"].get("seq"): e["unmapped"]["varek"] for e in evs if "seq" in e["unmapped"]["varek"]}
    assert d[1]["grant"] == "6e" * 32 and d[1]["certificate"]["grant"] == {"id": "6e" * 32, "rule": 0, "witness": "-"}
    assert d[4]["certificate"]["defer"] is True and d[4]["defer_marker"]["sha256"] == "33" * 32 and d[4]["defer"] == "d1"
    assert d[0]["step_up"] == "p1" and d[3]["step_up"] == "p2" and d[3]["held"] is True


def test_run_start_carries_the_request_and_the_approvals(tmp_path):
    rs = by(exported(tmp_path), "run_start")[0]["unmapped"]["varek"]
    assert rs["intent"] == {"sha256": "02" * 32, "bytes": 22, "text": "Review r.csv, résumé"}
    assert rs["scope_run"]["freeze"] is True and rs["plan_approved_by"]["name"] == "ops1"
    assert rs["notify_helper"]["uid"] == 65530


def test_the_webhooks_url_is_nowhere(tmp_path):
    evs = exported(tmp_path)
    blob = "\n".join(ocsf.dumps(e) for e in evs)
    assert "s3cret" not in blob and "hooks.example.test/T0" not in blob     # only its host and SHA-256
    n = by(evs, "notify")[0]["unmapped"]["varek"]["notify"]
    assert n == {"outcome": "sent", "host": "hooks.example.test", "url_sha256": URL_SHA, "status": 200, "attempts": 1}
    assert by(evs, "notify")[1]["status_code"] == "500"
    # the policy line's text, in every event decided under it, names the webhook's host only
    prop = [e for e in by(evs, "step_up") if e["unmapped"]["varek"]["step_up"] == "p1"][0]
    assert prop["policy"]["desc"] == "step_up path /w/data/ timeout=30 approvers=ops notify=https://hooks.example.test/..."
    assert ocsf._no_webhook_url("step_up path /a/ notify=http://127.0.0.1:8080/h?k=1") == \
        "step_up path /a/ notify=http://127.0.0.1:8080/..."


def test_the_exports_built_on_it(tmp_path):
    evs = exported(tmp_path)
    end = [e for e in by(evs, "step_up_end") if e["unmapped"]["varek"]["ending"] == "timeout"][0]
    r = sen.row(end)
    assert r["EventName"] == "varek.step_up_end" and r["Target"] == "/w/out/o.txt" and r["PolicyLine"] == 10
    assert r["Agent"] == "fetch" and r["Disposition"] == "Blocked" and r["Rule"] == "step_up" and r["RunId"] == RUN
    lr = otel.log_record(end)
    attrs = {a["key"]: a["value"] for a in lr["attributes"]}
    assert attrs["event.name"] == {"stringValue": "varek.step_up_end"}
    assert attrs["varek.target"] == {"stringValue": "/w/out/o.txt"}
    assert "Blocked:" in lr["body"]["stringValue"] and "policy line 10" in lr["body"]["stringValue"]
    h = spl.hec_event(end)
    assert h["event"] == end and h["fields"]["varek_run"] == RUN
    assert fal.event_of(end) is not None
    for e in evs:                                                 # each one goes through each export
        sen.row(e), otel.log_record(e), spl.hec_event(e), fal.event_of(e)


def kql_expired(rows):
    """Sentinel's rule for an approval nobody gave in time, as its query
    filters (sentinel-content.json; its own test checks the text)"""
    return [r for r in rows if r.get("EventName") in ("varek.step_up_end", "varek.defer_end")
            and str(r["OcsfEvent"]["unmapped"]["varek"].get("ending")) == "timeout"]


def test_sentinels_rule_for_an_approval_nobody_gave(tmp_path):
    rows = [sen.row(e) for e in exported(tmp_path)]
    hit = kql_expired(rows)
    assert [r["Target"] for r in hit] == ["/w/out/o.txt", "/w/m/y"]   # the approval and the deferral timed out
    content = json.load(open(os.path.join(HERE, "integrations", "sentinel", "sentinel-content.json")))
    rule = [r["properties"] for r in content["resources"] if r.get("kind") == "Scheduled"
            and r["properties"]["displayName"] == "VAREK: an approval nobody gave in time"][0]
    q = rule["query"]
    assert 'EventName in ("varek.step_up_end", "varek.defer_end")' in q
    assert 'tostring(OcsfEvent.unmapped.varek.ending) == "timeout"' in q
    # the columns it reads are in each row it matches
    for col in ("RunId", "Computer", "Agent", "PolicyLine", "PolicyText", "PolicyName", "Rule", "Target",
                "TimeGenerated"):
        assert col in q and all(col in r for r in hit), col
    assert rule["severity"] == "Medium" and rule["incidentConfiguration"]["createIncident"] is True


def test_the_request_file_beside_the_stream_goes_with_its_copy(tmp_path):
    log = tmp_path / "n2.log"
    log.write_text(json.dumps({"event": "run_start", "run": RUN, "intent": {"sha256": "5f" * 32, "bytes": 3,
                                                                             "file": "n2.log.intent"}}) + "\n")
    (tmp_path / "n2.log.intent").write_text("abc")
    cp, d = ocsf.private_copy(str(log))
    try:
        assert open(os.path.join(d, "n2.log.intent")).read() == "abc"
    finally:
        import shutil
        shutil.rmtree(d)
    log.write_text(json.dumps({"event": "run_start", "run": RUN, "intent": {"file": "../etc/passwd"}}) + "\n")
    cp, d = ocsf.private_copy(str(log))
    try:
        assert sorted(os.listdir(d)) == ["stream.log"]           # a name that is not one beside it: not copied
    finally:
        import shutil
        shutil.rmtree(d)
    assert re.fullmatch(r"[0-9a-f]{64}", URL_SHA)
