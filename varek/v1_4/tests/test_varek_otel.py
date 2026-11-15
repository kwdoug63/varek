# SPDX-License-Identifier: MIT
"""v1.39 (docs/security/v1.39-security-operations.md, section 1): the
OpenTelemetry export (tools/varek_otel.py): an OCSF event as an OTLP log
record, and the export to a collector over OTLP/HTTP (a local stand-in)."""
import http.server
import json
import os
import subprocess
import sys
import threading

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_otel as otel  # noqa: E402

DENIED = {
    "class_uid": 1001, "class_name": "File System Activity", "category_uid": 1, "activity_id": 14,
    "activity_name": "Open", "type_uid": 100114, "type_name": "File System Activity: Open",
    "time": 1794711677967, "severity_id": 3, "severity": "Medium",
    "action_id": 2, "action": "Denied", "disposition_id": 2, "disposition": "Blocked",
    "status_id": 2, "status": "Failure",
    "metadata": {"version": "1.9.0", "uid": "pr-1-122", "correlation_uid": "run1",
                 "product": {"name": "VAREK Warden", "version": "1.38.0"}},
    "device": {"hostname": "build-7", "name": "build-7"},
    "file": {"path": "/etc/shadow"},
    "actor": {"process": {"pid": 333}, "user": {"uid": "alice@example.test"}},
    "ai_agent": {"name": "python3", "type": "Other"},
    "policy": {"name": "p.txt", "uid": "ab" * 32, "desc": "deny  path /etc/shadow"},
    "unmapped": {"varek": {"report_id": "pr-1-122", "seq": 122, "decision": "UNSATISFIED", "decision_final": "DENY",
                           "rule": "policy_match", "policy_line": 91}},
}


def attrs(rec):
    return {kv["key"]: list(kv["value"].values())[0] for kv in rec["attributes"]}


def test_a_refusal_is_a_warning_naming_the_policy_line():
    r = otel.log_record(DENIED, observed_ns=5)
    a = attrs(r)
    assert r["timeUnixNano"] == "1794711677967000000" and r["observedTimeUnixNano"] == "5"
    assert r["severityNumber"] == 13 and r["severityText"] == "WARN"           # a level Loki reads
    assert attrs(r)["ocsf.severity"] == "Medium"
    assert r["body"]["stringValue"] == ("Blocked: File System Activity: Open /etc/shadow "
                                        "(policy line 91: deny  path /etc/shadow)")
    assert a["event.name"] == "varek.decision" and a["ocsf.disposition"] == "Blocked"
    assert a["varek.policy.line"] == "91" and a["varek.policy.text"] == "deny  path /etc/shadow"
    assert a["varek.verdict"] == "UNSATISFIED" and a["varek.decision"] == "DENY"
    assert a["varek.report_id"] == "pr-1-122"
    assert a["process.pid"] == "333" and a["user.id"] == "alice@example.test" and a["varek.agent"] == "python3"
    assert json.loads(a["ocsf.event"]) == DENIED                    # nothing the OCSF event says is lost
    assert "ocsf.event" not in attrs(otel.log_record(DENIED, full_event=False))
    assert otel.resource_of(DENIED) == {"service.name": "varek-warden", "service.version": "1.38.0",
                                        "host.name": "build-7", "varek.run": "run1"}


def test_the_default_deny_names_its_rule_and_no_line():
    ev = json.loads(json.dumps(DENIED))
    ev["unmapped"]["varek"].update(policy_line=-1, rule="default_deny_unknown", decision="UNKNOWN")
    ev["policy"].pop("desc")
    r = otel.log_record(ev)
    assert r["body"]["stringValue"].endswith("/etc/shadow (default_deny_unknown)")
    assert "varek.policy.line" not in attrs(r) and attrs(r)["varek.verdict"] == "UNKNOWN"


def test_severities_and_lifecycle_events():
    life = {"class_uid": 6002, "class_name": "Application Lifecycle", "type_name": "Application Lifecycle: Other",
            "time": 1, "severity_id": 4, "severity": "High", "metadata": {},
            "unmapped": {"varek": {"event": "audit", "audit": {"passed": False}}}}
    r = otel.log_record(life)
    assert r["severityNumber"] == 17 and r["severityText"] == "ERROR" and attrs(r)["event.name"] == "varek.audit"
    assert attrs(r)["varek.audit.passed"] is False
    assert [otel.SEVERITY[k][0] for k in (1, 2, 3, 4, 5)] == [9, 10, 13, 17, 21]
    with pytest.raises(otel.OtelError):
        otel.log_record({"time": 1})


def test_one_resource_entry_for_each_run():
    other = json.loads(json.dumps(DENIED))
    other["metadata"]["correlation_uid"] = "run2"
    items = [(otel.resource_of(e), otel.log_record(e)) for e in (DENIED, other, DENIED)]
    p = otel.payload(items)
    assert [len(rl["scopeLogs"][0]["logRecords"]) for rl in p["resourceLogs"]] == [2, 1]
    assert p["resourceLogs"][0]["scopeLogs"][0]["scope"] == {"name": "varek.ocsf", "version": "1.9.0"}


def test_endpoint_and_headers_from_the_environment():
    assert otel.endpoint_from_env({}) == "http://localhost:4318/v1/logs"
    assert otel.endpoint_from_env({"OTEL_EXPORTER_OTLP_ENDPOINT": "https://c:4318/"}) == "https://c:4318/v1/logs"
    assert otel.endpoint_from_env({"OTEL_EXPORTER_OTLP_ENDPOINT": "https://c:4318",
                                   "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "https://l/x"}) == "https://l/x"
    env = {"OTEL_EXPORTER_OTLP_HEADERS": "a=1,b%20c=d%3De", "KEY": "s3cret"}
    assert otel.headers_from(["x-api-key=KEY"], env) == {"a": "1", "b c": "d=e", "x-api-key": "s3cret"}
    for bad in (["x-api-key"], ["x-api-key=MISSING"]):
        with pytest.raises(otel.OtelError):
            otel.headers_from(bad, env)


class Collector:
    """a stand-in OTLP/HTTP receiver: answers each POST with the next status
    in `answers` (then 200), and keeps what it was sent"""

    def __init__(self, answers=(), body=b"{}"):
        self.got, self.answers, self.body = [], list(answers), body
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.got.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                  "body": json.loads(self.rfile.read(n))})
                code = outer.answers.pop(0) if outer.answers else 200
                self.send_response(code)
                if code == 429:
                    self.send_header("Retry-After", "0")
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(outer.body if code == 200 else b"{}")

            def log_message(self, *a):
                pass

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}/v1/logs"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def records(self):
        return [lr for g in self.got for rl in g["body"]["resourceLogs"]
                for sl in rl["scopeLogs"] for lr in sl["logRecords"]]

    def close(self):
        self.srv.shutdown()


def run(args, stdin_lines, env=None):
    return subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek_otel.py")] + args,
                          input="".join(json.dumps(e) + "\n" for e in stdin_lines), capture_output=True,
                          text=True, env=dict(os.environ, **(env or {})), timeout=60)


def test_events_reach_the_collector_in_batches_with_the_header():
    c = Collector()
    try:
        r = run(["-", "--endpoint", c.url, "--batch", "2", "--header", "x-api-key=K"], [DENIED] * 5, {"K": "s3cret"})
        assert r.returncode == 0, r.stderr
        assert "5 records sent" in r.stderr and "3 request(s)" in r.stderr
        assert len(c.records()) == 5 and [g["path"] for g in c.got] == ["/v1/logs"] * 3
        assert all(g["headers"].get("x-api-key") == "s3cret" for g in c.got)
        assert all(g["headers"].get("content-type") == "application/json" for g in c.got)
        assert "s3cret" not in r.stderr
    finally:
        c.close()


def test_a_busy_collector_is_tried_again_and_a_refusal_ends_the_export():
    c = Collector(answers=[503, 429])
    try:
        r = run(["--endpoint", c.url, "--retries", "3"], [DENIED])
        assert r.returncode == 0 and len(c.got) == 3 and len(c.records()) == 3     # sent three times, kept once
    finally:
        c.close()
    c = Collector(answers=[400])
    try:
        r = run(["--endpoint", c.url], [DENIED])
        assert r.returncode == 1 and "HTTP 400" in r.stderr
    finally:
        c.close()
    c = Collector(body=b'{"partialSuccess":{"rejectedLogRecords":1,"errorMessage":"too big"}}')
    try:
        r = run(["--endpoint", c.url], [DENIED, DENIED])
        assert r.returncode == 1 and "rejected 1 of 2" in r.stderr and "too big" in r.stderr
    finally:
        c.close()


def test_input_that_is_not_ocsf_is_refused():
    c = Collector()
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek_otel.py"), "--endpoint", c.url],
                           input="not json\n", capture_output=True, text=True, timeout=30)
        assert r.returncode == 2 and "line 1 is not JSON" in r.stderr and not c.got
        r = run(["--endpoint", c.url], [{"time": 1}])
        assert r.returncode == 2 and "not an OCSF event" in r.stderr
        r = run(["--endpoint", "ftp://x/v1/logs"], [DENIED])
        assert r.returncode == 2
    finally:
        c.close()
