# SPDX-License-Identifier: MIT
"""v1.40 (docs/security/v1.39-security-operations.md, section 3): the
Microsoft Sentinel export (tools/varek_sentinel.py): an OCSF event as a row of
VarekOCSF_CL, the deployment template's table and rule (integrations/sentinel),
and the export to the Logs Ingestion API, against a stand-in Azure: Entra ID's
token endpoint, an Azure VM's metadata service and the ingestion endpoint."""
import gzip
import http.server
import json
import os
import re
import subprocess
import sys
import threading
import urllib.parse

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_sentinel as sen  # noqa: E402

SENTINEL = os.path.join(HERE, "integrations", "sentinel")
DENIED = {
    "class_uid": 1001, "class_name": "File System Activity", "activity_name": "Open", "type_uid": 100114,
    "type_name": "File System Activity: Open", "time": 1794711677967, "severity_id": 3, "severity": "Medium",
    "action_id": 2, "action": "Denied", "disposition_id": 2, "disposition": "Blocked", "status": "Failure",
    "metadata": {"version": "1.9.0", "uid": "pr-1-122", "correlation_uid": "run1",
                 "product": {"name": "VAREK Warden", "version": "1.39.0"}},
    "device": {"hostname": "build-7"}, "file": {"path": "/etc/shadow"},
    "actor": {"process": {"pid": 333}, "user": {"uid": "alice@example.test"}},
    "ai_agent": {"name": "python3", "type": "Other"},
    "policy": {"name": "p.txt", "uid": "ab" * 32, "desc": "deny  path /etc/shadow"},
    "unmapped": {"varek": {"report_id": "pr-1-122", "seq": 122, "decision": "UNSATISFIED",
                           "decision_final": "DENY", "rule": "policy_match", "policy_line": 91}},
}
SECRET = "s3cret-value-never-printed"


def test_an_ocsf_event_as_a_row():
    r = sen.row(DENIED)
    assert r["TimeGenerated"] == "2026-11-15T03:01:17.967Z"
    assert (r["Decision"], r["Verdict"], r["Rule"], r["PolicyLine"]) == ("DENY", "UNSATISFIED", "policy_match", 91)
    assert r["PolicyText"] == "deny  path /etc/shadow" and r["Target"] == "/etc/shadow"
    assert (r["RunId"], r["ReportId"], r["Seq"], r["Computer"]) == ("run1", "pr-1-122", 122, "build-7")
    assert r["Disposition"] == "Blocked" and r["EventName"] == "varek.decision" and r["WardenVersion"] == "1.39.0"
    assert r["OcsfEvent"] == DENIED                               # nothing the OCSF event says is lost
    ev = json.loads(json.dumps(DENIED))
    ev["unmapped"]["varek"].update(policy_line=-1, rule="default_deny_unknown")
    assert "PolicyLine" not in sen.row(ev)
    audit = {"class_uid": 6002, "time": 1, "metadata": {}, "unmapped": {"varek": {"event": "audit",
                                                                              "audit": {"passed": False}}}}
    a = sen.row(audit)
    assert a["EventName"] == "varek.audit" and a["AuditPassed"] is False and "Decision" not in a
    with pytest.raises(sen.SentinelError):
        sen.row({"time": 1})


def test_the_template_table_rule_and_rows_agree():
    t = json.load(open(os.path.join(SENTINEL, "azuredeploy.json")))
    table = next(r for r in t["resources"] if r["type"].endswith("/tables"))
    dcr = next(r for r in t["resources"] if r["type"] == "Microsoft.Insights/dataCollectionRules")
    tcols = {c["name"]: c["type"] for c in table["properties"]["schema"]["columns"]}
    scols = {c["name"]: c["type"] for c in dcr["properties"]["streamDeclarations"]["Custom-VarekOCSF"]["columns"]}
    assert tcols == scols and table["properties"]["schema"]["name"] == "VarekOCSF_CL"
    assert dcr["properties"]["dataFlows"][0]["outputStream"] == "Custom-VarekOCSF_CL"
    assert dcr["kind"] == "Direct"                                 # its own logs ingestion endpoint
    py = {"string": str, "int": int, "long": int, "boolean": bool, "dynamic": dict}
    for ev in (DENIED, {"class_uid": 6002, "time": 1, "metadata": {},
                        "unmapped": {"varek": {"event": "audit", "audit": {"passed": True}}}}):
        for k, v in sen.row(ev).items():
            assert k in tcols, k
            if tcols[k] in py:
                assert isinstance(v, py[tcols[k]]), (k, v)
    content = json.load(open(os.path.join(SENTINEL, "sentinel-content.json")))
    queries = [r["properties"]["query"] for r in content["resources"] if r.get("kind") == "Scheduled"]
    queries += [i["content"]["query"] for i in content["variables"]["workbook"]["items"] if i["type"] == 3]
    assert len(queries) == 11                                     # 3 analytics rules, the workbook's 8
    made = {"DecidedBy", "Refused", "FirstSeen", "LastSeen", "Targets", "Verdicts", "Problems", "AuditMode",
            "LetThrough", "Decisions", "Runs", "Last", "Count", "Name", "Value", "Column", "Audit", "Start", "End",
            "Policy", "TimeRange", "Run"}                          # the queries' own names
    for q in queries:
        assert "VarekOCSF_CL" in q and not q.startswith("[")      # not an ARM expression
        body = re.sub(r'"[^"]*"', '""', q)                         # strings out
        for name in re.findall(r"\b([A-Z][A-Za-z0-9]+)\b", body):
            assert name in tcols or name in made or name == "VarekOCSF_CL", (name, q)



def test_the_rules_judge_each_row_once_when_it_arrives():
    # v1.40 (Sentinel's live test, November 19, 2026): a rule that looked back
    # 5 minutes by the decision's time raised nothing for a run exported later.
    # Microsoft's pattern for ingestion delay: a longer look-back, and only the
    # rows that arrived since the rule last ran, so each is judged once. Under
    # 2 days: a solution rule that looks back 2 days or more runs hourly at most.
    content = json.load(open(os.path.join(SENTINEL, "sentinel-content.json")))
    rules = [r["properties"] for r in content["resources"] if r.get("kind") == "Scheduled"]
    assert len(rules) == 3
    for r in rules:
        assert r["queryFrequency"] == "PT5M" and r["queryPeriod"] == "P1D", r["displayName"]
        first = r["query"].split("\n")[1]
        assert first == "| where TimeGenerated > ago(1d) and ingestion_time() > ago(5m)", (r["displayName"], first)

def test_batches_and_the_url():
    rows = [{"x": "a" * 100}] * 50
    bs = list(sen.batches(rows, limit=1000))
    assert sum(len(b) for b in bs) == 50 and all(len(json.dumps(b, separators=(",", ":"))) <= 1000 for b in bs)
    assert sen.ingestion_url("https://d-ab12.eastus-1.ingest.monitor.azure.com/", "dcr-0f1e", "Custom-VarekOCSF") == \
        ("https://d-ab12.eastus-1.ingest.monitor.azure.com/dataCollectionRules/dcr-0f1e/streams/Custom-VarekOCSF"
         "?api-version=2023-01-01")
    for bad in ((None, "dcr-1"), ("https://x", None), ("http://x.example", "dcr-1")):
        with pytest.raises(sen.SentinelError):
            sen.ingestion_url(*bad, "s")


class Azure:
    """a stand-in Azure: POST /TENANT/oauth2/v2.0/token (Entra ID), GET /imds
    (an Azure VM's metadata service) and POST .../streams/... (the Logs
    Ingestion API, answering with the next status in `answers`, then 204)"""

    def __init__(self, answers=(), token_status=200, too_big=None):
        self.tokens, self.imds, self.posts = [], [], []
        self.answers, self.token_status, self.too_big, self.issued = list(answers), token_status, too_big, 0
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def reply(self, code, body=None, headers=()):
                self.send_response(code)
                for k, v in headers:
                    self.send_header(k, v)
                data = json.dumps(body).encode() if body is not None else b""
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                p = urllib.parse.urlsplit(self.path)
                outer.imds.append({"query": dict(urllib.parse.parse_qsl(p.query)), "metadata": self.headers.get("Metadata")})
                outer.issued += 1
                self.reply(200, {"access_token": f"mi-token-{outer.issued}", "expires_in": "3600"})

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(n)
                if self.path.endswith("/oauth2/v2.0/token"):
                    outer.tokens.append({"path": self.path, "form": dict(urllib.parse.parse_qsl(raw.decode()))})
                    if outer.token_status != 200:
                        return self.reply(outer.token_status, {"error": "invalid_client",
                                                               "error_description": "AADSTS7000215: bad secret"})
                    outer.issued += 1
                    return self.reply(200, {"access_token": f"token-{outer.issued}", "expires_in": 3599})
                body = json.loads(gzip.decompress(raw)) if self.headers.get("Content-Encoding") == "gzip" else json.loads(raw)
                outer.posts.append({"path": self.path, "auth": self.headers.get("Authorization"), "rows": body})
                if outer.too_big and len(body) > outer.too_big:
                    return self.reply(413, {"error": {"code": "ContentLengthLimitExceeded", "message": "too big"}})
                code = outer.answers.pop(0) if outer.answers else 204
                if code == 204:
                    return self.reply(204)
                self.reply(code, {"error": {"code": "InvalidStream" if code == 400 else "Busy",
                                            "message": "the stream is not declared" if code == 400 else "try later"}},
                           headers=(("Retry-After", "0"),) if code == 429 else ())

            def log_message(self, *a):
                pass

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def rows(self, status_ok=True):
        return [r for p in self.posts for r in p["rows"]]

    def close(self):
        self.srv.shutdown()


def run(az, args, events, env=None):
    e = dict(os.environ, NO_PROXY="127.0.0.1", AZURE_TENANT_ID="tenant-1", AZURE_CLIENT_ID="client-1",
             AZURE_CLIENT_SECRET=SECRET, AZURE_AUTHORITY_HOST=az.base)
    for k in ("AZURE_MONITOR_TOKEN", "AZURE_LOGS_INGESTION_ENDPOINT", "AZURE_DCR_IMMUTABLE_ID"):
        e.pop(k, None)
    e.update(env or {})
    return subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek_sentinel.py"),
                           "--endpoint", az.base, "--dcr", "dcr-0f1e"] + args,
                          input="".join(json.dumps(x) + "\n" for x in events), capture_output=True, text=True,
                          env=e, timeout=60)


def test_rows_reach_the_workspace_with_entra_ids_token():
    az = Azure()
    try:
        r = run(az, ["--batch", "2"], [DENIED] * 5)
        assert r.returncode == 0, r.stderr
        assert "5 rows sent" in r.stderr and "3 request(s)" in r.stderr
        assert az.tokens == [{"path": "/tenant-1/oauth2/v2.0/token", "form": {
            "grant_type": "client_credentials", "client_id": "client-1", "client_secret": SECRET,
            "scope": "https://monitor.azure.com//.default"}}]           # one token, kept
        assert [p["path"] for p in az.posts] == \
            ["/dataCollectionRules/dcr-0f1e/streams/Custom-VarekOCSF?api-version=2023-01-01"] * 3
        assert all(p["auth"] == "Bearer token-1" for p in az.posts)
        assert [x["Decision"] for x in az.rows()] == ["DENY"] * 5 and az.rows()[0]["OcsfEvent"] == DENIED
        assert SECRET not in r.stderr and "token-1" not in r.stderr
    finally:
        az.close()


def test_a_managed_identity_and_a_token_from_the_environment():
    az = Azure()
    try:
        r = run(az, ["--auth", "managed-identity"], [DENIED], {"VAREK_AZURE_IMDS": az.base + "/imds"})
        assert r.returncode == 0, r.stderr
        assert az.imds == [{"query": {"api-version": "2018-02-01", "resource": "https://monitor.azure.com",
                                      "client_id": "client-1"}, "metadata": "true"}]
        assert az.posts[0]["auth"] == "Bearer mi-token-1" and not az.tokens
        r = run(az, ["--auth", "token"], [DENIED], {"AZURE_MONITOR_TOKEN": "had-before"})
        assert r.returncode == 0 and az.posts[-1]["auth"] == "Bearer had-before"
    finally:
        az.close()


def test_busy_too_big_and_expired_are_mended_and_a_refusal_ends_the_export():
    az = Azure(answers=[503, 429])
    try:
        r = run(az, ["--retries", "3"], [DENIED])
        assert r.returncode == 0 and len(az.posts) == 3, r.stderr
    finally:
        az.close()
    az = Azure(too_big=2)                                          # a batch over 2 rows: 413, split
    try:
        r = run(az, [], [DENIED] * 5)
        assert r.returncode == 0, r.stderr
        accepted = [p for p in az.posts if len(p["rows"]) <= 2]
        assert sum(len(p["rows"]) for p in accepted) == 5
    finally:
        az.close()
    az = Azure(answers=[401])                                      # a token gone stale: a new one, once
    try:
        r = run(az, [], [DENIED])
        assert r.returncode == 0 and len(az.tokens) == 2 and az.posts[-1]["auth"] == "Bearer token-2", r.stderr
    finally:
        az.close()
    az = Azure(answers=[400])
    try:
        r = run(az, [], [DENIED, DENIED])
        assert r.returncode == 1 and "HTTP 400" in r.stderr and "InvalidStream" in r.stderr
        assert "0 rows sent before" in r.stderr
    finally:
        az.close()
    az = Azure(answers=[401, 401])
    try:
        r = run(az, [], [DENIED])
        assert r.returncode == 1 and "HTTP 401" in r.stderr
    finally:
        az.close()


def test_credentials_refused_and_arguments_wrong():
    az = Azure(token_status=401)
    try:
        r = run(az, [], [DENIED])
        assert r.returncode == 1 and "no token" in r.stderr and "AADSTS7000215" in r.stderr and not az.posts
        assert SECRET not in r.stderr
    finally:
        az.close()
    az = Azure()
    try:
        r = run(az, [], [DENIED], {"AZURE_CLIENT_SECRET": ""})
        assert r.returncode == 2 and "AZURE_CLIENT_SECRET" in r.stderr
        r = run(az, ["--secret-env", "OTHER_SECRET"], [DENIED])
        assert r.returncode == 2 and "OTHER_SECRET" in r.stderr
        r = run(az, ["--auth", "token"], [DENIED])
        assert r.returncode == 2 and "AZURE_MONITOR_TOKEN" in r.stderr
        r = run(az, [], [{"time": 1}])
        assert r.returncode == 2 and "not an OCSF event" in r.stderr and not az.posts
        r = subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek_sentinel.py"), "--dcr", "d"],
                           input="", capture_output=True, text=True, timeout=30,
                           env={k: v for k, v in os.environ.items() if k != "AZURE_LOGS_INGESTION_ENDPOINT"})
        assert r.returncode == 2 and "no logs ingestion endpoint" in r.stderr
    finally:
        az.close()


VAREK = os.path.join(HERE, "tools", "varek")
BUILT = all(os.access(os.path.join(HERE, b), os.X_OK)
            for b in ("warden", "warden-proxy", "tools/vdp_check", "tools/vdp_cert_check", "tools/varek_keygen"))
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


@pytest.mark.skipif(not (BUILT and ROOT and sys.platform.startswith("linux")),
                    reason="needs Linux, root and a built runtime")
def test_a_refused_secret_is_the_send_failing_not_the_audit(tmp_path):
    # Sentinel's live test (November 16, 2026): Entra ID refused the secret
    # during `varek export --follow`; the reader then died on the closed pipe
    # with a traceback, and the CLI blamed the audit. Now the sender's message
    # stands, the CLI says the send failed, and no traceback follows.
    conf = str(tmp_path / "etc" / "varek.conf")

    def varek(*args, env=None):
        e = dict(os.environ, NO_COLOR="1", VAREK_CONFIG=conf, NO_PROXY="127.0.0.1")
        e.update(env or {})
        return subprocess.run([sys.executable, VAREK, *args], text=True, capture_output=True, env=e, timeout=180)

    assert varek("init", "--pack", "healthcare", "--log-dir", str(tmp_path / "log")).returncode == 0
    assert varek("run", "--", "/bin/sh", "-c", "cat /etc/hostname >/dev/null 2>&1; true").returncode == 0
    log = str(max((tmp_path / "log").glob("verdicts-*.log")))
    az = Azure(token_status=401)
    try:
        azure = {"AZURE_TENANT_ID": "tenant-1", "AZURE_CLIENT_ID": "client-1",
                 "AZURE_CLIENT_SECRET": SECRET, "AZURE_AUTHORITY_HOST": az.base}
        for how in ([log], ["--follow", log]):
            r = varek("export", "--format", "sentinel", *how, "--endpoint", az.base, "--dcr", "dcr-0f1e", env=azure)
            out = r.stdout + r.stderr
            assert r.returncode != 0, out
            assert "AADSTS7000215" in out                      # the sender's own message
            assert "sending the OCSF events of" in out and "failed (the sender exited" in out
            assert "audit refuses" not in out and "Traceback" not in out and "BrokenPipe" not in out
            assert SECRET not in out
        assert az.tokens and not az.posts                      # no row sent without a token
    finally:
        az.close()


def at(pos):
    """DENIED as varek_ocsf.py writes it: the position of its record in the stream"""
    ev = json.loads(json.dumps(DENIED))
    ev["unmapped"]["varek"]["position"] = pos
    return ev


def test_a_failed_send_names_where_the_rows_not_sent_begin():
    # v1.40: the first batch (positions 10, 11) accepted, the second refused
    az = Azure(answers=[204, 400])
    try:
        r = run(az, ["--batch", "2"], [at(p) for p in range(10, 15)])
        assert r.returncode == 1 and "HTTP 400" in r.stderr
        assert "2 rows sent before; those not sent begin at position 12: " \
               "`varek export --from-position 12` sends them" in r.stderr
    finally:
        az.close()
    # a batch too large, split, its first half accepted and its second
    # refused: the batch's first row, so the half accepted is sent again
    # rather than the half refused lost
    az = Azure(too_big=2, answers=[204, 400])
    try:
        r = run(az, ["--batch", "4"], [at(p) for p in range(10, 14)])
        assert r.returncode == 1 and "(0 rows sent before; those not sent begin at position 10" in r.stderr
    finally:
        az.close()
