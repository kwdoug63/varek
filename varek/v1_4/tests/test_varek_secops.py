# SPDX-License-Identifier: MIT
"""v1.44 (docs/security/v1.39-security-operations.md, section 6): the Google
Security Operations export (tools/varek_secops.py): an OCSF event as a UDM
event, and the export to the Chronicle API's events:import, against a stand-in
Google: a Compute Engine VM's metadata server, the OAuth token endpoint a
service account's key file names, and the instance's events:import."""
import base64
import http.server
import json
import os
import subprocess
import sys
import threading
import urllib.parse

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_secops as so  # noqa: E402

TOOL = os.path.join(HERE, "tools", "varek_secops.py")


def ocsf(cls, act, **parts):
    """an OCSF event as tools/varek_ocsf.py writes it, its class and activity
    and the parts given"""
    names = {1001: "File System Activity", 1007: "Process Activity", 4001: "Network Activity",
             4002: "HTTP Activity", 4003: "DNS Activity", 6002: "Application Lifecycle", 6003: "API Activity"}
    ev = {"class_uid": cls, "class_name": names[cls], "activity_id": act, "activity_name": "Act",
          "type_uid": cls * 100 + act, "type_name": f"{names[cls]}: Act", "time": 1794711677967,
          "severity_id": 3, "severity": "Medium", "action_id": 2, "action": "Denied",
          "disposition_id": 2, "disposition": "Blocked", "status": "Failure",
          "metadata": {"version": "1.9.0", "uid": "pr-1-122", "correlation_uid": "run1",
                       "product": {"name": "VAREK Warden", "version": "1.43.0"}},
          "device": {"hostname": "build-7"},
          "actor": {"process": {"pid": 333}, "user": {"uid": "alice@example.test"}},
          "ai_agent": {"name": "python3", "type": "Other"},
          "policy": {"name": "p.txt", "uid": "ab" * 32, "desc": "deny  path /etc/shadow"},
          "unmapped": {"varek": {"report_id": "pr-1-122", "seq": 122, "decision": "UNSATISFIED",
                                 "decision_final": "DENY", "rule": "policy_match", "policy_line": 91,
                                 "position": 12}}}
    ev.update(parts)
    return ev


DENIED = ocsf(1001, 14, file={"path": "/etc/shadow", "name": "shadow"})


def test_a_refused_open_as_a_udm_event():
    u = so.udm(DENIED)
    m = u["metadata"]
    assert m["event_type"] == "FILE_OPEN" and m["event_timestamp"] == "2026-11-15T03:01:17.967Z"
    assert (m["vendor_name"], m["product_name"], m["product_version"]) == \
        ("Sober Agentic Infrastructure", "VAREK", "1.43.0")
    assert m["product_event_type"] == "File System Activity: Act" and m["product_log_id"] == "run1/12"
    assert m["description"] == "Blocked: File System Activity: Act /etc/shadow (policy line 91: deny  path /etc/shadow)"
    assert u["principal"] == {"hostname": "build-7", "application": "python3", "process": {"pid": "333"},
                              "user": {"userid": "alice@example.test"}}
    assert u["target"] == {"file": {"full_path": "/etc/shadow"}}
    assert u["security_result"] == [{"action": ["BLOCK"], "rule_name": "policy line 91", "rule_id": "91",
                                     "summary": "deny  path /etc/shadow", "severity": "MEDIUM",
                                     "description": "VAREK verdict UNSATISFIED: DENY by policy_match"}]
    a = u["additional"]
    assert {k: a[k] for k in ("varek_decision", "varek_verdict", "varek_rule", "varek_policy_line",
                              "varek_policy_name", "varek_policy_sha256", "varek_run", "varek_agent",
                              "varek_position")} == \
        {"varek_decision": "DENY", "varek_verdict": "UNSATISFIED", "varek_rule": "policy_match",
         "varek_policy_line": "91", "varek_policy_name": "p.txt", "varek_policy_sha256": "ab" * 32,
         "varek_run": "run1", "varek_agent": "python3", "varek_position": "12"}
    assert json.loads(a["ocsf_event"]) == DENIED                  # nothing the OCSF event says is lost
    assert all(isinstance(v, str) for v in a.values())            # the rules read strings
    with pytest.raises(so.SecOpsError):
        so.udm({"time": 1})


def test_each_ocsf_class_its_event_type():
    cases = [
        (ocsf(1001, 14, file={"path": "/f"}), "FILE_OPEN", {"file": {"full_path": "/f"}}),
        (ocsf(1001, 1, file={"path": "/f"}), "FILE_CREATION", {"file": {"full_path": "/f"}}),
        (ocsf(1001, 3, file={"path": "/f"}), "FILE_MODIFICATION", {"file": {"full_path": "/f"}}),
        (ocsf(1001, 6, file={"path": "/f"}), "FILE_MODIFICATION", {"file": {"full_path": "/f"}}),
        (ocsf(1001, 4, file={"path": "/f"}), "FILE_DELETION", {"file": {"full_path": "/f"}}),
        (ocsf(1001, 2, file={"path": "/f"}), "FILE_READ", {"file": {"full_path": "/f"}}),
        (ocsf(1001, 8, file={"path": "/f"}), "GENERIC_EVENT", {"file": {"full_path": "/f"}}),   # a stat
        (ocsf(1007, 1, process={"pid": 444, "name": "curl", "file": {"path": "/usr/bin/curl"}}),
         "PROCESS_LAUNCH", {"process": {"pid": "444", "file": {"full_path": "/usr/bin/curl"}}}),
        (ocsf(4001, 1, dst_endpoint={"hostname": "api.example.test", "port": 443}),
         "NETWORK_CONNECTION", {"hostname": "api.example.test", "port": 443}),
        (ocsf(4001, 5, dst_endpoint={"ip": "10.0.0.9", "port": 22}),
         "NETWORK_CONNECTION", {"ip": ["10.0.0.9"], "port": 22}),
        (ocsf(4002, 6, http_request={"http_method": "POST", "url": {
            "url_string": "https://api.example.test:443/v1/x", "hostname": "api.example.test", "port": 443}},
            dst_endpoint={"hostname": "api.example.test", "port": 443}),
         "NETWORK_HTTP", {"hostname": "api.example.test", "port": 443, "url": "https://api.example.test:443/v1/x"}),
        (ocsf(4003, 1, query={"hostname": "evil.example.test"}), "GENERIC_EVENT",
         {"resource": {"name": "evil.example.test"}}),
        (ocsf(6003, 99, api={"operation": "tools/call", "service": {"name": "http://127.0.0.1:9/mcp"}}),
         "GENERIC_EVENT", {"url": "http://127.0.0.1:9/mcp", "resource": {"name": "tools/call"}}),
        (ocsf(1007, 99, process={"pid": 333}), "GENERIC_EVENT", {"process": {"pid": "333"}}),   # a syscall
    ]
    for ev, etype, target in cases:
        u = so.udm(ev)
        assert u["metadata"]["event_type"] == etype, (ev["class_uid"], ev["activity_id"])
        assert u["target"] == target, (etype, u["target"])
    http_ev = so.udm(cases[10][0])
    assert http_ev["network"] == {"http": {"method": "POST"}}


def test_an_event_without_its_noun_is_a_generic_event():
    # UDM refuses an event type whose required nouns are missing (G4)
    for ev in (ocsf(1001, 14, file={"path": ""}), ocsf(1001, 14),
               ocsf(1007, 1, process={"pid": 0, "name": "x"}),
               ocsf(4001, 1, dst_endpoint={"name": "unknown"}),
               ocsf(1001, 14, file={"path": "/f"}, device={})):          # no principal
        assert so.udm(ev)["metadata"]["event_type"] == "GENERIC_EVENT", ev


def test_severities_a_dry_run_an_allowed_call_and_audits():
    dry = ocsf(1001, 14, file={"path": "/f"}, disposition="Detected", disposition_id=15)
    dry["unmapped"]["varek"]["mode"] = "dry_run"
    s = so.udm(dry)["security_result"][0]
    assert s["action"] == ["ALLOW"] and s["severity"] == "INFORMATIONAL"      # let through, not enforced
    assert "dry run" in s["description"] and so.udm(dry)["additional"]["varek_mode"] == "dry_run"
    ok = ocsf(1001, 14, file={"path": "/f"})
    ok["unmapped"]["varek"].update(decision="SATISFIED", decision_final="ALLOW")
    assert so.udm(ok)["security_result"][0]["action"] == ["ALLOW"]
    assert so.udm(ok)["security_result"][0]["severity"] == "INFORMATIONAL"
    unk = ocsf(1001, 14, file={"path": "/f"})
    unk["unmapped"]["varek"].update(policy_line=-1, rule="default_deny_unknown", decision="UNKNOWN")
    s = so.udm(unk)["security_result"][0]
    assert s["rule_name"] == "default_deny_unknown" and "rule_id" not in s
    assert "varek_policy_line" not in so.udm(unk)["additional"]
    failed = {"class_uid": 6002, "class_name": "Application Lifecycle", "activity_id": 99, "time": 1794711677967,
              "severity_id": 4, "metadata": {"correlation_uid": "run1"}, "device": {"hostname": "build-7"},
              "unmapped": {"varek": {"event": "audit", "audit": {"passed": False}, "position": 40}}}
    u = so.udm(failed)
    assert u["metadata"]["event_type"] == "GENERIC_EVENT" and u["security_result"][0]["severity"] == "HIGH"
    assert u["additional"]["varek_audit_passed"] == "false" and u["additional"]["varek_event"] == "audit"
    failed["unmapped"]["varek"]["audit"]["passed"] = True
    assert so.udm(failed)["security_result"][0]["severity"] == "INFORMATIONAL"


def test_the_url_the_body_and_batches():
    assert so.import_url("varek-gke-test", "us", "0f1e-2d3c") == (
        "https://us-chronicle.googleapis.com/v1alpha/projects/varek-gke-test/locations/us"
        "/instances/0f1e-2d3c/events:import")
    assert so.import_url("p", "europe", "c", "v1beta").startswith(
        "https://europe-chronicle.googleapis.com/v1beta/projects/p/locations/europe/")
    for bad in ((None, "us", "c"), ("p", "us", None), ("p", None, "c")):
        with pytest.raises(so.SecOpsError):
            so.import_url(*bad)
    with pytest.raises(so.SecOpsError):
        so.import_url("p", "us", "c", endpoint="http://chronicle.example.test")
    body = json.loads(so.body_of([so.udm(DENIED)]))
    assert list(body) == ["inline_source"] and list(body["inline_source"]) == ["events"]
    assert body["inline_source"]["events"][0]["udm"]["metadata"]["event_type"] == "FILE_OPEN"
    evs = [{"x": "a" * 100}] * 50
    bs = list(so.batches(evs, limit=1000, most=100))
    assert sum(len(b) for b in bs) == 50 and all(len(so.body_of(b)) <= 1000 for b in bs)
    assert [len(b) for b in so.batches(evs, limit=10**6, most=20)] == [20, 20, 10]


# ---------------------------------------------------------------- the stand-in --

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()).decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Google:
    """a stand-in Google: GET /metadata (a VM's metadata server), POST /token
    (the OAuth token endpoint, checking a key file's signed JWT) and POST
    .../events:import (answering with the next status in `answers`, then 200)"""

    def __init__(self, answers=(), too_big=None, too_big_400=False, token_status=200):
        self.metadata, self.tokens, self.posts = [], [], []
        self.answers, self.too_big, self.too_big_400 = list(answers), too_big, too_big_400
        self.token_status, self.issued = token_status, 0
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def reply(self, code, body=None, headers=()):
                self.send_response(code)
                for k, v in headers:
                    self.send_header(k, v)
                data = json.dumps(body).encode() if body is not None else b""
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                p = urllib.parse.urlsplit(self.path)
                outer.metadata.append({"path": p.path, "query": dict(urllib.parse.parse_qsl(p.query)),
                                       "flavor": self.headers.get("Metadata-Flavor")})
                outer.issued += 1
                self.reply(200, {"access_token": f"vm-token-{outer.issued}", "expires_in": 3599,
                                 "token_type": "Bearer"})

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.path == "/token":
                    form = dict(urllib.parse.parse_qsl(raw.decode()))
                    h, c, s = form["assertion"].split(".")
                    head, claims = json.loads(_unb64(h)), json.loads(_unb64(c))
                    try:
                        KEY.public_key().verify(_unb64(s), f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())
                        good = True
                    except Exception:
                        good = False
                    outer.tokens.append({"form": form, "head": head, "claims": claims, "signed": good})
                    if outer.token_status != 200 or not good:
                        return self.reply(outer.token_status if outer.token_status != 200 else 400,
                                          {"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
                    outer.issued += 1
                    return self.reply(200, {"access_token": f"sa-token-{outer.issued}", "expires_in": 3599})
                body = json.loads(raw)
                outer.posts.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                n = len(body["inline_source"]["events"])
                if outer.too_big and n > outer.too_big:
                    if outer.too_big_400:
                        return self.reply(400, {"error": {"code": 400, "status": "INVALID_ARGUMENT",
                                                          "message": "Request payload size exceeds the limit: "
                                                                     "4194304 bytes."}})
                    return self.reply(413, {"error": {"code": 413, "message": "too large"}})
                code = outer.answers.pop(0) if outer.answers else 200
                if code == 200:
                    return self.reply(200, {})
                self.reply(code, {"error": {"code": code, "status": "INVALID_ARGUMENT" if code == 400 else
                                            "UNAVAILABLE", "message": "invalid UDM event" if code == 400 else
                                            "try later"}},
                           headers=(("Retry-After", "0"),) if code == 429 else ())

            def log_message(self, *a):
                pass

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def events(self):
        return [e["udm"] for p in self.posts for e in p["body"]["inline_source"]["events"]]

    def close(self):
        self.srv.shutdown()


def run(g, args, events, env=None, tmp=None):
    e = dict(os.environ, NO_PROXY="127.0.0.1", VAREK_GCE_METADATA=g.base + "/metadata")
    for k in ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN", "SECOPS_PROJECT", "GOOGLE_CLOUD_PROJECT",
              "SECOPS_CUSTOMER_ID", "SECOPS_REGION"):
        e.pop(k, None)
    e.update(env or {})
    return subprocess.run([sys.executable, TOOL, "--endpoint", g.base, "--project", "varek-gke-test",
                           "--customer-id", "cust-1"] + args,
                          input="".join(json.dumps(x) + "\n" for x in events), capture_output=True, text=True,
                          env=e, timeout=60)


PATH = "/v1alpha/projects/varek-gke-test/locations/us/instances/cust-1/events:import"


def test_events_reach_the_instance_with_the_vms_own_token():
    g = Google()
    try:
        r = run(g, ["--batch", "2"], [DENIED] * 5)
        assert r.returncode == 0, r.stderr
        assert "5 events sent" in r.stderr and "3 request(s)" in r.stderr
        assert g.metadata == [{"path": "/metadata", "query": {"scopes": "https://www.googleapis.com/auth/cloud-platform"},
                               "flavor": "Google"}]                       # one token, kept
        assert [p["path"] for p in g.posts] == [PATH] * 3
        assert all(p["auth"] == "Bearer vm-token-1" for p in g.posts)
        assert [u["security_result"][0]["action"] for u in g.events()] == [["BLOCK"]] * 5
        assert json.loads(g.events()[0]["additional"]["ocsf_event"]) == DENIED
        assert "vm-token-1" not in r.stderr
    finally:
        g.close()


def test_a_key_files_signed_jwt_and_a_token_from_the_environment(tmp_path):
    g = Google()
    keyfile = tmp_path / "sa.json"
    keyfile.write_text(json.dumps({"type": "service_account", "project_id": "varek-gke-test",
                                   "private_key_id": "k-1", "private_key": PEM,
                                   "client_email": "varek-export@varek-gke-test.iam.gserviceaccount.com",
                                   "token_uri": g.base + "/token"}))
    try:
        r = run(g, [], [DENIED] * 3, {"GOOGLE_APPLICATION_CREDENTIALS": str(keyfile)})   # auto: the key file
        assert r.returncode == 0, r.stderr
        assert len(g.tokens) == 1 and not g.metadata
        t = g.tokens[0]
        assert t["signed"] and t["form"]["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assert t["head"] == {"alg": "RS256", "typ": "JWT", "kid": "k-1"}
        c = t["claims"]
        assert (c["iss"], c["aud"], c["scope"]) == ("varek-export@varek-gke-test.iam.gserviceaccount.com",
                                                    g.base + "/token", "https://www.googleapis.com/auth/cloud-platform")
        assert c["exp"] - c["iat"] == 3600
        assert g.posts[0]["auth"] == "Bearer sa-token-1"
        assert "PRIVATE KEY" not in r.stderr and "sa-token-1" not in r.stderr
        r = run(g, ["--auth", "token"], [DENIED], {"GOOGLE_OAUTH_ACCESS_TOKEN": "had-before"})
        assert r.returncode == 0 and g.posts[-1]["auth"] == "Bearer had-before", r.stderr
        r = run(g, ["--auth", "metadata"], [DENIED], {"GOOGLE_APPLICATION_CREDENTIALS": str(keyfile)})
        assert r.returncode == 0 and len(g.metadata) == 1, r.stderr                 # asked for: the VM's
    finally:
        g.close()


def test_busy_too_large_and_expired_are_mended_and_a_refusal_ends_the_export():
    g = Google(answers=[503, 429])
    try:
        r = run(g, ["--retries", "3"], [DENIED])
        assert r.returncode == 0 and len(g.posts) == 3, r.stderr
    finally:
        g.close()
    for as_400 in (False, True):                       # 413, or Google's 400 "payload size exceeds"
        g = Google(too_big=2, too_big_400=as_400)
        try:
            r = run(g, [], [DENIED] * 5)
            assert r.returncode == 0, r.stderr
            accepted = [p for p in g.posts if len(p["body"]["inline_source"]["events"]) <= 2]
            assert sum(len(p["body"]["inline_source"]["events"]) for p in accepted) == 5
        finally:
            g.close()
    g = Google(answers=[401])                          # a token gone stale: a new one, once
    try:
        r = run(g, [], [DENIED])
        assert r.returncode == 0 and len(g.metadata) == 2 and g.posts[-1]["auth"] == "Bearer vm-token-2", r.stderr
    finally:
        g.close()
    g = Google(answers=[401, 401])
    try:
        r = run(g, [], [DENIED])
        assert r.returncode == 1 and "HTTP 401" in r.stderr
    finally:
        g.close()
    g = Google(answers=[400])
    try:
        r = run(g, [], [DENIED, DENIED])
        assert r.returncode == 1 and "HTTP 400" in r.stderr and "INVALID_ARGUMENT: invalid UDM event" in r.stderr
        assert "0 events sent before; those not sent begin at position 12" in r.stderr
    finally:
        g.close()


def at(pos):
    ev = json.loads(json.dumps(DENIED))
    ev["unmapped"]["varek"]["position"] = pos
    return ev


def test_a_failed_send_names_where_the_events_not_sent_begin():
    g = Google(answers=[200, 400])                     # the first request (10, 11) accepted, the second refused
    try:
        r = run(g, ["--batch", "2"], [at(p) for p in range(10, 15)])
        assert r.returncode == 1
        assert "2 events sent before; those not sent begin at position 12: " \
               "`varek export --from-position 12` sends them" in r.stderr
    finally:
        g.close()
    g = Google(too_big=2, answers=[200, 400])          # split, its first half accepted: sent again
    try:
        r = run(g, ["--batch", "4"], [at(p) for p in range(10, 14)])
        assert r.returncode == 1 and "(0 events sent before; those not sent begin at position 10" in r.stderr
    finally:
        g.close()
    g = Google()
    try:
        r = run(g, ["--max-bytes", "2000"], [DENIED])  # one event over the limit: not sent
        assert r.returncode == 1 and "over --max-bytes 2000" in r.stderr and not g.posts
    finally:
        g.close()


def test_missing_settings_and_credentials():
    g = Google()
    try:
        e = dict(os.environ, NO_PROXY="127.0.0.1")
        for k in ("SECOPS_PROJECT", "GOOGLE_CLOUD_PROJECT", "SECOPS_CUSTOMER_ID"):
            e.pop(k, None)
        r = subprocess.run([sys.executable, TOOL, "--customer-id", "c"], input="", capture_output=True, text=True,
                           env=e, timeout=30)
        assert r.returncode == 2 and "no Google Cloud project" in r.stderr
        r = subprocess.run([sys.executable, TOOL, "--project", "p"], input="", capture_output=True, text=True,
                           env=e, timeout=30)
        assert r.returncode == 2 and "SECOPS_CUSTOMER_ID" in r.stderr
        r = subprocess.run([sys.executable, TOOL], input="", capture_output=True, text=True, timeout=30,
                           env=dict(e, SECOPS_PROJECT="p", SECOPS_CUSTOMER_ID="c", VAREK_GCE_METADATA=g.base + "/metadata",
                                    NO_PROXY="127.0.0.1"))
        assert r.returncode == 0 and g.metadata, r.stderr                # from the environment
        r = run(g, ["--auth", "token"], [DENIED])
        assert r.returncode == 2 and "GOOGLE_OAUTH_ACCESS_TOKEN" in r.stderr
        r = run(g, ["--auth", "key-file"], [DENIED])
        assert r.returncode == 2 and "GOOGLE_APPLICATION_CREDENTIALS" in r.stderr
        r = run(g, ["--auth", "key-file"], [DENIED], {"GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/sa.json"})
        assert r.returncode == 2 and "can't be read" in r.stderr
        r = run(g, [], [{"time": 1}])
        assert r.returncode == 2 and "not an OCSF event" in r.stderr and not g.posts
        r = run(g, [], ["not json"])
        assert r.returncode == 2
    finally:
        g.close()


def test_a_refused_key_is_the_export_failing(tmp_path):
    g = Google()
    keyfile = tmp_path / "sa.json"
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)       # not the key Google knows
    keyfile.write_text(json.dumps({"type": "service_account", "client_email": "x@p.iam.gserviceaccount.com",
                                   "private_key": other.private_bytes(serialization.Encoding.PEM,
                                                                      serialization.PrivateFormat.PKCS8,
                                                                      serialization.NoEncryption()).decode(),
                                   "token_uri": g.base + "/token"}))
    try:
        r = run(g, [], [DENIED], {"GOOGLE_APPLICATION_CREDENTIALS": str(keyfile)})
        assert r.returncode == 1 and "no token" in r.stderr and "Invalid JWT Signature" in r.stderr
        assert not g.posts and "PRIVATE KEY" not in r.stderr
        keyfile.write_text(json.dumps({"type": "authorized_user", "client_id": "x"}))
        r = run(g, [], [DENIED], {"GOOGLE_APPLICATION_CREDENTIALS": str(keyfile)})
        assert r.returncode == 2 and "not a service account's key" in r.stderr
    finally:
        g.close()


VAREK = os.path.join(HERE, "tools", "varek")
BUILT = all(os.access(os.path.join(HERE, b), os.X_OK)
            for b in ("warden", "warden-proxy", "tools/vdp_check", "tools/vdp_cert_check", "tools/varek_keygen"))
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


@pytest.mark.skipif(not (BUILT and ROOT and sys.platform.startswith("linux")),
                    reason="needs Linux, root and a built runtime")
def test_varek_export_format_secops(tmp_path):
    conf = str(tmp_path / "etc" / "varek.conf")

    def varek(*args, env=None):
        e = dict(os.environ, NO_COLOR="1", VAREK_CONFIG=conf, NO_PROXY="127.0.0.1")
        e.update(env or {})
        return subprocess.run([sys.executable, VAREK, *args], text=True, capture_output=True, env=e, timeout=180)

    assert varek("init", "--pack", "healthcare", "--log-dir", str(tmp_path / "log")).returncode == 0
    assert varek("run", "--", "/bin/sh", "-c", "cat /etc/shadow; true").returncode == 0
    log = str(max((tmp_path / "log").glob("verdicts-*.log")))
    g = Google()
    try:
        r = varek("export", "--format", "secops", log, "--endpoint", g.base, "--secops-project", "varek-gke-test",
                  "--secops-customer-id", "cust-1", "--secops-auth", "token",
                  env={"GOOGLE_OAUTH_ACCESS_TOKEN": "had-before"})
        assert r.returncode == 0, r.stdout + r.stderr
        evs = g.events()
        assert evs and all(p["path"] == PATH and p["auth"] == "Bearer had-before" for p in g.posts)
        assert evs[-1]["additional"]["varek_event"] == "audit"            # the audit's own event, last
        refused = [u for u in evs if u["security_result"][0].get("action") == ["BLOCK"]]
        assert refused                                                   # the pack's refusals, as BLOCK
        for u in refused:
            assert u["additional"]["varek_decision"] == "DENY" and u["security_result"][0]["severity"] == "MEDIUM"
            assert u["security_result"][0]["rule_name"] and u["target"]
        assert all(u["additional"].get("varek_position") for u in evs if "varek_decision" in u["additional"])
    finally:
        g.close()
