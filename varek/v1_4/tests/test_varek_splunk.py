# SPDX-License-Identifier: MIT
"""v1.39 (docs/security/v1.39-security-operations.md, section 2): the Splunk
export (tools/varek_splunk.py): an OCSF event as an HTTP Event Collector
event, and the export to an HEC (a local stand-in), with its retries,
refusals, indexer acknowledgement and TLS trust."""
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_splunk as spl  # noqa: E402

DENIED = {
    "class_uid": 1001, "class_name": "File System Activity", "category_uid": 1, "activity_id": 14,
    "activity_name": "Open", "type_uid": 100114, "type_name": "File System Activity: Open",
    "time": 1794711677967, "severity_id": 3, "severity": "Medium",
    "action_id": 2, "action": "Denied", "disposition_id": 2, "disposition": "Blocked",
    "metadata": {"version": "1.9.0", "uid": "pr-1-122", "correlation_uid": "run1",
                 "product": {"name": "VAREK Warden", "version": "1.38.0"}},
    "device": {"hostname": "build-7"},
    "file": {"path": "/etc/shadow"},
    "policy": {"name": "p.txt", "uid": "ab" * 32, "desc": "deny  path /etc/shadow"},
    "unmapped": {"varek": {"report_id": "pr-1-122", "seq": 122, "decision": "UNSATISFIED",
                           "decision_final": "DENY", "rule": "policy_match", "policy_line": 91}},
}
TOKEN = "00000000-1111-2222-3333-444444444444"


def test_an_ocsf_event_as_an_hec_event():
    e = spl.hec_event(DENIED, index="varek")
    assert e["time"] == 1794711677.967 and e["host"] == "build-7"
    assert e["source"] == "varek-warden" and e["sourcetype"] == "varek:ocsf" and e["index"] == "varek"
    assert e["event"] == DENIED                                   # the whole OCSF event, nothing lost
    assert e["fields"] == {"varek_run": "run1", "varek_decision": "DENY", "ocsf_class_uid": "1001"}
    life = {"class_uid": 6002, "time": 0, "metadata": {}, "unmapped": {"varek": {"event": "audit"}}}
    e = spl.hec_event(life)
    assert "index" not in e and "time" not in e and "host" not in e and e["fields"] == {"ocsf_class_uid": "6002"}
    with pytest.raises(spl.SplunkError):
        spl.hec_event({"time": 1})
    body = spl.body_of([spl.hec_event(DENIED)] * 2).decode()
    dec = json.JSONDecoder()
    first, end = dec.raw_decode(body)
    assert first["event"] == DENIED and dec.raw_decode(body[end:].lstrip())[0] == first


def test_the_endpoints():
    assert spl.endpoint_of("https://s:8088") == "https://s:8088/services/collector/event"
    assert spl.endpoint_of("https://s:8088/") == "https://s:8088/services/collector/event"
    assert spl.endpoint_of("https://s/x/services/collector/event") == "https://s/x/services/collector/event"
    assert spl.ack_endpoint_of("https://s:8088/services/collector/event") == "https://s:8088/services/collector/ack"
    for bad in (None, "", "s:8088", "ftp://s/x"):
        with pytest.raises(spl.SplunkError):
            spl.endpoint_of(bad)


class Hec:
    """a stand-in HTTP Event Collector: answers each event POST with the next
    (status, body) in `answers` (then 200 Success), acknowledges after
    `ack_after` polls (never, if None), and keeps what it was sent"""

    def __init__(self, answers=(), ack=False, ack_after=1, tls=None):
        self.got, self.polls, self.answers = [], [], list(answers)
        self.ack, self.ack_after, self.next_ack = ack, ack_after, 0
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(n).decode()
                hdr = {k.lower(): v for k, v in self.headers.items()}
                if self.path.endswith("/ack"):
                    outer.polls.append({"headers": hdr, "body": json.loads(raw)})
                    done = outer.ack_after is not None and len(outer.polls) >= outer.ack_after
                    return self.answer(200, {"acks": {str(i): done for i in json.loads(raw)["acks"]}})
                evs, dec, i = [], json.JSONDecoder(), 0
                while i < len(raw):
                    e, i = dec.raw_decode(raw, i)
                    evs.append(e)
                    while i < len(raw) and raw[i].isspace():
                        i += 1
                outer.got.append({"path": self.path, "headers": hdr, "events": evs})
                code, body = outer.answers.pop(0) if outer.answers else (200, {"text": "Success", "code": 0})
                if code == 200 and outer.ack:
                    body = dict(body, ackId=outer.next_ack)
                    outer.next_ack += 1
                self.answer(code, body)

            def answer(self, code, body):
                self.send_response(code)
                if code == 503:
                    self.send_header("Retry-After", "0")
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, *a):
                pass

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        scheme = "http"
        if tls:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            c.minimum_version = ssl.TLSVersion.TLSv1_2
            c.load_cert_chain(*tls)
            self.srv.socket = c.wrap_socket(self.srv.socket, server_side=True)
            scheme = "https"
        self.url = f"{scheme}://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def events(self):
        return [e for g in self.got for e in g["events"]]

    def close(self):
        self.srv.shutdown()


def run(args, stdin_lines, token=TOKEN):
    env = dict(os.environ, NO_PROXY="127.0.0.1")
    env.pop("SPLUNK_HEC_TOKEN", None)
    if token:
        env["SPLUNK_HEC_TOKEN"] = token
    return subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek_splunk.py")] + args,
                          input="".join(json.dumps(e) + "\n" for e in stdin_lines), capture_output=True,
                          text=True, env=env, timeout=60)


def test_events_reach_the_hec_in_batches_with_the_token():
    h = Hec()
    try:
        r = run(["--hec", h.url, "--batch", "2", "--index", "varek"], [DENIED] * 5)
        assert r.returncode == 0, r.stderr
        assert "5 events sent" in r.stderr and "3 request(s)" in r.stderr
        assert [g["path"] for g in h.got] == ["/services/collector/event"] * 3
        assert [len(g["events"]) for g in h.got] == [2, 2, 1]
        assert all(g["headers"]["authorization"] == "Splunk " + TOKEN for g in h.got)
        assert all(e["event"] == DENIED and e["index"] == "varek" for e in h.events())
        assert TOKEN not in r.stderr
    finally:
        h.close()


def test_no_token_and_no_url_are_refused():
    r = run(["--hec", "http://127.0.0.1:9"], [DENIED], token=None)
    assert r.returncode == 2 and "SPLUNK_HEC_TOKEN" in r.stderr and "not set" in r.stderr
    r = run([], [DENIED])
    assert r.returncode == 2 and "no HEC URL" in r.stderr
    r = run(["--hec", "http://127.0.0.1:9", "--token-env", "OTHER"], [DENIED])
    assert r.returncode == 2 and "OTHER" in r.stderr


def test_a_busy_hec_is_tried_again_and_a_refusal_ends_the_export():
    h = Hec(answers=[(503, {"text": "Server is busy", "code": 9})])
    try:
        r = run(["--hec", h.url, "--retries", "2"], [DENIED])
        assert r.returncode == 0 and len(h.got) == 2 and len(h.events()) == 2   # sent twice, kept once
    finally:
        h.close()
    h = Hec(answers=[(400, {"text": "Invalid data format", "code": 6, "invalid-event-number": 1})])
    try:
        r = run(["--hec", h.url], [DENIED, DENIED])
        assert r.returncode == 1 and "HTTP 400" in r.stderr and "code 6" in r.stderr
        assert "events before number 1 were taken" in r.stderr
    finally:
        h.close()
    h = Hec(answers=[(403, {"text": "Invalid token", "code": 4})])
    try:
        r = run(["--hec", h.url], [DENIED])
        assert r.returncode == 1 and "HTTP 403" in r.stderr and "Invalid token" in r.stderr and TOKEN not in r.stderr
    finally:
        h.close()


def test_indexer_acknowledgement():
    h = Hec(ack=True, ack_after=2)
    try:
        r = run(["--hec", h.url, "--ack", "--batch", "2"], [DENIED] * 3)
        assert r.returncode == 0, r.stderr
        assert "3 events sent" in r.stderr and "3 acknowledged as indexed" in r.stderr
        ch = {g["headers"].get("x-splunk-request-channel") for g in h.got}
        assert len(ch) == 1 and None not in ch                    # one channel, on every request
        assert {p["headers"].get("x-splunk-request-channel") for p in h.polls} == ch
        assert sorted(set(i for p in h.polls for i in p["body"]["acks"])) == [0, 1]
    finally:
        h.close()
    h = Hec(ack=True, ack_after=None)
    try:
        r = run(["--hec", h.url, "--ack", "--ack-timeout", "2"], [DENIED])
        assert r.returncode == 1 and "not acknowledged as indexed within 2 s" in r.stderr
    finally:
        h.close()
    h = Hec(ack=False)
    try:
        r = run(["--hec", h.url, "--ack"], [DENIED])
        assert r.returncode == 1 and "no ackId" in r.stderr
    finally:
        h.close()


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl makes the test certificates")
def test_the_hec_certificate_is_checked(tmp_path):
    def ossl(*a):
        subprocess.run(["openssl", *a], check=True, capture_output=True, cwd=tmp_path)
    ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=test CA",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-keyout", "ca.key", "-out", "ca.pem")
    ossl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-keyout", "s.key", "-out", "s.csr")
    (tmp_path / "ext").write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
                                  "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                  "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n")
    ossl("x509", "-req", "-in", "s.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "2",
         "-extfile", "ext", "-out", "s.pem")
    h = Hec(tls=(str(tmp_path / "s.pem"), str(tmp_path / "s.key")))
    try:
        r = run(["--hec", h.url, "--ca", str(tmp_path / "ca.pem")], [DENIED])
        assert r.returncode == 0, r.stderr
        r = run(["--hec", h.url, "--retries", "0"], [DENIED])               # the system's CAs: not trusted
        assert r.returncode == 1 and "CERTIFICATE_VERIFY_FAILED" in r.stderr and len(h.got) == 1
        r = run(["--hec", h.url.replace("127.0.0.1", "localhost"), "--ca", str(tmp_path / "ca.pem")], [DENIED])
        assert r.returncode == 1 and "CERTIFICATE_VERIFY_FAILED" in r.stderr   # the name is checked
    finally:
        h.close()


def test_input_that_is_not_ocsf_is_refused():
    h = Hec()
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek_splunk.py"), "--hec", h.url],
                           input="not json\n", capture_output=True, text=True, timeout=30,
                           env=dict(os.environ, SPLUNK_HEC_TOKEN=TOKEN, NO_PROXY="127.0.0.1"))
        assert r.returncode == 2 and "line 1 is not JSON" in r.stderr and not h.got
        r = run(["--hec", h.url], [{"time": 1}])
        assert r.returncode == 2 and "not an OCSF event" in r.stderr and not h.got
    finally:
        h.close()
