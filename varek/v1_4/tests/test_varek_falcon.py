# SPDX-License-Identifier: MIT
"""v1.41 (docs/security/v1.39-security-operations.md, section 4): the Falcon
Next-Gen SIEM export (tools/varek_falcon.py): an OCSF event as an HEC event,
the connector's URL, and the export to a connector (a local stand-in), with
its retries, splits, refusals, resume point and TLS trust."""
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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import varek_falcon as fal  # noqa: E402
from test_varek_splunk import DENIED  # noqa: E402  (the same OCSF event)

KEY = "falcon-test-key-0123456789abcdef"


def test_an_ocsf_event_as_an_hec_event():
    e = fal.event_of(DENIED)
    assert e["time"] == 1794711677.967 and e["host"] == "build-7"
    assert e["source"] == "varek-warden" and e["sourcetype"] == "varek:ocsf" and "index" not in e
    assert e["event"] == DENIED                                   # the whole OCSF event, nothing lost
    assert e["fields"] == {"varek_run": "run1", "varek_decision": "DENY", "ocsf_class_uid": "1001"}
    assert all(isinstance(v, str) for v in e["fields"].values())  # flat: no nested field is dropped
    with pytest.raises(fal.FalconError):
        fal.event_of({"time": 1})
    body = fal.body_of([e, e]).decode().split("\n")
    assert len(body) == 2 and json.loads(body[0]) == e == json.loads(body[1])


def test_the_connector_url():
    hec = "https://abc.ingest.us-2.crowdstrike.com"
    assert fal.endpoint_of(hec) == (hec + "/services/collector", False)
    assert fal.endpoint_of(hec + "/") == (hec + "/services/collector", False)
    assert fal.endpoint_of(hec + "/services/collector") == (hec + "/services/collector", False)
    assert fal.endpoint_of(hec + "/services/collector/raw") == (hec + "/services/collector/raw", True)
    one = "https://ingest.us-2.crowdstrike.com/api/ingest/hec/0123abcd/v1"
    assert fal.endpoint_of(one) == (one + "/services/collector", False)
    assert fal.endpoint_of(one + "/services/collector/raw/") == (one + "/services/collector/raw", True)
    assert fal.endpoint_of("http://127.0.0.1:9") == ("http://127.0.0.1:9/services/collector", False)
    ls = "https://x.ingest.logscale.us-2.crowdstrike.com/api/v1/ingest/hec"   # LogScale's other HEC paths
    assert fal.endpoint_of(ls) == (ls, False)
    assert fal.endpoint_of(ls + "/raw") == (ls + "/raw", True)
    for bad in (None, "", "abc.crowdstrike.com", "ftp://x/y", "http://abc.ingest.us-2.crowdstrike.com"):
        with pytest.raises(fal.FalconError):
            fal.endpoint_of(bad)


def test_batches_stay_under_the_limit():
    e = fal.event_of(DENIED)
    n = len(json.dumps(e, separators=(",", ":"))) + 1
    bs = list(fal.batches([e] * 10, limit=3 * n))
    assert [len(b) for b in bs] == [3, 3, 3, 1]
    assert [len(b) for b in fal.batches([e] * 3)] == [3]


class Connector:
    """a stand-in Next-Gen SIEM HEC connector: answers each POST with the next
    (status, body) in `answers` (then 200 Success), and keeps what it was sent"""

    def __init__(self, answers=(), tls=None):
        self.got, self.answers = [], list(answers)
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(n).decode()
                hdr = {k.lower(): v for k, v in self.headers.items()}
                evs, dec, i = [], json.JSONDecoder(), 0
                while i < len(raw):
                    e, i = dec.raw_decode(raw, i)
                    evs.append(e)
                    while i < len(raw) and raw[i].isspace():
                        i += 1
                outer.got.append({"path": self.path, "headers": hdr, "body": raw, "events": evs})
                code, body = outer.answers.pop(0) if outer.answers else (200, {"text": "Success", "code": 0})
                self.send_response(code)
                if code != 200:
                    self.send_header("Retry-After", "0")
                if 300 <= code < 400:
                    self.send_header("Location", "/elsewhere")
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write((body if isinstance(body, str) else json.dumps(body)).encode())

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


def run(args, stdin_lines, key=KEY):
    env = dict(os.environ, NO_PROXY="127.0.0.1")
    for k in ("FALCON_HEC_API_KEY", "FALCON_HEC_URL"):
        env.pop(k, None)
    if key:
        env["FALCON_HEC_API_KEY"] = key
    return subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek_falcon.py")] + args,
                          input="".join(json.dumps(e) + "\n" for e in stdin_lines), capture_output=True,
                          text=True, env=env, timeout=60)


def test_events_reach_the_connector_in_batches_with_the_key():
    c = Connector()
    try:
        r = run(["--url", c.url, "--batch", "2"], [DENIED] * 5)
        assert r.returncode == 0, r.stderr
        assert "5 events sent" in r.stderr and "3 request(s)" in r.stderr
        assert [g["path"] for g in c.got] == ["/services/collector"] * 3
        assert [len(g["events"]) for g in c.got] == [2, 2, 1]
        assert all(g["headers"]["authorization"] == "Bearer " + KEY for g in c.got)
        assert all(g["headers"]["content-type"] == "application/json" for g in c.got)
        assert all(e["event"] == DENIED and e["sourcetype"] == "varek:ocsf" for e in c.events())
        assert KEY not in r.stderr
    finally:
        c.close()


def test_the_raw_endpoint_takes_each_ocsf_event_as_a_line():
    c = Connector()
    try:
        r = run(["--url", c.url + "/api/ingest/hec/0123abcd/v1/services/collector/raw", "--batch", "3"],
                [DENIED] * 3)
        assert r.returncode == 0, r.stderr
        g, = c.got
        assert g["path"] == "/api/ingest/hec/0123abcd/v1/services/collector/raw"
        assert g["headers"]["content-type"] == "text/plain"
        assert [json.loads(x) for x in g["body"].split("\n")] == [DENIED] * 3   # the events alone
    finally:
        c.close()


def test_the_url_and_key_come_from_the_environment():
    c = Connector()
    try:
        env = dict(os.environ, NO_PROXY="127.0.0.1", FALCON_HEC_URL=c.url, MY_KEY=KEY)
        env.pop("FALCON_HEC_API_KEY", None)
        r = subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek_falcon.py"), "--key-env", "MY_KEY"],
                           input=json.dumps(DENIED) + "\n", capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        assert c.got[0]["headers"]["authorization"] == "Bearer " + KEY
    finally:
        c.close()


def test_no_key_and_no_url_are_refused():
    r = run(["--url", "http://127.0.0.1:9"], [DENIED], key=None)
    assert r.returncode == 2 and "FALCON_HEC_API_KEY" in r.stderr and "not set" in r.stderr
    r = run([], [DENIED])
    assert r.returncode == 2 and "no connector URL" in r.stderr
    r = run(["--url", "http://abc.ingest.us-1.crowdstrike.com"], [DENIED])
    assert r.returncode == 2 and "not an https URL" in r.stderr


def test_busy_and_too_big_are_mended_and_a_refusal_ends_the_export():
    c = Connector(answers=[(503, {"text": "Server is busy", "code": 9}), (429, "")])
    try:
        r = run(["--url", c.url, "--retries", "2"], [DENIED])
        assert r.returncode == 0, r.stderr
        assert len(c.got) == 3 and "1 events sent" in r.stderr and "3 request(s)" in r.stderr
    finally:
        c.close()
    # only a 200 is taken: a 202 and a 302 (not followed) are sent again, as any 5xx is
    c = Connector(answers=[(202, ""), (302, ""), (507, "")])
    try:
        r = run(["--url", c.url, "--retries", "3"], [DENIED])
        assert r.returncode == 0, r.stderr
        assert [g["path"] for g in c.got] == ["/services/collector"] * 4 and "4 request(s)" in r.stderr
    finally:
        c.close()
    c = Connector(answers=[(302, "")] * 2)
    try:
        r = run(["--url", c.url, "--retries", "1"], [DENIED])
        assert r.returncode == 1 and "HTTP 302" in r.stderr and len(c.got) == 2
    finally:
        c.close()
    c = Connector(answers=[(413, "")])
    try:
        r = run(["--url", c.url, "--batch", "4"], [DENIED] * 4)
        assert r.returncode == 0, r.stderr
        assert [len(g["events"]) for g in c.got] == [4, 2, 2]     # refused whole, then taken in halves
    finally:
        c.close()
    c = Connector(answers=[(400, {"text": "Invalid data format", "code": 6})])
    try:
        r = run(["--url", c.url], [DENIED, DENIED])
        assert r.returncode == 1 and "HTTP 400" in r.stderr and "Invalid data format" in r.stderr
    finally:
        c.close()
    for code in (401, 403):
        c = Connector(answers=[(code, {"message": "invalid token"})])
        try:
            r = run(["--url", c.url], [DENIED])
            assert r.returncode == 1 and f"HTTP {code}" in r.stderr and "invalid token" in r.stderr
            assert "API key" in r.stderr and KEY not in r.stderr and len(c.got) == 1   # not tried again
        finally:
            c.close()
    c = Connector(answers=[(200, {"text": "Incorrect index", "code": 7})])
    try:
        r = run(["--url", c.url], [DENIED])
        assert r.returncode == 1 and "code 7: Incorrect index" in r.stderr
    finally:
        c.close()
    c = Connector(answers=[(200, "")])                              # an empty 200 is taken
    try:
        assert run(["--url", c.url], [DENIED]).returncode == 0
    finally:
        c.close()


def test_input_that_is_not_ocsf_is_refused():
    c = Connector()
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek_falcon.py"), "--url", c.url],
                           input="not json\n", capture_output=True, text=True, timeout=30,
                           env=dict(os.environ, FALCON_HEC_API_KEY=KEY, NO_PROXY="127.0.0.1"))
        assert r.returncode == 2 and "line 1 is not JSON" in r.stderr and not c.got
        r = run(["--url", c.url], [{"time": 1}])
        assert r.returncode == 2 and "not an OCSF event" in r.stderr and not c.got
    finally:
        c.close()


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl makes the test certificates")
def test_the_connector_certificate_is_checked(tmp_path):
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
    c = Connector(tls=(str(tmp_path / "s.pem"), str(tmp_path / "s.key")))
    try:
        r = run(["--url", c.url, "--ca", str(tmp_path / "ca.pem")], [DENIED])
        assert r.returncode == 0, r.stderr
        r = run(["--url", c.url, "--retries", "0"], [DENIED])              # the system's CAs: not trusted
        assert r.returncode == 1 and "CERTIFICATE_VERIFY_FAILED" in r.stderr and len(c.got) == 1
        r = run(["--url", c.url.replace("127.0.0.1", "localhost"), "--ca", str(tmp_path / "ca.pem")], [DENIED])
        assert r.returncode == 1 and "CERTIFICATE_VERIFY_FAILED" in r.stderr   # the name is checked
    finally:
        c.close()


def at(pos):
    """DENIED as varek_ocsf.py writes it: the position of its record in the stream"""
    ev = json.loads(json.dumps(DENIED))
    ev["unmapped"]["varek"]["position"] = pos
    return ev


def test_a_failed_send_names_where_the_events_not_sent_begin():
    # the first batch (positions 10, 11) taken, the second refused
    c = Connector(answers=[(200, {"text": "Success", "code": 0}), (400, {"text": "Invalid data format", "code": 6})])
    try:
        r = run(["--url", c.url, "--batch", "2"], [at(p) for p in range(10, 15)])
        assert r.returncode == 1 and "HTTP 400" in r.stderr
        assert "2 events sent before; those not sent begin at position 12: " \
               "`varek export --from-position 12` sends them" in r.stderr
    finally:
        c.close()
    # an event over 1 MB is not sent (the connector would keep it truncated, with a 200)
    big = at(31)
    big["unmapped"]["varek"]["pad"] = "x" * fal.MAX_EVENT
    c = Connector()
    try:
        r = run(["--url", c.url], [at(30), big, at(32)])
        assert r.returncode == 1 and "over the 1,000,000" in r.stderr and "begin at position 31" in r.stderr
        assert [e["event"]["unmapped"]["varek"]["position"] for e in c.events()] == [30]
    finally:
        c.close()
    # a batch too large, split, its first half taken and its second refused:
    # the batch's first event, so the half taken is sent again
    c = Connector(answers=[(413, ""), (200, {"text": "Success", "code": 0}), (400, "bad")])
    try:
        r = run(["--url", c.url, "--batch", "4"], [at(p) for p in range(20, 24)])
        assert r.returncode == 1 and "begin at position 20" in r.stderr
    finally:
        c.close()


VAREK = os.path.join(HERE, "tools", "varek")
BUILT = all(os.access(os.path.join(HERE, b), os.X_OK)
            for b in ("warden", "warden-proxy", "tools/vdp_check", "tools/vdp_cert_check", "tools/varek_keygen"))
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


@pytest.mark.skipif(not (BUILT and ROOT and sys.platform.startswith("linux")),
                    reason="needs Linux, root and a built runtime")
def test_varek_export_sends_a_run_and_a_live_one_to_falcon(tmp_path):
    conf = str(tmp_path / "etc" / "varek.conf")

    def varek(*args, env=None):
        e = dict(os.environ, NO_COLOR="1", VAREK_CONFIG=conf, NO_PROXY="127.0.0.1", FALCON_HEC_API_KEY=KEY)
        e.update(env or {})
        return subprocess.run([sys.executable, VAREK, *args], text=True, capture_output=True, env=e, timeout=180)

    assert varek("init", "--pack", "healthcare", "--log-dir", str(tmp_path / "log")).returncode == 0
    assert varek("run", "--", "/bin/sh", "-c", "read a < /etc/hostname; read b < /etc/shadow; true").returncode == 0
    log = str(max((tmp_path / "log").glob("verdicts-*.log")))
    out = str(tmp_path / "run.ocsf.jsonl")
    ocsf = varek("export", "--format", "ocsf", log, "-o", out)
    assert ocsf.returncode == 0, ocsf.stdout + ocsf.stderr
    want = [json.loads(x) for x in open(out) if x.strip()]
    c = Connector()
    try:
        r = varek("export", "--format", "falcon", log, "--endpoint", c.url)
        assert r.returncode == 0, r.stdout + r.stderr
        got = [e["event"] for e in c.events()]
        assert len(got) == len(want) and [e["metadata"]["uid"] for e in got] == [e["metadata"]["uid"] for e in want]
        denied = [e for e in got if e.get("action") == "Denied"]
        assert any(e.get("file", {}).get("path") == "/etc/shadow" and e["unmapped"]["varek"].get("policy_line")
                   for e in denied)                               # the refusal, with its policy line
        assert got[-1]["unmapped"]["varek"]["event"] == "audit" and got[-1]["unmapped"]["varek"]["audit"]["passed"]
        assert KEY not in r.stdout + r.stderr
        n = len(c.got)
        r = varek("export", "--format", "falcon", "--follow", log, "--endpoint", c.url)
        assert r.returncode == 0, r.stdout + r.stderr
        assert len([e for g in c.got[n:] for e in g["events"]]) == len(want)
        pos = want[len(want) // 2]["unmapped"]["varek"]["position"]
        n = len(c.got)
        r = varek("export", "--format", "falcon", log, "--endpoint", c.url, "--from-position", str(pos))
        assert r.returncode == 0, r.stdout + r.stderr
        k = next(i for i, e in enumerate(want) if e["unmapped"]["varek"]["position"] >= pos)
        assert [e["event"] for g in c.got[n:] for e in g["events"]] == want[k:]
    finally:
        c.close()
    c = Connector(answers=[(401, {"message": "invalid token"})])
    try:
        r = varek("export", "--format", "falcon", log, "--endpoint", c.url)
        out = r.stdout + r.stderr
        assert r.returncode != 0 and "HTTP 401" in out and "failed (the sender exited" in out
        assert "audit refuses" not in out and "Traceback" not in out and KEY not in out
    finally:
        c.close()
