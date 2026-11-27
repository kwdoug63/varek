# SPDX-License-Identifier: MIT
"""Tests for integrations/palantir (v1.43 step 5, docs/security/v1.43-palantir-ontology-mcp.md):
the token refresher against a stand-in token endpoint over TLS, `varek mcp tools --gateway
--credential`, the example policy, the client configurations and the headless client against
the stand-in OMCP server. Run with `make test-cli`.

The policy checks need tools/vdp_check and tools/vdp_cert_check built, and skip otherwise.
"""
import datetime as dt
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import base64
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # varek/v1_4
PAL = os.path.join(HERE, "integrations", "palantir")
sys.path.insert(0, os.path.join(HERE, "tools"))
sys.path.insert(0, os.path.join(HERE, "tests"))
import varek_mcp_tools as mt  # noqa: E402
import v1430_omcp_server as standin_mod  # noqa: E402

REFRESHER = os.path.join(PAL, "omcp_token.py")
AGENT = os.path.join(PAL, "clients", "omcp_agent.py")
EXAMPLE = os.path.join(PAL, "omcp.policy.example")
VAREK = os.path.join(HERE, "tools", "varek")
VDP = os.path.join(HERE, "tools", "vdp_check")
CERT = os.path.join(HERE, "tools", "vdp_cert_check")
STANDIN = os.path.join(HERE, "tests", "v1430_omcp_server.py")
HAVE_VDP = os.access(VDP, os.X_OK) and os.access(CERT, os.X_OK)
SECRET = "s3cret-never-in-output"
CLIENT_ID = "client-1234"
URL = "https://omcp.example.com/mcp/app1"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'ES256', 'typ': 'JWT'})}.{enc(claims)}.c2ln"


# ----------------------------------------------------- the token stand-in --

@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"), "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    return str(d / "c.pem"), str(d / "k.pem")


@pytest.fixture
def token_server(tls):
    """A token endpoint: state['mode'] picks the answer; state['got'] the forms received."""
    state = {"mode": "jwt", "got": [], "n": 0}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            form = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            state["got"].append(form)
            state["n"] += 1
            now = int(time.time())
            if self.path != "/multipass/api/oauth2/token":
                return self._send(404, {})
            if form.get("client_secret") != [SECRET] or form.get("client_id") != [CLIENT_ID]:
                return self._send(401, {"error": "invalid_client", "error_description": "bad credentials"})
            m = state["mode"]
            if m == "jwt":
                tok = _jwt({"iss": "https://localhost/multipass", "aud": URL, "iat": now, "exp": now + 3600,
                            "n": state["n"]})
                return self._send(200, {"access_token": tok, "token_type": "bearer", "expires_in": 3600})
            if m == "opaque":
                return self._send(200, {"access_token": f"opaque-{state['n']}-abcdef", "token_type": "Bearer"})
            if m == "short":
                tok = _jwt({"aud": URL, "iat": now, "exp": now + 50})
                return self._send(200, {"access_token": tok, "token_type": "bearer", "expires_in": 50})
            if m == "badchars":
                return self._send(200, {"access_token": "a b\r\nX-Evil: 1", "token_type": "bearer"})
            return self._send(500, {})

        def _send(self, code, body):
            b = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(*tls)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state["url"] = f"https://localhost:{srv.server_address[1]}/multipass/api/oauth2/token"
    state["cafile"] = tls[0]
    yield state
    srv.shutdown()


def _secret(tmp_path, mode=0o600):
    f = tmp_path / "client_secret"
    f.write_text(SECRET + "\n")
    os.chmod(f, mode)
    return str(f)


def _refresh(state, tmp_path, *extra, secret_mode=0o600, env=None):
    out = tmp_path / "omcp.token"
    args = [sys.executable, REFRESHER, "--token-url", state["url"], "--client-id", CLIENT_ID,
            "--secret-file", _secret(tmp_path, secret_mode), "--out", str(out), "--cafile", state["cafile"], *extra]
    r = subprocess.run(args, capture_output=True, text=True, timeout=60, env={**os.environ, **(env or {})})
    return r, out


# ------------------------------------------------------------ the refresher --

def test_refresher_once_jwt(token_server, tmp_path):
    r, out = _refresh(token_server, tmp_path, "--once")
    assert r.returncode == 0, r.stderr
    tok = out.read_text()
    assert tok.count(".") == 2 and "\n" not in tok
    assert os.stat(out).st_mode & 0o777 == 0o600
    assert f"JWT, aud {URL}, expires in 3" in r.stderr
    assert re.search(r"next fetch in 1[78]\d\d s", r.stderr)
    assert "warden-secrets will refuse the file" in r.stderr  # /tmp: other users can write it
    for s in (tok, SECRET):
        assert s not in r.stdout + r.stderr
    assert token_server["got"][-1]["grant_type"] == ["client_credentials"]
    assert not [n for n in os.listdir(tmp_path) if n.endswith(".new")]


def test_refresher_replaces_atomically(token_server, tmp_path):
    _refresh(token_server, tmp_path, "--once")
    first = (tmp_path / "omcp.token").read_text()
    ino = os.stat(tmp_path / "omcp.token").st_ino
    r, out = _refresh(token_server, tmp_path, "--once")
    assert r.returncode == 0 and out.read_text() != first and os.stat(out).st_ino != ino


def test_refresher_opaque_uses_interval(token_server, tmp_path):
    token_server["mode"] = "opaque"
    r, out = _refresh(token_server, tmp_path, "--once", "--interval", "600")
    assert r.returncode == 0, r.stderr
    assert out.read_text().startswith("opaque-")
    assert "opaque, its expiry not given; next fetch in 600 s" in r.stderr


def test_refresher_short_token_not_written(token_server, tmp_path):
    token_server["mode"] = "short"
    r, out = _refresh(token_server, tmp_path, "--once")
    assert r.returncode == 1 and "under 120 s: not written" in r.stderr and not out.exists()


def test_refresher_bad_token_chars_not_written(token_server, tmp_path):
    token_server["mode"] = "badchars"
    r, out = _refresh(token_server, tmp_path, "--once")
    assert r.returncode == 1 and "characters a bearer token may not" in r.stderr and not out.exists()


def test_refresher_wrong_secret(token_server, tmp_path):
    out = tmp_path / "omcp.token"
    r = subprocess.run([sys.executable, REFRESHER, "--token-url", token_server["url"], "--client-id", CLIENT_ID,
                        "--out", str(out), "--cafile", token_server["cafile"], "--once"],
                       capture_output=True, text=True, timeout=60, env={**os.environ, "OMCP_CLIENT_SECRET": "wrong"})
    assert r.returncode == 1 and "answered 401: invalid_client (bad credentials)" in r.stderr
    assert not out.exists()


def test_refresher_secret_file_others_can_read(token_server, tmp_path):
    r, out = _refresh(token_server, tmp_path, "--once", secret_mode=0o644)
    assert r.returncode == 2 and "chmod 600" in r.stderr and not token_server["got"]


def test_refresher_https_only_and_unverified_server(token_server, tmp_path):
    out = tmp_path / "t"
    r = subprocess.run([sys.executable, REFRESHER, "--token-url", "http://localhost:9/x", "--client-id", CLIENT_ID,
                        "--out", str(out), "--once"], capture_output=True, text=True,
                       env={**os.environ, "OMCP_CLIENT_SECRET": SECRET})
    assert r.returncode == 2 and "https:// only" in r.stderr
    # no --cafile: the stand-in's certificate is not trusted, and nothing is sent
    r = subprocess.run([sys.executable, REFRESHER, "--token-url", token_server["url"], "--client-id", CLIENT_ID,
                        "--out", str(out), "--once"], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "OMCP_CLIENT_SECRET": SECRET})
    assert r.returncode == 1 and "CERTIFICATE_VERIFY_FAILED" in r.stderr and not token_server["got"]


def test_refresher_runs_until_sigterm(token_server, tmp_path):
    out = tmp_path / "omcp.token"
    p = subprocess.Popen([sys.executable, REFRESHER, "--token-url", token_server["url"], "--client-id", CLIENT_ID,
                          "--secret-file", _secret(tmp_path), "--out", str(out), "--cafile", token_server["cafile"]],
                         stderr=subprocess.PIPE, text=True)
    for _ in range(100):
        if out.exists():
            break
        time.sleep(0.1)
    assert out.exists()
    p.send_signal(signal.SIGTERM)
    assert p.wait(timeout=5) == 0
    assert "stopped" in p.stderr.read()


def test_refresher_foundry_host_form():
    sys.path.insert(0, PAL)
    import omcp_token
    assert omcp_token.TOKEN_PATH == "/multipass/api/oauth2/token"
    form, left, desc = omcp_token.token_facts(_jwt({"aud": URL, "exp": 2000}), None, 1000)
    assert (form, left) == ("jwt", 1000) and URL in desc
    assert omcp_token.token_facts("abc", 77, 0)[:2] == ("opaque", 77)


# ------------------------------------------------ the writer, gateway mode --

def _tools():
    return standin_mod.tool_defs("base")


def test_writer_gateway_and_credential_text():
    t = mt.write_policy(URL, _tools(), approvers="ontology-approvers", gateway=True,
                        credential=("omcp", "file:/etc/varek/palantir/omcp.token", True))
    lines = t.splitlines()
    assert "require warden 1.43" in lines and "proxy on" in lines and "proxy ports 80 443" in lines
    assert f"mcp gateway {URL}" in lines and "proxy inspect" not in lines
    assert f"credential omcp from file:/etc/varek/palantir/omcp.token audience={URL} opaque" in lines
    assert f"allow mcp {URL} tools/call search-osdk-todo-task credential=omcp" in lines
    assert f"allow mcp {URL} tools/list credential=omcp" in lines
    # D10: a held action carries the token too, released only once a person approves it
    assert (f"step_up mcp {URL} tools/call create-osdk-todo-task credential=omcp mode=hold timeout=300 "
            "approvers=ontology-approvers") in lines
    assert "http://omcp.example.com/mcp/app1 (port 80)" in t


def test_writer_gateway_refusals():
    with pytest.raises(mt.McpToolsError, match="https://"):
        mt.write_policy("http://omcp.example.com/mcp", [], gateway=True)
    with pytest.raises(mt.McpToolsError, match="name is"):
        mt.write_policy(URL, [], credential=("Bad-Name", "file:/x", False))
    with pytest.raises(mt.McpToolsError, match="file:/PATH"):
        mt.write_policy(URL, [], credential=("omcp", "/etc/x", False))
    t = mt.write_policy("https://omcp.example.com:8443/mcp", [], gateway=True)
    assert "proxy ports 80 443 8443" in t


@pytest.mark.skipif(not HAVE_VDP, reason="needs tools/vdp_check and tools/vdp_cert_check")
@pytest.mark.parametrize("opaque", [False, True])
def test_writer_gateway_policy_both_parsers(tmp_path, opaque):
    f = tmp_path / "p.txt"
    f.write_text(mt.write_policy(URL, _tools(), approvers="ontology-approvers", gateway=True,
                                 credential=("omcp", "file:/etc/varek/palantir/omcp.token", opaque)))
    r = subprocess.run([VDP, str(f), "lint"], capture_output=True, text=True)
    assert r.returncode == 0 and "0 can never fire" in r.stdout, r.stderr
    r = subprocess.run([CERT, str(f), "proxy"], capture_output=True, text=True)
    assert r.returncode == 0 and "gateway https://omcp.example.com:443/mcp/app1" in r.stdout
    a = subprocess.run([VDP, str(f), "credentials"], capture_output=True, text=True).stdout
    b = subprocess.run([CERT, str(f), "credentials"], capture_output=True, text=True).stdout
    assert a and b


def test_cli_gateway_flags(tmp_path):
    src = tmp_path / "tools.json"
    src.write_text(json.dumps({"tools": _tools()}))
    run = lambda *a: subprocess.run([sys.executable, VAREK, "mcp", "tools", URL, "--from", str(src), *a],  # noqa
                                    capture_output=True, text=True, timeout=60)
    r = run("--gateway", "--credential", "omcp", "--credential-from", "file:/etc/varek/palantir/omcp.token",
            "--opaque")
    assert r.returncode == 0 and f"mcp gateway {URL}" in r.stdout and "audience=" + URL + " opaque" in r.stdout
    r = run("--credential", "omcp")
    assert r.returncode != 0 and "go together" in r.stderr
    r = run("--opaque")
    assert r.returncode != 0 and "--opaque needs --credential" in r.stderr


# --------------------------------------------------------- the example --

def test_example_is_the_writers_output():
    text = open(EXAMPLE).read()
    body = text[text.index("# varek mcp tools: "):]
    want = mt.write_policy(URL, _tools(), approvers="ontology-approvers", timeout=300,
                           now=dt.datetime(2026, 11, 27, tzinfo=dt.timezone.utc), gateway=True,
                           credential=("omcp", "file:/etc/varek/palantir/omcp.token", False))
    assert body == want, "regenerate omcp.policy.example (README.md, section 4)"
    ok, _ = mt.check_policy(text, _tools())
    assert ok
    assert "not affiliated with Palantir" in text


@pytest.mark.skipif(not HAVE_VDP, reason="needs tools/vdp_check")
def test_example_decides():
    def hx(s):
        return s.encode().hex()
    canon = "https://omcp.example.com:443/mcp/app1"
    objs = ["tools/call#search-osdk-todo-task", "tools/call#get-overdue-osdk-todo-tasks",
            "tools/call#create-osdk-todo-task", "tools/call#modify-osdk-todo-task-status",
            "tools/call#delete-osdk-todo-task", "tools/call#export-everything",
            "initialize#", "notifications/initialized#", "tools/list#"]
    q = "".join(f"mcp - {hx(canon + '#' + o)}\n" for o in objs)
    r = subprocess.run([VDP, EXAMPLE, "batch"], input=q, capture_output=True, text=True, timeout=30)
    got = [(g["verdict"], g.get("verb")) for g in map(json.loads, r.stdout.splitlines())]
    assert got == [("SATISFIED", "allow")] * 2 + [("UNSATISFIED", "step_up")] * 3 + [("UNKNOWN", None)] + \
        [("SATISFIED", "allow")] * 3, r.stderr


# --------------------------------------------------- the client configs --

def test_client_configs_point_at_the_gateway():
    gw = "http://omcp.example.com/mcp/app1"
    j = json.load(open(os.path.join(PAL, "clients", "vscode-mcp.json")))
    s = j["servers"]["palantir-omcp"]
    assert s["url"] == gw and s["type"] == "http" and "VAREK_CRED_OMCP" in s["headers"]["Authorization"]
    sdk = open(os.path.join(PAL, "clients", "claude_agent_sdk.py")).read()
    assert gw in sdk and "VAREK_CRED_OMCP" in sdk
    subprocess.run([sys.executable, "-m", "py_compile", os.path.join(PAL, "demo_d5.py")], check=True)
    for f in ("claude_agent_sdk.py", "omcp_agent.py"):
        subprocess.run([sys.executable, "-m", "py_compile", os.path.join(PAL, "clients", f)], check=True)
    subprocess.run([sys.executable, "-m", "py_compile", REFRESHER], check=True)


@pytest.fixture
def omcp(tmp_path):
    port = _free_port()
    p = subprocess.Popen([sys.executable, STANDIN, "--port", str(port), "--token", "tok-xyz", "--sse",
                          "--log", str(tmp_path / "s.log")], stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().startswith("ready")
    yield f"http://localhost:{port}/mcp/app1"
    p.terminate()
    p.wait(timeout=5)


def test_headless_agent_against_standin(omcp):
    env = {**os.environ, "VAREK_CRED_OMCP": "tok-xyz", "OMCP_GATEWAY_URL": omcp}
    r = subprocess.run([sys.executable, AGENT, "list"], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    assert {t["name"] for t in json.loads(r.stdout)["tools"]} == {t["name"] for t in _tools()}
    r = subprocess.run([sys.executable, AGENT, "call", "search-osdk-todo-task", '{"project_id": "p1"}'],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    r = subprocess.run([sys.executable, AGENT, "list"], capture_output=True, text=True,
                       env={**env, "VAREK_CRED_OMCP": "wrong"}, timeout=60)
    assert r.returncode == 4 and "HTTP 401" in r.stderr
