# SPDX-License-Identifier: MIT
"""Tests for `varek mcp tools` (v1.43 step 3, docs/security/v1.43-palantir-ontology-mcp.md
D2), against the stand-in Ontology MCP server (tests/v1430_omcp_server.py). Run with
`make test-cli`.

Everything runs anywhere with Python 3. The policy checks (lint, and each tool's
verdict from the decision procedure) need tools/vdp_check built, and skip otherwise.
"""
import json
import os
import socket
import subprocess
import sys
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # varek/v1_4
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_mcp_tools as mt  # noqa: E402

VAREK = os.path.join(HERE, "tools", "varek")
VDP = os.path.join(HERE, "tools", "vdp_check")
STANDIN = os.path.join(HERE, "tests", "v1430_omcp_server.py")
TOKEN = "standin-token-not-for-output"
HAVE_VDP = os.access(VDP, os.X_OK)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture
def standin(tmp_path, request):
    procs = []

    def start(*extra):
        port = _free_port()
        log = tmp_path / f"standin_{port}.log"
        p = subprocess.Popen([sys.executable, STANDIN, "--port", str(port), "--token", TOKEN,
                              "--log", str(log), *extra], stdout=subprocess.PIPE, text=True)
        assert p.stdout.readline().startswith("ready")
        procs.append(p)
        return f"http://localhost:{port}/mcp/app1", log

    yield start
    for p in procs:
        p.terminate()
        p.wait(timeout=5)


def _tokfile(tmp_path):
    f = tmp_path / "token"
    f.write_text(TOKEN)
    os.chmod(f, 0o600)
    return str(f)


def _cli(*args, env=None):
    return subprocess.run([sys.executable, VAREK, *args], capture_output=True, text=True,
                          env={**os.environ, **(env or {})}, timeout=60)


def _decide(policy_file, url, objects):
    def hx(s):
        return s.encode().hex()
    port = url.split(":")[2].split("/")[0]
    canon = url  # localhost:PORT already carries its port
    assert f":{port}/" in canon
    q = "".join(f"mcp - {hx(canon + '#' + o)}\n" for o in objects)
    r = subprocess.run([VDP, policy_file, "batch"], input=q, capture_output=True, text=True, timeout=30)
    return [json.loads(ln) for ln in r.stdout.splitlines()]


# ---------------------------------------------------------------- pure parts --

def test_classify():
    assert mt.classify({"name": "a", "annotations": {"readOnlyHint": True}})[0] == "allow"
    assert mt.classify({"name": "a", "annotations": {"readOnlyHint": True, "destructiveHint": True}})[0] == "step_up"
    assert mt.classify({"name": "a"})[0] == "step_up"
    assert mt.classify({"name": "a", "annotations": {"readOnlyHint": "true"}})[0] == "step_up"  # not a boolean
    assert mt.classify({"name": "a", "annotations": {"readOnlyHint": False}})[0] == "step_up"


@pytest.mark.parametrize("name", ["", "a b", "a#b", "get_*", "x?", "[x]", "a\\b", "café", "a\tb", "x" * 4096])
def test_unnamable(name):
    assert mt.classify({"name": name, "annotations": {"readOnlyHint": True}})[0] == "refuse"


def test_fingerprint_order_and_source():
    full = [{"name": "b", "inputSchema": {"properties": {"y": {}, "x": {}}, "required": ["x"]}},
            {"name": "a", "annotations": {"readOnlyHint": True}, "inputSchema": {}}]
    summary = [{"name": "a", "annotations": {"readOnlyHint": True}, "arguments": []},
               {"name": "b", "annotations": None, "arguments": ["x", "y"], "required": ["x"]}]
    assert mt.fingerprint(full) == mt.fingerprint(list(reversed(full))) == mt.fingerprint(summary)
    changed = [full[0], {**full[1], "annotations": {"readOnlyHint": False}}]
    assert mt.fingerprint(changed) != mt.fingerprint(full)


def test_url_rules():
    with pytest.raises(mt.McpToolsError, match="host name, not an address"):
        mt.write_policy("http://127.0.0.1:9/mcp", [])
    with pytest.raises(mt.McpToolsError, match="no query"):
        mt.write_policy("https://h.example/mcp?x=1", [])
    text = mt.write_policy("https://omcp.example.com/mcp/app1", [])
    assert "proxy ports" not in text and "allow host omcp.example.com:443" in text
    assert "root alone approves" in text


def test_load_tools_forms(tmp_path):
    tools = [{"name": "a"}]
    for i, d in enumerate([tools, {"tools": tools}, {"result": {"tools": tools}},
                           {"mcp": {"tools": tools}, "token": {"form": "JWT"}}]):
        f = tmp_path / f"t{i}.json"
        f.write_text(json.dumps(d))
        assert mt.load_tools(str(f)) == tools
    f = tmp_path / "bad.json"
    f.write_text("{}")
    with pytest.raises(mt.McpToolsError):
        mt.load_tools(str(f))


# -------------------------------------------------------- against the stand-in --

@pytest.mark.parametrize("sse", [False, True])
def test_fetch_pages_and_sse(standin, sse):
    url, _ = standin(*(["--sse"] if sse else []))
    got = mt.fetch_tools(url, TOKEN)
    assert [t["name"] for t in got["tools"]] == [
        "search-osdk-todo-task", "get-overdue-osdk-todo-tasks", "create-osdk-todo-task",
        "modify-osdk-todo-task-status", "delete-osdk-todo-task"]   # three pages of two
    assert got["server"]["name"] == "omcp-standin"


def test_no_tool_called_and_token_not_logged(standin):
    url, log = standin()
    mt.fetch_tools(url, TOKEN)
    recs = [json.loads(ln) for ln in log.read_text().splitlines()]
    assert {r["method"] for r in recs} == {"initialize", "notifications/initialized", "tools/list"}
    assert TOKEN not in log.read_text()


def test_token_refused(standin):
    url, _ = standin()
    with pytest.raises(mt.McpToolsError, match="refused the token"):
        mt.fetch_tools(url, "wrong")


def test_cli_write_check_and_no_token_in_output(standin, tmp_path):
    url, _ = standin("--sse")
    out = tmp_path / "omcp.txt"
    r = _cli("mcp", "tools", url, "--token-file", _tokfile(tmp_path), "--approvers", "varek-approvers",
             "-o", str(out))
    assert r.returncode == 0, r.stderr
    text = out.read_text()
    assert TOKEN not in text + r.stdout + r.stderr
    assert f"allow mcp {url} tools/call search-osdk-todo-task" in text
    assert f"allow mcp {url} tools/call get-overdue-osdk-todo-tasks" in text
    for name in ("create-osdk-todo-task", "modify-osdk-todo-task-status", "delete-osdk-todo-task"):
        assert (f"step_up mcp {url} tools/call {name} mode=hold timeout=300 approvers=varek-approvers"
                in text)
    assert _cli("mcp", "tools", url, "--token-file", _tokfile(tmp_path), "-o", str(out)).returncode == 2  # exists
    r = _cli("mcp", "tools", url, "--check", str(out), env={"VAREK_MCP_TOKEN": TOKEN})
    assert r.returncode == 0 and r.stdout.startswith("unchanged"), r.stdout + r.stderr


def test_cli_check_fails_on_change(standin, tmp_path):
    url, _ = standin()
    out = tmp_path / "omcp.txt"
    assert _cli("mcp", "tools", url, "--token-file", _tokfile(tmp_path), "-o", str(out)).returncode == 0
    url2, _ = standin("--variant", "changed")
    port2 = url2.split(":")[2].split("/")[0]
    text = out.read_text().replace(url.split(":")[2].split("/")[0], port2)   # same server, new list
    out.write_text(text)
    r = _cli("mcp", "tools", url2, "--token-file", _tokfile(tmp_path), "--check", str(out))
    assert r.returncode == 1
    assert "archive-osdk-todo-task" in r.stdout


def test_cli_check_other_url(standin, tmp_path):
    url, _ = standin()
    out = tmp_path / "omcp.txt"
    assert _cli("mcp", "tools", url, "--token-file", _tokfile(tmp_path), "-o", str(out)).returncode == 0
    r = _cli("mcp", "tools", "https://other.example/mcp", "--check", str(out))   # refused before any fetch
    assert r.returncode == 2 and "was written for" in r.stderr


def test_cli_from_not_json(tmp_path):
    f = tmp_path / "policy.txt"
    f.write_text("require warden 1.42\n")
    r = _cli("mcp", "tools", "https://omcp.example.com/mcp", "--from", str(f))
    assert r.returncode == 2 and "not JSON" in r.stderr and "Traceback" not in r.stderr


def test_cli_unnamable_refused(standin, tmp_path):
    url, _ = standin("--variant", "unnamable")
    r = _cli("mcp", "tools", url, "--token-file", _tokfile(tmp_path))
    assert r.returncode == 0
    assert "'export tasks*'" in r.stdout and "tools/call export" not in r.stdout


def test_cli_from_measure_output(tmp_path):
    measure = {"token": {"form": "JWT"}, "mcp": {"tools": [
        {"name": "search-osdk-todo-task", "annotations": {"readOnlyHint": True}, "arguments": ["project_id"]},
        {"name": "create-osdk-todo-task", "annotations": None, "arguments": ["title"], "required": ["title"]}]}}
    f = tmp_path / "omcp_measure_x.json"
    f.write_text(json.dumps(measure))
    r = _cli("mcp", "tools", "https://omcp.example.com/mcp/app1", "--from", str(f))
    assert r.returncode == 0
    assert "allow mcp https://omcp.example.com/mcp/app1 tools/call search-osdk-todo-task" in r.stdout
    assert "step_up mcp https://omcp.example.com/mcp/app1 tools/call create-osdk-todo-task" in r.stdout


# ------------------------------------------------ the decision procedure agrees --

@pytest.mark.skipif(not HAVE_VDP, reason="tools/vdp_check not built")
def test_written_policy_decides(standin, tmp_path):
    url, _ = standin()
    out = tmp_path / "omcp.txt"
    assert _cli("mcp", "tools", url, "--token-file", _tokfile(tmp_path), "--approvers", "varek-approvers",
                "-o", str(out)).returncode == 0
    lint = subprocess.run([VDP, str(out), "lint"], capture_output=True, text=True)
    assert lint.returncode == 0, lint.stdout + lint.stderr
    v = _decide(str(out), url, [
        "tools/call#search-osdk-todo-task", "tools/call#get-overdue-osdk-todo-tasks",
        "tools/call#create-osdk-todo-task", "tools/call#modify-osdk-todo-task-status",
        "tools/call#delete-osdk-todo-task", "tools/call#archive-osdk-todo-task",
        "initialize#", "notifications/initialized#", "tools/list#", "resources/read#file:///x"])
    assert [(x["verdict"], x.get("verb")) for x in v] == [
        ("SATISFIED", "allow"), ("SATISFIED", "allow"),
        ("UNSATISFIED", "step_up"), ("UNSATISFIED", "step_up"), ("UNSATISFIED", "step_up"),
        ("UNKNOWN", None),
        ("SATISFIED", "allow"), ("SATISFIED", "allow"), ("SATISFIED", "allow"),
        ("UNKNOWN", None)]
