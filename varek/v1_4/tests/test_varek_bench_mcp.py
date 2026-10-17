# SPDX-License-Identifier: MIT
"""Tests for `varek bench --mcp` and `varek bench --for` (v1.31, step 9). Run
with `make test-cli`.

The pure parts (the client's bodies, the policies, the checks, the report)
run anywhere. The end-to-end tests start the real Warden (and for --mcp its
proxy), so they need Linux, root, a built runtime and, for --mcp, an
address of this host's own other than loopback.
"""
import hashlib
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # varek/v1_4
sys.path.insert(0, os.path.join(HERE, "tools"))
import bench_mcp_client as cl  # noqa: E402
import varek_baseline as vbl  # noqa: E402
import varek_bench as vb  # noqa: E402
import varek_bench_mcp as bm  # noqa: E402

VAREK = os.path.join(HERE, "tools", "varek")
LINT = os.path.join(HERE, "tools", "vdp_check")
BUILT = all(os.access(os.path.join(HERE, b), os.X_OK)
            for b in ("warden", "warden-proxy", "tools/vdp_check", "tools/vdp_cert_check", "tools/bench_workload"))
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
LINUX = sys.platform.startswith("linux")


def _has_address():
    try:
        bm.vbp.host_address()
        return True
    except Exception:  # noqa: BLE001
        return False


needs_runtime = pytest.mark.skipif(not (BUILT and ROOT and LINUX), reason="needs Linux, root and a built runtime")
needs_address = pytest.mark.skipif(not (BUILT and ROOT and LINUX and _has_address()),
                                   reason="needs Linux, root, a built runtime and an address other than loopback")
PORTS = {"allowed": 1, "denied": 2, "request": 3}
D = "/tmp/varek-bench-x"


def varek(*args):
    env = dict(os.environ, NO_COLOR="1", VAREK_CONFIG="/nonexistent/varek.conf")
    return subprocess.run([sys.executable, VAREK, *args], text=True, capture_output=True, env=env)


# ------------------------------------------------------------- --mcp: pure --

def test_each_call_is_exactly_its_size_and_a_tools_call_of_echo():
    for size in bm.SIZES:
        b = cl.body(7, size)
        assert len(b) == size
        m = json.loads(b)
        assert (m["id"], m["method"], m["params"]["name"]) == (7, "tools/call", "echo")
    assert bm._Server.ID.match(cl.body(123456, 1024)).group(1) == b"123456"
    with pytest.raises(SystemExit):
        cl.body(1, 20)


def test_policies_name_the_endpoint_by_a_request_rule_or_an_mcp_rule():
    req, mcp = (bm.compose_policy(m, 4433, "/tmp/b") for m in ("request", "mcp"))
    url = "https://bench.example.com:4433/mcp"
    assert f"allow request POST {url}" in req and "allow mcp" not in req
    assert f"allow mcp {url} tools/call echo" in mcp and "allow request" not in mcp
    for t in (req, mcp):
        assert "require warden 1.31" in t and "proxy inspect" in t and "proxy ports 4433" in t


@pytest.mark.skipif(not os.access(LINT, os.X_OK), reason="needs tools/vdp_check")
def test_policies_lint(tmp_path):
    for mode in ("request", "mcp"):
        p = tmp_path / f"{mode}.policy"
        p.write_text(bm.compose_policy(mode, 4433, str(tmp_path)))
        r = subprocess.run([LINT, str(p), "lint"], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr


def mcp_recs(sizes, calls, **over):
    recs = [{"action": "net.proxy", "decision_final": "ALLOW", "check": "ok", "inspected": True, "latency_us": 90}]
    i, seq = 0, 1
    for s in sizes:
        for _ in range(calls):
            i += 1
            seq += 1
            r = {"action": "net.mcp", "seq": seq, "rule": "mcp_allowed", "decision_final": "ALLOW", "check": "ok",
                 "mcp_method": "tools/call", "mcp_name": "echo", "rpc_id": str(i), "body_len": s,
                 "body_sha256": hashlib.sha256(cl.body(i, s)).hexdigest(), "latency_us": s // 1024}
            r.update(over)
            recs.append(r)
    return recs


def outcome(sizes, calls, status=200):
    return {"classes": {bm.kind(s): {"ok": calls if status == 200 else 0, "fail": 0 if status == 200 else calls,
                                     "status": {status: calls}} for s in sizes}}


def test_checks_pass_when_every_call_is_as_promised():
    sizes, calls = (1024, 16384), 4
    assert all(ok for _, ok, _ in bm.check_mode("mcp", outcome(sizes, calls), mcp_recs(sizes, calls), sizes, calls))
    rq = [{"action": "net.proxy", "decision_final": "ALLOW", "check": "ok", "inspected": True}] + [
        {"action": "net.request", "rule": "request_allowed", "decision_final": "ALLOW", "check": "ok",
         "target": "POST https://bench.example.com:1/mcp"} for _ in range(calls * len(sizes))]
    assert all(ok for _, ok, _ in bm.check_mode("request", outcome(sizes, calls), rq, sizes, calls))
    assert all(ok for _, ok, _ in bm.check_mode("native", outcome(sizes, calls), [], sizes, calls))


def test_checks_fail_on_a_wrong_body_hash_a_wrong_name_a_missing_record_or_a_refusal():
    sizes, calls = (1024,), 3
    bad = mcp_recs(sizes, calls)
    bad[2]["body_sha256"] = "0" * 64
    assert not all(ok for _, ok, _ in bm.check_mode("mcp", outcome(sizes, calls), bad, sizes, calls))
    assert not all(ok for _, ok, _ in bm.check_mode("mcp", outcome(sizes, calls),
                                                     mcp_recs(sizes, calls, mcp_name="other"), sizes, calls))
    assert not all(ok for _, ok, _ in bm.check_mode("mcp", outcome(sizes, calls),
                                                     mcp_recs(sizes, calls)[:-1], sizes, calls))
    assert not all(ok for _, ok, _ in bm.check_mode("mcp", outcome(sizes, calls, 403),
                                                     mcp_recs(sizes, calls), sizes, calls))
    # a request-mode run whose calls were decided as MCP calls
    assert not all(ok for _, ok, _ in bm.check_mode("request", outcome(sizes, calls),
                                                     mcp_recs(sizes, calls), sizes, calls))


def test_by_size_drops_each_sizes_warmup():
    sizes, calls = (1024, 2048), 5
    got = bm.by_size(mcp_recs(sizes, calls), "net.mcp", sizes, calls, 2)
    assert got == {1024: [1, 1, 1], 2048: [2, 2, 2]}


def fake_result():
    st = lambda p: {"n": 10, "p50": p, "p90": p, "p99": p + 1, "min": p, "max": p + 2, "mean": p}  # noqa: E731
    sizes = {}
    for s in bm.SIZES:
        sizes[bm.kind(s)] = {"label": bm.label(s), "bytes": s, "native": st(100), "request": st(300), "mcp": st(400),
                             "added_p50_us": {"request": 200, "mcp": 300}, "held_p50_us": 100,
                             "warden_us": {"request": st(3), "mcp": st(20)}}
    return {"host": {"kernel": "6.1", "machine": "x86_64", "cpus": 4, "cpu_model": "", "memory": ""},
            "settings": {"rounds": 3, "calls_per_size_per_run": 10, "warmup": 1},
            "warden": {"version": "1.31.0", "sha256": "a" * 64, "proxy_sha256": "b" * 64},
            "date": "2026-10-14T00:00:00Z", "server": {"address": "192.0.2.2"}, "sizes": sizes,
            "checks": [{"check": "x", "ok": True, "detail": ""}], "ok": True}


def test_report_has_every_size_and_the_held_column():
    out = bm.format_report(fake_result(), "1.3.0")
    for s in bm.SIZES:
        assert f"  {bm.label(s):8}" in out
    assert "held" in out and "+100" in out and "all 1 checks passed" in out


def test_report_lists_failed_checks():
    res = fake_result()
    res["checks"] = [{"check": "round 1 mcp: x", "ok": False, "detail": "why"}]
    assert "FAIL  round 1 mcp: x: why" in bm.format_report(res)


# ------------------------------------------------------------- --for: pure --

def test_a_subject_adds_the_server_line_after_require_and_the_agents_exec_rule():
    base = "require warden 1.31\nallow path /usr/ readonly\n" + "\n".join(vbl.server_rules("bench", "/p")) + "\n"
    for subject in ("agent", "server"):
        t = vb.compose_policy(D, PORTS, base, subject=subject)
        lines = t.splitlines()
        assert lines[:2] == ["require warden 1.31", f"mcp server bench exec {D}/srv/server"]
        assert f"allow exec {D}/srv/agent" in lines
        own = [ln for ln in lines if f"{D}/allowed/" in ln or "127.0.0.1:" in ln or f"{D}/denied/" in ln]
        assert len(own) == 5
        assert all(ln.endswith(" for=bench") for ln in own) == (subject == "server")
        assert not any(ln.endswith(" for=bench") for ln in own) == (subject == "agent")
    with pytest.raises(vb.BenchError):
        vb.compose_policy(D, PORTS, "allow path /usr/ readonly\n", subject="server")
    bare = vb.compose_policy(D, PORTS, subject="server").splitlines()
    assert bare[1:3] == ["require warden 1.31", f"mcp server bench exec {D}/srv/server"]


@pytest.mark.skipif(not os.access(LINT, os.X_OK), reason="needs tools/vdp_check")
def test_subject_policies_lint(tmp_path):
    base = "require warden 1.31\nallow path /usr/ readonly\n" + "\n".join(vbl.server_rules("bench", "/p")) + "\n"
    for subject in ("agent", "server"):
        p = tmp_path / f"{subject}.policy"
        p.write_text(vb.compose_policy(str(tmp_path), PORTS, base, subject=subject))
        r = subprocess.run([LINT, str(p), "lint"], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr


def test_server_rules_are_the_baselines_and_the_working_directory_all_for_the_server():
    rules = [ln.split("#", 1)[0].strip() for ln in vbl.server_rules("srv", "/w")]
    assert rules and all(r.endswith(" for=srv") for r in rules)
    assert "allow path /w/ readonly for=srv" in rules and "allow path exact /w readonly for=srv" in rules
    n = sum(len(g) for g in (vbl.TRUST_READS, vbl.CREDENTIAL_DENIES, vbl.SYSTEM_DENIES, vbl.SYSTEM_READS))
    assert len(rules) == n + 2


def test_a_wrong_subject_is_refused():
    with pytest.raises(vb.BenchError):
        vb.run("/nonexistent", "/nonexistent", subject="other")


# ------------------------------------------------------------- end to end --

def test_bench_mcp_and_for_refuse_bare_and_policy():
    if not ROOT:
        pytest.skip("needs root")
    r = varek("bench", "--mcp", "--bare")
    assert r.returncode != 0 and "--policy and --bare do not apply" in r.stderr + r.stdout
    r = varek("bench", "--for", "--policy", "healthcare")
    assert r.returncode != 0 and "--policy and --bare do not apply" in r.stderr + r.stdout


@needs_address
def test_bench_mcp_end_to_end(tmp_path):
    out = tmp_path / "mcp.json"
    r = varek("bench", "--mcp", "-n", "10", "--warmup", "1", "--rounds", "1", "-o", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    res = json.loads(out.read_text())
    assert res["ok"] and all(c["ok"] for c in res["checks"])
    assert set(res["sizes"]) == {bm.kind(s) for s in bm.SIZES}
    assert res["sizes"]["s1048576"]["warden_us"]["mcp"]["n"] == 10
    # no delayed-ACK stall (about 40 ms) on a small call
    assert res["sizes"]["s1024"]["added_p50_us"]["mcp"] < 30000
    assert "VAREK bench --mcp" in r.stdout


@needs_runtime
def test_bench_for_end_to_end(tmp_path):
    out = tmp_path / "for.json"
    r = varek("bench", "--for", "-n", "100", "--warmup", "10", "--rounds", "1", "-o", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    res = json.loads(out.read_text())
    assert res["ok"]
    assert set(res["bases"]) == {"agent", "server", "server + own"}
    assert res["bases"]["server"]["decided_against"] == 5
    assert res["bases"]["agent"]["decided_against"] > res["bases"]["server + own"]["decided_against"] > 5
    assert "each call decided as its subject" in r.stdout
