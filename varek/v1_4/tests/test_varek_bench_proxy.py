# SPDX-License-Identifier: MIT
"""Tests for `varek bench --proxy` (v1.26.1, step 8). Run with `make test-cli`.

The pure parts (parsing the client's output, the policies, the checks, the DNS
answers, the report) run anywhere. The end-to-end test starts the real Warden
and its proxy, so it needs Linux, root, a built runtime and an address of this
host's own other than loopback.
"""
import json
import os
import struct
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # varek/v1_4
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_bench_proxy as bp  # noqa: E402

VAREK = os.path.join(HERE, "tools", "varek")
CERT = os.path.join(HERE, "tools", "vdp_cert_check")
BUILT = all(os.access(os.path.join(HERE, b), os.X_OK)
            for b in ("warden", "warden-proxy", "tools/vdp_check", "tools/vdp_cert_check"))
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def _has_address():
    try:
        bp.host_address()
        return True
    except Exception:  # noqa: BLE001
        return False


needs_runtime = pytest.mark.skipif(
    not (BUILT and ROOT and sys.platform.startswith("linux") and _has_address()),
    reason="needs Linux, root, a built runtime and an address other than loopback")


def varek(*args):
    env = dict(os.environ, NO_COLOR="1", VAREK_CONFIG="/nonexistent/varek.conf")
    return subprocess.run([sys.executable, VAREK, *args], text=True, capture_output=True, env=env)


def client_output(kinds, n, status=200):
    out = []
    for k in kinds:
        out.append(f"CLASS {k} ok={n if status == 200 else 0} fail={0 if status == 200 else n} status={status}:{n}")
        out.append(f"SAMPLES {k} " + " ".join(str(100.0 + i) for i in range(n)))
    return "\n".join(out + ["END"]) + "\n"


# ----------------------------------------------------------------- parsing --

def test_parse_client():
    r = bp.parse_client(client_output(["https", "request"], 3), ["https", "request"], 3)
    assert r["classes"]["https"] == {"ok": 3, "fail": 0, "status": {200: 3}}
    assert r["samples"]["request"] == [100.0, 101.0, 102.0]


def test_parse_client_rejects_incomplete_output():
    with pytest.raises(ValueError):
        bp.parse_client(client_output(["https"], 3).replace("END\n", ""), ["https"], 3)
    with pytest.raises(ValueError):
        bp.parse_client(client_output(["https"], 2), ["https"], 3)
    with pytest.raises(ValueError):
        bp.parse_client(client_output(["https"], 3), ["https", "denied"], 3)


def test_kinds_per_mode():
    assert bp.kinds_for("native") == ["https", "request", "denied"]
    assert bp.kinds_for("sni") == ["https", "request"]
    assert bp.kinds_for("inspect") == ["https", "request", "denied"]


# ------------------------------------------------------------------ policy --

def test_policies_name_the_mode_and_the_request_rules():
    sni = bp.compose_policy("sni", 4433, "/tmp/x")
    insp = bp.compose_policy("inspect", 4433, "/tmp/x")
    assert "proxy on\n" in sni and "request" not in sni
    assert "proxy inspect\n" in insp
    # the deny rule first: the first rule that matches decides
    assert insp.index("deny request GET https://bench.example.com:4433/denied") < \
        insp.index("allow request GET https://bench.example.com:4433/ok")
    assert "allow path /tmp/x/ readonly" in insp


@pytest.mark.skipif(not os.access(CERT, os.X_OK), reason="needs tools/vdp_cert_check")
def test_policies_parse_as_the_warden_reads_them(tmp_path):
    for mode, want in (("sni", "on"), ("inspect", "inspect")):
        p = tmp_path / f"{mode}.policy"
        p.write_text(bp.compose_policy(mode, 4433, str(tmp_path)))
        r = subprocess.run([CERT, str(p), "proxy"], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert r.stdout.split()[:2] == [want, "4433"]


# ------------------------------------------------------------------ checks --

def recs_for(mode, calls, ka_conns=1):
    insp = mode == "inspect"
    conns = calls * (2 if insp else 1) + ka_conns
    recs = [{"action": "net.proxy", "rule": "proxy_dialed", "decision_final": "ALLOW", "check": "ok",
             "latency_us": 100, **({"inspected": True} if insp else {})} for _ in range(conns)]
    if insp:
        recs += [{"action": "net.request", "rule": "request_allowed", "decision_final": "ALLOW", "check": "ok",
                  "target": "GET https://bench.example.com:1/ok", "latency_us": 3} for _ in range(2 * calls)]
        recs += [{"action": "net.request", "rule": "policy_match", "decision_final": "DENY",
                  "target": "GET https://bench.example.com:1/denied", "latency_us": 5} for _ in range(calls)]
    return recs


def run_for(mode, calls):
    st = {k: (403 if k == "denied" else 200) for k in bp.kinds_for(mode)}
    return {"classes": {k: {"ok": calls if s == 200 else 0, "fail": 0 if s == 200 else calls,
                            "status": {s: calls}} for k, s in st.items()}}


def test_checks_pass_when_every_request_is_as_promised():
    for mode in ("sni", "inspect"):
        res = bp.check_mode(mode, run_for(mode, 5), recs_for(mode, 5), 5, 0)
        assert all(ok for _, ok, _ in res), [c for c in res if not c[1]]


def test_checks_fail_on_a_denied_request_that_reached_the_server():
    res = bp.check_mode("inspect", run_for("inspect", 5), recs_for("inspect", 5), 5, 1)
    assert [c for c, ok, _ in res if not ok] == ["inspect: the server never saw a denied request"]


def test_checks_fail_on_an_uncertified_request_or_a_missing_record():
    recs = recs_for("inspect", 5)
    next(r for r in recs if r.get("rule") == "request_allowed")["check"] = "refused"
    assert any(not ok for _, ok, _ in bp.check_mode("inspect", run_for("inspect", 5), recs, 5, 0))
    recs = recs_for("inspect", 5)[:-1]
    assert any(not ok for _, ok, _ in bp.check_mode("inspect", run_for("inspect", 5), recs, 5, 0))


def test_checks_fail_on_an_sni_run_that_inspected_or_a_denied_request_answered():
    recs = recs_for("sni", 5)
    recs[0]["inspected"] = True
    assert any(not ok for _, ok, _ in bp.check_mode("sni", run_for("sni", 5), recs, 5, 0))
    run = run_for("inspect", 5)
    run["classes"]["denied"]["status"] = {403: 4, 200: 1}
    assert any(not ok for _, ok, _ in bp.check_mode("inspect", run, recs_for("inspect", 5), 5, 0))


def test_native_check():
    good = {"classes": {k: {"ok": 5, "fail": 0, "status": {200: 5}} for k in bp.kinds_for("native")}}
    assert bp.check_native(good, 5)[0][1]
    bad = {"classes": {k: {"ok": 4, "fail": 1, "status": {200: 4, 0: 1}} for k in bp.kinds_for("native")}}
    assert not bp.check_native(bad, 5)[0][1]


# --------------------------------------------------------------------- DNS --

def query(name, qtype=1):
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for lab in name.split("."):
        q += bytes([len(lab)]) + lab.encode()
    return q + b"\0" + struct.pack("!HH", qtype, 1)


def test_dns_answers_the_bench_name_only():
    d = bp._Dns.__new__(bp._Dns)
    d.a = bytes([192, 0, 2, 7])
    a = d.answer(query(bp.NAME))
    qid, flags, qd, an = struct.unpack("!HHHH", a[:8])
    assert (qid, flags & 0xF, qd, an) == (0x1234, 0, 1, 1) and a.endswith(bytes([192, 0, 2, 7]))
    a = d.answer(query("BENCH.example.com"))                 # case does not matter
    assert struct.unpack("!H", a[6:8])[0] == 1
    a = d.answer(query("other.example.com"))
    assert struct.unpack("!H", a[2:4])[0] & 0xF == 3         # NXDOMAIN
    a = d.answer(query(bp.NAME, 28))                         # AAAA: no answer
    assert struct.unpack("!HH", a[2:4] + a[6:8]) == (struct.unpack("!H", a[2:4])[0], 0)
    assert struct.unpack("!H", a[2:4])[0] & 0xF == 0


# ------------------------------------------------------------------ report --

def sample_result(ok=True):
    st = {"n": 10, "p50": 1000.0, "p90": 1100.0, "p99": 1200.0, "max": 1300.0, "mean": 1010.0}
    kinds = {}
    for k, label, ms in bp.KINDS:
        kinds[k] = {"label": label, **{m: (st if m in ms else None) for m in bp.MODES},
                    "added_p50_us": {m: 0.0 for m in ("sni", "inspect") if m in ms}, "round_p50_us": {}}
    return {"date": "2026-10-08T00:00:00Z",
            "host": {"kernel": "6", "machine": "x86_64", "cpus": 4, "cpu_model": "", "memory": ""},
            "warden": {"version": "1.26.0", "sha256": "a" * 64, "proxy_sha256": "b" * 64},
            "server": {"address": "192.0.2.2", "port": 1, "certificate": "RSA 2048, self-signed"},
            "settings": {"requests_per_kind_per_run": 10, "warmup": 1, "rounds": 1, "run_as": "nobody",
                         "signing": False},
            "kinds": kinds,
            "warden_us": {k: {"n": 1, "p50": 3.0, "p99": 5.0} for k in
                          ("connection_sni", "connection_inspect", "request_allowed", "request_denied")},
            "checks": [{"check": "x", "ok": ok, "detail": "" if ok else "it broke"}]}


def test_report_has_every_kind_and_mode():
    t = bp.format_report(sample_result(), "1.2.0")
    for _, label, _ in bp.KINDS:
        assert label in t
    assert "SNI mode" in t and "inspecting" in t and "a request decided and certified" in t
    assert "all 1 checks passed" in t


def test_report_lists_failed_checks():
    assert "FAIL  x: it broke" in bp.format_report(sample_result(ok=False))


# ------------------------------------------------------------- end to end --

def test_bench_proxy_refuses_bare_and_policy():
    if not ROOT:
        pytest.skip("needs root")
    r = varek("bench", "--proxy", "--bare")
    assert r.returncode != 0 and "--policy and --bare do not apply" in r.stderr + r.stdout


@needs_runtime
def test_bench_proxy_end_to_end(tmp_path):
    out = tmp_path / "px.json"
    r = varek("bench", "--proxy", "-n", "20", "--warmup", "2", "--rounds", "1", "-o", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    res = json.loads(out.read_text())
    assert res["ok"] and all(c["ok"] for c in res["checks"])
    assert res["kinds"]["https"]["inspect"]["n"] == 20 and res["kinds"]["denied"]["sni"] is None
    assert res["warden_us"]["request_allowed"]["n"] > 0
    # step 8: inspecting mode adds a second handshake to a new connection, not
    # a delayed-ACK stall (about 40 ms before quick ACKs during the handshake)
    assert res["kinds"]["https"]["added_p50_us"]["inspect"] < 30000
    assert "VAREK bench --proxy" in r.stdout
