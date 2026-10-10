# SPDX-License-Identifier: MIT
"""Tests for `varek bench --launches` (v1.27, step 7). Run with `make test-cli`.

The pure parts (parsing the workload's output, the policies, the checks, the
report) run anywhere; the end-to-end run needs Linux, root, Landlock and a
built runtime.
"""
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # varek/v1_4
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_bench_launch as bl  # noqa: E402

KINDS = [k for k, _ in bl.KINDS]
BUILT = all(os.access(os.path.join(HERE, b), os.X_OK)
            for b in ("warden", "tools/bench_workload", "tools/vdp_cert_check"))
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def workload_output(n, ok=True, denied_errno=None):
    out = [f"BENCHW 1 n={n} warmup=0"]
    for k in KINDS:
        if k == "launch_denied" and denied_errno:
            out.append(f"CLASS {k} ok=0 fail={n} errnos={denied_errno}:{n}")
        else:
            out.append(f"CLASS {k} ok={n if ok else 0} fail={0 if ok else n} errnos=")
        out.append(f"SAMPLES {k} " + " ".join(str(100.0 + i) for i in range(n)))
    return "\n".join(out + ["END"]) + "\n"


def test_parse():
    r = bl.parse(workload_output(3), KINDS)
    assert r["n"] == 3 and r["samples"]["launch_allowed"] == [100.0, 101.0, 102.0]
    assert r["classes"]["open_allowed"]["ok"] == 3


def test_parse_rejects_incomplete_output():
    with pytest.raises(ValueError):
        bl.parse(workload_output(3).replace("END\n", ""), KINDS)
    with pytest.raises(ValueError):
        bl.parse(workload_output(3).replace("SAMPLES open_allowed 100.0 101.0 102.0", "SAMPLES open_allowed 1"),
                 KINDS)


def test_policies():
    on, off = bl.compose_policy("/d", True), bl.compose_policy("/d", False)
    assert on.startswith("require warden 1.27\n") and off.startswith("require warden 1.26\n")
    # the deny rule first: the first rule that matches decides
    assert on.index("deny exec /d/bin/denied") < on.index("allow exec /d/bin/ok")
    assert "allow path /d/allowed/ readonly" in on


def recs_on(d, calls, results=None):
    recs = [{"action": "process.exec", "resolved": f"{d}/bin/ok", "rule": "exec_allowed", "check": "ok",
             "decision_final": "ALLOW", "latency_us": 50} for _ in range(calls)]
    recs += [{"action": "process.exec", "resolved": f"{d}/bin/denied", "rule": "policy_match",
              "decision_final": "DENY", "latency_us": 30} for _ in range(calls)]
    recs += [{"event": "exec_result", "result": "launched"} for _ in range(calls if results is None else results)]
    return recs


def test_checks_on_pass_and_fail():
    wl = bl.parse(workload_output(5, denied_errno=13), KINDS)
    assert all(ok for _, ok, _ in bl.check_on(wl, recs_on("/d", 5), "/d", 5))
    assert not all(ok for _, ok, _ in bl.check_on(wl, recs_on("/d", 5, results=4), "/d", 5))
    bad = recs_on("/d", 5) + [{"rule": "exec_identity_mismatch"}]
    assert not all(ok for _, ok, _ in bl.check_on(wl, bad, "/d", 5))
    wl2 = bl.parse(workload_output(5), KINDS)          # the denied launch ran
    assert not all(ok for _, ok, _ in bl.check_on(wl2, recs_on("/d", 5), "/d", 5))


def test_checks_off():
    wl = bl.parse(workload_output(5), KINDS)
    wl["classes"]["launch_allowed"] = {"ok": 0, "fail": 5, "errnos": {13: 5}}
    recs = [{"action": "process.exec", "rule": "deny_only_nonfile_v191"} for _ in range(5)]
    assert all(ok for _, ok, _ in bl.check_off(wl, recs, 5))
    assert not all(ok for _, ok, _ in bl.check_off(wl, recs[:4], 5))


def test_report():
    st = {"n": 10, "p50": 100.0, "p90": 110.0, "p99": 120.0, "max": 130.0, "mean": 101.0}
    res = {"date": "2026-10-10T00:00:00Z",
           "host": {"kernel": "6", "cpus": 4, "cpu_model": "x"},
           "warden": {"version": "1.27.0", "sha256": "a" * 64, "landlock": {"abi": 7}},
           "settings": {"calls_per_kind_per_run": 10, "warmup": 1, "rounds": 1, "run_as": "nobody"},
           "kinds": {k: {"label": l, "native": st, "off": st, "on": st,
                         "added_p50_us": {"off": 0.0, "on": 0.0},
                         "warden_decision_us": {"off": None, "on": st}} for k, l in bl.KINDS},
           "checks": [{"check": "x", "ok": True, "detail": ""}]}
    t = bl.format_report(res, "1.2.0")
    assert "Landlock ABI 7" in t and "launches on" in t and "All 1 checks passed." in t
    res["checks"][0]["ok"] = False
    res["checks"][0]["detail"] = "it broke"
    assert "FAIL  x: it broke" in bl.format_report(res)


@pytest.mark.skipif(not (BUILT and ROOT and sys.platform.startswith("linux")), reason="needs Linux, root and the runtime")
def test_bench_launches_end_to_end(tmp_path):
    env = dict(os.environ, NO_COLOR="1", VAREK_CONFIG="/nonexistent/varek.conf")
    out = tmp_path / "l.json"
    r = subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek"), "bench", "--launches",
                        "-n", "20", "--warmup", "2", "--rounds", "1", "-o", str(out)],
                       text=True, capture_output=True, env=env)
    import json
    res = json.loads(out.read_text()) if out.exists() else {}
    if res.get("warden", {}).get("landlock") is None and res:
        pytest.skip("no Landlock on this host")
    assert r.returncode == 0, r.stdout + r.stderr
    assert res["ok"] and res["kinds"]["launch_allowed"]["on"]["n"] == 20
