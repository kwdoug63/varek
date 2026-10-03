# SPDX-License-Identifier: MIT
"""Tests for `varek bench` (v1.22). Run with `make test-cli`.

The pure parts (percentiles, parsing, record matching, the policy it composes,
the verdict checks, the report) run anywhere. The end-to-end tests start the
real Warden, so they need Linux, root and a built runtime (`make`).
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # varek/v1_4
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_bench as vb  # noqa: E402

VAREK = os.path.join(HERE, "tools", "varek")
WORKLOAD = os.path.join(HERE, "tools", "bench_workload")
BUILT = all(os.access(os.path.join(HERE, b), os.X_OK)
            for b in ("warden", "tools/vdp_check", "tools/vdp_cert_check", "tools/bench_workload"))
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
needs_runtime = pytest.mark.skipif(not (BUILT and ROOT and sys.platform.startswith("linux")),
                                   reason="needs Linux, root and a built runtime")

D = "/tmp/varek-bench-test"
PORTS = {"allowed": 41001, "denied": 41002, "request": 41003}
KINDS = [k for k, _ in vb.KINDS]


def varek(*args, config=None):
    env = dict(os.environ, NO_COLOR="1", VAREK_CONFIG=config or "/nonexistent/varek.conf")
    return subprocess.run([sys.executable, VAREK, *args], text=True, capture_output=True, env=env)


# ------------------------------------------------------------- statistics --

def test_nearest_rank_percentiles():
    v = list(range(1, 101))  # 1..100
    assert vb.pct(v, 0.50) == 50
    assert vb.pct(v, 0.90) == 90
    assert vb.pct(v, 0.99) == 99
    assert vb.pct(v, 1.0) == 100
    assert vb.pct([7], 0.99) == 7
    assert vb.pct([], 0.5) is None


def test_stats_summary():
    s = vb.stats([4.0, 1.0, 3.0, 2.0])
    assert s == {"n": 4, "p50": 2.0, "p90": 4.0, "p99": 4.0, "max": 4.0, "mean": 2.5}
    assert vb.stats([]) == {"n": 0}


# ----------------------------------------------------------------- parsing --

def workload_text(n=3, warmup=1, fail=None, samples=None):
    """bench_workload output: CLASS counts every call (warm-up + n), SAMPLES the n timed."""
    fail = fail or {}
    lines = [f"BENCHW 1 n={n} warmup={warmup}"]
    for k in KINDS:
        f = fail.get(k, 0)
        err = f"13:{f}" if f else ""
        lines.append(f"CLASS {k} ok={n + warmup - f} fail={f} errnos={err}")
    for k in KINDS:
        vals = (samples or {}).get(k, [float(i + 1) for i in range(n)])
        lines.append(f"SAMPLES {k} " + " ".join(f"{x:.1f}" for x in vals))
    lines.append("END")
    return "\n".join(lines) + "\n"


def test_parse_workload():
    w = vb.parse_workload(workload_text(n=3, warmup=1, fail={"open_denied": 4}))
    assert w["n"] == 3 and w["warmup"] == 1
    assert w["classes"]["open_denied"] == {"ok": 0, "fail": 4, "errnos": {13: 4}}
    assert w["classes"]["open_allowed"] == {"ok": 4, "fail": 0, "errnos": {}}
    assert w["samples"]["request"] == [1.0, 2.0, 3.0]


def test_parse_workload_rejects_incomplete_output():
    text = workload_text()
    with pytest.raises(ValueError):
        vb.parse_workload(text.replace("END\n", ""))       # cut short
    with pytest.raises(ValueError):
        vb.parse_workload("\n".join(l for l in text.splitlines()
                                    if not l.startswith("SAMPLES request")) + "\n")


def rec(seq, action, resolved, raw, final, check=None, latency=10, dial=None):
    r = {"seq": seq, "action": action, "resolved": resolved, "decision_raw": raw,
         "decision_final": final, "latency_us": latency}
    if check:
        r["check"] = check
    if dial is not None:
        r["dial_us"] = dial
    return r


def good_records(n, warmup):
    """Records for one run under the Warden where every verdict is as promised."""
    out, seq = [], 0
    for _ in range(n + warmup):
        for k in KINDS:
            raw, final = vb.EXPECT[k]
            if k.startswith("open"):
                sub = {"open_allowed": "allowed", "open_denied": "denied", "open_unknown": "unknown"}[k]
                out.append(rec(seq, "file.open", f"{D}/{sub}/f", raw, final,
                               "ok" if final == "ALLOW" else None))
            else:
                port = {"connect_allowed": PORTS["allowed"], "connect_denied": PORTS["denied"],
                        "request": PORTS["request"]}[k]
                out.append(rec(seq, "net.connect", f"127.0.0.1:{port}", raw, final,
                               "ok" if final == "ALLOW" else None,
                               dial=5 if final == "ALLOW" else None))
            seq += 1
    return out


def test_classify_ignores_everything_but_the_bench_calls():
    assert vb.classify(rec(0, "file.open", f"{D}/allowed/f", "ALLOW", "ALLOW"), D, PORTS) == "open_allowed"
    assert vb.classify(rec(0, "net.connect", "127.0.0.1:41002", "DENY", "DENY"), D, PORTS) == "connect_denied"
    assert vb.classify(rec(0, "file.open", "/lib/x86_64-linux-gnu/libc.so.6", "ALLOW", "ALLOW"), D, PORTS) is None
    assert vb.classify(rec(0, "file.readlink", "/proc/self/exe", "UNKNOWN", "DENY"), D, PORTS) is None
    assert vb.classify(rec(0, "net.connect", "127.0.0.1:9", "DENY", "DENY"), D, PORTS) is None


def test_records_by_kind_keeps_all_and_times_after_the_warmup():
    recs = good_records(n=4, warmup=2)
    recs.insert(0, {"event": "run_start", "warden": "1.21.1"})
    every, timed = vb.records_by_kind(recs, D, PORTS, warmup=2)
    assert all(len(every[k]) == 6 for k in KINDS)
    assert all(len(timed[k]) == 4 for k in KINDS)
    # The first two of each kind (seq 0..11) are the warm-up: checked, not timed.
    assert min(r["seq"] for r in timed["open_allowed"]) == 12
    assert min(r["seq"] for r in every["open_allowed"]) == 0


# ------------------------------------------------------------------ policy --

def test_compose_policy_puts_the_base_policy_first():
    base = "require warden 1.14\ndeny path /etc/\nallow path /usr/lib/ readonly\n"
    text = vb.compose_policy(D, PORTS, base)
    assert text.index("deny path /etc/") < text.index(f"allow path {D}/allowed/ readonly")
    assert text.startswith("require warden 1.14")
    assert f"deny  host 127.0.0.1:{PORTS['denied']}" in text
    assert vb.count_rules(text) == 2 + 5
    assert "ld.so.cache" not in text                  # loader rules come from the base policy


def test_loader_rules_only_for_a_dynamic_workload_and_after_the_base_policy():
    assert vb.count_rules(vb.compose_policy(D, PORTS)) == 5
    dyn = vb.compose_policy(D, PORTS, dynamic=True)
    assert vb.count_rules(dyn) == 5 + len(vb.LOADER_RULES)
    assert "allow path /etc/ld.so.cache readonly" in dyn
    based = vb.compose_policy(D, PORTS, "deny path /etc/shadow\n", dynamic=True)
    assert based.index("deny path /etc/shadow") < based.index("ld.so.cache") \
        < based.index(f"{D}/allowed/")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads ELF files")
def test_is_dynamic_reads_the_elf_header():
    assert vb.is_dynamic(os.path.realpath(sys.executable)) is True   # python3 is dynamic
    assert vb.is_dynamic(VAREK) is False                              # a script, not ELF
    assert vb.is_dynamic("/nonexistent") is False


# ------------------------------------------------------------------ checks --

def test_checks_pass_when_every_verdict_is_as_promised():
    n, w = 4, 2
    run = vb.parse_workload(workload_text(n=n, warmup=w, fail={k: n + w for k in vb.REFUSED}))
    every, _ = vb.records_by_kind(good_records(n, w), D, PORTS, w)
    res = vb.check_warden(run, every, n + w)
    assert len(res) == len(KINDS)
    assert all(ok for _, ok, _ in res), res


def test_checks_fail_when_a_base_rule_decides_first():
    n, w = 4, 2
    recs = good_records(n, w)
    for r in recs:
        if r["resolved"] == f"{D}/unknown/f":
            r.update(decision_raw="ALLOW", decision_final="ALLOW", policy_line=1)
    run = vb.parse_workload(workload_text(n=n, warmup=w,
                                          fail={"open_denied": n + w, "connect_denied": n + w}))
    every, _ = vb.records_by_kind(recs, D, PORTS, w)
    res = {c: (ok, det) for c, ok, det in vb.check_warden(run, every, n + w)}
    ok, det = res["open_unknown: decided UNKNOWN"]
    assert not ok and "policy line 1" in det and "--bare" in det


def test_checks_fail_when_a_denied_call_succeeds_or_records_are_missing():
    n, w = 4, 2
    run = vb.parse_workload(workload_text(n=n, warmup=w,
                                          fail={"open_denied": n + w, "open_unknown": n + w}))
    recs = [r for r in good_records(n, w) if r["resolved"] != f"127.0.0.1:{PORTS['request']}"]
    every, _ = vb.records_by_kind(recs, D, PORTS, w)
    res = {c: ok for c, ok, _ in vb.check_warden(run, every, n + w)}
    assert res["connect_denied: refused with EACCES"] is False      # the agent saw success
    assert res["request: one verdict record per call"] is False      # no records at all


def test_a_wrong_verdict_during_the_warmup_is_caught():
    n, w = 4, 2
    recs = good_records(n, w)
    first_denied = next(r for r in recs if r["resolved"] == f"{D}/denied/f")  # a warm-up call
    first_denied.update(decision_raw="ALLOW", decision_final="ALLOW", check="ok")
    run = vb.parse_workload(workload_text(n=n, warmup=w, fail={k: n + w for k in vb.REFUSED}))
    every, _ = vb.records_by_kind(recs, D, PORTS, w)
    res = {c: ok for c, ok, _ in vb.check_warden(run, every, n + w)}
    assert res["open_denied: decided DENY"] is False
    # ... and so is a warm-up call that succeeded where it must be refused.
    run = vb.parse_workload(workload_text(n=n, warmup=w,
                                          fail={"open_denied": n + w - 1, "open_unknown": n + w,
                                                "connect_denied": n + w}))
    every, _ = vb.records_by_kind(good_records(n, w), D, PORTS, w)
    res = {c: ok for c, ok, _ in vb.check_warden(run, every, n + w)}
    assert res["open_denied: refused with EACCES"] is False


def test_resolve_user_accepts_names_uids_and_uid_gid():
    assert vb.resolve_user("root") == (0, 0)
    assert vb.resolve_user("0") == (0, 0)
    assert vb.resolve_user("1234:5678") == (1234, 5678)
    with pytest.raises(vb.BenchError):
        vb.resolve_user("no-such-user-varek")


def test_report_signs_a_negative_added_time():
    res = fake_result()
    res["kinds"]["connect_denied"]["added_p50_us"] = -3.0
    assert " -3.0 " in vb.format_report(res)


def test_native_check():
    assert vb.check_native(vb.parse_workload(workload_text()))[0][1] is True
    bad = vb.check_native(vb.parse_workload(workload_text(fail={"open_allowed": 1})))
    assert bad[0][1] is False and "open_allowed" in bad[0][2]


# ------------------------------------------------------------------ report --

def fake_result(ok=True):
    k = {}
    for key, label in vb.KINDS:
        k[key] = {"label": label,
                  "native": vb.stats([1.0, 2.0, 3.0]), "warden": vb.stats([50.0, 60.0, 70.0]),
                  "added_p50_us": 58.0,
                  "round_p50_us": {"native": [2.0], "warden": [60.0]},
                  "warden_decision_us": vb.stats([10.0, 12.0]),
                  "dial_us": vb.stats([5.0]) if key == "connect_allowed" else None}
    return {"host": {"kernel": "6.1.0", "machine": "x86_64", "cpus": 2, "cpu_model": "Test CPU",
                     "memory": "4096 MiB"},
            "settings": {"rounds": 1, "calls_per_kind_per_run": 3, "warmup": 0, "run_as": "nobody",
                         "signing": True},
            "policy": {"base": "healthcare", "rules": 38, "bench_rules": 5, "sha256": "ab" * 32},
            "warden": {"version": "1.21.1", "sha256": "cd" * 32}, "workload": {"static": True},
            "date": "2026-10-03T00:00:00Z", "kinds": k,
            "checks": [{"check": "x", "ok": ok, "detail": "" if ok else "it broke"}], "ok": ok}


def test_report_has_every_kind_and_the_provenance():
    text = vb.format_report(fake_result(), "1.2.0")
    for _, label in vb.KINDS:
        assert label in text
    for s in ("Warden    1.21.1", "varek command 1.2.0", "healthcare + 5 bench rules", "signed",
              "Test CPU", "all 1 checks passed", "+58"):
        assert s in text, s


def test_report_lists_failed_checks():
    text = vb.format_report(fake_result(ok=False))
    assert "CHECKS FAILED" in text and "it broke" in text


# ------------------------------------------------------------- end to end --

def test_help_lists_bench():
    r = varek("--help")
    assert r.returncode == 0 and "bench" in r.stdout


@pytest.mark.skipif(ROOT, reason="checks the message a non-root user gets")
def test_bench_needs_root():
    r = varek("bench", "--bare")
    assert r.returncode == 2 and "needs root" in r.stderr


@needs_runtime
def test_bench_bare_end_to_end(tmp_path):
    import time
    before = time.time() - 1
    out = tmp_path / "bench.json"
    r = varek("bench", "--bare", "-n", "200", "--warmup", "20", "--rounds", "2", "-o", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "checks passed" in r.stdout
    res = json.loads(out.read_text())
    assert res["ok"] is True and res["warden"]["version"]
    assert set(res["kinds"]) == set(KINDS)
    for k in KINDS:
        assert res["kinds"][k]["native"]["n"] == 400 and res["kinds"][k]["warden"]["n"] == 400
        assert res["kinds"][k]["warden_decision_us"]["n"] == 400
    assert res["kinds"]["connect_allowed"]["dial_us"]["n"] == 400
    assert res["kinds"]["connect_denied"]["dial_us"] is None   # nothing is dialed for a refusal
    # 2 native runs (1 check each) + 2 Warden runs (6 kinds + the denied listener each)
    assert len(res["checks"]) == 2 + 2 * 7
    # Nothing is left behind (other runs' --keep directories aside).
    for base in ("/tmp", "/run"):
        if os.path.isdir(base):
            for p in os.listdir(base):
                if p.startswith("varek-bench-"):
                    assert os.path.getmtime(os.path.join(base, p)) < before, p


@needs_runtime
def test_bench_with_a_pack_and_a_budget():
    r = varek("bench", "--policy", "healthcare", "-n", "200", "--warmup", "10", "--rounds", "1",
              "--json")
    assert r.returncode == 0, r.stderr
    res = json.loads(r.stdout)
    assert res["policy"]["base"] == "healthcare" and res["policy"]["rules"] > 30
    r = varek("bench", "--bare", "-n", "200", "--rounds", "1", "--max-added-p50", "0.001")
    assert r.returncode == 1 and "added p50 over" in r.stdout


@needs_runtime
def test_bench_reports_a_policy_that_decides_the_bench_calls_differently(tmp_path):
    loose = tmp_path / "loose.policy.txt"
    loose.write_text("allow path /tmp/\n")
    r = varek("bench", "--policy", str(loose), "-n", "200", "--warmup", "10", "--rounds", "1")
    assert r.returncode == 1
    assert "CHECKS FAILED" in r.stdout and "open_unknown: decided UNKNOWN" in r.stdout


@needs_runtime
def test_bench_runs_a_dynamic_workload_under_a_policy_without_loader_rules():
    """A host without a static libc builds the workload dynamically; the bench
    then adds read-only loader rules after the base policy's."""
    import pathlib
    import shutil
    import tempfile
    # Not pytest's tmp_path: it is root-only, and the agent user must run the workload.
    tmp_path = pathlib.Path(tempfile.mkdtemp(prefix="varek-bench-dyn-"))
    home = tmp_path / "home"
    (home / "tools").mkdir(parents=True)
    for f in ("varek", "varek_bench.py", "varek_license.py", "vdp_check", "vdp_cert_check"):
        shutil.copy2(os.path.join(HERE, "tools", f), home / "tools" / f)
    shutil.copy2(os.path.join(HERE, "warden"), home / "warden")
    subprocess.run(["cc", "-O2", "-o", str(home / "tools" / "bench_workload"),
                    os.path.join(HERE, "tools", "bench_workload.c")], check=True)
    assert vb.is_dynamic(str(home / "tools" / "bench_workload"))
    os.chmod(tmp_path, 0o755)
    pol = tmp_path / "base.policy.txt"
    pol.write_text("deny path /etc/shadow\n")
    env = dict(os.environ, NO_COLOR="1", VAREK_CONFIG="/nonexistent/varek.conf",
               VAREK_HOME=str(home))
    r = subprocess.run([sys.executable, str(home / "tools" / "varek"), "bench", "--policy", str(pol),
                        "-n", "200", "--warmup", "10", "--rounds", "1"],
                       text=True, capture_output=True, env=env)
    shutil.rmtree(tmp_path, ignore_errors=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "dynamically linked" in r.stdout and "checks passed" in r.stdout
