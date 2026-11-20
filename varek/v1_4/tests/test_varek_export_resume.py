# SPDX-License-Identifier: MIT
"""v1.40: the rest of an export that failed partway. A sender that fails
(tools/varek_otel.py, varek_splunk.py, varek_sentinel.py) names the position
its unsent events begin at; `varek export --from-position N` (tools/varek_ocsf.py
--from-position) audits the stream whole and writes the events from the
first whose record is at position N or later."""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import varek_ocsf as ocsf  # noqa: E402

RUN = "run-resume"


def dec(seq, action, target, **k):
    r = {"run": RUN, "seq": seq, "report_id": f"pr-{seq}", "action": action, "target": target,
         "decision_raw": "ALLOW", "decision_final": "ALLOW", "rule": "policy_match", "agent_pid": 7,
         "obo": ["agent"], "kernel_verdict": "ALLOW", "errno": 0, "timestamp_ns": 10**18 + seq, "chain": f"c{seq}"}
    r.update(k)
    return r


def exported(tmp_path, recs):
    pol = tmp_path / "p.policy"
    pol.write_text("require warden 1.27\nallow exec /bin/true\nallow path /etc/hostname readonly\n")
    ex = ocsf.Exporter(str(pol), "node-1")
    out = []
    for r in recs:
        out += ex.feed(r)
    return out + ex.finish()


def pos(ev):
    return ev["unmapped"]["varek"]["position"]


def test_events_come_out_in_their_records_order(tmp_path):
    # the launch waits for its exec_result (record 4) to fold into it, and
    # holds back the open (record 3) behind it: no event overtakes another
    evs = exported(tmp_path, [
        {"event": "run_start", "run": RUN, "warden": "1.40.0", "timestamp_ns": 10**18, "chain": "c0"},
        dec(0, "process.exec", "/bin/true"),
        dec(1, "file.open", "/etc/hostname"),
        {"event": "exec_result", "run": RUN, "decision_seq": 0, "timestamp_ns": 10**18 + 5, "chain": "cx"},
        {"event": "run_end", "run": RUN, "timestamp_ns": 10**18 + 9, "chain": "ce"}])
    assert [pos(e) for e in evs] == [1, 2, 3, 5]
    assert "exec_result" in evs[1]["unmapped"]["varek"]


def test_from_position_writes_every_event_from_the_first_at_or_past_it():
    def ev(p):
        return {"unmapped": {"varek": {"position": p}}}
    keep = ocsf.FromPosition(4)
    # 4 itself is absent (its record folded into an earlier event): from 5
    # on, every event, one finish() adds with an earlier position too
    got = [e for e in (ev(1), ev(2), ev(3), ev(5), ev(6), ev(2)) if keep(e)]
    assert [pos(e) for e in got] == [5, 6, 2] and keep.skipped == 3
    for none in (None, 0, 1):
        k = ocsf.FromPosition(none)
        assert all(k(ev(p)) for p in (1, 2)) and k.skipped == 0
    k = ocsf.FromPosition(3)
    assert not k({"unmapped": {"varek": {}}}) and not k({}) and k(ev(3))


VAREK = os.path.join(HERE, "tools", "varek")
BUILT = all(os.access(os.path.join(HERE, b), os.X_OK)
            for b in ("warden", "warden-proxy", "tools/vdp_check", "tools/vdp_cert_check", "tools/varek_keygen"))
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def events(path):
    return [json.loads(x) for x in open(path) if x.strip()]


@pytest.mark.skipif(not (BUILT and ROOT and sys.platform.startswith("linux")),
                    reason="needs Linux, root and a built runtime")
def test_an_export_resumed_from_a_position(tmp_path):
    from test_varek_sentinel import Azure, SECRET    # the stand-in Azure
    conf = str(tmp_path / "etc" / "varek.conf")

    def varek(*args, env=None):
        e = dict(os.environ, NO_COLOR="1", VAREK_CONFIG=conf, NO_PROXY="127.0.0.1")
        e.update(env or {})
        return subprocess.run([sys.executable, VAREK, *args], text=True, capture_output=True, env=e, timeout=180)

    assert varek("init", "--pack", "healthcare", "--log-dir", str(tmp_path / "log")).returncode == 0
    r = varek("run", "--", "/bin/sh", "-c",
              "read a < /etc/hostname; read b < /etc/shadow 2>/dev/null; read c < /etc/hostname; true")
    assert r.returncode == 0, r.stdout + r.stderr
    log = str(max((tmp_path / "log").glob("verdicts-*.log")))
    full_p = str(tmp_path / "full.jsonl")
    assert varek("export", "--format", "ocsf", log, "-o", full_p).returncode == 0
    full = events(full_p)
    assert len(full) >= 6 and full[-1]["unmapped"]["varek"]["event"] == "audit"
    ps = [pos(e) for e in full[:-1]]
    assert ps == sorted(ps)                                   # in their records' order
    k = len(full) // 2
    p = pos(full[k])

    # the rest, from p: the same events as the whole export's from p on, and
    # its audit's verdict
    rest_p = str(tmp_path / "rest.jsonl")
    r = varek("export", "--format", "ocsf", log, "--from-position", str(p), "-o", rest_p)
    assert r.returncode == 0, r.stdout + r.stderr
    rest = events(rest_p)
    assert rest == full[k:]
    assert f"the {k} event(s) before it not written" in r.stdout + r.stderr
    # --follow, on the stream that has ended: the same, its verdict a follow's
    fol_p = str(tmp_path / "follow.jsonl")
    r = varek("export", "--format", "ocsf", "--follow", log, "--from-position", str(p), "-o", fol_p)
    assert r.returncode == 0, r.stdout + r.stderr
    fol = events(fol_p)
    assert fol[:-1] == full[k:-1] and fol[-1]["unmapped"]["varek"]["audit"] == \
        {"passed": True, "mode": "follow", "problems": []}

    # the stream is audited whole: a record before p edited, nothing written
    bad = str(tmp_path / "log" / "verdicts-edited.log")
    lines = open(log).read().split("\n")
    i = next(n for n, x in enumerate(lines) if '"decision_final"' in x)
    lines[i] = lines[i].replace('"errno":', '"errno": ', 1) if '"errno":' in lines[i] else lines[i] + " "
    open(bad, "w").write("\n".join(lines))
    bad_p = str(tmp_path / "bad.jsonl")
    r = varek("export", "--format", "ocsf", bad, "--from-position", str(p), "-o", bad_p)
    assert r.returncode != 0 and not (os.path.exists(bad_p) and os.path.getsize(bad_p)), r.stdout + r.stderr

    for how in (["--format", "cyclonedx", log], ["--format", "ocsf", "--verify", full_p, log]):
        r = varek("export", *how, "--from-position", str(p))
        assert r.returncode != 0 and "--from-position" in r.stdout + r.stderr
    r = varek("export", "--format", "ocsf", log, "--from-position", "0")
    assert r.returncode != 0 and "1 or more" in r.stdout + r.stderr

    # a send that fails names where its rows not sent begin; the same export
    # with --from-position sends the rest, and the rows are the events
    azure = {"AZURE_TENANT_ID": "tenant-1", "AZURE_CLIENT_ID": "client-1", "AZURE_CLIENT_SECRET": SECRET}
    az = Azure(answers=[400])
    try:
        r = varek("export", "--format", "sentinel", log, "--endpoint", az.base, "--dcr", "dcr-0f1e",
                  env=dict(azure, AZURE_AUTHORITY_HOST=az.base))
        out = r.stdout + r.stderr
        assert r.returncode != 0 and "HTTP 400" in out, out
        assert f"those not sent begin at position {pos(full[0])}" in out and "--from-position" in out
    finally:
        az.close()
    az = Azure()
    try:
        r = varek("export", "--format", "sentinel", log, "--endpoint", az.base, "--dcr", "dcr-0f1e",
                  "--from-position", str(p), env=dict(azure, AZURE_AUTHORITY_HOST=az.base))
        assert r.returncode == 0, r.stdout + r.stderr
        assert [row["OcsfEvent"] for row in az.rows()] == full[k:]
    finally:
        az.close()


@pytest.mark.skipif(not (BUILT and ROOT and sys.platform.startswith("linux")),
                    reason="needs Linux, root and a built runtime")
def test_a_refused_stream_says_why_and_what_was_sent(tmp_path):
    # Sentinel's live test of the failed-audit rule (November 19, 2026): with
    # --follow the reason reached Sentinel but not the screen; the batch audit
    # named its private copy, not the file given; and the CLI said "what it
    # wrote before was sent" after 0 rows
    from test_varek_sentinel import Azure, SECRET
    conf = str(tmp_path / "etc" / "varek.conf")

    def varek(*args, env=None):
        e = dict(os.environ, NO_COLOR="1", VAREK_CONFIG=conf, NO_PROXY="127.0.0.1")
        e.update(env or {})
        return subprocess.run([sys.executable, VAREK, *args], text=True, capture_output=True, env=e, timeout=180)

    assert varek("init", "--pack", "healthcare", "--log-dir", str(tmp_path / "log")).returncode == 0
    os.makedirs("/tmp/varek", exist_ok=True)
    assert varek("run", "--", "/bin/sh", "-c", "read a < /etc/hostname; read b < /etc/shadow; true").returncode == 0
    log = str(max((tmp_path / "log").glob("verdicts-*.log")))
    lines = open(log).read().split("\n")
    i = next(n for n, x in enumerate(lines) if '"decision_final":"DENY"' in x)
    lines[i] = lines[i].replace('"decision_final":"DENY"', '"decision_final":"ALLOW"', 1)
    bad = log[:-len(".log")] + "-tampered.log"
    open(bad, "w").write("\n".join(lines))
    broken = f"{bad}:{i + 1}: hash chain broken"

    r = varek("export", "--format", "ocsf", "--follow", bad, "-o", str(tmp_path / "f.jsonl"))
    out = r.stdout + r.stderr
    assert r.returncode != 0 and f"the audit failed: {broken}" in out, out          # on the screen too
    r = varek("export", "--format", "ocsf", bad, "-o", str(tmp_path / "b.jsonl"))
    out = r.stdout + r.stderr
    assert r.returncode != 0 and broken in out and "varek-ocsf-" not in out, out     # the file given, not the copy

    azure = {"AZURE_TENANT_ID": "tenant-1", "AZURE_CLIENT_ID": "client-1", "AZURE_CLIENT_SECRET": SECRET}
    az = Azure()
    try:
        env = dict(azure, AZURE_AUTHORITY_HOST=az.base)
        r = varek("export", "--format", "sentinel", bad, "--endpoint", az.base, "--dcr", "dcr-0f1e", env=env)
        out = r.stdout + r.stderr
        assert r.returncode != 0 and "failed (exit 1): nothing was sent" in out and not az.rows(), out
        assert broken in out and "varek-ocsf-" not in out, out
        r = varek("export", "--format", "sentinel", "--follow", bad, "--endpoint", az.base, "--dcr", "dcr-0f1e",
                  env=env)
        out = r.stdout + r.stderr
        assert r.returncode != 0 and "the events it wrote before it stopped were sent" in out, out
        assert f"the audit failed: {broken}" in out, out
        audit = [x for x in az.rows() if x.get("EventName") == "varek.audit"]
        assert len(audit) == 1 and audit[0]["AuditPassed"] is False and audit[0]["OcsfEvent"]["severity"] == "High"
        assert broken in audit[0]["OcsfEvent"]["unmapped"]["varek"]["audit"]["problems"][0]
    finally:
        az.close()
