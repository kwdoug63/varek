# SPDX-License-Identifier: MIT
"""v1.34 step 9: the node exporter's reaper (tools/varek_node_export.py).
A follower whose stream ends with its run_end is in the whole-stream audit,
minutes for a day's stream: it is given --audit-grace, not --grace. One whose
stream stopped without its run_end (its supervisor gone) is left after
--grace."""
import argparse
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import varek_node_export as nx  # noqa: E402


def dead_pid():
    p = subprocess.Popen(["true"])
    p.wait()
    return p.pid


def exporter(tmp, audit_grace):
    args = argparse.Namespace(output=str(tmp / "out.jsonl"), state=None, grace=0.0, audit_grace=audit_grace)
    ex = nx.Exporter.__new__(nx.Exporter)
    ex.args, ex.lock, ex.out, ex.state = args, threading.Lock(), open(args.output, "a"), None
    ex.running, ex.gone_at, ex.failed = {}, {}, 0
    return ex


def follower(ex, path):
    p = subprocess.Popen(["sleep", "30"])          # a follower still in its audit
    t = threading.Thread(target=lambda: None)
    t.start()
    ex.running[str(path)] = (p, t, dead_pid())
    old = time.time() - 60                         # the stream quiet past QUIET_S
    os.utime(path, (old, old))
    return p


def test_ends_with_run_end(tmp_path):
    s = tmp_path / "c.1.jsonl"
    s.write_text('{"event":"run_start"}\n{"seq":0}\n{"event":"run_end","run":"r"}\n')
    assert nx.ends_with_run_end(str(s))
    s.write_text('{"event":"run_start"}\n{"event":"run_end"}\n{"seq":1}\n')
    assert not nx.ends_with_run_end(str(s))
    assert not nx.ends_with_run_end(str(tmp_path / "missing.jsonl"))


def test_follower_in_its_audit_kept(tmp_path):
    s = tmp_path / "c.1.jsonl"
    s.write_text('{"event":"run_start"}\n{"event":"run_end","run":"r"}\n')
    ex = exporter(tmp_path, audit_grace=3600)
    p = follower(ex, s)
    try:
        for _ in range(3):
            ex.reap()
        assert p.poll() is None and str(s) in ex.running
    finally:
        p.kill()
        p.wait()


def test_follower_in_its_audit_left_after_audit_grace(tmp_path, capsys):
    s = tmp_path / "c.1.jsonl"
    s.write_text('{"event":"run_start"}\n{"event":"run_end","run":"r"}\n')
    ex = exporter(tmp_path, audit_grace=0)
    p = follower(ex, s)
    ex.reap()
    assert p.poll() is not None and str(s) not in ex.running
    assert "its audit did not end" in capsys.readouterr().err


def test_stream_without_run_end_left_after_grace(tmp_path, capsys):
    s = tmp_path / "c.1.jsonl"
    s.write_text('{"event":"run_start"}\n{"seq":0}\n')
    ex = exporter(tmp_path, audit_grace=3600)
    p = follower(ex, s)
    ex.reap()
    assert p.poll() is not None and str(s) not in ex.running
    assert "without run_end" in capsys.readouterr().err
