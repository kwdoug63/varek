# SPDX-License-Identifier: MIT
"""v1.36 step 8 (D9): the one-pass audit's running state (tools/varek_audit.py):
the problems kept in sections, the connection ids as intervals, the records
held back until a signature seals them (on disk past what memory holds), and
the stream read in segments (tools/varek_cyclonedx.py's _iter_log)."""
import hashlib
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import varek_audit as va          # noqa: E402
import varek_cyclonedx as cdx     # noqa: E402


def test_sections_keep_the_first_shown_and_count_the_rest():
    p = va.Problems(("a", "b", "c"))
    for i in range(70):
        p["b"].append(f"b{i}")
    p["c"].append("c0")
    p["a"].append("a0")
    assert len(p) == 72 and len(p["b"]) == 70 and len(p["b"].items) == va.PROBLEMS_SHOWN
    shown = p.shown()
    assert shown[0] == "a0" and shown[1] == "b0" and len(shown) == va.PROBLEMS_SHOWN and "c0" not in shown
    assert p.before("b") == 1 and p.before("c") == 71
    p["b"].clear()
    assert p.before("c") == 1 and p.shown() == ["a0", "c0"]


def test_ids_as_intervals():
    s = va.IdSet()
    for x in (1, 2, 3, 7, 5, 6, 4):
        s.add(x)
    assert s.lo == [1] and s.hi == [7] and s.is_range(1, 7) and len(s) == 7
    s.add(10)
    assert 10 in s and 8 not in s and not s.is_range(1, 8) and len(s) == 8
    s.add(9)
    s.add(8)
    assert s.is_range(1, 10) and len(s.lo) == 1
    s.add(3)                                  # already there
    assert len(s) == 10


def test_held_records_wait_on_disk_past_memory(monkeypatch):
    monkeypatch.setattr(va.Delay, "HOLD", 3)
    d = va.Delay()
    items = [("dec", {"seq": i, "x": "é" * i}, i + 1) for i in range(10)]
    for it in items:
        d.put(it)
    assert len(d.mem) == 3 and d.ndisk == 7
    assert list(d.take()) == items
    assert list(d.take()) == []                # taken once
    d.put(items[0])
    assert list(d.take()) == [items[0]]


def chained(recs):
    """records as the Warden writes them: each with its chain value"""
    head, out = cdx.LOG_CHAIN_IV, []
    for r in recs:
        body = json.dumps(r, separators=(",", ":"))[:-1]
        if "prev_chain" in r and r["prev_chain"] is None:     # the chain value so far
            r["prev_chain"] = head.hex()
            body = json.dumps(r, separators=(",", ":"))[:-1]
        head = hashlib.sha256(head + body.encode()).digest()
        out.append(f'{body},"chain":"{head.hex()}"}}\n')
    return out


RUN = "a" * 32


def stream(nseg=3, per=2):
    """a stream of nseg segments, per decision records each"""
    recs, segs, seq = [{"event": "run_start", "run": RUN, "log": "chain-1", "warden": "1.36.0"}], [], 0
    for k in range(1, nseg + 1):
        if k > 1:
            segs.append(len(recs))
            recs.append({"event": "checkpoint", "run": RUN, "records": seq, "segment": k, "prev_chain": None})
        for _ in range(per):
            recs.append({"run": RUN, "seq": seq, "action": "file.open", "decision_final": "DENY"})
            seq += 1
    recs.append({"event": "run_end", "run": RUN, "records": seq})
    lines = chained(recs)
    cuts = [0] + segs + [len(lines)]
    return ["".join(lines[a:b]) for a, b in zip(cuts, cuts[1:])]


def read(texts):
    files = []
    for i, t in enumerate(texts):
        f = io.StringIO(t)
        f.name = "s.jsonl" + (f".{i + 1}" if i else "")
        files.append(f)
    meta = {}
    items = list(cdx._iter_log(files if len(files) > 1 else files[0], False, meta))
    return [x for x in items if x[0] == "dec"], meta


def test_segments_in_order_one_stream():
    decs, meta = read(stream())
    assert [d[1]["seq"] for d in decs] == list(range(6)) and meta["run_end"]["records"] == 6
    decs, _ = read(["".join(stream())])      # put together in one file
    assert len(decs) == 6


@pytest.mark.parametrize("change, why", [
    (lambda s: [s[0], s[2], s[1]], "segment 2 does not begin"),          # out of order
    (lambda s: [s[0], s[2]], "segment 2 does not begin"),                # one left out
    (lambda s: [s[0], s[1].replace('"segment":2', '"segment":5'), s[2]], "segment 2 does not begin"),
    (lambda s: [s[0], s[1] + s[2]], "segment 3"),                        # fine: put together ...
])
def test_segments_refused(change, why):
    s = stream()
    texts = change(s)
    if why == "segment 3":
        decs, _ = read(texts)                  # ... two segments in one file still run on
        assert len(decs) == 6
        return
    with pytest.raises(cdx.StreamError, match=why):
        read(texts)


def test_a_segment_named_out_of_turn_in_one_file_is_refused():
    s = stream()
    with pytest.raises(cdx.StreamError, match="segment 2 does not begin"):
        read([s[0] + s[1].replace('"segment":2', '"segment":3') + s[2]])


def test_the_exporters_list_parser_is_unchanged():
    run, records, complete, warden = cdx._parse_log(io.StringIO("".join(stream())), False, {})
    assert run == RUN and len(records) == 6 and complete and warden == "1.36.0"


CHECKER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "vdp_cert_check")


@pytest.mark.skipif(not os.access(CHECKER, os.X_OK), reason="tools/vdp_cert_check is not built")
def test_a_malformed_connection_id_fails_the_audit(tmp_path, capsys):
    """v1.36 step 11 (review): a connection id that is no number gives a FAIL
    with its problems, as v1.35.0's audit did, not a traceback"""
    pol = tmp_path / "p.policy"
    pol.write_text("allow path /tmp/\n")
    recs = [{"event": "run_start", "run": RUN, "log": "chain-1", "warden": "1.36.0", "arch": "x86_64",
             "policy_sha256": hashlib.sha256(pol.read_bytes()).hexdigest(), "timestamp_ns": 10**18,
             "operator": {"uid": 0, "verified": False}},
            {"run": RUN, "seq": 0, "action": "file.open", "target": "/etc/x", "decision_final": "DENY",
             "rule": "default_deny_unknown", "policy_line": -1, "proxy_handoff": True, "proxy_conn": 1,
             "agent_pid": [7], "timestamp_ns": 10**18 + 1},
            {"event": "proxy_close", "run": RUN, "proxy_conn": [1], "why": "closed"},
            {"event": "run_end", "run": RUN, "records": 1}]
    s = tmp_path / "s.jsonl"
    s.write_text("".join(chained(recs)))
    rc = va.main(["--policy", str(pol), "--checker", CHECKER, str(s)])
    out = capsys.readouterr().out
    assert rc != 0 and "varek_audit: FAIL" in out and "malformed connection id [1]" in out
