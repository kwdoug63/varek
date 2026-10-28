# SPDX-License-Identifier: MIT
"""v1.36 step 9 (D10): a key for each node. The audit's --node-keys (the
cluster's VarekNodeKey list: a stream's key must be the one listed for its
node, and not one retired before the run began), and the node agent's
node_key line, which the anchor's forwarder and receiver carry."""
import json
import os
import re
import subprocess
import sys
import types

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_anchor_forward as fwd   # noqa: E402
import varek_audit as va             # noqa: E402

K1, K2, K3 = "11" * 32, "22" * 32, "33" * 32
T0 = 1_800_000_000                   # seconds


def nk(node, key, at, kind="VarekNodeKey"):
    t = __import__("datetime").datetime.fromtimestamp(at, __import__("datetime").timezone.utc)
    return {"apiVersion": "varek.dev/v1alpha1", "kind": kind,
            "metadata": {"name": f"{node}-{key[:16]}", "creationTimestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ")},
            "spec": {"node": node, "publicKey": key}}


def listing(tmp_path, *items, single=False):
    p = tmp_path / "keys.json"
    p.write_text(json.dumps(items[0] if single else {"apiVersion": "v1", "kind": "List", "items": list(items)}))
    return str(p)


def test_the_list_by_node_in_the_order_admitted(tmp_path):
    keys, why = va._node_keys(listing(tmp_path, nk("node-1", K2, T0 + 60), nk("node-1", K1, T0), nk("node-2", K3, T0)))
    assert why is None
    assert [(t // 10**9, k.hex()) for t, k, _ in keys["node-1"]] == [(T0, K1), (T0 + 60, K2)]
    assert keys["node-2"][0][2] == "node-2-" + K3[:16]
    keys, why = va._node_keys(listing(tmp_path, nk("node-1", K1, T0), single=True))
    assert why is None and len(keys["node-1"]) == 1


@pytest.mark.parametrize("item, why", [
    (nk("node-1", K1, T0, kind="VarekPolicy"), "not a VarekNodeKey"),
    ({**nk("node-1", K1, T0), "spec": {"node": "node-1", "publicKey": "AB" * 32}}, "no 64-hex publicKey"),
    ({**nk("node-1", K1, T0), "metadata": {"name": "x"}}, "no creationTimestamp"),
    ({**nk("node-1", K1, T0), "spec": {"publicKey": K1}}, "has no node"),
])
def test_a_list_that_is_not_one(tmp_path, item, why):
    keys, msg = va._node_keys(listing(tmp_path, item))
    assert keys is None and why in msg


def integrity(path, node="node-1", key=K1, began=T0 + 120, rx=None):
    """an Integrity at run_end, for the node_key check alone"""
    a = types.SimpleNamespace(node_keys=path, pubkey=None, anchor=None)
    it = va.Integrity(a, {}, lambda n: None)
    it.rs = {"node": {"node_name": node} if node else {}, "timestamp_ns": began * 10**9}
    it.pk, it.start_rx = bytes.fromhex(key), (rx * 10**9 if rx else None)
    return it


def check(it):
    head = va.Section()
    return it.node_key(head), list(head.items)


def test_the_nodes_key_trusted(tmp_path):
    p = listing(tmp_path, nk("node-1", K1, T0), nk("node-2", K2, T0))
    it = integrity(p)
    pk, probs = check(it)
    assert pk == bytes.fromhex(K1) and not probs
    assert it.key_note.startswith(f"node node-1's key node-1-{K1[:16]}, admitted ") and "retired" not in it.key_note


def test_another_nodes_key_refused(tmp_path):
    pk, probs = check(integrity(listing(tmp_path, nk("node-1", K3, T0), nk("node-2", K1, T0))))
    assert pk is None and probs == [f"the stream is signed by {K1}, which the cluster's list does not hold for "
                                    f"node node-1 (it is node-2's)"]


def test_a_key_retired_before_the_run_began(tmp_path):
    p = listing(tmp_path, nk("node-1", K1, T0), nk("node-1", K2, T0 + 60))
    pk, probs = check(integrity(p, began=T0 + 120))
    assert pk is None and len(probs) == 1
    assert f"retired at {va._ns_text((T0 + 60) * 10**9)} when the node's next key (node-1-{K2[:16]}) was admitted" in probs[0]
    assert "by the node's own clock" in probs[0]
    # the anchor host received run_start before the next key was admitted: trusted
    it = integrity(p, began=T0 + 120, rx=T0 + 30)
    pk, probs = check(it)
    assert pk == bytes.fromhex(K1) and not probs and "(by the anchor host's clock)" in it.key_note
    # ... and after: refused, by the anchor host's clock, whatever the node says
    pk, probs = check(integrity(p, began=T0 + 30, rx=T0 + 90))
    assert pk is None and "(by the anchor host's clock), after" in probs[0]


def test_the_newest_key_is_not_retired(tmp_path):
    it = integrity(listing(tmp_path, nk("node-1", K1, T0), nk("node-1", K2, T0 + 60)), key=K2, began=T0 + 120)
    pk, probs = check(it)
    assert pk == bytes.fromhex(K2) and not probs and "retired" not in it.key_note


def test_a_stream_naming_no_node(tmp_path):
    pk, probs = check(integrity(listing(tmp_path, nk("node-1", K1, T0)), node=None))
    assert pk is None and "names no node" in probs[0]


def test_node_keys_and_pubkey_together():
    with pytest.raises(SystemExit) as e:
        va.main(["--policy", "p", "--checker", "c", "--node-keys", "k", "--pubkey", "x", "s.jsonl"])
    assert e.value.code == 2


LINE = f'{{"event":"node_key","node":"node-1.example","key":"{K1}","timestamp_ns":1700000000000000000}}'


@pytest.mark.parametrize("line, ok", [
    (LINE, True),
    (LINE.replace("node-1.example", "Node_1"), False),
    (LINE.replace("node-1.example", "-node"), False),
    (LINE.replace(K1, K1[:-1]), False),
    (LINE[:-1] + ',"x":1}', False),
])
def test_the_forwarder_and_the_receiver_carry_node_key_lines(line, ok):
    assert bool(fwd.NODE_KEY_LINE.match(line.encode())) is ok
    # the receiver's forced command keeps the lines its two patterns match
    sh = open(os.path.join(HERE, "tools", "varek_anchor_receiver.sh")).read()
    pats = [re.search(rf"^{v}='([^']*)'$", sh, re.M).group(1) for v in ("re", "nk")]
    r = subprocess.run(["grep", "-E", "-e", pats[0], "-e", pats[1]], input=line + "\n", capture_output=True,
                       text=True, env={"LC_ALL": "C"}, check=False)
    assert (r.returncode == 0) is ok
    old = f'{{"run":"{"a" * 32}","event":"checkpoint","records":3,"chain":"{"b" * 64}","timestamp_ns":5}}'
    assert fwd.LINE.match(old.encode()) and not fwd.NODE_KEY_LINE.match(old.encode())
