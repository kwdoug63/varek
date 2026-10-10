# SPDX-License-Identifier: MIT
"""v1270_forge.py — rewrite records of a v1.27 verdict stream and re-chain it
(test_v1270.sh section 5): the audit must refuse each forgery for its own
reason, not for a broken chain.

  v1270_forge.py IN OUT 'PYTHON'   PYTHON runs with `recs` (each record a dict,
                                   in order; lines that are not records are
                                   kept as strings) and may change, drop or add
"""
import hashlib
import json
import sys

src, out, code = sys.argv[1], sys.argv[2], sys.argv[3]
recs = []
for line in open(src, encoding="utf-8", errors="surrogateescape"):
    if line.startswith("{"):
        r = json.loads(line)
        r.pop("chain", None)
        recs.append(r)
    else:
        recs.append(line)
exec(code, {"recs": recs})
head = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
with open(out, "w", encoding="utf-8", errors="surrogateescape") as f:
    for r in recs:
        if isinstance(r, str):
            f.write(r)
            continue
        body = json.dumps(r, separators=(",", ":"))[:-1]
        head = hashlib.sha256(head + body.encode()).digest()
        f.write(body + ',"chain":"' + head.hex() + '"}\n')
