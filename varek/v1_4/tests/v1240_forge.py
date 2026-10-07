#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1240_forge.py — test_v1240.sh: forge a verdict stream the way someone who
holds the log (but not the signing key) could: drop a name from a connect's
candidates, decide it on the address instead, and recompute the hash chain.
varek_audit.py must still refuse it, from the resolution records.

  v1240_forge.py <in.log> <out.log> <port> [<address>]
"""
import hashlib
import sys

src, dst, port = sys.argv[1], sys.argv[2], sys.argv[3]
addr = sys.argv[4] if len(sys.argv) > 4 else "127.0.0.1"
head = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
out = []
with open(src, encoding="utf-8", errors="surrogateescape") as fh:
    for line in fh:
        if line.startswith("{") and ',"chain":"' in line:
            cut = line.index(',"chain":"')
            body = line[:cut]
            body = body.replace(f',"api.example.com:{port}"]', "]").replace(
                f'"resolved":"api.example.com:{port}"', f'"resolved":"{addr}:{port}"')
            head = hashlib.sha256(head + body.encode("utf-8", "surrogateescape")).digest()
            line = body + ',"chain":"' + head.hex() + line[cut + 10 + 64:]
        out.append(line)
with open(dst, "w", encoding="utf-8", errors="surrogateescape") as fh:
    fh.write("".join(out))
