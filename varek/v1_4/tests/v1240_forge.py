#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1240_forge.py — test_v1240.sh: forge a verdict stream the way someone who
holds the log (but not the signing key) could: drop a name from a connect's
candidates, decide it on the address instead, and recompute the hash chain.
varek_audit.py must still refuse it, from the resolution records.

  v1240_forge.py <in.log> <out.log> <port> [<address>]
"""
import sys

import varek_logfmt

src, dst, port = sys.argv[1], sys.argv[2], sys.argv[3]
addr = sys.argv[4] if len(sys.argv) > 4 else "127.0.0.1"
fmt = varek_logfmt.of_file(src)          # v1.41: chain-2 (SHA-384) or chain-1
head = fmt["iv"]
out = []
with open(src, encoding="utf-8", errors="surrogateescape") as fh:
    for line in fh:
        if line.startswith("{") and ',"chain":"' in line:
            cut = line.index(',"chain":"')
            body = line[:cut]
            body = body.replace(f',"api.example.com:{port}"]', "]").replace(
                f'"resolved":"api.example.com:{port}"', f'"resolved":"{addr}:{port}"')
            head = fmt["hash"](head + body.encode("utf-8", "surrogateescape")).digest()
            line = body + ',"chain":"' + head.hex() + line[cut + 10 + fmt["chain_hex"]:]
        out.append(line)
with open(dst, "w", encoding="utf-8", errors="surrogateescape") as fh:
    fh.write("".join(out))
