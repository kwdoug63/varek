#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1261_forge.py — edit a verdict stream's records and re-chain them, for the
tests' forged streams (as the forge helper in tests/test_v1261.sh, and also
dropping and moving records; from the v1.26.1 review by AI review agents).

  v1261_forge.py IN OUT [--sub FROM TO]... [--drop TEXT]... [--move A B]...

--sub rewrites the first record holding FROM; --drop removes every record
holding TEXT; --move puts the first record holding A just after the first
holding B. Exits 1 if an edit found no record to apply to.
"""
import hashlib
import sys

a = sys.argv[3:]
subs, drops, moves = [], [], []
i = 0
while i < len(a):
    if a[i] == "--sub":
        subs.append([a[i + 1], a[i + 2], False]); i += 3
    elif a[i] == "--drop":
        drops.append([a[i + 1], False]); i += 2
    elif a[i] == "--move":
        moves.append((a[i + 1], a[i + 2])); i += 3
    else:
        raise SystemExit(f"v1261_forge: bad argument {a[i]}")
lines = open(sys.argv[1], encoding="utf-8", errors="surrogateescape").read().splitlines(True)
for ma, mb in moves:
    ia = next((k for k, l in enumerate(lines) if ma in l), None)
    if ia is None:
        raise SystemExit(f"v1261_forge: no record holds {ma[:60]}")
    la = lines.pop(ia)
    ib = next((k for k, l in enumerate(lines) if mb in l), None)
    if ib is None:
        raise SystemExit(f"v1261_forge: no record holds {mb[:60]}")
    lines.insert(ib + 1, la)
head = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
out = []
for line in lines:
    if line.startswith("{") and ',"chain":"' in line:
        cut = line.index(',"chain":"')
        body = line[:cut]
        hit = [d for d in drops if d[0] in body]
        if hit:
            for d in hit:
                d[1] = True
            continue
        for s in subs:
            if not s[2] and s[0] in body:
                body = body.replace(s[0], s[1]); s[2] = True
        head = hashlib.sha256(head + body.encode("utf-8", "surrogateescape")).digest()
        line = body + ',"chain":"' + head.hex() + line[cut + 10 + 64:]
    out.append(line)
open(sys.argv[2], "w", encoding="utf-8", errors="surrogateescape").write("".join(out))
missed = [s[0] for s in subs if not s[2]] + [d[0] for d in drops if not d[1]]
for m in missed:
    print(f"v1261_forge: no record holds {m[:80]}", file=sys.stderr)
sys.exit(1 if missed else 0)
