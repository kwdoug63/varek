#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
log_rechain.py — TEST HELPER: recompute the hash chain of an edited v1.16
verdict stream, as someone holding the log (but not the signing key) would.

The chain carries no secret, so an editor can always make it consistent
again; the regression tests use this to show (a) that the v1.15 audit checks
still catch a tampered certificate once the chain is made to agree, and (b)
that only the signatures, the pinned key and the anchor stop such an editor.
Signatures are left as they are (the editor cannot make new ones), unless
--resign SEED is given: then the helper plays someone who also holds a signing
key (the Warden's own, or one of their choosing, whose public key it writes
into run_start) and signs every signed record again. That needs the Python
"cryptography" package; the tests skip those cases without it.

  log_rechain.py [--resign SEEDFILE] IN > OUT
"""

import hashlib
import json
import re
import sys

IV = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
TAIL = re.compile(rb',"chain":"[0-9a-f]{64}"((?:,"sig":"[0-9a-f]{128}")?)\}\n?\Z')


def main():
    head, run = IV, None
    out = sys.stdout.buffer
    args = sys.argv[1:]
    key = None
    if args[:1] == ["--resign"]:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        with open(args[1]) as fh:
            key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fh.read().strip()))
        pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw).hex().encode()
        args = args[2:]
    with open(args[0], "rb") as fh:
        for line in fh:
            m = TAIL.search(line) if line.startswith(b"{") else None
            rec = None
            if m:
                try:
                    rec = json.loads(line)
                except ValueError:
                    rec = None
            if rec is None or not (rec.get("event") == "run_start" or rec.get("run") == run):
                out.write(line)
                continue
            if rec.get("event") == "run_start":
                run = rec.get("run")
            body = line[:m.start()]
            if key is not None and rec.get("event") == "run_start":
                body = re.sub(rb'"log_pubkey":"[0-9a-f]{64}"', b'"log_pubkey":"' + pub + b'"', body)
            head = hashlib.sha256(head + body).digest()
            sig = m.group(1)
            if key is not None and sig:
                sig = b',"sig":"' + key.sign(b"VAREK-LOG-SIG-1" + head).hex().encode() + b'"'
            out.write(body + b',"chain":"' + head.hex().encode() + b'"' + sig + b"}\n")


if __name__ == "__main__":
    main()
