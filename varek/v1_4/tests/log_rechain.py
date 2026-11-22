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
--resign KEYFILE is given: then the helper plays someone who also holds a
signing key (the Warden's own, or one of their choosing, whose public key it
writes into run_start) and signs every signed record again. That needs the
Python "cryptography" package; the tests skip those cases without it.

v1.41: the stream's own format decides how it is re-chained and re-signed
(tests/varek_logfmt.py): chain-2 (SHA-384, ECDSA P-384; KEYFILE a PEM key
from tools/varek_keygen) or chain-1 (SHA-256, Ed25519; KEYFILE a v1.40 seed).

  log_rechain.py [--resign KEYFILE] IN > OUT
"""

import json
import re
import sys

import varek_logfmt

TAIL = re.compile(rb',"chain":"(?:[0-9a-f]{96}|[0-9a-f]{64})"((?:,"sig":"[0-9a-f]+")?)\}\n?\Z')
PUBKEY = re.compile(rb'"log_pubkey":"(?:04[0-9a-f]{192}|[0-9a-f]{64})"')


def _signer(path, fmt):
    """(sign(msg) -> signature bytes, public key hex) for KEYFILE, of the
    stream's kind."""
    from cryptography.hazmat.primitives import hashes, serialization
    data = open(path, "rb").read()
    if fmt["chain_hex"] == 96:
        from cryptography.hazmat.primitives.asymmetric import ec
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp384r1":
            raise SystemExit("log_rechain.py: a chain-2 stream is re-signed with a P-384 PEM key")
        pub = key.public_key().public_bytes(serialization.Encoding.X962,
                                            serialization.PublicFormat.UncompressedPoint)
        return (lambda m: key.sign(m, ec.ECDSA(hashes.SHA384()))), pub.hex().encode()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data.decode().strip()))
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key.sign, pub.hex().encode()


def main():
    args = sys.argv[1:]
    keyfile = None
    if args[:1] == ["--resign"]:
        keyfile, args = args[1], args[2:]
    with open(args[0], "rb") as fh:
        lines = fh.readlines()
    fmt = varek_logfmt.of_lines(lines)
    sign, pub = _signer(keyfile, fmt) if keyfile else (None, None)
    head, run = fmt["iv"], None
    out = sys.stdout.buffer
    for line in lines:
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
        if sign is not None and rec.get("event") == "run_start":
            body = PUBKEY.sub(b'"log_pubkey":"' + pub + b'"', body)
        head = fmt["hash"](head + body).digest()
        sig = m.group(1)
        if sign is not None and sig:
            sig = b',"sig":"' + sign(fmt["domain"] + head).hex().encode() + b'"'
        out.write(body + b',"chain":"' + head.hex().encode() + b'"' + sig + b"}\n")


if __name__ == "__main__":
    main()
