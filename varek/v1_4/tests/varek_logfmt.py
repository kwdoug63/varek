# SPDX-License-Identifier: MIT
"""varek_logfmt.py — TEST HELPER: a verdict stream's integrity format, as
someone who holds a log (and means to edit it) would compute it.

Written apart from tools/ on purpose: the forge and tamper tests play an
editor who re-chains a stream, and must not lean on the audit's own constants.

  chain-1 (the Warden v1.16 to v1.40): SHA-256 chain, IV SHA-256("VAREK-LOG-CHAIN-1"),
           Ed25519 signatures over "VAREK-LOG-SIG-1" || chain.
  chain-2 (the Warden from v1.41):     SHA-384 chain, IV SHA-384("VAREK-LOG-CHAIN-2"),
           ECDSA P-384 (SHA-384, DER) signatures over "VAREK-LOG-SIG-2" || chain.
"""

import hashlib
import json

FORMATS = {
    "chain-1": {"iv": hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest(), "hash": hashlib.sha256,
                "chain_hex": 64, "domain": b"VAREK-LOG-SIG-1"},
    "chain-2": {"iv": hashlib.sha384(b"VAREK-LOG-CHAIN-2").digest(), "hash": hashlib.sha384,
                "chain_hex": 96, "domain": b"VAREK-LOG-SIG-2"},
}


def of_lines(lines):
    """The format named by the first run_start record among lines (str or
    bytes), or chain-1 if none names one (the tests' own older fixtures)."""
    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8", "surrogateescape")
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("event") == "run_start":
            return FORMATS.get(rec.get("log"), FORMATS["chain-1"])
    return FORMATS["chain-1"]


def of_file(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        return of_lines(fh)
