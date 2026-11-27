# SPDX-License-Identifier: MIT
"""
varek_ed25519.py — signature verification for tools/varek_audit.py.

v1.41: this module no longer carries a cryptographic implementation of its own.
It verifies through the `cryptography` package, which is backed by the system
OpenSSL — the same validated module the Warden signs with on a FIPS-mode host.
The module name is kept so the audit's import sites are unchanged.

Two signature formats are verified, selected by the stream's version:

  * verify()      — Ed25519 (RFC 8032), the legacy format (streams whose
                    run_start says "log":"chain-1", signed "VAREK-LOG-SIG-1" ||
                    SHA-256 chain). Kept so audit logs written before v1.41 stay
                    verifiable offline.
  * verify_p384() — ECDSA P-384 with SHA-384 (CNSA-aligned), the v1.41 format
                    ("log":"chain-2", signed "VAREK-LOG-SIG-2" || SHA-384 chain).

Verification only: this module never handles a private key. Neither function
raises on malformed input; both return False. verify() raises
AlgorithmUnavailable when the host's crypto provider does not offer Ed25519:
on a host in FIPS mode it is not an approved algorithm, so a log of v1.40 or
earlier cannot be checked there (the audit says so; it is not a forgery).
"""

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm


class AlgorithmUnavailable(Exception):
    """The host's crypto provider does not offer the algorithm a signature was
    made with (Ed25519 on a host in FIPS mode)."""


ED25519_UNAVAILABLE = ("the signatures are Ed25519 (a Warden of v1.40 or earlier), which this host's "
                       "crypto provider does not offer (Ed25519 is not an approved algorithm on a host in "
                       "FIPS mode): they cannot be checked here; check this log on a host not in FIPS mode")


def ed25519_available() -> bool:
    """True if the host's crypto provider offers Ed25519 (not, typically, in FIPS mode)."""
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        return bool(backend.ed25519_supported())
    except Exception:            # an older or newer cryptography: try it
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
            return True
        except Exception:
            return False

# The v1.16 verifier was strict, and these keep it so in front of OpenSSL
# (whose Ed25519 accepts a small-order public key: a "signature" of R = a
# small-order point and S = 0 then verifies for about one message in eight).
# Each is a comparison of an encoding against fixed values, not arithmetic on
# the curve:
#   * A and R canonical: y < p (the sign bit aside);
#   * A not of small order: not one of the encodings of the eight points of
#     order 1, 2, 4 or 8 (the list libsodium's has_small_order refuses, its
#     non-canonical forms included), whatever the sign bit;
#   * S below the group order L.
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_SMALL_ORDER = {bytes.fromhex(h) for h in (
    "0000000000000000000000000000000000000000000000000000000000000000",   # y = 0     (order 4)
    "0100000000000000000000000000000000000000000000000000000000000000",   # y = 1     (order 1)
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",   # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",   # order 8
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",   # y = p - 1 (order 2)
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",   # y = p     (= 0)
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",   # y = p + 1 (= 1)
)}


def _canonical_y(b: bytes) -> bool:
    return (int.from_bytes(b, "little") & ((1 << 255) - 1)) < _P


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True if signature is a valid Ed25519 signature of message under
    public_key (32 raw bytes). Legacy (pre-v1.41) streams. Never raises."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    a, r = bytes(public_key), bytes(signature[:32])
    if bytes(a[:31]) + bytes([a[31] & 0x7f]) in _SMALL_ORDER:
        return False
    if not _canonical_y(a) or not _canonical_y(r):
        return False
    if int.from_bytes(signature[32:], "little") >= _L:
        return False
    if not ed25519_available():
        raise AlgorithmUnavailable(ED25519_UNAVAILABLE)
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(bytes(public_key))
        key.verify(bytes(signature), bytes(message))
        return True
    except UnsupportedAlgorithm as e:
        raise AlgorithmUnavailable(ED25519_UNAVAILABLE) from e
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_p384(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True if signature (DER ECDSA) is a valid ECDSA-P384-SHA384 signature of
    message under public_key, given as the uncompressed point 0x04||X||Y (97
    bytes). v1.41 streams. Never raises."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 97 \
            or public_key[0] != 0x04:
        return False
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        return False
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), bytes(public_key))
        key.verify(bytes(signature), bytes(message), ec.ECDSA(hashes.SHA384()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
