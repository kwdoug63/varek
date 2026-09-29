# SPDX-License-Identifier: MIT
"""
varek_ed25519.py — Ed25519 signature verification (RFC 8032), in pure Python,
for tools/varek_audit.py (v1.16).

The Warden signs its verdict stream with libsodium. The audit verifies those
signatures with this separate implementation, so it needs no third-party
package and does not trust the signer's library to check its own output.
It follows the RFC 8032 section 5.1.7 verification procedure, and is strict:

  * A (the public key) and R must be canonical encodings of curve points
    (y < p; x = 0 with the sign bit set is refused), and A must not have small
    order;
  * S must be below the group order L;
  * the equation checked is [S]B = R + [k]A (k = SHA-512(R || A || M) mod L).

Verification only: this module never handles a private key, and it is not
constant-time (it needs not be; everything it touches is public).
"""

import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)
IDENTITY = (0, 1, 1, 0)


def _add(a, b):
    # Extended twisted Edwards coordinates (RFC 8032 section 5.1.4).
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P
    B = (y1 + x1) * (y2 + x2) % P
    C = t1 * 2 * D * t2 % P
    Dd = z1 * 2 * z2 % P
    E, F, Gg, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, Gg * H % P, F * Gg % P, E * H % P)


def _mul(s, pt):
    q = IDENTITY
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _equal(a, b):
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _decode(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True if signature is a valid Ed25519 signature of message under
    public_key (32 bytes). Never raises on malformed input."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    A = _decode(bytes(public_key))
    if A is None or _equal(_mul(8, A), IDENTITY):
        return False
    Rb = bytes(signature[:32])
    R = _decode(Rb)
    if R is None:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= L:
        return False
    k = int.from_bytes(hashlib.sha512(Rb + bytes(public_key) + bytes(message)).digest(), "little") % L
    return _equal(_mul(S, G), _add(R, _mul(k, A)))
