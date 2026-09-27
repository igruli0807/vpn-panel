"""WireGuard-compatible keys without external tools: X25519 (RFC 7748) in pure Python."""
import base64
import os

_P = 2**255 - 19
_A24 = 121665


def _clamp(k: bytearray) -> bytearray:
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return k


def _x25519(scalar: bytes, u: bytes) -> bytes:
    k = int.from_bytes(_clamp(bytearray(scalar)), "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def genkey() -> str:
    return base64.b64encode(bytes(_clamp(bytearray(os.urandom(32))))).decode()


def pubkey(private_b64: str) -> str:
    return base64.b64encode(_x25519(base64.b64decode(private_b64), (9).to_bytes(32, "little"))).decode()


def genpsk() -> str:
    return base64.b64encode(os.urandom(32)).decode()
