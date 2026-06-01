import hashlib
import hmac
from typing import Tuple


def H256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def H512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 64
    return hmac.new(salt, ikm, hashlib.sha3_512).digest()


def hkdf_expand(prk: bytes, info: bytes = b"", length: int = 64) -> bytes:
    okm = b""
    previous = b""
    i = 1
    while len(okm) < length:
        previous = hmac.new(prk, previous + info + bytes([i]), hashlib.sha3_512).digest()
        okm += previous
        i += 1
    return okm[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes = b"", length: int = 64) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def compare_digest(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
