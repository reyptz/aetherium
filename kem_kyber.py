"""Optional Kyber wrapper using `pqcrypto` if available.

This module provides `keygen()`, `enc(pk, k_seed=None)`, `dec(sk, C)`.
If `pqcrypto` is not installed, importing this module raises ImportError.
"""
from typing import Tuple

try:
    from pqcrypto.kem import kyber1024
except Exception as e:
    raise ImportError("pqcrypto Kyber1024 modules not available. Strict mode requires Kyber-1024 (NIST Level 5).") from e


_KYBER = kyber1024

if _KYBER is None:
    raise ImportError("No Kyber variant found in pqcrypto")


def keygen() -> Tuple[bytes, bytes]:
    for name in ("keypair", "generate_keypair"):
        fn = getattr(_KYBER, name, None)
        if fn is not None:
            pk, sk = fn()
            return pk, sk
    raise RuntimeError("Unsupported pqcrypto Kyber API")


def enc(pk: bytes, k_seed: bytes = None) -> Tuple[bytes, bytes]:
    for name in ("encaps", "encapsulate", "encrypt"):
        fn = getattr(_KYBER, name, None)
        if fn is not None:
            ct, ss = fn(pk)
            return ct, ss
    raise RuntimeError("Unsupported pqcrypto Kyber API for encapsulation")


def dec(sk: bytes, C: bytes) -> bytes:
    for name in ("decaps", "decapsulate", "decrypt"):
        fn = getattr(_KYBER, name, None)
        if fn is not None:
            return fn(sk, C)
    raise RuntimeError("Unsupported pqcrypto Kyber API for decapsulation")
