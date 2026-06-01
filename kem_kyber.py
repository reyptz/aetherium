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
    # pqcrypto API: keypair() -> (pk, sk)
    if hasattr(_KYBER, "keypair"):
        pk, sk = _KYBER.keypair()
        return pk, sk
    if hasattr(_KYBER, "generate_keypair"):
        pk, sk = _KYBER.generate_keypair()
        return pk, sk
    raise RuntimeError("Unsupported pqcrypto Kyber API")


def enc(pk: bytes, k_seed: bytes = None) -> Tuple[bytes, bytes]:
    # Most pqcrypto Kyber wrappers expose `encapsulate(pk)` -> (ct, ss)
    if hasattr(_KYBER, "encapsulate"):
        ct, ss = _KYBER.encapsulate(pk)
        return ct, ss
    if hasattr(_KYBER, "encrypt"):
        ct, ss = _KYBER.encrypt(pk)
        return ct, ss
    raise RuntimeError("Unsupported pqcrypto Kyber API for encapsulation")


def dec(sk: bytes, C: bytes) -> bytes:
    if hasattr(_KYBER, "decapsulate"):
        return _KYBER.decapsulate(sk, C)
    if hasattr(_KYBER, "decrypt"):
        return _KYBER.decrypt(sk, C)
    raise RuntimeError("Unsupported pqcrypto Kyber API for decapsulation")
