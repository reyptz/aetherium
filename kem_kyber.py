"""ML-KEM-1024 (FIPS 203, Level 5) wrapper using `pqcrypto`.

This module provides `keygen()`, `enc(pk)`, `dec(sk, C)`.
If `pqcrypto` is not installed, importing this module raises ImportError.

Supported `pqcrypto` layouts:
    - pqcrypto >= 1.0: `pqcrypto.kem.ml_kem_1024` with keygen/encaps/decaps
    - older releases:  `pqcrypto.kem.kyber1024` with keypair/encrypt/decrypt
"""
from typing import Tuple

_KYBER = None
try:
    from pqcrypto.kem import ml_kem_1024 as _KYBER
except Exception:
    try:
        from pqcrypto.kem import kyber1024 as _KYBER
    except Exception as e:
        raise ImportError(
            "pqcrypto ML-KEM-1024 module not available. "
            "Install it with `pip install pqcrypto`."
        ) from e


def _first(*names):
    for name in names:
        fn = getattr(_KYBER, name, None)
        if fn is not None:
            return fn
    raise RuntimeError("Unsupported pqcrypto ML-KEM API: none of %s" % (names,))


_keygen = _first("keygen", "generate_keypair", "keypair")
_encaps = _first("encaps", "encrypt", "encapsulate")
_decaps = _first("decaps", "decrypt", "decapsulate")


def keygen() -> Tuple[bytes, bytes]:
    pk, sk = _keygen()
    return bytes(pk), bytes(sk)


def enc(pk: bytes, k_seed: bytes = None) -> Tuple[bytes, bytes]:
    # k_seed is ignored: ML-KEM draws its own randomness.
    ct, ss = _encaps(pk)
    return bytes(ct), bytes(ss)


def dec(sk: bytes, C: bytes) -> bytes:
    # ML-KEM uses implicit rejection: a tampered ciphertext yields a
    # pseudo-random secret instead of an error. The caller's key
    # confirmation (Sigma) is what detects it.
    return bytes(_decaps(sk, C))
