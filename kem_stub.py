import os
from typing import Tuple

# support both package-relative and top-level imports
try:
    from .utils import H256, xor_bytes
except Exception:
    from utils import H256, xor_bytes


def keygen(seed: bytes = None) -> Tuple[bytes, bytes]:
    """Return (pk, sk). For the stub, sk is a 32-byte seed, pk = H256(sk)."""
    if seed is None:
        seed = os.urandom(32)
    sk = seed
    pk = H256(sk)
    return pk, sk


def enc(pk: bytes, k_seed: bytes) -> Tuple[bytes, bytes]:
    """Deterministic KEM.Enc(pk; k_seed) -> (ciphertext, shared_secret)

    The ciphertext embeds k_seed xored with a mask derived from pk.
    """
    mask = H256(pk + b"kem-mask")
    C = xor_bytes(k_seed, mask[: len(k_seed)])
    SS = H256(k_seed + pk)
    return C, SS


def dec(sk: bytes, C: bytes) -> bytes:
    """Deterministic KEM.Dec(sk, C) -> shared_secret

    Recovers k_seed using sk -> pk, then derives SS.
    """
    pk = H256(sk)
    mask = H256(pk + b"kem-mask")
    k_seed = xor_bytes(C, mask[: len(C)])
    SS = H256(k_seed + pk)
    return SS
