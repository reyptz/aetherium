from typing import Union

# support both package-relative and top-level imports
try:
    from .utils import H512
except Exception:
    from utils import H512

# ByteString est dépréciée en Python 3.12+ ; on utilise un alias local.
_BytesLike = Union[bytes, bytearray]


def E(pk: _BytesLike, epsilon: _BytesLike, rounds: int = 64) -> bytes:
    """Deterministic cellular automaton as specified in the README.

    pk and epsilon are bytes-like objects. Returns 64-byte final state.
    """
    if not isinstance(pk, (bytes, bytearray)):
        pk = bytes(pk)
    if not isinstance(epsilon, (bytes, bytearray)):
        epsilon = bytes(epsilon)

    S = bytearray(H512(epsilon + pk))[:64]

    for r in range(rounds):
        r_bytes = r.to_bytes(4, "big")
        eta_r = H512(epsilon + pk + r_bytes)
        h_r = H512(bytes(S) + pk + eta_r + r_bytes)
        for i in range(64):
            if eta_r[i % 64] & 1:
                S[i] ^= h_r[i]

    return bytes(S)
