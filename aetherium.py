"""
Aetherium Ultra KEM — Hybrid Post-Quantum Key Encapsulation Mechanism.

Architecture:
    Layer 1: ML-KEM (Kyber-1024, NIST FIPS 203) — algebraic PQ hardness
    Layer 2: Deterministic chaotic automaton E(PK, epsilon) — stochastic complexity
    Fusion:  HKDF-SHA3-512(SS_kyber || S_final) -> K_final (512-bit session key)

Artifact:  A = (C_kyber, S_final, Sigma, C, epsilon)
    C_kyber  — KEM ciphertext (variable length)
    S_final  — 64-byte automaton final state
    Sigma    — 64-byte binding proof H(K_final || S_final || C_kyber)
    C        — 32-byte integrity tag H(C_kyber || S_final || Sigma || epsilon)[:32]
    epsilon  — 64-byte public seed

Security properties:
    - IND-CCA2 under KEM + chaos assumption
    - Constant-time comparisons (timing-attack resistant)
    - Deterministic reproducibility (E is a pure function)
    - Artifact integrity via truncated SHA3-512 tag
    - Binding proof Sigma prevents key-commitment attacks
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

try:
    from .utils import H512, hkdf, compare_digest
    from .automaton import E
    from .kem import enc as kem_enc, dec as kem_dec, keygen as kem_keygen
except ImportError:
    from utils import H512, hkdf, compare_digest
    from automaton import E
    from kem import enc as kem_enc, dec as kem_dec, keygen as kem_keygen


# -- Constants ----------------------------------------------------------------

KEY_BYTES = 64       # 512-bit keys and states
TAG_BYTES = 32       # 256-bit integrity tag (truncated SHA3-512)
HKDF_INFO = b"aetherium-v1"


# -- Data structures ----------------------------------------------------------

@dataclass(frozen=True)
class Artifact:
    """Public transport artifact A = (C_kyber, S_final, Sigma, C, epsilon)."""
    C_kyber: bytes
    S_final: bytes
    Sigma: bytes
    C: bytes
    epsilon: bytes

    def total_bytes(self) -> int:
        return len(self.C_kyber) + len(self.S_final) + len(self.Sigma) + len(self.C) + len(self.epsilon)


@dataclass(frozen=True)
class KeyPair:
    """KEM key pair (pk, sk)."""
    pk: bytes
    sk: bytes


# -- Key generation -----------------------------------------------------------

def keygen() -> KeyPair:
    """Generate a KEM key pair.

    Uses ML-KEM (Kyber-1024) when pqcrypto is available, else a
    deterministic HMAC-based stub for development and testing.
    """
    pk, sk = kem_keygen()
    return KeyPair(pk=pk, sk=sk)


# -- Encapsulation ------------------------------------------------------------

def encapsulate(pk_rec: bytes) -> Tuple[Artifact, bytes]:
    """Encapsulate(PK_rec) -> (Artifact, K_final).

    Steps:
        1. Sample epsilon <- {0,1}^512
        2. S_final = E(PK_rec, epsilon)           [chaotic automaton]
        3. (C_kyber, SS_kyber) = KEM.Enc(PK_rec)  [post-quantum KEM]
        4. K_final = HKDF(SS_kyber || S_final, salt=H(PK_rec), info)
        5. Sigma = H(K_final || S_final || C_kyber)
        6. C = H(C_kyber || S_final || Sigma || epsilon)[:32]

    Returns:
        (artifact, K_final) where K_final is the 512-bit session key.
    """
    epsilon = os.urandom(KEY_BYTES)

    S_final = E(pk_rec, epsilon)

    C_kyber, SS_kyber = kem_enc(pk_rec)

    K_material = SS_kyber + S_final
    salt = H512(pk_rec)
    K_final = hkdf(salt, K_material, info=HKDF_INFO, length=KEY_BYTES)

    Sigma = H512(K_final + S_final + C_kyber)
    C_tag = H512(C_kyber + S_final + Sigma + epsilon)[:TAG_BYTES]

    artifact = Artifact(
        C_kyber=C_kyber,
        S_final=S_final,
        Sigma=Sigma,
        C=C_tag,
        epsilon=epsilon,
    )
    return artifact, K_final


# -- Decapsulation ------------------------------------------------------------

def decapsulate(sk_rec: bytes, pk_rec: bytes, artifact: Artifact) -> bytes:
    """Decapsulate(SK_rec, PK_rec, A) -> K_final.

    Verification order:
        1. Integrity tag C
        2. KEM decapsulation
        3. Automaton state match
        4. HKDF key derivation
        5. Binding proof Sigma

    Raises:
        ValueError: if any verification step fails.
    """
    # Step 1: Verify artifact integrity tag
    C_recomputed = H512(
        artifact.C_kyber + artifact.S_final + artifact.Sigma + artifact.epsilon
    )[:TAG_BYTES]
    if not compare_digest(C_recomputed, artifact.C):
        raise ValueError("Artifact integrity check failed (tag mismatch)")

    # Step 2: KEM decapsulation
    SS_kyber = kem_dec(sk_rec, artifact.C_kyber)

    # Step 3: Recompute automaton state
    S_prime = E(pk_rec, artifact.epsilon)
    if not compare_digest(S_prime, artifact.S_final):
        raise ValueError("Automaton state mismatch (wrong PK or corrupted artifact)")

    # Step 4: Derive session key
    K_material = SS_kyber + S_prime
    salt = H512(pk_rec)
    K_final = hkdf(salt, K_material, info=HKDF_INFO, length=KEY_BYTES)

    # Step 5: Verify binding proof
    Sigma_prime = H512(K_final + S_prime + artifact.C_kyber)
    if not compare_digest(Sigma_prime, artifact.Sigma):
        raise ValueError("Binding proof Sigma verification failed")

    return K_final


__all__ = ["Artifact", "KeyPair", "keygen", "encapsulate", "decapsulate"]
