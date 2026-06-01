from typing import Dict, Tuple
import os

# support both package-relative and top-level imports
try:
    from .utils import H512, hkdf, compare_digest
    from .automaton import E
    from .kem import enc as kem_enc, dec as kem_dec
except Exception:
    from utils import H512, hkdf, compare_digest
    from automaton import E
    from kem import enc as kem_enc, dec as kem_dec


def encapsulate(pk_rec: bytes) -> Tuple[Dict[str, bytes], bytes]:
    """Return (artifact, K_final)

    artifact fields: C_kyber, S_final, Sigma, C, epsilon
    """
    epsilon = os.urandom(64)
    k_kyber = os.urandom(64)

    S_final = E(pk_rec, epsilon)

    C_kyber, SS_kyber = kem_enc(pk_rec, k_kyber)

    K_material = SS_kyber + S_final
    salt = H512(pk_rec)
    K_final = hkdf(salt, K_material, info=b"aetherium-v1", length=64)

    Sigma = H512(K_final + S_final + C_kyber)
    C_full = H512(C_kyber + S_final + Sigma + epsilon)
    C_tag = C_full[:32]

    artifact = {
        "C_kyber": C_kyber,
        "S_final": S_final,
        "Sigma": Sigma,
        "C": C_tag,
        "epsilon": epsilon,
    }

    return artifact, K_final


def decapsulate(sk_rec: bytes, pk_rec: bytes, artifact: Dict[str, bytes]) -> bytes:
    C_kyber = artifact["C_kyber"]
    S_final = artifact["S_final"]
    Sigma = artifact["Sigma"]
    C_tag = artifact["C"]
    epsilon = artifact["epsilon"]

    recomputed = H512(C_kyber + S_final + Sigma + epsilon)[:32]
    if not compare_digest(recomputed, C_tag):
        raise ValueError("Artefact integrity check failed")

    SS_kyber = kem_dec(sk_rec, C_kyber)

    S_final_prime = E(pk_rec, epsilon)
    # Comparaison en temps constant pour résister aux timing attacks
    if not compare_digest(S_final_prime, S_final):
        raise ValueError("Automaton state mismatch")

    K_material = SS_kyber + S_final_prime
    salt = H512(pk_rec)
    K_final_prime = hkdf(salt, K_material, info=b"aetherium-v1", length=64)

    Sigma_prime = H512(K_final_prime + S_final_prime + C_kyber)
    if not compare_digest(Sigma_prime, Sigma):
        raise ValueError("Sigma verification failed")

    return K_final_prime


__all__ = ["encapsulate", "decapsulate"]
