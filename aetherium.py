"""
Aetherium Ultra KEM v2 — Hybrid Key Encapsulation Mechanism.

Architecture (two independent hardness assumptions):
    Layer 1: ML-KEM-1024 (FIPS 203, Level 5) — module-lattice, post-quantum
    Layer 2: X25519 (RFC 7748)               — elliptic-curve Diffie-Hellman
    Context: chaotic automaton E(PK, epsilon) — PUBLIC, binds the transcript
    Fusion:  HKDF-SHA3-512(SS_mlkem || SS_x25519, info = label || transcript)

The session key stays secret as long as AT LEAST ONE of ML-KEM-1024 or X25519
is unbroken. The automaton has no secret input: it adds context binding,
not confidentiality.

Artifact:  A = (C_kyber, C_x25519, S_final, Sigma, C, epsilon)
    C_kyber   — ML-KEM ciphertext (1568 bytes)
    C_x25519  — 32-byte ephemeral X25519 public key
    S_final   — 64-byte automaton final state (public)
    Sigma     — 64-byte key confirmation HMAC(K_conf, transcript)
    C         — 32-byte corruption check H(...)[:32] (unkeyed, not a MAC)
    epsilon   — 64-byte public seed

Key layout:
    pk = pk_mlkem || pk_x25519 (32 bytes)
    sk = sk_mlkem || sk_x25519 (32 bytes)
"""

from __future__ import annotations

import hmac
import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

try:
    from .utils import H512, hkdf, compare_digest
    from .automaton import E
    from .kem import enc as kem_enc, dec as kem_dec, keygen as kem_keygen
except ImportError:
    from utils import H512, hkdf, compare_digest
    from automaton import E
    from kem import enc as kem_enc, dec as kem_dec, keygen as kem_keygen


# -- Constants ----------------------------------------------------------------

KEY_BYTES = 64       # 512-bit session key, automaton state, epsilon
CONF_BYTES = 64      # key-confirmation key
TAG_BYTES = 32       # 256-bit corruption check (truncated SHA3-512)
X25519_BYTES = 32
HKDF_INFO = b"aetherium-v2"


# -- Data structures ----------------------------------------------------------

@dataclass(frozen=True)
class Artifact:
    """Public transport artifact A = (C_kyber, C_x25519, S_final, Sigma, C, epsilon)."""
    C_kyber: bytes
    C_x25519: bytes
    S_final: bytes
    Sigma: bytes
    C: bytes
    epsilon: bytes

    def total_bytes(self) -> int:
        return (len(self.C_kyber) + len(self.C_x25519) + len(self.S_final)
                + len(self.Sigma) + len(self.C) + len(self.epsilon))


@dataclass(frozen=True)
class KeyPair:
    """Hybrid key pair (pk, sk)."""
    pk: bytes
    sk: bytes


# -- Helpers ------------------------------------------------------------------

def _split(key: bytes) -> Tuple[bytes, bytes]:
    """Split a hybrid key into (ML-KEM part, X25519 part)."""
    if len(key) <= X25519_BYTES:
        raise ValueError("Malformed hybrid key")
    return key[:-X25519_BYTES], key[-X25519_BYTES:]


def _x25519_raw(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _lp(*parts: bytes) -> bytes:
    """Length-prefixed concatenation: unambiguous encoding of the parts."""
    return b"".join(struct.pack(">I", len(p)) + p for p in parts)


def transcript(pk_rec: bytes, C_kyber: bytes, C_x25519: bytes,
               S_final: bytes, epsilon: bytes) -> bytes:
    """Hash of every public value of the exchange."""
    return H512(_lp(pk_rec, C_kyber, C_x25519, S_final, epsilon))


def derive_keys(ss_mlkem: bytes, ss_x25519: bytes, pk_rec: bytes,
                th: bytes) -> Tuple[bytes, bytes]:
    """Combiner: (K_final, K_conf) from both shared secrets and the transcript.

    Both secrets enter the IKM, so recovering K_final requires both.
    """
    okm = hkdf(H512(pk_rec), _lp(ss_mlkem, ss_x25519),
               info=HKDF_INFO + th, length=KEY_BYTES + CONF_BYTES)
    return okm[:KEY_BYTES], okm[KEY_BYTES:]


def _confirm(K_conf: bytes, th: bytes) -> bytes:
    return hmac.new(K_conf, b"aetherium-v2-confirm" + th, hashlib.sha3_512).digest()


def _tag(C_kyber: bytes, C_x25519: bytes, S_final: bytes,
         Sigma: bytes, epsilon: bytes) -> bytes:
    return H512(_lp(C_kyber, C_x25519, S_final, Sigma, epsilon))[:TAG_BYTES]


# -- Key generation -----------------------------------------------------------

def keygen() -> KeyPair:
    """Generate a hybrid ML-KEM-1024 + X25519 key pair."""
    pk_pq, sk_pq = kem_keygen()
    x_sk = X25519PrivateKey.generate()
    x_sk_raw = x_sk.private_bytes(serialization.Encoding.Raw,
                                  serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
    return KeyPair(pk=pk_pq + _x25519_raw(x_sk.public_key()), sk=sk_pq + x_sk_raw)


# -- Encapsulation ------------------------------------------------------------

def encapsulate(pk_rec: bytes) -> Tuple[Artifact, bytes]:
    """Encapsulate(PK_rec) -> (Artifact, K_final).

    Steps:
        1. epsilon <- {0,1}^512 ; S_final = E(PK_rec, epsilon)    [public]
        2. (C_kyber, SS_mlkem) = ML-KEM.Enc(pk_mlkem)
        3. ephemeral X25519: C_x25519 = e*G, SS_x25519 = e*pk_x25519
        4. th = H(PK_rec, C_kyber, C_x25519, S_final, epsilon)
        5. (K_final, K_conf) = HKDF(SS_mlkem || SS_x25519, salt=H(PK_rec), info || th)
        6. Sigma = HMAC(K_conf, th) ; C = H(artifact fields)[:32]
    """
    pk_pq, pk_x = _split(pk_rec)

    epsilon = os.urandom(KEY_BYTES)
    S_final = E(pk_rec, epsilon)

    C_kyber, ss_pq = kem_enc(pk_pq)

    eph = X25519PrivateKey.generate()
    C_x25519 = _x25519_raw(eph.public_key())
    ss_x = eph.exchange(X25519PublicKey.from_public_bytes(pk_x))

    th = transcript(pk_rec, C_kyber, C_x25519, S_final, epsilon)
    K_final, K_conf = derive_keys(ss_pq, ss_x, pk_rec, th)

    Sigma = _confirm(K_conf, th)
    C_tag = _tag(C_kyber, C_x25519, S_final, Sigma, epsilon)

    artifact = Artifact(C_kyber=C_kyber, C_x25519=C_x25519, S_final=S_final,
                        Sigma=Sigma, C=C_tag, epsilon=epsilon)
    return artifact, K_final


# -- Decapsulation ------------------------------------------------------------

def decapsulate(sk_rec: bytes, pk_rec: bytes, artifact: Artifact) -> bytes:
    """Decapsulate(SK_rec, PK_rec, A) -> K_final.

    Verification order:
        1. Corruption check C
        2. ML-KEM and X25519 decapsulation
        3. Automaton state match
        4. Key derivation
        5. Key confirmation Sigma (the check that matters against an attacker)

    Raises:
        ValueError: if any verification step fails.
    """
    if (len(artifact.C_x25519) != X25519_BYTES
            or len(artifact.S_final) != KEY_BYTES
            or len(artifact.epsilon) != KEY_BYTES):
        raise ValueError("Artifact integrity check failed (malformed field)")

    # Step 1: corruption check
    C_recomputed = _tag(artifact.C_kyber, artifact.C_x25519, artifact.S_final,
                        artifact.Sigma, artifact.epsilon)
    if not compare_digest(C_recomputed, artifact.C):
        raise ValueError("Artifact integrity check failed (tag mismatch)")

    # Step 2: both decapsulations
    sk_pq, sk_x = _split(sk_rec)
    ss_pq = kem_dec(sk_pq, artifact.C_kyber)
    try:
        ss_x = X25519PrivateKey.from_private_bytes(sk_x).exchange(
            X25519PublicKey.from_public_bytes(artifact.C_x25519))
    except ValueError:
        raise ValueError("X25519 decapsulation failed (invalid point)")

    # Step 3: recompute the public automaton state
    S_prime = E(pk_rec, artifact.epsilon)
    if not compare_digest(S_prime, artifact.S_final):
        raise ValueError("Automaton state mismatch (wrong PK or corrupted artifact)")

    # Step 4: derive keys
    th = transcript(pk_rec, artifact.C_kyber, artifact.C_x25519,
                    S_prime, artifact.epsilon)
    K_final, K_conf = derive_keys(ss_pq, ss_x, pk_rec, th)

    # Step 5: key confirmation
    if not compare_digest(_confirm(K_conf, th), artifact.Sigma):
        raise ValueError("Key confirmation Sigma verification failed")

    return K_final


__all__ = ["Artifact", "KeyPair", "keygen", "encapsulate", "decapsulate",
           "derive_keys", "transcript"]
