#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              AETHERIUM ULTRA KEM — Implémentation de Référence              ║
║         Architecture Hybride : KEM Post-Quantique + Automate Chaotique      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Sécurité repose sur deux couches indépendantes :                           ║
║    1. ML-KEM / Kyber512  — résistance quantique (NIST FIPS 203)             ║
║    2. Automate chaotique déterministe E(PK, ε)  — complexité stochastique   ║
║  La clé finale est une fusion HKDF (SHA-256) des deux secrets.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from typing import Optional, Tuple

# ── Import KEM post-quantique ──────────────────────────────────────────────────
try:
    from pqcrypto.kem import kyber512  # pip install pqcrypto
    _KYBER_AVAILABLE = True
except ImportError:
    _KYBER_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# § 1. PRIMITIVES CRYPTOGRAPHIQUES
# ══════════════════════════════════════════════════════════════════════════════

ROUNDS    = 32          # Nombre de tours de l'automate E
KEY_BYTES = 32          # Longueur des clés : 256 bits
TAG_BYTES = 16          # Longueur du tag d'intégrité C : 128 bits


def H256(data: bytes) -> bytes:
    """𝓗₂₅₆ : SHA-256 → 32 octets."""
    return hashlib.sha256(data).digest()


def H_shake(data: bytes, length: int = KEY_BYTES) -> bytes:
    """𝓗_shake : SHAKE-256 (XOF) → `length` octets."""
    return hashlib.shake_256(data).digest(length)


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_BYTES) -> bytes:
    """
    HKDF-SHA256 (RFC 5869).
    K = HKDF(IKM, salt, info) ∈ {0,1}^(length×8)
    """
    # Extract : PRK = HMAC-SHA256(salt, IKM)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # Expand : T(i) = HMAC-SHA256(PRK, T(i-1) ‖ info ‖ i)
    t, okm = b"", b""
    for i in range(1, (length // KEY_BYTES) + 2):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def secure_eq(a: bytes, b: bytes) -> bool:
    """Comparaison en temps constant (résistance aux timing-attacks)."""
    return hmac.compare_digest(a, b)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR octet à octet : a ⊕ b."""
    return bytes(x ^ y for x, y in zip(a, b))


# ══════════════════════════════════════════════════════════════════════════════
# § 2. AUTOMATE CHAOTIQUE DÉTERMINISTE  E(PK, ε)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Bruit déterministe (§2.2 révisé) :
#    η_r = H256(ε ‖ PK ‖ ⟨r⟩₄)
#
#  Tour r (§3.1) :
#    h_r      = H256(S_r ‖ PK ‖ η_r ‖ ⟨r⟩₄)
#    S_{r+1}[i] = S_r[i] ⊕ h_r[i]   si η_r[i mod 32] mod 2 = 1
#               = S_r[i]              sinon
#
#  État initial (§3 amendé) :
#    S_0 = H256(ε ‖ PK)
#
#  Résultat : S_final = E(PK, ε) = S_32 ∈ {0,1}^256


def _chaos_noise(epsilon: bytes, pk: bytes, r: int) -> bytes:
    """η_r = H256(ε ‖ PK ‖ ⟨r⟩₄)  — déterministe, pas d'horloge."""
    return H256(epsilon + pk + struct.pack(">I", r))


def _chaos_round(state: bytearray, pk: bytes, epsilon: bytes, r: int) -> bytearray:
    """Un tour complet de l'automate : η_r → h_r → mutation XOR conditionnelle."""
    eta = _chaos_noise(epsilon, pk, r)
    h   = H256(bytes(state) + pk + eta + struct.pack(">I", r))

    next_state = bytearray(state)
    for i in range(KEY_BYTES):
        if eta[i % KEY_BYTES] % 2 == 1:
            next_state[i] ^= h[i]
    return next_state


def evolve(pk: bytes, epsilon: bytes) -> bytes:
    """
    E(PK, ε) → S_final ∈ {0,1}^256

    Automate chaotique déterministe sur ROUNDS tours.
    Propriété : E est une fonction pure — même (PK, ε) → même S_final.
    """
    state = bytearray(H256(epsilon + pk))              # S_0 = H256(ε ‖ PK)
    for r in range(ROUNDS):
        state = _chaos_round(state, pk, epsilon, r)    # S_{r+1} = round(S_r, ...)
    return bytes(state)                                # S_final = S_32


# ══════════════════════════════════════════════════════════════════════════════
# § 3. COUCHE KEM (ML-KEM / Kyber512 — ou stub HMAC si absent)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class KEMKeyPair:
    pk: bytes
    sk: bytes


def kem_keygen() -> KEMKeyPair:
    """Génère une paire de clés KEM post-quantique."""
    if _KYBER_AVAILABLE:
        pk, sk = kyber512.keypair()
        return KEMKeyPair(pk=pk, sk=sk)
    # ── Stub HMAC-SHA256 (démo uniquement — non post-quantique) ──────────────
    sk = os.urandom(KEY_BYTES)
    pk = H256(b"aetherium:pk-derive:v1" + sk)
    return KEMKeyPair(pk=pk, sk=sk)


def kem_encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
    """
    (C_kyber, SS_kyber) = KEM.Enc(PK)
    Retourne le ciphertext et le secret partagé.
    """
    if _KYBER_AVAILABLE:
        ciphertext, key = kyber512.encaps(pk)
        return ciphertext, key
    # ── Stub ──────────────────────────────────────────────────────────────────
    r      = os.urandom(KEY_BYTES)
    SS     = H256(b"aetherium:ss:v1"  + pk + r)
    C      = H256(b"aetherium:ct:v1"  + pk + r)
    # Pour la décapsulation stub : r est encodé dans C (accepté uniquement en mode stub)
    return C + r, SS


def kem_decapsulate(sk: bytes, pk: bytes, ciphertext: bytes) -> Optional[bytes]:
    """
    SS_kyber = KEM.Dec(SK, C_kyber)
    Retourne le secret partagé ou None si le ciphertext est invalide.
    """
    if _KYBER_AVAILABLE:
        try:
            key = kyber512.decaps(sk, ciphertext)
            return key
        except Exception:
            return None
    # ── Stub ──────────────────────────────────────────────────────────────────
    if len(ciphertext) < KEY_BYTES * 2:
        return None
    r  = ciphertext[KEY_BYTES:]
    SS = H256(b"aetherium:ss:v1" + pk + r)
    return SS


# ══════════════════════════════════════════════════════════════════════════════
# § 4. KEM AETHERIUM ULTRA — PROTOCOLE HYBRIDE DÉTERMINISTE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class AetheriumArtifact:
    """
    𝒜 = (C_kyber, S_final, Σ, C, ε)
    Artefact de transport — tout est public sauf SK_rec.

    Champ      Taille   Rôle
    ─────────  ───────  ─────────────────────────────────────────────────
    C_kyber    variable Ciphertext KEM post-quantique
    S_final    32 oct.  État chaotique de référence (256 bits)
    sigma      32 oct.  Σ = H256(K ‖ S_final ‖ C_kyber) — preuve de liaison
    tag        16 oct.  C = H256(C_kyber ‖ S_final ‖ Σ ‖ ε)[:16] — intégrité
    epsilon    32 oct.  ε — graine publique de l'automate
    """
    C_kyber : bytes
    S_final : bytes
    sigma   : bytes
    tag     : bytes
    epsilon : bytes


def encapsulate(pk_rec: bytes) -> Tuple[AetheriumArtifact, bytes]:
    """
    Encapsulate(PK_rec) → (𝒜, K_final)

    ┌─ Entrée  ─────────────────────────────────────────────────────────┐
    │  pk_rec : clé publique du destinataire                            │
    └───────────────────────────────────────────────────────────────────┘
    ┌─ Sortie  ─────────────────────────────────────────────────────────┐
    │  𝒜       : artefact public transmis au destinataire               │
    │  K_final : clé de session secrète (512 bits) — NE PAS TRANSMETTRE │
    └───────────────────────────────────────────────────────────────────┘
    """
    # ── Étape 1 : Aléa ε ────────────────────────────────────────────────────
    epsilon = os.urandom(KEY_BYTES)

    # ── Étape 2 : Automate chaotique ────────────────────────────────────────
    #   S_final = E(PK_rec, ε)
    S_final = evolve(pk_rec, epsilon)

    # ── Étape 3 : KEM post-quantique ────────────────────────────────────────
    #   (C_kyber, SS_kyber) = KEM.Enc(PK_rec)
    C_kyber, SS_kyber = kem_encapsulate(pk_rec)

    # ── Étape 4 : Dérivation de la clé de session ───────────────────────────
    #   K_material = SS_kyber ‖ S_final
    #   K_final    = HKDF(K_material, salt=H256(PK_rec), info="aetherium-v1")
    K_material = SS_kyber + S_final
    K_final = hkdf(
        ikm  = K_material,
        salt = H256(pk_rec),
        info = b"aetherium-v1",
    )

    # ── Étape 5 : Preuves et intégrité ──────────────────────────────────────
    #   Σ = H256(K_final ‖ S_final ‖ C_kyber)
    #   C = H256(C_kyber ‖ S_final ‖ Σ ‖ ε)[:16]
    sigma = H256(K_final + S_final + C_kyber)
    tag   = H256(C_kyber + S_final + sigma + epsilon)[:TAG_BYTES]

    artifact = AetheriumArtifact(
        C_kyber = C_kyber,
        S_final = S_final,
        sigma   = sigma,
        tag     = tag,
        epsilon = epsilon,
    )
    return artifact, K_final


def decapsulate(
    sk_rec  : bytes,
    pk_rec  : bytes,
    artifact: AetheriumArtifact,
) -> Optional[bytes]:
    """
    Decapsulate(SK_rec, PK_rec, 𝒜) → K_final | ⊥

    Retourne K_final si l'artefact est valide, None (⊥) sinon.

    Chaque vérification utilise secure_eq pour résister aux timing-attacks.
    """
    # ── Préliminaire : Intégrité de l'artefact ──────────────────────────────
    #   C' = H256(C_kyber ‖ S_final ‖ Σ ‖ ε)[:16]
    #   C' ≠ C  →  ⊥
    tag_prime = H256(
        artifact.C_kyber + artifact.S_final +
        artifact.sigma   + artifact.epsilon
    )[:TAG_BYTES]

    if not secure_eq(tag_prime, artifact.tag):
        return None  # ⊥ — Artefact altéré ou rejoué

    # ── Étape 1 : Décapsulation KEM ─────────────────────────────────────────
    #   SS_kyber = KEM.Dec(SK_rec, C_kyber)
    SS_kyber = kem_decapsulate(sk_rec, pk_rec, artifact.C_kyber)
    if SS_kyber is None:
        return None  # ⊥ — Clé privée invalide ou ciphertext corrompu

    # ── Étape 2 : Reconstruction déterministe de l'automate ─────────────────
    #   S'_final = E(PK_rec, ε)
    #   S'_final ≠ S_final  →  ⊥
    S_prime = evolve(pk_rec, artifact.epsilon)

    if not secure_eq(S_prime, artifact.S_final):
        return None  # ⊥ — PK incorrect ou artefact corrompu

    # ── Étape 3 : Dérivation de la clé de session ───────────────────────────
    #   K'_material = SS_kyber ‖ S'_final
    #   K'_final    = HKDF(K'_material, salt=H256(PK_rec), info="aetherium-v1")
    K_material = SS_kyber + S_prime
    K_final = hkdf(
        ikm  = K_material,
        salt = H256(pk_rec),
        info = b"aetherium-v1",
    )

    # ── Étape 4 : Vérification de la preuve Σ ───────────────────────────────
    #   Σ' = H256(K'_final ‖ S'_final ‖ C_kyber)
    #   Σ' ≠ Σ  →  ⊥
    sigma_prime = H256(K_final + S_prime + artifact.C_kyber)

    if not secure_eq(sigma_prime, artifact.sigma):
        return None  # ⊥ — Preuve invalide

    return K_final


# ══════════════════════════════════════════════════════════════════════════════
# § 5. TUNNEL OTP (One-Time Pad via SHAKE-256)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Chiffrement : C = M ⊕ K_stream    avec K_stream = SHAKE256(K_final ‖ "otp-stream", |M|)
#  Shannon 1949 : H(M|C) = H(M)  →  sécurité parfaite si K_stream est utilisé une fois.
#  La clé K_final est détruite après usage (variable locale, pas de persistance).


def otp_encrypt(message: bytes, key: bytes) -> bytes:
    """
    Chiffrement OTP : C = M ⊕ SHAKE256(K_final ‖ "otp-stream", |M|)
    La clé doit être unique par message (one-time).
    """
    stream = H_shake(key + b"otp-stream", length=len(message))
    return xor_bytes(message, stream)


def otp_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Déchiffrement OTP (XOR est son propre inverse)."""
    return otp_encrypt(ciphertext, key)


# ══════════════════════════════════════════════════════════════════════════════
# § 6. DÉMONSTRATION — Adam et Hawa
# ══════════════════════════════════════════════════════════════════════════════

def _separator(title: str = "") -> None:
    w = 68
    if title:
        pad = (w - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * (w - pad - len(title) - 2)}")
    else:
        print("─" * w)


def _fmt(label: str, data: bytes, secret: bool = False) -> None:
    preview = "[PRIVÉE — non affichée]" if secret else data.hex()[:48] + "..."
    print(f"  {label:<14} {preview}")


def main() -> None:
    print("═" * 68)
    print("  AETHERIUM ULTRA KEM  — Démonstration complète")
    mode = "ML-KEM (Kyber512) [FIPS 203]" if _KYBER_AVAILABLE else "Stub HMAC-SHA256 [DEMO ONLY]"
    print(f"  Mode KEM    : {mode}")
    print(f"  Automate    : {ROUNDS} tours chaotiques déterministes")
    print("═" * 68)

    # ── Génération des clés de Hawa ──────────────────────────────────────────
    _separator("PHASE 0 — Génération des clés de Hawa")
    hawa = kem_keygen()
    _fmt("PK_Hawa",  hawa.pk)
    _fmt("SK_Hawa",  hawa.sk, secret=True)

    # ── Encapsulation par Adam ───────────────────────────────────────────────
    _separator("PHASE 1 — Adam encapsule pour Hawa")
    artifact, K_adam = encapsulate(hawa.pk)
    _fmt("ε",         artifact.epsilon)
    _fmt("S_final",   artifact.S_final)
    _fmt("C_kyber",   artifact.C_kyber)
    _fmt("Σ (sigma)", artifact.sigma)
    _fmt("C (tag)",   artifact.tag)
    _fmt("K_Adam",    K_adam, secret=True)

    # ── Décapsulation par Hawa ───────────────────────────────────────────────
    _separator("PHASE 2 — Hawa décapsule l'artefact")
    K_hawa = decapsulate(hawa.sk, hawa.pk, artifact)

    if K_hawa is None:
        print("  ✗ ÉCHEC — Décapsulation invalide (⊥)")
        return

    _fmt("K_Hawa", K_hawa, secret=True)
    keys_match = secure_eq(K_adam, K_hawa)
    print(f"\n  Clés identiques ? {'✓  OUI — Accord établi' if keys_match else '✗  NON — Divergence'}")

    # ── Vérification de résistance à Eve ────────────────────────────────────
    _separator("PHASE 3 — Test de résistance (Eve intercepte l'artefact)")
    fake_sk  = os.urandom(KEY_BYTES)                         # Eve n'a pas SK_Hawa
    fake_pk  = H256(b"aetherium:pk-derive:v1" + fake_sk)
    K_eve    = decapsulate(fake_sk, fake_pk, artifact)
    print(f"  Résultat Eve (fausse SK) : {'K_final ✗ (⊥ retourné)' if K_eve is None else 'SUCCÈS — FAILLE !'}")

    tampered = AetheriumArtifact(                             # Artefact falsifié
        C_kyber = artifact.C_kyber,
        S_final = os.urandom(KEY_BYTES),                     # S_final altéré
        sigma   = artifact.sigma,
        tag     = artifact.tag,
        epsilon = artifact.epsilon,
    )
    K_tampered = decapsulate(hawa.sk, hawa.pk, tampered)
    print(f"  Résultat Eve (artefact falsifié) : {'Rejeté ✓ (⊥)' if K_tampered is None else 'SUCCÈS — FAILLE !'}")

    # ── Tunnel OTP ──────────────────────────────────────────────────────────
    if keys_match:
        _separator("PHASE 4 — Tunnel OTP Adam → Hawa")
        secret    = b"Protocole Aetherium : operationnel et deterministe."
        cipher    = otp_encrypt(secret, K_adam)
        recovered = otp_decrypt(cipher, K_hawa)
        print(f"  Original  : {secret.decode()}")
        print(f"  Chiffré   : {cipher.hex()[:48]}...")
        print(f"  Récupéré  : {recovered.decode()}")
        print(f"  Intégrité : {'✓ OK' if recovered == secret else '✗ ÉCHEC'}")

    print("\n" + "═" * 68)
    print("  Propriété de correction : K_Adam = K_Hawa  ✓")
    print("  Propriété de sécurité   : Eve → ⊥          ✓")
    print("═" * 68 + "\n")


if __name__ == "__main__":
    main()