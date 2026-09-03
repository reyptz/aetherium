"""
Tests for Aetherium Ultra KEM.

Coverage:
    - Key generation
    - Encapsulation / decapsulation round-trip (correctness)
    - Automaton determinism
    - Artifact integrity tag rejection
    - Binding proof (Sigma) rejection
    - Wrong secret key rejection
    - Tampered S_final rejection
    - Tampered epsilon rejection
    - HKDF primitive
    - Constant-time comparison
"""

import os
import pytest

from aetherium import Artifact, KeyPair, keygen, encapsulate, decapsulate
from automaton import E
from utils import H512, hkdf, compare_digest, xor_bytes
from kem import keygen as kem_keygen, enc as kem_enc, dec as kem_dec


# -- Key generation -----------------------------------------------------------

class TestKeygen:
    def test_keygen_returns_keypair(self):
        kp = keygen()
        assert isinstance(kp, KeyPair)
        assert isinstance(kp.pk, bytes) and len(kp.pk) > 0
        assert isinstance(kp.sk, bytes) and len(kp.sk) > 0

    def test_keygen_uniqueness(self):
        kp1 = keygen()
        kp2 = keygen()
        assert kp1.pk != kp2.pk
        assert kp1.sk != kp2.sk


# -- Round-trip correctness ---------------------------------------------------

class TestRoundTrip:
    def test_encapsulate_decapsulate(self):
        kp = keygen()
        artifact, K_sender = encapsulate(kp.pk)
        K_receiver = decapsulate(kp.sk, kp.pk, artifact)
        assert K_sender == K_receiver
        assert len(K_sender) == 64  # 512-bit key

    def test_artifact_structure(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        assert isinstance(artifact, Artifact)
        assert len(artifact.S_final) == 64
        assert len(artifact.Sigma) == 64
        assert len(artifact.C) == 32
        assert len(artifact.epsilon) == 64
        assert artifact.total_bytes() > 0

    def test_multiple_roundtrips(self):
        kp = keygen()
        for _ in range(5):
            artifact, K1 = encapsulate(kp.pk)
            K2 = decapsulate(kp.sk, kp.pk, artifact)
            assert K1 == K2

    def test_different_sessions_produce_different_keys(self):
        kp = keygen()
        _, K1 = encapsulate(kp.pk)
        _, K2 = encapsulate(kp.pk)
        assert K1 != K2  # different epsilon -> different K_final


# -- Rejection tests ----------------------------------------------------------

class TestRejection:
    def test_wrong_secret_key_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        fake_kp = keygen()
        with pytest.raises(ValueError):
            decapsulate(fake_kp.sk, fake_kp.pk, artifact)

    def test_tampered_tag_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        tampered = Artifact(
            C_kyber=artifact.C_kyber,
            S_final=artifact.S_final,
            Sigma=artifact.Sigma,
            C=os.urandom(32),  # corrupted tag
            epsilon=artifact.epsilon,
        )
        with pytest.raises(ValueError, match="integrity"):
            decapsulate(kp.sk, kp.pk, tampered)

    def test_tampered_S_final_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        # Tamper S_final but keep the tag consistent to test deeper validation
        bad_S = os.urandom(64)
        bad_Sigma = artifact.Sigma
        bad_C = H512(artifact.C_kyber + bad_S + bad_Sigma + artifact.epsilon)[:32]
        tampered = Artifact(
            C_kyber=artifact.C_kyber,
            S_final=bad_S,
            Sigma=bad_Sigma,
            C=bad_C,
            epsilon=artifact.epsilon,
        )
        with pytest.raises(ValueError, match="Automaton state mismatch"):
            decapsulate(kp.sk, kp.pk, tampered)

    def test_tampered_epsilon_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        bad_eps = os.urandom(64)
        # Recompute tag for consistency
        bad_C = H512(artifact.C_kyber + artifact.S_final + artifact.Sigma + bad_eps)[:32]
        tampered = Artifact(
            C_kyber=artifact.C_kyber,
            S_final=artifact.S_final,
            Sigma=artifact.Sigma,
            C=bad_C,
            epsilon=bad_eps,
        )
        with pytest.raises(ValueError, match="Automaton state mismatch"):
            decapsulate(kp.sk, kp.pk, tampered)

    def test_tampered_sigma_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        bad_Sigma = os.urandom(64)
        bad_C = H512(artifact.C_kyber + artifact.S_final + bad_Sigma + artifact.epsilon)[:32]
        tampered = Artifact(
            C_kyber=artifact.C_kyber,
            S_final=artifact.S_final,
            Sigma=bad_Sigma,
            C=bad_C,
            epsilon=artifact.epsilon,
        )
        with pytest.raises(ValueError, match="Sigma"):
            decapsulate(kp.sk, kp.pk, tampered)

    def test_tampered_ciphertext_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        bad_ct = os.urandom(len(artifact.C_kyber))
        bad_C = H512(bad_ct + artifact.S_final + artifact.Sigma + artifact.epsilon)[:32]
        tampered = Artifact(
            C_kyber=bad_ct,
            S_final=artifact.S_final,
            Sigma=artifact.Sigma,
            C=bad_C,
            epsilon=artifact.epsilon,
        )
        with pytest.raises(ValueError):
            decapsulate(kp.sk, kp.pk, tampered)


# -- Automaton tests ----------------------------------------------------------

class TestAutomaton:
    def test_determinism(self):
        pk = os.urandom(32)
        eps = os.urandom(64)
        s1 = E(pk, eps)
        s2 = E(pk, eps)
        assert s1 == s2
        assert len(s1) == 64

    def test_sensitivity_to_pk(self):
        eps = os.urandom(64)
        s1 = E(os.urandom(32), eps)
        s2 = E(os.urandom(32), eps)
        assert s1 != s2

    def test_sensitivity_to_epsilon(self):
        pk = os.urandom(32)
        s1 = E(pk, os.urandom(64))
        s2 = E(pk, os.urandom(64))
        assert s1 != s2

    def test_custom_rounds(self):
        pk = os.urandom(32)
        eps = os.urandom(64)
        s1 = E(pk, eps, rounds=1)
        s64 = E(pk, eps, rounds=64)
        assert s1 != s64


# -- Primitive tests ----------------------------------------------------------

class TestPrimitives:
    def test_H512_determinism(self):
        data = b"test"
        assert H512(data) == H512(data)
        assert len(H512(data)) == 64

    def test_hkdf_determinism(self):
        salt = os.urandom(64)
        ikm = os.urandom(64)
        k1 = hkdf(salt, ikm, info=b"test", length=64)
        k2 = hkdf(salt, ikm, info=b"test", length=64)
        assert k1 == k2
        assert len(k1) == 64

    def test_hkdf_different_info_different_output(self):
        salt = os.urandom(64)
        ikm = os.urandom(64)
        k1 = hkdf(salt, ikm, info=b"a", length=64)
        k2 = hkdf(salt, ikm, info=b"b", length=64)
        assert k1 != k2

    def test_compare_digest_true(self):
        a = os.urandom(32)
        assert compare_digest(a, a) is True

    def test_compare_digest_false(self):
        a = os.urandom(32)
        b = os.urandom(32)
        assert compare_digest(a, b) is False

    def test_xor_bytes(self):
        a = bytes([0xFF, 0x00, 0xAA])
        b = bytes([0x0F, 0xF0, 0x55])
        assert xor_bytes(a, b) == bytes([0xF0, 0xF0, 0xFF])


# -- KEM backend tests --------------------------------------------------------

class TestKEMBackend:
    def test_stub_roundtrip(self):
        pk, sk = kem_keygen()
        ct, ss_enc = kem_enc(pk)
        ss_dec = kem_dec(sk, ct)
        assert ss_enc == ss_dec

    def test_stub_different_sessions(self):
        pk, sk = kem_keygen()
        _, ss1 = kem_enc(pk)
        _, ss2 = kem_enc(pk)
        assert ss1 != ss2
