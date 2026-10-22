"""
Tests for Aetherium Ultra KEM.

Coverage:
    - Key generation
    - Encapsulation / decapsulation round-trip (correctness)
    - Automaton determinism
    - Artifact integrity tag rejection
    - Key confirmation (Sigma) rejection
    - Hybrid combiner (both secrets, transcript)
    - Fail-closed backend selection
    - Wrong secret key rejection
    - Tampered S_final rejection
    - Tampered epsilon rejection
    - HKDF primitive
    - Constant-time comparison
"""

import os
import subprocess
import sys

import pytest

import kem
from aetherium import (Artifact, KeyPair, keygen, encapsulate, decapsulate,
                       derive_keys, _tag)
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

def _retag(artifact, **changes):
    """Copy an artifact with some fields replaced and a consistent tag C."""
    fields = dict(
        C_kyber=artifact.C_kyber,
        C_x25519=artifact.C_x25519,
        S_final=artifact.S_final,
        Sigma=artifact.Sigma,
        epsilon=artifact.epsilon,
    )
    fields.update(changes)
    return Artifact(C=_tag(fields["C_kyber"], fields["C_x25519"], fields["S_final"],
                           fields["Sigma"], fields["epsilon"]), **fields)


class TestRejection:
    def test_wrong_secret_key_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        fake_kp = keygen()
        with pytest.raises(ValueError):
            decapsulate(fake_kp.sk, fake_kp.pk, artifact)

    def test_wrong_secret_key_right_pk_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        fake_kp = keygen()
        with pytest.raises(ValueError, match="Sigma"):
            decapsulate(fake_kp.sk, kp.pk, artifact)

    def test_tampered_tag_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        tampered = Artifact(
            C_kyber=artifact.C_kyber,
            C_x25519=artifact.C_x25519,
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
        # Keep the tag consistent to test deeper validation
        tampered = _retag(artifact, S_final=os.urandom(64))
        with pytest.raises(ValueError, match="Automaton state mismatch"):
            decapsulate(kp.sk, kp.pk, tampered)

    def test_tampered_epsilon_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        tampered = _retag(artifact, epsilon=os.urandom(64))
        with pytest.raises(ValueError, match="Automaton state mismatch"):
            decapsulate(kp.sk, kp.pk, tampered)

    def test_tampered_sigma_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        tampered = _retag(artifact, Sigma=os.urandom(64))
        with pytest.raises(ValueError, match="Sigma"):
            decapsulate(kp.sk, kp.pk, tampered)

    def test_tampered_ciphertext_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        tampered = _retag(artifact, C_kyber=os.urandom(len(artifact.C_kyber)))
        with pytest.raises(ValueError):
            decapsulate(kp.sk, kp.pk, tampered)

    def test_tampered_x25519_rejected(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        other = keygen()
        tampered = _retag(artifact, C_x25519=other.pk[-32:])
        with pytest.raises(ValueError, match="Sigma"):
            decapsulate(kp.sk, kp.pk, tampered)


# -- Hybrid combiner ----------------------------------------------------------

class TestHybrid:
    def test_key_layout(self):
        kp = keygen()
        artifact, _ = encapsulate(kp.pk)
        assert len(artifact.C_x25519) == 32
        if not kem.IS_STUB:
            assert len(kp.pk) == 1568 + 32
            assert len(artifact.C_kyber) == 1568

    def test_key_depends_on_both_secrets(self):
        pk = os.urandom(1600)
        th = os.urandom(64)
        ss_pq, ss_x = os.urandom(32), os.urandom(32)
        K, _ = derive_keys(ss_pq, ss_x, pk, th)
        assert derive_keys(os.urandom(32), ss_x, pk, th)[0] != K
        assert derive_keys(ss_pq, os.urandom(32), pk, th)[0] != K

    def test_key_depends_on_transcript(self):
        pk = os.urandom(1600)
        ss_pq, ss_x = os.urandom(32), os.urandom(32)
        K1, _ = derive_keys(ss_pq, ss_x, pk, os.urandom(64))
        K2, _ = derive_keys(ss_pq, ss_x, pk, os.urandom(64))
        assert K1 != K2


# -- Backend selection --------------------------------------------------------

class TestBackendSelection:
    def _import_kem_without_kyber(self, allow_stub):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = (
            "import sys; sys.modules['kem_kyber'] = None; "
            "sys.path.insert(0, %r); import kem; print(kem.BACKEND)" % root
        )
        env = dict(os.environ)
        env.pop("AETHERIUM_ALLOW_STUB", None)
        if allow_stub:
            env["AETHERIUM_ALLOW_STUB"] = "1"
        return subprocess.run([sys.executable, "-c", code], env=env,
                              capture_output=True, text=True)

    def test_fails_closed_without_real_backend(self):
        r = self._import_kem_without_kyber(allow_stub=False)
        assert r.returncode != 0
        assert "No ML-KEM-1024 backend found" in r.stderr

    def test_stub_requires_explicit_opt_in(self):
        r = self._import_kem_without_kyber(allow_stub=True)
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == "kem_stub"


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


# -- KEM backend tests (real ML-KEM, or stub when opted in) --------------------------------------------------------

class TestKEMBackend:
    def test_kem_roundtrip(self):
        pk, sk = kem_keygen()
        ct, ss_enc = kem_enc(pk)
        ss_dec = kem_dec(sk, ct)
        assert ss_enc == ss_dec

    def test_kem_different_sessions(self):
        pk, sk = kem_keygen()
        _, ss1 = kem_enc(pk)
        _, ss2 = kem_enc(pk)
        assert ss1 != ss2
