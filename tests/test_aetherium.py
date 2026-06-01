import pytest

from aetherium import kem_keygen, encapsulate, decapsulate


def test_roundtrip_stub():
    keypair = kem_keygen()
    artifact, K1 = encapsulate(keypair.pk)
    K2 = decapsulate(keypair.sk, keypair.pk, artifact)
    assert K1 == K2


def test_roundtrip_real_kem():
    pytest.importorskip('pqcrypto')
    # When pqcrypto is available, kem functions should use real Kyber
    keypair = kem_keygen()
    artifact, K1 = encapsulate(keypair.pk)
    K2 = decapsulate(keypair.sk, keypair.pk, artifact)
    assert K1 == K2
