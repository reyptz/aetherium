#!/usr/bin/env python3
"""
Aetherium Ultra KEM v2 — adversarial break harness.

Self-audit of the Aetherium hybrid KEM: generate a key with the scheme, then
run a battery of attacks against it and report, for each, whether the session
key K_final was recovered or a bad artifact was accepted.

Run:
    python attacks/break_key.py                 # real ML-KEM-1024 backend
    AETHERIUM_ALLOW_STUB=1 python attacks/break_key.py
                                                # insecure stub: shows that
                                                # X25519 alone still holds

Attacks use only what an eavesdropper or active attacker sees (public key +
artifact), unless labelled as a simulated compromise of one layer. The harness
exits non-zero if any attack breaks the key.

These are tests against our OWN implementation, run locally, to find
weaknesses before anyone else does. Nothing here targets a third party.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import kem  # noqa: E402
from aetherium import (Artifact, keygen, encapsulate, decapsulate,  # noqa: E402
                       derive_keys, transcript, _confirm, _tag, _split)
from automaton import E  # noqa: E402
from utils import H256  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives import serialization  # noqa: E402


# -- Result bookkeeping -------------------------------------------------------

@dataclass
class Result:
    name: str
    broke_key: bool          # did the attack recover the key / get a bad artifact accepted?
    detail: str
    # False for observations that are not breaks (e.g. public values being public).
    is_attack: bool = True

    @property
    def verdict(self) -> str:
        if not self.is_attack:
            return "info"
        return "BROKEN" if self.broke_key else "resisted"


ATTACKS: List[Callable[[], Result]] = []


def attack(fn: Callable[[], Result]) -> Callable[[], Result]:
    ATTACKS.append(fn)
    return fn


def _x_raw(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _encapsulate_exposed(pk):
    """Same steps as aetherium.encapsulate, but also returns both layer secrets.

    Used only to SIMULATE the compromise of one layer. The result is checked
    against decapsulate() so it cannot drift from the real code.
    """
    pk_pq, pk_x = _split(pk)
    eps = os.urandom(64)
    s_final = E(pk, eps)
    c_kyber, ss_pq = kem.enc(pk_pq)
    eph = X25519PrivateKey.generate()
    c_x = _x_raw(eph.public_key())
    ss_x = eph.exchange(X25519PublicKey.from_public_bytes(pk_x))
    th = transcript(pk, c_kyber, c_x, s_final, eps)
    k_final, k_conf = derive_keys(ss_pq, ss_x, pk, th)
    sigma = _confirm(k_conf, th)
    art = Artifact(C_kyber=c_kyber, C_x25519=c_x, S_final=s_final, Sigma=sigma,
                   C=_tag(c_kyber, c_x, s_final, sigma, eps), epsilon=eps)
    return art, k_final, ss_pq, ss_x


def _retag(a: Artifact, **changes) -> Artifact:
    f = dict(C_kyber=a.C_kyber, C_x25519=a.C_x25519, S_final=a.S_final,
             Sigma=a.Sigma, epsilon=a.epsilon)
    f.update(changes)
    return Artifact(C=_tag(f["C_kyber"], f["C_x25519"], f["S_final"], f["Sigma"],
                           f["epsilon"]), **f)


def _stub_secret(pk_pq: bytes, c_kyber: bytes) -> bytes:
    """v1 break: the stub's mask depends on pk only, so (pk, ct) gives SS.

    Returns the real secret when the stub is active, garbage against ML-KEM.
    """
    mask = hashlib.shake_256(pk_pq + b"kem-mask").digest(len(c_kyber))
    k_seed = bytes(x ^ y for x, y in zip(c_kyber, mask))
    return H256(k_seed + pk_pq)


def _accepted(sk, pk, art) -> bool:
    try:
        decapsulate(sk, pk, art)
        return True
    except ValueError:
        return False


# -- Attack 1: key recovery from public data only -----------------------------

@attack
def a01_public_only_key_recovery() -> Result:
    """Eavesdropper: rebuild K_final from pk + artifact.

    Uses the v1 stub break on the ML-KEM part (works only if the stub is
    active) and has no way to obtain the X25519 secret, so it plugs in the
    only public X25519 value it has.
    """
    kp = keygen()
    art, k_real = encapsulate(kp.pk)
    ss_pq_guess = _stub_secret(_split(kp.pk)[0], art.C_kyber)

    th = transcript(kp.pk, art.C_kyber, art.C_x25519, art.S_final, art.epsilon)
    k_guess, _ = derive_keys(ss_pq_guess, art.C_x25519, kp.pk, th)
    broke = k_guess == k_real
    return Result("public-only-key-recovery", broke,
                  f"backend={kem.BACKEND}; match={broke}")


# -- Attack 2: ML-KEM layer fully compromised ---------------------------------

@attack
def a02_mlkem_layer_compromised() -> Result:
    """Simulate a total break of ML-KEM: the attacker knows SS_mlkem.

    The key must still hold thanks to X25519.
    """
    kp = keygen()
    art, k_real, ss_pq, _ = _encapsulate_exposed(kp.pk)
    assert decapsulate(kp.sk, kp.pk, art) == k_real
    th = transcript(kp.pk, art.C_kyber, art.C_x25519, art.S_final, art.epsilon)
    # Best public substitutes for the missing X25519 secret.
    guesses = [art.C_x25519, _split(kp.pk)[1], b"\x00" * 32]
    broke = any(derive_keys(ss_pq, g, kp.pk, th)[0] == k_real for g in guesses)
    return Result("mlkem-layer-compromised", broke,
                  f"attacker knows SS_mlkem; X25519 still protects K: match={broke}")


# -- Attack 3: X25519 layer fully compromised (quantum attacker) --------------

@attack
def a03_x25519_layer_compromised() -> Result:
    """Simulate a quantum attacker that solves ECDLP: knows SS_x25519.

    The key must still hold thanks to ML-KEM-1024.
    """
    kp = keygen()
    art, k_real, _, ss_x = _encapsulate_exposed(kp.pk)
    th = transcript(kp.pk, art.C_kyber, art.C_x25519, art.S_final, art.epsilon)
    guesses = [H256(art.C_kyber), art.C_kyber[:32], b"\x00" * 32,
               _stub_secret(_split(kp.pk)[0], art.C_kyber)]
    broke = any(derive_keys(g, ss_x, kp.pk, th)[0] == k_real for g in guesses)
    return Result("x25519-layer-compromised", broke,
                  f"attacker knows SS_x25519; ML-KEM still protects K: match={broke}")


# -- Attack 4: tamper with the ciphertext and re-tag --------------------------

@attack
def a04_tamper_and_retag() -> Result:
    """Active attacker flips a ciphertext byte and recomputes the public tag C.

    C is unkeyed, so recomputing it is easy; Sigma must catch the change.
    """
    kp = keygen()
    art, _ = encapsulate(kp.pk)
    ct = bytearray(art.C_kyber)
    ct[0] ^= 0x01
    accepted = _accepted(kp.sk, kp.pk, _retag(art, C_kyber=bytes(ct)))
    return Result("tamper-ciphertext-and-retag", accepted,
                  "modified C_kyber with valid tag " +
                  ("ACCEPTED" if accepted else "rejected by Sigma"))


# -- Attack 5: mix-and-match two artifacts ------------------------------------

@attack
def a05_mix_and_match() -> Result:
    """Splice the ML-KEM part of one session with the X25519 part of another."""
    kp = keygen()
    a1, _ = encapsulate(kp.pk)
    a2, _ = encapsulate(kp.pk)
    spliced = _retag(a1, C_x25519=a2.C_x25519)
    accepted = _accepted(kp.sk, kp.pk, spliced)
    return Result("mix-and-match-sessions", accepted,
                  "spliced artifact " + ("ACCEPTED" if accepted else "rejected"))


# -- Attack 6: downgrade to the insecure stub ---------------------------------

@attack
def a06_backend_downgrade() -> Result:
    """Hide the real ML-KEM backend and check Aetherium refuses to start."""
    code = ("import sys; sys.modules['kem_kyber'] = None; "
            "sys.path.insert(0, %r); import kem" % ROOT)
    env = {k: v for k, v in os.environ.items() if k != "AETHERIUM_ALLOW_STUB"}
    r = subprocess.run([sys.executable, "-c", code], env=env,
                       capture_output=True, text=True)
    downgraded = r.returncode == 0
    return Result("silent-downgrade-to-stub", downgraded,
                  "import without ML-KEM " +
                  ("SUCCEEDED (silent downgrade)" if downgraded else "refused"))


# -- Observation: the automaton is public -------------------------------------

@attack
def i01_automaton_is_public() -> Result:
    kp = keygen()
    art, _ = encapsulate(kp.pk)
    same = E(kp.pk, art.epsilon) == art.S_final
    return Result("automaton-state-is-public", same,
                  f"S_final recomputable from (pk, epsilon): {same}. "
                  "Expected: E binds context, it is not a secret.",
                  is_attack=False)


# -- Observation: anyone can encapsulate to a public key ----------------------

@attack
def i02_no_sender_authentication() -> Result:
    kp = keygen()
    art, k_attacker = encapsulate(kp.pk)  # anyone can do this with pk
    ok = decapsulate(kp.sk, kp.pk, art) == k_attacker
    return Result("no-sender-authentication", ok,
                  "a third party can encapsulate to pk and share a key with the "
                  "recipient. Normal for a KEM; authenticity needs a signature.",
                  is_attack=False)


# -- Runner -------------------------------------------------------------------

def main() -> int:
    print("=" * 70)
    print("Aetherium Ultra KEM v2 — adversarial break harness")
    print("KEM backend:", kem.BACKEND)
    print("=" * 70)

    results = [fn() for fn in ATTACKS]

    width = max(len(r.name) for r in results)
    broken = 0
    for r in results:
        flag = ""
        if r.is_attack and r.broke_key:
            flag = "  <== SECURITY BREAK"
            broken += 1
        print(f"  {r.name.ljust(width)}  {r.verdict:>8}{flag}")
        print(f"      {r.detail}")

    print("=" * 70)
    if broken:
        print(f"RESULT: {broken} attack(s) BROKE the key.")
    else:
        print("RESULT: no attack broke the key in this configuration.")
    print("=" * 70)
    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
