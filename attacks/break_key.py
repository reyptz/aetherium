#!/usr/bin/env python3
"""
Aetherium Ultra KEM — adversarial break harness.

Self-audit of the Aetherium hybrid KEM. The goal is literally "do everything
to break the key": generate a key with the scheme, then run a battery of
attacks against it and report, for each, whether the session key K_final (or a
shared secret it depends on) was recovered or forged.

Run:
    python attacks/break_key.py

Every attack uses ONLY data an adversary could legitimately observe
(public key + the transmitted artifact), unless a step is explicitly labelled
as using a secret. Each attack returns a Result; the harness prints a summary
and exits non-zero if any attack marked `must_fail_for_security` actually
broke the key.

These are tests against our OWN implementation, run locally, to find
weaknesses before anyone else does. Nothing here targets a third party.
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass, field
from typing import Callable, List, Optional

# Allow running from repo root or from inside attacks/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import kem  # noqa: E402
from aetherium import keygen, encapsulate, decapsulate, Artifact  # noqa: E402
from automaton import E  # noqa: E402
from utils import H512, H256, hkdf  # noqa: E402


# -- Result bookkeeping -------------------------------------------------------

@dataclass
class Result:
    name: str
    broke_key: bool          # did the attack recover/forge the key?
    detail: str
    # True when a successful break means the scheme is insecure (the attack
    # SHOULD fail). False for attacks that are expected to be blocked and are
    # only here to confirm a defense holds.
    must_fail_for_security: bool = True

    @property
    def verdict(self) -> str:
        if self.must_fail_for_security:
            return "BROKEN" if self.broke_key else "resisted"
        return "recovered" if self.broke_key else "blocked (good)"


ATTACKS: List[Callable[[], Result]] = []


def attack(fn: Callable[[], Result]) -> Callable[[], Result]:
    ATTACKS.append(fn)
    return fn


# -- Attack 1: full key recovery from public data (stub KEM) ------------------

@attack
def a01_full_key_recovery_from_public_artifact() -> Result:
    """Recover K_final using ONLY pk + artifact, no secret key.

    Root cause chain (stub backend):
      * kem_stub mask = SHAKE256(pk || "kem-mask") depends only on the PUBLIC
        pk, so k_seed = C_kyber XOR mask is recoverable by anyone, and the
        shared secret SS = H256(k_seed || pk) with it.
      * The chaos layer S_final = E(pk, epsilon) is a pure function of the
        PUBLIC pk and the PUBLIC epsilon, so it is recomputable by anyone.
      * K_final = HKDF(H512(pk), SS || S_final) therefore depends on no secret
        at all once the KEM secret leaks.
    """
    kp = keygen()
    artifact, K_real = encapsulate(kp.pk)

    pk = kp.pk  # public

    # Break the stub KEM shared secret from public values only.
    mask = hashlib.shake_256(pk + b"kem-mask").digest(len(artifact.C_kyber))
    k_seed = bytes(x ^ y for x, y in zip(artifact.C_kyber, mask))
    ss = H256(k_seed + pk)

    # Recompute the "chaos" layer (public pure function).
    s_final = E(pk, artifact.epsilon)

    k_attack = hkdf(H512(pk), ss + s_final, info=b"aetherium-v1", length=64)
    broke = (k_attack == K_real)
    backend = kem.impl.__name__
    return Result(
        "full-key-recovery-from-public-artifact",
        broke,
        f"backend={backend}; K_final reconstructed from pk+artifact only "
        f"(match={broke})",
    )


# -- Attack 2: the chaos layer provides zero confidentiality ------------------

@attack
def a02_chaos_layer_is_public() -> Result:
    """Show S_final leaks nothing: it is E(pk, epsilon), both public.

    The README claims an attacker "must break BOTH layers". This attack shows
    the chaos layer carries no secret, so breaking the KEM alone is enough —
    the layers are NOT independent sources of secrecy.
    """
    kp = keygen()
    artifact, _ = encapsulate(kp.pk)
    # An attacker recomputes the automaton's final state bit-for-bit.
    recomputed = E(kp.pk, artifact.epsilon)
    broke = (recomputed == artifact.S_final)
    return Result(
        "chaos-layer-adds-no-secrecy",
        broke,
        f"S_final recomputed from public (pk, epsilon): match={broke}. "
        "Second layer contributes integrity binding only, not confidentiality.",
    )


# -- Attack 3: shared-secret recovery against the KEM in isolation ------------

@attack
def a03_kem_shared_secret_recovery() -> Result:
    """Recover the KEM shared secret from (pk, ciphertext) without sk."""
    pk, sk = kem.keygen()
    ct, ss_real = kem.enc(pk)
    backend = kem.impl.__name__
    if backend != "kem_stub":
        # Against a real KEM (Kyber) this attack is not expected to work; we
        # report resisted rather than claiming a break we did not achieve.
        return Result(
            "kem-shared-secret-recovery",
            False,
            f"backend={backend}: no public-only recovery attempted/available.",
        )
    mask = hashlib.shake_256(pk + b"kem-mask").digest(len(ct))
    k_seed = bytes(x ^ y for x, y in zip(ct, mask))
    ss_attack = H256(k_seed + pk)
    broke = (ss_attack == ss_real)
    return Result(
        "kem-shared-secret-recovery",
        broke,
        f"backend={backend}: SS recovered from (pk, ct) only, match={broke}.",
    )


# -- Attack 4: forge a valid artifact for a chosen key (key-commitment) -------

@attack
def a04_forge_artifact_for_chosen_key() -> Result:
    """Given only pk, forge an artifact that decapsulates to a key we choose.

    With the stub broken, an attacker controls k_seed, hence SS, hence the
    whole derivation, and can emit an artifact that the honest recipient will
    accept and whose K_final the attacker already knows.
    """
    kp = keygen()
    pk = kp.pk
    backend = kem.impl.__name__
    if backend != "kem_stub":
        return Result(
            "forge-artifact-for-chosen-key",
            False,
            f"backend={backend}: forgery requires KEM control, not available.",
            must_fail_for_security=True,
        )

    # Attacker picks k_seed freely and builds a self-consistent artifact.
    chosen_seed = b"\xAA" * 64
    mask = hashlib.shake_256(pk + b"kem-mask").digest(len(chosen_seed))
    c_kyber = bytes(x ^ y for x, y in zip(chosen_seed, mask))
    ss = H256(chosen_seed + pk)

    epsilon = os.urandom(64)
    s_final = E(pk, epsilon)
    k_final = hkdf(H512(pk), ss + s_final, info=b"aetherium-v1", length=64)
    sigma = H512(k_final + s_final + c_kyber)
    tag = H512(c_kyber + s_final + sigma + epsilon)[:32]

    forged = Artifact(C_kyber=c_kyber, S_final=s_final, Sigma=sigma, C=tag,
                      epsilon=epsilon)

    # Honest recipient decapsulates; does it accept and land on our key?
    k_recipient = decapsulate(kp.sk, pk, forged)
    broke = (k_recipient == k_final)
    return Result(
        "forge-artifact-for-chosen-key",
        broke,
        f"backend={backend}: recipient accepted forged artifact and derived "
        f"the attacker-known key (match={broke}).",
    )


# -- Attack 5: tamper detection must hold (defense confirmation) --------------

@attack
def a05_tamper_is_rejected() -> Result:
    """Flip a byte of the ciphertext and confirm decapsulation rejects it.

    This one is expected to be BLOCKED; it confirms the integrity tag works.
    """
    kp = keygen()
    artifact, _ = encapsulate(kp.pk)
    bad_ct = bytearray(artifact.C_kyber)
    bad_ct[0] ^= 0x01
    tampered = Artifact(
        C_kyber=bytes(bad_ct),
        S_final=artifact.S_final,
        Sigma=artifact.Sigma,
        C=artifact.C,            # stale tag -> must be caught
        epsilon=artifact.epsilon,
    )
    accepted = True
    try:
        decapsulate(kp.sk, kp.pk, tampered)
    except ValueError:
        accepted = False
    # broke_key == attack succeeded == tamper accepted
    return Result(
        "tamper-rejection",
        accepted,
        "flipped ciphertext byte " + ("ACCEPTED (bad)" if accepted
                                      else "rejected (good)"),
        must_fail_for_security=True,
    )


# -- Runner -------------------------------------------------------------------

def main() -> int:
    print("=" * 70)
    print("Aetherium Ultra KEM — adversarial break harness")
    print("KEM backend:", kem.impl.__name__)
    print("=" * 70)

    results = [fn() for fn in ATTACKS]

    width = max(len(r.name) for r in results)
    insecure = 0
    for r in results:
        flag = ""
        if r.must_fail_for_security and r.broke_key:
            flag = "  <== SECURITY BREAK"
            insecure += 1
        print(f"  {r.name.ljust(width)}  {r.verdict:>16}{flag}")
        print(f"      {r.detail}")

    print("=" * 70)
    if insecure:
        print(f"RESULT: {insecure} attack(s) BROKE the key. Scheme is insecure "
              "in this configuration.")
    else:
        print("RESULT: no attack broke the key in this configuration.")
    print("=" * 70)
    return 1 if insecure else 0


if __name__ == "__main__":
    raise SystemExit(main())
