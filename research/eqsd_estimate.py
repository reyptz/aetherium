#!/usr/bin/env python3
"""Reproducible lattice-estimator runs for EqSD (see research/EqSD.md).

Requirements (not needed by the rest of the repository):
    pip install passagemath-standard          # SageMath via pip (tested 10.8.13)
    git clone https://github.com/malb/lattice-estimator
    git -C lattice-estimator checkout e4333d9bf9ef42fd8a29651b0c559fba7ce0d834

Run with the checkout on the import path:
    PYTHONPATH=lattice-estimator python research/eqsd_estimate.py

The script first reproduces published levels for ML-KEM-1024 and ML-DSA-87
(same estimator, same mode). If those do not match, do not trust the EqSD
numbers either.

The collision is estimated three ways (rough core-SVP, SIS.lattice with
ADPS16 core-SVP, SIS.lattice with the default cost model) to show how much
the figure depends on the model. Ring structure (degree 2) is ignored: the
lattice is Lambda_perp of the expanded matrix (dimension 4484, determinant
q^644, see rank_check), assumed to behave like a random lattice.
"""
import random

from estimator import LWE, SIS, ND, RC, schemes
from sage.all import GF, matrix, oo

Q = 28657
N_HAT, M_HAT = 644, 4484


def calibrate():
    print("== Calibration ==")
    print("ML-KEM-1024 (published core-SVP ~ 2^256):")
    LWE.estimate.rough(schemes.Kyber1024)
    print("ML-DSA-87 MSIS strong unforgeability (published core-SVP ~ 2^252):")
    SIS.estimate.rough(schemes.Dilithium5_MSIS_StrUnf)


def collision():
    # x != x' ternary with A x = A x'  =>  z = x - x' in {-2..2}^M_HAT, A z = 0
    # norm=oo: the estimator handles l_inf natively (no conversion to l_2).
    p = SIS.Parameters(n=N_HAT, q=Q, length_bound=2, m=M_HAT, norm=oo, tag="EqSD-coll")
    print("\n== EqSD collision: SIS, l_inf bound 2 ==")
    print("-- SIS.estimate.rough (core-SVP):")
    SIS.estimate.rough(p)
    print("-- SIS.lattice, RC.ADPS16 (core-SVP):")
    print(SIS.lattice(p, red_cost_model=RC.ADPS16))
    print("-- SIS.lattice, default cost model:")
    print(SIS.lattice(p))


def rank_check():
    # Expanded matrix of a uniform A over R_q: blocks M(a) = [[a0, a1], [a1, a0 + a1]].
    print("\n== Rank of an expanded block matrix (seeded, uniform over R_q) ==")
    rnd = random.Random(1)
    rows = []
    for _ in range(N_HAT // 2):
        r0, r1 = [], []
        for _ in range(M_HAT // 2):
            a0, a1 = rnd.randrange(Q), rnd.randrange(Q)
            r0 += [a0, a1]
            r1 += [a1, (a0 + a1) % Q]
        rows += [r0, r1]
    a_hat = matrix(GF(Q), rows)
    print("shape", a_hat.dimensions(), "rank", a_hat.rank())


def key_recovery():
    # y = A x, x ternary. Normal form with A = [A1 | A2], A1 invertible:
    # A1^-1 y = x1 + (A1^-1 A2) x2  ->  LWE, secret x2 (M_HAT - N_HAT coords),
    # N_HAT samples, error x1. Exact rewriting, not a reduction.
    print("\n== EqSD key recovery: LWE normal form ==")
    p = LWE.Parameters(n=M_HAT - N_HAT, q=Q, Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1),
                       m=N_HAT, tag="EqSD-KR")
    print(p)
    print("rough:", LWE.estimate.rough(p))
    print("primal uSVP (ADPS16):", LWE.primal_usvp(p, red_cost_model=RC.ADPS16))


if __name__ == "__main__":
    calibrate()
    collision()
    rank_check()
    key_recovery()
