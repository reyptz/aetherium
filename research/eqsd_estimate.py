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

Mode: `rough` (core-SVP style, ADPS16 cost model: 2^(0.292*beta) classical).
Ring structure (degree 2) is ignored: instances are estimated as
unstructured SIS/LWE of the expanded integer dimensions.
"""
from estimator import LWE, SIS, ND, RC, schemes
from sage.all import oo

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
    print("\n== EqSD collision: SIS, l_inf bound 2 ==")
    p = SIS.Parameters(n=N_HAT, q=Q, length_bound=2, m=M_HAT, norm=oo, tag="EqSD-coll")
    SIS.estimate.rough(p)


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
    key_recovery()
