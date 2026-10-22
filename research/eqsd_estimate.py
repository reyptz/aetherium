#!/usr/bin/env python3
"""Reproducible lattice-estimator runs for EqSD (see research/EqSD.md).

Requirements (not needed by the rest of the repository):
    pip install passagemath-standard          # SageMath via pip (tested 10.8.13)
    git clone https://github.com/malb/lattice-estimator
    git -C lattice-estimator checkout e4333d9bf9ef42fd8a29651b0c559fba7ce0d834

Run with the checkout on the import path:
    PYTHONPATH=lattice-estimator python research/eqsd_estimate.py

Key recovery for y = A s + e (s, e ternary, n_hat samples) is estimated with
the rough (core-SVP) and the full default models, next to ML-KEM-1024 with
the same calls, so that the two can be compared. Ring structure (degree 2)
is ignored: the lattice is assumed to behave like a random lattice.
Collisions are excluded statistically (research/eqsd_checks.py) and are not
estimated.
"""
from estimator import LWE, ND, schemes

Q = 28657
N_HAT = 1408
DENY = ("arora-gb", "bkw")   # need far more than N_HAT samples


def eqsd():
    return LWE.Parameters(n=N_HAT, q=Q, Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1),
                          m=N_HAT, tag="EqSD-1408")


def main():
    for name, p in (("EqSD-1408", eqsd()), ("ML-KEM-1024", schemes.Kyber1024)):
        print(f"\n== {name}: rough (core-SVP) ==")
        LWE.estimate.rough(p)
        print(f"== {name}: full (default cost models) ==")
        LWE.estimate(p, deny_list=DENY)


if __name__ == "__main__":
    main()
