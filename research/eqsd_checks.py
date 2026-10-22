#!/usr/bin/env python3
"""Exact checks for the EqSD model (stdlib only, no estimates).

Verifies the algebraic facts stated in research/EqSD.md:
  - q = 28657 is prime and is the Fibonacci number F_23
  - q = 2 (mod 5), so 5 is not a square mod q and X^2 - X - 1 is
    irreducible over F_q: R_q = F_q[X]/(X^2 - X - 1) is the field F_{q^2}
  - the multiplication matrix of a = a0 + a1*X in the basis (1, X)
  - counting bounds: key uniqueness and absence of short collisions for
    A_hat = [A | I], A uniform over R_q^(k x k)
"""
import random
from math import log2

Q = 28657
K = 704                          # dimension over R_q
N_HAT = 2 * K                    # integer dimension: y = A s + e, s, e in {-1,0,1}^N_HAT


def is_prime(p: int) -> bool:
    if p < 2:
        return False
    i = 2
    while i * i <= p:
        if p % i == 0:
            return False
        i += 1
    return True


def fib(k: int) -> int:
    a, b = 0, 1
    for _ in range(k):
        a, b = b, a + b
    return a


def mul(a, b, q=Q):
    """(a0 + a1 X)(b0 + b1 X) mod (X^2 - X - 1, q), using X^2 = X + 1."""
    a0, a1 = a
    b0, b1 = b
    return ((a0 * b0 + a1 * b1) % q, (a0 * b1 + a1 * b0 + a1 * b1) % q)


def mat(a, q=Q):
    """Matrix of multiplication by a acting on column vectors (b0, b1)."""
    a0, a1 = a
    return ((a0 % q, a1 % q), (a1 % q, (a0 + a1) % q))


def main() -> None:
    assert is_prime(Q), "q must be prime"
    assert fib(23) == Q, "q must be F_23"
    assert Q % 5 == 2, "q must be 2 mod 5"
    # Euler's criterion: 5 is a non-residue iff 5^((q-1)/2) = -1 mod q
    assert pow(5, (Q - 1) // 2, Q) == Q - 1, "5 must be a non-residue mod q"
    # Hence X^2 - X - 1 (discriminant 5) has no root in F_q: R_q is a field.
    assert all((x * x - x - 1) % Q for x in range(Q)), "X^2-X-1 must have no root"

    rng = random.Random(1)
    for _ in range(1000):
        a = (rng.randrange(Q), rng.randrange(Q))
        b = (rng.randrange(Q), rng.randrange(Q))
        m = mat(a)
        mb = ((m[0][0] * b[0] + m[0][1] * b[1]) % Q, (m[1][0] * b[0] + m[1][1] * b[1]) % Q)
        assert mb == mul(a, b), "multiplication matrix mismatch"
    assert mat((0, 1)) == ((0, 1), (1, 1)), "multiplication by X is the Fibonacci matrix"

    # Every nonzero element is invertible (field): a^(q^2 - 2) * a = 1
    def power(a, e):
        r = (1, 0)
        while e:
            if e & 1:
                r = mul(r, a)
            a = mul(a, a)
            e >>= 1
        return r
    for _ in range(200):
        a = (rng.randrange(Q), rng.randrange(Q))
        if a != (0, 0):
            assert mul(a, power(a, Q * Q - 2)) == (1, 0), "nonzero element not invertible"

    # A_hat = [A | I], z = (z1, z2) != 0 with |z_i| < q. If z1 != 0, A z1 is
    # uniform over R_q^K (R_q is a field): Pr[A_hat z = 0] = q^(-N_HAT).
    # If z1 = 0, A_hat z = z2 != 0. Union bounds:
    uniq = 2 * N_HAT * log2(3) - N_HAT * log2(Q)
    coll = 2 * N_HAT * log2(5) - N_HAT * log2(Q)
    print(f"q = {Q} = F_23, prime, q mod 5 = {Q % 5}, R_q = F_q^2: OK")
    print("multiplication matrix and Fibonacci matrix: OK")
    print(f"ring dim k = {K}  <->  integer dim {N_HAT}")
    print(f"E[# other ternary keys with the same y] <= 2^{uniq:.1f}")
    print(f"Pr[short collision, l_inf <= 2] <= 2^{coll:.1f}")
    print(f"public key: {N_HAT} x 15 bits + 32-byte seed = {N_HAT * 15 // 8 + 32} bytes")
    print(f"expanded secret (s, e), 2-bit coding: {2 * N_HAT * 2 // 8} bytes")


if __name__ == "__main__":
    main()
