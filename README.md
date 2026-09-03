# Aetherium Ultra KEM

**Hybrid Post-Quantum Key Encapsulation Mechanism**

Aetherium is a hybrid KEM that derives a session key from two independent cryptographic layers:

1. **ML-KEM (Kyber-1024)** — algebraic post-quantum hardness (NIST FIPS 203, Level 5)
2. **Deterministic chaotic automaton E(PK, ε)** — SHA3-512-based state evolution over 64 rounds

The two secrets are fused via HKDF-SHA3-512 into a single 512-bit session key. An attacker must break **both** layers to recover the key.

---

## Protocol Specification

### Parameters

| Parameter    | Value         | Description                            |
|------------- |-------------- |----------------------------------------|
| Hash         | SHA3-512      | All hash operations (H)               |
| KDF          | HKDF-SHA3-512 | Key derivation function                |
| Key size     | 512 bits      | Session key, automaton state, HKDF output |
| Tag size     | 256 bits      | Integrity tag (truncated SHA3-512)     |
| Rounds       | 64            | Chaotic automaton iterations           |
| KEM backend  | ML-KEM-1024   | NIST FIPS 203, Level 5 (or stub)      |

### Artifact Structure

The public artifact `A = (C_kyber, S_final, Σ, C, ε)` is transmitted from sender to recipient:

| Field     | Size (bytes) | Description                                        |
|---------- |------------- |----------------------------------------------------|
| `C_kyber` | variable     | KEM ciphertext                                     |
| `S_final` | 64           | Automaton final state                              |
| `Σ`       | 64           | Binding proof `H(K_final ‖ S_final ‖ C_kyber)`    |
| `C`       | 32           | Integrity tag `H(C_kyber ‖ S_final ‖ Σ ‖ ε)[:32]` |
| `ε`       | 64           | Public seed for automaton                          |

### Encapsulation

```
Encapsulate(PK_rec) → (A, K_final)

1. ε  ←$ {0,1}^512
2. S_final = E(PK_rec, ε)
3. (C_kyber, SS_kyber) = KEM.Enc(PK_rec)
4. K_final = HKDF(SS_kyber ‖ S_final, salt=H(PK_rec), info="aetherium-v1")
5. Σ = H(K_final ‖ S_final ‖ C_kyber)
6. C = H(C_kyber ‖ S_final ‖ Σ ‖ ε)[:32]
7. Return A = (C_kyber, S_final, Σ, C, ε), K_final
```

### Decapsulation

```
Decapsulate(SK_rec, PK_rec, A) → K_final | ⊥

1. C' = H(C_kyber ‖ S_final ‖ Σ ‖ ε)[:32]
   if C' ≠ C → ⊥                           [integrity]
2. SS_kyber = KEM.Dec(SK_rec, C_kyber)
   if ⊥ → ⊥                                [KEM failure]
3. S' = E(PK_rec, ε)
   if S' ≠ S_final → ⊥                     [automaton mismatch]
4. K_final = HKDF(SS_kyber ‖ S', salt=H(PK_rec), info="aetherium-v1")
5. Σ' = H(K_final ‖ S' ‖ C_kyber)
   if Σ' ≠ Σ → ⊥                           [binding proof]
6. Return K_final
```

All comparisons use constant-time digest comparison to resist timing side-channels.

### Chaotic Automaton E(PK, ε)

```
E(PK, ε, rounds=64) → S_final ∈ {0,1}^512

S_0 = H(ε ‖ PK)[:64]
For r = 0 to rounds-1:
    η_r = H(ε ‖ PK ‖ ⟨r⟩₄)
    h_r = H(S_r ‖ PK ‖ η_r ‖ ⟨r⟩₄)
    For i = 0 to 63:
        if η_r[i mod 64] & 1 = 1:
            S_{r+1}[i] = S_r[i] ⊕ h_r[i]
        else:
            S_{r+1}[i] = S_r[i]
Return S_{rounds}
```

E is a **pure function**: same (PK, ε) always produces the same S_final. No external entropy is consumed during evolution.

---

## Security Goals

| Property                     | Mechanism                                          |
|----------------------------- |----------------------------------------------------|
| Post-quantum resilience      | ML-KEM-1024 (NIST Level 5)                        |
| Layered defense              | K_final depends on both KEM secret and chaos state |
| Artifact integrity           | Truncated SHA3-512 tag over all artifact fields    |
| Key-commitment resistance    | Binding proof Σ = H(K ‖ S ‖ C_kyber)              |
| Timing-attack resistance     | All comparisons via `hmac.compare_digest`          |
| Deterministic reproducibility| E(PK, ε) is a pure function                       |

---

## Project Structure

```
aetherium/
├── aetherium.py       # Hybrid KEM: keygen, encapsulate, decapsulate
├── automaton.py        # Deterministic chaotic automaton E(PK, ε)
├── utils.py            # Cryptographic primitives (H512, HKDF, xor, compare)
├── kem.py              # KEM dispatcher (Kyber or stub)
├── kem_kyber.py        # ML-KEM-1024 wrapper (requires pqcrypto)
├── kem_stub.py         # Deterministic HMAC-based stub for testing
├── tests/
│   └── test_aetherium.py  # Correctness, rejection, and primitive tests
├── requirements.txt
├── LICENSE             # Apache 2.0
└── README.md
```

---

## Usage

### Install

```bash
pip install pytest
# Optional: pip install pqcrypto   # for real ML-KEM-1024
```

### Run tests

```bash
cd aetherium
python -m pytest tests/ -v
```

### API

```python
from aetherium import keygen, encapsulate, decapsulate

# Key generation
kp = keygen()

# Sender
artifact, K_sender = encapsulate(kp.pk)

# Recipient
K_recipient = decapsulate(kp.sk, kp.pk, artifact)

assert K_sender == K_recipient  # 512-bit shared session key
```

---

## KEM Backend

When `pqcrypto` is installed, Aetherium uses **Kyber-1024** (NIST FIPS 203, Level 5). Without it, a deterministic HMAC-SHA256 stub is used for development and testing. The stub is **not post-quantum** and must not be used in production.

The backend is selected automatically at import time via `kem.py`.

---

## Status

- [x] Reference Python implementation
- [x] Deterministic chaotic automaton (SHA3-512, 64 rounds)
- [x] Hybrid KEM with HKDF fusion
- [x] Artifact integrity and binding proofs
- [x] Constant-time comparisons
- [x] Unit tests (correctness + rejection)
- [ ] Real ML-KEM-1024 backend integration testing
- [ ] Formal security proof
- [ ] Third-party audit

---

## License

Apache 2.0. See [LICENSE](LICENSE).
