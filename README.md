# Aetherium Ultra KEM

**Hybrid Post-Quantum Key Encapsulation Mechanism (v2)**

Aetherium derives a 512-bit session key from two **independent hardness assumptions**:

1. **ML-KEM-1024** — module lattices, post-quantum (NIST FIPS 203, Level 5)
2. **X25519** — elliptic-curve Diffie-Hellman (RFC 7748), classical

Both shared secrets are fused with HKDF-SHA3-512 over the full transcript. The
session key stays secret as long as **at least one** of the two layers is
unbroken: a quantum computer that breaks X25519 still faces ML-KEM, and a
future attack on ML-KEM still faces X25519.

A deterministic chaotic automaton `E(PK, ε)` binds the exchange to its public
context. It has **no secret input** and adds **no confidentiality**.

---

## Protocol Specification

### Parameters

| Parameter    | Value              | Description                               |
|------------- |------------------- |------------------------------------------ |
| Hash         | SHA3-512           | All hash operations (H)                   |
| KDF          | HKDF-SHA3-512      | Combiner                                  |
| Session key  | 512 bits           | `K_final`                                 |
| Confirmation | HMAC-SHA3-512      | `Σ`, keyed by `K_conf`                    |
| Rounds       | 64                 | Automaton iterations                      |
| PQ layer     | ML-KEM-1024        | pk 1568 B, sk 3168 B, ct 1568 B, ss 32 B  |
| Classic layer| X25519             | pk 32 B, sk 32 B, ss 32 B                 |

### Keys

```
pk = pk_mlkem ‖ pk_x25519        (1568 + 32 bytes)
sk = sk_mlkem ‖ sk_x25519        (3168 + 32 bytes)
```

### Artifact

`A = (C_kyber, C_x25519, S_final, Σ, C, ε)`

| Field      | Size (bytes) | Description                                          |
|----------- |------------- |----------------------------------------------------- |
| `C_kyber`  | 1568         | ML-KEM ciphertext                                    |
| `C_x25519` | 32           | Ephemeral X25519 public key                          |
| `S_final`  | 64           | Automaton final state (public)                       |
| `Σ`        | 64           | Key confirmation `HMAC(K_conf, th)`                  |
| `C`        | 32           | Corruption check `H(fields)[:32]` — unkeyed, not a MAC |
| `ε`        | 64           | Public seed                                          |

`‖` below denotes length-prefixed concatenation (4-byte big-endian length).

### Encapsulation

```
Encapsulate(PK) → (A, K_final)

1. ε ←$ {0,1}^512 ;  S_final = E(PK, ε)                     [public context]
2. (C_kyber, SS_pq) = ML-KEM.Enc(pk_mlkem)
3. e ←$ X25519 ;  C_x25519 = e·G ;  SS_x = e·pk_x25519
4. th = H(PK ‖ C_kyber ‖ C_x25519 ‖ S_final ‖ ε)
5. K_final ‖ K_conf = HKDF(ikm = SS_pq ‖ SS_x, salt = H(PK),
                          info = "aetherium-v2" ‖ th, len = 128)
6. Σ = HMAC-SHA3-512(K_conf, "aetherium-v2-confirm" ‖ th)
7. C = H(C_kyber ‖ C_x25519 ‖ S_final ‖ Σ ‖ ε)[:32]
8. Return A, K_final
```

### Decapsulation

```
Decapsulate(SK, PK, A) → K_final | ⊥

1. Check field lengths and C                        else ⊥  [corruption]
2. SS_pq = ML-KEM.Dec(sk_mlkem, C_kyber)                    [implicit rejection]
   SS_x  = sk_x25519 · C_x25519                     else ⊥  [invalid point]
3. S' = E(PK, ε) ;  S' = S_final ?                  else ⊥  [context mismatch]
4. th, K_final, K_conf as in encapsulation
5. Σ' = HMAC(K_conf, …th) ;  Σ' = Σ ?               else ⊥  [key confirmation]
6. Return K_final
```

All comparisons use `hmac.compare_digest`.

### Chaotic Automaton E(PK, ε)

```
S_0 = H(ε ‖ PK)
For r = 0 to 63:
    η_r = H(ε ‖ PK ‖ ⟨r⟩₄)
    h_r = H(S_r ‖ PK ‖ η_r ‖ ⟨r⟩₄)
    S_{r+1}[i] = S_r[i] ⊕ h_r[i]  if η_r[i] & 1  else S_r[i]
Return S_64
```

E is a pure function of public inputs: anyone can recompute `S_final`.

---

## Security Goals

| Property                  | Mechanism                                            |
|-------------------------- |----------------------------------------------------- |
| Post-quantum confidentiality | ML-KEM-1024                                       |
| Hybrid robustness         | `K_final` needs **both** `SS_pq` and `SS_x`          |
| Transcript binding        | `th` covers PK and every artifact field              |
| Tamper detection          | Keyed confirmation `Σ` (the unkeyed `C` only catches accidental corruption) |
| No silent downgrade       | `kem.py` refuses to run without ML-KEM               |
| Timing                    | `hmac.compare_digest` for every comparison           |

**Not provided:** sender authentication. Anyone can encapsulate to a public
key; authenticity requires a signature (e.g. ML-DSA) on top.

**Status:** reference implementation, no formal proof, no third-party audit.
Do not use in production before an expert review.

See [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) for the v1 breaks and how v2 fixes them.

---

## Project Structure

```
aetherium/
├── aetherium.py       # Hybrid KEM: keygen, encapsulate, decapsulate
├── automaton.py        # Deterministic chaotic automaton E(PK, ε)
├── utils.py            # Cryptographic primitives (H512, HKDF, xor, compare)
├── kem.py              # KEM dispatcher (ML-KEM, fail-closed)
├── kem_kyber.py        # ML-KEM-1024 wrapper (pqcrypto)
├── kem_stub.py         # INSECURE stub, tests only (AETHERIUM_ALLOW_STUB=1)
├── attacks/
│   └── break_key.py    # Adversarial break harness
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
pip install -r requirements.txt
```

### Run tests and the break harness

```bash
python -m pytest tests/ -v
python attacks/break_key.py
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

Aetherium requires **ML-KEM-1024** through `pqcrypto`. If it is missing,
`kem.py` raises `ImportError` instead of falling back.

`kem_stub.py` is an insecure test double: its ciphertext can be opened with
the public key alone. It is loaded only when `AETHERIUM_ALLOW_STUB=1` is set,
and emits a `RuntimeWarning`.

---

## Status

- [x] Reference Python implementation
- [x] Hybrid ML-KEM-1024 + X25519 with HKDF combiner
- [x] Transcript binding and keyed key confirmation
- [x] Fail-closed backend selection
- [x] Constant-time comparisons
- [x] Unit tests on the real ML-KEM-1024 backend
- [x] Adversarial break harness
- [ ] Sender authentication (signature)
- [ ] Formal security proof
- [ ] Third-party audit

---

## License

Apache 2.0. See [LICENSE](LICENSE).
