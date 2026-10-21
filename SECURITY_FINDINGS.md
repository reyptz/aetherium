# Aetherium Ultra KEM — Security Findings (self-audit)

Adversarial review of our own hybrid KEM. Task: generate a key, then do
everything to break it. Reproduce with:

```bash
python attacks/break_key.py
```

All attacks use only data an adversary legitimately sees — the public key `pk`
and the transmitted artifact `A = (C_kyber, S_final, Σ, C, ε)` — unless a step
is explicitly labelled as using a secret. The harness exits non-zero if any key
break succeeds.

## Summary

| # | Finding | Severity | Config |
|---|---------|----------|--------|
| 1 | Total session-key recovery from public data | **Critical** | stub backend (default) |
| 2 | Chaos layer provides zero confidentiality | **High** (design) | both backends |
| 3 | KEM shared secret recoverable from `(pk, ct)` | **Critical** | stub backend |
| 4 | Artifact forgery for an attacker-chosen key | **Critical** | stub backend |
| 5 | Artifact tamper detection | — (holds) | both backends |

The default configuration ships the stub whenever `pqcrypto` is not installed
(`kem.py` falls back silently). In that configuration the key offers **no
confidentiality at all**.

---

## Finding 1 — Total key recovery from the public artifact (Critical)

With the stub backend, `K_final` is a deterministic function of values that are
all public, so an eavesdropper reconstructs the full 512-bit session key:

```
mask    = SHAKE256(pk || "kem-mask")          # pk is public
k_seed  = C_kyber XOR mask                     # C_kyber is public
SS      = H256(k_seed || pk)                   # KEM shared secret recovered
S_final = E(pk, ε)                             # pk, ε public -> recomputable
K_final = HKDF(H512(pk), SS || S_final, "aetherium-v1")
```

The harness confirms `K_final(attacker) == K_final(real)` using only `pk` and
the artifact. No secret key is touched.

**Root cause:** `kem_stub.enc` derives its one-time mask solely from the public
`pk`. The mask is therefore not secret, so XOR-ing it back off `C_kyber` reveals
`k_seed` and hence the shared secret.

**Fix:** never ship the stub as a confidentiality-bearing backend. Options:
- Make `kem.py` **fail closed**: raise unless a real ML-KEM backend
  (`pqcrypto` Kyber-1024) is importable, instead of silently substituting the
  stub. The stub stays available only under an explicit opt-in flag for tests.
- Label the stub in its own module docstring as *non-confidential test double*
  (it already warns it is "not post-quantum" — that undersells it: it provides
  **no** security).

## Finding 2 — The chaos layer adds no confidentiality (High, design)

The README's headline claim is: *"An attacker must break both layers to recover
the key."* This is false. `S_final = E(pk, ε)` is a **pure public function** of
two public inputs, so any observer recomputes it bit-for-bit (harness confirms
`match=True`). The second layer contributes only to the integrity binding `Σ`;
it adds **zero** secrecy.

Consequently, even with a perfect ML-KEM backend, the confidentiality of
`K_final` rests entirely on the KEM. The scheme is `HKDF(KEM_secret ||
public_nonce)`, i.e. the KEM alone, dressed up.

**Fix:** either drop the "two independent layers" security claim from the
README and position `E` honestly as a KDF-domain-separator / integrity input,
or redesign so the second layer consumes a genuine secret (e.g. mix a
PRF keyed by the KEM secret, not a function of public inputs only).

## Finding 3 — KEM shared-secret recovery (Critical)

Same root cause as #1, isolated to the KEM: given `(pk, ct)`, the harness
recovers the stub's shared secret directly. This is the primitive break that
Findings 1 and 4 build on.

## Finding 4 — Artifact forgery for a chosen key (Critical)

Because the attacker controls `k_seed` (stub), they can pick any `k_seed`,
build a fully self-consistent artifact (valid tag `C`, valid binding proof `Σ`),
and the honest recipient accepts it and derives a key the attacker already
knows. The harness builds such an artifact and confirms the recipient's
`K_final` equals the attacker's. This defeats key-commitment / authenticity for
the stub configuration.

## Finding 5 — Tamper detection holds (defense confirmed)

Flipping a byte of `C_kyber` while leaving the tag stale is correctly rejected
(`Artifact integrity check failed`). The truncated-SHA3-512 tag and
`hmac.compare_digest` comparisons behave as intended. Note this protects
**integrity**, not confidentiality, and does not mitigate Findings 1–4.

---

## Bottom line

The *protocol structure* (HKDF fusion, binding proof, constant-time checks,
tamper tag) is sound. The breaks come from (a) the stub being a
zero-confidentiality placeholder that the dispatcher installs silently, and
(b) a design overclaim that the public chaos layer contributes secrecy. Fixing
the dispatcher to fail closed and correcting the README claim removes the
critical findings; real security then reduces exactly to ML-KEM-1024, as
intended.
