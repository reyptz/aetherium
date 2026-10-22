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

| # | Finding (v1) | Severity | Status in v2 |
|---|---------|----------|--------|
| 1 | Total session-key recovery from public data | **Critical** | Fixed: fail-closed backend + X25519 layer |
| 2 | Chaos layer provides zero confidentiality | **High** (design) | Fixed: X25519 is the second secret; `E` documented as public |
| 3 | KEM shared secret recoverable from `(pk, ct)` | **Critical** | Fixed: stub only on explicit opt-in, real ML-KEM by default |
| 4 | Outsider can encapsulate to `pk` | Reclassified: not a break | Documented as a limit (no sender authentication) |
| 5 | Artifact tamper detection | — (holds) | Strengthened: keyed `Σ` replaces unkeyed binding |

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

## Finding 4 — Artifact forgery for a chosen key (reclassified)

Because the attacker controls `k_seed` (stub), they can pick any `k_seed`,
build a fully self-consistent artifact (valid tag `C`, valid binding proof `Σ`),
and the honest recipient accepts it and derives a key the attacker already
knows. The harness builds such an artifact and confirms the recipient's
`K_final` equals the attacker's.

**Correction:** this is not specific to the stub. With a real ML-KEM backend,
anyone can also call `encapsulate(pk)` and share a key with the recipient.
That is how every KEM works. The real issue was the README's claim of
protection against "key-substitution", which a KEM without a sender signature
cannot provide. v2 documents this as a limit instead of claiming it.

## Finding 5 — Tamper detection holds (defense confirmed)

Flipping a byte of `C_kyber` while leaving the tag stale is correctly rejected
(`Artifact integrity check failed`). The truncated-SHA3-512 tag and
`hmac.compare_digest` comparisons behave as intended. Note this protects
**integrity**, not confidentiality, and does not mitigate Findings 1–4.

---

## Bottom line (v1)

The breaks came from (a) a zero-confidentiality stub that the dispatcher
installed silently (regression introduced in commit `fbd0f42`; the first
commit `ca459f5` was fail-closed), and (b) a design overclaim that the public
chaos layer contributed secrecy.

---

## v2 — corrected logic

| Change | Why |
|--------|-----|
| `kem.py` fails closed; stub only with `AETHERIUM_ALLOW_STUB=1` | No silent downgrade (findings 1, 3) |
| `kem_kyber.py` supports `pqcrypto` 1.0 (`ml_kem_1024`) | The real backend was never loaded before |
| Second layer is **X25519**, a real secret | Independent hardness assumption (finding 2) |
| `K_final ‖ K_conf = HKDF(SS_mlkem ‖ SS_x25519, info = label ‖ th)` | Key needs both secrets, bound to the full transcript |
| `Σ = HMAC(K_conf, th)` | Keyed confirmation; the old `Σ = H(K ‖ …)` published a hash of the key |
| Length-prefixed encodings | Unambiguous transcript |
| `E(pk, ε)` kept, documented as public context | Preserves the design, no false claim |

Harness results on v2 (`python attacks/break_key.py`):

| Attack | ML-KEM backend | Stub (opt-in) |
|--------|----------------|---------------|
| Public-only key recovery | resisted | resisted (X25519 holds) |
| ML-KEM layer compromised | resisted | resisted |
| X25519 layer compromised | resisted | **BROKEN** (both layers gone, expected) |
| Tamper + recompute tag | resisted | resisted |
| Mix-and-match sessions | resisted | resisted |
| Silent downgrade to stub | resisted | resisted |

Remaining limits: no sender authentication, no formal proof, no audit.
