# Aetherium Ultra KEM

## Hybrid Post-Quantum KEM + Deterministic Chaotic Automaton

Aetherium is a hybrid key encapsulation mechanism (KEM) designed to resist long-term quantum threats by combining:

- a post-quantum algebraic KEM layer,
- a deterministic chaotic automaton layer.

The project is a research-oriented reference implementation in Python.

---

## English / Français

### What this project is

Aetherium is a hybrid security architecture where the final session key is derived from:

1. a post-quantum shared secret from a KEM,
2. a deterministic chaotic state computed from the recipient public key and a public seed.

This creates a layered defense: an attacker must break both the underlying KEM and the deterministic chaos function to recover the session key.

### Ce qu'est le projet

Aetherium est une architecture de sécurité hybride dans laquelle la clé de session finale est dérivée de :

1. un secret partagé post-quantique issu d'un KEM,
2. un état chaotique déterministe calculé à partir de la clé publique destinataire et d'une graine publique.

Cela crée une défense en profondeur : un attaquant doit casser à la fois le KEM et la fonction chaotique déterministe pour retrouver la clé de session.

---

## Key Concepts / Concepts clés

### Hybrid architecture / Architecture hybride

- `KEM layer` : supports an optional real post-quantum KEM backend when installed.
- `Chaos layer` : deterministic automaton `E(PK, ε)` produces `S_final` from public inputs.
- `HKDF layer` : fuses the two secrets into a single session key.

### Architecture hybride

- `couche KEM` : supporte un backend post-quantique réel si installé.
- `couche chaos` : l'automate déterministe `E(PK, ε)` produit `S_final` à partir d'entrées publiques.
- `couche HKDF` : fusionne les deux secrets en une clé unique.

### Security goals / Objectifs de sécurité

- Post-quantum resilience / Résistance post-quantique
- Deterministic reproducibility / Reproductibilité déterministe
- Artifact integrity / Intégrité des artefacts
- Clear attack separation / Séparation stricte des couches

---

## Design Summary / Résumé de conception

### Data flow / Flux de données

1. Sender generates a random public seed `ε`.
2. Sender computes `S_final = E(PK_rec, ε)`.
3. Sender performs `KEM.Enc(pk_rec)` to obtain `(C_kyber, SS_kyber)`.
4. Sender derives `K_final = HKDF(SS_kyber || S_final, salt=H(pk_rec), info="aetherium-v1")`.
5. Sender builds artifact `A = (C_kyber, S_final, Σ, C, ε)` and sends it.

### Protocol flow / Flux du protocole

1. L'émetteur génère une graine publique `ε`.
2. L'émetteur calcule `S_final = E(PK_rec, ε)`.
3. L'émetteur exécute `KEM.Enc(pk_rec)` pour obtenir `(C_kyber, SS_kyber)`.
4. L'émetteur dérive `K_final = HKDF(SS_kyber || S_final, salt=H(pk_rec), info="aetherium-v1")`.
5. L'émetteur construit l'artefact `A = (C_kyber, S_final, Σ, C, ε)` et l'envoie.

### Artifact validation / Validation de l'artefact

On receipt, the recipient:

- verifies the integrity tag `C`,
- decapsulates the KEM ciphertext to recover `SS_kyber`,
- recomputes `S_final` from `ε`,
- derives `K_final` with the same HKDF formula,
- checks the binding proof `Σ`.

### Validation de l'artefact

À la réception, le destinataire :

- vérifie le tag d'intégrité `C`,
- décapsule le ciphertext KEM pour retrouver `SS_kyber`,
- recompute `S_final` à partir de `ε`,
- dérive `K_final` avec la même formule HKDF,
- vérifie la preuve de liaison `Σ`.

---

## Implementation / Implémentation

### Files / Fichiers

- `aetherium.py` : core hybrid KEM implementation.
- `chiffrement.py` : demonstrative LWE-like encryption module.
- `aetherium_combined.py` : unified entrypoint and demo runner.
- `tests/` : unit tests for Aetherium and chiffrement.

### How it works / Comment ça marche

- `aetherium.py` computes its chaos function deterministically, so the recipient can rebuild the same state.
- The implementation supports a real KEM backend when `pqcrypto` or `kyber_py` is installed.
- Without a real KEM, the repository still works with a deterministic stub for exploration and validation.

---

## Getting started / Démarrage rapide

### Requirements / Prérequis

```bash
python -m pip install pytest numpy
```

Optional:

```bash
python -m pip install pqcrypto
```

### Run the hybrid demo / Exécuter la démo hybride

```bash
cd aetherium
python aetherium_combined.py --action all
```

### Run unit tests / Lancer les tests

```bash
python -m pytest -q
```

### Run the encryption demo / Exécuter le chiffrement

```bash
python aetherium_combined.py --action chiffrement
```

---

## White paper elements / Éléments pour white paper

### Problem statement / Problème adressé

Conventional KEMs can be broken by future quantum computers. Aetherium aims to harden the encapsulation process by adding a second entropy source that is deterministic and public, while remaining unpredictable without the private key and seed relationship.

### Technical novelty / Innovation technique

Aetherium is not just "KEM + chaos". It uses a deterministic chaotic automaton whose state depends on the recipient public key and a public seed. This state is fused with the KEM secret using HKDF, creating a hybrid key that depends on both algebraic hardness and chaotic state complexity.

### Research value / Valeur de recherche

- provides a reference Python implementation,
- isolates the chaotic state function for analysis,
- demonstrates how a deterministic entropy layer can be integrated with a KEM,
- keeps the design reproducible and audit-friendly.

### Contributions / Contributions

- hybrid KEM construction with deterministic chaos,
- clean implementation split across `aetherium.py`, `chiffrement.py`, and `aetherium_combined.py`,
- unit tests and usage examples,
- bilingual README for GitHub readers.

---

## Status / Statut

- ✅ Reference Python implementation complete
- ✅ Deterministic chaos layer implemented
- ✅ Unit tests passing
- ⚠️ Real Kyber backend optional and installable with `pqcrypto`
- 🔲 Third-party security audit pending
- 🔲 Formal specification publication pending

---

## License / Licence

This project is released under the **Apache 2.0** license.

Ce projet est distribué sous licence **Apache 2.0**.

---

## Contact / Contribution

Contributions are welcome. Please open issues or pull requests if you want to:

- improve the chaotic automaton,
- integrate a real post-quantum KEM backend,
- strengthen security proofs,
- make the implementation production-ready.

Les contributions sont bienvenues. Ouvrez une issue ou une pull request si vous souhaitez :

- améliorer l'automate chaotique,
- intégrer un véritable backend KEM post-quantique,
- renforcer les preuves de sécurité,
- rendre l'implémentation prête pour la production.